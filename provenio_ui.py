#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Provenio UI — современный интерфейс (чёрно-фиолетовое стекло, Apple-motion).
Запуск: python provenio_ui.py   (provenio.py, provenio_tools.py, provenio_osint.py рядом)
Готовая сборка: Provenio.exe (см. build.ps1).

Окно: pywebview (движок Edge WebView2). Если его нет — интерфейс откроется в браузере.
Сервер слушает только 127.0.0.1 на случайном порту и защищён одноразовым токеном.
"""
import base64
import json
import os
import secrets
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
import webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import provenio as P
import provenio_tools as TL
import provenio_osint  # noqa: F401  (регистрирует новые инструменты в TL.TOOLS)
import provenio_plus as X   # 2.1: фишинг, IP-радар, утечки, глобус, сценарии, ИИ-сводка
import provenio_auth as A   # 2.2: локальная учётная запись
import provenio_labs as XL  # 2.3: XSS-лаборатория (отдельный сервер, другой origin)
import provenio_sec as SEC  # 2.4: магия, криминалистика фото, email, вымогатели, CT-поток
import provenio_lan as LANM  # 2.6: интерфейс на телефоне через домашнюю сеть
import provenio_unique as UQ  # 2.5: якоря OpenTimestamps, свидетель, атрибуция, геопазл, самоаудит, ритм жизни
import hashlib

S = P.Store()
LOCK = S.lock
TOKEN = secrets.token_urlsafe(24)       # токен страницы: до входа открывает только вход/регистрацию и документы
SESSIONS = {}                            # токены сеансов после входа (компьютер и телефоны): {токен: {user, lan}}
ACC = A.Accounts(os.path.join(P.DATA_DIR, "account.json"))
LEGAL_DOCS = {"terms": "TERMS.md", "privacy": "PRIVACY.md", "refund": "REFUND.md", "thirdparty": "THIRD_PARTY.md"}
TL.configure(P.load_settings())
JOBS = {}
BLOBS = {}
UPDATE = {"ts": 0, "data": None}
MAX_BODY = 45 * 1024 * 1024   # загрузка файлов для анализа метаданных / проверки пакета
PLATFORM = os.environ.get("PROVENIO_PLATFORM", "desktop")   # "ios" — приложение для iPhone
EXPORT_DIR = os.environ.get("PROVENIO_EXPORT_DIR", "")       # куда сохранять экспорт на iPhone («Файлы»)


def capture_fn():
    """Функция снимка экрана/PDF по настройкам (или None, если выключено)."""
    st = P.load_settings()
    shot, pdf = bool(st.get("capture_screenshot")), bool(st.get("capture_pdf"))
    if not (shot or pdf) or not X.find_browser():
        return None
    return lambda url: X.capture_page(url, screenshot=shot, pdf=pdf)


def case_by_id(cid):
    return S.case(cid)


def state(cid):
    with LOCK:
        srcs, ents = S.sources(cid), S.entities(cid)
        ok, bad = S.verify_snapshots(cid)
        chain, _ = S.verify_audit()
        mons = {m["source_id"]: m for m in S.monitors(cid)}
        children = {}
        for s in srcs:
            if s.get("parent_id"):
                children[s["parent_id"]] = children.get(s["parent_id"], 0) + 1
        keys = ("id", "url", "title", "fetched", "status", "size", "sha256", "snapshot", "reliability",
                "note", "kind", "tool", "query", "parent_id", "found_on")
        atts = S.attachments(cid)
        inter = {(x["type"], x["value"]): [c["name"] for c in x["cases"] if c["id"] != cid]
                 for x in S.intersections(cid)}
        audit = [dict(r) for r in S.db.execute(
            "SELECT id,ts,action,detail,hash FROM audit ORDER BY id DESC LIMIT 300")]
    out_src = []
    for s in srcs:
        d = {k: s.get(k) for k in keys}
        m = mons.get(s["id"])
        d["monitor"] = {"interval": m["interval_min"], "last": m["last_check"], "changes": m["changes"]} if m else None
        d["versions"] = children.get(s["id"], 0)
        d["att"] = [{"kind": a["kind"], "file": a["file"], "sha256": a["sha256"], "size": a["size"]}
                    for a in atts.get(s["id"], [])]
        out_src.append(d)
    return {
        "sources": out_src,
        "entities": [{"id": e["id"], "type": e["type"], "value": e["value"],
                      "conf": e["confidence"], "src": [s["id"] for s in e["sources"]],
                      "other": inter.get((e["type"], e["value"]), [])} for e in ents],
        "audit": audit,
        "integrity": {"snap_ok": ok, "snap_bad": len(bad), "chain": chain},
    }


# ----------------------------------------------------------------- фоновые задачи
def start_job(body):
    name = str(body.get("name"))
    if name not in TL.TOOLS:
        raise KeyError(f"Неизвестный инструмент: {name}")
    jid = uuid.uuid4().hex[:12]
    job = TL.Job()
    rec = {"id": jid, "name": name, "q": str(body.get("q", ""))[:200], "job": job, "state": "running",
           "result": None, "error": None, "started": time.time(), "saved": None}
    params = {k: v for k, v in body.items() if k not in ("name", "case", "pivot", "autosave")}
    JOBS[jid] = rec

    def work():
        try:
            rec["result"] = TL.run_tool(name, params, job)
            rec["state"] = "done"
            if body.get("autosave") and body.get("case"):
                rec["saved"] = save_job(rec, int(body["case"]), body.get("pivot"))
        except TL.Cancelled:
            rec["state"] = "cancelled"
        except Exception as e:
            rec["state"] = "error"
            rec["error"] = f"{type(e).__name__}: {str(e)[:300]}"
    threading.Thread(target=work, daemon=True).start()
    # уборка старых задач
    for k in [k for k, r in JOBS.items() if time.time() - r["started"] > 3600 and r["state"] != "running"]:
        JOBS.pop(k, None)
    return {"id": jid}


def start_custom(name, q, fn, saveable=True):
    """Фоновая задача из произвольной функции fn(job) -> результат."""
    jid = uuid.uuid4().hex[:12]
    job = TL.Job()
    rec = {"id": jid, "name": name, "q": str(q)[:200], "job": job, "state": "running", "result": None,
           "error": None, "started": time.time(), "saved": None, "saveable": saveable}
    JOBS[jid] = rec

    def work():
        try:
            rec["result"] = fn(job)
            rec["state"] = "done"
        except TL.Cancelled:
            rec["state"] = "cancelled"
        except Exception as e:
            traceback.print_exc()
            rec["state"] = "error"
            rec["error"] = f"{type(e).__name__}: {str(e)[:300]}"
    threading.Thread(target=work, daemon=True).start()
    return {"id": jid}


def run_playbook(case_id, pid, q, job):
    steps = X.playbook_steps(pid, q)
    pb = X.PLAYBOOKS[pid]
    job.total(len(steps) + (1 if pb.get("archive") else 0))
    out = []
    if pb.get("archive"):
        job.note("Архивирование страницы…")
        sid, st = S.add_source(case_id, q if "://" in q else "https://" + q, capture=capture_fn())
        out.append({"tool": "archive", "q": q, "state": "done" if st.startswith("OK") else "error",
                    "source": sid, "error": None if st.startswith("OK") else st})
        job.step()

    def one(step):
        tool, val = step
        job.check()
        sub = TL.Job()
        sub.cancelled = job.cancelled
        try:
            res = TL.run_tool(tool, {"q": val}, sub)
            sid, n = S.add_tool_result(case_id, tool, val, res)
            return {"tool": tool, "q": val, "state": "done", "source": sid, "entities": n}
        except TL.Cancelled:
            raise
        except Exception as e:
            return {"tool": tool, "q": val, "state": "error", "error": f"{type(e).__name__}: {str(e)[:160]}"}
    job.note(f"Сценарий «{pb['title']}»: {len(steps)} инструментов…")
    for it, r, err in TL.pmap(one, steps, job, workers=3):
        out.append(r or {"tool": it[0], "q": it[1], "state": "error", "error": err})
    S.audit("playbook_run", f"{pb['title']} | {q} | шагов {len(out)}")
    return {"playbook": pb["title"], "query": q, "steps": out,
            "ok": sum(1 for x in out if x["state"] == "done"), "failed": sum(1 for x in out if x["state"] != "done")}


def run_expand(case_id, sid, depth, limit, same_host, job):
    """Обход ссылок источника на глубину N: каждая страница архивируется как отдельный источник."""
    src = S.source(sid)
    if not src or src.get("kind") != "web":
        raise ValueError("Обход возможен только для веб-источника")
    have = {s["url"] for s in S.sources(case_id)} | {s["final_url"] for s in S.sources(case_id)}
    root_host = P.host_of(src["final_url"] or src["url"])
    frontier, added, failed = [(sid, 0)], [], 0
    job.total(limit)
    while frontier and len(added) < limit:
        cur, d = frontier.pop(0)
        if d >= depth:
            continue
        for u in S.page_links(cur):
            if len(added) >= limit:
                break
            job.check()
            if u in have or X.O._SKIP_EXT.search(u):
                continue
            if same_host and P.host_of(u) != root_host:
                continue
            have.add(u)
            job.note(f"Архивирование {u[:80]}")
            nid, st = S.add_source(case_id, u, found_on=cur)
            added.append({"id": nid, "url": u, "status": st, "depth": d + 1})
            if st.startswith("OK"):
                frontier.append((nid, d + 1))
            else:
                failed += 1
            job.step()
    S.audit("links_expanded", f"id={sid} depth={depth} added={len(added)}")
    return {"root": sid, "added": len(added), "failed": failed, "pages": added}


def case_geo(cid):
    """Точки кейса для глобуса: IP-адреса (геолокация) и GPS из метаданных фото."""
    ents = S.entities(cid)
    ips = [e for e in ents if e["type"] == "ip"]
    geo = X.geolocate_ips([e["value"] for e in ips])
    pts = []
    for e in ips:
        g = geo.get(e["value"]) or {}
        if g.get("lat") is not None:
            pts.append({"kind": "ip", "label": e["value"], "lat": g["lat"], "lon": g["lon"], "entity": e["id"],
                        "conf": e["confidence"], "info": f"{g.get('city') or ''}, {g.get('country') or ''} · "
                                                         f"{g.get('isp') or ''}"})
    for s in S.sources(cid):
        if s.get("tool") != "file_meta":
            continue
        try:
            res = json.loads((S.snapshot_bytes(s) or b"{}").decode("utf-8")).get("result") or {}
        except ValueError:
            continue
        g = res.get("gps")
        if g and g.get("lat") is not None:
            pts.append({"kind": "photo", "label": res.get("name") or s.get("query"), "lat": g["lat"],
                        "lon": g["lon"], "source": s["id"], "info": "GPS из метаданных файла"})
    return {"items": pts, "ips_total": len(ips)}


def brand_loop_once():
    for m in S.due_brand_monitors():
        try:
            base = json.loads(m["baseline"] or "{}")
            snap = X.brand_snapshot(m["domain"])
            d = X.brand_diff(base, snap)
            changed = bool(d["new_lookalikes"] or d["new_subdomains"])
            if changed:
                S.add_tool_result(m["case_id"], "brand_monitor", m["domain"], {**d, "domain": m["domain"]})
                S.notify(m["case_id"], f"Бренд {m['domain']}: новых двойников {len(d['new_lookalikes'])}, "
                                       f"новых поддоменов {len(d['new_subdomains'])}")
            S.update_brand_monitor(m["id"], snap, changed)
        except Exception:
            traceback.print_exc()
            S.update_brand_monitor(m["id"], json.loads(m["baseline"] or "{}"), False)


def save_job(rec, case_id, pivot=None):
    if rec["state"] != "done":
        raise ValueError("Задача ещё не завершена")
    if rec.get("saveable") is False:
        raise ValueError("Результаты этой задачи уже сохранены в кейс")
    q = rec["q"] if rec["name"] not in ("file_meta", "evidence_verify") else \
        (rec["result"] or {}).get("name") or rec["q"] or "файл"
    result = json.loads(TL.redact(json.dumps(rec["result"], ensure_ascii=False, default=str)))
    sid, n = S.add_tool_result(case_id, rec["name"], q, result,
                               pivot=tuple(pivot) if pivot else None)
    rec["saved"] = {"source": sid, "entities": n}
    return rec["saved"]


def job_status(jid):
    rec = JOBS.get(jid)
    if not rec:
        raise KeyError("Задача не найдена")
    j = rec["job"]
    out = {"id": jid, "state": rec["state"], "done": j.done, "all": j.all, "msg": j.msg,
           "error": rec["error"], "saved": rec["saved"], "elapsed": round(time.time() - rec["started"], 1)}
    if rec["state"] == "done":
        out["result"] = rec["result"]
    return out


# ----------------------------------------------------------------- мониторинг страниц
def monitor_loop():
    last_brand = 0
    try:
        sec_init()
    except Exception:
        traceback.print_exc()
    try:
        if lan_cfg().get("autostart"):
            lan_start()
    except Exception:
        traceback.print_exc()
    while True:
        time.sleep(30)
        threading.Thread(target=SEC.RW.check, daemon=True).start()   # сама решает, пора ли (раз в 6 ч)
        if time.time() - globals().get("_LAST_ANCHOR", 0) > 3600:
            globals()["_LAST_ANCHOR"] = time.time()
            threading.Thread(target=anchors_loop_once, daemon=True).start()
        try:
            for sid in S.due_monitors():
                S.check_monitor(sid, capture=capture_fn())
        except Exception:
            traceback.print_exc()
        if time.time() - last_brand > 120:
            last_brand = time.time()
            threading.Thread(target=brand_loop_once, daemon=True).start()


# ----------------------------------------------------------------- 2.6: «Открыть на телефоне» (домашняя сеть)
LAN = {"srv": None, "ip": None, "port": None}


def lan_cfg():
    try:
        with open(os.path.join(P.DATA_DIR, "lan.json"), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    if not d.get("key"):
        d["key"] = secrets.token_urlsafe(18)
    d.setdefault("port", 48765)
    d.setdefault("autostart", False)
    return d


def lan_save(d):
    os.makedirs(P.DATA_DIR, exist_ok=True)
    with open(os.path.join(P.DATA_DIR, "lan.json"), "w", encoding="utf-8") as f:
        json.dump(d, f)


def lan_url(d=None):
    d = d or lan_cfg()
    return f"http://{LAN['ip']}:{LAN['port']}/?k={d['key']}" if LAN["srv"] else ""


def lan_start():
    if LAN["srv"]:
        return
    d = lan_cfg()
    ip = LANM.lan_ip()
    if ip.startswith("127."):
        raise ValueError("Компьютер не подключён к локальной сети (Wi-Fi или кабель)")
    try:
        srv = LANM.ExclusiveServer((ip, int(d["port"])), LanHandler)
    except OSError:
        srv = LANM.ExclusiveServer((ip, 0), LanHandler)        # порт занят — берём любой и запоминаем
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    LAN.update(srv=srv, ip=ip, port=srv.server_address[1])
    d["port"] = LAN["port"]
    lan_save(d)
    S.audit("lan_on", f"http://{ip}:{LAN['port']}/")


def lan_stop():
    srv = LAN["srv"]
    if srv:
        LAN.update(srv=None)
        threading.Thread(target=srv.shutdown, daemon=True).start()
        for t in [t for t, s in SESSIONS.items() if s.get("lan")]:
            SESSIONS.pop(t, None)                       # телефоны выходят из аккаунта
        S.audit("lan_off", "")


def lan_api(body):
    a = body.get("action")
    d = lan_cfg()
    if a == "start":
        lan_start()
    elif a == "stop":
        lan_stop()
    elif a == "rotate":
        d["key"] = secrets.token_urlsafe(18)
        lan_save(d)
        for t in [t for t, s in SESSIONS.items() if s.get("lan")]:
            SESSIONS.pop(t, None)
        S.audit("lan_key_rotated", "")
    elif a == "autostart":
        d["autostart"] = bool(body.get("value"))
        lan_save(d)
    d = lan_cfg()
    url = lan_url(d)
    return {"on": bool(LAN["srv"]), "url": url, "ip": LAN["ip"], "port": LAN["port"], "autostart": d["autostart"],
            "qr": LANM.qr_svg(url, scale=5) if url else "",
            "phones": sum(1 for s in SESSIONS.values() if s.get("lan"))}


# ----------------------------------------------------------------- 2.5: якоря, свидетель, гипотезы, геопазл
def anchor_public(a):
    info = {}
    try:
        info = UQ.ots_info(a["proof"])
    except Exception:
        pass
    return {k: a[k] for k in ("id", "case_id", "created", "kind", "subject", "digest", "status", "height", "block_time")} | \
        {"calendars": info.get("pending", [])}


def anchor_check(aid):
    a = next((x for x in S.anchors() if x["id"] == aid), None)
    if not a:
        raise KeyError("Нет такого якоря")
    proof, _ = UQ.ots_upgrade(a["proof"])
    info = UQ.ots_verify(proof)
    ok = [v for v in info["verified"] if v.get("ok")]
    if ok:
        S.update_anchor(aid, proof, "confirmed", ok[0]["height"], ok[0]["time"])
    elif proof != a["proof"]:
        S.update_anchor(aid, proof, "pending")
    return anchor_public(next(x for x in S.anchors() if x["id"] == aid))


def anchors_loop_once():
    for a in S.anchors(pending_only=True):
        try:
            anchor_check(a["id"])
        except Exception:
            traceback.print_exc()


def unique_api(path, q, body):
    qv = lambda k: (q.get(k) or [""])[0]   # noqa: E731
    if path == "anchors":
        return [anchor_public(a) for a in S.anchors(int(qv("case")))]
    if path == "anchor":
        c = case_by_id(int(body["case"]))
        S.audit("anchor_requested", f"case={c['id']} {c['name']}")
        head = S.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()["hash"]
        digest = hashlib.sha256(head.encode()).digest()
        proof, cals = UQ.ots_stamp(digest)
        aid = S.add_anchor(c["id"], "audit", f"audit_head:{head}", digest.hex(), proof)
        return {"id": aid, "calendars": cals, "audit_head": head}
    if path == "anchor_check":
        return anchor_check(int(body["id"]))
    if path == "witness":
        sid = int(body["id"])
        src = S.source(sid)
        ours = P.snapshot_text(S.snapshot_bytes(src) or b"")

        def work(job):
            job.note("Internet Archive сохраняет страницу (до 2 минут)…")
            r = UQ.witness(src["final_url"] or src["url"], ours)
            S.add_attachment(sid, "witness", json.dumps(r, ensure_ascii=False, indent=1).encode(), "json",
                             note=f"{r['verdict'] or ''} {r['similarity'] if r['similarity'] is not None else ''}%")
            return r
        return start_custom("witness", src["url"], work, saveable=False)
    if path == "ach":
        cid = int(body.get("case") or qv("case"))
        if body.get("data") is not None:
            S.ach_set(cid, body["data"])
        data, upd = S.ach_get(cid)
        return {"data": data, "updated": upd}
    if path == "geopuzzle_features":
        return [{"id": k, "label": v[0]} for k, v in UQ.FEATURES.items()] + [{"id": "custom", "label": "🏷 Свой тег OSM…"}]
    if path == "geopuzzle":
        params = {k: body.get(k) for k in ("area", "bbox", "anchor", "anchor_custom", "constraints", "name")}
        return start_custom("geopuzzle", params.get("area") or "вид глобуса", lambda job: UQ.geopuzzle({**params, "_job": job}))
    raise KeyError(path)


# ----------------------------------------------------------------- 2.4: CT-поток и наблюдение за вымогателями
def sec_api(path, body):
    if path == "ct":
        a = body.get("action")
        if a == "config":
            SEC.CT.configure(body.get("keywords"), body.get("allow"), body.get("background"))
        elif a == "start":
            SEC.CT.start()
        elif a == "stop":
            SEC.CT.stop()
        return SEC.CT.status()
    if path == "ransom_watch":
        if body.get("keywords") is not None:
            SEC.RW.set_keywords(body["keywords"])
            threading.Thread(target=SEC.RW.check, kwargs={"force": True}, daemon=True).start()
        return {"keywords": SEC.RW.cfg["keywords"], "last": SEC.RW.cfg.get("last", 0)}
    raise KeyError(path)


def sec_init():
    SEC.CT.notify = lambda text: S.notify(None, text)
    SEC.RW.notify = lambda text: S.notify(None, text)
    SEC.CT.load()
    SEC.RW.load()
    if SEC.CT.cfg.get("background"):
        SEC.CT.start()


# ----------------------------------------------------------------- учётная запись
def legal_doc(name):
    fn = LEGAL_DOCS.get(str(name))
    if not fn:
        raise KeyError("Нет такого документа")
    with open(TL.res_path(os.path.join("legal", fn)), encoding="utf-8") as f:
        return {"name": name, "text": f.read()}


def new_session(user, lan=False):
    tok = secrets.token_urlsafe(32)
    SESSIONS[tok] = {"user": user["username"], "lan": lan, "created": time.time()}
    return {"token": tok, "user": user}


def current_user():
    return ACC.public().get("username", "")


def auth_api(path, body, logged_in, lan=False):
    """Запросы, доступные до входа (с токеном страницы)."""
    if path == "auth/status":
        return {**ACC.public(), "logged_in": logged_in, "platform": PLATFORM}
    if path == "auth/register":
        user = ACC.register(body.get("username"), body.get("password"), body.get("password2"), body.get("birth"),
                            body.get("accept_terms"), body.get("accept_privacy"))
        cur = P.load_settings()
        cur["check_updates"] = body.get("check_updates") is True   # только по явному согласию
        TL.configure(P.save_settings(cur))
        S.audit("account_created", f"user={user['username']} terms={A.TERMS_VERSION} age_verified=18+")
        return new_session(user, lan)
    if path == "auth/login":
        user = ACC.login(body.get("username"), body.get("password"))
        S.audit("login", f"user={user['username']}" + (" (телефон, домашняя сеть)" if lan else ""))
        return new_session(user, lan)
    if path == "legal":
        return legal_doc(body.get("doc"))
    raise KeyError(path)


def account_api(path, body, tok=""):
    """Запросы, доступные только после входа."""
    global S, LOCK
    if path == "auth/logout":
        S.audit("logout", f"user={current_user()}")
        SESSIONS.pop(tok, None)
        return {}
    if path == "auth/password":
        ACC.change_password(body.get("old"), body.get("new"), body.get("new2"))
        S.audit("password_changed", f"user={current_user()}")
        for t in [t for t in SESSIONS if t != tok]:
            SESSIONS.pop(t, None)                       # смена пароля завершает остальные сеансы
        return {"message": "Пароль изменён"}
    if path == "auth/accept_terms":
        ACC.accept_terms()
        return ACC.public()
    if path == "auth/delete":
        ACC.check_password(body.get("password"))
        if str(body.get("confirm", "")).strip().upper() not in ("УДАЛИТЬ", "DELETE"):
            raise ValueError("Введите слово УДАЛИТЬ для подтверждения")
        for rec in JOBS.values():
            rec["job"].cancelled = True
        SEC.CT.stop()
        with LOCK:
            S.db.close()
            failed = A.wipe_data_dir(P.DATA_DIR)
            S = P.Store(P.DB_PATH, P.SNAP_DIR)   # пустая база; старые данные 1.x повторно не импортируются
            LOCK = S.lock
        JOBS.clear()
        BLOBS.clear()
        TL.configure(P.load_settings())
        SEC.CT.cfg.update({"keywords": [], "allow": [], "background": False})
        SEC.CT.load()
        SEC.RW.cfg.update({"keywords": [], "seen": {}, "last": 0})
        SESSIONS.clear()
        lan_stop()
        return {"deleted": True, "left": failed}
    raise KeyError(path)


# ----------------------------------------------------------------- XSS-лаборатория
def labs_progress_path():
    return os.path.join(P.DATA_DIR, "labs.json")


def labs_progress():
    try:
        with open(labs_progress_path(), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    return {"solved": d.get("solved") or {}, "revealed": d.get("revealed") or [], "hints": d.get("hints") or {}}


def labs_save(d):
    os.makedirs(P.DATA_DIR, exist_ok=True)
    with open(labs_progress_path(), "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False)


def labs_api(path, q, body):
    qv = lambda k: (q.get(k) or [""])[0]   # noqa: E731
    if path == "labs":
        pr = labs_progress()
        fixes = {k: XL.BY_ID[int(k)]["fix"] for k in pr["solved"] if int(k) in XL.BY_ID}
        return {"port": XL.ensure_server(), "secret": XL.SECRET, "labs": XL.catalog(), "levels": XL.LEVELS,
                "progress": pr, "fixes": fixes}
    lab_id = int(body.get("id") or qv("id"))
    if lab_id not in XL.BY_ID:
        raise KeyError("Нет такой лабы")
    pr = labs_progress()
    if path == "labs_solved":
        if not secrets.compare_digest(str(body.get("k", "")), XL.SECRET):
            raise ValueError("Решение не подтверждено")
        first = str(lab_id) not in pr["solved"]
        pr["solved"].setdefault(str(lab_id), {"ts": P.now_iso(), "fn": str(body.get("fn", ""))[:20],
                                              "hints": pr["hints"].get(str(lab_id), 0),
                                              "revealed": lab_id in pr["revealed"]})
        labs_save(pr)
        return {"first": first, "fix": XL.BY_ID[lab_id]["fix"], "solved": len(pr["solved"])}
    if path == "labs_hint":
        pr["hints"][str(lab_id)] = max(pr["hints"].get(str(lab_id), 0), min(3, int(body.get("n") or 1)))
        labs_save(pr)
        return {}
    if path == "labs_reveal":
        if lab_id not in pr["revealed"]:
            pr["revealed"].append(lab_id)
            labs_save(pr)
        return XL.reveal(lab_id)
    if path == "labs_reset":
        XL.reset(lab_id)
        return {}
    if path == "labs_exploit":
        XL.set_exploit(lab_id, body.get("html", ""))
        return {}
    raise KeyError(path)


# ----------------------------------------------------------------- настройки
def settings_public():
    s = P.load_settings()
    keys = {k: (("•" * 6 + v[-4:]) if v else "") for k, v in s["keys"].items()}
    out = {"proxy": s["proxy"], "timeout": s["timeout"], "keys": keys}
    for k in P.OPTIONS:
        out[k] = s.get(k)
    return out


def settings_save(body):
    cur = P.load_settings()
    new_keys = dict(cur["keys"])
    for k, v in (body.get("keys") or {}).items():
        if v is None or (isinstance(v, str) and v.startswith("•")):
            continue   # поле не меняли
        new_keys[k] = str(v).strip()
    new = {"proxy": body.get("proxy", cur["proxy"]), "timeout": body.get("timeout", cur["timeout"]),
           "keys": new_keys}
    for k in P.OPTIONS:
        new[k] = body.get(k, cur.get(k))
    s = P.save_settings(new)
    TL.configure(s)
    S.audit("settings_changed", "proxy=" + ("да" if s["proxy"] else "нет") +
            " keys=" + ",".join(k for k, v in s["keys"].items() if v))
    return settings_public()


def api(path, q, body):
    qv = lambda k: (q.get(k) or [""])[0]   # noqa: E731
    if path == "cases":
        return S.cases()
    if path == "case":
        name = str(body.get("name", "")).strip()[:80]
        if not name:
            raise ValueError("Пустое название")
        return {"id": S.add_case(name)}
    if path == "state":
        return state(int(qv("case")))
    if path == "add":
        sid, status = S.add_source(int(body["case"]), str(body["url"])[:2000], capture=capture_fn())
        return {"id": sid, "status": status, "attachments": len(S.attachments(int(body["case"])).get(sid, []))}
    if path == "intersections":
        return S.intersections(int(qv("case")) if qv("case") else None)
    if path == "dossier":
        return S.dossier(int(qv("case")), int(qv("id")))
    if path == "expand":
        cid, sid = int(body["case"]), int(body["id"])
        depth, limit = max(1, min(3, int(body.get("depth") or 1))), max(1, min(80, int(body.get("limit") or 25)))
        return start_custom("expand", f"#{sid}", lambda job: run_expand(cid, sid, depth, limit,
                                                                         bool(body.get("same_host", True)), job),
                            saveable=False)
    if path == "playbooks":
        return [{"id": k, "title": v["title"], "ph": v["ph"], "steps": v["steps"], "archive": bool(v.get("archive"))}
                for k, v in X.PLAYBOOKS.items()]
    if path == "playbook":
        cid, pid, qq = int(body["case"]), str(body["id"]), str(body.get("q", "")).strip()[:300]
        if not qq:
            raise ValueError("Введите значение для сценария")
        return start_custom("playbook", qq, lambda job: run_playbook(cid, pid, qq, job), saveable=False)
    if path == "capture":
        sid = int(body["id"])
        src = S.source(sid)
        fn = capture_fn() or (lambda url: X.capture_page(url, True, True))
        return start_custom("capture", src["url"], lambda job: {
            "added": S.capture_into(sid, src["final_url"] or src["url"], fn)}, saveable=False)
    if path == "brand":
        if body:
            cid, dom, iv = int(body["case"]), TL._host(str(body["domain"])), int(body.get("interval") or 0)
            if not iv:
                S.set_brand_monitor(cid, dom, 0)
                return {"off": True}

            def first(job):
                snap = X.brand_snapshot(dom, job)
                S.set_brand_monitor(cid, dom, iv, snap)
                S.add_tool_result(cid, "brand_monitor", dom, {"domain": dom, "baseline": True, **snap})
                return {"domain": dom, "lookalikes": len(snap["lookalikes"]), "subdomains": len(snap["subdomains"])}
            return start_custom("brand", dom, first, saveable=False)
        return [{k: v for k, v in m.items() if k != "baseline"}
                for m in S.brand_monitors(int(qv("case")) if qv("case") else None)]
    if path == "update_check":
        if time.time() - UPDATE["ts"] > 6 * 3600 or qv("force"):
            UPDATE["data"], UPDATE["ts"] = X.check_update(), time.time()
        return UPDATE["data"]
    if path == "ai_summary":
        cid = int(body["case"])
        c = S.case(cid)
        st = P.load_settings()
        return start_custom("ai_summary", c["name"], lambda job: (job.note("Claude анализирует кейс…"), X.ai_summary(
            S, c, st["keys"].get("anthropic"), st.get("ai_model") or "claude-opus-5-5", st.get("proxy")))[1])
    if path == "globe":
        layer = qv("layer")
        if layer == "flights":
            bb = [float(x) for x in qv("bbox").split(",")] if qv("bbox") else None
            return X.globe_flights(bb)
        if layer == "sats":
            return X.globe_satellites(qv("group") or "stations")
        if layer == "quakes":
            return X.globe_quakes(qv("period") or "day")
        if layer == "events":
            return X.globe_events()
        if layer == "case":
            return case_geo(int(qv("case")))
        if layer == "groups":
            return X.SAT_GROUPS
        if layer == "geocode":
            return X.geocode(qv("q"))
        raise KeyError("Неизвестный слой")
    if path == "globe_save":
        obj = body.get("obj") or {}
        sid, n = S.add_tool_result(int(body["case"]), "globe", str(body.get("label") or "объект")[:150],
                                   {"layer": body.get("layer"), "object": obj, "observed": P.now_iso()})
        return {"source": sid, "entities": n}
    if path == "blob":
        data = base64.b64decode(str(body.get("data", "")).split(",")[-1])
        bid = uuid.uuid4().hex[:12]
        BLOBS.clear() if len(BLOBS) > 20 else None
        BLOBS[bid] = (data, str(body.get("ctype") or "image/png"), str(body.get("name") or "graph.png"))
        return {"id": bid}
    if path == "portable":
        return make_portable()
    if path == "open_url":
        url = str(body.get("url", ""))
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("Открываются только веб-ссылки")
        webbrowser.open(url)
        return {}
    if path == "export_save":
        data, ctype, fname = download(str(body.get("kind")), str(body.get("case")))
        folder = EXPORT_DIR or os.path.join(P.DATA_DIR, "exports")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, fname), "wb") as f:
            f.write(data)
        S.audit("export_saved", fname)
        return {"name": fname, "folder": folder}
    if path == "rel":
        S.update_source(int(body["id"]), reliability=max(1, min(5, int(body["reliability"]))))
        return {}
    if path == "note":
        S.update_source(int(body["id"]), note=str(body["note"])[:500])
        return {}
    if path == "delete":
        S.delete_source(int(body["id"]))
        return {}
    if path == "job":
        return start_job(body)
    if path == "job_status":
        return job_status(qv("id"))
    if path == "job_cancel":
        rec = JOBS.get(str(body.get("id")))
        if rec:
            rec["job"].cancelled = True
        return {}
    if path == "job_save":
        rec = JOBS.get(str(body.get("id")))
        if not rec:
            raise KeyError("Задача не найдена (результаты хранятся 1 час)")
        if rec["saved"]:
            return rec["saved"]
        return save_job(rec, int(body["case"]), body.get("pivot"))
    if path == "monitor":
        S.set_monitor(int(body["id"]), int(body.get("interval") or 0))
        return {}
    if path == "monitor_check":
        return S.check_monitor(int(body["id"]))
    if path == "versions":
        return [{k: v.get(k) for k in ("id", "fetched", "status", "sha256", "size")}
                for v in S.versions(int(qv("id")))]
    if path == "diff":
        return S.diff(int(qv("a")), int(qv("b")))
    if path == "timeline":
        return S.timeline(int(qv("case")))
    if path == "notifications":
        return S.pop_notifications()
    if path == "settings":
        return settings_save(body) if body else settings_public()
    if path.startswith("labs"):
        return labs_api(path, q, body)
    if path in ("ct", "ransom_watch"):
        return sec_api(path, body)
    if path == "lan":
        return lan_api(body)
    if path in ("anchors", "anchor", "anchor_check", "witness", "ach", "geopuzzle_features", "geopuzzle"):
        return unique_api(path, q, body)
    if path == "info":
        return {"version": P.APP_VERSION, "data_dir": P.DATA_DIR, "frozen": P.FROZEN, "portable": P.PORTABLE,
                "sites": len(TL.load_sites()), "tools": len(TL.TOOLS), "browser": X.find_browser(),
                "ai_models": list(X.AI_MODELS)}
    if path == "open_data_dir":
        if os.name == "nt":
            os.startfile(P.DATA_DIR)
        return {}
    raise KeyError(path)


def make_portable():
    """Копирует данные в папку ProvenioData рядом с exe и создаёт portable.txt."""
    if P.PORTABLE:
        return {"portable": True, "message": "Уже работает в портативном режиме"}
    import shutil
    import sqlite3
    dst = P.PORTABLE_DIR
    os.makedirs(os.path.join(dst, "snapshots"), exist_ok=True)
    with LOCK:
        con = sqlite3.connect(os.path.join(dst, "provenio.db"))
        S.db.backup(con)
        con.close()
    for name in os.listdir(S.snap_dir):
        a, b = os.path.join(S.snap_dir, name), os.path.join(dst, "snapshots", name)
        if not os.path.exists(b):
            shutil.copy2(a, b)
    if os.path.exists(P.SETTINGS_PATH):
        shutil.copy2(P.SETTINGS_PATH, os.path.join(dst, "settings.json"))
    with open(P.PORTABLE_MARK, "w", encoding="utf-8") as f:
        f.write("Provenio: портативный режим. Данные хранятся в папке ProvenioData рядом с программой.\n"
                "Удалите этот файл, чтобы вернуться к хранению в профиле пользователя.\n")
    S.audit("portable_enabled", dst)
    return {"portable": True, "message": f"Данные скопированы в {dst}. Перезапустите Provenio. "
                                        "Ключи API зашифрованы для этой учётной записи Windows — "
                                        "на другом компьютере их нужно будет ввести заново."}


def download(kind, cid):
    if kind == "blob":
        data, ctype, fname = BLOBS.pop(str(cid), (None, None, None))
        if data is None:
            raise KeyError("Файл не найден")
        return data, ctype, fname
    if kind == "ots":
        a = next((x for x in S.anchors() if x["id"] == int(cid)), None)
        if not a:
            raise KeyError("Нет такого якоря")
        return a["proof"], "application/octet-stream", f"provenio_anchor_{a['id']}_{a['digest'][:8]}.ots"
    c = case_by_id(cid)
    if not c:
        raise KeyError("Кейс не найден")
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in c["name"])[:40] or "case"
    if kind == "report":
        S.audit("report_exported", c["name"])
        return P.build_report(S, c).encode("utf-8"), "text/html; charset=utf-8", f"provenio_{safe}.html"
    if kind == "json":
        S.audit("case_exported", f"{c['name']} json")
        data = json.dumps(P.export_case(S, c), ensure_ascii=False, indent=2, default=str).encode("utf-8")
        return data, "application/json", f"provenio_{safe}.json"
    if kind == "csv":
        S.audit("case_exported", f"{c['name']} csv")
        return P.entities_csv(S, c).encode("utf-8"), "text/csv; charset=utf-8", f"provenio_{safe}_entities.csv"
    if kind in ("gexf", "graphml", "edges"):
        S.audit("graph_exported", f"{c['name']} {kind}")
        if kind == "gexf":
            return X.graph_gexf(S, c), "application/xml", f"provenio_{safe}.gexf"
        if kind == "graphml":
            return X.graph_graphml(S, c), "application/xml", f"provenio_{safe}.graphml"
        return X.graph_edges_csv(S, c), "text/csv; charset=utf-8", f"provenio_{safe}_maltego.csv"
    if kind == "evidence":
        st = P.load_settings()
        tsa = ((st.get("tsa_url") or "").strip() or P.TSA_DEFAULT) if st.get("tsa_enabled") else None
        data, mh = P.build_evidence_zip(S, c, tsa_url=tsa,
                                        ots=(lambda d: UQ.ots_stamp(d)) if st.get("ots_enabled", True) else None)
        return data, "application/zip", f"provenio_{safe}_evidence_{mh[:8]}.zip"
    if kind == "verify":
        anc = [{"kind": "OpenTimestamps → Bitcoin" + (f", блок {a['height']}" if a["height"] else ""),
                "when": a["block_time"] or a["created"], "digest": a["digest"],
                "status": "подтверждено в блокчейне" if a["status"] == "confirmed" else "ожидает включения в блок",
                "check": f"скачайте .ots в Provenio (⛓ Якоря) и проверьте на opentimestamps.org; хэшируется {a['subject'][:80]}"}
               for a in S.anchors(c["id"])]
        S.audit("verify_report_exported", c["name"])
        return UQ.build_verify_html(S, c, anc), "application/octet-stream", f"provenio_{safe}_verifiable.html"
    raise KeyError(kind)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def out(self, code, body, ctype="application/json; charset=utf-8", headers=()):
        if ctype.startswith("application/json") and not isinstance(body, (bytes, str)):
            body = json.dumps(body, ensure_ascii=False, default=str)
        if isinstance(body, str):
            if not ctype.startswith("text/html"):
                body = TL.redact(body)
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def token(self, q):
        return self.headers.get("X-Token") or (q.get("t") or [""])[0]

    lan = False

    def authorized(self, q):
        """Только после входа: токен сеанса, выданный при входе/регистрации."""
        s = SESSIONS.get(self.token(q))
        return self.host_ok() and bool(s) and s.get("lan", False) == self.lan

    def page_token_ok(self, q):
        return self.host_ok() and (secrets.compare_digest(self.token(q), TOKEN) or self.authorized(q))

    def host_ok(self):
        return self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")

    def read_body(self, method):
        if method != "POST":
            return {}
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("Слишком большой запрос (максимум 45 МБ)")
        return json.loads(self.rfile.read(n) or b"{}")

    def handle_any(self, method):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path == "/":
                if not self.host_ok():
                    return self.out(403, "forbidden", "text/plain")
                head = ""
                if self.lan:
                    k = urllib.parse.quote((q.get("k") or [""])[0])
                    head = (f'<link rel="manifest" href="/manifest.webmanifest?k={k}"><meta name="apple-mobile-web-app-capable" content="yes">'
                            '<meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">'
                            '<meta name="apple-mobile-web-app-title" content="Provenio"><meta name="theme-color" content="#030205">'
                            '<link rel="apple-touch-icon" href="/icon.png">')
                return self.out(200, PAGE.replace("__TOKEN__", TOKEN).replace("__VER__", P.APP_VERSION)
                                .replace("__PLAT__", "lan" if self.lan else PLATFORM).replace("<!--PWA-->", head),
                                "text/html; charset=utf-8")
            if u.path == "/icon.png":
                with open(TL.res_path(os.path.join("assets", "provenio.png")), "rb") as f:
                    return self.out(200, f.read(), "image/png", [("Cache-Control", "max-age=86400")])
            if u.path in ("/api/auth/status", "/api/auth/register", "/api/auth/login", "/api/legal"):
                if not self.page_token_ok(q):
                    return self.out(403, {"error": "forbidden"})
                body = self.read_body(method)
                if u.path == "/api/legal" and not body:
                    body = {"doc": (q.get("doc") or [""])[0]}
                try:
                    return self.out(200, auth_api(u.path[5:], body, self.authorized(q), lan=self.lan))
                except (KeyError, ValueError) as e:
                    return self.out(400, {"error": str(e).strip("'")})
            if not self.authorized(q):
                return self.out(401 if self.page_token_ok(q) else 403,
                                {"error": "Войдите в аккаунт" if self.page_token_ok(q) else "forbidden"})
            if u.path.startswith("/api/auth/"):
                try:
                    return self.out(200, account_api(u.path[5:], self.read_body(method), self.token(q)))
                except (KeyError, ValueError) as e:
                    return self.out(400, {"error": str(e).strip("'")})
            if u.path == "/api/tool":   # совместимость с 1.x: синхронный вызов
                body = self.read_body(method)
                try:
                    return self.out(200, {"ok": True, "data": TL.run_tool(str(body.get("name")), body)})
                except Exception as e:
                    return self.out(200, {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"})
            if u.path.startswith("/api/"):
                try:
                    return self.out(200, api(u.path[5:], q, self.read_body(method)))
                except (KeyError, ValueError) as e:
                    return self.out(400, {"error": str(e).strip("'")})
            if u.path.startswith("/download/"):
                data, ctype, fname = download(u.path[10:], (q.get("case") or q.get("id") or ["0"])[0])
                disp = "attachment" if not ctype.startswith("text/html") else "inline"
                return self.out(200, data, ctype, [(
                    "Content-Disposition",
                    f"{disp}; filename=\"{fname.encode('ascii', 'replace').decode()}\"; "
                    f"filename*=UTF-8''{urllib.parse.quote(fname)}")])
            if u.path == "/report":
                data, ctype, _ = download("report", q["case"][0])
                return self.out(200, data, ctype)
            if u.path.startswith("/snapshot/"):
                name = os.path.basename(urllib.parse.unquote(u.path[10:]))
                with open(os.path.join(S.snap_dir, name), "rb") as f:
                    data = f.read()
                if name.endswith((".png", ".pdf")):
                    return self.out(200, data, "image/png" if name.endswith(".png") else "application/pdf")
                ctype = "text/plain; charset=utf-8" if name.endswith(".json") else "text/html"
                return self.out(200, data, ctype, [(
                    "Content-Security-Policy",
                    "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:")])
            if u.path == "/static/world.json":
                with open(TL.res_path(os.path.join("assets", "world-110m.json")), "rb") as f:
                    return self.out(200, f.read(), "application/json")
            self.out(404, {"error": "not found"})
        except Exception as e:
            traceback.print_exc()
            self.out(500, {"error": TL.redact(f"{type(e).__name__}: {e}")})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


class LanHandler(Handler):
    """Тот же интерфейс для телефона в домашней сети: только локальные адреса, только с ключом из QR-кода."""
    lan = True

    def host_ok(self):
        if not LAN["srv"] or not LANM.is_local_client(self.client_address[0]):
            return False
        return self.headers.get("Host", "") == f"{LAN['ip']}:{LAN['port']}"   # защита от DNS rebinding

    def key_ok(self, q):
        return secrets.compare_digest((q.get("k") or [""])[0], lan_cfg()["key"])

    def handle_any(self, method):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if not self.host_ok():
            return self.out(403, "forbidden", "text/plain")
        if u.path in ("/", "/manifest.webmanifest") and not self.key_ok(q):
            return self.out(403, LAN_DENIED, "text/html; charset=utf-8")
        if u.path == "/manifest.webmanifest":
            k = (q.get("k") or [""])[0]
            return self.out(200, json.dumps({"name": "Provenio", "short_name": "Provenio", "display": "standalone",
                                             "start_url": f"/?k={k}", "background_color": "#030205", "theme_color": "#030205",
                                             "icons": [{"src": "/icon.png", "sizes": "512x512", "type": "image/png"}]}),
                            "application/manifest+json")
        return super().handle_any(method)


LAN_DENIED = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Provenio</title><body style="margin:0;background:#030205;color:#ece8f5;font:16px system-ui;display:grid;place-items:center;min-height:100vh;text-align:center;padding:24px">
<div><div style="font-size:44px">📱</div><h2>Откройте по QR-коду</h2><p style="color:#9b93b5">В Provenio на компьютере нажмите «📱 Открыть на телефоне»<br>и отсканируйте QR-код камерой.</p></div></body>"""

# ----------------------------------------------------------------- запуск
def _message_box(text, title="Provenio", flags=0x40):
    if os.name == "nt":
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, text, title, flags)
    else:
        print(text)


def _single_instance():
    """Один экземпляр на пользователя: второй запуск сообщает об уже открытом окне."""
    if os.name != "nt":
        return True
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    # один экземпляр на папку данных: портативная копия или другой PROVENIO_DATA не мешают друг другу
    import hashlib
    tag = hashlib.md5(os.path.abspath(P.DATA_DIR).lower().encode("utf-8")).hexdigest()[:10]
    handle = kernel32.CreateMutexW(None, False, "Local\\ProvenioOSINT_" + tag)
    globals()["_MUTEX"] = handle   # держим дескриптор до выхода
    return kernel32.GetLastError() != 183   # ERROR_ALREADY_EXISTS


def _setup_logging():
    """В exe без консоли пишем вывод и ошибки в файл журнала в каталоге данных."""
    if not P.FROZEN:
        return
    os.makedirs(P.DATA_DIR, exist_ok=True)
    log = open(os.path.join(P.DATA_DIR, "provenio.log"), "a", encoding="utf-8", buffering=1)
    log.write(f"\n=== Provenio {P.APP_VERSION} {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    sys.stdout = sys.stderr = log


def main():
    _setup_logging()
    if not _single_instance():
        _message_box("Provenio уже запущен — переключитесь на открытое окно.")
        return
    srv = LANM.ExclusiveServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=monitor_loop, daemon=True).start()
    try:
        import webview
        webview.settings["ALLOW_DOWNLOADS"] = True
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
        webview.create_window(f"Provenio {P.APP_VERSION} — OSINT с доказательной базой", url,
                              width=1400, height=900, min_size=(1100, 680), background_color="#060509",
                              text_select=True)
        storage = os.path.join(P.DATA_DIR, "webview")
        try:
            webview.start(gui="edgechromium", private_mode=False, storage_path=storage)
        except TypeError:
            webview.start(private_mode=False, storage_path=storage)
    except Exception as e:   # нет pywebview или WebView2 — работаем в браузере
        traceback.print_exc()
        webbrowser.open(url)
        if P.FROZEN:
            _message_box(f"Provenio открыт в браузере:\n{url}\n\nНе закрывайте это окно, пока работаете.\n"
                         f"Нажмите OK, чтобы завершить работу.\n\n(Отдельное окно недоступно: {type(e).__name__})")
        else:
            print(f"Provenio запущен: {url}\n(Для отдельного окна: pip install pywebview)\nCtrl+C — выход")
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                pass
    srv.shutdown()


PAGE = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Provenio</title><!--PWA-->
<style>
:root{
 --bg:#060509; --bg2:#0a0713; --panel:rgba(20,14,34,.55);
 --card:rgba(255,255,255,.035); --card2:rgba(255,255,255,.06);
 --bd:rgba(168,130,255,.14); --bd2:rgba(168,130,255,.28);
 --tx:#ece8f5; --mu:#9b93b5; --mu2:#6f6690;
 --ac:#8b5cf6; --ac2:#c084fc; --ac3:#a855f7; --mag:#e879f9;
 --ok:#34d399; --warn:#fbbf24; --bad:#fb7185;
 --spring:cubic-bezier(.34,1.56,.64,1); --ease:cubic-bezier(.22,.9,.3,1);
 --glass:saturate(150%) blur(22px);
}
*{box-sizing:border-box;margin:0}
[hidden]{display:none!important}
html,body{height:100%}
body{font:14px/1.55 "Inter","Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--tx);
 height:100vh;overflow:hidden;display:grid;grid-template-columns:272px 1fr;
 -webkit-font-smoothing:antialiased;letter-spacing:.1px}

/* ---------- живой фон: фиолетовый mesh ---------- */
.bg{position:fixed;inset:0;z-index:-2;background:
 radial-gradient(1200px 800px at 15% -10%, #1a0f33 0%, transparent 55%),
 radial-gradient(900px 700px at 100% 0%, #230c3d 0%, transparent 50%),
 radial-gradient(1000px 900px at 50% 120%, #140a24 0%, transparent 55%), var(--bg)}
.mesh{position:fixed;inset:0;z-index:-1;overflow:hidden;pointer-events:none}
.mesh i{position:absolute;width:52vw;height:52vw;border-radius:50%;filter:blur(130px);opacity:.42;
 mix-blend-mode:screen;animation:drift 28s ease-in-out infinite alternate}
.mesh i:nth-child(1){background:#7c3aed;top:-18%;left:-12%}
.mesh i:nth-child(2){background:#c026d3;bottom:-22%;right:-14%;animation-delay:-9s;opacity:.3}
.mesh i:nth-child(3){background:#4c1d95;top:30%;left:38%;animation-delay:-16s;opacity:.28}
.grain{position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.04;
 background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='3'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}
@keyframes drift{to{transform:translate(9vw,7vh) scale(1.3) rotate(16deg)}}
@keyframes rise{from{opacity:0;transform:translateY(16px)}}
@keyframes pop{from{opacity:0;transform:scale(.9)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes shimmer{to{background-position:200% 0}}
@keyframes glowPulse{0%,100%{box-shadow:0 0 22px rgba(139,92,246,.5)}50%{box-shadow:0 0 34px rgba(192,132,252,.75)}}

/* ---------- боковая панель ---------- */
aside{padding:24px 16px;border-right:1px solid var(--bd);background:var(--panel);
 backdrop-filter:var(--glass);-webkit-backdrop-filter:var(--glass);
 display:flex;flex-direction:column;gap:18px;min-height:0;position:relative}
aside::after{content:"";position:absolute;top:0;right:0;width:1px;height:100%;
 background:linear-gradient(180deg,transparent,rgba(192,132,252,.35),transparent)}
.logo{display:flex;gap:12px;align-items:center;font-weight:800;font-size:20px;letter-spacing:.4px}
.logo b{width:36px;height:36px;border-radius:12px;background:linear-gradient(135deg,var(--ac),var(--mag));
 display:grid;place-items:center;font-size:17px;color:#fff;animation:glowPulse 4s var(--ease) infinite;
 position:relative;overflow:hidden}
.logo b::after{content:"";position:absolute;inset:0;background:linear-gradient(115deg,transparent 30%,rgba(255,255,255,.5),transparent 70%);
 background-size:220% 100%;animation:shimmer 3.5s linear infinite}
.logo span{background:linear-gradient(120deg,#fff,var(--ac2));-webkit-background-clip:text;background-clip:text;color:transparent}
.cap{font-size:10.5px;text-transform:uppercase;letter-spacing:1.6px;color:var(--mu2);font-weight:700}
.cases{display:flex;flex-direction:column;gap:5px;overflow:auto;flex:1;margin:0 -4px;padding:0 4px}
.case{padding:11px 13px;border-radius:12px;cursor:pointer;color:var(--mu);border:1px solid transparent;
 transition:all .35s var(--ease);animation:rise .5s var(--ease) both;position:relative;overflow:hidden;font-weight:500}
.case:hover{background:var(--card);color:var(--tx);transform:translateX(5px)}
.case.on{background:linear-gradient(90deg,rgba(139,92,246,.28),rgba(139,92,246,.04));
 border-color:var(--bd2);color:#fff;box-shadow:inset 0 0 0 1px rgba(192,132,252,.15)}
.case.on::before{content:"";position:absolute;left:0;top:18%;bottom:18%;width:3px;border-radius:3px;
 background:linear-gradient(var(--ac),var(--mag));box-shadow:0 0 12px var(--ac)}
.newc{display:flex;gap:7px}
input,textarea,select{background:rgba(255,255,255,.045);border:1px solid var(--bd);color:var(--tx);
 border-radius:12px;padding:11px 13px;font:inherit;outline:none;transition:all .25s var(--ease);min-width:0;width:100%}
input::placeholder{color:var(--mu2)}
input:focus,textarea:focus,select:focus{border-color:var(--ac);box-shadow:0 0 0 3.5px rgba(139,92,246,.22);
 background:rgba(255,255,255,.07)}
.hint{font-size:11px;color:var(--mu2);line-height:1.5}

/* ---------- кнопки ---------- */
.btn{position:relative;border:0;border-radius:12px;padding:11px 17px;font:700 13px inherit;color:#fff;cursor:pointer;
 background:linear-gradient(135deg,var(--ac),var(--ac3));transition:all .25s var(--spring);white-space:nowrap;
 box-shadow:0 8px 24px rgba(139,92,246,.32);overflow:hidden}
.btn::after{content:"";position:absolute;inset:0;background:linear-gradient(115deg,transparent 40%,rgba(255,255,255,.28),transparent 60%);
 background-size:220% 100%;background-position:-120% 0;transition:.5s}
.btn:hover{transform:translateY(-2px) scale(1.02);box-shadow:0 14px 34px rgba(139,92,246,.5)}
.btn:hover::after{background-position:120% 0}
.btn:active{transform:scale(.95)}
.btn.loading{pointer-events:none;color:transparent}
.btn.loading::before{content:"";position:absolute;inset:0;margin:auto;width:17px;height:17px;border-radius:50%;
 border:2px solid #fff;border-top-color:transparent;animation:spin .7s linear infinite}
.ghost{background:var(--card);border:1px solid var(--bd);color:var(--tx);border-radius:11px;padding:8px 13px;
 font:600 12px inherit;cursor:pointer;text-decoration:none;transition:all .25s var(--ease);white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.ghost:hover{background:var(--card2);transform:translateY(-1px);border-color:var(--bd2)}
.del:hover{color:var(--bad);border-color:rgba(251,113,133,.5)}

/* ---------- основная область ---------- */
main{display:flex;flex-direction:column;min-width:0;height:100vh}
header{padding:22px 28px 10px;display:flex;gap:11px;align-items:center}
header .grow{flex:1}
.pill{padding:7px 14px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid var(--bd);
 transition:all .45s var(--ease);white-space:nowrap;backdrop-filter:blur(10px)}
.pill.ok{color:var(--ok);border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.08)}
.pill.bad{color:var(--bad);border-color:rgba(251,113,133,.5);background:rgba(251,113,133,.1)}
.pill.ok::before,.pill.bad::before{content:"●";margin-right:6px;animation:glowDot 2s infinite}
@keyframes glowDot{50%{opacity:.4}}

.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:12px 28px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:18px;padding:17px;
 backdrop-filter:var(--glass);-webkit-backdrop-filter:var(--glass);transition:all .35s var(--spring);position:relative;overflow:hidden}
.card::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;
 background:linear-gradient(135deg,rgba(255,255,255,.14),transparent 40%);
 -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
.stat{animation:pop .55s var(--spring) both}
.stat:hover{transform:translateY(-4px);border-color:var(--bd2);box-shadow:0 16px 40px rgba(139,92,246,.2)}
.stat .lbl{color:var(--mu);font-size:12px;font-weight:500}
.stat b{display:block;font-size:34px;line-height:1.15;font-weight:800;margin-top:4px;
 background:linear-gradient(135deg,#fff,var(--ac2));-webkit-background-clip:text;background-clip:text;color:transparent}

.tabs{position:relative;display:flex;gap:2px;padding:8px 28px 0;border-bottom:1px solid var(--bd);margin:4px 0 16px}
.tab{background:none;border:0;color:var(--mu);padding:11px 17px;font:700 13px inherit;cursor:pointer;
 transition:color .25s;border-radius:10px 10px 0 0}
.tab:hover,.tab.on{color:#fff}
#ink{position:absolute;bottom:-1px;left:28px;height:2.5px;border-radius:3px;
 background:linear-gradient(90deg,var(--ac),var(--mag));transition:all .5s var(--spring);box-shadow:0 0 14px var(--ac)}
.panels{flex:1;overflow:auto;padding:0 28px 28px;min-height:0}
.panel{display:none}.panel.on{display:block;animation:rise .5s var(--ease)}

/* ---------- источники ---------- */
.src{margin-bottom:13px;animation:rise .55s var(--ease) both;animation-delay:calc(var(--i)*45ms)}
.src:hover{border-color:var(--bd2);transform:translateY(-2px);box-shadow:0 12px 30px rgba(0,0,0,.3)}
.row{display:flex;gap:11px;align-items:center;flex-wrap:wrap}.grow{flex:1;min-width:0}
.ttl{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.url{color:var(--ac2);font-size:12px;text-decoration:none;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.url:hover{text-decoration:underline}
.meta{display:flex;gap:15px;font-size:12px;color:var(--mu);margin:9px 0 11px;flex-wrap:wrap}
.sha{font-family:"JetBrains Mono",Consolas,monospace;cursor:pointer;transition:color .2s}.sha:hover{color:var(--ac2)}
.chip{padding:4px 11px;border-radius:99px;font-size:11px;font-weight:700}
.chip.ok{background:rgba(52,211,153,.14);color:var(--ok)}.chip.bad{background:rgba(251,113,133,.14);color:var(--bad)}
.seg{display:flex;gap:4px}.seg button{width:28px;height:28px;border-radius:9px;border:1px solid var(--bd);
 background:var(--card);color:var(--mu);cursor:pointer;font-size:12px;font-weight:600;transition:all .25s var(--spring)}
.seg button.on{background:linear-gradient(135deg,var(--ac),var(--mag));color:#fff;border-color:transparent;box-shadow:0 0 14px rgba(139,92,246,.5)}
.seg button:hover{transform:scale(1.18)}
.note{flex:1;min-width:150px;padding:7px 11px;font-size:12px}

/* ---------- сущности ---------- */
.chips{display:flex;gap:9px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.fc{padding:7px 14px;border-radius:99px;border:1px solid var(--bd);background:var(--card);color:var(--mu);
 cursor:pointer;font-size:12px;font-weight:600;transition:all .25s var(--spring)}
.fc:hover{color:#fff;transform:translateY(-2px)}
.fc.on{background:rgba(139,92,246,.26);border-color:var(--ac);color:#fff}
.ent{display:grid;grid-template-columns:12px 72px minmax(120px,1fr) 170px 46px 64px;gap:13px;align-items:center;
 padding:12px 15px;border-radius:13px;animation:rise .5s var(--ease) both;animation-delay:calc(var(--i)*28ms);
 transition:background .25s}.ent:hover{background:var(--card)}
.ent .ev{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}
.dot{width:11px;height:11px;border-radius:50%;box-shadow:0 0 12px currentColor}
.bar{height:7px;background:rgba(255,255,255,.06);border-radius:9px;overflow:hidden}
.bar i{display:block;height:100%;width:0;border-radius:9px;transition:width 1.1s var(--ease)}

/* ---------- граф ---------- */
#p-graph{height:calc(100vh - 300px);min-height:400px;border-radius:18px;overflow:hidden;border:1px solid var(--bd);
 background:rgba(0,0,0,.3);padding:0;position:relative;backdrop-filter:blur(8px)}
#cv{width:100%;height:100%;display:block;cursor:grab}
.legend{position:absolute;left:16px;bottom:14px;display:flex;gap:14px;font-size:11px;color:var(--mu);pointer-events:none;flex-wrap:wrap}

/* ---------- аудит ---------- */
.tl{position:relative;padding-left:24px}
.tl::before{content:"";position:absolute;left:5px;top:6px;bottom:6px;width:2px;
 background:linear-gradient(var(--ac),var(--mag),transparent)}
.ev2{position:relative;padding:9px 0 13px;animation:rise .5s var(--ease) both;animation-delay:calc(var(--i)*22ms)}
.ev2::before{content:"";position:absolute;left:-23px;top:14px;width:11px;height:11px;border-radius:50%;
 background:var(--ac);box-shadow:0 0 14px var(--ac);border:2px solid var(--bg2)}
.ev2 b{color:var(--ac2)}
.ev2 small{color:var(--mu2);font-family:Consolas,monospace;font-size:11px;word-break:break-all}

/* ---------- инструменты ---------- */
.toolcats{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}
.tgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:15px}
.tool{animation:rise .5s var(--ease) both;animation-delay:calc(var(--i)*35ms);display:flex;flex-direction:column;gap:11px}
.tool:hover{border-color:var(--bd2);transform:translateY(-3px);box-shadow:0 16px 40px rgba(139,92,246,.18)}
.tool .th{display:flex;gap:11px;align-items:center}
.tool .ic{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:18px;flex-shrink:0;
 background:linear-gradient(135deg,rgba(139,92,246,.25),rgba(232,121,249,.12));border:1px solid var(--bd2)}
.tool .tn{font-weight:700;font-size:14px}
.tool .td{font-size:11.5px;color:var(--mu);line-height:1.45}
.tool .tin{display:flex;gap:7px}
.tool .tin input,.tool .tin select{padding:9px 12px;font-size:13px}
.tbtn{border:0;border-radius:11px;padding:9px 15px;font:700 13px inherit;color:#fff;cursor:pointer;
 background:linear-gradient(135deg,var(--ac),var(--ac3));transition:all .2s var(--spring);white-space:nowrap;position:relative;min-width:46px}
.tbtn:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(139,92,246,.4)}.tbtn:active{transform:scale(.95)}
.tbtn.loading{color:transparent;pointer-events:none}
.tbtn.loading::before{content:"";position:absolute;inset:0;margin:auto;width:15px;height:15px;border-radius:50%;
 border:2px solid #fff;border-top-color:transparent;animation:spin .7s linear infinite}
.tres{display:none;font-size:12.5px;border-top:1px solid var(--bd);padding-top:11px;margin-top:2px;max-height:340px;overflow:auto;animation:rise .4s var(--ease)}
.tres.show{display:block}
.tres pre{font-family:"JetBrains Mono",Consolas,monospace;font-size:11.5px;white-space:pre-wrap;word-break:break-word;color:var(--mu);margin:0}
.kv{display:flex;gap:8px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.kv b{color:var(--ac2);min-width:120px;flex-shrink:0;font-weight:600}
.kv span{word-break:break-word}
.tag{display:inline-block;padding:2px 9px;margin:2px 4px 2px 0;border-radius:7px;font-size:11px;background:var(--card2);border:1px solid var(--bd)}
.tag.good{color:var(--ok);border-color:rgba(52,211,153,.3)}.tag.miss{color:var(--bad);border-color:rgba(251,113,133,.3)}
.grade{display:inline-grid;place-items:center;width:40px;height:40px;border-radius:12px;font-weight:800;font-size:19px}
.found{color:var(--ok);font-weight:600}.notfound{color:var(--mu2)}
.toolnote{font-size:11.5px;color:var(--mu2);background:rgba(139,92,246,.07);border:1px solid var(--bd);
 border-radius:12px;padding:11px 14px;margin-bottom:16px;line-height:1.5}

.empty{text-align:center;color:var(--mu);padding:70px 0;animation:rise .6s var(--ease)}
.empty b{display:block;font-size:17px;color:var(--tx);margin-bottom:6px}
#toasts{position:fixed;right:22px;bottom:22px;display:flex;flex-direction:column;gap:9px;z-index:30}
.toast{background:rgba(18,12,30,.92);border:1px solid var(--bd);border-left:3px solid var(--ac);padding:12px 17px;
 border-radius:13px;backdrop-filter:blur(16px);animation:rise .4s var(--spring);transition:all .35s;max-width:400px;box-shadow:0 12px 32px rgba(0,0,0,.4)}
.toast.ok{border-left-color:var(--ok)}.toast.bad{border-left-color:var(--bad)}
.toast.out{opacity:0;transform:translateX(34px)}
/* ---------- v2: прогресс, меню, модальные окна ---------- */
.prog{height:6px;border-radius:9px;background:rgba(255,255,255,.06);overflow:hidden;margin-top:2px}
.prog i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--ac),var(--mag));transition:width .3s var(--ease)}
.prog.ind i{width:35%!important;animation:indet 1.2s ease-in-out infinite}
@keyframes indet{from{transform:translateX(-100%)}to{transform:translateX(300%)}}
.pmsg{font-size:11px;color:var(--mu);margin-top:4px;min-height:15px}
.tacts{display:flex;gap:7px;margin-top:9px;flex-wrap:wrap}
.tacts .ghost{padding:6px 11px;font-size:11.5px}
.ghost.on{border-color:var(--ok);color:var(--ok)}
.menu{position:fixed;z-index:60;min-width:230px;max-height:70vh;overflow:auto;background:rgba(18,12,30,.97);border:1px solid var(--bd2);
 border-radius:14px;padding:6px;box-shadow:0 20px 50px rgba(0,0,0,.55);backdrop-filter:blur(18px);animation:pop .2s var(--spring)}
.menu .mh{font-size:10.5px;text-transform:uppercase;letter-spacing:1.3px;color:var(--mu2);padding:8px 10px 4px;font-weight:700}
.menu button{display:block;width:100%;text-align:left;background:none;border:0;color:var(--tx);padding:8px 10px;border-radius:9px;
 font:500 12.5px inherit;cursor:pointer}.menu button:hover{background:rgba(139,92,246,.22)}
.modal-bg{position:fixed;inset:0;z-index:50;background:rgba(4,3,8,.66);backdrop-filter:blur(6px);display:grid;place-items:center;animation:rise .25s}
.modal{width:min(900px,92vw);max-height:86vh;overflow:auto;background:rgba(16,11,27,.98);border:1px solid var(--bd2);border-radius:20px;
 padding:22px 24px;box-shadow:0 30px 80px rgba(0,0,0,.6);animation:pop .3s var(--spring)}
.modal h3{font-size:18px;margin-bottom:12px;display:flex;align-items:center;gap:10px}
.modal h3 .x{margin-left:auto;cursor:pointer;color:var(--mu);font-size:20px;background:none;border:0}
.frow{display:grid;grid-template-columns:170px 1fr;gap:10px;align-items:center;margin:8px 0}
.frow label{color:var(--mu);font-size:12.5px}
.dl{font-family:"JetBrains Mono",Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-word;padding:1px 8px;border-radius:5px}
.dl.add{background:rgba(52,211,153,.12);color:#a7f3d0}.dl.del{background:rgba(251,113,133,.12);color:#fecdd3;text-decoration:line-through}
.dl.gap{color:var(--mu2);font-style:italic}.dl.eq{color:var(--mu)}
.side-foot{display:flex;flex-direction:column;gap:6px}
.side-foot .ghost{justify-content:flex-start}
.ver{font-size:10.5px;color:var(--mu2)}
.kind-tool{border-left:3px solid var(--mag)}
.badge{display:inline-block;padding:2px 8px;border-radius:7px;font-size:10.5px;font-weight:700;background:rgba(232,121,249,.14);color:var(--mag)}
.badge.mon{background:rgba(52,211,153,.13);color:var(--ok)}
.tl2 .ev2.tool::before{background:var(--mag);box-shadow:0 0 14px var(--mag)}
.tl2 .ev2.fact::before{background:var(--ok);box-shadow:0 0 14px var(--ok)}
.tl2 .ev2 .d{font-family:Consolas,monospace;color:var(--ac2);font-size:12px}
.sev{font-weight:700;font-size:11px;padding:2px 7px;border-radius:6px}
.sev.c{background:rgba(251,113,133,.2);color:#fda4af}.sev.h{background:rgba(251,146,60,.18);color:#fdba74}
.sev.m{background:rgba(251,191,36,.15);color:#fde68a}.sev.i{background:rgba(96,165,250,.15);color:#bfdbfe}
table.t{width:100%;border-collapse:collapse;font-size:12px}table.t td,table.t th{padding:5px 7px;border-bottom:1px solid rgba(255,255,255,.05);text-align:left;vertical-align:top}
table.t th{color:var(--ac2);font-weight:600}
.batch textarea{min-height:90px;resize:vertical;font-family:Consolas,monospace;font-size:12px}
.sec{margin-top:9px}.sec>b{color:var(--ac2);display:block;margin-bottom:4px}
/* ---------- 2.1: глобус, радар, утечки ---------- */
#p-globe{height:calc(100vh - 300px);min-height:440px;border-radius:18px;overflow:hidden;border:1px solid var(--bd);
 background:radial-gradient(circle at 50% 50%,#120a22 0%,#05040a 70%);padding:0;position:relative}
#gcv{width:100%;height:100%;display:block;cursor:grab}
.ghud{position:absolute;left:14px;top:14px;width:250px;padding:13px 14px;display:flex;flex-direction:column;gap:8px;
 background:rgba(14,9,26,.72);max-height:calc(100% - 28px);overflow:auto}
.gtitle{font-weight:800;letter-spacing:.6px;display:flex;justify-content:space-between;align-items:center}
.gtitle span{font:600 11px Consolas,monospace;color:var(--ac2)}
.gl{display:flex;gap:8px;align-items:center;font-size:12.5px;color:var(--mu);cursor:pointer;padding:3px 0}
.gl input{width:auto;accent-color:var(--ac)}.gl b{margin-left:auto;color:var(--tx);font:600 11px Consolas,monospace}
.ghud select,.ghud input[type=text],#gq{padding:7px 10px;font-size:12px}
#gres div{padding:6px 8px;border-radius:8px;font-size:11.5px;cursor:pointer;color:var(--mu)}#gres div:hover{background:rgba(139,92,246,.2);color:#fff}
.ginfo{position:absolute;right:14px;top:14px;width:300px;padding:14px;display:none;background:rgba(14,9,26,.8);max-height:calc(100% - 28px);overflow:auto}
.ginfo.show{display:block;animation:pop .3s var(--spring)}
.ginfo h4{font-size:15px;margin-bottom:6px;display:flex;gap:8px;align-items:center}.ginfo h4 .x{margin-left:auto;cursor:pointer;color:var(--mu);background:none;border:0;font-size:16px}
.gcoord{position:absolute;right:16px;bottom:12px;font:11px Consolas,monospace;color:var(--mu2);pointer-events:none;text-align:right}
.gcred{position:absolute;left:16px;bottom:12px;font-size:10.5px;color:var(--mu2);pointer-events:none}
.bigin{display:flex;flex-direction:column;gap:11px;margin-bottom:16px}
.bigin textarea{min-height:70px;resize:vertical;font-family:Consolas,monospace;font-size:12.5px}
.rgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:14px}
.rcard{border-left:3px solid var(--c);animation:rise .5s var(--ease) both;display:flex;flex-direction:column;gap:9px}
.ring{width:58px;height:58px;border-radius:50%;flex-shrink:0;display:grid;place-items:center;
 background:conic-gradient(var(--c) calc(var(--p)*1%),rgba(255,255,255,.07) 0)}
.ring b{width:46px;height:46px;border-radius:50%;background:#0d0918;display:grid;place-items:center;font-size:16px}
.rip{font:700 17px Consolas,monospace}.rv{font-weight:800;font-size:13px;text-transform:uppercase;letter-spacing:.5px}
.mode{display:flex;gap:6px}
.lhead{display:flex;gap:16px;align-items:center;margin-bottom:14px}
.lhead .big{font-size:40px;font-weight:800;line-height:1}
.lgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;margin-top:12px}
.lcard{display:flex;flex-direction:column;gap:6px;animation:rise .5s var(--ease) both}
.lcard img{width:34px;height:34px;border-radius:9px;object-fit:contain;background:#fff;padding:3px}
.md h1,.md h2,.md h3{margin:14px 0 6px;font-size:15px;color:var(--ac2)}.md p{margin:6px 0}.md ul{margin:4px 0 4px 18px}
.md table{border-collapse:collapse;width:100%;font-size:12px;margin:6px 0}.md td,.md th{border-bottom:1px solid rgba(255,255,255,.07);padding:5px 7px;text-align:left}
.md code{font-family:Consolas,monospace;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:5px}
.upd{background:linear-gradient(135deg,rgba(52,211,153,.18),rgba(34,211,238,.1));border-color:rgba(52,211,153,.5);color:var(--ok)}
.pbs{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:9px;margin-bottom:12px}
.pb{padding:11px 13px;border-radius:13px;border:1px solid var(--bd);background:var(--card);cursor:pointer;transition:all .25s var(--spring)}
.pb:hover{transform:translateY(-2px);border-color:var(--bd2)}.pb.on{border-color:var(--ac);background:rgba(139,92,246,.2)}
.pb b{display:block}.pb small{color:var(--mu);font-size:11px}
.ent{cursor:pointer}
#cv,#gcv{touch-action:none}
/* ---------- 2.2: «жидкое стекло» — чёрный, фиолетовое свечение, объёмные стеклянные плитки ---------- */
:root{
 --bg:#030205; --bg2:#08060d; --panel:rgba(14,10,22,.42);
 --g1:rgba(255,255,255,.075); --g2:rgba(255,255,255,.018);
 --edge:rgba(255,255,255,.09); --bd:rgba(255,255,255,.09); --bd2:rgba(196,160,255,.38);
 --tx:#f1edf9; --mu:#a49cbd; --mu2:#6f6789;
 --ac:#8b5cf6; --ac2:#c4a1ff; --ac3:#7c3aed; --mag:#d946ef; --blu:#6366f1;
 --violet:linear-gradient(180deg,#a67bff 0%,#7c3aed 58%,#6421d1 100%);
 --bevel:inset 0 1px 0 rgba(255,255,255,.13),inset 0 -1px 0 rgba(0,0,0,.5),inset 0 0 0 1px rgba(255,255,255,.025);
 --lift:0 22px 50px rgba(0,0,0,.6),0 2px 8px rgba(0,0,0,.45);
 --glow:0 0 0 1px rgba(214,190,255,.5),0 0 22px rgba(139,92,246,.6),0 0 60px rgba(139,92,246,.22);
 --font:"Segoe UI Variable Display","Segoe UI Variable Text","Segoe UI","Inter",system-ui,sans-serif;
}
body{font-family:var(--font)}
.bg{background:radial-gradient(1000px 700px at 85% -15%,rgba(124,58,237,.30),transparent 60%),
 radial-gradient(900px 700px at -15% 115%,rgba(192,38,211,.20),transparent 60%),
 radial-gradient(700px 500px at 50% 50%,rgba(76,29,149,.10),transparent 70%),#030205}
.mesh i{opacity:.1}
.liquid{position:fixed;z-index:-1;pointer-events:none;mix-blend-mode:screen}
.liquid i{position:absolute;inset:0;border-radius:42% 58% 63% 37%/45% 38% 62% 55%;filter:blur(3px) saturate(135%);
 background:conic-gradient(from 200deg,#2e1065,#7c3aed,#c026d3,#f0abfc,#818cf8,#4c1d95,#2e1065);
 animation:morph 19s ease-in-out infinite alternate,spinb 46s linear infinite}
.liquid i::after{content:"";position:absolute;inset:0;border-radius:inherit;
 background:radial-gradient(circle at 30% 24%,rgba(255,255,255,.55),transparent 30%),
 radial-gradient(circle at 64% 72%,rgba(3,2,5,.9),transparent 52%),radial-gradient(circle at 80% 30%,rgba(99,102,241,.5),transparent 40%)}
.liquid.a{width:34vw;height:34vw;right:-15vw;top:-19vw;opacity:.38}
.liquid.b{width:26vw;height:26vw;left:-13vw;bottom:-15vw;opacity:.22}
.liquid.b i{animation-direction:alternate-reverse,reverse}
@keyframes morph{50%{border-radius:58% 42% 35% 65%/52% 61% 39% 48%}100%{border-radius:35% 65% 52% 48%/38% 45% 55% 62%}}
@keyframes spinb{to{transform:rotate(360deg)}}

aside{background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.01)),rgba(6,5,10,.72);border-right:1px solid var(--edge);
 box-shadow:inset -1px 0 0 rgba(255,255,255,.03)}
aside::after{background:linear-gradient(180deg,transparent,rgba(196,160,255,.4),transparent)}
.card{background:linear-gradient(160deg,var(--g1),var(--g2)),rgba(9,7,14,.62);border:1px solid var(--edge);border-radius:22px;box-shadow:var(--bevel),var(--lift)}
.card::before{background:linear-gradient(140deg,rgba(255,255,255,.22),transparent 35%,transparent 70%,rgba(196,160,255,.12))}
.stat:hover,.tool:hover,.src:hover{border-color:rgba(196,160,255,.32);box-shadow:var(--bevel),var(--lift),0 0 34px rgba(139,92,246,.22)}
.stat b{background:linear-gradient(180deg,#fff 30%,#c4a1ff);-webkit-background-clip:text;background-clip:text;text-shadow:0 0 30px rgba(139,92,246,.35)}

.logo b{border-radius:13px;background:var(--violet);box-shadow:var(--bevel),var(--glow);animation:none}
.logo span{font-weight:800;letter-spacing:.6px;background:linear-gradient(180deg,#fff,#d8c5ff);-webkit-background-clip:text;background-clip:text}
.user{display:flex;gap:10px;align-items:center;padding:10px 12px;border-radius:18px;border:1px solid var(--edge);
 background:linear-gradient(160deg,var(--g1),var(--g2)),rgba(9,7,14,.5);box-shadow:var(--bevel)}
.user .av{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:rgba(139,92,246,.22);
 border:1px solid rgba(196,160,255,.3);font-weight:800;color:#e9ddff;text-transform:uppercase}
.user b{display:block;font-size:13.5px;line-height:1.2}.user small{color:var(--mu2);font-size:11px}

.case{border-radius:16px;padding:11px 14px}
.case:hover{background:linear-gradient(160deg,var(--g1),var(--g2)),rgba(9,7,14,.5);border-color:var(--edge);box-shadow:var(--bevel)}
.case.on{background:var(--violet);border-color:rgba(226,206,255,.55);box-shadow:var(--bevel),var(--glow);color:#fff;font-weight:700}
.case.on::before{display:none}

input,textarea,select{border-radius:16px;background:rgba(0,0,0,.38);border:1px solid var(--edge);
 box-shadow:inset 0 2px 7px rgba(0,0,0,.5),inset 0 -1px 0 rgba(255,255,255,.04)}
input:focus,textarea:focus,select:focus{border-color:rgba(196,160,255,.6);background:rgba(0,0,0,.45);
 box-shadow:inset 0 2px 7px rgba(0,0,0,.5),0 0 0 3px rgba(139,92,246,.25),0 0 22px rgba(139,92,246,.25)}
select option{background:#120d1d}
#url{border-radius:99px;padding-left:44px;background:rgba(0,0,0,.38) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='18' height='18' fill='none' stroke='%23a49cbd' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='8' cy='8' r='6'/%3E%3Cpath d='m13 13 4 4'/%3E%3C/svg%3E") no-repeat 17px 50%}

.btn,.tbtn{border-radius:99px;background:var(--violet);
 box-shadow:inset 0 1px 0 rgba(255,255,255,.38),inset 0 -2px 0 rgba(0,0,0,.22),0 0 0 1px rgba(196,160,255,.45),0 10px 28px rgba(124,58,237,.45),0 0 44px rgba(139,92,246,.22)}
.btn:hover,.tbtn:hover{box-shadow:inset 0 1px 0 rgba(255,255,255,.42),inset 0 -2px 0 rgba(0,0,0,.22),0 0 0 1px rgba(226,206,255,.7),0 14px 34px rgba(124,58,237,.6),0 0 60px rgba(139,92,246,.35)}
.btn[disabled]{opacity:.45;pointer-events:none}
.btn.danger,.ghost.danger{background:linear-gradient(180deg,#fb7185,#e11d48);box-shadow:inset 0 1px 0 rgba(255,255,255,.35),0 0 0 1px rgba(253,164,175,.5),0 10px 26px rgba(225,29,72,.4);color:#fff;border:0}
.ghost{border-radius:99px;background:linear-gradient(180deg,rgba(255,255,255,.075),rgba(255,255,255,.02)),rgba(9,7,14,.45);border:1px solid var(--edge);box-shadow:var(--bevel)}
.ghost:hover{border-color:rgba(196,160,255,.45);background:linear-gradient(180deg,rgba(255,255,255,.1),rgba(255,255,255,.03));box-shadow:var(--bevel),0 0 20px rgba(139,92,246,.3)}
.pill{background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.015));box-shadow:var(--bevel)}

.tabs{border-bottom:0;gap:8px;padding:6px 28px 2px;margin:6px 0 18px;flex-wrap:wrap}
.tab{border-radius:99px;padding:9px 18px;border:1px solid var(--edge);color:var(--mu);
 background:linear-gradient(180deg,rgba(255,255,255,.065),rgba(255,255,255,.015));box-shadow:var(--bevel);transition:all .3s var(--spring)}
.tab:hover{color:#fff;transform:translateY(-1px);border-color:rgba(196,160,255,.35)}
.tab.on{color:#fff;background:var(--violet);border-color:rgba(226,206,255,.6);box-shadow:var(--bevel),var(--glow)}
#ink{display:none}

.fc,.seg button{background:linear-gradient(180deg,rgba(255,255,255,.065),rgba(255,255,255,.015));border:1px solid var(--edge);box-shadow:var(--bevel)}
.fc.on,.seg button.on,.pb.on{background:var(--violet);border-color:rgba(226,206,255,.6);color:#fff;box-shadow:var(--bevel),var(--glow)}
.pb{border-radius:18px;background:linear-gradient(160deg,var(--g1),var(--g2));border:1px solid var(--edge);box-shadow:var(--bevel)}
.tool .ic{border-radius:15px;background:linear-gradient(160deg,rgba(255,255,255,.1),rgba(255,255,255,.02));
 border:1px solid var(--edge);box-shadow:var(--bevel),0 8px 20px rgba(0,0,0,.4);text-shadow:0 0 14px rgba(196,160,255,.8)}
.tool:hover .ic{background:var(--violet);box-shadow:var(--bevel),var(--glow)}

/* тумблеры вместо флажков (как переключатель на референсе) */
input[type=checkbox]{appearance:none;-webkit-appearance:none;width:40px!important;min-width:40px;height:23px;padding:0;flex:0 0 40px;
 border-radius:99px;position:relative;cursor:pointer;vertical-align:middle;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.16);
 box-shadow:inset 0 2px 6px rgba(0,0,0,.65);transition:all .35s var(--spring)}
input[type=checkbox]::after{content:"";position:absolute;top:2px;left:2px;width:17px;height:17px;border-radius:50%;
 background:linear-gradient(180deg,#e4dff0,#8c83a3);box-shadow:0 2px 5px rgba(0,0,0,.55);transition:all .4s var(--spring)}
input[type=checkbox]:checked{background:linear-gradient(180deg,rgba(166,123,255,.7),rgba(100,33,209,.7));border-color:rgba(216,190,255,.6);
 box-shadow:inset 0 1px 0 rgba(255,255,255,.22),0 0 18px rgba(139,92,246,.6)}
input[type=checkbox]:checked::after{left:19px;background:radial-gradient(circle at 35% 30%,#fff,#efe4ff 40%,#c4a1ff);box-shadow:0 0 14px rgba(216,180,254,.95)}

.modal{background:linear-gradient(165deg,rgba(34,25,54,.94),rgba(10,7,17,.96));border:1px solid rgba(255,255,255,.1);border-radius:26px;
 box-shadow:var(--bevel),0 40px 100px rgba(0,0,0,.7),0 0 80px rgba(124,58,237,.18)}
.menu,.toast{background:linear-gradient(165deg,rgba(34,25,54,.95),rgba(12,9,20,.97));border-color:rgba(255,255,255,.1);box-shadow:var(--bevel),var(--lift)}
.menu{border-radius:18px}.toast{border-radius:16px}
.ghud,.ginfo{background:linear-gradient(165deg,rgba(30,22,48,.72),rgba(10,7,17,.8))}
.empty::before{content:"PROVENIO";display:block;font:900 clamp(40px,7vw,86px)/1 var(--font);letter-spacing:.12em;
 color:transparent;-webkit-text-stroke:1px rgba(196,160,255,.32);margin-bottom:18px}
.md a{color:var(--ac2)}.md pre{background:rgba(0,0,0,.4);border:1px solid var(--edge);border-radius:12px;padding:10px 12px;overflow:auto;font:12px Consolas,monospace}
.md table{display:block;overflow-x:auto}


/* ---------- 2.3: XSS-лаборатория ---------- */
.lhero{display:flex;gap:18px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
.lhero h2{font:900 30px/1 var(--font);letter-spacing:.5px;background:linear-gradient(180deg,#fff,#c4a1ff);-webkit-background-clip:text;background-clip:text;color:transparent}
.lhero .sub{color:var(--mu);font-size:12.5px;max-width:560px}
.lring{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;flex-shrink:0;
 background:conic-gradient(#a67bff calc(var(--p)*1%),rgba(255,255,255,.07) 0);box-shadow:0 0 26px rgba(139,92,246,.35)}
.lring b{width:52px;height:52px;border-radius:50%;background:#0b0812;display:grid;place-items:center;font-size:13px}
.lvls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.labgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:14px}
.lab{cursor:pointer;display:flex;flex-direction:column;gap:9px;animation:rise .5s var(--ease) both;animation-delay:calc(var(--i)*35ms);min-height:178px}
.lab:hover{transform:translateY(-4px);border-color:rgba(196,160,255,.4);box-shadow:var(--bevel),var(--lift),0 0 34px rgba(139,92,246,.28)}
.lab .lt{display:flex;gap:11px;align-items:center}
.lab .li{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;font-size:18px;font-weight:800;color:#fff;flex-shrink:0;
 background:linear-gradient(160deg,var(--lc),rgba(0,0,0,.35));box-shadow:var(--bevel),0 0 18px color-mix(in srgb,var(--lc) 55%,transparent)}
.lab .ln{font-weight:800;font-size:14.5px;line-height:1.25}.lab .lb{font-size:11.5px;color:var(--mu2)}
.lab .ld{font-size:12px;color:var(--mu);line-height:1.45;flex:1;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.lab .lf{display:flex;justify-content:space-between;align-items:center;gap:8px}
.lab.done{border-color:rgba(52,211,153,.35)}.lab.done .li{box-shadow:var(--bevel),0 0 22px rgba(52,211,153,.5)}
.dots{display:inline-flex;gap:3px;align-items:center}.dots i{width:7px;height:7px;border-radius:50%;background:rgba(255,255,255,.12)}
.dots i.on{background:var(--dc);box-shadow:0 0 8px var(--dc)}
.lvname{font-size:10.5px;font-weight:800;letter-spacing:1.2px;text-transform:uppercase;color:var(--dc)}
.ok-badge{font-size:11px;font-weight:800;color:var(--ok)}
.labview{display:grid;grid-template-columns:minmax(300px,380px) 1fr;gap:16px;align-items:start}
.lbrief{display:flex;flex-direction:column;gap:11px;position:sticky;top:0}
.lbrief h3{font-size:20px;line-height:1.2}
.goal{font-size:12.5px;padding:11px 13px;border-radius:14px;border:1px solid rgba(196,160,255,.3);background:rgba(139,92,246,.1)}
.lhint{font-size:12.5px;color:var(--tx);line-height:1.5}
.hintb{display:block;width:100%;text-align:left;margin-top:6px}
.hintt{font-size:12.5px;padding:9px 12px;border-radius:12px;background:rgba(0,0,0,.35);border:1px solid var(--edge);margin-top:6px;white-space:pre-wrap;word-break:break-word;font-family:"JetBrains Mono",Consolas,monospace}
.lsol{border-color:rgba(251,191,36,.35)}.lfix{border-color:rgba(52,211,153,.35);color:#d1fae5}
.browser{padding:0;overflow:hidden;display:flex;flex-direction:column}
.bbar{display:flex;gap:8px;align-items:center;padding:10px 12px;border-bottom:1px solid var(--edge);background:rgba(0,0,0,.25)}
.bdots{display:flex;gap:6px}.bdots i{width:11px;height:11px;border-radius:50%;background:#ff5f57}.bdots i:nth-child(2){background:#febc2e}.bdots i:nth-child(3){background:#28c840}
.bbar input{border-radius:99px;padding:8px 14px;font:12.5px "JetBrains Mono",Consolas,monospace}
.bbar .ghost{padding:7px 11px}
.bframe{width:100%;height:calc(100vh - 320px);min-height:440px;border:0;background:#fff;display:block}
.xpl{display:flex;flex-direction:column;gap:8px}
.xpl textarea{min-height:110px;font:12px "JetBrains Mono",Consolas,monospace}
.win{position:relative;overflow:hidden;border-color:rgba(52,211,153,.55)!important;box-shadow:var(--bevel),0 0 40px rgba(52,211,153,.35)!important;animation:pop .5s var(--spring)}
.win h3{color:#6ee7b7}
@media(max-width:820px){.labview{grid-template-columns:1fr}.lbrief{position:static}.bframe{height:62vh;min-height:360px}.lhero h2{font-size:24px}}

/* ---------- 2.4: криминалистика, CT-поток, хронолокация ---------- */
.fx{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px;margin-top:10px}
.fx figure{margin:0;display:flex;flex-direction:column;gap:6px}.fx canvas,.fx img{width:100%;border-radius:12px;border:1px solid var(--edge);background:#000}
.fx figcaption{font-size:11.5px;color:var(--mu)}
.flag{padding:7px 11px;border-radius:11px;margin:5px 0;font-size:12.5px;border:1px solid var(--edge);background:rgba(255,255,255,.03)}
.flag.bad{border-color:rgba(251,113,133,.45);background:rgba(251,113,133,.08)}.flag.warn{border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.07)}
.flag.ok{border-color:rgba(52,211,153,.35);background:rgba(52,211,153,.06)}
.chain{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:6px 0}.chain span{padding:4px 10px;border-radius:99px;font:600 11.5px Consolas,monospace;
 background:var(--violet);color:#fff;box-shadow:var(--bevel)}.chain i{color:var(--mu2);font-style:normal}
.mout{white-space:pre-wrap;word-break:break-word;font:12.5px "JetBrains Mono",Consolas,monospace;background:rgba(0,0,0,.4);border:1px solid var(--edge);border-radius:12px;padding:10px 12px;max-height:280px;overflow:auto}
#p-ct .cthead{display:grid;grid-template-columns:minmax(280px,380px) 1fr;gap:14px;align-items:start}
.ctstats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.ctstats .card{padding:12px}.ctstats b{display:block;font-size:24px;font-weight:800}
.ctfeed{font:11.5px "JetBrains Mono",Consolas,monospace;height:300px;overflow:hidden;position:relative;mask-image:linear-gradient(#000 70%,transparent)}
.ctfeed div{padding:3px 0;color:var(--mu);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;animation:rise .4s var(--ease)}
.ctfeed div b{color:var(--tx);font-weight:500}
.live{display:inline-flex;align-items:center;gap:7px;font-weight:800;font-size:12px;letter-spacing:1px}
.live i{width:9px;height:9px;border-radius:50%;background:#f43f5e;box-shadow:0 0 12px #f43f5e;animation:glowDot 1.2s infinite}
.live.off i{background:var(--mu2);box-shadow:none;animation:none}
.ctm{border-left:3px solid #f43f5e;padding:8px 12px;margin:6px 0;border-radius:10px;background:rgba(244,63,94,.07);font-size:12.5px}
.ctm code{font-size:12px}
.tool[data-id="img_forensics"] .tres,.tool[data-id="email_headers"] .tres,.tool[data-id="magic"] .tres,.tool[data-id="ransomware"] .tres{max-height:none}
.chrono label{display:flex;flex-direction:column;gap:4px;font-size:11.5px;color:var(--mu);margin:5px 0}
.chrono input{padding:7px 10px;font-size:12px}
@media(max-width:820px){#p-ct .cthead{grid-template-columns:1fr}.ctstats{grid-template-columns:repeat(2,1fr)}}

/* ---------- 2.5: гипотезы, атрибуция, ритм, самоаудит, якоря ---------- */
.ach{overflow:auto;max-height:62vh}.ach table{border-collapse:separate;border-spacing:0;font-size:12.5px;min-width:100%}
.ach th,.ach td{padding:5px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:middle}
.ach th{position:sticky;top:0;background:#140e22;z-index:1}.ach th input{min-width:130px;font-weight:700}
.ach td.ev{min-width:260px}.ach td.ev input{width:100%}.ach select{padding:5px 6px;font-size:12px;border-radius:9px;width:auto}
.ach .c-CC{background:rgba(52,211,153,.28)}.ach .c-C{background:rgba(52,211,153,.13)}.ach .c-I{background:rgba(251,113,133,.15)}
.ach .c-II{background:rgba(251,113,133,.32)}.ach .c-N{background:rgba(255,255,255,.04)}
.ach tr.nd td.ev input{opacity:.55}.ach tr.sens td.ev{box-shadow:inset 3px 0 0 var(--warn)}
.ach tfoot td{font-weight:800;border-top:1px solid var(--bd2)}.ach .best{color:var(--ok);text-shadow:0 0 12px rgba(52,211,153,.6)}
.clu{border-left:3px solid var(--ac);padding:10px 14px;margin:8px 0;border-radius:12px;background:rgba(139,92,246,.08)}
.clu b.n{font-size:15px}.clu .tag{margin:3px 4px 0 0}
.heat{display:grid;grid-template-columns:34px repeat(24,1fr);gap:2px;font-size:10px;margin:8px 0}
.heat span{aspect-ratio:1;border-radius:4px;background:rgba(255,255,255,.04)}.heat i{font-style:normal;color:var(--mu2);text-align:center;align-self:center}
.score{display:flex;gap:16px;align-items:center;margin-bottom:10px}
.fnd{display:grid;grid-template-columns:78px 1fr;gap:8px;padding:8px 10px;border-radius:11px;margin:5px 0;background:rgba(255,255,255,.03);border:1px solid var(--edge);font-size:12.5px}
.fnd .sv{font-weight:800;font-size:11px;text-transform:uppercase}.fnd .fx2{color:var(--mu);font-size:12px;margin-top:3px}
.anc{display:flex;gap:10px;align-items:center;padding:9px 12px;border-radius:12px;border:1px solid var(--edge);margin:6px 0;font-size:12.5px}
.anc .st{font-weight:800}.anc.confirmed{border-color:rgba(52,211,153,.45)}.anc.pending .st{color:var(--warn)}.anc.confirmed .st{color:var(--ok)}
.gp label{display:flex;flex-direction:column;gap:3px;font-size:11.5px;color:var(--mu);margin:4px 0}.gp select,.gp input{padding:6px 9px;font-size:12px}
.gp .cr{display:grid;grid-template-columns:1fr 78px 26px;gap:5px;align-items:center;margin:4px 0}
.gpres div{padding:6px 8px;border-radius:8px;font-size:11.5px;cursor:pointer;color:var(--mu)}.gpres div:hover{background:rgba(139,92,246,.2);color:#fff}
/* ---------- экран входа и регистрации ---------- */
#auth{position:fixed;inset:0;z-index:90;display:grid;place-items:center;overflow:auto;padding:28px 16px;background:#030205}
#auth .bg,#auth .liquid{position:absolute}
#auth .liquid.a{width:min(62vw,720px);height:min(62vw,720px);right:-10%;top:-18%;opacity:.7}
#auth .liquid.b{width:min(44vw,520px);height:min(44vw,520px);left:-12%;bottom:-20%;opacity:.5}
.ahero{position:absolute;left:5vw;bottom:5vh;font:900 clamp(56px,11vw,170px)/.9 var(--font);letter-spacing:.06em;color:transparent;
 -webkit-text-stroke:1px rgba(196,160,255,.22);pointer-events:none;user-select:none}
.abox{position:relative;width:min(450px,100%);padding:30px 30px 24px;display:flex;flex-direction:column;gap:12px;animation:pop .5s var(--spring)}
.abox h2{font:800 27px/1.15 var(--font);letter-spacing:.3px}
.abox h2 small{display:block;font:600 11px var(--font);letter-spacing:3px;text-transform:uppercase;color:var(--ac2);margin-bottom:8px}
.abox .sub{color:var(--mu);font-size:13px;margin-top:-4px}
label.f{display:flex;flex-direction:column;gap:6px;margin:6px 0;font-size:12px;color:var(--mu);font-weight:600}
.pw{position:relative}.pw input{padding-right:44px}
.pw button{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:0;color:var(--mu);cursor:pointer;font-size:15px;padding:4px 6px}
.meter{height:5px;border-radius:9px;background:rgba(255,255,255,.07);overflow:hidden}.meter i{display:block;height:100%;width:0;transition:all .4s var(--ease)}
.cons{display:flex;gap:11px;align-items:flex-start;font-size:12.5px;color:var(--tx);line-height:1.45;cursor:pointer}
.cons a,.alink{color:var(--ac2);cursor:pointer;text-decoration:underline;text-underline-offset:2px}
.aerr{color:var(--bad);font-size:12.5px;min-height:18px}
.afoot{display:flex;justify-content:space-between;gap:10px;font-size:11.5px;color:var(--mu2);flex-wrap:wrap}
.free{font-size:11.5px;color:var(--mu);padding:9px 12px;border-radius:14px;border:1px solid rgba(52,211,153,.25);background:rgba(52,211,153,.06)}
.docs{display:flex;gap:7px;flex-wrap:wrap}
@media(max-width:820px){
 body{display:block;height:auto;min-height:100vh;overflow:auto;padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}
 aside{flex-direction:row;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 12px;border-right:0;border-bottom:1px solid var(--bd);
  position:relative;min-height:auto}
 aside::after,aside>.cap,aside>.hint{display:none}
 .logo{font-size:16px;gap:9px}.logo b{width:28px;height:28px;font-size:14px;border-radius:9px}
 .newc{flex:1;min-width:140px}.newc input{padding:8px 10px}.newc .btn{padding:8px 13px}
 .cases{flex-direction:row;overflow-x:auto;flex:1 1 100%;margin:0;padding:1px 0;gap:6px}
 .case{white-space:nowrap;padding:7px 12px;animation:none;flex-shrink:0}.case:hover{transform:none}
 .side-foot{flex-direction:row;overflow-x:auto;flex:1 1 100%;gap:6px}
 .side-foot .ghost{padding:7px 10px;font-size:11.5px;flex-shrink:0}.side-foot .ver{display:none}
 main{height:auto;display:block}
 header{flex-wrap:wrap;padding:12px;gap:7px}
 header #url{flex:1 1 100%;order:-1}
 header .btn,header .ghost{padding:8px 11px;font-size:12px}header .pill{font-size:11px;padding:6px 10px}
 .stats{grid-template-columns:repeat(2,1fr);gap:9px;padding:4px 12px}
 .stat b{font-size:24px}.card{padding:13px;border-radius:15px}
 .tabs{overflow-x:auto;padding:4px 12px 0;margin:4px 0 12px;scrollbar-width:none}.tabs::-webkit-scrollbar{display:none}
 .tab{white-space:nowrap;padding:10px 12px;flex-shrink:0}#ink{display:none}.tab.on{box-shadow:inset 0 -2px 0 var(--ac)}
 .panels{overflow:visible;padding:0 12px 28px}
 .tgrid,.rgrid,.lgrid,.pbs{grid-template-columns:1fr}
 .tool .tin{flex-wrap:wrap}.tool .tin input,.tool .tin textarea{flex:1 1 100%}
 .ent{grid-template-columns:10px 58px minmax(0,1fr) 42px;gap:8px;padding:10px 8px}.ent .bar,.ent>span:last-child{display:none}
 #p-graph,#p-globe{height:70vh;min-height:360px}
 .ghud{width:auto;left:8px;right:8px;top:8px;max-height:46%;padding:10px 12px;gap:6px}
 .ghud.min>:not(.gtitle){display:none}
 .ginfo{width:auto;left:8px;right:8px;top:auto;bottom:8px;max-height:55%}
 .gcred{display:none}.gcoord{bottom:auto;top:8px;right:14px}
 .modal{width:96vw;max-height:88vh;padding:16px}.frow{grid-template-columns:1fr;gap:4px}
 .menu{max-width:92vw}
 #toasts{left:12px;right:12px;bottom:calc(12px + env(safe-area-inset-bottom))}.toast{max-width:none}
 table.t{display:block;overflow-x:auto}
 .lhead .big{font-size:32px}
 .tabs{flex-wrap:nowrap}.tab{padding:8px 14px}
 .user{flex:1 1 100%;padding:8px 10px}
 .abox{padding:22px 18px 18px}.ahero{display:none}
 .liquid.a{width:80vw;height:80vw;right:-35vw;top:-35vw}
}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:rgba(168,130,255,.2);border-radius:9px}
::-webkit-scrollbar-thumb:hover{background:rgba(168,130,255,.35)}
/* ---------- 2.6.1: производительность ----------
   Фон рисуется один раз: бесконечные анимации огромных размытых пятен и «стекло» поверх движущегося фона
   заставляли видеокарту перерисовывать весь экран 60 раз в секунду (≈150% ядра процессора в простое). */
.mesh i,.liquid i{animation:none!important}
.mesh i{mix-blend-mode:normal;filter:blur(90px)}
.liquid{mix-blend-mode:normal}
.logo b::after{display:none}
.pill.ok::before,.pill.bad::before{animation:none}
aside,.card,.pill,#p-graph,.toast,.menu,.ghud,.ginfo{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.modal-bg{backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px)}
</style></head><body>
<div class="bg"></div><div class="mesh"><i></i><i></i><i></i></div><div class="liquid a"><i></i></div><div class="liquid b"><i></i></div><div class="grain"></div>
<div id="auth"><div class="bg"></div><div class="liquid a"><i></i></div><div class="liquid b"><i></i></div><div class="ahero">PROVENIO</div>
 <div class="card abox" id="abox"><div class="hint">Загрузка…</div></div></div>
<aside>
 <div class="logo"><b>◈</b><span>Provenio</span></div>
 <div class="user" id="userbox"><div class="av" id="uav">?</div><div class="grow"><b id="uname">—</b><small>локальный аккаунт</small></div>
  <button class="ghost" id="logout" title="Выйти из аккаунта" style="padding:7px 10px">⏻</button></div>
 <div class="cap">Кейсы</div>
 <div class="cases" id="cases"></div>
 <div class="newc"><input id="ncase" placeholder="Новый кейс"><button class="btn" id="addc">+</button></div>
 <div class="hint">Доказательная OSINT-аналитика.<br>Только публичные данные. Соблюдайте закон.</div>
 <div class="side-foot">
  <button class="ghost" id="set">⚙ Настройки и ключи API</button>
  <button class="ghost" id="inter">🔀 Пересечения кейсов</button>
  <button class="ghost" id="brandb">🛡 Мониторинг бренда</button>
  <button class="ghost" id="ddir">📁 Папка данных</button>
  <button class="ghost" id="phoneb">📱 Открыть на телефоне</button>
  <button class="ghost" id="docsb">📄 Условия и конфиденциальность</button>
  <a class="ghost upd" id="updb" target="_blank" rel="noopener" hidden></a>
  <span class="ver">Provenio __VER__</span>
 </div>
</aside>
<main>
 <header>
  <input class="grow" id="url" placeholder="Вставьте URL (можно несколько через пробел или запятую)…">
  <button class="btn" id="add">Архивировать</button>
  <button class="ghost" id="ver">Проверить</button>
  <button class="ghost" id="pbb">▶ Сценарий</button>
  <button class="ghost" id="aib">✨ ИИ-сводка</button>
  <button class="ghost" id="achb">⚖ Гипотезы</button>
  <button class="ghost" id="ancb">⛓ Якоря</button>
  <button class="ghost" id="cmp">Сравнить</button>
  <button class="ghost" id="rep">Экспорт ▾</button>
  <span class="pill ok" id="pill">целостность</span>
 </header>
 <div class="stats">
  <div class="card stat"><span class="lbl">Источники</span><b id="n1" data-v="0">0</b></div>
  <div class="card stat" style="animation-delay:.06s"><span class="lbl">Сущности</span><b id="n2" data-v="0">0</b></div>
  <div class="card stat" style="animation-delay:.12s"><span class="lbl">Подтверждено 2+ источниками</span><b id="n3" data-v="0">0</b></div>
  <div class="card stat" style="animation-delay:.18s"><span class="lbl">Средняя достоверность, %</span><b id="n4" data-v="0">0</b></div>
 </div>
 <div class="tabs">
  <button class="tab on" data-t="src">Источники</button>
  <button class="tab" data-t="ents">Сущности</button>
  <button class="tab" data-t="graph">Граф</button>
  <button class="tab" data-t="time">Хронология</button>
  <button class="tab" data-t="globe">Глобус</button>
  <button class="tab" data-t="radar">IP-радар</button>
  <button class="tab" data-t="leaks">Утечки</button>
  <button class="tab" data-t="tools">Инструменты</button>
  <button class="tab" data-t="labs">🧪 XSS-лаб</button>
  <button class="tab" data-t="ct">🔴 CT-поток</button>
  <button class="tab" data-t="audit">Аудит</button>
  <span id="ink"></span>
 </div>
 <div class="panels">
  <div class="panel on" id="p-src"></div>
  <div class="panel" id="p-ents"><div class="chips" id="chips"></div><div id="ents"></div></div>
  <div class="panel" id="p-graph"><canvas id="cv"></canvas>
   <div class="legend"><span>■ источник</span><span style="color:#fb923c">● email</span><span style="color:#34d399">● телефон</span>
   <span style="color:#60a5fa">● домен</span><span style="color:#c084fc">● IP</span><span style="color:#f87171">● аккаунт</span>
   <span>· клик по узлу — пивот: запустить инструмент и добавить находки в кейс</span></div></div>
  <div class="panel" id="p-time"><div class="tl tl2" id="tline"></div></div>
  <div class="panel" id="p-tools">
   <div class="toolnote">🛡 Все инструменты работают с <b>публичными</b> данными и выполняются на вашей машине.
   Инструменты ИБ здесь <b>защитные</b>: проверка пароля по утечкам идёт по k-anonymity (сам пароль не покидает компьютер).
   Перебора паролей/логинов и сканирования чужих систем здесь нет — используйте всё в рамках закона.
   Кнопка <b>«В кейс»</b> сохраняет результат как доказательство (JSON + SHA-256 + журнал аудита) и добавляет найденные сущности в граф.</div>
   <div class="row" style="margin-bottom:14px;gap:9px"><input id="tsearch" placeholder="Поиск инструмента…" style="max-width:280px;padding:8px 12px">
    <label style="font-size:12px;color:var(--mu);display:flex;gap:6px;align-items:center;white-space:nowrap"><input type="checkbox" id="autosave" style="width:auto"> сразу сохранять результаты в кейс</label></div>
   <div class="toolcats" id="toolcats"></div>
   <div class="tgrid" id="tgrid"></div>
  </div>
  <div class="panel" id="p-audit"><div class="tl" id="tl"></div></div>
  <div class="panel" id="p-labs"></div>
  <div class="panel" id="p-ct"></div>
  <div class="panel" id="p-globe"><canvas id="gcv"></canvas>
   <div class="ghud card">
    <div class="gtitle">◉ ГЛОБУС <span id="gclock"></span></div>
    <div><input id="gq" type="text" placeholder="Найти место (Enter)…"><div id="gres"></div></div>
    <label class="gl"><input type="checkbox" data-l="flights" checked> ✈ Самолёты <b id="gn-flights">—</b></label>
    <label class="gl"><input type="checkbox" data-l="sats" checked> 🛰 Спутники <b id="gn-sats">—</b></label>
    <select id="ggroup"></select>
    <label class="gl"><input type="checkbox" data-l="quakes" checked> 〰 Землетрясения <b id="gn-quakes">—</b></label>
    <label class="gl"><input type="checkbox" data-l="events"> 🔥 События NASA <b id="gn-events">—</b></label>
    <label class="gl"><input type="checkbox" data-l="cas" checked> ◆ Объекты кейса <b id="gn-cas">—</b></label>
    <label class="gl"><input type="checkbox" id="gnight" checked> 🌗 День и ночь</label>
    <label class="gl"><input type="checkbox" id="gauto" checked> ⟳ Вращение</label>
    <button class="ghost" id="gchrono" style="justify-content:center">☀ Хронолокация по тени</button>
    <button class="ghost" id="gpuzzle" style="justify-content:center">🧩 Геопазл: место по приметам</button>
    <div class="pmsg" id="gstat"></div>
   </div>
   <div class="ginfo card" id="ginfo"></div>
   <div class="gcoord" id="gcoord"></div>
   <div class="gcred">Данные: OpenSky · CelesTrak · USGS · NASA EONET · OpenStreetMap · ip-api · идея — God's Eye View</div>
  </div>
  <div class="panel" id="p-radar">
   <div class="card bigin"><div class="tool"><div class="th"><div class="ic">📡</div><div><div class="tn">IP-радар</div>
    <div class="td">Один понятный вердикт на каждый IP: ~20 открытых списков угроз (FireHOL, Spamhaus, IPsum, Feodo, C2-фиды…),
    Tor, VPN/прокси, облака и CDN, гео и ASN, порты и CVE (Shodan InternetDB), OTX, DNSBL. Списки кэшируются локально на 12 ч.</div></div></div></div>
    <textarea id="rq" placeholder="IP-адреса через пробел, запятую или с новой строки (до 50). Понимает 1[.]2[.]3[.]4"></textarea>
    <div class="row"><button class="btn" id="rgo">Сканировать</button><button class="ghost" id="rcase">IP из кейса</button>
     <button class="ghost" id="rsave" hidden>＋ В кейс</button><button class="ghost" id="rstop" hidden>■ Стоп</button><span class="pmsg grow" id="rmsg"></span></div>
    <div class="prog" id="rprog" hidden><i></i></div></div>
   <div id="rres"></div></div>
  <div class="panel" id="p-leaks">
   <div class="card bigin"><div class="tool"><div class="th"><div class="ic">💧</div><div><div class="tn">Утечки данных · XposedOrNot</div>
    <div class="td">Email — в каких утечках он есть, какие данные раскрыты и насколько это опасно. Домен — известные утечки сервиса.
    Пароль — проверка по k-anonymity: в сеть уходят только 10 символов его хэша.</div></div></div></div>
    <div class="row"><div class="mode" id="lmode"><span class="fc on" data-m="email">Email</span><span class="fc" data-m="domain">Домен</span><span class="fc" data-m="password">Пароль</span></div></div>
    <div class="row"><input id="lq" class="grow" placeholder="user@example.com"><button class="btn" id="lgo">Проверить</button>
     <button class="ghost" id="lsave" hidden>＋ В кейс</button></div>
    <div class="pmsg" id="lmsg">Лимит бесплатного API: 25 запросов в час. Email отправляется в XposedOrNot.</div></div>
   <div id="lres"></div></div>
 </div>
</main>
<div id="toasts"></div>
<script>
const PLAT="__PLAT__",IOS=PLAT==="ios",PAGE_T="__TOKEN__",$=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const TY={email:"#fb923c",phone:"#34d399",domain:"#60a5fa",ip:"#c084fc",account:"#f87171",src:"#e5e7eb"};
const TL={email:"Email",phone:"Телефон",domain:"Домен",ip:"IP",account:"Аккаунт"};
let T=PAGE_T,ME=null,STARTED=false;
let cases=[],cur=null,st=null,tab="src",ef="all",eq="";
const host=u=>{try{return new URL(u).hostname.replace(/^www\./,"")}catch(e){return u}};
async function api(p,b){const r=await fetch("/api/"+p,{method:b?"POST":"GET",headers:{"X-Token":T,"Content-Type":"application/json"},
 body:b?JSON.stringify(b):undefined});const j=await r.json();
 if(r.status===401&&!p.startsWith("auth/")){showAuth();throw new Error("Войдите в аккаунт")}if(!r.ok)throw new Error(j.error||r.status);return j}
function toast(m,k){const t=document.createElement("div");t.className="toast "+(k||"");t.textContent=m;$("#toasts").append(t);
 setTimeout(()=>{t.classList.add("out");setTimeout(()=>t.remove(),400)},3600)}
function num(el,to){const f=+el.dataset.v||0;el.dataset.v=to;const t0=performance.now();
 (function s(t){const p=Math.min(1,(t-t0)/850),e=1-Math.pow(1-p,3);el.textContent=Math.round(f+(to-f)*e);if(p<1)requestAnimationFrame(s)})(t0)}
function moveInk(){const b=$(".tab.on"),k=$("#ink");if(!b)return;k.style.width=b.offsetWidth+"px";k.style.transform="translateX("+(b.offsetLeft-28)+"px)"}
function setTab(t){tab=t;$$(".tab").forEach(b=>b.classList.toggle("on",b.dataset.t===t));
 $$(".panel").forEach(p=>p.classList.toggle("on",p.id==="p-"+t));moveInk();if(t==="graph")setTimeout(()=>{sizeCv();loops()},30);if(t==="time")renderTimeline();
 if(t==="globe")setTimeout(()=>{globeOpen();loops()},30);if(t==="labs")labsOpen();if(t==="ct")ctOpen();loops()}
// циклы отрисовки графа и глобуса работают только на своей вкладке и в видимом окне
function loops(){if(tab==="graph"&&!GRAF)GRAF=requestAnimationFrame(tick);if(tab==="globe"&&GW&&!GV.raf){GV.last=performance.now();GV.raf=requestAnimationFrame(gTick)}}
document.addEventListener("visibilitychange",()=>{if(!document.hidden)loops()});
$$(".tab").forEach(b=>b.onclick=()=>setTab(b.dataset.t));

function renderCases(){$("#cases").innerHTML=cases.map((c,i)=>`<div class="case ${cur&&cur.id===c.id?"on":""}" data-id="${c.id}" style="animation-delay:${i*40}ms">${esc(c.name)}</div>`).join("")||'<div class="mu" style="padding:8px;color:var(--mu2)">Создайте первый кейс ↓</div>'}
$("#cases").onclick=e=>{const d=e.target.closest(".case");if(d){cur=cases.find(c=>c.id==d.dataset.id);renderCases();refresh()}};
async function loadCases(sel){cases=await api("cases");cur=cases.find(c=>c.id===sel)||cur||cases[0]||null;renderCases();if(cur)refresh();else render()}
$("#addc").onclick=async()=>{const n=$("#ncase").value.trim();if(!n)return;try{const r=await api("case",{name:n});$("#ncase").value="";await loadCases(r.id);toast("Кейс создан","ok")}catch(e){toast(e.message,"bad")}};
$("#ncase").onkeydown=e=>{if(e.key==="Enter")$("#addc").click()};

async function refresh(){if(!cur)return;st=await api("state?case="+cur.id);render();
 if(GV.inited&&GV.L.cas.on&&GV.L.cas.cid!==cur.id){GV.L.cas.cid=cur.id;gLoad("cas")}}
function render(){
 if(!st||!cur){$("#p-src").innerHTML='<div class="empty"><b>Нет активного кейса</b>Создайте кейс слева и добавьте первый URL</div>';return}
 const E=st.entities,multi=E.filter(e=>e.src.length>1).length,avg=E.length?Math.round(E.reduce((a,e)=>a+e.conf,0)/E.length):0;
 num($("#n1"),st.sources.length);num($("#n2"),E.length);num($("#n3"),multi);num($("#n4"),avg);
 const i=st.integrity,good=!i.snap_bad&&i.chain;$("#pill").className="pill "+(good?"ok":"bad");
 $("#pill").textContent=good?"целостность подтверждена":"целостность нарушена";
 $("#p-src").innerHTML=st.sources.map((s,i)=>{const tool=s.kind==="tool",tn=tool?(TOOLS.find(t=>t.id===s.tool)||{}).tn||s.tool:"";
  return `<div class="card src ${tool?"kind-tool":""}" style="--i:${Math.min(i,30)}"><div class="row"><div class="grow">
  <div class="ttl">${tool?'<span class="badge">🛠 '+esc(tn)+'</span> '+esc(s.query||""):esc(s.title||host(s.url))}
   ${s.found_on?'<span class="badge">найдено на #'+s.found_on+'</span>':""}${s.parent_id?'<span class="badge">версия #'+s.parent_id+'</span>':""}${s.monitor?'<span class="badge mon">👁 каждые '+s.monitor.interval+' мин · изменений: '+s.monitor.changes+'</span>':""}</div>
  ${tool?`<span class="url" style="color:var(--mu)">${esc(s.url)}</span>`:`<a class="url" href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.url)}</a>`}</div>
  <span class="chip ${s.status.startsWith("OK")?"ok":"bad"}">${esc(s.status.slice(0,34))}</span></div>
  <div class="meta"><span>#${s.id}</span><span>${esc(s.fetched)}</span><span>${(s.size/1024).toFixed(1)} KB</span>
  <span class="sha" data-c="${esc(s.sha256)}" title="Копировать SHA-256">${esc(s.sha256?s.sha256.slice(0,24)+"…":"нет снимка")}</span>
  ${s.versions?`<span>версий: ${s.versions}</span>`:""}</div>
  <div class="row"><div class="seg" data-id="${s.id}" title="Надёжность источника">${[1,2,3,4,5].map(n=>`<button data-r="${n}" class="${n<=s.reliability?"on":""}">${n}</button>`).join("")}</div>
  <input class="note" data-id="${s.id}" placeholder="Заметка…" value="${esc(s.note)}">
  ${s.snapshot?`<a class="ghost" target="_blank" href="/snapshot/${encodeURIComponent(s.snapshot)}?t=${T}">${tool?"JSON":"Снимок"}</a>`:""}
  ${(s.att||[]).map(a=>`<a class="ghost" target="_blank" title="SHA-256 ${esc(a.sha256)}" href="/snapshot/${encodeURIComponent(a.file)}?t=${T}">${a.kind==="screenshot"?"📷 Скриншот":a.kind==="witness"?"🧾 Свидетель: "+esc(a.note||""):"📄 PDF"}</a>`).join("")}
  ${!tool&&s.status.startsWith("OK")&&!(s.att||[]).length?`<button class="ghost cap" data-id="${s.id}">📷 Снять экран</button>`:""}
  ${!tool&&s.status.startsWith("OK")?`<button class="ghost exp" data-id="${s.id}">🔗 Обойти ссылки</button>`:""}
  ${!tool&&s.status.startsWith("OK")&&!(s.att||[]).some(a=>a.kind==="witness")?`<button class="ghost wit" data-id="${s.id}" title="Internet Archive сохранит страницу сейчас; Provenio сравнит его копию со своей">🧾 Независимый свидетель</button>`:""}
  ${!tool&&!s.parent_id?`<button class="ghost mon ${s.monitor?"on":""}" data-id="${s.id}">${s.monitor?"👁 Слежу":"👁 Следить"}</button>`:""}
  ${s.monitor?`<button class="ghost chk" data-id="${s.id}">Проверить сейчас</button>`:""}
  ${s.versions||s.parent_id?`<button class="ghost vers" data-id="${s.id}">Версии и сравнение</button>`:""}
  <button class="ghost del" data-id="${s.id}">Удалить</button></div></div>`}).join("")||'<div class="empty"><b>Источников пока нет</b>Вставьте URL в поле сверху и нажмите «Архивировать» — или сохраните в кейс результат любого инструмента</div>';
 renderEnts();
 $("#tl").innerHTML=st.audit.map((a,i)=>`<div class="ev2" style="--i:${Math.min(i,20)}"><b>${esc(a.action)}</b> <span style="color:var(--mu)">${esc(a.ts)}</span><br>${esc(a.detail)}<br><small>${esc(a.hash)}</small></div>`).join("");
 buildGraph();moveInk();if(tab==="time")renderTimeline()}
$("#p-src").onclick=async e=>{const b=e.target.closest("button,.sha")||e.target;
 if(b.classList.contains("wit")){b.classList.add("loading");try{const r=await api("witness",{id:b.dataset.id});const f=await waitJob(r.id);
  toast(f.state==="done"?`Архив-свидетель: ${f.result.verdict||"сохранено"}${f.result.similarity!=null?" ("+f.result.similarity+"%)":""}`:"Свидетель не получен: "+(f.error||""),f.state==="done"?"ok":"bad")}catch(x){toast(x.message,"bad")}refresh();return}
 if(b.classList.contains("cap")){b.classList.add("loading");try{const r=await api("capture",{id:b.dataset.id});const f=await waitJob(r.id);
  toast(f.state==="done"&&f.result.added?"Скриншот сохранён как доказательство":"Не удалось снять экран: "+(f.error||"браузер не ответил"),f.state==="done"&&f.result.added?"ok":"bad")}catch(x){toast(x.message,"bad")}refresh();return}
 if(b.classList.contains("exp")){openExpand(+b.dataset.id);return}
 if(b.classList.contains("mon")){const id=b.dataset.id;const r=b.getBoundingClientRect();
  showMenu(r.left,r.bottom+4,[["Следить за изменениями страницы",null],...[[15,"каждые 15 минут"],[60,"каждый час"],[360,"каждые 6 часов"],[1440,"раз в сутки"]].map(([m,l])=>[l,async()=>{await api("monitor",{id,interval:m});toast("Мониторинг включён: "+l,"ok");refresh()}]),
   ["Выключить мониторинг",async()=>{await api("monitor",{id,interval:0});toast("Мониторинг выключен","ok");refresh()}],
   ["Проверка идёт, пока Provenio открыт",null]]);return}
 if(b.classList.contains("chk")){b.classList.add("loading");try{const r=await api("monitor_check",{id:b.dataset.id});
  toast(r.changed?"Страница изменилась — сохранена новая версия":r.changed===false?"Изменений нет":"Не удалось проверить: "+r.status,r.changed?"ok":r.changed===false?"":"bad")}catch(x){toast(x.message,"bad")}refresh();return}
 if(b.classList.contains("vers")){openVersions(+b.dataset.id);return}
 if(b.dataset.r){await api("rel",{id:b.parentNode.dataset.id,reliability:+b.dataset.r});await refresh()}
 else if(b.classList.contains("del")){if(confirm("Удалить источник? Это попадёт в журнал аудита.")){await api("delete",{id:b.dataset.id});await refresh();toast("Источник удалён","ok")}}
 else if(b.classList.contains("sha")&&b.dataset.c){navigator.clipboard&&navigator.clipboard.writeText(b.dataset.c);toast("SHA-256 скопирован","ok")}};
$("#p-src").onchange=async e=>{if(e.target.classList.contains("note")){await api("note",{id:e.target.dataset.id,note:e.target.value});toast("Заметка сохранена","ok");refresh()}};

function renderEnts(){const types=[...new Set(st.entities.map(e=>e.type))];
 $("#chips").innerHTML=["all",...types].map(t=>`<span class="fc ${ef===t?"on":""}" data-t="${t}">${t==="all"?"Все":TL[t]||t} ${t==="all"?st.entities.length:st.entities.filter(e=>e.type===t).length}</span>`).join("")+
 '<input id="eq" placeholder="Поиск…" style="margin-left:auto;max-width:220px;padding:7px 13px" value="'+esc(eq)+'">';
 const L=st.entities.filter(e=>(ef==="all"||e.type===ef)&&e.value.toLowerCase().includes(eq)).sort((a,b)=>b.conf-a.conf);
 $("#ents").innerHTML=L.map((e,i)=>{const g=e.conf>=75?"#34d399,#22d3ee":e.conf>=45?"#fbbf24,#fb923c":"#f87171,#fb7185";
 return `<div class="ent" data-id="${e.id}" style="--i:${Math.min(i,25)}"><span class="dot" style="background:${TY[e.type]};color:${TY[e.type]}"></span><span style="color:var(--mu)">${TL[e.type]||e.type}</span>
 <span class="ev" title="${esc(e.value)}">${(e.other||[]).length?`<span class="badge" title="Также в кейсах: ${esc(e.other.join(", "))}">🔀 ${e.other.length}</span> `:""}${esc(e.value)}</span><div class="bar"><i data-w="${e.conf}" style="background:linear-gradient(90deg,${g})"></i></div><b>${e.conf}%</b><span style="color:var(--mu)">${e.src.length} ист.</span></div>`}).join("")||'<div class="empty">Ничего не найдено</div>';
 requestAnimationFrame(()=>requestAnimationFrame(()=>$$(".bar i").forEach(b=>b.style.width=b.dataset.w+"%")));
 const q=$("#eq");if(q)q.oninput=()=>{eq=q.value.toLowerCase();const p=q.selectionStart;renderEnts();const n=$("#eq");n.focus();n.setSelectionRange(p,p)}}
$("#chips").onclick=e=>{const c=e.target.closest(".fc");if(c){ef=c.dataset.t;renderEnts()}};
$("#ents").onclick=e=>{const r=e.target.closest(".ent");if(r)openDossier(+r.dataset.id)};

/* ---------- граф с физикой ---------- */
const cv=$("#cv"),cx=cv.getContext("2d"),G={nodes:[],edges:[],drag:null,hover:null};let W=0,H=0;const dpr=window.devicePixelRatio||1;
function sizeCv(){W=cv.clientWidth;H=cv.clientHeight;cv.width=W*dpr;cv.height=H*dpr}
window.addEventListener("resize",()=>{sizeCv();moveInk()});
function buildGraph(){if(!st)return;const old=new Map(G.nodes.map(n=>[n.id,n])),idx=new Map();const w=W||800,h=H||500;
 const mk=(id,t,l)=>{const o=old.get(id),n={id,t,l,x:w/2+(Math.random()-.5)*260,y:h/2+(Math.random()-.5)*260,vx:0,vy:0,age:0};
  if(o){n.x=o.x;n.y=o.y;n.age=o.age}idx.set(id,n);return n};
 const nodes=st.sources.map(s=>mk("s"+s.id,"src",host(s.url)+" #"+s.id)),edges=[];
 // большой кейс: показываем пересечения (2+ источника) и находки двух последних источников
 const recent=new Set(st.sources.slice(-2).map(s=>s.id));
 const E=st.entities.length>250?st.entities.filter(e=>e.src.length>1||e.src.some(i=>recent.has(i))).slice(0,400):st.entities;
 E.forEach(e=>{nodes.push(mk("e"+e.id,e.type,e.value));e.src.forEach(i=>{const a=idx.get("s"+i);if(a)edges.push([a,idx.get("e"+e.id)])})});
 G.nodes=nodes;G.edges=edges}
function nearest(x,y){let b=null,bd=1e9;const lim=matchMedia("(pointer:coarse)").matches?26:15;for(const n of G.nodes){const d=Math.hypot(n.x-x,n.y-y);if(d<lim&&d<bd){b=n;bd=d}}return b}
const pt=e=>{const r=cv.getBoundingClientRect();return[e.clientX-r.left,e.clientY-r.top]};
let downAt=null;
cv.onpointerdown=e=>{const[x,y]=pt(e);downAt=[e.clientX,e.clientY];G.drag=nearest(x,y);if(G.drag)cv.style.cursor="grabbing"};
window.addEventListener("pointerup",e=>{const n=G.drag;G.drag=null;cv.style.cursor="grab";
 if(n&&downAt&&Math.hypot(e.clientX-downAt[0],e.clientY-downAt[1])<5)pivotMenu(n,e.clientX,e.clientY);downAt=null});
cv.onpointermove=e=>{const[x,y]=pt(e);if(G.drag){G.drag.x=x;G.drag.y=y;G.drag.vx=G.drag.vy=0}G.hover=nearest(x,y)};
cv.onpointerleave=()=>G.hover=null;
let GRAF=0;function tick(){if(tab!=="graph"||!W||document.hidden){GRAF=0;return}GRAF=requestAnimationFrame(tick);const N=G.nodes;
 for(let i=0;i<N.length;i++){const a=N[i];a.age=Math.min(1,a.age+.04);
  for(let j=i+1;j<N.length;j++){const b=N[j];let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy+.5,m=Math.sqrt(d2),f=2800/d2;dx/=m;dy/=m;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f}
  a.vx+=(W/2-a.x)*.0016;a.vy+=(H/2-a.y)*.0016}
 for(const[a,b]of G.edges){const dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||1,f=(d-95)*.012;a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f}
 for(const n of N){if(n===G.drag)continue;n.vx*=.84;n.vy*=.84;n.x=Math.min(W-20,Math.max(20,n.x+n.vx));n.y=Math.min(H-20,Math.max(20,n.y+n.vy))}
 cx.setTransform(dpr,0,0,dpr,0,0);cx.clearRect(0,0,W,H);const hv=G.hover,near=new Set();
 if(hv){near.add(hv);G.edges.forEach(([a,b])=>{if(a===hv)near.add(b);if(b===hv)near.add(a)})}
 for(const[a,b]of G.edges){const hot=hv&&(a===hv||b===hv);cx.strokeStyle=hot?"rgba(192,132,252,.9)":"rgba(168,130,255,.14)";cx.lineWidth=hot?1.8:1;cx.beginPath();cx.moveTo(a.x,a.y);cx.lineTo(b.x,b.y);cx.stroke()}
 for(const n of N){const c=TY[n.t]||"#999",e=1-Math.pow(1-n.age,3),dim=hv&&!near.has(n),r=(n.t==="src"?9:6)*e*(n===hv?1.4:1);
  cx.globalAlpha=dim?.22:1;cx.shadowColor=c;cx.shadowBlur=n===hv?26:13;cx.fillStyle=c;cx.beginPath();
  if(n.t==="src")cx.roundRect?cx.roundRect(n.x-r,n.y-r,r*2,r*2,3):cx.rect(n.x-r,n.y-r,r*2,r*2);else cx.arc(n.x,n.y,r,0,7);cx.fill();cx.shadowBlur=0;
  if(n.t==="src"||near.has(n)){cx.fillStyle="#ece8f5";cx.font="11px Segoe UI,sans-serif";cx.textAlign="center";cx.fillText(n.l.slice(0,34),n.x,n.y+r+14)}}
 cx.globalAlpha=1}

/* =================== ПИВОТЫ (Maltego-подобно) =================== */
const PIVOTS={
 domain:["site_recon","dns","whois","subdomains","harvester","lookalikes","phishing","tracking","domain_history","reputation","leaks","email_sec","wayback_urls","secrets"],
 ip:["ip_radar","ip_info","internetdb","asn","reputation","reverse_dns","reverse_ip"],
 email:["email","leaks","reputation"],
 phone:["phone"],
 account:["username","github","telegram"]};
function pivotMenu(n,x,y){
 if(n.t==="src"){const s=st.sources.find(s=>"s"+s.id===n.id);if(s&&s.snapshot)window.open("/snapshot/"+encodeURIComponent(s.snapshot)+"?t="+T,"_blank");return}
 const e=st.entities.find(e=>"e"+e.id===n.id);if(!e)return;
 let q=e.value,list=PIVOTS[e.type]||[];
 if(e.type==="account"){const[net,name]=e.value.split(":");q=name;list=net==="github"?["github","username"]:net==="telegram"?["telegram","username"]:["username"]}
 if(e.type==="email")list=list.concat([["domain",e.value.split("@")[1]]]);
 const items=[[`${TL[e.type]||e.type}: ${e.value}`,null],["🗂 Досье сущности",()=>openDossier(e.id)]];
 if(e.type==="ip")items.push(["🌍 Показать на глобусе",()=>{setTab("globe");setTimeout(()=>globeFindIp(e.value),200)}]);
 for(const it of list){if(Array.isArray(it)){const v=it[1];PIVOTS.domain.slice(0,5).forEach(id=>{const t=TOOLS.find(t=>t.id===id);items.push([`${t.ic||"🔧"} ${t.tn} → ${v}`,()=>runPivot(id,v,e)])});continue}
  const t=TOOLS.find(t=>t.id===it);if(t)items.push([`${t.ic||"🔧"} ${t.tn}`,()=>runPivot(it,q,e)])}
 items.push(["📋 Копировать значение",()=>{navigator.clipboard&&navigator.clipboard.writeText(e.value);toast("Скопировано","ok")}]);
 showMenu(x,y,items)}
async function runPivot(id,q,e){if(!cur)return;const t=TOOLS.find(t=>t.id===id);
 toast(`${t.tn}: ${q} — запущено, результат попадёт в кейс`);
 try{const r=await api("job",{name:id,q,case:cur.id,autosave:1,pivot:[e.type,e.value]});
  const fin=await waitJob(r.id);
  if(fin.state==="done"){toast(`${t.tn}: готово, новых связей: ${fin.saved?fin.saved.entities:0}`,"ok");refresh()}
  else toast(`${t.tn}: ${fin.error||fin.state}`,"bad")}catch(x){toast(x.message,"bad")}}
async function waitJob(id,cb){for(;;){await new Promise(r=>setTimeout(r,450));const s=await api("job_status?id="+id);if(cb)cb(s);if(s.state!=="running")return s}}

/* =================== МЕНЮ И МОДАЛЬНЫЕ ОКНА =================== */
function closeMenu(){$$(".menu").forEach(m=>m.remove())}
function showMenu(x,y,items){closeMenu();const m=document.createElement("div");m.className="menu";
 items.forEach(([l,fn])=>{if(!fn){const h=document.createElement("div");h.className="mh";h.textContent=l;m.append(h);return}
  const b=document.createElement("button");b.textContent=l;b.onclick=()=>{closeMenu();fn()};m.append(b)});
 document.body.append(m);const r=m.getBoundingClientRect();
 m.style.left=Math.min(x,innerWidth-r.width-10)+"px";m.style.top=Math.min(y,innerHeight-r.height-10)+"px";
 setTimeout(()=>document.addEventListener("click",closeMenu,{once:true}),0)}
function modal(title,html){closeModal();const bg=document.createElement("div");bg.className="modal-bg";
 bg.innerHTML=`<div class="modal"><h3>${title}<button class="x" title="Закрыть">✕</button></h3><div class="mb">${html}</div></div>`;
 bg.onclick=e=>{if(e.target===bg||e.target.classList.contains("x"))closeModal()};document.body.append(bg);return bg.querySelector(".mb")}
function closeModal(){$$(".modal-bg").forEach(m=>m.remove())}
document.addEventListener("keydown",e=>{if(e.key==="Escape"){closeModal();closeMenu()}});

/* =================== ХРОНОЛОГИЯ =================== */
async function renderTimeline(){if(!cur){$("#tline").innerHTML="";return}
 const ev=await api("timeline?case="+cur.id);
 const K={archive:"архив",tool:"инструмент",fact:"факт"};
 $("#tline").innerHTML=ev.length?`<div class="toolnote" style="margin-left:-24px">Хронология собирается автоматически: даты архивации, даты публикации со страниц и даты из результатов инструментов
  (регистрация домена, выпуск сертификатов, первые снимки Wayback, создание аккаунтов…). Зелёные точки — факты, фиолетовые — результаты инструментов.</div>`+
  ev.map((e,i)=>`<div class="ev2 ${e.kind}" style="--i:${Math.min(i,20)}"><span class="d">${esc(e.date)}</span> <span class="badge" style="margin-left:6px">${K[e.kind]||e.kind}</span> <span style="color:var(--mu)">#${e.source}</span><br>${esc(e.label)}</div>`).join("")
  :'<div class="empty"><b>Хронология пуста</b>Добавьте источники или сохраните в кейс результаты инструментов (например «Хронология домена» или WHOIS)</div>'}

/* =================== ВЕРСИИ И СРАВНЕНИЕ =================== */
async function openVersions(id){const v=await api("versions?id="+id);
 const opts=v.map(x=>`<option value="${x.id}">#${x.id} · ${esc(x.fetched)} · ${esc(x.status)}</option>`).join("");
 const b=modal("Версии страницы и сравнение",`<div class="row"><select id="va">${opts}</select><span>→</span><select id="vb">${opts}</select><button class="btn" id="vgo">Сравнить</button></div><div id="vres" style="margin-top:14px"></div>`);
 if(v.length>1){b.querySelector("#va").value=v[v.length-2].id;b.querySelector("#vb").value=v[v.length-1].id}
 b.querySelector("#vgo").onclick=()=>showDiff(b.querySelector("#va").value,b.querySelector("#vb").value,b.querySelector("#vres"));
 if(v.length>1)b.querySelector("#vgo").click()}
function openCompare(){if(!st||st.sources.length<2)return toast("Нужно минимум два источника","bad");
 const opts=st.sources.map(s=>`<option value="${s.id}">#${s.id} · ${esc((s.kind==="tool"?"🛠 "+s.tool+": "+s.query:(s.title||s.url)).slice(0,70))}</option>`).join("");
 const b=modal("Сравнение двух снимков",`<div class="hint" style="margin-bottom:10px">Сравнивается видимый текст страниц (или JSON результатов инструментов): что удалено, что добавлено.</div>
  <div class="row"><select id="va">${opts}</select><span>→</span><select id="vb">${opts}</select><button class="btn" id="vgo">Сравнить</button></div><div id="vres" style="margin-top:14px"></div>`);
 b.querySelector("#vb").selectedIndex=1;b.querySelector("#vgo").onclick=()=>showDiff(b.querySelector("#va").value,b.querySelector("#vb").value,b.querySelector("#vres"))}
async function showDiff(a,bb,el){el.innerHTML='<div class="prog ind"><i></i></div>';
 try{const d=await api(`diff?a=${a}&b=${bb}`);
  el.innerHTML=`<div class="row" style="margin-bottom:10px"><span class="chip ok">+${d.added} добавлено</span><span class="chip bad">−${d.removed} удалено</span><span class="pill">сходство ${d.similarity}%</span></div>`+
  (d.added||d.removed?d.lines.map(l=>`<div class="dl ${l.op}">${l.op==="add"?"+ ":l.op==="del"?"− ":"  "}${esc(l.text)}</div>`).join(""):'<div class="empty" style="padding:30px">Тексты совпадают</div>')}
 catch(x){el.innerHTML=`<span style="color:var(--bad)">${esc(x.message)}</span>`}}

/* =================== ИНСТРУМЕНТЫ =================== */
const TOOLS=[
 {id:"attribution",cat:"Разведка организации",ic:"🧬",tn:"Один оператор: атрибуция доменов",td:"Список доменов → кластеры «один хозяин»: общие ID аналитики, сертификаты, favicon, IP, NS/MX, регистрация, похожая вёрстка — с объяснением каждой связи",ph:"phish-1.com\nphish-2.net\n…",area:1,wide:1},
 {id:"exposure",cat:"Информационная безопасность",ic:"🛡",tn:"Ваш цифровой след (самоаудит)",td:"Что любой узнает о вашей организации без взлома: почта, сайт, поддомены, порты и CVE, утечки, метаданные документов, архив. Оценка и чек-лист «что закрыть»",ph:"company.com  (и email через пробел)",wide:1},
 {id:"pattern",cat:"OSINT: люди",ic:"🕰",tn:"Ритм жизни",td:"Тепловая карта активности → часовой пояс, сон, будни/выходные, аномальные недели. github:ник · reddit:ник · bsky:handle · @user@instance (Mastodon) — или вставьте свои временные метки",ph:"github:torvalds  ·  или список дат/unix-времени",area:1,wide:1},
 {id:"magic",cat:"Утилиты",ic:"🪄",tn:"Магия декодирования (как CyberChef)",td:"Сам подберёт цепочку: base64/32/58, hex, URL, ROT/Цезарь, XOR с перебором ключа, gzip/zlib, Морзе, JWT… Ручной рецепт: первая строка «recipe: b64 > gunzip > xor:0x2a»",ph:"вставьте непонятную строку",area:1,wide:1,file:1},
 {id:"img_forensics",cat:"Файлы и медиа",ic:"🔬",tn:"Криминалистика фото",td:"ELA (вклейки и правки), битовые плоскости (стеганография), миниатюра EXIF против фото, качество JPEG, следы редакторов",ph:"URL изображения (или выберите файл)",file:1,wide:1,accept:"image/*"},
 {id:"email_headers",cat:"Информационная безопасность",ic:"📨",tn:"Разбор email-заголовков",td:"Путь письма по серверам (и на глобусе), SPF/DKIM/DMARC, подмена отправителя и Reply-To, задержки",ph:"вставьте исходник письма («Показать оригинал») или выберите .eml",area:1,wide:1,file:1,accept:".eml,.txt,message/rfc822"},
 {id:"ransomware",cat:"Разведка организации",ic:"☠️",tn:"Утечки вымогателей",td:"Есть ли компания на сайтах утечек ransomware-группировок (ransomware.live). Можно поставить на наблюдение",ph:"название компании или домен"},
 {id:"phishing",cat:"Информационная безопасность",ic:"🎣",tn:"Проверка ссылки на фишинг",td:"Риск 0–100: признаки в адресе, бренд-двойник, возраст домена, сертификат, редиректы, форма пароля, репутация",ph:"https://подозрительная.ссылка",wide:1},
 {id:"ip_radar",cat:"Информационная безопасность",ic:"📡",tn:"IP-радар",td:"Вердикт по IP из ~20 открытых источников: угрозы, C2, Tor, VPN, облака, гео (можно список; есть отдельная вкладка)",ph:"1.2.3.4, 5.6.7.8"},
 {id:"leaks",cat:"OSINT: люди",ic:"💧",tn:"Утечки (XposedOrNot)",td:"Email, домен или пароль: в каких утечках, какие данные, уровень риска",ph:"user@example.com · домен · пароль"},
 {id:"capture",cat:"Разведка сайта",ic:"📷",tn:"Скриншот и PDF страницы",td:"Снимок через Edge без окна — как страницу видит человек",ph:"https://example.com"},
 {id:"import_file",cat:"Файлы и медиа",ic:"📥",tn:"Импорт Sherlock / SpiderFoot",td:"Загрузите результат другого инструмента (txt/csv/json) — находки попадут в кейс и граф",ph:"выберите файл →",file:1,fileOnly:1,accept:".txt,.csv,.json"},
 {id:"tsa",cat:"Файлы и медиа",ic:"⏳",tn:"Метка времени RFC 3161",td:"Независимая служба подписывает хэш файла или текста — доказательство, что он существовал к этому моменту",ph:"текст или выберите файл",file:1},
 {id:"harvester",cat:"Разведка организации",ic:"🌾",tn:"Харвестер (как theHarvester)",td:"Email, поддомены и хосты организации из CT-логов, Wayback, HackerTarget и страниц сайта",ph:"example.com",wide:1},
 {id:"lookalikes",cat:"Разведка организации",ic:"🎭",tn:"Двойники домена (как dnstwist)",td:"Опечатки, гомоглифы, смена зоны — какие похожие домены уже зарегистрированы (фишинг)",ph:"example.com",wide:1},
 {id:"tracking",cat:"Разведка организации",ic:"🧷",tn:"Связанные сайты по ID счётчиков",td:"Google Analytics, AdSense, Метрика, Pixel, верификации, favicon. Несколько URL через запятую — покажет общие ID",ph:"site1.com, site2.com",wide:1},
 {id:"domain_history",cat:"Разведка организации",ic:"📅",tn:"Хронология домена",td:"Регистрация, первый SSL-сертификат, первый и последний снимок веб-архива, возраст домена",ph:"example.com"},
 {id:"asn",cat:"Разведка организации",ic:"🏢",tn:"ASN и сети организации",td:"Владелец IP/AS, анонсируемые сети; поиск AS по названию компании (RIPEstat)",ph:"8.8.8.8 · AS13335 · cloudflare"},
 {id:"crawl",cat:"Разведка сайта",ic:"🕷",tn:"Обход сайта (как Photon)",td:"До 60 страниц: email, телефоны, JS-файлы, формы, параметры, документы, комментарии в HTML",ph:"https://example.com",wide:1},
 {id:"wayback_urls",cat:"Разведка сайта",ic:"🗄",tn:"URL из веб-архива (как gau)",td:"Все известные архиву адреса: конфиги, бэкапы, документы, API, админки, параметры",ph:"example.com"},
 {id:"secrets",cat:"Информационная безопасность",ic:"🔑",tn:"Поиск утёкших ключей (как gitleaks)",td:"API-ключи и токены в странице, её JS-файлах или в вставленном тексте. Значения маскируются",ph:"https://example.com или вставьте текст"},
 {id:"reputation",cat:"Информационная безопасность",ic:"☣️",tn:"Репутация IOC",td:"IP / домен / URL / хэш: AlienVault OTX, urlscan, Shodan InternetDB, DNSBL (+VirusTotal, AbuseIPDB с ключом)",ph:"1.2.3.4 · evil.com · хэш"},
 {id:"internetdb",cat:"Информационная безопасность",ic:"📡",tn:"Порты и CVE без сканирования",td:"Открытые порты, уязвимости и ПО по базе Shodan InternetDB (бесплатно, Provenio сам не сканирует)",ph:"1.1.1.1 или домен"},
 {id:"cve",cat:"Информационная безопасность",ic:"🐞",tn:"CVE: уязвимости",td:"По номеру или по «продукт версия»: CVSS, эксплуатируется ли (CISA KEV), вероятность атаки (EPSS)",ph:"CVE-2021-44228 или nginx 1.18.0"},
 {id:"ioc",cat:"Информационная безопасность",ic:"🧪",tn:"Извлечь IOC из текста",td:"URL, IP, домены, хэши, CVE, BTC/ETH, техники ATT&CK; понимает hxxp и [.]",ph:"вставьте отчёт/лог",ioc:1,area:1},
 {id:"file_meta",cat:"Файлы и медиа",ic:"🖼",tn:"Метаданные файла (как ExifTool)",td:"EXIF и GPS фото, автор/программа PDF и Office. Файл с компьютера или URL",ph:"URL файла (или выберите файл)",file:1,wide:1},
 {id:"reverse_image",cat:"Файлы и медиа",ic:"🔍",tn:"Обратный поиск фото",td:"Ссылки поиска картинки в Google Lens, Яндексе, Bing и TinEye",ph:"https://…/photo.jpg"},
 {id:"evidence_verify",cat:"Файлы и медиа",ic:"🧾",tn:"Проверка пакета доказательств",td:"Выберите ZIP, выгруженный из Provenio: хэши файлов и цепочка аудита будут пересчитаны",ph:"выберите ZIP-файл →",file:1,fileOnly:1,accept:".zip"},
 {id:"github",cat:"OSINT: люди",ic:"🐙",tn:"GitHub-разведка",td:"Профиль, организации, языки, email из публичных коммитов, SSH-ключи",ph:"username"},
 {id:"telegram",cat:"OSINT: люди",ic:"✈️",tn:"Telegram-канал",td:"Публичный канал: описание, подписчики, последние посты, упоминания и ссылки",ph:"@channel или t.me/channel"},
 {id:"crypto",cat:"OSINT: люди",ic:"₿",tn:"Крипто-адрес",td:"Баланс и транзакции Bitcoin / Ethereum по публичным обозревателям",ph:"bc1… или 0x…"},
 {id:"mac",cat:"Утилиты",ic:"📶",tn:"Производитель по MAC",td:"OUI-производитель, признак случайного (приватного) MAC",ph:"00:1A:2B:3C:4D:5E"},
 {id:"site_recon",cat:"Разведка сайта",ic:"🛰",tn:"Полная разведка сайта",td:"Технологии, мета, OpenGraph, ссылки, контакты, формы — одним запросом",ph:"example.com",wide:1},
 {id:"tech",cat:"Разведка сайта",ic:"🧩",tn:"Технологии (fingerprint)",td:"CMS, фреймворки, сервер, аналитика, CDN",ph:"example.com"},
 {id:"robots",cat:"Разведка сайта",ic:"🤖",tn:"robots.txt + sitemap",td:"Запрещённые пути и карта сайта (список URL)",ph:"example.com"},
 {id:"redirects",cat:"Разведка сайта",ic:"➡️",tn:"Цепочка редиректов",td:"Все переходы до конечного URL",ph:"http://example.com"},
 {id:"favicon",cat:"Разведка сайта",ic:"⭐",tn:"Favicon-хэш (Shodan)",td:"mmh3-хэш для пивотинга + готовый поиск Shodan",ph:"example.com"},
 {id:"email_sec",cat:"Разведка сайта",ic:"📮",tn:"Антиспуфинг домена",td:"SPF, DMARC, DKIM, MX — защита почты",ph:"example.com"},
 {id:"security_txt",cat:"Разведка сайта",ic:"📄",tn:"security.txt",td:"Контакты безопасности (RFC 9116)",ph:"example.com"},
 {id:"dns",cat:"Сеть и домены",ic:"🌐",tn:"DNS-записи",td:"A, AAAA, MX, NS, TXT, CNAME, SOA, CAA через DNS-over-HTTPS",ph:"example.com"},
 {id:"whois",cat:"Сеть и домены",ic:"📜",tn:"WHOIS",td:"Регистратор, даты, статусы и NS домена",ph:"example.com"},
 {id:"rdap",cat:"Сеть и домены",ic:"🗂",tn:"RDAP",td:"Структурный WHOIS для домена / IP / ASN",ph:"example.com или 8.8.8.8"},
 {id:"subdomains",cat:"Сеть и домены",ic:"🧬",tn:"Поддомены",td:"Certificate Transparency (crt.sh, certspotter) + HackerTarget",ph:"example.com"},
 {id:"ssl",cat:"Сеть и домены",ic:"🔒",tn:"TLS-сертификат",td:"Издатель, срок действия, SAN, версия TLS",ph:"example.com"},
 {id:"headers",cat:"Сеть и домены",ic:"🧱",tn:"Заголовки безопасности",td:"Оценка HTTP security-заголовков (A–F)",ph:"https://example.com"},
 {id:"reverse_dns",cat:"Сеть и домены",ic:"↩️",tn:"Обратный DNS (PTR)",td:"Имя хоста по IP-адресу",ph:"8.8.8.8"},
 {id:"ip_info",cat:"Сеть и домены",ic:"📍",tn:"Гео и ASN по IP",td:"Страна, город, провайдер, автономная система",ph:"1.1.1.1"},
 {id:"reverse_ip",cat:"Сеть и домены",ic:"🔗",tn:"Reverse IP (соседи)",td:"Другие домены на том же IP (лимит в сутки)",ph:"8.8.8.8"},
 {id:"wayback",cat:"Сеть и домены",ic:"🕰",tn:"Wayback Machine",td:"Ближайший архивный снимок страницы",ph:"https://example.com"},
 {id:"username",cat:"OSINT: люди",ic:"🧑‍💻",tn:"Поиск по нику",td:"Публичные профили на ~460 сайтах (база Sherlock Project), параллельно",ph:"username"},
 {id:"email",cat:"OSINT: люди",ic:"✉️",tn:"Разбор email",td:"Синтаксис, MX-домен, наличие Gravatar",ph:"user@example.com"},
 {id:"phone",cat:"OSINT: люди",ic:"📞",tn:"Разбор телефона",td:"Страна по коду, формат E.164, валидация",ph:"+7 912 345-67-89"},
 {id:"pwned",cat:"Информационная безопасность",ic:"🛡",tn:"Пароль в утечках",td:"k-anonymity HIBP — сам пароль не передаётся",ph:"пароль для проверки",pw:1},
 {id:"strength",cat:"Информационная безопасность",ic:"💪",tn:"Стойкость пароля",td:"Энтропия и оценка времени подбора (локально)",ph:"пароль для оценки",pw:1},
 {id:"hash",cat:"Утилиты",ic:"#️⃣",tn:"Хэши строки",td:"MD5, SHA-1, SHA-256, SHA-512",ph:"текст"},
 {id:"hash_id",cat:"Утилиты",ic:"🔍",tn:"Определить хэш",td:"Тип хэша по длине и алфавиту",ph:"5d41402abc4b2a76b9719d911017c592"},
 {id:"jwt",cat:"Утилиты",ic:"🎫",tn:"JWT-декодер",td:"Header, payload, срок действия (без проверки подписи)",ph:"eyJhbGci…"},
 {id:"cidr",cat:"Утилиты",ic:"🧮",tn:"Калькулятор подсети",td:"Диапазон, маска, число хостов",ph:"192.168.1.0/24"},
 {id:"timestamp",cat:"Утилиты",ic:"⏱",tn:"Конвертер времени",td:"unix ↔ ISO (пусто = сейчас)",ph:"1600000000 или 2020-09-13"},
 {id:"uuid",cat:"Утилиты",ic:"🆔",tn:"UUID",td:"Сгенерировать v4 или разобрать переданный",ph:"пусто = сгенерировать"},
 {id:"idn",cat:"Утилиты",ic:"🔤",tn:"Punycode / IDN",td:"Кодирование домена + детект гомоглифов",ph:"пример.рф"},
 {id:"entropy",cat:"Утилиты",ic:"🎲",tn:"Энтропия Шеннона",td:"Оценка случайности строки (поиск секретов)",ph:"строка"},
 {id:"luhn",cat:"Утилиты",ic:"✅",tn:"Проверка Луна",td:"Валидность карты/IMEI по алгоритму Luhn",ph:"4111 1111 1111 1111"},
 {id:"base",cat:"Утилиты",ic:"🔢",tn:"Системы счисления",td:"dec · hex · oct · bin",ph:"255 или 0xff"},
 {id:"dork",cat:"Утилиты",ic:"🔎",tn:"Google Dorks",td:"Готовые поисковые запросы по домену",ph:"example.com"},
 {id:"transform",cat:"Утилиты",ic:"🔁",tn:"Кодирование",td:"base64 · hex · url · rot13 · binary",ph:"текст",tf:1},
];
let toolCat="все",toolQ="";const RES={};
function renderTools(){
 const cats=["все",...new Set(TOOLS.map(t=>t.cat))];
 $("#toolcats").innerHTML=cats.map(c=>`<span class="fc ${toolCat===c?"on":""}" data-c="${esc(c)}">${esc(c)} ${c==="все"?TOOLS.length:TOOLS.filter(t=>t.cat===c).length}</span>`).join("")+`<span class="fc ${toolCat==="пакет"?"on":""}" data-c="пакет">⚡ Пакетный режим</span>`;
 if(toolCat==="пакет"){renderBatch();return}
 const ql=toolQ.toLowerCase();
 const list=TOOLS.filter(t=>(toolCat==="все"||t.cat===toolCat)&&(!ql||(t.tn+" "+t.td+" "+t.cat).toLowerCase().includes(ql)));
 $("#tgrid").innerHTML=list.map((t,i)=>`<div class="card tool" data-id="${t.id}" style="--i:${Math.min(i,24)};${t.wide?"grid-column:1/-1;":""}">
  <div class="th"><div class="ic">${t.ic||"🔧"}</div><div><div class="tn">${esc(t.tn)}</div><div class="td">${esc(t.td)}</div></div></div>
  <div class="tin">
   ${t.tf?`<select class="tf-mode" style="max-width:110px"><option value="base64">base64</option><option value="hex">hex</option><option value="url">url</option><option value="rot13">rot13</option><option value="binary">binary</option></select>`:""}
   ${t.ioc?`<select class="tf-mode" style="max-width:150px"><option value="extract">извлечь</option><option value="defang">обезвредить</option><option value="refang">вернуть как было</option></select>`:""}
   ${t.fileOnly?"":t.area?`<textarea class="tq" rows="3" placeholder="${esc(t.ph)}"></textarea>`:`<input class="tq" type="${t.pw?"password":"text"}" placeholder="${esc(t.ph)}">`}
   ${t.file?`<label class="ghost" style="cursor:pointer">📎 Файл<input type="file" class="tfile" ${t.accept?`accept="${t.accept}"`:""} hidden></label>`:""}
   ${t.tf?`<button class="tbtn tf-act" data-act="encode">→</button><button class="tbtn tf-act" data-act="decode" style="background:linear-gradient(135deg,#6d28d9,#4c1d95)">←</button>`:`<button class="tbtn tf-act">Запуск</button>`}
  </div>
  <div class="tres" id="r-${t.id}"></div></div>`).join("")||'<div class="empty">Ничего не найдено</div>';
 list.forEach(t=>{if(RES[t.id])showRes(t.id)});
}
$("#tsearch").oninput=e=>{toolQ=e.target.value;renderTools()};
$("#autosave").onchange=e=>{try{localStorage.setItem("pv_autosave",e.target.checked?"1":"")}catch(x){}};
try{$("#autosave").checked=!!localStorage.getItem("pv_autosave")}catch(x){}
$("#toolcats").onclick=e=>{const c=e.target.closest(".fc");if(c){toolCat=c.dataset.c;renderTools()}};
$("#tgrid").onclick=e=>{const btn=e.target.closest(".tf-act");if(btn)return runTool(btn);
 const a=e.target.closest("[data-act2]");if(a)resAction(a.dataset.act2,a.closest(".tool").dataset.id)};
$("#tgrid").onkeydown=e=>{if(e.key==="Enter"&&e.target.tagName==="INPUT"&&e.target.classList.contains("tq")){const b=e.target.closest(".tool").querySelector(".tf-act");runTool(b)}};
$("#tgrid").onchange=e=>{if(e.target.classList.contains("tfile")&&e.target.files[0]){const card=e.target.closest(".tool");
 const q=card.querySelector(".tq");if(q)q.value="📎 "+e.target.files[0].name;runTool(card.querySelector(".tf-act"))}};
function readFile(f){return new Promise((ok,bad)=>{if(f.size>40*1024*1024)return bad(new Error("Файл больше 40 МБ"));
 const r=new FileReader();r.onload=()=>ok(String(r.result).split(",")[1]);r.onerror=()=>bad(r.error);r.readAsDataURL(f)})}
async function runTool(btn){
 const card=btn.closest(".tool"),id=card.dataset.id,t=TOOLS.find(t=>t.id===id),res=card.querySelector(".tres");
 if(RES[id]&&RES[id].state==="running")return;
 const qi=card.querySelector(".tq"),fi=card.querySelector(".tfile");let q=qi?qi.value.trim():"";
 const body={name:id,q};
 if(fi&&fi.files[0]&&(!q||q.startsWith("📎"))){try{body.file=await readFile(fi.files[0]);body.filename=fi.files[0].name;body.q=fi.files[0].name;LASTFILE[id]=fi.files[0]}catch(x){return toast(x.message,"bad")}}
 else if(t.fileOnly)return toast("Выберите файл","bad");
 if(!body.q&&!body.file&&!["timestamp","uuid"].includes(id))return toast("Введите значение","bad");
 if(q.startsWith("📎")&&!body.file)return toast("Выберите файл заново","bad");
 const mode=card.querySelector(".tf-mode");if(mode)body.mode=mode.value;
 if(btn.dataset.act&&id==="transform")body.action=btn.dataset.act;
 const auto=$("#autosave").checked&&cur&&!["pwned","strength","transform","hash","base","uuid","timestamp","luhn"].includes(id);
 if(auto){body.case=cur.id;body.autosave=1}
 RES[id]={state:"running",q:body.q,done:0,all:0,msg:"Запуск…"};showRes(id);
 try{const r=await api("job",body);RES[id].job=r.id;
  const fin=await waitJob(r.id,s=>{Object.assign(RES[id],{done:s.done,all:s.all,msg:s.msg});showRes(id)});
  RES[id]={...RES[id],state:fin.state,data:fin.result,error:fin.error,saved:fin.saved,elapsed:fin.elapsed,body};
  if(fin.saved){toast("Сохранено в кейс: источник #"+fin.saved.source+", сущностей "+fin.saved.entities,"ok");refresh()}
 }catch(x){RES[id]={state:"error",error:x.message}}
 showRes(id)}
function showRes(id){const el=document.getElementById("r-"+id);if(!el)return;const R=RES[id],card=el.closest(".tool");
 const b=card.querySelector(".tf-act");el.classList.add("show");
 if(R.state==="running"){if(b)b.classList.add("loading");const p=R.all?Math.round(R.done/R.all*100):0;
  el.innerHTML=`<div class="prog ${R.all?"":"ind"}"><i style="width:${p}%"></i></div><div class="pmsg">${esc(R.msg||"")}${R.all?` · ${R.done}/${R.all}`:""}</div>
   <div class="tacts"><button class="ghost" data-act2="cancel">■ Остановить</button></div>`;return}
 if(b)b.classList.remove("loading");
 if(R.state==="cancelled"){el.innerHTML='<span class="mu">Остановлено</span>';return}
 if(R.state==="error"){el.innerHTML=`<span style="color:var(--bad)">⚠ ${esc(R.error)}</span>`;return}
 let h="";try{h=fmtTool(id,R.data,R.body||{})}catch(x){h=fmtAny(R.data)}
 const saveable=!["pwned","strength","transform","hash","base","uuid","timestamp","luhn"].includes(id);
 el.innerHTML=h+`<div class="tacts">${saveable?(R.saved?`<span class="chip ok">✓ в кейсе: источник #${R.saved.source}</span>`:`<button class="ghost" data-act2="save">＋ В кейс</button>`):""}
  <button class="ghost" data-act2="copy">⧉ JSON</button><span class="pmsg" style="margin-left:auto">${R.elapsed!=null?R.elapsed+" с":""}</span></div>`}
async function resAction(act,id){const R=RES[id];if(!R)return;
 if(act==="cancel"&&R.job){await api("job_cancel",{id:R.job});return}
 if(act==="copy"){navigator.clipboard&&navigator.clipboard.writeText(JSON.stringify(R.data,null,2));toast("JSON скопирован","ok");return}
 if(act==="save"){if(!cur)return toast("Сначала создайте кейс","bad");
  try{const s=await api("job_save",{id:R.job,case:cur.id});R.saved=s;showRes(id);toast("Сохранено в кейс: сущностей "+s.entities,"ok");refresh()}catch(x){toast(x.message,"bad")}}}

/* ---------- пакетный режим ---------- */
function renderBatch(){
 const opts=TOOLS.filter(t=>!t.file&&!t.tf&&!t.area&&!t.pw).map(t=>`<option value="${t.id}">${esc(t.cat)} · ${esc(t.tn)}</option>`).join("");
 $("#tgrid").innerHTML=`<div class="card tool batch" style="grid-column:1/-1"><div class="th"><div class="ic">⚡</div><div><div class="tn">Пакетный режим</div>
  <div class="td">Один инструмент для списка значений (по одному в строке). Запускается по 3 одновременно; результаты можно разом сохранить в кейс.</div></div></div>
  <div class="row"><select id="bt" style="max-width:420px">${opts}</select><button class="tbtn" id="bgo">Запуск</button><button class="ghost" id="bstop">■ Стоп</button><button class="ghost" id="bsave">＋ Всё в кейс</button></div>
  <textarea id="bq" placeholder="example.com&#10;example.org&#10;1.1.1.1"></textarea>
  <div class="prog" id="bprog"><i></i></div><div class="pmsg" id="bmsg"></div><div id="bres"></div></div>`;
 $("#bgo").onclick=runBatch;$("#bstop").onclick=()=>{BATCH.stop=true;BATCH.items.forEach(it=>it.job&&it.state==="running"&&api("job_cancel",{id:it.job}))};
 $("#bsave").onclick=async()=>{if(!cur)return toast("Сначала создайте кейс","bad");let n=0;
  for(const it of BATCH.items)if(it.state==="done"&&!it.saved){try{it.saved=await api("job_save",{id:it.job,case:cur.id});n++}catch(x){}}
  toast("Сохранено результатов: "+n,"ok");refresh();drawBatch()};
 drawBatch()}
const BATCH={items:[],stop:false};
async function runBatch(){const tool=$("#bt").value,vals=[...new Set($("#bq").value.split(/\n|,|;/).map(x=>x.trim()).filter(Boolean))].slice(0,300);
 if(!vals.length)return toast("Добавьте значения","bad");BATCH.items=vals.map(v=>({q:v,state:"wait",tool}));BATCH.stop=false;drawBatch();
 let i=0;const worker=async()=>{while(i<BATCH.items.length&&!BATCH.stop){const it=BATCH.items[i++];it.state="running";drawBatch();
  try{const r=await api("job",{name:tool,q:it.q});it.job=r.id;const f=await waitJob(r.id);it.state=f.state;it.data=f.result;it.error=f.error}catch(x){it.state="error";it.error=x.message}
  drawBatch()}};
 await Promise.all([worker(),worker(),worker()]);toast("Пакет завершён","ok")}
function drawBatch(){const el=$("#bres");if(!el)return;const n=BATCH.items.length,d=BATCH.items.filter(x=>!["wait","running"].includes(x.state)).length;
 $("#bprog i").style.width=(n?d/n*100:0)+"%";$("#bmsg").textContent=n?`Готово ${d} из ${n}`:"";
 el.innerHTML=n?`<table class="t" style="margin-top:10px"><tr><th>Значение</th><th>Статус</th><th>Кратко</th></tr>${BATCH.items.map((it,k)=>`<tr><td>${esc(it.q)}</td>
  <td>${it.state==="done"?'<span class="found">✓</span>':it.state==="error"?'<span style="color:var(--bad)">ошибка</span>':it.state==="running"?"…":it.state==="cancelled"?"стоп":"ждёт"}${it.saved?' <span class="chip ok">в кейсе</span>':""}</td>
  <td style="color:var(--mu)">${esc(it.error||summary(it.data))}</td></tr>`).join("")}</table>`:""}
function summary(d){if(!d)return"";const parts=[];for(const k of Object.keys(d)){const v=d[k];if(v==null||typeof v==="object"&&!Array.isArray(v))continue;
 parts.push(k+": "+(Array.isArray(v)?v.length+" шт.":String(v).slice(0,40)));if(parts.length>=4)break}return parts.join(" · ")}

function kv(k,v){return `<div class="kv"><b>${esc(k)}</b><span>${v==null||v===""?"—":esc(v)}</span></div>`}
const lnk=(u,t)=>`<a class="url" style="display:inline" target="_blank" rel="noopener noreferrer" href="${esc(u)}">${esc(t||u)}</a>`;
const tags=(a,cls)=>(a&&a.length)?a.map(x=>`<span class="tag ${cls||""}">${esc(x)}</span>`).join(""):'<span class="mu" style="color:var(--mu2)">—</span>';
const sec=(t,h)=>`<div class="sec"><b>${esc(t)}</b>${h}</div>`;
const links=o=>Object.keys(o||{}).map(k=>`<div class="kv"><b>${esc(k)}</b><span>${lnk(o[k],"открыть ↗")}</span></div>`).join("");
const tbl=(cols,rows)=>`<table class="t"><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join("")}</tr>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join("")}</tr>`).join("")}</table>`;
function fmtAny(d,depth){depth=depth||0;if(d==null)return'<span class="mu">—</span>';
 if(Array.isArray(d)){if(!d.length)return'<span class="mu">—</span>';if(typeof d[0]!=="object")return tags(d.slice(0,200).map(String));
  return d.slice(0,60).map(x=>`<div style="border-left:2px solid var(--bd);padding-left:9px;margin:5px 0">${fmtAny(x,depth+1)}</div>`).join("")}
 if(typeof d==="object"){return Object.keys(d).map(k=>{const v=d[k];
  if(v!==null&&typeof v==="object")return depth>2?kv(k,JSON.stringify(v).slice(0,300)):sec(k,fmtAny(v,depth+1));
  if(typeof v==="string"&&/^https?:\/\//.test(v))return `<div class="kv"><b>${esc(k)}</b><span>${lnk(v)}</span></div>`;
  return kv(k,typeof v==="boolean"?(v?"да":"нет"):v)}).join("")}
 return esc(d)}
const SEVC={"критический":"c","высокий":"h","средний":"m","инфо":"i"};
function fmtTool(id,d,body){
 if(id==="attribution")return attribView(d);
 if(id==="exposure")return exposureView(d);
 if(id==="pattern")return patternView(d);
 if(id==="magic")return magicView(d);
 if(id==="img_forensics")return forensicsView(d);
 if(id==="email_headers")return mailView(d);
 if(id==="ransomware")return ransomView(d);
 if(id==="phishing")return phishView(d);
 if(id==="ip_radar")return radarView(d,true);
 if(id==="leaks")return leaksView(d);
 if(id==="capture")return (d.files||[]).map(f=>f.data_b64?`<img src="data:image/png;base64,${f.data_b64}" style="width:100%;border-radius:10px;border:1px solid var(--bd);margin:6px 0">`:kv(f.kind.toUpperCase(),(f.size/1024).toFixed(1)+" KB · sha256 "+f.sha256.slice(0,20)+"…")).join("")+'<div class="pmsg">Чтобы сохранить скриншот как доказательство, архивируйте страницу в кейс — снимок экрана сделается автоматически.</div>';
 if(id==="import_file"){let h=kv("Файл",d.file)+kv("Формат",d.format)+kv("SHA-256",d.sha256);
  if(d.found)h+=sec("Найдено профилей: "+d.found.length,d.found.slice(0,200).map(x=>`<div class="kv"><b>${esc(x.site||"")}</b><span>${lnk(x.url)}</span></div>`).join(""));
  if(d.types)h+=sec("Событий: "+d.events,Object.entries(d.types).map(([k,v])=>`<span class="tag">${esc(k)} ×${v}</span>`).join(""));
  if(d.iocs)h+=Object.entries(d.iocs).map(([k,v])=>sec(k.toUpperCase()+" ("+v.length+")",tags(v))).join("");
  return h+'<div class="pmsg">Нажмите «В кейс» — находки станут сущностями графа, а сам файл будет учтён по SHA-256.</div>'}
 if(id==="tsa")return kv("Объект",d.name)+kv("SHA-256",d.sha256)+`<div class="kv"><b>Время метки</b><span style="font-weight:800;color:var(--ok)">${esc(d.gen_time)}</span></div>`+kv("Служба (TSA)",d.tsa)+kv("Серийный номер",d.serial)+`<div class="pmsg">${esc(d.note)}</div>`;
 if(id==="harvester")return kv("Источники",(d.sources||[]).join(", "))+(Object.keys(d.errors||{}).length?kv("Недоступны",Object.keys(d.errors).join(", ")):"")+
  kv("Хостов",`${d.hosts_total} (отвечают: ${d.hosts_alive})`)+sec("Email ("+(d.emails||[]).length+")",tags(d.emails))+
  sec("Хосты и IP",tbl(["Хост","IP"],(d.hosts||[]).slice(0,300).map(h=>[esc(h.host),h.ips.length?esc(h.ips.join(", ")):'<span class="notfound">не резолвится</span>'])))+
  sec("Самые частые IP",tags((d.top_ips||[]).map(x=>x.ip+" ×"+x.hosts)));
 if(id==="lookalikes")return kv("Сгенерировано",d.generated)+kv("Проверено",d.checked)+`<div class="kv"><b>Зарегистрировано</b><span style="font-weight:700;color:${d.registered?"var(--warn)":"var(--ok)"}">${d.registered}</span></div>`+
  kv("По методам",Object.entries(d.by_method||{}).map(([k,v])=>k+": "+v).join(" · "))+
  sec("Найденные домены",tbl(["Домен","Метод","IP"],(d.results||[]).map(r=>[esc(r.domain)+(r.domain!==r.ascii?`<br><small class="mu">${esc(r.ascii)}</small>`:""),esc(r.method),esc(r.ips.slice(0,3).join(", "))+(r.same_ip_as_original?' <span class="chip ok">как у оригинала</span>':"")])))+
  `<div class="pmsg">${esc(d.note)}</div>`;
 if(id==="crawl")return kv("Страниц",d.pages_crawled)+sec("Email",tags(d.emails))+sec("Телефоны",tags(d.phones))+
  sec("Документы и файлы",(d.files||[]).slice(0,60).map(u=>`<div>${lnk(u)}</div>`).join("")||"—")+
  sec("Формы",tbl(["Страница","action","method"],(d.forms||[]).slice(0,30).map(f=>[esc(f.page),esc(f.action),esc(f.method)])))+
  sec("Параметры URL",tags(d.params))+sec("Комментарии в HTML",(d.comments||[]).map(c=>`<div class="pmsg">${esc(c.text)}</div>`).join("")||"—")+
  sec("JS-файлы",tags((d.scripts||[]).slice(0,60)))+sec("Внешние домены",tags((d.external_domains||[]).map(x=>x.domain+" ×"+x.links)))+
  sec("Страницы",tbl(["URL","Статус","Заголовок"],(d.pages||[]).map(p=>[esc(p.url),esc(p.status),esc(p.title||"")])));
 if(id==="wayback_urls")return kv("URL в архиве",d.total)+kv("Первый снимок",d.first_seen)+kv("Последний",d.last_seen)+
  Object.entries(d.groups||{}).map(([k,v])=>sec(k+" ("+v.length+")",v.slice(0,80).map(u=>`<div style="font-size:11.5px">${lnk("https://web.archive.org/web/2/"+u,u)}</div>`).join(""))).join("")+
  sec("Параметры",tags((d.params||[]).map(p=>p.param+" ×"+p.count)))+sec("Хосты",tags((d.hosts||[]).map(h=>h.host+" ×"+h.urls)));
 if(id==="secrets"){let h=kv("Проверено файлов",d.files_scanned)+`<div class="kv"><b>Находок</b><span style="font-weight:700;color:${d.count?"var(--bad)":"var(--ok)"}">${d.count?d.count:"✓ не найдено"}</span></div>`;
  if(d.count)h+=tbl(["Уровень","Тип","Значение","Где"],d.findings.map(f=>[`<span class="sev ${SEVC[f.severity]||"i"}">${esc(f.severity)}</span>`,esc(f.type),`<code>${esc(f.value)}</code>`,esc(String(f.where).slice(-60))+":"+f.line]));
  return h+`<div class="pmsg">${esc(d.note)}</div>`}
 if(id==="file_meta"){let h=kv("Файл",d.name)+kv("Тип",d.type)+kv("Размер",(d.size/1024).toFixed(1)+" KB")+kv("SHA-256",d.sha256)+kv("MD5",d.md5);
  if(d.gps)h+=`<div class="kv"><b style="color:var(--bad)">📍 GPS</b><span>${d.gps.lat}, ${d.gps.lon} — ${lnk(d.gps.osm,"OpenStreetMap")} · ${lnk(d.gps.google,"Google Maps")}</span></div>`;
  if((d.sensitive_fields||[]).length)h+=`<div class="kv"><b style="color:var(--warn)">Чувствительное</b><span>${esc(d.sensitive_fields.join(", "))}</span></div>`;
  const m=d.metadata||{};h+=sec("Метаданные ("+Object.keys(m).length+")",Object.keys(m).length?Object.keys(m).map(k=>kv(k,Array.isArray(m[k])?m[k].join(", "):m[k])).join(""):'<span class="mu">метаданных нет — файл чистый</span>');
  return h+`<div class="pmsg">${esc(d.note)}</div>`}
 if(id==="internetdb")return (d.results||[]).map(r=>sec(r.ip,kv("Порты",(r.ports||[]).join(", ")||r.note)+kv("Хосты",(r.hostnames||[]).slice(0,15).join(", "))+
  kv("ПО (CPE)",(r.cpes||[]).join(", "))+kv("Метки",(r.tags||[]).join(", "))+`<div class="kv"><b>Уязвимости</b><span>${(r.vulns||[]).length?(r.vulns||[]).slice(0,60).map(v=>`<span class="tag miss">${esc(v)}</span>`).join(""):'<span class="found">не найдено</span>'}</span></div>`)).join("")+
  sec("Shodan",(d.shodan_links||[]).map(u=>lnk(u)).join("<br>"));
 if(id==="reputation"){const c=d.risk_score>=60?"var(--bad)":d.risk_score>=25?"var(--warn)":"var(--ok)";
  let h=`<div style="display:flex;gap:12px;align-items:center;margin-bottom:8px"><div class="grade" style="background:${c}22;color:${c};border:1px solid ${c}55;width:56px">${d.risk_score}</div><div><b style="color:${c}">${esc(d.verdict)}</b><br><span class="mu" style="font-size:11px">${esc(d.type)}: ${esc(d.ioc)}</span></div></div>`;
  const s=d.sources||{},o=s["AlienVault OTX"];
  if(o)h+=sec("AlienVault OTX",kv("Упоминаний в отчётах (pulses)",o.pulses)+kv("В белом списке",o.whitelisted?"да":"нет")+(o.pulse_names&&o.pulse_names.length?kv("Отчёты",o.pulse_names.join(" · ")):"")+(o.link?`<div class="kv"><b>Ссылка</b><span>${lnk(o.link,"открыть")}</span></div>`:""));
  const u=s["urlscan.io"];if(u&&!u.skipped)h+=sec("urlscan.io — сканов: "+u.total,(u.recent||[]).map(r=>`<div style="font-size:11.5px">${esc((r.time||"").slice(0,10))} · ${esc(r.url||"")} ${r.result?lnk(r.result,"↗"):""}</div>`).join(""));
  const b=s["DNSBL"];if(b&&b.lists)h+=sec("Спам-листы (DNSBL) "+b.ip,Object.entries(b.lists).map(([k,v])=>kv(k,v)).join(""));
  const p=s["VirusTotal / AbuseIPDB"];if(p)h+=sec("VirusTotal / AbuseIPDB",fmtAny(p));
  const i=s["Shodan InternetDB"];if(Array.isArray(i))h+=sec("Shodan InternetDB",i.map(r=>kv(r.ip,"порты: "+(r.ports||[]).join(", ")+((r.vulns||[]).length?" · CVE: "+r.vulns.length:""))).join(""));
  if(Object.keys(d.errors||{}).length)h+=`<div class="pmsg">Недоступны: ${esc(Object.keys(d.errors).join(", "))}</div>`;return h}
 if(id==="asn"){if(d.search)return tbl(["Тип","Значение","Описание"],d.search.map(x=>[esc(x.category),esc(x.value),esc(x.description||"")]))+'<div class="pmsg">Запустите инструмент снова с нужным ASN (например AS13335)</div>';
  return kv("ASN",d.asn)+kv("Владелец",d.holder)+(d.prefix?kv("Сеть IP",d.prefix):"")+kv("Сетей анонсировано",d.prefix_count)+kv("IPv4-адресов",(d.ipv4_addresses||0).toLocaleString("ru"))+
  sec("IPv4-сети",tags((d.prefixes_v4||[]).slice(0,150)))+((d.prefixes_v6||[]).length?sec("IPv6-сети",tags(d.prefixes_v6.slice(0,40))):"")+sec("Ссылки",links(d.links))}
 if(id==="github")return `<div style="display:flex;gap:12px;align-items:center;margin-bottom:8px">${d.avatar?`<img src="${esc(d.avatar)}" style="width:54px;height:54px;border-radius:14px">`:""}<div><b>${esc(d.name||d.login)}</b><br>${lnk(d.profile)}</div></div>`+
  kv("Компания",d.company)+kv("Локация",d.location)+kv("Сайт",d.blog)+kv("Публичный email",d.email_public)+kv("Twitter",d.twitter)+kv("Создан",d.created_at)+kv("Подписчики",d.followers)+kv("Репозиториев",d.public_repos)+
  kv("Организации",(d.orgs||[]).join(", "))+kv("Языки",Object.entries(d.languages||{}).map(([k,v])=>k+" "+v).join(", "))+kv("SSH-ключей",d.ssh_keys&&d.ssh_keys.count)+
  sec("Email из коммитов",tbl(["Email","Коммитов",""],(d.commit_emails||[]).map(e=>[esc(e.email),e.commits,e.noreply?'<span class="mu">noreply</span>':'<span class="found">реальный</span>'])))+
  sec("Имена в коммитах",tags(d.commit_names))+sec("Репозитории",tbl(["Имя","★","Обновлён"],(d.repos||[]).slice(0,25).map(r=>[lnk(r.url,r.name)+(r.fork?' <span class="mu">fork</span>':""),r.stars,esc((r.pushed_at||"").slice(0,10))])));
 if(id==="telegram")return kv("Канал",d.title)+`<div class="kv"><b>Ссылка</b><span>${lnk(d.url)}</span></div>`+kv("Описание",d.description)+kv("Счётчики",Object.entries(d.counters||{}).map(([k,v])=>v+" "+k).join(" · "))+
  sec("Упоминания",tags((d.top_mentions||[]).map(m=>"@"+m.username+" ×"+m.count)))+sec("Домены в ссылках",tags((d.top_domains||[]).map(m=>m.domain+" ×"+m.count)))+
  sec("Последние посты",(d.posts||[]).map(p=>`<div style="border-left:2px solid var(--bd2);padding-left:9px;margin:7px 0"><div class="pmsg">${esc((p.date||"").replace("T"," ").slice(0,16))} · 👁 ${esc(p.views||"—")} · ${esc(p.id||"")}</div>${esc(p.text)}</div>`).join("")||'<span class="mu">постов нет (закрытый канал или пользователь)</span>');
 if(id==="ioc"){if(d.result!=null)return `<pre>${esc(d.result)}</pre>`;
  return kv("Всего",d.total)+Object.entries(d.iocs||{}).map(([k,v])=>sec(k.toUpperCase()+" ("+v.length+")",tags(v))).join("")}
 if(id==="cve")return kv("Найдено",d.total)+(d.results||[]).map(c=>{const col=c.score>=9?"var(--bad)":c.score>=7?"#fb923c":c.score>=4?"var(--warn)":"var(--ok)";
  return `<div class="card" style="padding:11px;margin:8px 0"><div class="row"><b>${lnk(c.nvd,c.id)}</b><span style="color:${col};font-weight:800">${c.score??"—"} ${esc(c.severity||"")}</span>
  ${c.kev?'<span class="sev c">эксплуатируется (CISA KEV)</span>':""}${c.epss!=null?`<span class="tag">EPSS ${c.epss}%</span>`:""}<span class="pmsg" style="margin-left:auto">${esc((c.published||"").slice(0,10))}</span></div>
  <div style="font-size:12px;margin-top:5px">${esc(c.description)}</div>${c.cwe.length?`<div class="pmsg">${esc(c.cwe.join(", "))}</div>`:""}</div>`}).join("");
 if(id==="crypto")return kv("Сеть",d.chain)+kv("Адрес",d.address)+(d.chain==="Bitcoin"?kv("Баланс",d.balance_btc+" BTC")+kv("Получено",d.received_btc+" BTC")+kv("Отправлено",d.sent_btc+" BTC"):
  kv("Баланс",d.balance_eth+" ETH")+kv("Контракт",d.is_contract?"да":"нет")+kv("Имя / ENS",[d.name,d.ens].filter(Boolean).join(" · "))+kv("Переводов токенов",d.token_transfers))+kv("Транзакций",d.transactions)+
  (d.recent&&d.recent.length?sec("Последние транзакции",tbl(["Время","BTC","txid"],d.recent.map(t=>[esc(t.time),`<span style="color:${t.btc<0?"var(--bad)":"var(--ok)"}">${t.btc}</span>`,`<code>${esc(t.txid.slice(0,20))}…</code>`]))):"")+sec("Обозреватели",links(d.explorers));
 if(id==="reverse_image")return links(d.links)+`<div class="pmsg">${esc(d.note)}</div>`;
 if(id==="mac")return kv("MAC",d.mac)+kv("Производитель",d.vendor)+kv("Случайный (локальный)",d.locally_administered?"да":"нет")+kv("Multicast",d.multicast?"да":"нет")+(d.note?`<div class="pmsg">${esc(d.note)}</div>`:"");
 if(id==="tracking"){let h="";if((d.shared||[]).length)h+=sec("🔗 Общие ID — признак одного владельца",tbl(["Тип","ID","Сайты"],d.shared.map(s=>[esc(s.kind),`<code>${esc(s.id)}</code>`,esc(s.sites.join(", "))])));
  h+=(d.sites||[]).map(s=>sec(s.url,s.error?`<span style="color:var(--bad)">${esc(s.error)}</span>`:(Object.keys(s.ids).length?Object.entries(s.ids).map(([k,v])=>kv(k,v.join(", "))).join(""):'<span class="mu">ID счётчиков не найдено</span>')+kv("Favicon mmh3",s.favicon_mmh3))).join("");
  h+=sec("Найти другие сайты с этими ID",tbl(["Тип","ID","Поиск"],(d.pivots||[]).map(p=>[esc(p.kind),`<code>${esc(p.id)}</code>`,Object.entries(p.links).map(([k,u])=>lnk(u,k)).join(" · ")])));
  return h+`<div class="pmsg">${esc(d.note)}</div>`}
 if(id==="domain_history")return kv("Домен",d.domain)+`<div class="kv"><b>Возраст</b><span style="font-weight:700;color:${d.age_years!=null&&d.age_years<1?"var(--bad)":"var(--ok)"}">${d.age_years!=null?d.age_years+" лет":"—"}</span></div>`+
  sec("Хронология",(d.timeline||[]).map(e=>`<div class="kv"><b style="font-family:Consolas,monospace">${esc(e.date.slice(0,16))}</b><span>${esc(e.event)} <span class="mu">· ${esc(e.source)}</span></span></div>`).join("")||"—")+
  (d.certificates?kv("Сертификатов в CT",d.certificates.total)+kv("Издатели",Object.entries(d.certificates.issuers||{}).map(([k,v])=>k+" ×"+v).join(" · ")):"")+
  kv("DNS сейчас",Object.entries(d.dns_now||{}).map(([k,v])=>k+": "+v.slice(0,3).join(", ")).join(" | "))+`<div class="pmsg">${esc(d.note)}</div>`;
 if(id==="evidence_verify"){const ok=d.verdict==="целостность подтверждена";
  return `<div class="kv"><b>Вердикт</b><span style="font-weight:800;color:${ok?"var(--ok)":"var(--bad)"}">${ok?"✓ ":"⚠ "}${esc(d.verdict)}</span></div>`+kv("Кейс",d.case)+kv("Создан",d.created)+kv("Программа",d.app)+
  kv("Файлов совпало",d.files_ok)+kv("Изменены",(d.files_bad||[]).join(", ")||"нет")+kv("Отсутствуют",(d.files_missing||[]).join(", ")||"нет")+kv("Записей аудита",d.audit_records)+kv("Цепочка аудита",d.audit_chain_ok?"цела":"НАРУШЕНА")+kv("SHA-256 манифеста",d.manifest_sha256)}
 if(id==="dns"){const r=d.records||{};const keys=Object.keys(r);
  return keys.length?keys.map(k=>kv(k,r[k].join(" · "))).join(""):'<span class="mu">Записей не найдено</span>';}
 if(id==="reverse_dns")return kv("IP",d.ip)+kv("PTR",d.ptr||"нет записи");
 if(id==="ip_info")return kv("IP",d.ip)+kv("Страна",d.country)+kv("Город",`${d.city||""} ${d.region||""}`)+kv("Провайдер",d.isp)+kv("Организация",d.org)+kv("ASN",d.asn)+kv("Координаты",d.lat!=null?d.lat+", "+d.lon:"")+kv("Таймзона",d.timezone);
 if(id==="whois"){const f=d.fields||{};let h=kv("WHOIS-сервер",d.server);
  for(const k in f)h+=kv(k,f[k].join(" · "));return h||'<pre>'+esc((d.raw||"").slice(0,1500))+'</pre>';}
 if(id==="ssl"){const dl=d.days_left;const col=dl==null?"var(--mu)":dl<0?"var(--bad)":dl<21?"var(--warn)":"var(--ok)";
  return kv("CN",d.subject_cn)+kv("Издатель",d.issuer)+kv("Действует до",d.valid_to)+
  `<div class="kv"><b>Осталось дней</b><span style="color:${col};font-weight:700">${dl==null?"—":dl}</span></div>`+
  kv("TLS",d.tls_version)+kv("Шифр",d.cipher)+kv("SAN ("+(d.san||[]).length+")",(d.san||[]).slice(0,14).join(" · "));}
 if(id==="headers"){const gc=d.grade==="A"?"#34d399":d.grade==="B"?"#a3e635":d.grade==="C"?"#fbbf24":d.grade==="D"?"#fb923c":"#fb7185";
  let h=`<div style="display:flex;gap:12px;align-items:center;margin-bottom:10px"><div class="grade" style="background:${gc}22;color:${gc};border:1px solid ${gc}55">${d.grade}</div>
   <div><b>${d.score}%</b> security-заголовков<br><span class="mu" style="font-size:11px">${esc(d.server||"")}</span></div></div>`;
  h+='<div style="margin-bottom:6px">'+Object.keys(d.present).map(k=>`<span class="tag good">✓ ${esc(k)}</span>`).join("")+'</div>';
  h+='<div>'+Object.keys(d.missing).map(k=>`<span class="tag miss">✗ ${esc(k)}</span>`).join("")+'</div>';
  return h;}
 if(id==="subdomains"){const s=d.subdomains||[];return kv("Найдено",d.count)+kv("Источники",(d.sources||[]).join(", "))+(Object.keys(d.errors||{}).length?kv("Недоступны",Object.keys(d.errors).join(", ")):"")+'<div style="margin-top:8px">'+(s.length?s.slice(0,200).map(x=>`<span class="tag">${esc(x)}</span>`).join(""):'<span class="mu">нет</span>')+'</div>';}
 if(id==="wayback")return kv("В архиве",d.available?"да":"нет")+kv("Снимок",d.closest?'<a class="url" target="_blank" href="'+esc(d.closest)+'">открыть</a>':"—")+kv("Дата",d.timestamp);
 if(id==="username"){const f=d.found||[];let h=`<div style="margin-bottom:8px"><span class="found">Найдено: ${f.length}</span> <span class="mu">из ${d.checked} платформ</span></div>`;
  h+=f.map(x=>`<div class="kv"><b class="found">${esc(x.site)}</b><span><a class="url" target="_blank" href="${esc(x.url)}">${esc(x.url)}</a></span></div>`).join("");
  if((d.unreliable||[]).length)h+=`<div class="pmsg" style="margin-top:8px">⚠ Недостоверно (сайт «находит» и случайный ник): ${esc(d.unreliable.map(x=>x.site).join(", "))}</div>`;
  const ab=(d.absent||[]).length;h+=`<div class="pmsg" style="margin-top:8px">Не найдено на ${ab} сайтах · без ответа: ${(d.errors||[]).length} · ник не подходит по правилам: ${d.skipped||0}</div>`;
  if(d.note)h+=`<div class="pmsg">${esc(d.note)}</div>`;
  return h;}
 if(id==="email")return kv("Email",d.email)+kv("Синтаксис",d.valid_syntax?"✓ корректен":"✗ ошибка")+(d.valid_syntax?kv("Домен",d.domain)+kv("MX (почта)",d.has_mx?"✓ "+(d.mx||[]).slice(0,3).join(", "):"✗ нет")+kv("Gravatar",d.gravatar?'✓ есть — '+'<a class="url" target="_blank" href="'+esc(d.gravatar_url)+'">фото</a>':"нет"):"");
 if(id==="phone")return kv("Ввод",d.input)+kv("Страна",d.country||"неизвестно")+kv("Код страны",d.country_code?"+"+d.country_code:"—")+kv("E.164",d.e164)+kv("Нац. номер",d.national)+kv("Валиден",d.valid?"✓ да":"✗ нет");
 if(id==="pwned"){const c=d.breached?"var(--bad)":"var(--ok)";
  return `<div class="kv"><b>Статус</b><span style="color:${c};font-weight:700">${d.breached?"⚠ найден в утечках":"✓ не найден"}</span></div>`+
  (d.breached?kv("Встречался раз",d.count.toLocaleString("ru")):"")+`<div class="mu" style="margin-top:6px;font-size:11px">${esc(d.advice)}</div>`;}
 if(id==="strength"){const map={"очень слабый":"#fb7185","слабый":"#fb923c","средний":"#fbbf24","сильный":"#a3e635","очень сильный":"#34d399"};const c=map[d.verdict]||"#fbbf24";
  return `<div class="kv"><b>Вердикт</b><span style="color:${c};font-weight:700">${esc(d.verdict)}</span></div>`+
  kv("Длина",d.length)+kv("Энтропия",d.entropy_bits+" бит")+kv("Алфавит",d.charset_size+" симв.")+kv("Подбор (offline)",d.crack_time_offline)+
  (d.notes&&d.notes.length?`<div class="mu" style="margin-top:6px;font-size:11px;color:var(--bad)">⚠ ${esc(d.notes.join("; "))}</div>`:"");}
 if(id==="hash"){const hh=d.hashes;return Object.keys(hh).map(k=>`<div class="kv"><b>${k.toUpperCase()}</b><span class="sha" style="font-family:monospace;font-size:11px;cursor:pointer" onclick="navigator.clipboard&&navigator.clipboard.writeText('${hh[k]}')">${esc(hh[k])}</span></div>`).join("");}
 if(id==="hash_id")return kv("Длина",d.length)+kv("Вероятный тип",(d.possible||[]).join(" / "));
 if(id==="transform")return `<pre>${esc(d.result)}</pre>`;
 // ----- разведка сайта -----
 if(id==="site_recon"){const tech=(d.technologies||[]).map(x=>`<span class="tag good">${esc(x)}</span>`).join("")||'<span class="mu">—</span>';
  const socn=(d.socials||[]).map(x=>`<span class="tag">${esc(x)}</span>`).join("")||"—";
  const em=(d.emails||[]).map(x=>`<span class="tag">${esc(x)}</span>`).join("")||'<span class="mu">не найдено</span>';
  const ed=(d.external_domains||[]).slice(0,40).map(x=>`<span class="tag">${esc(x)}</span>`).join("");
  let h=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 18px">`;
  h+=kv("Хост",d.host)+kv("Статус",d.status)+kv("Заголовок",d.title)+kv("Язык",d.language)+
     kv("Сервер",d.server)+kv("Powered-by",d.powered_by)+kv("Размер",d.page_size_kb+" KB")+
     kv("Ссылки",`${d.links_internal} внутр. / ${d.links_external} внеш.`)+
     kv("Формы",d.forms+(d.has_login_form?" (есть форма входа)":""))+
     kv("Sec-заголовки",`${(d.security_headers||[]).length}/${d.security_headers_total}`)+`</div>`;
  if(d.description)h+=kv("Описание",d.description);
  if(d.generator)h+=kv("Generator",d.generator);
  if(d.canonical)h+=kv("Canonical",d.canonical);
  h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Технологии</b><div style="margin-top:5px">${tech}</div></div>`;
  h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Соцсети</b><div style="margin-top:5px">${socn}</div></div>`;
  h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Email на странице</b><div style="margin-top:5px">${em}</div></div>`;
  if(ed)h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Внешние домены</b><div style="margin-top:5px">${ed}</div></div>`;
  return h;}
 if(id==="tech")return kv("URL",d.final)+kv("Сервер",d.server)+kv("Powered-by",d.powered_by)+
  `<div style="margin-top:6px">${(d.technologies||[]).map(x=>`<span class="tag good">${esc(x)}</span>`).join("")||'<span class="mu">не определено</span>'}</div>`;
 if(id==="robots"){let h=kv("robots.txt",d.robots_found?"✓ есть":"нет")+kv("User-agent блоков",d.user_agents)+kv("Sitemap",(d.sitemaps||[]).join(" "))+kv("URL в sitemap",d.sitemap_urls_count);
  if((d.disallow||[]).length)h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Disallow</b><div style="margin-top:5px">${d.disallow.slice(0,60).map(x=>`<span class="tag miss">${esc(x)}</span>`).join("")}</div></div>`;
  if((d.sitemap_urls||[]).length)h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">URL из карты</b><div style="margin-top:5px;max-height:160px;overflow:auto">${d.sitemap_urls.slice(0,120).map(x=>`<div style="font-size:11px;color:var(--mu)">${esc(x)}</div>`).join("")}</div></div>`;
  return h;}
 if(id==="redirects"){let h=kv("Переходов",d.count)+kv("Конечный URL",d.final);
  h+=`<div style="margin-top:8px">`+(d.hops||[]).map((x,i)=>`<div class="kv"><b>${i+1}. ${x.status}</b><span>${esc(x.url)}</span></div>`).join("")+`</div>`;return h;}
 if(id==="favicon")return kv("Favicon",d.favicon_url?'<a class="url" target="_blank" href="'+esc(d.favicon_url)+'">открыть</a>':"—")+
  `<div class="kv"><b>mmh3 (Shodan)</b><span style="font-weight:700;color:var(--ac2)">${esc(d.mmh3)}</span></div>`+
  kv("MD5",d.md5)+kv("Размер",d.bytes+" байт")+
  kv("Shodan-поиск",'<a class="url" target="_blank" href="'+esc(d.shodan_url)+'">'+esc(d.shodan)+'</a>');
 if(id==="email_sec"){const b=v=>v?'<span style="color:var(--ok)">✓</span>':'<span style="color:var(--bad)">✗</span>';
  return `<div class="kv"><b>Постура</b><span style="font-weight:700">${esc(d.posture_score)}</span></div>`+
  `<div class="kv"><b>SPF</b><span>${b(d.spf)} ${d.spf?esc(d.spf.slice(0,80)):"нет"}</span></div>`+
  `<div class="kv"><b>DMARC</b><span>${b(d.dmarc)} ${d.dmarc?esc(d.dmarc.slice(0,80)):"нет"}</span></div>`+
  `<div class="kv"><b>DKIM</b><span>${b((d.dkim_selectors||[]).length)} ${(d.dkim_selectors||[]).join(", ")||"не найдены частые селекторы"}</span></div>`+
  `<div class="kv"><b>MX</b><span>${b(d.has_mx)} ${(d.mx||[]).slice(0,3).join(", ")}</span></div>`;}
 if(id==="security_txt")return d.found?kv("Найден",'✓ '+esc(d.url))+Object.keys(d.fields||{}).map(k=>kv(k,(d.fields[k]||[]).join(", "))).join(""):kv("security.txt","не найден");
 if(id==="rdap"){const ev=d.events||{};let h=kv("Тип",d.type)+kv("Имя/диапазон",d.name)+kv("Handle",d.handle)+kv("Страна",d.country)+kv("Статусы",(d.status||[]).join(", "));
  if(d.start)h+=kv("Диапазон",d.start+" – "+d.end);
  for(const k in ev)h+=kv(k,ev[k]);
  if((d.entities||[]).length)h+=kv("Контакты",(d.entities||[]).join("; "));return h;}
 if(id==="reverse_ip"){if(d.error)return `<span style="color:var(--bad)">${esc(d.error)}</span>`;
  return kv("Домены на IP",d.count)+`<div style="margin-top:6px;max-height:200px;overflow:auto">${(d.domains||[]).map(x=>`<span class="tag">${esc(x)}</span>`).join("")}</div>`;}
 // ----- утилиты -----
 if(id==="jwt"){let h=kv("Алгоритм",d.alg)+kv("Тип",d.typ)+kv("Подпись",d.signature_present?"есть":"нет");
  if(d.expiry)h+=`<div class="kv"><b>Срок</b><span style="color:${d.expiry.expired?"var(--bad)":"var(--ok)"}">${d.expiry.expired?"истёк":"действует"} — ${esc(d.expiry.expires)}</span></div>`;
  h+=`<div style="margin-top:6px"><b style="color:var(--ac2)">Payload</b><pre>${esc(JSON.stringify(d.payload,null,2))}</pre></div>`;return h;}
 if(id==="cidr")return kv("Сеть",d.network)+kv("Broadcast",d.broadcast)+kv("Маска",d.netmask+" (/"+d.prefix+")")+kv("Всего адресов",d.total_addresses.toLocaleString("ru"))+kv("Хостов",d.usable_hosts.toLocaleString("ru"))+kv("Диапазон",d.first+" – "+d.last)+kv("Приватная",d.is_private?"да":"нет");
 if(id==="timestamp")return kv("Unix",d.unix)+kv("Unix (мс)",d.unix_ms)+kv("ISO UTC",d.iso_utc)+kv("RFC",d.rfc)+kv("День недели",d.weekday);
 if(id==="uuid")return d.generated?kv("UUID v4",'<span class="sha" style="cursor:pointer" onclick="navigator.clipboard&&navigator.clipboard.writeText(\''+d.generated+'\')">'+esc(d.generated)+'</span>'):kv("UUID",d.uuid)+kv("Версия",d.version)+kv("Вариант",d.variant)+(d.timestamp?kv("Время (v1)",d.timestamp):"");
 if(id==="idn")return kv("Punycode (ASCII)",d.ascii_punycode)+kv("Unicode",d.unicode)+kv("Алфавиты",(d.scripts||[]).join(", "))+(d.homograph_warning?`<div style="margin-top:6px;color:var(--bad);font-size:12px">⚠ Смешанные алфавиты — возможна фишинг-подмена (гомоглифы)</div>`:"");
 if(id==="entropy")return kv("Энтропия",d.entropy+" бит/символ")+kv("Всего",d.bits_total+" бит")+kv("Длина",d.length)+kv("Уникальных",d.unique_chars)+(d.looks_like_secret?`<div style="margin-top:6px;color:var(--warn);font-size:12px">⚠ Похоже на ключ/токен/секрет</div>`:"");
 if(id==="luhn")return `<div class="kv"><b>Результат</b><span style="font-weight:700;color:${d.valid?"var(--ok)":"var(--bad)"}">${d.valid?"✓ валиден":"✗ невалиден"}</span></div>`+kv("Цифр",d.digits);
 if(id==="base")return kv("DEC",d.decimal)+kv("HEX",d.hex)+kv("OCT",d.octal)+kv("BIN",d.binary)+kv("Бит",d.bit_length);
 if(id==="dork"){const L=d.links||{};return Object.keys(L).map(k=>`<div class="kv"><b>${esc(k)}</b><span><a class="url" target="_blank" href="${esc(L[k])}">открыть поиск ↗</a></span></div>`).join("");}
 return fmtAny(d)}

/* ---------- верхние действия ---------- */
async function addUrls(){const list=$("#url").value.split(/[\s,]+/).filter(Boolean);if(!list.length)return;
 if(!cur)return toast("Сначала создайте кейс","bad");const b=$("#add");b.classList.add("loading");let n=0;
 for(const u of list){try{const r=await api("add",{case:cur.id,url:u});n++;toast(n+"/"+list.length+": "+r.status,r.status.startsWith("OK")?"ok":"bad")}catch(e){toast(e.message,"bad")}await refresh()}
 b.classList.remove("loading");$("#url").value=""}
$("#add").onclick=addUrls;$("#url").onkeydown=e=>{if(e.key==="Enter")addUrls()};
$("#ver").onclick=async()=>{if(!cur)return;await refresh();const i=st.integrity;
 toast("Снимки: "+i.snap_ok+" целы, "+i.snap_bad+" нарушены. Журнал: "+(i.chain?"цел":"НАРУШЕН"),i.snap_bad||!i.chain?"bad":"ok")};
function viewer(u,title){modal(esc(title||"Просмотр"),`<iframe src="${esc(u)}" style="width:100%;height:72vh;border:0;border-radius:12px;background:#fff"></iframe>`)}
function saveIOS(kind,id){return api("export_save",{kind,case:id}).then(r=>toast("Сохранено: «Файлы» → На iPhone → Provenio → "+r.name,"ok")).catch(x=>toast(x.message,"bad"))}
if(IOS){
 document.addEventListener("click",e=>{const a=e.target.closest("a[target=_blank]");if(!a)return;e.preventDefault();e.stopPropagation();
  const h=a.getAttribute("href")||"";if(/^https?:/i.test(h))api("open_url",{url:h}).catch(x=>toast(x.message,"bad"));else viewer(h)},true);
 window.open=u=>{if(/^https?:/i.test(u))api("open_url",{url:u});else viewer(u);return null};
}
function dl(kind){if(!cur)return;
 if(IOS){if(kind==="report")viewer(`/download/report?case=${cur.id}&t=${T}`,"Отчёт");else saveIOS(kind,cur.id);setTimeout(refresh,800);return}const a=document.createElement("a");a.href=`/download/${kind}?case=${cur.id}&t=${T}`;
 if(kind==="report")a.target="_blank";else a.download="";document.body.append(a);a.click();a.remove();setTimeout(refresh,800)}
$("#rep").onclick=e=>{e.stopPropagation();if(!cur)return toast("Сначала выберите кейс","bad");const r=e.target.getBoundingClientRect();
 showMenu(r.left,r.bottom+6,[["Экспорт кейса",null],["📄 Отчёт HTML (откроется в браузере)",()=>dl("report")],["🧾 Пакет доказательств ZIP",()=>dl("evidence")],["🔐 Проверяемый отчёт HTML (сам себя проверяет)",()=>dl("verify")],["⛓ Якоря в блокчейне…",openAnchors],
  ["{ } Весь кейс JSON",()=>dl("json")],["📊 Сущности CSV (Excel)",()=>dl("csv")],["Граф связей",null],
  ["🕸 GEXF — для Gephi",()=>dl("gexf")],["🕸 GraphML — yEd, Gephi, Cytoscape",()=>dl("graphml")],["🕸 Таблица связей CSV — Maltego",()=>dl("edges")],
  ["🖼 Картинка графа PNG",exportPng]])};
$("#cmp").onclick=openCompare;
$("#ddir").onclick=async()=>{const i=await api("info");try{await api("open_data_dir",{})}catch(x){}toast("Данные: "+i.data_dir,"ok")};
$("#set").onclick=openSettings;
const KEYN={shodan:"Shodan",virustotal:"VirusTotal",abuseipdb:"AbuseIPDB",urlscan:"urlscan.io",otx:"AlienVault OTX",github:"GitHub token",anthropic:"Claude API (Anthropic)"};
const chk=(id,on,t)=>`<label class="gl" style="color:var(--tx)"><input type="checkbox" id="${id}" ${on?"checked":""}> ${t}</label>`;
async function openSettings(){const s=await api("settings"),i=await api("info");
 const b=modal("Настройки",`<div class="hint" style="margin-bottom:10px">Все ключи необязательны: без них работают бесплатные источники. Ключи хранятся только на этом компьютере,
  зашифрованные средствами Windows (DPAPI) — их может расшифровать только ваша учётная запись. Здесь видны только последние 4 символа,
  а из ошибок, отчётов и сохранённых результатов ключи вырезаются. Платные сервисы вы оплачиваете им напрямую — Provenio ничего не берёт.</div>
  <div class="frow"><label>Прокси (HTTP/HTTPS)</label><input id="sproxy" placeholder="http://127.0.0.1:8080" value="${esc(s.proxy)}"></div>
  <div class="frow"><label>Таймаут запросов, с</label><input id="stime" type="number" min="5" max="120" value="${esc(s.timeout)}"></div>
  ${Object.keys(KEYN).map(k=>`<div class="frow"><label>${KEYN[k]}</label><input data-k="${k}" class="skey" placeholder="не задан" value="${esc(s.keys[k]||"")}"></div>`).join("")}
  <div class="frow"><label>Модель для ИИ-сводки</label><select id="smodel">${(i.ai_models||[]).map(m=>`<option ${m===s.ai_model?"selected":""}>${m}</option>`).join("")}</select></div>
  <div class="sec" style="margin-top:14px"><b>Архивация страниц</b>
   ${chk("scap",s.capture_screenshot,"Сохранять скриншот страницы (PNG) как доказательство")}
   ${chk("spdf",s.capture_pdf,"Сохранять страницу в PDF")}
   <div class="hint">${IOS?"На iPhone скриншоты и PDF страниц пока недоступны — сохраняются HTML-снимок и SHA-256.":i.browser?"Браузер для снимков: "+esc(i.browser):"⚠ Не найден Microsoft Edge или Chrome — скриншоты недоступны"}</div></div>
  <div class="sec"><b>Метка времени RFC 3161 для пакета доказательств</b>
   ${chk("stsa",s.tsa_enabled,"Заверять manifest.json у независимой службы времени (TSA)")}
   ${chk("sots",s.ots_enabled!==false,"Закреплять пакет в блокчейне Bitcoin (OpenTimestamps, бесплатно)")}
   <div class="frow"><label>Служба TSA</label><input id="stsau" placeholder="http://timestamp.digicert.com (по умолчанию)" value="${esc(s.tsa_url||"")}"></div></div>
  <div class="sec"><b>Прочее</b>${chk("supd",s.check_updates,"Проверять обновления на GitHub при запуске")}</div>
  <div class="sec"><b>Портативный режим</b><div class="hint">${i.portable?"✓ Включён: данные хранятся в папке ProvenioData рядом с программой.":"Данные в профиле пользователя: "+esc(i.data_dir)}</div>
   ${i.portable||IOS?"":`<button class="ghost" id="sport" style="margin-top:6px">💾 Перенести данные к программе (флешка)</button>`}</div>
  ${accountSection()}
  <div class="row" style="margin-top:14px"><button class="btn" id="ssave">Сохранить</button><span class="pmsg">Provenio ${esc(i.version)} · инструментов: ${i.tools} · сайтов для поиска по нику: ${i.sites}<br>Данные: ${esc(i.data_dir)}</span></div>`);
 b.querySelector("#ssave").onclick=async()=>{const keys={};b.querySelectorAll(".skey").forEach(x=>keys[x.dataset.k]=x.value);
  const g=id=>b.querySelector(id);
  try{await api("settings",{proxy:g("#sproxy").value,timeout:+g("#stime").value||15,keys,ai_model:g("#smodel").value,
   capture_screenshot:g("#scap").checked,capture_pdf:g("#spdf").checked,tsa_enabled:g("#stsa").checked,ots_enabled:g("#sots").checked,tsa_url:g("#stsau").value,check_updates:g("#supd").checked});
   toast("Настройки сохранены","ok");closeModal()}catch(x){toast(x.message,"bad")}};
 bindAccount(b);
 const sp=b.querySelector("#sport");if(sp)sp.onclick=async()=>{if(!confirm("Скопировать все данные в папку ProvenioData рядом с программой и включить портативный режим?"))return;
  try{const r=await api("portable",{});toast(r.message,"ok");closeModal()}catch(x){toast(x.message,"bad")}}}

/* =================== 2.1: ДОСЬЕ =================== */
async function openDossier(id){if(!cur)return;let d;try{d=await api(`dossier?case=${cur.id}&id=${id}`)}catch(x){return toast(x.message,"bad")}
 const e=d.entity,col=d.confidence>=75?"var(--ok)":d.confidence>=45?"var(--warn)":"var(--bad)";
 const b=modal(`🗂 Досье: ${esc(e.value)}`,`<div class="row" style="margin-bottom:10px"><span class="badge">${esc(TL[e.type]||e.type)}</span>
  <span class="pill" style="color:${col}">достоверность ${d.confidence}% · ${esc(d.label)}</span><span class="pill">источников: ${d.sources.length}</span>
  ${d.domains.length?`<span class="pill">независимых доменов: ${d.domains.length}</span>`:""}</div>
  <div class="row" id="dtools" style="margin-bottom:8px"></div>
  ${d.other_cases.length?sec("🔀 Встречается в других кейсах",d.other_cases.map(c=>`<span class="tag good">${esc(c.name)}</span>`).join("")):""}
  ${sec("Источники",tbl(["#","Что","Когда","Надёжн."],d.sources.map(s=>[s.id,(s.kind==="tool"?"🛠 "+esc(s.tool)+": "+esc(s.query):esc(s.title||s.url))+`<br><small class="mu">${esc(s.url)}</small>`,esc(s.fetched),s.reliability+"/5"])))}
  ${d.context.length?sec("Контекст упоминаний",d.context.map(c=>`<div class="pmsg" style="border-left:2px solid var(--bd2);padding-left:8px;margin:6px 0"><b>#${c.source}</b> ${esc(c.text)}</div>`).join("")):""}
  ${d.related.length?sec("Связанные сущности (общие источники)",d.related.map(r=>`<span class="tag" style="cursor:pointer" data-rid="${r.id}">${esc(TL[r.type]||r.type)}: ${esc(r.value)} ×${r.shared}</span>`).join("")):""}
  ${d.timeline.length?sec("Хронология",d.timeline.map(t=>`<div class="kv"><b style="font-family:Consolas,monospace">${esc(t.date)}</b><span>${esc(t.label)} <span class="mu">#${t.source}</span></span></div>`).join("")):""}`);
 let q=e.value,list=PIVOTS[e.type]||[];if(e.type==="account"){q=e.value.split(":")[1];list=["username","github","telegram"]}
 b.querySelector("#dtools").innerHTML=list.map(id=>{const t=TOOLS.find(t=>t.id===id);return t?`<button class="ghost" data-tid="${id}">${t.ic} ${esc(t.tn)}</button>`:""}).join("");
 b.onclick=ev=>{const t=ev.target.closest("[data-tid]");if(t){runPivot(t.dataset.tid,q,e);closeModal();return}
  const r=ev.target.closest("[data-rid]");if(r)openDossier(+r.dataset.rid)}}

/* =================== ПЕРЕСЕЧЕНИЯ КЕЙСОВ =================== */
async function openIntersections(){const all=await api("intersections");
 const b=modal("🔀 Пересечения кейсов",`<div class="hint" style="margin-bottom:10px">Одни и те же email, домены, IP, телефоны и аккаунты в разных расследованиях — возможная связь между делами.</div>
  ${all.length?tbl(["Тип","Значение","Кейсы"],all.map(x=>[esc(TL[x.type]||x.type),esc(x.value),x.cases.map(c=>`<span class="tag ${cur&&c.id===cur.id?"good":""}" data-cid="${c.id}" style="cursor:pointer">${esc(c.name)}</span>`).join("")])):'<div class="empty" style="padding:30px"><b>Пересечений нет</b>Сущности не повторяются между кейсами</div>'}`);
 b.onclick=e=>{const t=e.target.closest("[data-cid]");if(t){cur=cases.find(c=>c.id==t.dataset.cid);renderCases();refresh();closeModal()}}}

/* =================== ОБХОД ССЫЛОК =================== */
function openExpand(id){if(!cur)return;
 const b=modal("🔗 Обойти ссылки страницы",`<div class="hint" style="margin-bottom:10px">Каждая найденная страница будет архивирована как отдельный источник (снимок, SHA-256, сущности) с пометкой, где её нашли.</div>
  <div class="frow"><label>Глубина</label><select id="xd"><option value="1">1 — ссылки этой страницы</option><option value="2">2 — и ссылки на них</option></select></div>
  <div class="frow"><label>Максимум страниц</label><input id="xl" type="number" min="1" max="80" value="20"></div>
  ${chk("xs",true,"Только в пределах того же сайта")}
  <div class="row" style="margin-top:12px"><button class="btn" id="xgo">Начать</button><button class="ghost" id="xstop">■ Стоп</button></div>
  <div class="prog" style="margin-top:12px"><i id="xp"></i></div><div class="pmsg" id="xm"></div>`);
 let jid=null;b.querySelector("#xstop").onclick=()=>jid&&api("job_cancel",{id:jid});
 b.querySelector("#xgo").onclick=async ev=>{ev.target.classList.add("loading");
  try{const r=await api("expand",{case:cur.id,id,depth:+b.querySelector("#xd").value,limit:+b.querySelector("#xl").value,same_host:b.querySelector("#xs").checked});jid=r.id;
   const f=await waitJob(r.id,s=>{b.querySelector("#xp").style.width=(s.all?s.done/s.all*100:5)+"%";b.querySelector("#xm").textContent=(s.msg||"")+(s.all?` · ${s.done}/${s.all}`:"")});
   ev.target.classList.remove("loading");
   b.querySelector("#xm").textContent=f.state==="done"?`Готово: добавлено ${f.result.added}, ошибок ${f.result.failed}`:(f.error||f.state);refresh()}catch(x){toast(x.message,"bad")}}}

/* =================== СЦЕНАРИИ =================== */
async function openPlaybooks(){if(!cur)return toast("Сначала выберите кейс","bad");const pbs=await api("playbooks");let sel=pbs[0];
 const b=modal("▶ Сценарий расследования",`<div class="hint" style="margin-bottom:10px">Сценарий запускает набор инструментов по одному значению и сохраняет каждый результат в кейс как доказательство.</div>
  <div class="pbs">${pbs.map((p,i)=>`<div class="pb ${i?"":"on"}" data-i="${i}"><b>${esc(p.title)}</b><small>${p.archive?"архив страницы + ":""}${p.steps.map(s=>{const t=TOOLS.find(t=>t.id===s.split(":").pop());return t?t.tn:s}).join(" · ")}</small></div>`).join("")}</div>
  <div class="row"><input id="pq" class="grow" placeholder="${esc(sel.ph)}"><button class="btn" id="pgo">Запустить</button><button class="ghost" id="pstop">■ Стоп</button></div>
  <div class="prog" style="margin-top:12px"><i id="pp"></i></div><div class="pmsg" id="pm"></div><div id="pr"></div>`);
 b.querySelector(".pbs").onclick=e=>{const c=e.target.closest(".pb");if(!c)return;b.querySelectorAll(".pb").forEach(x=>x.classList.toggle("on",x===c));sel=pbs[+c.dataset.i];b.querySelector("#pq").placeholder=sel.ph};
 let jid=null;b.querySelector("#pstop").onclick=()=>jid&&api("job_cancel",{id:jid});
 b.querySelector("#pgo").onclick=async ev=>{const q=b.querySelector("#pq").value.trim();if(!q)return toast("Введите значение","bad");ev.target.classList.add("loading");
  try{const r=await api("playbook",{case:cur.id,id:sel.id,q});jid=r.id;
   const f=await waitJob(r.id,s=>{b.querySelector("#pp").style.width=(s.all?s.done/s.all*100:5)+"%";b.querySelector("#pm").textContent=(s.msg||"")+(s.all?` · ${s.done}/${s.all}`:"")});
   ev.target.classList.remove("loading");
   if(f.state==="done"){b.querySelector("#pm").textContent=`Готово: успешно ${f.result.ok}, с ошибкой ${f.result.failed}`;
    b.querySelector("#pr").innerHTML=tbl(["Инструмент","Значение","Итог"],f.result.steps.map(x=>{const t=TOOLS.find(t=>t.id===x.tool);return[esc(t?t.tn:x.tool==="archive"?"Архив страницы":x.tool),esc(x.q),x.state==="done"?`<span class="found">✓ #${x.source}${x.entities!=null?" · сущн. "+x.entities:""}</span>`:`<span style="color:var(--bad)">${esc(x.error||"ошибка")}</span>`]}));refresh()}
   else b.querySelector("#pm").textContent=f.error||f.state}catch(x){toast(x.message,"bad")}}}

/* =================== ИИ-СВОДКА =================== */
function md(t){const L=esc(t).split("\n");let h="",inT=false,inL=false,inC=false;
 const il=s=>s.replace(/\\([*_|])/g,"$1").replace(/\*\*(.+?)\*\*/g,"<b>$1</b>").replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s.,;:)!?]|$)/g,"$1<i>$2</i>").replace(/`([^`]+)`/g,"<code>$1</code>");
 for(const raw of L){const l=raw.trim();
  if(/^```/.test(l)){h+=inC?"</pre>":"<pre>";inC=!inC;continue}if(inC){h+=raw+"\n";continue}
  if(/^\|/.test(l)){if(/^\|[\s:|-]+\|$/.test(l))continue;const cells=l.replace(/^\||\|$/g,"").split("|").map(c=>il(c.trim()));
   if(!inT){h+="<table><tr>"+cells.map(c=>`<th>${c}</th>`).join("")+"</tr>";inT=true}else h+="<tr>"+cells.map(c=>`<td>${c}</td>`).join("")+"</tr>";continue}
  if(inT){h+="</table>";inT=false}
  if(/^[-*] /.test(l)||/^\d+\. /.test(l)){if(!inL){h+="<ul>";inL=true}h+="<li>"+il(l.replace(/^([-*]|\d+\.) /,""))+"</li>";continue}
  if(inL){h+="</ul>";inL=false}
  const m=l.match(/^(#{1,4}) (.*)/);if(m){h+=`<h3>${il(m[2])}</h3>`;continue}
  if(l)h+=`<p>${il(l)}</p>`}
 return h+(inT?"</table>":"")+(inL?"</ul>":"")}
async function openAi(){if(!cur)return toast("Сначала выберите кейс","bad");const s=await api("settings");
 const b=modal("✨ ИИ-сводка кейса",`<div class="hint" style="margin-bottom:10px">Claude прочитает источники, сущности, хронологию и пересечения кейса и составит сводку: главное, ключевые сущности, связи, слабые места и следующие шаги.
  <br><b style="color:var(--warn)">Данные кейса будут отправлены в Anthropic API</b>. Запрос тратит кредиты вашего аккаунта Anthropic по его тарифу — Provenio ничего не берёт. (модель ${esc(s.ai_model||"claude-opus-5-5")}). ${s.keys.anthropic?"Ключ задан.":"⚠ Ключ не задан — добавьте его в ⚙ Настройках."}</div>
  <div class="row"><button class="btn" id="ago" ${s.keys.anthropic?"":"disabled"}>Составить сводку</button><button class="ghost" id="asave" hidden>＋ В кейс</button><button class="ghost" id="acopy" hidden>⧉ Копировать</button></div>
  <div class="prog ind" id="ap" hidden style="margin-top:12px"><i></i></div><div class="pmsg" id="am"></div><div class="md" id="ares" style="margin-top:10px"></div>`);
 let jid=null,text="";
 b.querySelector("#ago").onclick=async ev=>{ev.target.classList.add("loading");b.querySelector("#ap").hidden=false;
  try{const r=await api("ai_summary",{case:cur.id});jid=r.id;const f=await waitJob(r.id,x=>b.querySelector("#am").textContent=x.msg||"");
   b.querySelector("#ap").hidden=true;ev.target.classList.remove("loading");
   if(f.state!=="done"){b.querySelector("#am").innerHTML=`<span style="color:var(--bad)">${esc(f.error||f.state)}</span>`;return}
   text=f.result.summary;b.querySelector("#ares").innerHTML=md(text);
   b.querySelector("#am").textContent=`${f.result.model} · вход ${f.result.usage.input_tokens} ток. · выход ${f.result.usage.output_tokens} ток. · ${f.elapsed} с. ${f.result.note}`;
   b.querySelector("#asave").hidden=b.querySelector("#acopy").hidden=false}catch(x){toast(x.message,"bad")}};
 b.querySelector("#asave").onclick=async ev=>{try{const r=await api("job_save",{id:jid,case:cur.id});ev.target.outerHTML=`<span class="chip ok">✓ источник #${r.source}</span>`;refresh()}catch(x){toast(x.message,"bad")}};
 b.querySelector("#acopy").onclick=()=>{navigator.clipboard&&navigator.clipboard.writeText(text);toast("Скопировано","ok")}}

/* =================== МОНИТОРИНГ БРЕНДА =================== */
async function openBrand(){if(!cur)return toast("Сначала выберите кейс","bad");const list=await api("brand?case="+cur.id);
 const b=modal("🛡 Мониторинг бренда",`<div class="hint" style="margin-bottom:10px">Provenio периодически ищет новые зарегистрированные домены-двойники (опечатки, гомоглифы, другие зоны) и новые поддомены/сертификаты
  в логах Certificate Transparency. Новые находки сохраняются в кейс и приходят уведомлением. Проверка идёт, пока Provenio открыт.</div>
  <div class="row"><input id="bd" class="grow" placeholder="ваш-бренд.ru"><select id="bi" style="max-width:170px"><option value="360">каждые 6 часов</option><option value="720">каждые 12 часов</option><option value="1440" selected>раз в сутки</option><option value="10080">раз в неделю</option></select><button class="btn" id="bgo2">Следить</button></div>
  <div class="prog" style="margin-top:12px"><i id="bp"></i></div><div class="pmsg" id="bm"></div>
  <div style="margin-top:12px">${list.length?tbl(["Домен","Интервал","Последняя проверка","Изменений",""],list.map(m=>[esc(m.domain),Math.round(m.interval_min/60)+" ч",esc(m.last_check||"ещё нет"),m.changes,`<button class="ghost del" data-off="${esc(m.domain)}">Выключить</button>`])):'<span class="mu">Мониторинг ещё не настроен</span>'}</div>`);
 b.onclick=async e=>{const o=e.target.closest("[data-off]");if(o){await api("brand",{case:cur.id,domain:o.dataset.off,interval:0});toast("Мониторинг выключен","ok");closeModal()}};
 b.querySelector("#bgo2").onclick=async ev=>{const d=b.querySelector("#bd").value.trim();if(!d)return;ev.target.classList.add("loading");
  try{const r=await api("brand",{case:cur.id,domain:d,interval:+b.querySelector("#bi").value});
   const f=await waitJob(r.id,s=>{b.querySelector("#bp").style.width=(s.all?s.done/s.all*100:5)+"%";b.querySelector("#bm").textContent=s.msg||""});
   ev.target.classList.remove("loading");
   b.querySelector("#bm").textContent=f.state==="done"?`Исходное состояние сохранено: двойников ${f.result.lookalikes}, поддоменов ${f.result.subdomains}. Дальше — только новые.`:(f.error||f.state);refresh()}catch(x){toast(x.message,"bad")}}}

/* =================== ЭКСПОРТ ГРАФА PNG =================== */
async function exportPng(){if(tab!=="graph"){setTab("graph");await new Promise(r=>setTimeout(r,900))}
 const c=document.createElement("canvas");c.width=cv.width;c.height=cv.height;const x=c.getContext("2d");
 x.fillStyle="#08060f";x.fillRect(0,0,c.width,c.height);x.drawImage(cv,0,0);
 x.fillStyle="#9b93b5";x.font=(12*dpr)+"px Segoe UI";x.fillText(`Provenio · ${cur?cur.name:""} · ${new Date().toISOString().slice(0,16).replace("T"," ")} UTC`,14*dpr,22*dpr);
 const r=await api("blob",{data:c.toDataURL("image/png"),ctype:"image/png",name:`provenio_graph_${(cur&&cur.name||"case").replace(/[^\w-]+/g,"_")}.png`});
 if(IOS)return saveIOS("blob",r.id);
 const a=document.createElement("a");a.href=`/download/blob?id=${r.id}&t=${T}`;a.download="";document.body.append(a);a.click();a.remove()}

/* =================== IP-РАДАР =================== */
function vcol(r){const v=r.verdict;return r.confidence>=70||v.startsWith("C2")?"#fb7185":r.confidence>=35?"#fbbf24":/Tor|прокси/.test(v)?"#e879f9":/инфраструктура/.test(v)?"#60a5fa":"#34d399"}
function radarView(d,compact){return `<div class="${compact?"":"rgrid"}">`+d.results.map((r,i)=>{const c=vcol(r);return `<div class="card rcard" style="--c:${c};--i:${i};animation-delay:${Math.min(i,12)*50}ms">
 <div class="row"><div class="ring" style="--p:${r.confidence};--c:${c}"><b>${r.confidence}</b></div>
 <div class="grow"><div class="rip">${esc(r.ip)}</div><div class="rv" style="color:${c}">${esc(r.verdict)}</div>
 <div class="pmsg">${esc([r.geo.city,r.geo.country].filter(Boolean).join(", ")||"—")} · ${esc(r.network.as||"")}</div></div></div>
 <div>${r.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join("")}${r.infrastructure.map(t=>`<span class="tag good">${esc(t)}</span>`).join("")}</div>
 ${r.evidence.length?tbl(["Источник","Категория","Детали"],r.evidence.map(e=>[esc(e.source),esc(e.category),esc(e.detail)])):'<div class="pmsg">Ни один источник не отметил этот адрес</div>'}
 ${kv("Провайдер",r.network.isp||r.network.org)}${r.network.ptr?kv("PTR",r.network.ptr):""}${r.ports.length?kv("Открытые порты",r.ports.join(", ")):""}
 ${r.vulns.length?`<div class="kv"><b>CVE</b><span>${r.vulns.map(v=>`<span class="tag miss">${esc(v)}</span>`).join("")}</span></div>`:""}${r.hostnames.length?kv("Хосты",r.hostnames.join(", ")):""}
 ${r.geo.lat!=null&&!compact?`<div><button class="ghost" data-go="${r.geo.lon},${r.geo.lat}" data-lbl="${esc(r.ip)}">🌍 На глобусе</button></div>`:""}</div>`}).join("")+`</div>`+
 `<details class="pmsg" style="margin-top:12px"><summary>Открытые списки (${d.feeds.length})</summary>${d.feeds.map(f=>`${esc(f.name)}: ${f.records} записей${f.age_h!=null?", обновлён "+f.age_h+" ч назад":""}${f.error?" · ошибка "+esc(f.error):""}`).join("<br>")}</details><div class="pmsg">${esc(d.note)}</div>`}
const RADAR={job:null};
$("#rgo").onclick=async()=>{const q=$("#rq").value.trim();if(!q)return toast("Введите IP","bad");$("#rgo").classList.add("loading");$("#rprog").hidden=false;$("#rstop").hidden=false;$("#rsave").hidden=true;
 try{const r=await api("job",{name:"ip_radar",q});RADAR.job=r.id;
  const f=await waitJob(r.id,s=>{$("#rprog i").style.width=(s.all?s.done/s.all*100:5)+"%";$("#rmsg").textContent=s.msg||""});
  if(f.state==="done"){$("#rres").innerHTML=radarView(f.result);$("#rmsg").textContent=`Проверено ${f.result.count} IP за ${f.elapsed} с`;$("#rsave").hidden=false}
  else $("#rmsg").textContent=f.error||f.state}catch(x){toast(x.message,"bad")}
 $("#rgo").classList.remove("loading");$("#rprog").hidden=true;$("#rstop").hidden=true};
$("#rq").onkeydown=e=>{if(e.key==="Enter"&&e.ctrlKey)$("#rgo").click()};
$("#rstop").onclick=()=>RADAR.job&&api("job_cancel",{id:RADAR.job});
$("#rcase").onclick=()=>{if(!st)return;const ips=st.entities.filter(e=>e.type==="ip").map(e=>e.value);if(!ips.length)return toast("В кейсе нет IP-адресов","bad");$("#rq").value=ips.slice(0,50).join("\n")};
$("#rsave").onclick=async()=>{if(!cur)return toast("Сначала создайте кейс","bad");try{const r=await api("job_save",{id:RADAR.job,case:cur.id});$("#rsave").hidden=true;toast("Сохранено в кейс: источник #"+r.source+", сущностей "+r.entities,"ok");refresh()}catch(x){toast(x.message,"bad")}};
$("#rres").onclick=e=>{const g=e.target.closest("[data-go]");if(g){const[lon,lat]=g.dataset.go.split(",").map(Number);globeGo(lon,lat,g.dataset.lbl)}};

/* =================== УТЕЧКИ =================== */
function leaksView(d){
 if(d.kind==="password")return `<div class="lhead"><div class="big" style="color:${d.exposed?"var(--bad)":"var(--ok)"}">${d.exposed?d.count.toLocaleString("ru"):"✓"}</div>
  <div><b style="color:${d.exposed?"var(--bad)":"var(--ok)"}">${d.exposed?"Пароль найден в утечках — раз":"Пароль не найден в известных утечках"}</b><div class="pmsg">${esc(d.note)}</div></div></div>
  ${d.composition?kv("Состав",Object.entries(d.composition).map(([k,v])=>k+": "+v).join(" · ")):""}${kv("Отправлено в API",d.hash_prefix_sent+"…")}`;
 const risk=d.risk&&d.risk.label?`<span class="pill" style="color:${/high|critical/i.test(d.risk.label)?"var(--bad)":/medium/i.test(d.risk.label)?"var(--warn)":"var(--ok)"}">риск: ${esc(d.risk.label)} ${d.risk.score??""}</span>`:"";
 return `<div class="lhead"><div class="big" style="color:${d.exposed?"var(--bad)":"var(--ok)"}">${d.exposed?d.breaches_count:"✓"}</div>
  <div><b>${d.exposed?(d.kind==="email"?"утечек с этим адресом":"известных утечек сервиса"):"В известных утечках не найдено"}</b> <span class="mu">${esc(d.query||"")}</span>
  <div class="row" style="margin-top:6px">${risk}${d.password_strength?`<span class="pill">пароли: ${esc(JSON.stringify(d.password_strength).replace(/[{}"\[\]]/g," ").slice(0,90))}</span>`:""}</div></div></div>
  ${(d.data_types||[]).length?sec("Какие данные раскрыты",d.data_types.map(t=>`<span class="tag miss">${esc(t.type)} ×${t.breaches}</span>`).join("")):""}
  <div class="lgrid">${(d.breaches||[]).map((x,i)=>`<div class="card lcard" style="animation-delay:${Math.min(i,20)*30}ms"><div class="row">${x.logo?`<img src="${esc(x.logo)}" alt="" onerror="this.remove()">`:""}<div class="grow"><b>${esc(x.name)}</b><div class="pmsg">${esc(x.domain||"")} · ${esc((x.date||"").slice(0,10))}</div></div>
   ${x.password_risk?`<span class="sev ${/plain|easy/.test(x.password_risk)?"c":"m"}">${esc(x.password_risk)}</span>`:""}</div>
   ${x.records?`<div class="pmsg">записей: ${Number(x.records).toLocaleString("ru")}${x.industry?" · "+esc(x.industry):""}</div>`:""}
   ${x.data?`<div>${String(x.data).split(";").filter(Boolean).slice(0,10).map(t=>`<span class="tag">${esc(t)}</span>`).join("")}</div>`:""}
   ${x.details?`<div class="pmsg">${esc(x.details)}</div>`:""}</div>`).join("")}</div><div class="pmsg" style="margin-top:10px">${esc(d.note||"")} · Источник: ${esc(d.source||"XposedOrNot")}</div>`}
let lmode="email",LJOB=null;
$("#lmode").onclick=e=>{const c=e.target.closest(".fc");if(!c)return;lmode=c.dataset.m;$$("#lmode .fc").forEach(x=>x.classList.toggle("on",x===c));
 $("#lq").type=lmode==="password"?"password":"text";$("#lq").placeholder={email:"user@example.com",domain:"example.com",password:"пароль для проверки"}[lmode];$("#lq").value=""};
$("#lgo").onclick=async()=>{const q=$("#lq").value.trim();if(!q)return;
 if(lmode==="email"&&!q.includes("@"))return toast("Введите email","bad");if(lmode==="domain"&&(q.includes("@")||!q.includes(".")))return toast("Введите домен","bad");
 $("#lgo").classList.add("loading");$("#lsave").hidden=true;
 try{const r=await api("job",{name:"leaks",q:lmode==="password"&&/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q)?q+" ":q});LJOB=r.id;const f=await waitJob(r.id,s=>$("#lmsg").textContent=s.msg||"");
  if(f.state==="done"){$("#lres").innerHTML=leaksView(f.result);$("#lmsg").textContent=`Готово за ${f.elapsed} с`;if(lmode!=="password")$("#lsave").hidden=false}
  else{$("#lres").innerHTML=`<div class="card" style="color:var(--bad)">⚠ ${esc(f.error||f.state)}</div>`;$("#lmsg").textContent=""}}catch(x){toast(x.message,"bad")}
 $("#lgo").classList.remove("loading")};
$("#lq").onkeydown=e=>{if(e.key==="Enter")$("#lgo").click()};
$("#lsave").onclick=async()=>{if(!cur)return toast("Сначала создайте кейс","bad");try{const r=await api("job_save",{id:LJOB,case:cur.id});$("#lsave").hidden=true;toast("Сохранено в кейс: источник #"+r.source,"ok");refresh()}catch(x){toast(x.message,"bad")}};

/* =================== ФИШИНГ =================== */
function phishView(d){const c=d.risk_score>=60?"var(--bad)":d.risk_score>=30?"var(--warn)":"var(--ok)";
 return `<div class="row" style="margin-bottom:10px"><div class="ring" style="--p:${d.risk_score};--c:${c}"><b>${d.risk_score}</b></div><div class="grow"><b style="color:${c};font-size:15px;text-transform:uppercase">${esc(d.verdict)}</b>
  <div class="pmsg">${esc(d.host)}${d.final_url!==d.url?" · итоговый адрес: "+esc(d.final_url):""}</div></div></div>
  ${d.signals.map(s=>`<div class="kv"><b style="min-width:44px;color:${s.weight<0?"var(--ok)":s.level==="bad"?"var(--bad)":"var(--warn)"}">${s.weight>0?"+":""}${s.weight}</b><span>${esc(s.text)}</span></div>`).join("")||'<div class="pmsg">Подозрительных признаков нет</div>'}
  ${kv("Домен создан",d.domain_created?(d.domain_created.slice(0,10)+(d.domain_age_days!=null?` (${d.domain_age_days} дн.)`:"")):"неизвестно")}
  ${d.certificate?kv("Сертификат",(d.certificate.issuer||"")+" · с "+(d.certificate.valid_from||"")):""}
  ${d.page&&d.page.title?kv("Заголовок страницы",d.page.title):""}${d.reputation?kv("Репутация",d.reputation.risk_score+"/100 · "+d.reputation.verdict):""}
  <div class="pmsg">${esc(d.note)}</div>`}

/* =================== ОБНОВЛЕНИЯ =================== */
async function checkUpdates(){try{const s=await api("settings");if(!s.check_updates)return;const u=await api("update_check");
 if(u&&u.newer){const a=$("#updb");a.hidden=false;a.href=u.url;a.textContent="⬆ Доступна версия "+u.latest;toast("Вышла Provenio "+u.latest+" — ссылка слева внизу","ok")}}catch(x){}}

/* =================== ГЛОБУС =================== */
const RAD=Math.PI/180,MU=398600.4418,RE=6378.137,J2=1.08263e-3;
const GV={lon:40,lat:35,zoom:1,auto:true,night:true,drag:null,sel:null,track:false,hits:[],land:null,borders:null,inited:false,mark:null,last:performance.now(),
 L:{flights:{on:true,items:[],t:0},sats:{on:true,group:"stations",items:[]},quakes:{on:true,items:[]},events:{on:false,items:[]},cas:{on:true,items:[]}}};
const gc=$("#gcv"),gx=gc.getContext("2d");let GW=0,GH=0;
function gSize(){GW=gc.clientWidth;GH=gc.clientHeight;gc.width=GW*dpr;gc.height=GH*dpr}
window.addEventListener("resize",()=>{if(tab==="globe")gSize()});
function gR(){return Math.min(GW,GH)*.43*GV.zoom}
function proj(lon,lat,r){r=r||1;const l=(lon-GV.lon)*RAD,p=lat*RAD,p0=GV.lat*RAD,cp=Math.cos(p),cl=Math.cos(l);
 const x=r*cp*Math.sin(l),y=r*(Math.cos(p0)*Math.sin(p)-Math.sin(p0)*cp*cl),z=r*(Math.sin(p0)*Math.sin(p)+Math.cos(p0)*cp*cl),R=gR();
 return{x:GW/2+x*R,y:GH/2-y*R,z,ux:x,uy:y,vis:z>0||x*x+y*y>1}}
function unproj(sx,sy){const R=gR(),x=(sx-GW/2)/R,y=-(sy-GH/2)/R,r2=x*x+y*y;if(r2>1)return null;const z=Math.sqrt(1-r2),p0=GV.lat*RAD;
 const lat=Math.asin(y*Math.cos(p0)+z*Math.sin(p0)),lon=GV.lon+Math.atan2(x,z*Math.cos(p0)-y*Math.sin(p0))/RAD;return{lat:lat/RAD,lon:((lon+540)%360)-180}}
function topo(t){const sc=t.transform.scale,tr=t.transform.translate;
 const arcs=t.arcs.map(a=>{let x=0,y=0;return a.map(p=>{x+=p[0];y+=p[1];return[x*sc[0]+tr[0],y*sc[1]+tr[1]]})});
 const arc=i=>i<0?arcs[~i].slice().reverse():arcs[i];
 const ring=r=>{let o=[];r.forEach((i,k)=>{const a=arc(i);o=o.concat(k?a.slice(1):a)});return o};
 const polys=g=>g.type==="Polygon"?[g.arcs.map(ring)]:g.type==="MultiPolygon"?g.arcs.map(p=>p.map(ring)):[];
 const land=[],brd=[];t.objects.land.geometries.forEach(g=>polys(g).forEach(p=>p.forEach(r=>land.push(r))));
 t.objects.countries.geometries.forEach(g=>polys(g).forEach(p=>p.forEach(r=>brd.push({r,n:(g.properties||{}).name}))));return{land,brd}}
function satPos(o,t){if(!o._p){const n=o.MEAN_MOTION*2*Math.PI/86400,a=Math.cbrt(MU/(n*n)),e=o.ECCENTRICITY,i=o.INCLINATION*RAD,pp=a*(1-e*e),f=1.5*n*J2*(RE/pp)**2;
  o._p={n,a,e,i,O:o.RA_OF_ASC_NODE*RAD,w:o.ARG_OF_PERICENTER*RAD,M:o.MEAN_ANOMALY*RAD,ep:Date.parse(o.EPOCH+"Z"),dO:-f*Math.cos(i),dw:f*(2-2.5*Math.sin(i)**2)}}
 const q=o._p,dt=(t-q.ep)/1000,M=q.M+q.n*dt,O=q.O+q.dO*dt,w=q.w+q.dw*dt;let E=M;for(let k=0;k<6;k++)E-=(E-q.e*Math.sin(E)-M)/(1-q.e*Math.cos(E));
 const nu=2*Math.atan2(Math.sqrt(1+q.e)*Math.sin(E/2),Math.sqrt(1-q.e)*Math.cos(E/2)),r=q.a*(1-q.e*Math.cos(E)),u=w+nu,ci=Math.cos(q.i),si=Math.sin(q.i);
 const x=r*(Math.cos(O)*Math.cos(u)-Math.sin(O)*Math.sin(u)*ci),y=r*(Math.sin(O)*Math.cos(u)+Math.cos(O)*Math.sin(u)*ci),z=r*Math.sin(u)*si;
 const jd=t/864e5+2440587.5,g=((280.46061837+360.98564736629*(jd-2451545))%360)*RAD,lon=(Math.atan2(y,x)-g)/RAD;
 return{lon:((lon%360)+540)%360-180,lat:Math.atan2(z,Math.hypot(x,y))/RAD,alt:r-RE,v:Math.sqrt(MU*(2/r-1/q.a)),period:2*Math.PI/q.n/60}}
let LM=null;const lc=document.createElement("canvas"),lctx=lc.getContext("2d");
function buildMask(){const w=2048,h=1024,c=document.createElement("canvas");c.width=w;c.height=h;const x=c.getContext("2d");x.fillStyle="#fff";x.beginPath();
 for(const r of GV.land){r.forEach(([lo,la],i)=>{const X=(lo+180)/360*w,Y=(90-la)/180*h;i?x.lineTo(X,Y):x.moveTo(X,Y)});x.closePath()}x.fill("evenodd");x.fillRect(0,(90+85.5)/180*h,w,h);
 const d=x.getImageData(0,0,w,h).data,m=new Uint8Array(w*h);for(let i=0;i<w*h;i++)m[i]=d[i*4]>127?1:0;LM={w,h,m}}
function drawSphere(now){const R=gR(),cx=GW/2,cy=GH/2,step=R>700?3:2;
 const x0=Math.max(0,Math.floor(cx-R)),x1=Math.min(GW,Math.ceil(cx+R)),y0=Math.max(0,Math.floor(cy-R)),y1=Math.min(GH,Math.ceil(cy+R));
 const w=Math.ceil((x1-x0)/step),h=Math.ceil((y1-y0)/step);if(w<=0||h<=0)return;
 if(lc.width<w||lc.height<h){lc.width=Math.max(w,lc.width);lc.height=Math.max(h,lc.height)}
 const id=lctx.createImageData(w,h),d=id.data,p0=GV.lat*RAD,sp=Math.sin(p0),cp=Math.cos(p0),l0=GV.lon*RAD;
 const sun=sunPos(now),sd=sun.lat*RAD,ssd=Math.sin(sd),csd=Math.cos(sd),sl=sun.lon*RAD,night=GV.night,M=LM;
 for(let j=0;j<h;j++){const yy=-(y0+j*step-cy)/R;for(let i=0;i<w;i++){const xx=(x0+i*step-cx)/R,r2=xx*xx+yy*yy;if(r2>1)continue;
  const z=Math.sqrt(1-r2),sl_=yy*cp+z*sp,lat=Math.asin(sl_),lon=l0+Math.atan2(xx,z*cp-yy*sp);
  let land=0;if(M){let u=((lon/RAD+180)%360+360)%360/360*M.w|0,v=(90-lat/RAD)/180*M.h|0;if(v>=M.h)v=M.h-1;land=M.m[v*M.w+u]}
  let day=1;if(night){const cz=sl_*ssd+Math.cos(lat)*csd*Math.cos(lon-sl);day=cz>.12?1:cz<-.12?0:(cz+.12)/.24}
  const sh=.55+.45*z,k=(j*w+i)*4;
  if(land){d[k]=(34+86*day)*sh;d[k+1]=(18+44*day)*sh;d[k+2]=(66+130*day)*sh}else{d[k]=(8+16*day)*sh;d[k+1]=(6+10*day)*sh;d[k+2]=(18+36*day)*sh}
  d[k+3]=255}}
 lctx.putImageData(id,0,0);gx.imageSmoothingEnabled=true;gx.drawImage(lc,0,0,w,h,x0,y0,w*step,h*step)}
function sunPos(t){const d=new Date(t),doy=(t-Date.UTC(d.getUTCFullYear(),0,0))/864e5,decl=-23.44*Math.cos(2*Math.PI/365*(doy+10)),
 h=d.getUTCHours()+d.getUTCMinutes()/60+d.getUTCSeconds()/3600;return{lat:decl,lon:((-(h-12)*15)+540)%360-180}}
async function gLoad(layer){const L=GV.L[layer];try{
 if(layer==="flights"){const r=await api("globe?layer=flights");L.items=r.items;L.t=performance.now();L.src=r.source+(r.note?" · "+r.note:"")}
 if(layer==="sats"){const r=await api("globe?layer=sats&group="+L.group);L.items=r.items}
 if(layer==="quakes"){const r=await api("globe?layer=quakes");L.items=r.items}
 if(layer==="events"){const r=await api("globe?layer=events");L.items=r.items}
 if(layer==="cas"){L.items=cur?(await api("globe?layer=case&case="+cur.id)).items:[]}
 $("#gn-"+layer).textContent=L.items.length}catch(x){$("#gn-"+layer).textContent="ошибка";$("#gstat").textContent=layer+": "+x.message}}
async function globeOpen(){gSize();if(GV.inited)return;GV.inited=true;
 try{const r=await fetch("/static/world.json",{headers:{"X-Token":T}});const w=topo(await r.json());GV.land=w.land;GV.borders=w.brd;buildMask()}catch(x){$("#gstat").textContent="Карта не загрузилась"}
 api("globe?layer=groups").then(g=>{$("#ggroup").innerHTML=Object.entries(g).map(([k,v])=>`<option value="${k}">${esc(v)}</option>`).join("")});
 for(const l of Object.keys(GV.L))if(GV.L[l].on)gLoad(l);
 setInterval(()=>{if(tab==="globe"&&GV.L.flights.on)gLoad("flights")},30000);loops()}
$$("#p-globe [data-l]").forEach(c=>c.onchange=()=>{const L=GV.L[c.dataset.l];L.on=c.checked;if(L.on&&!L.items.length)gLoad(c.dataset.l)});
$("#ggroup").onchange=e=>{GV.L.sats.group=e.target.value;GV.L.sats.items=[];gLoad("sats")};
$("#gauto").onchange=e=>GV.auto=e.target.checked;
$(".gtitle").onclick=()=>$(".ghud").classList.toggle("min");if(innerWidth<820)$(".ghud").classList.add("min");$("#gnight").onchange=e=>GV.night=e.target.checked;
$("#gq").onkeydown=async e=>{if(e.key!=="Enter")return;try{const r=await api("globe?layer=geocode&q="+encodeURIComponent(e.target.value));
 $("#gres").innerHTML=r.map((x,i)=>`<div data-i="${i}">${esc(x.name)}</div>`).join("")||'<div>Ничего не найдено</div>';
 $("#gres").onclick=ev=>{const d=ev.target.closest("[data-i]");if(d){const x=r[+d.dataset.i];globeGo(x.lon,x.lat,x.name.split(",")[0]);$("#gres").innerHTML=""}}}catch(x){toast(x.message,"bad")}};
function globeGo(lon,lat,label){setTab("globe");GV.auto=false;$("#gauto").checked=false;GV.fly={lon,lat};GV.mark={lon,lat,label};GV.zoom=Math.max(GV.zoom,2.2)}
async function globeFindIp(ip){const L=GV.L.cas;if(!L.items.length)await gLoad("cas");const p=L.items.find(x=>x.label===ip);if(p){globeGo(p.lon,p.lat,ip);gSelect("cas",p)}else toast("Нет координат для "+ip,"bad")}
let gDown=null;const GP=new Map();let pinch0=null;
gc.onpointerdown=e=>{GP.set(e.pointerId,[e.clientX,e.clientY]);
 if(GP.size===2){const[a,b]=[...GP.values()];pinch0={d:Math.hypot(a[0]-b[0],a[1]-b[1])||1,z:GV.zoom};gDown=null;return}
 gDown={x:e.clientX,y:e.clientY,lon:GV.lon,lat:GV.lat,moved:false,touch:e.pointerType==="touch"};gc.style.cursor="grabbing"};
window.addEventListener("pointermove",e=>{if(GP.has(e.pointerId))GP.set(e.pointerId,[e.clientX,e.clientY]);
 if(pinch0&&GP.size===2){const[a,b]=[...GP.values()];GV.zoom=Math.max(.6,Math.min(30,pinch0.z*Math.hypot(a[0]-b[0],a[1]-b[1])/pinch0.d));return}const r=gc.getBoundingClientRect();if(tab==="globe"){const u=unproj(e.clientX-r.left,e.clientY-r.top);$("#gcoord").textContent=u?`${u.lat.toFixed(3)}°, ${u.lon.toFixed(3)}°`:""}
 if(!gDown)return;const dx=e.clientX-gDown.x,dy=e.clientY-gDown.y;if(Math.abs(dx)+Math.abs(dy)>3)gDown.moved=true;
 const k=90/gR();GV.lon=gDown.lon-dx*k;GV.lat=Math.max(-85,Math.min(85,gDown.lat+dy*k));GV.fly=null;GV.track=false});
window.addEventListener("pointerup",e=>{GP.delete(e.pointerId);if(GP.size<2)pinch0=null;if(!gDown)return;const m=gDown.moved,tch=gDown.touch;gDown=null;gc.style.cursor="grab";if(m)return;
 const r=gc.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;let best=null,bd=tch?24:10;
 for(const h of GV.hits){const d=Math.hypot(h.x-x,h.y-y);if(d<bd){bd=d;best=h}}if(best)gSelect(best.l,best.o);else{GV.sel=null;$("#ginfo").classList.remove("show")}});
gc.addEventListener("wheel",e=>{e.preventDefault();GV.zoom=Math.max(.6,Math.min(30,GV.zoom*(e.deltaY<0?1.15:1/1.15)))},{passive:false});
function gSelect(l,o){GV.sel={l,o};GV.track=false;const el=$("#ginfo");el.classList.add("show");const now=Date.now();let h="";
 if(l==="flights")h=`<h4>✈ ${esc(o.cs||o.id)}<button class="x">✕</button></h4>${kv("ICAO24",o.id)}${kv("Страна регистрации",o.co)}${kv("Высота",o.alt+" м")}${kv("Скорость",o.v+" км/ч")}${kv("Курс",o.hd+"°")}${o.sq?kv("Squawk",o.sq):""}
  <div class="tacts"><a class="ghost" target="_blank" href="https://globe.adsbexchange.com/?icao=${esc(o.id)}">ADS-B Exchange ↗</a><a class="ghost" target="_blank" href="https://www.flightradar24.com/${esc(o.cs||"")}">Flightradar24 ↗</a></div>`;
 if(l==="sats"){const p=satPos(o,now);h=`<h4>🛰 ${esc(o.OBJECT_NAME)}<button class="x">✕</button></h4>${kv("NORAD",o.NORAD_CAT_ID)}${kv("COSPAR",o.OBJECT_ID)}${kv("Высота",Math.round(p.alt)+" км")}${kv("Скорость",p.v.toFixed(2)+" км/с")}${kv("Период",p.period.toFixed(1)+" мин")}${kv("Наклонение",o.INCLINATION+"°")}${kv("Эпоха TLE",o.EPOCH)}
  <div class="tacts"><a class="ghost" target="_blank" href="https://www.n2yo.com/satellite/?s=${o.NORAD_CAT_ID}">N2YO ↗</a></div><div class="pmsg">Положение рассчитано по орбитальным элементам (Кеплер + J2), точность — километры.</div>`}
 if(l==="quakes")h=`<h4>〰 M${o.mag}<button class="x">✕</button></h4>${kv("Место",o.place)}${kv("Время",new Date(o.time).toISOString().replace("T"," ").slice(0,19)+" UTC")}${kv("Глубина",o.depth+" км")}${o.tsunami?kv("Цунами","возможна угроза"):""}<div class="tacts"><a class="ghost" target="_blank" href="${esc(o.url)}">USGS ↗</a></div>`;
 if(l==="events")h=`<h4>🔥 ${esc(o.title)}<button class="x">✕</button></h4>${kv("Категория",o.cat)}${kv("Дата",o.date)}${o.url?`<div class="tacts"><a class="ghost" target="_blank" href="${esc(o.url)}">Источник ↗</a></div>`:""}`;
 if(l==="cas")h=`<h4>◆ ${esc(o.label)}<button class="x">✕</button></h4>${kv("Тип",o.kind==="ip"?"IP-адрес кейса":"GPS из фото")}${kv("Где",o.info)}${o.conf!=null?kv("Достоверность",o.conf+"%"):""}${o.entity?`<div class="tacts"><button class="ghost" data-dos="${o.entity}">🗂 Досье</button></div>`:""}`;
 const pos=gPos(l,o,now);h+=kv("Координаты",pos?pos.lat.toFixed(4)+", "+pos.lon.toFixed(4):"—");
 h+=`<div class="tacts"><button class="ghost" data-gtrack>🎯 Следить</button>${l!=="cas"?`<button class="ghost" data-gsave>＋ В кейс</button>`:""}<a class="ghost" target="_blank" href="https://www.openstreetmap.org/?mlat=${pos?pos.lat:0}&mlon=${pos?pos.lon:0}#map=9/${pos?pos.lat:0}/${pos?pos.lon:0}">Карта ↗</a></div>`;
 el.innerHTML=h}
$("#ginfo").onclick=async e=>{if(e.target.classList.contains("x")){GV.sel=null;$("#ginfo").classList.remove("show");return}
 if(e.target.closest("[data-gtrack]")){GV.track=true;GV.auto=false;$("#gauto").checked=false;GV.zoom=Math.max(GV.zoom,2);return}
 const d=e.target.closest("[data-dos]");if(d){openDossier(+d.dataset.dos);return}
 if(e.target.closest("[data-gsave]")&&GV.sel){if(!cur)return toast("Сначала создайте кейс","bad");const{l,o}=GV.sel,pos=gPos(l,o,Date.now());
  const obj={...o};delete obj._p;delete obj.dlat;delete obj.dlon;obj.position_at_save=pos;
  const label=l==="flights"?"рейс "+(o.cs||o.id):l==="sats"?"спутник "+o.OBJECT_NAME:l==="quakes"?"землетрясение M"+o.mag+" "+o.place:o.title;
  try{const r=await api("globe_save",{case:cur.id,layer:l,label,obj});toast("Сохранено в кейс: источник #"+r.source,"ok");refresh()}catch(x){toast(x.message,"bad")}}};
function gPos(l,o,now){if(l==="sats")return satPos(o,now);if(l==="flights"){const dt=(performance.now()-GV.L.flights.t)/3600000,dist=o.v*dt,h=o.hd*RAD;
  return{lat:o.lat+dist*Math.cos(h)/111.32,lon:o.lon+dist*Math.sin(h)/(111.32*Math.max(.1,Math.cos(o.lat*RAD)))}}return{lat:o.lat,lon:o.lon}}
function gPath(ring,clamp){let first=true;for(const[lon,lat]of ring){const p=proj(lon,lat);let x=p.x,y=p.y;
 if(p.z<0){if(!clamp){first=true;continue}const n=Math.hypot(p.ux,p.uy)||1,R=gR();x=GW/2+p.ux/n*R;y=GH/2-p.uy/n*R}
 if(first){gx.moveTo(x,y);first=false}else gx.lineTo(x,y)}}
function gTick(t){if(tab!=="globe"||!GW||document.hidden){GV.raf=0;return}GV.raf=requestAnimationFrame(gTick);const dt=Math.min(100,t-GV.last);GV.last=t;const now=Date.now();
 if(GV.auto&&!gDown&&!GV.sel)GV.lon+=dt*.004;
 if(GV.fly){GV.lon+=(((GV.fly.lon-GV.lon+540)%360)-180)*.08;GV.lat+=(GV.fly.lat-GV.lat)*.08;if(Math.abs(GV.fly.lat-GV.lat)<.05)GV.fly=null}
 if(GV.track&&GV.sel){const p=gPos(GV.sel.l,GV.sel.o,now);if(p){GV.lon+=(((p.lon-GV.lon+540)%360)-180)*.1;GV.lat+=(p.lat-GV.lat)*.1}}
 const R=gR(),cx=GW/2,cy=GH/2;gx.setTransform(dpr,0,0,dpr,0,0);gx.clearRect(0,0,GW,GH);GV.hits=[];
 const atm=gx.createRadialGradient(cx,cy,R*.95,cx,cy,R*1.25);atm.addColorStop(0,"rgba(139,92,246,.35)");atm.addColorStop(1,"rgba(139,92,246,0)");gx.fillStyle=atm;gx.beginPath();gx.arc(cx,cy,R*1.25,0,7);gx.fill();
 drawSphere(now);
 gx.save();gx.beginPath();gx.arc(cx,cy,R,0,7);gx.clip();
 gx.strokeStyle="rgba(168,130,255,.09)";gx.lineWidth=1;
 for(let lo=-180;lo<180;lo+=30){gx.beginPath();const ring=[];for(let la=-90;la<=90;la+=3)ring.push([lo,la]);gPath(ring,false);gx.stroke()}
 for(let la=-60;la<=60;la+=30){gx.beginPath();const ring=[];for(let lo=-180;lo<=180;lo+=3)ring.push([lo,la]);gPath(ring,false);gx.stroke()}
 if(GV.land){gx.strokeStyle="rgba(192,132,252,.35)";gx.lineWidth=.7;gx.beginPath();for(const b of GV.borders)gPath(b.r,false);gx.stroke()}
 if(GV.night){const s=sunPos(now),sp=proj(s.lon,s.lat);if(sp.z>0){gx.fillStyle="#fde68a";gx.shadowColor="#fde68a";gx.shadowBlur=18;gx.beginPath();gx.arc(sp.x,sp.y,4,0,7);gx.fill();gx.shadowBlur=0}}
 gx.restore();
 const L=GV.L,sel=GV.sel;
 if(L.events.on)for(const o of L.events.items){const p=proj(o.lon,o.lat);if(p.z<=0)continue;gx.font="13px Segoe UI Emoji";gx.textAlign="center";gx.fillText(/fire/i.test(o.cat)?"🔥":/volcan/i.test(o.cat)?"🌋":/storm/i.test(o.cat)?"🌀":/ice/i.test(o.cat)?"🧊":"⚠",p.x,p.y+4);GV.hits.push({x:p.x,y:p.y,l:"events",o})}
 if(L.quakes.on)for(const o of L.quakes.items){const p=proj(o.lon,o.lat);if(p.z<=0)continue;const r=Math.max(2.5,(o.mag-2)*2.6),ph=(now/900+o.mag)%1;
  gx.strokeStyle=`rgba(251,113,133,${.7*(1-ph)})`;gx.lineWidth=1.2;gx.beginPath();gx.arc(p.x,p.y,r+ph*10,0,7);gx.stroke();gx.fillStyle="rgba(251,113,133,.85)";gx.beginPath();gx.arc(p.x,p.y,r*.55,0,7);gx.fill();GV.hits.push({x:p.x,y:p.y,l:"quakes",o})}
 if(L.flights.on){gx.fillStyle="#fbbf24";const fdt=(performance.now()-L.flights.t)/3600000;
  for(const o of L.flights.items){const dist=o.v*fdt,h=o.hd*RAD,la=o.lat+dist*Math.cos(h)/111.32,lo=o.lon+dist*Math.sin(h)/(111.32*Math.max(.1,Math.cos(o.lat*RAD)));
   const p=proj(lo,la,1+o.alt/6371000*20);if(p.z<=0)continue;
   if(GV.zoom>2.5){gx.save();gx.translate(p.x,p.y);gx.rotate(h);gx.beginPath();gx.moveTo(0,-4);gx.lineTo(3,3);gx.lineTo(-3,3);gx.closePath();gx.fill();gx.restore()}else gx.fillRect(p.x-1,p.y-1,2,2);
   GV.hits.push({x:p.x,y:p.y,l:"flights",o})}}
 if(L.sats.on){for(const o of L.sats.items){const s=satPos(o,now),p=proj(s.lon,s.lat,1+s.alt/RE);if(!p.vis)continue;
  gx.fillStyle="#22d3ee";gx.shadowColor="#22d3ee";gx.shadowBlur=8;gx.beginPath();gx.arc(p.x,p.y,2.2,0,7);gx.fill();gx.shadowBlur=0;
  if(L.sats.items.length<=40){gx.fillStyle="rgba(165,243,252,.8)";gx.font="10px Segoe UI";gx.textAlign="left";gx.fillText(o.OBJECT_NAME.slice(0,18),p.x+5,p.y-4)}
  GV.hits.push({x:p.x,y:p.y,l:"sats",o})}}
 if(sel&&sel.l==="sats"){const o=sel.o,per=satPos(o,now).period;gx.strokeStyle="rgba(34,211,238,.55)";gx.lineWidth=1.2;gx.beginPath();let first=true;
  for(let k=0;k<=120;k++){const s=satPos(o,now+k/120*per*60000),p=proj(s.lon,s.lat,1+s.alt/RE);if(!p.vis){first=true;continue}if(first){gx.moveTo(p.x,p.y);first=false}else gx.lineTo(p.x,p.y)}gx.stroke()}
 if(L.cas.on)for(const o of L.cas.items){const p=proj(o.lon,o.lat);if(p.z<=0)continue;gx.fillStyle="#e879f9";gx.shadowColor="#e879f9";gx.shadowBlur=14;
  gx.beginPath();gx.moveTo(p.x,p.y-6);gx.lineTo(p.x+5,p.y);gx.lineTo(p.x,p.y+6);gx.lineTo(p.x-5,p.y);gx.closePath();gx.fill();gx.shadowBlur=0;
  gx.fillStyle="#f5d0fe";gx.font="11px Segoe UI";gx.textAlign="left";gx.fillText(o.label,p.x+8,p.y+4);GV.hits.push({x:p.x,y:p.y,l:"cas",o})}
 drawOverlays(now);
 if(GV.puzzle&&GV.puzzle.length){gx.save();for(const x of GV.puzzle){const p=proj(x.lon,x.lat);if(p.z<=0)continue;gx.fillStyle="#f472b6";gx.shadowColor="#f472b6";gx.shadowBlur=10;
  gx.beginPath();gx.arc(p.x,p.y,3.5,0,7);gx.fill()}gx.restore()}
 if(GV.mark){const p=proj(GV.mark.lon,GV.mark.lat);if(p.z>0){const ph=(now/1000)%1;gx.strokeStyle=`rgba(255,255,255,${1-ph})`;gx.lineWidth=1.5;gx.beginPath();gx.arc(p.x,p.y,4+ph*16,0,7);gx.stroke();
  gx.fillStyle="#fff";gx.font="600 12px Segoe UI";gx.textAlign="left";gx.fillText(GV.mark.label||"",p.x+10,p.y-8)}}
 if(sel){const pos=gPos(sel.l,sel.o,now),p=pos&&proj(pos.lon,pos.lat,sel.l==="sats"?1+pos.alt/RE:1);if(p&&p.vis){gx.strokeStyle="#fff";gx.lineWidth=1.5;gx.strokeRect(p.x-8,p.y-8,16,16)}}
 if(now%1000<dt+20){$("#gclock").textContent=new Date(now).toISOString().slice(11,19)+" UTC";
  $("#gstat").textContent=(GV.L.flights.src?"Самолёты: "+GV.L.flights.src:"")}}


/* =================== 2.2: АККАУНТ =================== */
const DOCN={terms:"Условия использования",privacy:"Политика конфиденциальности",refund:"Политика возврата и отмены",thirdparty:"Сторонние сервисы и SDK"};
async function aget(p,b){const r=await fetch("/api/"+p,{method:b?"POST":"GET",headers:{"X-Token":T,"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined});
 const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
async function openDoc(name){try{const d=await aget("legal?doc="+name);const b=modal("📄 "+esc(DOCN[name]||name),`<div class="md">${md(d.text)}</div>`);
  b.closest(".modal-bg").style.zIndex=95}catch(x){toast(x.message,"bad")}}
function openDocs(){const b=modal("📄 Документы",`<div class="docs">${Object.keys(DOCN).map(k=>`<button class="ghost" data-doc="${k}">${DOCN[k]}</button>`).join("")}</div>
 <div class="hint" style="margin-top:12px">Provenio бесплатен: без подписок, платных функций и скрытых платежей. Нет телеметрии, рекламы и рассылок — нечего «отписывать».</div>`);
 b.onclick=e=>{const d=e.target.closest("[data-doc]");if(d)openDoc(d.dataset.doc)}}
const eye=id=>`<div class="pw"><input id="${id}" type="password" autocomplete="${id==="ap"?"current-password":"new-password"}"><button type="button" data-eye="${id}" title="Показать пароль">👁</button></div>`;
function pwScore(p){let s=0;if(p.length>=8)s++;if(p.length>=12)s++;if(/[a-zа-я]/.test(p)&&/[A-ZА-Я]/.test(p))s++;if(/\d/.test(p))s++;if(/[^\w\s]/.test(p))s++;return Math.min(4,s)}
async function showAuth(){STARTED&&closeModal();const a=$("#auth");a.hidden=false;let st;
 try{st=await aget("auth/status")}catch(x){$("#abox").innerHTML=`<div class="aerr">${esc(x.message)}</div>`;return}
 const box=$("#abox"),today=new Date().toISOString().slice(0,10);
 if(!st.exists){box.innerHTML=`<h2><small>Provenio __VER__</small>Создайте аккаунт</h2>
  <div class="sub">Аккаунт локальный: он хранится только на этом устройстве и никуда не отправляется.</div>
  <label class="f">Имя пользователя<input id="au" autocomplete="username" maxlength="32" placeholder="латиница, цифры, . _ -"></label>
  <label class="f">Пароль${eye("ap1")}<div class="meter"><i id="am"></i></div></label>
  <label class="f">Повторите пароль${eye("ap2")}</label>
  <label class="f"><span>Дата рождения <span style="font-weight:400;color:var(--mu2)">— только для проверки возраста 18+, не сохраняется</span></span><input id="ab" type="date" max="${today}" min="1900-01-01"></label>
  <label class="cons"><input type="checkbox" id="at"> <span>Я принимаю <a data-doc="terms">Условия использования</a></span></label>
  <label class="cons"><input type="checkbox" id="apr"> <span>Я прочитал(а) <a data-doc="privacy">Политику конфиденциальности</a></span></label>
  <label class="cons"><input type="checkbox" id="aupd"> <span>Проверять обновления на GitHub при запуске <span class="mu">(необязательно)</span></span></label>
  <div class="free">✓ Бесплатно навсегда: без подписок, пробных периодов, скрытых платежей и рассылок. <a class="alink" data-doc="refund">Политика возврата</a></div>
  <div class="aerr" id="aerr"></div>
  <button class="btn" id="ago">Создать аккаунт</button>
  <div class="afoot"><span>Пароль нельзя восстановить — запомните его</span><a class="alink" data-doc="thirdparty">Сторонние сервисы</a></div>`;
  const p1=box.querySelector("#ap1");p1.oninput=()=>{const sc=pwScore(p1.value),m=box.querySelector("#am");m.style.width=(sc*25)+"%";
   m.style.background=["#fb7185","#fb7185","#fbbf24","#a3e635","#34d399"][sc]};
  box.querySelector("#ago").onclick=async e=>{const g=id=>box.querySelector(id);e.target.classList.add("loading");g("#aerr").textContent="";
   try{const r=await aget("auth/register",{username:g("#au").value,password:g("#ap1").value,password2:g("#ap2").value,birth:g("#ab").value,
     accept_terms:g("#at").checked,accept_privacy:g("#apr").checked,check_updates:g("#aupd").checked});enter(r)}
   catch(x){g("#aerr").textContent=x.message}finally{e.target.classList.remove("loading")}}}
 else{box.innerHTML=`<h2><small>Provenio __VER__</small>С возвращением</h2>
  <div class="sub">Войдите, чтобы открыть кейсы.</div>
  <label class="f">Имя пользователя<input id="au" autocomplete="username" value="${esc(st.username)}"></label>
  <label class="f">Пароль${eye("ap")}</label>
  <div class="aerr" id="aerr"></div>
  <button class="btn" id="ago">Войти</button>
  <div class="afoot"><a class="alink" id="aforgot">Забыли пароль?</a><span><a class="alink" data-doc="terms">Условия</a> · <a class="alink" data-doc="privacy">Конфиденциальность</a></span></div>`;
  const go=async()=>{const g=id=>box.querySelector(id),b=g("#ago");b.classList.add("loading");g("#aerr").textContent="";
   try{enter(await aget("auth/login",{username:g("#au").value,password:g("#ap").value}))}catch(x){g("#aerr").textContent=x.message}finally{b.classList.remove("loading")}};
  box.querySelector("#ago").onclick=go;box.querySelector("#ap").onkeydown=e=>{if(e.key==="Enter")go()};
  box.querySelector("#aforgot").onclick=()=>{const m=modal("Забыли пароль?",`<div class="md"><p>Сервера и почты у Provenio нет, поэтому сбросить пароль письмом нельзя.</p>
   <p>Пароль защищает доступ к программе на этом устройстве. Если вы его забыли, закройте Provenio и удалите файл <code>account.json</code> в папке данных
   (<code>%LOCALAPPDATA%\\Provenio</code>). При следующем запуске создайте аккаунт заново, кейсы останутся на месте.</p>
   <p>Доступ к папке данных защищает ваша учётная запись Windows. Ключи API зашифрованы для неё же.</p></div>`);m.closest(".modal-bg").style.zIndex=95};
  setTimeout(()=>box.querySelector(st.username?"#ap":"#au").focus(),60)}
 box.onclick=e=>{const d=e.target.closest("[data-doc]");if(d){e.preventDefault();openDoc(d.dataset.doc)}
  const y=e.target.closest("[data-eye]");if(y){const i=box.querySelector("#"+y.dataset.eye);i.type=i.type==="password"?"text":"password"}}}
function enter(r){T=r.token;ME=r.user;$("#auth").hidden=true;$("#uname").textContent=ME.username;$("#uav").textContent=ME.username.slice(0,1);
 if(ME.terms_version!==ME.current_terms)termsUpdate();
 if(!STARTED){STARTED=true;renderTools();moveInk();sizeCv();setTimeout(checkUpdates,4000)}cur=null;loadCases()}
function termsUpdate(){const b=modal("Обновлены условия",`<div class="hint">Условия использования и Политика конфиденциальности изменились. Прочитайте их и примите, чтобы продолжить, или выйдите.</div>
 <div class="docs" style="margin:12px 0"><button class="ghost" data-doc="terms">Условия</button><button class="ghost" data-doc="privacy">Конфиденциальность</button></div>
 <div class="row"><button class="btn" id="tacc">Принимаю</button><button class="ghost" id="tdec">Не принимаю — выйти</button></div>`);
 b.closest(".modal-bg").onclick=null;
 b.onclick=async e=>{const d=e.target.closest("[data-doc]");if(d)return openDoc(d.dataset.doc);
  if(e.target.id==="tacc"){await api("auth/accept_terms",{});closeModal()}if(e.target.id==="tdec")logout()}}
async function logout(){try{await api("auth/logout",{})}catch(x){}T=PAGE_T;ME=null;cases=[];cur=null;st=null;closeModal();showAuth()}
$("#logout").onclick=logout;$("#docsb").onclick=openDocs;
function accountSection(){return `<div class="sec" style="margin-top:14px"><b>Аккаунт</b>
  <div class="hint">Пользователь <b style="color:var(--tx)">${esc(ME?ME.username:"")}</b> · создан ${esc(ME?ME.created:"")}. Аккаунт и данные хранятся только на этом устройстве.</div>
  <div class="row" style="margin-top:8px;gap:7px"><button class="ghost" id="spw">🔑 Сменить пароль</button><button class="ghost" id="sdocs">📄 Документы</button>
  <button class="ghost" id="sout">⎋ Выйти</button><button class="ghost danger" id="sdel">🗑 Удалить аккаунт</button></div></div>`}
function bindAccount(b){b.querySelector("#sout").onclick=logout;b.querySelector("#sdocs").onclick=openDocs;
 b.querySelector("#spw").onclick=()=>{const m=modal("🔑 Смена пароля",`<label class="f">Текущий пароль${eye("po")}</label><label class="f">Новый пароль${eye("pn")}</label>
  <label class="f">Повторите новый пароль${eye("pn2")}</label><div class="aerr" id="perr"></div>
  <div class="row"><button class="btn" id="pgo">Сменить</button><button class="ghost" id="pcancel">Отмена</button></div>`);m.classList.add("abox");m.style.width="auto";m.style.padding="0";
  m.onclick=async e=>{const y=e.target.closest("[data-eye]");if(y){const i=m.querySelector("#"+y.dataset.eye);i.type=i.type==="password"?"text":"password"}
   if(e.target.id==="pcancel")closeModal();
   if(e.target.id==="pgo")try{const r=await api("auth/password",{old:m.querySelector("#po").value,new:m.querySelector("#pn").value,new2:m.querySelector("#pn2").value});toast(r.message,"ok");closeModal()}
   catch(x){m.querySelector("#perr").textContent=x.message}}};
 b.querySelector("#sdel").onclick=()=>{const m=modal("🗑 Удаление аккаунта",`<div class="md"><p>Будут <b>безвозвратно</b> удалены с этого устройства:</p>
  <ul><li>аккаунт <b>${esc(ME.username)}</b> и пароль;</li><li>все кейсы, источники, сущности и журнал аудита;</li><li>снимки страниц, скриншоты и PDF;</li><li>ключи API и настройки.</li></ul>
  <p>Если нужны копии — сначала сделайте <b>Экспорт ▾ → Пакет доказательств</b> для каждого кейса.</p></div>
  <label class="f" style="margin-top:8px">Пароль${eye("dp")}</label>
  <label class="f"><span>Для подтверждения введите слово <b style="color:var(--bad)">УДАЛИТЬ</b></span><input id="dc" autocomplete="off"></label>
  <div class="aerr" id="derr"></div>
  <div class="row"><button class="btn danger" id="dgo">Удалить навсегда</button><button class="ghost" id="dcancel">Отмена</button></div>`);
  m.onclick=async e=>{const y=e.target.closest("[data-eye]");if(y){const i=m.querySelector("#"+y.dataset.eye);i.type=i.type==="password"?"text":"password"}
   if(e.target.id==="dcancel")closeModal();
   if(e.target.id==="dgo"){e.target.classList.add("loading");
    try{const r=await api("auth/delete",{password:m.querySelector("#dp").value,confirm:m.querySelector("#dc").value});
     T=PAGE_T;ME=null;cases=[];cur=null;st=null;closeModal();render&&render();renderCases();
     toast(r.left&&r.left.length?"Аккаунт удалён. Не удалось стереть: "+r.left.join(", "):"Аккаунт и все данные удалены","ok");showAuth()}
    catch(x){m.querySelector("#derr").textContent=x.message}finally{e.target.classList.remove("loading")}}}}}

/* =================== 2.3: XSS-ЛАБОРАТОРИЯ =================== */
const LVC={1:"#34d399",2:"#22d3ee",3:"#a78bfa",4:"#fb923c",5:"#f43f5e"};
let LAB=null,labLvl=0,labCur=null,labNav="";
const dots=l=>`<span class="dots" style="--dc:${LVC[l]}">${[1,2,3,4,5].map(i=>`<i class="${i<=l?"on":""}"></i>`).join("")}</span>`;
async function labsOpen(){if(PLAT==="lan"){$("#p-labs").innerHTML='<div class="empty"><b>XSS-лаборатория — только на компьютере</b>Лабы работают на отдельном защищённом сервере, доступном лишь с этого компьютера.</div>';return}try{LAB=await api("labs")}catch(x){$("#p-labs").innerHTML=`<div class="empty"><b>Лаборатория недоступна</b>${esc(x.message)}</div>`;return}
 labCur?labOpen(labCur.id):labsGrid()}
function labsGrid(){labCur=null;const L=LAB.labs,sol=LAB.progress.solved,n=Object.keys(sol).length,pc=Math.round(n/L.length*100);
 $("#p-labs").innerHTML=`<div class="lhero"><div class="lring" style="--p:${pc}"><b>${n}/${L.length}</b></div>
  <div><h2>XSS-ЛАБОРАТОРИЯ</h2><div class="sub">14 намеренно уязвимых сайтов: от отражённой XSS до обхода CSP, побега из песочницы шаблонов и DOM clobbering.
  Цель в каждой — выполнить <code>alert()</code>, <code>confirm()</code>, <code>prompt()</code> или <code>print()</code> в контексте сайта.
  Лабы работают на отдельном локальном сервере в изолированной песочнице — они не могут навредить Provenio и вашим данным.</div></div></div>
  <div class="lvls"><span class="fc ${!labLvl?"on":""}" data-lv="0">Все уровни</span>${Object.keys(LAB.levels).map(k=>`<span class="fc ${labLvl==k?"on":""}" data-lv="${k}">${dots(+k)} ${esc(LAB.levels[k])}</span>`).join("")}</div>
  <div class="labgrid">${L.filter(l=>!labLvl||l.level==labLvl).map((l,i)=>`<div class="card lab ${sol[l.id]?"done":""}" data-lab="${l.id}" style="--i:${i};--lc:${l.color}">
   <div class="lt"><div class="li">${esc(l.icon)}</div><div><div class="ln">${l.id}. ${esc(l.title)}</div><div class="lb">${esc(l.brand)} · ${esc(l.ctx)}</div></div></div>
   <div class="ld">${esc(l.story)}</div>
   <div class="lf"><span style="--dc:${LVC[l.level]}" class="row" ><span class="lvname">${esc(l.level_name)}</span>${dots(l.level)}</span>
    ${sol[l.id]?`<span class="ok-badge">✓ решено</span>`:(LAB.progress.revealed.includes(l.id)?`<span class="mu" style="font-size:11px">решение открыто</span>`:"")}</div></div>`).join("")}</div>`;
 $("#p-labs").onclick=e=>{const f=e.target.closest("[data-lv]");if(f){labLvl=+f.dataset.lv;labsGrid();return}
  const c=e.target.closest("[data-lab]");if(c)labOpen(+c.dataset.lab)}}
function labOrigin(){return `http://127.0.0.1:${LAB.port}`}
function labGo(path){const fr=$("#lframe");if(!fr)return;if(!path.startsWith("/"))path="/"+path;labNav=path;$("#laddr").value=path;fr.src=labOrigin()+path}
function labOpen(id){const l=LAB.labs.find(x=>x.id===id);labCur=l;const pr=LAB.progress,solved=pr.solved[id],h=pr.hints[id]||0;
 $("#p-labs").innerHTML=`<div class="row" style="margin-bottom:12px"><button class="ghost" id="lback">← Все лабы</button>
  <span class="lvname" style="--dc:${LVC[l.level]}">${esc(l.level_name)}</span>${dots(l.level)}<span class="mu" style="font-size:12px">${esc(l.ctx)}</span></div>
 <div class="labview"><div class="lbrief">
  <div class="card ${solved?"win":""}" id="lcard"><h3>${l.id}. ${esc(l.title)}</h3><div class="pmsg" style="margin-bottom:8px">${esc(l.brand)}</div>
   <div style="font-size:13px;line-height:1.55">${esc(l.story)}</div>
   <div class="goal" style="margin-top:10px">🎯 <b>Цель:</b> выполнить <code>alert()</code> / <code>confirm()</code> / <code>prompt()</code> / <code>print()</code> на этом сайте${l.exploit?" — атакуя жертву со своего exploit-сервера":""}.</div>
   <div id="lstat" class="pmsg" style="margin-top:8px">${solved?"✓ Решено "+esc(solved.ts):"Меняйте адрес и формы во встроенном браузере справа."}</div></div>
  <div class="card"><b style="font-size:13px">💡 Подсказки</b>${l.hints.map((t,i)=>i<h?`<div class="hintt">${esc(t)}</div>`:`<button class="ghost hintb" data-h="${i+1}" ${i>h?"disabled style='opacity:.45'":""}>Подсказка ${i+1}</button>`).join("")}
   <div class="row" style="margin-top:10px;gap:7px"><button class="ghost" id="lsolb">🔓 Показать решение</button><button class="ghost" id="lreset" title="Сбросить состояние сайта">↺ Сброс</button></div>
   <div id="lsol"></div></div>
  <div id="lfixc">${solved&&LAB.fixes[id]?`<div class="card lfix"><b>🛠 Как исправить</b><div class="lhint" style="margin-top:6px">${esc(LAB.fixes[id])}</div></div>`:""}</div>
 </div>
 <div class="flexcol" style="display:flex;flex-direction:column;gap:12px">
  <div class="card browser"><div class="bbar"><span class="bdots"><i></i><i></i><i></i></span>
   <input id="laddr" spellcheck="false" autocomplete="off"><button class="ghost" id="lgo" title="Перейти">→</button><button class="ghost" id="lreload" title="Обновить">⟳</button></div>
   <iframe id="lframe" class="bframe" sandbox="allow-scripts allow-forms" referrerpolicy="no-referrer"></iframe></div>
  ${l.exploit?`<div class="card xpl"><b>🧨 Exploit-сервер</b><div class="pmsg">Ваша страница-ловушка. «Доставить жертве» откроет её в браузере жертвы — справа.</div>
   <textarea id="lx" spellcheck="false" placeholder="<iframe src=&quot;/lab/${l.id}/&quot; onload=&quot;…&quot;></iframe>"></textarea>
   <div class="row"><button class="btn" id="lxgo">Доставить жертве</button><button class="ghost" id="lxsite">Открыть сайт</button></div></div>`:""}
 </div></div>`;
 labGo(`/lab/${id}/`);
 const P=$("#p-labs");P.onclick=async e=>{const t=e.target;
  if(t.id==="lback"){labsGrid();return}
  if(t.dataset.h){await api("labs_hint",{id,n:+t.dataset.h});LAB.progress.hints[id]=+t.dataset.h;labOpen(id);labGo(labNav);return}
  if(t.id==="lsolb"){if(!confirm("Показать готовое решение? Лаба будет отмечена как «решение открыто».")) return;
   const r=await api("labs_reveal",{id});if(!LAB.progress.revealed.includes(id))LAB.progress.revealed.push(id);
   $("#lsol").innerHTML=`<div class="hintt lsol">${esc(r.solution)}</div><div class="lhint" style="margin-top:8px"><b>Как исправить:</b> ${esc(r.fix)}</div>`;return}
  if(t.id==="lreset"){await api("labs_reset",{id});labGo(`/lab/${id}/`);toast("Состояние сайта сброшено","ok");return}
  if(t.id==="lgo")labGo($("#laddr").value.trim()||`/lab/${id}/`);
  if(t.id==="lreload")labGo(labNav);
  if(t.id==="lxsite")labGo(`/lab/${id}/`);
  if(t.id==="lxgo"){try{await api("labs_exploit",{id,html:$("#lx").value});labGo(`/exploit/${id}`);toast("Ловушка доставлена жертве","ok")}catch(x){toast(x.message,"bad")}}};
 $("#laddr").onkeydown=e=>{if(e.key==="Enter")labGo(e.target.value.trim())}}
async function labWin(m){if(!LAB||!labCur||m.provenioLab!==labCur.id||m.k!==LAB.secret)return;
 const id=labCur.id;if(LAB.progress.solved[id]){toast(`✓ ${m.fn}(${m.arg}) — уже решено`,"ok");return}
 try{const r=await api("labs_solved",{id,k:m.k,fn:m.fn});LAB.progress.solved[id]={ts:"только что",fn:m.fn};LAB.fixes[id]=r.fix;
  const c=$("#lcard");if(c){c.classList.add("win");$("#lstat").innerHTML=`🎉 <b style="color:#6ee7b7">Решено!</b> Ваш payload вызвал <code>${esc(m.fn)}(${esc(m.arg)})</code> на сайте ${esc(labCur.brand)}.`}
  $("#lfixc").innerHTML=`<div class="card lfix"><b>🛠 Как исправить</b><div class="lhint" style="margin-top:6px">${esc(r.fix)}</div></div>`;
  toast(`🎉 Лаба «${labCur.title}» решена! Всего: ${r.solved}/${LAB.labs.length}`,"ok")}catch(x){toast(x.message,"bad")}}
window.addEventListener("message",e=>{const m=e.data;if(!m||typeof m!=="object"||!m.provenioLab)return;
 const fr=$("#lframe");if(!fr||e.origin!=="null"&&e.origin!==labOrigin())return;
 if(m.nav&&e.source===fr.contentWindow){labNav=m.nav;$("#laddr").value=m.nav;return}
 if(m.fn)labWin(m)});

/* =================== 2.4: МАГИЯ =================== */
function outView(o){if(!o)return"";if(o.type==="text")return `<div class="mout">${esc(o.text)}</div>`;
 if(o.type==="file")return kv("Файл",o.file_type+" · "+o.size+" байт")+`<div class="mout">${esc(o.hex)}</div>`+
  (o.b64?`<a class="ghost" style="margin-top:6px" download="decoded.${(o.file_type||"bin").split("/")[0].toLowerCase()}" href="data:application/octet-stream;base64,${o.b64}">⬇ Сохранить файл</a>`:"");
 return kv("Двоичные данные",o.size+" байт")+`<div class="mout">${esc(o.hex)}</div>`}
function magicView(d){const ch=d.steps.length?`<div class="chain">${d.steps.map((s,i)=>`${i?"<i>→</i>":""}<span title="${esc(s.preview)}">${esc(s.op)}</span>`).join("")}</div>`:`<div class="pmsg">Похоже, это уже обычный текст — декодировать нечего.</div>`;
 return (d.mode==="magic"?`<div class="row" style="gap:8px"><b>🪄 Найденная цепочка</b><span class="pmsg">уверенность ${Math.round(d.score*100)}%</span></div>`:`<b>📜 Рецепт</b>`)+ch+
  (d.recipe&&d.mode==="magic"?`<div class="pmsg">Рецепт для повтора: <code>recipe: ${esc(d.recipe)}</code></div>`:"")+outView(d.output)+
  (d.steps.length>1?sec("Шаги",d.steps.map((s,i)=>`<div class="kv"><b>${i+1}. ${esc(s.op)}</b><span class="pmsg" style="font-family:Consolas,monospace">${esc(s.preview)}</span></div>`).join("")):"")+
  ((d.alternatives||[]).length?sec("Другие варианты",d.alternatives.map(a=>`<div class="kv"><b>${esc(a.chain.join(" → "))}</b><span>${esc(a.preview)}</span></div>`).join("")):"")}

/* =================== 2.4: КРИМИНАЛИСТИКА ФОТО =================== */
const LASTFILE={};
function forensicsView(d){const j=d.jpeg||{},fid="fx"+Math.random().toString(36).slice(2,8);
 const flags=(d.flags||[]).map(f=>`<div class="flag ${f.level==="warn"?"warn":""}">${f.level==="warn"?"⚠":"ℹ"} ${esc(f.text)}</div>`).join("")||`<div class="flag ok">Явных следов обработки в метаданных нет. Смотрите ELA ниже.</div>`;
 setTimeout(()=>forensicsCanvas(fid,d),30);
 return kv("Файл",`${d.name} · ${d.type} · ${(d.size/1024).toFixed(0)} KB`)+(j.quality?kv("Качество JPEG",`≈${j.quality}${j.standard_tables?" (стандартные таблицы)":" (нестандартные таблицы)"}${j.progressive?" · progressive":""}`):"")+
  (j.size?kv("Размер",j.size.join("×")+" px"):"")+(d.xmp&&d.xmp.creator_tool?kv("Создано в",d.xmp.creator_tool):"")+(d.xmp&&d.xmp.history.length?kv("История правок",d.xmp.history.join(", ")):"")+
  sec("Признаки",flags)+
  `<div class="fx" id="${fid}"><div class="pmsg">Готовлю ELA и битовые плоскости…</div></div>
  <div class="row" style="margin-top:8px;gap:10px"><label class="pmsg" style="display:flex;gap:8px;align-items:center">Усиление ELA <input type="range" min="5" max="60" value="20" data-ela="${fid}" style="width:160px;padding:0"></label>
   <label class="pmsg" style="display:flex;gap:8px;align-items:center">Бит <select data-bit="${fid}" style="width:auto;padding:4px 8px"><option>0</option><option>1</option><option>2</option></select></label></div>
  <div class="pmsg" style="margin-top:6px">ELA: области с иной историей сжатия светятся ярче — у вклеек и подретушированных мест «другая яркость шума». Однородный шум по всему кадру — норма.
  Битовая плоскость: у обычного фото младший бит похож на шум; чёткие узоры и полосы — признак скрытых данных (LSB-стеганография).</div>`}
async function fxImage(d){let src;if(d.image_b64)src=`data:${d.mime||"image/jpeg"};base64,${d.image_b64}`;
 else if(LASTFILE.img_forensics)src=URL.createObjectURL(LASTFILE.img_forensics);else return null;
 const im=new Image();im.src=src;await im.decode();return im}
function fxCanvas(w,h){const c=document.createElement("canvas");c.width=w;c.height=h;return c}
async function forensicsCanvas(fid,d){const box=document.getElementById(fid);if(!box)return;let im;
 try{im=await fxImage(d)}catch(x){im=null}if(!im){box.innerHTML='<div class="pmsg">Изображение недоступно для анализа в окне (формат не поддерживается браузером).</div>';return}
 const sc=Math.min(1,1400/Math.max(im.naturalWidth,im.naturalHeight)),W=Math.round(im.naturalWidth*sc),H=Math.round(im.naturalHeight*sc);
 const a=fxCanvas(W,H),ax=a.getContext("2d",{willReadFrequently:true});ax.drawImage(im,0,0,W,H);const A=ax.getImageData(0,0,W,H).data;
 const blob=await new Promise(r=>a.toBlob(r,"image/jpeg",.9));const im2=new Image();im2.src=URL.createObjectURL(blob);await im2.decode();
 const b=fxCanvas(W,H),bx=b.getContext("2d",{willReadFrequently:true});bx.drawImage(im2,0,0);const B=bx.getImageData(0,0,W,H).data;
 const ela=fxCanvas(W,H),ex=ela.getContext("2d"),bit=fxCanvas(W,H),btx=bit.getContext("2d");
 function drawEla(k){const o=ex.createImageData(W,H);for(let i=0;i<A.length;i+=4){o.data[i]=Math.min(255,Math.abs(A[i]-B[i])*k);o.data[i+1]=Math.min(255,Math.abs(A[i+1]-B[i+1])*k);
  o.data[i+2]=Math.min(255,Math.abs(A[i+2]-B[i+2])*k);o.data[i+3]=255}ex.putImageData(o,0,0)}
 // для LSB берём исходный размер без масштабирования (масштаб портит младшие биты)
 const fw=Math.min(im.naturalWidth,1400),fh=Math.min(im.naturalHeight,1400),f=fxCanvas(fw,fh),fxx=f.getContext("2d",{willReadFrequently:true});fxx.drawImage(im,0,0);
 const F=fxx.getImageData(0,0,fw,fh).data;bit.width=fw;bit.height=fh;
 function drawBit(n){const o=btx.createImageData(fw,fh);for(let i=0;i<F.length;i+=4){o.data[i]=(F[i]>>n&1)*255;o.data[i+1]=(F[i+1]>>n&1)*255;o.data[i+2]=(F[i+2]>>n&1)*255;o.data[i+3]=255}btx.putImageData(o,0,0)}
 drawEla(20);drawBit(0);
 // LSB-извлечение: биты RGB подряд → байты; ищем текст или сигнатуру файла
 let bytes=[],cur=0,nb=0;for(let i=0;i<F.length&&bytes.length<4096;i++){if(i%4===3)continue;cur=cur<<1|F[i]&1;if(++nb===8){bytes.push(cur);cur=0;nb=0}}
 const pr=bytes.slice(0,400).filter(x=>x>=32&&x<127||x===10).length/400,txt=String.fromCharCode(...bytes.slice(0,240)).replace(/[^\x20-\x7e\n]/g,"·");
 const sig=bytes.slice(0,4).map(x=>x.toString(16).padStart(2,"0")).join(" ");
 const lsbNote=pr>.85?`<div class="flag warn">⚠ Младшие биты складываются в читаемый текст — вероятно, скрытое сообщение: <code>${esc(txt.slice(0,160))}</code></div>`:
  ["89 50 4e 47","ff d8 ff e0","ff d8 ff e1","50 4b 03 04","25 50 44 46"].includes(sig)?`<div class="flag warn">⚠ В младших битах сигнатура файла (${sig}) — спрятан файл.</div>`:`<div class="pmsg">LSB-поток (RGB, бит 0) на текст и файлы не похож.</div>`;
 let thumb="";if(d.thumbnail){thumb=`<figure><img id="${fid}t" src="data:image/jpeg;base64,${d.thumbnail.b64}"><figcaption>Миниатюра из EXIF <span id="${fid}tm"></span></figcaption></figure>`}
 box.innerHTML=`<figure><img src="${a.toDataURL("image/jpeg",.85)}"><figcaption>Оригинал</figcaption></figure><figure id="${fid}e"></figure><figure id="${fid}b"></figure>${thumb}<div style="grid-column:1/-1">${lsbNote}</div>`;
 const fe=document.getElementById(fid+"e");fe.append(ela);fe.insertAdjacentHTML("beforeend","<figcaption>ELA — анализ уровня ошибок</figcaption>");
 const fb=document.getElementById(fid+"b");fb.append(bit);fb.insertAdjacentHTML("beforeend","<figcaption>Битовая плоскость (стеганография)</figcaption>");
 if(d.thumbnail){const ti=document.getElementById(fid+"t");await ti.decode().catch(()=>{});const tw=32,th=32,c1=fxCanvas(tw,th),c2=fxCanvas(tw,th),x1=c1.getContext("2d"),x2=c2.getContext("2d");
  x1.drawImage(a,0,0,tw,th);x2.drawImage(ti,0,0,tw,th);const p1=x1.getImageData(0,0,tw,th).data,p2=x2.getImageData(0,0,tw,th).data;let df=0;for(let i=0;i<p1.length;i+=4)df+=Math.abs(p1[i]-p2[i])+Math.abs(p1[i+1]-p2[i+1])+Math.abs(p1[i+2]-p2[i+2]);
  df=df/(tw*th*3);document.getElementById(fid+"tm").innerHTML=df>28?`<b style="color:var(--warn)">— НЕ совпадает с фото (разница ${df.toFixed(0)}): снимок обрезали или изменили после съёмки</b>`:`— совпадает с фото (разница ${df.toFixed(0)})`}
 document.querySelector(`[data-ela="${fid}"]`).oninput=e=>drawEla(+e.target.value);
 document.querySelector(`[data-bit="${fid}"]`).onchange=e=>drawBit(+e.target.value)}

/* =================== 2.4: EMAIL =================== */
const MAILROUTE={};
function mailView(d){const col={bad:"var(--bad)",warn:"var(--warn)",ok:"var(--ok)",info:"var(--mu)"};
 const v=d.verdict==="подозрительное"?"bad":d.verdict==="есть вопросы"?"warn":"ok",rid="m"+Math.random().toString(36).slice(2,8);MAILROUTE[rid]=d.hops;
 return `<div class="flag ${v}" style="font-size:14px"><b>Вердикт: ${esc(d.verdict)}</b></div>`+kv("Тема",d.subject)+kv("От",d.from)+kv("Кому",d.to)+kv("Reply-To",d.reply_to)+kv("Return-Path",d.return_path)+kv("Дата",d.date)+kv("Почтовый клиент",d.x_mailer)+
  `<div class="row" style="gap:6px;margin:8px 0">${["spf","dkim","dmarc"].map(k=>{const r=(d.auth[k]||"нет").toLowerCase();return `<span class="pill ${r==="pass"?"ok":r==="нет"?"":"bad"}">${k.toUpperCase()}: ${esc(r)}</span>`}).join("")}</div>`+
  sec("Признаки",(d.flags||[]).map(f=>`<div class="flag ${f.level==="bad"?"bad":f.level==="warn"?"warn":f.level==="ok"?"ok":""}" style="color:${col[f.level]}">${esc(f.text)}</div>`).join("")||"—")+
  sec(`Путь письма — ${d.hops.length} хопов${d.transit_sec!=null?`, ${d.transit_sec} с в пути`:""}`,tbl(["#","Откуда","Куда","IP","Где","Задержка","TLS"],d.hops.map((h,i)=>[i+1,esc(h.from||"—"),esc(h.by||"—"),esc(h.ips.join(", ")),
   h.geo?esc([h.geo.city,h.geo.country].filter(Boolean).join(", "))+`<br><small class="mu">${esc(h.geo.isp||"")}</small>`:"—",h.delay!=null?h.delay+" с":"",h.tls?"🔒":""])))+
  (d.hops.some(h=>h.geo)?`<button class="ghost" style="margin-top:8px" onclick="mailOnGlobe('${rid}')">🌍 Показать путь на глобусе</button>`:"")+(d.origin_ip?kv("Исходный IP отправителя",d.origin_ip):"")}
function mailOnGlobe(rid){const pts=(MAILROUTE[rid]||[]).filter(h=>h.geo&&h.geo.lat!=null).map((h,i)=>({lon:h.geo.lon,lat:h.geo.lat,label:`${i+1}. ${h.geo.city||h.geo.country||h.geo.ip}`}));
 if(!pts.length)return toast("Нет координат серверов","bad");GV.route=pts;globeGo(pts[0].lon,pts[0].lat,pts[0].label)}

/* =================== 2.4: ВЫМОГАТЕЛИ =================== */
function ransomView(d){return `<div class="flag ${d.count?"bad":"ok"}" style="font-size:13.5px">${d.count?`☠ Найдено упоминаний на сайтах утечек: <b>${d.count}</b>`:"✓ По этому запросу жертв на сайтах утечек не найдено"}</div>`+
 (d.groups.length?`<div class="row" style="gap:6px;margin:6px 0">${d.groups.map(([g,n])=>`<span class="tag">${esc(g)} ×${n}</span>`).join("")}</div>`:"")+
 (d.victims.length?tbl(["Жертва","Группа","Страна","Атака / обнаружено","Описание"],d.victims.map(v=>[`<b>${esc(v.victim)}</b>${v.domain?`<br><small class="mu">${esc(v.domain)}</small>`:""}`,esc(v.group),esc(v.country),
  `${esc(v.attackdate)}<br><small class="mu">${esc(v.discovered)}</small>`,`<small>${esc(v.description)}</small>`])):"")+
 `<div class="row" style="margin-top:8px;gap:8px"><button class="ghost" data-rw="${esc(d.query)}" onclick="ransomWatch(this.dataset.rw)">👁 Следить за «${esc(d.query)}»</button><span class="pmsg">${esc(d.source)}. ${esc(d.note)}</span></div>`}
async function ransomWatch(kw){try{const c=await api("ransom_watch");const k=[...new Set([...(c.keywords||[]),kw])];await api("ransom_watch",{keywords:k});
 toast(`Наблюдение включено: ${k.join(", ")}. Проверка раз в 6 часов, новое — в уведомлениях`,"ok")}catch(x){toast(x.message,"bad")}}

/* =================== 2.4: ХРОНОЛОКАЦИЯ ПО ТЕНЯМ =================== */
function solar(t){const n=t/864e5+2440587.5-2451545,L=(280.46+.9856474*n)%360,g=((357.528+.9856003*n)%360)*RAD,
 lam=(L+1.915*Math.sin(g)+.02*Math.sin(2*g))*RAD,eps=(23.439-4e-7*n)*RAD,ra=Math.atan2(Math.cos(eps)*Math.sin(lam),Math.cos(lam)),
 dec=Math.asin(Math.sin(eps)*Math.sin(lam)),gmst=(280.46061837+360.98564736629*n)%360;let lon=(ra/RAD-gmst)%360;lon=(lon+540)%360-180;return{lat:dec/RAD,lon}}
function sunElAz(lat,lon,t){const s=solar(t),p=lat*RAD,d=s.lat*RAD,H=(lon-s.lon)*RAD;
 const el=Math.asin(Math.sin(p)*Math.sin(d)+Math.cos(p)*Math.cos(d)*Math.cos(H))/RAD;
 const az=(Math.atan2(-Math.sin(H)*Math.cos(d),Math.cos(p)*Math.sin(d)-Math.sin(p)*Math.cos(d)*Math.cos(H))/RAD+360)%360;return{el,az}}
function gDest(lat,lon,brg,dist){const p1=lat*RAD,l1=lon*RAD,th=brg*RAD,de=dist*RAD,p2=Math.asin(Math.sin(p1)*Math.cos(de)+Math.cos(p1)*Math.sin(de)*Math.cos(th)),
 l2=l1+Math.atan2(Math.sin(th)*Math.sin(de)*Math.cos(p1),Math.cos(de)-Math.sin(p1)*Math.sin(p2));return[((l2/RAD+540)%360)-180,p2/RAD]}
const angDiff=(a,b)=>Math.abs(((a-b)%360+540)%360-180);
function chronoPanel(){const el=$("#ginfo");el.classList.add("show");GV.sel=null;const now=new Date().toISOString().slice(0,16);
 el.innerHTML=`<h4>☀ Хронолокация по тени<button class="x">✕</button></h4><div class="chrono">
  <div class="pmsg">Измерьте на фото высоту любого вертикального объекта и длину его тени (в одних единицах: пикселях, метрах, шагах).</div>
  <div class="row" style="gap:8px;flex-wrap:nowrap"><label>Высота<input id="ch-h" type="number" step="any" value="1"></label><label>Тень<input id="ch-l" type="number" step="any" value="1.2"></label></div>
  <label>Дата и время снимка (UTC)<input id="ch-t" type="datetime-local" value="${now}"></label>
  <label>Направление тени, ° (необязательно; 0 — север, 90 — восток)<input id="ch-az" type="number" step="any" placeholder="например 315"></label>
  <div class="row" style="gap:6px;margin-top:6px"><button class="btn" id="ch-where" style="padding:8px 13px">Где?</button><button class="ghost" id="ch-when">Когда? (для метки на глобусе)</button><button class="ghost" id="ch-clear">✕</button></div>
  <div class="pmsg" id="ch-res" style="margin-top:8px"></div></div>`;
 const g=id=>+el.querySelector(id).value,ts=()=>Date.parse(el.querySelector("#ch-t").value+":00Z");
 el.querySelector("#ch-where").onclick=()=>{const h=g("#ch-h"),L=g("#ch-l"),t=ts();if(!(h>0&&L>0)||isNaN(t))return toast("Заполните высоту, тень и время","bad");
  const e=Math.atan(h/L)/RAD,s=solar(t),ring=[];for(let b=0;b<=360;b+=1)ring.push(gDest(s.lat,s.lon,b,90-e));
  const azs=el.querySelector("#ch-az").value.trim(),hits=[];if(azs!==""){const sa=(+azs+180)%360;for(const[lo,la]of ring){if(angDiff(sunElAz(la,lo,t).az,sa)<4)hits.push([lo,la])}}
  GV.chrono={ring,hits,sun:s};const c=hits.length?hits[Math.floor(hits.length/2)]:[s.lon,s.lat];GV.fly={lon:c[0],lat:c[1]};GV.auto=false;$("#gauto").checked=false;
  el.querySelector("#ch-res").innerHTML=`Высота солнца <b>${e.toFixed(1)}°</b>. Снимок сделан где-то на <b style="color:#fde68a">жёлтой окружности</b> (все точки, где солнце в это время стоит на ${e.toFixed(1)}°).`+
   (azs!==""?(hits.length?` По направлению тени остаётся <b style="color:#f43f5e">красный участок</b> — ${hits.length>1?"примерно "+Math.round(hits.length*111.2*Math.sin((90-e)*RAD))+" км":"точка"}: от ${hits[0][1].toFixed(1)}°, ${hits[0][0].toFixed(1)}° до ${hits[hits.length-1][1].toFixed(1)}°, ${hits[hits.length-1][0].toFixed(1)}°.`:" С таким направлением тени точек нет — проверьте время (UTC!) и угол."):" Укажите направление тени, чтобы сузить до участка.")+
   `<br><span class="mu">Точность ±1–2°: рельеф, наклон поверхности и рефракция у горизонта.</span>`};
 el.querySelector("#ch-when").onclick=()=>{const m=GV.mark||{lon:GV.lon,lat:GV.lat,label:"центр глобуса"},h=g("#ch-h"),L=g("#ch-l"),t=ts();if(!(h>0&&L>0)||isNaN(t))return toast("Заполните высоту, тень и дату","bad");
  const e=Math.atan(h/L)/RAD,day=Date.UTC(new Date(t).getUTCFullYear(),new Date(t).getUTCMonth(),new Date(t).getUTCDate()),azs=el.querySelector("#ch-az").value.trim(),out=[];let prev=-9;
  for(let k=0;k<1440;k++){const tt=day+k*6e4,p=sunElAz(m.lat,m.lon,tt);if(Math.abs(p.el-e)<.35&&(azs===""||angDiff(p.az,(+azs+180)%360)<6)){if(k-prev>5)out.push({tt,az:p.az});prev=k}}
  const loc=x=>new Date(x+m.lon/15*36e5).toISOString().slice(11,16);
  el.querySelector("#ch-res").innerHTML=`Для «${esc(m.label||"точки")}» (${m.lat.toFixed(2)}°, ${m.lon.toFixed(2)}°) в этот день солнце на ${e.toFixed(1)}° `+
   (out.length?`было в: ${out.map(o=>`<b>${new Date(o.tt).toISOString().slice(11,16)} UTC</b> (≈${loc(o.tt)} по солнцу, тень на ${((o.az+180)%360).toFixed(0)}°)`).join("; ")}.`:"не стояло ни разу — проверьте дату или место.")};
 el.querySelector("#ch-clear").onclick=()=>{GV.chrono=null;el.querySelector("#ch-res").textContent=""}}
function drawOverlays(now){
 if(GV.chrono){gx.save();gx.setLineDash([6,5]);gx.strokeStyle="rgba(253,230,138,.85)";gx.lineWidth=1.6;gx.beginPath();gPath(GV.chrono.ring,false);gx.stroke();gx.setLineDash([]);
  if(GV.chrono.hits.length){gx.strokeStyle="#f43f5e";gx.lineWidth=4;gx.shadowColor="#f43f5e";gx.shadowBlur=12;gx.beginPath();gPath(GV.chrono.hits,false);gx.stroke();gx.shadowBlur=0}
  const sp=proj(GV.chrono.sun.lon,GV.chrono.sun.lat);if(sp.z>0){gx.fillStyle="#fde68a";gx.font="15px Segoe UI Emoji";gx.textAlign="center";gx.fillText("☀",sp.x,sp.y+5)}gx.restore()}
 if(GV.route&&GV.route.length){gx.save();gx.strokeStyle="#22d3ee";gx.lineWidth=2;gx.shadowColor="#22d3ee";gx.shadowBlur=10;
  for(let i=1;i<GV.route.length;i++){const a=GV.route[i-1],b=GV.route[i],seg=[];for(let k=0;k<=40;k++){const f=k/40;seg.push(gInterp(a,b,f))}gx.beginPath();gPath(seg,false);gx.stroke()}
  gx.shadowBlur=0;GV.route.forEach(r=>{const p=proj(r.lon,r.lat);if(p.z<=0)return;gx.fillStyle="#22d3ee";gx.beginPath();gx.arc(p.x,p.y,4,0,7);gx.fill();gx.fillStyle="#cffafe";gx.font="11px Segoe UI";gx.textAlign="left";gx.fillText(r.label,p.x+7,p.y-6)});gx.restore()}}
function gInterp(a,b,f){const p1=a.lat*RAD,l1=a.lon*RAD,p2=b.lat*RAD,l2=b.lon*RAD,d=2*Math.asin(Math.sqrt(Math.sin((p2-p1)/2)**2+Math.cos(p1)*Math.cos(p2)*Math.sin((l2-l1)/2)**2));
 if(d<1e-9)return[a.lon,a.lat];const A=Math.sin((1-f)*d)/Math.sin(d),B=Math.sin(f*d)/Math.sin(d),x=A*Math.cos(p1)*Math.cos(l1)+B*Math.cos(p2)*Math.cos(l2),
 y=A*Math.cos(p1)*Math.sin(l1)+B*Math.cos(p2)*Math.sin(l2),z=A*Math.sin(p1)+B*Math.sin(p2);return[Math.atan2(y,x)/RAD,Math.atan2(z,Math.hypot(x,y))/RAD]}

/* =================== 2.4: CT-ПОТОК =================== */
let CTT=null;
async function ctOpen(){let s;try{s=await api("ct")}catch(x){$("#p-ct").innerHTML=`<div class="empty"><b>Недоступно</b>${esc(x.message)}</div>`;return}
 if(!$("#ctkw")){$("#p-ct").innerHTML=`<div class="lhero"><div class="lring" style="--p:100"><b>CT</b></div><div><h2>ПОТОК СЕРТИФИКАТОВ</h2>
  <div class="sub">Каждый TLS-сертификат публикуется в журналах Certificate Transparency. Provenio читает свежие записи логов Let's Encrypt (через них выпускается
  большинство фишинговых сертификатов) и сразу сообщает, если появился домен, похожий на ваш бренд: <code>paypa1-login.com</code>, <code>secure-sberbanc.ru</code>…</div></div></div>
  <div class="cthead"><div class="card" style="display:flex;flex-direction:column;gap:9px">
   <div class="row"><span class="live off" id="ctlive"><i></i>ВЫКЛЮЧЕН</span><span class="grow"></span><button class="btn" id="ctgo">▶ Запустить</button></div>
   <label class="f">Ключевые слова бренда (по одному в строке)<textarea id="ctkw" rows="4" placeholder="paypal&#10;sberbank&#10;mycompany"></textarea></label>
   <label class="f">Свои домены — не считать угрозой<textarea id="ctal" rows="2" placeholder="paypal.com&#10;paypal.me"></textarea></label>
   <label class="cons"><input type="checkbox" id="ctbg"> <span>Работать в фоне, пока открыт Provenio</span></label>
   <button class="ghost" id="ctsave">Сохранить</button>
   <div class="pmsg">Ищем вхождение слова и «опечатки» (1 символ, 0→o, 1→l…). Трафик — примерно <b id="ctmb">90</b> МБ в час, пока поток включён.
   Охват: логи Let's Encrypt, не все центры сертификации.</div></div>
   <div style="display:flex;flex-direction:column;gap:12px"><div class="ctstats"><div class="card"><span class="pmsg">сертификатов/с</span><b id="ct-rate">—</b></div>
    <div class="card"><span class="pmsg">прочитано</span><b id="ct-n">0</b></div><div class="card"><span class="pmsg">совпадений</span><b id="ct-m">0</b></div><div class="card"><span class="pmsg">трафик</span><b id="ct-mb">0</b></div></div>
    <div class="card"><div class="row"><b style="font-size:13px">Живая лента</b><span class="pmsg grow" id="ct-err"></span></div><div class="ctfeed" id="ctfeed"></div></div></div></div>
  <div class="card" style="margin-top:14px"><b style="font-size:13px">🔴 Совпадения</b><div id="ctmatch"><div class="pmsg">Пока пусто.</div></div></div>`;
  $("#ctkw").value=(s.cfg.keywords||[]).join("\n");$("#ctal").value=(s.cfg.allow||[]).join("\n");$("#ctbg").checked=!!s.cfg.background;$("#ctmb").textContent=s.est_mb_per_hour;
  const cfg=()=>({keywords:$("#ctkw").value.split(/\n|,/),allow:$("#ctal").value.split(/\n|,/),background:$("#ctbg").checked});
  $("#ctsave").onclick=async()=>{await api("ct",{action:"config",...cfg()});toast("Сохранено","ok")};
  ctBind();$("#ctgo").onclick=async()=>{const r=await api("ct");await api("ct",{action:"config",...cfg()});await api("ct",{action:r.running?"stop":"start"});ctPoll()}}
 ctDraw(s);clearInterval(CTT);CTT=setInterval(()=>{if(tab!=="ct")return clearInterval(CTT);ctPoll()},2000)}
async function ctPoll(){try{ctDraw(await api("ct"))}catch(x){}}
function ctDraw(s){const l=$("#ctlive");if(!l)return;l.className="live"+(s.running?"":" off");l.innerHTML=`<i></i>${s.running?"В ЭФИРЕ":"ВЫКЛЮЧЕН"}`;$("#ctgo").textContent=s.running?"■ Остановить":"▶ Запустить";
 const st=s.stats;$("#ct-rate").textContent=s.running?st.rate:"—";$("#ct-n").textContent=st.certs.toLocaleString("ru");$("#ct-m").textContent=s.matches.length;
 $("#ct-mb").textContent=(st.bytes/1e6).toFixed(1)+" МБ";$("#ct-err").textContent=st.last_error?"⚠ "+st.last_error:(st.skipped?`пропущено при догоне: ${st.skipped}`:"");
 $("#ctfeed").innerHTML=s.feed.slice().reverse().map(f=>`<div>${new Date(f.t).toISOString().slice(11,19)} <b>${esc(f.d)}</b>${f.n>1?` +${f.n-1}`:""}</div>`).join("")||'<div>Запустите поток, и здесь побегут свежие сертификаты.</div>';
 $("#ctmatch").innerHTML=s.matches.length?s.matches.map(m=>`<div class="ctm"><b>${esc(m.domains.join(", "))}</b> <span class="mu">· ключ «${esc(m.keyword)}» · ${esc(m.time)} · ${esc(m.log)}</span>
  <div class="row" style="gap:6px;margin-top:5px">${m.domains.slice(0,3).map(d=>`<button class="ghost" style="padding:5px 10px" data-ctd="${esc(d.replace(/^\*\./,""))}">🎣 Проверить ${esc(d.replace(/^\*\./,""))}</button>`).join("")}</div></div>`).join(""):'<div class="pmsg">Пока пусто. Добавьте ключевые слова и запустите поток.</div>'}
function ctBind(){const m=$("#ctmatch");if(m)m.onclick=e=>{const b=e.target.closest("[data-ctd]");if(b)ctCheck(b.dataset.ctd)}}
function ctCheck(d){setTab("tools");setTimeout(()=>{const c=document.querySelector('.tool[data-id="phishing"]');if(!c)return;c.querySelector(".tq").value="https://"+d;runTool(c.querySelector(".tf-act"))},200)}

/* =================== 2.5: АТРИБУЦИЯ =================== */
function attribView(d){const cl=d.clusters.map((c,i)=>`<div class="clu"><b class="n">Оператор ${i+1}</b> <span class="pmsg">· ${c.domains.length} домен(а) · сила связи ${Math.round(c.strength*100)}%</span>
  <div>${c.domains.map(x=>`<span class="tag good">${esc(x)}</span>`).join("")}</div><div class="pmsg" style="margin-top:5px">Почему: ${esc(c.why.join(" · "))}</div></div>`).join("")||'<div class="flag">Общих операторов не найдено — домены выглядят независимыми.</div>';
 return `<div class="row" style="gap:8px;margin-bottom:4px"><b>Найдено групп: ${d.clusters.length}</b><span class="pmsg">из ${d.domains.length} доменов</span></div>`+cl+
  (d.alone.length?sec("Без связей",d.alone.map(x=>`<span class="tag">${esc(x)}</span>`).join("")):"")+
  (d.pairs.length?sec("Все связи",tbl(["Пара","Сила","Признаки"],d.pairs.slice(0,40).map(p=>[`${esc(p.a)}<br>${esc(p.b)}`,`<b style="color:${p.score>=.55?"var(--ok)":"var(--mu)"}">${Math.round(p.score*100)}%</b>`,esc(p.reasons.join("; "))]))):"")+
  `<div class="pmsg" style="margin-top:6px">${esc(d.method)}</div>`}

/* =================== 2.5: САМОАУДИТ =================== */
function exposureView(d){const C={critical:"#f43f5e",high:"#fb923c",medium:"#fbbf24",low:"#60a5fa"},L={critical:"критично",high:"высокий",medium:"средний",low:"низкий"},col=d.score>=50?"#f43f5e":d.score>=20?"#fbbf24":"#34d399";
 return `<div class="score"><div class="ring" style="--c:${col};--p:${d.score}"><b>${d.score}</b></div><div><b style="font-size:16px">Открытость: ${esc(d.level)}</b><div class="pmsg">${esc(d.domain)}${d.emails.length?" · "+esc(d.emails.join(", ")):""} · поддоменов ${d.subdomains} · документов проверено ${d.docs_checked}</div></div></div>`+
  (d.findings.length?d.findings.map(f=>`<div class="fnd"><span class="sv" style="color:${C[f.sev]}">${L[f.sev]}</span><div><b>${esc(f.area)}:</b> ${esc(f.text)}<div class="fx2">✔ ${esc(f.fix)}</div></div></div>`).join(""):'<div class="flag ok">Явных проблем не найдено.</div>')+
  `<div class="pmsg" style="margin-top:6px">${esc(d.note)}</div>`}

/* =================== 2.5: РИТМ ЖИЗНИ =================== */
const DOW=["Пн","Вт","Ср","Чт","Пт","Сб","Вс"];
function patternView(d){const id="pl"+Math.random().toString(36).slice(2,7);const off=d.utc_offset;
 const draw=(local)=>{const h=d.heat_utc;let mx=1;h.forEach(r=>r.forEach(v=>mx=Math.max(mx,v)));let g=`<i></i>${[...Array(24).keys()].map(x=>`<i>${x}</i>`).join("")}`;
  for(let w=0;w<7;w++){g+=`<i>${DOW[w]}</i>`;for(let x=0;x<24;x++){const src=local?(x-off+24)%24:x;const v=h[w][src],a=v/mx;g+=`<span title="${DOW[w]} ${x}:00 — ${v}" style="background:rgba(167,123,255,${(.06+a*.94).toFixed(2)});box-shadow:${a>.6?"0 0 10px rgba(167,123,255,.6)":"none"}"></span>`}}return g};
 setTimeout(()=>{const t=document.getElementById(id+"t");if(t)t.onchange=()=>{document.getElementById(id).innerHTML=draw(t.checked)}},20);
 const tz=`UTC${off>=0?"+":""}${off}`;
 return `<div class="score"><div class="ring" style="--c:#a78bfa;--p:${d.confidence}"><b>${d.confidence}%</b></div><div><b style="font-size:16px">Вероятный часовой пояс: ${tz}</b>
  <div class="pmsg">${esc(d.tz_examples)} · уверенность ${d.confidence}% (±1–2 ч) · ${d.events} событий · ${esc(d.first)} — ${esc(d.last)}</div></div></div>`+
  kv("Сон (местное время)",`${d.sleep_local[0]}:00 — ${d.sleep_local[1]}:00`)+kv("Пик активности",`${d.peak_local}:00 местного`)+
  kv("Выходные / будни",d.weekend_ratio==null?"—":`${d.weekend_ratio} ${d.weekend_ratio<.6?"— активность в основном в будни (работа?)":d.weekend_ratio>1.3?"— больше в выходные (хобби?)":""}`)+
  (d.url?kv("Источник",d.url):"")+
  `<label class="pmsg" style="display:flex;gap:8px;align-items:center;margin-top:8px"><input type="checkbox" id="${id}t"> показать по местному времени (${tz})</label>
  <div class="heat" id="${id}">${draw(false)}</div>`+
  (d.anomalies.length?sec("Аномальные недели",d.anomalies.map(a=>`<div class="flag warn">${esc(a.week)}: режим сдвинут на ${a.shift_h>0?"+":""}${a.shift_h} ч (${a.events} событий) — поездка, смена режима или другой человек</div>`).join("")):"")+
  `<div class="pmsg">${esc(d.note)}</div>`}

/* =================== 2.5: ЯКОРЯ, СВИДЕТЕЛЬ, ПРОВЕРЯЕМЫЙ ОТЧЁТ =================== */
async function openAnchors(){if(!cur)return toast("Сначала выберите кейс","bad");let L;try{L=await api("anchors?case="+cur.id)}catch(x){return toast(x.message,"bad")}
 const b=modal("⛓ Якоря в блокчейне Bitcoin",`<div class="hint" style="margin-bottom:10px">Хэш журнала аудита кейса записывается в календари <b>OpenTimestamps</b>, а они раз в несколько часов
  заносят его в блокчейн Bitcoin. После подтверждения любой человек сможет доказать, что все собранные доказательства существовали в этот момент и с тех пор не менялись —
  не доверяя ни вам, ни нам. Бесплатно и без ключей; в сеть уходит только хэш.</div>
  <div class="row" style="gap:8px;margin-bottom:8px"><button class="btn" id="anew">⛓ Закрепить кейс сейчас</button><button class="ghost" id="arep">🔐 Проверяемый отчёт HTML</button></div>
  <div id="alist">${L.map(anchorRow).join("")||'<div class="pmsg">Якорей пока нет. Они создаются и автоматически при экспорте пакета доказательств.</div>'}</div>`);
 b.onclick=async e=>{const t=e.target;
  if(t.id==="anew"){t.classList.add("loading");try{const r=await api("anchor",{case:cur.id});toast(`Отправлено в ${r.calendars.length} календаря OpenTimestamps`,"ok");openAnchors()}catch(x){toast(x.message,"bad")}finally{t.classList.remove("loading")}}
  if(t.id==="arep")dl("verify");
  if(t.dataset.ach){t.classList.add("loading");try{const r=await api("anchor_check",{id:+t.dataset.ach});toast(r.status==="confirmed"?`Подтверждено: блок ${r.height}`:"Пока ждёт блок Bitcoin (обычно 1–12 ч)",r.status==="confirmed"?"ok":"");openAnchors()}catch(x){toast(x.message,"bad")}}
  if(t.dataset.aots){const a=document.createElement("a");a.href=`/download/ots?id=${t.dataset.aots}&t=${T}`;a.download="";document.body.append(a);a.click();a.remove()}}}
function anchorRow(a){return `<div class="anc ${a.status}"><span class="st">${a.status==="confirmed"?"✓ В блокчейне":"⏳ Ожидает блок"}</span>
 <div class="grow"><b>${a.kind==="evidence"?"Пакет доказательств":"Журнал кейса"}</b> · ${esc(a.created)}${a.height?` · блок <b>${a.height}</b> (${esc(a.block_time)})`:""}<br><code style="font-size:11px">${esc(a.digest)}</code></div>
 <button class="ghost" data-ach="${a.id}">Проверить</button><button class="ghost" data-aots="${a.id}">⬇ .ots</button></div>`}

/* =================== 2.5: МАТРИЦА ГИПОТЕЗ (ACH) =================== */
const ACHV=["","CC","C","N","I","II"],ACHN={"":"—",CC:"++ очень согласуется",C:"+ согласуется",N:"нейтрально",I:"− противоречит",II:"−− сильно противоречит"};
const RELW={L:.5,M:1,H:1.5};let ACH=null,ACHT=null;
async function openAch(){if(!cur)return toast("Сначала выберите кейс","bad");const r=await api("ach?case="+cur.id);
 ACH=r.data||{hyps:[{id:1,text:"Гипотеза А"},{id:2,text:"Гипотеза Б"}],ev:[],cells:{}};
 modal("⚖ Матрица конкурирующих гипотез",`<div class="hint" style="margin-bottom:8px">Метод аналитиков разведки (ACH): побеждает не та версия, которую больше всего подтверждают,
  а та, которой <b>меньше всего противоречат</b> улики. Отметьте для каждой улики, как она соотносится с каждой гипотезой. Надёжность улики берётся из надёжности источника.</div>
  <div class="row" style="gap:7px;margin-bottom:8px"><button class="ghost" id="ah">＋ Гипотеза</button><button class="ghost" id="ae">＋ Улика</button><button class="ghost" id="as">⇩ Улики из источников кейса</button>
  <span class="pmsg grow" id="ast">${r.updated?"сохранено "+esc(r.updated):""}</span></div><div class="ach" id="achbox"></div>
  <div class="pmsg" style="margin-top:8px">⚪ Бледные улики ничего не различают (одинаковы для всех версий). 🟡 Отмеченные слева — на них держится вывод: без любой из них лидер меняется.</div>`);
 document.querySelector(".modal").style.width="min(1280px,96vw)";achDraw();const box=document.querySelector(".modal .mb");
 box.onclick=e=>{const t=e.target;if(t.id==="ah"){ACH.hyps.push({id:Date.now(),text:"Новая гипотеза"});achChanged()}
  if(t.id==="ae"){ACH.ev.push({id:Date.now(),text:"",cred:3,rel:"M"});achChanged()}
  if(t.id==="as"&&st){const have=new Set(ACH.ev.map(e=>e.src));st.sources.filter(s=>!have.has(s.id)).forEach(s=>ACH.ev.push({id:Date.now()+s.id,src:s.id,text:`#${s.id} ${s.title||s.url}`,cred:s.reliability,rel:"M"}));achChanged()}
  if(t.dataset.delh){ACH.hyps=ACH.hyps.filter(h=>h.id!=t.dataset.delh);achChanged()}
  if(t.dataset.dele){ACH.ev=ACH.ev.filter(x=>x.id!=t.dataset.dele);achChanged()}};
 box.onchange=box.oninput=e=>{const t=e.target,d=t.dataset;
  if(d.h)ACH.hyps.find(h=>h.id==d.h).text=t.value;
  if(d.e)ACH.ev.find(x=>x.id==d.e)[d.f]=d.f==="cred"?+t.value:t.value;
  if(d.ce){(ACH.cells[d.ce]=ACH.cells[d.ce]||{})[d.ch]=t.value}
  if(e.type==="change"&&(d.ce||d.f==="cred"||d.f==="rel"))achDraw(true);achSave()}}
function achChanged(){achDraw();achSave()}
function achSave(){clearTimeout(ACHT);ACHT=setTimeout(async()=>{try{const r=await api("ach",{case:cur.id,data:ACH});const s=$("#ast");if(s)s.textContent="сохранено "+r.updated}catch(x){}},600)}
function achScore(ev){const s={};ACH.hyps.forEach(h=>s[h.id]=0);for(const e of ev){const w=(e.cred||3)/5*(RELW[e.rel]||1),c=ACH.cells[e.id]||{};
  for(const h of ACH.hyps){const v=c[h.id];if(v==="I")s[h.id]+=w;if(v==="II")s[h.id]+=2*w}}return s}
function achBest(s){let b=null;for(const h of ACH.hyps)if(b===null||s[h.id]<s[b])b=h.id;return b}
function achDraw(keepFocus){const box=$("#achbox");if(!box)return;const s=achScore(ACH.ev),best=achBest(s);
 const sens=new Set(ACH.ev.filter(e=>achBest(achScore(ACH.ev.filter(x=>x!==e)))!==best&&ACH.hyps.length>1).map(e=>e.id));
 const nd=e=>{const c=ACH.cells[e.id]||{},vals=ACH.hyps.map(h=>c[h.id]||"");return vals.every(v=>v===vals[0])};
 if(keepFocus){box.querySelectorAll("tfoot td[data-s]").forEach(td=>{const id=td.dataset.s;td.textContent=s[id].toFixed(1);td.className=id==best?"best":""});
  box.querySelectorAll("tr[data-row]").forEach(tr=>{const e=ACH.ev.find(x=>x.id==tr.dataset.row);tr.className=(nd(e)?"nd ":"")+(sens.has(e.id)?"sens":"")});
  box.querySelectorAll("select[data-ce]").forEach(x=>x.parentElement.className="c-"+(x.value||"x"));return}
 box.innerHTML=`<table><thead><tr><th>Улика</th><th>Надёжн.</th><th>Важн.</th>${ACH.hyps.map(h=>`<th><div class="row" style="gap:4px;flex-wrap:nowrap"><input data-h="${h.id}" value="${esc(h.text)}"><button class="ghost" style="padding:3px 7px" data-delh="${h.id}">✕</button></div></th>`).join("")}<th></th></tr></thead>
 <tbody>${ACH.ev.map(e=>`<tr data-row="${e.id}" class="${nd(e)?"nd ":""}${sens.has(e.id)?"sens":""}"><td class="ev"><input data-e="${e.id}" data-f="text" value="${esc(e.text)}" placeholder="Факт или улика…"></td>
  <td><select data-e="${e.id}" data-f="cred">${[1,2,3,4,5].map(n=>`<option ${n==e.cred?"selected":""}>${n}</option>`).join("")}</select></td>
  <td><select data-e="${e.id}" data-f="rel">${["L","M","H"].map(n=>`<option value="${n}" ${n==e.rel?"selected":""}>${{L:"низкая",M:"средняя",H:"высокая"}[n]}</option>`).join("")}</select></td>
  ${ACH.hyps.map(h=>{const v=(ACH.cells[e.id]||{})[h.id]||"";return `<td class="c-${v||"x"}"><select data-ce="${e.id}" data-ch="${h.id}">${ACHV.map(o=>`<option value="${o}" ${o===v?"selected":""}>${ACHN[o]}</option>`).join("")}</select></td>`}).join("")}
  <td><button class="ghost" style="padding:3px 7px" data-dele="${e.id}">✕</button></td></tr>`).join("")||`<tr><td colspan="${ACH.hyps.length+4}" class="pmsg">Добавьте улики — вручную или из источников кейса.</td></tr>`}</tbody>
 <tfoot><tr><td colspan="3">Противоречий (меньше — вероятнее)</td>${ACH.hyps.map(h=>`<td data-s="${h.id}" class="${h.id==best?"best":""}">${s[h.id].toFixed(1)}</td>`).join("")}<td></td></tr></tfoot></table>`}

/* =================== 2.5: ГЕОПАЗЛ =================== */
let GPF=null;
async function geoPuzzlePanel(){if(!GPF)try{GPF=await api("geopuzzle_features")}catch(x){return toast(x.message,"bad")}
 const el=$("#ginfo");el.classList.add("show");GV.sel=null;const opts=GPF.map(f=>`<option value="${f.id}">${esc(f.label)}</option>`).join("");
 el.innerHTML=`<h4>🧩 Геопазл<button class="x">✕</button></h4><div class="gp"><div class="pmsg">Опишите, что видно на фото — Provenio найдёт в OpenStreetMap места, где всё это есть рядом.</div>
  <label>Где искать (город, район) — или пусто: текущий вид глобуса<input id="gp-area" placeholder="например: Казань"></label>
  <label>Главная примета<select id="gp-a">${opts}</select></label><input id="gp-ac" placeholder="свой тег: key=value" hidden>
  <label>Название содержит (необязательно)<input id="gp-n" placeholder="например: Никол"></label>
  <div class="pmsg" style="margin-top:6px">…а рядом с ней (в пределах, м):</div><div id="gp-c"></div>
  <button class="ghost" id="gp-add" style="margin:4px 0">＋ примета рядом</button>
  <div class="row" style="gap:6px;margin-top:4px"><button class="btn" id="gp-go" style="padding:8px 14px">Найти места</button><button class="ghost" id="gp-clr">✕</button></div>
  <div class="pmsg" id="gp-msg" style="margin-top:6px"></div><div class="gpres" id="gp-res"></div></div>`;
 const addRow=(k="river",d=300)=>{const r=document.createElement("div");r.className="cr";r.innerHTML=`<select>${opts}</select><input type="number" value="${d}" min="10" max="5000"><button class="ghost" style="padding:3px 7px">✕</button>`;
  r.querySelector("select").value=k;r.querySelector("button").onclick=()=>r.remove();$("#gp-c").append(r)};
 addRow("river",300);$("#gp-add").onclick=()=>{if($$("#gp-c .cr").length<4)addRow("fuel",500)};
 $("#gp-a").onchange=e=>{$("#gp-ac").hidden=e.target.value!=="custom"};
 $("#gp-clr").onclick=()=>{GV.puzzle=null;$("#gp-res").innerHTML="";$("#gp-msg").textContent=""};
 $("#gp-go").onclick=async e=>{const b=e.target,area=$("#gp-area").value.trim();let bbox=null;
  if(!area){const span=Math.max(.05,Math.min(1.2,30/GV.zoom));bbox=[GV.lat-span,GV.lon-span*1.6,GV.lat+span,GV.lon+span*1.6]}
  const cons=$$("#gp-c .cr").map(r=>({key:r.querySelector("select").value,dist:+r.querySelector("input").value}));
  b.classList.add("loading");$("#gp-msg").textContent="Ищу в OpenStreetMap…";
  try{const j=await api("geopuzzle",{area,bbox,anchor:$("#gp-a").value,anchor_custom:$("#gp-ac").value,name:$("#gp-n").value,constraints:cons});
   const f=await waitJob(j.id);if(f.state!=="done")throw new Error(f.error||"не удалось");const d=f.result;GV.puzzle=d.items;
   $("#gp-msg").innerHTML=d.count?`Кандидатов: <b>${d.count}</b>${d.count>=150?" (показаны первые 150 — уточните)":""}. ${esc(d.note)}`:"Мест с таким сочетанием нет — ослабьте условия или увеличьте расстояния.";
   $("#gp-res").innerHTML=d.items.map((x,i)=>`<div data-gi="${i}">📍 ${esc(x.name||"без названия")} <span class="mu">${x.lat.toFixed(4)}, ${x.lon.toFixed(4)}</span></div>`).join("");
   $("#gp-res").onclick=ev=>{const r=ev.target.closest("[data-gi]");if(!r)return;const x=d.items[+r.dataset.gi];globeGo(x.lon,x.lat,x.name||"кандидат");GV.zoom=Math.max(GV.zoom,40);
    showMenu(ev.clientX,ev.clientY,[["Открыть",null],["🗺 OpenStreetMap",()=>window.open(x.osm,"_blank")],["🚶 Панорама Google",()=>window.open(x.gmaps,"_blank")],["🛰 Спутник Яндекса",()=>window.open(x.yandex,"_blank")]])};
   if(d.items.length){const c=d.items[0];GV.fly={lon:c.lon,lat:c.lat};GV.auto=false;$("#gauto").checked=false;GV.zoom=Math.max(GV.zoom,25)}}
  catch(x){$("#gp-msg").textContent="⚠ "+x.message}finally{b.classList.remove("loading")}}}

/* =================== 2.6: ОТКРЫТЬ НА ТЕЛЕФОНЕ =================== */
const LANMODE=PLAT==="lan";
async function openPhone(){let s;try{s=await api("lan")}catch(x){return toast(x.message,"bad")}
 const b=modal("📱 Provenio на телефоне",`<div class="row" style="gap:18px;align-items:flex-start;flex-wrap:wrap">
  <div style="flex:1;min-width:260px"><div class="hint" style="font-size:12.5px;line-height:1.6">Телефон открывает этот же Provenio через вашу домашнюю сеть: кейсы, инструменты, глобус —
   всё считается и хранится на компьютере, телефон — экран. Ничего ставить и подписывать не нужно.</div>
   <ol class="pmsg" style="margin:10px 0 0 18px;line-height:1.7;font-size:12.5px"><li>Телефон и компьютер — в одной сети Wi-Fi.</li><li>Включите доступ и отсканируйте QR-код камерой.</li>
   <li>Войдите своим паролем Provenio.</li><li>iPhone: «Поделиться» → «На экран „Домой“» — появится иконка, откроется как приложение.</li></ol>
   <div class="row" style="gap:8px;margin-top:12px"><button class="btn" id="lanon">${s.on?"■ Выключить доступ":"▶ Включить доступ"}</button>
    ${s.on?`<button class="ghost" id="lanrot" title="Старые QR-коды и иконки на телефонах перестанут работать">↻ Сменить ключ</button>`:""}</div>
   <label class="cons" style="margin-top:10px"><input type="checkbox" id="lanauto" ${s.autostart?"checked":""}> <span>Включать при запуске Provenio (чтобы иконка на телефоне работала сразу)</span></label>
   <div class="toolnote" style="margin-top:12px">🔒 Доступ только из локальной сети и только с ключом из QR-кода, затем — пароль аккаунта. Выключение сразу закрывает доступ и выходит из аккаунта на телефонах.
   Соединение в домашней сети не шифруется — не включайте доступ в общественном Wi-Fi.
   При первом включении Windows спросит разрешение для Provenio — разрешите <b>частные сети</b>. XSS-лаборатория работает только на компьютере.</div></div>
  <div style="text-align:center">${s.on?`<div style="background:#fff;border-radius:18px;padding:10px;display:inline-block;box-shadow:0 0 40px rgba(139,92,246,.35)">${s.qr}</div>
   <div class="pmsg" style="margin-top:8px;max-width:300px;word-break:break-all"><code>${esc(s.url)}</code></div>
   <div class="pmsg">Телефонов в аккаунте: ${s.phones}</div>`:`<div class="empty" style="padding:30px 10px"><b>Доступ выключен</b>Включите, чтобы показать QR-код</div>`}</div></div>`);
 b.onclick=async e=>{const t=e.target;
  if(t.id==="lanon"){t.classList.add("loading");try{await api("lan",{action:s.on?"stop":"start"});openPhone()}catch(x){toast(x.message,"bad");t.classList.remove("loading")}}
  if(t.id==="lanrot"){if(!confirm("Сменить ключ? Телефоны выйдут из аккаунта, понадобится отсканировать новый QR-код."))return;await api("lan",{action:"rotate"});openPhone()}};
 b.querySelector("#lanauto").onchange=e=>api("lan",{action:"autostart",value:e.target.checked})}
$("#phoneb").onclick=openPhone;if(LANMODE)$("#phoneb").hidden=true;
$("#gchrono").onclick=chronoPanel;$("#gpuzzle").onclick=geoPuzzlePanel;$("#achb").onclick=openAch;$("#ancb").onclick=openAnchors;
$("#inter").onclick=openIntersections;$("#brandb").onclick=openBrand;$("#pbb").onclick=openPlaybooks;$("#aib").onclick=openAi;
setInterval(async()=>{if(!ME)return;try{const n=await api("notifications");if(n.length){n.forEach(x=>toast("🔔 "+x.text,"ok"));refresh()}}catch(x){}},20000);
window.addEventListener("load",showAuth);
</script></body></html>
"""

if __name__ == "__main__":
    main()
