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

S = P.Store()
LOCK = S.lock
TOKEN = secrets.token_urlsafe(24)
TL.configure(P.load_settings())
JOBS = {}
MAX_BODY = 45 * 1024 * 1024   # загрузка файлов для анализа метаданных / проверки пакета


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
                "note", "kind", "tool", "query", "parent_id")
        audit = [dict(r) for r in S.db.execute(
            "SELECT id,ts,action,detail,hash FROM audit ORDER BY id DESC LIMIT 300")]
    out_src = []
    for s in srcs:
        d = {k: s.get(k) for k in keys}
        m = mons.get(s["id"])
        d["monitor"] = {"interval": m["interval_min"], "last": m["last_check"], "changes": m["changes"]} if m else None
        d["versions"] = children.get(s["id"], 0)
        out_src.append(d)
    return {
        "sources": out_src,
        "entities": [{"id": e["id"], "type": e["type"], "value": e["value"],
                      "conf": e["confidence"], "src": [s["id"] for s in e["sources"]]} for e in ents],
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


def save_job(rec, case_id, pivot=None):
    if rec["state"] != "done":
        raise ValueError("Задача ещё не завершена")
    q = rec["q"] if rec["name"] not in ("file_meta", "evidence_verify") else \
        (rec["result"] or {}).get("name") or rec["q"] or "файл"
    sid, n = S.add_tool_result(case_id, rec["name"], q, rec["result"],
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
    while True:
        time.sleep(30)
        try:
            for sid in S.due_monitors():
                S.check_monitor(sid)
        except Exception:
            traceback.print_exc()


# ----------------------------------------------------------------- настройки
def settings_public():
    s = P.load_settings()
    keys = {k: (("•" * 6 + v[-4:]) if v else "") for k, v in s["keys"].items()}
    return {"proxy": s["proxy"], "timeout": s["timeout"], "keys": keys}


def settings_save(body):
    cur = P.load_settings()
    new_keys = dict(cur["keys"])
    for k, v in (body.get("keys") or {}).items():
        if v is None or (isinstance(v, str) and v.startswith("•")):
            continue   # поле не меняли
        new_keys[k] = str(v).strip()
    s = P.save_settings({"proxy": body.get("proxy", cur["proxy"]), "timeout": body.get("timeout", cur["timeout"]),
                         "keys": new_keys})
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
        sid, status = S.add_source(int(body["case"]), str(body["url"])[:2000])
        return {"id": sid, "status": status}
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
    if path == "info":
        return {"version": P.APP_VERSION, "data_dir": P.DATA_DIR, "frozen": P.FROZEN,
                "sites": len(TL.load_sites()), "tools": len(TL.TOOLS)}
    if path == "open_data_dir":
        if os.name == "nt":
            os.startfile(P.DATA_DIR)
        return {}
    raise KeyError(path)


def download(kind, cid):
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
    if kind == "evidence":
        data, mh = P.build_evidence_zip(S, c)
        return data, "application/zip", f"provenio_{safe}_evidence_{mh[:8]}.zip"
    raise KeyError(kind)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def out(self, code, body, ctype="application/json; charset=utf-8", headers=()):
        if ctype.startswith("application/json") and not isinstance(body, (bytes, str)):
            body = json.dumps(body, ensure_ascii=False, default=str)
        if isinstance(body, str):
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

    def authorized(self, q):
        tok = self.headers.get("X-Token") or (q.get("t") or [""])[0]
        return self.host_ok() and secrets.compare_digest(tok, TOKEN)

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
                return self.out(200, PAGE.replace("__TOKEN__", TOKEN).replace("__VER__", P.APP_VERSION),
                                "text/html; charset=utf-8")
            if not self.authorized(q):
                return self.out(403, {"error": "forbidden"})
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
                data, ctype, fname = download(u.path[10:], (q.get("case") or ["0"])[0])
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
                ctype = "text/plain; charset=utf-8" if name.endswith(".json") else "text/html"
                return self.out(200, data, ctype, [(
                    "Content-Security-Policy",
                    "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:")])
            self.out(404, {"error": "not found"})
        except Exception as e:
            traceback.print_exc()
            self.out(500, {"error": f"{type(e).__name__}: {e}"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


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
    handle = kernel32.CreateMutexW(None, False, "Local\\ProvenioOSINT_SingleInstance")
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
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Provenio</title>
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
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:rgba(168,130,255,.2);border-radius:9px}
::-webkit-scrollbar-thumb:hover{background:rgba(168,130,255,.35)}
</style></head><body>
<div class="bg"></div><div class="mesh"><i></i><i></i><i></i></div><div class="grain"></div>
<aside>
 <div class="logo"><b>◈</b><span>Provenio</span></div>
 <div class="cap">Кейсы</div>
 <div class="cases" id="cases"></div>
 <div class="newc"><input id="ncase" placeholder="Новый кейс"><button class="btn" id="addc">+</button></div>
 <div class="hint">Доказательная OSINT-аналитика.<br>Только публичные данные. Соблюдайте закон.</div>
 <div class="side-foot">
  <button class="ghost" id="set">⚙ Настройки и ключи API</button>
  <button class="ghost" id="ddir">📁 Папка данных</button>
  <span class="ver">Provenio __VER__</span>
 </div>
</aside>
<main>
 <header>
  <input class="grow" id="url" placeholder="Вставьте URL (можно несколько через пробел или запятую)…">
  <button class="btn" id="add">Архивировать</button>
  <button class="ghost" id="ver">Проверить</button>
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
  <button class="tab" data-t="tools">Инструменты</button>
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
 </div>
</main>
<div id="toasts"></div>
<script>
const T="__TOKEN__",$=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const TY={email:"#fb923c",phone:"#34d399",domain:"#60a5fa",ip:"#c084fc",account:"#f87171",src:"#e5e7eb"};
const TL={email:"Email",phone:"Телефон",domain:"Домен",ip:"IP",account:"Аккаунт"};
let cases=[],cur=null,st=null,tab="src",ef="all",eq="";
const host=u=>{try{return new URL(u).hostname.replace(/^www\./,"")}catch(e){return u}};
async function api(p,b){const r=await fetch("/api/"+p,{method:b?"POST":"GET",headers:{"X-Token":T,"Content-Type":"application/json"},
 body:b?JSON.stringify(b):undefined});const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
function toast(m,k){const t=document.createElement("div");t.className="toast "+(k||"");t.textContent=m;$("#toasts").append(t);
 setTimeout(()=>{t.classList.add("out");setTimeout(()=>t.remove(),400)},3600)}
function num(el,to){const f=+el.dataset.v||0;el.dataset.v=to;const t0=performance.now();
 (function s(t){const p=Math.min(1,(t-t0)/850),e=1-Math.pow(1-p,3);el.textContent=Math.round(f+(to-f)*e);if(p<1)requestAnimationFrame(s)})(t0)}
function moveInk(){const b=$(".tab.on"),k=$("#ink");if(!b)return;k.style.width=b.offsetWidth+"px";k.style.transform="translateX("+(b.offsetLeft-28)+"px)"}
function setTab(t){tab=t;$$(".tab").forEach(b=>b.classList.toggle("on",b.dataset.t===t));
 $$(".panel").forEach(p=>p.classList.toggle("on",p.id==="p-"+t));moveInk();if(t==="graph")setTimeout(sizeCv,30);if(t==="time")renderTimeline()}
$$(".tab").forEach(b=>b.onclick=()=>setTab(b.dataset.t));

function renderCases(){$("#cases").innerHTML=cases.map((c,i)=>`<div class="case ${cur&&cur.id===c.id?"on":""}" data-id="${c.id}" style="animation-delay:${i*40}ms">${esc(c.name)}</div>`).join("")||'<div class="mu" style="padding:8px;color:var(--mu2)">Создайте первый кейс ↓</div>'}
$("#cases").onclick=e=>{const d=e.target.closest(".case");if(d){cur=cases.find(c=>c.id==d.dataset.id);renderCases();refresh()}};
async function loadCases(sel){cases=await api("cases");cur=cases.find(c=>c.id===sel)||cur||cases[0]||null;renderCases();if(cur)refresh();else render()}
$("#addc").onclick=async()=>{const n=$("#ncase").value.trim();if(!n)return;try{const r=await api("case",{name:n});$("#ncase").value="";await loadCases(r.id);toast("Кейс создан","ok")}catch(e){toast(e.message,"bad")}};
$("#ncase").onkeydown=e=>{if(e.key==="Enter")$("#addc").click()};

async function refresh(){if(!cur)return;st=await api("state?case="+cur.id);render()}
function render(){
 if(!st||!cur){$("#p-src").innerHTML='<div class="empty"><b>Нет активного кейса</b>Создайте кейс слева и добавьте первый URL</div>';return}
 const E=st.entities,multi=E.filter(e=>e.src.length>1).length,avg=E.length?Math.round(E.reduce((a,e)=>a+e.conf,0)/E.length):0;
 num($("#n1"),st.sources.length);num($("#n2"),E.length);num($("#n3"),multi);num($("#n4"),avg);
 const i=st.integrity,good=!i.snap_bad&&i.chain;$("#pill").className="pill "+(good?"ok":"bad");
 $("#pill").textContent=good?"целостность подтверждена":"целостность нарушена";
 $("#p-src").innerHTML=st.sources.map((s,i)=>{const tool=s.kind==="tool",tn=tool?(TOOLS.find(t=>t.id===s.tool)||{}).tn||s.tool:"";
  return `<div class="card src ${tool?"kind-tool":""}" style="--i:${Math.min(i,30)}"><div class="row"><div class="grow">
  <div class="ttl">${tool?'<span class="badge">🛠 '+esc(tn)+'</span> '+esc(s.query||""):esc(s.title||host(s.url))}
   ${s.parent_id?'<span class="badge">версия #'+s.parent_id+'</span>':""}${s.monitor?'<span class="badge mon">👁 каждые '+s.monitor.interval+' мин · изменений: '+s.monitor.changes+'</span>':""}</div>
  ${tool?`<span class="url" style="color:var(--mu)">${esc(s.url)}</span>`:`<a class="url" href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.url)}</a>`}</div>
  <span class="chip ${s.status.startsWith("OK")?"ok":"bad"}">${esc(s.status.slice(0,34))}</span></div>
  <div class="meta"><span>#${s.id}</span><span>${esc(s.fetched)}</span><span>${(s.size/1024).toFixed(1)} KB</span>
  <span class="sha" data-c="${esc(s.sha256)}" title="Копировать SHA-256">${esc(s.sha256?s.sha256.slice(0,24)+"…":"нет снимка")}</span>
  ${s.versions?`<span>версий: ${s.versions}</span>`:""}</div>
  <div class="row"><div class="seg" data-id="${s.id}" title="Надёжность источника">${[1,2,3,4,5].map(n=>`<button data-r="${n}" class="${n<=s.reliability?"on":""}">${n}</button>`).join("")}</div>
  <input class="note" data-id="${s.id}" placeholder="Заметка…" value="${esc(s.note)}">
  ${s.snapshot?`<a class="ghost" target="_blank" href="/snapshot/${encodeURIComponent(s.snapshot)}?t=${T}">${tool?"JSON":"Снимок"}</a>`:""}
  ${!tool&&!s.parent_id?`<button class="ghost mon ${s.monitor?"on":""}" data-id="${s.id}">${s.monitor?"👁 Слежу":"👁 Следить"}</button>`:""}
  ${s.monitor?`<button class="ghost chk" data-id="${s.id}">Проверить сейчас</button>`:""}
  ${s.versions||s.parent_id?`<button class="ghost vers" data-id="${s.id}">Версии и сравнение</button>`:""}
  <button class="ghost del" data-id="${s.id}">Удалить</button></div></div>`}).join("")||'<div class="empty"><b>Источников пока нет</b>Вставьте URL в поле сверху и нажмите «Архивировать» — или сохраните в кейс результат любого инструмента</div>';
 renderEnts();
 $("#tl").innerHTML=st.audit.map((a,i)=>`<div class="ev2" style="--i:${Math.min(i,20)}"><b>${esc(a.action)}</b> <span style="color:var(--mu)">${esc(a.ts)}</span><br>${esc(a.detail)}<br><small>${esc(a.hash)}</small></div>`).join("");
 buildGraph();moveInk();if(tab==="time")renderTimeline()}
$("#p-src").onclick=async e=>{const b=e.target.closest("button,.sha")||e.target;
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
 return `<div class="ent" style="--i:${Math.min(i,25)}"><span class="dot" style="background:${TY[e.type]};color:${TY[e.type]}"></span><span style="color:var(--mu)">${TL[e.type]||e.type}</span>
 <span class="ev" title="${esc(e.value)}">${esc(e.value)}</span><div class="bar"><i data-w="${e.conf}" style="background:linear-gradient(90deg,${g})"></i></div><b>${e.conf}%</b><span style="color:var(--mu)">${e.src.length} ист.</span></div>`}).join("")||'<div class="empty">Ничего не найдено</div>';
 requestAnimationFrame(()=>requestAnimationFrame(()=>$$(".bar i").forEach(b=>b.style.width=b.dataset.w+"%")));
 const q=$("#eq");if(q)q.oninput=()=>{eq=q.value.toLowerCase();const p=q.selectionStart;renderEnts();const n=$("#eq");n.focus();n.setSelectionRange(p,p)}}
$("#chips").onclick=e=>{const c=e.target.closest(".fc");if(c){ef=c.dataset.t;renderEnts()}};

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
function nearest(x,y){let b=null,bd=1e9;for(const n of G.nodes){const d=Math.hypot(n.x-x,n.y-y);if(d<15&&d<bd){b=n;bd=d}}return b}
const pt=e=>{const r=cv.getBoundingClientRect();return[e.clientX-r.left,e.clientY-r.top]};
let downAt=null;
cv.onmousedown=e=>{const[x,y]=pt(e);downAt=[e.clientX,e.clientY];G.drag=nearest(x,y);if(G.drag)cv.style.cursor="grabbing"};
window.addEventListener("mouseup",e=>{const n=G.drag;G.drag=null;cv.style.cursor="grab";
 if(n&&downAt&&Math.hypot(e.clientX-downAt[0],e.clientY-downAt[1])<5)pivotMenu(n,e.clientX,e.clientY);downAt=null});
cv.onmousemove=e=>{const[x,y]=pt(e);if(G.drag){G.drag.x=x;G.drag.y=y;G.drag.vx=G.drag.vy=0}G.hover=nearest(x,y)};
cv.onmouseleave=()=>G.hover=null;
function tick(){requestAnimationFrame(tick);if(tab!=="graph"||!W)return;const N=G.nodes;
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
requestAnimationFrame(tick);

/* =================== ПИВОТЫ (Maltego-подобно) =================== */
const PIVOTS={
 domain:["site_recon","dns","whois","subdomains","harvester","lookalikes","tracking","domain_history","reputation","email_sec","wayback_urls","secrets"],
 ip:["ip_info","internetdb","asn","reputation","reverse_dns","reverse_ip"],
 email:["email","reputation"],
 phone:["phone"],
 account:["username","github","telegram"]};
function pivotMenu(n,x,y){
 if(n.t==="src"){const s=st.sources.find(s=>"s"+s.id===n.id);if(s&&s.snapshot)window.open("/snapshot/"+encodeURIComponent(s.snapshot)+"?t="+T,"_blank");return}
 const e=st.entities.find(e=>"e"+e.id===n.id);if(!e)return;
 let q=e.value,list=PIVOTS[e.type]||[];
 if(e.type==="account"){const[net,name]=e.value.split(":");q=name;list=net==="github"?["github","username"]:net==="telegram"?["telegram","username"]:["username"]}
 if(e.type==="email")list=list.concat([["domain",e.value.split("@")[1]]]);
 const items=[[`${TL[e.type]||e.type}: ${e.value}`,null]];
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
 if(fi&&fi.files[0]&&(!q||q.startsWith("📎"))){try{body.file=await readFile(fi.files[0]);body.filename=fi.files[0].name;body.q=fi.files[0].name}catch(x){return toast(x.message,"bad")}}
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
function dl(kind){if(!cur)return;const a=document.createElement("a");a.href=`/download/${kind}?case=${cur.id}&t=${T}`;
 if(kind==="report")a.target="_blank";else a.download="";document.body.append(a);a.click();a.remove();setTimeout(refresh,800)}
$("#rep").onclick=e=>{e.stopPropagation();if(!cur)return toast("Сначала выберите кейс","bad");const r=e.target.getBoundingClientRect();
 showMenu(r.left,r.bottom+6,[["Экспорт кейса",null],["📄 Отчёт HTML (откроется в браузере)",()=>dl("report")],["🧾 Пакет доказательств ZIP",()=>dl("evidence")],
  ["{ } Весь кейс JSON",()=>dl("json")],["📊 Сущности CSV (Excel)",()=>dl("csv")]])};
$("#cmp").onclick=openCompare;
$("#ddir").onclick=async()=>{const i=await api("info");try{await api("open_data_dir",{})}catch(x){}toast("Данные: "+i.data_dir,"ok")};
$("#set").onclick=openSettings;
const KEYN={shodan:"Shodan",virustotal:"VirusTotal",abuseipdb:"AbuseIPDB",urlscan:"urlscan.io",otx:"AlienVault OTX",github:"GitHub token"};
async function openSettings(){const s=await api("settings"),i=await api("info");
 const b=modal("Настройки",`<div class="hint" style="margin-bottom:10px">Все ключи необязательны: без них работают бесплатные источники. Ключи хранятся только на этом компьютере,
  зашифрованные средствами Windows (DPAPI) — их может расшифровать только ваша учётная запись.</div>
  <div class="frow"><label>Прокси (HTTP/HTTPS)</label><input id="sproxy" placeholder="http://127.0.0.1:8080" value="${esc(s.proxy)}"></div>
  <div class="frow"><label>Таймаут запросов, с</label><input id="stime" type="number" min="5" max="120" value="${esc(s.timeout)}"></div>
  ${Object.keys(KEYN).map(k=>`<div class="frow"><label>${KEYN[k]}</label><input data-k="${k}" class="skey" placeholder="не задан" value="${esc(s.keys[k]||"")}"></div>`).join("")}
  <div class="row" style="margin-top:14px"><button class="btn" id="ssave">Сохранить</button><span class="pmsg">Provenio ${esc(i.version)} · инструментов: ${i.tools} · сайтов для поиска по нику: ${i.sites}<br>Данные: ${esc(i.data_dir)}</span></div>`);
 b.querySelector("#ssave").onclick=async()=>{const keys={};b.querySelectorAll(".skey").forEach(x=>keys[x.dataset.k]=x.value);
  try{await api("settings",{proxy:b.querySelector("#sproxy").value,timeout:+b.querySelector("#stime").value||15,keys});toast("Настройки сохранены","ok");closeModal()}catch(x){toast(x.message,"bad")}}}
setInterval(async()=>{try{const n=await api("notifications");if(n.length){n.forEach(x=>toast("🔔 "+x.text,"ok"));refresh()}}catch(x){}},20000);
window.addEventListener("load",()=>{renderTools();moveInk();sizeCv();loadCases()});
</script></body></html>
"""

if __name__ == "__main__":
    main()
