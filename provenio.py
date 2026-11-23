#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Provenio - платформа доказательной OSINT-аналитики (MVP).

Что умеет:
  * Кейсы и источники (URL) с авто-архивацией: снимок HTML, SHA-256, время, статус
  * Автоизвлечение сущностей: email, телефоны, домены, IP, аккаунты соцсетей
  * Граф связей "источник - сущность"
  * Оценка достоверности факта: по числу независимых доменов и надёжности источников
  * Журнал аудита с хэш-цепочкой (нельзя незаметно изменить историю)
  * Проверка целостности снимков и экспорт HTML-отчёта

Только стандартная библиотека Python 3.9+. Запуск: python provenio.py
Используйте только для публичных данных и в рамках закона.
"""
import sqlite3
import hashlib
import re
import os
import sys
import threading
import ipaddress
import math
import random
import html
import webbrowser
import datetime as dt
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser

APP_NAME = "Provenio"
BASE_DIR = os.path.dirname(sys.executable if getattr(sys, "frozen", False)
                           else os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "provenio_data")
SNAP_DIR = os.path.join(DATA_DIR, "snapshots")
DB_PATH = os.path.join(DATA_DIR, "provenio.db")
USER_AGENT = "Mozilla/5.0 (compatible; Provenio/1.0; +OSINT-research)"
MAX_BYTES = 5 * 1024 * 1024

SOCIAL = {
    "twitter.com": "twitter", "x.com": "twitter", "github.com": "github",
    "t.me": "telegram", "linkedin.com": "linkedin", "facebook.com": "facebook",
    "instagram.com": "instagram", "youtube.com": "youtube", "vk.com": "vk",
    "tiktok.com": "tiktok", "reddit.com": "reddit",
}
GENERIC_SEGMENTS = {"", "share", "intent", "sharer", "sharer.php", "home", "login",
                    "in", "company", "watch", "hashtag", "search", "explore", "u", "user", "r"}

RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
RE_PHONE = re.compile(r"\+\d[\d\s().\-]{8,16}\d")
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ----------------------------------------------------------------- утилиты
def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def host_of(url):
    h = urllib.parse.urlparse(url).netloc.lower().split("@")[-1].split(":")[0]
    return h[4:] if h.startswith("www.") else h


def normalize_url(url):
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


# ----------------------------------------------------------------- разбор HTML
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.text = []
        self.links = []
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._skip:
            self.text.append(data)


def extract_entities(html_text, base_url):
    """Возвращает набор (тип, значение) и заголовок страницы."""
    p = PageParser()
    try:
        p.feed(html_text)
    except Exception:
        pass
    text = " ".join(p.text)
    found = set()

    for m in RE_EMAIL.findall(text):
        found.add(("email", m.lower().strip(".")))
    for href in p.links:
        if href.lower().startswith("mailto:"):
            addr = href[7:].split("?")[0].strip().lower()
            if RE_EMAIL.fullmatch(addr):
                found.add(("email", addr))
    for m in RE_PHONE.findall(text):
        digits = re.sub(r"\D", "", m)
        if 10 <= len(digits) <= 15:
            found.add(("phone", "+" + digits))
    for m in RE_IP.findall(text):
        try:
            ip = ipaddress.ip_address(m)
            if ip.is_global:
                found.add(("ip", m))
        except ValueError:
            pass

    own = host_of(base_url)
    found.add(("domain", own))
    for href in p.links:
        full = urllib.parse.urljoin(base_url, href)
        pr = urllib.parse.urlparse(full)
        if pr.scheme not in ("http", "https"):
            continue
        h = host_of(full)
        if not h or h == own:
            continue
        if h in SOCIAL:
            seg = pr.path.strip("/").split("/")[0].lstrip("@")
            if seg.lower() not in GENERIC_SEGMENTS:
                found.add(("account", f"{SOCIAL[h]}:{seg}"))
        else:
            found.add(("domain", h))
    return found, " ".join(p.title.split())[:300]


# ----------------------------------------------------------------- хранилище
class Store:
    def __init__(self, path=DB_PATH, snap_dir=SNAP_DIR):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.makedirs(snap_dir, exist_ok=True)
        self.snap_dir = snap_dir
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, name TEXT UNIQUE, created TEXT);
        CREATE TABLE IF NOT EXISTS sources(
            id INTEGER PRIMARY KEY, case_id INTEGER, url TEXT, final_url TEXT,
            fetched TEXT, status TEXT, title TEXT, sha256 TEXT, size INTEGER,
            snapshot TEXT, reliability INTEGER DEFAULT 3, note TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS entities(
            id INTEGER PRIMARY KEY, case_id INTEGER, type TEXT, value TEXT,
            UNIQUE(case_id, type, value));
        CREATE TABLE IF NOT EXISTS links(
            entity_id INTEGER, source_id INTEGER, PRIMARY KEY(entity_id, source_id));
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY, ts TEXT, action TEXT, detail TEXT,
            prev TEXT, hash TEXT);
        """)
        self.db.commit()

    # --- аудит с хэш-цепочкой
    def audit(self, action, detail=""):
        with self.lock:
            row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else "GENESIS"
            ts = now_iso()
            h = sha256_bytes(f"{prev}|{ts}|{action}|{detail}".encode())
            self.db.execute("INSERT INTO audit(ts,action,detail,prev,hash) VALUES(?,?,?,?,?)",
                            (ts, action, detail, prev, h))
            self.db.commit()

    def verify_audit(self):
        prev = "GENESIS"
        for r in self.db.execute("SELECT * FROM audit ORDER BY id"):
            expect = sha256_bytes(f"{prev}|{r['ts']}|{r['action']}|{r['detail']}".encode())
            if r["prev"] != prev or r["hash"] != expect:
                return False, r["id"]
            prev = r["hash"]
        return True, None

    # --- кейсы
    def cases(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM cases ORDER BY id")]

    def add_case(self, name):
        with self.lock:
            cur = self.db.execute("INSERT OR IGNORE INTO cases(name,created) VALUES(?,?)",
                                  (name, now_iso()))
            self.db.commit()
            cid = self.db.execute("SELECT id FROM cases WHERE name=?", (name,)).fetchone()["id"]
            if cur.rowcount:
                self.audit("case_created", name)
            return cid

    # --- источники
    def fetch(self, url):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   "Accept": "text/html,*/*;q=0.8"})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = r.read(MAX_BYTES + 1)
            charset = r.headers.get_content_charset() or "utf-8"
            return r.status, r.geturl(), data[:MAX_BYTES], charset

    def add_source(self, case_id, url):
        url = normalize_url(url)
        fetched = now_iso()
        try:
            status, final, data, charset = self.fetch(url)
            digest = sha256_bytes(data)
            fname = f"{digest[:16]}.html"
            with open(os.path.join(self.snap_dir, fname), "wb") as f:
                f.write(data)
            text = data.decode(charset, errors="replace")
            ents, title = extract_entities(text, final)
            status_s, size, snap = f"OK {status}", len(data), fname
        except Exception as e:  # сеть, SSL, таймаут, HTTP-ошибка
            final, digest, size, snap, title, ents = url, "", 0, "", "", set()
            status_s = f"ERR: {type(e).__name__} {str(e)[:80]}"
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO sources(case_id,url,final_url,fetched,status,title,sha256,size,snapshot)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (case_id, url, final, fetched, status_s, title, digest, size, snap))
            sid = cur.lastrowid
            for t, v in ents:
                self.db.execute("INSERT OR IGNORE INTO entities(case_id,type,value) VALUES(?,?,?)",
                                (case_id, t, v))
                eid = self.db.execute(
                    "SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, t, v)).fetchone()["id"]
                self.db.execute("INSERT OR IGNORE INTO links VALUES(?,?)", (eid, sid))
            self.db.commit()
            self.audit("source_added", f"{url} | {status_s} | sha256={digest or '-'}")
        return sid, status_s

    def sources(self, case_id):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM sources WHERE case_id=? ORDER BY id", (case_id,))]

    def update_source(self, sid, reliability=None, note=None):
        with self.lock:
            if reliability is not None:
                self.db.execute("UPDATE sources SET reliability=? WHERE id=?", (reliability, sid))
            if note is not None:
                self.db.execute("UPDATE sources SET note=? WHERE id=?", (note, sid))
            self.db.commit()
            self.audit("source_updated", f"id={sid} reliability={reliability} note={note}")

    def delete_source(self, sid):
        with self.lock:
            self.db.execute("DELETE FROM links WHERE source_id=?", (sid,))
            self.db.execute("DELETE FROM sources WHERE id=?", (sid,))
            self.db.commit()
            self.audit("source_deleted", f"id={sid}")

    def verify_snapshots(self, case_id):
        bad, ok = [], 0
        for s in self.sources(case_id):
            if not s["snapshot"]:
                continue
            p = os.path.join(self.snap_dir, s["snapshot"])
            try:
                with open(p, "rb") as f:
                    good = sha256_bytes(f.read()) == s["sha256"]
            except OSError:
                good = False
            ok += good
            if not good:
                bad.append(s["url"])
        return ok, bad

    # --- сущности и достоверность
    def entities(self, case_id):
        out = []
        rows = self.db.execute("SELECT * FROM entities WHERE case_id=? ORDER BY type,value",
                               (case_id,)).fetchall()
        for e in rows:
            srcs = [dict(r) for r in self.db.execute(
                "SELECT s.* FROM sources s JOIN links l ON l.source_id=s.id "
                "WHERE l.entity_id=?", (e["id"],))]
            out.append({"id": e["id"], "type": e["type"], "value": e["value"],
                        "sources": srcs, "confidence": confidence(srcs)})
        return out


def confidence(sources):
    """Достоверность 0-100: независимые домены с учётом надёжности источника.
    Один домен считается один раз (берём максимальную надёжность)."""
    best = {}
    for s in sources:
        h = host_of(s["final_url"] or s["url"])
        best[h] = max(best.get(h, 0), s["reliability"] or 3)
    miss = 1.0
    for rel in best.values():
        miss *= 1 - 0.15 * rel       # надёжность 1..5 -> вклад 15%..75%
    return round((1 - miss) * 100)


def label(score):
    return "высокая" if score >= 75 else "средняя" if score >= 45 else "низкая"


# ----------------------------------------------------------------- отчёт
def build_report(store, case):
    srcs, ents = store.sources(case["id"]), store.entities(case["id"])
    ok, bad = store.verify_snapshots(case["id"])
    chain_ok, broken = store.verify_audit()
    e = html.escape
    rows_s = "".join(
        f"<tr><td>{s['id']}</td><td>{e(s['url'])}<br><small>{e(s['title'])}</small></td>"
        f"<td>{e(s['fetched'])}</td><td>{e(s['status'])}</td><td>{s['reliability']}/5</td>"
        f"<td><code>{e(s['sha256'])}</code></td><td>{e(s['note'])}</td></tr>" for s in srcs)
    rows_e = "".join(
        f"<tr><td>{e(x['type'])}</td><td>{e(x['value'])}</td>"
        f"<td>{x['confidence']}% ({label(x['confidence'])})</td>"
        f"<td>{', '.join('#' + str(s['id']) for s in x['sources'])}</td></tr>"
        for x in sorted(ents, key=lambda x: -x["confidence"]))
    return f"""<!doctype html><html lang="ru"><meta charset="utf-8">
<title>Provenio: {e(case['name'])}</title><style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:30px auto;padding:0 16px;color:#222}}
table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border:1px solid #ccc;padding:6px;
vertical-align:top;text-align:left}}th{{background:#f0f2f5}}code{{font-size:11px;word-break:break-all}}
.ok{{color:#0a7d33}}.bad{{color:#b00020}}</style>
<h1>Отчёт Provenio: {e(case['name'])}</h1>
<p>Создан: {e(now_iso())}. Кейс открыт: {e(case['created'])}.</p>
<p>Целостность снимков: <b class="{'ok' if not bad else 'bad'}">{ok} подтверждено, {len(bad)} нарушено</b>.
Журнал аудита: <b class="{'ok' if chain_ok else 'bad'}">{'цепочка цела' if chain_ok else f'нарушена в записи {broken}'}</b>.</p>
<h2>Источники</h2><table><tr><th>#</th><th>URL</th><th>Получен</th><th>Статус</th>
<th>Надёжность</th><th>SHA-256 снимка</th><th>Заметка</th></tr>{rows_s}</table>
<h2>Сущности и достоверность</h2><table><tr><th>Тип</th><th>Значение</th><th>Достоверность</th>
<th>Источники</th></tr>{rows_e}</table>
<p><small>Достоверность рассчитана по числу независимых доменов и оценке надёжности источников.
Это вспомогательная оценка, а не окончательный вывод: проверяйте факты вручную.</small></p></html>"""


# ----------------------------------------------------------------- граф
def layout(nodes, edges, w, h, iters=200):
    """Простая силовая раскладка (Fruchterman-Reingold)."""
    random.seed(1)
    pos = {n: [random.uniform(0.2, 0.8) * w, random.uniform(0.2, 0.8) * h] for n in nodes}
    if len(nodes) < 2:
        return pos
    k = math.sqrt(w * h / len(nodes)) * 0.8
    t = w / 8
    for _ in range(iters):
        disp = {n: [0.0, 0.0] for n in nodes}
        names = list(nodes)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = math.hypot(dx, dy) or 0.01
                f = k * k / d
                disp[a][0] += dx / d * f; disp[a][1] += dy / d * f
                disp[b][0] -= dx / d * f; disp[b][1] -= dy / d * f
        for a, b in edges:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = math.hypot(dx, dy) or 0.01
            f = d * d / k
            disp[a][0] -= dx / d * f; disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f; disp[b][1] += dy / d * f
        for n in names:
            dx, dy = disp[n]
            d = math.hypot(dx, dy) or 0.01
            pos[n][0] = min(w - 30, max(30, pos[n][0] + dx / d * min(d, t)))
            pos[n][1] = min(h - 30, max(30, pos[n][1] + dy / d * min(d, t)))
        t *= 0.97
    return pos


# ----------------------------------------------------------------- интерфейс
def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, simpledialog

    store = Store()
    root = tk.Tk()
    root.title(f"{APP_NAME} - OSINT с доказательной базой")
    root.geometry("1180x720")
    state = {"case": None}

    # верхняя панель
    top = ttk.Frame(root, padding=6)
    top.pack(fill="x")
    ttk.Label(top, text="Кейс:").pack(side="left")
    case_var = tk.StringVar()
    case_box = ttk.Combobox(top, textvariable=case_var, state="readonly", width=28)
    case_box.pack(side="left", padx=4)
    url_var = tk.StringVar()
    url_entry = ttk.Entry(top, textvariable=url_var, width=55)
    status_var = tk.StringVar(value="Создайте кейс и добавьте URL источника.")

    def cases_by_name():
        return {c["name"]: c for c in store.cases()}

    def refresh_cases(select=None):
        names = list(cases_by_name().keys())
        case_box["values"] = names
        if select:
            case_var.set(select)
        elif names and not case_var.get():
            case_var.set(names[0])
        on_case()

    def new_case():
        name = simpledialog.askstring(APP_NAME, "Название кейса:", parent=root)
        if name and name.strip():
            store.add_case(name.strip())
            refresh_cases(name.strip())

    def on_case(*_):
        state["case"] = cases_by_name().get(case_var.get())
        refresh_all()

    ttk.Button(top, text="Новый кейс", command=new_case).pack(side="left")
    ttk.Label(top, text="   URL:").pack(side="left")
    url_entry.pack(side="left", padx=4)
    case_box.bind("<<ComboboxSelected>>", on_case)

    def add_urls(urls):
        c = state["case"]
        if not c:
            messagebox.showinfo(APP_NAME, "Сначала создайте кейс.")
            return
        urls = [u for u in urls if u.strip()]
        if not urls:
            return
        add_btn.config(state="disabled")

        def work():
            res = []
            for u in urls:
                _, st = store.add_source(c["id"], u)
                res.append(st)
                root.after(0, status_var.set, f"Обработано {len(res)}/{len(urls)}: {st}")
            root.after(0, lambda: (add_btn.config(state="normal"), refresh_all()))
        threading.Thread(target=work, daemon=True).start()

    def add_one():
        add_urls([url_var.get()])
        url_var.set("")

    def add_many():
        dlg = tk.Toplevel(root)
        dlg.title("Список URL (по одному в строке)")
        txt = tk.Text(dlg, width=70, height=15)
        txt.pack(padx=8, pady=8)

        def go():
            lines = txt.get("1.0", "end").splitlines()
            dlg.destroy()
            add_urls(lines)
        ttk.Button(dlg, text="Добавить все", command=go).pack(pady=6)

    add_btn = ttk.Button(top, text="Добавить и заархивировать", command=add_one)
    add_btn.pack(side="left")
    ttk.Button(top, text="Список URL...", command=add_many).pack(side="left", padx=4)
    url_entry.bind("<Return>", lambda e: add_one())

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=6, pady=4)

    # --- вкладка: источники
    f_src = ttk.Frame(nb)
    nb.add(f_src, text="Источники")
    cols = ("id", "url", "fetched", "status", "rel", "sha")
    tv_s = ttk.Treeview(f_src, columns=cols, show="headings", height=18)
    for c, t, w in (("id", "#", 40), ("url", "URL / заголовок", 430), ("fetched", "Получен", 160),
                    ("status", "Статус", 120), ("rel", "Надёжн.", 60), ("sha", "SHA-256", 300)):
        tv_s.heading(c, text=t)
        tv_s.column(c, width=w, anchor="w")
    tv_s.pack(fill="both", expand=True)
    bar = ttk.Frame(f_src, padding=4)
    bar.pack(fill="x")
    rel_var = tk.IntVar(value=3)
    ttk.Label(bar, text="Надёжность (1-5):").pack(side="left")
    ttk.Spinbox(bar, from_=1, to=5, textvariable=rel_var, width=4).pack(side="left", padx=4)

    def selected_sid():
        sel = tv_s.selection()
        return int(tv_s.item(sel[0])["values"][0]) if sel else None

    def apply_rel():
        sid = selected_sid()
        if sid:
            store.update_source(sid, reliability=max(1, min(5, rel_var.get())))
            refresh_all()

    def edit_note():
        sid = selected_sid()
        if sid:
            note = simpledialog.askstring(APP_NAME, "Заметка к источнику:", parent=root)
            if note is not None:
                store.update_source(sid, note=note)
                refresh_all()

    def open_snapshot():
        sid = selected_sid()
        for s in store.sources(state["case"]["id"]):
            if s["id"] == sid and s["snapshot"]:
                webbrowser.open("file:///" + os.path.join(SNAP_DIR, s["snapshot"]).replace("\\", "/"))

    def del_src():
        sid = selected_sid()
        if sid and messagebox.askyesno(APP_NAME, "Удалить источник? Действие попадёт в журнал аудита."):
            store.delete_source(sid)
            refresh_all()

    for t, cmd in (("Применить", apply_rel), ("Заметка", edit_note),
                   ("Открыть снимок", open_snapshot), ("Удалить", del_src)):
        ttk.Button(bar, text=t, command=cmd).pack(side="left", padx=3)

    # --- вкладка: сущности
    f_ent = ttk.Frame(nb)
    nb.add(f_ent, text="Сущности")
    tv_e = ttk.Treeview(f_ent, columns=("type", "value", "conf", "src"), show="headings")
    for c, t, w in (("type", "Тип", 90), ("value", "Значение", 450),
                    ("conf", "Достоверность", 150), ("src", "Источники", 300)):
        tv_e.heading(c, text=t)
        tv_e.column(c, width=w, anchor="w")
    tv_e.pack(fill="both", expand=True)

    # --- вкладка: граф
    f_gr = ttk.Frame(nb)
    nb.add(f_gr, text="Граф связей")
    canvas = tk.Canvas(f_gr, bg="#fafbfc")
    canvas.pack(fill="both", expand=True)
    colors = {"email": "#e8710a", "phone": "#188038", "domain": "#1a73e8",
              "ip": "#9334e6", "account": "#d93025"}

    def draw_graph(_=None):
        canvas.delete("all")
        c = state["case"]
        if not c:
            return
        srcs, ents = store.sources(c["id"]), store.entities(c["id"])
        nodes, edges = {}, []
        for s in srcs:
            nodes[f"s{s['id']}"] = ("src", f"#{s['id']} {host_of(s['final_url'] or s['url'])}")
        multi = [e for e in ents if len(e["sources"]) > 1]
        shown = multi if len(ents) > 120 else ents   # при большом графе - только пересечения
        for e in shown:
            k = f"e{e['id']}"
            nodes[k] = (e["type"], e["value"][:28])
            for s in e["sources"]:
                edges.append((f"s{s['id']}", k))
        if not nodes:
            return
        w, h = max(canvas.winfo_width(), 600), max(canvas.winfo_height(), 400)
        pos = layout(nodes, edges, w, h)
        for a, b in edges:
            canvas.create_line(*pos[a], *pos[b], fill="#c4c7cc")
        for k, (t, name) in nodes.items():
            x, y = pos[k]
            if t == "src":
                canvas.create_rectangle(x - 9, y - 9, x + 9, y + 9, fill="#202124", outline="")
            else:
                canvas.create_oval(x - 7, y - 7, x + 7, y + 7, fill=colors.get(t, "#5f6368"), outline="")
            canvas.create_text(x, y + 17, text=name, font=("Segoe UI", 8))
        canvas.create_text(10, 10, anchor="nw", font=("Segoe UI", 8),
                           text="■ источник   ● сущность (цвет = тип)"
                                + ("   |  показаны только сущности из 2+ источников" if shown is multi else ""))

    canvas.bind("<Configure>", lambda e: root.after(200, draw_graph) if e.width > 50 else None)

    # --- вкладка: аудит
    f_au = ttk.Frame(nb)
    nb.add(f_au, text="Журнал аудита")
    tv_a = ttk.Treeview(f_au, columns=("id", "ts", "action", "detail", "hash"), show="headings")
    for c, t, w in (("id", "#", 40), ("ts", "Время", 150), ("action", "Действие", 120),
                    ("detail", "Детали", 560), ("hash", "Хэш", 200)):
        tv_a.heading(c, text=t)
        tv_a.column(c, width=w, anchor="w")
    tv_a.pack(fill="both", expand=True)

    def refresh_all():
        for tv in (tv_s, tv_e, tv_a):
            tv.delete(*tv.get_children())
        c = state["case"]
        if c:
            for s in store.sources(c["id"]):
                tv_s.insert("", "end", values=(
                    s["id"], (s["title"] + " | " if s["title"] else "") + s["url"],
                    s["fetched"], s["status"], s["reliability"], s["sha256"]))
            for e in sorted(store.entities(c["id"]), key=lambda x: -x["confidence"]):
                tv_e.insert("", "end", values=(
                    e["type"], e["value"], f"{e['confidence']}% ({label(e['confidence'])})",
                    ", ".join("#" + str(s["id"]) for s in e["sources"])))
        for r in store.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500"):
            tv_a.insert("", "end", values=(r["id"], r["ts"], r["action"], r["detail"], r["hash"][:24] + "..."))
        draw_graph()

    # нижняя панель
    bottom = ttk.Frame(root, padding=6)
    bottom.pack(fill="x")

    def verify():
        c = state["case"]
        if not c:
            return
        ok, bad = store.verify_snapshots(c["id"])
        chain, broken = store.verify_audit()
        msg = f"Снимки: {ok} целы, {len(bad)} нарушены.\n"
        msg += "Журнал аудита: цепочка цела." if chain else f"Журнал аудита нарушен в записи #{broken}!"
        if bad:
            msg += "\n\nНарушены:\n" + "\n".join(bad)
        messagebox.showinfo(APP_NAME, msg)

    def export():
        c = state["case"]
        if not c:
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", initialfile=f"provenio_{c['name']}.html",
                                            filetypes=[("HTML", "*.html")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(build_report(store, c))
            store.audit("report_exported", f"{c['name']} -> {path}")
            webbrowser.open("file:///" + path.replace("\\", "/"))
            refresh_all()

    ttk.Button(bottom, text="Проверить целостность", command=verify).pack(side="left")
    ttk.Button(bottom, text="Экспорт отчёта (HTML)", command=export).pack(side="left", padx=6)
    ttk.Label(bottom, textvariable=status_var).pack(side="left", padx=12)

    refresh_cases()
    root.mainloop()


if __name__ == "__main__":
    run_gui()
