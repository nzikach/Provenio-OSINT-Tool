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
import io
import sys
import json
import time
import shutil
import zipfile
import difflib
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
APP_VERSION = "3.0.0"
FROZEN = getattr(sys, "frozen", False)
BASE_DIR = os.path.dirname(sys.executable if FROZEN else os.path.abspath(__file__))
# каталог с ресурсами (в exe PyInstaller распаковывает их во временную папку)
RES_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


PORTABLE_MARK = os.path.join(BASE_DIR, "portable.txt")
PORTABLE_DIR = os.path.join(BASE_DIR, "ProvenioData")


def _default_data_dir():
    """Данные храним в профиле пользователя: exe может лежать в Program Files,
    куда писать нельзя. PROVENIO_DATA позволяет переопределить путь (тесты).
    Портативный режим: файл portable.txt рядом с exe — данные в папке ProvenioData рядом."""
    env = os.environ.get("PROVENIO_DATA")
    if env:
        return env
    if os.path.isfile(PORTABLE_MARK):
        return PORTABLE_DIR
    root = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(root, APP_NAME)


DATA_DIR = _default_data_dir()
PORTABLE = os.path.abspath(DATA_DIR) == os.path.abspath(PORTABLE_DIR)
LEGACY_DIR = os.path.join(BASE_DIR, "provenio_data")   # где данные лежали в версии 1.x
SNAP_DIR = os.path.join(DATA_DIR, "snapshots")
DB_PATH = os.path.join(DATA_DIR, "provenio.db")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
USER_AGENT = f"Mozilla/5.0 (compatible; Provenio/{APP_VERSION}; +OSINT-research)"
MAX_BYTES = 5 * 1024 * 1024


def migrate_legacy():
    """Однократно копирует данные версии 1.x (рядом со скриптом) в новый каталог.
    Копируем, а не переносим: старая папка остаётся нетронутой как резервная."""
    if PORTABLE or os.path.exists(DB_PATH) or not os.path.isfile(os.path.join(LEGACY_DIR, "provenio.db")):
        return False
    if os.path.abspath(LEGACY_DIR) == os.path.abspath(DATA_DIR):
        return False
    shutil.copytree(LEGACY_DIR, DATA_DIR, dirs_exist_ok=True)
    return True

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
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
# «домены», которые на деле расширения файлов, и служебные сервисы самих инструментов
FILE_EXT = {"js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "json", "html", "htm",
            "php", "asp", "aspx", "jsp", "xml", "txt", "pdf", "zip", "gz", "rar", "exe", "dll", "py",
            "md", "csv", "log", "bak", "sql", "env", "map", "woff", "woff2", "ttf", "mp4", "mp3", "doc",
            "docx", "xls", "xlsx", "ppt", "pptx", "yml", "yaml", "ini", "conf", "cfg", "sh", "bat", "local"}
SERVICE_HOSTS = {"shodan.io", "google.com", "lens.google.com", "bing.com", "yandex.com", "yandex.ru",
                 "tineye.com", "archive.org", "web.archive.org", "crt.sh", "gravatar.com",
                 "builtwith.com", "publicwww.com", "virustotal.com", "urlscan.io", "otx.alienvault.com",
                 "nvd.nist.gov", "blockstream.info", "eth.blockscout.com", "stat.ripe.net",
                 "internetdb.shodan.io", "rdap.org", "cloudflare-dns.com", "api.github.com",
                 "spyonweb.com", "dnslytics.com", "hackertarget.com", "api.hackertarget.com"}


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
        if host_of(full) != own:
            found |= url_entities(full)
    return found, " ".join(p.title.split())[:300]


def url_entities(url):
    """Сущности из одного URL: аккаунт соцсети или домен."""
    pr = urllib.parse.urlparse(url)
    if pr.scheme not in ("http", "https"):
        return set()
    h = host_of(url)
    if not h:
        return set()
    if h in SOCIAL:
        seg = pr.path.strip("/").split("/")[0].lstrip("@")
        if seg and seg.lower() not in GENERIC_SEGMENTS:
            return {("account", f"{SOCIAL[h]}:{seg}")}
        return set()
    if h in SERVICE_HOSTS or any(h.endswith("." + s) for s in SERVICE_HOSTS):
        return set()
    try:
        ipaddress.ip_address(h)
        return {("ip", h)}
    except ValueError:
        return {("domain", h)} if "." in h else set()


def _strings(data, out, limit=5000):
    """Все строковые значения из вложенной структуры (ключи не берём)."""
    if len(out) >= limit:
        return out
    if isinstance(data, dict):
        for v in data.values():
            _strings(v, out, limit)
    elif isinstance(data, (list, tuple)):
        for v in data:
            _strings(v, out, limit)
    elif isinstance(data, str):
        out.append(data)
    return out


def extract_entities_data(data, cap=500):
    """Сущности из результата инструмента (dict/list): email, IP, телефоны, домены, аккаунты."""
    found = set()
    for s in _strings(data, []):
        if len(found) >= cap:
            break
        low = s.lower()
        for m in RE_EMAIL.findall(s):
            found.add(("email", m.lower().strip(".")))
        for m in RE_URL.findall(s):
            found |= url_entities(m.rstrip(".,);]"))
        for m in RE_IP.findall(s):
            try:
                if ipaddress.ip_address(m).is_global:
                    found.add(("ip", m))
            except ValueError:
                pass
        if s.startswith("+") and RE_PHONE.fullmatch(s.strip()):
            found.add(("phone", "+" + re.sub(r"\D", "", s)))
        # «голые» домены — только если строка целиком похожа на хост
        cand = low.strip().rstrip(".")
        if len(cand) < 254 and RE_DOMAIN.fullmatch(cand):
            tld = cand.rsplit(".", 1)[-1]
            if tld not in FILE_EXT and cand not in SERVICE_HOSTS:
                found.add(("domain", cand[4:] if cand.startswith("www.") else cand))
    return found


# ----------------------------------------------------------------- защита от SQL-инъекций
# Все запросы Provenio параметризованы (значения передаются через «?», а не вставляются в текст).
# SafeConnection проверяет это на каждом вызове, поэтому ошибка в будущем коде не станет дырой:
#  * классическая/UNION/boolean/time-based инъекция — в тексте запроса запрещены строковые литералы,
#    комментарии и «;»: значение пользователя физически не может оказаться в SQL, только в параметрах;
#  * stacked queries (несколько команд через «;») — запрещены и sqlite3, и проверкой;
#  * second-order (вредная строка сначала сохраняется, потом попадает в запрос) — тоже только параметры;
#  * подмена типов — параметры только None/int/float/str/bytes, число «?» должно совпадать;
#  * ATTACH/DETACH чужой базы, PRAGMA, load_extension, DROP — блокирует авторизатор SQLite;
#  * подмена схемы (trusted_schema, defensive mode) — выключены опасные возможности ядра SQLite.
SQL_FORBIDDEN = re.compile(r"'|\"|--|/\*|\*/|;|\x00|\b(?:ATTACH|DETACH|PRAGMA|VACUUM|load_extension)\b", re.I)
SQL_PARAM_TYPES = (type(None), int, float, str, bytes)


class SQLInjectionError(sqlite3.ProgrammingError):
    pass


def check_sql(sql, params=()):
    if not isinstance(sql, str):
        raise SQLInjectionError("SQL-запрос должен быть строкой")
    m = SQL_FORBIDDEN.search(sql)
    if m:
        raise SQLInjectionError(f"Запрещённый фрагмент в тексте SQL: {m.group(0)!r} — значения передавайте параметрами")
    if isinstance(params, dict):
        raise SQLInjectionError("Именованные параметры не используются")
    params = tuple(params or ())
    if sql.count("?") != len(params):
        raise SQLInjectionError(f"Число параметров ({len(params)}) не совпадает с числом «?» ({sql.count('?')})")
    for v in params:
        if not isinstance(v, SQL_PARAM_TYPES):
            raise SQLInjectionError(f"Недопустимый тип параметра: {type(v).__name__}")
    return params


_DENY = {getattr(sqlite3, n) for n in ("SQLITE_ATTACH", "SQLITE_DETACH", "SQLITE_DROP_TABLE", "SQLITE_DROP_INDEX",
                                        "SQLITE_DROP_TRIGGER", "SQLITE_DROP_VIEW", "SQLITE_CREATE_TRIGGER",
                                        "SQLITE_CREATE_VIEW", "SQLITE_CREATE_TEMP_TABLE", "SQLITE_CREATE_TEMP_TRIGGER",
                                        "SQLITE_CREATE_VTABLE", "SQLITE_DROP_VTABLE") if hasattr(sqlite3, n)}
_FUNC_DENY = {"load_extension", "readfile", "writefile", "fts3_tokenizer", "edit"}


def _authorizer(action, a1, a2, db, trigger):
    if action in _DENY:
        return sqlite3.SQLITE_DENY
    if action == getattr(sqlite3, "SQLITE_PRAGMA", -1) and (a1 or "").lower() not in ("table_info", "data_version"):
        return sqlite3.SQLITE_DENY
    if action == getattr(sqlite3, "SQLITE_FUNCTION", -2) and (a2 or "").lower() in _FUNC_DENY:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


class SafeCursor(sqlite3.Cursor):
    def execute(self, sql, params=()):
        if getattr(self.connection, "sealed", False):
            params = check_sql(sql, params)
        return super().execute(sql, params)

    def executemany(self, sql, seq):
        if getattr(self.connection, "sealed", False):
            seq = [check_sql(sql, p) for p in seq]
        return super().executemany(sql, seq)

    def executescript(self, script):
        raise SQLInjectionError("executescript запрещён")


class SafeConnection(sqlite3.Connection):
    """Соединение SQLite, которое пропускает только параметризованные запросы."""
    sealed = False

    def cursor(self, factory=None):
        return super().cursor(factory or SafeCursor)

    def execute(self, sql, params=()):
        return self.cursor().execute(sql, params)

    def executemany(self, sql, seq):
        return self.cursor().executemany(sql, seq)

    def executescript(self, script):
        if self.sealed:
            raise SQLInjectionError("executescript запрещён после инициализации базы")
        return super().executescript(script)

    def seal(self):
        """Включает защиту: после миграций схемы — только параметризованные DML-запросы."""
        try:
            self.enable_load_extension(False)
        except (AttributeError, sqlite3.Error):
            pass
        if hasattr(self, "setconfig"):   # Python 3.12+
            for name in ("SQLITE_DBCONFIG_DEFENSIVE", "SQLITE_DBCONFIG_TRUSTED_SCHEMA"):
                if hasattr(sqlite3, name):
                    try:
                        self.setconfig(getattr(sqlite3, name), name.endswith("DEFENSIVE"))
                    except sqlite3.Error:
                        pass
        self.set_authorizer(_authorizer)
        self.sealed = True


def connect_safe(path):
    con = sqlite3.connect(path, check_same_thread=False, factory=SafeConnection)
    con.row_factory = sqlite3.Row
    return con


# ----------------------------------------------------------------- хранилище
class Store:
    def __init__(self, path=None, snap_dir=None):
        if path is None:
            migrate_legacy()
        path = path or DB_PATH
        snap_dir = snap_dir or SNAP_DIR
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.makedirs(snap_dir, exist_ok=True)
        self.snap_dir = snap_dir
        self.lock = threading.RLock()
        self.db = connect_safe(path)
        self.db.execute("PRAGMA trusted_schema=OFF")
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
        CREATE TABLE IF NOT EXISTS monitors(
            source_id INTEGER PRIMARY KEY, case_id INTEGER, interval_min INTEGER,
            last_check TEXT DEFAULT '', next_ts REAL DEFAULT 0, changes INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS notifications(
            id INTEGER PRIMARY KEY, ts TEXT, case_id INTEGER, text TEXT, seen INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS attachments(
            id INTEGER PRIMARY KEY, source_id INTEGER, kind TEXT, file TEXT, sha256 TEXT,
            size INTEGER, created TEXT, note TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS brand_monitors(
            id INTEGER PRIMARY KEY, case_id INTEGER, domain TEXT, interval_min INTEGER,
            last_check TEXT DEFAULT '', next_ts REAL DEFAULT 0, baseline TEXT DEFAULT '',
            changes INTEGER DEFAULT 0, UNIQUE(case_id, domain));
        CREATE TABLE IF NOT EXISTS anchors(
            id INTEGER PRIMARY KEY, case_id INTEGER, created TEXT, kind TEXT, subject TEXT, digest TEXT,
            proof BLOB, status TEXT DEFAULT 'pending', height INTEGER, block_time TEXT);
        CREATE TABLE IF NOT EXISTS ach(case_id INTEGER PRIMARY KEY, data TEXT, updated TEXT);
        """)
        # миграция схемы 1.x -> 2.x: новые поля источников
        have = {r[1] for r in self.db.execute("PRAGMA table_info(sources)")}
        for name, decl in (("kind", "TEXT DEFAULT 'web'"), ("tool", "TEXT DEFAULT ''"),
                           ("query", "TEXT DEFAULT ''"), ("parent_id", "INTEGER"),
                           ("ctype", "TEXT DEFAULT 'text/html'"), ("found_on", "INTEGER")):
            if name not in have:
                self.db.executescript(f"ALTER TABLE sources ADD COLUMN {name} {decl}")
        self.db.commit()
        self.db.seal()   # дальше — только параметризованные запросы (защита от SQL-инъекций)

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
        return verify_chain(dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY id"))

    # --- кейсы
    def cases(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM cases ORDER BY id")]

    def case(self, cid):
        r = self.db.execute("SELECT * FROM cases WHERE id=?", (int(cid),)).fetchone()
        return dict(r) if r else None

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
        """Загрузка страницы. Если сайт отдаёт неполную цепочку сертификатов, страница
        всё равно архивируется, но в статусе честно помечается «TLS не проверен»."""
        import ssl
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   "Accept": "text/html,*/*;q=0.8"})
        note = ""
        try:
            r = urllib.request.urlopen(req, timeout=25)
        except urllib.error.URLError as e:
            if not isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                raise
            handlers = [urllib.request.HTTPSHandler(context=ssl._create_unverified_context())]
            proxy = load_settings().get("proxy")
            if proxy:
                handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            r = urllib.request.build_opener(*handlers).open(req, timeout=25)
            note = " (TLS не проверен)"
        with r:
            data = r.read(MAX_BYTES + 1)
            charset = r.headers.get_content_charset() or "utf-8"
            return f"{r.status}{note}", r.geturl(), data[:MAX_BYTES], charset

    def _save_snapshot(self, data, ext):
        digest = sha256_bytes(data)
        fname = f"{digest[:16]}.{ext}"
        with open(os.path.join(self.snap_dir, fname), "wb") as f:
            f.write(data)
        return digest, fname

    def _link_entities(self, case_id, sid, ents):
        for t, v in ents:
            self.db.execute("INSERT OR IGNORE INTO entities(case_id,type,value) VALUES(?,?,?)",
                            (case_id, t, v))
            eid = self.db.execute(
                "SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                (case_id, t, v)).fetchone()["id"]
            self.db.execute("INSERT OR IGNORE INTO links VALUES(?,?)", (eid, sid))

    def add_source(self, case_id, url, parent_id=None, found_on=None, capture=None):
        """capture — функция url -> [(вид, байты, расширение, заметка)] (скриншот/PDF через Edge)."""
        url = normalize_url(url)
        fetched = now_iso()
        try:
            status, final, data, charset = self.fetch(url)
            digest, snap = self._save_snapshot(data, "html")
            text = data.decode(charset, errors="replace")
            ents, title = extract_entities(text, final)
            status_s, size = f"OK {status}", len(data)
        except Exception as e:  # сеть, SSL, таймаут, HTTP-ошибка
            final, digest, size, snap, title, ents = url, "", 0, "", "", set()
            status_s = f"ERR: {type(e).__name__} {str(e)[:80]}"
        with self.lock:
            rel = 3
            if parent_id:
                p = self.db.execute("SELECT reliability FROM sources WHERE id=?", (parent_id,)).fetchone()
                rel = p["reliability"] if p else 3
            cur = self.db.execute(
                "INSERT INTO sources(case_id,url,final_url,fetched,status,title,sha256,size,snapshot,"
                "reliability,kind,parent_id,ctype,found_on) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (case_id, url, final, fetched, status_s, title, digest, size, snap, rel,
                 "web", parent_id, "text/html", found_on))
            sid = cur.lastrowid
            self._link_entities(case_id, sid, ents)
            self.db.commit()
            self.audit("source_added" if not parent_id else "source_version",
                       f"{url} | {status_s} | sha256={digest or '-'}"
                       + (f" | parent={parent_id}" if parent_id else "")
                       + (f" | found_on={found_on}" if found_on else ""))
        if capture and status_s.startswith("OK"):
            self.capture_into(sid, final, capture)
        return sid, status_s

    def capture_into(self, sid, url, capture):
        try:
            items = capture(url) or []
        except Exception as e:   # нет Edge, таймаут — источник всё равно сохранён
            items = []
            self.audit("capture_failed", f"id={sid} {type(e).__name__}: {str(e)[:120]}")
        for kind, data, ext, note in items:
            self.add_attachment(sid, kind, data, ext, note)
        return len(items)

    def add_attachment(self, sid, kind, data, ext, note=""):
        digest, fname = self._save_snapshot(data, ext)
        with self.lock:
            self.db.execute("INSERT INTO attachments(source_id,kind,file,sha256,size,created,note) "
                            "VALUES(?,?,?,?,?,?,?)", (sid, kind, fname, digest, len(data), now_iso(), note))
            self.db.commit()
            self.audit("attachment_added", f"id={sid} {kind} {fname} sha256={digest}")
        return fname

    def attachments(self, case_id):
        with self.lock:
            rows = [dict(r) for r in self.db.execute(
                "SELECT a.* FROM attachments a JOIN sources s ON s.id=a.source_id WHERE s.case_id=? "
                "ORDER BY a.id", (case_id,))]
        out = {}
        for r in rows:
            out.setdefault(r["source_id"], []).append(r)
        return out

    # --- 2.5: якоря во времени (OpenTimestamps) и матрица гипотез
    def add_anchor(self, case_id, kind, subject, digest, proof):
        with self.lock:
            cur = self.db.execute("INSERT INTO anchors(case_id,created,kind,subject,digest,proof) VALUES(?,?,?,?,?,?)",
                                  (case_id, now_iso(), kind, subject, digest, proof))
            self.db.commit()
            self.audit("anchor_created", f"case={case_id} {kind} sha256={digest} (OpenTimestamps)")
            return cur.lastrowid

    def anchors(self, case_id=None, pending_only=False):
        q = "SELECT * FROM anchors WHERE 1=1" + (" AND case_id=?" if case_id else "") + \
            (" AND status=?" if pending_only else "") + " ORDER BY id DESC"
        args = ((case_id,) if case_id else ()) + (("pending",) if pending_only else ())
        with self.lock:
            return [dict(r) for r in self.db.execute(q, args)]

    def update_anchor(self, aid, proof, status, height=None, block_time=None):
        with self.lock:
            self.db.execute("UPDATE anchors SET proof=?, status=?, height=?, block_time=? WHERE id=?",
                            (proof, status, height, block_time, aid))
            self.db.commit()
            if status == "confirmed":
                self.audit("anchor_confirmed", f"anchor={aid} bitcoin block {height} {block_time or ''}")

    def ach_get(self, case_id):
        with self.lock:
            r = self.db.execute("SELECT data, updated FROM ach WHERE case_id=?", (case_id,)).fetchone()
        return (json.loads(r["data"]), r["updated"]) if r else (None, None)

    def ach_set(self, case_id, data):
        blob = json.dumps(data, ensure_ascii=False)
        if len(blob) > 2_000_000:
            raise ValueError("Слишком большая матрица")
        with self.lock:
            self.db.execute("INSERT INTO ach(case_id,data,updated) VALUES(?,?,?) "
                            "ON CONFLICT(case_id) DO UPDATE SET data=excluded.data, updated=excluded.updated",
                            (case_id, blob, now_iso()))
            self.db.commit()
            self.audit("ach_saved", f"case={case_id} гипотез={len(data.get('hyps') or [])} улик={len(data.get('ev') or [])}")

    def page_links(self, sid):
        """Абсолютные http(s)-ссылки из сохранённого снимка страницы."""
        s = self.source(sid)
        data = self.snapshot_bytes(s)
        if not data or s.get("kind") != "web":
            return []
        p = PageParser()
        try:
            p.feed(data.decode("utf-8", "replace"))
        except Exception:
            pass
        out, seen = [], set()
        for h in p.links:
            u = urllib.parse.urljoin(s["final_url"] or s["url"], h).split("#")[0]
            if u.startswith(("http://", "https://")) and u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def add_tool_result(self, case_id, tool, query, data, title="", pivot=None):
        """Результат любого инструмента -> доказательство: JSON-снимок с SHA-256,
        извлечённые сущности, запись в журнале аудита. pivot=(тип, значение) —
        сущность, от которой запускали инструмент (связывается с результатом)."""
        payload = {"tool": tool, "query": query, "collected": now_iso(),
                   "app": f"{APP_NAME} {APP_VERSION}", "result": data}
        raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        digest, snap = self._save_snapshot(raw, "json")
        ents = extract_entities_data(data)
        if pivot:
            ents.add(tuple(pivot))
        url = f"tool://{tool}/{urllib.parse.quote(str(query), safe='')}"
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO sources(case_id,url,final_url,fetched,status,title,sha256,size,snapshot,"
                "kind,tool,query,ctype) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (case_id, url, url, payload["collected"], "OK tool", title or f"{tool}: {query}",
                 digest, len(raw), snap, "tool", tool, str(query), "application/json"))
            sid = cur.lastrowid
            self._link_entities(case_id, sid, ents)
            self.db.commit()
            self.audit("tool_result_added", f"{tool} | {query} | sha256={digest} | entities={len(ents)}")
        return sid, len(ents)

    def sources(self, case_id):
        with self.lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM sources WHERE case_id=? ORDER BY id", (case_id,))]

    def source(self, sid):
        with self.lock:
            r = self.db.execute("SELECT * FROM sources WHERE id=?", (int(sid),)).fetchone()
        return dict(r) if r else None

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
            self.db.execute("DELETE FROM monitors WHERE source_id=?", (sid,))
            self.db.execute("DELETE FROM attachments WHERE source_id=?", (sid,))
            self.db.execute("UPDATE sources SET parent_id=NULL WHERE parent_id=?", (sid,))
            self.db.execute("DELETE FROM sources WHERE id=?", (sid,))
            # сущности, которые больше ни на что не ссылаются, тоже убираем
            self.db.execute("DELETE FROM entities WHERE id NOT IN (SELECT entity_id FROM links)")
            self.db.commit()
            self.audit("source_deleted", f"id={sid}")

    def snapshot_bytes(self, s):
        if not s or not s.get("snapshot"):
            return None
        try:
            with open(os.path.join(self.snap_dir, s["snapshot"]), "rb") as f:
                return f.read()
        except OSError:
            return None

    def verify_snapshots(self, case_id):
        bad, ok = [], 0
        for s in self.sources(case_id):
            if not s["snapshot"]:
                continue
            data = self.snapshot_bytes(s)
            good = data is not None and sha256_bytes(data) == s["sha256"]
            ok += good
            if not good:
                bad.append(s["url"])
        for lst in self.attachments(case_id).values():
            for a in lst:
                data = self.snapshot_bytes({"snapshot": a["file"]})
                good = data is not None and sha256_bytes(data) == a["sha256"]
                ok += good
                if not good:
                    bad.append(a["file"])
        return ok, bad

    # --- сущности и достоверность
    def entities(self, case_id):
        with self.lock:
            return self._entities(case_id)

    def _entities(self, case_id):
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

    # --- версии и мониторинг изменений
    def root_of(self, sid):
        s = self.source(sid)
        while s and s.get("parent_id"):
            p = self.source(s["parent_id"])
            if not p:
                break
            s = p
        return s

    def versions(self, sid):
        root = self.root_of(sid)
        if not root:
            return []
        rows = [root] + [dict(r) for r in self.db.execute(
            "SELECT * FROM sources WHERE parent_id=? ORDER BY id", (root["id"],))]
        return rows

    def set_monitor(self, sid, interval_min):
        s = self.root_of(sid)
        if not s or s["kind"] != "web":
            raise ValueError("Следить можно только за веб-источником")
        with self.lock:
            if not interval_min:
                self.db.execute("DELETE FROM monitors WHERE source_id=?", (s["id"],))
                self.audit("monitor_off", f"id={s['id']}")
            else:
                iv = max(5, int(interval_min))
                self.db.execute(
                    "INSERT INTO monitors(source_id,case_id,interval_min,next_ts) VALUES(?,?,?,?) "
                    "ON CONFLICT(source_id) DO UPDATE SET interval_min=excluded.interval_min, "
                    "next_ts=excluded.next_ts", (s["id"], s["case_id"], iv, time.time() + iv * 60))
                self.audit("monitor_on", f"id={s['id']} every {iv} min")
            self.db.commit()

    def monitors(self, case_id=None):
        q = "SELECT * FROM monitors" + (" WHERE case_id=?" if case_id else "")
        return [dict(r) for r in self.db.execute(q, (case_id,) if case_id else ())]

    def check_monitor(self, sid, capture=None):
        """Переснимает источник. Если видимый текст изменился — сохраняет новую версию."""
        root = self.root_of(sid)
        if not root:
            return None
        last = self.versions(root["id"])[-1]
        old_text = snapshot_text(self.snapshot_bytes(last), last.get("ctype"))
        new_sid, status = self.add_source(root["case_id"], root["url"], parent_id=root["id"])
        new = self.source(new_sid)
        changed = None
        if status.startswith("OK"):
            new_text = snapshot_text(self.snapshot_bytes(new), "text/html")
            changed = new_text != old_text
        with self.lock:
            if changed is False:
                # не изменилось — новую копию не держим, пишем только факт проверки
                self.db.execute("DELETE FROM links WHERE source_id=?", (new_sid,))
                self.db.execute("DELETE FROM sources WHERE id=?", (new_sid,))
                self.db.execute("DELETE FROM entities WHERE id NOT IN (SELECT entity_id FROM links)")
                if new.get("snapshot") and new["snapshot"] != last.get("snapshot"):
                    in_use = self.db.execute("SELECT 1 FROM sources WHERE snapshot=?",
                                             (new["snapshot"],)).fetchone()
                    if not in_use:
                        try:
                            os.remove(os.path.join(self.snap_dir, new["snapshot"]))
                        except OSError:
                            pass
                self.audit("monitor_check", f"id={root['id']} без изменений")
            elif changed:
                self.db.execute("UPDATE monitors SET changes=changes+1 WHERE source_id=?", (root["id"],))
                self.notify(root["case_id"], f"Изменилась страница: {root['url']} (версия #{new_sid})")
            else:
                self.notify(root["case_id"], f"Не удалось проверить {root['url']}: {status}")
            self.db.execute("UPDATE monitors SET last_check=?, next_ts=? WHERE source_id=?",
                            (now_iso(), time.time() + self._interval(root["id"]) * 60, root["id"]))
            self.db.commit()
        if changed and capture:
            self.capture_into(new_sid, new.get("final_url") or root["url"], capture)
        return {"changed": changed, "version": new_sid if changed else None, "status": status}

    def _interval(self, sid):
        r = self.db.execute("SELECT interval_min FROM monitors WHERE source_id=?", (sid,)).fetchone()
        return r["interval_min"] if r else 60

    def due_monitors(self):
        return [r["source_id"] for r in self.db.execute(
            "SELECT source_id FROM monitors WHERE next_ts<=?", (time.time(),))]

    def notify(self, case_id, text):
        with self.lock:
            self.db.execute("INSERT INTO notifications(ts,case_id,text) VALUES(?,?,?)",
                            (now_iso(), case_id, text))
            self.db.commit()

    def pop_notifications(self):
        with self.lock:
            rows = [dict(r) for r in self.db.execute(
                "SELECT * FROM notifications WHERE seen=0 ORDER BY id")]
            self.db.execute("UPDATE notifications SET seen=1 WHERE seen=0")
            self.db.commit()
        return rows

    # --- пересечения кейсов
    def intersections(self, case_id=None):
        """Сущности, которые встречаются в нескольких кейсах."""
        with self.lock:
            rows = self.db.execute(
                "SELECT type, value, group_concat(DISTINCT case_id) AS cs FROM entities "
                "GROUP BY type, value HAVING count(DISTINCT case_id) > 1").fetchall()
            names = {c["id"]: c["name"] for c in self.db.execute("SELECT id, name FROM cases")}
        out = []
        for r in rows:
            cids = sorted(int(x) for x in r["cs"].split(","))
            if case_id and int(case_id) not in cids:
                continue
            out.append({"type": r["type"], "value": r["value"],
                        "cases": [{"id": c, "name": names.get(c, "?")} for c in cids]})
        out.sort(key=lambda x: (-len(x["cases"]), x["type"], x["value"]))
        return out

    # --- досье сущности
    def dossier(self, case_id, entity_id):
        with self.lock:
            e = self.db.execute("SELECT * FROM entities WHERE id=? AND case_id=?",
                                (int(entity_id), int(case_id))).fetchone()
            if not e:
                raise KeyError("Сущность не найдена")
            e = dict(e)
            srcs = [dict(r) for r in self.db.execute(
                "SELECT s.* FROM sources s JOIN links l ON l.source_id=s.id WHERE l.entity_id=? "
                "ORDER BY s.id", (e["id"],))]
            sids = [s["id"] for s in srcs] or [0]
            q = ",".join("?" * len(sids))
            co = [dict(r) for r in self.db.execute(
                f"SELECT e.id, e.type, e.value, count(*) AS shared FROM entities e "
                f"JOIN links l ON l.entity_id=e.id WHERE l.source_id IN ({q}) AND e.id<>? "
                f"GROUP BY e.id ORDER BY shared DESC, e.type LIMIT 60", (*sids, e["id"]))]
            other = [dict(r) for r in self.db.execute(
                "SELECT c.id, c.name FROM entities x JOIN cases c ON c.id=x.case_id "
                "WHERE x.type=? AND x.value=? AND x.case_id<>?", (e["type"], e["value"], int(case_id)))]
        ctx = []
        needle = e["value"].split(":", 1)[-1].lower()
        for s in srcs:
            text = snapshot_text(self.snapshot_bytes(s), s.get("ctype"))
            low = text.lower()
            i = low.find(needle)
            if i >= 0:
                a, b = max(0, i - 140), min(len(text), i + len(needle) + 140)
                ctx.append({"source": s["id"], "text": ("…" if a else "") + " ".join(text[a:b].split())
                            + ("…" if b < len(text) else "")})
        tl = [ev for ev in self.timeline(case_id) if ev["source"] in set(sids)]
        return {"entity": {"id": e["id"], "type": e["type"], "value": e["value"]},
                "confidence": confidence(srcs), "label": label(confidence(srcs)),
                "sources": [{k: s.get(k) for k in ("id", "url", "title", "fetched", "status", "reliability",
                                                   "kind", "tool", "query", "sha256", "note")} for s in srcs],
                "domains": sorted({host_of(s["final_url"] or s["url"]) for s in srcs if s.get("kind") == "web"}),
                "related": co, "other_cases": other, "context": ctx[:12], "timeline": tl[:80]}

    # --- мониторинг бренда (двойники домена и новые поддомены/сертификаты)
    def set_brand_monitor(self, case_id, domain, interval_min, baseline=None):
        with self.lock:
            if not interval_min:
                self.db.execute("DELETE FROM brand_monitors WHERE case_id=? AND domain=?", (case_id, domain))
                self.audit("brand_monitor_off", f"{domain}")
            else:
                iv = max(60, int(interval_min))
                self.db.execute(
                    "INSERT INTO brand_monitors(case_id,domain,interval_min,next_ts,baseline) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(case_id,domain) DO UPDATE SET interval_min=excluded.interval_min, "
                    "next_ts=excluded.next_ts", (case_id, domain, iv, time.time() + iv * 60,
                                                 json.dumps(baseline or {})))
                self.audit("brand_monitor_on", f"{domain} every {iv} min")
            self.db.commit()

    def brand_monitors(self, case_id=None):
        with self.lock:
            q = "SELECT * FROM brand_monitors" + (" WHERE case_id=?" if case_id else "") + " ORDER BY id"
            return [dict(r) for r in self.db.execute(q, (case_id,) if case_id else ())]

    def due_brand_monitors(self):
        with self.lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM brand_monitors WHERE next_ts<=?", (time.time(),))]

    def update_brand_monitor(self, bid, baseline, changed):
        with self.lock:
            r = self.db.execute("SELECT interval_min FROM brand_monitors WHERE id=?", (bid,)).fetchone()
            iv = r["interval_min"] if r else 1440
            self.db.execute("UPDATE brand_monitors SET baseline=?, last_check=?, next_ts=?, "
                            "changes=changes+? WHERE id=?",
                            (json.dumps(baseline), now_iso(), time.time() + iv * 60, int(changed), bid))
            self.db.commit()

    # --- сравнение снимков
    def diff(self, sid_a, sid_b, context=2):
        a, b = self.source(sid_a), self.source(sid_b)
        if not a or not b:
            raise ValueError("Источник не найден")
        la = snapshot_text(self.snapshot_bytes(a), a.get("ctype")).splitlines()
        lb = snapshot_text(self.snapshot_bytes(b), b.get("ctype")).splitlines()
        return {"a": a["id"], "b": b["id"], **diff_lines(la, lb, context)}

    # --- хронология кейса
    def timeline(self, case_id):
        events = []
        for s in self.sources(case_id):
            kind = "tool" if s.get("kind") == "tool" else "archive"
            events.append({"date": iso_from_store(s["fetched"]), "kind": kind, "source": s["id"],
                           "label": ("Результат инструмента: " if kind == "tool" else
                                     "Версия страницы: " if s.get("parent_id") else "Архивирован: ")
                           + (s["title"] or s["url"])[:120]})
            data = self.snapshot_bytes(s)
            if not data:
                continue
            if s.get("ctype") == "application/json":
                try:
                    payload = json.loads(data.decode("utf-8"))
                except ValueError:
                    continue
                for path, d in dates_in(payload.get("result")):
                    events.append({"date": d, "kind": "fact", "source": s["id"],
                                   "label": f"{s.get('tool')} {s.get('query')}: {path}"})
            else:
                for label_, d in html_dates(data.decode("utf-8", "replace")):
                    events.append({"date": d, "kind": "fact", "source": s["id"],
                                   "label": f"{label_} — {host_of(s['url'])}"})
        seen, out = set(), []
        for e in sorted(events, key=lambda e: e["date"]):
            k = (e["date"], e["label"])
            if k not in seen:
                seen.add(k)
                out.append(e)
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


def verify_chain(rows):
    """Проверка хэш-цепочки журнала аудита. rows — записи по возрастанию id."""
    prev = "GENESIS"
    for r in rows:
        expect = sha256_bytes(f"{prev}|{r['ts']}|{r['action']}|{r['detail']}".encode())
        if r["prev"] != prev or r["hash"] != expect:
            return False, r["id"]
        prev = r["hash"]
    return True, None


# ----------------------------------------------------------------- текст, даты, сравнение
def snapshot_text(data, ctype="text/html"):
    """Видимый текст снимка построчно (для сравнения версий и мониторинга)."""
    if not data:
        return ""
    s = data.decode("utf-8", "replace")
    if ctype == "application/json":
        try:
            payload = json.loads(s)
            return json.dumps(payload.get("result", payload), ensure_ascii=False, indent=1, sort_keys=True)
        except ValueError:
            return s
    p = PageParser()
    try:
        p.feed(s)
    except Exception:
        pass
    lines = (" ".join(x.split()) for x in p.text)
    return "\n".join(x for x in lines if x)


def diff_lines(la, lb, context=2):
    """Построчный diff: список {op: eq|add|del|gap, text}. Длинные совпадения сжимаются."""
    out, added, removed = [], 0, 0
    sm = difflib.SequenceMatcher(None, la, lb, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            block = la[i1:i2]
            if len(block) > context * 2 + 1:
                out += [{"op": "eq", "text": t} for t in block[:context]]
                out.append({"op": "gap", "text": f"… без изменений: {len(block) - context * 2} строк"})
                out += [{"op": "eq", "text": t} for t in block[-context:]]
            else:
                out += [{"op": "eq", "text": t} for t in block]
            continue
        if tag in ("replace", "delete"):
            out += [{"op": "del", "text": t} for t in la[i1:i2]]
            removed += i2 - i1
        if tag in ("replace", "insert"):
            out += [{"op": "add", "text": t} for t in lb[j1:j2]]
            added += j2 - j1
    return {"lines": out[:4000], "added": added, "removed": removed,
            "similarity": round(sm.ratio() * 100, 1)}


_RE_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?")
_DATE_KEYS = re.compile(r"date|time|created|updated|expir|valid|registr|first|last|seen|"
                        r"publish|modified|issued|changed|since|birth", re.I)


def parse_date(v):
    """Строка -> ISO 'YYYY-MM-DD HH:MM' или None. Понимает ISO, wayback (14 цифр),
    формат сертификатов ('Jan  5 12:00:00 2025 GMT') и 'UTC'-строки Provenio."""
    if not isinstance(v, str):
        return None
    v = v.strip()
    if len(v) > 40:
        return None
    m = _RE_ISO.match(v)
    if m:
        y, mo, d, hh, mm = m.group(1), m.group(2), m.group(3), m.group(4) or "00", m.group(5) or "00"
        if 1990 <= int(y) <= 2100 and 1 <= int(mo) <= 12 and 1 <= int(d) <= 31:
            return f"{y}-{mo}-{d} {hh}:{mm}"
        return None
    if re.fullmatch(r"(19|20)\d{12}", v):
        return f"{v[:4]}-{v[4:6]}-{v[6:8]} {v[8:10]}:{v[10:12]}"
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y"):
        try:
            return dt.datetime.strptime(" ".join(v.split()), fmt).strftime("%Y-%m-%d %H:%M")
        except ValueError:
            pass
    return None


def iso_from_store(s):
    return parse_date(s or "") or (s or "")[:16]


def dates_in(data, path="", out=None, limit=200):
    """Пары (путь_ключа, дата) из вложенного результата инструмента."""
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if isinstance(data, dict):
        for k, v in data.items():
            p = f"{path}.{k}" if path else str(k)
            if isinstance(v, str) and _DATE_KEYS.search(str(k)):
                d = parse_date(v)
                if d:
                    out.append((p, d))
            elif isinstance(v, list) and _DATE_KEYS.search(str(k)) and v and isinstance(v[0], str):
                for x in v[:5]:
                    d = parse_date(x)
                    if d:
                        out.append((p, d))
            else:
                dates_in(v, p, out, limit)
    elif isinstance(data, list):
        for i, v in enumerate(data[:100]):
            dates_in(v, f"{path}[{i}]", out, limit)
    return out


def html_dates(text):
    """Даты публикации из HTML: article:published_time, <time datetime>, JSON-LD."""
    out = []
    for prop, lab in (("article:published_time", "Опубликовано"), ("article:modified_time", "Изменено"),
                      ("og:updated_time", "Обновлено"), ("datePublished", "Опубликовано"),
                      ("dateModified", "Изменено")):
        for m in re.finditer(rf'{re.escape(prop)}["\']?\s*(?:content=|:)\s*["\']([^"\']+)', text):
            d = parse_date(m.group(1))
            if d:
                out.append((lab, d))
    for m in re.finditer(r'<time[^>]+datetime=["\']([^"\']+)', text, re.I):
        d = parse_date(m.group(1))
        if d:
            out.append(("Дата на странице", d))
    return out[:30]


# ----------------------------------------------------------------- экспорт и пакет доказательств
def export_case(store, case):
    srcs = store.sources(case["id"])
    return {"app": f"{APP_NAME} {APP_VERSION}", "exported": now_iso(), "case": case,
            "sources": srcs,
            "entities": [{"type": e["type"], "value": e["value"], "confidence": e["confidence"],
                          "sources": [s["id"] for s in e["sources"]]}
                         for e in store.entities(case["id"])],
            "timeline": store.timeline(case["id"])}


def entities_csv(store, case):
    import csv
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["type", "value", "confidence", "label", "sources"])
    for e in sorted(store.entities(case["id"]), key=lambda x: -x["confidence"]):
        w.writerow([e["type"], e["value"], e["confidence"], label(e["confidence"]),
                    " ".join(str(s["id"]) for s in e["sources"])])
    return "﻿" + buf.getvalue()   # BOM — чтобы Excel открыл кириллицу


EVIDENCE_README = """Пакет доказательств Provenio
============================

manifest.json   — описание кейса, источники, сущности, ПОЛНЫЙ журнал аудита
                  и SHA-256 каждого файла пакета.
snapshots/      — снимки страниц (HTML), скриншоты (PNG), PDF и результаты инструментов (JSON).
timestamp/      — метка времени RFC 3161 на manifest.json от независимой службы (если включено).
report.html     — человекочитаемый отчёт.

Как проверить, что ничего не подменили:
  1. Откройте Provenio -> Инструменты -> «Проверка пакета доказательств»
     и выберите этот ZIP. Будут пересчитаны хэши файлов и хэш-цепочка аудита.
  2. Вручную: SHA-256 каждого файла из snapshots/ должен совпадать с
     manifest.json -> files, а также с полем sha256 соответствующего источника.
  3. Зафиксируйте SHA-256 самого manifest.json (показывается при выгрузке) —
     так подмена манифеста тоже будет заметна.
  4. Метка времени (OpenSSL):
       openssl ts -reply -in timestamp/manifest.tsr -token_in -text
       openssl ts -verify -data manifest.json -in timestamp/manifest.tsr -token_in -CAfile <корневой сертификат TSA>
     Метка доказывает, что manifest.json (а значит, хэши всех файлов) существовал
     не позже указанного времени, и подписана независимой службой.
"""


# ----------------------------------------------------------------- RFC 3161 (метки времени)
def _der(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def _der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return _der(0x02, b)


def _tlv(buf, pos=0):
    """Разбор одного DER-элемента: (тег, начало содержимого, конец)."""
    tag = buf[pos]
    ln = buf[pos + 1]
    pos += 2
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + ln > len(buf):
        raise ValueError("Повреждённая DER-структура")
    return tag, pos, pos + ln


def _children(buf, start, end):
    out, pos = [], start
    while pos < end:
        t, a, b = _tlv(buf, pos)
        out.append((t, a, b, pos))
        pos = b
    return out


SHA256_OID = bytes.fromhex("0609608648016503040201")


def rfc3161_request(digest, nonce):
    imprint = _der(0x30, _der(0x30, SHA256_OID + b"\x05\x00") + _der(0x04, digest))
    return _der(0x30, _der_int(1) + imprint + _der_int(nonce) + _der(0x01, b"\xff"))


def rfc3161_parse_token(token):
    """Находит TSTInfo в подписанном токене и возвращает время, серийный номер и хэш."""
    def walk(a, b, depth=0):
        if depth > 12:
            return None
        for t, x, y, _h in _children(token, a, b):
            if t == 0x04:   # OCTET STRING — возможно, внутри TSTInfo
                try:
                    tt, xa, xb = _tlv(token, x)
                    if tt == 0x30 and xb == y:
                        ch = _children(token, xa, xb)
                        if len(ch) >= 5 and ch[0][0] == 0x02 and ch[1][0] == 0x06 and ch[2][0] == 0x30 \
                                and ch[4][0] == 0x18:
                            mi = _children(token, ch[2][1], ch[2][2])
                            return {"imprint": token[mi[1][1]:mi[1][2]].hex(),
                                    "serial": token[ch[3][1]:ch[3][2]].hex(),
                                    "gen_time_raw": token[ch[4][1]:ch[4][2]].decode("ascii", "replace")}
                except (ValueError, IndexError):
                    pass
            if t & 0x20:   # составной элемент
                r = walk(x, y, depth + 1)
                if r:
                    return r
        return None
    t, a, b = _tlv(token, 0)
    info = walk(0, len(token)) if t == 0x30 else None
    if not info:
        raise ValueError("В ответе нет TSTInfo")
    g = info["gen_time_raw"]
    info["gen_time"] = f"{g[0:4]}-{g[4:6]}-{g[6:8]} {g[8:10]}:{g[10:12]}:{g[12:14]} UTC"
    return info


TSA_DEFAULT = "http://timestamp.digicert.com"
TSA_FALLBACKS = ("http://timestamp.digicert.com", "http://timestamp.sectigo.com",
                 "https://freetsa.org/tsr", "http://ts.ssl.com")


def rfc3161_stamp(digest, tsa_url=TSA_DEFAULT, timeout=25):
    """Запрашивает метку времени на SHA-256-хэш у службы TSA (с запасными службами)."""
    nonce = random.getrandbits(63)
    req = rfc3161_request(digest, nonce)
    errors = []
    for url in [tsa_url] + [u for u in TSA_FALLBACKS if u != tsa_url]:
        try:
            r = urllib.request.Request(url, data=req, headers={
                "Content-Type": "application/timestamp-query", "User-Agent": USER_AGENT})
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                body = resp.read(200_000)
            t, a, b = _tlv(body, 0)
            ch = _children(body, a, b)
            st = _children(body, ch[0][1], ch[0][2])
            status = int.from_bytes(body[st[0][1]:st[0][2]], "big")
            if status not in (0, 1) or len(ch) < 2:
                raise ValueError(f"TSA отказала: статус {status}")
            token = body[ch[1][3]:ch[1][2]]
            info = rfc3161_parse_token(token)
            if info["imprint"] != digest.hex():
                raise ValueError("Хэш в метке не совпадает")
            return {"tsa": url, "gen_time": info["gen_time"], "serial": info["serial"],
                    "hash": digest.hex(), "token": token, "request": req}
        except Exception as e:
            errors.append(f"{url}: {type(e).__name__}")
    raise ConnectionError("; ".join(errors))



def build_evidence_zip(store, case, tsa_url=None, ots=None):
    """tsa_url — адрес службы меток времени RFC 3161: хэш manifest.json заверяется
    независимой третьей стороной (доказывает, что пакет существовал не позже этого момента)."""
    srcs = store.sources(case["id"])
    atts = store.attachments(case["id"])
    files, blobs = {}, {}
    for s in srcs:
        data = store.snapshot_bytes(s)
        if data is not None:
            path = "snapshots/" + s["snapshot"]
            blobs[path] = data
            files[path] = sha256_bytes(data)
        for a in atts.get(s["id"], []):
            data = store.snapshot_bytes({"snapshot": a["file"]})
            if data is not None:
                blobs["snapshots/" + a["file"]] = data
                files["snapshots/" + a["file"]] = sha256_bytes(data)
    report = build_report(store, case).encode("utf-8")
    blobs["report.html"] = report
    files["report.html"] = sha256_bytes(report)
    audit = [dict(r) for r in store.db.execute("SELECT * FROM audit ORDER BY id")]
    manifest = {"format": "provenio-evidence/1", "app": f"{APP_NAME} {APP_VERSION}",
                "created": now_iso(), "case": case, "sources": srcs,
                "entities": [{"type": e["type"], "value": e["value"], "confidence": e["confidence"],
                              "sources": [x["id"] for x in e["sources"]]}
                             for e in store.entities(case["id"])],
                "attachments": [a for lst in atts.values() for a in lst],
                "files": files, "audit": audit,
                "audit_head": audit[-1]["hash"] if audit else "GENESIS"}
    mbytes = json.dumps(manifest, ensure_ascii=False, indent=2, default=str).encode("utf-8")
    ts = None
    if tsa_url:
        try:
            ts = rfc3161_stamp(hashlib.sha256(mbytes).digest(), tsa_url)
        except Exception as e:
            ts = {"error": f"{type(e).__name__}: {str(e)[:160]}", "tsa": tsa_url}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", mbytes)
        z.writestr("README.txt", EVIDENCE_README)
        for path, data in blobs.items():
            z.writestr(path, data)
        if ots:
            try:
                proof, cals = ots(hashlib.sha256(mbytes).digest())
                z.writestr("timestamp/manifest.ots", proof)
                z.writestr("timestamp/OPENTIMESTAMPS.txt",
                           "manifest.ots — доказательство OpenTimestamps: SHA-256 файла manifest.json записан в календари\n"
                           f"{', '.join(cals)} и через несколько часов попадёт в блокчейн Bitcoin.\n"
                           "Проверка: https://opentimestamps.org (перетащите manifest.ots и manifest.json) или `ots verify manifest.ots`.\n")
                store.add_anchor(case["id"], "evidence", "manifest.json", hashlib.sha256(mbytes).hexdigest(), proof)
            except Exception as e:
                z.writestr("timestamp/OPENTIMESTAMPS.txt", f"Якорь OpenTimestamps не получен: {type(e).__name__}: {e}\n")
        if ts and ts.get("token"):
            z.writestr("timestamp/manifest.tsq", ts["request"])
            z.writestr("timestamp/manifest.tsr", ts["token"])
            z.writestr("timestamp/info.json", json.dumps(
                {k: v for k, v in ts.items() if k not in ("token", "request")}, ensure_ascii=False, indent=2))
    store.audit("evidence_exported", f"{case['name']} | manifest sha256={sha256_bytes(mbytes)}"
                + (f" | RFC3161 {ts.get('gen_time')} {ts.get('tsa')}" if ts and ts.get("token") else "")
                + (f" | метка времени не получена: {ts['error']}" if ts and ts.get("error") else ""))
    return buf.getvalue(), sha256_bytes(mbytes)


def verify_evidence_zip(data):
    """Проверка пакета: хэши файлов, совпадение с источниками, хэш-цепочка аудита."""
    z = zipfile.ZipFile(io.BytesIO(data))
    mbytes = z.read("manifest.json")
    m = json.loads(mbytes.decode("utf-8"))
    names = set(z.namelist())
    bad, missing, ok = [], [], 0
    for path, h in m.get("files", {}).items():
        if path not in names:
            missing.append(path)
        elif sha256_bytes(z.read(path)) != h:
            bad.append(path)
        else:
            ok += 1
    src_bad = [s["id"] for s in m.get("sources", [])
               if s.get("snapshot") and m["files"].get("snapshots/" + s["snapshot"]) not in (None, s["sha256"])]
    chain_ok, broken = verify_chain(m.get("audit", []))
    head_ok = (m["audit"][-1]["hash"] if m.get("audit") else "GENESIS") == m.get("audit_head")
    stamp = None
    if "timestamp/manifest.tsr" in names:
        try:
            info = rfc3161_parse_token(z.read("timestamp/manifest.tsr"))
            stamp = {"gen_time": info.get("gen_time"), "serial": info.get("serial"),
                     "matches_manifest": info.get("imprint") == hashlib.sha256(mbytes).hexdigest()}
            if not stamp["matches_manifest"]:
                bad.append("timestamp/manifest.tsr")
        except Exception as e:
            stamp = {"error": f"{type(e).__name__}: {e}"}
    return {"timestamp": stamp,"case": (m.get("case") or {}).get("name"), "created": m.get("created"), "app": m.get("app"),
            "files_ok": ok, "files_bad": bad, "files_missing": missing, "sources_mismatch": src_bad,
            "audit_records": len(m.get("audit", [])), "audit_chain_ok": chain_ok and head_ok,
            "audit_broken_at": broken, "manifest_sha256": sha256_bytes(mbytes),
            "verdict": "целостность подтверждена" if not (bad or missing or src_bad) and chain_ok and head_ok
            else "ОБНАРУЖЕНЫ НАРУШЕНИЯ"}


# ----------------------------------------------------------------- настройки (ключи API шифруются DPAPI)
def _dpapi(data, protect):
    """Шифрование данных ключом текущего пользователя Windows (DPAPI).
    На других ОС возвращает None — тогда ключи хранятся как есть."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    src = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    dst = BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if not fn(ctypes.byref(src), None, None, None, None, 0x01, ctypes.byref(dst)):
        return None
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        kernel32.LocalFree(dst.pbData)


SECRET_KEYS = ("shodan", "virustotal", "abuseipdb", "urlscan", "otx", "github", "anthropic")
OPTIONS = {"capture_screenshot": True, "capture_pdf": False, "tsa_enabled": True, "tsa_url": "",
           "check_updates": False, "ai_model": "claude-opus-5-5", "ots_enabled": True}


def load_settings():
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        raw = {}
    keys = {}
    enc = raw.get("keys_dpapi")
    if enc:
        import base64
        plain = _dpapi(base64.b64decode(enc), False)
        if plain:
            keys = json.loads(plain.decode("utf-8"))
    keys.update(raw.get("keys_plain") or {})
    out = {"proxy": raw.get("proxy", ""), "timeout": raw.get("timeout", 15),
           "keys": {k: keys.get(k, "") for k in SECRET_KEYS}}
    for k, v in OPTIONS.items():
        out[k] = raw.get(k, v)
    return out


def save_settings(s):
    import base64
    keys = {k: str((s.get("keys") or {}).get(k, "")).strip() for k in SECRET_KEYS}
    out = {"proxy": str(s.get("proxy", "")).strip(), "timeout": int(s.get("timeout") or 15)}
    for k, v in OPTIONS.items():
        val = s.get(k, v)
        out[k] = bool(val) if isinstance(v, bool) else str(val or "").strip()[:200]
    enc = _dpapi(json.dumps(keys).encode("utf-8"), True)
    if enc:
        out["keys_dpapi"] = base64.b64encode(enc).decode()
    else:
        out["keys_plain"] = keys
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    return load_settings()


# ----------------------------------------------------------------- отчёт
def build_report(store, case):
    srcs, ents = store.sources(case["id"]), store.entities(case["id"])
    atts = store.attachments(case["id"])
    ok, bad = store.verify_snapshots(case["id"])
    chain_ok, broken = store.verify_audit()
    e = html.escape
    rows_s = "".join(
        f"<tr><td>{s['id']}</td><td>{'инструмент: ' if s.get('kind') == 'tool' else ''}{e(s['url'])}"
        f"{' (версия источника #' + str(s['parent_id']) + ')' if s.get('parent_id') else ''}"
        f"<br><small>{e(s['title'])}</small>"
        + "".join(f"<br><small>{e(a['kind'])}: {e(a['file'])} · sha256 <code>{e(a['sha256'])}</code></small>"
                  for a in atts.get(s["id"], [])) + "</td>"
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
