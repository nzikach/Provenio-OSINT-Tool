#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Provenio Tools — набор пассивных OSINT / ИБ / аналитических инструментов.

Принципы:
  * Только стандартная библиотека Python 3.9+ (никаких внешних пакетов).
  * Только пассивный сбор публичных данных и защитные проверки.
  * Никакого перебора паролей/логинов, эксплойтов, сканов портов чужих систем.
    Вместо «брутфорса» — защитные проверки: утечки паролей через k-anonymity
    HaveIBeenPwned (сам пароль не покидает машину) и оценка стойкости пароля.

Каждая функция возвращает dict и при ошибке бросает исключение — слой API
наверху ловит и отдаёт {"error": ...}. Сетевые вызовы идут с таймаутом и
единым User-Agent; всё работает на машине пользователя.

Используйте только для публичных данных и в рамках закона.
"""
import base64
import binascii
import hashlib
import html
import ipaddress
import json
import math
import re
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error
import os
import time
import sys
import threading
import datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "Mozilla/5.0 (compatible; Provenio/2.0; +OSINT-research)"
# для проверки профилей нужен «браузерный» UA: многие сайты режут ботов кодом 403
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")
TIMEOUT = 15
SETTINGS = {"proxy": "", "timeout": 15, "keys": {}}


def configure(settings):
    """Применяет настройки: прокси для всех HTTP-запросов, таймаут, API-ключи."""
    global TIMEOUT
    SETTINGS.update(settings or {})
    TIMEOUT = int(SETTINGS.get("timeout") or 15)
    proxy = (SETTINGS.get("proxy") or "").strip()
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    urllib.request.install_opener(urllib.request.build_opener(*handlers))


def key(name):
    return ((SETTINGS.get("keys") or {}).get(name) or "").strip()


# ----------------------------------------------------------------- задачи с прогрессом
class Cancelled(Exception):
    pass


class Job:
    """Прогресс и отмена для долгих инструментов. Инструмент вызывает
    job.total(n) / job.step(msg) / job.check(); интерфейс опрашивает состояние."""

    def __init__(self):
        self.done = 0
        self.all = 0
        self.msg = ""
        self.cancelled = False
        self.partial = None
        self._lock = threading.Lock()

    def total(self, n):
        self.all = n

    def step(self, msg=None, n=1):
        with self._lock:
            self.done += n
            if msg:
                self.msg = msg
        self.check()

    def note(self, msg):
        self.msg = msg
        self.check()

    def check(self):
        if self.cancelled:
            raise Cancelled("Остановлено пользователем")


NULL_JOB = Job()


def pmap(fn, items, job=None, workers=16):
    """Параллельно применяет fn к items. Ошибки отдельных элементов не роняют всё.
    Возвращает список (item, result|None, error|None) в порядке завершения."""
    job = job or Job()
    items = list(items)
    out = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items) or 1))) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        try:
            for f in as_completed(futs):
                it = futs[f]
                try:
                    out.append((it, f.result(), None))
                except Exception as e:
                    out.append((it, None, f"{type(e).__name__}: {str(e)[:120]}"))
                job.step()
        except Cancelled:
            for f in futs:
                f.cancel()
            raise
    return out


def res_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


# ----------------------------------------------------------------- HTTP helpers
def _open(req, timeout, insecure=False):
    """urlopen с учётом прокси из настроек. insecure=True — без проверки сертификата
    (только как запасной вариант для сайтов с неполной цепочкой сертификатов)."""
    handlers = []
    proxy = (SETTINGS.get("proxy") or "").strip()
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def _is_cert_error(e):
    return isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError) or         isinstance(e, ssl.SSLCertVerificationError)


def _get(url, headers=None, timeout=None, max_bytes=2_000_000, retries=1):
    """GET с таймаутом, одним повтором при 502/503/504/таймауте и запасным
    режимом без проверки сертификата (только чтение публичных данных)."""
    timeout = timeout or TIMEOUT
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    insecure = False
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers=h)
        try:
            with _open(req, timeout, insecure) as r:
                data = r.read(max_bytes)
                return r.status, dict(r.headers), r.geturl(), data
        except urllib.error.HTTPError as e:
            if e.code in (502, 503, 504, 429) and attempt < retries:
                time.sleep(1.5)
                continue
            raise
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, socket.timeout) as e:
            if _is_cert_error(e) and not insecure:
                insecure = True
                try:
                    with _open(req, timeout, True) as r:
                        data = r.read(max_bytes)
                        return r.status, dict(r.headers), r.geturl(), data
                except Exception:
                    raise e
            if isinstance(e, (TimeoutError, socket.timeout)) and attempt < retries:
                continue
            raise


def _get_json(url, headers=None, timeout=None):
    hh = {"Accept": "application/json"}
    if headers:
        hh.update(headers)
    _, _, _, data = _get(url, hh, timeout)
    return json.loads(data.decode("utf-8", "replace"))


def _host(x):
    x = x.strip()
    if "//" in x:
        x = urllib.parse.urlparse(x if re.match(r"^\w+://", x) else "http://" + x).netloc
    return x.split("@")[-1].split(":")[0].lower().lstrip(".")


# ================================================================= DNS / сеть
_DOH = "https://cloudflare-dns.com/dns-query"
_RTYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


def _doh(name, rtype):
    """Один тип DNS-записи через DNS-over-HTTPS (пусто, если записи нет или ошибка)."""
    codes = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
    try:
        j = _get_json(f"{_DOH}?name={urllib.parse.quote(name)}&type={rtype}",
                      headers={"Accept": "application/dns-json"}, timeout=10)
        return [a.get("data", "").strip('"') for a in j.get("Answer", []) if a.get("type") == codes.get(rtype)]
    except Exception:
        return []


def dns_lookup(domain):
    """DNS-over-HTTPS (Cloudflare): все основные типы записей одним махом."""
    name = _host(domain)

    def one(t):
        j = _get_json(f"{_DOH}?name={urllib.parse.quote(name)}&type={t}",
                      headers={"Accept": "application/dns-json"}, timeout=10)
        return [a.get("data", "").strip('"') for a in j.get("Answer", [])]
    out = {t: ans for t, ans, err in pmap(one, _RTYPES, workers=8) if ans}
    return {"domain": name, "records": {t: out[t] for t in _RTYPES if t in out}}


def reverse_dns(ip):
    """PTR-запись (обратный DNS)."""
    ip = ip.strip()
    ipaddress.ip_address(ip)  # валидация, бросит при мусоре
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "ptr": host, "aliases": aliases}
    except socket.herror:
        return {"ip": ip, "ptr": None, "aliases": []}


def ip_info(ip):
    """Гео/ASN/организация по IP (ip-api.com, без ключа)."""
    ip = ip.strip()
    ipaddress.ip_address(ip)
    j = _get_json(f"http://ip-api.com/json/{urllib.parse.quote(ip)}"
                  "?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query")
    if j.get("status") != "success":
        raise ValueError(j.get("message", "lookup failed"))
    return {
        "ip": j.get("query"), "country": j.get("country"), "region": j.get("regionName"),
        "city": j.get("city"), "lat": j.get("lat"), "lon": j.get("lon"),
        "timezone": j.get("timezone"), "isp": j.get("isp"), "org": j.get("org"),
        "asn": j.get("as"),
    }


def whois_domain(domain):
    """WHOIS по домену: IANA → реферальный сервер регистратуры/регистратора."""
    name = _host(domain)

    def query(server, q):
        with socket.create_connection((server, 43), timeout=TIMEOUT) as s:
            s.sendall((q + "\r\n").encode("idna" if False else "utf-8", "replace"))
            buf = b""
            while len(buf) < 200_000:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return buf.decode("utf-8", "replace")

    raw = query("whois.iana.org", name)
    m = re.search(r"refer:\s*(\S+)", raw, re.I)
    server = m.group(1) if m else None
    if server:
        try:
            raw2 = query(server, name)
            if raw2.strip():
                raw = raw2
        except Exception:
            pass
    raw = raw.replace("\r", "")
    # у .com/.net подробности (организация, контакты) — на сервере регистратора
    m2 = re.search(r"^\s*Registrar WHOIS Server:\s*(\S+)", raw, re.I | re.M)
    reg_raw = ""
    if m2 and m2.group(1).lower() != (server or "").lower():
        try:
            reg_raw = query(m2.group(1), name).replace("\r", "")
        except Exception:
            pass
    text = raw + "\n" + reg_raw
    fields = {}
    for key in ("Registrar", "Creation Date", "Registry Expiry Date", "Registrar Registration Expiration Date",
                "Updated Date", "Registrant Organization", "Registrant Country", "Registrant Email",
                "Name Server", "Domain Status", "Registrar WHOIS Server", "Registrar Abuse Contact Email",
                "DNSSEC", "created", "paid-till", "org", "registrar", "nserver", "state"):
        vals = re.findall(rf"^\s*{re.escape(key)}:\s*(.+?)\s*$", text, re.I | re.M)
        vals = [v for v in vals if v and not v.lower().startswith(("redacted", "please query"))]
        if vals:
            fields[key] = sorted(set(v.split(" ")[0] if key == "Domain Status" else v for v in vals))[:12]
    return {"domain": name, "server": server, "registrar_server": m2.group(1) if m2 else None,
            "fields": fields, "raw": (reg_raw or raw)[:8000]}


def ssl_cert(host):
    """Инспекция TLS-сертификата: subject, issuer, срок, SAN."""
    h = _host(host)
    ctx = ssl.create_default_context()
    with socket.create_connection((h, 443), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=h) as ss:
            cert = ss.getpeercert()
            cipher = ss.cipher()
            version = ss.version()

    def flat(seq):
        d = {}
        for rdn in seq or ():
            for k, v in rdn:
                d[k] = v
        return d

    subj = flat(cert.get("subject"))
    iss = flat(cert.get("issuer"))
    san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    fmt = "%b %d %H:%M:%S %Y %Z"
    na = cert.get("notAfter")
    days = None
    if na:
        try:
            exp = dt.datetime.strptime(na, fmt).replace(tzinfo=dt.timezone.utc)
            days = (exp - dt.datetime.now(dt.timezone.utc)).days
        except Exception:
            pass
    return {
        "host": h, "subject_cn": subj.get("commonName"),
        "issuer": iss.get("organizationName") or iss.get("commonName"),
        "valid_from": cert.get("notBefore"), "valid_to": na,
        "days_left": days, "san": san[:40],
        "tls_version": version, "cipher": cipher[0] if cipher else None,
    }


# ================================================================= HTTP / web
_SEC_HEADERS = {
    "strict-transport-security": "HSTS — форсирует HTTPS",
    "content-security-policy": "CSP — защита от XSS/инъекций",
    "x-frame-options": "Защита от clickjacking",
    "x-content-type-options": "Запрет MIME-sniffing",
    "referrer-policy": "Контроль Referer",
    "permissions-policy": "Ограничение браузерных API",
    "cross-origin-opener-policy": "Изоляция контекста",
}


def http_headers(url):
    """Заголовки ответа + оценка безопасности (как securityheaders)."""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    status, headers, final, _ = _get(url, max_bytes=1)
    low = {k.lower(): v for k, v in headers.items()}
    present, missing = {}, {}
    for h, desc in _SEC_HEADERS.items():
        (present if h in low else missing)[h] = low.get(h, desc)
    score = round(len(present) / len(_SEC_HEADERS) * 100)
    grade = ("A" if score >= 85 else "B" if score >= 65 else
             "C" if score >= 45 else "D" if score >= 25 else "F")
    return {
        "url": final, "status": status, "grade": grade, "score": score,
        "server": low.get("server"), "powered_by": low.get("x-powered-by"),
        "present": present, "missing": missing,
        "all_headers": dict(sorted(headers.items())),
    }


def subdomains(domain):
    """Поддомены через Certificate Transparency (crt.sh)."""
    name = _host(domain)
    subs, used, errors = set(), [], {}

    def add(n):
        n = n.strip().lstrip("*.").lower().rstrip(".")
        if (n == name or n.endswith("." + name)) and "@" not in n and re.fullmatch(r"[a-z0-9.\-]+", n):
            subs.add(n)

    def crtsh():
        for row in _get_json(f"https://crt.sh/?q={urllib.parse.quote('%.' + name)}&output=json", timeout=40):
            for n in str(row.get("name_value", "")).splitlines():
                add(n)

    def certspotter():
        for row in _get_json("https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(name)
                             + "&include_subdomains=true&expand=dns_names", timeout=30):
            for n in row.get("dns_names", []):
                add(n)

    def hackertarget():
        _, _, _, data = _get(f"https://api.hackertarget.com/hostsearch/?q={name}", timeout=20)
        body = data.decode("utf-8", "replace")
        if "API count" in body or body.lower().startswith("error"):
            raise ValueError(body[:60])
        for line in body.splitlines():
            add(line.split(",")[0])

    for src, fn in (("crt.sh", crtsh), ("certspotter", certspotter), ("hackertarget", hackertarget)):
        try:
            fn()
            used.append(src)
        except Exception as e:
            errors[src] = type(e).__name__
    if not used:
        raise ConnectionError("Все источники поддоменов недоступны: " + ", ".join(errors))
    subs.discard(name)
    return {"domain": name, "count": len(subs), "subdomains": sorted(subs)[:600],
            "sources": used, "errors": errors}


def wayback(url):
    """Архив Wayback Machine: ближайший снимок + оценка числа копий."""
    u = url.strip()
    j = _get_json(f"http://archive.org/wayback/available?url={urllib.parse.quote(u)}")
    snap = (j.get("archived_snapshots") or {}).get("closest") or {}
    total = None
    try:
        _, _, _, data = _get(
            "http://web.archive.org/cdx/search/cdx?url="
            f"{urllib.parse.quote(u)}&output=json&limit=1&showNumPages=true", timeout=20)
        total = int(data.decode().strip() or 0)
    except Exception:
        pass
    return {"url": u, "available": snap.get("available", False),
            "closest": snap.get("url"), "timestamp": snap.get("timestamp"),
            "approx_pages": total}


# ================================================================= OSINT: люди
# Проверка СУЩЕСТВОВАНИЯ публичного профиля (как Sherlock/WhatsMyName).
# Это не перебор: один GET на сайт, смотрим код ответа / строку-маркер.
_USER_SITES = [
    ("GitHub", "https://github.com/{u}", 404),
    ("GitLab", "https://gitlab.com/{u}", 404),
    ("Twitter/X", "https://x.com/{u}", 404),
    ("Instagram", "https://www.instagram.com/{u}/", 404),
    ("Reddit", "https://www.reddit.com/user/{u}", 404),
    ("Telegram", "https://t.me/{u}", 404),
    ("TikTok", "https://www.tiktok.com/@{u}", 404),
    ("YouTube", "https://www.youtube.com/@{u}", 404),
    ("Pinterest", "https://www.pinterest.com/{u}/", 404),
    ("Twitch", "https://www.twitch.tv/{u}", 404),
    ("Medium", "https://medium.com/@{u}", 404),
    ("Steam", "https://steamcommunity.com/id/{u}", None),
    ("VK", "https://vk.com/{u}", None),
    ("Keybase", "https://keybase.io/{u}", 404),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", None),
    ("Replit", "https://replit.com/@{u}", 404),
    ("Dev.to", "https://dev.to/{u}", 404),
    ("PyPI", "https://pypi.org/user/{u}/", 404),
    ("DockerHub", "https://hub.docker.com/u/{u}", 404),
    ("SoundCloud", "https://soundcloud.com/{u}", 404),
]


_SITES_CACHE = None


def load_sites():
    """База сайтов (Sherlock Project, MIT) + собственные 20 проверок как запасной вариант."""
    global _SITES_CACHE
    if _SITES_CACHE is None:
        sites = {}
        try:
            with open(res_path("provenio_sites.json"), encoding="utf-8") as f:
                sites = json.load(f)["sites"]
        except (OSError, ValueError, KeyError):
            pass
        hosts = {_host(s["url"]).removeprefix("www.") for s in sites.values()}
        for name, tmpl, miss in _USER_SITES:
            if _host(tmpl).removeprefix("www.") not in hosts:
                sites.setdefault(name, {"url": tmpl.replace("{u}", "{}"), "main": tmpl.split("{u}")[0],
                                        "type": "status_code"})
        _SITES_CACHE = sites
    return _SITES_CACHE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _check_site(name, site, u):
    """Проверка одного сайта по правилам Sherlock: status_code / message / response_url."""
    if site.get("regex") and not re.search(site["regex"], u):
        return None   # ник не подходит под правила сайта
    url = site["url"].replace("{}", u)
    probe = (site.get("probe") or site["url"]).replace("{}", u)
    kind = site.get("type", "status_code")
    headers = {"User-Agent": BROWSER_UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.8"}
    headers.update(site.get("headers") or {})
    method = site.get("method") or ("GET" if kind == "message" else "GET")
    req = urllib.request.Request(probe, headers=headers, method=method)
    opener = (urllib.request.build_opener(_NoRedirect) if kind == "response_url"
              else urllib.request.build_opener())
    proxy = (SETTINGS.get("proxy") or "").strip()
    if proxy:
        opener.add_handler(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    body = ""
    try:
        with opener.open(req, timeout=10) as r:
            code = r.status
            if kind == "message":
                body = r.read(400_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as he:
        code = he.code
        if kind == "message":
            try:
                body = he.read(400_000).decode("utf-8", "replace")
            except Exception:
                body = ""
    if kind == "status_code":
        exists = 200 <= code < 300 and code not in (site.get("codes") or [])
    elif kind == "message":
        exists = 200 <= code < 400 and not any(m in body for m in site.get("msg", []))
    else:  # response_url: профиль есть, если нет редиректа на страницу ошибки
        exists = 200 <= code < 300
    return {"site": name, "url": url, "code": code, "exists": exists}


def username_search(username, sites=None, job=None):
    """Ищет публичные профили с данным ником на ~460 сайтах (параллельно).
    Это не перебор: один запрос на сайт, смотрим код ответа / строку-маркер."""
    u = re.sub(r"[^\w.\-]", "", username.strip())[:40]
    if not u:
        raise ValueError("Пустой ник")
    job = job or Job()
    db = load_sites()
    names = sites or sorted(db, key=str.lower)
    job.total(len(names))
    res = pmap(lambda n: _check_site(n, db[n], u), names, job, workers=40)
    found, absent, errors, skipped = [], [], [], 0
    for name, r, err in res:
        if err:
            errors.append({"site": name, "err": err})
        elif r is None:
            skipped += 1
        else:
            (found if r["exists"] else absent).append(r)
    # Контроль: сайты, которые «находят» и заведомо несуществующий ник, отвечают одинаково на всё —
    # их находки недостоверны. Проверяем только сайты, где ник найден.
    import random
    import string
    unreliable = []
    if found:
        job.note("Контрольная проверка найденных…")
        job.total(job.all + len(found))
        n = max(8, min(len(u), 12))
        ctrl = random.choice(string.ascii_lowercase) + "".join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(n - 1))
        res2 = pmap(lambda r: _check_site(r["site"], db[r["site"]], ctrl), found, job, workers=40)
        bad = {r["site"] for r, c, err in res2 if c is not None and c["exists"]}
        unreliable = [r for r in found if r["site"] in bad]
        found = [r for r in found if r["site"] not in bad]
    found.sort(key=lambda x: x["site"].lower())
    return {"username": u, "found": found, "absent": [{"site": a["site"]} for a in absent],
            "unreliable": [{"site": r["site"], "url": r["url"]} for r in unreliable],
            "errors": errors, "checked": len(names) - skipped, "skipped": skipped,
            "note": "Сайты, которые «находят» и случайный несуществующий ник, вынесены в «недостоверные». "
                    "Найденные профили всё равно откройте и проверьте вручную."}


_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)$")


def email_recon(email):
    """Разбор email: синтаксис, MX-записи домена, наличие Gravatar."""
    email = email.strip().lower()
    m = _RE_EMAIL.match(email)
    if not m:
        return {"email": email, "valid_syntax": False}
    domain = m.group(1)
    mx = []
    try:
        mx = dns_lookup(domain)["records"].get("MX", [])
    except Exception:
        pass
    gravatar = None
    try:
        h = hashlib.md5(email.encode()).hexdigest()
        req = urllib.request.Request(f"https://www.gravatar.com/avatar/{h}?d=404",
                                     method="HEAD", headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                gravatar = r.status == 200
        except urllib.error.HTTPError as he:
            gravatar = he.code == 200
    except Exception:
        pass
    return {"email": email, "valid_syntax": True, "domain": domain,
            "has_mx": bool(mx), "mx": mx[:8], "gravatar": gravatar,
            "gravatar_url": f"https://www.gravatar.com/avatar/{hashlib.md5(email.encode()).hexdigest()}"}


# ================================================================= ИБ (защита)
def pwned_password(password):
    """Проверка пароля по утечкам через k-anonymity HaveIBeenPwned.
    На сервер уходят только первые 5 символов SHA-1 — сам пароль НЕ передаётся."""
    if not password:
        raise ValueError("Пустой пароль")
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    _, _, _, data = _get(f"https://api.pwnedpasswords.com/range/{prefix}",
                         headers={"Add-Padding": "true"}, timeout=12)
    count = 0
    for line in data.decode("utf-8", "replace").splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip().upper() == suffix:
            count = int(parts[1].strip() or 0)
            break
    return {"breached": count > 0, "count": count,
            "advice": "Пароль найден в утечках — не используйте его." if count
            else "В известных утечках не найден (не гарантия стойкости)."}


_COMMON = {"password", "123456", "123456789", "qwerty", "12345678", "111111",
           "123123", "admin", "letmein", "welcome", "monkey", "iloveyou",
           "qwerty123", "1q2w3e", "000000", "password1", "root", "toor"}


def password_strength(password):
    """Оценка стойкости пароля: энтропия, классы символов, оценка времени подбора.
    Чисто локально, ничего не передаётся."""
    pw = password or ""
    L = len(pw)
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^\w]", pw):
        pool += 33
    entropy = round(L * math.log2(pool), 1) if pool and L else 0.0
    penalties = []
    if pw.lower() in _COMMON:
        entropy = min(entropy, 10)
        penalties.append("есть в списке самых частых паролей")
    if re.search(r"(.)\1{2,}", pw):
        penalties.append("повторяющиеся символы")
    if re.search(r"(?:012|123|234|345|456|567|678|789|abc|qwe)", pw.lower()):
        penalties.append("последовательность символов")
    # грубая оценка времени перебора offline (10^10 хэшей/с)
    guesses = 2 ** entropy / 2
    secs = guesses / 1e10
    crack = _human_time(secs)
    verdict = ("очень слабый" if entropy < 28 else "слабый" if entropy < 40 else
               "средний" if entropy < 60 else "сильный" if entropy < 80 else "очень сильный")
    return {"length": L, "entropy_bits": entropy, "charset_size": pool,
            "verdict": verdict, "crack_time_offline": crack, "notes": penalties}


def _human_time(secs):
    if secs < 1:
        return "мгновенно"
    units = [("лет", 31557600), ("дней", 86400), ("часов", 3600),
             ("минут", 60), ("секунд", 1)]
    for name, span in units:
        if secs >= span:
            v = secs / span
            return f"{v:,.0f} {name}" if v < 1e9 else "практически вечно"
    return "мгновенно"


# ================================================================= утилиты
_HASHES = {32: ["MD5", "NTLM"], 40: ["SHA-1"], 56: ["SHA-224"],
           64: ["SHA-256"], 96: ["SHA-384"], 128: ["SHA-512"]}


def hash_text(text):
    """Считает набор хэшей для строки."""
    b = text.encode("utf-8")
    algos = ["md5", "sha1", "sha256", "sha512"]
    out = {a: hashlib.new(a, b).hexdigest() for a in algos}
    return {"input_len": len(text), "hashes": out}


def hash_identify(value):
    """Определяет вероятный тип хэша по длине и алфавиту."""
    v = value.strip()
    guesses = []
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in _HASHES:
        guesses = _HASHES[len(v)]
    elif re.fullmatch(r"\$2[aby]\$\d\d\$.{53}", v):
        guesses = ["bcrypt"]
    elif v.startswith("$argon2"):
        guesses = ["Argon2"]
    elif re.fullmatch(r"[A-Za-z0-9./]{13}", v):
        guesses = ["DES (crypt)"]
    return {"value": v, "length": len(v), "possible": guesses or ["неизвестно"]}


def transform(text, mode, action):
    """Кодирование/декодирование: base64, hex, url, rot13, binary."""
    try:
        if mode == "base64":
            return (base64.b64encode(text.encode()).decode() if action == "encode"
                    else base64.b64decode(text).decode("utf-8", "replace"))
        if mode == "hex":
            return (text.encode().hex() if action == "encode"
                    else binascii.unhexlify(re.sub(r"\s", "", text)).decode("utf-8", "replace"))
        if mode == "url":
            return (urllib.parse.quote(text) if action == "encode"
                    else urllib.parse.unquote(text))
        if mode == "rot13":
            import codecs
            return codecs.encode(text, "rot13")
        if mode == "binary":
            if action == "encode":
                return " ".join(format(b, "08b") for b in text.encode())
            return bytes(int(x, 2) for x in text.split()).decode("utf-8", "replace")
    except Exception as e:
        raise ValueError(f"Не удалось: {type(e).__name__}")
    raise ValueError("Неизвестный режим")


# Телефонные коды стран (компактный набор самых частых).
_PHONE_CC = {
    "1": "США/Канада", "7": "Россия/Казахстан", "20": "Египет", "27": "ЮАР",
    "30": "Греция", "31": "Нидерланды", "32": "Бельгия", "33": "Франция",
    "34": "Испания", "39": "Италия", "40": "Румыния", "41": "Швейцария",
    "43": "Австрия", "44": "Великобритания", "45": "Дания", "46": "Швеция",
    "47": "Норвегия", "48": "Польша", "49": "Германия", "51": "Перу",
    "52": "Мексика", "53": "Куба", "54": "Аргентина", "55": "Бразилия",
    "56": "Чили", "57": "Колумбия", "58": "Венесуэла", "60": "Малайзия",
    "61": "Австралия", "62": "Индонезия", "63": "Филиппины", "64": "Нов. Зеландия",
    "65": "Сингапур", "66": "Таиланд", "81": "Япония", "82": "Юж. Корея",
    "84": "Вьетнам", "86": "Китай", "90": "Турция", "91": "Индия",
    "92": "Пакистан", "93": "Афганистан", "94": "Шри-Ланка", "95": "Мьянма",
    "98": "Иран", "212": "Марокко", "213": "Алжир", "351": "Португалия",
    "352": "Люксембург", "353": "Ирландия", "358": "Финляндия", "359": "Болгария",
    "370": "Литва", "371": "Латвия", "372": "Эстония", "373": "Молдова",
    "374": "Армения", "375": "Беларусь", "376": "Андорра", "380": "Украина",
    "381": "Сербия", "386": "Словения", "420": "Чехия", "421": "Словакия",
    "852": "Гонконг", "886": "Тайвань", "971": "ОАЭ", "972": "Израиль",
    "994": "Азербайджан", "995": "Грузия", "996": "Киргизия", "998": "Узбекистан",
}


def phone_info(number):
    """Разбор номера: код страны, длина, базовая валидация (E.164)."""
    raw = number.strip()
    digits = re.sub(r"\D", "", raw)
    if raw.startswith("+") or number.strip().startswith("00"):
        digits = re.sub(r"\D", "", raw.lstrip("+").lstrip("0") if number.strip().startswith("00") else raw)
    cc, country = None, None
    for length in (3, 2, 1):
        pref = digits[:length]
        if pref in _PHONE_CC:
            cc, country = pref, _PHONE_CC[pref]
            break
    valid = 8 <= len(digits) <= 15
    return {"input": raw, "digits": digits, "e164": "+" + digits if valid else None,
            "country_code": cc, "country": country, "valid": valid,
            "national": digits[len(cc):] if cc else digits}


# ================================================================= РАЗВЕДКА САЙТА
def _fetch_html(url, max_bytes=900_000):
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    status, headers, final, data = _get(url, max_bytes=max_bytes)
    low = {k.lower(): v for k, v in headers.items()}
    text = data.decode("utf-8", "replace")
    return status, low, final, text


def _tags(text, tag):
    """Грубо вытаскивает теги вида <tag ...> и парсит их атрибуты в dict."""
    out = []
    for m in re.finditer(rf"<{tag}\b([^>]*)>", text, re.I):
        attrs = {}
        for a in re.finditer(r'([\w:-]+)\s*=\s*"([^"]*)"|([\w:-]+)\s*=\s*\'([^\']*)\'', m.group(1)):
            k = (a.group(1) or a.group(3)).lower()
            attrs[k] = a.group(2) if a.group(2) is not None else a.group(4)
        out.append(attrs)
    return out


# сигнатуры технологий: (название, где, шаблон). где: header:<имя> | html | cookie
_TECH = [
    ("WordPress", "html", r"/wp-(content|includes)/"),
    ("Drupal", "html", r"Drupal|/sites/(all|default)/"),
    ("Joomla", "html", r"/media/jui/|com_content"),
    ("Bitrix", "html", r"bitrix|/bitrix/"),
    ("Tilda", "html", r"tilda|tildacdn"),
    ("Shopify", "html", r"cdn\.shopify\.com|Shopify"),
    ("Wix", "html", r"wix\.com|_wixCIDX"),
    ("Ghost", "html", r"content=\"Ghost"),
    ("React", "html", r"react(\.production)?\.min\.js|data-reactroot|__NEXT_DATA__"),
    ("Next.js", "html", r"/_next/|__NEXT_DATA__"),
    ("Nuxt.js", "html", r"__NUXT__|/_nuxt/"),
    ("Vue.js", "html", r"vue(\.min)?\.js|data-v-[0-9a-f]"),
    ("Angular", "html", r"ng-version|angular(\.min)?\.js"),
    ("Svelte", "html", r"svelte-[0-9a-z]"),
    ("jQuery", "html", r"jquery[.-]"),
    ("Bootstrap", "html", r"bootstrap(\.min)?\.(css|js)"),
    ("Tailwind", "html", r"tailwind"),
    ("Google Analytics", "html", r"google-analytics\.com|gtag\(|googletagmanager"),
    ("Yandex Metrika", "html", r"mc\.yandex\.ru|metrika"),
    ("Cloudflare", "header:server", r"cloudflare"),
    ("Nginx", "header:server", r"nginx"),
    ("Apache", "header:server", r"apache"),
    ("LiteSpeed", "header:server", r"litespeed"),
    ("Microsoft IIS", "header:server", r"iis|microsoft"),
    ("PHP", "header:x-powered-by", r"php"),
    ("ASP.NET", "header:x-powered-by", r"asp\.net"),
    ("Express", "header:x-powered-by", r"express"),
    ("Varnish", "header:via", r"varnish"),
]


def _detect_tech(low_headers, text):
    found = []
    for name, where, pat in _TECH:
        rx = re.compile(pat, re.I)
        if where == "html":
            hit = rx.search(text)
        elif where.startswith("header:"):
            hit = rx.search(low_headers.get(where.split(":", 1)[1], ""))
        else:
            hit = None
        if hit:
            found.append(name)
    return sorted(set(found))


def site_recon(url):
    """Разведка сайта одним запросом: технологии, мета, OpenGraph, ссылки,
    формы, контакты, безопасность заголовков — всё из публичной страницы."""
    status, low, final, text = _fetch_html(url)
    base = _host(final)
    metas = _tags(text, "meta")
    links_tags = _tags(text, "link")
    title = ""
    mt = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if mt:
        title = html.unescape(re.sub(r"\s+", " ", mt.group(1)).strip())[:300]

    def meta_val(key, attr="name"):
        for m in metas:
            if m.get(attr, "").lower() == key.lower():
                return m.get("content", "").strip()
        return ""

    og = {m.get("property")[3:]: m.get("content", "")
          for m in metas if m.get("property", "").lower().startswith("og:")}
    canonical = next((l.get("href") for l in links_tags if l.get("rel", "").lower() == "canonical"), "")

    # ссылки
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', text, re.I)
    internal, external = set(), set()
    for h in hrefs:
        full = urllib.parse.urljoin(final, h)
        pr = urllib.parse.urlparse(full)
        if pr.scheme not in ("http", "https"):
            continue
        (internal if _host(full) == base else external).add(full.split("#")[0])
    ext_domains = sorted(set(_host(u) for u in external if _host(u)))[:60]

    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", text)))[:40]
    socials = sorted(set(d for d in ext_domains if re.search(
        r"(twitter|x|facebook|instagram|youtube|linkedin|t\.me|vk|tiktok|github|telegram)\.", d)))

    forms = _tags(text, "form")
    has_pw = bool(re.search(r'<input[^>]+type=["\']?password', text, re.I))
    sec = [h for h in _SEC_HEADERS if h in low]

    return {
        "url": final, "status": status, "host": base, "title": title,
        "description": html.unescape(meta_val("description"))[:400],
        "generator": meta_val("generator"),
        "language": meta_val("content-language", "http-equiv") or re.search(
            r'<html[^>]*lang=["\']([^"\']+)', text, re.I).group(1) if re.search(
            r'<html[^>]*lang=["\']([^"\']+)', text, re.I) else "",
        "server": low.get("server"), "powered_by": low.get("x-powered-by"),
        "technologies": _detect_tech(low, text),
        "og": og, "canonical": canonical,
        "links_internal": len(internal), "links_external": len(external),
        "external_domains": ext_domains,
        "emails": emails, "socials": socials,
        "forms": len(forms), "has_login_form": has_pw,
        "security_headers": sec, "security_headers_total": len(_SEC_HEADERS),
        "page_size_kb": round(len(text) / 1024, 1),
    }


def robots_sitemap(url):
    """robots.txt + обнаружение и разбор sitemap.xml."""
    host = _host(url)
    root = ("https://" + host).rstrip("/")
    disallow, sitemaps, agents = [], [], 0
    try:
        _, _, _, data = _get(root + "/robots.txt", max_bytes=200_000)
        robots = data.decode("utf-8", "replace")
        for line in robots.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                disallow.append(line.split(":", 1)[1].strip())
            elif line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
            elif line.lower().startswith("user-agent:"):
                agents += 1
    except Exception:
        robots = ""
    if not sitemaps:
        sitemaps = [root + "/sitemap.xml"]
    urls = []
    for sm in sitemaps[:3]:
        try:
            _, _, _, data = _get(sm, max_bytes=500_000)
            urls += re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", data.decode("utf-8", "replace"))
        except Exception:
            pass
    return {"host": host, "robots_found": bool(robots), "user_agents": agents,
            "disallow": [d for d in disallow if d][:80], "sitemaps": sitemaps,
            "sitemap_urls_count": len(urls), "sitemap_urls": urls[:150]}


def redirect_chain(url):
    """Трассировка цепочки перенаправлений (до 10 переходов)."""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    class _NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedir)
    hops, cur, seen = [], url, set()
    for _ in range(10):
        if cur in seen:
            break
        seen.add(cur)
        req = urllib.request.Request(cur, headers={"User-Agent": UA}, method="HEAD")
        try:
            resp = opener.open(req, timeout=TIMEOUT)
            code = resp.status
            loc = resp.headers.get("Location")
        except urllib.error.HTTPError as he:
            code = he.code
            loc = he.headers.get("Location")
        hops.append({"url": cur, "status": code})
        if loc and 300 <= code < 400:
            cur = urllib.parse.urljoin(cur, loc)
        else:
            break
    return {"start": url, "hops": hops, "final": hops[-1]["url"] if hops else url,
            "count": len(hops)}


def email_security(domain):
    """Антиспуфинг-постура домена: SPF, DMARC, DKIM, MX."""
    name = _host(domain)
    txt = _doh(name, "TXT")
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    dmarc = None
    try:
        dt = _doh("_dmarc." + name, "TXT")
        dmarc = next((t for t in dt if "v=dmarc1" in t.lower()), None)
    except Exception:
        pass
    sels = ("default", "google", "selector1", "selector2", "k1", "k2", "k3", "dkim", "mail", "s1", "s2",
            "smtp", "mx", "key1", "key2", "20230601", "20221208", "20210112", "20161025", "mandrill",
            "everlytickey1", "zoho", "mailjet", "sendgrid", "s1024", "s2048", "sig1", "fm1", "fm2",
            "protonmail", "protonmail2", "yandex", "mail-ru", "dk", "pm", "amazonses", "turbo-smtp")

    def has(sel):
        return bool(_doh(f"{sel}._domainkey.{name}", "TXT") or _doh(f"{sel}._domainkey.{name}", "CNAME"))
    dkim = sorted(sel for sel, ok, err in pmap(has, sels, workers=16) if ok)
    mx = _doh(name, "MX")
    score = sum([bool(spf), bool(dmarc), bool(dkim), bool(mx)])
    return {"domain": name, "spf": spf, "dmarc": dmarc, "dkim_selectors": dkim,
            "mx": mx[:6], "has_mx": bool(mx), "posture_score": f"{score}/4"}


def security_txt(url):
    """/.well-known/security.txt (RFC 9116)."""
    host = _host(url)
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            _, _, final, data = _get("https://" + host + path, max_bytes=50_000)
            body = data.decode("utf-8", "replace")
            if "contact" in body.lower() or "expires" in body.lower():
                fields = {}
                for line in body.splitlines():
                    if ":" in line and not line.strip().startswith("#"):
                        k, v = line.split(":", 1)
                        fields.setdefault(k.strip(), []).append(v.strip())
                return {"found": True, "url": final, "fields": fields, "raw": body[:2000]}
        except Exception:
            pass
    return {"found": False, "host": host}


def _mmh3_32(data, seed=0):
    """MurmurHash3 x86 32-bit (для favicon-хэша в стиле Shodan). Знаковый."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed
    rend = length & 0xfffffffc
    for i in range(0, rend, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | ((data[i + 3] & 0xff) << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 3
    if tail == 3:
        k1 ^= (data[rend + 2] & 0xff) << 16
    if tail >= 2:
        k1 ^= (data[rend + 1] & 0xff) << 8
    if tail >= 1:
        k1 ^= (data[rend] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(url):
    """Favicon-хэш (mmh3, совместим с Shodan http.favicon.hash) + ссылки для пивотинга."""
    host = _host(url)
    tried = []
    fav = None
    # пробуем из HTML <link rel=icon>, затем /favicon.ico
    candidates = ["https://" + host + "/favicon.ico"]
    try:
        _, _, final, text = _fetch_html("https://" + host, max_bytes=300_000)
        for l in _tags(text, "link"):
            if "icon" in l.get("rel", "").lower() and l.get("href"):
                candidates.insert(0, urllib.parse.urljoin(final, l["href"]))
    except Exception:
        pass
    for c in candidates:
        tried.append(c)
        try:
            _, _, _, data = _get(c, max_bytes=1_000_000)
            if data and len(data) > 60:
                fav = (c, data)
                break
        except Exception:
            pass
    if not fav:
        raise ValueError("favicon не найден")
    c, data = fav
    b64 = base64.encodebytes(data)  # как в Shodan (с переносами строк)
    mm = _mmh3_32(b64)
    return {"favicon_url": c, "mmh3": mm, "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "shodan": f"http.favicon.hash:{mm}",
            "shodan_url": f"https://www.shodan.io/search?query=http.favicon.hash%3A{mm}"}


def rdap(target):
    """RDAP (структурированный WHOIS) для домена или IP/ASN через rdap.org."""
    t = target.strip()
    kind = "ip" if re.match(r"^[\d.:a-fA-F]+$", t) and (":" in t or t.count(".") == 3) else "domain"
    j = _get_json(f"https://rdap.org/{kind}/{urllib.parse.quote(t)}", timeout=20)
    events = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    entities = []
    for e in j.get("entities", [])[:6]:
        roles = ",".join(e.get("roles", []))
        handle = e.get("handle", "")
        entities.append(f"{roles}: {handle}" if handle else roles)
    return {"target": t, "kind": kind, "handle": j.get("handle"),
            "name": j.get("name") or j.get("ldhName"),
            "type": j.get("objectClassName"), "status": j.get("status", []),
            "country": j.get("country"), "start": j.get("startAddress"),
            "end": j.get("endAddress"), "events": events, "entities": entities}


def reverse_ip(ip):
    """Другие домены на том же IP (hackertarget; есть суточный лимит)."""
    ip = ip.strip()
    ipaddress.ip_address(ip)
    _, _, _, data = _get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=20)
    body = data.decode("utf-8", "replace").strip()
    if "error" in body.lower() or "API count exceeded" in body:
        return {"ip": ip, "error": body[:120], "domains": []}
    doms = [d.strip() for d in body.splitlines() if d.strip()]
    return {"ip": ip, "count": len(doms), "domains": doms[:200]}


# ================================================================= ДОП. УТИЛИТЫ
def jwt_decode(token):
    """Разбор JWT без проверки подписи: header, payload, срок действия."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Не похоже на JWT (нужно 3 части через точку)")

    def b64u(s):
        s += "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s).decode("utf-8", "replace"))

    header = b64u(parts[0])
    payload = b64u(parts[1])
    exp_info = None
    if "exp" in payload:
        try:
            exp = dt.datetime.fromtimestamp(int(payload["exp"]), dt.timezone.utc)
            delta = (exp - dt.datetime.now(dt.timezone.utc)).total_seconds()
            exp_info = {"expires": exp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "expired": delta < 0,
                        "in": _human_time(abs(delta))}
        except Exception:
            pass
    return {"alg": header.get("alg"), "typ": header.get("typ"),
            "header": header, "payload": payload, "signature_present": len(parts) == 3,
            "expiry": exp_info}


def cidr_calc(cidr):
    """Калькулятор подсети: диапазон, маска, число хостов."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    hosts = list(net.hosts()) if net.num_addresses <= 2 else None
    return {"network": str(net.network_address), "broadcast": str(net.broadcast_address),
            "netmask": str(net.netmask), "prefix": net.prefixlen,
            "version": net.version, "total_addresses": net.num_addresses,
            "usable_hosts": max(net.num_addresses - 2, 0) if net.version == 4 and net.prefixlen < 31 else net.num_addresses,
            "first": str(net[0]), "last": str(net[-1]), "is_private": net.is_private}


def timestamp_tool(value):
    """Конвертер времени: unix ↔ ISO. Пусто → текущее время."""
    v = value.strip()
    if not v:
        ts = dt.datetime.now(dt.timezone.utc)
        unix = int(ts.timestamp())
    elif re.fullmatch(r"\d{10,13}", v):
        n = int(v)
        if len(v) == 13:
            n //= 1000
        unix = n
        ts = dt.datetime.fromtimestamp(n, dt.timezone.utc)
    else:
        ts = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.timezone.utc)
        unix = int(ts.timestamp())
    return {"unix": unix, "unix_ms": unix * 1000,
            "iso_utc": ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "rfc": ts.astimezone(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "weekday": ts.astimezone(dt.timezone.utc).strftime("%A")}


def uuid_tool(value):
    """Генерация UUIDv4 (если пусто) или разбор переданного UUID."""
    import uuid as _uuid
    v = value.strip()
    if not v:
        u = _uuid.uuid4()
        return {"generated": str(u), "version": 4}
    u = _uuid.UUID(v)
    info = {"uuid": str(u), "version": u.version, "variant": u.variant, "hex": u.hex}
    if u.version == 1:
        ts = (u.time - 0x01b21dd213814000) / 1e7
        info["timestamp"] = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return info


def idn_tool(domain):
    """Punycode/IDN + предупреждение о гомоглифах (смешанные алфавиты)."""
    d = domain.strip().lower()
    try:
        ascii_form = d.encode("idna").decode()
    except Exception:
        ascii_form = d
    try:
        unicode_form = ascii_form.encode().decode("idna")
    except Exception:
        unicode_form = d
    scripts = set()
    for ch in unicode_form:
        if ch.isalpha():
            if "Ѐ" <= ch <= "ӿ":
                scripts.add("Кириллица")
            elif "a" <= ch <= "z":
                scripts.add("Латиница")
            elif "Ͱ" <= ch <= "Ͽ":
                scripts.add("Греческий")
            else:
                scripts.add("Другой")
    return {"input": d, "ascii_punycode": ascii_form, "unicode": unicode_form,
            "scripts": sorted(scripts),
            "homograph_warning": len(scripts) > 1}


def shannon_entropy(text):
    """Энтропия Шеннона строки — помогает заметить ключи/секреты."""
    if not text:
        return {"entropy": 0, "bits_total": 0, "length": 0}
    from collections import Counter
    counts = Counter(text)
    n = len(text)
    ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
    likely = ent > 3.5 and len(text) >= 16 and bool(re.fullmatch(r"[A-Za-z0-9+/=_\-]+", text))
    return {"entropy": round(ent, 3), "bits_total": round(ent * n, 1),
            "length": n, "unique_chars": len(counts),
            "looks_like_secret": likely}


def luhn_check(number):
    """Проверка по алгоритму Луна (карты, IMEI и т.п.)."""
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not digits:
        raise ValueError("Нет цифр")
    s, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return {"input": number.strip(), "digits": len(digits), "valid": s % 10 == 0}


def base_convert(value):
    """Перевод числа между системами: dec/hex/oct/bin. Вход авто-определяется."""
    v = value.strip().lower().replace(" ", "")
    if v.startswith("0x"):
        n = int(v, 16)
    elif v.startswith("0o"):
        n = int(v, 8)
    elif v.startswith("0b"):
        n = int(v, 2)
    elif re.fullmatch(r"[0-9a-f]+", v) and re.search(r"[a-f]", v):
        n = int(v, 16)
    else:
        n = int(v, 10)
    return {"decimal": n, "hex": hex(n), "octal": oct(n), "binary": bin(n), "bit_length": n.bit_length()}


def dork_builder(domain):
    """Генератор поисковых dork-ссылок (Google/Bing/GitHub) по домену."""
    d = _host(domain)
    g = "https://www.google.com/search?q="
    def q(s): return g + urllib.parse.quote(s)
    return {"domain": d, "links": {
        "Файлы (pdf/doc/xls)": q(f'site:{d} (filetype:pdf OR filetype:doc OR filetype:xls)'),
        "Логины/админки": q(f'site:{d} (inurl:login OR inurl:admin OR intitle:login)'),
        "Конфиги/.env/бэкапы": q(f'site:{d} (ext:env OR ext:bak OR ext:sql OR ext:log OR ext:config)'),
        "Открытые директории": q(f'site:{d} intitle:"index of"'),
        "Поддомены (минус www)": q(f'site:*.{d} -www'),
        "Email на странице": q(f'site:{d} "@{d}"'),
        "GitHub-упоминания": f'https://github.com/search?q={urllib.parse.quote(d)}&type=code',
        "Pastebin": q(f'site:pastebin.com {d}'),
    }}


# -------------------------------------------- диспетчер (используется из UI)
TOOLS = {
    # разведка домена/сети
    "dns": lambda p: dns_lookup(p["q"]),
    "reverse_dns": lambda p: reverse_dns(p["q"]),
    "ip_info": lambda p: ip_info(p["q"]),
    "whois": lambda p: whois_domain(p["q"]),
    "rdap": lambda p: rdap(p["q"]),
    "ssl": lambda p: ssl_cert(p["q"]),
    "headers": lambda p: http_headers(p["q"]),
    "subdomains": lambda p: subdomains(p["q"]),
    "wayback": lambda p: wayback(p["q"]),
    "reverse_ip": lambda p: reverse_ip(p["q"]),
    # полная разведка сайта
    "site_recon": lambda p: site_recon(p["q"]),
    "robots": lambda p: robots_sitemap(p["q"]),
    "tech": lambda p: {"url": p["q"], **_tech_only(p["q"])},
    "redirects": lambda p: redirect_chain(p["q"]),
    "email_sec": lambda p: email_security(p["q"]),
    "security_txt": lambda p: security_txt(p["q"]),
    "favicon": lambda p: favicon_hash(p["q"]),
    # OSINT: люди
    "username": lambda p: username_search(p["q"], job=p.get("_job")),
    "email": lambda p: email_recon(p["q"]),
    "phone": lambda p: phone_info(p["q"]),
    # ИБ (защита)
    "pwned": lambda p: pwned_password(p["q"]),
    "strength": lambda p: password_strength(p["q"]),
    # утилиты
    "hash": lambda p: hash_text(p["q"]),
    "hash_id": lambda p: hash_identify(p["q"]),
    "jwt": lambda p: jwt_decode(p["q"]),
    "cidr": lambda p: cidr_calc(p["q"]),
    "timestamp": lambda p: timestamp_tool(p["q"]),
    "uuid": lambda p: uuid_tool(p["q"]),
    "idn": lambda p: idn_tool(p["q"]),
    "entropy": lambda p: shannon_entropy(p["q"]),
    "luhn": lambda p: luhn_check(p["q"]),
    "base": lambda p: base_convert(p["q"]),
    "dork": lambda p: dork_builder(p["q"]),
    "transform": lambda p: {"result": transform(p["q"], p.get("mode", "base64"),
                                                p.get("action", "encode"))},
}


def _tech_only(url):
    status, low, final, text = _fetch_html(url, max_bytes=500_000)
    return {"final": final, "server": low.get("server"),
            "powered_by": low.get("x-powered-by"),
            "technologies": _detect_tech(low, text)}


def run_tool(name, params, job=None):
    if name not in TOOLS:
        raise KeyError(f"Неизвестный инструмент: {name}")
    params = dict(params)
    params["_job"] = job or Job()
    return TOOLS[name](params)
