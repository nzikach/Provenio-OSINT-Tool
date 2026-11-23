#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Provenio OSINT+ — расширенный набор инструментов (версия 2).

Идеи взяты у известных открытых проектов, код написан заново на стандартной
библиотеке Python (без копирования чужого кода):
  theHarvester -> harvester        dnstwist   -> lookalikes
  Photon / gau -> crawl, wayback_urls gitleaks -> secrets_scan
  ExifTool     -> file_meta        iocextract -> ioc_extract
  gitrecon     -> github_recon     cve-search -> cve_lookup

Собственные инструменты Provenio: tracking_ids (связанные сайты по ID счётчиков),
domain_history (хронология домена), evidence_verify (проверка пакета доказательств).

Принципы те же: только публичные данные, никаких переборов паролей,
эксплойтов и проб уязвимостей чужих систем.
"""
import base64
import hashlib
import io
import ipaddress
import json
import re
import socket
import struct
import urllib.parse
import urllib.request
import urllib.error
import zipfile
import zlib
import datetime as dt
from collections import Counter, defaultdict

import provenio_tools as T

RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|mp3|avi|mov|zip|rar|7z|"
                       r"gz|exe|dmg|iso|pdf|docx?|xlsx?|pptx?)(\?|$)", re.I)


def _job(p):
    return p.get("_job") or T.Job()


def _url(u):
    u = u.strip()
    return u if re.match(r"^https?://", u, re.I) else "https://" + u


def _resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def _mask(v):
    v = str(v)
    return v if len(v) <= 10 else f"{v[:4]}…{v[-4:]} ({len(v)} симв.)"


# ================================================================= theHarvester-подобный сбор
_CONTACT_PATHS = ["", "/contact", "/contacts", "/about", "/about-us", "/kontakty", "/impressum",
                  "/team", "/.well-known/security.txt"]


def harvester(domain, job=None):
    """Email, поддомены и хосты организации из публичных источников:
    Certificate Transparency, архив Wayback, HackerTarget, страницы сайта."""
    job = job or T.Job()
    d = T._host(domain)
    if "." not in d:
        raise ValueError("Нужен домен, например example.com")
    hosts, emails, used, errors = set(), set(), [], {}
    job.total(4 + len(_CONTACT_PATHS))

    job.note("Certificate Transparency (crt.sh, certspotter)…")
    try:
        sd = T.subdomains(d)
        hosts |= set(sd["subdomains"])
        used += sd["sources"]
        errors.update(sd["errors"])
    except Exception as e:
        errors["CT-логи"] = type(e).__name__
    job.step()

    job.note("HackerTarget…")
    try:
        _, _, _, data = T._get(f"https://api.hackertarget.com/hostsearch/?q={d}", timeout=20)
        body = data.decode("utf-8", "replace")
        if "error" not in body.lower() and "API count" not in body:
            for line in body.splitlines():
                h = line.split(",")[0].strip().lower()
                if h.endswith(d):
                    hosts.add(h)
            used.append("hackertarget")
        else:
            errors["hackertarget"] = body[:80]
    except Exception as e:
        errors["hackertarget"] = type(e).__name__
    job.step()

    job.note("Архив Wayback…")
    try:
        _, _, _, data = T._get("https://web.archive.org/cdx/search/cdx?url=*." + d +
                               "&fl=original&collapse=urlkey&limit=2000", timeout=25, max_bytes=4_000_000,
                               retries=0)
        for line in data.decode("utf-8", "replace").splitlines():
            h = T._host(line)
            if h.endswith(d) and re.fullmatch(r"[a-z0-9.\-]+", h):
                hosts.add(h)
            for m in RE_EMAIL.findall(urllib.parse.unquote(line)):
                emails.add(m.lower())
        used.append("wayback")
    except Exception as e:
        errors["wayback"] = type(e).__name__
    job.step()

    for path in _CONTACT_PATHS:
        job.note(f"Страница {path or '/'}…")
        try:
            _, _, _, data = T._get(f"https://{d}{path}", max_bytes=1_500_000, timeout=12)
            text = data.decode("utf-8", "replace")
            for m in RE_EMAIL.findall(text):
                if not _SKIP_EXT.search(m):
                    emails.add(m.lower().strip("."))
            for m in re.findall(r"mailto:([^\"'?>\s]+)", text, re.I):
                emails.add(urllib.parse.unquote(m).lower())
        except Exception:
            pass
        job.step()
    if any(True for _ in emails):
        used.append("страницы сайта")

    hosts.discard("")
    hosts = sorted(h for h in hosts if "*" not in h)[:600]
    job.note(f"Разрешение {len(hosts)} хостов в IP…")
    job.total(job.all + len(hosts))
    res = T.pmap(lambda h: _resolve(h), hosts, job, workers=48)
    rows = sorted(({"host": h, "ips": ips or []} for h, ips, _ in res), key=lambda r: r["host"])
    ip_count = Counter(ip for r in rows for ip in r["ips"])
    own = [e for e in emails if e.endswith("@" + d) or e.endswith("." + d)]
    return {"domain": d, "sources": list(dict.fromkeys(used)), "errors": errors,
            "emails": sorted(own) + sorted(e for e in emails if e not in own)[:100],
            "hosts_total": len(rows), "hosts_alive": sum(1 for r in rows if r["ips"]),
            "hosts": rows, "top_ips": [{"ip": ip, "hosts": n} for ip, n in ip_count.most_common(30)]}


# ================================================================= dnstwist-подобные «двойники»
_KEYB = {
    "q": "12wa", "w": "23qeas", "e": "34wrsd", "r": "45etdf", "t": "56ryfg", "y": "67tugh", "u": "78yihj",
    "i": "89uojk", "o": "90ipkl", "p": "0ol", "a": "qwsz", "s": "weadzx", "d": "erfcxs", "f": "rtgvcd",
    "g": "tyhbvf", "h": "yujnbg", "j": "uikmnh", "k": "iolmj", "l": "opk", "z": "asx", "x": "zsdc",
    "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk", "1": "2q", "2": "13wq", "3": "24ew",
    "4": "35re", "5": "46tr", "6": "57yt", "7": "68uy", "8": "79iu", "9": "80oi", "0": "9po"}
_GLYPHS = {
    "a": ["а", "à", "á", "â", "ã", "ä", "å", "ɑ"], "b": ["d", "lb", "ь"], "c": ["с", "e", "ç"],
    "d": ["b", "cl", "dl", "ԁ"], "e": ["е", "c", "é", "è", "ê", "ë"], "g": ["q", "ɡ"],
    "h": ["lh", "һ"], "i": ["1", "l", "і", "í", "ï"], "j": ["ј"], "k": ["lk", "ik", "к"],
    "l": ["1", "i", "ӏ"], "m": ["n", "nn", "rn", "rr"], "n": ["m", "r", "п"], "o": ["0", "о", "ο", "ö", "ó"],
    "p": ["р"], "q": ["g"], "r": ["г"], "s": ["ѕ", "5"], "t": ["т"], "u": ["υ", "ü", "ú"],
    "v": ["ѵ"], "w": ["vv", "ѡ"], "x": ["х"], "y": ["у", "ý"], "z": ["2"]}
_TLDS = ["com", "net", "org", "ru", "info", "biz", "co", "io", "xyz", "online", "site", "shop",
         "app", "top", "me", "su", "pro", "store", "live", "tech", "cc", "us", "uk", "de", "kz", "by", "ua"]
_WORDS = ["login", "secure", "support", "account", "online", "verify", "pay", "help", "my", "app",
          "auth", "id", "portal", "service", "update", "web", "mail", "bank", "official", "office"]


def _split_domain(d):
    parts = d.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "edu", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def domain_permutations(domain):
    """Генерация похожих доменов (typosquatting/фишинг). Возвращает {домен: метод}."""
    name, tld = _split_domain(domain)
    sub, _, core = name.rpartition(".")
    pre = sub + "." if sub else ""
    out = {}

    def add(n, kind, t=tld):
        if not n or n == core and t == tld or n.startswith("-") or n.endswith("-") or len(n) > 63:
            return
        dom = f"{pre}{n}.{t}"
        out.setdefault(dom, kind)

    for t in _TLDS:
        if t != tld:
            add(core, "смена зоны", t)
    for i in range(len(core)):
        add(core[:i] + core[i + 1:], "пропуск буквы")
        add(core[:i] + core[i] * 2 + core[i + 1:], "повтор буквы")
        if i < len(core) - 1:
            add(core[:i] + core[i + 1] + core[i] + core[i + 2:], "перестановка")
        for g in _GLYPHS.get(core[i], []):
            add(core[:i] + g + core[i + 1:], "гомоглиф")
        for k in _KEYB.get(core[i], ""):
            add(core[:i] + k + core[i + 1:], "соседняя клавиша")
            add(core[:i] + k + core[i:], "вставка")
        if core[i] in "aeiou":
            for v in "aeiou":
                if v != core[i]:
                    add(core[:i] + v + core[i + 1:], "замена гласной")
        for bit in range(8):
            c = chr(ord(core[i]) ^ (1 << bit))
            if re.fullmatch(r"[a-z0-9\-]", c):
                add(core[:i] + c + core[i + 1:], "bitsquatting")
        if 0 < i < len(core):
            add(core[:i] + "-" + core[i:], "дефис")
            out.setdefault(f"{pre}{core[:i]}.{core[i:]}.{tld}", "поддомен")
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789":
        add(core + ch, "добавление")
    for w in _WORDS:
        add(f"{core}-{w}", "словарь")
        add(f"{w}-{core}", "словарь")
        add(core + w, "словарь")
    out.pop(domain, None)
    return out


def _idna(d):
    try:
        return d.encode("idna").decode()
    except UnicodeError:
        return None


def lookalikes(domain, job=None, limit=1500):
    """Проверка, какие из похожих доменов уже зарегистрированы и указывают на IP
    (защита бренда от фишинга, как dnstwist)."""
    job = job or T.Job()
    d = T._host(domain)
    if "." not in d:
        raise ValueError("Нужен домен, например example.com")
    perms = domain_permutations(d)
    items = []
    for dom, kind in perms.items():
        a = _idna(dom)
        if a:
            items.append((dom, a, kind))
    items = items[:limit]
    # защита от провайдеров, которые отвечают IP-адресом на несуществующие домены
    junk = set(_resolve(f"provenio-nx-{hashlib.md5(d.encode()).hexdigest()[:10]}.com"))
    job.total(len(items))
    job.note(f"Проверка {len(items)} вариантов…")
    res = T.pmap(lambda it: _resolve(it[1]), items, job, workers=64)
    hits = [{"domain": it[0], "ascii": it[1], "method": it[2], "ips": ips}
            for it, ips, err in res if ips and not set(ips) <= junk]
    own_ips = set(_resolve(d))
    for h in hits:
        h["same_ip_as_original"] = bool(own_ips & set(h["ips"]))
    hits.sort(key=lambda h: (h["method"] != "гомоглиф", h["domain"]))
    by_method = Counter(h["method"] for h in hits)
    return {"domain": d, "generated": len(perms), "checked": len(items), "registered": len(hits),
            "by_method": dict(by_method), "results": hits,
            "note": "Найденные домены — кандидаты. Совпадение IP с оригиналом обычно значит, "
                    "что домен принадлежит самому владельцу бренда."}


# ================================================================= Photon-подобный обход сайта
def crawl(url, job=None, max_pages=60):
    """Обход сайта в пределах одного хоста: страницы, JS, email, телефоны,
    формы, внешние домены, интересные файлы и комментарии в HTML."""
    job = job or T.Job()
    start = _url(url)
    host = T._host(start)
    seen, queue = {start.split("#")[0]}, [start.split("#")[0]]
    pages, scripts, emails, phones, ext_domains = [], set(), set(), set(), Counter()
    files, params, comments, forms = set(), set(), [], []
    job.total(max_pages)

    def fetch(u):
        status, low, final, text = T._fetch_html(u, max_bytes=1_200_000)
        ctype = low.get("content-type", "")
        return status, final, text if "html" in ctype or not ctype else ""

    while queue and len(pages) < max_pages:
        batch, queue = queue[:8], queue[8:]
        for u, r, err in T.pmap(fetch, batch, job, workers=8):
            if err or not r:
                pages.append({"url": u, "status": err or "?"})
                continue
            status, final, text = r
            title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            pages.append({"url": final, "status": status,
                          "title": re.sub(r"\s+", " ", title.group(1)).strip()[:120] if title else ""})
            for m in RE_EMAIL.findall(text):
                if not _SKIP_EXT.search(m):
                    emails.add(m.lower())
            for m in re.findall(r"tel:([+\d][\d\s().\-]{6,20})", text, re.I):
                phones.add(re.sub(r"[^\d+]", "", m))
            for m in re.findall(r"<!--(.*?)-->", text, re.S):
                c = " ".join(m.split())
                if 8 < len(c) < 300 and re.search(r"todo|fixme|password|passwd|secret|key|token|debug|"
                                                  r"admin|test|api|internal|staging|dev", c, re.I):
                    comments.append({"page": final, "text": c})
            for f in T._tags(text, "form"):
                forms.append({"page": final, "action": f.get("action", ""), "method": f.get("method", "get")})
            for s in T._tags(text, "script"):
                if s.get("src"):
                    scripts.add(urllib.parse.urljoin(final, s["src"]))
            for h in re.findall(r'(?:href|src)=["\']([^"\'#]+)', text, re.I):
                full = urllib.parse.urljoin(final, h)
                pr = urllib.parse.urlparse(full)
                if pr.scheme not in ("http", "https"):
                    continue
                for k in urllib.parse.parse_qs(pr.query):
                    params.add(k)
                if T._host(full) != host:
                    ext_domains[T._host(full)] += 1
                    continue
                if re.search(r"\.(pdf|docx?|xlsx?|pptx?|zip|rar|7z|bak|sql|csv|txt|xml|json|log)(\?|$)",
                             pr.path, re.I):
                    files.add(full)
                    continue
                if _SKIP_EXT.search(pr.path):
                    continue
                clean = full.split("#")[0]
                if clean not in seen and len(seen) < max_pages * 6:
                    seen.add(clean)
                    queue.append(clean)
        job.note(f"Страниц: {len(pages)}, в очереди: {len(queue)}")
    return {"start": start, "host": host, "pages_crawled": len(pages), "pages": pages,
            "emails": sorted(emails), "phones": sorted(phones)[:50],
            "scripts": sorted(scripts)[:150], "files": sorted(files)[:200],
            "forms": forms[:60], "params": sorted(params)[:200], "comments": comments[:60],
            "external_domains": [{"domain": d, "links": n} for d, n in ext_domains.most_common(80)]}


# ================================================================= gau/waymore: URL из архива
_URL_GROUPS = [
    ("Конфиги и бэкапы", r"\.(env|bak|old|orig|swp|sql|db|sqlite|config|conf|cfg|ini|ya?ml|log|tar|gz|zip|7z|rar)(\?|$)"),
    ("Документы", r"\.(pdf|docx?|xlsx?|pptx?|csv|odt|rtf|txt)(\?|$)"),
    ("Скрипты и API", r"\.(js|json|php|aspx?|jsp|cgi|pl|py)(\?|$)|/api/|/graphql|/v\d+/"),
    ("Админки и вход", r"admin|login|signin|wp-admin|dashboard|panel|cpanel|phpmyadmin|auth"),
]


def wayback_urls(domain, job=None, limit=8000):
    """Все известные архиву Wayback URL домена (как gau/waymore), сгруппированные."""
    job = job or T.Job()
    d = T._host(domain)
    rows, used, errors = [], [], {}
    job.total(2)
    job.note("Запрос к CDX-индексу Wayback…")
    try:
        _, _, _, data = T._get(f"https://web.archive.org/cdx/search/cdx?url={d}/*&output=json"
                               f"&fl=original,timestamp&collapse=urlkey&limit={min(limit, 5000)}",
                               timeout=30, max_bytes=12_000_000, retries=0)
        rows = [(r[0], r[1]) for r in json.loads(data.decode("utf-8", "replace") or "[]")[1:]]
        used.append("Wayback")
    except Exception as e:
        errors["Wayback"] = type(e).__name__
    job.step()
    job.note("AlienVault OTX…")
    try:
        for page in range(1, 6):
            j = T._get_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/url_list"
                            f"?limit=500&page={page}", timeout=25)
            for x in j.get("url_list", []):
                ts = re.sub(r"\D", "", x.get("date") or "")[:14]
                rows.append((x.get("url"), ts))
            if not j.get("has_next"):
                break
        used.append("AlienVault OTX")
    except Exception as e:
        errors["AlienVault OTX"] = type(e).__name__
    job.step()
    if not used:
        raise ConnectionError("Wayback и OTX недоступны: " + ", ".join(f"{k}: {v}" for k, v in errors.items()))
    seen = {}
    for u, ts in rows:
        if u and u not in seen:
            seen[u] = ts
    urls = list(seen)
    stamps = sorted(t for t in seen.values() if t)
    groups = {}
    for name, rx in _URL_GROUPS:
        groups[name] = [u for u in urls if re.search(rx, u, re.I)][:300]
    params = Counter()
    for u in urls:
        for k in urllib.parse.parse_qs(urllib.parse.urlparse(u).query):
            params[k] += 1
    subs = Counter(T._host(u) for u in urls)
    return {"domain": d, "total": len(urls), "sources": used, "errors": errors,
            "first_seen": stamps[0] if stamps else None, "last_seen": stamps[-1] if stamps else None,
            "groups": {k: v for k, v in groups.items() if v},
            "params": [{"param": k, "count": n} for k, n in params.most_common(60)],
            "hosts": [{"host": h, "urls": n} for h, n in subs.most_common(40)],
            "sample": urls[:400]}


# ================================================================= gitleaks-подобный поиск секретов
_SECRET_RULES = [
    ("AWS Access Key ID", "высокий", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Google API Key", "средний", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("GitHub Token", "высокий", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ("GitLab Token", "высокий", r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
    ("Slack Token", "высокий", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    ("Slack Webhook", "высокий", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("Stripe Secret Key", "высокий", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"),
    ("Stripe Publishable Key", "инфо", r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
    ("Telegram Bot Token", "высокий", r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b"),
    ("Twilio API Key", "высокий", r"\bSK[0-9a-fA-F]{32}\b"),
    ("SendGrid API Key", "высокий", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("Mailgun API Key", "высокий", r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("OpenAI API Key", "высокий", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"),
    ("Anthropic API Key", "высокий", r"\bsk-ant-[A-Za-z0-9_\-]{80,}\b"),
    ("Private Key", "критический", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("JWT", "средний", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("Firebase URL", "инфо", r"\b[a-z0-9\-]+\.firebaseio\.com\b"),
    ("Azure Storage Key", "высокий", r"AccountKey=[A-Za-z0-9+/=]{60,}"),
    ("Пароль в URL", "высокий", r"\b[a-z][a-z0-9+.\-]*://[^/\s:@\"']{1,64}:[^/\s:@\"']{1,64}@[^\s\"'/]+"),
    ("Yandex Cloud / OAuth", "средний", r"\b(?:AQVN[A-Za-z0-9_\-]{35,38}|y[0-3]_[A-Za-z0-9_\-]{55,})\b"),
]
_GENERIC = re.compile(r"""(?i)\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|"""
                      r"""passw(?:or)?d|private[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{12,200})["']""")


def _entropy(s):
    import math
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def scan_text(text, where="текст"):
    found = []
    lines = text.splitlines() or [text]
    for i, line in enumerate(lines[:200_000], 1):
        if len(line) > 20000:
            line = line[:20000]
        for name, sev, rx in _SECRET_RULES:
            for m in re.finditer(rx, line):
                found.append({"type": name, "severity": sev, "where": where, "line": i,
                              "value": _mask(m.group(0))})
        for m in _GENERIC.finditer(line):
            val = m.group(2)
            if _entropy(val) > 3.3 and not re.fullmatch(r"[a-z_\-.]+", val, re.I):
                found.append({"type": f"Секрет в присваивании ({m.group(1)})", "severity": "средний",
                              "where": where, "line": i, "value": _mask(val)})
    return found


def secrets_scan(q, job=None):
    """Ищет утёкшие ключи/токены. Вход: URL (страница + её JS-файлы) или произвольный текст.
    Значения маскируются — полные секреты в отчёт не попадают."""
    job = job or T.Job()
    q = q.strip()
    targets = []
    if re.fullmatch(r"(https?://)?[^\s/]+\.[^\s]+", q) and "\n" not in q:
        url = _url(q)
        job.note("Загрузка страницы…")
        status, low, final, text = T._fetch_html(url, max_bytes=3_000_000)
        targets.append((final, text))
        srcs = [urllib.parse.urljoin(final, s["src"]) for s in T._tags(text, "script") if s.get("src")]
        srcs = list(dict.fromkeys(srcs))[:40]
        job.total(len(srcs) + 1)
        job.step()
        for u, r, err in T.pmap(lambda u: T._get(u, max_bytes=4_000_000, timeout=20)[3], srcs, job, workers=8):
            if r is not None:
                targets.append((u, r.decode("utf-8", "replace")))
        mode = "url"
    else:
        targets.append(("введённый текст", q))
        mode = "text"
    found = []
    for where, text in targets:
        found += scan_text(text, where)
    seen, uniq = set(), []
    for f in found:
        k = (f["type"], f["value"], f["where"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    order = {"критический": 0, "высокий": 1, "средний": 2, "инфо": 3}
    uniq.sort(key=lambda f: order.get(f["severity"], 9))
    return {"mode": mode, "scanned": [w for w, _ in targets], "files_scanned": len(targets),
            "findings": uniq[:300], "count": len(uniq),
            "by_severity": dict(Counter(f["severity"] for f in uniq)),
            "note": "Значения замаскированы. Нашли свой ключ — отзовите и перевыпустите его."}


# ================================================================= ExifTool-подобные метаданные
_EXIF_TAGS = {0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
              0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist", 0x013C: "HostComputer",
              0x8298: "Copyright", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
              0x9011: "OffsetTimeOriginal", 0xA002: "ImageWidth", 0xA003: "ImageHeight",
              0xA430: "CameraOwnerName", 0xA431: "BodySerialNumber", 0xA433: "LensMake",
              0xA434: "LensModel", 0xA435: "LensSerialNumber", 0x829A: "ExposureTime",
              0x829D: "FNumber", 0x8827: "ISO", 0x920A: "FocalLength", 0x9286: "UserComment"}
_GPS_TAGS = {1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef", 4: "GPSLongitude",
             5: "GPSAltitudeRef", 6: "GPSAltitude", 7: "GPSTimeStamp", 29: "GPSDateStamp"}
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def parse_tiff(buf):
    """Разбор TIFF/EXIF-блока: IFD0, Exif IFD, GPS IFD."""
    if len(buf) < 8:
        return {}
    end = "<" if buf[:2] == b"II" else ">"
    out = {}

    def val(typ, count, off_or_val, raw_pos):
        size = _TYPE_SIZE.get(typ, 1) * count
        data = buf[raw_pos:raw_pos + 4] if size <= 4 else buf[off_or_val:off_or_val + size]
        if typ == 2:
            return data[:count].split(b"\0")[0].decode("utf-8", "replace").strip()
        if typ == 3:
            v = struct.unpack(end + "H" * count, data[:2 * count])
        elif typ in (4, 9):
            v = struct.unpack(end + ("L" if typ == 4 else "l") * count, data[:4 * count])
        elif typ in (5, 10):
            nums = struct.unpack(end + ("L" if typ == 5 else "l") * (2 * count), data[:8 * count])
            v = tuple(round(nums[i] / nums[i + 1], 6) if nums[i + 1] else 0 for i in range(0, len(nums), 2))
        elif typ == 7:
            txt = data[8:].split(b"\0")[0] if data[:8] in (b"ASCII\0\0\0", b"UNICODE\0") else b""
            return txt.decode("utf-8", "replace").strip() if txt else None
        else:
            v = tuple(data[:count])
        return v[0] if len(v) == 1 else list(v)

    def ifd(pos, names, depth=0):
        if pos <= 0 or pos + 2 > len(buf) or depth > 3:
            return
        n = struct.unpack(end + "H", buf[pos:pos + 2])[0]
        for i in range(min(n, 300)):
            e = pos + 2 + i * 12
            if e + 12 > len(buf):
                break
            tag, typ, count, off = struct.unpack(end + "HHLL", buf[e:e + 12])
            try:
                if tag == 0x8769:
                    ifd(off, _EXIF_TAGS, depth + 1)
                elif tag == 0x8825:
                    ifd(off, _GPS_TAGS, depth + 1)
                elif tag in names and count < 10000:
                    v = val(typ, count, off, e + 8)
                    if v not in (None, "", []):
                        out[names[tag]] = v
            except struct.error:
                continue

    first = struct.unpack(end + "L", buf[4:8])[0]
    ifd(first, _EXIF_TAGS)
    return out


def _gps(meta):
    try:
        def dec(v, ref):
            d, m, s = (list(v) + [0, 0, 0])[:3]
            x = d + m / 60 + s / 3600
            return round(-x if ref in ("S", "W") else x, 6)
        lat = dec(meta["GPSLatitude"], meta.get("GPSLatitudeRef", "N"))
        lon = dec(meta["GPSLongitude"], meta.get("GPSLongitudeRef", "E"))
        return {"lat": lat, "lon": lon,
                "osm": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
                "google": f"https://www.google.com/maps?q={lat},{lon}"}
    except (KeyError, TypeError, ValueError):
        return None


def _xmp(text):
    out = {}
    for tag in ("CreatorTool", "creator", "Author", "ModifyDate", "CreateDate", "MetadataDate",
                "Producer", "DocumentID", "OriginalDocumentID", "title", "Make", "Model", "Lens",
                "GPSLatitude", "GPSLongitude", "City", "Country", "Credit", "Rights"):
        m = re.search(rf"<(?:\w+:)?{tag}[^>]*>(.*?)</(?:\w+:)?{tag}>", text, re.S) or \
            re.search(rf'(?:\w+:)?{tag}="([^"]+)"', text)
        if m:
            v = re.sub(r"<[^>]+>", " ", m.group(1))
            v = " ".join(v.split())
            if v:
                out[tag] = v[:300]
    return out


def _jpeg(data):
    meta, pos = {}, 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):
            break
        ln = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg = data[pos + 4:pos + 2 + ln]
        if marker == 0xE1 and seg[:6] == b"Exif\0\0":
            meta.update(parse_tiff(seg[6:]))
        elif marker == 0xE1 and b"ns.adobe.com/xap" in seg[:40]:
            meta.update({"XMP:" + k: v for k, v in _xmp(seg.decode("utf-8", "replace")).items()})
        elif marker == 0xFE:
            meta["Comment"] = seg.decode("utf-8", "replace")[:300]
        pos += 2 + ln
    return meta


def _png(data):
    meta, pos = {}, 8
    while pos + 8 <= len(data):
        ln, typ = struct.unpack(">L4s", data[pos:pos + 8])
        chunk = data[pos + 8:pos + 8 + ln]
        if typ == b"tEXt":
            k, _, v = chunk.partition(b"\0")
            meta[k.decode("latin-1")] = v.decode("latin-1")[:500]
        elif typ == b"zTXt":
            k, _, v = chunk.partition(b"\0")
            try:
                meta[k.decode("latin-1")] = zlib.decompress(v[1:]).decode("latin-1")[:500]
            except zlib.error:
                pass
        elif typ == b"iTXt":
            k, _, rest = chunk.partition(b"\0")
            comp, rest = rest[0], rest[2:]
            _, _, rest = rest.partition(b"\0")
            _, _, text = rest.partition(b"\0")
            try:
                text = zlib.decompress(text) if comp else text
            except zlib.error:
                pass
            t = text.decode("utf-8", "replace")
            if "xmpmeta" in t:
                meta.update({"XMP:" + a: b for a, b in _xmp(t).items()})
            else:
                meta[k.decode("latin-1")] = t[:500]
        elif typ == b"eXIf":
            meta.update(parse_tiff(chunk))
        elif typ == b"tIME" and len(chunk) == 7:
            y, mo, d, h, mi, s = struct.unpack(">HBBBBB", chunk)
            meta["ModifyTime"] = f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}"
        elif typ == b"IEND":
            break
        pos += 12 + ln
    if len(data) > 24:
        w, h = struct.unpack(">LL", data[16:24])
        meta["ImageWidth"], meta["ImageHeight"] = w, h
    return meta


def _pdf(data):
    text = data.decode("latin-1", "replace")
    meta = {"PDFVersion": text[5:8] if text.startswith("%PDF-") else None,
            "Encrypted": "/Encrypt" in text,
            "PagesApprox": len(re.findall(r"/Type\s*/Page[^s]", text))}

    def pdfstr(s):
        if s.startswith("<") and s.endswith(">"):
            try:
                b = bytes.fromhex(s[1:-1])
                return b.decode("utf-16") if b[:2] in (b"\xfe\xff", b"\xff\xfe") else b.decode("latin-1")
            except ValueError:
                return s
        s = s[1:-1]
        b = s.encode("latin-1", "replace")
        if b[:2] == b"\xfe\xff":
            try:
                return b.decode("utf-16")
            except UnicodeDecodeError:
                pass
        return re.sub(r"\\([()\\])", r"\1", s)

    for key in ("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"):
        m = re.search(rf"/{key}\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f]+>)", text)
        if m:
            v = pdfstr(m.group(1)).strip()
            if key.endswith("Date"):
                d = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?", v)
                if d:
                    v = "{}-{}-{} {}:{}".format(d.group(1), d.group(2) or "01", d.group(3) or "01",
                                                d.group(4) or "00", d.group(5) or "00")
            meta[key] = v[:300]
    x = re.search(r"<x:xmpmeta.*?</x:xmpmeta>", text, re.S)
    if x:
        meta.update({"XMP:" + k: v for k, v in _xmp(x.group(0)).items()})
    return {k: v for k, v in meta.items() if v not in (None, "")}


def _office(data):
    meta = {}
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()

    def grab(name, prefix=""):
        if name not in names:
            return
        t = z.read(name).decode("utf-8", "replace")
        for m in re.finditer(r"<(?:[\w]+:)?([\w\-]+)[^>/]*>([^<]{1,300})</", t):
            k, v = m.group(1), m.group(2).strip()
            if v and k not in ("Properties", "coreProperties", "vt"):
                meta[prefix + k] = v

    grab("docProps/core.xml")
    grab("docProps/app.xml")
    grab("docProps/custom.xml", "custom:")
    grab("meta.xml")   # OpenDocument
    meta["ZipEntries"] = len(names)
    media = [n for n in names if "/media/" in n]
    if media:
        meta["EmbeddedMedia"] = len(media)
    return meta


def file_meta(p):
    """Метаданные файла (как ExifTool): EXIF/GPS фото, автор и программа PDF/DOCX/XLSX/PPTX/ODT.
    Вход: загруженный файл (base64) или URL файла."""
    job = _job(p)
    if p.get("file"):
        data = base64.b64decode(p["file"])
        name = p.get("filename") or "файл"
    else:
        url = _url(p.get("q", ""))
        job.note("Загрузка файла…")
        _, _, _, data = T._get(url, max_bytes=30_000_000, timeout=60)
        name = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1] or url
    if len(data) > 30_000_000:
        raise ValueError("Файл больше 30 МБ")
    kind, meta = "неизвестно", {}
    try:
        if data[:3] == b"\xff\xd8\xff":
            kind, meta = "JPEG", _jpeg(data)
        elif data[:8] == b"\x89PNG\r\n\x1a\n":
            kind, meta = "PNG", _png(data)
        elif data[:4] in (b"II*\0", b"MM\0*"):
            kind, meta = "TIFF / RAW", parse_tiff(data)
        elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            kind = "WebP"
            i = data.find(b"EXIF")
            if i > 0:
                ln = struct.unpack("<L", data[i + 4:i + 8])[0]
                blk = data[i + 8:i + 8 + ln]
                meta = parse_tiff(blk[6:] if blk[:6] == b"Exif\0\0" else blk)
        elif data[:5] == b"%PDF-":
            kind, meta = "PDF", _pdf(data)
        elif data[:2] == b"PK":
            kind, meta = "Office / ZIP", _office(data)
        elif data[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftypmsf1"):
            kind = "HEIC"
            i = data.find(b"Exif\0\0")
            if i > 0:
                meta = parse_tiff(data[i + 6:])
    except Exception as e:
        meta["_parse_error"] = f"{type(e).__name__}: {e}"
    gps = _gps(meta)
    meta = {k: (v if not isinstance(v, (bytes, bytearray)) else v.hex()) for k, v in meta.items()}
    sensitive = [k for k in meta if re.search(r"GPS|Owner|Serial|Artist|Author|creator|lastModifiedBy|"
                                              r"Company|HostComputer|initial-creator", k, re.I)]
    return {"name": name, "type": kind, "size": len(data),
            "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "gps": gps, "metadata": meta, "sensitive_fields": sensitive,
            "note": "Метаданные часто раскрывают автора, устройство и место съёмки. "
                    "Перед публикацией своих файлов удаляйте их."}


# ================================================================= Shodan InternetDB (бесплатно, без ключа)
def internetdb(target):
    """Открытые порты, уязвимости (CVE) и технологии IP по данным Shodan InternetDB.
    Provenio сам ничего не сканирует — это уже собранные Shodan публичные данные."""
    t = target.strip()
    try:
        ips = [str(ipaddress.ip_address(t))]
    except ValueError:
        ips = [ip for ip in _resolve(T._host(t)) if ":" not in ip][:5]
        if not ips:
            raise ValueError("Не удалось получить IP")
    out = []
    for ip in ips:
        try:
            j = T._get_json(f"https://internetdb.shodan.io/{ip}", timeout=15)
            out.append({"ip": ip, "ports": j.get("ports", []), "hostnames": j.get("hostnames", []),
                        "cpes": j.get("cpes", []), "tags": j.get("tags", []), "vulns": j.get("vulns", [])})
        except urllib.error.HTTPError as he:
            out.append({"ip": ip, "ports": [], "note": "нет данных" if he.code == 404 else f"HTTP {he.code}"})
    return {"target": t, "results": out,
            "shodan_links": [f"https://www.shodan.io/host/{r['ip']}" for r in out]}


# ================================================================= репутация IOC
def _ioc_type(v):
    v = v.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", v):
        return "hash"
    if re.match(r"^https?://", v, re.I):
        return "url"
    if re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", v.lower()):
        return "domain"
    raise ValueError("Ожидается IP, домен, URL или хэш")


_DNSBL = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net"]


def reputation(ioc, job=None):
    """Репутация IP/домена/URL/хэша по открытым базам угроз: AlienVault OTX, urlscan.io,
    Shodan InternetDB, DNSBL; с ключами — ещё VirusTotal и AbuseIPDB."""
    job = job or T.Job()
    v = ioc.strip()
    kind = _ioc_type(v)
    res, errors = {}, {}
    job.total(5)

    def run(name, fn):
        job.note(name + "…")
        try:
            res[name] = fn()
        except Exception as e:
            errors[name] = f"{type(e).__name__}: {str(e)[:100]}"
        job.step()

    def otx():
        sect = {"ip": "IPv4" if ":" not in v else "IPv6", "domain": "domain", "url": "url", "hash": "file"}[kind]
        h = {"X-OTX-API-KEY": T.key("otx")} if T.key("otx") else None
        j = T._get_json(f"https://otx.alienvault.com/api/v1/indicators/{sect}/{urllib.parse.quote(v, safe='')}/general",
                        headers=h, timeout=25)
        pi = j.get("pulse_info") or {}
        return {"pulses": pi.get("count", 0),
                "pulse_names": [x.get("name") for x in (pi.get("pulses") or [])[:8]],
                "reputation": j.get("reputation"),
                "whitelisted": bool(j.get("validation")),
                "link": f"https://otx.alienvault.com/indicator/{sect.lower()}/{v}"}

    def urlscan():
        if kind == "hash":
            return {"skipped": "для хэшей не применяется"}
        q = f"ip:{v}" if kind == "ip" else f"domain:{T._host(v)}"
        h = {"API-Key": T.key("urlscan")} if T.key("urlscan") else None
        j = T._get_json("https://urlscan.io/api/v1/search/?size=10&q=" + urllib.parse.quote(q), headers=h, timeout=25)
        rs = j.get("results") or []
        return {"total": j.get("total", 0),
                "recent": [{"time": (r.get("task") or {}).get("time"), "url": (r.get("page") or {}).get("url"),
                            "ip": (r.get("page") or {}).get("ip"), "result": r.get("result")} for r in rs[:10]]}

    def idb():
        if kind not in ("ip", "domain"):
            return {"skipped": "только для IP и доменов"}
        return internetdb(v)["results"]

    def dnsbl():
        ips = [v] if kind == "ip" else ([x for x in _resolve(T._host(v)) if ":" not in x][:1] if kind != "hash" else [])
        if not ips or ":" in ips[0]:
            return {"skipped": "нужен IPv4"}
        rev = ".".join(reversed(ips[0].split(".")))
        out = {}
        for bl in _DNSBL:
            try:
                a = socket.gethostbyname(f"{rev}.{bl}")
                out[bl] = "запрос отклонён (публичный DNS)" if a.startswith("127.255.255") else f"В СПИСКЕ ({a})"
            except socket.gaierror:
                out[bl] = "чисто"
        return {"ip": ips[0], "lists": out}

    def paid():
        out = {}
        if T.key("virustotal"):
            path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}.get(kind)
            ident = v
            if kind == "url":
                path, ident = "urls", base64.urlsafe_b64encode(v.encode()).decode().strip("=")
            j = T._get_json(f"https://www.virustotal.com/api/v3/{path}/{ident}",
                            headers={"x-apikey": T.key("virustotal")}, timeout=25)
            st = ((j.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            out["virustotal"] = st
        if T.key("abuseipdb") and kind == "ip":
            j = T._get_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={v}&maxAgeInDays=365",
                            headers={"Key": T.key("abuseipdb")}, timeout=25)
            d = j.get("data") or {}
            out["abuseipdb"] = {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
                                "isp": d.get("isp"), "usage": d.get("usageType")}
        if not out:
            out["note"] = "Добавьте ключи VirusTotal / AbuseIPDB в настройках для дополнительных проверок"
        return out

    run("AlienVault OTX", otx)
    run("urlscan.io", urlscan)
    run("Shodan InternetDB", idb)
    run("DNSBL", dnsbl)
    run("VirusTotal / AbuseIPDB", paid)

    score = 0
    o = res.get("AlienVault OTX") or {}
    score += min(o.get("pulses", 0), 10) * 5
    lists = ((res.get("DNSBL") or {}).get("lists") or {}).values()
    score += 20 * sum(1 for x in lists if str(x).startswith("В СПИСКЕ"))
    vt = (res.get("VirusTotal / AbuseIPDB") or {}).get("virustotal") or {}
    score += min(vt.get("malicious", 0), 10) * 6
    ab = (res.get("VirusTotal / AbuseIPDB") or {}).get("abuseipdb") or {}
    score += (ab.get("score") or 0) // 2
    if o.get("whitelisted"):
        score = min(score, 10)
    score = min(score, 100)
    verdict = "опасно" if score >= 60 else "подозрительно" if score >= 25 else "угроз не найдено"
    return {"ioc": v, "type": kind, "risk_score": score, "verdict": verdict, "sources": res, "errors": errors}


# ================================================================= ASN / сети (RIPEstat)
def asn_info(target):
    """Кому принадлежит IP или ASN, какие сети анонсирует; поиск AS по названию организации."""
    t = target.strip()
    base = "https://stat.ripe.net/data/{}/data.json?resource={}"

    def get(kind, res):
        return (T._get_json(base.format(kind, urllib.parse.quote(res)), timeout=30) or {}).get("data") or {}

    out = {"query": t}
    asn = None
    try:
        ipaddress.ip_address(t)
        ni = get("network-info", t)
        out["prefix"] = ni.get("prefix")
        out["asns"] = ni.get("asns", [])
        asn = out["asns"][0] if out["asns"] else None
    except ValueError:
        m = re.fullmatch(r"(?i)as?(\d+)", t)
        if m:
            asn = m.group(1)
        else:
            sc = get("searchcomplete", t)
            sugg = []
            for cat in sc.get("categories", []):
                for s in cat.get("suggestions", []):
                    sugg.append({"category": cat.get("category"), "value": s.get("value"),
                                 "description": s.get("description")})
            out["search"] = sugg[:40]
            return out
    if asn:
        ov = get("as-overview", f"AS{asn}")
        out["asn"] = f"AS{asn}"
        out["holder"] = ov.get("holder")
        out["announced"] = ov.get("announced")
        pf = get("announced-prefixes", f"AS{asn}")
        prefixes = [p.get("prefix") for p in pf.get("prefixes", [])]
        v4 = [p for p in prefixes if ":" not in p]
        out["prefixes_v4"] = v4[:300]
        out["prefixes_v6"] = [p for p in prefixes if ":" in p][:100]
        out["prefix_count"] = len(prefixes)
        total = 0
        for p in v4:
            try:
                total += ipaddress.ip_network(p, strict=False).num_addresses
            except ValueError:
                pass
        out["ipv4_addresses"] = total
        out["links"] = {"bgp.he.net": f"https://bgp.he.net/AS{asn}",
                        "RIPEstat": f"https://stat.ripe.net/AS{asn}"}
    return out


# ================================================================= GitHub-разведка
def github_recon(username, job=None):
    """Публичный профиль GitHub: репозитории, организации, email из публичных коммитов, SSH-ключи."""
    job = job or T.Job()
    u = username.strip().lstrip("@")
    u = re.sub(r"^https?://github\.com/", "", u).split("/")[0]
    if not re.fullmatch(r"[A-Za-z0-9\-]{1,39}", u):
        raise ValueError("Некорректный логин GitHub")
    h = {"Accept": "application/vnd.github+json"}
    if T.key("github"):
        h["Authorization"] = "Bearer " + T.key("github")
    api = "https://api.github.com"
    job.total(4)
    job.note("Профиль…")
    prof = T._get_json(f"{api}/users/{u}", headers=h)
    job.step()
    repos = T._get_json(f"{api}/users/{u}/repos?per_page=100&sort=pushed", headers=h)
    orgs = T._get_json(f"{api}/users/{u}/orgs", headers=h)
    job.step()
    own = [r for r in repos if not r.get("fork")][:8]
    emails = Counter()
    names = Counter()
    job.total(4 + len(own))
    job.note("Email из публичных коммитов…")

    def commits(r):
        return T._get_json(f"{api}/repos/{u}/{r['name']}/commits?per_page=20", headers=h)

    for r, cs, err in T.pmap(commits, own, job, workers=4):
        for c in cs or []:
            for who in ("author", "committer"):
                a = (c.get("commit") or {}).get(who) or {}
                if a.get("email"):
                    emails[a["email"].lower()] += 1
                if a.get("name"):
                    names[a["name"]] += 1
    keys = []
    try:
        _, _, _, data = T._get(f"https://github.com/{u}.keys", timeout=15)
        keys = [line.split()[0] for line in data.decode().splitlines() if line.strip()]
    except Exception:
        pass
    job.step()
    langs = Counter(r.get("language") for r in repos if r.get("language"))
    return {"login": prof.get("login"), "name": prof.get("name"), "bio": prof.get("bio"),
            "company": prof.get("company"), "blog": prof.get("blog"), "location": prof.get("location"),
            "email_public": prof.get("email"), "twitter": prof.get("twitter_username"),
            "created_at": prof.get("created_at"), "updated_at": prof.get("updated_at"),
            "followers": prof.get("followers"), "following": prof.get("following"),
            "public_repos": prof.get("public_repos"), "avatar": prof.get("avatar_url"),
            "profile": prof.get("html_url"),
            "orgs": [o.get("login") for o in orgs],
            "languages": dict(langs.most_common(10)),
            "repos": [{"name": r["name"], "stars": r.get("stargazers_count"), "fork": r.get("fork"),
                       "pushed_at": r.get("pushed_at"), "url": r.get("html_url"),
                       "description": (r.get("description") or "")[:150]} for r in repos[:40]],
            "commit_emails": [{"email": e, "commits": n, "noreply": "noreply" in e}
                              for e, n in emails.most_common(20)],
            "commit_names": [n for n, _ in names.most_common(10)],
            "ssh_keys": {"count": len(keys), "types": dict(Counter(keys))}}


# ================================================================= публичный Telegram-канал
def telegram_channel(name):
    """Публичный канал Telegram через веб-превью t.me/s/: описание, подписчики, последние посты."""
    n = name.strip().lstrip("@")
    n = re.sub(r"^(https?://)?(t\.me|telegram\.me)/(s/)?", "", n).split("/")[0].split("?")[0]
    if not re.fullmatch(r"[A-Za-z0-9_]{4,64}", n):
        raise ValueError("Некорректное имя канала")
    status, low, final, text = T._fetch_html(f"https://t.me/s/{n}", max_bytes=3_000_000)

    def clean(s):
        s = re.sub(r"<br\s*/?>", "\n", s)
        s = re.sub(r"<[^>]+>", "", s)
        import html as _h
        return _h.unescape(s).strip()

    def first(rx):
        m = re.search(rx, text, re.S)
        return clean(m.group(1)) if m else None

    counters = dict((clean(t), clean(v)) for v, t in re.findall(
        r'<span class="counter_value">(.*?)</span>\s*<span class="counter_type">(.*?)</span>', text, re.S))
    posts = []
    for block in re.split(r'<div class="tgme_widget_message_wrap', text)[1:]:
        pid = re.search(r'data-post="([^"]+)"', block)
        body = re.search(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', block, re.S)
        when = re.search(r'<time[^>]+datetime="([^"]+)"', block)
        views = re.search(r'<span class="tgme_widget_message_views">([^<]+)', block)
        links = re.findall(r'href="(https?://[^"]+)"', body.group(1)) if body else []
        posts.append({"id": pid.group(1) if pid else None, "date": when.group(1) if when else None,
                      "views": views.group(1) if views else None,
                      "text": clean(body.group(1))[:600] if body else "",
                      "links": [l for l in links if "t.me/" not in l][:10]})
    mentions = Counter(m.lower() for p in posts for m in re.findall(r"@([A-Za-z0-9_]{4,32})", p["text"]))
    domains = Counter(T._host(l) for p in posts for l in p["links"])
    title = first(r'<div class="tgme_channel_info_header_title"[^>]*>(.*?)</div>') or \
        first(r'<meta property="og:title" content="([^"]*)"')
    return {"channel": n, "url": f"https://t.me/{n}", "is_public_channel": bool(posts) or bool(counters),
            "title": title,
            "description": first(r'<div class="tgme_channel_info_description"[^>]*>(.*?)</div>') or
            first(r'<meta property="og:description" content="([^"]*)"'),
            "counters": counters, "posts": posts[-25:][::-1],
            "top_mentions": [{"username": k, "count": v} for k, v in mentions.most_common(20)],
            "top_domains": [{"domain": k, "count": v} for k, v in domains.most_common(20)]}


# ================================================================= извлечение IOC (iocextract)
def refang(t):
    t = re.sub(r"(?i)hxxp", "http", t)
    t = re.sub(r"(?i)fxp", "ftp", t)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), (" dot ", "."),
                 ("[:]", ":"), ("[@]", "@"), ("[at]", "@"), ("(at)", "@"), (" at ", "@"), ("[://]", "://")):
        t = t.replace(a, b).replace(a.upper(), b)
    return t


def defang(v):
    return v.replace("http", "hxxp").replace(".", "[.]").replace("@", "[@]")


_IOC_RX = {
    "url": r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{}]+",
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b",
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "btc": r"\b(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
    "eth": r"\b0x[a-fA-F0-9]{40}\b",
    "mitre_attack": r"\bT1\d{3}(?:\.\d{3})?\b",
    "domain": r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
}
_TLD_JUNK = {"js", "css", "png", "jpg", "jpeg", "gif", "svg", "json", "html", "htm", "php", "exe", "dll",
             "txt", "xml", "zip", "py", "log", "bak", "md", "ini", "bat", "ps1", "sh", "doc", "docx", "pdf",
             "xls", "xlsx", "tmp", "dat", "bin", "sys", "vbs", "jar", "msi", "lnk", "conf", "yml"}


def ioc_extract(text, mode="extract"):
    """Извлекает индикаторы (URL, IP, домены, хэши, CVE, крипто-адреса, техники ATT&CK),
    понимает «обезвреженную» запись (hxxp, [.]); mode: extract | defang | refang."""
    if mode == "defang":
        return {"result": refang(text).replace("http", "hxxp").replace(".", "[.]")}
    if mode == "refang":
        return {"result": refang(text)}
    t = refang(text)
    out = {}
    taken = set()
    for k in ("url", "email", "sha256", "sha1", "md5", "cve", "eth", "btc", "ipv4", "ipv6", "mitre_attack", "domain"):
        vals = []
        flags = re.I if k in ("domain",) else 0
        for m in re.finditer(_IOC_RX[k], t if k != "domain" else t.lower(), flags):
            v = m.group(0).rstrip(".,;:)")
            if k == "domain":
                if v.rsplit(".", 1)[-1] in _TLD_JUNK or any(v in x for x in taken):
                    continue
            if k in ("sha1", "md5") and any(v.lower() in x.lower() for x in out.get("sha256", []) + out.get("sha1", [])):
                continue
            if k == "btc" and re.fullmatch(r"[a-fA-F0-9]+", v):
                continue
            vals.append(v)
        vals = list(dict.fromkeys(vals))
        if vals:
            out[k] = vals[:500]
            taken.update(vals)
    total = sum(len(v) for v in out.values())
    return {"total": total, "iocs": out,
            "defanged": {k: [defang(x) for x in v] for k, v in out.items() if k in ("url", "domain", "ipv4", "email")}}


# ================================================================= CVE (NVD + CISA KEV + EPSS)
_KEV = None


def _kev():
    global _KEV
    if _KEV is None:
        try:
            j = T._get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                            timeout=30)
            _KEV = {v["cveID"]: v for v in j.get("vulnerabilities", [])}
        except Exception:
            _KEV = {}
    return _KEV


def cve_lookup(q, job=None):
    """CVE по номеру или поиск по продукту/версии (например «nginx 1.18.0»):
    CVSS, описание, эксплуатируется ли в дикой природе (CISA KEV), вероятность эксплуатации (EPSS)."""
    job = job or T.Job()
    q = q.strip()
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,7}", q):
        url = base + "cveId=" + q.upper()
    else:
        url = base + "resultsPerPage=25&keywordSearch=" + urllib.parse.quote(q)
    job.note("Запрос к NVD…")
    j = T._get_json(url, timeout=40)
    m = re.fullmatch(r"([A-Za-z0-9_.\-]+)[ /:]+v?(\d[\w.\-]*)", q)
    if not j.get("vulnerabilities") and m:
        job.note("Поиск по CPE (продукт и версия)…")
        cpe = f"cpe:2.3:*:*:{m.group(1).lower()}:{m.group(2)}"
        j = T._get_json(base + "resultsPerPage=50&virtualMatchString=" + urllib.parse.quote(cpe), timeout=40)
    kev = _kev()
    items = []
    for v in j.get("vulnerabilities", []):
        c = v.get("cve") or {}
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score, sev, vec = None, None, None
        mets = c.get("metrics") or {}
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if mets.get(k):
                d = mets[k][0].get("cvssData") or {}
                score, vec = d.get("baseScore"), d.get("vectorString")
                sev = d.get("baseSeverity") or mets[k][0].get("baseSeverity")
                break
        cwe = [d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])]
        items.append({"id": c.get("id"), "published": c.get("published"), "modified": c.get("lastModified"),
                      "score": score, "severity": sev, "vector": vec, "cwe": cwe[:3],
                      "description": desc[:700], "kev": c.get("id") in kev,
                      "kev_due": (kev.get(c.get("id")) or {}).get("dueDate"),
                      "references": [r.get("url") for r in c.get("references", [])[:6]],
                      "nvd": f"https://nvd.nist.gov/vuln/detail/{c.get('id')}"})
    if items:
        job.note("EPSS…")
        try:
            ids = ",".join(i["id"] for i in items[:25])
            e = T._get_json("https://api.first.org/data/v1/epss?cve=" + ids, timeout=20)
            ep = {x["cve"]: x for x in e.get("data", [])}
            for i in items:
                if i["id"] in ep:
                    i["epss"] = round(float(ep[i["id"]]["epss"]) * 100, 2)
        except Exception:
            pass
    items.sort(key=lambda i: (not i["kev"], -(i["score"] or 0)))
    return {"query": q, "total": j.get("totalResults", len(items)), "results": items}


# ================================================================= крипто-адреса
def crypto_address(addr):
    """Баланс и активность BTC/ETH-адреса по публичным обозревателям блокчейна."""
    a = addr.strip()
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", a):
        j = T._get_json(f"https://eth.blockscout.com/api/v2/addresses/{a}", timeout=25)
        cnt = {}
        try:
            cnt = T._get_json(f"https://eth.blockscout.com/api/v2/addresses/{a}/counters", timeout=25)
        except Exception:
            pass
        wei = int(j.get("coin_balance") or 0)
        return {"chain": "Ethereum", "address": a, "balance_eth": round(wei / 1e18, 8),
                "is_contract": j.get("is_contract"), "name": j.get("name"),
                "ens": j.get("ens_domain_name"), "transactions": cnt.get("transactions_count"),
                "token_transfers": cnt.get("token_transfers_count"),
                "explorers": {"Blockscout": f"https://eth.blockscout.com/address/{a}",
                              "Etherscan": f"https://etherscan.io/address/{a}"}}
    if re.fullmatch(r"(bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})", a):
        j = T._get_json(f"https://blockstream.info/api/address/{a}", timeout=25)
        cs, ms = j.get("chain_stats") or {}, j.get("mempool_stats") or {}
        txs = []
        try:
            for t in T._get_json(f"https://blockstream.info/api/address/{a}/txs", timeout=25)[:15]:
                delta = sum(o.get("value", 0) for o in t.get("vout", []) if o.get("scriptpubkey_address") == a) - \
                    sum((i.get("prevout") or {}).get("value", 0) for i in t.get("vin", [])
                        if (i.get("prevout") or {}).get("scriptpubkey_address") == a)
                bt = (t.get("status") or {}).get("block_time")
                txs.append({"txid": t.get("txid"), "btc": round(delta / 1e8, 8),
                            "time": dt.datetime.fromtimestamp(bt, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
                            if bt else "в мемпуле"})
        except Exception:
            pass
        bal = cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)
        return {"chain": "Bitcoin", "address": a, "balance_btc": round(bal / 1e8, 8),
                "received_btc": round(cs.get("funded_txo_sum", 0) / 1e8, 8),
                "sent_btc": round(cs.get("spent_txo_sum", 0) / 1e8, 8),
                "transactions": cs.get("tx_count"), "unconfirmed": ms.get("tx_count"), "recent": txs,
                "explorers": {"Blockstream": f"https://blockstream.info/address/{a}",
                              "Mempool": f"https://mempool.space/address/{a}"}}
    raise ValueError("Поддерживаются адреса Bitcoin (1…, 3…, bc1…) и Ethereum (0x…)")


# ================================================================= поиск по фото и MAC
def reverse_image(url):
    """Готовые ссылки обратного поиска изображения в Google Lens, Яндексе, Bing и TinEye."""
    u = _url(url)
    q = urllib.parse.quote(u, safe="")
    return {"image": u, "links": {
        "Google Lens": f"https://lens.google.com/uploadbyurl?url={q}",
        "Яндекс Картинки": f"https://yandex.com/images/search?rpt=imageview&url={q}",
        "Bing Visual Search": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}",
        "TinEye": f"https://tineye.com/search?url={q}"},
        "note": "Для фото с компьютера: загрузите его вручную на любой из сервисов."}


def mac_vendor(mac):
    """Производитель сетевого устройства по MAC-адресу (OUI) + признаки случайного MAC."""
    h = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(h) < 6:
        raise ValueError("Нужно минимум 6 hex-символов MAC")
    first = int(h[:2], 16)
    norm = ":".join(h[i:i + 2] for i in range(0, min(len(h), 12), 2)).upper()
    vendor = None
    try:
        _, _, _, data = T._get(f"https://api.macvendors.com/{h[:6]}", timeout=10)
        vendor = data.decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as he:
        vendor = "не найден" if he.code == 404 else f"HTTP {he.code}"
    return {"mac": norm, "oui": h[:6].upper(), "vendor": vendor,
            "locally_administered": bool(first & 2), "multicast": bool(first & 1),
            "note": "Локально администрируемый MAC обычно означает случайный адрес (приватность в Wi-Fi)."
            if first & 2 else ""}


# ================================================================= связанные сайты по ID счётчиков (Provenio)
_TRACKERS = [
    ("Google Analytics (UA)", r"\bUA-\d{4,10}-\d{1,4}\b"),
    ("Google Analytics 4", r"\bG-[A-Z0-9]{8,12}\b"),
    ("Google Tag Manager", r"\bGTM-[A-Z0-9]{5,9}\b"),
    ("Google AdSense", r"\b(?:ca-)?pub-\d{10,20}\b"),
    ("Google Ads", r"\bAW-\d{9,12}\b"),
    ("Яндекс Метрика", r"(?:mc\.yandex\.ru/watch/|ym\(\s*|yaCounter)(\d{5,10})"),
    ("Facebook Pixel", r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})"),
    ("Hotjar", r"hjid\s*:\s*(\d{5,10})"),
    ("TikTok Pixel", r"ttq\.load\(\s*['\"]([A-Z0-9]{15,25})"),
    ("VK Pixel", r"\bVK-RTRG-\d+-[A-Za-z0-9]+\b"),
    ("Top.Mail.ru", r"_tmr[^;]{0,80}?id:\s*['\"]?(\d{5,10})"),
    ("Microsoft Clarity", r"clarity['\"]\s*,\s*['\"]script['\"]\s*,\s*['\"]([a-z0-9]{8,12})"),
    ("Google Site Verification", r"google-site-verification['\"]\s+content=['\"]([^'\"]+)"),
    ("Яндекс Верификация", r"yandex-verification['\"]\s+content=['\"]([^'\"]+)"),
    ("Facebook Domain Verification", r"facebook-domain-verification['\"]\s+content=['\"]([^'\"]+)"),
    ("Bing Verification", r"msvalidate\.01['\"]\s+content=['\"]([^'\"]+)"),
]


def _pivot_links(kind, val):
    q = urllib.parse.quote(f'"{val}"')
    links = {"PublicWWW": f"https://publicwww.com/websites/{q}/"}
    if kind.startswith("Google") or kind == "Яндекс Метрика":
        links["BuiltWith"] = f"https://builtwith.com/relationships/tag/{urllib.parse.quote(val)}"
    if kind in ("Google Analytics (UA)", "Google AdSense", "Google Analytics 4", "Google Tag Manager"):
        links["DNSlytics"] = f"https://dnslytics.com/reverse-analytics/{urllib.parse.quote(val)}"
        links["SpyOnWeb"] = f"https://spyonweb.com/{urllib.parse.quote(val)}"
    return links


def tracking_ids(q, job=None):
    """Собственный инструмент Provenio: ID аналитики/рекламы/верификаций и favicon-хэш сайта.
    Одинаковые ID на разных сайтах почти всегда означают одного владельца.
    Можно передать несколько URL через пробел или запятую — общие ID будут показаны."""
    job = job or T.Job()
    targets = [x for x in re.split(r"[\s,;]+", q.strip()) if x]
    if not targets:
        raise ValueError("Нужен URL или домен")
    job.total(len(targets) * 2)

    def one(t):
        status, low, final, text = T._fetch_html(_url(t), max_bytes=2_500_000)
        ids = defaultdict(set)
        for kind, rx in _TRACKERS:
            for m in re.finditer(rx, text):
                ids[kind].add(m.group(1) if m.groups() else m.group(0))
        fav = None
        try:
            fav = T.favicon_hash(final)["mmh3"]
        except Exception:
            pass
        return {"url": final, "ids": {k: sorted(v) for k, v in ids.items()}, "favicon_mmh3": fav}

    sites = []
    for t, r, err in T.pmap(one, targets, job, workers=6):
        sites.append(r or {"url": t, "error": err, "ids": {}})
        job.step()
    occ = defaultdict(set)
    for s in sites:
        for kind, vals in s.get("ids", {}).items():
            for v in vals:
                base = re.sub(r"-\d{1,4}$", "", v) if kind == "Google Analytics (UA)" else v
                occ[(kind, base)].add(s["url"])
        if s.get("favicon_mmh3") is not None:
            occ[("Favicon mmh3", str(s["favicon_mmh3"]))].add(s["url"])
    shared = [{"kind": k, "id": v, "sites": sorted(urls)} for (k, v), urls in occ.items() if len(urls) > 1]
    pivots = []
    for (k, v), urls in occ.items():
        if k == "Favicon mmh3":
            pivots.append({"kind": k, "id": v, "links": {
                "Shodan": f"https://www.shodan.io/search?query=http.favicon.hash%3A{v}"}})
        else:
            pivots.append({"kind": k, "id": v, "links": _pivot_links(k, v)})
    return {"sites": sites, "shared": shared, "pivots": pivots,
            "note": "Откройте ссылки поиска, чтобы найти другие сайты с теми же ID."
                    + (" Общие ID между вашими сайтами показаны выше." if shared else "")}


# ================================================================= хронология домена (Provenio)
def domain_history(domain, job=None):
    """Собственный инструмент Provenio: ключевые даты домена из разных источников —
    регистрация (RDAP/WHOIS), первый SSL-сертификат (CT), первый и последний снимок Wayback."""
    job = job or T.Job()
    d = T._host(domain)
    events, errors = [], {}
    job.total(4)

    def add(date, what, src):
        if date:
            events.append({"date": str(date)[:19].replace("T", " "), "event": what, "source": src})

    job.note("RDAP…")
    try:
        r = T.rdap(d)
        names = {"registration": "Регистрация домена", "last changed": "Изменение записи",
                 "expiration": "Окончание регистрации", "last update of RDAP database": None,
                 "transfer": "Перенос к другому регистратору"}
        for k, v in (r.get("events") or {}).items():
            if names.get(k, k):
                add(v, names.get(k, k), "RDAP")
    except Exception as e:
        errors["rdap"] = type(e).__name__
    job.step()

    job.note("Certificate Transparency…")
    certs = None
    try:
        j = T._get_json(f"https://crt.sh/?q={urllib.parse.quote(d)}&output=json", timeout=40)
        nb = sorted(x.get("not_before") for x in j if x.get("not_before"))
        if nb:
            add(nb[0], "Первый SSL-сертификат в CT-логах", "crt.sh")
            add(nb[-1], "Последний выпущенный сертификат", "crt.sh")
        certs = {"total": len(j), "issuers": dict(Counter(
            re.sub(r".*O=([^,]+).*", r"\1", x.get("issuer_name", "")) for x in j).most_common(6))}
    except Exception as e:
        errors["crt.sh"] = type(e).__name__
    job.step()

    job.note("Wayback Machine…")
    for lim, what in (("1", "Первый снимок в веб-архиве"), ("-1", "Последний снимок в веб-архиве")):
        try:
            _, _, _, data = T._get(f"http://web.archive.org/cdx/search/cdx?url={d}&fl=timestamp,statuscode"
                                   f"&limit={lim}", timeout=30)
            line = data.decode().strip().splitlines()
            if line:
                ts = line[0].split()[0]
                add(f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}", what, "Wayback")
        except Exception as e:
            errors["wayback"] = type(e).__name__
    job.step()

    job.note("Текущий DNS…")
    dns = {}
    try:
        dns = T.dns_lookup(d)["records"]
    except Exception as e:
        errors["dns"] = type(e).__name__
    job.step()
    events.sort(key=lambda e: e["date"])
    age = None
    reg = next((e for e in events if e["event"] == "Регистрация домена"), None) or (events[0] if events else None)
    if reg:
        try:
            y, m, dd = int(reg["date"][:4]), int(reg["date"][5:7]), int(reg["date"][8:10])
            age = round((dt.date.today() - dt.date(y, m, dd)).days / 365.25, 1)
        except ValueError:
            pass
    return {"domain": d, "age_years": age, "timeline": events, "certificates": certs,
            "dns_now": {k: v for k, v in dns.items() if k in ("A", "AAAA", "NS", "MX")}, "errors": errors,
            "note": "Молодой домен (меньше года) у «известного» бренда — частый признак фишинга."}


# ================================================================= проверка пакета доказательств
def evidence_verify(p):
    import provenio as P
    if not p.get("file"):
        raise ValueError("Выберите ZIP-файл пакета доказательств")
    return P.verify_evidence_zip(base64.b64decode(p["file"]))


# ================================================================= регистрация
NEW_TOOLS = {
    "harvester": lambda p: harvester(p["q"], job=p.get("_job")),
    "lookalikes": lambda p: lookalikes(p["q"], job=p.get("_job")),
    "crawl": lambda p: crawl(p["q"], job=p.get("_job")),
    "wayback_urls": lambda p: wayback_urls(p["q"], job=p.get("_job")),
    "secrets": lambda p: secrets_scan(p["q"], job=p.get("_job")),
    "file_meta": file_meta,
    "internetdb": lambda p: internetdb(p["q"]),
    "reputation": lambda p: reputation(p["q"], job=p.get("_job")),
    "asn": lambda p: asn_info(p["q"]),
    "github": lambda p: github_recon(p["q"], job=p.get("_job")),
    "telegram": lambda p: telegram_channel(p["q"]),
    "ioc": lambda p: ioc_extract(p["q"], p.get("mode", "extract")),
    "cve": lambda p: cve_lookup(p["q"], job=p.get("_job")),
    "crypto": lambda p: crypto_address(p["q"]),
    "reverse_image": lambda p: reverse_image(p["q"]),
    "mac": lambda p: mac_vendor(p["q"]),
    "tracking": lambda p: tracking_ids(p["q"], job=p.get("_job")),
    "domain_history": lambda p: domain_history(p["q"], job=p.get("_job")),
    "evidence_verify": evidence_verify,
}
T.TOOLS.update(NEW_TOOLS)
