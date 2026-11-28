#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Provenio 2.1 — расширения:
  * снимок экрана и PDF страницы при архивации (Edge/Chrome в фоновом режиме)
  * проверка ссылки на фишинг (оценка риска по 20+ признакам)
  * IP-радар: один вердикт по IP из ~20 открытых источников
    (идея — проект ip-radar, код написан заново)
  * утечки: XposedOrNot (публичный API, MIT) — email, пароль (k-anonymity), домен
  * данные для «Глобуса» (идея — God's Eye View, MIT; свой интерфейс и код):
    самолёты (OpenSky / airplanes.live), спутники (CelesTrak), землетрясения (USGS),
    природные события (NASA EONET), поиск места (OpenStreetMap Nominatim)
  * сценарии расследования, мониторинг бренда, экспорт графа (GEXF / GraphML / CSV),
    импорт результатов Sherlock и SpiderFoot, проверка обновлений, ИИ-сводка кейса (Claude)

Как и раньше: только публичные данные, никаких переборов и сканирования чужих систем.
"""
import base64
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import xml.sax.saxutils as sx
from collections import Counter

import provenio as P
import provenio_tools as T
import provenio_osint as O

REPO = "nzikach/Provenio-OSINT-Tool"


# ================================================================= снимок экрана / PDF
def find_browser():
    """Edge есть на любом Windows 10/11; если нет — Chrome. Возвращает путь или None."""
    env = os.environ
    cands = []
    for root in (env.get("PROGRAMFILES(X86)"), env.get("PROGRAMFILES"), env.get("LOCALAPPDATA")):
        if root:
            cands += [os.path.join(root, "Microsoft", "Edge", "Application", "msedge.exe"),
                      os.path.join(root, "Google", "Chrome", "Application", "chrome.exe")]
    for c in cands:
        if os.path.isfile(c):
            return c
    for name in ("msedge", "chrome", "chromium", "google-chrome"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _wait_file(path, timeout):
    """Edge запускается отдельным процессом и сразу возвращает управление —
    ждём, пока файл появится и перестанет расти."""
    end, last = time.time() + timeout, -1
    while time.time() < end:
        if os.path.exists(path):
            sz = os.path.getsize(path)
            if sz > 0 and sz == last:
                return True
            last = sz
        time.sleep(0.5)
    return os.path.exists(path) and os.path.getsize(path) > 0


def capture_page(url, screenshot=True, pdf=False, timeout=45, width=1366, height=2200):
    """Снимок страницы средствами браузера без окна. Возвращает [(вид, байты, расширение, заметка)]."""
    exe = find_browser()
    if not exe:
        raise FileNotFoundError("Не найден Microsoft Edge или Google Chrome")
    work = tempfile.mkdtemp(prefix="provenio_cap_")
    base = [exe, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--hide-scrollbars", "--mute-audio", "--disable-sync",
            f"--user-data-dir={os.path.join(work, 'profile')}", "--virtual-time-budget=6000",
            f"--user-agent={T.BROWSER_UA}"]
    proxy = (T.SETTINGS.get("proxy") or "").strip()
    if proxy:
        base.append(f"--proxy-server={proxy}")
    out = []
    flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
    try:
        jobs = []
        if screenshot:
            jobs.append(("screenshot", "png", [f"--window-size={width},{height}",
                                              f"--screenshot={os.path.join(work, 'page.png')}"]))
        if pdf:
            jobs.append(("pdf", "pdf", ["--no-pdf-header-footer", "--print-to-pdf-no-header",
                                        f"--print-to-pdf={os.path.join(work, 'page.pdf')}"]))
        for kind, ext, extra in jobs:
            target = os.path.join(work, "page." + ext)
            subprocess.Popen(base + extra + [url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=flags)
            if _wait_file(target, timeout):
                with open(target, "rb") as f:
                    out.append((kind, f.read(), ext,
                                f"{os.path.basename(exe)} headless · {width}×{height}" if kind == "screenshot"
                                else os.path.basename(exe) + " headless"))
    finally:
        threading.Thread(target=lambda: (time.sleep(20), shutil.rmtree(work, ignore_errors=True)),
                         daemon=True).start()
    return out


def capture_tool(p):
    """Инструмент: скриншот + PDF страницы (без сохранения в кейс — для просмотра)."""
    url = P.normalize_url(p["q"])
    items = capture_page(url, screenshot=True, pdf=True)
    return {"url": url, "files": [{"kind": k, "ext": e, "size": len(b), "sha256": hashlib.sha256(b).hexdigest(),
                                   "data_b64": base64.b64encode(b).decode() if k == "screenshot" else None}
                                  for k, b, e, n in items],
            "browser": find_browser()}


# ================================================================= фишинг
SUSPICIOUS_TLD = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link", "rest",
                  "country", "kim", "work", "fit", "cam", "icu", "sbs", "cfd", "lol", "monster", "quest",
                  "bond", "cyou", "support", "help", "live", "online", "site", "store", "shop", "info"}
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "clck.ru", "goo.su", "t.ly", "is.gd", "ow.ly", "rb.gy",
              "shorturl.at", "tiny.cc", "s.id", "v.gd", "u.to", "qps.ru", "t.co"}
KEYWORDS = ("login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "confirm",
            "wallet", "bank", "password", "billing", "recover", "unlock", "support", "auth", "payment",
            "invoice", "gift", "prize", "bonus", "vhod", "oplata", "vozvrat", "kompensac")
BRANDS = {
    "paypal": ["paypal.com"], "apple": ["apple.com", "icloud.com"], "icloud": ["icloud.com", "apple.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com"],
    "office365": ["office.com", "microsoft.com"], "outlook": ["outlook.com", "live.com", "microsoft.com"],
    "google": ["google.com", "google.ru", "gmail.com"], "gmail": ["gmail.com", "google.com"],
    "facebook": ["facebook.com", "fb.com"], "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"], "amazon": ["amazon.com"], "netflix": ["netflix.com"],
    "steam": ["steampowered.com", "steamcommunity.com"], "binance": ["binance.com"],
    "coinbase": ["coinbase.com"], "metamask": ["metamask.io"], "github": ["github.com"],
    "sberbank": ["sberbank.ru", "sber.ru"], "sber": ["sber.ru", "sberbank.ru"],
    "gosuslugi": ["gosuslugi.ru"], "tinkoff": ["tinkoff.ru", "tbank.ru"], "tbank": ["tbank.ru"],
    "vtb": ["vtb.ru"], "alfabank": ["alfabank.ru"], "yandex": ["yandex.ru", "ya.ru", "yandex.com"],
    "mailru": ["mail.ru"], "ozon": ["ozon.ru"], "wildberries": ["wildberries.ru", "wb.ru"],
    "avito": ["avito.ru"], "vk": ["vk.com", "vk.ru"], "kaspi": ["kaspi.kz"], "halyk": ["halykbank.kz"],
    "privatbank": ["privatbank.ua"], "monobank": ["monobank.ua"], "dhl": ["dhl.com"], "post": [],
}


def _lev(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _reg_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("com", "co", "org", "net", "gov", "edu", "msk", "spb") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def phishing_check(url, job=None):
    """Проверка подозрительной ссылки: признаки в самом адресе, возраст домена, сертификат,
    редиректы, форма ввода пароля, бренд в заголовке, репутация. Итог — риск 0–100."""
    job = job or T.Job()
    url = P.normalize_url(url)
    sig = []

    def add(w, text, level="warn"):
        sig.append({"weight": w, "text": text, "level": level})

    pr = urllib.parse.urlparse(url)
    host = (pr.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("Не удалось разобрать адрес")
    job.total(7)
    # --- признаки в адресе
    if pr.scheme == "http":
        add(10, "Нет HTTPS — данные передаются открыто")
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
        add(25, "Вместо домена — IP-адрес")
    except ValueError:
        pass
    if "@" in pr.netloc:
        add(25, "Символ @ в адресе — настоящий сайт указан после него")
    if host.startswith("xn--") or ".xn--" in host:
        add(20, "Punycode-домен (возможна подмена букв)")
    try:
        if not is_ip and T.idn_tool(host).get("homograph_warning"):
            add(25, "Смешанные алфавиты в домене (гомоглифы)", "bad")
    except Exception:
        pass
    if len(url) > 120:
        add(5, f"Очень длинный адрес ({len(url)} символов)")
    labels = host.split(".")
    if len(labels) >= 5:
        add(10, f"Много уровней поддоменов ({len(labels)})")
    reg = host if is_ip else _reg_domain(host)
    if reg.count("-") >= 2:
        add(8, "Много дефисов в имени домена")
    tld = labels[-1]
    if tld in SUSPICIOUS_TLD:
        add(10, f"Зона .{tld} часто используется для фишинга")
    if reg in SHORTENERS:
        add(10, "Сокращённая ссылка — реальный адрес скрыт")
    low = (host + pr.path + "?" + pr.query).lower()
    kw = [k for k in KEYWORDS if k in low]
    if kw:
        add(min(16, 4 * len(kw)), "Слова-приманки: " + ", ".join(kw[:6]))
    # --- бренд
    brand_hit = None
    reg_label = reg.split(".")[0]
    flat = host.replace("-", "").replace(".", "")
    norm = flat.translate(str.maketrans("01345", "olesa"))
    tokens = [t for t in re.split(r"[.\-]", host) if t]
    for b, official in BRANDS.items():
        if not official:
            continue
        if reg in official:
            brand_hit = None
            break
        near = next((t for t in tokens if len(b) >= 5 and len(t) >= 5 and 0 < _lev(t, b) <= 1), None)
        if near:
            brand_hit = b
            add(35, f"«{near}» похоже на бренд «{b}», а домен не официальный ({', '.join(official)})", "bad")
            break
        if len(b) >= 4 and (b in flat or b in norm):
            brand_hit = b
            add(30, f"Бренд «{b}» в адресе, но домен не официальный ({', '.join(official)})", "bad")
            break
        for off in official:
            ol = off.split(".")[0]
            d = _lev(reg_label, ol)
            if len(ol) >= 4 and 0 < d <= (1 if len(ol) <= 5 else 2):
                brand_hit = b
                add(30, f"Домен похож на {off} (отличие в {d} симв.)", "bad")
                break
        if brand_hit:
            break
    job.step("Редиректы…")
    final = url
    try:
        rc = T.redirect_chain(url)
        final = rc.get("final") or url
        fh = (urllib.parse.urlparse(final).hostname or "").lower()
        if fh and _reg_domain(fh) != reg:
            add(10, f"Перенаправляет на другой домен: {fh}")
        if rc.get("count", 0) >= 3:
            add(5, f"Длинная цепочка редиректов ({rc['count']})")
    except Exception as e:
        add(10, f"Сайт не открывается ({type(e).__name__})")
    fhost = (urllib.parse.urlparse(final).hostname or host).lower()
    freg = fhost if is_ip else _reg_domain(fhost)
    job.step("Возраст домена…")
    age_days, created = None, None
    if not is_ip:
        try:
            ev = T.rdap(freg).get("events") or {}
            created = ev.get("registration")
            if created:
                d = P.parse_date(created)
                if d:
                    import datetime as dt
                    age_days = (dt.datetime.utcnow() - dt.datetime.strptime(d[:10], "%Y-%m-%d")).days
                    if age_days < 30:
                        add(30, f"Домен зарегистрирован {age_days} дн. назад", "bad")
                    elif age_days < 180:
                        add(15, f"Молодой домен: {age_days} дн.")
                    elif age_days > 365 * 5:
                        add(-10, f"Домену больше 5 лет ({age_days // 365} г.)", "good")
        except Exception:
            pass
    job.step("Сертификат…")
    cert = None
    if final.startswith("https"):
        try:
            cert = T.ssl_cert(fhost)
            vf = P.parse_date(cert.get("valid_from") or "")
            if vf:
                import datetime as dt
                cd = (dt.datetime.utcnow() - dt.datetime.strptime(vf[:10], "%Y-%m-%d")).days
                if cd < 7:
                    add(10, f"Сертификат выпущен {cd} дн. назад")
        except Exception:
            add(10, "Ошибка TLS-сертификата")
    job.step("Содержимое страницы…")
    page = {}
    try:
        status, low_h, fin2, text = T._fetch_html(final, max_bytes=800_000)
        t_low = text.lower()
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if m:
            import html as _h
            title = _h.unescape(" ".join(m.group(1).split()))[:200]
        pw = bool(re.search(r"<input[^>]+type=[\"']?password", t_low))
        forms = re.findall(r"<form[^>]*action=[\"']([^\"']+)", text, re.I)
        ext = sorted({(urllib.parse.urlparse(urllib.parse.urljoin(final, a)).hostname or "")
                      for a in forms} - {fhost, ""})
        page = {"status": status, "title": title, "password_field": pw, "external_form_targets": ext}
        if pw:
            add(10 if not brand_hit else 20, "На странице форма ввода пароля")
        if ext:
            add(15, "Форма отправляет данные на другой домен: " + ", ".join(ext[:3]), "bad")
        tl = title.lower()
        for b, official in BRANDS.items():
            if official and len(b) >= 4 and b in tl and freg not in official:
                add(20, f"Заголовок упоминает «{b}», а домен чужой", "bad")
                break
        if re.search(r"(?:atob|unescape|fromCharCode)\s*\(", text) and len(re.findall(r"[A-Za-z0-9+/]{200,}", text)) > 2:
            add(8, "Обфусцированный JavaScript")
    except Exception as e:
        page = {"error": type(e).__name__}
    job.step("Репутация…")
    rep = None
    try:
        rep = O.reputation(fhost)
        rs = rep.get("risk_score") or 0
        if rs >= 25:
            add(round(rs * 0.5), f"Плохая репутация в базах угроз: {rs}/100 ({rep.get('verdict')})", "bad")
    except Exception:
        pass
    job.step()
    score = max(0, min(100, sum(s["weight"] for s in sig)))
    verdict = ("вероятно фишинг" if score >= 60 else "подозрительно" if score >= 30
               else "явных признаков фишинга нет")
    sig.sort(key=lambda s: -s["weight"])
    return {"url": url, "final_url": final, "host": fhost, "registered_domain": freg, "risk_score": score,
            "verdict": verdict, "signals": sig, "domain_created": created, "domain_age_days": age_days,
            "certificate": {k: cert.get(k) for k in ("issuer", "valid_from", "valid_to")} if cert else None,
            "page": page, "reputation": {"risk_score": rep.get("risk_score"), "verdict": rep.get("verdict")}
            if rep else None,
            "note": "Оценка эвристическая. Не вводите данные на сайте, пока не убедитесь, что он настоящий."}


# ================================================================= IP-радар
FEEDS = {
    # имя: (url, формат, категория, вес)
    "IPsum (3+ списка)": ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "ip", "threat", .8),
    "FireHOL level1": ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                       "cidr", "threat", .85),
    "Spamhaus DROP": ("https://www.spamhaus.org/drop/drop.txt", "cidr", "hijacked", .95),
    "Blocklist.de": ("https://lists.blocklist.de/lists/all.txt", "ip", "attacker", .6),
    "CINS Army": ("https://cinsscore.com/list/ci-badguys.txt", "ip", "attacker", .6),
    "GreenSnow": ("https://blocklist.greensnow.co/greensnow.txt", "ip", "attacker", .6),
    "Binary Defense": ("https://www.binarydefense.com/banlist.txt", "ip", "attacker", .7),
    "Emerging Threats": ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ip", "compromised", .75),
    "DShield": ("https://feeds.dshield.org/block.txt", "dshield", "attacker", .6),
    "Feodo Tracker (C2)": ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "ip", "c2", .95),
    "C2IntelFeeds": ("https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
                     "csv", "c2", .85),
    "Tor (выходные узлы)": ("https://check.torproject.org/torbulkexitlist", "ip", "tor", 0),
    "Cloudflare": ("https://www.cloudflare.com/ips-v4", "cidr", "cdn", 0),
    "Fastly": ("https://api.fastly.com/public-ip-list", "json:addresses", "cdn", 0),
    "Amazon AWS": ("https://ip-ranges.amazonaws.com/ip-ranges.json", "json:prefixes.ip_prefix", "cloud", 0),
    "Google Cloud": ("https://www.gstatic.com/ipranges/cloud.json", "json:prefixes.ipv4Prefix", "cloud", 0),
}
KNOWN_SERVICES = {"8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS", "1.1.1.1": "Cloudflare DNS",
                  "1.0.0.1": "Cloudflare DNS", "9.9.9.9": "Quad9 DNS", "149.112.112.112": "Quad9 DNS",
                  "77.88.8.8": "Яндекс.DNS", "77.88.8.1": "Яндекс.DNS", "208.67.222.222": "OpenDNS",
                  "208.67.220.220": "OpenDNS", "94.140.14.14": "AdGuard DNS", "94.140.15.15": "AdGuard DNS"}
_FEED_LOCK = threading.Lock()
_FEED_MEM = {}


def _feed_dir():
    d = os.path.join(P.DATA_DIR, "feeds")
    os.makedirs(d, exist_ok=True)
    return d


def _parse_feed(fmt, raw):
    """-> (множество int-адресов, список (сеть, маска))"""
    ips, nets = set(), []
    text = raw.decode("utf-8", "replace")
    items = []
    if fmt.startswith("json:"):
        j = json.loads(text)
        path = fmt[5:].split(".")
        arr = j.get(path[0], [])
        items = [x.get(path[1]) if len(path) > 1 and isinstance(x, dict) else x for x in arr]
    elif fmt == "dshield":
        for line in text.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and re.match(r"\d", parts[0]):
                items.append(f"{parts[0]}/{parts[2]}")
    else:
        for line in text.splitlines():
            line = line.split("#")[0].split(";")[0].strip()
            if fmt == "csv":
                line = line.split(",")[0].strip()
            if line and re.match(r"^[\d.:/a-fA-F]+$", line.split()[0]):
                items.append(line.split()[0])
    for it in items:
        if not it:
            continue
        try:
            if "/" in it:
                n = ipaddress.ip_network(it, strict=False)
                if n.version == 4:
                    nets.append((int(n.network_address), int(n.netmask)))
            else:
                a = ipaddress.ip_address(it)
                if a.version == 4:
                    ips.add(int(a))
        except ValueError:
            pass
    return ips, nets


def load_feeds(job=None, max_age=12 * 3600):
    """Скачивает (или берёт из кэша) открытые списки. Возвращает {имя: (ips, nets, возраст_ч, ошибка)}."""
    job = job or T.Job()
    out, todo = {}, []
    for name, (url, fmt, cat, w) in FEEDS.items():
        path = os.path.join(_feed_dir(), hashlib.md5(name.encode()).hexdigest()[:12] + ".bin")
        fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age
        if fresh and name in _FEED_MEM and _FEED_MEM[name][3] == os.path.getmtime(path):
            out[name] = _FEED_MEM[name][:3] + (None,)
        elif fresh:
            todo.append((name, url, fmt, path, False))
        else:
            todo.append((name, url, fmt, path, True))

    def get(it):
        name, url, fmt, path, download = it
        err = None
        if download:
            try:
                _, _, _, data = T._get(url, timeout=40, max_bytes=30_000_000)
                with open(path, "wb") as f:
                    f.write(data)
            except Exception as e:
                err = type(e).__name__
        if not os.path.exists(path):
            return name, None, err
        with open(path, "rb") as f:
            ips, nets = _parse_feed(fmt, f.read())
        age = round((time.time() - os.path.getmtime(path)) / 3600, 1)
        with _FEED_LOCK:
            _FEED_MEM[name] = (ips, nets, age, os.path.getmtime(path))
        return name, (ips, nets, age), err

    if todo:
        job.note(f"Обновление открытых списков ({len(todo)})…")
        for it, res, err in T.pmap(get, todo, None, workers=8):
            name, data, e2 = res if res else (it[0], None, err)
            out[name] = (data + (e2,)) if data else (set(), [], None, e2 or err or "нет данных")
    return out


def _in_feed(ip_int, feed):
    ips, nets = feed[0], feed[1]
    if ip_int in ips:
        return True
    return any(ip_int & m == n for n, m in nets)


def _ip_api(ips):
    """ip-api.com batch: страна, город, провайдер, признаки proxy/hosting/mobile (до 100 IP)."""
    fields = "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting"
    body = json.dumps([{"query": ip, "fields": fields} for ip in ips[:100]]).encode()
    req = T.urllib.request.Request("http://ip-api.com/batch", data=body,
                                   headers={"Content-Type": "application/json", "User-Agent": T.BROWSER_UA})
    with T._open(req, 20) as r:
        return {x.get("query"): x for x in json.loads(r.read().decode("utf-8", "replace"))}


def _sfs(ip):
    j = T._get_json(f"https://api.stopforumspam.org/api?ip={ip}&json", timeout=12)
    x = j.get("ip") or {}
    return {"appears": bool(x.get("appears")), "frequency": x.get("frequency", 0), "lastseen": x.get("lastseen")}


def ip_radar(q, job=None):
    """IP-радар: для каждого IP — вердикт, уверенность 0–100 и доказательства по источникам."""
    job = job or T.Job()
    raw = re.split(r"[\s,;]+", O.refang(q or "").strip())
    ips = []
    for x in raw:
        try:
            a = ipaddress.ip_address(x.strip("[]"))
            if str(a) not in ips:
                ips.append(str(a))
        except ValueError:
            pass
    if not ips:
        raise ValueError("Введите один или несколько IP-адресов")
    ips = ips[:50]
    job.total(3 + len(ips) * 3)
    feeds = load_feeds(job)
    job.step("Геолокация и признаки прокси…")
    try:
        geo = _ip_api(ips)
    except Exception:
        geo = {}
    job.note("Живые источники…")

    def live(ip):
        r = {}
        for name, fn in (("Shodan InternetDB", lambda: O.internetdb(ip)["results"][0]),
                         ("StopForumSpam", lambda: _sfs(ip)),
                         ("Репутация (OTX, DNSBL, ключи)", lambda: O.reputation(ip))):
            try:
                r[name] = fn()
            except Exception as e:
                r[name] = {"error": type(e).__name__}
            job.step()
        return r
    lives = {ip: res for ip, res, err in T.pmap(live, ips, None, workers=6)}
    results = []
    for ip in ips:
        a = ipaddress.ip_address(ip)
        ev, infra = [], []
        threat_w = []
        tags = set()
        if a.version == 4 and a.is_global:
            n = int(a)
            for name, (url, fmt, cat, w) in FEEDS.items():
                f = feeds.get(name)
                if not f or f[3] and not f[0] and not f[1]:
                    continue
                if _in_feed(n, f):
                    if cat in ("cdn", "cloud"):
                        infra.append(name)
                        tags.add(cat)
                    elif cat == "tor":
                        tags.add("tor")
                        ev.append({"source": name, "category": "анонимайзер", "detail": "выходной узел Tor"})
                    else:
                        threat_w.append(w)
                        tags.add(cat)
                        ev.append({"source": name, "category": {"threat": "угроза", "hijacked": "захваченная сеть",
                                                                "attacker": "атаки/сканирование",
                                                                "compromised": "скомпрометирован",
                                                                "c2": "C2 вредоносного ПО"}.get(cat, cat),
                                   "detail": f"в списке (вес {w})"})
        g = geo.get(ip) or {}
        if g.get("proxy"):
            tags.add("proxy")
            ev.append({"source": "ip-api", "category": "прокси/VPN", "detail": "отмечен как прокси, VPN или Tor"})
        if g.get("hosting"):
            tags.add("hosting")
        L = lives.get(ip, {})
        idb = L.get("Shodan InternetDB") or {}
        for t in idb.get("tags") or []:
            tags.add(t)
            if t in ("malware", "c2", "compromised", "scanner", "honeypot"):
                threat_w.append(.6 if t == "scanner" else .8)
                ev.append({"source": "Shodan InternetDB", "category": t, "detail": "метка Shodan"})
            if t in ("vpn", "proxy", "tor"):
                ev.append({"source": "Shodan InternetDB", "category": "анонимайзер", "detail": t})
        sfs = L.get("StopForumSpam") or {}
        if sfs.get("appears"):
            threat_w.append(min(.7, .3 + .05 * int(sfs.get("frequency") or 0)))
            ev.append({"source": "StopForumSpam", "category": "спам",
                       "detail": f"жалоб: {sfs.get('frequency')}, последняя {sfs.get('lastseen') or '—'}"})
        rep = L.get("Репутация (OTX, DNSBL, ключи)") or {}
        srcs = rep.get("sources") or {}
        otx = srcs.get("AlienVault OTX") or {}
        if otx.get("pulses"):
            threat_w.append(min(.75, .25 + .05 * otx["pulses"]))
            ev.append({"source": "AlienVault OTX", "category": "отчёты об угрозах",
                       "detail": f"упоминаний: {otx['pulses']}"})
        bl = (srcs.get("DNSBL") or {}).get("lists") or {}
        hits = [k for k, v in bl.items() if str(v).startswith("В СПИСКЕ")]
        if hits:
            threat_w.append(.55)
            ev.append({"source": "DNSBL", "category": "спам-листы", "detail": ", ".join(hits)})
        paid = srcs.get("VirusTotal / AbuseIPDB") or {}
        vt = paid.get("virustotal") or {}
        if vt.get("malicious"):
            threat_w.append(min(.9, .4 + .08 * vt["malicious"]))
            ev.append({"source": "VirusTotal", "category": "антивирусы",
                       "detail": f"вредоносным считают {vt['malicious']} движков"})
        ab = paid.get("abuseipdb") or {}
        if (ab.get("score") or 0) >= 25:
            threat_w.append(min(.9, ab["score"] / 100))
            ev.append({"source": "AbuseIPDB", "category": "жалобы",
                       "detail": f"уверенность {ab['score']}%, жалоб {ab.get('reports')}"})
        miss = 1.0
        for w in threat_w:
            miss *= 1 - w
        conf = round((1 - miss) * 100)
        svc = KNOWN_SERVICES.get(ip)
        if svc:
            infra.insert(0, svc)
        anon = "vpn" in tags or "proxy" in (idb.get("tags") or []) or (g.get("proxy") and not svc)
        if "c2" in tags:
            verdict = "C2-сервер вредоносного ПО"
        elif conf >= 35 and "tor" in tags:
            verdict = ("вредоносный" if conf >= 70 else "подозрительный") + " · выходной узел Tor"
        elif conf >= 70:
            verdict = "вредоносный"
        elif conf >= 35:
            verdict = "подозрительный"
        elif "tor" in tags:
            verdict = "выходной узел Tor"
        elif svc:
            verdict = "инфраструктура: " + svc
        elif anon:
            verdict = "прокси / VPN"
        elif infra:
            verdict = "инфраструктура: " + ", ".join(infra)
        elif not a.is_global:
            verdict = "частный / служебный адрес"
        else:
            verdict = "угроз не найдено"
        results.append({
            "ip": ip, "verdict": verdict, "confidence": conf, "tags": sorted(tags), "evidence": ev,
            "infrastructure": infra,
            "geo": {k: g.get(k) for k in ("country", "countryCode", "regionName", "city", "lat", "lon")} if g else {},
            "network": {"isp": g.get("isp"), "org": g.get("org"), "as": g.get("as"), "ptr": g.get("reverse"),
                        "mobile": g.get("mobile"), "hosting": g.get("hosting")} if g else {},
            "ports": idb.get("ports") or [], "vulns": (idb.get("vulns") or [])[:30],
            "hostnames": (idb.get("hostnames") or [])[:10]})
    results.sort(key=lambda r: -r["confidence"])
    return {"count": len(results), "results": results,
            "feeds": [{"name": k, "records": len(v[0]) + len(v[1]), "age_h": v[2], "error": v[3]}
                      for k, v in feeds.items()],
            "note": "Уверенность 0 означает «нет свидетельств», а не «адрес безопасен». "
                    "Списки обновляются раз в 12 часов и хранятся локально; IP проверяются на вашей машине."}


# ================================================================= утечки: XposedOrNot
XON = "https://api.xposedornot.com/v1"
_KRC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
        0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_KROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _keccak_f(A):
    for rc in _KRC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[x - 1] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _KROT[x][y]
                B[y][(2 * x + 3 * y) % 5] = ((A[x][y] << r) | (A[x][y] >> (64 - r))) & _M64 if r else A[x][y]
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A


def keccak512(data):
    """Оригинальный Keccak-512 (не SHA3-512: другое дополнение) — так хэширует пароли XposedOrNot."""
    rate = 72
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(msg[off + 8 * i: off + 8 * i + 8], "little")
        A = _keccak_f(A)
    out = b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(8))
    return out.hex()


def _xon_get(url):
    try:
        return T._get_json(url, timeout=25)
    except T.urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        if e.code == 429:
            raise ConnectionError("XposedOrNot: превышен лимит запросов (25 в час) — повторите позже")
        raise


def leaks_check(q, job=None):
    """Утечки по email (список и аналитика), по домену (известные утечки сервиса) или пароль (k-anonymity)."""
    job = job or T.Job()
    q = (q or "").strip()
    if not q:
        raise ValueError("Введите email, домен или пароль")
    if "@" in q and P.RE_EMAIL.fullmatch(q):
        email = q.lower()
        job.total(2)
        job.note("Проверка email…")
        chk = _xon_get(f"{XON}/check-email/{urllib.parse.quote(email)}")
        job.step("Аналитика утечек…")
        names = (chk or {}).get("breaches") or []
        names = [n for grp in names for n in (grp if isinstance(grp, list) else [grp])]
        an = _xon_get(f"{XON}/breach-analytics?email={urllib.parse.quote(email)}") if names else None
        job.step()
        det = (((an or {}).get("ExposedBreaches") or {}).get("breaches_details")) or []
        metrics = (an or {}).get("BreachMetrics") or {}
        risk = ((metrics.get("risk") or [{}])[0]) if isinstance(metrics.get("risk"), list) else {}
        data_types = Counter()
        for d in det:
            for t in str(d.get("xposed_data") or "").split(";"):
                if t.strip():
                    data_types[t.strip()] += 1
        return {"kind": "email", "query": email, "exposed": bool(names), "breaches_count": len(names),
                "breaches": [{"name": d.get("breach"), "domain": d.get("domain"), "date": d.get("xposed_date"),
                              "records": d.get("xposed_records"), "industry": d.get("industry"),
                              "data": d.get("xposed_data"), "password_risk": d.get("password_risk"),
                              "verified": d.get("verified"), "details": (d.get("details") or "")[:400],
                              "logo": d.get("logo")} for d in det] or [{"name": n} for n in names],
                "risk": {"label": risk.get("risk_label"), "score": risk.get("risk_score")},
                "data_types": [{"type": k, "breaches": v} for k, v in data_types.most_common(30)],
                "password_strength": metrics.get("passwords_strength"),
                "years": metrics.get("yearwise_details"),
                "pastes": ((an or {}).get("PastesSummary") or {}),
                "source": "XposedOrNot (xposedornot.com)",
                "note": "Email передаётся в XposedOrNot. Лимит API — 25 запросов в час."}
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", q.lower()) and " " not in q:
        dom = T._host(q)
        job.note("Утечки сервиса…")
        j = _xon_get(f"{XON}/breaches?domain={urllib.parse.quote(dom)}") or {}
        br = j.get("exposedBreaches") or []
        return {"kind": "domain", "query": dom, "exposed": bool(br), "breaches_count": len(br),
                "breaches": [{"name": b.get("breachID"), "domain": b.get("domain"), "date": b.get("breachedDate"),
                              "records": b.get("exposedRecords"), "industry": b.get("industry"),
                              "data": ";".join(b.get("exposedData") or []), "password_risk": b.get("passwordRisk"),
                              "verified": b.get("verified"), "details": (b.get("exposureDescription") or "")[:400],
                              "logo": b.get("logo")} for b in br],
                "source": "XposedOrNot (xposedornot.com)",
                "note": "Показаны известные утечки самого сервиса (домена), а не адреса на нём."}
    # пароль: в сеть уходят только первые 10 символов хэша Keccak-512
    h = keccak512(q.encode("utf-8"))
    job.note("Проверка пароля (k-anonymity)…")
    try:
        j = T._get_json(f"https://passwords.xposedornot.com/api/v1/pass/anon/{h[:10]}", timeout=20)
    except T.urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        j = None
    a = (j or {}).get("SearchPassAnon") or {}
    chars = dict(x.split(":") for x in str(a.get("char") or "").split(";") if ":" in x)
    return {"kind": "password", "exposed": bool(a), "count": int(a.get("count") or 0) if a else 0,
            "composition": {"цифр": chars.get("D"), "букв": chars.get("A"), "спецсимволов": chars.get("S"),
                            "длина": chars.get("L")} if chars else None,
            "hash_prefix_sent": h[:10], "source": "XposedOrNot Passwords",
            "note": "Пароль не передаётся: отправлены только первые 10 символов его хэша Keccak-512."}


# ================================================================= ГЛОБУС: открытые данные
_GCACHE = {}


def _cached(key, ttl, fn):
    now = time.time()
    c = _GCACHE.get(key)
    if c and now - c[0] < ttl:
        return c[1]
    v = fn()
    _GCACHE[key] = (now, v)
    return v


SAT_GROUPS = {"stations": "Станции (МКС, Тяньгун)", "visual": "Яркие (видны глазом)", "gps-ops": "GPS",
              "glo-ops": "ГЛОНАСС", "galileo": "Galileo", "weather": "Погодные", "geo": "Геостационарные",
              "starlink": "Starlink", "oneweb": "OneWeb", "science": "Научные", "military": "Военные (открытые)"}


def globe_flights(bbox=None):
    """Самолёты в воздухе: OpenSky Network (без ключа, ~10 с задержки); запасной — airplanes.live."""
    def opensky():
        url = "https://opensky-network.org/api/states/all"
        if bbox:
            url += "?lamin={}&lomin={}&lamax={}&lomax={}".format(*bbox)
        j = T._get_json(url, timeout=30)
        out = []
        for s in j.get("states") or []:
            if s[5] is None or s[6] is None or s[8]:
                continue
            out.append({"id": s[0], "cs": (s[1] or "").strip(), "co": s[2], "lon": round(s[5], 4),
                        "lat": round(s[6], 4), "alt": round(s[13] or s[7] or 0), "v": round((s[9] or 0) * 3.6),
                        "hd": round(s[10] or 0), "vr": s[11], "sq": s[14]})
        return {"source": "OpenSky Network", "time": j.get("time"), "items": out}

    def adsb():
        lat, lon = ((bbox[0] + bbox[2]) / 2, (bbox[1] + bbox[3]) / 2) if bbox else (50, 10)
        j = T._get_json(f"https://api.airplanes.live/v2/point/{lat:.3f}/{lon:.3f}/250", timeout=25)
        out = [{"id": a.get("hex"), "cs": (a.get("flight") or "").strip(), "co": a.get("r"), "lon": a.get("lon"),
                "lat": a.get("lat"), "alt": round((a.get("alt_geom") or 0) * 0.3048) if isinstance(a.get("alt_geom"), (int, float)) else 0,
                "v": round((a.get("gs") or 0) * 1.852), "hd": round(a.get("track") or 0), "sq": a.get("squawk"),
                "type": a.get("t")} for a in j.get("ac") or [] if a.get("lat") is not None]
        return {"source": "airplanes.live (радиус 250 nm)", "time": int(time.time()), "items": out}
    key = "flights:" + (",".join(map(str, bbox)) if bbox else "all")
    try:
        return _cached(key, 25, opensky)
    except Exception as e:
        r = _cached(key + ":fb", 25, adsb)
        r["note"] = f"OpenSky недоступен ({type(e).__name__}) — показан регион вокруг центра экрана"
        return r


def globe_satellites(group="stations"):
    if group not in SAT_GROUPS:
        raise ValueError("Неизвестная группа спутников")

    def get():
        j = T._get_json(f"https://celestrak.org/NORAD/elements/gp.php?GROUP={group}&FORMAT=json", timeout=40)
        keep = ("OBJECT_NAME", "OBJECT_ID", "NORAD_CAT_ID", "EPOCH", "MEAN_MOTION", "ECCENTRICITY", "INCLINATION",
                "RA_OF_ASC_NODE", "ARG_OF_PERICENTER", "MEAN_ANOMALY")
        return {"source": "CelesTrak", "group": group, "label": SAT_GROUPS[group],
                "items": [{k: o.get(k) for k in keep} for o in j[:3000]]}
    return _cached("sat:" + group, 6 * 3600, get)


def globe_quakes(period="day"):
    feed = {"day": "2.5_day", "week": "4.5_week", "month": "significant_month"}.get(period, "2.5_day")

    def get():
        j = T._get_json(f"https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/{feed}.geojson", timeout=25)
        return {"source": "USGS", "items": [
            {"id": f.get("id"), "mag": f["properties"].get("mag"), "place": f["properties"].get("place"),
             "time": f["properties"].get("time"), "url": f["properties"].get("url"),
             "tsunami": f["properties"].get("tsunami"), "lon": f["geometry"]["coordinates"][0],
             "lat": f["geometry"]["coordinates"][1], "depth": f["geometry"]["coordinates"][2]}
            for f in j.get("features") or []]}
    return _cached("quakes:" + feed, 300, get)


def globe_events():
    def get():
        j = T._get_json("https://eonet.gsfc.nasa.gov/api/v3/events?status=open&days=30&limit=400", timeout=30)
        out = []
        for e in j.get("events") or []:
            g = (e.get("geometry") or [])[-1:] or []
            if not g or g[0].get("type") != "Point":
                continue
            lon, lat = g[0]["coordinates"][:2]
            out.append({"id": e.get("id"), "title": e.get("title"),
                        "cat": ((e.get("categories") or [{}])[0]).get("title"), "date": g[0].get("date"),
                        "lon": lon, "lat": lat, "url": ((e.get("sources") or [{}])[0]).get("url")})
        return {"source": "NASA EONET", "items": out}
    return _cached("eonet", 900, get)


def geocode(q):
    q = (q or "").strip()
    if not q:
        raise ValueError("Пустой запрос")
    j = T._get_json("https://nominatim.openstreetmap.org/search?format=json&limit=6&accept-language=ru&q="
                    + urllib.parse.quote(q), headers={"User-Agent": f"Provenio/{P.APP_VERSION} (OSINT desktop app)"},
                    timeout=20)
    return [{"name": x.get("display_name"), "lat": float(x["lat"]), "lon": float(x["lon"]),
             "type": x.get("type")} for x in j]


def geolocate_ips(ips):
    ips = [i for i in ips if i][:100]
    if not ips:
        return {}
    return _cached("geo:" + ",".join(sorted(ips)), 3600, lambda: _ip_api(ips))


# ================================================================= сценарии расследования
PLAYBOOKS = {
    "org": {"title": "Организация по домену", "ph": "example.com", "archive": True,
            "steps": ["whois", "dns", "subdomains", "site_recon", "ssl", "email_sec", "domain_history",
                      "tracking", "harvester", "reputation", "leaks"]},
    "phish": {"title": "Подозрительная ссылка", "ph": "https://…", "archive": True,
              "steps": ["phishing", "redirects", "ssl", "domain_history", "reputation", "whois", "headers"]},
    "person": {"title": "Человек по нику", "ph": "username",
               "steps": ["username", "github", "telegram"]},
    "email": {"title": "Email", "ph": "user@example.com",
              "steps": ["email", "leaks", "reputation", "@domain:whois", "@domain:email_sec", "@domain:site_recon"]},
    "ip": {"title": "IP-адрес", "ph": "1.2.3.4",
           "steps": ["ip_radar", "ip_info", "internetdb", "asn", "reverse_dns", "reverse_ip"]},
    "infra": {"title": "Угроза / IOC", "ph": "IP, домен или хэш",
              "steps": ["reputation", "internetdb", "wayback_urls"]},
}


def playbook_steps(pid, q):
    pb = PLAYBOOKS.get(pid)
    if not pb:
        raise KeyError("Неизвестный сценарий")
    q = q.strip()
    out = []
    for st in pb["steps"]:
        if st.startswith("@domain:"):
            dom = q.split("@")[-1]
            out.append((st.split(":", 1)[1], dom))
        else:
            out.append((st, q))
    return out


# ================================================================= мониторинг бренда
def brand_snapshot(domain, job=None):
    """Текущее состояние: зарегистрированные двойники и известные поддомены/сертификаты."""
    job = job or T.Job()
    look = O.lookalikes(domain, job=job)
    try:
        subs = T.subdomains(domain)["subdomains"]
    except Exception:
        subs = []
    return {"lookalikes": sorted(h["domain"] for h in look["results"] if not h.get("same_ip_as_original")),
            "lookalike_ips": {h["domain"]: h["ips"][:3] for h in look["results"]},
            "subdomains": sorted(subs)}


def brand_diff(old, new):
    o_l, o_s = set(old.get("lookalikes") or []), set(old.get("subdomains") or [])
    return {"new_lookalikes": sorted(set(new["lookalikes"]) - o_l),
            "new_subdomains": sorted(set(new["subdomains"]) - o_s) if o_s else []}


# ================================================================= экспорт / импорт графа
def _graph(store, case):
    srcs = store.sources(case["id"])
    ents = store.entities(case["id"])
    nodes = [{"id": f"s{s['id']}", "label": (s.get("title") or s["url"])[:120], "type": "source",
              "url": s["url"], "kind": s.get("kind"), "sha256": s.get("sha256"), "reliability": s.get("reliability")}
             for s in srcs]
    edges = []
    for e in ents:
        nodes.append({"id": f"e{e['id']}", "label": e["value"], "type": e["type"], "confidence": e["confidence"]})
        for s in e["sources"]:
            edges.append((f"s{s['id']}", f"e{e['id']}"))
    return nodes, edges


def graph_gexf(store, case):
    nodes, edges = _graph(store, case)
    q = sx.quoteattr
    x = ['<?xml version="1.0" encoding="UTF-8"?>',
         '<gexf xmlns="http://gexf.net/1.3" version="1.3"><meta><creator>Provenio '
         f'{P.APP_VERSION}</creator><description>{sx.escape(case["name"])}</description></meta>',
         '<graph defaultedgetype="undirected"><attributes class="node">'
         '<attribute id="0" title="type" type="string"/><attribute id="1" title="confidence" type="integer"/>'
         '<attribute id="2" title="url" type="string"/></attributes><nodes>']
    for n in nodes:
        x.append(f'<node id={q(n["id"])} label={q(n["label"])}><attvalues>'
                 f'<attvalue for="0" value={q(n["type"])}/><attvalue for="1" value="{n.get("confidence") or 0}"/>'
                 f'<attvalue for="2" value={q(n.get("url") or "")}/></attvalues></node>')
    x.append("</nodes><edges>")
    for i, (a, b) in enumerate(edges):
        x.append(f'<edge id="{i}" source="{a}" target="{b}"/>')
    x.append("</edges></graph></gexf>")
    return "\n".join(x).encode("utf-8")


def graph_graphml(store, case):
    nodes, edges = _graph(store, case)
    q = sx.escape
    x = ['<?xml version="1.0" encoding="UTF-8"?>',
         '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
         '<key id="label" for="node" attr.name="label" attr.type="string"/>',
         '<key id="type" for="node" attr.name="type" attr.type="string"/>',
         '<key id="confidence" for="node" attr.name="confidence" attr.type="int"/>',
         '<key id="url" for="node" attr.name="url" attr.type="string"/>',
         '<graph id="provenio" edgedefault="undirected">']
    for n in nodes:
        x.append(f'<node id="{n["id"]}"><data key="label">{q(n["label"])}</data><data key="type">{q(n["type"])}'
                 f'</data><data key="confidence">{n.get("confidence") or 0}</data>'
                 f'<data key="url">{q(n.get("url") or "")}</data></node>')
    for i, (a, b) in enumerate(edges):
        x.append(f'<edge id="e{i}" source="{a}" target="{b}"/>')
    x.append("</graph></graphml>")
    return "\n".join(x).encode("utf-8")


MALTEGO_TYPES = {"email": "maltego.EmailAddress", "domain": "maltego.Domain", "ip": "maltego.IPv4Address",
                 "phone": "maltego.PhoneNumber", "account": "maltego.Alias", "source": "maltego.URL"}


def graph_edges_csv(store, case):
    """Таблица связей для Maltego (Import Graph from Table) и Excel."""
    nodes, edges = _graph(store, case)
    idx = {n["id"]: n for n in nodes}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["source_type", "source_value", "target_type", "target_value", "target_confidence"])
    for a, b in edges:
        na, nb = idx[a], idx[b]
        w.writerow([MALTEGO_TYPES["source"], na.get("url") or na["label"], MALTEGO_TYPES.get(nb["type"], nb["type"]),
                    nb["label"], nb.get("confidence")])
    return ("﻿" + buf.getvalue()).encode("utf-8")


SPIDERFOOT_MAP = {"EMAILADDR": "email", "INTERNET_NAME": "domain", "DOMAIN_NAME": "domain", "IP_ADDRESS": "ip",
                  "IPV6_ADDRESS": "ip", "PHONE_NUMBER": "phone", "AFFILIATE_INTERNET_NAME": "domain",
                  "CO_HOSTED_SITE": "domain", "SOCIAL_MEDIA": "url", "ACCOUNT_EXTERNAL_OWNED": "url",
                  "LINKED_URL_EXTERNAL": "url", "USERNAME": "username", "HUMAN_NAME": "name"}


def import_file(p):
    """Импорт результатов других инструментов: Sherlock (txt/csv/json), SpiderFoot (csv/json),
    любой текст — извлечение индикаторов."""
    name = p.get("filename") or "файл"
    data = base64.b64decode(p["file"]) if p.get("file") else str(p.get("q", "")).encode("utf-8")
    text = data.decode("utf-8-sig", "replace")
    sha = hashlib.sha256(data).hexdigest()
    base = {"file": name, "sha256": sha, "size": len(data)}
    first = text.lstrip()[:2000]
    # SpiderFoot JSON
    if first.startswith("[") and '"type"' in first and ('"module"' in first or '"data"' in first):
        rows = json.loads(text)
        items = [{"type": r.get("type") or r.get("event_type"), "data": r.get("data"), "module": r.get("module"),
                  "source": r.get("source")} for r in rows]
        return _spiderfoot(items, base)
    lines = text.splitlines()
    head = lines[0].lower() if lines else ""
    # SpiderFoot CSV: Scan Name,Updated,Type,Module,Source,F/P,Data
    if "module" in head and "type" in head and "data" in head:
        rd = csv.DictReader(io.StringIO(text))
        items = [{"type": r.get("Type") or r.get("type"), "data": r.get("Data") or r.get("data"),
                  "module": r.get("Module") or r.get("module"), "source": r.get("Source") or r.get("source")}
                 for r in rd]
        return _spiderfoot(items, base)
    # Sherlock CSV: username,name,url_main,url_user,exists,http_status,response_time_s
    if "url_user" in head and "exists" in head:
        rd = csv.DictReader(io.StringIO(text))
        found = [{"site": r.get("name"), "url": r.get("url_user"), "username": r.get("username")}
                 for r in rd if str(r.get("exists", "")).lower() in ("claimed", "true", "1", "yes")]
        return {**base, "format": "Sherlock CSV", "username": found[0]["username"] if found else None,
                "found": found, "count": len(found)}
    # Sherlock JSON / Maigret-подобный {site: {url_user, status}}
    if first.startswith("{"):
        try:
            j = json.loads(text)
            found = []
            for site, v in j.items():
                if isinstance(v, dict):
                    st = str(v.get("status") or v.get("exists") or "").lower()
                    url = v.get("url_user") or v.get("url")
                    if url and ("claimed" in st or st in ("true", "found")):
                        found.append({"site": site, "url": url})
            if found:
                return {**base, "format": "Sherlock/Maigret JSON", "found": found, "count": len(found)}
        except ValueError:
            pass
    # Sherlock TXT: список URL + «Total Websites Username Detected On : N»
    urls = [l.strip() for l in lines if re.match(r"^https?://\S+$", l.strip())]
    if urls and (any("Total Websites" in l for l in lines[-3:]) or len(urls) >= max(1, len(lines) - 2)):
        return {**base, "format": "Sherlock TXT", "found": [{"site": T._host(u), "url": u} for u in urls],
                "count": len(urls)}
    # иначе — индикаторы из текста
    r = O.ioc_extract(text)
    return {**base, "format": "текст (извлечены индикаторы)", **r}


def _spiderfoot(items, base):
    groups = {}
    for it in items:
        t = it.get("type") or "?"
        if it.get("data") in (None, ""):
            continue
        groups.setdefault(t, []).append(str(it["data"])[:500])
    mapped = {k: sorted(set(v))[:2000] for k, v in groups.items()}
    return {**base, "format": "SpiderFoot", "events": sum(len(v) for v in groups.values()),
            "types": {k: len(v) for k, v in sorted(mapped.items(), key=lambda x: -len(x[1]))},
            "data": {k: v for k, v in mapped.items() if SPIDERFOOT_MAP.get(k) or k.endswith("_NAME")
                     or k in ("EMAILADDR", "IP_ADDRESS", "PHONE_NUMBER")}}


# ================================================================= обновления
def check_update(current=P.APP_VERSION):
    j = T._get_json(f"https://api.github.com/repos/{REPO}/releases/latest", timeout=15)
    tag = str(j.get("tag_name") or "").lstrip("v")

    def ver(v):
        return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
    assets = [a for a in j.get("assets") or [] if a.get("name", "").endswith(".exe")]
    assets.sort(key=lambda a: "setup" not in a.get("name", "").lower())   # сначала установщик
    exe = assets[0].get("browser_download_url") if assets else None
    return {"current": current, "latest": tag, "newer": bool(tag) and ver(tag) > ver(current),
            "url": j.get("html_url"), "exe": exe, "published": j.get("published_at"),
            "notes": (j.get("body") or "")[:1500]}


# ================================================================= ИИ-сводка кейса (Claude)
AI_SYSTEM = (
    "Ты — аналитик OSINT. Тебе дают данные одного расследования из программы Provenio: источники "
    "(архивированные страницы и результаты инструментов с оценкой надёжности 1–5), извлечённые сущности "
    "с расчётной достоверностью (0–100, по числу независимых доменов), хронологию и пересечения с другими кейсами. "
    "Напиши сводку на русском языке в Markdown:\n"
    "1. «Главное» — 3–6 пунктов с ключевыми выводами.\n"
    "2. «Ключевые сущности» — таблица: сущность, тип, достоверность, на чём основано (номера источников #id).\n"
    "3. «Связи и хронология» — что с чем связано и в каком порядке происходило.\n"
    "4. «Противоречия и слабые места» — что подтверждено одним источником, что выглядит недостоверно.\n"
    "5. «Следующие шаги» — конкретные проверки (какие инструменты Provenio запустить и для чего).\n"
    "Опирайся только на переданные данные и ссылайся на источники как #id. Не выдумывай фактов; "
    "если данных мало, так и скажи. Не делай выводов о частной жизни сверх того, что есть в данных."
)
AI_MODELS = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-2")
_FALLBACK_OK = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-2")


def ai_case_payload(store, case):
    srcs = store.sources(case["id"])
    ents = sorted(store.entities(case["id"]), key=lambda e: -e["confidence"])[:300]
    inter = store.intersections(case["id"])[:60]
    lines = [f"Кейс: {case['name']} (открыт {case['created']})", "", "ИСТОЧНИКИ:"]
    for s in srcs[:250]:
        lines.append(f"#{s['id']} [{'инструмент ' + (s.get('tool') or '') if s.get('kind') == 'tool' else 'страница'}] "
                     f"{s.get('query') or s['url']} | {s.get('title') or ''} | {s['fetched']} | {s['status']} | "
                     f"надёжность {s['reliability']}/5" + (f" | заметка: {s['note']}" if s.get("note") else ""))
    lines += ["", "СУЩНОСТИ (тип | значение | достоверность | источники):"]
    for e in ents:
        lines.append(f"{e['type']} | {e['value']} | {e['confidence']}% | "
                     + ",".join("#" + str(x["id"]) for x in e["sources"][:12]))
    tl = store.timeline(case["id"])[:150]
    if tl:
        lines += ["", "ХРОНОЛОГИЯ:"] + [f"{t['date']} | {t['kind']} | #{t['source']} | {t['label']}" for t in tl]
    if inter:
        lines += ["", "ПЕРЕСЕЧЕНИЯ С ДРУГИМИ КЕЙСАМИ:"] + [
            f"{x['type']} {x['value']}: " + ", ".join(c["name"] for c in x["cases"]) for x in inter]
    # краткое содержание результатов инструментов (обрезано)
    lines += ["", "ВЫДЕРЖКИ ИЗ РЕЗУЛЬТАТОВ ИНСТРУМЕНТОВ:"]
    budget = 60_000
    for s in srcs:
        if s.get("kind") != "tool" or budget <= 0:
            continue
        txt = P.snapshot_text(store.snapshot_bytes(s), "application/json")[:3000]
        budget -= len(txt)
        lines.append(f"--- #{s['id']} {s.get('tool')} {s.get('query')}\n{txt}")
    return "\n".join(lines)


def ai_summary(store, case, api_key, model="claude-opus-5-5", proxy=""):
    if not api_key:
        raise ValueError("Добавьте ключ Anthropic API в настройках (Настройки → Claude API)")
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("Не установлен пакет anthropic (pip install anthropic)")
    model = model if model in AI_MODELS else "claude-opus-5-5"
    kw = {"api_key": api_key, "max_retries": 2, "timeout": 600}
    if proxy:
        kw["http_client"] = anthropic.DefaultHttpxClient(proxy=proxy)
    client = anthropic.Anthropic(**kw)
    payload = ai_case_payload(store, case)
    req = {"model": model, "max_tokens": 16000, "system": AI_SYSTEM,
           "messages": [{"role": "user", "content": payload}]}
    try:
        if model in _FALLBACK_OK:
            resp = client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **req)
        else:
            resp = client.messages.create(**req)
    except anthropic.AuthenticationError:
        raise ValueError("Ключ Anthropic API не принят — проверьте его в настройках")
    except anthropic.PermissionDeniedError:
        raise ValueError("У ключа нет доступа к этой модели")
    except anthropic.RateLimitError:
        raise ConnectionError("Превышен лимит запросов Anthropic API — повторите через минуту")
    except anthropic.APIConnectionError:
        raise ConnectionError("Нет связи с Anthropic API (проверьте интернет или прокси)")
    except anthropic.APIStatusError as e:
        raise ConnectionError(f"Anthropic API: ошибка {e.status_code}")
    if resp.stop_reason == "refusal":
        cat = getattr(getattr(resp, "stop_details", None), "category", None)
        raise ValueError(f"Модель отказалась составлять сводку (категория: {cat or 'не указана'})")
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()
    u = resp.usage
    return {"case": case["name"], "model": resp.model, "summary": text,
            "stop_reason": resp.stop_reason,
            "usage": {"input_tokens": getattr(u, "input_tokens", None), "output_tokens": getattr(u, "output_tokens", None)},
            "input_chars": len(payload), "generated": P.now_iso(),
            "note": "Сводку составила языковая модель по данным кейса — проверяйте выводы по источникам."}


# ================================================================= регистрация инструментов
PLUS_TOOLS = {
    "phishing": lambda p: phishing_check(p["q"], job=p.get("_job")),
    "ip_radar": lambda p: ip_radar(p["q"], job=p.get("_job")),
    "leaks": lambda p: leaks_check(p["q"], job=p.get("_job")),
    "capture": capture_tool,
    "import_file": import_file,
    "tsa": lambda p: tsa_tool(p),
}


def tsa_tool(p):
    """Метка времени RFC 3161 на файл или текст."""
    if p.get("file"):
        data = base64.b64decode(p["file"])
        name = p.get("filename") or "файл"
    else:
        data = str(p.get("q", "")).encode("utf-8")
        name = "текст"
    tsa = (T.SETTINGS.get("tsa_url") or "").strip() or P.TSA_DEFAULT
    r = P.rfc3161_stamp(hashlib.sha256(data).digest(), tsa)
    return {"name": name, "sha256": r["hash"], "tsa": r["tsa"], "gen_time": r["gen_time"], "serial": r["serial"],
            "token_b64": base64.b64encode(r["token"]).decode(),
            "note": "Сохраните результат в кейс: токен (token_b64) — подписанное службой TSA подтверждение, "
                    "что файл с этим SHA-256 существовал не позже указанного времени. "
                    "Проверка: openssl ts -verify -digest <sha256> -in token.tsr -token_in -CAfile <корень TSA>."}


T.TOOLS.update(PLUS_TOOLS)
