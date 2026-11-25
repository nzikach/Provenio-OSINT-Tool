# -*- coding: utf-8 -*-
"""
Provenio 2.5 — собственные функции, которых нет в других OSINT-инструментах:
  1. Неоспоримые доказательства: якорь в блокчейне Bitcoin (OpenTimestamps), независимый свидетель
     (Wayback Save Page Now + сравнение), самопроверяющийся HTML-отчёт.
  2. «Один оператор»: автоматическая атрибуция набора доменов по общей инфраструктуре.
  3. Геопазл: поиск места по приметам с фото через OpenStreetMap (Overpass).
  4. Матрица конкурирующих гипотез (ACH) — хранится в базе кейса, считается в интерфейсе.
  5. «Ваш цифровой след»: самоаудит открытости организации.
  6. Ритм жизни: тепловая карта активности, часовой пояс, режим сна, аномалии.
Только стандартная библиотека.
"""
import base64
import collections
import datetime as dt
import difflib
import hashlib
import html
import json
import math
import re
import time
import urllib.parse

import provenio as P
import provenio_tools as T
import provenio_osint as O
import provenio_plus as X


def _job(p):
    return p.get("_job") or T.Job()


# ======================================================================= 1a. OpenTimestamps
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
CALENDARS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org",
             "https://a.pool.eternitywall.com"]
ATT_BTC = bytes.fromhex("0588960d73d71901")
ATT_PENDING = bytes.fromhex("83dfe30d2ef90c8e")


def _uvar(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _rvar(buf, i):
    n = shift = 0
    while True:
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return n, i


def _rbytes(buf, i):
    n, i = _rvar(buf, i)
    return buf[i:i + n], i + n


def _op(tag, arg, msg):
    if tag == 0x08:
        return hashlib.sha256(msg).digest()
    if tag == 0x02:
        return hashlib.sha1(msg).digest()
    if tag == 0x03:
        return hashlib.new("ripemd160", msg).digest()
    if tag == 0xF0:
        return msg + arg
    if tag == 0xF1:
        return arg + msg
    if tag == 0xF2:
        return msg[::-1]
    if tag == 0xF3:
        return msg.hex().encode()
    if tag == 0x67:
        raise ValueError("keccak256 в доказательстве не поддерживается")
    raise ValueError(f"Неизвестная операция OTS 0x{tag:02x}")


class OTS:
    """Узел дерева доказательства OpenTimestamps."""

    def __init__(self, msg):
        self.msg = msg
        self.att = []     # [(tag8, payload)]
        self.ops = []     # [(tag, arg, OTS)]

    @classmethod
    def parse(cls, buf, i, msg):
        node = cls(msg)

        def item(tag, i):
            if tag == 0x00:
                atag = buf[i:i + 8]
                payload, i = _rbytes(buf, i + 8)
                node.att.append((atag, payload))
                return i
            arg = b""
            if tag in (0xF0, 0xF1):
                arg, i = _rbytes(buf, i)
            child, i = cls.parse(buf, i, _op(tag, arg, msg))
            node.ops.append((tag, arg, child))
            return i
        tag = buf[i]
        i += 1
        while tag == 0xFF:
            i = item(buf[i], i + 1)
            tag = buf[i]
            i += 1
        return node, item(tag, i)

    def serialize(self):
        items = [b"\x00" + t + _uvar(len(p)) + p for t, p in self.att]
        items += [bytes([tag]) + (_uvar(len(arg)) + arg if tag in (0xF0, 0xF1) else b"") + ch.serialize()
                  for tag, arg, ch in self.ops]
        if not items:
            raise ValueError("Пустое доказательство")
        return b"".join(b"\xff" + x for x in items[:-1]) + items[-1]

    def walk(self):
        yield self
        for _, _, ch in self.ops:
            yield from ch.walk()

    def merge(self, other):
        self.att += other.att
        self.ops += other.ops


def ots_file(digest, root):
    return OTS_MAGIC + _uvar(1) + b"\x08" + digest + root.serialize()


def ots_parse_file(data):
    if not data.startswith(OTS_MAGIC):
        raise ValueError("Это не файл .ots")
    i = len(OTS_MAGIC)
    _, i = _rvar(data, i)
    if data[i] != 0x08:
        raise ValueError("Поддерживается только SHA-256")
    digest = data[i + 1:i + 33]
    root, _ = OTS.parse(data, i + 33, digest)
    return digest, root


def _http(url, data=None, timeout=25, accept="application/vnd.opentimestamps.v1"):
    req = T.urllib.request.Request(url, data=data, headers={"User-Agent": f"Provenio/{P.APP_VERSION}", "Accept": accept})
    with T._open(req, timeout) as r:
        return r.read()


def ots_stamp(digest):
    """Отправляет SHA-256 (32 байта) в календари OpenTimestamps → (байты .ots, список календарей)."""
    if len(digest) != 32:
        raise ValueError("Нужен SHA-256")
    root, ok, errors = OTS(digest), [], {}
    for cal in CALENDARS:
        try:
            resp = _http(cal + "/digest", data=digest)
            child, _ = OTS.parse(resp, 0, digest)
            root.merge(child)
            ok.append(cal)
        except Exception as e:
            errors[cal] = f"{type(e).__name__}: {str(e)[:80]}"
    if not ok:
        raise ValueError("Ни один календарь OpenTimestamps не ответил: " + "; ".join(errors.values()))
    return ots_file(digest, root), ok


def ots_info(data):
    digest, root = ots_parse_file(data)
    pending, btc = [], []
    for node in root.walk():
        for t, p in node.att:
            if t == ATT_PENDING:
                uri, _ = _rbytes(p, 0)
                pending.append(uri.decode("utf-8", "replace"))
            elif t == ATT_BTC:
                h, _ = _rvar(p, 0)
                btc.append({"height": h, "merkle": node.msg[::-1].hex()})
    return {"digest": digest.hex(), "pending": pending, "bitcoin": btc}


def ots_upgrade(data):
    """Подтягивает подтверждения из календарей (обычно через 1–12 часов после отправки)."""
    digest, root = ots_parse_file(data)
    changed = False
    for node in list(root.walk()):
        keep = []
        for t, p in node.att:
            if t != ATT_PENDING:
                keep.append((t, p))
                continue
            uri, _ = _rbytes(p, 0)
            uri = uri.decode("utf-8", "replace")
            if not uri.startswith("https://"):
                keep.append((t, p))
                continue
            try:
                resp = _http(uri.rstrip("/") + "/timestamp/" + node.msg.hex())
                child, _ = OTS.parse(resp, 0, node.msg)
                if any(a[0] == ATT_BTC for n in child.walk() for a in n.att):
                    node.merge(child)
                    changed = True
                    continue
            except Exception:
                pass
            keep.append((t, p))
        node.att = keep
    return (ots_file(digest, root) if changed else data), changed


def ots_verify(data):
    """Сверяет подтверждения Bitcoin с реальными блоками (blockstream.info)."""
    info = ots_info(data)
    out = []
    for b in info["bitcoin"]:
        try:
            bh = _http(f"https://blockstream.info/api/block-height/{b['height']}", accept="text/plain").decode().strip()
            blk = json.loads(_http(f"https://blockstream.info/api/block/{bh}", accept="application/json"))
            ok = blk.get("merkle_root") == b["merkle"]
            out.append({"height": b["height"], "block": bh, "ok": ok,
                        "time": dt.datetime.fromtimestamp(blk.get("timestamp", 0), dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")})
        except Exception as e:
            out.append({"height": b["height"], "ok": None, "error": f"{type(e).__name__}"})
    info["verified"] = out
    return info


# ======================================================================= 1b. независимый свидетель
def witness(url, our_text=""):
    """Просит Internet Archive сохранить страницу сейчас и сравнивает его копию с нашей."""
    url = P.normalize_url(url)
    snap, fresh, why = "", True, ""
    try:
        req = T.urllib.request.Request("https://web.archive.org/save/" + url, headers={"User-Agent": T.BROWSER_UA})
        with T._open(req, 120) as r:
            final = r.geturl()
            loc = r.headers.get("Content-Location") or ""
        snap = final if "/web/" in final else ("https://web.archive.org" + loc if loc.startswith("/web/") else "")
    except Exception as e:
        why = f"{type(e).__name__}: {str(e)[:80]}"
    m = re.search(r"/web/(\d{14})/", snap)
    if not m:     # сохранить «сейчас» не дали (лимиты) — берём последний существующий снимок архива
        fresh = False
        j = T._get_json("https://archive.org/wayback/available?url=" + urllib.parse.quote(url, safe=""), timeout=30)
        snap = (((j or {}).get("archived_snapshots") or {}).get("closest") or {}).get("url", "")
        m = re.search(r"/web/(\d{14})/", snap)
        if not m:
            raise ValueError("Internet Archive не сохранил страницу и прежних снимков нет" + (f" ({why})" if why else ""))
    raw_url = snap.replace(f"/web/{m.group(1)}/", f"/web/{m.group(1)}id_/", 1)
    _, _, _, data = T._get(raw_url, timeout=60, max_bytes=5_000_000)
    theirs = P.snapshot_text(data)
    sim = None
    if our_text:
        a, b = our_text.splitlines(), theirs.splitlines()
        sim = round(difflib.SequenceMatcher(None, a, b, autojunk=False).ratio() * 100, 1) if a or b else 100.0
    return {"witness": "Internet Archive (Wayback Machine)", "snapshot": snap, "timestamp": m.group(1), "fresh": fresh,
            "note": "" if fresh else f"Сохранить сейчас не удалось ({why or 'лимит сервиса'}) — сравнение с последним снимком архива от "
                                     f"{m.group(1)[:4]}-{m.group(1)[4:6]}-{m.group(1)[6:8]}; различия могут быть из-за обновлений сайта.",
            "sha256": P.sha256_bytes(data), "size": len(data), "similarity": sim,
            "verdict": None if sim is None else ("совпадает" if sim >= 90 else "в основном совпадает" if sim >= 70
                                                  else "РАЗЛИЧАЕТСЯ — сайт мог показать архиву другое содержимое")}


# ======================================================================= 1c. самопроверяющийся отчёт
VERIFY_HTML = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Provenio — проверяемый отчёт: __TITLE__</title><style>
body{margin:0;font:14px/1.55 "Segoe UI",system-ui,sans-serif;background:#05040a;color:#ece8f5}main{max-width:1000px;margin:0 auto;padding:28px 18px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:17px;margin:26px 0 10px;color:#c4a1ff}.mu{color:#9b93b5}
.card{background:linear-gradient(160deg,rgba(255,255,255,.07),rgba(255,255,255,.02));border:1px solid rgba(255,255,255,.1);border-radius:18px;padding:16px 18px;margin:12px 0}
.big{display:flex;gap:14px;align-items:center;font-size:18px;font-weight:700}.dot{width:16px;height:16px;border-radius:50%;background:#6f6690}
.ok .dot{background:#34d399;box-shadow:0 0 14px #34d399}.bad .dot{background:#fb7185;box-shadow:0 0 14px #fb7185}
table{width:100%;border-collapse:collapse;font-size:12.5px}td,th{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;vertical-align:top}
th{color:#c4a1ff}code{font:11.5px Consolas,monospace;word-break:break-all}.y{color:#34d399}.n{color:#fb7185}a{color:#c4a1ff}
</style></head><body><main>
<h1>__TITLE__</h1><div class="mu">Отчёт Provenio __VER__ · создан __CREATED__ · этот файл проверяет себя сам: ничего не нужно устанавливать.</div>
<div class="card big" id="sum"><span class="dot"></span><span id="sumt">Проверяю…</span></div>
<div class="card"><b>Что проверяется прямо сейчас, в вашем браузере</b><ul class="mu">
<li>SHA-256 каждого вложенного файла (снимки страниц, скриншоты, результаты инструментов) сравнивается с хэшем, записанным при сборе;</li>
<li>журнал аудита — цепочка хэшей: изменение любой записи ломает все последующие;</li>
<li>якоря во времени: метка RFC 3161 и подтверждение в блокчейне Bitcoin (OpenTimestamps) — их можно перепроверить независимо (см. ниже).</li></ul></div>
<h2>Файлы</h2><div class="card"><table id="files"><tr><th>Файл</th><th>SHA-256 (записан)</th><th>Проверка</th></tr></table></div>
<h2>Журнал аудита</h2><div class="card"><div id="audit" class="mu">…</div></div>
<h2>Якоря во времени</h2><div class="card" id="anch"></div>
<h2>Источники</h2><div class="card"><table id="src"><tr><th>#</th><th>Источник</th><th>Когда</th><th>Надёжн.</th></tr></table></div>
<h2>Сущности</h2><div class="card"><table id="ent"><tr><th>Тип</th><th>Значение</th><th>Достоверность</th></tr></table></div>
</main><script id="data" type="application/json">__DATA__</script><script>
const D=JSON.parse(document.getElementById("data").textContent),$=s=>document.querySelector(s);
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function sha(bytes){return hex(await crypto.subtle.digest("SHA-256",bytes))}
function b64(s){const b=atob(s),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
(async()=>{let bad=0,checked=0;if(!(window.crypto&&crypto.subtle)){$("#sumt").textContent="Браузер не дал доступ к WebCrypto — откройте файл в Chrome, Edge или Firefox";return}
 for(const f of D.files){const tr=document.createElement("tr");let st;
  if(f.b64!=null){const h=await sha(b64(f.b64));checked++;const ok=h===f.sha256;if(!ok)bad++;st=ok?'<span class="y">✓ совпадает</span>':`<span class="n">✗ ИЗМЕНЁН<br><code>${h}</code></span>`}
  else st='<span class="mu">не вложен (большой) — проверьте по пакету ZIP</span>';
  tr.innerHTML=`<td>${esc(f.path)}</td><td><code>${esc(f.sha256)}</code></td><td>${st}</td>`;$("#files").append(tr)}
 let prev="GENESIS",broken=null;const enc=new TextEncoder();
 for(const r of D.audit){const h=await sha(enc.encode(`${prev}|${r.ts}|${r.action}|${r.detail}`));if(r.prev!==prev||r.hash!==h){broken=r.id;break}prev=r.hash}
 $("#audit").innerHTML=broken?`<span class="n">✗ Цепочка нарушена в записи #${broken}</span>`:`<span class="y">✓ Цепочка цела</span> — ${D.audit.length} записей, последняя: <code>${esc(prev)}</code>`;
 if(broken)bad++;
 const an=[];for(const a of D.anchors){an.push(`<div style="margin:6px 0"><b>${esc(a.kind)}</b> · ${esc(a.when||"")} · ${esc(a.status||"")}<br><span class="mu">Хэш: <code>${esc(a.digest)}</code>${a.check?`<br>Как проверить: ${esc(a.check)}`:""}</span></div>`)}
 $("#anch").innerHTML=an.join("")||'<span class="mu">Якорей нет.</span>';
 for(const s of D.sources){const tr=document.createElement("tr");tr.innerHTML=`<td>${s.id}</td><td>${esc(s.title||s.url)}<br><span class="mu">${esc(s.url)}</span></td><td>${esc(s.fetched)}</td><td>${s.reliability}/5</td>`;$("#src").append(tr)}
 for(const e of D.entities){const tr=document.createElement("tr");tr.innerHTML=`<td>${esc(e.type)}</td><td>${esc(e.value)}</td><td>${e.confidence}%</td>`;$("#ent").append(tr)}
 const s=$("#sum");s.classList.add(bad?"bad":"ok");$("#sumt").textContent=bad?`Обнаружены изменения: ${bad}. Доверять этому отчёту нельзя.`:`Подлинность подтверждена: ${checked} файлов и журнал аудита не изменялись с момента сбора.`})();
</script></body></html>"""


def build_verify_html(store, case, anchors=(), max_embed=60_000_000):
    srcs = store.sources(case["id"])
    atts = store.attachments(case["id"])
    files, total = [], 0
    for s in srcs:
        names = ([s["snapshot"]] if s.get("snapshot") else []) + [a["file"] for a in atts.get(s["id"], [])]
        for name in names:
            data = store.snapshot_bytes({"snapshot": name})
            if data is None:
                continue
            emb = total + len(data) <= max_embed
            total += len(data) if emb else 0
            files.append({"path": name, "sha256": P.sha256_bytes(data), "b64": base64.b64encode(data).decode() if emb else None})
    audit = [dict(r) for r in store.db.execute("SELECT * FROM audit ORDER BY id")]
    data = {"files": files, "audit": audit,
            "sources": [{k: s.get(k) for k in ("id", "url", "title", "fetched", "reliability")} for s in srcs],
            "entities": [{"type": e["type"], "value": e["value"], "confidence": e["confidence"]} for e in store.entities(case["id"])],
            "anchors": list(anchors)}
    blob = json.dumps(data, ensure_ascii=False, default=str).replace("</", "<\\/")
    return (VERIFY_HTML.replace("__TITLE__", html.escape(case["name"])).replace("__VER__", P.APP_VERSION)
            .replace("__CREATED__", P.now_iso()).replace("__DATA__", blob)).encode("utf-8")


# ======================================================================= 2. атрибуция «Один оператор»
GENERIC_NS = ("cloudflare.com", "awsdns", "domaincontrol.com", "registrar-servers.com", "googledomains.com", "nsone.net",
              "azure-dns", "dnsmadeeasy", "ultradns", "akam.net", "ns.cloudflare", "name-services.com", "dns.google",
              "reg.ru", "nic.ru", "timeweb.ru", "beget.com", "hostinger", "wixdns.net", "squarespacedns", "vercel-dns")
CDN_ASN = ("AS13335", "AS54113", "AS16625", "AS20940", "AS16509", "AS15169", "AS8075", "AS14618", "AS209242", "AS396982")
GENERIC_MX = ("google.com", "googlemail.com", "outlook.com", "yandex.net", "mail.ru", "zoho", "protonmail", "icloud.com")


def _simhash(text):
    tags = re.findall(r"<\s*([a-zA-Z0-9]+)", text[:400000])
    shingles = ["/".join(tags[i:i + 4]) for i in range(max(1, len(tags) - 3))]
    v = [0] * 64
    for sh in shingles:
        h = int.from_bytes(hashlib.md5(sh.encode()).digest()[:8], "big")
        for b in range(64):
            v[b] += 1 if h >> b & 1 else -1
    return sum(1 << b for b in range(64) if v[b] > 0), len(tags)


def _sim(a, b):
    return 1 - bin(a ^ b).count("1") / 64


def _dom(q):
    q = q.strip().lower()
    return P.host_of(q if "://" in q else "http://" + q)


def attribution(q, job=None):
    job = job or T.Job()
    doms = list(dict.fromkeys(d for d in (_dom(x) for x in re.split(r"[\s,;]+", q or "") if x.strip()) if d and "." in d))
    if len(doms) < 2:
        raise ValueError("Нужно минимум 2 домена (через пробел, запятую или с новой строки)")
    if len(doms) > 60:
        raise ValueError("Не больше 60 доменов за раз")
    job.total(len(doms))

    def one(d):
        f = {"domain": d}
        try:
            st, _, final, text = T._fetch_html("https://" + d, max_bytes=2_000_000)
            f["final"], f["status"] = final, st
            ids = set()
            for kind, rx in O._TRACKERS:
                for m in re.finditer(rx, text):
                    v = m.group(1) if m.groups() else m.group(0)
                    ids.add(f"{kind}: {re.sub(r'-[0-9]{1,4}$', '', v) if 'UA' in kind else v}")
            f["ids"] = sorted(ids)
            t = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            f["title"] = html.unescape(t.group(1)).strip()[:120] if t else ""
            f["simhash"], f["tags"] = _simhash(text)
            try:
                f["favicon"] = T.favicon_hash(final)["mmh3"]
            except Exception:
                pass
        except Exception as e:
            f["error"] = f"{type(e).__name__}"
        try:
            rec = T.dns_lookup(d).get("records", {})
            f["ips"], f["ns"], f["mx"] = rec.get("A", []), [n.rstrip(".").lower() for n in rec.get("NS", [])], \
                [m.split()[-1].rstrip(".").lower() for m in rec.get("MX", [])]
        except Exception:
            f["ips"], f["ns"], f["mx"] = [], [], []
        try:
            c = T.ssl_cert(d)
            f["san"], f["issuer"] = sorted(set(c.get("san") or [])), c.get("issuer")
        except Exception:
            f["san"] = []
        try:
            r = T.rdap(d)
            f["registrar"] = next((x for x in r.get("entities", []) if x.startswith("registrar")), "")
            f["created"] = (r.get("events") or {}).get("registration")
        except Exception:
            pass
        return f

    feats = []
    for d, r, err in T.pmap(one, doms, job, workers=6):
        feats.append(r or {"domain": d, "error": err})
        job.step(d)
    ips = sorted({ip for f in feats for ip in f.get("ips", [])})
    geo = {}
    try:
        geo = X.geolocate_ips(ips) if ips else {}
    except Exception:
        pass
    for f in feats:
        f["asn"] = sorted({(geo.get(ip) or {}).get("as", "").split(" ")[0] for ip in f.get("ips", [])} - {""})
    idx = {f["domain"]: i for i, f in enumerate(feats)}
    count = collections.Counter()
    for f in feats:
        for k in set(f.get("ids", [])) | {f"fav:{f['favicon']}" for _ in [0] if f.get("favicon") is not None}:
            count[k] += 1
    pairs = []
    for i in range(len(feats)):
        for j in range(i + 1, len(feats)):
            a, b, ev = feats[i], feats[j], []
            shared_ids = set(a.get("ids", [])) & set(b.get("ids", []))
            for s in sorted(shared_ids):
                ev.append((0.9, f"общий ID: {s}"))
            if a.get("favicon") is not None and a.get("favicon") == b.get("favicon") and count[f"fav:{a['favicon']}"] < max(3, len(feats) * 0.8):
                ev.append((0.6, f"одинаковый favicon (mmh3 {a['favicon']})"))
            san_a = {s.lstrip("*.") for s in a.get("san", [])}
            san_b = {s.lstrip("*.") for s in b.get("san", [])}
            if a["domain"] in san_b or b["domain"] in san_a:
                ev.append((0.85, "один TLS-сертификат на оба домена"))
            sip = set(a.get("ips", [])) & set(b.get("ips", []))
            if sip:
                cdn = any(x in CDN_ASN for x in a.get("asn", []))
                ev.append((0.12 if cdn else 0.5, f"общий IP {', '.join(sorted(sip)[:3])}" + (" (CDN — слабый признак)" if cdn else "")))
            sns = set(a.get("ns", [])) & set(b.get("ns", []))
            if sns:
                gen = all(any(g in n for g in GENERIC_NS) for n in sns)
                ev.append((0.06 if gen else 0.4, f"общие NS {', '.join(sorted(sns)[:2])}" + (" (массовый хостинг)" if gen else "")))
            smx = {m for m in set(a.get("mx", [])) & set(b.get("mx", [])) if not any(g in m for g in GENERIC_MX)}
            if smx:
                ev.append((0.35, f"общий почтовый сервер {', '.join(sorted(smx)[:2])}"))
            if a.get("registrar") and a.get("registrar") == b.get("registrar") and a.get("created") and b.get("created"):
                try:
                    da = dt.datetime.fromisoformat(a["created"].replace("Z", "+00:00"))
                    db = dt.datetime.fromisoformat(b["created"].replace("Z", "+00:00"))
                    if abs((da - db).total_seconds()) < 3 * 86400:
                        ev.append((0.4, f"один регистратор, зарегистрированы с разницей {abs((da - db).days)} дн."))
                except ValueError:
                    pass
            if a.get("simhash") is not None and b.get("simhash") is not None and min(a.get("tags", 0), b.get("tags", 0)) > 40:
                s = _sim(a["simhash"], b["simhash"])
                if s >= 0.9:
                    ev.append((0.5 if s >= 0.95 else 0.3, f"почти одинаковая вёрстка ({round(s * 100)}%)"))
            if a.get("title") and a.get("title") == b.get("title") and len(a["title"]) > 6:
                ev.append((0.2, f"одинаковый заголовок «{a['title'][:50]}»"))
            if ev:
                p = 1.0
                for w, _ in ev:
                    p *= 1 - w
                pairs.append({"a": a["domain"], "b": b["domain"], "score": round(1 - p, 2),
                              "reasons": [r for _, r in sorted(ev, reverse=True)]})
    parent = list(range(len(feats)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for pr in pairs:
        if pr["score"] >= 0.55:
            parent[find(idx[pr["a"]])] = find(idx[pr["b"]])
    groups = collections.defaultdict(list)
    for f in feats:
        groups[find(idx[f["domain"]])].append(f["domain"])
    clusters = []
    for members in groups.values():
        if len(members) < 2:
            continue
        inside = [p for p in pairs if p["a"] in members and p["b"] in members and p["score"] >= 0.55]
        reasons = collections.Counter(r.split(":")[0].split(" (")[0] for p in inside for r in p["reasons"])
        clusters.append({"domains": sorted(members), "strength": round(max(p["score"] for p in inside), 2),
                         "why": [r for r, _ in reasons.most_common(4)]})
    clusters.sort(key=lambda c: (-len(c["domains"]), -c["strength"]))
    alone = sorted(d for m in groups.values() if len(m) == 1 for d in m)
    pairs.sort(key=lambda x: -x["score"])
    for f in feats:
        f.pop("simhash", None)
    return {"domains": doms, "clusters": clusters, "alone": alone, "pairs": pairs[:200], "sites": feats,
            "method": "Признаки: общие ID аналитики/рекламы/верификаций (сильный), один сертификат, favicon, IP (без CDN), "
                      "NS и MX (без массовых провайдеров), регистратор+дата, похожесть вёрстки (simhash), заголовок. "
                      "Сила связи — вероятностное «ИЛИ»; кластер — связь ≥ 0.55."}


# ======================================================================= 3. геопазл (Overpass)
FEATURES = {
    "church": ("⛪ Церковь", 'nwr["amenity"="place_of_worship"]["religion"="christian"]'),
    "mosque": ("🕌 Мечеть", 'nwr["amenity"="place_of_worship"]["religion"="muslim"]'),
    "temple": ("🛕 Храм (любой)", 'nwr["amenity"="place_of_worship"]'),
    "river": ("🌊 Река", 'way["waterway"="river"]'),
    "canal": ("〰 Канал", 'way["waterway"="canal"]'),
    "lake": ("💧 Озеро/пруд", 'nwr["natural"="water"]'),
    "beach": ("🏖 Пляж", 'nwr["natural"="beach"]'),
    "railway": ("🛤 Железная дорога", 'way["railway"="rail"]'),
    "station": ("🚉 Ж/д станция", 'nwr["railway"~"^(station|halt)$"]'),
    "tram": ("🚋 Трамвайные пути", 'way["railway"="tram"]'),
    "bridge": ("🌉 Мост", 'way["bridge"="yes"]["highway"]'),
    "motorway": ("🛣 Автомагистраль", 'way["highway"~"^(motorway|trunk)$"]'),
    "roundabout": ("⭕ Круговое движение", 'way["junction"="roundabout"]'),
    "fuel": ("⛽ Заправка", 'nwr["amenity"="fuel"]'),
    "power_line": ("⚡ ЛЭП", 'way["power"="line"]'),
    "substation": ("🔌 Подстанция", 'nwr["power"="substation"]'),
    "tower": ("📡 Вышка/мачта", 'nwr["man_made"~"^(tower|mast|communications_tower)$"]'),
    "water_tower": ("🗼 Водонапорная башня", 'nwr["man_made"="water_tower"]'),
    "chimney": ("🏭 Труба", 'nwr["man_made"="chimney"]'),
    "wind": ("🌬 Ветряк", 'nwr["generator:source"="wind"]'),
    "lighthouse": ("🗼 Маяк", 'nwr["man_made"="lighthouse"]'),
    "stadium": ("🏟 Стадион", 'nwr["leisure"="stadium"]'),
    "school": ("🏫 Школа", 'nwr["amenity"="school"]'),
    "hospital": ("🏥 Больница", 'nwr["amenity"="hospital"]'),
    "pharmacy": ("💊 Аптека", 'nwr["amenity"="pharmacy"]'),
    "supermarket": ("🛒 Супермаркет", 'nwr["shop"="supermarket"]'),
    "mcdonalds": ("🍔 McDonald's", 'nwr["brand:wikidata"="Q38076"]'),
    "playground": ("🛝 Детская площадка", 'nwr["leisure"="playground"]'),
    "cemetery": ("🪦 Кладбище", 'nwr["landuse"="cemetery"]'),
    "park": ("🌳 Парк", 'nwr["leisure"="park"]'),
    "castle": ("🏰 Замок/крепость", 'nwr["historic"~"^(castle|fort)$"]'),
    "monument": ("🗿 Памятник", 'nwr["historic"~"^(monument|memorial)$"]'),
    "fountain": ("⛲ Фонтан", 'nwr["amenity"="fountain"]'),
    "airport": ("✈ Аэродром", 'nwr["aeroway"="aerodrome"]'),
    "helipad": ("🚁 Вертолётная площадка", 'nwr["aeroway"="helipad"]'),
    "port": ("⚓ Порт/причал", 'nwr["harbour"="yes"];nwr["man_made"="pier"]'),
    "peak": ("⛰ Вершина", 'node["natural"="peak"]'),
    "bus_stop": ("🚏 Остановка", 'node["highway"="bus_stop"]'),
    "parking": ("🅿 Парковка", 'nwr["amenity"="parking"]'),
}
OVERPASS = ["https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"]


def _sel(key, custom=""):
    if key == "custom":
        m = re.fullmatch(r'\s*([\w:\-]+)\s*(=|~)\s*([^\s"\]]+)\s*', custom or "")
        if not m:
            raise ValueError("Свой тег: формат key=value, например man_made=crane")
        return [f'nwr["{m.group(1)}"{m.group(2)}"{m.group(3)}"]']
    if key not in FEATURES:
        raise ValueError(f"Неизвестная примета: {key}")
    return [s.strip() for s in FEATURES[key][1].split(";") if s.strip()]


def geo_bbox(q):
    j = T._get_json("https://nominatim.openstreetmap.org/search?format=json&limit=1&accept-language=ru&q=" + urllib.parse.quote(q),
                    headers={"User-Agent": f"Provenio/{P.APP_VERSION} (OSINT desktop app)"}, timeout=20)
    if not j:
        raise ValueError("Место не найдено")
    s, n, w, e = (float(x) for x in j[0]["boundingbox"])
    return {"name": j[0].get("display_name"), "bbox": [s, w, n, e]}


def overpass_query(anchor, constraints, bbox, name=""):
    s, w, n, e = bbox
    lines = [f"[out:json][timeout:90][bbox:{s:.5f},{w:.5f},{n:.5f},{e:.5f}];"]
    clean = re.sub(r"[^\w\s\-]", "", name or "").strip()
    nm = f'["name"~"{clean}",i]' if clean else ""
    lines.append("(" + "".join(f"{x}{nm};" for x in _sel(*anchor)) + ")->.a;")
    for k, (key, custom, dist) in enumerate(constraints):
        d = max(10, min(5000, int(dist or 300)))
        lines.append("(" + "".join(f"{x}(around.a:{d});" for x in _sel(key, custom)) + f")->.f{k};")
        lines.append(f"(node.a(around.f{k}:{d});way.a(around.f{k}:{d});relation.a(around.f{k}:{d}););")
        lines.append("->.a;")
    lines.append(".a out center 150;")
    return "\n".join(lines).replace(");\n->.a;", ")->.a;")


def geopuzzle(p):
    job = _job(p)
    bbox = p.get("bbox")
    if not bbox and p.get("area"):
        job.note("Ищу область…")
        bbox = geo_bbox(p["area"])["bbox"]
    if not bbox or len(bbox) != 4:
        raise ValueError("Укажите область поиска (город/регион или текущий вид глобуса)")
    s, w, n, e = (float(x) for x in bbox)
    if (n - s) * (e - w) * math.cos(math.radians((n + s) / 2)) > 4.5:
        raise ValueError("Слишком большая область — сузьте до города или района (до ~200×200 км)")
    anchor = (p.get("anchor") or "church", p.get("anchor_custom", ""))
    cons = [(c.get("key"), c.get("custom", ""), c.get("dist", 300)) for c in (p.get("constraints") or [])][:5]
    q = overpass_query(anchor, cons, [s, w, n, e], p.get("name", ""))
    job.note("Запрос к OpenStreetMap (Overpass)…")
    last = None
    for url in OVERPASS:
        try:
            req = T.urllib.request.Request(url, data=urllib.parse.urlencode({"data": q}).encode(),
                                           headers={"User-Agent": f"Provenio/{P.APP_VERSION}"})
            with T._open(req, 120) as r:
                j = json.loads(r.read().decode("utf-8", "replace"))
            break
        except Exception as ex:
            last = ex
    else:
        raise ValueError(f"Overpass недоступен: {type(last).__name__}")
    items = []
    for el in j.get("elements", []):
        lat = el.get("lat") or (el.get("center") or {}).get("lat")
        lon = el.get("lon") or (el.get("center") or {}).get("lon")
        if lat is None:
            continue
        tags = el.get("tags") or {}
        items.append({"lat": lat, "lon": lon, "name": tags.get("name") or tags.get("brand") or "", "osm": f"https://www.openstreetmap.org/{el['type']}/{el['id']}",
                      "gmaps": f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}",
                      "yandex": f"https://yandex.ru/maps/?ll={lon},{lat}&z=18&l=sat",
                      "tags": {k: v for k, v in tags.items() if k in ("amenity", "religion", "denomination", "man_made", "railway", "highway", "addr:street", "addr:city")}})
    return {"count": len(items), "items": items[:150], "bbox": [s, w, n, e], "query": q,
            "note": "Каждая точка — главная примета, рядом с которой есть все остальные. Проверьте кандидатов на панорамах и спутнике."}


def geopuzzle_tool(p):
    """Для пакетного/обычного запуска: q = JSON с параметрами."""
    return geopuzzle(json.loads(p.get("q") or "{}") | {"_job": p.get("_job")})


# ======================================================================= 5. цифровой след (самоаудит)
INTERESTING_SUB = ("dev", "test", "stage", "staging", "admin", "vpn", "jenkins", "git", "gitlab", "jira", "confluence",
                   "backup", "old", "beta", "internal", "intranet", "portal", "remote", "owa", "webmail", "grafana", "kibana", "db")


def exposure(p):
    job = _job(p)
    parts = [x for x in re.split(r"[\s,;]+", p.get("q") or "") if x]
    domain = next((_dom(x) for x in parts if "@" not in x and "." in x), None)
    emails = [x for x in parts if "@" in x][:5]
    if not domain:
        raise ValueError("Нужен домен организации (и, по желанию, email через пробел)")
    steps = ["email_sec", "headers", "security_txt", "ssl", "subdomains", "leaks", "dns", "wayback_urls"] + ["leaks_email"] * len(emails)
    job.total(len(steps) + 2)
    res, findings = {}, []

    def f(sev, area, text, fix):
        findings.append({"sev": sev, "area": area, "text": text, "fix": fix})

    def run(name, q):
        job.check()
        job.step(name)
        try:
            return T.run_tool(name, {"q": q, "_job": T.Job()})
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)[:120]}"}
    es = res["email_sec"] = run("email_sec", domain)
    if not es.get("error"):
        if not es.get("spf"):
            f("high", "Почта", "Нет SPF — письма от имени домена может отправить кто угодно.", "Добавьте TXT-запись v=spf1 … -all со своими почтовыми серверами.")
        elif "~all" in es["spf"] or "?all" in es["spf"]:
            f("low", "Почта", "SPF мягкий (~all / ?all).", "Когда все отправители учтены — перейдите на -all.")
        dm = es.get("dmarc") or ""
        if not dm:
            f("high", "Почта", "Нет DMARC — подделку писем от вашего домена получатели не отклонят.", "Добавьте _dmarc TXT: v=DMARC1; p=quarantine; rua=mailto:…")
        elif "p=none" in dm.replace(" ", ""):
            f("medium", "Почта", "DMARC в режиме p=none — только наблюдение.", "После анализа отчётов поднимите до p=quarantine или p=reject.")
    hd = res["headers"] = run("headers", "https://" + domain)
    if not hd.get("error") and hd.get("grade") in ("D", "E", "F"):
        f("medium", "Сайт", f"Заголовки безопасности сайта — оценка {hd['grade']} ({hd.get('score')}/100).", "Включите HSTS, CSP, X-Content-Type-Options, frame-ancestors.")
    if hd.get("powered_by") or (hd.get("server") or "").count("/"):
        f("low", "Сайт", f"Сервер раскрывает версии ПО: {hd.get('server') or ''} {hd.get('powered_by') or ''}".strip(), "Уберите версии из заголовков Server и X-Powered-By.")
    st = res["security_txt"] = run("security_txt", domain)
    if not st.get("found"):
        f("low", "Процессы", "Нет security.txt — исследователю некуда сообщить об уязвимости.", "Опубликуйте /.well-known/security.txt (RFC 9116) с контактом.")
    sc = res["ssl"] = run("ssl", domain)
    if not sc.get("error") and (sc.get("days_left") or 999) < 21:
        f("high", "Сайт", f"Сертификат истекает через {sc['days_left']} дн.", "Продлите сертификат или включите автопродление.")
    sd = res["subdomains"] = run("subdomains", domain)
    subs = sd.get("subdomains") or []
    risky = sorted({s for s in subs if any(re.search(rf"(^|[.\-]){k}\d*([.\-]|$)", s.split("." + domain)[0]) for k in INTERESTING_SUB)})
    if risky:
        f("medium", "Периметр", f"Публично видны служебные поддомены ({len(risky)}): {', '.join(risky[:8])}{'…' if len(risky) > 8 else ''}.",
          "Закройте их VPN/SSO или ограничьте доступ по IP; уберите забытые стенды.")
    lk = res["leaks"] = run("leaks", domain)
    if lk.get("breaches_count"):
        f("high", "Утечки", f"Сервис {domain} фигурирует в известных утечках: {lk['breaches_count']}.", "Сбросьте пароли пользователей, включите 2FA, уведомите затронутых.")
    for em in emails:
        r = run("leaks", em)
        res.setdefault("leaks_email", {})[em] = r
        if r.get("breaches_count"):
            f("high", "Утечки", f"{em} найден в утечках: {r['breaches_count']} ({', '.join(b.get('name', '') for b in (r.get('breaches') or [])[:4])}).",
              "Смените пароль этой почты и везде, где он повторялся; включите 2FA.")
    dn = res["dns"] = run("dns", domain)
    ips = (dn.get("records") or {}).get("A", [])[:5]
    if ips:
        job.step("internetdb")
        try:
            idb = T.run_tool("internetdb", {"q": " ".join(ips), "_job": T.Job()})
            res["internetdb"] = idb
            for h in idb.get("results") or []:
                bad_ports = sorted(set(h.get("ports") or []) & {21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 11211})
                if bad_ports:
                    f("high", "Периметр", f"{h['ip']}: из интернета доступны служебные порты {', '.join(map(str, bad_ports))}.", "Закройте их файрволом или спрячьте за VPN.")
                if h.get("vulns"):
                    f("critical", "Периметр", f"{h['ip']}: известные уязвимости ПО ({len(h['vulns'])}): {', '.join(h['vulns'][:5])}.", "Обновите ПО на этом хосте; проверьте по вкладке «CVE».")
        except Exception:
            pass
    wb = res["wayback_urls"] = run("wayback_urls", domain)
    groups = wb.get("groups") or {}
    if groups.get("Конфиги и бэкапы"):
        f("medium", "Утечки с сайта", f"В веб-архиве есть адреса конфигов и бэкапов ({len(groups['Конфиги и бэкапы'])}), например {groups['Конфиги и бэкапы'][0][:90]}.",
          "Проверьте, что этих файлов больше нет на сервере; запретите листинг каталогов.")
    if groups.get("Админки и вход"):
        f("low", "Периметр", f"Видны адреса входа и админок ({len(groups['Админки и вход'])}).", "Включите 2FA и защиту от перебора на этих страницах.")
    docs = [u for u in groups.get("Документы", []) if re.search(r"\.(pdf|docx?|xlsx?|pptx?)(\?|$)", u, re.I)][:5]
    authors = collections.Counter()
    job.step("метаданные документов")
    for u in docs:
        try:
            m = T.run_tool("file_meta", {"q": u, "_job": T.Job()}).get("metadata") or {}
            for k in ("Author", "Creator", "LastModifiedBy", "creator", "lastModifiedBy", "Producer", "Software"):
                if m.get(k):
                    authors[f"{k}: {m[k]}"] += 1
        except Exception:
            continue
    if authors:
        f("medium", "Метаданные", "Опубликованные документы раскрывают авторов и ПО: " + "; ".join(a for a, _ in authors.most_common(6)) + ".",
          "Очищайте метаданные перед публикацией (Файл → Сведения → Проверить документ).")
    weight = {"critical": 25, "high": 14, "medium": 7, "low": 3}
    score = min(100, sum(weight[x["sev"]] for x in findings))
    findings.sort(key=lambda x: list(weight).index(x["sev"]))
    job.step("готово")
    return {"domain": domain, "emails": emails, "score": score,
            "level": "высокая" if score >= 50 else "средняя" if score >= 20 else "низкая",
            "findings": findings, "subdomains": len(subs), "docs_checked": len(docs),
            "note": "Это то, что о вас может узнать любой — без взлома, из открытых источников. Чем выше балл, тем больше открыто."}


# ======================================================================= 6. ритм жизни
def _parse_times(text):
    out = []
    for line in re.split(r"[\n,;]+", text):
        s = line.strip().strip('"')
        if not s:
            continue
        if re.fullmatch(r"\d{10}(\.\d+)?", s):
            out.append(float(s))
            continue
        if re.fullmatch(r"\d{13}", s):
            out.append(int(s) / 1000)
            continue
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00").replace(" UTC", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            out.append(d.timestamp())
        except ValueError:
            continue
    return out


def _iso(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def activity(source, user, job):
    ts, url = [], ""
    ua = {"User-Agent": f"Provenio/{P.APP_VERSION} (OSINT research)"}
    if source == "github":
        url = f"https://github.com/{user}"
        for page in range(1, 4):
            ev = T._get_json(f"https://api.github.com/users/{urllib.parse.quote(user)}/events/public?per_page=100&page={page}", timeout=20)
            if not ev:
                break
            ts += [_iso(e["created_at"]) for e in ev if e.get("created_at")]
    elif source == "reddit":
        url = f"https://www.reddit.com/user/{user}"
        for kind in ("comments", "submitted"):
            after = ""
            for _ in range(3):
                j = T._get_json(f"https://www.reddit.com/user/{urllib.parse.quote(user)}/{kind}.json?limit=100&raw_json=1{after}", headers=ua, timeout=20)
                kids = ((j or {}).get("data") or {}).get("children") or []
                ts += [k["data"]["created_utc"] for k in kids if k.get("data", {}).get("created_utc")]
                nxt = ((j or {}).get("data") or {}).get("after")
                if not nxt:
                    break
                after = f"&after={nxt}"
    elif source == "bluesky":
        url = f"https://bsky.app/profile/{user}"
        cursor = ""
        for _ in range(6):
            j = T._get_json("https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?filter=posts_with_replies&limit=100&actor="
                            + urllib.parse.quote(user) + (f"&cursor={urllib.parse.quote(cursor)}" if cursor else ""), timeout=20)
            for it in j.get("feed") or []:
                post = it.get("post") or {}
                if (post.get("author") or {}).get("handle", "").lower() == user.lower() and not it.get("reason"):
                    t = (post.get("record") or {}).get("createdAt")
                    if t:
                        try:
                            ts.append(_iso(t))
                        except ValueError:
                            pass
            cursor = j.get("cursor") or ""
            if not cursor:
                break
    elif source == "mastodon":
        name, _, inst = user.lstrip("@").partition("@")
        if not inst:
            raise ValueError("Mastodon: укажите @user@instance")
        url = f"https://{inst}/@{name}"
        acc = T._get_json(f"https://{inst}/api/v1/accounts/lookup?acct={urllib.parse.quote(name)}", timeout=20)
        max_id = ""
        for _ in range(8):
            st = T._get_json(f"https://{inst}/api/v1/accounts/{acc['id']}/statuses?limit=40" + (f"&max_id={max_id}" if max_id else ""), timeout=20)
            if not st:
                break
            ts += [_iso(s["created_at"]) for s in st if s.get("created_at")]
            max_id = st[-1]["id"]
    job.note(f"{source}: {len(ts)} событий")
    return ts, url


TZ_CITIES = {-8: "Лос-Анджелес", -7: "Денвер", -6: "Мехико, Чикаго", -5: "Нью-Йорк, Богота", -4: "Сантьяго, Галифакс",
             -3: "Сан-Паулу, Буэнос-Айрес", 0: "Лондон, Лиссабон", 1: "Берлин, Париж, Лагос", 2: "Киев, Каир, Хельсинки",
             3: "Москва, Стамбул, Эр-Рияд", 4: "Дубай, Баку, Самара", 5: "Ташкент, Екатеринбург", 6: "Алматы, Омск",
             7: "Бангкок, Новосибирск", 8: "Пекин, Сингапур, Иркутск", 9: "Токио, Сеул, Якутск", 10: "Сидней, Владивосток",
             11: "Магадан", 12: "Окленд, Камчатка"}


def pattern_of_life(p):
    job = _job(p)
    q = (p.get("q") or "").strip()
    m = re.match(r"^(github|reddit|bsky|bluesky|mastodon)\s*:\s*(\S+)$", q, re.I)
    source, url = "timestamps", ""
    if m:
        source = {"bsky": "bluesky"}.get(m.group(1).lower(), m.group(1).lower())
        ts, url = activity(source, m.group(2), job)
    elif re.fullmatch(r"@[\w.]+@[\w.\-]+\.\w+", q):
        source = "mastodon"
        ts, url = activity("mastodon", q, job)
    elif re.fullmatch(r"[\w\-]+\.bsky\.social|[\w.\-]+\.[a-z]{2,}", q) and "\n" not in q:
        source = "bluesky"
        ts, url = activity("bluesky", q, job)
    else:
        ts = _parse_times(q)
    ts = sorted(set(t for t in ts if t > 0))
    if len(ts) < 20:
        raise ValueError(f"Мало событий ({len(ts)}): нужно хотя бы 20 временных меток")
    heat = [[0] * 24 for _ in range(7)]
    hours = [0] * 24
    for t in ts:
        d = dt.datetime.fromtimestamp(t, dt.timezone.utc)
        heat[d.weekday()][d.hour] += 1
        hours[d.hour] += 1
    best = min(range(24), key=lambda h: sum(hours[(h + k) % 24] for k in range(6)))
    quiet = sum(hours[(best + k) % 24] for k in range(6))
    center = (best + 3) % 24                     # середина 6-часового «тихого окна» (UTC)
    off = round(3.5 - center)
    off = (off + 12) % 24 - 12
    if off < -11:
        off += 24
    # уверенность: насколько «тихое» окно тише среднего, с поправкой на объём выборки
    conf = round(max(0.0, 1 - quiet / (len(ts) * 6 / 24)) * min(1.0, len(ts) / 300) * 100)
    weekly = collections.defaultdict(lambda: [0] * 24)
    for t in ts:
        d = dt.datetime.fromtimestamp(t, dt.timezone.utc)
        weekly[d.strftime("%G-W%V")][d.hour] += 1
    anomalies = []
    for wk, hs in sorted(weekly.items()):
        if sum(hs) < 15:
            continue
        b = min(range(24), key=lambda h: sum(hs[(h + k) % 24] for k in range(6)))
        shift = ((b - best + 12) % 24) - 12
        if abs(shift) >= 3:
            anomalies.append({"week": wk, "shift_h": shift, "events": sum(hs)})
    days = [sum(r) for r in heat]
    wkend = (days[5] + days[6]) / 2
    wkday = sum(days[:5]) / 5
    local = lambda h: (h + off) % 24   # noqa: E731
    return {"source": source, "url": url, "events": len(ts),
            "first": dt.datetime.fromtimestamp(ts[0], dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "last": dt.datetime.fromtimestamp(ts[-1], dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "heat_utc": heat, "hours_utc": hours, "utc_offset": off, "confidence": conf,
            "tz_examples": TZ_CITIES.get(off, ""), "sleep_local": [local(best), local(best + 6)],
            "peak_local": local(max(range(24), key=lambda h: hours[h])),
            "weekend_ratio": round(wkend / wkday, 2) if wkday else None, "anomalies": anomalies[:20],
            "note": "Часовой пояс оценивается по «тихому» 6-часовому окну (предполагается, что это сон, примерно 00:30–06:30 местного времени). "
                    "Сдвиг окна на 3+ часа в отдельные недели — признак поездки, смены режима или другого человека за аккаунтом."}


UNIQUE_TOOLS = {
    "attribution": lambda p: attribution(p["q"], job=p.get("_job")),
    "exposure": exposure,
    "pattern": pattern_of_life,
    "geopuzzle": geopuzzle_tool,
}
T.TOOLS.update(UNIQUE_TOOLS)
