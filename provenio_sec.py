# -*- coding: utf-8 -*-
"""
Provenio 2.4 — инструменты ИБ и криминалистики:
  * «Магия» декодирования: автоподбор цепочки (base64 → gzip → XOR …) и ручные рецепты;
  * криминалистика изображений: качество JPEG по таблицам квантования, следы редакторов,
    миниатюра EXIF (сравнение с фото и ELA/LSB делает интерфейс на canvas);
  * разбор email-заголовков: путь письма по серверам, SPF/DKIM/DMARC, признаки подделки;
  * утечки вымогателей: поиск жертв по публичному агрегатору ransomware.live + наблюдение;
  * поток сертификатов: живое чтение CT-логов Let's Encrypt и поиск доменов-двойников бренда.
Только стандартная библиотека.
"""
import base64
import binascii
import bz2
import codecs
import collections
import email.parser
import email.utils
import gzip
import html
import ipaddress
import json
import lzma
import math
import os
import quopri
import re
import struct
import threading
import time
import urllib.parse
import zlib

import provenio as P
import provenio_tools as T
import provenio_osint as O
import provenio_plus as X


def _job(p):
    return p.get("_job") or T.Job()


# ======================================================================= «Магия» декодирования
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I",
         ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
         "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z",
         "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
         "--...": "7", "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?", "-..-.": "/",
         "-....-": "-", "-.--.": "(", "-.--.-": ")", ".--.-.": "@", "---...": ":", "-...-": "="}
FILE_MAGIC = [(b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff", "JPEG"), (b"GIF8", "GIF"), (b"%PDF-", "PDF"),
              (b"PK\x03\x04", "ZIP/Office"), (b"\x7fELF", "ELF"), (b"MZ", "Windows EXE"), (b"Rar!", "RAR"),
              (b"7z\xbc\xaf", "7z"), (b"SQLite format 3", "SQLite"), (b"\x1f\x8b\x08", "GZIP"), (b"BZh9", "BZIP2"),
              (b"\xfd7zXZ", "XZ")]
WORDS = {"the", "and", "you", "that", "is", "are", "was", "for", "with", "this", "flag", "password", "secret", "user",
         "admin", "key", "http", "https", "www", "com", "hello", "world", "data", "token", "login", "ctf", "of", "to",
         "in", "it", "on", "not", "have", "from", "your", "pass", "name", "email",
         "и", "в", "не", "на", "что", "это", "как", "пароль", "привет", "мир", "ключ", "секрет", "для", "по", "с", "из"}
TEXTISH = re.compile(r"[\w\s.,;:!?'\"()\[\]{}<>/@#%&*+=\-|\\^~`$]", re.U)


def file_type(b):
    for sig, name in FILE_MAGIC:
        if b.startswith(sig):
            return name
    return None


def as_text(b):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None


def score(b):
    """0..1 — насколько данные похожи на осмысленный результат."""
    if not b:
        return 0.0
    if file_type(b):
        return 0.93
    s = as_text(b)
    if s is None:
        good = sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)
        return round(good * 0.35, 4)
    n = len(s)
    good = sum(1 for ch in s if TEXTISH.match(ch)) / n
    ctrl = sum(1 for ch in s if ord(ch) < 32 and ch not in "\r\n\t") / n
    words = re.findall(r"[a-zа-яё]{1,12}", s.lower())
    wb = min(1.0, sum(w in WORDS for w in words) / max(1, len(words)) * 3) if words else 0
    letters = [ch for ch in s.lower() if "a" <= ch <= "z"]
    vow = (sum(ch in "aeiouy" for ch in letters) / len(letters)) if len(letters) >= 8 else 0.38
    vb = max(0.0, 1 - abs(vow - 0.38) * 3)
    sc = good * 0.55 + wb * 0.25 + vb * 0.12 + (0.08 if " " in s or "\n" in s else 0) - ctrl * 2
    if re.search(r"(flag|ctf|htb|thm)\{[^}]{1,80}\}", s, re.I):
        sc += 0.35
    try:
        if s.strip()[:1] in "{[":
            json.loads(s)
            sc += 0.2
    except ValueError:
        pass
    # всё ещё похоже на кодировку — результат «промежуточный»
    t = s.strip()
    if len(t) >= 12 and (re.fullmatch(r"[A-Za-z0-9+/=_\-\s]+", t) and not re.search(r"\s\w+\s", t)
                         or re.fullmatch(r"(?:[0-9a-fA-F]{2}[\s:]?)+", t) or re.fullmatch(r"[01\s]+", t)
                         or re.fullmatch(r"[.\-/\s]+", t) or "%" in t and re.search(r"%[0-9A-Fa-f]{2}", t)):
        sc -= 0.3
    return round(max(0.0, min(1.0, sc)), 4)


def _b64(s, alt=None):
    t = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", t) or len(t) < 4:
        raise ValueError
    t = t.replace("-", "+").replace("_", "/")
    return base64.b64decode(t + "=" * (-len(t) % 4), validate=True)


def _b32(s):
    t = re.sub(r"\s+", "", s).upper()
    if not re.fullmatch(r"[A-Z2-7]+=*", t) or len(t) < 8:
        raise ValueError
    return base64.b32decode(t + "=" * (-len(t) % 8))


def _b58(s):
    t = s.strip()
    if not re.fullmatch(f"[{B58}]+", t) or len(t) < 6:
        raise ValueError
    n = 0
    for ch in t:
        n = n * 58 + B58.index(ch)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(t) - len(t.lstrip("1"))) + out


def _hex(s):
    t = re.sub(r"0x|\\x|[\s:,]", "", s, flags=re.I)
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", t):
        raise ValueError
    return bytes.fromhex(t)


def _bin(s):
    t = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[01]+", t) or len(t) % 8:
        raise ValueError
    return bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))


def _dec(s):
    parts = re.split(r"[\s,;]+", s.strip())
    if len(parts) < 3 or not all(p.isdigit() and int(p) < 256 for p in parts):
        raise ValueError
    return bytes(int(p) for p in parts)


def _oct(s):
    parts = re.findall(r"\\?([0-7]{3})", s)
    if len(parts) < 3 or len("".join(parts)) * 1.0 < len(re.sub(r"[\s\\]", "", s)) * 0.9:
        raise ValueError
    return bytes(int(p, 8) & 255 for p in parts)


def _url(s):
    if not re.search(r"%[0-9A-Fa-f]{2}|\+", s):
        raise ValueError
    return urllib.parse.unquote_to_bytes(s.replace("+", " "))


def _html(s):
    if not re.search(r"&(#\d+|#x[0-9a-f]+|[a-z]+);", s, re.I):
        raise ValueError
    return html.unescape(s).encode("utf-8")


def _uesc(s):
    if not re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", s):
        raise ValueError
    return codecs.decode(s.encode("latin-1", "backslashreplace"), "unicode_escape").encode("utf-8")


def _qp(s):
    if not re.search(r"=[0-9A-F]{2}", s):
        raise ValueError
    return quopri.decodestring(s.encode("latin-1", "ignore"))


def _rot13(s):
    if not re.search(r"[A-Za-z]", s):
        raise ValueError
    return codecs.encode(s, "rot13").encode("utf-8")


def _rot47(s):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s).encode("utf-8")


def _atbash(s):
    def f(c):
        if "a" <= c <= "z":
            return chr(219 - ord(c))
        if "A" <= c <= "Z":
            return chr(155 - ord(c))
        return c
    return "".join(map(f, s)).encode("utf-8")


def _morse(s):
    t = s.strip()
    if not re.fullmatch(r"[.\-/\s|]+", t) or len(t) < 5:
        raise ValueError
    words = re.split(r"\s*[/|]\s*|\s{3,}", t)
    return " ".join("".join(MORSE.get(ch, "?") for ch in w.split()) for w in words).encode()


def _decompress(b):
    for f in (gzip.decompress, zlib.decompress, lambda x: zlib.decompress(x, -15), bz2.decompress, lzma.decompress):
        try:
            out = f(b)
            if out:
                return out
        except Exception:
            continue
    raise ValueError


def _rot_best(s):
    best = None
    for n in range(1, 26):
        if n == 13:
            continue
        out = "".join(chr((ord(c) - 97 + n) % 26 + 97) if "a" <= c <= "z" else
                      chr((ord(c) - 65 + n) % 26 + 65) if "A" <= c <= "Z" else c for c in s).encode()
        sc = score(out)
        if not best or sc > best[0]:
            best = (sc, n, out)
    return best


def _xor_best(b):
    best = None
    for k in range(1, 256):
        out = bytes(x ^ k for x in b)
        sc = score(out)
        if not best or sc > best[0]:
            best = (sc, k, out)
    return best


def _xor_key(b, key):
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(b))


TEXT_OPS = [("base64", _b64), ("base32", _b32), ("base58", _b58), ("hex", _hex), ("binary", _bin), ("decimal", _dec),
            ("octal", _oct), ("url", _url), ("html", _html), ("unicode_escape", _uesc), ("quoted_printable", _qp),
            ("morse", _morse), ("rot13", _rot13), ("rot47", lambda s: _rot47(s)), ("atbash", _atbash),
            ("reverse", lambda s: s[::-1].encode("utf-8"))]
OP_NAMES = {"b64": "base64", "base64": "base64", "b32": "base32", "base32": "base32", "b58": "base58", "base58": "base58",
            "hex": "hex", "bin": "binary", "binary": "binary", "dec": "decimal", "decimal": "decimal", "oct": "octal",
            "url": "url", "html": "html", "unicode": "unicode_escape", "unicode_escape": "unicode_escape", "qp": "quoted_printable",
            "morse": "morse", "rot13": "rot13", "rot47": "rot47", "atbash": "atbash", "reverse": "reverse",
            "gunzip": "decompress", "unzip": "decompress", "inflate": "decompress", "decompress": "decompress",
            "xor": "xor", "rot": "rot"}


def _candidates(b):
    """Все применимые к данным шаги: (название, результат)."""
    out = []
    s = as_text(b)
    if s is not None and len(s) < 2_000_000:
        for name, fn in TEXT_OPS:
            try:
                r = fn(s)
                if r and r != b:
                    out.append((name, r))
            except Exception:
                continue
        if re.search(r"[A-Za-z]{4}", s) and score(b) < 0.9:
            best = _rot_best(s)
            if best and best[0] > score(b) + 0.1:
                out.append((f"rot{best[1]}", best[2]))
        if s.count(".") == 2 and re.fullmatch(r"[\w\-]+\.[\w\-]+\.[\w\-]*", s.strip()):
            try:
                h, pl = s.strip().split(".")[:2]
                out.append(("jwt", json.dumps({"header": json.loads(_b64(h)), "payload": json.loads(_b64(pl))},
                                              ensure_ascii=False, indent=1).encode()))
            except Exception:
                pass
    try:
        out.append(("decompress", _decompress(b)))
    except Exception:
        pass
    sb = score(b)
    if s is None or sb < 0.85:         # XOR с перебором ключа — для двоичных или «бессмысленных» данных
        best = _xor_best(b[:4096])
        if best and best[0] > max(0.6, sb + 0.15):
            out.append((f"xor 0x{best[1]:02x}", bytes(x ^ best[1] for x in b)))
    return out


def magic(data, depth=8, beam=10):
    start = (score(data), [], data)
    beam_states, seen, finals = [start], {data}, [start]
    for _ in range(depth):
        nxt = []
        for sc, chain, b in beam_states:
            for name, r in _candidates(b):
                if r in seen or len(r) > 5_000_000:
                    continue
                seen.add(r)
                st = (score(r), chain + [(name, r)], r)
                nxt.append(st)
                finals.append(st)
        if not nxt:
            break
        # структурные шаги (декодирование, распаковка, XOR) держим в луче, даже если их результат пока «некрасивый»
        structural = ("base", "hex", "binary", "decimal", "octal", "url", "decompress", "xor", "quoted", "unicode", "html", "jwt")
        nxt.sort(key=lambda x: (-x[0], len(x[1])))
        keep = [st for st in nxt if st[1][-1][0].startswith(structural)][:beam // 2 + 1]
        beam_states = keep + [st for st in nxt if st not in keep][:beam - len(keep)]
    finals.sort(key=lambda x: (-(x[0] - 0.01 * len(x[1])), len(x[1])))
    return finals


def _show(b):
    ft = file_type(b)
    s = as_text(b)
    if ft:
        return {"type": "file", "file_type": ft, "size": len(b), "hex": b[:96].hex(" "),
                "b64": base64.b64encode(b[:3_000_000]).decode()}
    if s is not None:
        return {"type": "text", "text": s[:20000], "size": len(b)}
    return {"type": "binary", "size": len(b), "hex": b[:512].hex(" ")}


def run_recipe(data, recipe):
    steps = []
    for raw in [x.strip() for x in re.split(r">|\|", recipe) if x.strip()]:
        name, _, arg = raw.partition(":")
        op = OP_NAMES.get(name.strip().lower())
        if not op:
            raise ValueError(f"Неизвестная операция: {name}. Доступно: {', '.join(sorted(set(OP_NAMES)))}")
        if op == "decompress":
            data = _decompress(data)
        elif op == "xor":
            a = arg.strip()
            if not a:
                k = _xor_best(data[:4096])
                a, data = f"0x{k[1]:02x}", bytes(x ^ k[1] for x in data)
            else:
                key = bytes.fromhex(a[2:]) if a.lower().startswith("0x") else a.encode()
                data = _xor_key(data, key)
            raw = f"xor {a}"
        elif op == "rot":
            n = int(arg or 13)
            s = as_text(data) or ""
            data = "".join(chr((ord(c) - 97 + n) % 26 + 97) if "a" <= c <= "z" else
                           chr((ord(c) - 65 + n) % 26 + 65) if "A" <= c <= "Z" else c for c in s).encode()
        else:
            fn = dict(TEXT_OPS)[op]
            s = as_text(data)
            if s is None:
                raise ValueError(f"Шаг «{raw}»: на входе не текст")
            data = fn(s)
        steps.append({"op": raw, "preview": _preview(data)})
    return steps, data


def _preview(b, n=160):
    s = as_text(b)
    if file_type(b):
        return f"[файл {file_type(b)}, {len(b)} байт]"
    if s is not None:
        return s[:n] + ("…" if len(s) > n else "")
    return b[:48].hex(" ") + (" …" if len(b) > 48 else "")


def magic_tool(p):
    """Автоподбор цепочки декодирования или рецепт: первая строка «recipe: b64 > gunzip > xor:0x2a»."""
    job = _job(p)
    if p.get("file"):
        data = base64.b64decode(p["file"])
        recipe = ""
    else:
        q = p.get("q") or ""
        m = re.match(r"\s*(?:recipe|рецепт)\s*:\s*(.+?)\n(.*)", q, re.S | re.I)
        recipe, text = (m.group(1), m.group(2)) if m else ("", q)
        data = text.strip().encode("utf-8")
    if not data:
        raise ValueError("Пустой ввод")
    if len(data) > 5_000_000:
        raise ValueError("Слишком много данных (максимум 5 МБ)")
    if recipe:
        steps, out = run_recipe(data, recipe)
        return {"mode": "recipe", "recipe": recipe, "steps": steps, "output": _show(out), "score": score(out)}
    job.note("Подбираю цепочку…")
    finals = magic(data)
    best = finals[0]
    alts, shown = [], {best[2]}
    for sc, chain, b in finals[1:]:
        if b in shown or not chain or sc < 0.45:
            continue
        shown.add(b)
        alts.append({"chain": [c[0] for c in chain], "score": sc, "preview": _preview(b)})
        if len(alts) >= 5:
            break
    return {"mode": "magic", "input_score": score(data),
            "steps": [{"op": name, "preview": _preview(b)} for name, b in best[1]],
            "recipe": " > ".join(n.replace("xor 0x", "xor:0x").replace(" ", "") for n, _ in best[1]),
            "output": _show(best[2]), "score": best[0], "alternatives": alts}


# ======================================================================= криминалистика изображений
STD_LUMA = [16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29,
            51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121,
            120, 101, 72, 92, 95, 98, 112, 100, 103, 99]
ZIGZAG = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21,
          28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61,
          54, 47, 55, 62, 63]
EDITORS = ["photoshop", "gimp", "lightroom", "affinity", "pixelmator", "snapseed", "picsart", "canva", "paint.net",
           "facetune", "luminar", "capture one", "darktable", "krita", "corel", "acdsee", "meitu", "remini", "midjourney",
           "dall-e", "stable diffusion", "firefly"]


def jpeg_segments(data):
    segs, pos = [], 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        m = data[pos + 1]
        if m in (0xD9, 0xDA):
            segs.append((m, b""))
            break
        if m == 0xFF:
            pos += 1
            continue
        ln = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        segs.append((m, data[pos + 4:pos + 2 + ln]))
        pos += 2 + ln
    return segs


def jpeg_quality(dqt_tables):
    """Оценка качества JPEG по таблице квантования яркости (стандарт IJG)."""
    luma = dqt_tables.get(0)
    if not luma:
        return None, False
    nat = [0] * 64
    for i, v in enumerate(luma):
        nat[ZIGZAG[i]] = v
    best = None
    for q in range(1, 101):
        sc = 5000 / q if q < 50 else 200 - 2 * q
        tbl = [min(255, max(1, int((v * sc + 50) // 100))) for v in STD_LUMA]
        err = sum(abs(a - b) for a, b in zip(tbl, nat))
        if best is None or err < best[1]:
            best = (q, err)
    return best[0], best[1] <= 16      # (качество, совпадает ли со стандартной таблицей)


def _dqt(payload):
    out, i = {}, 0
    while i < len(payload):
        pq, tq = payload[i] >> 4, payload[i] & 15
        n = 128 if pq else 64
        vals = payload[i + 1:i + 1 + n]
        out[tq] = list(struct.unpack(">64H", vals)) if pq else list(vals)
        i += 1 + n
    return out


def exif_thumbnail(app1):
    """JPEG-миниатюра из IFD1 блока EXIF (если есть)."""
    if not app1.startswith(b"Exif\0\0"):
        return None
    t = app1[6:]
    if len(t) < 8:
        return None
    e = "<" if t[:2] == b"II" else ">"
    try:
        ifd0 = struct.unpack(e + "I", t[4:8])[0]
        n = struct.unpack(e + "H", t[ifd0:ifd0 + 2])[0]
        ifd1 = struct.unpack(e + "I", t[ifd0 + 2 + n * 12:ifd0 + 6 + n * 12])[0]
        if not ifd1:
            return None
        n1 = struct.unpack(e + "H", t[ifd1:ifd1 + 2])[0]
        off = ln = None
        for k in range(n1):
            tag, typ, cnt, val = struct.unpack(e + "HHII", t[ifd1 + 2 + k * 12:ifd1 + 14 + k * 12])
            if tag == 0x0201:
                off = val
            elif tag == 0x0202:
                ln = val
        if off and ln and t[off:off + 2] == b"\xff\xd8":
            return t[off:off + ln]
    except (struct.error, IndexError):
        return None
    return None


def jpeg_size(data):
    for m, seg in jpeg_segments(data):
        if m in (0xC0, 0xC1, 0xC2) and len(seg) >= 5:
            h, w = struct.unpack(">HH", seg[1:5])
            return w, h
    return None


def img_forensics(p):
    """Признаки обработки изображения. ELA, LSB и сравнение миниатюры считает интерфейс (canvas)."""
    job = _job(p)
    if p.get("file"):
        data = base64.b64decode(p["file"])
        name = p.get("filename") or "image"
    else:
        url = O._url(p.get("q", ""))
        job.note("Загрузка изображения…")
        _, _, _, data = T._get(url, max_bytes=25_000_000, timeout=60)
        name = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1] or url
    kind = file_type(data) or ("WebP" if data[:4] == b"RIFF" and data[8:12] == b"WEBP" else "неизвестно")
    flags, out = [], {"name": name, "type": kind, "size": len(data), "sha256": P.sha256_bytes(data)}
    meta = {}
    try:
        meta = (O.file_meta({"file": base64.b64encode(data).decode(), "filename": name}) or {}).get("metadata") or {}
    except Exception:
        pass
    out["metadata"] = {k: (v if isinstance(v, (str, int, float)) else str(v)) for k, v in list(meta.items())[:60]}
    blob = " ".join(str(v) for v in meta.values()).lower()
    if kind == "JPEG":
        segs = jpeg_segments(data)
        tables = {}
        for m, seg in segs:
            if m == 0xDB:
                tables.update(_dqt(seg))
        q, standard = jpeg_quality(tables)
        out["jpeg"] = {"quality": q, "standard_tables": standard, "progressive": any(m == 0xC2 for m, _ in segs),
                       "size": jpeg_size(data),
                       "segments": [f"APP{m - 0xE0}" if 0xE0 <= m <= 0xEF else hex(m) for m, _ in segs if m != 0xDA][:30]}
        if q and not standard:
            flags.append(("info", "Нестандартные таблицы квантования — так сохраняют камеры и некоторые редакторы (Photoshop)."))
        if q and q < 75:
            flags.append(("info", f"Качество ≈{q}: так сохраняют мессенджеры и соцсети — снимок, вероятно, пересжат."))
        apps = {m: seg for m, seg in segs if 0xE0 <= m <= 0xEF}
        if 0xED in apps and b"Photoshop" in apps[0xED][:20]:
            flags.append(("warn", "Есть блок Photoshop (APP13) — файл сохранялся в Photoshop."))
        if 0xEE in apps and apps[0xEE][:5] == b"Adobe":
            flags.append(("info", "Есть блок Adobe (APP14)."))
        app1 = [seg for m, seg in segs if m == 0xE1 and seg.startswith(b"Exif")]
        thumb = exif_thumbnail(app1[0]) if app1 else None
        if thumb:
            out["thumbnail"] = {"b64": base64.b64encode(thumb).decode(), "size": jpeg_size(thumb)}
        if not app1:
            flags.append(("info", "EXIF нет — его удаляют мессенджеры, соцсети и «очистка метаданных»."))
        xmp = b"".join(seg for m, seg in segs if m == 0xE1 and b"ns.adobe.com/xap" in seg[:64])
        if xmp:
            tool = re.search(rb"CreatorTool[\"'>=\s]+([^<\"']{2,60})", xmp)
            hist = re.findall(rb"stEvt:softwareAgent[\"'>=\s]+([^<\"']{2,60})", xmp)
            out["xmp"] = {"creator_tool": tool.group(1).decode("utf-8", "replace") if tool else None,
                          "history": sorted({h.decode("utf-8", "replace") for h in hist})[:10]}
            blob += " " + xmp.decode("utf-8", "replace").lower()
    for ed in EDITORS:
        if ed in blob:
            flags.append(("warn", f"В метаданных упоминается «{ed}» — изображение обрабатывалось в редакторе/генераторе."))
            break
    d1 = meta.get("DateTimeOriginal")
    d2 = meta.get("DateTime") or meta.get("ModifyDate")
    if d1 and d2 and str(d1) != str(d2):
        flags.append(("warn", f"Дата съёмки ({d1}) и дата изменения ({d2}) различаются — файл менялся после съёмки."))
    if re.search(r"c2pa|contentcredentials|jumbf", blob) or b"c2pa" in data[:200000]:
        flags.append(("info", "Есть Content Credentials (C2PA) — проверьте происхождение на contentcredentials.org/verify."))
    out["flags"] = [{"level": lv, "text": t} for lv, t in flags]
    out["mime"] = {"JPEG": "image/jpeg", "PNG": "image/png", "GIF": "image/gif", "WebP": "image/webp"}.get(kind)
    if not p.get("file") and out["mime"] and len(data) <= 12_000_000:
        out["image_b64"] = base64.b64encode(data).decode()     # для ELA/LSB в интерфейсе (картинка с чужого сайта)
    return out


# ======================================================================= email-заголовки
RX_IP = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])|\[(IPv6:)?([0-9a-fA-F:]{6,})\]")


def _public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast)
    except ValueError:
        return False


def _dom(addr):
    a = email.utils.parseaddr(addr or "")[1]
    return a.rsplit("@", 1)[-1].lower().strip(">") if "@" in a else ""


def _org(d):
    parts = d.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_received(h):
    h = " ".join(h.split())
    body, _, date = h.rpartition(";")
    if not body:
        body, date = h, ""
    m = lambda rx: (re.search(rx, body, re.I) or [None, None])[1]   # noqa: E731
    ips = []
    for g in RX_IP.finditer(body):
        ip = g.group(1) or g.group(3)
        if ip and ip not in ips:
            ips.append(ip)
    ts = None
    try:
        ts = email.utils.parsedate_to_datetime(date.strip()).timestamp() if date.strip() else None
    except (TypeError, ValueError, IndexError):
        ts = None
    return {"from": m(r"\bfrom\s+(\S+)"), "by": m(r"\bby\s+(\S+)"), "with": m(r"\bwith\s+(\S+)"),
            "ips": ips, "date": date.strip()[:60], "ts": ts, "tls": bool(re.search(r"TLS|ESMTPS|cipher", body)),
            "raw": h[:400]}


def email_headers(p):
    job = _job(p)
    raw = base64.b64decode(p["file"]).decode("utf-8", "replace") if p.get("file") else (p.get("q") or "")
    raw = raw.replace("\r\n", "\n")
    head = raw.split("\n\n", 1)[0] if "\n\n" in raw else raw
    msg = email.parser.HeaderParser().parsestr(head + "\n\n")
    if not msg.keys():
        raise ValueError("Не нашёл заголовков. Вставьте исходный текст письма («Показать оригинал»).")
    hops = [parse_received(h) for h in (msg.get_all("Received") or [])][::-1]     # от отправителя к получателю
    prev = None
    for h in hops:
        h["delay"] = round(h["ts"] - prev, 1) if h["ts"] and prev else None
        prev = h["ts"] or prev
    frm, rp, rt = msg.get("From", ""), msg.get("Return-Path", ""), msg.get("Reply-To", "")
    fd, rpd, rtd = _dom(frm), _dom(rp), _dom(rt)
    auth = " ".join(msg.get_all("Authentication-Results") or []) + " " + " ".join(msg.get_all("ARC-Authentication-Results") or [])
    res = {k: (re.search(rf"\b{k}=(\w+)", auth, re.I) or [None, None])[1] for k in ("spf", "dkim", "dmarc")}
    rspf = msg.get("Received-SPF", "")
    if not res["spf"] and rspf:
        res["spf"] = rspf.split()[0].lower()
    dkims = [dict(re.findall(r"\b([a-z])=([^;\s]+)", s)) for s in (msg.get_all("DKIM-Signature") or [])]
    dkim_d = [d.get("d", "").lower() for d in dkims if d.get("d")]
    mid = msg.get("Message-ID", "")
    mid_d = mid.rsplit("@", 1)[-1].strip("> ").lower() if "@" in mid else ""
    flags = []

    def flag(level, text):
        flags.append({"level": level, "text": text})
    for k in ("spf", "dkim", "dmarc"):
        v = (res[k] or "").lower()
        if v in ("fail", "softfail", "permerror", "none") and v:
            flag("bad" if k != "spf" or v == "fail" else "warn", f"{k.upper()} = {v}")
        elif v == "pass":
            flag("ok", f"{k.upper()} = pass")
    if not any(res.values()):
        flag("warn", "Нет Authentication-Results: проверки SPF/DKIM/DMARC в заголовках не видно.")
    if fd and rpd and _org(fd) != _org(rpd):
        flag("warn", f"Домен From ({fd}) и Return-Path ({rpd}) различаются — частый признак рассылок и подделки.")
    if fd and rtd and _org(fd) != _org(rtd):
        flag("bad", f"Reply-To ведёт на другой домен ({rtd}) — ответ уйдёт не отправителю. Классика фишинга и BEC.")
    if fd and dkim_d and not any(_org(d) == _org(fd) for d in dkim_d):
        flag("warn", f"Подпись DKIM от {', '.join(dkim_d)}, а не от домена отправителя {fd} — нет выравнивания DMARC.")
    if fd and mid_d and _org(mid_d) != _org(fd):
        flag("info", f"Message-ID создан на {mid_d}, а не на {fd}.")
    disp = email.utils.parseaddr(frm)[0]
    if disp and re.search(r"@[\w.-]+\.\w+", disp) and _dom(disp) != fd:
        flag("bad", f"В имени отправителя спрятан другой адрес: «{disp}».")
    for i, h in enumerate(hops):
        if h["delay"] is not None and h["delay"] < -300:
            flag("warn", f"Хоп {i + 1}: время раньше предыдущего на {int(-h['delay'])} с — часы сервера или подделанный Received.")
        if h["delay"] and h["delay"] > 3600:
            flag("info", f"Хоп {i + 1}: задержка {int(h['delay'] // 60)} мин.")
    ips = [ip for h in hops for ip in h["ips"] if _public(ip)]
    geo = {}
    if ips:
        job.note("Геолокация серверов…")
        try:
            geo = X.geolocate_ips(list(dict.fromkeys(ips)))
        except Exception:
            geo = {}
    for h in hops:
        g = next((geo.get(ip) for ip in h["ips"] if geo.get(ip, {}).get("status") == "success"), None)
        if g:
            h["geo"] = {"ip": g.get("query"), "country": g.get("country"), "city": g.get("city"), "isp": g.get("isp"),
                        "lat": g.get("lat"), "lon": g.get("lon")}
    origin = next((h for h in hops if any(_public(ip) for ip in h["ips"])), None)
    total = (hops[-1]["ts"] - hops[0]["ts"]) if len(hops) > 1 and hops[-1]["ts"] and hops[0]["ts"] else None
    bad = sum(f["level"] == "bad" for f in flags)
    warn = sum(f["level"] == "warn" for f in flags)
    verdict = "подозрительное" if bad else "есть вопросы" if warn else "признаков подделки не найдено"
    return {"subject": msg.get("Subject", ""), "from": frm, "to": msg.get("To", ""), "date": msg.get("Date", ""),
            "return_path": rp, "reply_to": rt, "message_id": mid, "x_mailer": msg.get("X-Mailer") or msg.get("User-Agent"),
            "auth": res, "dkim_domains": dkim_d, "hops": hops, "origin_ip": origin and next(
                (ip for ip in origin["ips"] if _public(ip)), None),
            "transit_sec": total, "flags": flags, "verdict": verdict,
            "ips": list(dict.fromkeys(ips)), "domains": [d for d in {fd, rpd, rtd, mid_d, *dkim_d} if d]}


# ======================================================================= утечки вымогателей
RL_LOCK = threading.Lock()
RL = {"last": 0.0, "cache": {}}


def ransom_search(keyword):
    kw = keyword.strip()
    if len(kw) < 3:
        raise ValueError("Минимум 3 символа")
    ck = kw.lower()
    with RL_LOCK:
        c = RL["cache"].get(ck)
        if c and time.time() - c[0] < 3600:
            return c[1]
        wait = 61 - (time.time() - RL["last"])
        if wait > 0:
            time.sleep(wait)       # публичный API: 1 запрос в минуту
        RL["last"] = time.time()
        j = T._get_json("https://api.ransomware.live/v2/searchvictims/" + urllib.parse.quote(kw), timeout=30)
    if isinstance(j, dict) and j.get("message"):
        raise ValueError("ransomware.live: " + str(j["message"]))
    items = []
    for v in j if isinstance(j, list) else []:
        g = lambda *ks: next((v.get(k) for k in ks if v.get(k)), "")   # noqa: E731
        items.append({"victim": html.unescape(str(g("victim", "post_title", "name"))), "group": g("group", "group_name"),
                      "domain": g("domain", "website"), "country": g("country"), "activity": g("activity"),
                      "attackdate": str(g("attackdate"))[:10], "discovered": str(g("discovered"))[:10],
                      "description": html.unescape(str(g("description")))[:400],
                      "onion": str(g("claim_url", "post_url", "url"))[:200]})
    items.sort(key=lambda x: x["discovered"] or x["attackdate"], reverse=True)
    RL["cache"][ck] = (time.time(), items)
    return items


def ransomware_tool(p):
    job = _job(p)
    kw = (p.get("q") or "").strip()
    job.note("Запрос к ransomware.live (лимит — 1 запрос в минуту)…")
    items = ransom_search(kw)
    groups = collections.Counter(i["group"] for i in items if i["group"])
    return {"query": kw, "count": len(items), "victims": items[:200], "groups": groups.most_common(15),
            "source": "ransomware.live (публичный агрегатор сайтов утечек)",
            "note": "Ссылки .onion показаны только текстом. Совпадение по названию не всегда означает ту же компанию."}


# ======================================================================= поток сертификатов (CT)
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
FALLBACK_LOGS = ["https://mon.sycamore.ct.letsencrypt.org/2026h2/", "https://mon.willow.ct.letsencrypt.org/2026h2/"]
BYTES_PER_HOUR_EST = 90_000_000


def _len3(b, i):
    return int.from_bytes(b[i:i + 3], "big"), i + 3


def der_len(b, i):
    n = b[i]
    if n < 0x80:
        return n, i + 1
    k = n & 0x7F
    return int.from_bytes(b[i + 1:i + 1 + k], "big"), i + 1 + k


def san_names(der):
    """DNS-имена из расширения subjectAltName (сертификат или TBSCertificate)."""
    names = []
    i = der.find(b"\x06\x03\x55\x1d\x11")
    if i < 0:
        return names
    try:
        i += 5
        if der[i] == 0x01:          # critical BOOLEAN
            i += 3
        if der[i] != 0x04:
            return names
        ln, i = der_len(der, i + 1)
        val = der[i:i + ln]
        if val[0] != 0x30:
            return names
        sl, j = der_len(val, 1)
        end = j + sl
        while j < end:
            tag = val[j]
            l2, k = der_len(val, j + 1)
            if tag == 0x82:
                names.append(val[k:k + l2].decode("ascii", "replace").lower())
            j = k + l2
    except IndexError:
        pass
    return names


def parse_data_tile(data):
    """static-ct-api: последовательность TileLeaf → [(timestamp_ms, [домены])]."""
    out, i, n = [], 0, len(data)
    while i + 10 <= n:
        ts = int.from_bytes(data[i:i + 8], "big")
        et = int.from_bytes(data[i + 8:i + 10], "big")
        i += 10
        if et == 0:
            ln, i = _len3(data, i)
            cert = data[i:i + ln]
            i += ln
            ext = int.from_bytes(data[i:i + 2], "big")
            i += 2 + ext
            ch = int.from_bytes(data[i:i + 2], "big")
            i += 2 + ch
        elif et == 1:
            i += 32
            ln, i = _len3(data, i)
            cert = data[i:i + ln]
            i += ln
            ext = int.from_bytes(data[i:i + 2], "big")
            i += 2 + ext
            pl, i = _len3(data, i)
            i += pl
            ch = int.from_bytes(data[i:i + 2], "big")
            i += 2 + ch
        else:
            break
        out.append((ts, san_names(cert)))
    return out


def tile_path(idx):
    s = str(idx)
    s = s.rjust(((len(s) + 2) // 3) * 3, "0")
    g = [s[j:j + 3] for j in range(0, len(s), 3)]
    return "/".join(["x" + x for x in g[:-1]] + [g[-1]])


LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _norm(s):
    return s.lower().translate(LEET).replace("-", "").replace("_", "")


def _lev1(a, b):
    """Расстояние Левенштейна ≤ 1."""
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) <= 1
    if len(a) > len(b):
        a, b = b, a
    i = j = d = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            d += 1
            if d > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True


def ct_match(domain, keywords, allow):
    d = domain.lstrip("*.").lower()
    for a in allow:
        if d == a or d.endswith("." + a):
            return None
    nd = _norm(d)
    labels = [_norm(x) for x in re.split(r"[.\-]", d) if x]
    for k in keywords:
        nk = _norm(k)
        if not nk:
            continue
        if nk in nd:
            return k
        if len(nk) >= 5 and any(_lev1(nk, lab) for lab in labels):
            return k
    return None


class CTStream:
    """Живое чтение хвоста CT-логов Let's Encrypt (static-ct-api): новые сертификаты каждые ~10 секунд."""

    def __init__(self):
        self.lock = threading.Lock()
        self.thread = None
        self.running = False
        self.logs = []
        self.next = {}
        self.stats = {"certs": 0, "names": 0, "tiles": 0, "skipped": 0, "bytes": 0, "started": 0, "errors": 0,
                      "last_error": "", "rate": 0.0}
        self.feed = collections.deque(maxlen=60)
        self.matches = collections.deque(maxlen=300)
        self.cfg = {"keywords": [], "allow": [], "background": False}
        self.notify = None
        self._rate = collections.deque(maxlen=30)

    # --- настройки и найденное
    def path(self):
        return os.path.join(P.DATA_DIR, "ctwatch.json")

    def load(self):
        try:
            with open(self.path(), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        self.cfg.update({k: d.get(k, v) for k, v in self.cfg.items()})
        self.matches.clear()
        self.matches.extend(d.get("matches") or [])

    def save(self):
        os.makedirs(P.DATA_DIR, exist_ok=True)
        with open(self.path(), "w", encoding="utf-8") as f:
            json.dump({**self.cfg, "matches": list(self.matches)}, f, ensure_ascii=False)

    def configure(self, keywords=None, allow=None, background=None):
        clean = lambda xs: [x for x in dict.fromkeys(str(x).strip().lower() for x in xs or []) if 2 <= len(x) <= 60][:50]   # noqa: E731
        if keywords is not None:
            self.cfg["keywords"] = clean(keywords)
        if allow is not None:
            self.cfg["allow"] = clean(allow)
        if background is not None:
            self.cfg["background"] = bool(background)
        self.save()

    # --- логи
    def discover(self):
        try:
            j = T._get_json(LOG_LIST_URL, timeout=30)
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            logs = []
            for op in j.get("operators") or []:
                if "let's encrypt" not in op.get("name", "").lower():
                    continue
                for lg in op.get("tiled_logs") or []:
                    ti = lg.get("temporal_interval") or {}
                    if "usable" in (lg.get("state") or {}) and ti.get("start_inclusive", "") <= now < ti.get("end_exclusive", "9"):
                        logs.append(lg["monitoring_url"].rstrip("/") + "/")
            return logs or FALLBACK_LOGS
        except Exception:
            return FALLBACK_LOGS

    def _get(self, url, timeout=30):
        req = T.urllib.request.Request(url, headers={"User-Agent": T.USER_AGENT if hasattr(T, "USER_AGENT") else "Provenio",
                                                       "Accept-Encoding": "gzip"})
        with T._open(req, timeout) as r:
            raw = r.read()
        self.stats["bytes"] += len(raw)
        return gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw

    def size(self, log):
        return int(self._get(log + "checkpoint", 15).decode().split("\n")[1])

    # --- цикл
    def start(self):
        with self.lock:
            if self.running:
                return
            self.running = True
            self.stats.update({"started": time.time(), "certs": 0, "names": 0, "tiles": 0, "skipped": 0, "bytes": 0})
            self.thread = threading.Thread(target=self.loop, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False

    def loop(self):
        self.logs = self.discover()
        self.next = {}
        while self.running:
            t0 = time.time()
            for log in self.logs:
                if not self.running:
                    break
                try:
                    full = self.size(log) // 256
                    nx = self.next.get(log)
                    if nx is None or full - nx > 30:      # после сна/обрыва — прыгаем к хвосту
                        if nx is not None:
                            self.stats["skipped"] += (full - 1 - nx) * 256
                        nx = full - 1
                    for _ in range(4):
                        if nx >= full or not self.running:
                            break
                        self.ingest(log, self._get(log + "tile/data/" + tile_path(nx)))
                        nx += 1
                    self.next[log] = nx
                except Exception as e:
                    self.stats["errors"] += 1
                    self.stats["last_error"] = f"{type(e).__name__}: {str(e)[:120]}"
            time.sleep(max(2.0, 10 - (time.time() - t0)))

    def ingest(self, log, tile):
        entries = parse_data_tile(tile)
        kw, allow = self.cfg["keywords"], self.cfg["allow"]
        now = time.time()
        self.stats["tiles"] += 1
        self.stats["certs"] += len(entries)
        self._rate.append((now, len(entries)))
        if len(self._rate) > 1:
            span = now - self._rate[0][0]
            self.stats["rate"] = round(sum(n for _, n in list(self._rate)[1:]) / span, 1) if span else 0.0
        found = False
        for k, (ts, names) in enumerate(entries):
            self.stats["names"] += len(names)
            if names and k % 16 == 0:
                self.feed.append({"t": ts, "d": names[0], "n": len(names)})
            if not kw:
                continue
            hit = [(d, ct_match(d, kw, allow)) for d in names]
            hit = [(d, k2) for d, k2 in hit if k2]
            if hit:
                rec = {"ts": ts, "time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts / 1000)) + " UTC",
                       "keyword": hit[0][1], "domains": sorted({d for d, _ in hit})[:10], "all": names[:20],
                       "log": log.split("//")[1].split("/")[0]}
                if not any(m["domains"] == rec["domains"] for m in list(self.matches)[-50:]):
                    self.matches.append(rec)
                    found = True
                    if self.notify:
                        try:
                            self.notify(f"CT: новый сертификат для «{', '.join(rec['domains'][:3])}» (ключ «{rec['keyword']}»)")
                        except Exception:
                            pass
        if found:
            self.save()

    def status(self):
        up = time.time() - self.stats["started"] if self.running and self.stats["started"] else 0
        return {"running": self.running, "logs": self.logs or FALLBACK_LOGS, "stats": dict(self.stats), "uptime": round(up),
                "mb_per_hour": round(self.stats["bytes"] / up * 3600 / 1e6, 1) if up > 30 else None,
                "feed": list(self.feed)[-40:], "matches": list(self.matches)[-100:][::-1], "cfg": dict(self.cfg),
                "est_mb_per_hour": BYTES_PER_HOUR_EST // 1_000_000}


CT = CTStream()


# ======================================================================= наблюдение за вымогателями
class RansomWatch:
    def __init__(self):
        self.cfg = {"keywords": [], "seen": {}, "last": 0}
        self.notify = None
        self.busy = False

    def path(self):
        return os.path.join(P.DATA_DIR, "ransomwatch.json")

    def load(self):
        try:
            with open(self.path(), encoding="utf-8") as f:
                self.cfg.update(json.load(f))
        except (OSError, ValueError):
            pass

    def save(self):
        os.makedirs(P.DATA_DIR, exist_ok=True)
        with open(self.path(), "w", encoding="utf-8") as f:
            json.dump(self.cfg, f, ensure_ascii=False)

    def set_keywords(self, kws):
        self.cfg["keywords"] = [k for k in dict.fromkeys(str(k).strip() for k in kws or []) if len(k) >= 3][:10]
        self.save()

    def check(self, force=False):
        """Раз в 6 часов: новые жертвы по ключевым словам → уведомление."""
        if self.busy or not self.cfg["keywords"] or (not force and time.time() - self.cfg.get("last", 0) < 6 * 3600):
            return []
        self.busy = True
        new = []
        try:
            for kw in self.cfg["keywords"]:
                try:
                    items = ransom_search(kw)
                except Exception:
                    continue
                seen = set(self.cfg["seen"].get(kw, []))
                fresh = [i for i in items if f"{i['group']}|{i['victim']}|{i['attackdate']}" not in seen]
                if seen and fresh and self.notify:
                    for i in fresh[:5]:
                        self.notify(f"Вымогатели: «{i['victim']}» на сайте группы {i['group']} (ключ «{kw}»)")
                new += fresh if seen else []
                self.cfg["seen"][kw] = sorted(seen | {f"{i['group']}|{i['victim']}|{i['attackdate']}" for i in items})[-2000:]
            self.cfg["last"] = time.time()
            self.save()
        finally:
            self.busy = False
        return new


RW = RansomWatch()

SEC_TOOLS = {
    "magic": magic_tool,
    "img_forensics": img_forensics,
    "email_headers": email_headers,
    "ransomware": ransomware_tool,
}
T.TOOLS.update(SEC_TOOLS)
