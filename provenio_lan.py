# -*- coding: utf-8 -*-
"""
Provenio 2.6 — «Открыть на телефоне»: интерфейс Provenio в Safari/Chrome телефона через домашнюю сеть.

Безопасность:
  * режим включается вручную и выключается одной кнопкой;
  * отвечает только устройствам из локальной сети (192.168.x.x, 10.x.x.x, 172.16–31.x.x, fe80::/fc00::);
  * без ключа из QR-кода страница не открывается (ключ можно сменить — старые ссылки перестанут работать);
  * после ключа всё равно нужен вход по паролю аккаунта Provenio.
QR-код генерируется локально (свой кодировщик, стандарт ISO/IEC 18004, байтовый режим, уровень коррекции M).
"""
import ipaddress
import socket

# ======================================================================= QR-код
_EXP, _LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gmul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rs_gen(n):
    g = [1]
    for i in range(n):
        g = [a ^ b for a, b in zip(g + [0], [0] + [_gmul(c, _EXP[i]) for c in g])]
    return g


def _rs_ecc(data, n):
    gen = _rs_gen(n)
    rem = list(data) + [0] * n
    for i in range(len(data)):
        c = rem[i]
        if c:
            for j in range(1, len(gen)):
                rem[i + j] ^= _gmul(gen[j], c)
    return rem[len(data):]


# уровень M: (EC-кодовых слов на блок, [(число блоков, слов данных в блоке), ...])
_ECC_M = {1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]), 5: (24, [(2, 43)]),
          6: (16, [(4, 27)]), 7: (18, [(4, 31)]), 8: (22, [(2, 38), (2, 39)]), 9: (22, [(3, 36), (2, 37)]),
          10: (26, [(4, 43), (1, 44)])}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42],
          9: [6, 26, 46], 10: [6, 28, 50]}


def _bch(value, poly, bits):
    v = value << bits
    while v.bit_length() > bits:
        v ^= poly << (v.bit_length() - poly.bit_length())
    return (value << bits) | v


def qr_matrix(text, mask=None):
    """Матрица QR-кода (список строк из True/False) для текста в байтовом режиме, уровень M."""
    data = text.encode("utf-8")
    ver = next((v for v in range(1, 11) if 4 + (8 if v < 10 else 16) + 8 * len(data) <= 8 * sum(n * k for n, k in _ECC_M[v][1])), None)
    if ver is None:
        raise ValueError("Слишком длинный текст для QR (версии 1–10)")
    ec_n, groups = _ECC_M[ver]
    cap = sum(n * k for n, k in groups)
    bits = [0, 1, 0, 0] + [int(b) for b in format(len(data), "08b" if ver < 10 else "016b")]
    for byte in data:
        bits += [int(b) for b in format(byte, "08b")]
    bits += [0] * min(4, cap * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = [0xEC, 0x11]
    while len(words) < cap:
        words.append(pad[(len(words) - len(bits) // 8) % 2])
    blocks, pos = [], 0
    for n, k in groups:
        for _ in range(n):
            blocks.append(words[pos:pos + k])
            pos += k
    eccs = [_rs_ecc(b, ec_n) for b in blocks]
    final = []
    for i in range(max(len(b) for b in blocks)):
        final += [b[i] for b in blocks if i < len(b)]
    for i in range(ec_n):
        final += [e[i] for e in eccs]
    size = 17 + 4 * ver
    m = [[None] * size for _ in range(size)]

    def finder(r, c):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = r + dr, c + dc
                if 0 <= rr < size and 0 <= cc < size:
                    m[rr][cc] = (0 <= dr <= 6 and dc in (0, 6)) or (0 <= dc <= 6 and dr in (0, 6)) or (2 <= dr <= 4 and 2 <= dc <= 4)
    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)
    for i in range(8, size - 8):
        m[6][i] = m[i][6] = i % 2 == 0
    al = _ALIGN[ver]
    last = len(al) - 1
    for i, r in enumerate(al):
        for j, c in enumerate(al):
            if (i, j) in ((0, 0), (0, last), (last, 0)):    # углы с поисковыми узорами
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    m[r + dr][c + dc] = max(abs(dr), abs(dc)) != 1
    m[size - 8][8] = True                                   # «тёмный модуль»
    reserved = [[v is not None for v in row] for row in m]
    for i in range(9):                                      # место под формат-информацию
        reserved[8][i] = reserved[i][8] = True
    for i in range(8):
        reserved[8][size - 1 - i] = reserved[size - 1 - i][8] = True
    if ver >= 7:
        for i in range(6):
            for j in range(3):
                reserved[size - 11 + j][i] = reserved[i][size - 11 + j] = True
    stream = [int(b) for w in final for b in format(w, "08b")]
    idx, up, col = 0, True, size - 1
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if up else range(size)
        for r in rows:
            for c in (col, col - 1):
                if not reserved[r][c]:
                    m[r][c] = bool(stream[idx]) if idx < len(stream) else False
                    idx += 1
        up = not up
        col -= 2
    masks = [lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0,
             lambda r, c: (r + c) % 3 == 0, lambda r, c: (r // 2 + c // 3) % 2 == 0,
             lambda r, c: (r * c) % 2 + (r * c) % 3 == 0, lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
             lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0]

    def build(k):
        g = [row[:] for row in m]
        for r in range(size):
            for c in range(size):
                if not reserved[r][c] and masks[k](r, c):
                    g[r][c] = not g[r][c]
        fmt = _bch((0b00 << 3) | k, 0b10100110111, 10) ^ 0b101010000010010
        fb = [(fmt >> i) & 1 for i in range(15)]
        for i in range(6):
            g[i][8] = bool(fb[i])
        g[7][8], g[8][8], g[8][7] = bool(fb[6]), bool(fb[7]), bool(fb[8])
        for i in range(9, 15):
            g[8][14 - i] = bool(fb[i])
        for i in range(8):
            g[8][size - 1 - i] = bool(fb[i])
        for i in range(8, 15):
            g[size - 15 + i][8] = bool(fb[i])
        if ver >= 7:
            vb = _bch(ver, 0b1111100100101, 12)
            for i in range(18):
                bit = bool((vb >> i) & 1)
                g[size - 11 + i % 3][i // 3] = bit
                g[i // 3][size - 11 + i % 3] = bit
        return g

    def penalty(g):
        p = 0
        for lines in (g, list(zip(*g))):
            for line in lines:
                run, prev = 1, line[0]
                for v in line[1:]:
                    if v == prev:
                        run += 1
                    else:
                        p += run - 2 if run >= 5 else 0
                        run, prev = 1, v
                p += run - 2 if run >= 5 else 0
                s = "".join("1" if v else "0" for v in line)
                p += 40 * (s.count("10111010000") + s.count("00001011101"))
        for r in range(size - 1):
            for c in range(size - 1):
                if g[r][c] == g[r + 1][c] == g[r][c + 1] == g[r + 1][c + 1]:
                    p += 3
        dark = sum(v for row in g for v in row) * 100 / (size * size)
        return p + int(abs(dark - 50) / 5) * 10
    if mask is not None:
        return build(mask)
    return min((build(k) for k in range(8)), key=penalty)


def qr_svg(text, scale=6, border=4, dark="#0b0812", light="#ffffff"):
    g = qr_matrix(text)
    n = len(g) + border * 2
    rects = "".join(f'<rect x="{c + border}" y="{r + border}" width="1" height="1"/>'
                    for r, row in enumerate(g) for c, v in enumerate(row) if v)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n * scale}" height="{n * scale}" '
            f'shape-rendering="crispEdges"><rect width="{n}" height="{n}" fill="{light}"/><g fill="{dark}">{rects}</g></svg>')


# ======================================================================= сеть
def lan_ip():
    """IP этого компьютера в локальной сети (без отправки трафика: UDP-сокет только выбирает маршрут)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def is_local_client(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_private or a.is_link_local or a.is_loopback
