#!/usr/bin/env python3
"""Генерирует assets/provenio.ico и provenio.png: белый скруглённый квадрат с чёрной буквой P, без сторонних библиотек.
Запуск: python assets/make_icon.py"""
import math
import os
import struct
import zlib


def mark(u, v):
    """Буква P знака Provenio в координатах 0..1: ствол и чаша."""
    if 0.31 <= u <= 0.43 and 0.22 <= v <= 0.78:
        return True
    outer = (0.31 <= u <= 0.52 and 0.22 <= v <= 0.60) or (u >= 0.52 and (u - 0.52) ** 2 + (v - 0.41) ** 2 <= 0.19 ** 2)
    hole = (0.43 <= u <= 0.52 and 0.33 <= v <= 0.49) or (u >= 0.52 and (u - 0.52) ** 2 + (v - 0.41) ** 2 <= 0.08 ** 2)
    return outer and not hole


def ink(x, y, size):
    """Доля пикселя, покрытая буквой (сглаживание по 4 или 16 точкам)."""
    n = 2 if size > 256 else 4
    hit = sum(mark((x + (i + .5) / n) / size, (y + (j + .5) / n) / size) for i in range(n) for j in range(n))
    return hit / (n * n)


def png(size):
    rows = []
    r_corner = size * 0.22
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            # скруглённый квадрат: расстояние до ближайшего угла
            cx = min(max(x + .5, r_corner), size - r_corner)
            cy = min(max(y + .5, r_corner), size - r_corner)
            d = math.hypot(x + .5 - cx, y + .5 - cy)
            a = max(0.0, min(1.0, r_corner - d + .5))
            k = ink(x, y, size)                          # белый #f2f2f2 -> чёрный #0a0a0a
            c = int(0xf2 + (0x0a - 0xf2) * k)
            row += bytes([c, c, c, int(255 * a)])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(t, data):
        return struct.pack(">I", len(data)) + t + data + struct.pack(">I", zlib.crc32(t + data) & 0xffffffff)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico(path, sizes=(16, 24, 32, 48, 64, 128, 256)):
    images = [png(s) for s in sizes]
    head = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries, blobs = b"", b""
    for s, img in zip(sizes, images):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(img), offset + len(blobs))
        blobs += img
    with open(path, "wb") as f:
        f.write(head + entries + blobs)


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    ico(os.path.join(here, "provenio.ico"))
    with open(os.path.join(here, "provenio.png"), "wb") as f:
        f.write(png(256))
    print("ok")
