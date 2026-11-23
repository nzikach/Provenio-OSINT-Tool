#!/usr/bin/env python3
"""Генерирует assets/provenio.ico (фиолетовый градиент + ромб ◈) без сторонних библиотек.
Запуск: python assets/make_icon.py"""
import math
import os
import struct
import zlib


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
            t = (x + y) / (2 * size)                   # диагональный градиент #8b5cf6 -> #e879f9
            r = int(0x8b + (0xe8 - 0x8b) * t)
            g = int(0x5c + (0x79 - 0x5c) * t)
            b = int(0xf6 + (0xf9 - 0xf6) * t)
            # ромб: внешний контур и внутренний ромб (◈)
            u, v = abs(x + .5 - size / 2), abs(y + .5 - size / 2)
            m = (u + v) / (size / 2)
            ring = 0.52 < m < 0.66
            core = m < 0.30
            if ring or core:
                r, g, b = 255, 255, 255
            row += bytes([r, g, b, int(255 * a)])
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
