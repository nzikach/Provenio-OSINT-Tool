#!/usr/bin/env python3
"""Готовит iOS-проект к сборке Briefcase:
  * копирует ядро Provenio и данные в ios/src/provenio_app/
  * рисует иконки приложения для iOS (ios/icons/provenio-<размер>.png)
Запуск из корня репозитория: python ios/prepare.py"""
import math
import os
import shutil
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "ios", "src", "provenio_app")
ICONS = os.path.join(ROOT, "ios", "icons")

MODULES = ["provenio.py", "provenio_tools.py", "provenio_osint.py", "provenio_plus.py", "provenio_ui.py",
           "provenio_auth.py", "provenio_labs.py", "provenio_sec.py", "provenio_unique.py", "provenio_lan.py", "provenio_sites.json"]


def copy_sources():
    for m in MODULES:
        shutil.copy2(os.path.join(ROOT, m), os.path.join(APP, m))
    os.makedirs(os.path.join(APP, "assets"), exist_ok=True)
    shutil.copy2(os.path.join(ROOT, "assets", "world-110m.json"), os.path.join(APP, "assets", "world-110m.json"))
    shutil.copytree(os.path.join(ROOT, "legal"), os.path.join(APP, "legal"), dirs_exist_ok=True)


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
    """Квадратная непрозрачная иконка (углы скругляет сама iOS): белый фон и чёрная буква P."""
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            c = int(0xf2 + (0x0a - 0xf2) * ink(x, y, size))
            row += bytes([c, c, c])
        rows.append(bytes(row))
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))


def make_icons():
    os.makedirs(ICONS, exist_ok=True)
    cache = {}
    for s in (20, 29, 40, 58, 60, 76, 80, 87, 120, 152, 167, 180, 640, 1024):
        if s not in cache:
            cache[s] = png(s)
        with open(os.path.join(ICONS, f"provenio-{s}.png"), "wb") as f:
            f.write(cache[s])


if __name__ == "__main__":
    copy_sources()
    make_icons()
    print("ios: sources and icons ready")
