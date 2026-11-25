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
           "provenio_auth.py", "provenio_labs.py", "provenio_sec.py", "provenio_unique.py", "provenio_sites.json"]


def copy_sources():
    for m in MODULES:
        shutil.copy2(os.path.join(ROOT, m), os.path.join(APP, m))
    os.makedirs(os.path.join(APP, "assets"), exist_ok=True)
    shutil.copy2(os.path.join(ROOT, "assets", "world-110m.json"), os.path.join(APP, "assets", "world-110m.json"))
    shutil.copytree(os.path.join(ROOT, "legal"), os.path.join(APP, "legal"), dirs_exist_ok=True)


def png(size):
    """Квадратная непрозрачная иконка (углы скругляет сама iOS): градиент + ромб ◈."""
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            t = (x + y) / (2 * size)
            r = int(0x8b + (0xe8 - 0x8b) * t)
            g = int(0x5c + (0x79 - 0x5c) * t)
            b = int(0xf6 + (0xf9 - 0xf6) * t)
            u, v = abs(x + .5 - size / 2), abs(y + .5 - size / 2)
            m = (u + v) / (size / 2)
            if 0.40 < m < 0.51 or m < 0.23:
                r, g, b = 255, 255, 255
            row += bytes([r, g, b])
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
