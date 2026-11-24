# -*- coding: utf-8 -*-
"""
Provenio — локальная учётная запись.

Аккаунт один на папку данных (то есть на пользователя Windows или на портативную копию).
Ничего не отправляется в сеть: имя и хэш пароля хранятся в account.json рядом с базой.

* Пароль не хранится и не шифруется обратимо: хранится только хэш scrypt (соль 16 байт,
  N=2^15, r=8, p=1). Сравнение — за постоянное время (hmac.compare_digest).
* Дата рождения нужна только для проверки возраста (18+) и не сохраняется — сохраняется факт проверки.
* Перебор паролей замедляется: после 5 неудачных попыток вход блокируется на 30 с, 60 с, 120 с…
* Удаление аккаунта стирает все данные Provenio в этой папке: кейсы, снимки, ключи API, настройки.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import threading
import time

MIN_AGE = 18
TERMS_VERSION = "2026-11-24"
USER_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
COMMON = {"password", "password1", "12345678", "123456789", "1234567890", "qwerty123", "qwertyui",
          "11111111", "00000000", "iloveyou", "admin123", "provenio", "йцукенгш", "пароль123"}


class AuthError(ValueError):
    pass


def hash_password(password, salt=None, params=None):
    params = dict(params or SCRYPT)
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=params["n"], r=params["r"], p=params["p"],
                        maxmem=128 * 1024 * 1024, dklen=32)
    return {"alg": "scrypt", **params, "salt": salt.hex(), "hash": dk.hex()}


def verify_password(password, rec):
    if not rec or rec.get("alg") != "scrypt":
        return False
    calc = hash_password(password, bytes.fromhex(rec["salt"]), rec)
    return hmac.compare_digest(calc["hash"], rec["hash"])


def age_on(birth, today=None):
    """Полных лет на сегодня. birth — 'ГГГГ-ММ-ДД'."""
    try:
        b = dt.date.fromisoformat(str(birth).strip())
    except ValueError:
        raise AuthError("Укажите дату рождения")
    today = today or dt.date.today()
    if b > today or b.year < 1900:
        raise AuthError("Проверьте дату рождения")
    return today.year - b.year - ((today.month, today.day) < (b.month, b.day))


def password_problems(password, username=""):
    p = password or ""
    out = []
    if len(p) < 8:
        out.append("не короче 8 символов")
    if len(p) > 256:
        out.append("не длиннее 256 символов")
    if p.lower() in COMMON or (username and p.lower() == username.lower()):
        out.append("слишком простой или совпадает с именем")
    if p and len(set(p)) < 4:
        out.append("слишком мало разных символов")
    return out


class Accounts:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.fails = 0
        self.locked_until = 0.0

    # --- хранение
    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _save(self, rec):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    def exists(self):
        rec = self._load()
        return bool(rec and rec.get("username") and rec.get("password"))

    def public(self):
        rec = self._load() or {}
        return {"exists": self.exists(), "username": rec.get("username", ""), "created": rec.get("created", ""),
                "terms_version": rec.get("terms_accepted", ""), "current_terms": TERMS_VERSION,
                "min_age": MIN_AGE}

    # --- регистрация
    def register(self, username, password, password2, birth, accept_terms, accept_privacy):
        username = str(username or "").strip()
        with self.lock:
            if self.exists():
                raise AuthError("Аккаунт уже создан — войдите")
            if not USER_RE.match(username):
                raise AuthError("Имя: 3–32 символа, латиница, цифры, точка, дефис или подчёркивание")
            probs = password_problems(password, username)
            if probs:
                raise AuthError("Пароль: " + ", ".join(probs))
            if password != password2:
                raise AuthError("Пароли не совпадают")
            if age_on(birth) < MIN_AGE:
                raise AuthError(f"Provenio доступен только с {MIN_AGE} лет")
            if accept_terms is not True or accept_privacy is not True:
                raise AuthError("Чтобы продолжить, примите Условия использования и Политику конфиденциальности")
            now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            self._save({"v": 1, "username": username, "password": hash_password(password), "created": now,
                        "age_verified": True, "terms_accepted": TERMS_VERSION, "privacy_accepted": TERMS_VERSION,
                        "accepted_at": now})
            return self.public()

    # --- вход
    def login(self, username, password):
        with self.lock:
            wait = self.locked_until - time.time()
            if wait > 0:
                raise AuthError(f"Слишком много попыток. Подождите {int(wait) + 1} с")
            rec = self._load()
            ok = bool(rec) and hmac.compare_digest(str(username or "").strip().lower(),
                                                    str(rec.get("username", "")).lower())
            # хэш считаем всегда — время ответа не выдаёт, верно ли имя
            pw_ok = verify_password(str(password or ""), (rec or {}).get("password") or hash_password("x"))
            if ok and pw_ok:
                self.fails = 0
                return self.public()
            self.fails += 1
            if self.fails >= 5:
                self.locked_until = time.time() + 30 * 2 ** min(self.fails - 5, 6)
            raise AuthError("Неверное имя пользователя или пароль")

    def check_password(self, password):
        rec = self._load()
        if not rec or not verify_password(str(password or ""), rec.get("password")):
            raise AuthError("Неверный пароль")

    def change_password(self, old, new, new2):
        with self.lock:
            rec = self._load()
            if not rec or not verify_password(str(old or ""), rec.get("password")):
                raise AuthError("Текущий пароль неверен")
            probs = password_problems(new, rec.get("username", ""))
            if probs:
                raise AuthError("Пароль: " + ", ".join(probs))
            if new != new2:
                raise AuthError("Пароли не совпадают")
            rec["password"] = hash_password(new)
            self._save(rec)

    def accept_terms(self):
        rec = self._load()
        if rec:
            rec["terms_accepted"] = rec["privacy_accepted"] = TERMS_VERSION
            rec["accepted_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            self._save(rec)


def wipe_data_dir(data_dir, keep=("portable.txt",)):
    """Удаляет всё содержимое папки данных Provenio. Возвращает список того, что не удалось удалить
    (например, файлы, открытые окном приложения)."""
    failed = []
    if not os.path.isdir(data_dir):
        return failed
    for name in os.listdir(data_dir):
        if name in keep:
            continue
        p = os.path.join(data_dir, name)
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=False)
            else:
                os.remove(p)
        except OSError:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)   # что занято (кэш окна) — удалится при следующем запуске
            else:
                try:   # журнал открыт самим приложением: удалить нельзя, но можно очистить
                    open(p, "w").close()
                except OSError:
                    failed.append(name)
    return failed
