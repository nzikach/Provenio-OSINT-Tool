# -*- coding: utf-8 -*-
"""Офлайн-тесты Provenio (сеть не нужна). Запуск: python -m unittest discover -s tests"""
import base64
import io
import json
import os
import struct
import sys
import sqlite3
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["PROVENIO_DATA"] = tempfile.mkdtemp(prefix="provenio_test_")

import provenio as P            # noqa: E402
import provenio_tools as T      # noqa: E402
import provenio_osint as O      # noqa: E402
import provenio_plus as X       # noqa: E402


def new_store():
    d = tempfile.mkdtemp(prefix="pv_store_")
    return P.Store(os.path.join(d, "t.db"), os.path.join(d, "snaps"))


class CoreTests(unittest.TestCase):
    def test_entities_from_html(self):
        html = """<html><title>T</title><body>mail me: a.b@example.org, +7 (912) 345-67-89, 8.8.8.8
        <a href="https://github.com/someone">gh</a><a href="https://other.net/x">x</a></body></html>"""
        ents, title = P.extract_entities(html, "https://example.com/page")
        self.assertEqual(title, "T")
        for e in [("email", "a.b@example.org"), ("phone", "+79123456789"), ("ip", "8.8.8.8"),
                  ("account", "github:someone"), ("domain", "other.net"), ("domain", "example.com")]:
            self.assertIn(e, ents)

    def test_entities_from_tool_data(self):
        data = {"a": ["93.184.216.34", "sub.example.com", "file.js"], "url": "https://www.shodan.io/x",
                "c": "contact: admin@example.com", "p": "+79123456789", "priv": "10.0.0.1"}
        ents = P.extract_entities_data(data)
        self.assertIn(("ip", "93.184.216.34"), ents)
        self.assertIn(("domain", "sub.example.com"), ents)
        self.assertIn(("email", "admin@example.com"), ents)
        self.assertIn(("phone", "+79123456789"), ents)
        self.assertNotIn(("domain", "file.js"), ents)
        self.assertNotIn(("ip", "10.0.0.1"), ents)
        self.assertFalse(any(v == "shodan.io" for _, v in ents))

    def test_confidence(self):
        one = [{"url": "https://a.com", "final_url": "", "reliability": 3}]
        two = one + [{"url": "https://b.com", "final_url": "", "reliability": 5}]
        self.assertLess(P.confidence(one), P.confidence(two))
        self.assertEqual(P.confidence(one), P.confidence(one * 3))   # один домен — один голос

    def test_audit_chain_detects_tampering(self):
        s = new_store()
        s.add_case("c1")
        s.audit("x", "y")
        self.assertTrue(s.verify_audit()[0])
        s.db.execute("UPDATE audit SET detail=? WHERE action=?", ("подмена", "x"))
        self.assertFalse(s.verify_audit()[0])

    def test_tool_result_evidence_and_verify(self):
        s = new_store()
        cid = s.add_case("кейс")
        sid, n = s.add_tool_result(cid, "dns", "example.com",
                                   {"records": {"A": ["93.184.216.34"]}, "created": "2020-01-02T03:04:05Z"},
                                   pivot=("domain", "example.com"))
        self.assertGreaterEqual(n, 2)
        self.assertEqual(s.source(sid)["kind"], "tool")
        self.assertEqual(s.verify_snapshots(cid), (1, []))
        tl = s.timeline(cid)
        self.assertTrue(any(e["date"].startswith("2020-01-02") for e in tl))
        data, mh = P.build_evidence_zip(s, s.case(cid))
        r = P.verify_evidence_zip(data)
        self.assertEqual(r["verdict"], "целостность подтверждена")
        # подменяем снимок внутри архива -> нарушение
        zin = zipfile.ZipFile(io.BytesIO(data))
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            for n_ in zin.namelist():
                b = zin.read(n_)
                if n_.startswith("snapshots/"):
                    b = b.replace(b"93.184.216.34", b"1.2.3.4")
                z.writestr(n_, b)
        self.assertEqual(P.verify_evidence_zip(out.getvalue())["verdict"], "ОБНАРУЖЕНЫ НАРУШЕНИЯ")

    def test_delete_source_cleans_orphans(self):
        s = new_store()
        cid = s.add_case("c")
        sid, _ = s.add_tool_result(cid, "x", "q", {"e": "only@here.com"})
        self.assertEqual(len(s.entities(cid)), 1)
        s.delete_source(sid)
        self.assertEqual(len(s.entities(cid)), 0)

    def test_diff(self):
        d = P.diff_lines(["a", "b", "c"], ["a", "x", "c"])
        self.assertEqual((d["added"], d["removed"]), (1, 1))

    def test_parse_date(self):
        self.assertEqual(P.parse_date("2021-03-04T05:06:07Z"), "2021-03-04 05:06")
        self.assertEqual(P.parse_date("20200101120000"), "2020-01-01 12:00")
        self.assertEqual(P.parse_date("Jan  5 12:00:00 2025 GMT"), "2025-01-05 12:00")
        self.assertIsNone(P.parse_date("не дата"))

    def test_versions_match(self):
        """Версия в exe (свойства файла), приложении для iPhone и в коде — одна."""
        vi = open(os.path.join(ROOT, "assets", "version_info.txt"), encoding="utf-8").read()
        self.assertIn(f"'{P.APP_VERSION}'", vi)
        self.assertIn("(" + ", ".join(P.APP_VERSION.split(".")) + ", 0)", vi)
        self.assertIn(f'version = "{P.APP_VERSION}"', open(os.path.join(ROOT, "ios", "pyproject.toml"), encoding="utf-8").read())

    def test_settings_roundtrip(self):
        P.save_settings({"proxy": "http://127.0.0.1:8080", "keys": {"shodan": "secret123"}})
        s = P.load_settings()
        self.assertEqual(s["keys"]["shodan"], "secret123")
        raw = open(P.SETTINGS_PATH, encoding="utf-8").read()
        if os.name == "nt":
            self.assertNotIn("secret123", raw)   # на Windows ключи зашифрованы DPAPI
        T.configure(P.save_settings({"proxy": "", "keys": {}}))


class ToolTests(unittest.TestCase):
    def test_permutations(self):
        p = O.domain_permutations("example.com")
        self.assertIn("exmple.com", p)
        self.assertIn("example.net", p)
        self.assertIn("examp1e.com", p)
        self.assertNotIn("example.com", p)

    def test_ioc_extract_refang(self):
        r = O.ioc_extract("hxxp://evil[.]com/a 1.2.3.4 CVE-2021-44228 "
                          "d41d8cd98f00b204e9800998ecf8427e x[@]evil[.]com")
        i = r["iocs"]
        self.assertIn("http://evil.com/a", i["url"])
        self.assertIn("1.2.3.4", i["ipv4"])
        self.assertIn("CVE-2021-44228", i["cve"])
        self.assertIn("x@evil.com", i["email"])
        self.assertEqual(O.ioc_extract("a.com", "defang")["result"], "a[.]com")

    def test_secret_scan_masks(self):
        r = O.scan_text("key = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab'\nAKIAIOSFODNN7EXAMPLE")
        types = {f["type"] for f in r}
        self.assertIn("GitHub Token", types)
        self.assertIn("AWS Access Key ID", types)
        self.assertTrue(all("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ" not in f["value"] for f in r))

    def test_exif_gps(self):
        # минимальный TIFF/EXIF с GPS-блоком: 55°45'0"N 37°37'0"E
        def rat(n, d=1):
            return struct.pack("<II", n, d)
        entries_gps = [(1, 2, 2, b"N\0\0\0"), (2, 5, 3, None), (3, 2, 2, b"E\0\0\0"), (4, 5, 3, None)]
        base = 8
        ifd0 = struct.pack("<H", 1) + struct.pack("<HHII", 0x8825, 4, 1, base + 2 + 12 + 4) + struct.pack("<I", 0)
        gps_off = base + len(ifd0)
        data_off = gps_off + 2 + 12 * len(entries_gps) + 4
        gps, blob = struct.pack("<H", len(entries_gps)), b""
        for tag, typ, cnt, val in entries_gps:
            if val is None:
                vals = rat(55) + rat(45) + rat(0) if tag == 2 else rat(37) + rat(37) + rat(0)
                gps += struct.pack("<HHII", tag, typ, cnt, data_off + len(blob))
                blob += vals
            else:
                gps += struct.pack("<HHI", tag, typ, cnt) + val
        gps += struct.pack("<I", 0)
        tiff = b"II*\0" + struct.pack("<I", 8) + ifd0 + gps + blob
        meta = O.parse_tiff(tiff)
        g = O._gps(meta)
        self.assertAlmostEqual(g["lat"], 55.75, places=3)
        self.assertAlmostEqual(g["lon"], 37.616667, places=3)
        r = O.file_meta({"file": base64.b64encode(tiff).decode(), "filename": "x.tif"})
        self.assertEqual(r["type"], "TIFF / RAW")
        self.assertIsNotNone(r["gps"])

    def test_office_meta(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("docProps/core.xml", "<cp:coreProperties><dc:creator>Иван</dc:creator>"
                                            "<cp:lastModifiedBy>Пётр</cp:lastModifiedBy></cp:coreProperties>")
            z.writestr("word/document.xml", "<w:document/>")
        r = O.file_meta({"file": base64.b64encode(buf.getvalue()).decode(), "filename": "a.docx"})
        self.assertEqual(r["metadata"]["creator"], "Иван")
        self.assertIn("creator", r["sensitive_fields"])

    def test_job_cancel(self):
        j = T.Job()
        j.cancelled = True
        with self.assertRaises(T.Cancelled):
            T.pmap(lambda x: x, range(5), j)

    def test_sites_loaded(self):
        self.assertGreater(len(T.load_sites()), 400)

    def test_all_tools_registered(self):
        for name in ("harvester", "lookalikes", "crawl", "secrets", "file_meta", "reputation", "tracking",
                     "domain_history", "evidence_verify", "username", "dns"):
            self.assertIn(name, T.TOOLS)


class PlusTests(unittest.TestCase):
    def test_keccak512_vector(self):
        # оригинальный Keccak-512 отличается от SHA3-512 дополнением
        self.assertTrue(X.keccak512(b"").startswith("0eab42de4c3ceb9235fc91acffe746b2"))
        self.assertNotEqual(X.keccak512(b"abc"), __import__("hashlib").sha3_512(b"abc").hexdigest())

    def test_rfc3161_request_and_parse(self):
        import hashlib
        d = hashlib.sha256(b"manifest").digest()
        req = P.rfc3161_request(d, 12345)
        self.assertEqual(req[0], 0x30)
        self.assertIn(d, req)
        tst = P._der(0x30, P._der_int(1) + P._der(0x06, b"\x2a\x03") +
                     P._der(0x30, P._der(0x30, P.SHA256_OID + b"\x05\x00") + P._der(0x04, d)) +
                     P._der_int(777) + P._der(0x18, b"20261124101112Z"))
        token = P._der(0x30, P._der(0x06, b"\x2a\x03") + P._der(0xA0, P._der(0x04, tst)))
        info = P.rfc3161_parse_token(token)
        self.assertEqual(info["imprint"], d.hex())
        self.assertEqual(info["gen_time"], "2026-11-24 10:11:12 UTC")

    def test_intersections_dossier_attachments(self):
        s = new_store()
        a, b = s.add_case("A"), s.add_case("B")
        sa, _ = s.add_tool_result(a, "x", "q", {"m": "shared@corp.com", "ip": "93.184.216.34"})
        s.add_tool_result(b, "x", "q", {"m": "shared@corp.com"})
        inter = s.intersections(a)
        self.assertEqual([x["value"] for x in inter], ["shared@corp.com"])
        eid = next(e["id"] for e in s.entities(a) if e["value"] == "shared@corp.com")
        d = s.dossier(a, eid)
        self.assertEqual(d["other_cases"][0]["name"], "B")
        self.assertTrue(any(r["value"] == "93.184.216.34" for r in d["related"]))
        self.assertTrue(d["context"])
        s.add_attachment(sa, "screenshot", b"\x89PNG fake", "png")
        self.assertEqual(s.verify_snapshots(a)[1], [])
        data, _ = P.build_evidence_zip(s, s.case(a))
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        self.assertTrue(any(n.endswith(".png") for n in names))
        self.assertEqual(P.verify_evidence_zip(data)["verdict"], "целостность подтверждена")

    def test_graph_exports(self):
        import xml.dom.minidom
        s = new_store()
        cid = s.add_case("g")
        s.add_tool_result(cid, "x", "q", {"m": "a@b.com"})
        c = s.case(cid)
        xml.dom.minidom.parseString(X.graph_gexf(s, c))
        xml.dom.minidom.parseString(X.graph_graphml(s, c))
        self.assertIn("maltego.EmailAddress", X.graph_edges_csv(s, c).decode("utf-8-sig"))

    def test_import_sherlock_spiderfoot(self):
        r = X.import_file({"q": "https://github.com/jd\nhttps://www.reddit.com/user/jd\n"
                                "Total Websites Username Detected On : 2", "filename": "jd.txt"})
        self.assertEqual((r["format"], r["count"]), ("Sherlock TXT", 2))
        sf = "Scan Name,Updated,Type,Module,Source,F/P,Data\nx,1,EMAILADDR,sfp,s,0,admin@ex.com\n"
        r = X.import_file({"file": base64.b64encode(sf.encode()).decode(), "filename": "sf.csv"})
        self.assertEqual(r["format"], "SpiderFoot")
        self.assertIn(("email", "admin@ex.com"), P.extract_entities_data(r))

    def test_feed_parsing(self):
        ips, nets = X._parse_feed("ip", b"# c\n1.2.3.4\n5.6.7.8 ; note\n")
        self.assertEqual(len(ips), 2)
        ips, nets = X._parse_feed("cidr", b"10.0.0.0/8 ; SBL1\n")
        import ipaddress
        self.assertTrue(X._in_feed(int(ipaddress.ip_address("10.1.2.3")), (ips, nets)))
        ips, nets = X._parse_feed("json:prefixes.ip_prefix", b'{"prefixes":[{"ip_prefix":"3.0.0.0/15"}]}')
        self.assertEqual(len(nets), 1)

    def test_phishing_helpers(self):
        self.assertEqual(X._lev("paypa1", "paypal"), 1)
        self.assertEqual(X._reg_domain("login.secure.example.co.uk"), "example.co.uk")
        self.assertEqual(len(X.playbook_steps("email", "a@b.com")), 6)
        self.assertEqual(X.playbook_steps("email", "a@b.com")[3], ("whois", "b.com"))

    def test_new_tools_registered(self):
        for t in ("phishing", "ip_radar", "leaks", "capture", "import_file", "tsa"):
            self.assertIn(t, T.TOOLS)


class SQLInjectionTests(unittest.TestCase):
    PAYLOADS = ["x'); DROP TABLE cases;--", "' OR '1'='1", "1 UNION SELECT name, sql FROM sqlite_master--",
                "'; ATTACH DATABASE 'evil.db' AS e;--", "1; SELECT load_extension('x')", "\" OR \"\"=\"",
                "admin'/*", "1 AND (SELECT 1 FROM (SELECT SLEEP(5)))", "%' AND 1=1 AND '%'='"]

    def test_payloads_stored_as_plain_data(self):
        s = new_store()
        for p in self.PAYLOADS:
            cid = s.add_case(p)
            self.assertEqual(s.case(cid)["name"], p)          # сохранено буквально, не выполнено
            s.add_tool_result(cid, "ioc", p, {"text": p, "iocs": {"domain": ["evil.com"]}})
        self.assertTrue(set(self.PAYLOADS) <= {c["name"] for c in s.cases()})
        self.assertTrue(s.verify_audit()[0])                  # таблицы на месте, журнал цел

    def test_guard_rejects_unsafe_sql(self):
        s = new_store()
        bad = ["SELECT * FROM cases WHERE name='x'",            # строковый литерал
               "SELECT * FROM cases WHERE id=1; DROP TABLE cases",   # stacked query
               "SELECT * FROM cases -- comment", "SELECT /* c */ 1",
               "ATTACH DATABASE ? AS e", "PRAGMA writable_schema=1",
               'SELECT * FROM cases WHERE name="x"']
        for q in bad:
            with self.assertRaises(sqlite3.Error, msg=q):
                s.db.execute(q, ("x",) if "?" in q else ())
        with self.assertRaises(P.SQLInjectionError):      # число параметров не совпадает
            s.db.execute("SELECT * FROM cases WHERE id=?", ())
        with self.assertRaises(P.SQLInjectionError):      # подмена типа параметра
            s.db.execute("SELECT * FROM cases WHERE id=?", ([1],))
        with self.assertRaises(sqlite3.Error):            # авторизатор SQLite: DROP запрещён
            s.db.execute("DROP TABLE cases")
        with self.assertRaises(sqlite3.Error):
            s.db.execute("SELECT load_extension(?)", ("evil",))
        with self.assertRaises(sqlite3.Error):
            s.db.executescript("DELETE FROM cases")
        self.assertIsInstance(s.cases(), list)              # база цела

    def test_ui_ids_must_be_integers(self):
        import provenio_ui as U
        for bad in ("1 OR 1=1", "1;DROP TABLE cases", "' OR ''='"):
            with self.assertRaises(ValueError):
                U.api("state", {"case": [bad]}, {})


class AuthTests(unittest.TestCase):
    def acc(self):
        import provenio_auth as A
        return A, A.Accounts(os.path.join(tempfile.mkdtemp(prefix="pv_acc_"), "account.json"))

    def test_register_login_and_hash(self):
        A, acc = self.acc()
        self.assertFalse(acc.exists())
        acc.register("analyst_1", "Str0ng-pass!", "Str0ng-pass!", "1990-05-01", True, True)
        raw = open(acc.path, encoding="utf-8").read()
        self.assertNotIn("Str0ng-pass!", raw)          # пароль не хранится
        self.assertNotIn("1990", raw)                  # дата рождения не хранится
        self.assertIn("scrypt", raw)
        self.assertEqual(acc.login("ANALYST_1", "Str0ng-pass!")["username"], "analyst_1")
        with self.assertRaises(A.AuthError):
            acc.login("analyst_1", "wrong-password")
        with self.assertRaises(A.AuthError):         # второй аккаунт в той же папке не создаётся
            acc.register("other", "Str0ng-pass!", "Str0ng-pass!", "1990-05-01", True, True)

    def test_registration_rules(self):
        import datetime as dt
        A, acc = self.acc()
        young = (dt.date.today() - dt.timedelta(days=365 * 17)).isoformat()
        cases = [("ab", "Str0ng-pass!", "Str0ng-pass!", "1990-01-01", True, True),        # короткое имя
                 ("x' OR 1=1", "Str0ng-pass!", "Str0ng-pass!", "1990-01-01", True, True), # недопустимые символы
                 ("user1", "short", "short", "1990-01-01", True, True),                   # слабый пароль
                 ("user1", "password1", "password1", "1990-01-01", True, True),           # из словаря
                 ("user1", "Str0ng-pass!", "Other-pass!", "1990-01-01", True, True),      # не совпадают
                 ("user1", "Str0ng-pass!", "Str0ng-pass!", young, True, True),            # младше 18
                 ("user1", "Str0ng-pass!", "Str0ng-pass!", "", True, True),               # нет даты
                 ("user1", "Str0ng-pass!", "Str0ng-pass!", "1990-01-01", False, True),    # не принял условия
                 ("user1", "Str0ng-pass!", "Str0ng-pass!", "1990-01-01", True, "yes")]    # согласие только явное
        for c in cases:
            with self.assertRaises(A.AuthError, msg=str(c)):
                acc.register(*c)
        self.assertFalse(acc.exists())
        self.assertEqual(A.age_on("2000-06-15", dt.date(2018, 6, 14)), 17)
        self.assertEqual(A.age_on("2000-06-15", dt.date(2018, 6, 15)), 18)

    def test_lockout_and_password_change(self):
        A, acc = self.acc()
        acc.register("user1", "Str0ng-pass!", "Str0ng-pass!", "1990-01-01", True, True)
        for _ in range(5):
            with self.assertRaises(A.AuthError):
                acc.login("user1", "bad")
        with self.assertRaises(A.AuthError) as e:      # заблокировано даже с верным паролем
            acc.login("user1", "Str0ng-pass!")
        self.assertIn("Подождите", str(e.exception))
        acc.locked_until = 0
        acc.change_password("Str0ng-pass!", "N3w-secret-pw", "N3w-secret-pw")
        self.assertTrue(acc.login("user1", "N3w-secret-pw"))

    def test_wipe_data_dir(self):
        import provenio_auth as A
        d = tempfile.mkdtemp(prefix="pv_wipe_")
        os.makedirs(os.path.join(d, "snapshots"))
        for f in ("provenio.db", "settings.json", "account.json", "portable.txt", os.path.join("snapshots", "a.html")):
            open(os.path.join(d, f), "w").close()
        self.assertEqual(A.wipe_data_dir(d), [])
        self.assertEqual(os.listdir(d), ["portable.txt"])

    def test_redact_hides_keys(self):
        T.configure({"keys": {"shodan": "SECRETKEY123456"}})
        try:
            self.assertNotIn("SECRETKEY123456", T.redact("HTTPError https://api.shodan.io/x?key=SECRETKEY123456"))
        finally:
            T.configure({"keys": {}})


class UITests(unittest.TestCase):
    def test_page_and_api(self):
        import threading
        import urllib.request
        from http.server import ThreadingHTTPServer
        import provenio_ui as U
        srv = ThreadingHTTPServer(("127.0.0.1", 0), U.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # мимо системного прокси
        try:
            page = direct.open(base + "/").read().decode()
            self.assertIn(U.TOKEN, page)
            with self.assertRaises(urllib.error.HTTPError):
                direct.open(base + "/api/cases")             # без токена — 403

            tok = {"t": U.TOKEN}

            def call(path, body=None):
                req = urllib.request.Request(base + "/api/" + path, headers={"X-Token": tok["t"],
                                             "Content-Type": "application/json"},
                                             data=json.dumps(body).encode() if body is not None else None)
                return json.loads(direct.open(req).read())
            # до входа токен страницы открывает только вход, регистрацию и документы
            with self.assertRaises(urllib.error.HTTPError) as e:
                call("cases")
            self.assertEqual(e.exception.code, 401)
            self.assertIn("Условия", call("legal?doc=terms")["text"])
            self.assertFalse(call("auth/status")["exists"])
            reg = call("auth/register", {"username": "tester", "password": "Str0ng-pass!", "password2": "Str0ng-pass!",
                                         "birth": "1990-01-01", "accept_terms": True, "accept_privacy": True})
            tok["t"] = reg["token"]
            self.assertNotEqual(reg["token"], U.TOKEN)
            cid = call("case", {"name": "ui-test"})["id"]
            jid = call("job", {"name": "ioc", "q": "1.2.3.4 evil[.]com"})["id"]
            import time
            for _ in range(50):
                st = call("job_status?id=" + jid)
                if st["state"] != "running":
                    break
                time.sleep(0.1)
            self.assertEqual(st["state"], "done")
            saved = call("job_save", {"id": jid, "case": cid})
            self.assertGreaterEqual(saved["entities"], 2)
            state = call("state?case=" + str(cid))
            self.assertEqual(state["sources"][0]["kind"], "tool")
            self.assertIn("att", state["sources"][0])
            self.assertEqual(len(call("playbooks")), len(X.PLAYBOOKS))
            self.assertIsInstance(call("intersections"), list)
            for tab in ("p-globe", "p-radar", "p-leaks"):
                self.assertIn(tab, page)
            world = direct.open(urllib.request.Request(base + "/static/world.json",
                                                       headers={"X-Token": tok["t"]})).read()
            self.assertIn(b"Topology", world)
            for doc in ("privacy", "refund", "thirdparty"):
                self.assertTrue(call("legal?doc=" + doc)["text"])
            # выход: старый токен сеанса больше не работает
            call("auth/logout", {})
            with self.assertRaises(urllib.error.HTTPError):
                call("cases")
            tok["t"] = U.TOKEN
            with self.assertRaises(urllib.error.HTTPError):
                call("auth/login", {"username": "tester", "password": "nope"})
            tok["t"] = call("auth/login", {"username": "tester", "password": "Str0ng-pass!"})["token"]
            self.assertIn("ui-test", [c["name"] for c in call("cases")])
            # удаление аккаунта: нужен пароль и слово УДАЛИТЬ, после — пусто
            with self.assertRaises(urllib.error.HTTPError):
                call("auth/delete", {"password": "Str0ng-pass!", "confirm": "нет"})
            self.assertTrue(call("auth/delete", {"password": "Str0ng-pass!", "confirm": "УДАЛИТЬ"})["deleted"])
            tok["t"] = U.TOKEN
            self.assertFalse(call("auth/status")["exists"])
            self.assertFalse(os.path.exists(os.path.join(P.DATA_DIR, "provenio.db")) and U.S.cases())
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
