# -*- coding: utf-8 -*-
"""Офлайн-тесты Provenio (сеть не нужна). Запуск: python -m unittest discover -s tests"""
import base64
import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["PROVENIO_DATA"] = tempfile.mkdtemp(prefix="provenio_test_")

import provenio as P            # noqa: E402
import provenio_tools as T      # noqa: E402
import provenio_osint as O      # noqa: E402


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
        s.db.execute("UPDATE audit SET detail='подмена' WHERE action='x'")
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

            def call(path, body=None):
                req = urllib.request.Request(base + "/api/" + path, headers={"X-Token": U.TOKEN,
                                             "Content-Type": "application/json"},
                                             data=json.dumps(body).encode() if body is not None else None)
                return json.loads(direct.open(req).read())
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
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
