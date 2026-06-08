"""Smoke tests for IOCEXTRACT. Standard library only, no network."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iocextract import TOOL_NAME, TOOL_VERSION, defang, extract, refang  # noqa: E402
from iocextract.cli import main  # noqa: E402


SAMPLE = (
    "C2 hxxps://bad-host[.]top/gate.php  fallback cdn-sync[.]xyz "
    "ip 185.220.101.47  v6 2001:db8::1  mail evil[at]phish[.]shop "
    "md5 44d88612fea8a8f36de82e1278abb02f "
    "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
    "decoy update.dll  resolver 8.8.8.8"
)


class TestRefangDefang(unittest.TestCase):
    def test_refang_roundtrip_markers(self):
        self.assertEqual(refang("a[.]b"), "a.b")
        self.assertEqual(refang("hxxps://x[.]y"), "https://x.y")
        self.assertEqual(refang("user[at]host[.]com"), "user@host.com")

    def test_defang_url_and_domain(self):
        self.assertEqual(defang("https://a.com/x", "url"), "hxxps://a[.]com/x")
        self.assertEqual(defang("a.com", "domain"), "a[.]com")

    def test_defang_hash_is_inert(self):
        h = "44d88612fea8a8f36de82e1278abb02f"
        self.assertEqual(defang(h, "md5"), h)


class TestExtract(unittest.TestCase):
    def setUp(self):
        self.result = extract(SAMPLE)
        self.by_type = self.result.by_type()

    def test_finds_each_type(self):
        for t in ("url", "domain", "ipv4", "ipv6", "email", "md5", "sha256"):
            self.assertIn(t, self.by_type, f"missing type {t}")

    def test_url_refanged(self):
        self.assertTrue(
            any("https://bad-host.top/gate.php" in u for u in self.by_type["url"])
        )

    def test_ipv4_present(self):
        self.assertIn("185.220.101.47", self.by_type["ipv4"])
        self.assertIn("8.8.8.8", self.by_type["ipv4"])

    def test_email_refanged(self):
        self.assertIn("evil@phish.shop", self.by_type["email"])

    def test_hashes_classified_correctly(self):
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", self.by_type["md5"])
        self.assertNotIn(
            "44d88612fea8a8f36de82e1278abb02f", self.by_type.get("sha256", [])
        )

    def test_decoy_filename_not_a_domain(self):
        self.assertNotIn("update.dll", self.by_type.get("domain", []))

    def test_url_host_not_double_counted_as_domain(self):
        self.assertNotIn("bad-host.top", self.by_type.get("domain", []))

    def test_dedup(self):
        dup = extract("1.2.3.4 1.2.3.4 1.2.3.4")
        self.assertEqual(dup.count, 1)

    def test_clean_text_empty(self):
        self.assertEqual(extract("just some ordinary prose here").count, 0)

    def test_as_dict_shape(self):
        d = self.result.as_dict()
        self.assertEqual(set(d), {"count", "by_type", "iocs"})
        self.assertEqual(d["count"], len(d["iocs"]))


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__), "_tmp_alert.txt")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(SAMPLE)

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "iocextract")
        self.assertTrue(TOOL_VERSION)

    def test_cli_json_nonzero_on_findings(self):
        from io import StringIO

        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = main(["extract", "--format", "json", self.path])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 1)  # findings -> non-zero
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["tool"], "iocextract")
        self.assertGreater(payload["count"], 0)

    def test_cli_clean_zero_exit(self):
        clean = os.path.join(os.path.dirname(__file__), "_tmp_clean.txt")
        with open(clean, "w", encoding="utf-8") as fh:
            fh.write("nothing actionable in this sentence")
        try:
            from io import StringIO

            buf = StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                rc = main(["extract", "--format", "json", clean])
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
        finally:
            os.remove(clean)

    def test_cli_missing_file_returns_2(self):
        old = sys.stderr
        from io import StringIO

        sys.stderr = StringIO()
        try:
            rc = main(["extract", "no_such_file_12345.txt"])
        finally:
            sys.stderr = old
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
