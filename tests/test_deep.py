"""Deep tests for IOCEXTRACT — exercises the full 12-type feature set.

Standard library only, no network.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iocextract import (  # noqa: E402
    IOC_TYPES,
    TOOL_NAME,
    TOOL_VERSION,
    defang,
    extract,
    refang,
)
from iocextract.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "02-deep", "threat_report.txt",
)

# A compact sample covering all 12 types with heavy defanging.
SAMPLE = (
    "C2 hxxps://bad-host[.]top/gate.php  fallback cdn-sync[.]xyz "
    "staging ftp[:]//drop[.]example[.]store/p "
    "ip 185.220.101.47  ip2 1[.]1[.]1[.]1  v6 2001:db8::dead:beef "
    "mapped ::ffff:192.168.1.10 "
    "mail evil[at]phish[.]shop  op nullbyte.ops(at)proton(dot)me "
    "md5 44d88612fea8a8f36de82e1278abb02f "
    "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 "
    "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
    "exploit CVE-2021-44228 also cve-2023-23397 "
    "wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
    "p2sh 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy "
    "bech32 bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
    "reg HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater "
    "decoy invoice_2026.docx  lib wininet.dll  resolver 8.8.8.8"
)


def _capture(fn, *a, **k):
    buf = StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        rc = fn(*a, **k)
    finally:
        sys.stdout = old
    return rc, buf.getvalue()


class TestVersionBump(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "iocextract")
        self.assertEqual(TOOL_VERSION, "2.0.0")

    def test_eleven_named_types(self):
        self.assertEqual(
            set(IOC_TYPES),
            {"ipv4", "ipv6", "url", "domain", "email",
             "md5", "sha1", "sha256", "cve", "btc", "registry"},
        )


class TestAllTypesPresent(unittest.TestCase):
    def setUp(self):
        self.bt = extract(SAMPLE).by_type()

    def test_every_supported_type_found(self):
        for t in IOC_TYPES:
            self.assertIn(t, self.bt, f"missing type {t}")


class TestNewTypes(unittest.TestCase):
    def setUp(self):
        self.bt = extract(SAMPLE).by_type()

    def test_cve_normalized_uppercase(self):
        self.assertIn("CVE-2021-44228", self.bt["cve"])
        self.assertIn("CVE-2023-23397", self.bt["cve"])  # lowercased input

    def test_btc_checksum_valid_accepted(self):
        self.assertIn("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", self.bt["btc"])
        self.assertIn("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", self.bt["btc"])

    def test_btc_bech32_accepted(self):
        self.assertIn(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", self.bt["btc"]
        )

    def test_btc_checksum_rejects_garbage(self):
        bad = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfXX"
        self.assertNotIn(bad, extract(f"wallet {bad}").by_type().get("btc", []))

    def test_registry_key_captured_whole(self):
        regs = self.bt["registry"]
        self.assertTrue(
            any(r.endswith("Run\\Updater") and r.upper().startswith("HKLM")
                for r in regs),
            regs,
        )

    def test_ipv6_mapped_form(self):
        self.assertTrue(any("::ffff:192.168.1.10" in v for v in self.bt["ipv6"]))


class TestRefangDefang(unittest.TestCase):
    def test_refang_scheme_and_markers(self):
        self.assertEqual(refang("hxxps://x[.]y"), "https://x.y")
        self.assertEqual(refang("ftp[:]//x[.]y"), "ftp://x.y")
        self.assertEqual(refang("user[at]host(dot)com"), "user@host.com")

    def test_defang_email_and_url(self):
        self.assertEqual(defang("a@b.com", "email"), "a[at]b[.]com")
        self.assertEqual(defang("https://a.com/x", "url"), "hxxps://a[.]com/x")

    def test_defang_inert_types_unchanged(self):
        for t in ("md5", "sha1", "sha256", "cve", "btc", "registry"):
            self.assertEqual(defang("VALUE.1", t), "VALUE.1")


class TestSuppressionAndDedup(unittest.TestCase):
    def setUp(self):
        self.bt = extract(SAMPLE).by_type()

    def test_url_host_not_double_counted(self):
        self.assertNotIn("bad-host.top", self.bt.get("domain", []))

    def test_email_host_not_double_counted(self):
        self.assertNotIn("phish.shop", self.bt.get("domain", []))

    def test_decoy_filenames_not_domains(self):
        doms = self.bt.get("domain", [])
        self.assertNotIn("invoice_2026.docx", doms)
        self.assertNotIn("wininet.dll", doms)

    def test_hashes_not_cross_classified(self):
        self.assertIn(
            "44d88612fea8a8f36de82e1278abb02f", self.bt["md5"]
        )
        self.assertNotIn(
            "44d88612fea8a8f36de82e1278abb02f", self.bt.get("sha256", [])
        )

    def test_dedup(self):
        self.assertEqual(extract("1.2.3.4 1.2.3.4 1.2.3.4").count, 1)


class TestTypeFilter(unittest.TestCase):
    def test_filter_restricts_output(self):
        res = extract(SAMPLE, types=["ipv4", "cve"])
        seen = set(res.by_type())
        self.assertEqual(seen, {"ipv4", "cve"})

    def test_filter_via_result_object(self):
        res = extract(SAMPLE).filter_types(["btc"])
        self.assertTrue(res.count >= 3)
        self.assertEqual(set(res.by_type()), {"btc"})


class TestCLI(unittest.TestCase):
    def test_extract_json_nonzero_on_findings(self):
        rc, out = _capture(
            main, ["extract", "--format", "json", DEMO]
        )
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "iocextract")
        self.assertEqual(payload["version"], "2.0.0")
        for t in IOC_TYPES:
            self.assertIn(t, payload["by_type"], f"demo missing {t}")

    def test_extract_type_filter_cli(self):
        rc, out = _capture(
            main, ["extract", "--type", "btc,cve", "--format", "json", DEMO]
        )
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(set(payload["by_type"]), {"btc", "cve"})

    def test_extract_bad_type_returns_2(self):
        old = sys.stderr
        sys.stderr = StringIO()
        try:
            rc = main(["extract", "--type", "bogus", DEMO])
        finally:
            sys.stderr = old
        self.assertEqual(rc, 2)

    def test_types_subcommand_json(self):
        rc, out = _capture(main, ["types", "--format", "json"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["types"], list(IOC_TYPES))

    def test_defang_subcommand(self):
        rc, out = _capture(main, ["defang", "https://evil.example.com/x"])
        self.assertEqual(rc, 0)
        self.assertIn("hxxps://evil[.]example[.]com/x", out)

    def test_clean_text_zero_exit(self):
        clean = os.path.join(os.path.dirname(__file__), "_tmp_clean_deep.txt")
        with open(clean, "w", encoding="utf-8") as fh:
            fh.write("nothing actionable in this ordinary sentence")
        try:
            rc, _ = _capture(main, ["extract", "--format", "json", clean])
            self.assertEqual(rc, 0)
        finally:
            os.remove(clean)


if __name__ == "__main__":
    unittest.main()
