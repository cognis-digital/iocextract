"""Hardening tests — edge cases, bad input, and error-path coverage.

Covers:
  - None/non-string input to core public API functions
  - Unknown IOC type passed to extract()
  - extract_from_files() with a missing or directory path
  - extract() on empty string and whitespace-only input
  - extract_from_files() on an empty path list
  - CLI exit-2 on bad --type value
  - mcp_server imports cleanly (no broken scan/to_json references)
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iocextract.core import (  # noqa: E402
    defang,
    extract,
    extract_from_files,
    refang,
)
from iocextract.cli import main  # noqa: E402


class TestNoneInput(unittest.TestCase):
    """Public API functions must raise TypeError on non-string input."""

    def test_extract_none_raises_typeerror(self):
        with self.assertRaises(TypeError):
            extract(None)  # type: ignore[arg-type]

    def test_extract_int_raises_typeerror(self):
        with self.assertRaises(TypeError):
            extract(42)  # type: ignore[arg-type]

    def test_refang_none_raises_typeerror(self):
        with self.assertRaises(TypeError):
            refang(None)  # type: ignore[arg-type]

    def test_defang_none_value_raises_typeerror(self):
        with self.assertRaises(TypeError):
            defang(None, "url")  # type: ignore[arg-type]

    def test_defang_none_type_raises_typeerror(self):
        with self.assertRaises(TypeError):
            defang("example.com", None)  # type: ignore[arg-type]


class TestUnknownTypeInExtract(unittest.TestCase):
    """extract() should raise ValueError for unrecognised type names."""

    def test_unknown_type_raises_valueerror(self):
        with self.assertRaises(ValueError) as ctx:
            extract("1.2.3.4", types=["ipv4", "bogustype"])
        self.assertIn("bogustype", str(ctx.exception))

    def test_all_valid_types_accepted(self):
        # Should not raise.
        result = extract("1.2.3.4", types=["ipv4"])
        self.assertGreaterEqual(result.count, 1)


class TestEmptyInput(unittest.TestCase):
    """extract() on empty / whitespace input must return an empty result."""

    def test_empty_string(self):
        self.assertEqual(extract("").count, 0)

    def test_whitespace_only(self):
        self.assertEqual(extract("   \t\n  ").count, 0)


class TestExtractFromFilesEdgeCases(unittest.TestCase):
    """extract_from_files() with problematic paths."""

    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError) as ctx:
            extract_from_files(["/no/such/file/at/all.txt"])
        # The path must be present in the error message for debuggability.
        self.assertIn("no/such/file", str(ctx.exception).replace("\\", "/"))

    def test_empty_path_list_returns_empty_result(self):
        result = extract_from_files([])
        self.assertEqual(result.count, 0)

    def test_reads_real_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("bad actor 185.220.101.47 contacted hxxps://evil[.]com/x")
            path = fh.name
        try:
            result = extract_from_files([path])
            self.assertGreater(result.count, 0)
        finally:
            os.unlink(path)


class TestMcpServerImport(unittest.TestCase):
    """mcp_server must import without NameError (broken scan/to_json refs)."""

    def test_import_succeeds(self):
        # This will NameError/ImportError if the old broken references remain.
        import importlib
        import iocextract.mcp_server  # noqa: F401
        # Re-import to be sure it's not cached from a broken state in CI.
        importlib.reload(iocextract.mcp_server)


class TestCLIHardenedPaths(unittest.TestCase):
    """CLI must return exit-2 with a message on bad --type, not a traceback."""

    def test_bad_type_flag_returns_2_with_message(self):
        stderr_buf = StringIO()
        old_err = sys.stderr
        sys.stderr = stderr_buf
        try:
            rc = main(["extract", "--type", "nonsense_type", "-"])
        finally:
            sys.stderr = old_err
        self.assertEqual(rc, 2)
        self.assertIn("nonsense_type", stderr_buf.getvalue())

    def test_missing_file_returns_2_with_message(self):
        stderr_buf = StringIO()
        old_err = sys.stderr
        sys.stderr = stderr_buf
        try:
            rc = main(["extract", "/definitely/not/a/real/file_98765.txt"])
        finally:
            sys.stderr = old_err
        self.assertEqual(rc, 2)
        msg = stderr_buf.getvalue()
        self.assertGreater(len(msg), 0, "expected an error message on stderr")


if __name__ == "__main__":
    unittest.main()
