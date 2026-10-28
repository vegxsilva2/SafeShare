"""CLI, report and 'no network, ever' tests."""
import contextlib
import io
import re
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers
from helpers import fixture, insert_after_soi, segment
from safeshare import __version__
from safeshare.cli import main as cli_main
from safeshare.jpeg import PrivacyMode, SanitizeOptions, inspect_bytes, sanitize_bytes
from safeshare.report import MODE_LABELS, format_inspection, format_sanitization

SRC = helpers.ROOT / "src" / "safeshare"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli_main([str(a) for a in argv])
        except SystemExit as exc:  # argparse
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def dirty() -> bytes:
    return insert_after_soi(
        fixture("rgb_baseline.jpg"),
        segment(0xE1, helpers.rich_exif()),
        segment(0xFE, b"private comment"),
    ) + b"TRAILER"


class ReportTests(unittest.TestCase):
    def test_inspection_report_lists_risks_hashes_and_trailing_data(self):
        report = format_inspection(inspect_bytes(dirty()))
        for expected in ("GPS location", "Device serial number", "40.420094, -3.708333",
                         "Data stored after the end of the image", "SHA-256:", "private comment"):
            self.assertIn(expected, report)

    def test_clean_report_says_nothing_found(self):
        out, _ = sanitize_bytes(dirty(), SanitizeOptions(PrivacyMode.MAXIMUM))
        report = format_inspection(inspect_bytes(out))
        self.assertIn("None of the known risks", report)
        self.assertNotIn("Data stored after", report)

    def test_sanitization_report_contains_proof(self):
        _, result = sanitize_bytes(dirty(), SanitizeOptions(PrivacyMode.BALANCED))
        report = format_sanitization(result)
        self.assertIn("PASS", report)
        self.assertIn("✔", report)
        self.assertNotIn("✘", report)
        self.assertIn(result.verification.source_sha256, report)
        self.assertIn(result.verification.output_sha256, report)
        self.assertIn(MODE_LABELS[PrivacyMode.BALANCED], report)
        # The report must not leak the values it just removed.
        self.assertNotIn("SN-0042", report.split("Verification")[0].split("Removed:")[1])

    def test_every_mode_has_a_label_and_ui_help(self):
        for mode in PrivacyMode:
            self.assertIn(mode, MODE_LABELS)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "photo.jpg"
        self.source.write_bytes(dirty())

    def test_version(self):
        code, out, _ = run("--version")
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)

    def test_inspect(self):
        code, out, _ = run("inspect", self.source)
        self.assertEqual(code, 0)
        self.assertIn("GPS location", out)

    def test_clean_default_output_name_and_mode(self):
        code, out, _ = run("clean", self.source)
        self.assertEqual(code, 0, out)
        cleaned = self.root / "photo_safeshare.jpg"
        self.assertTrue(cleaned.exists())
        info = inspect_bytes(cleaned.read_bytes())
        self.assertEqual(info.exif_tags, ["Orientation"])
        self.assertIsNone(info.trailing)
        self.assertIn("PASS", out)

    def test_clean_maximum_and_keep_trailing(self):
        target = self.root / "max.jpg"
        code, _, _ = run("clean", self.source, "-o", target, "--mode", "maximum", "--keep-trailing-data")
        self.assertEqual(code, 0)
        info = inspect_bytes(target.read_bytes())
        self.assertEqual(info.markers, [])
        self.assertIsNotNone(info.trailing)

    def test_never_overwrites(self):
        target = self.root / "exists.jpg"
        target.write_bytes(b"keep")
        code, _, err = run("clean", self.source, "-o", target)
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)
        self.assertEqual(target.read_bytes(), b"keep")

    def test_invalid_files_and_arguments(self):
        bad = self.root / "bad.jpg"
        bad.write_bytes(b"nope")
        self.assertEqual(run("inspect", bad)[0], 1)
        self.assertEqual(run("inspect", self.root / "missing.jpg")[0], 1)
        self.assertEqual(run("clean", bad)[0], 1)
        self.assertEqual(run("bogus")[0], 2)
        self.assertEqual(run()[0], 2)


class OfflineTests(unittest.TestCase):
    """SafeShare's promise: processing never touches the network."""

    FORBIDDEN = re.compile(
        r"^\s*(?:import|from)\s+(socket|ssl|http|urllib|ftplib|smtplib|telnetlib|requests|httpx|aiohttp|xmlrpc)\b",
        re.MULTILINE,
    )

    def test_source_never_imports_network_modules(self):
        for path in SRC.rglob("*.py"):
            self.assertIsNone(self.FORBIDDEN.search(path.read_text(encoding="utf-8")), path)

    def test_inspect_and_sanitize_work_with_the_network_blocked(self):
        def blocked(*args, **kwargs):
            raise AssertionError("network access attempted")

        with mock.patch.object(socket, "socket", blocked), \
                mock.patch.object(socket, "create_connection", blocked), \
                mock.patch.object(socket, "getaddrinfo", blocked):
            data = dirty()
            inspect_bytes(data)
            sanitize_bytes(data)

    def test_runtime_dependencies_are_only_customtkinter(self):
        text = (helpers.ROOT / "pyproject.toml").read_text(encoding="utf-8")
        deps = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.S).group(1)
        names = re.findall(r'"([A-Za-z0-9_.-]+)', deps)
        self.assertEqual(names, ["customtkinter"])
        self.assertNotIn("pillow", (helpers.ROOT / "requirements.txt").read_text().lower())


class UITests(unittest.TestCase):
    def test_ui_module_imports_and_exposes_every_mode(self):
        try:
            from safeshare.ui import app
        except ImportError as exc:
            self.skipTest(f"GUI libraries not available: {exc}")
        for mode in PrivacyMode:
            self.assertIn(mode, app.MODE_HELP)
        self.assertEqual(set(app.LABEL_TO_MODE.values()), set(PrivacyMode))


if __name__ == "__main__":
    unittest.main()
