"""Sanitization, verification and file-writing tests."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers
from helpers import fixture, insert_after_soi, pixels, segment
import safeshare.jpeg as jpeg
from safeshare.jpeg import (
    JPEGFormatError,
    PrivacyMode,
    SanitizeOptions,
    VerificationError,
    inspect_bytes,
    sanitize_bytes,
    sanitize_jpeg,
)

BASE = fixture("rgb_baseline.jpg")
MAX = SanitizeOptions(PrivacyMode.MAXIMUM)
BAL = SanitizeOptions(PrivacyMode.BALANCED)


def dirty(base: bytes = BASE, orientation: int = 6, tail: bytes = b"") -> bytes:
    return insert_after_soi(
        base,
        segment(0xE1, helpers.rich_exif(orientation=orientation)),
        segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>GPSLatitude</x:xmpmeta>"),
        segment(0xED, b"Photoshop 3.0\x008BIM"),
        segment(0xFE, b"private comment"),
    ) + tail


class ModeTests(unittest.TestCase):
    def test_maximum_removes_everything_and_keeps_pixels(self):
        data = dirty()
        out, result = sanitize_bytes(data, MAX)
        after = inspect_bytes(out)
        self.assertEqual(after.markers, [])
        self.assertEqual(after.exif_tags, [])
        self.assertEqual(after.risk_flags, [])
        self.assertTrue(result.verification.pixel_identical)
        self.assertTrue(result.verification.passed)
        self.assertEqual(inspect_bytes(data).image_digest, after.image_digest)
        self.assertNotIn(b"private comment", out)
        self.assertNotIn(b"SN-0042", out)
        self.assertTrue(any("orientation" in note for note in result.notes))

    def test_balanced_keeps_only_orientation(self):
        out, result = sanitize_bytes(dirty(orientation=6), BAL)
        after = inspect_bytes(out)
        self.assertEqual(after.exif_tags, ["Orientation"])
        self.assertEqual(after.orientation, 6)
        self.assertEqual(after.risk_flags, [])
        self.assertEqual(out.count(b"Exif\x00\x00"), 1)
        self.assertTrue(result.verification.passed)
        for secret in (b"AcmeCam", b"Jane", b"SN-0042", b"private comment", b"GPSLatitude", b"station"):
            self.assertNotIn(secret, out)

    def test_balanced_without_rotation_writes_no_exif_at_all(self):
        out, _ = sanitize_bytes(dirty(orientation=1), BAL)
        self.assertEqual(inspect_bytes(out).markers, [])

    def test_balanced_orientation_survives_every_value(self):
        for value in range(2, 9):
            with self.subTest(orientation=value):
                out, _ = sanitize_bytes(dirty(orientation=value), BAL)
                self.assertEqual(inspect_bytes(out).orientation, value)

    def test_icc_profile_kept_in_balanced_removed_in_maximum(self):
        icc = fixture("rgb_icc.jpg")
        self.assertIn("ICC profile", inspect_bytes(icc).markers)
        out_bal, res_bal = sanitize_bytes(icc, BAL)
        self.assertIn("ICC profile", inspect_bytes(out_bal).markers)
        self.assertTrue(res_bal.verification.passed)
        out_max, res_max = sanitize_bytes(icc, MAX)
        self.assertNotIn("ICC profile", inspect_bytes(out_max).markers)
        self.assertTrue(any("ICC" in note for note in res_max.notes))

    def test_adobe_colour_transform_is_kept_for_cmyk_in_both_modes(self):
        cmyk = fixture("cmyk_adobe.jpg")
        self.assertIn("Adobe", inspect_bytes(cmyk).markers)
        for options in (MAX, BAL):
            with self.subTest(mode=options.mode):
                out, result = sanitize_bytes(cmyk, options)
                self.assertIn("Adobe", inspect_bytes(out).markers)
                self.assertTrue(result.verification.passed)
                original, cleaned = pixels(cmyk), pixels(out)
                if original is not None:
                    self.assertEqual(original, cleaned)

    def test_adobe_segment_is_rebuilt_not_copied(self):
        weird = insert_after_soi(
            fixture("cmyk_adobe.jpg"), segment(0xEE, b"Adobe\x00\x64\xab\xcd\xef\x01\x00")
        )
        out, _ = sanitize_bytes(weird, MAX)
        self.assertNotIn(b"\xab\xcd\xef\x01", out)
        self.assertEqual(out.count(b"Adobe"), 1)

    def test_adobe_not_kept_for_grayscale(self):
        gray = insert_after_soi(fixture("gray.jpg"), segment(0xEE, b"Adobe\x00\x64\x00\x00\x00\x00\x01"))
        out, _ = sanitize_bytes(gray, BAL)
        self.assertEqual(inspect_bytes(out).markers, [])


class AllowListTests(unittest.TestCase):
    def test_unknown_and_reserved_markers_are_dropped(self):
        data = insert_after_soi(
            BASE,
            segment(0xF3, b"vendor jpg3 data"),
            segment(0xE5, b"APP5 private"),
            segment(0x05, b"reserved marker"),
            segment(0xFD, b"JPG13"),
        )
        self.assertTrue({"0xFFF3", "APP5", "0xFF05", "0xFFFD"} <= set(inspect_bytes(data).markers))
        out, result = sanitize_bytes(data, MAX)
        self.assertEqual(inspect_bytes(out).markers, [])
        self.assertEqual(inspect_bytes(out).image_digest, inspect_bytes(BASE).image_digest)

    def test_decoding_segments_are_preserved_byte_for_byte(self):
        for name in ("rgb_baseline.jpg", "rgb_progressive.jpg", "rgb_restart.jpg", "gray.jpg"):
            with self.subTest(name=name):
                original = fixture(name)
                out, _ = sanitize_bytes(dirty(original), MAX)
                parsed_in, parsed_out = jpeg.parse_jpeg(original), jpeg.parse_jpeg(out)
                structural = lambda p: [(m.code, p.data[m.start:m.end]) for m in p.markers if m.code in jpeg._STRUCTURAL]
                self.assertEqual(structural(parsed_in), structural(parsed_out))
                original_px, cleaned_px = pixels(original), pixels(out)
                if original_px is not None:
                    self.assertEqual(original_px, cleaned_px)

    def test_sanitizing_is_idempotent(self):
        for options in (MAX, BAL):
            with self.subTest(mode=options.mode):
                first, _ = sanitize_bytes(dirty(), options)
                second, result = sanitize_bytes(first, options)
                self.assertEqual(first, second)
                self.assertEqual(result.removed, [])


class TrailingTests(unittest.TestCase):
    TAIL = b"\xff\xd8\xff\xe0SECOND-IMAGE\xff\xd9" + b"\x00\x00\x00\x18ftypmp42" + b"VIDEO" * 10

    def test_trailing_data_is_removed_by_default(self):
        data = dirty(tail=self.TAIL)
        out, result = sanitize_bytes(data, BAL)
        self.assertNotIn(b"SECOND-IMAGE", out)
        self.assertNotIn(b"VIDEO", out)
        self.assertIsNone(inspect_bytes(out).trailing)
        self.assertTrue(any("data after the image" in item for item in result.removed))
        self.assertTrue(result.verification.passed)
        self.assertTrue(out.endswith(b"\xff\xd9"))

    def test_trailing_data_can_be_kept_explicitly(self):
        data = BASE + self.TAIL
        out, result = sanitize_bytes(data, SanitizeOptions(strip_trailing_data=False))
        self.assertTrue(out.endswith(self.TAIL))
        self.assertIsNotNone(inspect_bytes(out).trailing)
        self.assertTrue(any("kept at your request" in note for note in result.notes))

    def test_motion_photo_like_file_is_now_processable(self):
        data = dirty(tail=b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 4096)
        out, _ = sanitize_bytes(data, MAX)
        self.assertIsNone(inspect_bytes(out).trailing)
        self.assertEqual(inspect_bytes(out).image_digest, inspect_bytes(BASE).image_digest)


class VerificationTests(unittest.TestCase):
    def test_leaked_exif_is_caught_before_anything_is_returned(self):
        def leaky(parsed, before, options):
            return insert_after_soi(parsed.data[: parsed.eoi_end], segment(0xE1, helpers.rich_exif())), [], []

        with mock.patch.object(jpeg, "_build_sanitized", leaky):
            with self.assertRaises(VerificationError) as ctx:
                sanitize_bytes(BASE, MAX)
        self.assertFalse(ctx.exception.result.verification.passed)
        self.assertTrue(ctx.exception.result.verification.residual)

    def test_changed_image_data_is_caught(self):
        def corrupt(parsed, before, options):
            out = bytearray(parsed.data[: parsed.eoi_end])
            sos_end = next(m.end for m in parsed.markers if m.code == 0xDA)
            # Flip one bit of plain entropy-coded data without creating a marker.
            k = next(i for i in range(sos_end + 1, len(out) - 2)
                     if 2 <= out[i] <= 0x7F and out[i - 1] != 0xFF)
            out[k] ^= 0x01
            return bytes(out), [], []

        with mock.patch.object(jpeg, "_build_sanitized", corrupt):
            with self.assertRaises(VerificationError) as ctx:
                sanitize_bytes(BASE, MAX)
        self.assertFalse(ctx.exception.result.verification.pixel_identical)

    def test_raw_signature_scan_is_independent_of_the_parser(self):
        # A comment placed *inside* entropy-less padding would be invisible to the
        # marker parser; the raw scan still flags the XMP namespace string.
        def sneaky(parsed, before, options):
            return parsed.data[: parsed.eoi_end] + b"http://ns.adobe.com/hidden", [], []

        with mock.patch.object(jpeg, "_build_sanitized", sneaky):
            with self.assertRaises(VerificationError) as ctx:
                sanitize_bytes(BASE, SanitizeOptions(strip_trailing_data=False))
        self.assertTrue(ctx.exception.result.verification.signature_hits)

    def test_unparseable_output_is_rejected(self):
        with mock.patch.object(jpeg, "_build_sanitized", lambda *a: (b"garbage", [], [])):
            with self.assertRaises(VerificationError):
                sanitize_bytes(BASE, MAX)

    def test_hashes_are_reported(self):
        data = dirty()
        out, result = sanitize_bytes(data, MAX)
        self.assertEqual(result.verification.source_sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.verification.output_sha256, hashlib.sha256(out).hexdigest())

    def test_invalid_input_raises_format_error(self):
        with self.assertRaises(JPEGFormatError):
            sanitize_bytes(b"\xff\xd8\xff\xe1\x00\x06x", MAX)


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.jpg"
        self.source.write_bytes(dirty(tail=b"TRAILER"))
        self.output = self.root / "output.jpg"

    def leftovers(self):
        return sorted(p.name for p in self.root.iterdir())

    def test_writes_verified_copy_and_leaves_original_untouched(self):
        original = self.source.read_bytes()
        result = sanitize_jpeg(self.source, self.output, MAX)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(result.output_path, str(self.output))
        self.assertEqual(inspect_bytes(self.output.read_bytes()).markers, [])
        self.assertEqual(self.leftovers(), ["input.jpg", "output.jpg"])  # no temp files

    def test_refuses_overwrite(self):
        self.output.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            sanitize_jpeg(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), b"keep")

    def test_file_appearing_during_processing_is_not_overwritten(self):
        real = jpeg.sanitize_bytes

        def racing(*args, **kwargs):
            outcome = real(*args, **kwargs)
            self.output.write_bytes(b"someone else's file")  # appears after the first check
            return outcome

        with mock.patch.object(jpeg, "sanitize_bytes", racing):
            with self.assertRaises(FileExistsError):
                sanitize_jpeg(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), b"someone else's file")
        self.assertEqual(self.leftovers(), ["input.jpg", "output.jpg"])

    def test_refuses_same_path(self):
        with self.assertRaises(ValueError):
            sanitize_jpeg(self.source, self.source)

    def test_invalid_input_creates_no_output(self):
        bad = self.root / "bad.jpg"
        bad.write_bytes(b"\xff\xd8\xff\xe1\x00\x06x")
        with self.assertRaises(JPEGFormatError):
            sanitize_jpeg(bad, self.output)
        self.assertEqual(self.leftovers(), ["bad.jpg", "input.jpg"])

    def test_failed_verification_creates_no_output_or_temp_file(self):
        def leaky(parsed, before, options):
            return insert_after_soi(parsed.data[: parsed.eoi_end], segment(0xFE, b"oops")), [], []

        with mock.patch.object(jpeg, "_build_sanitized", leaky):
            with self.assertRaises(VerificationError):
                sanitize_jpeg(self.source, self.output)
        self.assertEqual(self.leftovers(), ["input.jpg"])

    def test_write_failure_leaves_no_partial_file(self):
        with mock.patch.object(jpeg.os, "fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                sanitize_jpeg(self.source, self.output)
        self.assertEqual(self.leftovers(), ["input.jpg"])

    def test_falls_back_when_hard_links_are_unavailable(self):
        with mock.patch.object(jpeg.os, "link", side_effect=OSError("no links here")):
            sanitize_jpeg(self.source, self.output)
        self.assertTrue(self.output.exists())
        self.assertEqual(self.leftovers(), ["input.jpg", "output.jpg"])

    def test_creates_missing_output_folder(self):
        target = self.root / "nested" / "dir" / "out.jpg"
        sanitize_jpeg(self.source, target)
        self.assertTrue(target.exists())

    def test_disk_content_is_checked_after_writing(self):
        real_write = jpeg._write_new_file_atomically

        def tampering(destination, data):
            real_write(destination, data + b"X")

        with mock.patch.object(jpeg, "_write_new_file_atomically", tampering):
            with self.assertRaises(VerificationError):
                sanitize_jpeg(self.source, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
