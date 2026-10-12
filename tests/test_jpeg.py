import tempfile
import unittest
from pathlib import Path

from safeshare.jpeg import JPEGFormatError, _read_exif_tags, inspect_jpeg, sanitize_jpeg


def segment(marker: int, payload: bytes) -> bytes:
    length = len(payload) + 2
    return b"\xff" + bytes([marker]) + length.to_bytes(2, "big") + payload


class JPEGTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_detects_and_removes_app_and_comment_markers(self):
        # Structurally sufficient fixture for marker-level tests; not a decodable photo.
        data = (
            b"\xff\xd8"
            + segment(0xE1, b"Exif\x00\x00fake-exif")
            + segment(0xFE, b"private comment")
            + segment(0xDB, b"\x00")
            + segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
            + b"\x11\x22\xff\x00\x33"
            + b"\xff\xd9"
        )
        source = self.root / "input.jpg"
        output = self.root / "output.jpg"
        source.write_bytes(data)

        before = inspect_jpeg(source)
        self.assertIn("EXIF", before.markers)
        self.assertIn("JPEG comment", before.markers)

        after = sanitize_jpeg(source, output)
        self.assertNotIn("EXIF", after.markers)
        self.assertNotIn("JPEG comment", after.markers)
        self.assertEqual(source.read_bytes(), data)
        self.assertNotEqual(output.read_bytes(), data)

    def test_reports_unknown_exif_tags_instead_of_silently_ignoring_them(self):
        # Little-endian TIFF header + one unknown SHORT tag (0xC123) with value 7.
        tiff = (
            b"II" + (42).to_bytes(2, "little") + (8).to_bytes(4, "little")
            + (1).to_bytes(2, "little")
            + (0xC123).to_bytes(2, "little") + (3).to_bytes(2, "little")
            + (1).to_bytes(4, "little") + (7).to_bytes(2, "little") + b"\x00\x00"
            + (0).to_bytes(4, "little")
        )
        tags, details, warnings = _read_exif_tags(b"Exif\x00\x00" + tiff)
        self.assertIn("UnknownTag_0xC123", tags)
        self.assertTrue(any("UnknownTag_0xC123: 7" in detail for detail in details))
        self.assertEqual(warnings, [])

    def test_rejects_non_jpeg(self):
        source = self.root / "not.jpg"
        source.write_bytes(b"not a jpeg")
        with self.assertRaises(JPEGFormatError):
            inspect_jpeg(source)

    def test_rejects_jpeg_missing_eoi(self):
        source = self.root / "missing_eoi.jpg"
        source.write_bytes(b"\xff\xd8" + segment(0xDB, b"\x00"))

        with self.assertRaisesRegex(JPEGFormatError, "EOI"):
            inspect_jpeg(source)

    def test_eoi_bytes_inside_segment_payload_do_not_validate_file(self):
        source = self.root / "fake_eoi.jpg"
        output = self.root / "sanitized.jpg"
        # The FF D9 sequence is payload data, not a JPEG marker, because the
        # APP segment length explicitly includes it. There is no real EOI.
        data = b"\xff\xd8" + segment(0xE1, b"payload\xff\xd9still-payload")
        source.write_bytes(data)

        with self.assertRaisesRegex(JPEGFormatError, "EOI"):
            inspect_jpeg(source)
        with self.assertRaisesRegex(JPEGFormatError, "EOI"):
            sanitize_jpeg(source, output)
        self.assertFalse(output.exists())

    def test_inspection_and_sanitization_reject_malformed_marker_streams(self):
        malformed = {
            "incomplete marker": b"\xff\xd8\xff\xe1\x00\x02\xff",
            "truncated length field": b"\xff\xd8\xff\xe1\x00",
            "length below minimum": b"\xff\xd8\xff\xe1\x00\x01\xff\xd9",
            "length exceeds available bytes": b"\xff\xd8\xff\xe1\x00\x06x",
            "undersized scan header": b"\xff\xd8\xff\xda\x00\x02\xff\xd9",
            "undersized frame header": b"\xff\xd8\xff\xc0\x00\x02\xff\xd9",
            "unexpected SOI": b"\xff\xd8\xff\xd8\xff\xd9",
            "restart marker outside scan": b"\xff\xd8\xff\xd0\xff\xd9",
            "stuffed byte outside scan": b"\xff\xd8\xff\x00\xff\xd9",
            "fill byte before stuffed byte": b"\xff\xd8\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\xff\xff\x00\xff\xd9",
            "trailing data after EOI": b"\xff\xd8\xff\xd9unexpected",
        }
        for name, data in malformed.items():
            with self.subTest(name=name):
                source = self.root / f"{name.replace(' ', '_')}.jpg"
                output = self.root / f"{name.replace(' ', '_')}_clean.jpg"
                source.write_bytes(data)

                with self.assertRaises(JPEGFormatError):
                    inspect_jpeg(source)
                with self.assertRaises(JPEGFormatError):
                    sanitize_jpeg(source, output)
                self.assertFalse(output.exists())

    def test_refuses_overwrite(self):
        source = self.root / "input.jpg"
        output = self.root / "output.jpg"
        source.write_bytes(b"\xff\xd8\xff\xd9")
        output.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            sanitize_jpeg(source, output)
        self.assertEqual(output.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
