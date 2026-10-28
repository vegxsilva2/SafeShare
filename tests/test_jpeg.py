"""Parsing and inspection tests."""
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import fixture, insert_after_soi, segment
from safeshare.jpeg import (
    JPEGFormatError,
    _read_exif_tags,
    inspect_bytes,
    inspect_jpeg,
    parse_jpeg,
)

BASE = fixture("rgb_baseline.jpg")


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_fixtures_parse(self):
        for name in ("rgb_baseline.jpg", "rgb_progressive.jpg", "rgb_icc.jpg",
                     "gray.jpg", "cmyk_adobe.jpg", "rgb_restart.jpg"):
            with self.subTest(name=name):
                parsed = parse_jpeg(fixture(name))
                self.assertEqual(parsed.trailing_size, 0)

    def test_rejects_non_jpeg(self):
        source = self.root / "not.jpg"
        source.write_bytes(b"not a jpeg")
        with self.assertRaises(JPEGFormatError):
            inspect_jpeg(source)

    def test_rejects_jpeg_missing_eoi(self):
        with self.assertRaisesRegex(JPEGFormatError, "EOI"):
            inspect_bytes(b"\xff\xd8" + segment(0xDB, b"\x00"))

    def test_eoi_bytes_inside_segment_payload_do_not_validate_file(self):
        # FF D9 is payload data here because the APP segment length includes it.
        data = b"\xff\xd8" + segment(0xE1, b"payload\xff\xd9still-payload")
        with self.assertRaisesRegex(JPEGFormatError, "EOI"):
            inspect_bytes(data)

    def test_rejects_malformed_marker_streams(self):
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
        }
        for name, data in malformed.items():
            with self.subTest(name=name):
                with self.assertRaises(JPEGFormatError):
                    inspect_bytes(data)

    def test_every_truncation_of_a_valid_file_is_rejected(self):
        for name in ("rgb_baseline.jpg", "rgb_progressive.jpg", "rgb_restart.jpg"):
            data = fixture(name)
            for cut in range(len(data)):
                with self.subTest(name=name, cut=cut):
                    with self.assertRaises(JPEGFormatError):
                        parse_jpeg(data[:cut])

    def test_restart_markers_inside_scan_are_not_segments(self):
        parsed = parse_jpeg(fixture("rgb_restart.jpg"))
        self.assertFalse(any(0xD0 <= m.code <= 0xD7 for m in parsed.markers))
        self.assertIn(0xDD, [m.code for m in parsed.markers])

    def test_file_size_limit(self):
        from unittest import mock

        import safeshare.jpeg as jpeg

        path = self.root / "big.jpg"
        path.write_bytes(BASE)
        with mock.patch.object(jpeg, "MAX_FILE_SIZE", 10):
            with self.assertRaisesRegex(JPEGFormatError, "larger"):
                inspect_jpeg(path)


class TrailingDataTests(unittest.TestCase):
    def test_trailing_data_is_reported_instead_of_rejected(self):
        for label, tail, expected in (
            ("embedded image", b"\xff\xd8\xff\xe0JFIF-secondary\xff\xd9", "embedded JPEG"),
            ("video", b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 20, "video"),
            ("padding", b"\x00" * 64, "zero padding"),
            ("unknown", b"SECRET-APPENDED-DATA", "unrecognised"),
        ):
            with self.subTest(label=label):
                result = inspect_bytes(BASE + tail)
                self.assertIsNotNone(result.trailing)
                self.assertEqual(result.trailing.offset, len(BASE))
                self.assertEqual(result.trailing.size, len(tail))
                self.assertTrue(any(expected in kind for kind in result.trailing.kinds), result.trailing.kinds)
                self.assertTrue(any("appended" in flag for flag in result.risk_flags))
                self.assertTrue(result.has_metadata)

    def test_clean_file_has_no_trailing_data(self):
        self.assertIsNone(inspect_bytes(BASE).trailing)


class MetadataInspectionTests(unittest.TestCase):
    def test_rich_exif_is_fully_reported(self):
        data = insert_after_soi(BASE, segment(0xE1, helpers.rich_exif()))
        result = inspect_bytes(data)
        self.assertIn("EXIF", result.markers)
        self.assertEqual(result.orientation, 6)
        for flag in ("GPS location", "Device serial number", "Owner/author name",
                     "Capture date/time", "Camera make/model", "Free-text description"):
            self.assertIn(flag, result.risk_flags)
        self.assertTrue(any("Embedded EXIF thumbnail" in f for f in result.risk_flags))
        self.assertTrue(any("MakerNote" in f for f in result.risk_flags))
        self.assertIn("GPS coordinates (decimal): 40.420094, -3.708333", result.exif_details)
        self.assertIn("UserComment: meet me behind the station", result.exif_details)
        self.assertIn("BodySerialNumber: SN-0042-0042", result.exif_details)
        self.assertEqual(result.warnings, [])

    def test_big_endian_exif(self):
        data = insert_after_soi(BASE, segment(0xE1, helpers.rich_exif("big", orientation=3)))
        result = inspect_bytes(data)
        self.assertEqual(result.orientation, 3)
        self.assertIn("GPS location", result.risk_flags)

    def test_makernote_content_is_never_printed(self):
        data = insert_after_soi(BASE, segment(0xE1, helpers.rich_exif()))
        joined = "\n".join(inspect_bytes(data).exif_details)
        self.assertNotIn("MAKERNOTE-SERIAL", joined)
        self.assertIn("MakerNote: [26 opaque byte(s)]", joined)

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

    def test_broken_exif_warns_but_never_crashes(self):
        cases = {
            "truncated header": b"Exif\x00\x00II*",
            "bad byte order": b"Exif\x00\x00XX*\x00\x08\x00\x00\x00",
            "bad magic": b"Exif\x00\x00II\x2b\x00\x08\x00\x00\x00",
            "offset out of range": b"Exif\x00\x00II*\x00\xff\xff\x00\x00",
            "huge entry count": b"Exif\x00\x00II*\x00\x08\x00\x00\x00\xff\xff",
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                data = insert_after_soi(BASE, segment(0xE1, payload))
                result = inspect_bytes(data)
                self.assertTrue(result.warnings, name)

    def test_circular_ifd_pointers_terminate(self):
        # IFD0 whose next-IFD pointer points back at itself.
        tiff = b"II*\x00\x08\x00\x00\x00" + (0).to_bytes(2, "little") + (8).to_bytes(4, "little")
        result = inspect_bytes(insert_after_soi(BASE, segment(0xE1, b"Exif\x00\x00" + tiff)))
        self.assertEqual(result.exif_tags, [])

    def test_xmp_iptc_mpf_comment_and_thumbnails_are_flagged(self):
        xmp = b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta><exif:GPSLatitude>1</exif:GPSLatitude>" \
              b"<dc:creator>Jane</dc:creator><aux:SerialNumber>77</aux:SerialNumber></x:xmpmeta>"
        data = insert_after_soi(
            BASE,
            segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x02\x02" + b"\x00" * 12),  # 2x2 thumbnail
            segment(0xE1, xmp),
            segment(0xE1, b"http://ns.adobe.com/xmp/extension/\x00zzz"),
            segment(0xE2, b"MPF\x00" + b"\x00" * 8),
            segment(0xED, b"Photoshop 3.0\x008BIM"),
            segment(0xFE, b"hello from my laptop"),
        )
        result = inspect_bytes(data)
        for label in ("XMP", "XMP (extended)", "MPF", "IPTC/Photoshop", "JPEG comment", "JFIF"):
            self.assertIn(label, result.markers)
        for flag in ("GPS location (XMP)", "Owner/author name (XMP)", "Device serial number (XMP)",
                     "JFIF thumbnail", "Free-text JPEG comment"):
            self.assertIn(flag, result.risk_flags)
        self.assertIn("JPEG comment: hello from my laptop", result.extra_details)
        self.assertTrue(any("Multi-picture" in f for f in result.risk_flags))
        self.assertTrue(any("IPTC/Photoshop" in f for f in result.risk_flags))

    def test_clean_image_reports_nothing_sensitive(self):
        result = inspect_bytes(fixture("rgb_progressive.jpg"))
        self.assertEqual(result.risk_flags, [])
        self.assertEqual(result.exif_tags, [])
        self.assertEqual(len(result.sha256), 64)
        self.assertEqual(len(result.image_digest), 64)

    def test_image_digest_ignores_metadata_but_not_pixels(self):
        plain = inspect_bytes(BASE)
        with_meta = inspect_bytes(insert_after_soi(BASE, segment(0xE1, helpers.rich_exif()), segment(0xFE, b"x")))
        self.assertEqual(plain.image_digest, with_meta.image_digest)
        self.assertNotEqual(plain.sha256, with_meta.sha256)
        other = inspect_bytes(fixture("rgb_progressive.jpg"))
        self.assertNotEqual(plain.image_digest, other.image_digest)


if __name__ == "__main__":
    unittest.main()
