"""Shared test helpers: path setup, fixtures and a tiny EXIF/TIFF writer."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

FIXTURES = ROOT / "tests" / "fixtures"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes([marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


def insert_after_soi(jpeg: bytes, *segments: bytes) -> bytes:
    """Put metadata segments right after SOI, like a camera would."""
    return jpeg[:2] + b"".join(segments) + jpeg[2:]


def pixels(jpeg: bytes) -> bytes | None:
    """Decode with Pillow when it is installed (it is optional, tests-only)."""
    try:
        import io

        from PIL import Image
    except ImportError:
        return None
    return Image.open(io.BytesIO(jpeg)).tobytes()


# --- minimal TIFF/EXIF writer -------------------------------------------------

def ascii_(text: str) -> tuple[int, int, bytes]:
    raw = text.encode("ascii") + b"\x00"
    return 2, len(raw), raw


def short(value: int, endian: str = "little") -> tuple[int, int, bytes]:
    return 3, 1, value.to_bytes(2, endian)


def undefined(raw: bytes) -> tuple[int, int, bytes]:
    return 7, len(raw), raw


def rationals(pairs, endian: str = "little") -> tuple[int, int, bytes]:
    raw = b"".join(n.to_bytes(4, endian) + d.to_bytes(4, endian) for n, d in pairs)
    return 5, len(pairs), raw


def build_exif(ifd0, exif=None, gps=None, thumbnail: bytes | None = None, endian: str = "little") -> bytes:
    """Build an APP1 'Exif' payload.

    Each IFD is a list of ``(tag, (type, count, raw_bytes))`` items.
    """
    bo = b"II" if endian == "little" else b"MM"

    def i(value: int, size: int) -> int | bytes:
        return value.to_bytes(size, endian)

    names = ["ifd0"]
    tables = {"ifd0": [(t, *v) for t, v in ifd0]}
    if exif is not None:
        names.append("exif")
        tables["exif"] = [(t, *v) for t, v in exif]
        tables["ifd0"].append((0x8769, 4, 1, None))
    if gps is not None:
        names.append("gps")
        tables["gps"] = [(t, *v) for t, v in gps]
        tables["ifd0"].append((0x8825, 4, 1, None))
    if thumbnail is not None:
        names.append("ifd1")
        tables["ifd1"] = [(0x0201, 4, 1, None), (0x0202, 4, 1, i(len(thumbnail), 4))]
    for name in names:
        tables[name].sort(key=lambda entry: entry[0])

    offsets = {}
    cursor = 8
    for name in names:
        offsets[name] = cursor
        cursor += 2 + 12 * len(tables[name]) + 4
    data = bytearray()
    data_start = cursor

    thumb_offset = None
    if thumbnail is not None:
        thumb_offset = data_start + len(data)
        data += thumbnail + (b"\x00" if len(thumbnail) % 2 else b"")

    body = bytearray()
    for name in names:
        entries = tables[name]
        body += i(len(entries), 2)
        for tag, typ, count, raw in entries:
            if raw is None:
                if tag == 0x8769:
                    raw = i(offsets["exif"], 4)
                elif tag == 0x8825:
                    raw = i(offsets["gps"], 4)
                elif tag == 0x0201:
                    raw = i(thumb_offset, 4)
            if len(raw) <= 4:
                value = raw + b"\x00" * (4 - len(raw))
            else:
                value = i(data_start + len(data), 4)
                data += raw + (b"\x00" if len(raw) % 2 else b"")
            body += i(tag, 2) + i(typ, 2) + i(count, 4) + value
        body += i(offsets["ifd1"] if name == "ifd0" and thumbnail is not None else 0, 4)

    tiff = bo + i(42, 2) + i(8, 4) + bytes(body) + bytes(data)
    return b"Exif\x00\x00" + tiff


def rich_exif(endian: str = "little", orientation: int = 6) -> bytes:
    """An EXIF block resembling a phone photo with plenty of identifying data."""
    return build_exif(
        ifd0=[
            (0x010F, ascii_("AcmeCam")),
            (0x0110, ascii_("Phone 9 Pro")),
            (0x0112, short(orientation, endian)),
            (0x0131, ascii_("AcmeOS 14.2")),
            (0x0132, ascii_("2026:03:14 09:26:53")),
            (0x013B, ascii_("Jane Q. Example")),
        ],
        exif=[
            (0x9003, ascii_("2026:03:14 09:26:53")),
            (0x927C, undefined(b"MAKERNOTE-SERIAL-123456789")),
            (0x9286, undefined(b"ASCII\x00\x00\x00meet me behind the station")),
            (0xA431, ascii_("SN-0042-0042")),
        ],
        gps=[
            (0x0001, ascii_("N")),
            (0x0002, rationals([(40, 1), (25, 1), (1234, 100)], endian)),
            (0x0003, ascii_("W")),
            (0x0004, rationals([(3, 1), (42, 1), (3000, 100)], endian)),
        ],
        thumbnail=b"\xff\xd8\xff\xd9",
        endian=endian,
    )
