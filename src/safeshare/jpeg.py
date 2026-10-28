"""Standard-library JPEG inspector and metadata sanitizer for SafeShare.

Design notes
------------
* No third-party code is used. Pillow is deliberately avoided because the
  project requires its runtime dependencies to be MIT-licensed.
* Sanitization is **allow-list based**: the output is rebuilt from the
  segments required to decode the picture (quantisation/Huffman tables, frame
  and scan headers, restart interval, ...) plus the entropy-coded image data,
  copied byte for byte. Everything else (APPn, COM, reserved and unknown
  markers) is dropped unless a privacy mode explicitly keeps a rebuilt,
  minimal replacement.
* Data appended after the EOI marker (Motion Photo videos, MPF secondary
  images, vendor trailers, ...) is detected, reported and, by default,
  removed instead of making the file unprocessable.
* Every sanitized output is verified *before* it is written to disk: the
  structural/pixel-data digest must be identical to the source, no
  disallowed segment may remain, and a raw byte-signature scan that does not
  rely on the parser must come back clean. The result is then written to a
  temporary file in the destination folder and moved into place atomically,
  so a failed run never leaves a half-written file behind.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import re
import secrets
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

#: Refuse to load files larger than this (the whole file is processed in memory).
MAX_FILE_SIZE = 256 * 1024 * 1024


class JPEGFormatError(ValueError):
    """Raised when the input does not look like a supported JPEG stream."""


class VerificationError(RuntimeError):
    """Raised when a sanitized output does not pass post-conditions.

    No output file is created when this error is raised.
    """

    def __init__(self, message: str, result: "SanitizeResult | None" = None) -> None:
        super().__init__(message)
        self.result = result


class PrivacyMode(str, Enum):
    #: Remove everything that is not needed to decode the picture.
    MAXIMUM = "maximum"
    #: Like MAXIMUM, but keep the ICC colour profile and a rebuilt,
    #: minimal EXIF block that contains only the Orientation flag.
    BALANCED = "balanced"


@dataclass(frozen=True)
class SanitizeOptions:
    mode: PrivacyMode = PrivacyMode.BALANCED
    strip_trailing_data: bool = True


@dataclass(frozen=True)
class Marker:
    code: int
    start: int       # first byte of the marker (including any 0xFF fill bytes)
    end: int         # first byte after the segment
    payload: bytes
    gap_start: int   # end of the previous segment; data[gap_start:start] is entropy-coded data


@dataclass
class ParsedJPEG:
    data: bytes
    markers: list[Marker]
    eoi_end: int

    @property
    def trailing_size(self) -> int:
        return len(self.data) - self.eoi_end


@dataclass
class TrailingData:
    offset: int
    size: int
    kinds: list[str]


@dataclass
class Inspection:
    path: str
    file_size: int
    markers: list[str]
    exif_tags: list[str]
    exif_details: list[str]
    warnings: list[str]
    sha256: str = ""
    image_digest: str = ""
    risk_flags: list[str] = field(default_factory=list)
    extra_details: list[str] = field(default_factory=list)
    orientation: int | None = None
    trailing: TrailingData | None = None

    @property
    def has_metadata(self) -> bool:
        return bool(self.markers or self.exif_tags or self.trailing)


@dataclass
class Verification:
    pixel_identical: bool
    source_sha256: str
    output_sha256: str
    image_digest: str
    residual: list[str] = field(default_factory=list)
    signature_hits: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.pixel_identical and not self.residual and not self.signature_hits

    def problems(self) -> list[str]:
        found = []
        if not self.pixel_identical:
            found.append("image data differs from the source")
        found.extend(f"disallowed content remains: {item}" for item in self.residual)
        found.extend(f"raw signature found in output: {item}" for item in self.signature_hits)
        return found


@dataclass
class SanitizeResult:
    before: Inspection
    after: Inspection
    verification: Verification
    removed: list[str]
    notes: list[str]
    options: SanitizeOptions
    output_path: str | None = None


@dataclass
class ExifInfo:
    tags: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    orientation: int | None = None
    has_thumbnail: bool = False
    thumbnail_size: int = 0


# --------------------------------------------------------------------------
# Tag tables
# --------------------------------------------------------------------------

# Common TIFF/EXIF tag names. Unknown tags are still reported by numeric ID.
TAG_NAMES = {
    0x00FE: "NewSubfileType", 0x00FF: "SubfileType", 0x0100: "ImageWidth",
    0x0101: "ImageLength", 0x0102: "BitsPerSample", 0x0103: "Compression",
    0x0106: "PhotometricInterpretation", 0x010E: "ImageDescription",
    0x010F: "Make", 0x0110: "Model", 0x0111: "StripOffsets",
    0x0112: "Orientation", 0x0115: "SamplesPerPixel", 0x0116: "RowsPerStrip",
    0x0117: "StripByteCounts", 0x011A: "XResolution", 0x011B: "YResolution",
    0x011C: "PlanarConfiguration", 0x0128: "ResolutionUnit", 0x012D: "TransferFunction",
    0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
    0x013E: "WhitePoint", 0x013F: "PrimaryChromaticities",
    0x0201: "JPEGInterchangeFormat", 0x0202: "JPEGInterchangeFormatLength",
    0x0211: "YCbCrCoefficients",
    0x0213: "YCbCrPositioning", 0x0214: "ReferenceBlackWhite", 0x8298: "Copyright",
    0x829A: "ExposureTime", 0x829D: "FNumber", 0x83BB: "IPTC/NAA",
    0x8649: "ImageResources", 0x8769: "ExifIFDPointer", 0x8773: "InterColorProfile",
    0x8822: "ExposureProgram", 0x8824: "SpectralSensitivity", 0x8825: "GPSInfoIFDPointer",
    0x8827: "ISOSpeedRatings", 0x8828: "OECF", 0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime", 0x9011: "OffsetTimeOriginal", 0x9012: "OffsetTimeDigitized",
    0x9101: "ComponentsConfiguration",
    0x9102: "CompressedBitsPerPixel", 0x9201: "ShutterSpeedValue", 0x9202: "ApertureValue",
    0x9203: "BrightnessValue", 0x9204: "ExposureBiasValue", 0x9205: "MaxApertureValue",
    0x9206: "SubjectDistance", 0x9207: "MeteringMode", 0x9208: "LightSource",
    0x9209: "Flash", 0x920A: "FocalLength", 0x927C: "MakerNote",
    0x9286: "UserComment", 0x9290: "SubSecTime", 0x9291: "SubSecTimeOriginal",
    0x9292: "SubSecTimeDigitized",
    0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords", 0x9C9F: "XPSubject",
    0xA000: "FlashpixVersion", 0xA001: "ColorSpace",
    0xA002: "PixelXDimension", 0xA003: "PixelYDimension", 0xA004: "RelatedSoundFile",
    0xA005: "InteroperabilityIFDPointer", 0xA20B: "FlashEnergy", 0xA20C: "SpatialFrequencyResponse",
    0xA20E: "FocalPlaneXResolution", 0xA20F: "FocalPlaneYResolution", 0xA210: "FocalPlaneResolutionUnit",
    0xA214: "SubjectLocation", 0xA215: "ExposureIndex", 0xA217: "SensingMethod",
    0xA300: "FileSource", 0xA301: "SceneType", 0xA302: "CFAPattern",
    0xA401: "CustomRendered", 0xA402: "ExposureMode", 0xA403: "WhiteBalance",
    0xA404: "DigitalZoomRatio", 0xA405: "FocalLengthIn35mmFilm", 0xA406: "SceneCaptureType",
    0xA407: "GainControl", 0xA408: "Contrast", 0xA409: "Saturation", 0xA40A: "Sharpness",
    0xA40B: "DeviceSettingDescription", 0xA40C: "SubjectDistanceRange", 0xA420: "ImageUniqueID",
    0xA430: "CameraOwnerName", 0xA431: "BodySerialNumber", 0xA432: "LensSpecification",
    0xA433: "LensMake", 0xA434: "LensModel", 0xA435: "LensSerialNumber",
    0xA460: "CompositeImage", 0xA461: "SourceImageNumberOfCompositeImage",
    0xA462: "SourceExposureTimesOfCompositeImage",
}
GPS_TAG_NAMES = {
    0x0000: "GPSVersionID", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude", 0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude", 0x0007: "GPSTimeStamp", 0x0008: "GPSSatellites",
    0x0009: "GPSStatus", 0x000A: "GPSMeasureMode", 0x000B: "GPSDOP",
    0x000C: "GPSSpeedRef", 0x000D: "GPSSpeed", 0x000E: "GPSTrackRef",
    0x000F: "GPSTrack", 0x0010: "GPSImgDirectionRef", 0x0011: "GPSImgDirection",
    0x0012: "GPSMapDatum", 0x0013: "GPSDestLatitudeRef", 0x0014: "GPSDestLatitude",
    0x0015: "GPSDestLongitudeRef", 0x0016: "GPSDestLongitude", 0x0017: "GPSDestBearingRef",
    0x0018: "GPSDestBearing", 0x0019: "GPSDestDistanceRef", 0x001A: "GPSDestDistance",
    0x001B: "GPSProcessingMethod", 0x001C: "GPSAreaInformation", 0x001D: "GPSDateStamp",
    0x001E: "GPSDifferential", 0x001F: "GPSHPositioningError",
}

# Tag name -> human-readable privacy risk.
_EXIF_RISKS = {
    "Make": "Camera make/model", "Model": "Camera make/model",
    "Software": "Software used",
    "DateTime": "Capture date/time", "DateTimeOriginal": "Capture date/time",
    "DateTimeDigitized": "Capture date/time",
    "OffsetTime": "Capture date/time", "OffsetTimeOriginal": "Capture date/time",
    "Artist": "Owner/author name", "CameraOwnerName": "Owner/author name",
    "XPAuthor": "Owner/author name", "Copyright": "Owner/author name",
    "BodySerialNumber": "Device serial number", "LensSerialNumber": "Device serial number",
    "ImageUniqueID": "Unique image ID",
    "ImageDescription": "Free-text description", "UserComment": "Free-text description",
    "XPComment": "Free-text description", "XPTitle": "Free-text description",
    "XPSubject": "Free-text description", "XPKeywords": "Free-text description",
    "MakerNote": "Manufacturer MakerNote (may contain serial numbers)",
}
_OPAQUE_TAGS = frozenset({0x927C, 0x83BB, 0x8649, 0x8773})
_XP_TAGS = frozenset({0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F})

_XMP_RISKS = {
    "GPSLatitude": "GPS location (XMP)", "GPSLongitude": "GPS location (XMP)",
    "SerialNumber": "Device serial number (XMP)", "InternalSerialNumber": "Device serial number (XMP)",
    "LensSerialNumber": "Device serial number (XMP)",
    "OwnerName": "Owner/author name (XMP)", "CameraOwnerName": "Owner/author name (XMP)",
    "creator": "Owner/author name (XMP)", "Creator": "Owner/author name (XMP)",
    "CreatorTool": "Software used (XMP)",
    "CreateDate": "Capture date/time (XMP)", "DateTimeOriginal": "Capture date/time (XMP)",
    "City": "Place names (XMP)", "Country": "Place names (XMP)",
    "Location": "Place names (XMP)", "Sublocation": "Place names (XMP)",
    "DocumentID": "Unique document IDs (XMP)", "InstanceID": "Unique document IDs (XMP)",
    "OriginalDocumentID": "Unique document IDs (XMP)",
    "History": "Editing history (XMP)",
}

# --------------------------------------------------------------------------
# Marker classification
# --------------------------------------------------------------------------

_SOF_CODES = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                        0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF})
# Segments needed to decode the picture. Everything else is metadata-like.
# DHT, DAC, DQT, DRI, DNL, DHP, EXP, SOS, EOI (+ every SOFn).
_STRUCTURAL = _SOF_CODES | frozenset({0xC4, 0xCC, 0xDB, 0xDD, 0xDC, 0xDE, 0xDF, 0xDA, 0xD9})

_ICC_PREFIX = b"ICC_PROFILE\x00"
_EXIF_PREFIX = b"Exif\x00\x00"
_XMP_PREFIX = b"http://ns.adobe.com/xap/1.0/\x00"
_XMP_EXT_PREFIX = b"http://ns.adobe.com/xmp/extension/\x00"
_PHOTOSHOP_PREFIX = b"Photoshop 3.0\x00"
_CANONICAL_ADOBE_HEAD = b"Adobe\x00\x64\x00\x00\x00\x00"  # version 100, flags 0/0


def _primary_label(marker: Marker) -> str:
    code, payload = marker.code, marker.payload
    if code == 0xFE:
        return "JPEG comment"
    if 0xE0 <= code <= 0xEF:
        generic = f"APP{code - 0xE0}"
        if code == 0xE0:
            if payload.startswith(b"JFIF\x00"):
                return "JFIF"
            if payload.startswith(b"JFXX\x00"):
                return "JFIF extension"
        elif code == 0xE1:
            if payload.startswith(_EXIF_PREFIX):
                return "EXIF"
            if payload.startswith(_XMP_PREFIX):
                return "XMP"
            if payload.startswith(_XMP_EXT_PREFIX):
                return "XMP (extended)"
        elif code == 0xE2:
            if payload.startswith(_ICC_PREFIX):
                return "ICC profile"
            if payload.startswith(b"MPF\x00"):
                return "MPF"
            if payload.startswith(b"FPXR\x00"):
                return "Flashpix"
        elif code == 0xED:
            if payload.startswith(_PHOTOSHOP_PREFIX):
                return "IPTC/Photoshop"
        elif code == 0xEE:
            if payload.startswith(b"Adobe"):
                return "Adobe"
        return generic
    return f"0xFF{code:02X}"


def _labels(marker: Marker) -> list[str]:
    primary = _primary_label(marker)
    if 0xE0 <= marker.code <= 0xEF:
        generic = f"APP{marker.code - 0xE0}"
        return [generic] if primary == generic else [generic, primary]
    return [primary]


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def _iter_markers(data: bytes):
    """Yield marker segments from a JPEG, including markers between scans.

    Iteration ends at the EOI marker. Anything after EOI is *not* validated
    here; callers decide what to do with it.
    """
    if len(data) < 2 or data[:2] != b"\xff\xd8":
        raise JPEGFormatError("File does not start with the JPEG SOI marker.")

    pos = 2
    size = len(data)
    while pos < size:
        if data[pos] != 0xFF:
            raise JPEGFormatError(f"Expected JPEG marker at byte offset {pos}.")
        start = pos
        while pos < size and data[pos] == 0xFF:
            pos += 1
        if pos >= size:
            raise JPEGFormatError("Truncated JPEG marker.")
        code = data[pos]
        pos += 1

        if code == 0x00:
            raise JPEGFormatError("Stuffed JPEG byte found outside image data.")
        if code == 0xD8:
            raise JPEGFormatError("Unexpected JPEG SOI marker.")
        if 0xD0 <= code <= 0xD7:
            raise JPEGFormatError("JPEG restart marker found outside image data.")

        # EOI and TEM have no length field. Restart markers are handled only
        # while scanning entropy-coded image data.
        if code in (0xD9, 0x01):
            yield Marker(code, start, pos, b"", 0)
            if code == 0xD9:
                return
            continue

        if pos + 2 > size:
            raise JPEGFormatError("Truncated JPEG segment length.")
        length = int.from_bytes(data[pos:pos + 2], "big")
        if length < 2:
            raise JPEGFormatError("Invalid JPEG segment length (minimum is 2 bytes).")
        if pos + length > size:
            raise JPEGFormatError("Truncated JPEG segment payload.")
        payload_start = pos + 2
        segment_end = pos + length
        payload = data[payload_start:segment_end]
        if code == 0xDA:
            if length < 8 or payload[0] == 0 or length != 6 + 2 * payload[0]:
                raise JPEGFormatError("Invalid or truncated JPEG scan header.")
        elif code in _SOF_CODES:
            if length < 11 or payload[5] == 0 or length != 8 + 3 * payload[5]:
                raise JPEGFormatError("Invalid or truncated JPEG frame header.")
        yield Marker(code, start, segment_end, payload, 0)
        pos = segment_end

        if code == 0xDA:  # Start of Scan: entropy-coded data follows.
            while pos < size:
                marker_start = data.find(b"\xff", pos)
                if marker_start < 0:
                    raise JPEGFormatError("JPEG scan has no terminating marker.")
                cursor = marker_start + 1
                while cursor < size and data[cursor] == 0xFF:
                    cursor += 1
                if cursor >= size:
                    raise JPEGFormatError("Truncated marker in JPEG scan.")
                next_code = data[cursor]
                fill_count = cursor - marker_start - 1
                if next_code == 0x00:
                    if fill_count:
                        raise JPEGFormatError("Unexpected JPEG fill byte in image data.")
                    pos = cursor + 1
                    continue
                # Restart markers belong to the entropy-coded scan, not to
                # the outer marker stream.
                if 0xD0 <= next_code <= 0xD7:
                    pos = cursor + 1
                    continue
                pos = marker_start
                break

    # Reaching EOF is not equivalent to finding the JPEG End Of Image marker.
    # In particular, FF D9 bytes inside a length-delimited payload must not count.
    raise JPEGFormatError("JPEG is missing the EOI marker.")


def parse_jpeg(data: bytes) -> ParsedJPEG:
    """Validate the marker structure and return the parsed segments."""
    markers: list[Marker] = []
    previous_end = 2
    eoi_end = None
    for marker in _iter_markers(data):
        markers.append(Marker(marker.code, marker.start, marker.end, marker.payload, previous_end))
        previous_end = marker.end
        if marker.code == 0xD9:
            eoi_end = marker.end
    if eoi_end is None:  # pragma: no cover - _iter_markers raises first
        raise JPEGFormatError("JPEG is missing the EOI marker.")
    return ParsedJPEG(data=data, markers=markers, eoi_end=eoi_end)


def _components(parsed: ParsedJPEG) -> int | None:
    for marker in parsed.markers:
        if marker.code in _SOF_CODES:
            return marker.payload[5]
    return None


def _image_digest(parsed: ParsedJPEG) -> str:
    """SHA-256 over every byte needed to decode the picture, in file order."""
    digest = hashlib.sha256()
    digest.update(b"\xff\xd8")
    for marker in parsed.markers:
        digest.update(parsed.data[marker.gap_start:marker.start])
        if marker.code in _STRUCTURAL:
            digest.update(parsed.data[marker.start:marker.end])
    return digest.hexdigest()


def _classify_trailing(tail: bytes) -> list[str]:
    if not tail.strip(b"\x00"):
        return ["zero padding"]
    kinds: list[str] = []
    embedded = tail.count(b"\xff\xd8\xff")
    if embedded:
        kinds.append(f"{embedded} embedded JPEG image(s) (preview, depth map or MPF secondary image)")
    ftyp = tail.find(b"ftyp")
    if 0 < ftyp <= len(tail) - 4:
        kinds.append("embedded video (e.g. Motion Photo)")
    if b"SEFT" in tail[-256:] or b"SEFH" in tail:
        kinds.append("Samsung extension data (SEF)")
    if b"http://ns.adobe.com/" in tail:
        kinds.append("embedded XMP")
    if not kinds:
        kinds.append("unrecognised data")
    return kinds


# --------------------------------------------------------------------------
# EXIF
# --------------------------------------------------------------------------

_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


def _parse_exif(payload: bytes) -> ExifInfo:
    """Parse EXIF directory entries; values are bounded and rendered for local review."""
    info = ExifInfo()
    if not payload.startswith(_EXIF_PREFIX):
        return info
    tiff = payload[6:]
    if len(tiff) < 8:
        info.warnings.append("EXIF TIFF header is truncated.")
        return info
    endian_mark = tiff[:2]
    if endian_mark == b"II":
        endian = "little"
    elif endian_mark == b"MM":
        endian = "big"
    else:
        info.warnings.append("EXIF byte order is invalid.")
        return info
    if int.from_bytes(tiff[2:4], endian) != 42:
        info.warnings.append("EXIF TIFF signature is invalid.")
        return info

    def u16(offset: int) -> int:
        if offset < 0 or offset + 2 > len(tiff):
            raise ValueError
        return int.from_bytes(tiff[offset:offset + 2], endian)

    def u32(offset: int) -> int:
        if offset < 0 or offset + 4 > len(tiff):
            raise ValueError
        return int.from_bytes(tiff[offset:offset + 4], endian)

    tags_found: set[str] = set()
    visited: set[int] = set()
    gps_values: dict[str, str] = {}
    ifd1_values: dict[int, int] = {}
    budget = [20000]

    def raw_bytes(typ: int, count: int, value_offset: int, inline_offset: int) -> bytes | None:
        total = _TYPE_SIZES.get(typ, 0) * count
        off = inline_offset if total <= 4 else value_offset
        if total == 0 or off < 0 or off + total > len(tiff):
            return None
        return tiff[off:off + total]

    def render_value(tag: int, typ: int, count: int, value_offset: int, inline_offset: int) -> str:
        if tag in _XP_TAGS and typ == 1 and count <= 2048:
            raw = raw_bytes(typ, count, value_offset, inline_offset)
            if raw is not None:
                return raw.decode("utf-16-le", errors="replace").rstrip("\x00")[:256] or "(empty)"
        if tag == 0x9286 and typ == 7 and count > 8 and count <= 2048:
            raw = raw_bytes(typ, count, value_offset, inline_offset)
            if raw is not None:
                charset, body = raw[:8], raw[8:]
                if charset.startswith(b"ASCII"):
                    return body.decode("ascii", errors="replace").rstrip("\x00 ")[:256] or "(empty)"
                if charset.startswith(b"UNICODE"):
                    codec = "utf-16-be" if endian == "big" else "utf-16-le"
                    return body.decode(codec, errors="replace").rstrip("\x00 ")[:256] or "(empty)"
                return f"[{count} byte(s), charset not decoded]"
        if typ not in _TYPE_SIZES or count > 128:
            return "[value omitted: unsupported type or large field]"
        total = _TYPE_SIZES[typ] * count
        off = inline_offset if total <= 4 else value_offset
        if off < 0 or off + total > len(tiff):
            return "[invalid value offset]"
        raw = tiff[off:off + total]
        if typ == 2:
            return raw.split(b"\x00", 1)[0][:256].decode("utf-8", errors="replace") or "(empty)"
        if typ in (1, 6, 7):
            if count <= 16:
                return raw.hex(" ")
            return f"[{count} bytes]"
        if typ in (3, 8):
            values = [int.from_bytes(raw[i:i + 2], endian, signed=(typ == 8)) for i in range(0, total, 2)]
        elif typ in (4, 9):
            values = [int.from_bytes(raw[i:i + 4], endian, signed=(typ == 9)) for i in range(0, total, 4)]
        elif typ in (5, 10):
            values = []
            for i in range(0, total, 8):
                numerator = int.from_bytes(raw[i:i + 4], endian, signed=(typ == 10))
                denominator = int.from_bytes(raw[i + 4:i + 8], endian, signed=(typ == 10))
                values.append(f"{numerator}/{denominator}")
        elif typ in (11, 12):
            return f"[{count} floating-point value(s) omitted]"
        else:  # pragma: no cover - guarded by _TYPE_SIZES
            return "[unsupported value type]"
        return ", ".join(str(v) for v in values[:16]) + (" …" if len(values) > 16 else "")

    def walk(offset: int, kind: str, depth: int = 0) -> None:
        if depth > 4 or offset in visited:
            return
        visited.add(offset)
        try:
            count = u16(offset)
            if count > 4096 or offset + 2 + count * 12 + 4 > len(tiff):
                info.warnings.append("An EXIF directory is malformed or truncated.")
                return
            for i in range(count):
                budget[0] -= 1
                if budget[0] < 0:
                    info.warnings.append("EXIF contains too many entries; parsing stopped.")
                    return
                entry = offset + 2 + i * 12
                tag = u16(entry)
                typ = u16(entry + 2)
                n = u32(entry + 4)
                names = GPS_TAG_NAMES if kind == "gps" else TAG_NAMES
                name = names.get(tag, f"UnknownTag_0x{tag:04X}")
                tags_found.add(name)
                try:
                    total = _TYPE_SIZES.get(typ, 0) * n
                    value_offset = u32(entry + 8) if total > 4 else entry + 8
                    value = render_value(tag, typ, n, value_offset, entry + 8)
                    # Do not print binary maker notes or large opaque fields as content.
                    if tag in _OPAQUE_TAGS or (typ == 7 and n > 16 and tag != 0x9286):
                        value = f"[{n} opaque byte(s)]"
                    info.details.append(f"{name}: {value}")
                    if kind == "gps":
                        gps_values[name] = value
                    if kind == "ifd0" and tag == 0x0112 and typ == 3 and n == 1:
                        candidate = u16(entry + 8)
                        if 1 <= candidate <= 8:
                            info.orientation = candidate
                    if kind == "ifd1" and tag in (0x0201, 0x0202) and typ == 4 and n == 1:
                        ifd1_values[tag] = u32(entry + 8)
                except (ValueError, OverflowError):
                    info.details.append(f"{name}: [unreadable value]")
                if typ == 4 and n == 1 and tag in (0x8769, 0x8825, 0xA005):
                    child_kind = {0x8769: "exif", 0x8825: "gps", 0xA005: "interop"}[tag]
                    walk(u32(entry + 8), child_kind, depth + 1)
            if kind == "ifd0":
                next_ifd = u32(offset + 2 + count * 12)
                if next_ifd:
                    walk(next_ifd, "ifd1", depth + 1)
        except ValueError:
            info.warnings.append("An EXIF directory contains out-of-range offsets.")

    try:
        first_ifd = u32(4)
        if first_ifd:
            walk(first_ifd, "ifd0")
    except ValueError:
        info.warnings.append("EXIF IFD offset is invalid.")

    if 0x0201 in ifd1_values or 0x0202 in ifd1_values:
        info.has_thumbnail = True
        info.thumbnail_size = ifd1_values.get(0x0202, 0)

    # Derive decimal coordinates when standard GPS rational fields are available.
    try:
        def dms(value: str) -> float:
            pieces = []
            for part in value.split(",")[:3]:
                n, d = part.strip().split("/", 1)
                denominator = float(d)
                if denominator == 0:
                    raise ValueError
                pieces.append(float(n) / denominator)
            if len(pieces) != 3:
                raise ValueError
            return pieces[0] + pieces[1] / 60 + pieces[2] / 3600
        lat = dms(gps_values["GPSLatitude"])
        lon = dms(gps_values["GPSLongitude"])
        if gps_values.get("GPSLatitudeRef", "N").strip().upper().startswith("S"):
            lat = -lat
        if gps_values.get("GPSLongitudeRef", "E").strip().upper().startswith("W"):
            lon = -lon
        info.details.append(f"GPS coordinates (decimal): {lat:.6f}, {lon:.6f}")
        info.flags.append("GPS location")
    except (KeyError, ValueError, ZeroDivisionError):
        if any(name.startswith("GPS") and name != "GPSVersionID" for name in tags_found):
            info.flags.append("GPS data")

    for name in tags_found:
        risk = _EXIF_RISKS.get(name)
        if risk:
            info.flags.append(risk)
    if info.has_thumbnail:
        info.flags.append("Embedded EXIF thumbnail (may show the uncropped original)")

    info.tags = sorted(tags_found)
    info.flags = sorted(set(info.flags))
    return info


def _read_exif_tags(payload: bytes) -> tuple[list[str], list[str], list[str]]:
    """Backward-compatible wrapper around :func:`_parse_exif`."""
    info = _parse_exif(payload)
    return info.tags, info.details, info.warnings


def _scan_xmp(payload: bytes) -> list[str]:
    """Return privacy-relevant field names mentioned in an XMP packet."""
    text = payload.decode("utf-8", errors="replace")
    found = []
    for key in _XMP_RISKS:
        if re.search(rf"(?<![A-Za-z]){key}(?![A-Za-z])", text):
            found.append(key)
    return found


# --------------------------------------------------------------------------
# Inspection
# --------------------------------------------------------------------------

def _inspect_parsed(parsed: ParsedJPEG, path: str) -> Inspection:
    found_markers: set[str] = set()
    exif_tags: set[str] = set()
    exif_details: list[str] = []
    warnings: list[str] = []
    risks: set[str] = set()
    extra: list[str] = []
    orientation: int | None = None

    for marker in parsed.markers:
        if marker.code in _STRUCTURAL:
            continue
        found_markers.update(_labels(marker))
        label = _primary_label(marker)
        if label == "EXIF":
            info = _parse_exif(marker.payload)
            exif_tags.update(info.tags)
            exif_details.extend(info.details)
            warnings.extend(info.warnings)
            risks.update(info.flags)
            if orientation is None:
                orientation = info.orientation
        elif label in ("XMP", "XMP (extended)"):
            names = _scan_xmp(marker.payload)
            extra.extend(f"{label} mentions: {name}" for name in names)
            risks.update(_XMP_RISKS[name] for name in names)
            risks.add("XMP packet (may hold author, location, editing history)")
        elif label == "IPTC/Photoshop":
            risks.add("IPTC/Photoshop block (may hold author, caption, location)")
        elif label == "MPF":
            risks.add("Multi-picture data (may point to extra embedded images)")
        elif label == "JPEG comment":
            text = marker.payload.decode("utf-8", errors="replace").strip("\x00")
            extra.append(f"JPEG comment: {text[:120]}" + ("…" if len(text) > 120 else ""))
            risks.add("Free-text JPEG comment")
        elif label == "JFIF" and len(marker.payload) >= 14 and marker.payload[12] * marker.payload[13] > 0:
            risks.add("JFIF thumbnail")
        elif label == "JFIF extension":
            risks.add("JFIF thumbnail")
        elif label == "Flashpix":
            risks.add("Flashpix data (may hold extra images or history)")

    trailing = None
    if parsed.trailing_size:
        tail = parsed.data[parsed.eoi_end:]
        trailing = TrailingData(parsed.eoi_end, parsed.trailing_size, _classify_trailing(tail))
        risks.add(f"Data appended after the image ({parsed.trailing_size:,} bytes)")

    return Inspection(
        path=path,
        file_size=len(parsed.data),
        markers=sorted(found_markers),
        exif_tags=sorted(exif_tags),
        exif_details=exif_details,
        warnings=warnings,
        sha256=hashlib.sha256(parsed.data).hexdigest(),
        image_digest=_image_digest(parsed),
        risk_flags=sorted(risks),
        extra_details=extra,
        orientation=orientation,
        trailing=trailing,
    )


def inspect_bytes(data: bytes, path: str = "") -> Inspection:
    return _inspect_parsed(parse_jpeg(data), path)


def _read_source(path: Path) -> bytes:
    if path.stat().st_size > MAX_FILE_SIZE:
        raise JPEGFormatError(
            f"File is larger than the {MAX_FILE_SIZE // (1024 * 1024)} MiB limit."
        )
    return path.read_bytes()


def inspect_jpeg(path: str | Path) -> Inspection:
    file_path = Path(path)
    return inspect_bytes(_read_source(file_path), str(file_path))


# --------------------------------------------------------------------------
# Sanitization
# --------------------------------------------------------------------------

def _segment(code: int, payload: bytes) -> bytes:
    length = len(payload) + 2
    if length > 0xFFFF:
        raise JPEGFormatError("Segment too large to rebuild.")
    return b"\xff" + bytes([code]) + length.to_bytes(2, "big") + payload


def _minimal_exif(orientation: int) -> bytes:
    """A 32-byte EXIF block that contains only the Orientation tag."""
    tiff = (
        b"MM\x00\x2a" + (8).to_bytes(4, "big")
        + (1).to_bytes(2, "big")
        + (0x0112).to_bytes(2, "big") + (3).to_bytes(2, "big")
        + (1).to_bytes(4, "big") + orientation.to_bytes(2, "big") + b"\x00\x00"
        + (0).to_bytes(4, "big")
    )
    return _EXIF_PREFIX + tiff


def _is_adobe_candidate(marker: Marker, components: int | None) -> bool:
    return (
        marker.code == 0xEE
        and marker.payload.startswith(b"Adobe")
        and len(marker.payload) == 12
        and components in (3, 4)
    )


def _is_canonical_adobe(marker: Marker, components: int | None) -> bool:
    return _is_adobe_candidate(marker, components) and marker.payload[:11] == _CANONICAL_ADOBE_HEAD


def _is_icc(marker: Marker) -> bool:
    return marker.code == 0xE2 and marker.payload.startswith(_ICC_PREFIX)


def _is_minimal_exif(marker: Marker) -> bool:
    if marker.code != 0xE1 or not marker.payload.startswith(_EXIF_PREFIX) or len(marker.payload) != 32:
        return False
    info = _parse_exif(marker.payload)
    return info.tags == ["Orientation"] and info.orientation is not None and info.orientation > 1


def _build_sanitized(
    parsed: ParsedJPEG, before: Inspection, options: SanitizeOptions
) -> tuple[bytes, list[str], list[str]]:
    data = parsed.data
    balanced = options.mode is PrivacyMode.BALANCED
    components = _components(parsed)
    removed: Counter[str] = Counter()
    notes: list[str] = []
    parts: list[bytes] = [b"\xff\xd8"]

    rebuilt_orientation = None
    if balanced and before.orientation is not None and before.orientation > 1:
        rebuilt_orientation = before.orientation
        parts.append(_segment(0xE1, _minimal_exif(rebuilt_orientation)))

    adobe_kept = False
    icc_kept = 0
    for marker in parsed.markers:
        parts.append(data[marker.gap_start:marker.start])
        if marker.code in _STRUCTURAL:
            parts.append(data[marker.start:marker.end])
            continue
        if balanced and _is_icc(marker):
            parts.append(_segment(marker.code, marker.payload))
            icc_kept += 1
            continue
        if not adobe_kept and _is_adobe_candidate(marker, components):
            # Only the colour-transform byte matters; everything else is rebuilt.
            parts.append(_segment(0xEE, _CANONICAL_ADOBE_HEAD + marker.payload[11:12]))
            adobe_kept = True
            continue
        if rebuilt_orientation and _is_minimal_exif(marker):
            continue  # our own minimal block from an earlier run: replaced, not removed
        removed[_primary_label(marker)] += 1

    if parsed.trailing_size:
        tail = data[parsed.eoi_end:]
        if options.strip_trailing_data:
            kinds = "; ".join(_classify_trailing(tail))
            removed[f"data after the image ({parsed.trailing_size:,} bytes: {kinds})"] += 1
        else:
            parts.append(tail)
            notes.append(
                f"Data appended after the image ({parsed.trailing_size:,} bytes) was kept at "
                "your request. It may contain hidden or private content."
            )

    if rebuilt_orientation:
        notes.append(
            "EXIF was replaced by a minimal block that keeps only the orientation flag, "
            "so the picture is not shown rotated."
        )
    if icc_kept:
        notes.append(
            "The ICC colour profile was kept unchanged. It normally describes only colours, "
            "but profile descriptions can name a device; use Maximum privacy to remove it."
        )
    if adobe_kept:
        notes.append(
            "A rebuilt 12-byte Adobe colour-transform flag was kept: without it, RGB/CMYK "
            "JPEGs decode with wrong colours. It carries no personal data."
        )
    if not balanced:
        if before.orientation is not None and before.orientation > 1:
            notes.append(
                "The EXIF orientation flag was removed, so some viewers may show this picture "
                "rotated. Balanced mode keeps it."
            )
        if "ICC profile" in before.markers:
            notes.append(
                "The ICC colour profile was removed; colours may look slightly different "
                "on some screens."
            )

    removed_list = [
        f"{label} ×{count}" if count > 1 else label for label, count in sorted(removed.items())
    ]
    return b"".join(parts), removed_list, notes


_SIGNATURES = (
    (b"Exif\x00\x00", "EXIF header"),
    (b"http://ns.adobe.com", "XMP / Adobe namespace"),
    (b"Photoshop 3.0\x00", "Photoshop/IPTC block"),
    (b"JFIF\x00", "JFIF header"),
    (b"JFXX\x00", "JFIF extension"),
    (b"FPXR\x00", "Flashpix header"),
    (b"ICC_PROFILE\x00", "ICC profile"),
)


def _verify(
    output: bytes,
    before: Inspection,
    after: Inspection,
    out_parsed: ParsedJPEG,
    options: SanitizeOptions,
) -> Verification:
    balanced = options.mode is PrivacyMode.BALANCED
    components = _components(out_parsed)
    residual: list[str] = []
    allowed_exif = 0
    allowed_icc = 0
    for marker in out_parsed.markers:
        if marker.code in _STRUCTURAL:
            continue
        if _is_canonical_adobe(marker, components):
            continue
        if balanced and _is_icc(marker):
            allowed_icc += 1
            continue
        if balanced and _is_minimal_exif(marker):
            allowed_exif += 1
            continue
        residual.append(_primary_label(marker))
    if options.strip_trailing_data and out_parsed.trailing_size:
        residual.append("data after the image")

    # Independent of the marker parser: scan the raw bytes for known signatures.
    expected = {b"Exif\x00\x00": allowed_exif, b"ICC_PROFILE\x00": allowed_icc}
    hits = []
    for signature, label in _SIGNATURES:
        if output.count(signature) > expected.get(signature, 0):
            hits.append(label)

    return Verification(
        pixel_identical=before.image_digest == after.image_digest,
        source_sha256=before.sha256,
        output_sha256=after.sha256,
        image_digest=after.image_digest,
        residual=sorted(set(residual)),
        signature_hits=hits,
    )


def sanitize_bytes(
    data: bytes, options: SanitizeOptions | None = None, path: str = ""
) -> tuple[bytes, SanitizeResult]:
    """Sanitize an in-memory JPEG. Raises before returning anything unverified."""
    options = options or SanitizeOptions()
    parsed = parse_jpeg(data)
    before = _inspect_parsed(parsed, path)
    output, removed, notes = _build_sanitized(parsed, before, options)
    try:
        out_parsed = parse_jpeg(output)
    except JPEGFormatError as exc:
        raise VerificationError(f"The sanitized output could not be parsed: {exc}") from exc
    after = _inspect_parsed(out_parsed, "")
    verification = _verify(output, before, after, out_parsed, options)
    result = SanitizeResult(before, after, verification, removed, notes, options)
    if not verification.passed:
        raise VerificationError(
            "Verification failed; no file was written: " + "; ".join(verification.problems()),
            result,
        )
    return output, result


def _write_new_file_atomically(destination: Path, data: bytes) -> None:
    """Write *data* to *destination* without ever exposing a partial file.

    The bytes go to a temporary file in the same folder first. The final step
    is a hard link (atomic and refuses to replace an existing file); on file
    systems without hard links it falls back to ``os.replace``.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(f".{destination.name}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(temp, flags, 0o666)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp, destination)
        except FileExistsError:
            raise
        except OSError:
            if os.path.lexists(destination):
                raise FileExistsError(f"{destination} already exists.") from None
            os.replace(temp, destination)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()


def sanitize_jpeg(
    source: str | Path, destination: str | Path, options: SanitizeOptions | None = None
) -> SanitizeResult:
    """Create a verified, sanitized copy of *source* at *destination*."""
    src = Path(source)
    dst = Path(destination)
    if src.resolve() == dst.resolve():
        raise ValueError("The output path must differ from the original file.")
    if os.path.lexists(dst):
        raise FileExistsError(f"{dst} already exists. SafeShare never overwrites files.")

    data = _read_source(src)
    # Everything is validated and verified in memory before touching the disk.
    output, result = sanitize_bytes(data, options, path=str(src))
    _write_new_file_atomically(dst, output)

    written = hashlib.sha256(dst.read_bytes()).hexdigest()
    if written != result.verification.output_sha256:
        with contextlib.suppress(OSError):
            dst.unlink()
        raise VerificationError("The file on disk differs from the verified output; it was removed.", result)
    result.output_path = str(dst)
    return result
