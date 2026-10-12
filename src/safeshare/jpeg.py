"""Small standard-library JPEG marker and EXIF inspector for SafeShare.

This module deliberately avoids Pillow because the project currently requires
third-party libraries to use the MIT license.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


class JPEGFormatError(ValueError):
    """Raised when the input does not look like a supported JPEG stream."""


@dataclass(frozen=True)
class Marker:
    code: int
    start: int
    end: int
    payload: bytes


@dataclass
class Inspection:
    path: str
    file_size: int
    markers: list[str]
    exif_tags: list[str]
    exif_details: list[str]
    warnings: list[str]

    @property
    def has_metadata(self) -> bool:
        return bool(self.markers or self.exif_tags)


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
    0x013E: "WhitePoint", 0x013F: "PrimaryChromaticities", 0x0211: "YCbCrCoefficients",
    0x0213: "YCbCrPositioning", 0x0214: "ReferenceBlackWhite", 0x8298: "Copyright",
    0x829A: "ExposureTime", 0x829D: "FNumber", 0x83BB: "IPTC/NAA",
    0x8649: "ImageResources", 0x8769: "ExifIFDPointer", 0x8773: "InterColorProfile",
    0x8822: "ExposureProgram", 0x8824: "SpectralSensitivity", 0x8825: "GPSInfoIFDPointer",
    0x8827: "ISOSpeedRatings", 0x8828: "OECF", 0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized", 0x9101: "ComponentsConfiguration",
    0x9102: "CompressedBitsPerPixel", 0x9201: "ShutterSpeedValue", 0x9202: "ApertureValue",
    0x9203: "BrightnessValue", 0x9204: "ExposureBiasValue", 0x9205: "MaxApertureValue",
    0x9206: "SubjectDistance", 0x9207: "MeteringMode", 0x9208: "LightSource",
    0x9209: "Flash", 0x920A: "FocalLength", 0x927C: "MakerNote",
    0x9286: "UserComment", 0x9290: "SubSecTime", 0x9291: "SubSecTimeOriginal",
    0x9292: "SubSecTimeDigitized", 0xA000: "FlashpixVersion", 0xA001: "ColorSpace",
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


def _marker_name(code: int) -> str:
    if 0xE0 <= code <= 0xEF:
        return f"APP{code - 0xE0}"
    if code == 0xFE:
        return "COM"
    return f"0xFF{code:02X}"


def _iter_markers(data: bytes):
    """Yield marker segments from a JPEG, including markers between scans."""
    if len(data) < 4 or data[:2] != b"\xff\xd8":
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

        # SOI, EOI, TEM and restart markers have no length field.
        if code in (0xD8, 0xD9, 0x01) or 0xD0 <= code <= 0xD7:
            yield Marker(code, start, pos, b"")
            if code == 0xD9:
                return
            continue

        if pos + 2 > size:
            raise JPEGFormatError("Truncated JPEG segment length.")
        length = int.from_bytes(data[pos:pos + 2], "big")
        if length < 2 or pos + length > size:
            raise JPEGFormatError("Invalid or truncated JPEG segment.")
        payload_start = pos + 2
        segment_end = pos + length
        payload = data[payload_start:segment_end]
        yield Marker(code, start, segment_end, payload)
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
                # FF00 is a stuffed data byte; restart markers are scan data.
                if next_code == 0x00 or 0xD0 <= next_code <= 0xD7:
                    pos = cursor + 1
                    continue
                pos = marker_start
                break

    # Reaching EOF is not equivalent to finding the JPEG End Of Image marker.
    # In particular, FF D9 bytes inside a length-delimited payload must not count.
    raise JPEGFormatError("JPEG is missing the EOI marker.")


def _read_exif_tags(payload: bytes) -> tuple[list[str], list[str], list[str]]:
    """Parse EXIF directory entries; values are bounded and rendered for local review."""
    if not payload.startswith(b"Exif\x00\x00"):
        return [], [], []
    tiff = payload[6:]
    warnings: list[str] = []
    if len(tiff) < 8:
        return [], [], ["EXIF TIFF header is truncated."]
    endian_mark = tiff[:2]
    if endian_mark == b"II":
        endian = "little"
    elif endian_mark == b"MM":
        endian = "big"
    else:
        return [], [], ["EXIF byte order is invalid."]
    if int.from_bytes(tiff[2:4], endian) != 42:
        return [], [], ["EXIF TIFF signature is invalid."]

    def u16(offset: int) -> int:
        if offset < 0 or offset + 2 > len(tiff):
            raise ValueError
        return int.from_bytes(tiff[offset:offset + 2], endian)

    def u32(offset: int) -> int:
        if offset < 0 or offset + 4 > len(tiff):
            raise ValueError
        return int.from_bytes(tiff[offset:offset + 4], endian)

    type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
    tags_found: set[str] = set()
    details: list[str] = []
    visited: set[int] = set()

    def render_value(typ: int, count: int, value_offset: int, inline_offset: int) -> str:
        if typ not in type_sizes or count > 128:
            return "[value omitted: unsupported type or large field]"
        total = type_sizes[typ] * count
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
            values = [int.from_bytes(raw[i:i+2], endian, signed=(typ == 8)) for i in range(0, total, 2)]
        elif typ in (4, 9):
            values = [int.from_bytes(raw[i:i+4], endian, signed=(typ == 9)) for i in range(0, total, 4)]
        elif typ in (5, 10):
            values = []
            for i in range(0, total, 8):
                numerator = int.from_bytes(raw[i:i+4], endian, signed=(typ == 10))
                denominator = int.from_bytes(raw[i+4:i+8], endian, signed=(typ == 10))
                values.append(f"{numerator}/{denominator}" if denominator else f"{numerator}/0")
        elif typ in (11, 12):
            return f"[{count} floating-point value(s) omitted]"
        else:
            return "[unsupported value type]"
        return ", ".join(str(v) for v in values[:16]) + (" …" if len(values) > 16 else "")

    def walk_ifd(offset: int, depth: int = 0, gps: bool = False) -> None:
        if depth > 4 or offset in visited:
            return
        visited.add(offset)
        try:
            count = u16(offset)
            if count > 4096 or offset + 2 + count * 12 + 4 > len(tiff):
                warnings.append("An EXIF directory is malformed or truncated.")
                return
            for i in range(count):
                entry = offset + 2 + i * 12
                tag = u16(entry)
                typ = u16(entry + 2)
                n = u32(entry + 4)
                names = GPS_TAG_NAMES if gps else TAG_NAMES
                name = names.get(tag, f"UnknownTag_0x{tag:04X}")
                tags_found.add(name)
                if tag in (0x8769, 0x8825, 0xA005):
                    name = names.get(tag, {0x8769: "ExifIFDPointer", 0x8825: "GPSInfoIFDPointer", 0xA005: "InteroperabilityIFDPointer"}[tag])
                try:
                    total = type_sizes.get(typ, 0) * n
                    value_offset = u32(entry + 8) if total > 4 else entry + 8
                    value = render_value(typ, n, value_offset, entry + 8)
                    # Do not print binary maker notes or large opaque fields as content.
                    if tag in (0x927C, 0x83BB, 0x8649, 0xA005) or (typ == 7 and n > 16):
                        value = f"[{n} opaque byte(s)]"
                    details.append(f"{name}: {value}")
                except (ValueError, OverflowError):
                    details.append(f"{name}: [unreadable value]")
                if typ == 4 and n == 1 and tag in (0x8769, 0x8825, 0xA005):
                    child = u32(entry + 8)
                    walk_ifd(child, depth + 1, gps=(tag == 0x8825))
            next_ifd = u32(offset + 2 + count * 12)
            if next_ifd:
                walk_ifd(next_ifd, depth + 1, gps=gps)
        except ValueError:
            warnings.append("An EXIF directory contains out-of-range offsets.")

    try:
        first_ifd = u32(4)
        if first_ifd:
            walk_ifd(first_ifd)
    except ValueError:
        warnings.append("EXIF IFD offset is invalid.")

    # Derive decimal coordinates when standard GPS rational fields are available.
    by_name = {}
    for item in details:
        if ": " in item:
            key, val = item.split(": ", 1)
            by_name[key] = val
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
        lat = dms(by_name["GPSLatitude"])
        lon = dms(by_name["GPSLongitude"])
        if by_name.get("GPSLatitudeRef", "N").strip().upper().startswith("S"):
            lat = -lat
        if by_name.get("GPSLongitudeRef", "E").strip().upper().startswith("W"):
            lon = -lon
        details.append(f"GPS coordinates (decimal): {lat:.6f}, {lon:.6f}")
    except (KeyError, ValueError, ZeroDivisionError):
        pass

    return sorted(tags_found), details, warnings


def inspect_jpeg(path: str | Path) -> Inspection:
    file_path = Path(path)
    data = file_path.read_bytes()
    found_markers: set[str] = set()
    exif_tags: set[str] = set()
    exif_details: list[str] = []
    warnings: list[str] = []
    for marker in _iter_markers(data):
        if 0xE0 <= marker.code <= 0xEF:
            found_markers.add(_marker_name(marker.code))
            if marker.code == 0xE1:
                if marker.payload.startswith(b"Exif\x00\x00"):
                    found_markers.add("EXIF")
                    tags, details, tag_warnings = _read_exif_tags(marker.payload)
                    exif_tags.update(tags)
                    exif_details.extend(details)
                    warnings.extend(tag_warnings)
                elif marker.payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                    found_markers.add("XMP")
            elif marker.code == 0xED:
                found_markers.add("IPTC/Photoshop")
            elif marker.code == 0xE2 and marker.payload.startswith(b"ICC_PROFILE\x00"):
                found_markers.add("ICC profile")
        elif marker.code == 0xFE:
            found_markers.add("JPEG comment")
    return Inspection(
        path=str(file_path),
        file_size=len(data),
        markers=sorted(found_markers),
        exif_tags=sorted(exif_tags),
        exif_details=exif_details,
        warnings=warnings,
    )


def sanitize_jpeg(source: str | Path, destination: str | Path) -> Inspection:
    """Strip all APP0–APP15 and COM segments, preserving compressed image data."""
    src = Path(source)
    dst = Path(destination)
    if src.resolve() == dst.resolve():
        raise ValueError("The output path must differ from the original file.")

    data = src.read_bytes()
    chunks = [data[:2]]
    last_end = 2
    removed = 0
    for marker in _iter_markers(data):
        if marker.start < last_end:
            continue
        chunks.append(data[last_end:marker.start])
        if 0xE0 <= marker.code <= 0xEF or marker.code == 0xFE:
            removed += 1
        else:
            chunks.append(data[marker.start:marker.end])
        last_end = marker.end
    chunks.append(data[last_end:])
    output = b"".join(chunks)
    if not output.startswith(b"\xff\xd8") or b"\xff\xd9" not in output:
        raise JPEGFormatError("The JPEG appears incomplete; refusing to write output.")

    dst.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids accidentally overwriting an existing file.
    with dst.open("xb") as handle:
        handle.write(output)

    result = inspect_jpeg(dst)
    result.warnings.append(f"Sanitization removed {removed} APP/COM marker segment(s).")
    return result
