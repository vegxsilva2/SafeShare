"""Plain-text reports shared by the desktop UI and the command line.

Kept free of any GUI import so it can be unit-tested everywhere.
"""
from __future__ import annotations

from pathlib import Path

from safeshare.jpeg import Inspection, PrivacyMode, SanitizeResult

MODE_LABELS = {
    PrivacyMode.BALANCED: "Balanced (recommended)",
    PrivacyMode.MAXIMUM: "Maximum privacy",
}


def _bullets(items, empty: str) -> list[str]:
    items = list(items)
    return [f"  • {item}" for item in items] if items else [f"  {empty}"]


def format_inspection(result: Inspection, title: str = "Inspection") -> str:
    lines = [
        title,
        "=" * len(title),
        f"File: {Path(result.path).name}" if result.path else "File: (in memory)",
        f"Size: {result.file_size:,} bytes",
        f"SHA-256: {result.sha256}",
        "",
        "Privacy risks found:",
    ]
    lines += _bullets(result.risk_flags, "None of the known risks were detected by this scanner.")
    lines += ["", "Detected metadata markers:"]
    lines += _bullets(result.markers, "None detected by this scanner.")
    lines += ["", f"EXIF fields detected ({len(result.exif_tags)}):"]
    lines += _bullets(result.exif_tags, "No EXIF fields detected.")
    if result.exif_details:
        lines += ["", "EXIF values (sensitive values may appear here):"]
        lines += [f"  • {item}" for item in result.exif_details]
    if result.extra_details:
        lines += ["", "Other embedded details:"]
        lines += [f"  • {item}" for item in result.extra_details]
    if result.trailing:
        lines += [
            "",
            f"Data stored after the end of the image ({result.trailing.size:,} bytes):",
        ]
        lines += [f"  • {kind}" for kind in result.trailing.kinds]
        lines.append("  Sanitizing removes it by default; it can hide a video, extra photos or private data.")
    if result.warnings:
        lines += ["", "Warnings:"] + [f"  • {warning}" for warning in result.warnings]
    lines += [
        "",
        "Interpretation:",
        "This report covers supported JPEG metadata structures only. "
        "It does not prove that the image contains no identifying information.",
    ]
    return "\n".join(lines)


def _check(ok: bool, text: str) -> str:
    return f"  {'✔' if ok else '✘'} {text}"


def format_sanitization(result: SanitizeResult) -> str:
    before, after, check = result.before, result.after, result.verification
    lines = [
        "Sanitization and verification",
        "=============================",
        f"Output: {result.output_path}" if result.output_path else "Output: (in memory)",
        f"Mode: {MODE_LABELS[result.options.mode]}",
        f"Output size: {after.file_size:,} bytes (original: {before.file_size:,} bytes)",
        "",
        "Removed:",
    ]
    lines += _bullets(result.removed, "Nothing: the file had no removable metadata.")
    if result.notes:
        lines += ["", "Please note:"] + [f"  • {note}" for note in result.notes]
    lines += [
        "",
        f"Before — markers: {', '.join(before.markers) if before.markers else 'none'}",
        f"Before — EXIF fields: {', '.join(before.exif_tags) if before.exif_tags else 'none'}",
        f"After  — markers: {', '.join(after.markers) if after.markers else 'none'}",
        f"After  — EXIF fields: {', '.join(after.exif_tags) if after.exif_tags else 'none'}",
        "",
        "Verification (done before the file was written):",
        _check(check.pixel_identical, "Image data is byte-for-byte identical to the original."),
        _check(not check.residual, "No metadata segments other than the allowed ones remain."),
        _check(not check.signature_hits, "A raw byte scan (independent of the parser) found no metadata signatures."),
        "",
        f"Original SHA-256:  {check.source_sha256}",
        f"Sanitized SHA-256: {check.output_sha256}",
        f"Image-data digest: {check.image_digest}",
        "",
        "Result: " + (
            "PASS — the sanitized copy contains the same picture data and no unexpected metadata."
            if check.passed else "REVIEW — " + "; ".join(check.problems())
        ),
        "",
        "Limitations:",
        "• Only the metadata structures supported by this version are checked.",
        "• It does not inspect faces, text, landmarks or other visible content.",
        "• EXIF values can include sensitive personal data; avoid sharing screenshots of this report.",
        "• File names and file-system dates are not changed.",
    ]
    return "\n".join(lines)
