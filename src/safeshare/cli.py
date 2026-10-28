"""Command-line interface (standard library only)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from safeshare import __version__
from safeshare.jpeg import (
    JPEGFormatError,
    PrivacyMode,
    SanitizeOptions,
    VerificationError,
    inspect_jpeg,
    sanitize_jpeg,
)
from safeshare.report import format_inspection, format_sanitization


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safeshare",
        description="Inspect and remove identifying metadata from JPEG files. "
        "Run without arguments to open the desktop application.",
    )
    parser.add_argument("--version", action="version", version=f"SafeShare {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect", help="show the metadata found in a JPEG file")
    inspect.add_argument("file", type=Path)

    clean = sub.add_parser("clean", help="write a sanitized, verified copy of a JPEG file")
    clean.add_argument("file", type=Path)
    clean.add_argument("-o", "--output", type=Path,
                       help="output path (default: <name>_safeshare.jpg next to the original)")
    clean.add_argument("--mode", choices=[m.value for m in PrivacyMode], default=PrivacyMode.BALANCED.value,
                       help="balanced keeps the colour profile and orientation; "
                            "maximum removes everything (default: balanced)")
    clean.add_argument("--keep-trailing-data", action="store_true",
                       help="keep data stored after the end of the image (not recommended)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            print(format_inspection(inspect_jpeg(args.file)))
            return 0

        output = args.output or args.file.with_name(f"{args.file.stem}_safeshare.jpg")
        options = SanitizeOptions(
            mode=PrivacyMode(args.mode), strip_trailing_data=not args.keep_trailing_data
        )
        print(format_sanitization(sanitize_jpeg(args.file, output, options)))
        return 0
    except VerificationError as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        return 3
    except (OSError, JPEGFormatError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
