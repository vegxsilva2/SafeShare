# SafeShare

**Inspect. Sanitize. Verify. Share with confidence.**

SafeShare is an open-source, privacy-focused desktop application that helps users inspect JPEG files for potentially identifying metadata, create a sanitized copy, and inspect the result again.

## Current status

This is the first MVP scaffold. The initial implementation supports JPEG metadata-marker inspection and removal. It does not yet guarantee removal of every possible identifying trace, and it does not yet support PNG, PDF, or DOCX.

## Features

- Inspect JPEG files without uploading them anywhere.
- Identify EXIF tags such as camera make/model, timestamps, and GPS fields when the EXIF structure can be parsed.
- Detect XMP/IPTC-related application markers and JPEG comment markers.
- Create a sanitized copy without modifying the original.
- Re-inspect the output and report remaining supported metadata markers.
- Local-only processing; no telemetry or network functionality.

## Requirements

- Python 3.12.2
- CustomTkinter (MIT license)

The JPEG parser and EXIF inspection code use the Python standard library. Pillow is intentionally not used because its license is not MIT; this keeps third-party runtime dependencies aligned with the project's strict MIT-only dependency goal. Python itself is distributed under the PSF License, not MIT.

## Run from source

```bash
py -3.12.2 -m venv .venv
```

Activate the environment:

**Windows PowerShell**
```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m safeshare
```

**Linux/macOS**
```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m safeshare
```

If your Python launcher does not recognize `-3.12.2`, invoke the exact Python 3.12.2 executable directly when creating the virtual environment.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Important limitations

- The initial version targets JPEG files only.
- Sanitization removes JPEG APP0–APP15 segments and COM segments from the JPEG marker stream. This is intentionally conservative and may remove useful non-private metadata or application-specific information.
- JPEG files with malformed marker sequences, truncated segments, invalid lengths, missing EOI markers, or trailing data are rejected before a sanitized output is created.
- JPEG files with otherwise unsupported structures may also be rejected rather than modified.
- Verification reports the metadata classes and EXIF tags this version can parse. It is not proof that the image content itself contains no identifying information.
- The application does not currently perform face/plate detection, OCR, or visual-content anonymization.

## License

The project source is intended to be released under the MIT License. Third-party components retain their own licenses. CustomTkinter is distributed under the MIT License; Python uses the PSF License.
