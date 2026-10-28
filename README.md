# SafeShare

**Inspect. Sanitize. Verify. Share with confidence.**

SafeShare is an open-source, privacy-focused desktop application (with a command-line mode) that finds identifying metadata in JPEG photos, creates a sanitized copy, and **proves** the copy still holds exactly the same picture and no leftover metadata, before saving it.

Everything runs locally. There is no telemetry and no network code (a test enforces it).

## Current status

Version 0.2.0 supports **JPEG only**. PNG, PDF and Office documents are not supported yet. See [CHANGELOG.md](CHANGELOG.md) for what changed since the first scaffold.

## What it does

- **Inspects** a JPEG without uploading it anywhere and summarises the privacy risks in plain language: GPS location, camera make/model, capture date, owner or author name, device serial numbers, free-text comments, embedded EXIF thumbnails (which can show the uncropped original), XMP, IPTC/Photoshop blocks, multi-picture (MPF) data, and **data hidden after the end of the image** (Motion Photo videos, secondary images, vendor trailers).
- **Sanitizes** into a *new* file; the original is never modified and an existing file is never overwritten.
- **Verifies** the result before writing it:
  1. the picture data (tables, frame/scan headers and compressed image bytes) is byte-for-byte identical to the original (SHA-256 digest);
  2. no metadata segment other than the explicitly allowed ones remains;
  3. a raw byte scan that does not depend on the parser finds no metadata signatures.

  If any check fails nothing is written. The report shows the SHA-256 of the original and of the copy.
- Writes through a temporary file and an atomic move, then re-reads the file and checks its hash, so a crash or full disk never leaves a half-written photo.

### Privacy levels

| | Balanced (default) | Maximum privacy |
|---|---|---|
| EXIF (GPS, camera, dates, names, serials, thumbnail, MakerNote) | removed | removed |
| XMP, IPTC/Photoshop, MPF, JFIF, comments, unknown segments | removed | removed |
| Data after the end of the image | removed* | removed* |
| ICC colour profile | kept unchanged | removed (colours may shift slightly) |
| Orientation flag | kept, rebuilt as a minimal 32-byte EXIF block | removed (some photos may appear rotated) |
| Adobe colour-transform flag (RGB/CMYK JPEGs) | kept, rebuilt (12 bytes, no personal data) | kept, rebuilt |

\* unless you choose to keep it (`--keep-trailing-data` / the checkbox in the app).

Sanitization is **allow-list based**: only the segments needed to decode the picture (quantisation and Huffman tables, frame and scan headers, restart interval, and so on) plus the compressed image data are copied. Everything else is dropped by default, including segment types this version does not know.

## Requirements

- Python 3.10 or newer (the test suite is run locally on 3.11, 3.12 and 3.13; CI also covers 3.10)
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) 5.2.2 (MIT) for the desktop interface. The inspector, sanitizer and command line use only the Python standard library.

Pillow is intentionally **not** used: its licence is not MIT, and the project keeps its runtime dependencies MIT-only. Python itself is distributed under the PSF License.

## Run from source

```bash
python -m venv .venv
```

Activate the environment, then install the dependency and start the app:

**Windows PowerShell**
```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python src\main.py
```

**Linux/macOS**
```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python src/main.py
```

Optionally install it as a package (`python -m pip install -e .`) to get the `safeshare` command and `python -m safeshare`.

### Command line

```bash
python src/main.py inspect photo.jpg
python src/main.py clean photo.jpg                     # writes photo_safeshare.jpg
python src/main.py clean photo.jpg -o out.jpg --mode maximum
python src/main.py clean photo.jpg --keep-trailing-data
```

Exit codes: `0` success, `1` error (invalid file, file exists, ...), `2` usage error, `3` verification failed (no file written).

## Run tests

```bash
python -m unittest discover -s tests -v
```

The suite covers malformed and truncated files, real JPEG fixtures (baseline, progressive, grayscale, restart markers, ICC, CMYK/Adobe), synthesised EXIF/XMP/MPF metadata, deterministic fuzzing of thousands of corrupted files, verification failures, atomic writes, the CLI, and a check that processing works with the network blocked. If Pillow happens to be installed, tests also decode the original and sanitized files and compare the pixels. Pillow is never required.

## Important limitations

- JPEG only for now.
- Verification covers the metadata structures this version parses. It is not proof that the picture itself contains nothing identifying: faces, licence plates, text, landmarks and shadows are not analysed.
- MakerNote blocks are removed but their contents are not decoded; the report only says they *may* contain serial numbers.
- The ICC profile kept in Balanced mode normally describes colours only, but a profile's description text can name a device. Use Maximum privacy to drop it.
- File names and file-system dates are not changed.
- Files with malformed marker sequences, truncated segments, invalid lengths or a missing EOI marker are rejected rather than repaired. Files above 256 MiB are rejected.

## License

SafeShare is released under the [MIT License](LICENSE). Third-party components retain their own licenses: CustomTkinter is MIT; Python uses the PSF License.
