# Changelog

## 0.2.0

### Parser and sanitizer
- **Data after the EOI marker is handled instead of rejected.** Motion Photos, MPF
  secondary images and vendor trailers are detected, classified, reported and (by
  default) removed. Keeping them is an explicit opt-in.
- **Allow-list sanitization.** The output is rebuilt from the segments needed to
  decode the picture (DQT, DHT, DAC, DRI, DNL, DHP, EXP, SOFn, SOS) plus the
  entropy-coded data. APPn, COM, reserved and unknown markers are dropped.
- **Two privacy modes.** *Balanced* (default) keeps the ICC colour profile and a
  rebuilt 32-byte EXIF block containing only the Orientation flag, so photos are
  not shown rotated. *Maximum* removes everything and says what that may cost.
- **Adobe APP14 colour-transform flag** is kept (rebuilt canonically, 12 bytes) for
  3- and 4-component images in both modes, because dropping it corrupts RGB/CMYK
  colours. Everything else in APP14 is discarded.
- **Richer inspection:** embedded EXIF thumbnail, XMP and extended XMP, MPF,
  IPTC/Photoshop, JFIF thumbnails, MakerNote, serial numbers, owner names, Windows
  XP* tags and UserComment text, plus a plain-language "privacy risks" summary.
- **Independent verification, run before anything is written:** image-data digest
  must be identical, no disallowed segment may remain, and a raw byte-signature scan
  (which does not rely on the parser) must be clean. SHA-256 of source and output
  and the image-data digest are shown.
- **Atomic, never-overwrite writes** through a temporary file in the destination
  folder, followed by a read-back hash check. Failures leave nothing behind.
- 256 MiB input size limit; bounded EXIF parsing.

### Application
- Privacy-level selector and "remove hidden data" option in the UI.
- Command-line interface: `safeshare inspect FILE`, `safeshare clean FILE`.
- **Bug fix:** error dialogs in the UI raised `NameError` (the `except ... as exc`
  variable was used by a callback after it had been deleted). Worker threads now
  post results through a queue polled by the Tk main loop.

### Repository
- `.gitignore`; removed committed `__pycache__` and `egg-info`.
- `src/main.py` is now a real entry point.
- `requires-python` relaxed from `==3.12.*` to `>=3.10`.
- Tests grew from 7 to 65: real JPEG fixtures, decoded-pixel comparisons (when
  Pillow is present), deterministic fuzzing, a "network is blocked" test, CLI and
  report tests. CI runs them on Windows, macOS and Linux for Python 3.10–3.13.

## 0.1.0
- First MVP scaffold: JPEG marker/EXIF inspection and APP/COM removal.
