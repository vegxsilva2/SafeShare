# Test fixtures

Small synthetic JPEG files (gradients) used by the test suite. They contain no
personal data; the only segments they carry are those the encoder writes by
itself (JFIF, ICC profile, Adobe colour-transform flag).

They are regenerated with `python tests/tools/make_fixtures.py`, a
development-only helper that needs Pillow. Pillow is **not** a runtime
dependency of SafeShare and the tests run without it (pixel-by-pixel decoding
comparisons are simply skipped when Pillow is not installed).

Realistic metadata (GPS, serial numbers, thumbnails, XMP, ...) is synthesised
inside the tests by `tests/helpers.py`.
