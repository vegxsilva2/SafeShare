"""Regenerate the small JPEG fixtures used by the tests.

Development-only helper. It needs Pillow, which is NOT a runtime dependency
of SafeShare (Pillow's licence is not MIT). The generated images are synthetic
gradients; they contain no personal data.

    python tests/tools/make_fixtures.py
"""
from __future__ import annotations

import io
from pathlib import Path

from PIL import Image, ImageCms

OUT = Path(__file__).resolve().parent.parent / "fixtures"
W, H = 32, 24


def _image(mode: str) -> Image.Image:
    im = Image.new(mode, (W, H))
    px = im.load()
    for x in range(W):
        for y in range(H):
            if mode == "RGB":
                px[x, y] = ((x * 8) % 256, (y * 10) % 256, ((x * y) // 2) % 256)
            elif mode == "CMYK":
                px[x, y] = ((x * 8) % 256, (y * 10) % 256, 0, (x + y) % 64)
            else:
                px[x, y] = (x * 7 + y * 3) % 256
    return im


def _save(name: str, im: Image.Image, **kwargs) -> None:
    buffer = io.BytesIO()
    im.save(buffer, "JPEG", **kwargs)
    (OUT / name).write_bytes(buffer.getvalue())
    print(f"{name}: {buffer.tell()} bytes")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    srgb = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    _save("rgb_baseline.jpg", _image("RGB"), quality=80)
    _save("rgb_progressive.jpg", _image("RGB"), quality=80, progressive=True)
    _save("rgb_icc.jpg", _image("RGB"), quality=80, icc_profile=srgb)
    _save("gray.jpg", _image("L"), quality=80)
    _save("cmyk_adobe.jpg", _image("CMYK"), quality=80)
    _save("rgb_restart.jpg", _image("RGB"), quality=80, restart_marker_blocks=2)


if __name__ == "__main__":
    main()
