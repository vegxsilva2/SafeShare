"""Entry point for ``python src/main.py`` and for freezing tools such as PyInstaller."""
from safeshare.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
