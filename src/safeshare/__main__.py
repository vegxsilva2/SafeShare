from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        from safeshare.cli import main as cli_main

        return cli_main(argv)
    try:
        from safeshare.ui.app import main as gui_main
    except ImportError as exc:  # customtkinter / tkinter not available
        print(
            f"The desktop interface needs CustomTkinter and tkinter ({exc}).\n"
            "The command line still works: python -m safeshare --help",
            file=sys.stderr,
        )
        return 1
    gui_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
