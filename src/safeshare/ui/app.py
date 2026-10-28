from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from safeshare.jpeg import (
    JPEGFormatError,
    PrivacyMode,
    SanitizeOptions,
    VerificationError,
    inspect_jpeg,
    sanitize_jpeg,
)
from safeshare.report import MODE_LABELS, format_inspection, format_sanitization

MODE_HELP = {
    PrivacyMode.BALANCED: (
        "Removes location, camera, dates, comments and hidden data. Keeps the colour profile "
        "and the rotation flag so the photo looks the same."
    ),
    PrivacyMode.MAXIMUM: (
        "Removes everything that is not needed to display the picture. Colours may shift "
        "slightly and some photos may appear rotated."
    ),
}
LABEL_TO_MODE = {label: mode for mode, label in MODE_LABELS.items()}


class SafeShareApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SafeShare")
        self.geometry("900x700")
        self.minsize(740, 560)
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.selected_path: Path | None = None
        self.last_inspection = None
        # Worker threads never touch Tk: they post results here and the main
        # thread polls the queue.
        self._results: queue.Queue = queue.Queue()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(self, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header, text="SafeShare", font=ctk.CTkFont(size=28, weight="bold")
        ).grid(row=0, column=0, padx=24, pady=(18, 2), sticky="w")
        ctk.CTkLabel(
            header, text="Inspect. Sanitize. Verify. Share with confidence.",
            font=ctk.CTkFont(size=13)
        ).grid(row=1, column=0, padx=24, pady=(0, 18), sticky="w")

        actions = ctk.CTkFrame(self)
        actions.grid(row=1, column=0, padx=18, pady=(14, 8), sticky="ew")
        actions.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(actions, text="Choose JPEG…", command=self.choose_file).grid(
            row=0, column=0, padx=10, pady=10
        )
        self.file_label = ctk.CTkLabel(actions, text="No file selected", anchor="w")
        self.file_label.grid(row=0, column=1, padx=8, pady=10, sticky="ew")
        self.inspect_button = ctk.CTkButton(
            actions, text="Inspect", command=self.inspect_selected, state="disabled"
        )
        self.inspect_button.grid(row=0, column=2, padx=10, pady=10)
        self.clean_button = ctk.CTkButton(
            actions, text="Sanitize copy…", command=self.sanitize_selected, state="disabled"
        )
        self.clean_button.grid(row=0, column=3, padx=(0, 10), pady=10)

        options = ctk.CTkFrame(self)
        options.grid(row=2, column=0, padx=18, pady=(0, 8), sticky="ew")
        options.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(options, text="Privacy level:").grid(row=0, column=0, padx=(12, 8), pady=(10, 2), sticky="w")
        self.mode_button = ctk.CTkSegmentedButton(
            options, values=list(LABEL_TO_MODE), command=self._mode_changed
        )
        self.mode_button.set(MODE_LABELS[PrivacyMode.BALANCED])
        self.mode_button.grid(row=0, column=1, padx=8, pady=(10, 2), sticky="w")
        self.mode_help = ctk.CTkLabel(
            options, text=MODE_HELP[PrivacyMode.BALANCED], anchor="w", justify="left", wraplength=780
        )
        self.mode_help.grid(row=1, column=0, columnspan=2, padx=12, pady=(0, 4), sticky="ew")
        self.strip_trailing = ctk.CTkCheckBox(
            options, text="Also remove data hidden after the end of the image (recommended)"
        )
        self.strip_trailing.select()
        self.strip_trailing.grid(row=2, column=0, columnspan=2, padx=12, pady=(0, 10), sticky="w")

        content = ctk.CTkFrame(self)
        content.grid(row=3, column=0, padx=18, pady=(0, 14), sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            content, text="Privacy inspection report",
            font=ctk.CTkFont(size=17, weight="bold")
        ).grid(row=0, column=0, padx=16, pady=(14, 8), sticky="w")
        self.report = ctk.CTkTextbox(content, wrap="word")
        self.report.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="nsew")
        self._set_report(
            "Welcome to SafeShare.\n\n"
            "Choose a JPEG file to inspect its metadata. "
            "Sanitization creates a new file, checks it before saving, and leaves the original untouched.\n\n"
            "This version checks JPEG segments, EXIF, XMP, comments and data hidden after the image. "
            "It does not inspect identifying information visible in the picture itself."
        )

        self.status = ctk.CTkLabel(self, text="Ready · Processing stays on this device", anchor="w")
        self.status.grid(row=4, column=0, padx=22, pady=(0, 12), sticky="ew")

        self.after(100, self._poll_results)

    # ----- helpers ---------------------------------------------------------

    def _set_report(self, text: str) -> None:
        self.report.configure(state="normal")
        self.report.delete("1.0", tk.END)
        self.report.insert("1.0", text)
        self.report.configure(state="disabled")

    def _current_options(self) -> SanitizeOptions:
        return SanitizeOptions(
            mode=LABEL_TO_MODE[self.mode_button.get()],
            strip_trailing_data=bool(self.strip_trailing.get()),
        )

    def _mode_changed(self, label: str) -> None:
        self.mode_help.configure(text=MODE_HELP[LABEL_TO_MODE[label]])

    def _busy(self, busy: bool, status: str) -> None:
        state = "disabled" if busy else ("normal" if self.selected_path else "disabled")
        self.inspect_button.configure(state=state)
        self.clean_button.configure(state=state)
        self.status.configure(text=status)

    def _run_in_background(self, work, on_success, on_success_status: str) -> None:
        def runner() -> None:
            try:
                self._results.put(("ok", work(), on_success, on_success_status))
            except VerificationError as exc:
                self._results.put(("error", f"The sanitized copy failed verification and was NOT saved.\n\n{exc}", None, ""))
            except (OSError, JPEGFormatError, ValueError) as exc:
                self._results.put(("error", str(exc), None, ""))
            except Exception as exc:  # never let a worker die silently
                self._results.put(("error", f"Unexpected error: {exc!r}", None, ""))

        threading.Thread(target=runner, daemon=True).start()

    def _poll_results(self) -> None:
        try:
            while True:
                kind, payload, on_success, status = self._results.get_nowait()
                if kind == "ok":
                    on_success(payload)
                    self._busy(False, status)
                else:
                    self._busy(False, "Operation failed")
                    messagebox.showerror("SafeShare", payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_results)

    # ----- actions -----------------------------------------------------------

    def choose_file(self) -> None:
        chosen = filedialog.askopenfilename(
            title="Select a JPEG image",
            filetypes=[("JPEG images", "*.jpg *.jpeg *.jpe"), ("All files", "*.*")]
        )
        if not chosen:
            return
        self.selected_path = Path(chosen)
        self.file_label.configure(text=self.selected_path.name)
        self.inspect_button.configure(state="normal")
        self.clean_button.configure(state="normal")
        self.last_inspection = None
        self._set_report(f"Selected file:\n{self.selected_path}\n\nClick Inspect to analyze its metadata.")
        self.status.configure(text="File selected")

    def inspect_selected(self) -> None:
        if not self.selected_path:
            return
        source = self.selected_path
        self._busy(True, "Inspecting JPEG…")
        self._run_in_background(
            lambda: inspect_jpeg(source), self._inspection_done, "Inspection complete"
        )

    def _inspection_done(self, result) -> None:
        self.last_inspection = result
        self._set_report(format_inspection(result))

    def sanitize_selected(self) -> None:
        if not self.selected_path:
            return
        source = self.selected_path
        options = self._current_options()
        suggested = source.with_name(f"{source.stem}_safeshare.jpg")
        chosen = filedialog.asksaveasfilename(
            title="Save sanitized copy",
            initialdir=str(suggested.parent),
            initialfile=suggested.name,
            defaultextension=".jpg",
            filetypes=[("JPEG images", "*.jpg")]
        )
        if not chosen:
            return
        destination = Path(chosen)
        if destination.exists():
            messagebox.showerror(
                "File already exists",
                "SafeShare will not overwrite an existing file. Choose a different filename."
            )
            return
        self._busy(True, "Sanitizing and verifying…")
        self._run_in_background(
            lambda: sanitize_jpeg(source, destination, options),
            self._sanitize_done,
            f"Sanitized copy saved: {destination.name}",
        )

    def _sanitize_done(self, result) -> None:
        self._set_report(format_sanitization(result))


def main() -> None:
    app = SafeShareApp()
    app.mainloop()
