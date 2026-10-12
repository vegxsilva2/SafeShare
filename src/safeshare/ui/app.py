from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

import customtkinter as ctk

from safeshare.jpeg import JPEGFormatError, inspect_jpeg, sanitize_jpeg


class SafeShareApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SafeShare")
        self.geometry("880x640")
        self.minsize(720, 520)
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.selected_path: Path | None = None
        self.last_inspection = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

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
        actions.grid(row=1, column=0, padx=18, pady=14, sticky="ew")
        actions.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(actions, text="Choose JPEG…", command=self.choose_file).grid(
            row=0, column=0, padx=10, pady=10
        )
        self.file_label = ctk.CTkLabel(
            actions, text="No file selected", anchor="w"
        )
        self.file_label.grid(row=0, column=1, padx=8, pady=10, sticky="ew")
        self.inspect_button = ctk.CTkButton(
            actions, text="Inspect", command=self.inspect_selected, state="disabled"
        )
        self.inspect_button.grid(row=0, column=2, padx=10, pady=10)
        self.clean_button = ctk.CTkButton(
            actions, text="Sanitize copy…", command=self.sanitize_selected,
            state="disabled"
        )
        self.clean_button.grid(row=0, column=3, padx=(0, 10), pady=10)

        content = ctk.CTkFrame(self)
        content.grid(row=2, column=0, padx=18, pady=(0, 14), sticky="nsew")
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
            "Choose a JPEG file to inspect its supported metadata. "
            "Sanitization creates a new file and leaves the original untouched.\n\n"
            "This MVP checks JPEG application markers and a broad set of EXIF fields. "
            "It does not inspect identifying information visible in the image itself."
        )

        self.status = ctk.CTkLabel(self, text="Ready · Processing stays on this device", anchor="w")
        self.status.grid(row=3, column=0, padx=22, pady=(0, 12), sticky="ew")

    def _set_report(self, text: str) -> None:
        self.report.configure(state="normal")
        self.report.delete("1.0", tk.END)
        self.report.insert("1.0", text)
        self.report.configure(state="disabled")

    def choose_file(self) -> None:
        chosen = filedialog.askopenfilename(
            title="Select a JPEG image",
            filetypes=[("JPEG images", "*.jpg *.jpeg"), ("All files", "*.*")]
        )
        if not chosen:
            return
        self.selected_path = Path(chosen)
        self.file_label.configure(text=self.selected_path.name)
        self.inspect_button.configure(state="normal")
        self.clean_button.configure(state="normal")
        self.last_inspection = None
        self._set_report(f"Selected file:\n{self.selected_path}\n\nClick Inspect to analyze supported metadata.")
        self.status.configure(text="File selected")

    def inspect_selected(self) -> None:
        if not self.selected_path:
            return
        self._busy(True, "Inspecting JPEG…")
        threading.Thread(target=self._inspect_worker, daemon=True).start()

    def _inspect_worker(self) -> None:
        try:
            result = inspect_jpeg(self.selected_path)
            report = self._format_report(result, "Inspection")
            self.after(0, lambda: self._inspection_done(result, report))
        except (OSError, JPEGFormatError, ValueError) as exc:
            self.after(0, lambda: self._error_done(str(exc)))

    def _inspection_done(self, result, report: str) -> None:
        self.last_inspection = result
        self._set_report(report)
        self._busy(False, "Inspection complete")

    def sanitize_selected(self) -> None:
        if not self.selected_path:
            return
        source = self.selected_path
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
        threading.Thread(
            target=self._sanitize_worker, args=(source, destination), daemon=True
        ).start()

    def _sanitize_worker(self, source: Path, destination: Path) -> None:
        try:
            before = inspect_jpeg(source)
            after = sanitize_jpeg(source, destination)
            report = self._format_comparison(before, after, destination)
            self.after(0, lambda: self._sanitize_done(report, destination))
        except FileExistsError:
            self.after(0, lambda: self._error_done(
                "The destination already exists. No file was overwritten."
            ))
        except (OSError, JPEGFormatError, ValueError) as exc:
            self.after(0, lambda: self._error_done(str(exc)))

    def _sanitize_done(self, report: str, destination: Path) -> None:
        self._set_report(report)
        self._busy(False, f"Sanitized copy saved: {destination.name}")

    def _error_done(self, error: str) -> None:
        self._busy(False, "Operation failed")
        messagebox.showerror("SafeShare", error)

    def _busy(self, busy: bool, status: str) -> None:
        state = "disabled" if busy else ("normal" if self.selected_path else "disabled")
        self.inspect_button.configure(state=state)
        self.clean_button.configure(state=state)
        self.status.configure(text=status)

    @staticmethod
    def _format_report(result, title: str) -> str:
        lines = [
            title,
            "=" * len(title),
            f"File: {Path(result.path).name}",
            f"Size: {result.file_size:,} bytes",
            "",
            "Detected metadata markers:",
        ]
        lines.extend(f"  • {item}" for item in result.markers) if result.markers else lines.append("  None detected by this scanner.")
        lines += ["", f"EXIF fields detected ({len(result.exif_tags)}):"]
        lines.extend(f"  • {tag}" for tag in result.exif_tags) if result.exif_tags else lines.append("  No EXIF fields detected.")
        if result.exif_details:
            lines += ["", "EXIF values (sensitive values may appear here):"]
            lines.extend(f"  • {item}" for item in result.exif_details)
        if result.warnings:
            lines += ["", "Warnings:"] + [f"  • {warning}" for warning in result.warnings]
        lines += [
            "", "Interpretation:",
            "This report covers supported JPEG metadata structures only. "
            "It does not prove that the image contains no identifying information."
        ]
        return "\n".join(lines)

    @staticmethod
    def _format_comparison(before, after, destination: Path) -> str:
        lines = [
            "Sanitization and verification",
            "=============================",
            f"Output: {destination}",
            f"Output size: {after.file_size:,} bytes",
            "",
            f"Before — detected markers: {', '.join(before.markers) if before.markers else 'none'}",
            f"Before — EXIF fields: {', '.join(before.exif_tags) if before.exif_tags else 'none'}",
            f"After  — detected markers: {', '.join(after.markers) if after.markers else 'none'}",
            f"After  — EXIF fields: {', '.join(after.exif_tags) if after.exif_tags else 'none'}",
            "",
            "Verification result:",
        ]
        if not after.markers and not after.exif_tags:
            lines.append("PASS — no supported APP/COM metadata markers or recognized EXIF tags were detected in the output.")
        else:
            lines.append("REVIEW — supported metadata markers or EXIF tags remain in the output.")
        lines += [
            "",
            "Limitations:",
            "• This checks metadata structures supported by the current MVP only.",
            "• It does not inspect faces, text, landmarks, or other visible content.",
            "• EXIF values can include sensitive personal data; avoid sharing screenshots of this report publicly.",
            "• Sanitization removes all JPEG APP0–APP15 and COM segments, which can also remove useful non-private information.",
        ]
        if after.warnings:
            lines += ["", "Warnings:"] + [f"• {warning}" for warning in after.warnings]
        return "\n".join(lines)


def main() -> None:
    app = SafeShareApp()
    app.mainloop()
