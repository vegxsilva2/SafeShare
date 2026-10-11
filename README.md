# ShareSafe

**Inspect. Sanitize. Verify. Share with confidence.**

ShareSafe is an open-source, privacy-focused desktop application designed to help users identify and remove sensitive metadata from files before sharing them.

Instead of blindly removing metadata, ShareSafe aims to provide a transparent workflow: inspect a file, understand what information it may reveal, generate a sanitized copy, and verify the result through a second analysis.

The goal is simple: make digital privacy accessible to everyone, without requiring technical knowledge or uploading personal files to external services.

> **Project status:** Early-stage concept / MVP in development. Features described below represent the intended design and may not yet be implemented.

## The Problem

Files often contain more information than their visible content suggests.

A photograph may reveal GPS coordinates, camera information, or the time it was taken. A document may expose its author's name, organization, comments, or internal properties.

This information can unintentionally disclose personal details, reveal a user's identity, or expose sensitive information about an organization.

Existing metadata removal tools address part of this problem, but users may still struggle to understand what was exposed, what was removed, and what information remains.

ShareSafe aims to make this process transparent and verifiable.

## Key Features

### 1. Privacy Inspection

Analyze supported files to identify potentially sensitive metadata and embedded information.

Planned detection targets include:

* GPS coordinates and location information.
* Camera and device metadata.
* Document author and organization properties.
* Comments and document properties.
* Other format-specific metadata that may expose sensitive information.

### 2. Metadata Sanitization

Generate a sanitized copy of the original file by removing supported metadata.

* Preserve the original file by default.
* Process files locally.
* Support batch processing.
* Report fields that could not be safely removed.

### 3. Post-Sanitization Verification

ShareSafe is designed to analyze the sanitized output again instead of assuming that the removal process was successful.

The verification report will distinguish between:

* **Removed:** Information detected before sanitization but not detected afterward.
* **Remaining:** Information that is still present.
* **Unverified:** Information that the tool cannot reliably inspect or assess.

This distinction is important: the absence of detected metadata does not guarantee that a file contains no identifying information.

### 4. Privacy-Focused Design

Privacy should be a property of the application itself.

The intended design follows these principles:

* Local processing by default.
* No account or cloud upload required for core functionality.
* No telemetry by default.
* No unnecessary collection of user data.
* Clear disclosure of limitations and unsupported file features.

### 5. Cross-Platform Support

The initial goal is to support:

* Windows
* macOS
* GNU/Linux

The application is intended to offer a simple graphical interface suitable for non-technical users.

## Supported File Formats

The initial MVP targets the following formats:

| Format | Planned inspection                                    | Planned sanitization |
| ------ | ----------------------------------------------------- | -------------------- |
| JPEG   | EXIF, GPS and other supported metadata                | Yes                  |
| PNG    | Textual metadata and supported ancillary chunks       | Yes                  |
| PDF    | Document properties and supported metadata structures | Yes                  |
| DOCX   | Core properties and supported document metadata       | Yes                  |

Support will depend on the specific features implemented and tested for each format. Complex documents may contain additional information that cannot be safely removed without modifying their content.

## How It Works

The intended workflow consists of five steps:

1. **Select:** Choose one or more files.
2. **Inspect:** Analyze their metadata and identify potential privacy risks.
3. **Review:** Understand what information may be exposed.
4. **Sanitize:** Generate a cleaned copy of each supported file.
5. **Verify:** Re-analyze the output and display the results.

The original file remains untouched unless the user explicitly chooses otherwise.

## Architecture

ShareSafe is planned as a modular application with independent components for analysis, sanitization, and verification.

```text
ShareSafe
├── User Interface
│   ├── File Selection
│   ├── Privacy Findings
│   └── Verification Report
├── Analysis Engine
│   ├── Format Detection
│   ├── Metadata Extractors
│   └── Risk Classification
├── Sanitization Engine
│   ├── Format-Specific Sanitizers
│   └── Safe Output Generation
├── Verification Engine
│   ├── Post-Sanitization Analysis
│   └── Before/After Comparison
└── Reporting
    ├── Privacy Summary
    └── Export Results
```

Each format handler should explicitly define which metadata fields it can inspect, which fields it can remove, and which limitations apply.

## Technology Stack

The initial implementation is expected to use:

* **Python** for the core application logic.
* **PySide6** for the desktop graphical interface.
* **Format-specific libraries and tools** for metadata inspection and sanitization.
* **Automated tests** to validate file handling and sanitization results.
* **Reproducible build and packaging workflows** for supported operating systems.

Dependencies will be evaluated for security, maintenance status, compatibility, and license compatibility before inclusion.

## Security and Privacy Principles

ShareSafe is intended to follow a privacy-first development approach.

* **Data minimization:** Process only the information necessary for the requested operation.
* **Local-first operation:** Avoid transferring user files to external services.
* **Safe file handling:** Treat input files as untrusted and handle malformed files carefully.
* **Non-destructive processing:** Preserve the original file by default.
* **Transparent results:** Never claim complete privacy when the tool cannot verify it.
* **Testable guarantees:** Validate sanitization behavior using automated tests and deliberately crafted sample files.

ShareSafe does not aim to replace digital forensics, comprehensive document inspection, or professional security assessments.

## Roadmap

### Phase 1 — MVP

* [ ] Build the desktop interface.
* [ ] Implement file selection and batch processing.
* [ ] Add initial JPEG, PNG, PDF, and DOCX analysis.
* [ ] Implement format-specific sanitization.
* [ ] Add post-sanitization verification.
* [ ] Generate clear before-and-after reports.
* [ ] Create automated tests with known metadata fixtures.

### Phase 2 — Security and Reliability

* [ ] Test malformed and adversarial input files.
* [ ] Expand metadata coverage and document limitations.
* [ ] Add regression tests for sanitization failures.
* [ ] Improve error handling and safe output generation.
* [ ] Validate dependency licenses and security posture.

### Phase 3 — Distribution

* [ ] Package builds for Windows, macOS, and GNU/Linux.
* [ ] Document reproducible build procedures.
* [ ] Publish checksums and release artifacts.
* [ ] Add contribution guidelines and security reporting instructions.

## Contributing

Contributions are welcome.

Potential areas for contribution include:

* Metadata analysis for additional file formats.
* Sanitization and verification tests.
* Cross-platform packaging.
* Security reviews and vulnerability reports.
* Accessibility and usability improvements.
* Documentation and translations.

Please open an issue before implementing major changes so that the proposed work can be discussed first.

## License

The project is intended to use a permissive open-source license, such as the MIT License, subject to final dependency and competition requirements.

The final repository should include the selected license and appropriate notices for third-party components.

## Disclaimer

ShareSafe is a privacy-enhancement tool, not a guarantee of anonymity.

Removing metadata does not necessarily remove identifying information visible in the file's content. For example, an image may still contain a recognizable face, a document may reveal confidential information in its text, and a PDF may contain embedded objects or other structures outside the current inspection scope.

Always review the verification report before sharing sensitive files.

---

**ShareSafe — Make privacy visible before you share.**
