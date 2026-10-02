# Changelog

All notable changes to this project will be documented in this file.

The project follows an unreleased-first changelog. Versioned releases should
move the relevant entries into a dated section.

## Unreleased

### Added

- Cross-platform macOS and Linux Bash analysis and Runbox application models.
- Bidirectional persistent cmd and PowerShell parent shells.
- Source-attributed cross-platform ClickFix fixtures and false-negative
  regressions.
- Bounded PE, ELF, thin Mach-O, and universal Mach-O structural inspection.
- Binary entropy, overlay, packer-marker, signature, entitlement, build-ID,
  interpreter, and runtime-path metadata.
- Typed causal provenance linking network activity, artifacts, virtual files,
  extraction, executable marking, and modeled process launches.
- Detector CI covering formatting, strict Clippy, tests, dependency auditing,
  fuzz-target compilation, and the release WebAssembly target.

### Changed

- Report schema version 5 adds binary inspection and causal-provenance data.
- Bash now executes heredocs and C-style arithmetic loops and supports
  standalone deterministic `ls`.
- Alternate PowerShell process-launch surfaces return synchronous modeled
  output and preserve native stderr.
- Automatic input inference distinguishes zsh pipelines from PowerShell
  environment-variable syntax.
- `url` and `idna` use patched, Rust-1.85-compatible releases.

### Security

- Removed the vulnerable `idna` 0.4 dependency path associated with
  RUSTSEC-2024-0421.
