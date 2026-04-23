# Changelog

All notable changes to this project will be documented in this file.

## [v0.2.2] - 2026-04-23

This release tightens MEL audit behavior by replacing whole-surface
body-assembly heuristics with sink-aware analysis and by making review-only
signals affect final audit disposition.

### Added

- Added sink-aware MEL string-flow facts in the `formats` and `observe` layers
  so audit can distinguish fixed literals, assembled literals, proc references,
  dynamic values, and unresolved values at known MEL execution sinks.
- Added the review signal `mel_body_assembly_without_sink` for reconstructed
  code-like MEL bodies that appear in execution context without proven sink
  reachability.

### Changed

- Replaced MEL’s previous whole-surface `obfuscation_markers` deny heuristic
  with sink-aware sink-argument analysis for `python`, `eval`,
  `evalDeferred`, callback payloads, and `scriptJob`.
- Updated callback handling so bare proc references remain review-only while
  inline callback bodies are treated as sink-reaching execution surfaces.
- Made review signals disposition-relevant:
  - `strict_default` now escalates to at least `Review`
  - `hardened_untrusted` now escalates to at least `DenyUncertain`
- Updated CLI, GUI, and Python-facing audit surfaces to carry the new review
  semantics and MEL fact model.

### Fixed

- Fixed false positives where ordinary MEL string assembly for names,
  namespaces, attribute paths, and UI labels could be escalated as malicious
  body assembly.
- Fixed a dead review path where audit review signals were collected but could
  not influence the final disposition.
- Removed retired MEL text-scan code that was no longer part of the active
  audit model.

## [v0.2.1] - 2026-04-23

This release summarizes the changes introduced between `v0.1.0` and `v0.2.1`.
It marks the transition from an early CLI-focused tool into a broader Maya scene
toolkit with layered workspace crates, a desktop GUI, and Python bindings.

### Added

- Expanded the project from a single package into a layered Rust workspace with
  dedicated `formats`, `observe`, `audit`, `edit`, `cli`, `gui`, and `python`
  crates.
- Added a desktop GUI for interactive scene review, audit triage, path review,
  and staged edit workflows.
- Added Python bindings for embedding inspection, audit, clean, and replace
  flows into external tools and pipelines.
- Added structured Maya Binary path decoding support behind the `replace`
  command.
- Added FOR4 format support.
- Added persistent analysis cache controls and cache maintenance flows in the
  GUI.
- Added GUI workspace file list filters and count displays.
- Added Windows release packaging on a Windows runner.
- Added a Windows Python release artifact.

### Changed

- Repositioned the project from a standalone CLI utility to an open-source Maya
  scene toolkit covering GUI, CLI, and Python entry points.
- Refactored internal boundaries across the workspace to separate low-level
  format handling, observation, audit policy, edit planning, and adapter code.
- Refined observe public seams and source/query ownership boundaries.
- Tightened audit and CLI scene facades.
- Improved GUI path workflows, including helper cleanup, context actions, menu
  cleanup, and exit warning behavior.
- Deferred schema loading for Maya ASCII observations and cached schema contexts
  across observe APIs.
- Expanded path coverage to include `fileTextureName` owners.
- Improved GUI responsiveness for large workspaces by reducing cache restore
  stalls, reducing cache persistence pressure, and suppressing low-priority auto
  analysis during restore.
- Refreshed project documentation, including README updates, Japanese README
  coverage, and third-party notice material.

### Fixed

- Fixed false positives in MB reference metadata audit results.
- Fixed MB head test payload encoding issues.
- Fixed MB plugin require test fixture encoding.
- Fixed GUI path style test isolation.
- Fixed Linux CI workflow dependency issues.
- Fixed Python binding tests by initializing PyO3 correctly.
- Fixed audit detail dialog header wrapping.
- Fixed workspace-wide clippy and formatting issues.
- Removed dead Maya ASCII token parsers and the legacy Maya ASCII parser
  harness.

### Performance

- Optimized observe recovery hotspot lookups.
- Reduced path rewrite allocations in the formats layer.
- Interned repeated observe IR strings.
- Reduced analysis cache overhead in the GUI for large workspaces.
- Adapted MB budgets from source bytes.

### Notes

- `clean` and `replace` remain forensic, best-effort workflows rather than
  fully validated rewrite guarantees.
