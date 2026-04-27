# Changelog

All notable changes to this project will be documented in this file.

## [v0.2.4] - 2026-04-27

This release tightens execution-surface detection across Maya ASCII and Maya
Binary scenes. MEL audit behavior now uses sink-aware analysis instead of
whole-surface body-assembly heuristics, schema data can drive execution
observation for script-bearing attributes, and adapter surfaces expose richer
evidence for review.

### Added

- Added sink-aware MEL string-flow facts in the `formats` and `observe` layers
  so audit can distinguish fixed literals, assembled literals, proc references,
  dynamic values, and unresolved values at known MEL execution sinks.
- Added the review signal `mel_body_assembly_without_sink` for reconstructed
  code-like MEL bodies that appear in execution context without proven sink
  reachability.
- Added a dedicated GUI action to stage deletion of
  `uiConfigurationScriptNode` from the main Edit menu and file-list context
  menu using the existing scene-edit clean pipeline.
- Added schema-driven execution observation profiles for script-bearing Maya
  node attributes, backed by `schemas/node_info.yaml`.
- Added file-list Explorer actions in the GUI so users can open selected scene
  files or their containing folders directly from workspace tables.

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
- Enriched audit finding and review previews so adapter surfaces prefer
  finding-specific snippets, include node-name evidence, and expose richer
  provenance in GUI detail views, clipboard payloads, CLI output, and Python
  JSON.
- Updated `maya-mel` to `0.1.3` and aligned selective Maya ASCII parsing with
  the newer MEL parsing behavior.
- Cached parsed schema node information so repeated observe/audit flows can
  reuse the same node semantics more efficiently.

### Fixed

- Fixed false positives where ordinary MEL string assembly for names,
  namespaces, attribute paths, and UI labels could be escalated as malicious
  body assembly.
- Fixed false positives where non-script string attributes and Maya Binary
  reference metadata could be treated as raw execution surfaces.
- Fixed Maya ASCII analysis coverage so execution-bearing attributes discovered
  during selective loading are included in audit analysis.
- Fixed Python obfuscation marker detection so markers produced after parsing
  still affect audit results.
- Fixed GUI file-list Explorer actions for path-owner rows and missing-file
  cases.
- Fixed a dead review path where audit review signals were collected but could
  not influence the final disposition.
- Removed retired MEL text-scan code that was no longer part of the active
  audit model.

### Performance

- Optimized Maya Binary audit execution scans by reusing loaded scene/source
  data and reducing redundant execution-surface extraction work.

### Documentation

- Updated README coverage for GUI workflows, Maya Binary to Maya ASCII
  conversion, release wheel installation, and Python binding entry points.
- Split Python source-build guidance into the development docs and expanded
  Python usage docs with wheel extraction, API signatures, and a sanitized Maya
  pre-open audit callback example.
- Added studio-specific `node_info` authoring guidance, including curated
  execution profiles, overlay behavior, validation steps, and public fixture
  sanitization rules.
- Expanded advanced usage docs for repeatable `--node-info` overlays,
  schema-driven execution profiles, conservative audit disposition, and
  `to-ascii --issues-json`.

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
