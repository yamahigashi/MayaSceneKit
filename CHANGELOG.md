# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- MbChildren, MbTruncationReason, and MbCompleteness are now non-exhaustive.
  MbInspectReport adds a public completeness field (excluded from serialization).
  Inspect text starts with a completeness= line, including --at-offset output.
  Formats exposes MbRootFormsAndRequiresRemoval and MbRootFormRemoval type aliases
  and require_complete_mb_tree. Rewrites now refuse scenes exceeding the default
  parse budget of 100 000 children per group or 1 000 000 chunks.

- Maya Binary chunk parsing now exposes MbChildren, MbTruncationReason, and
  MbCompleteness through maya-mb and the formats MB module. A malformed child
  preserves its successfully parsed siblings and the original error. Successful
  parsing can still return an incomplete tree; use file or chunk completeness()
  to check the whole retained subtree. Depth-limited NotExpanded groups count
  as DepthLimit truncation; not_expanded_groups() reports their count separately.
- children_complete() now returns true for leaves. It describes only the direct
  child sequence; use completeness() to detect truncation in descendants.
- MB rewrite and removal functions now return Result and reject incomplete
  subtrees, including depth-limited trees and requests with no matching targets.
  Edit operations report these refusals without materializing output.
- Accept omitted padding for the final child whose payload ends exactly at its
  parent boundary. Inspect now shows previously hidden children in that case and
  prints a completeness summary. Observe and audit cache schemas advance to 6.

## [v0.3.1] - 2026-11-10

### Changed

- The GUI paths table "Delete owner nodes" context action now applies to every
  selected path entry when the right-clicked entry is part of the selection.
  Right-clicking an entry outside the selection still affects only that entry.

## [v0.3.0] - 2026-11-09

This release adds allowlist-based review of known scripts across the CLI,
Python, and GUI, exposes standalone source auditing, extracts the Maya Binary
chunk layer into the `maya-mb` crate, and makes the GUI faster and clearer on
large workspaces.

### Added

- Added audit allowlists keyed by script body hash. Matching findings are kept
  in the report but marked as allowed.
- Added `--allowlist` to the CLI `audit` command (repeatable; earlier files
  win) and `allowlist_paths` to the Python audit API.
- Added a default app allowlist (`dist/allowlist.json`) to the release
  archives, placed next to the executables. It allows the
  `LookdevXUIConfigurationScriptNode` UI configuration script written by
  Autodesk LookdevX (`python_maya_eval_deferred`, `python_maya_load_plugin`).
- Added standalone source auditing for MEL and Python text that is not inside a
  scene file: `audit_source_text` and `observe_source_text` in Rust, and
  `audit_source_text` in Python.
- Added a non-recursive audit option to the Python API that stops at the root
  scene instead of walking the reference graph.
- Added GUI allowlist support: load allowlists, show allowed findings
  separately, add findings to the user allowlist from the audit detail dialog,
  and manage user entries in an allowlist manager dialog.
- Added GUI context-menu plugin actions for the file list and audit table.
- Added a GUI action to find missing path files on disk and stage the found
  locations as replacement paths.
- Added full script text and readable field labels to the GUI audit detail
  dialog.
- Added GUI keyboard shortcuts: Ctrl+O (select folder), F5 (reload folder),
  Ctrl+S / Ctrl+Shift+S (save selected / save all), Ctrl+Z / Ctrl+Y (undo /
  redo), Ctrl+F or `/` (focus the file-list or paths search box), and Escape in
  a search box (clear, then leave the box). Added Ctrl+A to select all path
  rows.
- Added a File > Reload Folder menu item.

### Changed

- Extracted the Maya Binary IFF chunk reader and encoder from
  `maya-scene-kit-formats` into the standalone `maya-mb` crate and tightened its
  API. Rust code that used the moved `formats::mb` modules must switch to
  `maya-mb`.
- The GUI file list now refreshes its filtered and sorted rows every second
  during workspace auto analyze, and also after path resolution finishes, so
  filters such as missing paths fill in while a scan runs.
- The GUI audit table shows the origin node instead of the internal sink name.
  The sink stays available in the detail dialog and search.
- Selected rows in the GUI file list and paths table keep their state visible
  through a left-edge mark and an outlined status badge (modified, error,
  saved).
- The GUI path replace dialog keeps the previous preview visible while the
  rules are retyped, shows non-matching candidates in grey instead of hiding
  them, marks matched rows on the left edge, and renders the candidate list as a
  virtualized table.
- Menu shortcuts use the platform modifier, so Windows shows Ctrl instead of
  Win.
- Clarified audit gate semantics and coverage limits in the documentation.

### Fixed

- Fixed selective Maya ASCII parsing so reference paths are recovered after
  long command options.
- Fixed the quoted-literal scan to stop at an unterminated quote.
- Fixed Maya Binary execution clean so unselected script nodes and requires are
  kept.
- Fixed clean and composite range edits to apply against the original bytes.
- Fixed the reference graph limit to count each admitted scene once.
- Fixed observe cache reads to reject rows from other schema versions on every
  read path.
- Fixed observe to report failed and unsupported chunk decodes with an explicit
  quality.
- Fixed refedit auto-grouping to advance past zero-count groups.
- Fixed the GUI path edit transaction to open only after previews succeed.
- Fixed GUI persisted state to save in snapshot order with atomic writes.
- Fixed the GUI Edit menu `uiConfigurationScriptNode` delete to skip analyzed
  files that do not contain the node instead of failing.

### Performance

- Precomputed GUI file-list sort keys and skipped building search text when the
  search box is empty.
- Stopped cloning the whole path replace dialog state on every frame.

## [v0.2.4] - 2026-06-11

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
- Added Python audit findings for file open, file write, and Maya autorun
  persistence markers such as `userSetup` script paths.
- Added first-party fuzz targets for Maya Binary parsing, Maya ASCII selective
  extraction, MEL top-level audit candidate parsing, and observe execution
  extraction.

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
- Made Maya Binary execution coverage fail closed for unexplained text-like raw
  payloads instead of relying only on marker words.
- Extended execution-surface extraction to catch generic render MEL callback
  attributes on unprofiled node types.
- Made hardened audit treat partial Maya Binary validation as
  disposition-relevant uncertainty.
- Reclassified non-standard declarative `requires` entries as reviewable
  dependency facts while keeping `requires maya` informational.

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
- Fixed indexed Maya Binary reference rewrites for mirrored records.
- Fixed workspace clippy failures under `-D warnings`.
- Removed retired MEL text-scan code that was no longer part of the active
  audit model.

### Performance

- Optimized Maya Binary audit execution scans by reusing loaded scene/source
  data and reducing redundant execution-surface extraction work.

### Tooling

- Updated CI formatting checks to use nightly rustfmt so the repository's
  unstable rustfmt import-grouping settings are enforced.
- Added cargo-fuzz harness scaffolding with sanitized public seed corpora and
  ignore rules for generated corpus growth and fuzz artifacts.

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
