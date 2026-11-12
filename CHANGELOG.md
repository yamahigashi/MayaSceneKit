# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [v0.4.0] - 2026-11-12

This release expands script audit coverage, makes path replacement and cleaning
preserve more original scene data, and keeps GUI previews, staged audits, and
saved files consistent. It includes the changes from the unreleased v0.3.1.

### Migration notes

- Stricter audits can change verdicts from allow to review or deny on unchanged
  scenes. Audit now reports aliases of maya.mel.eval, connectAttr commands with
  unresolvable plugs, Maya Binary connections into unmapped execution-capable
  attributes, and budget-truncated code-like text. Scene scripts that call
  loadPlugin or source are denied by design.
- Persistent caches rebuild automatically: observe cache schema is 34 and audit
  cache schema is 38. Cache identities now include the loaded schema and
  node-info contents; audit caches also account for load options.
- CLI paths text adds a validation_state: line, and standalone and collection
  JSON add validation_state. Python paths JSON already included validation_state
  in v0.3.0. CLI and Python paths JSON add diagnostics only when the source
  changes during reading. Do not treat partial results as complete coverage.
- Breaking: audit now returns exit code 20 for an unreadable scene passed alone
  or in a directory, including runs where every scene fails to load. JSON mode
  emits graph traversal issues and a summary. Configuration errors, including
  invalid node-info overlays or schema configuration, retain exit code 1.
- Directory traversal no longer silently skips symbolic links. Audit reports
  unfollowed links as traversal issues, changing an otherwise successful run to
  review (exit 20); deny takes precedence. Dump, paths, and replace warn for each
  link and exit with code 2 if no scenes remain. Audit text and JSON expose
  outside_input_tree.
- Python error categories add source_changed, source_unstable, and
  python_parse_budget_exceeded.
- Python path replacement result JSON adds skipped, which was absent in v0.3.0.
  MA fields are non_utf8, non_canonical_escape, unrepresentable,
  crosses_concat_boundary, unterminated_tail, and unterminated_tail_from.
  MB fields are non_utf8, payload_rejected, unmatched_locator, and
  duplicate_request. Inapplicable fields are null. For MB with no skips,
  non_utf8 and the three MB counters are zero; MA-only fields are null.
  CLI skip lines also include the three MB reason counters. Rust PathReplaceSkips
  is a new type.
- Preview JSON adds applied_count. matched_count counts changed report entries;
  applied_count counts all changes, including records without a report entry.
  replacement_count, replaced_count, and items[].replacement_count count changed
  MA literals or MB payload records, not rule hits. One reference backed by FREF
  and FRDI can contribute two changes. GUI summaries show both counts when they
  differ.
- In MA files declaring an unsupported codeset, replacement skips introduced
  non-ASCII text. ASCII replacements still work and preserve untouched bytes.
- Rust MB callers must handle non-exhaustive MbChildren, MbTruncationReason,
  MbCompleteness, MbWalkResult, and MbSectionScanState. Successful parsing can
  retain an incomplete tree: use file or chunk completeness() to check the
  whole subtree. children_complete() now returns true for leaves and describes
  only direct children. Depth-limited NotExpanded groups count as DepthLimit;
  not_expanded_groups() reports their count separately.
- Rust walk_group_chunks_with_layout returns MbWalkResult rather than a vector.
  ParsedSection::into_chunks is replaced by into_parts; inspect state() or the
  returned MbSectionScanState. Formats scan_raw_script_nodes_in_mb,
  extract_raw_script_entries_from_mb, extract_raw_scene_paths_from_mb,
  collect_rtft_owner_traces_from_mb, and
  locate_raw_script_node_forms_in_mb_by_name return MbSectionScan with value
  and state. HeadMetadata gains section_state. The name readers
  extract_mb_script_node_name_with_layout and
  extract_mb_form_node_name_with_layout take MbParseBudget and return
  MbSectionScan<Option<String>>.
- Rust MB rewrite and removal functions now return Result with MbRewriteError,
  including remove_plugin_requires_from_mb,
  remove_root_forms_and_plugin_requires_from_mb,
  remove_root_forms_from_mb_by_locator, remove_raw_script_nodes_from_mb, and
  remove_raw_script_nodes_from_mb_by_name. Path replacement functions return
  MbPathChanges alongside bytes. Formats exposes MbRootFormsAndRequiresRemoval,
  MbRootFormRemoval, and require_complete_mb_tree. MbInspectReport gains a
  public completeness field excluded from serialization.
- Rust replace_raw_scene_paths_in_ma and
  replace_raw_scene_paths_in_ma_by_index return
  Result<MaPathReplaceResult, MaPathReplaceError>. RawMaScriptEntry replaces its
  body, script_type, and source_type fields with assignments and corresponding
  accessor methods, preserving assignment history.
- Rust stage_scene_edits_in_report_with_bytes and its _with_options variant
  are replaced by stage_scene_edit_plan and stage_scene_edit_plan_with_options,
  taking SceneEditPlan. PatchPlanner uses stage_scene_edit_plan too.
  stage_scene_edits and stage_scene_edits_with_options take clean_source and
  return SceneEditError; handle NoEffectiveEdits and its skipped records.
  SceneEditChanges records applied, skipped, covered, and superseded edits.
  ScenePathsReport gains source, kind, and diagnostics; report-based edits
  validate SceneSourceFingerprint before applying changes.
- Rust ObserveCacheStore::new and AuditCacheStore::new now take LoadOptions;
  observe cache lookup methods no longer take load options per call.
  ObserveCacheIdentity::new gains schema_bundle_sha256; AuditCacheIdentity::new
  gains schema_bundle_sha256 and load_options_fingerprint.
  AuditedSceneSnapshot::new takes LoadOptions and returns io::Result<Option<Self>>;
  ObservedSceneSnapshot::from_observation also returns an optional snapshot.
  Both snapshot types offer with_file_state for load-time state.
- Rust ObservedExecutionSurface gains python_parse_budget_limit, and
  ObservedExecutionCatalog gains python_max_body_bytes. ExecutionOrigin gains
  overwritten, assignment_index, overwritten_by_connection,
  connection_source_plug, connection_source_range, and connection_range.
- Rust write_output_bytes_atomic returns WriteOutcome with dir_sync_error so
  callers can distinguish a completed replacement from a directory sync issue.
  The CLI library main entrypoint now takes Vec<OsString> instead of Vec<String>.

### Added

- Audit follows script bodies connected into execution attributes in MA and MB
  scenes, including short and long attribute names, and reports overwritten
  script-node assignments and connection provenance.
- MEL audit now emits mel_system, mel_popen, mel_file_open, mel_file_write,
  mel_evalecho, mel_callpython, mel_source, mel_loadplugin, and mel_sysfile
  finding codes for dangerous command and function calls. Read-only fopen modes
  and query-only sysFile calls are excluded. Existing allowlist entries for
  other finding codes do not cover these new codes.
- Inspect text starts with a completeness= line, including --at-offset output.
  Audit reports truncated MB trees and stopped section scans as coverage issues.
- The GUI replacement preview shows per-entry skip reasons, including partially
  replaced and fully skipped matched entries.

### Changed

- The GUI paths table "Delete owner nodes" context action now applies to every
  selected path entry when the right-clicked entry is part of the selection.
  Right-clicking an entry outside the selection still affects only that entry.
- Clean and owner deletion previews and staged outputs now use the same
  application result. cleaned_targets includes only targets that performed a
  change; targets consumed by preceding deletions are covered. removed_count
  follows the actual removal list. A named clean or owner request missing from
  the original input now fails even if other requested targets exist, and
  produces no artifact.
- MB rewrites refuse incomplete subtrees, depth-limited trees, and stopped
  section scans, even when no targets match. Default parse limits are 100 000
  children per group and 1 000 000 chunks. Encoding failures produce no output.
- Report-based edits retry unstable reads once, reject changed source files,
  and require re-analysis when a report has no source fingerprint. GUI staging
  and Save reject source changes since analysis or staging.
- Release tags vX.Y.Z-rc.N publish pre-releases with release-candidate Python
  wheels. The Python package version now comes from Cargo.

### Fixed

- MA path replacement edits literal byte ranges without reserializing commands,
  preserves unrelated bytes, and reports skipped literals. Replacement text
  uses the declared codeset even in ASCII-only input. Owner deletion also
  preserves untouched non-UTF-8 bytes.
- MB path replacement preserves one enclosing quote pair on RTFT values and
  treats bytes after the first value NUL as an opaque tail. Multiple quote pairs
  and one-sided quotes are retained; only one complete outer pair is a frame.
  Overrides without enclosing quotes replace the framed value's interior.
  FRDI replacements preserve surrounding whitespace and count unchanged parts
  as unchanged.
- Non-UTF-8 MB path values are preserved and reported as undecodable, including
  explicit overrides. Payload size rejection skips only that record. An
  entirely rejected child retains its original span, including padding.
- Combined path replacement, clean, and owner deletion apply to original bytes.
  Deletion covers a path candidate only when its range lies inside a deleted
  range. Named clean handles non-script owners, quoted node types, flags before
  node types, and encoded node names; each block is removed once. Clean honours
  --max-bytes and --node-info.
- MA parsing tracks blocks by command semantics instead of indentation, resolves
  absolute plugs and attribute aliases, and reports malformed createNode,
  unknown top-level statements, and unmapped execution attributes. File command
  callbacks accept both -c and -command. ASCII conversion escapes scene-derived
  values; non-ASCII addAttr names no longer break prefix stripping.
- MB parsing accepts omitted padding for a final child ending at its parent
  boundary and retains parsed siblings when another child is malformed.
  Section scans accept all chunk tags and respect the parse-time budget.
- Python audit visits all AST positions and resolves lexical scopes, wildcard
  imports, loop bindings, and unresolved calls more accurately. Python 2
  normalization preserves string contents and print/exec used as names. MEL
  analysis examines every sink argument and nested literal eval bodies.
- Python analysis reports excessive nesting, oversized bodies, and thread
  creation failures as coverage gaps instead of panicking. Other surfaces
  remain eligible for analysis when one body exceeds its budget.
- Cache snapshots use the file state and digests of the bytes actually read.
  Budget-blocked reports retain load-time state when available; in-memory
  reports without that state do not produce cache snapshots.
- GUI staged edits survive replacement, clean, conversion, and undo. File counts
  and the audit table use the staged report; plan changes trigger background
  re-audits. Pending audits no longer appear as zero findings, and Save drops
  stale pre-save audits. Blocked rows show the Python parse limit and surface.
- GUI Save checks conversion destinations, keeps source reports after conversion,
  and preserves successful saves even if re-analysis fails. Re-read failures
  remain visible and eligible for auto-analysis. Workspace changes and row
  mutations are blocked during conflicting jobs, and late job results cannot
  overwrite newer work.
- GUI settings recovery preserves unreadable settings and unavailable workspace
  roots, keeps the recovery banner until dismissed, and reuses identical backups
  instead of creating a new one on each start.
- CLI directory traversal reports symlinks. CLI arguments, CLI and Python graph
  paths, and audit snippets handle non-UTF-8 paths or multibyte text without
  panics; closed stdout no longer causes a panic. Bare output filenames resolve
  against the current directory, and a completed replacement is not reported
  as failed because of a later directory sync error.

### Performance

- Clean reuses bytes loaded for script-owner analysis instead of performing a
  full execution observation.
- MB path overrides extract path entries once per batch, reducing repeated work
  when replacing many paths.
- MB connection scans compute chunk-tree completeness once per scan rather than
  once per connection.

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
