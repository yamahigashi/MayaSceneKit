# Advanced Usage

This document collects reference-heavy material that does not need to live in the
top-level README.

## CLI Command Summary

```bash
maya-scene-kit <command> [options]
```

Current CLI commands:

- `inspect`: inspect Maya Binary chunk structure
- `dump`: dump `requires` plus script nodes from a file or directory
- `paths`: extract file and reference paths from a file or directory, including `fileTextureName` owners such as `file`, `psdFileTex`, and `movie`
- `audit`: audit execution-capable surfaces
- `to-ascii`: convert Maya Binary scenes to Maya ASCII and optionally emit decode issues
- `clean`: remove script nodes and save in forensic mode
- `replace`: replace file and reference paths in forensic mode

Common options:

- `--node-info <path>` can be repeated on `dump`, `paths`, `audit`,
  `to-ascii`, `clean`, and `replace` to load additional node semantics files
- `--max-bytes <bytes>` caps scene parsing for defensive batch runs
- `dump`, `paths`, and `replace` use `--out` for single-file output and
  `--out-dir` for directory output

Command-specific options worth knowing:

- `audit --json` emits the full machine-readable report; `audit --summary-only`
  prints a one-line summary per file; `audit --rule <marker>` (repeatable) adds
  literal markers; `audit --allowlist <file>` (repeatable) marks findings listed
  in an allowlist file as allowed; `audit --max-preview <chars>` caps evidence
  preview length
- `paths --json` and `paths --kind <file|reference|all>` control path output
- `inspect --max-depth`, `--preview-bytes`, and `--at <offset>` scope the chunk dump
- `to-ascii --issues-json`, `--write-unknown-blobs`, `--embed-metadata`, and
  `--mode <strict|best-effort|forensic>` control conversion reporting

Run `maya-scene-kit <command> --help` for the authoritative flag list.

## Execution Modes

Commands that mutate or gate scenes run in one of three modes:

- `strict`: succeeds only when the relevant surface is validated authoritatively
- `best-effort`: allows partial structured recovery, but does not claim full validation
- `forensic`: allows heuristic or transport-level handling and reports that the result is not validated

Public reports expose `validation_state` as one of:

- `validated`
- `partial`
- `unsupported`
- `invalid`
- `copied_unvalidated`

## Audit Model

`audit` does not run scene code. It collects execution surfaces from `.ma` and
`.mb` scenes through the observe layer, classifies what each surface would do,
and returns a single gate decision plus the evidence behind it. Reference graph
traversal is included, and traversal failures are reported separately.

### Disposition

The top-level `disposition` is the gate decision. From least to most severe:

| `disposition` | Meaning |
| --- | --- |
| `allow` | No execution surface was found. |
| `allow_with_notice` | Execution surfaces exist but classify as benign, for example pure computation or diagnostic output. |
| `review` | A human is needed: uncertain semantics, incomplete coverage, degraded validation, or a review-only signal. |
| `deny_uncertain` | Uncertainty under the hardened profile (see below). Not produced by the default profile. |
| `deny_malicious` | A finding proved a dynamic-evaluation, hook-registration, or script-bearing-write sink. |

For a pre-open gate, treat only `allow` and `allow_with_notice` as passing.

### What forces review or deny

`blocked_on_uncertainty` becomes true — moving the scene to `review`, or to
`deny_uncertain` under the hardened profile — when any of the following hold:

- `coverage_state` is not `complete` (it is `incomplete` or `unsupported`)
- coverage issues were recorded
- a surface produced unknown semantics
- `validation_state` is `invalid`, `unsupported`, or `copied_unvalidated`
- an analysis budget was exceeded

### Audit profiles

Two profiles exist:

- `strict_default`: uncertainty maps to `review`. **This is the only profile used
  by the CLI and the Python binding.**
- `hardened_untrusted`: uncertainty maps to `deny_uncertain`. It is used by
  internal harnesses and is not currently selectable from the CLI or Python, so
  `deny_uncertain` (and CLI exit code `11`) does not occur with the shipped tools.

### Coverage depends on execution profiles

Surface extraction is driven by curated `node_info.execution` profiles. The
built-in bundle profiles only three node types: `script`, `expression`, and
`renderGlobals`. A node type that executes code but is not profiled — for example
a third-party renderer's settings node or a custom plugin node — is **not**
extracted as an execution surface, and on its own will not move the scene to
`review`. To audit those nodes, supply their execution profiles with
`--node-info`. See [node_info authoring](node_info_authoring.md).

## Current Scope

- IFF chunk parsing for `.mb` (`tag / offset / aux / size`)
- Script node detection, removal, and extraction for `.ma/.mb`
- Execution-surface audit and report generation for `.ma/.mb`
- Requires extraction for `.ma/.mb`
- File and reference path extraction for `.ma/.mb`
- File and reference path rewrite for `.ma/.mb`
- Best-effort `.mb` to `.ma` conversion with structured issue reporting

## Embedded Schema And `node_info` Overlays

CLI commands use the embedded schema bundle shipped with the binary.
The only external schema-like input accepted by the CLI is repeatable `--node-info`
files.

Node-info merge order for `.mb` reads and `to-ascii` is:

1. Embedded built-in `node_info`
2. `--node-info` files in argument order, with later files winning

Angular `setAttr` conversion (radian payload to degree output) uses node-local
rules from merged `node_info` data (`node_type + attrs.{token}.unit/kind`), plus
`addAttr`-defined custom `doubleAngle` and `floatAngle` attributes in the scene.

Execution-surface extraction also uses curated node-local `node_info` profiles.
The checked-in profile set is intentionally small:

- `script`: `script_node` profile with body attrs `a` and `b`, trigger attr `st`,
  and language attr `stp`
- `expression`: `attr_callbacks` profile for `expression` and
  `internalExpression`, using MEL and the `time_changed` trigger
- `renderGlobals`: `attr_callbacks` profile for MEL render callback attrs such as
  `preRenderMel`, `preMel`, and `postRenderMel`

Profile attr references may use either short names or aliases from `attrs`, but
they are normalized to the node-local short attr. Long report labels come from
`attrs.*.aliases`; profiles do not carry their own display labels.

For plugin or custom node entries, include the full node entry because later
`--node-info` files replace earlier node entries as a whole:

```yaml
version: 1
nodes:
  ExampleRenderNode:
    typeid: 0x45584D50
    execution:
      profiles:
        - kind: attr_callbacks
          default_language: mel
          default_trigger: render
          attrs: [preRenderMel]
    attrs:
      prm: { unit: none, kind: scalar, aliases: [preRenderMel] }
```

Generated execution candidates are review input only. Runtime audit only consumes
curated `node_info.execution` profiles that are checked into the schema bundle or
provided through explicit `--node-info` files.

Additional `node_info` files are primarily for studio or pipeline administrators
who maintain site-specific Maya/plugin semantics. For guidance, see
[Supplying and extrapolating studio-specific Maya node knowledge](node_info_authoring.md).

## `to-ascii --issues-json`

When `--issues-json` is specified, the JSON includes:

- `issues` with decoder attempts and trace info
- `unknown_inventory`
- `decode_quality_distribution`
- payload totals and ratios

If you also specify `--write-unknown-blobs`, large unknown chunk payloads are
materialized as binary files:

- Directory: `<issues_json_stem>.unknown_blobs/`
- File name: `<payload_digest_hex>.bin`
- JSON link field: `payload_blob_ref`

Blob export is used when unknown payload is not embedded inline
(`payload_inline_hex` absent, for example when payload is larger than 256 bytes).
For small payloads, inline hex is kept and no blob file is written.

## Dump Artifact Privacy Defaults

`dump` output no longer embeds the local source file path by default.
`to-ascii` output embeds `//Source:` only when `--embed-metadata` is specified.

## `audit` Hit Counting Semantics

`audit --rule` counts every literal-rule match, not just the first hit per node or file.

- Per-file `hits`: total matches in all script node bodies in that file
- Top-level `hit_count` in `--json`: total matches across all files

Exit codes:

- `0`: allow or allow-with-notice
- `10`: malicious findings triggered deny (`deny_malicious`)
- `11`: uncertainty triggered deny (`deny_uncertain`; only under the hardened
  profile, so the default CLI never emits it)
- `20`: review
- `1`: scene decode or processing error
- `2`: CLI usage or I/O error

## Audit Allowlists

An allowlist marks findings that a reviewer has already accepted for one exact
script body. Pass it with `audit --allowlist <file>` (repeatable; when two files
list the same entry, the earlier file wins) or `audit(..., allowlist_paths=[...])`.

```json
{
  "version": 1,
  "entries": [
    {
      "hash": "sha256:<64 lowercase hex>",
      "codes": ["mel_exec"],
      "label": "optional",
      "preview": "optional",
      "reason": "optional",
      "added_at": "optional",
      "added_by": "optional"
    }
  ]
}
```

- `hash` covers the script body text together with its language, surface kind,
  attribute, trigger, and source kind. Node names and file positions are not
  part of it, so the same body under another node still matches, while the same
  body under another trigger does not. Findings inside text derived from a body
  (for example `python("...")` inside MEL) use the hash of the outer body.
- `codes` lists finding ids to allow. User markers are listed as
  `custom_rule_match:<marker>`. There is no wildcard.
- Allowed findings stay in the report with `allowed_by` and no longer count as
  findings for the disposition. Units, dependency facts, review signals, and
  coverage are unchanged, so an allowed body can still produce `review`.
- These ids are never allowed, and any of them anywhere in a body blocks every
  allowance for that body: `unknown_execution_language`,
  `unknown_execution_trigger`, `python_parse_failure`,
  `python_unresolved_call_target`, `mel_parse_diagnostics`, `mel_callback_flag`.
- An unreadable or invalid file is an error (exit code `2`), not an empty list.
- With an allowlist, text output adds `allowed=<n>` to each file line,
  `allowed=<source>` to allowed findings, and `total_allowed=<n>`; JSON output
  adds `allowed_finding_count` and per-hit `allowed_by`. Without one, output is
  unchanged.
- An allowed body that evaluates data at run time (for example `eval` of an
  attribute value) trusts that data, because the hash covers only the body.

In the GUI, two allowlist files are merged: `allowlist.json` next to the GUI
executable (distributed by an administrator) and `allowlist.json` next to the GUI
state file (the user's own list, for example `%APPDATA%\maya-scene-kit\` on
Windows). A file that cannot be read keeps showing an error line and counts as
empty. Use **Settings > Reload allowlists** after editing a file outside the GUI.
Allowed findings are hidden in the audit table until **Show allowed** is toggled,
are not counted as threats, and are skipped by bulk threat removal.
In **Settings > Manage allowlists…**, you can view both allowlist files and remove
user entries; app entries are read-only, and a code that is also listed in the app
file or in another user entry stays allowed.

To add an entry from the GUI, open a finding's audit detail, wait for the full
script text to load, and choose **Allow this threat…**. Pick the finding ids to
allow (the opened finding's id is always included), optionally give a reason,
and choose **Add**. The GUI re-audits the scene with the candidate entry first
and writes to the user file only if the finding would actually be allowed; it
never overwrites a user file it cannot parse. The button stays disabled, with the
reason shown, for findings that are already allowed, ids that can never be
allowed, files with unsaved edits or pending re-audit, and grouped rows.

## Related Docs

- [README](../README.md)
- [Python usage](python_usage.md)
- [Development](development.md)
- [Supplying and extrapolating studio-specific Maya node knowledge](node_info_authoring.md)
