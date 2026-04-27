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

`audit` is conservative by design:

- `.ma` and `.mb` execution surfaces are collected through the observe layer
- reference graph traversal is included, and traversal failures are reported separately
- incomplete coverage, unknown semantics, degraded validation, or parse-budget exhaustion can make `blocked_on_uncertainty` true
- review-only signals affect disposition under both built-in audit profiles

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
- `10`: malicious findings triggered deny
- `11`: uncertainty triggered deny
- `20`: review
- `1`: scene decode or processing error
- `2`: CLI usage or I/O error

## Related Docs

- [README](../README.md)
- [Python usage](python_usage.md)
- [Development](development.md)
- [Supplying and extrapolating studio-specific Maya node knowledge](node_info_authoring.md)
