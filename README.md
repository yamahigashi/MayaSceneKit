# maya-scene-kit

`maya-scene-kit` is an open-source toolkit for inspecting, auditing, and rewriting
Maya scene files (`.mb` / `.ma`) without requiring a Maya runtime.

It currently ships three practical entry points:

- GUI for interactive review and staged edits
- CLI for batch inspection and automation
- Python bindings for embedding scene checks into other tools

## Project Status

| Surface | Best for | Distribution | Status |
| --- | --- | --- | --- |
| GUI | Interactive review, staged clean/replace/to-ascii workflows | Release artifacts + source build | Public surface |
| CLI | Batch inspection, CI, scripting, release binaries | GitHub Releases | Most stable public surface |
| Python | Tool integration and automation | Release artifacts + source build | Public surface |
| Rust crates | Internal workspace architecture | Source only | Not a stable public library API |

- Public release artifacts: CLI, GUI, and Python bindings
- The repository currently includes source-build workflows for GUI and Python
- Workspace crates: public source, but not yet a stable public API

Related docs:

- [Python usage](docs/python_usage.md)
- [Advanced usage](docs/advanced_usage.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## Quick Starts

### GUI

Download the release archive for your OS from GitHub Releases and extract it.
The release bundle contains both `maya-scene-kit` and `maya-scene-kit-gui`.

Example:

```powershell
maya-scene-kit-gui.exe
```

Use the GUI when you want to load files or folders, inspect audit findings, review
dump and path data, stage edits, and save results without dropping into the CLI.

### CLI

Download the release archive for your OS from GitHub Releases and extract it.
The same bundle includes the CLI and GUI executables.

1. Open the Releases page
2. Download the `maya-scene-kit` archive for your platform
3. Extract it anywhere and run `maya-scene-kit --help`

Release archives currently contain:

- the `maya-scene-kit` executable
- the `maya-scene-kit-gui` executable
- `LICENSE`
- `THIRD_PARTY_NOTICES.md`
- `README.md`

Example:

```powershell
maya-scene-kit.exe --help
```

### Python

Python bindings live in `crates/maya-scene-kit-python`.
Download the release wheel from GitHub Releases and install it directly.

```powershell
uv pip install --system .\maya_scene_kit-0.1.0-*.whl
```

Quick smoke test:

```powershell
python -c "import maya_scene_kit; print(maya_scene_kit.inspect_mb('tests/02/sphere.mb', max_depth=0)['scene_format'])"
```

See [docs/python_usage.md](docs/python_usage.md) for source builds, editable installs,
and API examples.

## Typical Workflows

### GUI workflow

The GUI is aimed at interactive scene triage and staged rewrite work:

1. Add one or more files, or scan a folder
2. Run audit and inspect the result table
3. Review requires, script dump, and extracted paths
4. Stage `clean`, `replace`, or `to-ascii`
5. Save selected outputs

### Python workflow

The Python bindings are useful when another tool wants to inspect a scene before
handing it off to a downstream open or import step.

This is an operational pattern built on the current API surface, not a dedicated
callback API:

```python
from maya_scene_kit import audit

report = audit("scene.mb", max_preview=120)

if report["blocked_on_uncertainty"]:
    raise RuntimeError("scene requires manual review before open")

if report["disposition"] not in {"allow", "allow_with_notice"}:
    raise RuntimeError(f"audit blocked scene: {report['disposition']}")

# Your tool decides what to do next.
# For example: open the file in a DCC, queue it for review, or copy it to a safe area.
```

Other Python entry points include `inspect_mb`, `collect_paths`, `dump_requires`,
`dump_scripts`, `preview_clean`, `clean`, `preview_replace`, `replace`, and
`to_ascii`.

### CLI workflow

For untrusted or unknown scenes, start with `audit` or `dump`.
`clean` and `replace` currently run in `forensic` mode only because the strict
IR-native mutator path is not complete yet.
If a scene relies on script nodes for render setup or other initialization,
removing them can change behavior.

Representative commands:

```bash
maya-scene-kit audit input.mb
maya-scene-kit dump input.mb --out /tmp/scene_dump.txt
maya-scene-kit paths input.mb --kind reference --json
maya-scene-kit inspect input.mb --max-depth 2
maya-scene-kit clean input.mb output_clean.mb
maya-scene-kit replace input.mb --rule "V:/dcc=X:/dcc" --out output.mb
maya-scene-kit to-ascii input.mb output.ma --mode best-effort
```

## Command Summary

```bash
maya-scene-kit <command> [options]
```

Current CLI commands:

- `inspect`: inspect Maya Binary chunk structure
- `dump`: dump `requires` plus script nodes from a file or directory
- `paths`: extract file and reference paths from a file or directory
- `audit`: audit execution-capable surfaces
- `to-ascii`: convert Maya Binary (`.mb`) scenes to Maya ASCII (`.ma`)
- `clean`: remove script nodes and save in forensic mode
- `replace`: replace file and reference paths in forensic mode

## Execution Modes

Commands that mutate, gate, or convert scenes run in one of three modes:

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

- `.ma` execution surfaces are audited directly
- `.mb` strict audit remains fail-closed until binary surface extraction is authoritative
- parse failures on autorun Python surfaces are treated conservatively in strict-capable paths

## Current Scope

- IFF chunk parsing for `.mb` (`tag / offset / aux / size`)
- Script node detection, removal, and extraction for `.ma/.mb`
- Execution-surface audit and report generation for `.ma/.mb`
- Requires extraction for `.ma/.mb`
- File and reference path extraction for `.ma/.mb`
- File and reference path rewrite for `.ma/.mb`
- `.mb` to `.ma` conversion via `to-ascii`

For deeper reference material, including `--node-info` overlays, `plugin_node_info`
generation, and `to-ascii --issues-json`, see [docs/advanced_usage.md](docs/advanced_usage.md).
