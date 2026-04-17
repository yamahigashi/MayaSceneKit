# maya-scene-kit

`maya-scene-kit` is an open-source toolkit for inspecting, auditing, and rewriting
Maya scene files (`.mb` / `.ma`) without requiring a Maya runtime.

`maya-scene-kit` can be used to:

- inspect unknown Maya scenes before opening them in Maya
- audit script nodes and other execution-capable scene content
- scan folders from the GUI and review audit results and reference paths in one place
- extract file, reference, texture, and cache paths from `.ma` / `.mb` scenes
- stage clean or path replacement edits and save the resulting files
- integrate pre-open scene checks into Python tools or batch pipelines

It currently ships three practical entry points:

- GUI for interactive review and staged edits
- CLI for batch inspection and automation
- Python bindings for embedding scene checks into other tools

## Distribution

| Form | Best for | Distribution |
| --- | --- | --- |
| GUI | Interactive review and staged clean/replace workflows | Release artifacts + source build |
| CLI | Batch inspection, CI, scripting, release binaries | GitHub Releases |
| Python | Tool integration and automation | Release artifacts + source build |
| Rust crates | Internal workspace architecture | Source only |

- Public release artifacts: CLI, GUI, and Python bindings
- The repository currently includes source-build workflows for GUI and Python
- Internal source crates are not yet stable public APIs

## Current Limitations

- `clean` and `replace` currently run only in `forensic` mode in both the CLI and the GUI
- They are intended for investigation and temporary remediation, and do not guarantee a fully validated rewrite

Related docs:

- [Python usage](docs/python_usage.md)
- [Advanced usage](docs/advanced_usage.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## Quick Starts

The GUI and CLI are shipped in the same release archive. Download the archive
for your OS from GitHub Releases and extract it.

1. Open the Releases page
2. Download the `maya-scene-kit` archive for your platform
3. Extract it anywhere

Release archives currently contain:

- the `maya-scene-kit` executable
- the `maya-scene-kit-gui` executable
- supporting documentation

### GUI

Example:

```powershell
maya-scene-kit-gui.exe
```

Use the GUI when you want to load files or folders, inspect audit findings, review
dump and path data, apply edits in stages, and save results without dropping into the CLI.

TODO: Screenshots of the GUI
TODO: Documentation of the GUI workflow and features

### CLI

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

Quick check:

```powershell
python -c "import maya_scene_kit; print(maya_scene_kit.inspect_mb('tests/02/sphere.mb', max_depth=0)['scene_format'])"
```

See [docs/python_usage.md](docs/python_usage.md) for practical Maya integration
examples, source builds, editable installs, and other details.

## Typical Workflows

### GUI workflow

The GUI is aimed at interactive scene triage and staged rewrite work:

1. Open a folder, enable `Auto Analyse`, and let it scan
2. Use the `Audit` tab to review results and run clean (quarantine) when needed
3. Use the `Paths` tab to review reference paths and run replacements or related actions
4. Save the changes

### Python workflow

The Python bindings make it possible to inspect a scene before Maya itself opens
or imports the file.

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
`dump_scripts`, `preview_clean`, `clean`, `preview_replace`, and `replace`.

### CLI workflow

For untrusted or unknown scenes, start with `audit` or `dump`.
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
```

## Command Summary

```bash
maya-scene-kit <command> [options]
```

Current CLI commands:

- `inspect`: inspect Maya Binary chunk structure
- `dump`: dump `requires` plus script nodes from a file or directory
- `paths`: extract file and reference paths from a file or directory, including `fileTextureName` owners such as `file`, `psdFileTex`, and `movie`
- `audit`: audit execution-capable surfaces
- `clean`: remove script nodes and save in forensic mode
- `replace`: replace file and reference paths in forensic mode

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

For deeper reference material, including `--node-info` overlays and
`plugin_node_info` generation, see [docs/advanced_usage.md](docs/advanced_usage.md).
