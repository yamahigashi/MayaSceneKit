# Python Usage

`maya-scene-kit` exposes Python bindings from the
`crates/maya-scene-kit-python` adapter crate.

This document covers the source-build workflow that lives in this repository.

## Build A Wheel

The recommended flow uses `uv` to invoke `maturin` directly:

```powershell
uv run --with maturin maturin build --manifest-path crates/maya-scene-kit-python/Cargo.toml
```

Built wheels are written to `target\wheels\`.
On Windows the filename will end in `win_amd64.whl`.

Install a built wheel:

```powershell
uv pip install --system .\target\wheels\maya_scene_kit-0.1.0-*.whl
```

Quick smoke test:

```powershell
python -c "import maya_scene_kit; print(maya_scene_kit.inspect_mb('tests/02/sphere.mb', max_depth=0)['scene_format'])"
```

## Editable Local Environment

If you want an editable local environment instead of a wheel build:

```powershell
uv venv
.venv\Scripts\Activate.ps1
uv pip install maturin
maturin develop --manifest-path crates/maya-scene-kit-python/Cargo.toml
```

## Exported API

The package currently exports:

- `audit`
- `clean`
- `collect_paths`
- `dump_requires`
- `dump_scripts`
- `inspect_mb`
- `preview_clean`
- `preview_replace`
- `replace`
- `to_ascii`
- `MayaSceneKitError`

## Patterns

### Audit Before Open

This is an operational pattern using the current API surface, not a dedicated callback API:

```python
from maya_scene_kit import audit

report = audit("scene.mb", max_preview=120)

if report["blocked_on_uncertainty"]:
    raise RuntimeError("manual review required before open")

if report["disposition"] not in {"allow", "allow_with_notice"}:
    raise RuntimeError(f"scene blocked: {report['disposition']}")

# Continue with your own tool's open or import flow.
```

Useful audit report fields include:

- `disposition`
- `validation_state`
- `coverage_state`
- `blocked_on_uncertainty`
- `finding_count`
- `review_signal_count`
- `notice_count`

### Inspect Maya Binary Structure

```python
from maya_scene_kit import inspect_mb

report = inspect_mb("scene.mb", max_depth=1, preview_bytes=24)
print(report["scene_format"])
print(report["root"]["tag"])
```

### Extract File And Reference Paths

```python
from maya_scene_kit import collect_paths

report = collect_paths("scene.ma", kind="reference")
for entry in report["entries"]:
    print(entry["node_name"], entry["value"])
```

`kind="file"` includes `fileTextureName` owners such as `file`, `psdFileTex`, and `movie`.

### Preview Mutations Before Writing

```python
from maya_scene_kit import preview_clean, preview_replace

clean_preview = preview_clean("scene.mb")
replace_preview = preview_replace("scene.mb", [("V:/dcc", "X:/dcc")])

print(clean_preview["removed_count"])
print(replace_preview["matched_count"])
```

### Materialize Outputs

```python
from maya_scene_kit import clean, replace, to_ascii

clean("scene.mb", "scene_clean.mb")
replace("scene.mb", "scene_paths.mb", [("V:/dcc", "X:/dcc")])
to_ascii("scene.mb", "scene.ma", mode="best_effort")
```

## Error Handling

The binding raises `MayaSceneKitError`.
The exception carries the Rust-side message, and common error categories include:

- `unsupported_scene_format`
- `config`
- `ascii_syntax`
- `encode_invariant`
- `atomic_write`
- `invalid_utf8`
- `rejected_by_mode`
- `io`
- `parse`

## Related Docs

- [README](../README.md)
- [Advanced usage](advanced_usage.md)
