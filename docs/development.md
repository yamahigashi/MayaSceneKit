# Development

This document is for people building, testing, or changing this repository.
For end-user Python package usage, see [Python usage](python_usage.md).

## Workspace Shape

The repository is a layered Rust workspace:

- `crates/maya-scene-kit-formats`: low-level `.ma` / `.mb` parsing, spans,
  bytes, and format-native rewrite helpers
- `crates/maya-scene-kit-observe`: scene facts, recovery, schema lookup,
  diagnostics, and read-only query surfaces
- `crates/maya-scene-kit-audit`: rules, findings, severities, and gate decisions
- `crates/maya-scene-kit-edit`: patch planning, rewrite/materialization,
  conversion, and write-path reporting
- `crates/maya-scene-kit-cli`: command-line adapter
- `crates/maya-scene-kit-gui`: desktop adapter
- `crates/maya-scene-kit-python`: Python binding adapter

## Verification

Use targeted tests for the crates affected by a change:

```bash
cargo test -p maya-scene-kit-observe
cargo test -p maya-scene-kit-audit
cargo test -p maya-scene-kit-edit
cargo test -p maya-scene-kit-cli
```

Run the layer checker after changes that affect crate boundaries, manifests, or
cross-layer ownership:

```bash
python .agents/references/layer-boundary-review/scripts/check_layering.py --root .
```

For docs-only changes, at minimum check Markdown diffs for whitespace errors:

```bash
git diff --check
```

## Python Binding Development

The Python binding lives in `crates/maya-scene-kit-python`.

Build a wheel with `uv` and `maturin`:

```powershell
uv run --with maturin maturin build --manifest-path crates/maya-scene-kit-python/Cargo.toml
```

Built wheels are written to `target\wheels\`.
On Windows the filename will end in `win_amd64.whl`.

Install a locally built wheel:

```powershell
uv pip install --system .\target\wheels\maya_scene_kit-*.whl
```

Quick source-tree smoke test:

```powershell
python -c "import maya_scene_kit; print(maya_scene_kit.inspect_mb('tests/02/sphere.mb', max_depth=0)['scene_format'])"
```

Use `maturin develop` when you want an editable local environment instead of a
wheel build:

```powershell
uv venv
.venv\Scripts\Activate.ps1
uv pip install maturin
maturin develop --manifest-path crates/maya-scene-kit-python/Cargo.toml
```

The Rust-side binding tests live with the adapter crate:

```bash
cargo test -p maya-scene-kit-python
```

Those tests link against the local Python development library. If the linker
reports a missing `-lpythonX.Y`, install the matching Python development package
or run the tests in an environment that provides it.

## Related Docs

- [Python usage](python_usage.md)
- [Advanced usage](advanced_usage.md)
- [Supplying and extrapolating studio-specific Maya node knowledge](node_info_authoring.md)
