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

## Releasing

Prepare the release on one commit:

1. Move the [Unreleased] entries in CHANGELOG.md into a section headed
   "## [vX.Y.Z] - YYYY-MM-DD". Include Migration notes when behaviour or output
   changes, and leave an empty [Unreleased] section for future work.
2. Bump the version in [workspace.package] in Cargo.toml. The Python package
   follows Cargo through its dynamic version. Run cargo check to update the
   workspace crate versions in Cargo.lock, and include that file in the commit.
3. Commit the release changes with the message "release: vX.Y.Z".
4. Create an annotated tag vX.Y.Z-rc.1 on that commit with git tag -a, then
   push the commit and tag. This publishes a pre-release with Python wheel
   version X.Y.Zrc1; later candidates use X.Y.ZrcN.
5. If you need fixes, commit them and create and push a new annotated tag
   vX.Y.Z-rc.N+1 on the corrected commit. Increment only N in the version;
   keep the base version X.Y.Z and its CHANGELOG.md section. Do not move an
   existing candidate tag.
6. When the candidate is stable, create and push the annotated tag vX.Y.Z on
   the same commit as the accepted candidate.

The committed [workspace.package] version is always X.Y.Z; the rc rewrite happens
only in CI (build_python), never in a commit.

The annotated tag message convention applies from v0.4.0 on; earlier tags carry
only the tag name. For each annotated tag message, use "maya-scene-kit vX.Y.Z" (or
"maya-scene-kit vX.Y.Z-rc.N") as the first line, followed by a blank line and
then the intro paragraph of the CHANGELOG.md section.

The release workflow generates the GitHub Release description from CHANGELOG.md.
Both stable and candidate tags use the base vX.Y.Z section; candidates include
an introductory pre-release notice. The release fails before builds if the
section is missing, duplicated, or empty.

## Related Docs

- [Python usage](python_usage.md)
- [Advanced usage](advanced_usage.md)
- [Supplying and extrapolating studio-specific Maya node knowledge](node_info_authoring.md)
