# maya-scene-kit

`maya-scene-kit` is a standalone CLI for working with Maya scene files (`.mb` / `.ma`) without requiring a Maya runtime.

Main use cases:
- Remove script nodes (`clean`)
- Export requires + script bodies (`dump`)
- Extract file/reference paths (`paths`)
- Rewrite file/reference paths (`replace`)
- Audit script bodies against NG rules (`audit`)
- Inspect `.mb` chunk structure (`inspect`)
- Convert `.mb -> .ma` on a best-effort basis (`to-ascii`, experimental)

## Installation

Download the binary for your OS from GitHub Releases.

1. Open the Releases page
2. Download the `maya-scene-kit` executable (for Windows, `.exe`)
3. Place it in any folder and run it

Example (Windows):

```powershell
maya-scene-kit.exe --help
```

## Basic Usage

```bash
maya-scene-kit <command> [options]
```

## Common Tasks

### `clean` (remove script nodes and save)

```bash
maya-scene-kit clean input.mb output_clean.mb
maya-scene-kit clean input.ma output_clean.ma
```

### `dump` (export requires + script together)

```bash
# Print one file to stdout
maya-scene-kit dump tests/02/sphere.mb

# Save one file to disk
maya-scene-kit dump tests/02/sphere.mb --out /tmp/sphere_scene_dump.txt

# Recursively process a directory and write outputs
maya-scene-kit dump tests --out-dir /tmp/scene_dump_dir
```

### `audit` (match script bodies against NG rules)

```bash
maya-scene-kit audit tests/02/sphere.mb --rule "python(" --rule "eval"
maya-scene-kit audit tests --rule-file /tmp/ng_rules.txt --ignore-case
maya-scene-kit audit tests/02/sphere.mb --rule "python\\(" --regex --json
```

- If no rules are specified, default rules are used: `python(` / `eval` / `exec`.
- If you omit the command and pass only `<file-or-dir>`, `audit` runs by default.

### `paths` (extract file/reference paths)

```bash
# Extract all path-like entries from one file
maya-scene-kit paths tests/02/sphere.ma

# Extract only file node paths
maya-scene-kit paths tests --kind file

# Extract only reference node paths and save outputs by directory
maya-scene-kit paths tests --kind reference --out-dir /tmp/scene_paths_dir

# JSON output (includes origin metadata for FREF-based references)
maya-scene-kit paths --kind reference --json tests/02/sphere.mb
```

### `replace` (rewrite path strings in `.ma/.mb`)

```bash
# Single file output
maya-scene-kit replace input.mb --rule "V:/dcc=X:/dcc" --out output.mb

# Multiple rules
maya-scene-kit replace input.mb \
  --rule "V:/dcc=X:/dcc" \
  --rule "rig/=asset/" \
  --out output.mb

# Rules from file (one FROM=TO per line, '#' comments allowed)
maya-scene-kit replace input.mb --rule-file /tmp/replace_rules.txt --out output.mb

# Directory input (recursive) -> mirrored output directory
maya-scene-kit replace scenes --rule "old_root/=new_root/" --out-dir /tmp/rewritten_scenes
```

### `inspect` (show chunk structure)

```bash
maya-scene-kit inspect tests/02/sphere.mb --max-depth 2
maya-scene-kit inspect tests/02/sphere.mb --preview-bytes 32
```

### `to-ascii` (`.mb -> .ma` conversion)

```bash
maya-scene-kit to-ascii tests/02/sphere.mb /tmp/sphere_best_effort.ma
```

**Experimental**

`to-ascii` is an experimental feature. It is best-effort, so generated `.ma` output may be incomplete or invalid.

## Current Scope

- IFF chunk parsing for `.mb` (`tag / offset / aux / size`)
- Script node detection/removal/extraction for `.ma/.mb`
- Requires extraction for `.ma/.mb`
- File/reference path extraction for `.ma/.mb`
- Best-effort `.mb -> .ma` conversion (partial recovery of major chunks/attributes/links)
