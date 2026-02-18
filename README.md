# maya-scene-kit

`maya-scene-kit` is a standalone CLI for working with Maya scene files (`.mb` / `.ma`) without requiring a Maya runtime.

Main use cases:
- Remove script nodes (`clean`)
- Export requires + script bodies (`dump`)
- Audit script bodies against NG rules (`audit`)
- Inspect `.mb` chunk structure (`inspect`)
- Convert `.mb -> .ma` on a best-effort basis (`to-ascii`, experimental)

## Installation (No Development Environment Needed)

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

## Recommended Command Order

### 1) `clean` (remove script nodes and save)

```bash
maya-scene-kit clean input.mb output_clean.mb
maya-scene-kit clean input.ma output_clean.ma
```

### 2) `dump` (export requires + script together)

```bash
# Print one file to stdout
maya-scene-kit dump tests/02/sphere.mb

# Save one file to disk
maya-scene-kit dump tests/02/sphere.mb --out /tmp/sphere_scene_dump.txt

# Recursively process a directory and write outputs
maya-scene-kit dump tests --out-dir /tmp/scene_dump_dir
```

### 3) `audit` (match script bodies against NG rules)

```bash
maya-scene-kit audit tests/02/sphere.mb --rule "python(" --rule "eval"
maya-scene-kit audit tests --rule-file /tmp/ng_rules.txt --ignore-case
maya-scene-kit audit tests/02/sphere.mb --rule "python\\(" --regex --json
```

- If no rules are specified, default rules are used: `python(` / `eval` / `exec`.
- If you omit the command and pass only `<file-or-dir>`, `audit` runs by default.

### 4) `inspect` (show chunk structure)

```bash
maya-scene-kit inspect tests/02/sphere.mb --max-depth 2
maya-scene-kit inspect tests/02/sphere.mb --preview-bytes 32
```

### 5) `to-ascii` (`.mb -> .ma` conversion)

```bash
maya-scene-kit to-ascii tests/02/sphere.mb /tmp/sphere_best_effort.ma
```

**Experimental**

`to-ascii` is an experimental feature. It is best-effort, so generated `.ma` output may be incomplete or invalid.

## Current Scope

- IFF chunk parsing for `.mb` (`tag / offset / aux / size`)
- Script node detection/removal/extraction for `.ma/.mb`
- Requires extraction for `.ma/.mb`
- Best-effort `.mb -> .ma` conversion (partial recovery of major chunks/attributes/links)
