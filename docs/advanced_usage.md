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

## Embedded Schema And `node_info` Overlays

CLI commands use the embedded schema bundle shipped with the binary.
The only external schema-like input accepted by the CLI is repeatable `--node-info`
overlay files.

Node-info merge order for `.mb` reads and `to-ascii` is:

1. Embedded built-in `node_info`
2. `--node-info` files in argument order, with later files winning

Angular `setAttr` conversion (radian payload to degree output) uses node-local
rules from merged `node_info` data (`node_type + attrs.{token}.unit/kind`), plus
`addAttr`-defined custom `doubleAngle` and `floatAngle` attributes in the scene.

## Generate `plugin_node_info.yaml`

Use this `mayapy` snippet to dump a single YAML file (`plugin_node_info.yaml`) as
seed data for node-based semantics review (`node_type + typeid + attrs(unit=angle)`).

```python
import maya.standalone
maya.standalone.initialize(name="python")

import re
import maya.cmds as cmds
import maya.api.OpenMaya as om

# Load one or more plugins before collecting node type ids.
plugins = ["yourPluginA", "yourPluginB"]
for plugin in plugins:
    if not cmds.pluginInfo(plugin, q=True, loaded=True):
        cmds.loadPlugin(plugin, quiet=True)

node_types = []
for plugin in plugins:
    node_types.extend(cmds.pluginInfo(plugin, q=True, dependNode=True) or [])

def yaml_quote(value):
    value = value.replace("\\", "\\\\").replace("\"", "\\\"")
    return f"\"{value}\""

def yaml_token(value):
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value):
        return value
    return yaml_quote(value)

def collect_angle_attrs(node_class):
    out = {}
    attr_count = node_class.attributeCount
    for idx in range(attr_count):
        attr_obj = node_class.attribute(idx)
        fn_attr = om.MFnAttribute(attr_obj)
        short_name = fn_attr.shortName
        long_name = fn_attr.name

        if attr_obj.hasFn(om.MFn.kUnitAttribute):
            fn_unit = om.MFnUnitAttribute(attr_obj)
            if fn_unit.unitType == om.MFnUnitAttribute.kAngle:
                key = short_name or long_name
                aliases = [name for name in [long_name] if name and name != key]
                out[key] = {"kind": "scalar", "aliases": aliases}
                continue

        if attr_obj.hasFn(om.MFn.kCompoundAttribute):
            fn_compound = om.MFnCompoundAttribute(attr_obj)
            angle_children = []
            for cidx in range(fn_compound.numChildren):
                child_obj = fn_compound.child(cidx)
                if not child_obj.hasFn(om.MFn.kUnitAttribute):
                    continue
                fn_child_unit = om.MFnUnitAttribute(child_obj)
                if fn_child_unit.unitType != om.MFnUnitAttribute.kAngle:
                    continue
                fn_child_attr = om.MFnAttribute(child_obj)
                angle_children.append((fn_child_attr.shortName, fn_child_attr.name))

            if len(angle_children) >= 2:
                key = short_name or long_name
                aliases = [name for name in [long_name] if name and name != key]
                out[key] = {"kind": "vector3", "aliases": aliases}
                for child_short, child_long in angle_children:
                    child_key = child_short or child_long
                    child_aliases = [name for name in [child_long] if name and name != child_key]
                    out[child_key] = {"kind": "scalar", "aliases": child_aliases}
    return out

node_info = {}
for node_type in sorted(set(node_types)):
    try:
        node_class = om.MNodeClass(node_type)
        type_id = node_class.typeId.id()
    except Exception:
        continue

    node_info[node_type] = {
        "typeid": f"0x{type_id:08X}",
        "attrs": collect_angle_attrs(node_class),
    }

out_path = "plugin_node_info.yaml"
with open(out_path, "w", encoding="utf-8") as f:
    f.write("version: 1\n")
    f.write("nodes:\n")
    for node_type in sorted(node_info.keys()):
        info = node_info[node_type]
        f.write(f"  {yaml_token(node_type)}:\n")
        f.write(f"    typeid: {info['typeid']}\n")
        f.write("    attrs:\n")
        attrs = info["attrs"]
        if not attrs:
            f.write("      {}\n")
            continue
        for attr_name in sorted(attrs.keys()):
            rule = attrs[attr_name]
            aliases = ", ".join(yaml_quote(v) for v in rule["aliases"])
            f.write(
                f"      {yaml_token(attr_name)}: "
                f"{{ unit: angle, kind: {rule['kind']}, aliases: [{aliases}] }}\n"
            )

print(f"written: {out_path} ({len(node_info)} node types)")
```

Use `plugin_node_info.yaml` as review input when curating node-specific semantics.

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
