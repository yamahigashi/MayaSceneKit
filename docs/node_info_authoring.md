# Supplying and Extrapolating Studio-Specific Maya Node Knowledge

This document is for studio administrators, pipeline administrators, and schema
curators who maintain site-specific Maya and plugin node semantics.

`node_info` is the YAML format used by the `--node-info` option. Additional
`node_info` files let a studio inject private or environment-specific node
knowledge without rebuilding `maya-scene-kit` and without committing that
knowledge to the public schema bundle. For runtime `--node-info` usage, see
[Advanced usage](advanced_usage.md).

Most users do not need to create these files. They are meant for people who
administer a Maya environment and know which plugins are loaded, which custom
nodes they provide, and which node attributes have semantic meaning.

Treat an additional `node_info` file as trusted configuration. It can affect:

- `.mb` node type identification through `typeid`
- angular value interpretation through `attrs`
- audit coverage through curated `execution.profiles`

Do not promote generated data directly into runtime use. Generate seed data,
review it, remove private or irrelevant material as needed, and keep only the
semantic entries that the site is prepared to trust.

## Start from This Shape

A curated file should be small enough to review and should describe the whole
node entry it overrides or adds:

```yaml
version: 1
nodes:
  ExampleRenderNode:
    typeid: 0x45584D50
    attrs:
      rx: { unit: angle, kind: scalar, aliases: [rotateX] }
      r: { unit: angle, kind: vector3, aliases: [rotate] }
      prm: { unit: none, kind: scalar, aliases: [preRenderMel] }
    execution:
      profiles:
        - kind: attr_callbacks
          default_language: mel
          default_trigger: render
          attrs: [preRenderMel]
```

`attrs` entries are keyed by the Maya short attribute name when one exists.
Aliases normally carry the long attribute name and may also include additional
known spellings. Execution profiles may refer to either the short name or an
alias, but they are normalized to the short name during loading.

## Authoring Workflow

Use this workflow when introducing a studio-specific file:

1. Load the relevant Maya plugins in a controlled environment.
2. Generate a seed file for plugin node types, type ids, and attribute tables.
3. Review the generated node list and remove nodes the site does not intend to
   support.
4. Review angular attrs. Keep `unit: angle` only where the value is actually an
   angular scalar or angular vector.
5. Add execution profiles manually only for attributes known to carry script or
   callback payloads.
6. Validate the file with representative `.ma` and `.mb` scenes through a CLI
   command that accepts `--node-info`.
7. If any example, fixture, or documentation copy is checked into this public
   repository, replace all real project names, asset names, paths, identifiers,
   and scene fragments with generic synthetic vocabulary.

## Field Reference

| Field | Meaning | Accepted values |
| --- | --- | --- |
| `version` | Schema version for this YAML file. | `1` |
| `nodes.<nodeType>` | Maya node type entry. Lookup is normalized for matching, while the written name remains the display name. | Non-empty string |
| `typeid` | Maya plugin/custom node type id used to identify `.mb` nodes. | Decimal integer, quoted decimal string, or `0x` hex |
| `attrs.<shortName>` | Node-local attribute entry. Prefer the Maya short name as the key. | Non-empty string |
| `attrs.*.unit` | Unit semantics used by angular conversion. Non-angular attrs should still be listed when execution profiles need aliases. | `angle` or `none` |
| `attrs.*.kind` | Shape of an angular value. | `scalar` or `vector3` |
| `attrs.*.aliases` | Long name and other accepted references for the same attr. The first alias is used as the long display label. | List of strings |
| `execution.profiles[].kind` | Execution profile shape. | `attr_callbacks` or `script_node` |
| `execution.profiles[].attrs` | Callback attrs for `attr_callbacks`. | Attr short names or aliases listed under `attrs` |
| `execution.profiles[].default_language` | Language assigned to callback attrs when no per-attr decoder exists. | `mel`, `python`, or `unknown` |
| `execution.profiles[].default_trigger` | Trigger assigned to callback attrs. | `unknown`, `manual`, `file_open`, `file_close`, `gui_open_close`, `render`, `time_changed`, or `event_hook` |
| `execution.profiles[].body_attrs` | Script body attrs for `script_node`. | Attr short names or aliases listed under `attrs` |
| `execution.profiles[].trigger_attr` | Optional attr used to infer a `script_node` trigger. | Attr short name or alias listed under `attrs` |
| `execution.profiles[].trigger_decoder` | Decoder for `trigger_attr`. | `maya_script_node_script_type` or `maya_script_node_source_type` |
| `execution.profiles[].language_attr` | Optional attr used to infer a `script_node` language. | Attr short name or alias listed under `attrs` |
| `execution.profiles[].language_decoder` | Decoder for `language_attr`. | `maya_script_node_script_type` or `maya_script_node_source_type` |

Only `unit: angle` attrs participate in angular interpretation. Non-angular
entries still matter because `attrs` is also the validation table for execution
profile attr references.

## Overlay Behavior

CLI commands use the embedded schema bundle first, then apply repeatable
`--node-info` files in argument order. Later files win.

Overlays replace a node entry as a whole. They do not deep-merge one attr or one
execution profile into an earlier node entry. When a file overrides a node that
already exists in the embedded schema or in an earlier overlay, include the full
node entry that should be used at runtime.

## Generate a Typeid and Attribute Seed

Use this `mayapy` snippet to dump a seed YAML file
(`plugin_node_info_seed.yaml`) for node-based semantics review. It collects
plugin node types, type ids, and the attributes exposed by those node types.
Angular attributes are marked when the Maya API exposes that unit information.
Non-angular entries are emitted with `unit: none` so the file also carries a
usable attribute table for aliases and execution-profile validation.

The seed does not infer execution profiles and should not be treated as a
complete `node_info` file.

```python
import maya.standalone
maya.standalone.initialize(name="python")

import re
import maya.cmds as cmds
import maya.api.OpenMaya as om

# Load one or more plugins before collecting node type ids.
plugins = ["ExamplePluginA", "ExamplePluginB"]
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

def attr_entry(unit="none", kind="scalar", aliases=None):
    return {"unit": unit, "kind": kind, "aliases": aliases or []}

def add_attr(out, short_name, long_name, unit="none", kind="scalar"):
    key = short_name or long_name
    if not key:
        return
    aliases = [name for name in [long_name] if name and name != key]
    out[key] = attr_entry(unit=unit, kind=kind, aliases=aliases)

def unit_for_attr(attr_obj):
    if not attr_obj.hasFn(om.MFn.kUnitAttribute):
        return "none"
    fn_unit = om.MFnUnitAttribute(attr_obj)
    if fn_unit.unitType == om.MFnUnitAttribute.kAngle:
        return "angle"
    return "none"

def collect_attr_seed(node_class):
    out = {}
    attr_count = node_class.attributeCount
    for idx in range(attr_count):
        attr_obj = node_class.attribute(idx)
        fn_attr = om.MFnAttribute(attr_obj)
        short_name = fn_attr.shortName
        long_name = fn_attr.name

        if attr_obj.hasFn(om.MFn.kCompoundAttribute):
            fn_compound = om.MFnCompoundAttribute(attr_obj)
            child_units = []
            child_count = fn_compound.numChildren
            for cidx in range(fn_compound.numChildren):
                child_obj = fn_compound.child(cidx)
                fn_child_attr = om.MFnAttribute(child_obj)
                child_unit = unit_for_attr(child_obj)
                child_units.append(child_unit)
                add_attr(
                    out,
                    fn_child_attr.shortName,
                    fn_child_attr.name,
                    unit=child_unit,
                    kind="scalar",
                )

            parent_unit = "angle" if child_units.count("angle") >= 2 else "none"
            parent_kind = "vector3" if child_count >= 2 else "scalar"
            add_attr(out, short_name, long_name, unit=parent_unit, kind=parent_kind)
            continue

        add_attr(out, short_name, long_name, unit=unit_for_attr(attr_obj), kind="scalar")

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
        "attrs": collect_attr_seed(node_class),
    }

out_path = "plugin_node_info_seed.yaml"
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
                f"{{ unit: {rule['unit']}, kind: {rule['kind']}, aliases: [{aliases}] }}\n"
            )

print(f"written: {out_path} ({len(node_info)} node types)")
```

Use `plugin_node_info_seed.yaml` as review input when curating site-specific node
semantics. If a `node_info` file or fixture is checked into this public
repository, do not copy real project names, paths, asset identifiers, or scene
fragments into the checked-in data.

## Curate Execution Semantics Separately

Execution profiles should be added only for attributes that are known to be
script or callback payloads in the studio environment. A curated entry should
name the node, declare the relevant attrs, and choose the execution language and
trigger deliberately.

Callback attrs use `attr_callbacks`:

```yaml
version: 1
nodes:
  ExampleRenderNode:
    typeid: 0x45584D50
    attrs:
      prm: { unit: none, kind: scalar, aliases: [preRenderMel] }
    execution:
      profiles:
        - kind: attr_callbacks
          default_language: mel
          default_trigger: render
          attrs: [preRenderMel]
```

Script-like nodes use `script_node` when one or more attrs hold script bodies and
other attrs encode language or trigger values:

```yaml
version: 1
nodes:
  ExampleScriptNode:
    typeid: 0x45584D51
    attrs:
      b: { unit: none, kind: scalar, aliases: [beforeScript] }
      a: { unit: none, kind: scalar, aliases: [afterScript] }
      st: { unit: none, kind: scalar, aliases: [scriptType] }
      stp: { unit: none, kind: scalar, aliases: [sourceType] }
    execution:
      profiles:
        - kind: script_node
          body_attrs: [beforeScript, afterScript]
          trigger_attr: scriptType
          trigger_decoder: maya_script_node_script_type
          language_attr: sourceType
          language_decoder: maya_script_node_source_type
```

The `attrs` section is required for execution attrs because profile attr
references are validated against the node's attr table and normalized to the
short attr name.

## Validate Before Runtime Use

There is no separate public `node_info` linter command. Load the file through a
CLI command that accepts `--node-info`; schema parsing and profile attr
validation happen before the command uses the scene:

```bash
cargo run -p maya-scene-kit-cli -- paths tests/fixtures/semantic/custom_unknown_node.ma --node-info site_node_info.yaml --json
cargo run -p maya-scene-kit-cli -- audit tests/fixtures/semantic/custom_unknown_node.ma --node-info site_node_info.yaml --json
```

Use representative `.mb` scenes when validating `typeid` and angular conversion,
because those entries primarily affect binary recovery and conversion. Use
representative `.ma` or `.mb` scenes when validating execution profiles, because
both formats can expose execution surfaces.

## Execution Candidate Review

Internal development environments may provide research tooling that emits a
review-only list of suspicious string attrs, for example by passing
`--execution-candidates-file execution_attr_candidates.json` to an internal Maya
attribute-map dumper.

Do not feed that candidate file directly to runtime loading. Runtime audit only
consumes curated `node_info.execution` profiles that are checked into the schema
bundle or provided through explicit `--node-info` files.

## Curation Checklist

Before using or publishing a `node_info` file, confirm that:

- `version` is `1`
- every overridden node entry is complete
- every `typeid` was collected from the intended plugin version
- every execution attr is present in the same node's `attrs`
- every `unit: angle` entry is intentionally angular
- generated execution candidates were reviewed by a human before promotion
- public examples, fixtures, and docs use only generic synthetic vocabulary

## Related Docs

- [Advanced usage](advanced_usage.md)
- [Development](development.md)
