# Python Usage

`maya-scene-kit` exposes Python bindings for inspecting and auditing Maya scenes
before another tool opens them.

This document is for people using the Python package. For source builds and
repository development, see [Development](development.md).

## Install

Download a release wheel from GitHub Releases and install it with `pip`:

```powershell
$wheel = Get-ChildItem .\maya_scene_kit-*.whl | Select-Object -First 1
python -m pip install $wheel.FullName
```

If you use `uv`, the equivalent install command is:

```powershell
uv pip install --system .\maya_scene_kit-*.whl
```

## Use From An Extracted Wheel Without Installation

If you cannot install into the target Python environment, use the wheel as a ZIP
archive and point Python at the extracted package directory instead. Choose a
wheel that matches the target OS and CPU architecture.

```powershell
$wheel = Get-ChildItem .\maya_scene_kit-*.whl | Select-Object -First 1
New-Item -ItemType Directory -Force C:\tools\maya_scene_kit_pkg
python -m zipfile -e $wheel.FullName C:\tools\maya_scene_kit_pkg
$env:PYTHONPATH = "C:\tools\maya_scene_kit_pkg;$env:PYTHONPATH"
```

For embedded Python hosts, add the extracted wheel directory before importing:

```python
import sys

sys.path.insert(0, r"C:\tools\maya_scene_kit_pkg")

import maya_scene_kit
```

The directory added to `PYTHONPATH` or `sys.path` must be the directory that
contains the extracted `maya_scene_kit` package directory.

Quick import check:

```powershell
python -c "import maya_scene_kit; print('maya_scene_kit ok')"
```

## Exported API

The package currently exports:

- `inspect_mb(path, max_depth=None, preview_bytes=24, max_bytes=None)`
- `dump_scripts(path, max_bytes=None)`
- `dump_requires(path, max_bytes=None)`
- `collect_paths(path, kind="all", max_bytes=None)`
- `audit(path, rules=[], max_preview=96, include_digests=True, node_info_paths=[], max_bytes=None)`
- `preview_clean(path, max_bytes=None)`
- `clean(input_path, output_path, max_bytes=None)`
- `preview_replace(path, rules, max_bytes=None)`
- `replace(input_path, output_path, rules, max_bytes=None)`
- `to_ascii(input_path, output_path, mode="best_effort", embed_metadata=False, node_info_paths=[], max_bytes=None)`
- `MayaSceneKitError`

`rules` is a list of literal audit markers. `node_info_paths` accepts additional
YAML files using the same semantics as the CLI `--node-info` option. Python
operation mode names use underscores, for example `best_effort`.

## Patterns

### Audit Before Open

This is an operational pattern using the current API surface, not a dedicated
callback API. For tool code that owns the open/import flow, gate the open before
calling into the host:

```python
from maya_scene_kit import audit

report = audit("scene.mb", max_preview=120)

if report["blocked_on_uncertainty"]:
    raise RuntimeError("manual review required before open")

if report["disposition"] not in {"allow", "allow_with_notice"}:
    raise RuntimeError(f"scene blocked: {report['disposition']}")

# Continue with your own tool's open or import flow.
```

`disposition` is one of `allow`, `allow_with_notice`, `review`,
`deny_uncertain`, or `deny_malicious`. The binding uses the `strict_default`
audit profile, so `deny_uncertain` is not emitted; uncertainty surfaces as
`review` with `blocked_on_uncertainty` set. Gating on the allowed set above stays
correct regardless of profile. For the full gate semantics and the limits of
what `audit` inspects, see the
[Audit Model](advanced_usage.md#audit-model).

For Maya startup integration, register check callbacks and return `False` when
the scene should not be opened or referenced. This example is intentionally
standalone: adapt the UI text, override permissions, `node_info_paths`, and
`max_bytes` for your studio policy.

```python
import logging

from maya.api import OpenMaya as om
from maya import cmds

import maya_scene_kit
from maya_scene_kit import MayaSceneKitError

LOG = logging.getLogger(__name__)

ALLOWED_DISPOSITIONS = {"allow", "allow_with_notice"}
CALLBACK_IDS = []
NODE_INFO_PATHS = []
MAX_PREVIEW = 120
MAX_BYTES = None
MAX_DIALOG_ROWS = 8


def _scene_path_from_callback(file_object):
    if not file_object:
        return ""
    return om.MFileObject(file_object).resolvedFullName()


def _is_allowed(report):
    if report.get("blocked_on_uncertainty", False):
        return False
    return report.get("disposition") in ALLOWED_DISPOSITIONS


def _report_rows(report):
    rows = []
    for scene_report in report.get("reports", []):
        for field in ("findings", "review_signals"):
            for item in scene_report.get(field, []):
                code = item.get("code") or "unknown"
                text = item.get("preview_override") or item.get("message") or ""
                rows.append("[{}] {}".format(code, text).strip())
                if len(rows) >= MAX_DIALOG_ROWS:
                    return rows
    return rows


def _confirm_open_anyway(path, report):
    rows = _report_rows(report)
    summary = [
        "maya-scene-kit blocked this scene.",
        "",
        "File: {}".format(path),
        "Disposition: {}".format(report.get("disposition", "unknown")),
        "Findings: {}".format(report.get("finding_count", 0)),
        "Review signals: {}".format(report.get("review_signal_count", 0)),
    ]
    if report.get("blocked_on_uncertainty", False):
        summary.append("Audit coverage was uncertain.")
    if rows:
        summary.extend(["", "Details:", *rows])

    choice = cmds.confirmDialog(
        title="Scene audit blocked open",
        message="\n".join(summary),
        button=["Cancel Open", "Open Anyway"],
        defaultButton="Cancel Open",
        cancelButton="Cancel Open",
        dismissString="Cancel Open",
        icon="warning",
    )
    if choice != "Open Anyway":
        return False

    second_choice = cmds.confirmDialog(
        title="Open scene anyway?",
        message="Open this scene despite the audit result?\n\n{}".format(path),
        button=["Cancel Open", "Open Anyway"],
        defaultButton="Cancel Open",
        cancelButton="Cancel Open",
        dismissString="Cancel Open",
        icon="warning",
    )
    return second_choice == "Open Anyway"


def _show_audit_error(path, error):
    cmds.confirmDialog(
        title="Scene audit failed",
        message=(
            "maya-scene-kit could not audit this scene, so the open was blocked.\n\n"
            "File: {}\n\n{}"
        ).format(path, error),
        button=["Cancel Open"],
        defaultButton="Cancel Open",
        cancelButton="Cancel Open",
        dismissString="Cancel Open",
        icon="critical",
    )


def _audit_scene_before_open(file_object, client_data):
    path = _scene_path_from_callback(file_object)
    if not path:
        return True

    try:
        report = maya_scene_kit.audit(
            path,
            max_preview=MAX_PREVIEW,
            node_info_paths=NODE_INFO_PATHS,
            max_bytes=MAX_BYTES,
        )
    except MayaSceneKitError as error:
        LOG.exception("maya-scene-kit audit failed for %s", path)
        _show_audit_error(path, error)
        return False

    if _is_allowed(report):
        return True

    LOG.warning(
        "maya-scene-kit blocked %s with disposition=%s",
        path,
        report.get("disposition", "unknown"),
    )
    return _confirm_open_anyway(path, report)


def install_scene_audit_callbacks():
    if CALLBACK_IDS:
        return

    for message in (
        om.MSceneMessage.kBeforeOpenCheck,
        om.MSceneMessage.kBeforeReferenceCheck,
        om.MSceneMessage.kBeforeLoadReferenceCheck,
    ):
        callback_id = om.MSceneMessage.addCheckFileCallback(
            message,
            _audit_scene_before_open,
        )
        CALLBACK_IDS.append(callback_id)


def remove_scene_audit_callbacks():
    while CALLBACK_IDS:
        om.MMessage.removeCallback(CALLBACK_IDS.pop())
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
- `message`
- `config`
- `ascii_syntax`
- `unsupported_ascii_feature`
- `encode_invariant`
- `atomic_write`
- `invalid_utf8`
- `rejected_by_mode`
- `io`
- `mel_parse_budget_exceeded`
- `mb_parse_budget_exceeded`
- `parse`

## Related Docs

- [README](../README.md)
- [Advanced usage](advanced_usage.md)
- [Development](development.md)
