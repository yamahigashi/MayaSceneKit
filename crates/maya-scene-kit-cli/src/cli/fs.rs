use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use serde_json::json;
use thiserror::Error;

use super::output_contracts::{JSON_CONTRACT_VERSION, scene_path_kind_label};
use crate::scene::{
    LoadOptions, PathKind, SceneToolError, collect_scene_paths_with_options,
    render_scene_dump_with_options, write_output_bytes_atomic,
};

#[derive(Debug, Error)]
pub(crate) enum CliOutputError {
    #[error(transparent)]
    Scene(#[from] SceneToolError),
    #[error("json render error: {0}")]
    JsonRender(String),
}

pub(crate) fn write_scene_dump(
    input: &Path,
    output: &Path,
    load_options: &LoadOptions,
) -> Result<(), CliOutputError> {
    let text = render_scene_dump_text(input, load_options)?;
    write_output_bytes(output, text.as_bytes())?;
    Ok(())
}

pub(super) fn write_scene_paths(
    input: &Path,
    kind: PathKind,
    output: &Path,
    json_output: bool,
    load_options: &LoadOptions,
) -> Result<(), CliOutputError> {
    let text = if json_output {
        render_scene_paths_json(input, kind, load_options)?
    } else {
        render_scene_paths_text(input, kind, load_options)?
    };
    write_output_bytes(output, text.as_bytes())?;
    Ok(())
}

pub(super) fn write_output_bytes(output: &Path, bytes: &[u8]) -> Result<(), CliOutputError> {
    write_output_bytes_atomic(output, bytes)?;
    Ok(())
}

pub(super) fn render_scene_paths_text(
    input: &Path,
    kind: PathKind,
    load_options: &LoadOptions,
) -> Result<String, CliOutputError> {
    let report = collect_scene_paths_with_options(input, kind, load_options)?;
    let kind_label = scene_path_kind_label(kind);
    let mut out = format!(
        "# maya-scene-kit Scene Paths\nsource: {}\nformat: {}\nkind: {}\ncount: {}\n",
        report.scene_path.display(),
        report.scene_format,
        kind_label,
        report.entries.len()
    );

    for e in report.entries {
        let value = e
            .value
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        out.push_str(&format!(
            "- node_type={} node={} attr={} value=\"{}\"\n",
            e.node_type, e.node_name, e.attr, value
        ));
        if let Some(meta) = e.meta {
            let mut bits = Vec::new();
            bits.push(format!("origin={}", meta.origin));
            if let Some(v) = meta.short_name {
                bits.push(format!("short_name={}", v));
            }
            if let Some(v) = meta.reference_node {
                bits.push(format!("reference_node={}", v));
            }
            if let Some(v) = meta.format_hint {
                bits.push(format!("format_hint={}", v));
            }
            if let Some(v) = meta.reference_options {
                bits.push(format!("reference_options={}", v));
            }
            if let Some(v) = meta.color_space {
                bits.push(format!("color_space={}", v));
            }
            if !meta.raw_fields.is_empty() {
                bits.push(format!("raw_fields={}", meta.raw_fields.join("|")));
            }
            if let Some(v) = meta.trace_form {
                bits.push(format!("trace_form={v}"));
            }
            if let Some(v) = meta.trace_tag {
                bits.push(format!("trace_tag={v}"));
            }
            if let Some(v) = meta.trace_node_offset {
                bits.push(format!("trace_node_offset=0x{v:X}"));
            }
            if let Some(v) = meta.trace_child_alignment {
                bits.push(format!("trace_child_alignment={v}"));
            }
            if let Some(v) = meta.trace_child_header_size {
                bits.push(format!("trace_child_header_size={v}"));
            }
            out.push_str(&format!("  meta: {}\n", bits.join(" ")));
        }
    }
    Ok(out)
}

pub(super) fn render_scene_paths_json(
    input: &Path,
    kind: PathKind,
    load_options: &LoadOptions,
) -> Result<String, CliOutputError> {
    let report = collect_scene_paths_with_options(input, kind, load_options)?;
    let kind_label = scene_path_kind_label(kind);
    let doc = json!({
        "contract_version": JSON_CONTRACT_VERSION,
        "scene_path": report.scene_path.display().to_string(),
        "scene_format": report.scene_format,
        "kind": kind_label,
        "count": report.entries.len(),
        "entries": report.entries.into_iter().map(|e| json!({
            "node_type": e.node_type,
            "node_name": e.node_name,
            "attr": e.attr,
            "value": e.value,
            "meta": e.meta.as_ref().map(|m| json!({
                "origin": m.origin,
                "short_name": m.short_name,
                "reference_node": m.reference_node,
                "format_hint": m.format_hint,
                "reference_options": m.reference_options,
                "color_space": m.color_space,
                "raw_fields": m.raw_fields,
                "trace_form": m.trace_form,
                "trace_tag": m.trace_tag,
                "trace_node_offset": m.trace_node_offset,
                "trace_child_alignment": m.trace_child_alignment,
                "trace_child_header_size": m.trace_child_header_size,
            })),
        })).collect::<Vec<_>>()
    });
    serde_json::to_string_pretty(&doc)
        .map(|s| format!("{s}\n"))
        .map_err(|e| CliOutputError::JsonRender(format!("failed to render json: {e}")))
}

pub(super) fn render_scene_paths_collection_json(
    files: &[PathBuf],
    kind: PathKind,
    input: &Path,
    load_options: &LoadOptions,
) -> Result<String, CliOutputError> {
    let kind_label = scene_path_kind_label(kind);
    let mut items = Vec::new();
    for file in files {
        let report = collect_scene_paths_with_options(file, kind, load_options)?;
        items.push(json!({
            "scene_path": report.scene_path.display().to_string(),
            "scene_format": report.scene_format,
            "count": report.entries.len(),
            "entries": report.entries.into_iter().map(|e| json!({
                "node_type": e.node_type,
                "node_name": e.node_name,
                "attr": e.attr,
                "value": e.value,
                "meta": e.meta.as_ref().map(|m| json!({
                    "origin": m.origin,
                    "short_name": m.short_name,
                    "reference_node": m.reference_node,
                    "format_hint": m.format_hint,
                    "reference_options": m.reference_options,
                    "color_space": m.color_space,
                    "raw_fields": m.raw_fields,
                    "trace_form": m.trace_form,
                    "trace_tag": m.trace_tag,
                    "trace_node_offset": m.trace_node_offset,
                    "trace_child_alignment": m.trace_child_alignment,
                    "trace_child_header_size": m.trace_child_header_size,
                })),
            })).collect::<Vec<_>>()
        }));
    }
    let doc = json!({
        "contract_version": JSON_CONTRACT_VERSION,
        "input": input.display().to_string(),
        "kind": kind_label,
        "file_count": items.len(),
        "files": items,
    });
    serde_json::to_string_pretty(&doc)
        .map(|s| format!("{s}\n"))
        .map_err(|e| CliOutputError::JsonRender(format!("failed to render json: {e}")))
}

pub(super) fn render_scene_dump_text(
    input: &Path,
    load_options: &LoadOptions,
) -> Result<String, CliOutputError> {
    Ok(render_scene_dump_with_options(input, load_options)?)
}

pub(super) fn collect_scene_files(input: &Path) -> std::io::Result<Vec<PathBuf>> {
    if input.is_file() {
        return Ok(if is_scene_file(input) {
            vec![input.to_path_buf()]
        } else {
            Vec::new()
        });
    }

    let mut out = Vec::new();
    let mut stack = vec![input.to_path_buf()];
    let mut visited_dirs = HashSet::new();

    while let Some(dir) = stack.pop() {
        let canonical = fs::canonicalize(&dir).unwrap_or(dir.clone());
        if !visited_dirs.insert(canonical) {
            continue;
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(path);
            } else if is_scene_file(&path) {
                out.push(path);
            }
        }
    }

    out.sort();
    Ok(out)
}

fn is_scene_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("ma") | Some("mb")
    )
}
