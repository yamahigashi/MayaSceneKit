use std::{
    collections::{BTreeMap, HashSet},
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
    write_scene_bytes(output, bytes)?;
    Ok(())
}

pub(super) fn write_scene_bytes(output: &Path, bytes: &[u8]) -> Result<(), SceneToolError> {
    let outcome = write_output_bytes_atomic(output, bytes)?;
    if let Some(error) = outcome.dir_sync_error {
        eprintln!("warning: output written but directory sync failed: {error}");
    }
    Ok(())
}

pub(super) fn render_scene_paths_text(
    input: &Path,
    kind: PathKind,
    load_options: &LoadOptions,
) -> Result<String, CliOutputError> {
    let report = collect_scene_paths_with_options(input, kind, load_options)?;
    Ok(render_paths_report_text(report, kind))
}

fn render_paths_report_text(report: crate::scene::ScenePathsReport, kind: PathKind) -> String {
    let kind_label = scene_path_kind_label(kind);
    let mut out = format!(
        "# maya-scene-kit Scene Paths\nsource: {}\nformat: {}\nkind: {}\ncount: {}\n",
        report.scene_path.display(),
        report.scene_format,
        kind_label,
        report.entries.len()
    );

    out.push_str(&format!("validation_state: {}\n", report.validation_state));
    for diagnostic in &report.diagnostics {
        out.push_str(&format!("diagnostic: {diagnostic}\n"));
    }

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
    out
}

pub(super) fn render_scene_paths_json(
    input: &Path,
    kind: PathKind,
    load_options: &LoadOptions,
) -> Result<String, CliOutputError> {
    let report = collect_scene_paths_with_options(input, kind, load_options)?;
    let kind_label = scene_path_kind_label(kind);
    let mut doc = json!({
        "contract_version": JSON_CONTRACT_VERSION,
        "scene_path": report.scene_path.to_string_lossy(),
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
    if !report.diagnostics.is_empty() {
        doc["diagnostics"] = json!(report.diagnostics);
    }
    doc["validation_state"] = json!(report.validation_state);
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
        let mut item = json!({
            "scene_path": report.scene_path.to_string_lossy(),
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
        });
        if !report.diagnostics.is_empty() {
            item["diagnostics"] = json!(report.diagnostics);
        }
        item["validation_state"] = json!(report.validation_state);
        items.push(item);
    }
    let doc = json!({
        "contract_version": JSON_CONTRACT_VERSION,
        "input": input.to_string_lossy(),
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

pub(super) struct SceneFileCollection {
    pub(super) files: Vec<PathBuf>,
    pub(super) issues: Vec<SceneFileIssue>,
    pub(super) details: BTreeMap<PathBuf, SceneFileDetails>,
}

#[derive(Default)]
pub(super) struct SceneFileDetails {
    pub(super) aliases: Vec<PathBuf>,
    pub(super) outside_input_tree: bool,
}

pub(super) struct SceneFileIssue {
    pub(super) path: PathBuf,
    pub(super) message: String,
}

impl SceneFileCollection {
    pub(super) fn warn_and_take_files(self) -> Vec<PathBuf> {
        for issue in self.issues {
            eprintln!("warning: {}: {}", issue.path.display(), issue.message);
        }
        for (path, details) in self.details {
            for alias in details.aliases {
                eprintln!("note: {}: alias of {}", alias.display(), path.display());
            }
            if details.outside_input_tree {
                eprintln!("note: {}: outside_input_tree=true", path.display());
            }
        }
        self.files
    }
}

pub(super) fn collect_scene_files(input: &Path) -> std::io::Result<SceneFileCollection> {
    if input.is_file() {
        return Ok(SceneFileCollection {
            files: if is_scene_file(input)
                || fs::canonicalize(input).is_ok_and(|p| is_scene_file(&p))
            {
                vec![input.to_path_buf()]
            } else {
                Vec::new()
            },
            issues: Vec::new(),
            details: BTreeMap::new(),
        });
    }

    let mut out = Vec::new();
    let mut issues = Vec::new();
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
            if is_directory_reparse_point(&metadata) {
                issues.push(SceneFileIssue {
                    path,
                    message: "directory symlink skipped without traversal".to_string(),
                });
                continue;
            }
            if metadata.file_type().is_symlink() {
                match fs::metadata(&path) {
                    Ok(target) if target.is_file() => {
                        if is_scene_file(&path)
                            || fs::canonicalize(&path).is_ok_and(|p| is_scene_file(&p))
                        {
                            out.push(path);
                        }
                    }
                    Ok(target) if target.is_dir() => issues.push(SceneFileIssue {
                        path,
                        message: "directory symlink skipped without traversal".to_string(),
                    }),
                    Ok(_) => issues.push(SceneFileIssue {
                        path,
                        message: "symlink target is not a regular file".to_string(),
                    }),
                    Err(error) if is_scene_file(&path) => issues.push(SceneFileIssue {
                        path,
                        message: format!("cannot read symlink target: {error}"),
                    }),
                    Err(_) => {}
                }
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
    issues.sort_by(|a, b| a.path.cmp(&b.path));
    let root = fs::canonicalize(input)?;
    let mut canonical_files = BTreeMap::<PathBuf, PathBuf>::new();
    let mut details = BTreeMap::<PathBuf, SceneFileDetails>::new();
    let mut files = Vec::new();
    for path in out {
        let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if let Some(first) = canonical_files.get(&canonical) {
            details.get_mut(first).unwrap().aliases.push(path);
        } else {
            details.insert(
                path.clone(),
                SceneFileDetails {
                    aliases: Vec::new(),
                    outside_input_tree: !canonical.starts_with(&root),
                },
            );
            canonical_files.insert(canonical, path.clone());
            files.push(path);
        }
    }
    Ok(SceneFileCollection {
        files,
        issues,
        details,
    })
}

fn is_scene_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("ma") | Some("mb")
    )
}

#[cfg(windows)]
fn is_directory_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let attributes = metadata.file_attributes();
    attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_directory_reparse_point(_: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod paths_report_tests {
    use super::*;

    #[test]
    fn paths_text_exposes_validation_and_every_diagnostic() {
        let report = crate::scene::ScenePathsReport {
            source: None,
            kind: Some(PathKind::All),
            scene_path: "Example.ma".into(),
            scene_format: crate::scene::SceneFormat::Ma,
            validation_state: crate::scene::ValidationState::Partial,
            diagnostics: vec![
                "scene file changed while it was being read".into(),
                "Example diagnostic".into(),
            ],
            entries: vec![],
        };
        let text = render_paths_report_text(report, PathKind::All);
        assert!(text.contains("validation_state: partial\n"), "{text}");
        assert!(text.contains("scene file changed while it was being read"));
        assert!(text.contains("Example diagnostic"));
    }

    #[test]
    fn paths_json_exposes_validation_for_single_and_collection() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("Example.ma");
        std::fs::write(&input, "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n").unwrap();
        let options = LoadOptions::default();
        let single: serde_json::Value = serde_json::from_str(
            &render_scene_paths_json(&input, PathKind::All, &options).unwrap(),
        )
        .unwrap();
        let collection: serde_json::Value = serde_json::from_str(
            &render_scene_paths_collection_json(
                std::slice::from_ref(&input),
                PathKind::All,
                dir.path(),
                &options,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(single["validation_state"], "validated");
        assert_eq!(collection["files"][0]["validation_state"], "validated");
    }
}
