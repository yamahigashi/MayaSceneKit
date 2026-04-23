use std::path::PathBuf;

use maya_scene_kit_audit::{
    audit::{audit_script_nodes_with_options_and_digests, build_script_audit_plan},
    scene::AuditOptions,
};
use maya_scene_kit_edit::scene::{
    MaterializeOptions, OperationMode, PathReplaceMode, PathReplaceRule,
    convert_to_maya_ascii_with_report_and_options, preview_remove_script_nodes_with_options,
    preview_replace_scene_paths_with_options, remove_script_nodes_with_options,
    replace_scene_paths_with_options,
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, SceneToolError, collect_scene_paths_with_options,
    collect_script_node_entries_with_options,
    inspect::{MbInspectOptions, inspect_mb, inspect_mb_with_max_parse_bytes},
    paths::PathKind,
};
use serde_json::Value;

use crate::{json as json_map, schema};

pub(crate) fn inspect_mb_json(
    path: &str,
    max_depth: Option<usize>,
    preview_bytes: usize,
    max_bytes: Option<usize>,
) -> Result<Value, SceneToolError> {
    let options = MbInspectOptions {
        max_depth,
        preview_bytes,
    };
    let report = match max_bytes {
        Some(max_bytes) => inspect_mb_with_max_parse_bytes(path, options, max_bytes)?,
        None => inspect_mb(path, options)?,
    };
    Ok(json_map::inspect_report(&report))
}

pub(crate) fn dump_scripts_text(
    path: &str,
    max_bytes: Option<usize>,
) -> Result<String, SceneToolError> {
    let options = load_options(&[], max_bytes)?;
    let report = collect_script_node_entries_with_options(path, &options)?;
    let entries_json = json_map::script_entries_report(&report);
    let entries = entries_json["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut lines = vec![
        "# maya-scene-kit Script Node Dump".to_string(),
        format!("format: {}", report.scene_format.as_str()),
        format!("count: {}", report.entries.len()),
        String::new(),
    ];

    for (idx, entry) in entries.iter().enumerate() {
        let name = entry["name"].as_str().unwrap_or_default();
        let body = entry["body"].as_str().unwrap_or_default();
        lines.push(format!("[[scriptNode {}: {}]]", idx + 1, name));
        if body.is_empty() {
            lines.push("<empty>".to_string());
        } else {
            lines.push(body.trim_end_matches('\n').to_string());
        }
        lines.push(String::new());
    }

    if report.entries.is_empty() {
        lines.push("# no script node found".to_string());
        lines.push(String::new());
    }

    Ok(lines.join("\n") + "\n")
}

pub(crate) fn dump_requires_text(
    path: &str,
    max_bytes: Option<usize>,
) -> Result<String, SceneToolError> {
    let options = load_options(&[], max_bytes)?;
    let observation = Loader::new(options).observe_path(path)?;
    let requires = observation.requires()?;

    let mut lines = vec![
        "# maya-scene-kit Requires Dump".to_string(),
        format!("format: {}", observation.scene_format().as_str()),
        format!("count: {}", requires.len()),
        String::new(),
    ];

    if requires.is_empty() {
        lines.push("# no requires found".to_string());
        lines.push(String::new());
        return Ok(lines.join("\n") + "\n");
    }

    lines.extend(requires);
    lines.push(String::new());
    Ok(lines.join("\n") + "\n")
}

pub(crate) fn collect_paths_json(
    path: &str,
    kind: &str,
    max_bytes: Option<usize>,
) -> Result<Value, SceneToolError> {
    let parsed_kind = parse_path_kind(kind)?;
    let report =
        collect_scene_paths_with_options(path, parsed_kind, &load_options(&[], max_bytes)?)?;
    Ok(json_map::scene_paths_report(&report))
}

pub(crate) fn audit_json(
    path: &str,
    rules: &[String],
    max_preview: usize,
    include_digests: bool,
    node_info_paths: &[String],
    max_bytes: Option<usize>,
) -> Result<Value, SceneToolError> {
    let load_options = load_options(node_info_paths, max_bytes)?;
    let plan = build_script_audit_plan(rules.to_vec(), max_preview)?;
    let report = audit_script_nodes_with_options_and_digests(
        path,
        &plan,
        &load_options,
        AuditOptions::strict_default(),
        include_digests,
    )?;
    Ok(json_map::audit_report(&report))
}

pub(crate) fn preview_clean_json(
    path: &str,
    max_bytes: Option<usize>,
) -> Result<Value, SceneToolError> {
    let preview = preview_remove_script_nodes_with_options(
        path,
        &materialize_options(OperationMode::Forensic, false, &[], max_bytes)?,
    )?;
    Ok(json_map::script_node_clean_preview(&preview))
}

pub(crate) fn clean_json(
    input_path: &str,
    output_path: &str,
    max_bytes: Option<usize>,
) -> Result<Value, SceneToolError> {
    let options = materialize_options(OperationMode::Forensic, false, &[], max_bytes)?;
    let result = remove_script_nodes_with_options(input_path, output_path, &options)?;
    Ok(json_map::script_node_clean_result(&result))
}

pub(crate) fn preview_replace_json(
    path: &str,
    rules: &[(String, String)],
    max_bytes: Option<usize>,
) -> Result<Value, SceneToolError> {
    let preview = preview_replace_scene_paths_with_options(
        path,
        &path_replace_rules(rules),
        &materialize_options(OperationMode::Forensic, false, &[], max_bytes)?,
    )?;
    Ok(json_map::path_replace_preview(&preview))
}

pub(crate) fn replace_json(
    input_path: &str,
    output_path: &str,
    rules: &[(String, String)],
    max_bytes: Option<usize>,
) -> Result<Value, SceneToolError> {
    let options = materialize_options(OperationMode::Forensic, false, &[], max_bytes)?;
    let result = replace_scene_paths_with_options(
        input_path,
        output_path,
        &path_replace_rules(rules),
        &options,
    )?;
    Ok(json_map::path_replace_result(&result))
}

pub(crate) fn to_ascii_json(
    input_path: &str,
    output_path: &str,
    mode: &str,
    embed_metadata: bool,
    node_info_paths: &[String],
    max_bytes: Option<usize>,
) -> Result<Value, SceneToolError> {
    let options = materialize_options(
        parse_operation_mode(mode)?,
        embed_metadata,
        node_info_paths,
        max_bytes,
    )?;
    let report = convert_to_maya_ascii_with_report_and_options(input_path, output_path, &options)?;
    Ok(json_map::maya_ascii_conversion_report(&report))
}

fn load_options(
    node_info_paths: &[String],
    max_bytes: Option<usize>,
) -> Result<LoadOptions, SceneToolError> {
    let mut options = LoadOptions::default().with_schema_root(
        schema::schema_root()
            .map_err(SceneToolError::Config)?
            .clone(),
    );
    if !node_info_paths.is_empty() {
        options = options
            .with_additional_node_info_paths(node_info_paths.iter().map(PathBuf::from).collect());
    }
    if let Some(max_bytes) = max_bytes {
        options = options.with_max_parse_bytes(max_bytes);
    }
    Ok(options)
}

fn materialize_options(
    mode: OperationMode,
    embed_metadata: bool,
    node_info_paths: &[String],
    max_bytes: Option<usize>,
) -> Result<MaterializeOptions, SceneToolError> {
    let mut options = MaterializeOptions::new(load_options(node_info_paths, max_bytes)?)
        .with_operation_mode(mode)
        .with_embed_output_metadata(embed_metadata);
    if !node_info_paths.is_empty() {
        options = options
            .with_additional_node_info_paths(node_info_paths.iter().map(PathBuf::from).collect());
    }
    Ok(options)
}

fn path_replace_rules(rules: &[(String, String)]) -> Vec<PathReplaceRule> {
    rules
        .iter()
        .map(|(from, to)| PathReplaceRule {
            from: from.clone(),
            to: to.clone(),
            mode: PathReplaceMode::Literal,
        })
        .collect()
}

fn parse_path_kind(kind: &str) -> Result<PathKind, SceneToolError> {
    match kind {
        "all" => Ok(PathKind::All),
        "file" => Ok(PathKind::File),
        "reference" => Ok(PathKind::Reference),
        other => Err(SceneToolError::Config(format!(
            "unsupported path kind '{other}', expected one of: all, file, reference"
        ))),
    }
}

fn parse_operation_mode(mode: &str) -> Result<OperationMode, SceneToolError> {
    match mode {
        "strict" => Ok(OperationMode::Strict),
        "best_effort" => Ok(OperationMode::BestEffort),
        "forensic" => Ok(OperationMode::Forensic),
        other => Err(SceneToolError::Config(format!(
            "unsupported operation mode '{other}', expected one of: strict, best_effort, forensic"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        audit_json, clean_json, collect_paths_json, dump_requires_text, dump_scripts_text,
        inspect_mb_json, preview_clean_json, preview_replace_json, replace_json, to_ascii_json,
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .to_path_buf()
    }

    #[test]
    fn inspect_json_reports_root_chunk() {
        let source = repo_root().join("tests/02/sphere.mb");
        let value =
            inspect_mb_json(&source.display().to_string(), Some(0), 24, None).expect("inspect");

        assert_eq!(value["scene_format"], "mb");
        assert!(
            value["root"]["children"]
                .as_array()
                .expect("children")
                .is_empty()
        );
    }

    #[test]
    fn dump_text_matches_cli_shape() {
        let source = repo_root().join("tests/02/sphere.ma");
        let script_dump =
            dump_scripts_text(&source.display().to_string(), None).expect("script dump");
        let requires_dump =
            dump_requires_text(&source.display().to_string(), None).expect("requires dump");

        assert!(script_dump.contains("# maya-scene-kit Script Node Dump"));
        assert!(requires_dump.contains("# maya-scene-kit Requires Dump"));
    }

    #[test]
    fn collect_paths_json_reports_entries() {
        let source = repo_root().join("tests/02/sphere.ma");
        let value = collect_paths_json(&source.display().to_string(), "all", None).expect("paths");

        assert_eq!(value["scene_format"], "ma");
        assert!(value["count"].is_number());
        assert!(value["entries"].is_array());
    }

    #[test]
    fn audit_json_reports_disposition() {
        let source = repo_root().join("tests/02/sphere.mb");
        let value =
            audit_json(&source.display().to_string(), &[], 96, true, &[], None).expect("audit");

        assert!(value["disposition"].is_string());
        assert!(value["notices"].is_array());
        assert!(value["finding_count"].is_number());
    }

    #[test]
    fn audit_json_returns_blocked_report_for_budget_exceed() {
        let source = repo_root().join("tests/02/sphere.ma");
        let value = audit_json(&source.display().to_string(), &[], 96, true, &[], Some(1))
            .expect("budget blocked audit");

        assert_eq!(value["disposition"], "review");
        assert_eq!(value["blocked_on_uncertainty"], true);
        assert_eq!(value["notice_count"], 1);
        assert_eq!(value["finding_count"], 0);
        assert_eq!(value["review_signal_count"], 0);
        assert_eq!(value["notices"][0]["code"], "parse_budget_exceeded");
        assert_eq!(
            value["notices"][0]["message"],
            "parse budget exceeded: max_bytes"
        );
    }

    #[test]
    fn clean_and_replace_support_preview_and_write() {
        let source = repo_root().join("tests/02/sphere.ma");
        let dir = tempfile::tempdir().expect("tmpdir");
        let clean_output = dir.path().join("clean.ma");
        let replace_output = dir.path().join("replace.ma");

        let preview =
            preview_clean_json(&source.display().to_string(), None).expect("preview clean");
        let _clean = clean_json(
            &source.display().to_string(),
            &clean_output.display().to_string(),
            None,
        )
        .expect("clean");
        let replace_preview = preview_replace_json(
            &source.display().to_string(),
            &[("persp".to_string(), "persp_renamed".to_string())],
            None,
        )
        .expect("preview replace");
        let replace = replace_json(
            &source.display().to_string(),
            &replace_output.display().to_string(),
            &[("persp".to_string(), "persp_renamed".to_string())],
            None,
        )
        .expect("replace");

        assert!(preview["removed_count"].is_number());
        assert!(clean_output.exists());
        assert!(replace_preview["matched_count"].is_number());
        assert!(replace_output.exists());
        assert!(replace["replaced_count"].is_number());
    }

    #[test]
    fn to_ascii_reports_output_path() {
        let source = repo_root().join("tests/02/sphere.mb");
        let dir = tempfile::tempdir().expect("tmpdir");
        let output = dir.path().join("sphere.ma");
        let value = to_ascii_json(
            &source.display().to_string(),
            &output.display().to_string(),
            "best_effort",
            false,
            &[],
            None,
        )
        .expect("to ascii");

        assert_eq!(value["output_path"], output.display().to_string());
        assert!(output.exists());
    }
}
