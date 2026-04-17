use std::path::Path;

#[allow(unused_imports)]
pub use maya_scene_kit_audit::{
    audit::{
        ScriptAuditPlan, audit_observation, build_parse_budget_blocked_audit_report,
        build_script_audit_plan,
    },
    scene::{
        AnalysisBudgets, AuditDisposition, AuditEvidence, AuditEvidenceKey, AuditFinding,
        AuditFindingCode, AuditFindingDetail, AuditHit, AuditNotice, AuditNoticeCode, AuditOptions,
        AuditProfile, AuditReport, AuditReviewCode, AuditReviewDetail, AuditReviewSignal,
        AuditSeverity, AuditSinkKind, AuditSurface, AuditSurfaceDerivation, ScriptAuditReport,
        StaticAuditFindingDetail, StaticAuditReviewDetail,
    },
};
#[allow(unused_imports)]
pub use maya_scene_kit_edit::scene::{
    Confidence, DecodeAttemptResult, DecodeQuality, DecodeQualityDistributionEntry, IssueKind,
    MaterializeOptions, MayaAsciiConversionReport, MayaAsciiDecodeAttempt, MayaAsciiIssue,
    OperationMode, PathReplaceMode, PathReplaceResult, PathReplaceRule, RawChunkDump, SceneFormat,
    SceneToolError, ScriptNodeCleanResult, SemanticProvenance, UnknownInventoryEntry,
    ValidationState, convert_to_maya_ascii_with_options, convert_to_maya_ascii_with_report,
    convert_to_maya_ascii_with_report_and_options, remove_script_nodes_with_options,
    replace_scene_paths_with_options, write_output_bytes_atomic,
};
#[allow(unused_imports)]
pub use maya_scene_kit_observe::scene::dump::SceneDumpReport;
#[allow(unused_imports)]
pub use maya_scene_kit_observe::scene::evidence::{
    DependencyFact, DependencyFactDetail, DependencyFactKind, DependencyRiskClass, EffectCertainty,
    ExecutionCoverageIssue, ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind,
    ExecutionCoverageState, ExecutionEffectClass, ExecutionLanguage, ExecutionOrigin,
    ExecutionReason, ExecutionReasonTemplate, ExecutionSemanticClass, ExecutionSurfaceKind,
    ExecutionTrigger, ExecutionUnitSummary, SceneDigestSet, StaticExecutionReason,
    UnknownSemanticDetail, UnknownSemanticFact,
};
#[allow(unused_imports)]
pub use maya_scene_kit_observe::scene::inspect::{
    MbInspectNode, MbInspectOptions, MbInspectReport, inspect_mb, inspect_mb_with_max_parse_bytes,
};
#[allow(unused_imports)]
pub use maya_scene_kit_observe::scene::paths::{
    PathKind, ScenePathEntry, ScenePathMeta, ScenePathsReport,
};
#[allow(unused_imports)]
pub use maya_scene_kit_observe::scene::scripts::ScriptNodeEntry;
#[allow(unused_imports)]
pub use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, MbParseBudget, ObservationBundle, check_script_nodes_with_options,
    collect_scene_paths, collect_scene_paths_with_options,
};

pub fn audit_script_nodes_with_options_without_digests(
    path: impl AsRef<Path>,
    plan: &ScriptAuditPlan,
    load_options: &LoadOptions,
    options: AuditOptions,
) -> Result<AuditReport, SceneToolError> {
    maya_scene_kit_audit::audit::audit_script_nodes_with_options_and_digests(
        path,
        plan,
        load_options,
        options,
        false,
    )
}

#[cfg(test)]
pub fn render_script_dump(path: impl AsRef<Path>) -> Result<String, SceneToolError> {
    render_script_dump_with_options(path, &LoadOptions::default())
}

#[cfg(test)]
pub fn render_script_dump_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<String, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path(path)?;
    render_script_dump_from_observation(&observation)
}

#[cfg(test)]
pub(crate) fn render_script_dump_from_observation(
    observation: &ObservationBundle,
) -> Result<String, SceneToolError> {
    let report = observation.scene_dump_report()?;
    Ok(build_script_dump_text(&report))
}

#[cfg(test)]
pub fn render_requires_dump(path: impl AsRef<Path>) -> Result<String, SceneToolError> {
    render_requires_dump_with_options(path, &LoadOptions::default())
}

#[cfg(test)]
pub fn render_requires_dump_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<String, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path(path)?;
    render_requires_dump_from_observation(&observation)
}

#[cfg(test)]
pub(crate) fn render_requires_dump_from_observation(
    observation: &ObservationBundle,
) -> Result<String, SceneToolError> {
    let report = observation.scene_dump_report()?;
    Ok(build_requires_dump_text(&report))
}

pub(crate) fn render_scene_dump_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<String, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path(path)?;
    let report = observation.scene_dump_report()?;
    Ok(render_scene_dump_from_report(&report))
}

pub(crate) fn render_scene_dump_from_report(report: &SceneDumpReport) -> String {
    let requires_text = build_requires_dump_text(report);
    let script_text = build_script_dump_text(report);
    format!(
        "# maya-scene-kit Scene Dump\n\n{}\n{}",
        requires_text, script_text
    )
}

fn build_script_dump_text(report: &SceneDumpReport) -> String {
    let mut lines = vec![
        "# maya-scene-kit Script Node Dump".to_string(),
        format!("format: {}", report.scene_format.as_str()),
        format!("count: {}", report.script_entries.len()),
        String::new(),
    ];

    for (idx, entry) in report.script_entries.iter().enumerate() {
        lines.push(format!("[[scriptNode {}: {}]]", idx + 1, entry.name));
        let body = normalize_script_body(entry);
        if body.is_empty() {
            lines.push("<empty>".to_string());
        } else {
            lines.push(body);
        }
        lines.push(String::new());
    }

    if report.script_entries.is_empty() {
        lines.push("# no script node found".to_string());
        lines.push(String::new());
    }

    lines.join("\n") + "\n"
}

fn build_requires_dump_text(report: &SceneDumpReport) -> String {
    let mut lines = vec![
        "# maya-scene-kit Requires Dump".to_string(),
        format!("format: {}", report.scene_format.as_str()),
        format!("count: {}", report.requires.len()),
        String::new(),
    ];

    if report.requires.is_empty() {
        lines.push("# no requires found".to_string());
        lines.push(String::new());
        return lines.join("\n") + "\n";
    }

    lines.extend(report.requires.iter().cloned());
    lines.push(String::new());
    lines.join("\n") + "\n"
}

fn normalize_script_body(entry: &ScriptNodeEntry) -> String {
    entry.body.trim_end_matches('\n').to_string()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;
    use crate::cli;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn script_dump_ma_text_contains_expected_sections() {
        let source = repo_root().join("tests/02/sphere.ma");
        let text = render_script_dump(&source).expect("script dump");

        assert!(text.contains("# maya-scene-kit Script Node Dump"));
        assert!(text.contains("uiConfigurationScriptNode"));
        assert!(!text.contains("source: "));
    }

    #[test]
    fn requires_dump_mb_text_contains_expected_sections() {
        let source = repo_root().join("tests/02/sphere.mb");
        let text = render_requires_dump(&source).expect("requires dump");

        assert!(text.contains("# maya-scene-kit Requires Dump"));
        assert!(text.contains("requires maya \""));
        assert!(!text.contains("source: "));
    }

    #[test]
    fn scene_dump_writer_emits_combined_dump_file() {
        let source = repo_root().join("tests/02/sphere.mb");
        let dir = tempdir().expect("tmpdir");
        let output = dir.path().join("scene_dump.txt");

        cli::fs::write_scene_dump(&source, &output, &LoadOptions::default())
            .expect("write scene dump");

        let text = std::fs::read_to_string(output).expect("read dump");
        assert!(text.contains("# maya-scene-kit Scene Dump"));
        assert!(text.contains("# maya-scene-kit Requires Dump"));
        assert!(text.contains("# maya-scene-kit Script Node Dump"));
    }

    #[test]
    fn scene_dump_report_formats_existing_sections() {
        let source = repo_root().join("tests/02/sphere.ma");
        let report =
            maya_scene_kit_observe::scene::collect_scene_dump(&source).expect("scene dump");
        let text = render_scene_dump_from_report(&report);

        assert!(text.contains("# maya-scene-kit Scene Dump"));
        assert!(text.contains("# maya-scene-kit Requires Dump"));
        assert!(text.contains("# maya-scene-kit Script Node Dump"));
        assert!(text.contains("uiConfigurationScriptNode"));
    }

    #[test]
    fn requires_dump_rejects_unknown_scene_format_with_typed_error() {
        let dir = tempdir().expect("tmpdir");
        let source = dir.path().join("unknown_scene.dat");
        std::fs::write(&source, b"\x00\xFFnot-a-maya-scene").expect("write source");

        let err = render_requires_dump(&source).expect_err("expected unsupported format");
        assert!(matches!(
            err,
            SceneToolError::UnsupportedSceneFormat {
                detected: SceneFormat::Unknown,
                ..
            }
        ));
    }
}
