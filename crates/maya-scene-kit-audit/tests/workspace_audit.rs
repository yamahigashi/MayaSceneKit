use std::path::PathBuf;

use maya_scene_kit_audit::{
    audit::{
        ScriptAuditPlan, audit_observation, audit_reference_graph_roots_with_options_and_digests,
        audit_reference_graph_roots_with_traversal_options_and_digests, audit_script_nodes,
        audit_script_nodes_with_options, build_script_audit_plan,
    },
    scene::{
        AuditDisposition, AuditFinding, AuditNoticeCode, AuditOptions, AuditReport, AuditSeverity,
        AuditSinkKind, AuditSurfaceDerivation, AuditTraversalIssueKind, ReferenceGraphOptions,
    },
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, MbParseBudget, MelParseBudget, SceneToolError, check_script_nodes,
    collect_scene_paths, collect_script_node_entries,
    core::ValidationState,
    evidence::{
        DependencyFactKind, DependencyRiskClass, ExecutionCoverageIssueDetail,
        ExecutionCoverageIssueKind, ExecutionCoverageState, ExecutionEffectClass,
        ExecutionLanguage, ExecutionSurfaceKind,
    },
    paths::PathKind,
};
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn audit_plan() -> ScriptAuditPlan {
    build_script_audit_plan(vec![], 64).expect("audit plan")
}

#[test]
fn default_audit_plan_has_no_implicit_custom_rules() {
    let plan = audit_plan();
    assert!(plan.effective_rules().is_empty());
}

fn finding_code_str(finding: &AuditFinding) -> &'static str {
    finding.code.as_str()
}

fn finding_severity(report: &AuditReport, code: &str) -> Option<AuditSeverity> {
    report
        .findings
        .iter()
        .find(|finding| finding_code_str(finding) == code)
        .map(|finding| finding.severity)
}

fn write_scene(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).expect("write fixture");
}

fn escape_ma_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

fn write_python_script_node_scene(path: &std::path::Path, node_name: &str, body: &str) {
    write_scene(
        path,
        &format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"{}\";\n",
                "    setAttr \".st\" 1;\n",
                "    setAttr \".stp\" 1;\n",
                "    setAttr \".b\" -type \"string\" \"{}\";\n",
            ),
            node_name,
            escape_ma_string(body),
        ),
    );
}

fn write_basic_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!("//Maya ASCII 2026 scene\n", "requires maya \"2026\";\n"),
    );
}

fn write_reference_scene(path: &std::path::Path, reference_path: &str, reference_node: &str) {
    write_scene(
        path,
        &format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "file -r -rfn \"{}\" \"{}\";\n",
                "createNode reference -n \"{}\";\n",
                "    setAttr \".fn\" -type \"string\" \"{}\";\n",
            ),
            reference_node, reference_path, reference_node, reference_path
        ),
    );
}

fn build_mb_chunk_with_alignment(tag: &str, payload: &[u8], sibling_alignment: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    while (out.len() - 16) % sibling_alignment != 0 {
        out.push(0);
    }
    out
}

fn build_mb_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
    build_mb_chunk_with_alignment(tag, payload, 8)
}

fn build_mb_form(form: &str, children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = form.as_bytes().to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    build_mb_chunk_with_alignment("FOR8", &payload, 4)
}

fn build_mb_root(children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = b"Maya".to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"FOR8");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn write_literal_mel_python_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"literalPythonReview\";\n",
            "    setAttr \".b\" -type \"string\" \"python(\\\"print('hello')\\\")\";\n",
            "    setAttr \".st\" 0;\n",
        ),
    );
}

fn write_autorun_mel_python_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"autorunPythonReview\";\n",
            "    setAttr \".b\" -type \"string\" \"python(\\\"import os\\\")\";\n",
            "    setAttr \".st\" 1;\n",
        ),
    );
}

fn write_top_level_command_port_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "commandPort -n \":7001\";\n",
        ),
    );
}

fn write_mel_exec_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"ExampleExecScript\";\n",
            "    setAttr \".b\" -type \"string\" \"exec \\\"SampleTool.exe\\\"\";\n",
            "    setAttr \".st\" 1;\n",
        ),
    );
}

fn write_top_level_exec_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "exec \"SampleTool.exe\";\n",
        ),
    );
}

fn write_top_level_python_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "python(\"import subprocess\\nsubprocess.call(['echo', 'hi'])\");\n",
        ),
    );
}

fn write_top_level_eval_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "eval(\"python(\\\"import subprocess\\\\nsubprocess.call(['echo', 'hi'])\\\")\");\n",
        ),
    );
}

fn write_cp932_ui_scene(path: &std::path::Path) {
    let source = concat!(
        "//Maya ASCII 2026 scene\n",
        "//Codeset: 932\n",
        "//アウトライナ プラス\n",
        "requires maya \"2026\";\n",
        "createNode script -n \"cp932SafeScript\";\n",
        "    setAttr \".b\" -type \"string\" \"print(\\\"アウトライナ プラス\\\")\";\n",
        "    setAttr \".st\" 0;\n",
    );
    let (bytes, _, had_errors) = encoding_rs::SHIFT_JIS.encode(source);
    assert!(!had_errors);
    std::fs::write(path, bytes.as_ref()).expect("write cp932 fixture");
}

fn write_file_command_callback_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "file -r -command \"onLoad\" \"print(\\\"ok\\\")\" \"C:/ref.ma\";\n",
        ),
    );
}

fn write_model_editor_callback_scene(path: &std::path::Path, callback_body: &str) {
    write_scene(
        path,
        &format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"callbackAuditScene\";\n",
                "    setAttr \".b\" -type \"string\" \"modelEditor -e -editorChanged \\\"{callback_body}\\\" modelPanel4;\";\n",
                "    setAttr \".st\" 1;\n",
            ),
            callback_body = callback_body
        ),
    );
}

fn write_dynamic_model_editor_callback_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"callbackAuditScene\";\n",
            "    setAttr \".b\" -type \"string\" \"$callback = `optionVar -q sampleCallbackName`; modelEditor -e -editorChanged $callback modelPanel4;\";\n",
            "    setAttr \".st\" 1;\n",
        ),
    );
}

fn write_top_level_schema_script_flag_callback_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "nodeOutliner -e -selectCommand \"eval \\\"hello\\\"\" $examplePanel;\n",
        ),
    );
}

fn write_assembled_code_like_without_sink_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"assembledReviewScene\";\n",
            "    setAttr \".b\" -type \"string\" \"$body = \\\"python(\\\" + \\\"\\\\\\\"print('ok')\\\\\\\"\\\" + \\\")\\\";\";\n",
            "    setAttr \".st\" 0;\n",
        ),
    );
}

fn write_benign_namespace_assembly_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"namespaceAssemblyScene\";\n",
            "    setAttr \".b\" -type \"string\" \"$side = \\\"Example\\\"; $kind = \\\"Control\\\"; $name = $side + \\\"_\\\" + $kind + \\\"_option_control\\\"; optionMenu -label $name sampleMenu;\";\n",
            "    setAttr \".st\" 0;\n",
        ),
    );
}

fn write_opaque_tail_script_scene(path: &std::path::Path) {
    let body = "opaque tail body";
    let padding = " ".repeat(520);
    write_scene(
        path,
        &format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"opaqueTailScript\";\n",
                "    setAttr \".b\" -type \"string\"{padding}\"{body}\";\n",
                "    setAttr \".st\" 0;\n",
            ),
            padding = padding,
            body = body
        ),
    );
}

fn write_marker_free_indirect_exec_scene(path: &std::path::Path) {
    write_scene(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"markerFreeIndirectExec\";\n",
            "    setAttr \".st\" 0;\n",
            "    setAttr \".stp\" 1;\n",
            "    setAttr \".b\" -type \"string\" \"import builtins\\nrunner = getattr(builtins, \\\"exec\\\")\\nrunner(\\\"print('hi')\\\")\";\n",
        ),
    );
}

#[test]
fn audit_fixed_literal_mel_python_is_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("mel_python_literal.ma");
    write_literal_mel_python_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(report.finding_count() >= 1);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelPython)
    );
}

#[test]
fn audit_dynamic_autorun_mel_python_is_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("mel_python_dynamic_autorun.ma");
    write_autorun_mel_python_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(report.finding_count() >= 1);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelPython)
    );
}

#[test]
fn audit_top_level_command_port_is_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("top_level_command_port.ma");
    write_top_level_command_port_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelCommandPort)
    );
}

#[test]
fn audit_mel_exec_script_node_is_block_without_unknown_semantics() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("mel_exec_script_node.ma");
    write_mel_exec_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(!report.blocked_on_uncertainty);
    assert!(report.unknown_semantics.is_empty());
    assert!(
        report.findings.iter().any(|finding| {
            finding_code_str(finding) == "mel_exec"
                && finding.sink == AuditSinkKind::MelExec
                && finding.severity == AuditSeverity::Critical
        }),
        "missing MEL exec finding: {:?}",
        report.findings
    );
    assert!(
        report
            .unit_summaries
            .iter()
            .any(|summary| summary.effect == ExecutionEffectClass::ExternalDependency)
    );
}

#[test]
fn audit_top_level_exec_is_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("top_level_exec.ma");
    write_top_level_exec_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelExec)
    );
    assert!(report.surfaces.iter().any(|surface| {
        surface.origin.surface_kind == ExecutionSurfaceKind::TopLevelCommand
            && surface.origin.source_kind.as_deref() == Some("exec")
    }));
}

#[test]
fn audit_top_level_python_is_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("top_level_python.ma");
    write_top_level_python_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelPython)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::PySubprocess)
    );
}

#[test]
fn audit_top_level_eval_is_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("top_level_eval.ma");
    write_top_level_eval_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelEval)
    );
}

#[test]
fn audit_python_file_open_is_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("python_file_open.ma");
    write_python_script_node_scene(
        &source,
        "ExampleFileOpenScript",
        "handle = open('asset/example/file.txt')",
    );
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report.findings.iter().any(|finding| {
            finding_code_str(finding) == "python_file_open"
                && finding.sink == AuditSinkKind::PyFileOpen
                && finding.severity == AuditSeverity::Critical
        }),
        "missing Python file-open finding: {:?}",
        report.findings
    );
}

#[test]
fn audit_python_file_write_is_block_without_path_context() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("python_file_write.ma");
    write_python_script_node_scene(
        &source,
        "ExampleFileWriteScript",
        "handle.writelines(['Sample'])",
    );
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report.findings.iter().any(|finding| {
            finding_code_str(finding) == "python_file_write"
                && finding.sink == AuditSinkKind::PyFileWrite
                && finding.severity == AuditSeverity::Critical
        }),
        "missing Python file-write finding: {:?}",
        report.findings
    );
}

#[test]
fn audit_python_autorun_persistence_marker_is_recorded_as_block() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("python_autorun_marker.ma");
    write_python_script_node_scene(
        &source,
        "ExampleAutorunMarkerScript",
        "setup_path = 'scripts/userSetup.py'",
    );
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report.findings.iter().any(|finding| {
            finding_code_str(finding) == "python_autorun_persistence_marker"
                && finding.sink == AuditSinkKind::PyAutorunPersistence
                && finding.severity == AuditSeverity::Critical
        }),
        "missing Python autorun persistence marker finding: {:?}",
        report.findings
    );
}

#[test]
fn audit_python_file_persistence_shape_is_blocked_without_eval() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("python_file_persistence_shape.ma");
    write_scene(
        &source,
        &format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"ExampleSetupScript\";\n",
                "    setAttr \".st\" 1;\n",
                "    setAttr \".stp\" 1;\n",
                "    setAttr \".b\" -type \"string\" \"{}\";\n",
                "createNode script -n \"ExamplePayloadScript\";\n",
                "    setAttr \".st\" 1;\n",
                "    setAttr \".stp\" 1;\n",
                "    setAttr \".b\" -type \"string\" \"{}\";\n",
            ),
            escape_ma_string(concat!(
                "setup_path = cmds.internalVar(userAppDir=True) + 'scripts/userSetup.py'\n",
                "lines = ['import maya.cmds as cmds\\n']\n",
                "with open(setup_path, 'w') as handle:\n",
                "\thandle.writelines(lines)"
            )),
            escape_ma_string(concat!(
                "payload_path = cmds.internalVar(userAppDir=True) + '/scripts/SamplePayload.py'\n",
                "if not os.path.exists(payload_path):\n",
                "\twith open(payload_path, 'w') as handle:\n",
                "\t\thandle.write('Sample')"
            )),
        ),
    );
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    for expected in [
        "python_file_open",
        "python_file_write",
        "python_autorun_persistence_marker",
    ] {
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding_code_str(finding) == expected),
            "missing {expected} finding: {:?}",
            report.findings
        );
    }
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "python_pyeval"),
        "shape regression should not depend on eval: {:?}",
        report.findings
    );
}

#[test]
fn audit_indented_top_level_python_is_block_with_findings_despite_incomplete_coverage() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("indented_top_level_python.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "    python(\"import subprocess\\nsubprocess.call(['echo', 'hi'])\");\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelPython)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::PySubprocess)
    );
    assert!(report.coverage_issues.iter().any(|issue| {
        matches!(
            &issue.detail,
            ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic }
                if diagnostic.contains("indented top-level MEL statement requires conservative audit coverage")
        )
    }));
}

#[test]
fn audit_indented_top_level_eval_is_block_with_findings_despite_incomplete_coverage() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("indented_top_level_eval.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "    eval(\"python(\\\"import subprocess\\\\nsubprocess.call(['echo', 'hi'])\\\")\");\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelEval)
    );
    assert!(report.coverage_issues.iter().any(|issue| {
        matches!(
            &issue.detail,
            ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic }
                if diagnostic.contains("indented top-level MEL statement requires conservative audit coverage")
        )
    }));
}

#[test]
fn audit_cp932_scene_is_review_due_to_non_utf8_selective_coverage() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("cp932_scene.ma");
    write_cp932_ui_scene(&source);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.coverage_issues.iter().any(|issue| {
        matches!(
            &issue.detail,
            ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic }
                if diagnostic.contains("non-utf8 MEL source decoded via cp932 selective path requires conservative audit coverage")
        )
    }));
}

#[test]
fn audit_file_command_callback_is_review_due_to_heuristic_coverage() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("file_command_callback.ma");
    write_file_command_callback_scene(&source);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert!(report.coverage_issues.iter().any(|issue| {
        matches!(
            &issue.detail,
            ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic }
                if diagnostic.contains("file -command selective extraction relies on heuristic flag parsing and requires conservative audit coverage")
        )
    }));
}

#[test]
fn audit_opaque_tail_script_body_is_review_due_to_incomplete_coverage() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("opaque_tail_script.ma");
    write_opaque_tail_script_scene(&source);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.coverage_issues.iter().any(|issue| {
        matches!(
            &issue.detail,
            ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic }
                if diagnostic.contains("setAttr .b selective extraction depends on opaque tail beyond the light-prefix budget and requires conservative audit coverage")
        )
    }));
}

#[test]
fn audit_sphere_pair_reviews_for_proc_callback_flags_without_mb_unknown_surface_noise() {
    for ext in ["ma", "mb"] {
        let report = audit_script_nodes(
            repo_root().join(format!("tests/02/sphere.{ext}")),
            &audit_plan(),
        )
        .expect("audit report");

        assert_eq!(report.disposition, AuditDisposition::Review);
        assert!(
            report
                .review_signals
                .iter()
                .any(|review| review.code.as_str() == "mel_callback_proc_reference"),
            "missing callback review signal for {ext}"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding_code_str(finding) != "mel_callback_flag"),
            "unexpected callback finding for {ext}"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding_code_str(finding) != "obfuscation_markers"),
            "unexpected obfuscation finding for {ext}"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding_code_str(finding) != "unknown_execution_language"),
            "unexpected unknown-language finding for {ext}"
        );
        assert_eq!(
            report.coverage_state,
            ExecutionCoverageState::Complete,
            "unexpected coverage state for {ext}"
        );
        assert!(
            report.blocked_on_uncertainty,
            "expected uncertainty block for {ext}"
        );
    }
}

#[test]
fn audit_mb_frdi_fbx_source_metadata_is_not_raw_execution_surface() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("frdi_fbx_source.mb");
    let frdi_payload = b"\0\0\0\x02assets/example/ExampleAsset.fbx\0Source\0\x01\0Import_00_Example:SourceRN\0\0\0\0VERS|2020|UVER|undef|MADE|undef|CHNG|Mon, Jan 01, 2024 00:00:00 AM|ICON|undef|INFO|undef|OBJN|123|INCL|undef(|LUNI|cm|TUNI|ntscf|AUNI|deg|TDUR|120|\0FBX export\0";
    std::fs::write(
        &source,
        build_mb_root(&[build_mb_form(
            "FRDI",
            &[build_mb_chunk("FRDI", frdi_payload)],
        )]),
    )
    .expect("write mb fixture");

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_parse_diagnostics"),
        "unexpected MEL diagnostics finding: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "unknown_execution_language"),
        "unexpected unknown language finding: {:?}",
        report.findings
    );
    assert!(
        report.coverage_issues.iter().all(|issue| !matches!(
            issue.detail,
            ExecutionCoverageIssueDetail::SurfaceDiagnostics { .. }
        )),
        "unexpected surface diagnostics coverage issue: {:?}",
        report.coverage_issues
    );
}

#[test]
fn audit_mb_fref_fbx_source_metadata_is_not_raw_execution_surface() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("fref_fbx_source.mb");
    let fref_payload = b"assets/example/ExampleAsset.fbx\0Source\0\x01\x01SourceRN\0\0\0\0\0VERS|2020|UVER|undef|MADE|undef|CHNG|Mon, Jan 01, 2024 00:00:00 AM|ICON|undef|INFO|undef|OBJN|123|INCL|undef(|LUNI|cm|TUNI|ntscf|AUNI|deg|TDUR|120|\0FBX export\0";
    std::fs::write(
        &source,
        build_mb_root(&[build_mb_form(
            "FREF",
            &[build_mb_chunk("FREF", fref_payload)],
        )]),
    )
    .expect("write mb fixture");

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_parse_diagnostics"),
        "unexpected MEL diagnostics finding: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "unknown_execution_language"),
        "unexpected unknown language finding: {:?}",
        report.findings
    );
    assert!(
        report.coverage_issues.iter().all(|issue| !matches!(
            issue.detail,
            ExecutionCoverageIssueDetail::SurfaceDiagnostics { .. }
        )),
        "unexpected surface diagnostics coverage issue: {:?}",
        report.coverage_issues
    );
}

#[test]
fn audit_mb_raw_marker_payload_is_coverage_uncertainty_not_unknown_language_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("unknown_raw_marker.mb");
    std::fs::write(
        &source,
        build_mb_root(&[build_mb_form(
            "UNKN",
            &[build_mb_chunk(
                "DATA",
                b"source \"asset/example/startup.mel\"",
            )],
        )]),
    )
    .expect("write mb fixture");

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "unknown_execution_language"),
        "unexpected unknown language finding: {:?}",
        report.findings
    );
    assert!(report.coverage_issues.iter().any(|issue| {
        issue.kind == ExecutionCoverageIssueKind::UnknownRawMbPayload
            && matches!(
                &issue.detail,
                ExecutionCoverageIssueDetail::UnknownRawMbPayload { marker }
                    if marker == "source"
            )
    }));
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
}

#[test]
fn audit_inline_print_callback_is_review_without_callback_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("inline_print_callback.ma");
    write_model_editor_callback_scene(&source, r#"print \\\"ok\\\";"#);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.findings.is_empty());
    assert!(
        report
            .review_signals
            .iter()
            .any(|review| review.code.as_str() == "mel_callback_body")
    );
    assert!(
        report
            .surfaces
            .iter()
            .any(|surface| surface.derivation == AuditSurfaceDerivation::MelCallbackLiteral)
    );
}

#[test]
fn audit_inline_python_callback_denies_via_derived_sink_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("inline_python_callback.ma");
    write_model_editor_callback_scene(&source, r#"python(\\\"import os\\\")"#);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .review_signals
            .iter()
            .any(|review| review.code.as_str() == "mel_callback_body")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelPython)
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_callback_flag")
    );
}

#[test]
fn audit_dynamic_callback_payload_still_denies_via_callback_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("dynamic_callback.ma");
    write_dynamic_model_editor_callback_scene(&source);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding_code_str(finding) == "mel_callback_flag")
    );
}

#[test]
fn audit_top_level_schema_script_flag_callback_denies_via_derived_eval_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("top_level_schema_callback.ma");
    write_top_level_schema_script_flag_callback_scene(&source);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .review_signals
            .iter()
            .any(|review| review.code.as_str() == "mel_callback_body")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelEval)
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_callback_flag")
    );
}

#[test]
fn audit_assembled_code_like_without_sink_is_review_in_strict_mode() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("assembled_code_like_without_sink.ma");
    write_assembled_code_like_without_sink_scene(&source);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(
        report
            .review_signals
            .iter()
            .any(|review| review.code.as_str() == "mel_body_assembly_without_sink")
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "obfuscation_markers")
    );
}

#[test]
fn audit_assembled_code_like_without_sink_is_deny_uncertain_in_hardened_mode() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("assembled_code_like_hardened.ma");
    write_assembled_code_like_without_sink_scene(&source);

    let report = audit_script_nodes_with_options(
        &source,
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::hardened_untrusted(),
    )
    .expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyUncertain);
    assert!(
        report
            .review_signals
            .iter()
            .any(|review| review.code.as_str() == "mel_body_assembly_without_sink")
    );
}

#[test]
fn audit_benign_namespace_assembly_does_not_emit_body_assembly_signals() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("benign_namespace_assembly.ma");
    write_benign_namespace_assembly_scene(&source);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert!(
        report
            .review_signals
            .iter()
            .all(|review| review.code.as_str() != "mel_body_assembly_without_sink")
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "obfuscation_markers")
    );
}

#[test]
fn audit_mb_load_path_respects_additional_node_info_inputs() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempfile::tempdir().expect("tmpdir");
    let bad_node_info = dir.path().join("bad_node_info.yaml");
    std::fs::write(&bad_node_info, "not: [valid").expect("write bad node info");

    let err = audit_script_nodes_with_options(
        &source,
        &audit_plan(),
        &LoadOptions::default().with_additional_node_info_paths(vec![bad_node_info]),
        AuditOptions::strict_default(),
    )
    .expect_err("expected config failure");

    assert!(matches!(err, SceneToolError::Config(_)));
}

#[test]
fn audit_default_run_avoids_custom_rule_duplicates_for_detected_sinks() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let cases = [
        ("mel_python_literal.ma", AuditSinkKind::MelPython),
        ("top_level_eval.ma", AuditSinkKind::MelEval),
        ("marker_free_indirect_exec.ma", AuditSinkKind::PyExec),
    ];

    for (file_name, expected_sink) in cases {
        let source = dir.path().join(file_name);
        match file_name {
            "mel_python_literal.ma" => write_literal_mel_python_scene(&source),
            "top_level_eval.ma" => write_top_level_eval_scene(&source),
            "marker_free_indirect_exec.ma" => write_marker_free_indirect_exec_scene(&source),
            _ => unreachable!("unexpected case"),
        }
        let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");
        assert!(
            report.effective_rules.is_empty(),
            "expected no implicit rules for {file_name}"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.sink == expected_sink),
            "missing dedicated sink finding for {file_name}"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding_code_str(finding) != "custom_rule_match"),
            "unexpected custom rule fallback for {file_name}"
        );
    }
}

#[test]
fn audit_marker_free_indirect_exec_uses_python_analysis_without_custom_rules() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("marker_free_indirect_exec.ma");
    write_marker_free_indirect_exec_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(report.effective_rules.is_empty());
    assert!(report.findings.iter().any(|finding| {
        finding_code_str(finding) == "python_pyexec"
            && finding.sink == AuditSinkKind::PyExec
            && finding.rule.is_none()
    }));
    assert_eq!(
        finding_severity(&report, "python_pyexec"),
        Some(AuditSeverity::Critical)
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "custom_rule_match")
    );
}

fn write_manual_python_scene(path: &std::path::Path, body: &str) {
    std::fs::write(
        path,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"manual_python\";\n",
                "\tsetAttr \".b\" -type \"string\" \"{body}\";\n",
                "\tsetAttr \".st\" 1;\n",
                "\tsetAttr \".stp\" 1;\n",
            ),
            body = body
        ),
    )
    .expect("write fixture");
}

fn write_python2_print_concat_scene(path: &std::path::Path) {
    write_manual_python_scene(
        path,
        concat!(
            "print 'start scriptNode ExampleGroup'\\n",
            "dLayer = 'Sample:ExampleGroup:ExampleLayer'\\n",
            "cmds.setAttr(dLayer + '.color', 13)"
        ),
    );
}

#[test]
fn audit_manual_python_eval_and_compile_are_critical() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let cases = [
        ("python_eval.ma", "eval('1 + 1')", "python_pyeval"),
        (
            "python_compile.ma",
            "compile('1 + 1', '<audit>', 'eval')",
            "python_pycompile",
        ),
    ];

    for (file_name, body, expected_code) in cases {
        let source = dir.path().join(file_name);
        write_manual_python_scene(&source, body);
        let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

        assert_eq!(
            finding_severity(&report, expected_code),
            Some(AuditSeverity::Critical),
            "unexpected severity for {expected_code}"
        );
    }
}

#[test]
fn mb_read_only_apis_share_validation_state_for_canonical_recovery() {
    let source = repo_root().join("tests/02/sphere.mb");
    let check = check_script_nodes(&source).expect("check");
    let entries = collect_script_node_entries(&source).expect("entries");
    let paths = collect_scene_paths(&source, PathKind::All).expect("paths");
    let audit = audit_script_nodes(&source, &audit_plan()).expect("audit");

    assert_eq!(check.validation_state, entries.validation_state);
    assert_eq!(check.validation_state, paths.validation_state);
    assert_eq!(check.validation_state, audit.validation_state);
    assert_eq!(check.validation_state, ValidationState::Partial);
}

#[test]
fn audit_observation_matches_path_entrypoint_for_existing_fixture() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("mel_python_literal.ma");
    write_literal_mel_python_scene(&source);
    let plan = audit_plan();
    let observation = Loader::new(LoadOptions::default())
        .observe_path(&source)
        .expect("observe");

    let via_observation = audit_observation(&observation, &plan, AuditOptions::strict_default())
        .expect("audit via observation");
    let via_path = audit_script_nodes(&source, &plan).expect("audit via path");

    assert_eq!(via_observation.disposition, via_path.disposition);
    assert_eq!(via_observation.surface_count, via_path.surface_count);
    assert_eq!(via_observation.finding_count(), via_path.finding_count());
}

#[test]
fn audit_observation_matches_path_entrypoint_for_ma_render_callbacks() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("render_callbacks.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "select -ne :defaultRenderGlobals;\n",
            "    setAttr \".poam\" -type \"string\" \"eval(\\\"ExampleCallback;\\\")\";\n",
            "    setAttr \".prlm\" -type \"string\" \"python(\\\"print(\\\\\\\"Example\\\\\\\")\\\")\";\n",
        ),
    );
    let plan = audit_plan();
    let observation = Loader::new(LoadOptions::default())
        .observe_path(&source)
        .expect("observe");

    let via_observation = audit_observation(&observation, &plan, AuditOptions::strict_default())
        .expect("audit via observation");
    let via_path = audit_script_nodes(&source, &plan).expect("audit via path");

    assert_eq!(via_observation.disposition, via_path.disposition);
    assert_eq!(via_observation.surface_count, via_path.surface_count);
    assert_eq!(via_observation.finding_count(), via_path.finding_count());
    assert!(via_observation.surfaces.iter().any(|surface| {
        surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
            && surface.origin.attr_name.as_deref() == Some(".poam")
    }));
}

#[test]
fn reference_graph_multi_root_audits_shared_child_once_and_preserves_edges() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_scene(&dir.path().join("workspace.mel"), "// workspace\n");
    let root_a = dir.path().join("root_a.ma");
    let root_b = dir.path().join("root_b.ma");
    let child = dir.path().join("shared_child.ma");
    write_reference_scene(&root_a, "shared_child.ma", "sharedChildARn");
    write_reference_scene(&root_b, "shared_child.ma", "sharedChildBRn");
    write_basic_scene(&child);

    let graph = audit_reference_graph_roots_with_options_and_digests(
        [&root_a, &root_b],
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
        false,
    );

    assert_eq!(graph.roots.len(), 2);
    assert_eq!(graph.edges.len(), 2);
    assert_eq!(graph.reports.len(), 3);
    assert!(graph.traversal_issues.is_empty());
    let child_edge_indexes = graph
        .edges
        .iter()
        .map(|edge| edge.target_report_index.expect("child report index"))
        .collect::<Vec<_>>();
    assert_eq!(child_edge_indexes[0], child_edge_indexes[1]);
}

#[test]
fn reference_graph_non_recursive_records_edges_without_auditing_children() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_scene(&dir.path().join("workspace.mel"), "// workspace\n");
    let root = dir.path().join("root.ma");
    let child = dir.path().join("child.ma");
    write_reference_scene(&root, "child.ma", "childRn");
    write_basic_scene(&child);

    let graph = audit_reference_graph_roots_with_traversal_options_and_digests(
        [&root],
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
        ReferenceGraphOptions::non_recursive(),
        false,
    );

    assert_eq!(graph.roots.len(), 1);
    assert_eq!(graph.reports.len(), 1);
    assert_eq!(graph.edges.len(), 1);
    assert!(graph.traversal_issues.is_empty());
    assert_eq!(graph.edges[0].raw_target, "child.ma");
    assert!(graph.edges[0].target_identity.is_some());
    assert!(graph.edges[0].target_report_index.is_none());
}

#[test]
fn reference_graph_cycle_emits_cycle_issue() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_scene(&dir.path().join("workspace.mel"), "// workspace\n");
    let root = dir.path().join("root.ma");
    let child = dir.path().join("child.ma");
    write_reference_scene(&root, "child.ma", "childRn");
    write_reference_scene(&child, "root.ma", "rootRn");

    let graph = audit_reference_graph_roots_with_options_and_digests(
        [&root],
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
        false,
    );

    assert!(graph.traversal_issues.iter().any(|issue| {
        issue.kind == AuditTraversalIssueKind::Cycle
            && issue.raw_target.as_deref() == Some("root.ma")
    }));
    assert_eq!(graph.disposition, AuditDisposition::Review);
}

#[test]
fn audit_report_surfaces_include_bridge_surface_for_literal_mel_python() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("mel_python_literal.ma");
    write_literal_mel_python_scene(&source);
    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    let bridge_surface = report
        .surfaces
        .iter()
        .find(|surface| surface.derivation == AuditSurfaceDerivation::MelPythonLiteralBridge)
        .expect("bridge-derived surface");

    assert!(report.surfaces.len() > report.surface_count);
    assert_eq!(
        bridge_surface.derivation,
        AuditSurfaceDerivation::MelPythonLiteralBridge
    );
    assert_eq!(bridge_surface.origin.lang, ExecutionLanguage::Python);
    assert_eq!(
        bridge_surface.origin.source_kind.as_deref(),
        Some("mel->python literal bridge")
    );
}

#[test]
fn audit_proven_python_print_only_is_allow_with_notice() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("print_only.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"print_only\";\n",
            "\tsetAttr \".b\" -type \"string\" \"print('safe')\";\n",
            "\tsetAttr \".st\" 1;\n",
            "\tsetAttr \".stp\" 1;\n",
        ),
    )
    .expect("write fixture");

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::AllowWithNotice);
    assert!(
        report
            .unit_summaries
            .iter()
            .any(|summary| summary.effect.as_str() == "diagnostic_output")
    );
}

#[test]
fn audit_python2_print_with_non_sink_concat_avoids_body_assembly_false_positive() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("python2_print_concat.ma");
    write_python2_print_concat_scene(&source);

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "python_body_assembly")
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "python_parse_failure")
    );
}

#[test]
fn audit_python_join_without_execution_sink_does_not_emit_body_assembly_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("python_join_attr_path.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"script_a\";\n",
            "\tsetAttr \".b\" -type \"string\" \"",
            "import maya.cmds as cmds\\n",
            "node_name = 'node_a'\\n",
            "attr_name = '.'.join([node_name, 'sample_attr'])\\n",
            "cmds.setAttr(attr_name, 'sample_value', type='string')",
            "\";\n",
            "\tsetAttr \".st\" 1;\n",
            "\tsetAttr \".stp\" 1;\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "python_body_assembly")
    );
    assert_ne!(report.disposition, AuditDisposition::DenyMalicious);
}

#[test]
fn audit_python_join_reaching_exec_keeps_sink_finding_with_marker_evidence() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("python_join_exec.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"script_a\";\n",
            "\tsetAttr \".b\" -type \"string\" \"",
            "code = ''.join(['pri', 'nt(1)'])\\n",
            "exec(code)",
            "\";\n",
            "\tsetAttr \".st\" 1;\n",
            "\tsetAttr \".stp\" 1;\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(report.findings.iter().any(|finding| {
        finding.sink == AuditSinkKind::PyExec
            && finding
                .evidence
                .iter()
                .any(|evidence| format!("{evidence:?}").contains("join("))
    }));
}

#[test]
fn audit_python_hard_marker_without_sink_emits_body_assembly_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("python_hard_marker.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"script_a\";\n",
            "\tsetAttr \".b\" -type \"string\" \"",
            "sample = bytes.fromhex('7072696e74283129').decode()",
            "\";\n",
            "\tsetAttr \".st\" 1;\n",
            "\tsetAttr \".stp\" 1;\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding_code_str(finding) == "python_body_assembly")
    );
}

#[test]
fn audit_source_command_emits_review_dependency_fact() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("source_dep.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "source \"tools/startup.mel\";\n",
        ),
    )
    .expect("write fixture");

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert!(report.dependency_facts.iter().any(|fact| {
        fact.kind == DependencyFactKind::SourceCommand
            && fact.risk == DependencyRiskClass::Review
            && fact.target == "tools/startup.mel"
    }));
}

#[test]
fn audit_file_path_absolute_dependency_remains_allow() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("absolute_file_path.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode file -n \"SampleFile\";\n",
            "    setAttr \".ftn\" -type \"string\" \"/asset/example/albedo.png\";\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Allow);
    assert!(report.dependency_facts.iter().any(|fact| {
        fact.kind == DependencyFactKind::FilePath
            && fact.risk == DependencyRiskClass::Informational
            && fact.target == "/asset/example/albedo.png"
    }));
}

#[test]
fn audit_file_path_parent_segments_dependency_remains_allow() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("parent_segment_file_path.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode file -n \"SampleFile\";\n",
            "    setAttr \".ftn\" -type \"string\" \"assets/../textures/albedo.png\";\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Allow);
    assert!(report.dependency_facts.iter().any(|fact| {
        fact.kind == DependencyFactKind::FilePath
            && fact.risk == DependencyRiskClass::Informational
            && fact.target == "assets/../textures/albedo.png"
    }));
}

#[test]
fn audit_reference_path_absolute_dependency_remains_review() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("absolute_reference_path.ma");
    write_reference_scene(&source, "/asset/example/child.ma", "SampleReferenceRN");

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.dependency_facts.iter().any(|fact| {
        fact.kind == DependencyFactKind::ReferencePath
            && fact.risk == DependencyRiskClass::Uncertain
            && fact.target == "/asset/example/child.ma"
    }));
}

#[test]
fn audit_script_bearing_setattr_write_is_deny_malicious() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("script_attr_write.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"targetScript\";\n",
            "\tsetAttr \".b\" -type \"string\" \"print(\\\"safe\\\")\";\n",
            "createNode script -n \"writerScript\";\n",
            "\tsetAttr \".b\" -type \"string\" \"setAttr \\\"targetScript.b\\\" -type \\\"string\\\" \\\"python(\\\\\\\"import os\\\\\\\")\\\"\";\n",
            "\tsetAttr \".st\" 1;\n",
        ),
    )
    .expect("write fixture");

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(report.unit_summaries.iter().any(|summary| {
        summary.semantic_class.as_str() == "script_bearing_write"
            && summary.effect.as_str() == "scene_mutation"
    }));
}

#[test]
fn audit_expression_internal_expression_assignment_is_not_parse_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("expression_assignment.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode expression -n \"ExampleExpression\";\n",
            "    setAttr \".ixp\" -type \"string\" \".exampleAttr[0] = frame;\";\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::AllowWithNotice);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_parse_diagnostics"),
        "unexpected MEL diagnostics finding: {:?}",
        report.findings
    );
    assert!(
        report.coverage_issues.iter().all(|issue| !matches!(
            issue.detail,
            ExecutionCoverageIssueDetail::SurfaceDiagnostics { .. }
        )),
        "unexpected surface diagnostics coverage issue: {:?}",
        report.coverage_issues
    );
}

#[test]
fn audit_expression_literal_python_print_is_allowed_with_notice_without_mel_python_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("expression_python_print.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode expression -n \"ExampleExpression\";\n",
            "    setAttr \".ixp\" -type \"string\" \"python(\\\"print('Sample')\\\");\";\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::AllowWithNotice);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_python"),
        "unexpected MEL python finding: {:?}",
        report.findings
    );
    assert!(report.surfaces.iter().any(|surface| {
        surface.derivation == AuditSurfaceDerivation::MelPythonLiteralBridge
            && surface.origin.lang == ExecutionLanguage::Python
    }));
}

#[test]
fn audit_expression_literal_python_import_is_review_without_mel_python_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("expression_sink.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode expression -n \"ExampleExpression\";\n",
            "    setAttr \".ixp\" -type \"string\" \"python(\\\"import os\\\");\";\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.unit_summaries.iter().any(|summary| {
        summary.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
            && summary.origin.attr_name.as_deref() == Some(".ixp")
            && summary.effect == ExecutionEffectClass::ExternalDependency
    }));
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_python"),
        "unexpected MEL python finding: {:?}",
        report.findings
    );
    assert!(
        report.coverage_issues.iter().all(|issue| !matches!(
            issue.detail,
            ExecutionCoverageIssueDetail::SurfaceDiagnostics { .. }
        )),
        "unexpected surface diagnostics coverage issue: {:?}",
        report.coverage_issues
    );
}

#[test]
fn audit_expression_literal_python_dangerous_body_uses_python_findings() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("expression_python_subprocess.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode expression -n \"ExampleExpression\";\n",
            "    setAttr \".ixp\" -type \"string\" \"python(\\\"import subprocess\\\\nsubprocess.call(['echo', 'Sample'])\\\");\";\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_python"),
        "unexpected MEL python finding: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::PySubprocess),
        "expected Python subprocess finding: {:?}",
        report.findings
    );
}

#[test]
fn audit_expression_dynamic_python_bridge_keeps_mel_python_finding() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("expression_python_dynamic.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode expression -n \"ExampleExpression\";\n",
            "    setAttr \".ixp\" -type \"string\" \"$body = \\\"print('Sample')\\\"; python($body);\";\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding_code_str(finding) == "mel_python"),
        "expected MEL python finding: {:?}",
        report.findings
    );
    assert!(
        report.coverage_issues.iter().all(|issue| !matches!(
            issue.detail,
            ExecutionCoverageIssueDetail::SurfaceDiagnostics { .. }
        )),
        "unexpected surface diagnostics coverage issue: {:?}",
        report.coverage_issues
    );
}

#[test]
fn audit_budget_exceed_returns_blocked_report_instead_of_error() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("budget_blocked_top_level.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"blocked\";\n",
            "    setAttr \".b\" -type \"string\" \"print(\\\"hi\\\")\";\n",
            "    setAttr \".st\" 0;\n",
        ),
    );

    let report = audit_script_nodes_with_options(
        &source,
        &audit_plan(),
        &LoadOptions::default().with_max_parse_bytes(1),
        AuditOptions::strict_default(),
    )
    .expect("blocked audit report");

    assert_eq!(report.validation_state, ValidationState::Invalid);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.surfaces.is_empty());
    assert!(report.findings.is_empty());
    assert!(report.review_signals.is_empty());
    assert_eq!(report.notice_count(), 1);
    assert!(report.is_parse_budget_blocked());
    assert_eq!(report.notices[0].code, AuditNoticeCode::ParseBudgetExceeded);
    assert_eq!(report.notices[0].severity, AuditSeverity::Info);
    assert_eq!(
        report.notices[0].message,
        "parse budget exceeded: max_bytes"
    );
}

#[test]
fn audit_observation_surface_budget_exceed_returns_blocked_report() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("budget_blocked_surface.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"nestedBudget\";\n",
            "    setAttr \".b\" -type \"string\" \"if (1) { if (1) { print(\\\"hi\\\"); } }\";\n",
            "    setAttr \".st\" 1;\n",
        ),
    );

    let observation = Loader::new(
        LoadOptions::default().with_mel_parse_budget(MelParseBudget {
            max_nesting_depth: 1,
            ..MelParseBudget::default()
        }),
    )
    .observe_path(&source)
    .expect("observation");
    let report = audit_observation(&observation, &audit_plan(), AuditOptions::strict_default())
        .expect("blocked audit report");

    assert_eq!(report.validation_state, ValidationState::Validated);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.surfaces.is_empty());
    assert!(report.findings.is_empty());
    assert!(report.review_signals.is_empty());
    assert_eq!(report.notice_count(), 1);
    assert!(report.is_parse_budget_blocked());
    assert_eq!(report.notices[0].code, AuditNoticeCode::ParseBudgetExceeded);
    assert_eq!(
        report.notices[0].message,
        "parse budget exceeded: max_nesting_depth"
    );
}

#[test]
fn audit_mb_budget_exceed_returns_blocked_report_instead_of_error() {
    let source = repo_root().join("tests/02/sphere.mb");
    let report = audit_script_nodes_with_options(
        &source,
        &audit_plan(),
        &LoadOptions::default().with_max_parse_bytes(1),
        AuditOptions::strict_default(),
    )
    .expect("blocked audit report");

    assert_eq!(report.validation_state, ValidationState::Invalid);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.surfaces.is_empty());
    assert!(report.findings.is_empty());
    assert!(report.review_signals.is_empty());
    assert_eq!(report.notice_count(), 1);
    assert!(report.is_parse_budget_blocked());
    assert_eq!(report.notices[0].code, AuditNoticeCode::ParseBudgetExceeded);
    assert_eq!(report.notices[0].severity, AuditSeverity::Info);
    assert_eq!(
        report.notices[0].message,
        "parse budget exceeded: max_parse_bytes"
    );
}

#[test]
fn audit_mb_child_budget_exceed_returns_blocked_report() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("budget_blocked_surface.mb");
    std::fs::write(
        &source,
        build_mb_root(&[build_mb_form(
            "TEST",
            &[build_mb_chunk("ONE ", b"1"), build_mb_chunk("TWO ", b"2")],
        )]),
    )
    .expect("write mb fixture");

    let report = audit_script_nodes_with_options(
        &source,
        &audit_plan(),
        &LoadOptions::default().with_mb_parse_budget(MbParseBudget {
            max_children_per_group: 1,
            ..MbParseBudget::default()
        }),
        AuditOptions::strict_default(),
    )
    .expect("blocked audit report");

    assert_eq!(report.validation_state, ValidationState::Invalid);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.surfaces.is_empty());
    assert!(report.findings.is_empty());
    assert!(report.review_signals.is_empty());
    assert_eq!(report.notice_count(), 1);
    assert!(report.is_parse_budget_blocked());
    assert_eq!(report.notices[0].code, AuditNoticeCode::ParseBudgetExceeded);
    assert_eq!(
        report.notices[0].message,
        "parse budget exceeded: max_children_per_group"
    );
}

#[test]
fn allowlist_report_json_compatibility() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("Example.ma");
    write_scene(
        &source,
        "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"ExampleScriptNode\";\n\tsetAttr \".b\" -type \"string\" \"exec \\\"Example\\\"\";\n\tsetAttr \".st\" 1;\n",
    );
    let mut report = audit_script_nodes(&source, &audit_plan()).expect("audit");
    report.scene_path = PathBuf::from("Example.ma");
    report.digests.schema_bundle_sha256 = Some("ExampleSchemaDigest".into());
    const BASELINE: &str = r###"{"scene_path":"Example.ma","scene_format":"ma","profile":"strict_default","validation_state":"validated","effective_rules":[],"surface_count":1,"coverage_state":"complete","coverage_issues":[],"blocked_on_uncertainty":false,"disposition":"deny_malicious","unit_summaries":[{"origin":{"lang":"mel","trigger":"file_open","surface_kind":"script_node_body","node_name":"ExampleScriptNode","attr_name":".b","source_kind":"scriptType=1","source_range":null,"chunk_form":null,"chunk_tag":null,"chunk_node_offset":null,"chunk_aux":null,"chunk_payload_offset":null,"chunk_payload_size":null,"chunk_child_alignment":null,"chunk_child_header_size":null},"effect":"external_dependency","semantic_class":"dependency_write","certainty":"proven","preview":"exec \"Example\"","reasons":[{"kind":"named","template":"external_dependency_mel_command_detected","value":"exec"}]}],"dependency_facts":[{"kind":"require","risk":"informational","target":"requires maya \"2026\";","detail":{"kind":"require"},"origin":null}],"unknown_semantics":[],"digests":{"scene_sha256":"647ae161e9ad85afd2341c5b361e65f0b34667e3365eda94ef48ad2f9a2462b7","schema_bundle_sha256":"ExampleSchemaDigest","policy_bundle_sha256":null},"notices":[],"surfaces":[{"origin":{"lang":"mel","trigger":"file_open","surface_kind":"script_node_body","node_name":"ExampleScriptNode","attr_name":".b","source_kind":"scriptType=1","source_range":null,"chunk_form":null,"chunk_tag":null,"chunk_node_offset":null,"chunk_aux":null,"chunk_payload_offset":null,"chunk_payload_size":null,"chunk_child_alignment":null,"chunk_child_header_size":null},"preview":"exec \"Example\"","derivation":"observed"}],"review_signals":[],"findings":[{"code":"mel_exec","severity":"critical","surface_index":0,"sink":"mel_exec","rule":null,"detail":{"kind":"static","value":"mel_exec_command_detected"},"evidence":[{"kind":"key_value","key":"node_name","value":"ExampleScriptNode"},{"kind":"key_value","key":"command","value":"exec"},{"kind":"free_text","value":"fixed literal command: Example"}],"preview_override":"Example"}]}"###;
    const IDENTITY: &str = r###"{"cache_schema_version":32,"scene_sha256":"647ae161e9ad85afd2341c5b361e65f0b34667e3365eda94ef48ad2f9a2462b7","schema_bundle_sha256":"ExampleSchemaDigest","audit_options_fingerprint":"f745b246cbd75ea83b68ab51dc1ec867f43236e180c77c6a20ef5298b905628e","audit_plan_fingerprint":"9b3f437efff889198d09e4aa020ec1badd32e3bbe3d6161fa0c41e526aa9f5f1"}"###;
    assert_eq!(serde_json::to_vec(&report).unwrap(), BASELINE.as_bytes());
    let empty_plan =
        audit_plan().with_allowlist(maya_scene_kit_audit::scene::AuditAllowlist::default());
    let mut empty = audit_script_nodes(&source, &empty_plan).unwrap();
    empty.scene_path = PathBuf::from("Example.ma");
    empty.digests.schema_bundle_sha256 = Some("ExampleSchemaDigest".into());
    assert_eq!(serde_json::to_vec(&empty).unwrap(), BASELINE.as_bytes());
    let old: AuditReport = serde_json::from_str(BASELINE).unwrap();
    assert!(
        old.findings
            .iter()
            .all(|finding| finding.allowed_by.is_none())
    );
    let old_identity: maya_scene_kit_audit::scene::AuditCacheIdentity =
        serde_json::from_str(IDENTITY).unwrap();
    let mut expected_identity = old_identity.clone();
    if usize::BITS == 32 {
        expected_identity.audit_plan_fingerprint =
            "b7aaf7542765ede5b774dcf911800f6bce37c8ceaf6508b528be0a4987138cff".into();
    }
    assert_eq!(
        maya_scene_kit_audit::scene::AuditCacheIdentity::new(
            report.digests.scene_sha256.clone(),
            AuditOptions::strict_default(),
            maya_scene_kit_audit::scene::fingerprint_audit_plan(&empty_plan),
            "ExampleSchemaDigest",
        ),
        expected_identity
    );
    let snapshot = format!(
        r###"{{"identity":{IDENTITY},"file_state":{{"path":"Example.ma","size":0,"modified_unix_nanos":null}},"report":{BASELINE}}}"###
    );
    let old_snapshot: maya_scene_kit_audit::scene::AuditedSceneSnapshot =
        serde_json::from_str(&snapshot).unwrap();
    assert_eq!(old_snapshot.identity, old_identity);
    assert!(
        old_snapshot
            .report
            .findings
            .iter()
            .all(|finding| finding.allowed_by.is_none())
    );
    let hash = maya_scene_kit_audit::scene::allowlist_surface_hash(
        &report.surfaces[0].origin,
        "exec \"Example\"",
    );
    let allowed = allowlist_contract_tests::allow(hash, &["mel_exec"]);
    let mut permitted = audit_script_nodes(&source, &audit_plan().with_allowlist(allowed)).unwrap();
    permitted.scene_path = PathBuf::from("Example.ma");
    permitted.digests.schema_bundle_sha256 = Some("ExampleSchemaDigest".into());
    let json = serde_json::to_string(&permitted).unwrap();
    assert!(json.contains(&format!(
        r###""allowed_by":{{"hash":"{hash}","source":"app"}}"###
    )));
    let roundtrip: AuditReport = serde_json::from_str(&json).unwrap();
    assert_eq!(
        roundtrip.findings[0].allowed_by,
        permitted.findings[0].allowed_by
    );
    assert!(roundtrip.findings[0].allowed_by.is_some());
    for finding in &mut permitted.findings {
        finding.allowed_by = None;
    }
    permitted.disposition = report.disposition;
    assert_eq!(serde_json::to_vec(&permitted).unwrap(), BASELINE.as_bytes());
}

mod allowlist_contract_tests {
    use maya_scene_kit_audit::scene::{
        AllowlistHash, AllowlistSource, AuditAllowlist, AuditFindingCode, allowlist_surface_hash,
    };
    use serde_json::json;

    use super::*;

    const BODY: &str = "exec \"Example\"";

    pub(super) fn allow(hash: AllowlistHash, codes: &[&str]) -> AuditAllowlist {
        AuditAllowlist::from_json(
            &json!({"version":1,"entries":[{"hash":hash,"codes":codes}]}).to_string(),
            AllowlistSource::App,
        )
        .unwrap()
    }

    fn scene(body: &str, python: bool) -> String {
        format!(
            "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"ExampleScriptNode\";\n\tsetAttr \".b\" -type \"string\" \"{}\";\n\tsetAttr \".st\" 1;\n{}",
            escape_ma_string(body),
            if python {
                "\tsetAttr \".stp\" 1;\n"
            } else {
                ""
            }
        )
    }

    fn run(text: &str, plan: &ScriptAuditPlan, options: AuditOptions) -> AuditReport {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Example.ma");
        write_scene(&path, text);
        let mut report =
            audit_script_nodes_with_options(&path, plan, &LoadOptions::default(), options).unwrap();
        report.scene_path = PathBuf::from("Example.ma");
        report
    }

    fn hash(report: &AuditReport, body: &str) -> AllowlistHash {
        allowlist_surface_hash(&report.surfaces[0].origin, body)
    }

    #[test]
    fn allowlist_matches_body_context_and_exact_rule() {
        let text = scene(BODY, false);
        let plan = audit_plan();
        let baseline = run(&text, &plan, AuditOptions::strict_default());
        let h = hash(&baseline, BODY);
        let permitted = run(
            &text,
            &plan.clone().with_allowlist(allow(h, &["mel_exec"])),
            AuditOptions::strict_default(),
        );
        assert_eq!(permitted.findings.len(), 1);
        assert_eq!(
            permitted.findings[0].allowed_by.as_ref().unwrap().source,
            AllowlistSource::App
        );
        assert_eq!(permitted.findings[0].allowed_by.as_ref().unwrap().hash, h);
        for changed in [text.replace(".b", ".a"), text.replace(".st\" 1", ".st\" 0")] {
            let report = run(
                &changed,
                &plan.clone().with_allowlist(allow(h, &["mel_exec"])),
                AuditOptions::strict_default(),
            );
            assert!(!report.findings.is_empty());
            assert!(report.findings.iter().all(|f| f.allowed_by.is_none()));
        }
        let wrong_code = run(
            &text,
            &plan.with_allowlist(allow(h, &["mel_eval"])),
            AuditOptions::strict_default(),
        );
        assert!(wrong_code.findings.iter().all(|f| f.allowed_by.is_none()));
        let plan = build_script_audit_plan(vec!["exec".into(), "Example".into()], 64)
            .unwrap()
            .with_allowlist(allow(h, &["custom_rule_match:exec"]));
        let report = run(&text, &plan, AuditOptions::strict_default());
        let rules: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.code == AuditFindingCode::CustomRuleMatch)
            .collect();
        assert_eq!(rules.len(), 2);
        for finding in rules {
            assert_eq!(
                finding.allowed_by.is_some(),
                finding.rule.as_deref() == Some("exec")
            );
        }
        let bare = build_script_audit_plan(vec!["exec".into(), "Example".into()], 64)
            .unwrap()
            .with_allowlist(allow(h, &["custom_rule_match"]));
        let report = run(&text, &bare, AuditOptions::strict_default());
        assert!(
            report
                .findings
                .iter()
                .filter(|f| f.code == AuditFindingCode::CustomRuleMatch)
                .all(|f| f.allowed_by.is_none())
        );
    }

    #[test]
    fn allowlist_never_allows_uncertainty_or_poisoned_surfaces() {
        let cases = [
            (
                scene(BODY, false).replace(".st\" 1", ".st\" 99"),
                BODY,
                "unknown_execution_trigger",
            ),
            (
                scene("getattr(example_object, example_name)()", true),
                "getattr(example_object, example_name)()",
                "python_unresolved_call_target",
            ),
            (
                scene(
                    "$callback = `optionVar -q exampleCallbackName`; modelEditor -e -editorChanged $callback examplePanel;",
                    false,
                ),
                "$callback = `optionVar -q exampleCallbackName`; modelEditor -e -editorChanged $callback examplePanel;",
                "mel_callback_flag",
            ),
            (
                scene("if example syntax:\n    value = data.decode(", true),
                "if example syntax:\n    value = data.decode(",
                "python_body_assembly",
            ),
            (
                scene(
                    "python(\"if example syntax:\\n    value = data.decode(\");",
                    false,
                ),
                "python(\"if example syntax:\\n    value = data.decode(\");",
                "mel_python",
            ),
        ];
        for (text, body, code) in cases {
            for options in [
                AuditOptions::strict_default(),
                AuditOptions::hardened_untrusted(),
            ] {
                let baseline = run(&text, &audit_plan(), options);
                assert!(
                    baseline.findings.iter().any(|f| f.code.as_str() == code),
                    "{code}: {:?}",
                    baseline.findings
                );
                let plan = audit_plan().with_allowlist(allow(hash(&baseline, body), &[code]));
                let report = run(&text, &plan, options);
                assert!(
                    report.findings.iter().all(|f| f.allowed_by.is_none()),
                    "{code}"
                );
                assert_eq!(
                    serde_json::to_vec(&report).unwrap(),
                    serde_json::to_vec(&baseline).unwrap()
                );
                if code == "python_body_assembly" {
                    assert!(
                        report
                            .findings
                            .iter()
                            .any(|f| f.code == AuditFindingCode::PythonParseFailure)
                    );
                    let indices: Vec<_> = report
                        .findings
                        .iter()
                        .filter(|f| {
                            matches!(
                                f.code,
                                AuditFindingCode::PythonParseFailure
                                    | AuditFindingCode::PythonBodyAssembly
                            )
                        })
                        .map(|f| f.surface_index)
                        .collect();
                    assert_eq!(indices.len(), 2);
                    assert_eq!(indices[0], indices[1]);
                }
            }
        }
    }

    #[test]
    fn allowlist_derived_findings_use_the_observed_root_hash() {
        let body = "python(\"exec('print(1)')\")";
        let text = scene(body, false);
        let baseline = run(&text, &audit_plan(), AuditOptions::strict_default());
        let index = baseline
            .findings
            .iter()
            .find(|f| f.code == AuditFindingCode::PythonExec)
            .unwrap()
            .surface_index;
        assert_eq!(
            baseline.surfaces[index].derivation,
            AuditSurfaceDerivation::MelPythonLiteralBridge
        );
        let root_hash = hash(&baseline, body);
        let derived_hash =
            allowlist_surface_hash(&baseline.surfaces[index].origin, "exec('print(1)')");
        for (hash, expected) in [(root_hash, true), (derived_hash, false)] {
            let report = run(
                &text,
                &audit_plan().with_allowlist(allow(hash, &["python_pyexec"])),
                AuditOptions::strict_default(),
            );
            assert_eq!(
                report
                    .findings
                    .iter()
                    .find(|f| f.code == AuditFindingCode::PythonExec)
                    .unwrap()
                    .allowed_by
                    .is_some(),
                expected
            );
            assert!(
                report
                    .findings
                    .iter()
                    .find(|f| f.code == AuditFindingCode::MelPython)
                    .unwrap()
                    .allowed_by
                    .is_none()
            );
            assert_eq!(report.surface_count, 1);
        }
        let callback = "button -command \"python(\\\"exec('print(1)')\\\")\";";
        let text = scene(callback, false);
        let baseline = run(&text, &audit_plan(), AuditOptions::strict_default());
        let report = run(
            &text,
            &audit_plan().with_allowlist(allow(hash(&baseline, callback), &["python_pyexec"])),
            AuditOptions::strict_default(),
        );
        assert!(
            report
                .findings
                .iter()
                .find(|f| f.code == AuditFindingCode::PythonExec)
                .unwrap()
                .allowed_by
                .is_some()
        );
        assert!(
            report
                .surfaces
                .iter()
                .any(|s| s.derivation == AuditSurfaceDerivation::MelCallbackLiteral)
        );
        assert!(!report.review_signals.is_empty());
        assert_eq!(
            serde_json::to_value(&report.review_signals).unwrap(),
            serde_json::to_value(&baseline.review_signals).unwrap()
        );
        assert_eq!(report.surface_count, 1);

        let body = "import maya.mel as mel\nmel.eval('eval(\"print(1)\")')";
        let text = scene(body, true);
        let baseline = run(&text, &audit_plan(), AuditOptions::strict_default());
        let finding = baseline
            .findings
            .iter()
            .find(|f| f.code == AuditFindingCode::MelEval)
            .unwrap();
        assert_eq!(
            baseline.surfaces[finding.surface_index].derivation,
            AuditSurfaceDerivation::Observed
        );
        assert_eq!(baseline.surface_count, 2);
        let independent = allowlist_surface_hash(
            &baseline.surfaces[finding.surface_index].origin,
            "eval(\"print(1)\")",
        );
        for (h, expected) in [(hash(&baseline, body), false), (independent, true)] {
            let report = run(
                &text,
                &audit_plan().with_allowlist(allow(h, &["mel_eval"])),
                AuditOptions::strict_default(),
            );
            assert_eq!(
                report
                    .findings
                    .iter()
                    .find(|f| f.code == AuditFindingCode::MelEval)
                    .unwrap()
                    .allowed_by
                    .is_some(),
                expected
            );
        }
    }

    #[test]
    fn allowlist_dispositions_preserve_unit_contributions() {
        let text = scene(BODY, false);
        for options in [
            AuditOptions::strict_default(),
            AuditOptions::hardened_untrusted(),
        ] {
            let expected =
                if options.profile == maya_scene_kit_audit::scene::AuditProfile::StrictDefault {
                    AuditDisposition::Review
                } else {
                    AuditDisposition::DenyUncertain
                };
            for rules in [
                vec![],
                vec!["exec".into()],
                vec!["exec".into(), "Example".into()],
            ] {
                let plan = build_script_audit_plan(rules, 64).unwrap();
                let baseline = run(&text, &plan, options);
                assert_eq!(baseline.disposition, AuditDisposition::DenyMalicious);
                let h = hash(&baseline, BODY);
                let all = [
                    "mel_exec",
                    "custom_rule_match:exec",
                    "custom_rule_match:Example",
                ];
                let permitted = run(&text, &plan.clone().with_allowlist(allow(h, &all)), options);
                assert!(permitted.findings.iter().all(|f| f.allowed_by.is_some()));
                assert_eq!(permitted.disposition, expected);
                assert_eq!(permitted.unit_summaries.len(), 1);
                assert_eq!(
                    permitted.unit_summaries[0].effect,
                    ExecutionEffectClass::ExternalDependency
                );
                assert!(permitted.review_signals.is_empty());
                assert!(!permitted.blocked_on_uncertainty);
                assert!(
                    permitted
                        .dependency_facts
                        .iter()
                        .all(|f| f.risk == DependencyRiskClass::Informational)
                );
                assert_eq!(
                    serde_json::to_value(&permitted.unit_summaries).unwrap(),
                    serde_json::to_value(&baseline.unit_summaries).unwrap()
                );
                if !plan.effective_rules().is_empty() {
                    for codes in [&["mel_exec"][..], &["custom_rule_match:exec"][..]] {
                        let partial = run(
                            &text,
                            &plan.clone().with_allowlist(allow(h, codes)),
                            options,
                        );
                        assert!(partial.findings.iter().any(|f| f.allowed_by.is_some()));
                        assert!(partial.findings.iter().any(|f| f.allowed_by.is_none()));
                        assert_eq!(partial.disposition, AuditDisposition::DenyMalicious);
                    }
                }
            }
        }
    }
}

#[test]
fn reference_graph_scene_limit_admits_root_and_child_once() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_scene(&dir.path().join("workspace.mel"), "// Example\n");
    let root = dir.path().join("TestScene.ma");
    write_reference_scene(&root, "Example.ma", "Example");
    write_basic_scene(&dir.path().join("Example.ma"));

    let graph = audit_reference_graph_roots_with_traversal_options_and_digests(
        [&root],
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
        ReferenceGraphOptions {
            max_scenes: 2,
            ..ReferenceGraphOptions::default()
        },
        false,
    );

    assert_eq!(graph.reports.len(), 2);
    assert_eq!(
        graph
            .traversal_issues
            .iter()
            .filter(|issue| { issue.kind == AuditTraversalIssueKind::SceneLimit })
            .count(),
        0
    );
}

#[test]
fn reference_graph_scene_limit_rejects_second_child() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_scene(&dir.path().join("workspace.mel"), "// Example\n");
    let root = dir.path().join("TestScene.ma");
    write_reference_scene(&root, "Example.ma", "Example");
    write_basic_scene(&dir.path().join("Example.ma"));
    let second = dir.path().join("Example2.ma");
    write_basic_scene(&second);
    let mut source = std::fs::read_to_string(&root).expect("read scene");
    source.push_str("file -r -rfn \"Example2\" \"Example2.ma\";\n");
    write_scene(&root, &source);

    let graph = audit_reference_graph_roots_with_traversal_options_and_digests(
        [&root],
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
        ReferenceGraphOptions {
            max_scenes: 2,
            ..ReferenceGraphOptions::default()
        },
        false,
    );

    assert_eq!(graph.reports.len(), 2);
    assert_eq!(
        graph
            .traversal_issues
            .iter()
            .filter(|issue| { issue.kind == AuditTraversalIssueKind::SceneLimit })
            .count(),
        1
    );
}

fn audit_example_mel_body(body: &str, expression: bool) -> AuditReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    let (node_type, attr, settings) = if expression {
        ("expression", ".ixp", "")
    } else {
        ("script", ".b", "setAttr \".st\" 1;\n")
    };
    write_scene(
        &path,
        &format!(
            "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode {node_type} -n \"Example\";\n{settings}setAttr \"{attr}\" -type \"string\" \"{}\";\n",
            escape_ma_string(body)
        ),
    );
    audit_script_nodes(&path, &audit_plan()).unwrap()
}

#[test]
fn audit_multiple_python_bodies_retain_later_dangerous_body() {
    for expression in [true, false] {
        let report = audit_example_mel_body(
            "python(\"print('Example')\"); python(\"import subprocess; subprocess.call(['echo', 'Example'])\");",
            expression,
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code.as_str() == "python_subprocess")
        );
        assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
        assert_eq!(
            report
                .surfaces
                .iter()
                .filter(
                    |surface| surface.derivation == AuditSurfaceDerivation::MelPythonLiteralBridge
                )
                .count(),
            2
        );
        if expression {
            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| finding.code.as_str() != "mel_python")
            );
        }
    }
}

#[test]
fn audit_nested_literal_eval_depth_is_bounded_and_reported() {
    for mixed in [false, true] {
        for callback in [false, true] {
            for depth in [7, 8, 9] {
                let mut body = "exec(\"Example\");".to_string();
                for level in 0..depth {
                    let sink = if mixed && level % 2 == 0 {
                        "evalDeferred"
                    } else {
                        "eval"
                    };
                    body = format!(
                        "python(\"print(1)\"); {sink}({}); evalDeferred(\"print(1)\");",
                        serde_json::to_string(&body).unwrap()
                    );
                    if callback && level == 3 {
                        body =
                            format!("button -command {};", serde_json::to_string(&body).unwrap());
                    }
                }
                let report = audit_example_mel_body(&body, false);
                assert_eq!(
                    report
                        .findings
                        .iter()
                        .any(|finding| finding.code.as_str() == "mel_exec"),
                    depth <= 8,
                    "depth={depth}, mixed={mixed}, callback={callback}"
                );
                let depth_issues = report.coverage_issues.iter().filter(|issue| matches!(&issue.detail, ExecutionCoverageIssueDetail::SurfaceDiagnostics { diagnostic } if diagnostic.contains("literal evaluation depth"))).collect::<Vec<_>>();
                assert_eq!(depth_issues.len(), 2 * usize::from(depth > 8));
                if depth > 8 {
                    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
                    assert!(report.blocked_on_uncertainty);
                    assert!(depth_issues[0].origin.is_some());
                } else {
                    assert_eq!(report.coverage_state, ExecutionCoverageState::Complete);
                    assert!(report.coverage_issues.is_empty());
                }
            }
        }
    }
}

#[test]
fn audit_depth_limit_issues_are_capped_across_surfaces() {
    let mut body = "eval(\"print(1)\");\n".repeat(60);
    for _ in 0..8 {
        body = format!("eval({});", serde_json::to_string(&body).unwrap());
    }
    let repeated = format!("{body}\n{body}");
    let report = audit_example_mel_body(&repeated, false);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.coverage_issues.len(), 101);
    assert_eq!(report.coverage_issues.iter().filter(|issue| matches!(&issue.detail, ExecutionCoverageIssueDetail::SurfaceDiagnostics { diagnostic } if diagnostic.contains("further depth-limit issues were suppressed"))).count(), 1);
}

#[test]
fn python_mel_imported_callable_denies_system_payload() {
    assert_python_mel_callable_denies_system_payload(
        "from maya.mel import eval as run\nrun('system(\"Example\");')",
    );
}

#[test]
fn python_mel_assignment_callable_denies_system_payload() {
    assert_python_mel_callable_denies_system_payload(
        "import maya.mel as mm\nrun = mm.eval\nrun('system(\"Example\");')",
    );
}

#[test]
fn python_mel_bare_imported_callable_denies_system_payload() {
    assert_python_mel_callable_denies_system_payload(
        "from maya.mel import eval\neval('system(\"Example\");')",
    );
}

fn assert_python_mel_callable_denies_system_payload(body: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    write_python_script_node_scene(&path, "ExampleScript", body);
    let report = audit_script_nodes(&path, &audit_plan()).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == "mel_system"),
        "{body}"
    );
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    let body =
        "from maya.mel import eval as run\ndef Example(run):\n    run('system(\"Example\");')";
    write_python_script_node_scene(&path, "ExampleScript", body);
    let report = audit_script_nodes(&path, &audit_plan()).unwrap();
    assert!(
        report
            .surfaces
            .iter()
            .all(|surface| surface.origin.lang != ExecutionLanguage::Mel)
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == "mel_system")
    );
}

#[test]
fn python_mel_may_alias_scopes_preserve_findings_and_shadowing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    let cases = [
        (
            "try_body",
            "try:\n    from maya.mel import eval as run\n    run('system(\"Example\");')\nexcept Exception:\n    pass",
            true,
        ),
        (
            "conditional_body",
            "if Example:\n    from maya.mel import eval as run\n    run('system(\"Example\");')",
            true,
        ),
        (
            "comprehension",
            "from maya.mel import eval as run\n[run('system(\"Example\");') for item in Example]",
            true,
        ),
        (
            "generator",
            "from maya.mel import eval as run\n(run('system(\"Example\");') for item in Example)",
            true,
        ),
        (
            "rebound_name",
            "import maya.mel as mm\nrun = mm.eval\nrun('system(\"Example\");')\nrun = print",
            true,
        ),
        (
            "class_local_method",
            "class Example:\n    from maya.mel import eval as run\n    def method(self):\n        run('system(\"Example\");')",
            false,
        ),
        (
            "class_attribute_shadow",
            "from maya.mel import eval as run\nclass Example:\n    run = print\n    def method(self):\n        run('system(\"Example\");')",
            true,
        ),
        (
            "later_outer_binding",
            "def Example():\n    run('system(\"Example\");')\nfrom maya.mel import eval as run",
            true,
        ),
        (
            "shared_import_root",
            "import maya.cmds\nimport maya.mel\nrun = maya.mel.eval\nrun('system(\"Example\");')",
            true,
        ),
        (
            "mel_module",
            "import mel\nrun = mel.eval\nrun('system(\"Example\");')",
            true,
        ),
        (
            "nested_mel_module",
            "import Example.maya.mel as mm\nrun = mm.eval\nrun('system(\"Example\");')",
            true,
        ),
    ];
    let actual: Vec<_> = cases
        .iter()
        .map(|(name, body, _)| {
            write_python_script_node_scene(&path, "ExampleScript", body);
            let report = audit_script_nodes(&path, &audit_plan()).unwrap();
            let mel_surface = report
                .surfaces
                .iter()
                .any(|surface| surface.origin.lang == ExecutionLanguage::Mel);
            let mel_system = report
                .findings
                .iter()
                .any(|finding| finding.code.as_str() == "mel_system");
            (
                *name,
                mel_surface,
                mel_system,
                mel_system && report.disposition == AuditDisposition::DenyMalicious,
            )
        })
        .collect();
    let expected: Vec<_> = cases
        .iter()
        .map(|(name, _, present)| (*name, *present, *present, *present))
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn python_mel_module_assignment_detects_payload_and_preserves_class_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    write_python_script_node_scene(
        &path,
        "ExampleScript",
        "class Example:\n    from maya.mel import eval as run\nExample.run('system(\"Example\");')",
    );
    let report = audit_script_nodes(&path, &audit_plan()).unwrap();
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(
        report
            .surfaces
            .iter()
            .all(|surface| surface.origin.lang != ExecutionLanguage::Mel)
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == "mel_system")
    );
    let body = "import maya.mel as mm\nalias = mm\nalias.eval('system(\"Example\");')";
    assert_python_mel_callable_denies_system_payload(body);
    write_python_script_node_scene(&path, "ExampleScript", body);
    let report = audit_script_nodes(&path, &audit_plan()).unwrap();
    assert!(
        report
            .surfaces
            .iter()
            .any(|surface| surface.origin.lang == ExecutionLanguage::Mel)
    );
}

#[test]
fn python_mel_callable_catalog_preserves_alias_uncertainty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    write_python_script_node_scene(
        &path,
        "ExampleScript",
        "import maya.mel as mm\nmm.eval('print(1)')",
    );
    let direct = audit_script_nodes(&path, &audit_plan()).unwrap();
    write_python_script_node_scene(
        &path,
        "ExampleScript",
        "from maya.mel import eval as run\nrun('print(1)')",
    );
    let alias = audit_script_nodes(&path, &audit_plan()).unwrap();
    assert!(
        !serde_json::to_string(&alias)
            .unwrap()
            .contains("unclassified_python_call")
    );
    let alias_python = alias
        .unit_summaries
        .iter()
        .find(|summary| summary.origin.lang == ExecutionLanguage::Python)
        .unwrap();
    let direct_python = direct
        .unit_summaries
        .iter()
        .find(|summary| summary.origin.lang == ExecutionLanguage::Python)
        .unwrap();
    assert_eq!(
        alias_python.certainty,
        maya_scene_kit_observe::scene::evidence::EffectCertainty::Uncertain
    );
    assert_eq!(
        direct_python.certainty,
        maya_scene_kit_observe::scene::evidence::EffectCertainty::Proven
    );
    assert_eq!(alias.disposition, direct.disposition);
    assert_eq!(
        serde_json::to_value(&alias.findings).unwrap(),
        serde_json::to_value(&direct.findings).unwrap()
    );
}

#[test]
fn python_mel_conditional_benign_payload_preserves_direct_classification() {
    let report = audit_conditional_python_mel_payload("print(1)");
    assert_eq!(report.disposition, AuditDisposition::Review);
}

#[test]
fn python_mel_conditional_system_payload_preserves_direct_classification() {
    let report = audit_conditional_python_mel_payload("system(\"Example\");");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == "mel_system")
    );
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
}

fn audit_conditional_python_mel_payload(payload: &str) -> AuditReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    let body = format!(
        "if Example:\n    import maya.mel as mm\nmm.eval({})",
        serde_json::to_string(payload).unwrap()
    );
    write_python_script_node_scene(&path, "ExampleScript", &body);
    let report = audit_script_nodes_with_options(
        &path,
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
    )
    .unwrap();
    assert!(
        report
            .surfaces
            .iter()
            .any(|surface| surface.origin.lang == ExecutionLanguage::Mel)
    );
    assert!(report.blocked_on_uncertainty);
    let python = report
        .unit_summaries
        .iter()
        .find(|summary| summary.origin.lang == ExecutionLanguage::Python)
        .unwrap();
    assert_eq!(
        python.certainty,
        maya_scene_kit_observe::scene::evidence::EffectCertainty::Proven
    );
    report
}

#[test]
fn python_mel_scope_mutations_keep_callable_uncertainty() {
    assert_uncertain_python_mel_cases(&[
        (
            "global",
            "from maya.mel import eval as run\ndef Example():\n    global run\n    run = print\nrun(PAYLOAD)",
        ),
        (
            "nonlocal",
            "def Example():\n    from maya.mel import eval as run\n    def Sample():\n        nonlocal run\n        run = print\n    run(PAYLOAD)",
        ),
    ]);
    for source in [
        "from maya.mel import eval as run\nmatch Example:\n    case run: run('x')",
        "import maya.mel as mm\nif Example:\n    run = mm.eval\nrun('print(1)')",
    ] {
        let report = audit_python_mel_case(source);
        let python = report
            .unit_summaries
            .iter()
            .find(|summary| summary.origin.lang == ExecutionLanguage::Python)
            .unwrap();
        assert_eq!(
            python.certainty,
            maya_scene_kit_observe::scene::evidence::EffectCertainty::Uncertain,
            "{source}"
        );
    }
}

#[test]
fn python_mel_star_import_keeps_callable_uncertainty() {
    assert_uncertain_python_mel_cases(&[(
        "star_import",
        "from maya.mel import eval as run\nfrom Example import *\nrun(PAYLOAD)",
    )]);
}

#[test]
fn python_mel_starred_targets_keep_callable_uncertainty() {
    assert_uncertain_python_mel_cases(&[
        (
            "tuple",
            "import maya.mel as mm\nrun = mm.eval\n*sample, run, last = Example, mm.eval, Example\nrun(PAYLOAD)",
        ),
        (
            "list",
            "import maya.mel as mm\nrun = mm.eval\n[*sample, run, last] = [Example, mm.eval, Example]\nrun(PAYLOAD)",
        ),
    ]);
    for source in [
        "import maya.mel as mm\n*sample, run, last = Example, mm.eval, Example\nrun('print(1)')",
        "import maya.mel as mm\n[*sample, run, last] = [Example, mm.eval, Example]\nrun('print(1)')",
    ] {
        let report = audit_python_mel_case(source);
        assert!(
            report
                .surfaces
                .iter()
                .all(|surface| surface.origin.lang != ExecutionLanguage::Mel),
            "{source}"
        );
    }
}

fn assert_uncertain_python_mel_cases(cases: &[(&str, &str)]) {
    let mut failures = Vec::new();
    for (name, source) in cases {
        for (payload, disposition, system) in [
            ("print(1)", AuditDisposition::Review, false),
            (
                "system(\"Example\");",
                AuditDisposition::DenyMalicious,
                true,
            ),
        ] {
            let body = source.replace("PAYLOAD", &serde_json::to_string(payload).unwrap());
            let report = audit_python_mel_case(&body);
            let python = report
                .unit_summaries
                .iter()
                .find(|summary| summary.origin.lang == ExecutionLanguage::Python)
                .unwrap();
            let has_payload = report
                .surfaces
                .iter()
                .any(|surface| surface.origin.lang == ExecutionLanguage::Mel);
            let has_system = report
                .findings
                .iter()
                .any(|finding| finding.code.as_str() == "mel_system");
            if python.certainty
                != maya_scene_kit_observe::scene::evidence::EffectCertainty::Uncertain
                || report.disposition != disposition
                || !has_payload
                || has_system != system
            {
                failures.push(format!("{name}, {payload}: certainty={:?}, disposition={:?}, payload={has_payload}, mel_system={has_system}", python.certainty, report.disposition));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn audit_python_mel_case(body: &str) -> AuditReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    write_python_script_node_scene(&path, "ExampleScript", body);
    audit_script_nodes_with_options(
        &path,
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
    )
    .unwrap()
}

#[test]
fn python_mel_mutated_attribute_alias_stays_uncertain() {
    assert_uncertain_python_mel_cases(&[(
        "attribute_store",
        "import maya.mel as mm\nalias = mm\nmm.eval = print\nalias.eval(PAYLOAD)",
    )]);
}

#[test]
fn python_mel_mutated_comprehension_alias_stays_uncertain() {
    assert_uncertain_python_mel_cases(&[(
        "comprehension_walrus",
        "import maya.mel as mm\nalias = mm\n[(alias := Example) for sample in []]\nalias.eval(PAYLOAD)",
    )]);
}

#[test]
fn python_mel_conditional_eval_retains_dynamic_call_evidence() {
    assert_python_mel_eval_retains_dynamic_call_evidence(
        "if Example:\n    from maya.mel import eval\neval(Example_python_text)",
    );
}

#[test]
fn python_mel_try_import_eval_retains_dynamic_call_evidence() {
    assert_python_mel_eval_retains_dynamic_call_evidence(
        "try:\n    from maya.mel import eval\nexcept ImportError:\n    pass\neval(text)",
    );
}

fn assert_python_mel_eval_retains_dynamic_call_evidence(source: &str) {
    use maya_scene_kit_observe::scene::evidence::{
        EffectCertainty, ExecutionReason, ExecutionReasonTemplate, StaticExecutionReason,
    };
    let report = audit_python_mel_case(source);
    let python = report
        .unit_summaries
        .iter()
        .find(|summary| summary.origin.lang == ExecutionLanguage::Python)
        .unwrap();
    assert_eq!(python.certainty, EffectCertainty::Uncertain);
    assert!(
        python.reasons.iter().any(|reason| matches!(
            reason,
            ExecutionReason::Static {
                value: StaticExecutionReason::UnresolvedPythonCallTargetDetected
            }
        )),
        "{source}"
    );
    assert!(python.reasons.iter().any(|reason| matches!(reason,
        ExecutionReason::Named { template: ExecutionReasonTemplate::DynamicPythonCallDetected, value } if value == "eval"
    )), "{source}: {:?}", python.reasons);
}
