use std::path::PathBuf;

use maya_scene_kit_audit::{
    audit::{
        ScriptAuditPlan, audit_observation, audit_script_nodes, audit_script_nodes_with_options,
        build_script_audit_plan,
    },
    scene::{
        AuditDisposition, AuditFinding, AuditNoticeCode, AuditOptions, AuditReport, AuditSeverity,
        AuditSinkKind, AuditSurfaceDerivation,
    },
};
use maya_scene_kit_observe::scene::{
    DependencyFactKind, DependencyRiskClass, ExecutionCoverageIssueDetail, ExecutionCoverageState,
    ExecutionLanguage, LoadOptions, Loader, MbParseBudget, MelParseBudget, PathKind,
    SceneToolError, ValidationState, check_script_nodes, collect_scene_paths,
    collect_script_node_entries,
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

fn build_mb_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    while (out.len() - 16) % 8 != 0 {
        out.push(0);
    }
    out
}

fn build_mb_form(form: &str, children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = form.as_bytes().to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    build_mb_chunk("FOR8", &payload)
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
            .findings
            .iter()
            .all(|finding| finding_code_str(finding) != "mel_callback_flag")
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
            "print 'start scriptNode gimmickGrp'\\n",
            "dLayer = 'Weapon:gmGrp:bs_two001_Layer'\\n",
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
