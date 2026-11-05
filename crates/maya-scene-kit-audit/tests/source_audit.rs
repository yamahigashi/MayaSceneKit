use maya_scene_kit_audit::{
    audit::{audit_script_nodes_with_options, build_script_audit_plan},
    scene::{
        AuditDisposition, AuditFindingCode, AuditOptions, AuditReport, AuditSeverity,
        AuditSinkKind, ExecutionLanguage, audit_source_text,
    },
};
use maya_scene_kit_observe::scene::{
    LoadOptions, MelParseBudget, SceneToolError,
    core::{SceneFormat, ValidationState},
    evidence::{
        DependencyFactKind, ExecutionCoverageState, ExecutionSurfaceKind, ExecutionTrigger,
    },
};

fn audit(source: &str, language: ExecutionLanguage) -> AuditReport {
    let report = audit_source_text(source, language).expect("audit source");
    for finding in &report.findings {
        assert!(finding.surface_index < report.surfaces.len());
    }
    for review in &report.review_signals {
        assert!(review.surface_index < report.surfaces.len());
    }
    report
}

#[test]
fn unknown_language_is_a_configuration_error() {
    assert!(matches!(
        audit_source_text("print('Example')", ExecutionLanguage::Unknown),
        Err(SceneToolError::Config(_))
    ));
}

#[test]
fn empty_and_comment_only_inputs_keep_source_provenance() {
    for (language, source) in [
        (ExecutionLanguage::Python, ""),
        (ExecutionLanguage::Python, "# Example\n"),
        (ExecutionLanguage::Mel, ""),
        (ExecutionLanguage::Mel, "// Example\n"),
    ] {
        let report = audit(source, language);
        assert_eq!(report.disposition, AuditDisposition::AllowWithNotice);
        assert_eq!(report.validation_state, ValidationState::Validated);
        assert_eq!(report.coverage_state, ExecutionCoverageState::Complete);
        assert!(!report.blocked_on_uncertainty);
        assert!(report.findings.is_empty());
        assert!(report.review_signals.is_empty());
        assert!(report.coverage_issues.is_empty());
        assert!(report.scene_path.as_os_str().is_empty());
        assert_eq!(report.scene_format, SceneFormat::Unknown);
        assert!(report.digests.scene_sha256.is_empty());
        assert!(report.digests.schema_bundle_sha256.is_none());
        assert!(report.digests.policy_bundle_sha256.is_none());
        assert_eq!(report.surface_count, 1);
        assert_eq!(report.surfaces.len(), 1);
        assert_eq!(report.unit_summaries.len(), 1);
        let origin = &report.surfaces[0].origin;
        assert_eq!(origin.lang, language);
        assert_eq!(origin.trigger, ExecutionTrigger::Manual);
        assert_eq!(origin.surface_kind, ExecutionSurfaceKind::RawChunkText);
        assert_eq!(
            origin.source_kind.as_deref(),
            Some("standalone_source_text")
        );
        assert!(origin.node_name.is_none());
        assert!(origin.attr_name.is_none());
        assert!(origin.source_range.is_none());
        assert!(origin.chunk_payload_offset.is_none());
    }
}

#[test]
fn diagnostic_source_supports_unicode_and_python_compatibility() {
    for (language, source) in [
        (ExecutionLanguage::Python, "print('Example é')"),
        (ExecutionLanguage::Python, "print u'Example é'\n"),
        (ExecutionLanguage::Mel, "print(\"Example é\");"),
    ] {
        let report = audit(source, language);
        assert_eq!(report.disposition, AuditDisposition::AllowWithNotice);
        assert!(!report.blocked_on_uncertainty);
        assert!(report.findings.is_empty());
        assert!(report.surfaces[0].preview.contains("Example"));
    }
}

#[test]
fn existing_python_capabilities_use_existing_findings_and_severity() {
    for (source, sink, severity) in [
        (
            "exec('print(1)')",
            AuditSinkKind::PyExec,
            AuditSeverity::Critical,
        ),
        (
            "eval('1 + 1')",
            AuditSinkKind::PyEval,
            AuditSeverity::Critical,
        ),
        (
            "compile('1', 'Example', 'eval')",
            AuditSinkKind::PyCompile,
            AuditSeverity::Critical,
        ),
        (
            "open('asset/example/file.txt', 'w')",
            AuditSinkKind::PyFileOpen,
            AuditSeverity::Critical,
        ),
        (
            "example_handle.write('Sample')",
            AuditSinkKind::PyFileWrite,
            AuditSeverity::Critical,
        ),
        (
            "import subprocess",
            AuditSinkKind::PySubprocess,
            AuditSeverity::High,
        ),
        (
            "import socket",
            AuditSinkKind::PySocket,
            AuditSeverity::High,
        ),
        (
            "import ctypes",
            AuditSinkKind::PyCtypes,
            AuditSeverity::High,
        ),
    ] {
        let report = audit(source, ExecutionLanguage::Python);
        assert_eq!(
            report.disposition,
            AuditDisposition::DenyMalicious,
            "{source}"
        );
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.sink == sink)
            .expect("existing capability finding");
        assert_eq!(finding.severity, severity, "{source}");
    }
}

#[test]
fn literal_python_to_mel_bridge_reuses_mel_analysis() {
    let report = audit(
        "import maya.mel as mm\nmm.eval('exec \"Example\";')",
        ExecutionLanguage::Python,
    );
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert_eq!(report.surface_count, 2);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.sink == AuditSinkKind::MelExec)
        .expect("MEL exec finding");
    assert_eq!(finding.severity, AuditSeverity::High);
    assert_eq!(
        report.surface_for(finding).origin.lang,
        ExecutionLanguage::Mel
    );
    assert_eq!(
        report.surface_for(finding).origin.source_kind.as_deref(),
        Some("python->maya.mel.eval literal bridge")
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::PyEval)
    );
}

#[test]
fn literal_operational_bridge_is_not_python_eval() {
    let report = audit(
        "import maya.mel as mm\nmm.eval('setProject \"asset/example\";')",
        ExecutionLanguage::Python,
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::PyEval)
    );
    assert_eq!(report.surface_count, 2);
    assert!(!report.blocked_on_uncertainty);
}

#[test]
fn dynamic_python_to_mel_bridge_keeps_uncertainty() {
    let report = audit(
        "import maya.mel as mm\nmm.eval(example_body)",
        ExecutionLanguage::Python,
    );
    assert!(report.blocked_on_uncertainty);
    assert!(!report.unknown_semantics.is_empty());
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::PyEval)
    );
}

#[test]
fn mel_to_python_bridge_keeps_existing_findings() {
    let report = audit("python(\"exec('print(1)')\");", ExecutionLanguage::Mel);
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
            .any(|finding| finding.sink == AuditSinkKind::PyExec)
    );
}

#[test]
fn nested_language_bridge_remains_denied() {
    let report = audit(
        "python(\"import maya.mel as mm; mm.eval('print(1);')\");",
        ExecutionLanguage::Mel,
    );
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelPython)
    );
}

#[test]
fn parse_failures_never_return_an_allowed_report() {
    for (language, source) in [
        (ExecutionLanguage::Python, "if :"),
        (ExecutionLanguage::Mel, "print(\"Example\";"),
        (
            ExecutionLanguage::Python,
            "import maya.mel as mm\nmm.eval('print(\"Example\";')",
        ),
    ] {
        let report = audit(source, language);
        assert!(report.blocked_on_uncertainty, "{source}");
        assert_eq!(
            report.validation_state,
            ValidationState::Invalid,
            "{source}"
        );
        assert_eq!(
            report.coverage_state,
            ExecutionCoverageState::Incomplete,
            "{source}"
        );
        assert!(!report.coverage_issues.is_empty());
        assert!(!matches!(
            report.disposition,
            AuditDisposition::Allow | AuditDisposition::AllowWithNotice
        ));
    }
}

#[test]
fn source_dependencies_are_reported_without_loading_files() {
    let report = audit("source \"asset/example/file.mel\";", ExecutionLanguage::Mel);
    let dependency = report
        .dependency_facts
        .iter()
        .find(|fact| fact.kind == DependencyFactKind::SourceCommand)
        .expect("source dependency");
    assert_eq!(dependency.target, "asset/example/file.mel");
    assert_eq!(
        dependency.origin.as_ref().expect("origin").surface_kind,
        ExecutionSurfaceKind::RawChunkText
    );
    assert_eq!(report.disposition, AuditDisposition::Review);
}

#[test]
fn source_parse_budget_exhaustion_returns_a_blocked_report() {
    let depth = MelParseBudget::default().max_nesting_depth + 1;
    let source = format!("print({}1{});", "(".repeat(depth), ")".repeat(depth));
    let report = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || audit(&source, ExecutionLanguage::Mel))
        .expect("parser thread")
        .join()
        .expect("bounded parser");
    assert!(report.is_parse_budget_blocked());
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert_eq!(report.validation_state, ValidationState::Invalid);
    assert_eq!(report.disposition, AuditDisposition::Review);
}

#[test]
fn unresolved_python_target_keeps_existing_denial() {
    let report = audit(
        "getattr(example_object, example_name)()",
        ExecutionLanguage::Python,
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == AuditFindingCode::PythonUnresolvedCallTarget)
    );
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
}

#[test]
fn manual_scene_and_source_findings_match_without_provenance() {
    let dir = tempfile::tempdir().expect("temporary scene directory");
    let scene_path = dir.path().join("TestScene.ma");
    let plan = build_script_audit_plan(Vec::new(), 96).expect("audit plan");
    for source in [
        "print('Example')",
        "exec('print(1)')",
        "import maya.mel as mm\nmm.eval('exec \"Example\";')",
        "getattr(example_object, example_name)()",
    ] {
        let escaped = source
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        std::fs::write(&scene_path, format!(
            "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"Example\";\n    setAttr \".st\" 0;\n    setAttr \".stp\" 1;\n    setAttr \".b\" -type \"string\" \"{escaped}\";\n"
        )).expect("write synthetic scene");
        let scene = audit_script_nodes_with_options(
            &scene_path,
            &plan,
            &LoadOptions::default(),
            AuditOptions::strict_default(),
        )
        .expect("audit scene");
        let standalone = audit(source, ExecutionLanguage::Python);
        let normalize = |report: &AuditReport| {
            report
                .findings
                .iter()
                .map(|finding| {
                    (
                        finding.code,
                        finding.severity,
                        finding.sink,
                        finding.detail.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(normalize(&scene), normalize(&standalone), "{source}");
        assert_eq!(scene.disposition, standalone.disposition, "{source}");
        assert_eq!(
            scene.blocked_on_uncertainty, standalone.blocked_on_uncertainty,
            "{source}"
        );
        assert_eq!(scene.scene_path, scene_path);
        assert_eq!(scene.scene_format, SceneFormat::Ma);
    }
}
