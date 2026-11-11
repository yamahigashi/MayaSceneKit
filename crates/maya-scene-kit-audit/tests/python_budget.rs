use maya_scene_kit_audit::{
    audit::{audit_script_nodes_with_options, build_script_audit_plan},
    scene::{AuditDisposition, AuditOptions, AuditProfile},
};
use maya_scene_kit_observe::scene::{LoadOptions, MelParseBudget};

fn audit(
    deny: bool,
    profile: AuditProfile,
    bridge: bool,
) -> maya_scene_kit_audit::scene::AuditReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let body = format!(
        "{}1",
        "not ".repeat(MelParseBudget::DEFAULT_MAX_PYTHON_NESTING_DEPTH + 1)
    );
    let body = if bridge {
        format!("python(\\\"{body}\\\");")
    } else {
        body
    };
    let language = if bridge { 0 } else { 1 };
    let other = if deny {
        "createNode script -n \"ExampleMel\";\nsetAttr \".st\" 1;\nsetAttr \".b\" -type \"string\" \"system(\\\"Example\\\");\";\n"
    } else {
        ""
    };
    std::fs::write(&path, format!("//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"ExamplePython\";\nsetAttr \".st\" 1;\nsetAttr \".stp\" {language};\nsetAttr \".b\" -type \"string\" \"{body}\";\n{other}")).unwrap();
    let mut options = AuditOptions::strict_default();
    options.profile = profile;
    let report = audit_script_nodes_with_options(
        &path,
        &build_script_audit_plan(Vec::new(), 96).unwrap(),
        &LoadOptions::default(),
        options,
    )
    .unwrap();
    assert!(report.is_parse_budget_blocked());
    assert!(report.file_state().is_some());
    report
}

#[test]
fn oversized_python_preserves_other_surface_findings() {
    for profile in [AuditProfile::StrictDefault, AuditProfile::HardenedUntrusted] {
        let report = audit(true, profile, false);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code.as_str() == "mel_system")
        );
        assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
        assert_eq!(report.surface_count, 2);
        assert!(report.blocked_on_uncertainty);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.code.as_str().starts_with("python_"))
        );
    }
}

#[test]
fn oversized_python_alone_preserves_profile_dispositions() {
    for (profile, disposition) in [
        (AuditProfile::StrictDefault, AuditDisposition::Review),
        (
            AuditProfile::HardenedUntrusted,
            AuditDisposition::DenyUncertain,
        ),
    ] {
        let report = audit(false, profile, false);
        assert_eq!(report.disposition, disposition);
        assert!(report.blocked_on_uncertainty);
        assert!(report.findings.is_empty());
        assert_eq!(report.surface_count, 1);
        assert!(report.coverage_issues.iter().any(|issue| {
            serde_json::to_string(issue)
                .unwrap()
                .contains("parse budget exceeded: python_max_nesting_depth")
        }));
    }
}

#[test]
fn oversized_python_bridge_preserves_other_surface_findings() {
    let report = audit(true, AuditProfile::StrictDefault, true);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == "mel_system")
    );
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    assert!(report.blocked_on_uncertainty);
    assert!(report.coverage_issues.iter().any(|issue| {
        serde_json::to_string(issue)
            .unwrap()
            .contains("python_max_nesting_depth")
    }));
}

#[test]
fn oversized_python_keeps_custom_raw_text_findings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let body = format!(
        "# ExamplePayload\\n{}1",
        "not ".repeat(MelParseBudget::DEFAULT_MAX_PYTHON_NESTING_DEPTH + 1)
    );
    std::fs::write(&path, format!("//Maya ASCII 2026 scene\ncreateNode script -n \"Example\";\nsetAttr \".st\" 1;\nsetAttr \".stp\" 1;\nsetAttr \".b\" -type \"string\" \"{body}\";\n")).unwrap();
    let report = audit_script_nodes_with_options(
        &path,
        &build_script_audit_plan(vec!["ExamplePayload".into()], 96).unwrap(),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
    )
    .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == "custom_rule_match")
    );
}

#[test]
fn nested_python_budget_updates_source_validation() {
    use maya_scene_kit_audit::scene::{ExecutionLanguage, audit_source_text};
    use maya_scene_kit_observe::scene::ValidationState;
    let body = format!(
        "{}1",
        "not ".repeat(MelParseBudget::DEFAULT_MAX_PYTHON_NESTING_DEPTH + 1)
    );
    let top = audit_source_text(&body, ExecutionLanguage::Python).unwrap();
    let nested = audit_source_text(
        &format!("eval(\"python(\\\"{body}\\\");\");"),
        ExecutionLanguage::Mel,
    )
    .unwrap();
    assert_eq!(top.validation_state, ValidationState::Invalid);
    assert_eq!(nested.validation_state, top.validation_state);
}

#[test]
fn python_bridge_budget_has_one_coverage_issue() {
    let report = audit(true, AuditProfile::StrictDefault, true);
    assert_eq!(report.coverage_issues.len(), 1);
}

#[test]
fn python_budget_keeps_budget_blocked_indication() {
    let report = audit(false, AuditProfile::StrictDefault, false);
    assert!(report.is_parse_budget_blocked());
}
