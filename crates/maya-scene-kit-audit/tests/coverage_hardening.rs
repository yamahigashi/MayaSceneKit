use std::path::PathBuf;

use maya_scene_kit_audit::{
    audit::{audit_script_nodes, audit_script_nodes_with_options, build_script_audit_plan},
    scene::{AuditDisposition, AuditOptions},
};
use maya_scene_kit_observe::scene::{
    LoadOptions,
    core::ValidationState,
    evidence::{
        ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind, ExecutionCoverageState,
        ExecutionSurfaceKind,
    },
};

fn audit_plan() -> maya_scene_kit_audit::audit::ScriptAuditPlan {
    build_script_audit_plan(vec![], 64).expect("audit plan")
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

fn write_scene(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).expect("write fixture");
}

#[test]
fn audit_mb_unexplained_text_payload_without_marker_blocks_clean_allow() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source: PathBuf = dir.path().join("unexplained_text_payload.mb");
    std::fs::write(
        &source,
        build_mb_root(&[build_mb_form(
            "XPLT",
            &[build_mb_chunk("DATA", b"system \"asset/example/file.txt\"")],
        )]),
    )
    .expect("write mb fixture");

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Review);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.blocked_on_uncertainty);
    assert!(
        report
            .surfaces
            .iter()
            .all(|surface| { surface.origin.surface_kind != ExecutionSurfaceKind::RawChunkText }),
        "unexplained raw payloads should be coverage uncertainty, not execution surfaces"
    );
    assert!(
        report.coverage_issues.iter().any(|issue| {
            issue.kind == ExecutionCoverageIssueKind::UnexplainedRawMbPayload
                && matches!(
                    &issue.detail,
                    ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason }
                        if reason.contains("XPLT:DATA")
                )
        }),
        "missing unexplained raw MB coverage issue: {:?}",
        report.coverage_issues
    );
}

#[test]
fn hardened_audit_treats_partial_mb_validation_as_uncertainty() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source: PathBuf = dir.path().join("partial_validation.mb");
    std::fs::write(&source, build_mb_root(&[])).expect("write mb fixture");

    let report = audit_script_nodes_with_options(
        &source,
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::hardened_untrusted(),
    )
    .expect("audit report");

    assert_eq!(report.validation_state, ValidationState::Partial);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Complete);
    assert!(report.coverage_issues.is_empty());
    assert!(report.blocked_on_uncertainty);
    assert_eq!(report.disposition, AuditDisposition::DenyUncertain);
}

#[test]
fn audit_keeps_maya_requires_informational() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("maya_requires.ma");
    write_scene(
        &source,
        concat!("//Maya ASCII 2026 scene\n", "requires maya \"2026\";\n"),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Allow);
    assert!(
        report
            .dependency_facts
            .iter()
            .any(|fact| fact.target == "requires maya \"2026\";")
    );
}

#[test]
fn audit_non_standard_plugin_requires_needs_review() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let source = dir.path().join("plugin_requires.ma");
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "requires \"SamplePlugin\" \"1.0\";\n",
        ),
    );

    let report = audit_script_nodes(&source, &audit_plan()).expect("audit report");

    assert_eq!(report.disposition, AuditDisposition::Review);
    assert!(report.dependency_facts.iter().any(|fact| {
        fact.target == "requires \"SamplePlugin\" \"1.0\";" && fact.risk.as_str() == "review"
    }));
}

#[test]
fn audit_selective_unknown_statements_require_review() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("Example.ma");
    for statement in [
        "file -r -ns \"Example\" \x60system \"echo Example\"\x60 \"asset/example/file.ma\";",
        "system \"echo Example\";",
        "evalEcho \"print 1\";",
        "expression -s \"print 1\";",
        "scriptNode -bs \"print 1\" -st 1;",
        "sysFile -delete \"asset/example/file.ma\";",
        "    system \"echo Example\";",
        "createNode script -n \"ExampleScript\";\n    system \"echo Example\";",
        "if (1) system \"echo Example\";",
        "for ($i=0;$i<1;$i++) system \"echo Example\";",
        "while (0) system \"echo Example\";",
    ] {
        write_scene(&source, &format!("//Maya ASCII 2026 scene\n{statement}\n"));
        let report = audit_script_nodes(&source, &audit_plan()).unwrap();
        assert!(
            !matches!(
                report.disposition,
                AuditDisposition::Allow | AuditDisposition::AllowWithNotice
            ),
            "{statement}"
        );
    }
    write_scene(
        &source,
        "//Maya ASCII 2026 scene\nsystem \"echo Example\";\n",
    );
    let hardened = audit_script_nodes_with_options(
        &source,
        &audit_plan(),
        &LoadOptions::default(),
        AuditOptions::hardened_untrusted(),
    )
    .unwrap();
    assert_eq!(hardened.disposition, AuditDisposition::DenyUncertain);
    write_scene(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n",
            "fileInfo \"application\" \"Example\";\ncurrentUnit -l centimeter -a degree -t film;\n",
            "createNode transform -n \"Example\";\n    setAttr \".tx\" 1;\n",
            "connectAttr \"Example.tx\" \"Sample.tx\";\nrelationship \"link\" \"Example\" \"Sample\";\nselect -ne \"Example\";\nlockNode -l 1 \"Example\";\n",
        ),
    );
    assert_eq!(
        audit_script_nodes(&source, &audit_plan())
            .unwrap()
            .disposition,
        AuditDisposition::Allow
    );
}

#[test]
fn audit_context_layouts_preserve_python_script_surfaces() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("Example.ma");
    let plan = audit_plan();
    let payload = "exec('print(1)')";
    for separator in [
        "\n",
        " ",
        "/**/",
        "\ncurrentUnit -t film;\n",
        "\nfileInfo \"Example\" \"Sample\";\n",
        "\nselect -ne Example;\n",
        "\nselect -r Example;\n",
        "\nselect -add Example;\n",
        "\nselect Example;\n",
        "\nselect :Example;\n",
    ] {
        write_scene(
            &source,
            &format!(
                "//Maya ASCII 2026 scene\ncreateNode script -n \"Example\";{separator}setAttr \".stp\" 1; setAttr \".b\" -type \"string\" \"{payload}\";"
            ),
        );
        let report = audit_script_nodes(&source, &plan).unwrap();
        assert_eq!(
            report.disposition,
            AuditDisposition::DenyMalicious,
            "{separator}"
        );
        assert!(
            report
                .surfaces
                .iter()
                .any(
                    |surface| surface.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody
                        && surface.origin.node_name.as_deref() == Some("Example")
                        && surface.preview == payload
                ),
            "{separator}"
        );
    }
}

#[test]
fn audit_context_unbound_and_unresolved_attributes_use_coverage_gate() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("Example.ma");
    let plan = audit_plan();
    for statement in [
        "setAttr \".tx\" 1; setAttr \".ty\" 2;",
        "setAttr \".b\" -type \"string\" \"Example\";",
        "createNode;",
        "setAttr;",
        "select Example; setAttr \".before\" -type \"string\" \"Example\";",
    ] {
        write_scene(&source, &format!("//Maya ASCII 2026 scene\n{statement}"));
        let report = audit_script_nodes(&source, &plan).unwrap();
        assert_eq!(report.disposition, AuditDisposition::Review, "{statement}");
        assert!(
            report
                .coverage_issues
                .iter()
                .any(|issue| issue.kind == ExecutionCoverageIssueKind::TopLevelDiagnostics),
            "{statement}"
        );
    }
    let hardened = audit_script_nodes_with_options(
        &source,
        &plan,
        &LoadOptions::default(),
        AuditOptions::hardened_untrusted(),
    )
    .unwrap();
    assert_eq!(hardened.disposition, AuditDisposition::DenyUncertain);
    write_scene(
        &source,
        "//Maya ASCII 2026 scene\ncreateNode transform -n \"Example\"; setAttr \".tx\" 1;",
    );
    assert_eq!(
        audit_script_nodes(&source, &plan).unwrap().disposition,
        AuditDisposition::Allow
    );
}

#[test]
fn single_script_body_with_flag_alias_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("Example.ma");
    for flag in [
        "-cb on",
        "-channelBox on",
        "-keyable on",
        "-lock off",
        "-size 1",
        "-capacityHint 1",
    ] {
        write_scene(
            &source,
            &format!(
                "//Maya ASCII 2026 scene\ncreateNode script -n Example; setAttr {flag} \".b\" -type \"string\" \"python(\\\"exec('print(1)')\\\");\";"
            ),
        );
        let report = audit_script_nodes(&source, &audit_plan()).unwrap();
        assert_eq!(
            report.disposition,
            AuditDisposition::DenyMalicious,
            "{flag}"
        );
        assert!(
            report
                .surfaces
                .iter()
                .any(
                    |surface| surface.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody
                        && surface.origin.node_name.as_deref() == Some("Example")
                )
        );
    }
}
