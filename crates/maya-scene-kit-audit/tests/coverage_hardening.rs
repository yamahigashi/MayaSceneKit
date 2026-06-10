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
