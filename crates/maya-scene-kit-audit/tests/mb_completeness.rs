use std::path::Path;

use maya_scene_kit_audit::{
    audit::{audit_script_nodes_with_options, build_script_audit_plan},
    scene::{AuditDisposition, AuditOptions},
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, MbParseBudget,
    core::{SceneFormat, ValidationState},
    evidence::{ExecutionCoverageIssueDetail, ExecutionCoverageState},
};

fn chunk(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

fn form(name: &[u8; 4], children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = name.to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    chunk(b"FOR4", &payload)
}

fn malformed() -> Vec<u8> {
    let mut bytes = b"DATA".to_vec();
    bytes.extend_from_slice(&100u32.to_be_bytes());
    bytes
}

fn assert_incomplete(bytes: Vec<u8>, budget: MbParseBudget, reason_name: &str, script: bool) {
    let options = LoadOptions::default().with_mb_parse_budget(budget);
    let loader = Loader::new(options.clone());
    let path = Path::new("Example.mb");
    let observation = loader
        .observe_execution_bytes(
            path,
            SceneFormat::Mb,
            ValidationState::Validated,
            bytes.clone(),
        )
        .expect("observation");
    let catalog = observation.observed_execution_catalog(8).expect("catalog");
    assert_eq!(catalog.coverage_state, ExecutionCoverageState::Incomplete);
    assert_eq!(catalog.coverage_issues.len(), 1);
    let issue = &catalog.coverage_issues[0];
    assert!(issue.origin.is_none());
    let ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason } = &issue.detail else {
        panic!("unexpected issue: {issue:?}");
    };
    assert!(reason.contains(reason_name), "{reason}");
    assert!(reason.contains("truncated_groups=1"), "{reason}");
    if script {
        assert!(catalog.surfaces.iter().any(|surface| surface.surface.origin.node_name.as_deref() == Some("ExampleScript")));
        assert!(reason.contains("exceeds"), "{reason}");
    }
    assert_eq!(observation.validation_state(), ValidationState::Partial);
    assert_eq!(
        observation
            .observed_execution_catalog(8)
            .unwrap()
            .coverage_issues
            .len(),
        1
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        loader
            .observe_analysis_path(&path)
            .unwrap()
            .validation_state(),
        ValidationState::Partial
    );
    assert_eq!(
        loader
            .observe_execution_path(&path)
            .unwrap()
            .validation_state(),
        ValidationState::Partial
    );
    let plan = build_script_audit_plan(vec![], 64).unwrap();
    for (profile, disposition) in [
        (AuditOptions::strict_default(), AuditDisposition::Review),
        (
            AuditOptions::hardened_untrusted(),
            AuditDisposition::DenyUncertain,
        ),
    ] {
        let report = audit_script_nodes_with_options(&path, &plan, &options, profile).unwrap();
        assert_eq!(report.disposition, disposition);
        assert_eq!(report.coverage_issues.len(), 1);
    }
}

#[test]
fn malformed_last_child_preserves_script_and_reports_incomplete_coverage() {
    let script = form(
        b"SCRP",
        &[
            chunk(b"CREA", b"ExampleScript\0"),
            chunk(b"STR ", b"b\0print \"Example\";\0"),
        ],
    );
    assert_incomplete(
        form(b"Maya", &[script, malformed()]),
        MbParseBudget::default(),
        "Malformed",
        true,
    );
}

#[test]
fn exact_child_limit_reports_incomplete_coverage() {
    assert_incomplete(
        form(b"Maya", &[form(b"HEAD", &[]), form(b"HEAD", &[])]),
        MbParseBudget {
            max_children_per_group: 1,
            ..MbParseBudget::default()
        },
        "ChildLimit",
        false,
    );
}

#[test]
fn exact_chunk_budget_reports_incomplete_coverage() {
    assert_incomplete(
        form(b"Maya", &[form(b"HEAD", &[]), form(b"HEAD", &[])]),
        MbParseBudget {
            max_total_chunks: 2,
            ..MbParseBudget::default()
        },
        "ChunkBudget",
        false,
    );
}

#[test]
fn depth_limit_reports_incomplete_coverage() {
    assert_incomplete(
        form(b"Maya", &[form(b"HEAD", &[])]),
        MbParseBudget {
            max_depth: 0,
            ..MbParseBudget::default()
        },
        "DepthLimit",
        false,
    );
}

#[test]
fn truncated_input_caps_only_validated_input() {
    let bytes = form(b"Maya", &[malformed()]);
    let loader = Loader::new(LoadOptions::default());
    for (input, expected) in [
        (ValidationState::Validated, ValidationState::Partial),
        (ValidationState::Partial, ValidationState::Partial),
        (ValidationState::Unsupported, ValidationState::Unsupported),
        (ValidationState::Invalid, ValidationState::Invalid),
    ] {
        for observation in [
            loader
                .observe_bytes(
                    Path::new("Example.mb"),
                    SceneFormat::Mb,
                    input,
                    bytes.clone(),
                )
                .unwrap()
                .validation_state(),
            loader
                .observe_analysis_bytes(
                    Path::new("Example.mb"),
                    SceneFormat::Mb,
                    input,
                    bytes.clone(),
                )
                .unwrap()
                .validation_state(),
            loader
                .observe_execution_bytes(
                    Path::new("Example.mb"),
                    SceneFormat::Mb,
                    input,
                    bytes.clone(),
                )
                .unwrap()
                .validation_state(),
        ] {
            assert_eq!(observation, expected);
        }
    }
}

#[test]
fn previous_cache_versions_are_rejected_for_truncated_input() {
    use maya_scene_kit_audit::scene::{
        AuditCacheStore, AuditedSceneSnapshot, fingerprint_audit_plan,
    };
    use maya_scene_kit_observe::scene::{ObserveCacheStore, ObservedSceneSnapshot};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    std::fs::write(&path, form(b"Maya", &[malformed()])).unwrap();
    let options = LoadOptions::default();
    let observation = Loader::new(options.clone()).observe_path(&path).unwrap();
    let snapshot = ObservedSceneSnapshot::from_observation(&observation, &options)
        .unwrap()
        .expect("cacheable schema");
    let mut old = snapshot.clone();
    old.identity.cache_schema_version = snapshot.identity.cache_schema_version - 1;
    let store = ObserveCacheStore::new(dir.path().join("ExampleObserve"), &options);
    store.save(&old).unwrap();
    assert!(store.load_by_path_if_fresh(&path).unwrap().is_none());
    assert!(store.load_by_identity(&old.identity).unwrap().is_none());
    assert_eq!(
        snapshot.paths_report.validation_state,
        ValidationState::Partial
    );
    store.save(&snapshot).unwrap();
    assert!(store.load_by_path_if_fresh(&path).unwrap().is_some());

    let plan = build_script_audit_plan(vec![], 64).unwrap();
    let profile = AuditOptions::strict_default();
    let fingerprint = fingerprint_audit_plan(&plan);
    let report = audit_script_nodes_with_options(&path, &plan, &options, profile).unwrap();
    let snapshot = AuditedSceneSnapshot::new(report, profile, &fingerprint, &options)
        .unwrap()
        .expect("cacheable schema");
    let mut old = snapshot.clone();
    old.identity.cache_schema_version = snapshot.identity.cache_schema_version - 1;
    let store = AuditCacheStore::new(dir.path().join("ExampleAudit"), &options);
    store.save(&old).unwrap();
    assert!(
        store
            .load_by_path_if_fresh(&path, profile, &fingerprint)
            .unwrap()
            .is_none()
    );
    assert!(store.load_by_identity(&old.identity).unwrap().is_none());
    assert_eq!(
        snapshot.report.coverage_state,
        ExecutionCoverageState::Incomplete
    );
    assert_eq!(snapshot.report.disposition, AuditDisposition::Review);
    store.save(&snapshot).unwrap();
    assert!(
        store
            .load_by_path_if_fresh(&path, profile, &fingerprint)
            .unwrap()
            .is_some()
    );
}

#[test]
fn nonempty_group_depth_limit_reports_parse_budget_notice() {
    let bytes = form(b"Maya", &[form(b"HEAD", &[chunk(b"DATA", &[0; 4])])]);
    let options = LoadOptions::default().with_mb_parse_budget(MbParseBudget {
        max_depth: 1,
        ..MbParseBudget::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    std::fs::write(&path, bytes).unwrap();
    let plan = build_script_audit_plan(vec![], 64).unwrap();
    let report =
        audit_script_nodes_with_options(&path, &plan, &options, AuditOptions::strict_default())
            .unwrap();
    assert_eq!(report.disposition, AuditDisposition::Review);
    assert_eq!(report.validation_state, ValidationState::Invalid);
    assert_eq!(report.coverage_state, ExecutionCoverageState::Incomplete);
    assert!(report.coverage_issues.is_empty());
    assert!(report.is_parse_budget_blocked());
    assert_eq!(report.notices.len(), 1);
    assert_eq!(
        report.notices[0].code,
        maya_scene_kit_audit::scene::AuditNoticeCode::ParseBudgetExceeded
    );
    assert_eq!(
        report.notices[0].message,
        "parse budget exceeded: max_depth"
    );
}

#[test]
fn nested_malformed_script_group_reports_incomplete_coverage() {
    assert_incomplete(
        form(
            b"Maya",
            &[form(
                b"SCRP",
                &[chunk(b"CREA", b"ExampleScript\0"), malformed()],
            )],
        ),
        MbParseBudget::default(),
        "Malformed",
        false,
    );
}

#[test]
fn different_malformed_groups_list_reason_kind_once() {
    let mut other = b"DATA".to_vec();
    other.extend_from_slice(&200u32.to_be_bytes());
    let bytes = form(
        b"Maya",
        &[form(b"SCRP", &[malformed()]), form(b"SCRP", &[other])],
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    std::fs::write(&path, bytes).unwrap();
    let plan = build_script_audit_plan(vec![], 64).unwrap();
    let report = audit_script_nodes_with_options(
        &path,
        &plan,
        &LoadOptions::default(),
        AuditOptions::strict_default(),
    )
    .unwrap();
    assert_eq!(report.coverage_issues.len(), 1);
    let ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason } =
        &report.coverage_issues[0].detail
    else {
        panic!("unexpected issue");
    };
    assert!(reason.contains("truncated_groups=2"), "{reason}");
    let reasons = reason.split("reasons=[").nth(1).unwrap();
    assert_eq!(reasons.matches("Malformed").count(), 1, "{reason}");
    assert!(!matches!(
        report.disposition,
        AuditDisposition::Allow | AuditDisposition::AllowWithNotice
    ));
}

#[test]
fn truncated_input_preserves_malicious_script_denial() {
    let script = form(
        b"SCRP",
        &[
            chunk(b"CREA", b"ExampleScript\0"),
            chunk(
                b"STR ",
                b"b\0 python(\"import os; os.system('Example')\");\0",
            ),
        ],
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    std::fs::write(&path, form(b"Maya", std::slice::from_ref(&script))).unwrap();
    let plan = build_script_audit_plan(vec![], 64).unwrap();
    let report = audit_script_nodes_with_options(
        &path,
        &plan,
        &LoadOptions::default(),
        AuditOptions::strict_default(),
    )
    .unwrap();
    assert!(report.coverage_issues.is_empty());
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    std::fs::write(&path, form(b"Maya", &[script, malformed()])).unwrap();
    let truncated = audit_script_nodes_with_options(
        &path,
        &plan,
        &LoadOptions::default(),
        AuditOptions::strict_default(),
    )
    .unwrap();
    assert_eq!(truncated.disposition, AuditDisposition::DenyMalicious);
    assert_eq!(truncated.coverage_issues.len(), 1);
    assert_eq!(truncated.findings.len(), report.findings.len());
}
