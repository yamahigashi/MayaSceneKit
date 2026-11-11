#[path = "../../maya-scene-kit-observe/tests/support/mb_connections.rs"]
mod fixture;
use std::path::Path;

use maya_scene_kit_audit::{
    audit::{audit_observation, build_script_audit_plan},
    scene::{AuditDisposition, AuditOptions, allowlist_surface_hash},
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader,
    core::{SceneFormat, ValidationState},
};

#[test]
fn connected_python_is_denied_and_has_distinct_allowlist_hash() {
    let bytes = fixture::example(
        &[b"import os; os.system('echo Example')"],
        "ExampleSource.note",
        "ExampleScript.b",
        &[],
    );
    let observation = Loader::new(LoadOptions::default())
        .observe_analysis_bytes(
            Path::new("Example.mb"),
            SceneFormat::Mb,
            ValidationState::Validated,
            bytes,
        )
        .unwrap();
    let plan = build_script_audit_plan(vec![], 64).unwrap();
    let report = audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    let catalog = observation.observed_execution_catalog(8).unwrap();
    assert_eq!(catalog.surfaces.len(), 1);
    let surface = &catalog.surfaces[0].surface;
    let mut direct = surface.origin.clone();
    direct.connection_source_plug = None;
    assert_ne!(
        allowlist_surface_hash(&surface.origin, &surface.text),
        allowlist_surface_hash(&direct, &surface.text)
    );
    let mut marked = surface.origin.clone();
    marked.overwritten = true;
    marked.assignment_index = Some(99);
    assert_eq!(
        allowlist_surface_hash(&surface.origin, &surface.text),
        allowlist_surface_hash(&marked, &surface.text)
    );
}

#[test]
fn unresolved_connection_cannot_be_complete_and_allowed() {
    for values in [vec![], vec![b"Example".as_slice(), b"Sample"]] {
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                Path::new("Example.mb"),
                SceneFormat::Mb,
                ValidationState::Validated,
                fixture::example(&values, "ExampleSource.note", "ExampleScript.b", &[]),
            )
            .unwrap();
        let plan = build_script_audit_plan(vec![], 64).unwrap();
        let report =
            audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
        assert_ne!(report.coverage_state.as_str(), "complete");
        assert_eq!(report.disposition, AuditDisposition::Review);
    }
}

#[test]
fn mb_connection_hash_matches_fixed_vectors() {
    for source in ["ExampleSource.note", ":ExampleSource.note"] {
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                Path::new("Example.mb"),
                SceneFormat::Mb,
                ValidationState::Validated,
                fixture::example(&[b"print(\"Example\")"], source, "ExampleScript.b", &[]),
            )
            .unwrap();
        let catalog = observation.observed_execution_catalog(256).unwrap();
        assert_eq!(catalog.surfaces.len(), 1);
        let surface = &catalog.surfaces[0].surface;
        let hash = allowlist_surface_hash(&surface.origin, &surface.text);
        assert_eq!(
            hash.to_string(),
            "sha256:50f19a81de94e1703f3abc03455099396f39cf834f482f4ec1005ce5ba229637"
        );
        let mut direct = surface.origin.clone();
        direct.connection_source_plug = None;
        assert_eq!(
            allowlist_surface_hash(&direct, &surface.text).to_string(),
            "sha256:e39d04f6a0ddfd4ad16c2cd2ec25058ae43764bb9895c9145fafe241becbbaa7"
        );
        let mut changed = surface.origin.clone();
        changed.connection_source_plug = Some("Sample.note".into());
        assert_ne!(allowlist_surface_hash(&changed, &surface.text), hash);
        changed = surface.origin.clone();
        changed.node_name = Some("SampleScript".into());
        assert_ne!(allowlist_surface_hash(&changed, &surface.text), hash);
    }
}

#[test]
fn unknown_connection_attributes_require_review_only_for_execution_nodes() {
    for (destination, unresolved) in [
        ("ExampleSource.sampleAttribute", false),
        ("ExampleScript.sampleAttribute", true),
    ] {
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                Path::new("Example.mb"),
                SceneFormat::Mb,
                ValidationState::Validated,
                fixture::example(
                    &[b"print('Example')"],
                    "ExampleSource.note",
                    destination,
                    &[],
                ),
            )
            .unwrap();
        let plan = build_script_audit_plan(vec![], 64).unwrap();
        let report =
            audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
        assert_eq!(
            report.coverage_issues.len(),
            usize::from(unresolved),
            "{destination}"
        );
        assert_eq!(
            report.disposition,
            if unresolved {
                AuditDisposition::Review
            } else {
                AuditDisposition::Allow
            },
            "{destination}"
        );
    }
}
