use std::path::Path;

use maya_scene_kit_audit::{
    audit::{audit_observation, build_script_audit_plan},
    scene::{AuditDisposition, AuditOptions},
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader,
    core::{SceneFormat, ValidationState},
};

#[test]
fn script_history_bodies_are_individually_audited() {
    let payload = "import os; os.system('echo Example')";
    for bodies in [
        vec!["", payload],
        vec!["print('Example')", payload],
        vec![payload, "print('Example')"],
        vec![payload, ""],
        vec![payload, payload],
    ] {
        let mut scene = String::from("createNode script -n ExampleScript;\n");
        for body in &bodies {
            scene.push_str(&format!("setAttr \".b\" -type \"string\" \"{body}\";\n"));
        }
        scene.push_str(
            "setAttr \".st\" 0; setAttr \".st\" 1; setAttr \".stp\" 0; setAttr \".stp\" 1;\n",
        );
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                Path::new("Example.ma"),
                SceneFormat::Ma,
                ValidationState::Validated,
                scene.into_bytes(),
            )
            .unwrap();
        let catalog = observation.observed_execution_catalog(8).unwrap();
        let surfaces: Vec<_> = catalog
            .surfaces
            .iter()
            .filter(|s| s.surface.origin.attr_name.as_deref() == Some(".b"))
            .collect();
        assert_eq!(
            surfaces.len(),
            bodies.iter().filter(|body| !body.is_empty()).count()
        );
        for surface in &surfaces {
            assert_eq!(surface.surface.origin.trigger.as_str(), "file_open");
            assert_eq!(surface.surface.origin.lang.as_str(), "python");
        }
        let plan = build_script_audit_plan(vec![], 64).unwrap();
        let report =
            audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
        assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    }
    let scene = concat!(
        "createNode script -n ExampleScript; setAttr \".st\" 1; setAttr \".stp\" 1;",
        "setAttr \".b\" -type \"string\" \"import maya.mel as mel; mel.eval('print 1;')\";",
        "setAttr \".b\" -type \"string\" \"print('Example')\";"
    );
    let observation = Loader::new(LoadOptions::default())
        .observe_analysis_bytes(
            Path::new("Example.ma"),
            SceneFormat::Ma,
            ValidationState::Validated,
            scene.as_bytes().to_vec(),
        )
        .unwrap();
    let catalog = observation.observed_execution_catalog(8).unwrap();
    let bridge = catalog
        .surfaces
        .iter()
        .find(|surface| {
            surface.surface.origin.source_kind.as_deref()
                == Some("python->maya.mel.eval literal bridge")
        })
        .unwrap();
    assert!(bridge.surface.origin.overwritten);
    assert_eq!(bridge.surface.origin.assignment_index, Some(2));
}

#[test]
fn script_history_bodies_keep_independent_allowlist_decisions() {
    use maya_scene_kit_audit::scene::{
        AllowlistSource, AuditAllowlist, AuditCacheStore, AuditedSceneSnapshot,
        allowlist_surface_hash, fingerprint_audit_plan,
    };
    use maya_scene_kit_observe::scene::{ObserveCacheStore, ObservedSceneSnapshot};
    let payload = "import os; os.system('echo Example')";
    for last in [payload, "print('Example')"] {
        let scene = format!(
            "createNode script -n ExampleScript; setAttr \".st\" 1; setAttr \".stp\" 1; setAttr \".b\" -type \"string\" \"{payload}\"; setAttr \".b\" -type \"string\" \"{last}\";"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Example.ma");
        std::fs::write(&path, &scene).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let file_state = maya_scene_kit_observe::scene::persistent_cache::ObserveFileState {
            path: path.clone(),
            size: metadata.len(),
            modified_unix_nanos: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos()),
        };
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                &path,
                SceneFormat::Ma,
                ValidationState::Validated,
                scene.into_bytes(),
            )
            .unwrap();
        let catalog = observation.observed_execution_catalog(8).unwrap();
        let surfaces: Vec<_> = catalog
            .surfaces
            .iter()
            .filter(|s| s.surface.origin.attr_name.as_deref() == Some(".b"))
            .collect();
        assert_eq!(surfaces.len(), 2);
        assert!(surfaces[0].surface.origin.overwritten);
        assert!(!surfaces[1].surface.origin.overwritten);
        let hashes: Vec<_> = surfaces
            .iter()
            .map(|s| allowlist_surface_hash(&s.surface.origin, &s.surface.text))
            .collect();
        assert_eq!(hashes[0] == hashes[1], last == payload);
        let mut other_node = surfaces[0].surface.origin.clone();
        other_node.node_name = Some("SampleScript".to_string());
        assert_eq!(hashes[0], allowlist_surface_hash(&other_node, payload));
        let plan = build_script_audit_plan(vec![], 64).unwrap();
        let baseline =
            audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
        let snapshot = AuditedSceneSnapshot::with_file_state(
            baseline.clone(),
            AuditOptions::strict_default(),
            fingerprint_audit_plan(&plan),
            file_state.clone().into(),
            &LoadOptions::default(),
        )
        .unwrap()
        .expect("cacheable schema");
        let cache = AuditCacheStore::new(dir.path().join("audit-cache"), &LoadOptions::default());
        cache.save(&snapshot).unwrap();
        let cached = cache.load_by_identity(&snapshot.identity).unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&cached.report.surfaces).unwrap(),
            serde_json::to_value(&baseline.surfaces).unwrap()
        );
        let observed = ObservedSceneSnapshot::with_file_state(
            &observation,
            &LoadOptions::default(),
            file_state,
        )
        .unwrap()
        .expect("cacheable schema");
        let cache =
            ObserveCacheStore::new(dir.path().join("observe-cache"), &LoadOptions::default());
        cache.save(&observed).unwrap();
        let cached = cache.load_by_identity(&observed.identity).unwrap().unwrap();
        assert_eq!(cached.dump_report.script_entries[0].body, last);
        let codes: Vec<_> = baseline
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect();
        let allowlist = AuditAllowlist::from_json(
            &serde_json::json!({"version":1,"entries":[{"hash":hashes[1],"codes":codes}]})
                .to_string(),
            AllowlistSource::App,
        )
        .unwrap();
        let report = audit_observation(
            &observation,
            &plan.with_allowlist(allowlist),
            AuditOptions::strict_default(),
        )
        .unwrap();
        if last == payload {
            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| finding.allowed_by.is_some())
            );
            assert_ne!(report.disposition, AuditDisposition::DenyMalicious);
        } else {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.allowed_by.is_none())
            );
            assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
        }
    }
}
