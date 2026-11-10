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
fn connected_python_histories_are_denied_and_hashes_are_separate() {
    let payload = "import os; os.system('echo Example')";
    for bodies in [
        vec![payload],
        vec!["print('Sample')", payload],
        vec![payload, "print('Sample')"],
        vec![payload, ""],
        vec![payload, payload],
    ] {
        let mut scene =
            String::from("createNode transform -n ExampleSource; addAttr -ln note -dt string;");
        for body in &bodies {
            scene.push_str(&format!("setAttr \".note\" -type \"string\" \"{body}\";"));
        }
        scene.push_str("createNode script -n ExampleScript; setAttr \".st\" 1; setAttr \".stp\" 1; connectAttr :ExampleSource.note ExampleScript.b;");
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                Path::new("Example.ma"),
                SceneFormat::Ma,
                ValidationState::Validated,
                scene.into_bytes(),
            )
            .unwrap();
        let plan = build_script_audit_plan(vec![], 64).unwrap();
        let report =
            audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
        assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
        let catalog = observation.observed_execution_catalog(8).unwrap();
        assert_eq!(
            catalog.surfaces.len(),
            bodies.iter().filter(|value| !value.is_empty()).count()
        );
        for surface in &catalog.surfaces {
            let origin = &surface.surface.origin;
            let mut direct_json = serde_json::to_value(origin).unwrap();
            direct_json
                .as_object_mut()
                .unwrap()
                .remove("connection_source_plug");
            direct_json
                .as_object_mut()
                .unwrap()
                .remove("connection_source_range");
            direct_json
                .as_object_mut()
                .unwrap()
                .remove("connection_range");
            let direct = serde_json::from_value(direct_json).unwrap();
            assert_ne!(
                allowlist_surface_hash(origin, &surface.surface.text),
                allowlist_surface_hash(&direct, &surface.surface.text)
            );
            let mut changed = origin.clone();
            changed.overwritten = !changed.overwritten;
            changed.assignment_index = Some(99);
            assert_eq!(
                allowlist_surface_hash(origin, &surface.surface.text),
                allowlist_surface_hash(&changed, &surface.surface.text)
            );
            let round_trip = serde_json::from_slice::<
                maya_scene_kit_observe::scene::evidence::ExecutionOrigin,
            >(&serde_json::to_vec(origin).unwrap())
            .unwrap();
            assert_eq!(&round_trip, origin);
        }
    }
}

#[test]
fn connection_hashes_bind_destination_and_preserve_direct_vector() {
    use maya_scene_kit_observe::scene::evidence::{
        ExecutionLanguage, ExecutionOrigin, ExecutionSurfaceKind, ExecutionTrigger,
    };
    let mut origin = ExecutionOrigin {
        lang: ExecutionLanguage::Mel,
        surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
        trigger: ExecutionTrigger::FileOpen,
        node_name: Some("ExampleScript".into()),
        attr_name: Some(".b".into()),
        ..ExecutionOrigin::without_chunk_address()
    };
    let body = "print(\"Example\")";
    assert_eq!(
        allowlist_surface_hash(&origin, body).to_string(),
        "sha256:fc2dc8d6dab10944c5867113d5bb2d4a36c03d6a706879ac6780574aa309f2e6"
    );
    origin.connection_source_plug = Some("ExampleSource.note".into());
    let hash = allowlist_surface_hash(&origin, body);
    assert_eq!(
        hash.to_string(),
        "sha256:1e4466b1967bee4be5a68f5de16cfe547fe3cd5d623b0faa062fd16deda95e08"
    );
    origin.node_name = Some("SampleScript".into());
    assert_ne!(hash, allowlist_surface_hash(&origin, body));
    origin.node_name = Some("ExampleScript".into());
    origin.connection_source_plug = Some("SampleSource.note".into());
    assert_ne!(hash, allowlist_surface_hash(&origin, body));
}
