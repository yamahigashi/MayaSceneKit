use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, MaterializeOptions, OperationMode, PatchPlanner,
};
use maya_scene_kit_observe::scene::{LoadOptions, Loader, paths::SceneSourceFingerprint};

fn example_scene() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    PatchPlanner,
    SceneSourceFingerprint,
) {
    let dir = tempfile::tempdir().unwrap();
    let schema = dir.path().join("Example.yaml");
    std::fs::write(&schema, "version: 1\nnodes:\n  Example:\n    typeid: 0x45584d50\n    execution:\n      profiles:\n        - kind: script_node\n          body_attrs: [body]\n    attrs:\n      body: { unit: none, kind: scalar }\n").unwrap();
    let path = dir.path().join("TestScene.ma");
    std::fs::write(&path, "//Maya ASCII 2026 scene\ncreateNode \"Example\" -name ExampleScript;\n    setAttr \".body\" -type \"string\" \"print(1)\";\ncreateNode transform -n \"Sample\";\n").unwrap();
    let load_options = LoadOptions::default().with_additional_node_info_paths(vec![schema]);
    let source = Loader::new(load_options.clone())
        .observe_path(&path)
        .unwrap()
        .source_fingerprint()
        .unwrap();
    let options =
        MaterializeOptions::new(load_options).with_operation_mode(OperationMode::Forensic);
    (dir, path, PatchPlanner::new(options), source)
}

#[test]
fn composite_removes_reported_non_script_owner() {
    let (_dir, path, planner, source) = example_scene();
    let target = ExecutionCleanTarget::ScriptNode {
        node_name: "ExampleScript".into(),
    };
    let full = planner.stage_remove_script_nodes(&path).unwrap();
    let composite = planner
        .stage_scene_edits(&path, Some(&source), std::slice::from_ref(&target), &[])
        .unwrap();
    assert_eq!(composite.artifact.bytes, full.artifact.bytes);
    assert_eq!(
        composite.artifact.bytes,
        b"//Maya ASCII 2026 scene\ncreateNode transform -n \"Sample\";\n"
    );
    assert_eq!(composite.preview.cleaned_targets, vec![target]);
}

#[test]
fn composite_rejects_unreported_owner_after_reported_owner() {
    let (_dir, path, planner, source) = example_scene();
    let targets = ["ExampleScript", "Sample"].map(|name| ExecutionCleanTarget::ScriptNode {
        node_name: name.into(),
    });
    let error = planner
        .stage_scene_edits(&path, Some(&source), &targets, &[])
        .unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("requested deletion was not found"),
        "{message}"
    );
    assert!(message.contains("Sample"), "{message}");
    assert!(!message.contains("ExampleScript"), "{message}");
}
