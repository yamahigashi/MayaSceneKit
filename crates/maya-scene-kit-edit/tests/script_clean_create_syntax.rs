use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, stage_clean_execution_targets, stage_remove_script_nodes,
    stage_scene_edits,
};
use maya_scene_kit_observe::scene::{LoadOptions, Loader};
use tempfile::tempdir;

fn assert_clean(declaration: &str, named: bool) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    let header = "//Maya ASCII 2026 scene\n";
    let retained = concat!(
        "createNode transform -n \"script\";\n",
        "    setAttr \".tx\" 1;\n",
        "createNode transform -n \"Sample\";\n",
        "    setAttr \".ty\" 2;\n",
    );
    let input = format!(
        "{header}{declaration}\n    setAttr \".b\" -type \"string\" \"print(1);\";\n{retained}"
    );
    std::fs::write(&path, input).unwrap();
    let output = if named {
        let targets = [ExecutionCleanTarget::ScriptNode {
            node_name: "ExampleScript".to_string(),
        }];
        let staged = stage_clean_execution_targets(&path, &targets).unwrap();
        assert_eq!(staged.preview.removed_script_nodes, ["ExampleScript"]);
        let source = Loader::new(LoadOptions::default())
            .observe_path(&path)
            .unwrap()
            .source_fingerprint()
            .unwrap();
        let composite = stage_scene_edits(&path, Some(&source), &targets, &[]).unwrap();
        assert_eq!(
            composite.artifact.bytes,
            format!("{header}{retained}").as_bytes()
        );
        staged.artifact.bytes
    } else {
        let staged = stage_remove_script_nodes(&path).unwrap();
        assert_eq!(staged.preview.removed_nodes, ["ExampleScript"]);
        staged.artifact.bytes
    };
    assert_eq!(output, format!("{header}{retained}").as_bytes());
    std::fs::write(&path, output).unwrap();
    let observation = Loader::new(LoadOptions::default())
        .observe_path(&path)
        .unwrap();
    assert!(
        observation
            .observed_execution_catalog(64)
            .unwrap()
            .surfaces
            .is_empty()
    );
}

#[test]
fn full_clean_removes_quoted_script_type() {
    assert_clean("createNode \"script\" -n \"ExampleScript\";", false);
}

#[test]
fn named_clean_removes_quoted_script_type() {
    assert_clean("createNode \"script\" -n \"ExampleScript\";", true);
}

#[test]
fn full_clean_removes_flags_before_script_type() {
    for declaration in [
        "createNode -n \"ExampleScript\" script;",
        "createNode -name \"ExampleScript\" -parent \"Example\" script;",
        "createNode -p \"Example\" -n ExampleScript script;",
        "createNode -ss -n \"ExampleScript\" script;",
        "createNode -skipSelect -name \"ExampleScript\" \"script\";",
    ] {
        assert_clean(declaration, false);
    }
}

#[test]
fn named_clean_removes_flags_before_script_type() {
    for declaration in [
        "createNode -n \"ExampleScript\" script;",
        "createNode -name \"ExampleScript\" -parent \"Example\" script;",
        "createNode -p \"Example\" -n ExampleScript script;",
        "createNode -ss -n \"ExampleScript\" script;",
        "createNode -skipSelect -name \"ExampleScript\" \"script\";",
    ] {
        assert_clean(declaration, true);
    }
}

#[test]
fn clean_ignores_name_flags_inside_quoted_arguments() {
    for named in [false, true] {
        assert_clean(
            "createNode script -p \"Example -n Sample\" -n ExampleScript;",
            named,
        );
    }
}

#[test]
fn clean_removes_multiline_create_command_once() {
    for declaration in [
        "createNode script\n    -n ExampleScript;",
        "createNode script -n\nExampleScript;",
        "createNode\n    script -n ExampleScript;",
        "createNode -p \"Example\n    -n Sample\" script -n ExampleScript;",
    ] {
        for named in [false, true] {
            assert_clean(declaration, named);
        }
    }
}
