use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, PathOwnerDeleteTarget, clean_execution_targets,
    preview_clean_execution_targets, preview_delete_path_owner_nodes,
    preview_remove_script_nodes_by_name, remove_script_nodes_by_name,
    stage_clean_execution_targets, stage_delete_path_owner_nodes,
    stage_remove_script_nodes_by_name,
};
use maya_scene_kit_observe::scene::evidence::ExecutionSourceRange;

#[path = "support/mb_chunks.rs"]
mod mb_chunks;

#[test]
fn partially_missing_named_scripts_reject_preview_stage_and_save() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    let output = directory.path().join("Sample.ma");
    let source = b"//Maya ASCII 2026 scene\ncreateNode script -n \"ExampleScript\";\n    setAttr \".b\" -type \"string\" \"print(1)\";\n";
    std::fs::write(&input, source).unwrap();
    let names = ["ExampleScript".into(), "MissingScript".into()];
    assert!(preview_remove_script_nodes_by_name(&input, &names).is_err());
    assert!(stage_remove_script_nodes_by_name(&input, &names).is_err());
    assert!(remove_script_nodes_by_name(&input, &output, &names).is_err());
    assert!(!output.exists());
    assert_eq!(std::fs::read(input).unwrap(), source);
}

#[test]
fn partially_missing_binary_forms_reject_preview_stage_and_save() {
    use mb_chunks::{build_mb_chunk, build_mb_form_with_alignment, build_mb_root};
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.mb");
    let output = directory.path().join("Sample.mb");
    let bytes = build_mb_root(&[build_mb_form_with_alignment(
        "SCRP",
        &[build_mb_chunk("CREA", b"ExampleScript\0")],
        4,
    )]);
    let mb = maya_scene_kit_formats::mb::parse_bytes(bytes.clone()).unwrap();
    std::fs::write(&input, &bytes).unwrap();
    let targets = [
        ExecutionCleanTarget::MbOwnerForm {
            form: "SCRP".into(),
            node_offset: mb.root().children()[0].offset(),
        },
        ExecutionCleanTarget::MbOwnerForm {
            form: "SCRP".into(),
            node_offset: bytes.len() + 100,
        },
    ];
    assert!(preview_clean_execution_targets(&input, &targets).is_err());
    assert!(stage_clean_execution_targets(&input, &targets).is_err());
    assert!(clean_execution_targets(&input, &output, &targets).is_err());
    assert!(!output.exists());
    assert_eq!(std::fs::read(input).unwrap(), bytes);
}

#[test]
fn partially_missing_path_owners_reject_preview_and_stage() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    let bytes = b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\n    setAttr \".ftn\" -type \"string\" \"asset/example/file.png\";\n";
    std::fs::write(&input, bytes).unwrap();
    let targets = [
        PathOwnerDeleteTarget {
            node_type: "file".into(),
            node_name: "Example".into(),
        },
        PathOwnerDeleteTarget {
            node_type: "file".into(),
            node_name: "Missing".into(),
        },
    ];
    assert!(preview_delete_path_owner_nodes(&input, &targets).is_err());
    assert!(stage_delete_path_owner_nodes(&input, &targets).is_err());
    assert_eq!(std::fs::read(input).unwrap(), bytes);
}

#[test]
fn script_consumed_by_an_earlier_command_is_covered() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    let output = directory.path().join("Sample.ma");
    let header = "//Maya ASCII 2026 scene\n";
    let command = "createNode script -n \"ExampleScript\";";
    let tail = "\n    setAttr \".b\" -type \"string\" \"print(1)\";\n";
    std::fs::write(&input, format!("{header}{command}{tail}")).unwrap();
    let command_target = ExecutionCleanTarget::TopLevelCommand {
        source_range: ExecutionSourceRange {
            start: header.len(),
            end: header.len() + command.len(),
        },
    };
    let targets = [
        ExecutionCleanTarget::ScriptNode {
            node_name: "ExampleScript".into(),
        },
        command_target.clone(),
        ExecutionCleanTarget::ScriptNode {
            node_name: "  ".into(),
        },
    ];
    let preview = preview_clean_execution_targets(&input, &targets).unwrap();
    let staged = stage_clean_execution_targets(&input, &targets).unwrap();
    let saved = clean_execution_targets(&input, &output, &targets).unwrap();
    assert_eq!(preview.cleaned_targets, vec![command_target]);
    assert!(preview.removed_script_nodes.is_empty());
    assert_eq!(staged.changes.physical_deletion_count, 1);
    assert_eq!(
        staged
            .changes
            .records
            .iter()
            .filter(|change| {
                change.status == maya_scene_kit_edit::scene::SceneEditStatus::Covered
            })
            .count(),
        2,
    );
    assert_eq!(preview, staged.preview);
    assert_eq!(saved.cleaned_targets, preview.cleaned_targets);
    assert_eq!(staged.artifact.bytes, format!("{header}{tail}").as_bytes());
    assert_eq!(std::fs::read(output).unwrap(), staged.artifact.bytes);
}
