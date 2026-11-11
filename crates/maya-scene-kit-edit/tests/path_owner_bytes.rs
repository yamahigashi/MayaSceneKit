use maya_scene_kit_edit::scene::{
    PathOwnerDeleteTarget, SceneEditLocator, preview_delete_path_owner_nodes,
    stage_delete_path_owner_nodes,
};

fn check_owner_deletion(codeset: &str, sample: &[u8]) {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    let prefix = [
        format!("//Maya ASCII 2026 scene\n//Codeset: {codeset}\n// ").as_bytes(),
        sample,
        b"\n",
    ]
    .concat();
    let owner = b"createNode file -n \"Example\";\n    setAttr \".ftn\" -type \"string\" \"asset/example/file.png\";\n";
    let suffix = [
        b"createNode transform -n \"Sample\";\n// ".as_slice(),
        sample,
        b"\n",
    ]
    .concat();
    let source = [prefix.as_slice(), owner.as_slice(), suffix.as_slice()].concat();
    std::fs::write(&input, &source).unwrap();
    let targets = [PathOwnerDeleteTarget {
        node_type: "file".into(),
        node_name: "Example".into(),
    }];
    let staged = stage_delete_path_owner_nodes(&input, &targets).unwrap();
    let preview = preview_delete_path_owner_nodes(&input, &targets).unwrap();
    assert_eq!(preview, staged.preview);
    assert_eq!(preview.deleted_targets, targets);
    assert_eq!(staged.changes.physical_deletion_count, 1);
    assert_eq!(staged.changes.records.len(), 1);
    let record = &staged.changes.records[0];
    assert_eq!(record.before, owner);
    assert!(record.after.is_empty());
    assert_eq!(
        record.locator,
        SceneEditLocator::MaRange {
            start: prefix.len(),
            end: prefix.len() + owner.len(),
        }
    );
    assert_eq!(staged.artifact.bytes, [prefix, suffix].concat());
    assert_eq!(std::fs::read(input).unwrap(), source);
}

#[test]
fn public_owner_deletion_preserves_cp932_bytes() {
    check_owner_deletion("932", b"\x83\x54\x83\x93\x83\x76\x83\x8b");
}

#[test]
fn public_owner_deletion_preserves_utf8_bytes() {
    check_owner_deletion("UTF-8", "サンプル".as_bytes());
}
