use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, stage_remove_script_nodes, stage_scene_edits,
};
use maya_scene_kit_observe::scene::{LoadOptions, Loader};
use tempfile::tempdir;

fn scene(cp932: bool) -> (Vec<u8>, Vec<u8>) {
    let header = if cp932 {
        b"//Maya ASCII 2026 scene\n//Codeset: 932\n".as_slice()
    } else {
        b"//Maya ASCII 2026 scene\n//Codeset: 65001\n".as_slice()
    };
    let name = if cp932 {
        b"\x83\x65\x83\x58\x83\x67".as_slice()
    } else {
        "テスト".as_bytes()
    };
    let tail = b"createNode transform -n \"Example\";\n";
    let bytes = [
        header,
        b"createNode script -n \"",
        name,
        b"\";\n    setAttr \".b\" -type \"string\" \"print(1)\";\n",
        tail,
    ]
    .concat();
    (bytes, [header, tail].concat())
}

#[test]
fn full_clean_reports_decoded_script_name() {
    for cp932 in [false, true] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("Example.ma");
        let (bytes, expected) = scene(cp932);
        std::fs::write(&path, bytes).unwrap();
        let staged = stage_remove_script_nodes(&path).unwrap();
        assert_eq!(staged.preview.removed_nodes, ["テスト"]);
        assert_eq!(staged.artifact.bytes, expected);
    }
}

#[test]
fn named_composite_clean_matches_decoded_script_name() {
    for cp932 in [false, true] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("Example.ma");
        let (bytes, expected) = scene(cp932);
        std::fs::write(&path, bytes).unwrap();
        let source = Loader::new(LoadOptions::default())
            .observe_path(&path)
            .unwrap()
            .source_fingerprint()
            .unwrap();
        let staged = stage_scene_edits(
            &path,
            Some(&source),
            &[ExecutionCleanTarget::ScriptNode {
                node_name: "テスト".to_string(),
            }],
            &[],
        )
        .unwrap();
        assert_eq!(staged.artifact.bytes, expected);
    }
}

fn assert_cp932_name_clean(raw_name: &[u8], decoded_name: &str) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    let header = b"//Maya ASCII 2026 scene\n//Codeset: 932\n";
    let bytes = [
        header.as_slice(),
        b"createNode script -n \"",
        raw_name,
        b"\";\n    setAttr \".b\" -type \"string\" \"print(1)\";\n",
        b"createNode script -n \"ExampleScript\";\n",
        b"    setAttr \".b\" -type \"string\" \"print(2)\";\n",
    ]
    .concat();
    std::fs::write(&path, bytes).unwrap();
    let full = stage_remove_script_nodes(&path).unwrap();
    assert_eq!(full.preview.removed_nodes, [decoded_name, "ExampleScript"]);
    assert_eq!(full.artifact.bytes, header);

    let targets = [decoded_name, "ExampleScript"].map(|name| ExecutionCleanTarget::ScriptNode {
        node_name: name.to_string(),
    });
    let named = maya_scene_kit_edit::scene::stage_clean_execution_targets(&path, &targets).unwrap();
    assert_eq!(
        named.preview.removed_script_nodes,
        ["ExampleScript", decoded_name]
    );
    assert_eq!(named.artifact.bytes, header);

    let source = Loader::new(LoadOptions::default())
        .observe_path(&path)
        .unwrap()
        .source_fingerprint()
        .unwrap();
    let composite = stage_scene_edits(&path, Some(&source), &targets, &[]).unwrap();
    assert_eq!(composite.artifact.bytes, header);
}

#[test]
fn cp932_trail_backslash_is_part_of_script_name() {
    assert_cp932_name_clean(b"\x83\x5c", "ソ");
}

#[test]
fn invalid_cp932_script_name_keeps_replacement_character() {
    assert_cp932_name_clean(b"Example\x83", "Example\u{fffd}");
}
