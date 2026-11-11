use maya_scene_kit_formats::ma::rewrite::remove_path_owner_nodes_from_ma;

#[test]
fn owner_deletion_preserves_cp932_bytes_outside_the_owner() {
    let prefix = b"//Maya ASCII 2026 scene\n//Codeset: 932\n// \x83\x54\x83\x93\x83\x76\x83\x8b\n";
    let owner = b"createNode file -n \"Example\";\n    setAttr \".ftn\" -type \"string\" \"asset/example/file.png\";\n";
    let suffix = b"createNode transform -n \"Sample\";\n// \x83\x54\x83\x93\x83\x76\x83\x8b\n";
    let input = [prefix.as_slice(), owner.as_slice(), suffix.as_slice()].concat();
    let targets = vec![("file".into(), "Example".into())];
    let (output, removed) = remove_path_owner_nodes_from_ma(&input, &targets);
    assert_eq!(removed, targets);
    assert_eq!(output, [prefix.as_slice(), suffix.as_slice()].concat());
}
