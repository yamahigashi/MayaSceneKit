use maya_scene_kit_edit::scene::remove_script_nodes;

#[test]
fn complete_mixed_width_tree_refuses_clean_without_output() {
    let mut bytes =
        b"FOR4\0\0\0\x2cMayaFOR4\0\0\0\x20HEADFOR8\0\0\0\x14TESTDATA\0\0\0\x01X".to_vec();
    bytes.extend_from_slice(&[0; 7]);
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("Example.mb");
    let output = dir.path().join("Sample.mb");
    std::fs::write(&source, bytes).unwrap();
    let error = remove_script_nodes(&source, &output).unwrap_err();
    assert!(error.to_string().contains("MB section scan stopped"));
    assert!(!output.exists());
}
