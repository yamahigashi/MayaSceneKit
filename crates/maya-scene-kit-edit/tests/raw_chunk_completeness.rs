#[test]
fn raw_chunks_refuse_stopped_mixed_width_section() {
    let mut bytes =
        b"FOR4\0\0\0\x2cMayaFOR4\0\0\0\x20HEADFOR8\0\0\0\x14TESTDATA\0\0\0\x01X".to_vec();
    bytes.extend_from_slice(&[0; 7]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("TestScene.mb");
    std::fs::write(&path, bytes).unwrap();
    assert!(maya_scene_kit_edit::scene::collect_raw_chunks(&path).is_err());
}
