use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, PathOwnerDeleteTarget, PathReplaceMode, PathReplaceRule,
    clean_execution_targets, remove_script_nodes, replace_scene_paths,
    stage_delete_path_owner_nodes,
};

#[test]
fn incomplete_mb_edits_do_not_create_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("Example.mb");
    let output = dir.path().join("ExampleOutput.mb");
    let bytes = b"FOR4\0\0\0\x18MayaFOR4\0\0\0\x04SCRPDATA\0\0\0\x20";
    std::fs::write(&input, bytes).unwrap();
    let error = remove_script_nodes(&input, &output).unwrap_err();
    assert!(
        error.to_string().contains("cannot rewrite incomplete"),
        "{error}"
    );
    assert!(!output.exists());
    let error = replace_scene_paths(
        &input,
        &output,
        &[PathReplaceRule {
            from: "asset/example".into(),
            to: "asset/sample".into(),
            mode: PathReplaceMode::Literal,
        }],
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("cannot rewrite incomplete"),
        "{error}"
    );
    assert!(!output.exists());
    let error = clean_execution_targets(
        &input,
        &output,
        &[ExecutionCleanTarget::MbOwnerForm {
            form: "SCRP".into(),
            node_offset: 12,
        }],
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("cannot rewrite incomplete"),
        "{error}"
    );
    assert!(!output.exists());
    assert_eq!(std::fs::read(&input).unwrap(), bytes);
    let mut payload = b"RTFT".to_vec();
    payload.extend_from_slice(&chunk(b"CREA", b"Example\0"));
    payload.extend_from_slice(&chunk(b"STR ", b"ftn\0\x00asset/example/file.tx\0"));
    let mut root_payload = b"Maya".to_vec();
    root_payload.extend_from_slice(&chunk(b"FOR4", &payload));
    root_payload.extend_from_slice(b"DATA\0\0\0\x20");
    let bytes = chunk(b"FOR4", &root_payload);
    std::fs::write(&input, &bytes).unwrap();
    let error = stage_delete_path_owner_nodes(
        &input,
        &[PathOwnerDeleteTarget {
            node_type: "file".into(),
            node_name: "Example".into(),
        }],
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("cannot rewrite incomplete"),
        "{error}"
    );
    assert!(!output.exists());
    assert_eq!(std::fs::read(&input).unwrap(), bytes);
}

fn chunk(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}
