use maya_scene_kit_edit::scene::{
    PathReplaceMode, PathReplaceRule, preview_replace_scene_paths, replace_scene_paths,
    stage_replace_scene_paths,
};

fn chunk(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

fn scene(forms: &[(&[u8; 4], &[u8; 4], &[u8])]) -> Vec<u8> {
    let mut root = b"Maya".to_vec();
    for (form, tag, payload) in forms {
        let mut inner = form.to_vec();
        inner.extend(chunk(tag, payload));
        root.extend(chunk(b"FOR4", &inner));
    }
    chunk(b"FOR4", &root)
}

fn rules() -> [PathReplaceRule; 1] {
    [PathReplaceRule {
        from: "example".into(),
        to: "sample".into(),
        mode: PathReplaceMode::Literal,
    }]
}

#[test]
fn reference_records_count_physical_changes_in_preview_stage_and_save() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.mb");
    let output = directory.path().join("Sample.mb");
    let bytes = scene(&[
        (
            b"FREF",
            b"FREF",
            b"asset/example/file.mb\0Example\0ExampleRN\0",
        ),
        (
            b"FRDI",
            b"FRDI",
            b"\x01asset/example/file.mb\0Example\0\x01\0ExampleRN\0",
        ),
    ]);
    std::fs::write(&input, &bytes).unwrap();
    let preview = preview_replace_scene_paths(&input, &rules()).unwrap();
    let staged = stage_replace_scene_paths(&input, &rules()).unwrap();
    let saved = replace_scene_paths(&input, &output, &rules()).unwrap();
    assert_eq!(saved.replaced_count, 2);
    assert_eq!(staged.changes.replacement_count, 2);
    assert_eq!(preview.items.len(), 1);
    assert_eq!(preview.items[0].replacement_count, 2);
    assert_eq!(preview.matched_count, 1);
    assert_eq!(preview, staged.preview);
    assert_eq!(std::fs::read(&input).unwrap(), bytes);
    assert_eq!(std::fs::read(&output).unwrap(), staged.artifact.bytes);
}

#[test]
fn binary_skips_are_measured_and_preserve_input_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.mb");
    let output = directory.path().join("Sample.mb");
    let bytes = scene(&[(b"RTFT", b"STR ", b"ftn\0\x01asset/example/\x83\x65.png\0")]);
    std::fs::write(&input, &bytes).unwrap();
    let staged = stage_replace_scene_paths(&input, &rules()).unwrap();
    let saved = replace_scene_paths(&input, &output, &rules()).unwrap();
    assert_eq!(staged.artifact.bytes, bytes);
    assert_eq!(staged.changes.replacement_count, 0);
    assert_eq!(staged.changes.skipped.as_ref().unwrap().non_utf8, 1);
    assert_eq!(saved.replaced_count, 0);
    assert_eq!(saved.skipped, staged.changes.skipped);
    assert_eq!(staged.preview.matched_count, 0);
    assert_eq!(std::fs::read(output).unwrap(), bytes);
}
