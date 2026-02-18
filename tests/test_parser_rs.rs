use std::path::PathBuf;

use maya_scene_kit::{parse_file, MayaBinaryParseError};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn parse_small_sample_root_and_header_group() {
    let mb = parse_file(repo_root().join("tests/02/sphere.mb")).unwrap();
    assert_eq!(mb.root.tag, "FOR8");
    assert_eq!(mb.root.form_type.as_deref(), Some("Maya"));
    assert!(!mb.root.children.is_empty());
    assert_eq!(mb.root.children[0].tag, "FOR8");
    assert_eq!(mb.root.children[0].form_type.as_deref(), Some("HEAD"));
}

#[test]
fn parse_legacy_sample() {
    let mb = parse_file(repo_root().join("tests/01/skin.mb")).unwrap();
    assert_eq!(mb.root.tag, "FOR8");
    assert_eq!(mb.root.form_type.as_deref(), Some("Maya"));
    assert!(mb.walk().len() > 10);
}

#[test]
fn parse_error_for_too_small_data() {
    let path = repo_root().join("tests/tmp_too_small.mb");
    std::fs::write(&path, b"FOR8").unwrap();
    let result = parse_file(&path);
    let _ = std::fs::remove_file(&path);
    assert!(matches!(result, Err(MayaBinaryParseError::Message(_))));
}
