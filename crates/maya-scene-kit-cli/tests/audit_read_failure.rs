use std::{path::Path, process::Command};

fn audit(input: &Path, json: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"));
    command.arg("audit").arg(input);
    if json {
        command.arg("--json");
    }
    command.output().unwrap()
}

#[test]
fn unreadable_scene_json_matches_directory() {
    let dir = tempfile::tempdir().unwrap();
    let scene = dir.path().join("Example.mb");
    std::fs::write(&scene, b"FOR4").unwrap();
    let single = audit(&scene, true);
    let directory = audit(dir.path(), true);
    assert_eq!(single.status.code(), Some(20));
    assert_eq!(directory.status.code(), Some(20));
    let mut single: serde_json::Value = serde_json::from_slice(&single.stdout).unwrap();
    let mut directory: serde_json::Value = serde_json::from_slice(&directory.stdout).unwrap();
    assert_eq!(single["graph"]["traversal_issue_count"], 1);
    assert_eq!(single["graph"]["disposition"], "review");
    assert_eq!(
        single["graph"]["traversal_issues"][0]["scene_path"],
        scene.to_string_lossy().as_ref()
    );
    single.as_object_mut().unwrap().remove("input");
    directory.as_object_mut().unwrap().remove("input");
    assert_eq!(single, directory);
}

#[test]
fn unreadable_scene_text_returns_review() {
    let dir = tempfile::tempdir().unwrap();
    let scene = dir.path().join("Example.mb");
    std::fs::write(&scene, b"FOR4").unwrap();
    for input in [scene.as_path(), dir.path()] {
        let output = audit(input, false);
        assert_eq!(output.status.code(), Some(20));
    }
}
