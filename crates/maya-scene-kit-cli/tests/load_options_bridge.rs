use std::{path::PathBuf, process::Command};

use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn write_bad_node_info(dir: &std::path::Path) -> PathBuf {
    let bad_node_info = dir.join("bad_node_info.yaml");
    std::fs::write(&bad_node_info, "not: [valid").expect("write bad node info");
    bad_node_info
}

#[test]
fn dump_cli_respects_node_info_overlay_for_mb_reads() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().expect("tmpdir");
    let bad_node_info = write_bad_node_info(dir.path());

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("dump")
        .arg(&source)
        .arg("--node-info")
        .arg(&bad_node_info)
        .output()
        .expect("run dump cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("config error"));
}

#[test]
fn paths_cli_respects_node_info_overlay_for_mb_reads() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().expect("tmpdir");
    let bad_node_info = write_bad_node_info(dir.path());

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("paths")
        .arg(&source)
        .arg("--node-info")
        .arg(&bad_node_info)
        .output()
        .expect("run paths cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("config error"));
}

#[test]
fn audit_cli_respects_node_info_overlay_for_mb_reads() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().expect("tmpdir");
    let bad_node_info = write_bad_node_info(dir.path());

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(&source)
        .arg("--node-info")
        .arg(&bad_node_info)
        .output()
        .expect("run audit cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("config error"));
}

#[test]
fn replace_cli_respects_node_info_overlay_for_mb_reads() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().expect("tmpdir");
    let bad_node_info = write_bad_node_info(dir.path());
    let output_scene = dir.path().join("replaced.mb");

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("replace")
        .arg(&source)
        .arg("--rule")
        .arg("persp=perspRenamed")
        .arg("--out")
        .arg(&output_scene)
        .arg("--node-info")
        .arg(&bad_node_info)
        .output()
        .expect("run replace cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("config error"));
}

#[test]
fn dump_cli_ignores_scenekit_schema_env_overrides() {
    let source = repo_root().join("tests/02/sphere.mb");

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("dump")
        .arg(&source)
        .env("SCENEKIT_SCHEMA_ROOT", "/definitely/missing")
        .env("SCENEKIT_SCHEMA_DIR", "/definitely/missing")
        .env("SCENEKIT_REFE_SCHEMA", "/definitely/missing")
        .output()
        .expect("run dump cli");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn inspect_cli_rejects_mb_file_smaller_than_explicit_parse_budget() {
    let source = repo_root().join("tests/02/sphere.mb");

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("inspect")
        .arg(&source)
        .arg("--max-bytes")
        .arg("1")
        .output()
        .expect("run inspect cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("parse budget exceeded: max_parse_bytes"));
}
