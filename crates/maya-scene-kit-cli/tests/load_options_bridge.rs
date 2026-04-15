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

fn build_mb_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    while (out.len() - 16) % 8 != 0 {
        out.push(0);
    }
    out
}

fn build_mb_form(form: &str, children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = form.as_bytes().to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"FOR8");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn build_mb_root(children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = b"Maya".to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"FOR8");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(&payload);
    out
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

#[test]
fn inspect_cli_at_offset_prints_chunk_payload_fields() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("frdi_fbx_source.mb");
    let frdi_payload = b"\0\0\0\x02assets/example/ExampleAsset.fbx\0Source\0\x01\0Import_00_Example:SourceRN\0\0\0\0VERS|2020|\0FBX export\0";
    std::fs::write(
        &source,
        build_mb_root(&[build_mb_form(
            "FRDI",
            &[build_mb_chunk("FRDI", frdi_payload)],
        )]),
    )
    .expect("write mb fixture");

    for offset in ["40", "0x28"] {
        let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .arg("inspect")
            .arg(&source)
            .arg("--at")
            .arg(offset)
            .arg("--preview-bytes")
            .arg("64")
            .output()
            .expect("run inspect cli");

        assert_eq!(
            output.status.code(),
            Some(0),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
        assert!(stdout.contains("offset=0x00000028"), "{stdout}");
        assert!(stdout.contains("FRDI off=0x00000028"), "{stdout}");
        assert!(stdout.contains("payload=0x00000038.."), "{stdout}");
        assert!(
            stdout.contains("assets/example/ExampleAsset.fbx"),
            "{stdout}"
        );
        assert!(stdout.contains("Source"), "{stdout}");
    }
}
