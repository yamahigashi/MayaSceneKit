#![cfg(unix)]

use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

use serde_json::Value;
use tempfile::tempdir;

const CLEAN: &str = "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n";

fn run(command: &str, input: &Path, json: bool) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"));
    cmd.arg(command).arg(input);
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

#[test]
fn audit_follows_file_symlink_and_reports_link_path() {
    let dir = tempdir().unwrap();
    let gate = dir.path().join("ExampleGate");
    let store = dir.path().join("ExampleStore");
    fs::create_dir(&gate).unwrap();
    fs::create_dir(&store).unwrap();
    fs::write(gate.join("Sample.ma"), CLEAN).unwrap();
    fs::write(store.join("Example.ma"), concat!(
        "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n",
        "createNode script -n \"ExampleScript\";\n",
        "setAttr \".st\" 0;\n",
        "setAttr \".b\" -type \"string\" \"python(\\\"import os; os.system('echo Example')\\\")\";\n",
    )).unwrap();
    let link = gate.join("Example.ma");
    symlink("../ExampleStore/Example.ma", &link).unwrap();
    symlink(".", gate.join("ExampleDirectory")).unwrap();
    let output = run("audit", &gate, true);
    assert_eq!(output.status.code(), Some(10));
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["graph"]["traversal_issue_count"], 1);
    assert_eq!(doc["files"][0]["outside_input_tree"], true);
    assert_eq!(
        doc["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|file| file["path"] == link.to_string_lossy().as_ref())
            .count(),
        1
    );
}

#[test]
fn audit_reports_skipped_directory_symlink() {
    let dir = tempdir().unwrap();
    let link = dir.path().join("ExampleDirectory");
    symlink(".", &link).unwrap();
    for json in [false, true] {
        let output = run("audit", dir.path(), json);
        assert_eq!(output.status.code(), Some(20));
        assert!(String::from_utf8_lossy(&output.stdout).contains(link.to_str().unwrap()));
        if json {
            let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(doc["graph"]["disposition"], "review");
            assert_eq!(doc["graph"]["traversal_issue_count"], 1);
        }
    }
}

#[test]
fn audit_reports_broken_symlink() {
    let dir = tempdir().unwrap();
    let link = dir.path().join("Example.ma");
    symlink("Missing.ma", &link).unwrap();
    for json in [false, true] {
        let output = run("audit", dir.path(), json);
        assert_eq!(output.status.code(), Some(20));
        assert!(String::from_utf8_lossy(&output.stdout).contains(link.to_str().unwrap()));
        if json {
            let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(doc["graph"]["disposition"], "review");
        }
    }
}

#[test]
fn dump_lists_file_symlink() {
    let dir = tempdir().unwrap();
    let gate = dir.path().join("ExampleGate");
    fs::create_dir(&gate).unwrap();
    fs::write(dir.path().join("Sample.ma"), CLEAN).unwrap();
    let link = gate.join("Example.ma");
    symlink("../Sample.ma", &link).unwrap();
    let output = run("dump", &gate, false);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains(link.to_str().unwrap()));
}

#[test]
fn aliases_and_link_chains_are_processed_once() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Sample.ma"), CLEAN).unwrap();
    symlink("Sample.ma", dir.path().join("Example.ma")).unwrap();
    symlink("Example.ma", dir.path().join("ExampleChain.ma")).unwrap();
    let output = run("audit", dir.path(), true);
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["files"].as_array().unwrap().len(), 1);
    assert_eq!(
        doc["files"][0]["path"],
        dir.path().join("Example.ma").to_str().unwrap()
    );
    assert_eq!(doc["files"][0]["aliases"].as_array().unwrap().len(), 2);
    let output = run("audit", dir.path(), false);
    assert!(String::from_utf8_lossy(&output.stdout).contains("aliases="));
}

#[test]
fn extensionless_external_link_and_non_scene_broken_link() {
    let dir = tempdir().unwrap();
    let gate = dir.path().join("ExampleGate");
    fs::create_dir(&gate).unwrap();
    fs::write(dir.path().join("Sample.ma"), CLEAN).unwrap();
    symlink("../Sample.ma", gate.join("Example")).unwrap();
    symlink("Missing", gate.join("Sample.txt")).unwrap();
    let output = run("audit", &gate, true);
    assert_eq!(output.status.code(), Some(0));
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["files"].as_array().unwrap().len(), 1);
    assert_eq!(doc["files"][0]["outside_input_tree"], true);
    let output = run("audit", &gate, false);
    assert!(String::from_utf8_lossy(&output.stdout).contains("outside_input_tree=true"));
}

#[test]
fn all_failed_with_collection_issue_still_exits_one() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Example.mb"), b"invalid").unwrap();
    symlink(".", dir.path().join("ExampleDirectory")).unwrap();
    assert_eq!(run("audit", dir.path(), true).status.code(), Some(1));
}

#[test]
fn adapter_warnings_include_aliases_and_skipped_links() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Sample.ma"), CLEAN).unwrap();
    symlink("Sample.ma", dir.path().join("Example.ma")).unwrap();
    symlink(".", dir.path().join("ExampleDirectory")).unwrap();
    symlink("Absent.ma", dir.path().join("Missing.ma")).unwrap();
    for command in ["dump", "paths", "replace"] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"));
        cmd.arg(command).arg(dir.path());
        let output_dir = tempdir().unwrap();
        if command == "replace" {
            cmd.arg("--rule")
                .arg("Example=Sample")
                .arg("--out-dir")
                .arg(output_dir.path());
        }
        let output = cmd.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        let lines: Vec<_> = stderr.lines().collect();
        assert_eq!(lines.len(), 3, "{stderr}");
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with(&format!(
                    "warning: {}: cannot read symlink target:",
                    dir.path().join("Missing.ma").display()
                )))
                .count(),
            1
        );
        assert!(
            lines.contains(
                &format!(
                    "warning: {}: directory symlink skipped without traversal",
                    dir.path().join("ExampleDirectory").display()
                )
                .as_str()
            )
        );
        assert!(
            lines.contains(
                &format!(
                    "note: {}: alias of {}",
                    dir.path().join("Sample.ma").display(),
                    dir.path().join("Example.ma").display()
                )
                .as_str()
            )
        );
    }
}

#[test]
fn binary_link_is_listed_once_with_alias() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Sample.mb"), b"FOR4\0\0\0\x04Maya").unwrap();
    symlink("Sample.mb", dir.path().join("Example.mb")).unwrap();
    let output = run("audit", dir.path(), true);
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["files"].as_array().unwrap().len(), 1);
    assert_eq!(doc["files"][0]["aliases"].as_array().unwrap().len(), 1);
}
