use std::{path::PathBuf, process::Command};

use serde_json::Value;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn write_marker_free_indirect_exec_scene(path: &std::path::Path) {
    std::fs::write(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"markerFreeIndirectExec\";\n",
            "    setAttr \".st\" 0;\n",
            "    setAttr \".stp\" 1;\n",
            "    setAttr \".b\" -type \"string\" \"import builtins\\nrunner = getattr(builtins, \\\"exec\\\")\\nrunner(\\\"print('hi')\\\")\";\n",
        ),
    )
    .expect("write fixture");
}

#[test]
fn audit_cli_default_run_omits_legacy_default_rule_banner() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("marker_free_indirect_exec.ma");
    write_marker_free_indirect_exec_scene(&source);

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(&source)
        .arg("--json")
        .output()
        .expect("run audit cli");

    assert_eq!(output.status.code(), Some(10));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        !stderr.contains("using default rules:"),
        "unexpected legacy default-rule banner: {stderr}"
    );
}

#[test]
fn audit_cli_explicit_rule_still_emits_custom_rule_match() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("marker_free_indirect_exec.ma");
    write_marker_free_indirect_exec_scene(&source);

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(&source)
        .arg("--rule")
        .arg("exec")
        .arg("--json")
        .output()
        .expect("run audit cli");

    assert_eq!(output.status.code(), Some(10));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let json: Value = serde_json::from_str(&stdout).expect("audit json");
    let hits = json["hits"].as_array().expect("hits array");
    assert!(hits.iter().any(|hit| {
        hit["finding_id"].as_str() == Some("custom_rule_match")
            && hit["rule"].as_str() == Some("exec")
    }));
}

#[test]
fn audit_cli_json_includes_disposition_and_fact_sections() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("print_only.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"print_only\";\n",
            "\tsetAttr \".b\" -type \"string\" \"print('safe')\";\n",
            "\tsetAttr \".st\" 1;\n",
            "\tsetAttr \".stp\" 1;\n",
        ),
    )
    .expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(&source)
        .arg("--json")
        .output()
        .expect("run audit cli");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let json: Value = serde_json::from_str(&stdout).expect("audit json");
    assert_eq!(json["profile"].as_str(), Some("strict_default"));
    assert!(json["unit_summaries"].as_array().is_some());
    assert!(json["dependency_facts"].as_array().is_some());
    assert_eq!(
        json["files"][0]["disposition"].as_str(),
        Some("allow_with_notice")
    );
}

#[test]
fn audit_cli_text_uses_concise_unit_and_finding_sections() {
    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(repo_root().join("tests/02/sphere.mb"))
        .output()
        .expect("run audit cli");

    assert_eq!(output.status.code(), Some(20));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("- unit path="));
    assert!(stdout.contains("- review "));
    assert!(stdout.contains("review_id=mel_callback_proc_reference"));
    assert!(stdout.contains("reviews="));
    assert!(stdout.contains("(+"));
    assert!(!stdout.contains("; read-only MEL command"));
}
