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

const ALLOWLIST_SCENE: &str = "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"ExampleScriptNode\";\n\tsetAttr \".b\" -type \"string\" \"exec \\\"Example\\\"\";\n\tsetAttr \".st\" 1;\n";

fn write_allowlist_fixture(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    use maya_scene_kit_audit::{
        audit::{audit_script_nodes, build_script_audit_plan},
        scene::allowlist_surface_hash,
    };

    let scene = dir.join("allowlist_example.ma");
    std::fs::write(&scene, ALLOWLIST_SCENE).expect("write scene");
    let plan = build_script_audit_plan(vec![], 64).expect("audit plan");
    let report = audit_script_nodes(&scene, &plan).expect("audit report");
    let hash = allowlist_surface_hash(&report.surfaces[0].origin, "exec \"Example\"");
    let allowlist = dir.join("allowlist.json");
    std::fs::write(
        &allowlist,
        serde_json::json!({
            "version": 1,
            "entries": [{"hash": hash.to_string(), "codes": ["mel_exec"], "reason": "Example"}],
        })
        .to_string(),
    )
    .expect("write allowlist");
    (scene, allowlist)
}

fn run_audit_cli(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .args(args)
        .output()
        .expect("run audit cli")
}

#[test]
fn audit_cli_without_allowlist_omits_allowlist_fields() {
    let dir = tempdir().expect("tmpdir");
    let (scene, _) = write_allowlist_fixture(dir.path());

    let text = run_audit_cli(&[scene.as_os_str()]);
    assert_eq!(text.status.code(), Some(10));
    assert!(!String::from_utf8(text.stdout).unwrap().contains("allowed"));

    let json = run_audit_cli(&[scene.as_os_str(), "--json".as_ref()]);
    assert_eq!(json.status.code(), Some(10));
    let stdout = String::from_utf8(json.stdout).unwrap();
    assert!(!stdout.contains("allowed"), "{stdout}");
}

#[test]
fn audit_cli_allowlist_marks_matching_findings() {
    let dir = tempdir().expect("tmpdir");
    let (scene, allowlist) = write_allowlist_fixture(dir.path());

    let json = run_audit_cli(&[
        scene.as_os_str(),
        "--allowlist".as_ref(),
        allowlist.as_os_str(),
        "--json".as_ref(),
    ]);
    // The allowed exec finding no longer denies; its unit still asks for review.
    assert_eq!(json.status.code(), Some(20));
    let doc: Value = serde_json::from_str(&String::from_utf8(json.stdout).unwrap()).unwrap();
    assert_eq!(doc["allowed_finding_count"], 1);
    assert_eq!(doc["files"][0]["allowed_finding_count"], 1);
    assert_eq!(doc["finding_count"], 1);
    let hit = &doc["hits"][0];
    assert_eq!(hit["finding_id"], "mel_exec");
    assert_eq!(hit["allowed_by"]["source"], "app");
    assert!(
        hit["allowed_by"]["hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );

    let text = run_audit_cli(&[
        scene.as_os_str(),
        "--allowlist".as_ref(),
        allowlist.as_os_str(),
    ]);
    assert_eq!(text.status.code(), Some(20));
    let stdout = String::from_utf8(text.stdout).unwrap();
    let header = stdout.lines().next().unwrap();
    assert!(
        header.ends_with(" findings=1 reviews=0 notices=0 surfaces=1 allowed=1"),
        "{header}"
    );
    assert!(
        stdout.lines().any(|line| line.starts_with("- finding ")
            && line.contains("finding_id=mel_exec allowed=app node=")),
        "{stdout}"
    );

    let summary = run_audit_cli(&[
        scene.as_os_str(),
        "--allowlist".as_ref(),
        allowlist.as_os_str(),
        "--summary-only".as_ref(),
    ]);
    let summary = String::from_utf8(summary.stdout).unwrap();
    let lines = summary.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2, "{summary}");
    assert!(lines[0].ends_with(" allowed=1"), "{summary}");
    assert_eq!(lines[1], "total_findings=1 total_allowed=1");
}

#[test]
fn audit_cli_rejects_unreadable_or_invalid_allowlist() {
    let dir = tempdir().expect("tmpdir");
    let (scene, _) = write_allowlist_fixture(dir.path());
    let invalid = dir.path().join("invalid.json");
    std::fs::write(&invalid, r#"{"version":2,"entries":[]}"#).unwrap();
    let missing = dir.path().join("missing.json");

    for path in [&invalid, &missing] {
        let output = run_audit_cli(&[scene.as_os_str(), "--allowlist".as_ref(), path.as_os_str()]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("allowlist"), "{stderr}");
    }
}

#[test]
fn audit_cli_selective_unknown_statements_require_review() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("Example.ma");
    for statement in ["system \"echo Example\";", "system(\"echo Example\");"] {
        std::fs::write(&source, format!("//Maya ASCII 2026 scene\n{statement}\n")).unwrap();
        let output = run_audit_cli(&[source.as_os_str(), "--json".as_ref()]);
        assert_eq!(output.status.code(), Some(20), "{statement}");
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["files"][0]["disposition"], "review");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("unsupported_coverage")
        );
    }
    std::fs::write(&source, concat!(
        "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n",
        "fileInfo \"application\" \"Example\";\ncurrentUnit -l centimeter -a degree -t film;\n",
        "createNode transform -n \"Example\";\n    setAttr \".tx\" 1;\n",
        "connectAttr \"Example.tx\" \"Sample.tx\";\nrelationship \"link\" \"Example\" \"Sample\";\nselect -ne \"Example\";\nlockNode -l 1 \"Example\";\n",
    )).unwrap();
    let output = run_audit_cli(&[source.as_os_str(), "--json".as_ref()]);
    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["files"][0]["disposition"], "allow");
}

#[test]
fn audit_cli_context_binding_sets_deny_and_review_exit_codes() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("Example.ma");
    for (statement, code) in [
        (
            "createNode script -n \"Example\"; setAttr \".stp\" 1; setAttr \".b\" -type \"string\" \"exec('print(1)')\";",
            10,
        ),
        ("setAttr \".tx\" 1;", 20),
        (
            "select Example; setAttr \".before\" -type \"string\" \"Example\";",
            20,
        ),
        ("createNode transform -n \"Example\"; setAttr \".tx\" 1;", 0),
    ] {
        std::fs::write(&source, format!("//Maya ASCII 2026 scene\n{statement}")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .arg("audit")
            .arg(&source)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{statement}");
    }
}
