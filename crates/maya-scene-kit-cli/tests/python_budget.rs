use std::process::Command;

#[test]
fn python_budget_preserves_cli_findings_and_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let body = format!("{}1", "-".repeat(8193));
    for (other, expected_exit, expected_count) in [
        ("", 20, 1),
        (
            "createNode script -n \"ExampleMel\";\nsetAttr \".st\" 1;\nsetAttr \".b\" -type \"string\" \"system(\\\"Example\\\");\";\n",
            10,
            2,
        ),
    ] {
        std::fs::write(&path, format!("//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"ExamplePython\";\nsetAttr \".st\" 1;\nsetAttr \".stp\" 1;\nsetAttr \".b\" -type \"string\" \"{body}\";\n{other}")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .arg("audit")
            .arg(&path)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected_exit));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["files"][0]["surface_count"], expected_count);
    }
}
