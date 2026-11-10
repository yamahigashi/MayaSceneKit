use std::process::Command;

#[test]
fn clean_writes_bare_output_name() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("Example.ma"),
        r#"//Maya ASCII 2026 scene
requires maya "2026";
createNode script -n "ExampleScript";
    setAttr ".b" -type "string" "python(\"import os; os.system('echo Example')\")";
    setAttr ".st" 1;
    setAttr ".stp" 0;
"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .args(["clean", "Example.ma", "Sample.ma"])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(directory.path().join("Sample.ma").is_file());
    let written = std::fs::read_to_string(directory.path().join("Sample.ma")).unwrap();
    assert!(!written.contains("ExampleScript"));
    assert!(!written.contains("os.system"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("warning"));
}

#[test]
fn to_ascii_writes_bare_issues_json_name() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("Example.ma"),
        "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode transform -n \"Example\";\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .args([
            "to-ascii",
            "Example.ma",
            "Sample.ma",
            "--issues-json",
            "Example.json",
        ])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(directory.path().join("Example.json").is_file());
}
