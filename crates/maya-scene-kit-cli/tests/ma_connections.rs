use std::process::Command;

#[test]
fn connected_python_body_is_denied_with_connection_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    std::fs::write(&path, "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode transform -n ExampleSource; addAttr -ln note -dt string; setAttr \".note\" -type \"string\" \"import os; os.system('echo Example')\"; createNode script -n ExampleScript; setAttr \".st\" 1; setAttr \".stp\" 1; connectAttr ExampleSource.note ExampleScript.b;").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(&path)
        .arg("--json")
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(10),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["files"][0]["disposition"], "deny_malicious");
    let origin = &json["hits"][0]["origin"];
    assert_eq!(origin["connection_source_plug"], "ExampleSource.note");
    assert_eq!(origin["lang"], "python");
    assert_eq!(origin["trigger"], "file_open");
}
