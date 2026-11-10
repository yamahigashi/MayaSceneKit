use std::process::Command;

#[test]
fn truncated_mb_default_audit_exits_review_with_json_issue() {
    let mut bytes = b"FOR4".to_vec();
    bytes.extend_from_slice(&12u32.to_be_bytes());
    bytes.extend_from_slice(b"MayaDATA");
    bytes.extend_from_slice(&100u32.to_be_bytes());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    std::fs::write(&path, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(20),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["files"][0]["disposition"], "review");
    let issues = value["coverage_issues"].as_array().unwrap();
    assert_eq!(issues.len(), 1);
    let message = issues[0]["message"].as_str().unwrap();
    assert!(message.contains("Malformed"), "{message}");
    assert!(message.contains("truncated_groups=1"), "{message}");
}
