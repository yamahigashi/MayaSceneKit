use std::process::Command;

#[test]
fn script_history_is_denied_and_marked_in_json_and_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    for first in [
        "",
        "import os; os.system('echo Example')",
        "import os; os.system('echo Sample')",
    ] {
        std::fs::write(&path, format!("//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n ExampleScript; setAttr \".st\" 1; setAttr \".stp\" 1; setAttr \".b\" -type \"string\" \"{first}\"; setAttr \".b\" -type \"string\" \"import os; os.system('echo Sample')\";")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .arg("audit")
            .arg(&path)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["files"][0]["disposition"], "deny_malicious");
        let summaries = value["unit_summaries"].as_array().unwrap();
        assert_eq!(
            summaries
                .iter()
                .any(|summary| summary["origin"]["overwritten"] == true),
            !first.is_empty()
        );
        let findings = value["hits"].as_array().unwrap();
        let overwritten: Vec<_> = findings
            .iter()
            .filter(|finding| finding["origin"]["overwritten"] == true)
            .collect();
        if first.is_empty() {
            assert!(overwritten.is_empty());
        } else {
            assert!(!overwritten.is_empty());
            for finding in overwritten {
                assert_eq!(finding["origin"]["assignment_index"], 2);
            }
        }
        for finding in findings
            .iter()
            .filter(|finding| finding["origin"].get("overwritten").is_none())
        {
            assert!(finding["origin"].get("assignment_index").is_none());
        }
        let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .arg("audit")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(10));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("count=2"));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).contains("overwritten assignment_index=2"),
            !first.is_empty()
        );
    }
}
