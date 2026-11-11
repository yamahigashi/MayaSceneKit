use std::process::Command;

#[test]
fn file_callback_aliases_produce_the_same_malicious_findings() {
    let dir = tempfile::tempdir().unwrap();
    let reference = dir.path().join("asset/example/file.ma");
    std::fs::create_dir_all(reference.parent().unwrap()).unwrap();
    std::fs::write(
        &reference,
        "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n",
    )
    .unwrap();
    let scene = dir.path().join("Example.ma");
    let mut baseline = None;
    for flag in ["-command", "-c"] {
        std::fs::write(
            &scene,
            format!(
                r#"//Maya ASCII 2026 scene
requires maya "2026";
file -r {flag} "Example" "system(\"echo Example\")" "asset/example/file.ma";
"#,
            ),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .current_dir(dir.path())
            .env("XDG_CACHE_HOME", dir.path().join(format!("cache{flag}")))
            .args(["audit", "--json"])
            .arg(&scene)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(10),
            "{flag}: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["files"][0]["disposition"], "deny_malicious");
        let findings: Vec<_> = result["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hit| {
                (
                    hit["finding_id"].clone(),
                    hit["severity"].clone(),
                    hit["rule"].clone(),
                )
            })
            .collect();
        assert!(!findings.is_empty());
        if let Some(expected) = &baseline {
            assert_eq!(&findings, expected);
        } else {
            baseline = Some(findings);
        }
    }
}
