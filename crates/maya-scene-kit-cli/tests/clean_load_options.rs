use std::process::Command;

#[path = "../../maya-scene-kit-edit/tests/support/mb_chunks.rs"]
mod mb_chunks;

use mb_chunks::{build_mb_chunk, build_mb_form_with_alignment, build_mb_root};

#[test]
fn clean_rejects_input_over_byte_budget_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("Example.ma");
    let output = dir.path().join("Sample.ma");
    std::fs::write(
        &input,
        "//Maya ASCII 2026 scene\ncreateNode script -n ExampleScript;\n",
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("clean")
        .arg(&input)
        .arg(&output)
        .args(["--max-bytes", "1"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("budget"));
    assert!(!output.exists());
}

#[test]
fn clean_removes_script_owner_declared_by_node_info() {
    let dir = tempfile::tempdir().unwrap();
    let schema = dir.path().join("Example.yaml");
    std::fs::write(&schema, "version: 1\nnodes:\n  Example:\n    typeid: 0x45584d50\n    execution:\n      profiles:\n        - kind: script_node\n          body_attrs: [body]\n    attrs:\n      body: { unit: none, kind: scalar }\n").unwrap();
    for extension in ["mb", "ma"] {
        let input = dir.path().join(format!("Example.{extension}"));
        let output = dir.path().join(format!("Sample.{extension}"));
        let (source, expected) = if extension == "ma" {
            (
                b"//Maya ASCII 2026 scene\ncreateNode \"Example\" -name ExampleScript;\n    setAttr \".body\" -type \"string\" \"print(1)\";\ncreateNode transform -n \"Sample\";\n".to_vec(),
                b"//Maya ASCII 2026 scene\ncreateNode transform -n \"Sample\";\n".to_vec(),
            )
        } else {
            let kept =
                build_mb_form_with_alignment("XFRM", &[build_mb_chunk("CREA", b"Sample\0")], 4);
            (
                build_mb_root(&[
                    build_mb_form_with_alignment(
                        "EXMP",
                        &[
                            build_mb_chunk("CREA", b"ExampleScript\0"),
                            build_mb_chunk("STR ", b"body\0\x00print(1)\0"),
                        ],
                        4,
                    ),
                    kept.clone(),
                ]),
                build_mb_root(&[kept]),
            )
        };
        std::fs::write(&input, source).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .arg("clean")
            .arg(&input)
            .arg(&output)
            .arg("--node-info")
            .arg(&schema)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}: {}",
            extension,
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read(output).unwrap(), expected, "{extension}");
        assert!(String::from_utf8_lossy(&result.stdout).contains("removed=1"));
    }
}

#[test]
fn named_script_clean_control_matches_observed_escaped_name() {
    use maya_scene_kit_edit::scene::{ExecutionCleanTarget, clean_execution_targets};
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("Example.ma");
    let output = dir.path().join("Sample.ma");
    std::fs::write(
        &source,
        br#"//Maya ASCII 2026 scene
createNode script -n "Example\"Name";
    setAttr ".b" -type "string" "system(\"Example\");";
    setAttr ".st" 1;
createNode script -n "SampleScript";
    setAttr ".st" 1;
"#,
    )
    .unwrap();
    clean_execution_targets(
        &source,
        &output,
        &[ExecutionCleanTarget::ScriptNode {
            node_name: "Example\"Name".into(),
        }],
    )
    .unwrap();
    let bytes = std::fs::read(output).unwrap();
    assert_eq!(
        bytes,
        b"//Maya ASCII 2026 scene\ncreateNode script -n \"SampleScript\";\n    setAttr \".st\" 1;\n"
    );
}
