use std::{fs, process::Command};

#[test]
fn replace_reports_skips_for_single_file_and_directory() {
    let directory = tempfile::tempdir().unwrap();
    let input_directory = directory.path().join("input");
    fs::create_dir(&input_directory).unwrap();
    let input = input_directory.join("Example.ma");
    let prefix = b"//Maya ASCII 2026 scene\n// Codeset: 932\ncreateNode file -n \"Example\";\n    setAttr -l on \".ftn\" -type \"string\" \"old/old/Example.ma\";\r\ncreateNode file -n \"Sample\";\n    setAttr \".ftn\" -type \"string\" \"old/\x81?Sample.ma\";\r\ncreateNode file -n \"TestAsset\";\n    setAttr \".ftn\" -type \"string\" \"old/a\\d.ma\";\r\n";
    let original = [prefix.as_slice(), b"file -r \"unfinished"].concat();
    fs::write(&input, &original).unwrap();
    for is_directory in [false, true] {
        let output_path = directory
            .path()
            .join(if is_directory { "output" } else { "Sample.ma" });
        let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .arg("replace")
            .arg(if is_directory {
                &input_directory
            } else {
                &input
            })
            .args(["--rule", "old/=asset/"])
            .arg(if is_directory { "--out-dir" } else { "--out" })
            .arg(&output_path)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines.len(), 2, "{stdout}");
        assert!(lines[0].ends_with("replaced=1"), "{stdout}");
        assert_eq!(
            lines[1],
            format!(
                "skipped non_utf8=1 non_canonical_escape=1 unrepresentable=0 crosses_concat_boundary=0 unterminated_tail=1 unterminated_tail_from={} payload_rejected=0 unmatched_locator=0 duplicate_request=0",
                prefix.len()
            )
        );
        let saved = fs::read(if is_directory {
            output_path.join("Example.ma")
        } else {
            output_path
        })
        .unwrap();
        assert!(
            saved
                .windows(b"asset/asset/Example.ma".len())
                .any(|w| w == b"asset/asset/Example.ma")
        );
        assert!(saved.ends_with(b"file -r \"unfinished"));
    }
    fs::write(
        &input,
        b"//Maya ASCII 2026 scene\nfile -r \"old/Example.ma\";\r\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("replace")
        .arg(&input)
        .args(["--rule", "old/=asset/", "--out"])
        .arg(directory.path().join("TestScene.ma"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 1);
}
