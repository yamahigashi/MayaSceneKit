use std::process::{Command, Output, Stdio};

fn assert_no_panic(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert_ne!(output.status.code(), Some(101), "{stderr}");
}

fn write_scene(path: &std::path::Path) {
    std::fs::write(
        path,
        "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode transform -n \"Example\";\n",
    )
    .expect("write synthetic scene");
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_reads_existing_scene() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join(OsString::from_vec(b"Example\xff.ma".to_vec()));
    write_scene(&path);
    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(&path)
        .output()
        .unwrap();
    assert_no_panic(&output);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&format!("path={} format=ma", path.display()))
    );
}

#[test]
fn closed_stdout_preserves_audit_disposition() {
    let dir = tempfile::tempdir().unwrap();
    use std::io::Read;

    for index in 0..2048 {
        std::fs::write(
            dir.path().join(format!("Example{index}.ma")),
            r#"//Maya ASCII 2026 scene
requires maya "2026";
createNode script -n "ExampleScript";
    setAttr ".b" -type "string" "python(\"import os; os.system('echo Example')\")";
    setAttr ".st" 1;
    setAttr ".stp" 0;
"#,
        )
        .unwrap();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(dir.path())
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdout.take().unwrap();
    let mut buffer = [0; 1024];
    let read = pipe.read(&mut buffer).unwrap();
    drop(pipe);
    let output = child.wait_with_output().unwrap();
    assert_no_panic(&output);
    assert_eq!(output.status.code(), Some(10));
    assert!(output.stderr.is_empty());
    let expected = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(dir.path())
        .arg("--json")
        .output()
        .unwrap();
    assert_no_panic(&expected);
    assert_eq!(expected.status.code(), Some(10));
    assert!(expected.stdout.len() >= 4 * 1024 * 1024);
    assert!(expected.stderr.is_empty());
    assert!(read < expected.stdout.len());
}

#[cfg(unix)]
#[test]
fn non_utf8_scene_name_produces_valid_json() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join(OsString::from_vec(b"Example\xff.ma".to_vec()));
    let child = dir
        .path()
        .join(OsString::from_vec(b"Sample\xff.ma".to_vec()));
    write_scene(&child);
    std::fs::write(&path, b"//Maya ASCII 2026 scene\nrequires maya \"2026\";\nfile -r -ns \"Sample\" \"Sample\xff.ma\";\nfile -r -ns \"Missing\" \"Missing\xff.ma\";\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(dir.path())
        .arg("--json")
        .output()
        .unwrap();
    assert_no_panic(&output);
    assert_eq!(output.status.code(), Some(20));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json["graph"]["roots"][0]["path"],
        path.to_string_lossy().as_ref()
    );
    let edges = json["graph"]["edges"].as_array().unwrap();
    assert!(!edges.is_empty());
    assert!(
        edges
            .iter()
            .all(|edge| edge["source_path"].as_str().unwrap().contains('�'))
    );
    assert!(edges.iter().any(|edge| {
        edge["resolved_path"]
            .as_str()
            .is_some_and(|path| path.contains('�'))
    }));
    let issues = json["graph"]["traversal_issues"].as_array().unwrap();
    assert!(issues.iter().any(|issue| {
        ["scene_path", "source_path"]
            .iter()
            .any(|key| issue[key].as_str().is_some_and(|path| path.contains('�')))
    }));
}

#[cfg(unix)]
#[test]
fn full_stdout_reports_one_error() {
    let full = std::path::Path::new("/dev/full");
    if !full.exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let scene = dir.path().join("Example.ma");
    write_scene(&scene);
    for command in ["audit", "dump", "paths"] {
        let output = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
            .arg(command)
            .arg(&scene)
            .stdout(std::fs::OpenOptions::new().write(true).open(full).unwrap())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{command}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.lines().count(), 1, "{command}: {stderr}");
        assert!(
            stderr.starts_with("error: failed to write stdout"),
            "{command}: {stderr}"
        );
    }
}
