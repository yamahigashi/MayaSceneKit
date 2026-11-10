use std::{fs, process::Command};

fn check_discarded_result(name: &str, expression: &str) {
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let library = fs::read_dir(&deps)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name.starts_with("libmaya_mb-") && name.ends_with(".rlib")
        })
        .max_by_key(|path| fs::metadata(path).unwrap().modified().unwrap())
        .expect("compiled maya-mb library");
    let temp = std::env::temp_dir().join(format!("maya-mb-{name}-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    let source = temp.join("example.rs");
    let compile = |statement: &str| {
        fs::write(&source, format!("pub fn example() {{ {statement}; }}")).unwrap();
        Command::new("rustc")
            .args(["--edition=2024", "--crate-type=lib", "-Dunused-must-use"])
            .arg("--extern")
            .arg(format!("maya_mb={}", library.display()))
            .arg("-L")
            .arg(format!("dependency={}", deps.display()))
            .arg(&source)
            .arg("-o")
            .arg(temp.join("example.rlib"))
            .output()
            .unwrap()
    };
    let consumed = compile(&format!("let _result = {expression}"));
    assert!(
        consumed.status.success(),
        "{}",
        String::from_utf8_lossy(&consumed.stderr)
    );
    let discarded = compile(expression);
    fs::remove_dir_all(temp).unwrap();
    assert!(
        !discarded.status.success(),
        "discarding {name} must fail with unused-must-use denied"
    );
    assert!(String::from_utf8_lossy(&discarded.stderr).contains("unused"));
}

#[test]
fn scan_state_requires_acknowledgement() {
    check_discarded_result(
        "state",
        "maya_mb::visit_group_chunks_with_layout(&[], maya_mb::LayoutHints::new(), |_| {})",
    );
}

#[test]
fn walk_result_requires_acknowledgement() {
    check_discarded_result(
        "walk",
        "maya_mb::walk_group_chunks_with_layout(&[], maya_mb::LayoutHints::new())",
    );
}
