use std::{path::Path, process::Command};

use sha2::{Digest, Sha256};

#[test]
fn complete_mb_fixtures_preserve_paths_and_audit_results() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (fixture, inspect_hash, paths_hash, disposition, findings) in [
        (
            "tests/01/skin.mb",
            "788307e01cad3724b88ea7e5c9f800ad8eb00b963f47ad90c7f2b116c2a76dae",
            "90a6c47a0d7d0c39f6bd611cf434b164ccc2153afc0dbb26616927584296765a",
            "allow_with_notice",
            0,
        ),
        (
            "tests/02/sphere.mb",
            "45b210d0c8e1d5c1e133da6ce2309d13f4c642e3633c078cab381f2ee70243f4",
            "f294ef47718493c569389d393fc2f65835de79f23ff766297dc4452e1d36d7ce",
            "review",
            0,
        ),
        (
            "tests/fixtures/mb/owner_delete/connected_file_owner_delete.mb",
            "302792c323dbe0cc69343a04233e366583258c73207557a16a46dd6ff073daaf",
            "d44735d5a0ed059cb9b608e6a97e606f27ea0d52d80d1ba1a1c254d4f94345c9",
            "allow_with_notice",
            0,
        ),
        (
            "tests/fixtures/mb/owner_delete/file_owner_delete.mb",
            "7523b311d2c89504b0dc73112a4f84d4fae6c91f36920b5c9a674692f30597ee",
            "82a5e47cced33c5bd3f1bf0df74d22f1d015f41ee8b77cee7fd6735d46e2f9d9",
            "allow_with_notice",
            0,
        ),
    ] {
        let run = |command: &str, json: bool| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"));
            cmd.current_dir(&root).arg(command).arg(fixture);
            if json {
                cmd.arg("--json");
            }
            cmd.output().unwrap()
        };
        let inspect = run("inspect", false);
        assert!(inspect.status.success());
        assert!(inspect.stdout.starts_with(b"completeness=complete\n"));
        assert_eq!(
            format!("{:x}", Sha256::digest(&inspect.stdout)),
            inspect_hash,
            "inspect {fixture}"
        );
        let paths = run("paths", true);
        assert!(paths.status.success());
        let mut paths_json: serde_json::Value = serde_json::from_slice(&paths.stdout).unwrap();
        sort_json_keys(&mut paths_json);
        let normalized = format!("{}\n", serde_json::to_string_pretty(&paths_json).unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(normalized.as_bytes())),
            paths_hash,
            "paths {fixture}"
        );
        let audit = run("audit", true);
        assert_eq!(
            audit.status.code(),
            Some(if disposition == "review" { 20 } else { 0 })
        );
        let value: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
        assert_eq!(
            value["files"][0]["disposition"], disposition,
            "audit {fixture}"
        );
        assert_eq!(
            value["files"][0]["finding_count"], findings,
            "findings {fixture}"
        );
    }
}

fn sort_json_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = std::mem::take(map).into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, mut value) in entries {
                sort_json_keys(&mut value);
                map.insert(key, value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                sort_json_keys(value);
            }
        }
        _ => {}
    }
}
