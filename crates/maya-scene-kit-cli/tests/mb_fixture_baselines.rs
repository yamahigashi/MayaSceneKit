use std::{path::Path, process::Command};

use sha2::{Digest, Sha256};

#[test]
fn complete_mb_fixtures_preserve_paths_and_audit_results() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (fixture, inspect_hash, paths_hash, disposition, findings, surfaces, owners) in [
        (
            "tests/01/skin.mb",
            "788307e01cad3724b88ea7e5c9f800ad8eb00b963f47ad90c7f2b116c2a76dae",
            "6813f09148e620fce34303e611852a5b4670cdfc9d377fd14791d1a76eb37cb5",
            "allow_with_notice",
            0,
            1,
            0,
        ),
        (
            "tests/02/sphere.mb",
            "45b210d0c8e1d5c1e133da6ce2309d13f4c642e3633c078cab381f2ee70243f4",
            "067cb28ac4c22e0f7639b7525f66cc6bd501f17643cff8ef87e9c6c315c801da",
            "review",
            0,
            2,
            0,
        ),
        (
            "tests/fixtures/mb/owner_delete/connected_file_owner_delete.mb",
            "302792c323dbe0cc69343a04233e366583258c73207557a16a46dd6ff073daaf",
            "d37de92c2fe28f466b9216b77cd5d975b59c9deaa38ec94d7c9ed2f524a4be65",
            "allow_with_notice",
            0,
            2,
            2,
        ),
        (
            "tests/fixtures/mb/owner_delete/file_owner_delete.mb",
            "7523b311d2c89504b0dc73112a4f84d4fae6c91f36920b5c9a674692f30597ee",
            "707dcf1969e019aacb6f30d630c28e539cac6435e34a9db2c00d6396269d31d4",
            "allow_with_notice",
            0,
            2,
            2,
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
        let report = maya_scene_kit_observe::scene::collect_scene_paths(
            root.join(fixture),
            maya_scene_kit_observe::scene::paths::PathKind::All,
        )
        .unwrap();
        let targets = report
            .entries
            .iter()
            .filter(|entry| {
                entry
                    .meta
                    .as_ref()
                    .is_some_and(|meta| meta.trace_form.as_deref() == Some("RTFT"))
            })
            .map(|entry| maya_scene_kit_edit::scene::PathOwnerDeleteTarget {
                node_type: entry.node_type.clone(),
                node_name: entry.node_name.clone(),
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(targets.len(), owners, "owner candidates {fixture}");
        if !targets.is_empty() {
            let planner = maya_scene_kit_edit::scene::PatchPlanner::new(
                maya_scene_kit_edit::scene::MaterializeOptions::default()
                    .with_operation_mode(maya_scene_kit_edit::scene::OperationMode::Forensic),
            );
            let preview = planner
                .preview_delete_path_owner_nodes_in_report(&report, &targets)
                .unwrap();
            assert_eq!(
                preview.deleted_targets, targets,
                "owner candidates {fixture}"
            );
        }
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
            value["files"][0]["surface_count"], surfaces,
            "surfaces {fixture}"
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
