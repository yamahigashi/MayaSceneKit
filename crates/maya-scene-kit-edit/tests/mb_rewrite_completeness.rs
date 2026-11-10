use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, PathOwnerDeleteTarget, PathReplaceMode, PathReplaceRule,
    clean_execution_targets, remove_script_nodes, replace_scene_paths,
    stage_delete_path_owner_nodes,
};

#[test]
fn incomplete_mb_edits_do_not_create_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("Example.mb");
    let output = dir.path().join("ExampleOutput.mb");
    let bytes = b"FOR4\0\0\0\x18MayaFOR4\0\0\0\x04SCRPDATA\0\0\0\x20";
    std::fs::write(&input, bytes).unwrap();
    let error = remove_script_nodes(&input, &output).unwrap_err();
    assert!(
        error.to_string().contains("cannot rewrite incomplete"),
        "{error}"
    );
    assert!(!output.exists());
    let error = replace_scene_paths(
        &input,
        &output,
        &[PathReplaceRule {
            from: "asset/example".into(),
            to: "asset/sample".into(),
            mode: PathReplaceMode::Literal,
        }],
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("cannot rewrite incomplete"),
        "{error}"
    );
    assert!(!output.exists());
    let error = clean_execution_targets(
        &input,
        &output,
        &[ExecutionCleanTarget::MbOwnerForm {
            form: "SCRP".into(),
            node_offset: 12,
        }],
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("cannot rewrite incomplete"),
        "{error}"
    );
    assert!(!output.exists());
    assert_eq!(std::fs::read(&input).unwrap(), bytes);
    let mut payload = b"RTFT".to_vec();
    payload.extend_from_slice(&chunk(b"CREA", b"Example\0"));
    payload.extend_from_slice(&chunk(b"STR ", b"ftn\0\x00asset/example/file.tx\0"));
    let mut root_payload = b"Maya".to_vec();
    root_payload.extend_from_slice(&chunk(b"FOR4", &payload));
    root_payload.extend_from_slice(b"DATA\0\0\0\x20");
    let bytes = chunk(b"FOR4", &root_payload);
    std::fs::write(&input, &bytes).unwrap();
    let error = stage_delete_path_owner_nodes(
        &input,
        &[PathOwnerDeleteTarget {
            node_type: "file".into(),
            node_name: "Example".into(),
        }],
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("cannot rewrite incomplete"),
        "{error}"
    );
    assert!(!output.exists());
    assert_eq!(std::fs::read(&input).unwrap(), bytes);
}

fn chunk(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

#[test]
fn incomplete_mb_preview_composite_and_indexed_callers_refuse() {
    use maya_scene_kit_edit::scene::{
        MaterializeOptions, OperationMode, PatchPlanner, PathReplaceOverride,
    };
    use maya_scene_kit_observe::scene::{
        SceneFormat, ValidationState,
        paths::{ScenePathEntry, ScenePathsReport},
    };

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("Example.mb");
    let output = dir.path().join("ExampleOutput.mb");
    let mut owner = b"RTFT".to_vec();
    owner.extend_from_slice(&chunk(b"CREA", b"Example\0"));
    owner.extend_from_slice(&chunk(b"STR ", b"ftn\0\x00asset/example/file.tx\0"));
    let mut payload = b"Maya".to_vec();
    payload.extend_from_slice(&chunk(b"FOR4", &owner));
    payload.extend_from_slice(b"DATA\0\0\0\x20");
    let bytes = chunk(b"FOR4", &payload);
    std::fs::write(&input, &bytes).unwrap();
    let planner = PatchPlanner::new(
        MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    );
    let check = |error: maya_scene_kit_edit::scene::SceneToolError| {
        assert!(
            error.to_string().contains("cannot rewrite incomplete"),
            "{error}"
        );
        assert!(!output.exists());
        assert_eq!(std::fs::read(&input).unwrap(), bytes);
    };
    check(planner.preview_remove_script_nodes(&input).unwrap_err());
    check(
        planner
            .preview_remove_script_nodes_by_name(&input, &["ExampleScript".into()])
            .unwrap_err(),
    );
    for target in [
        ExecutionCleanTarget::ScriptNode {
            node_name: "ExampleScript".into(),
        },
        ExecutionCleanTarget::PluginRequire {
            rendered: "Example".into(),
        },
        ExecutionCleanTarget::MbOwnerForm {
            form: "RTFT".into(),
            node_offset: 12,
        },
    ] {
        check(
            planner
                .preview_clean_execution_targets(&input, &[target])
                .unwrap_err(),
        );
    }
    check(
        planner
            .remove_script_nodes_by_name(&input, &output, &["ExampleScript".into()])
            .unwrap_err(),
    );
    let report = ScenePathsReport {
        source: None,
        kind: Some(maya_scene_kit_observe::scene::paths::PathKind::All),
        scene_path: input.clone(),
        scene_format: SceneFormat::Mb,
        validation_state: ValidationState::CopiedUnvalidated,
        entries: vec![ScenePathEntry {
            node_type: "file".into(),
            node_name: "Example".into(),
            attr: "ftn".into(),
            value: "asset/example/file.tx".into(),
            meta: None,
        }],
    };
    check(
        planner
            .stage_replace_scene_paths_with_overrides_in_report(
                &report,
                &[PathReplaceOverride {
                    entry_index: 0,
                    before_value: "asset/example/file.tx".into(),
                    after_value: "asset/sample/file.tx".into(),
                }],
            )
            .unwrap_err(),
    );
    // Owner-only composition reaches materialization without an execution-clean preview.
    let report = maya_scene_kit_observe::scene::collect_scene_paths(
        &input,
        maya_scene_kit_observe::scene::paths::PathKind::All,
    )
    .unwrap();
    let error = planner
        .stage_scene_edit_plan(
            &maya_scene_kit_edit::scene::SceneEditPlan {
                report,
                clean_source: None,
                intents: vec![maya_scene_kit_edit::scene::SceneEditIntent::DeleteOwner(
                    PathOwnerDeleteTarget {
                        node_type: "file".into(),
                        node_name: "Example".into(),
                    },
                )],
            },
            &bytes,
        )
        .unwrap_err();
    assert!(error.to_string().contains("cannot rewrite incomplete"));
    assert!(!output.exists());
    assert_eq!(std::fs::read(&input).unwrap(), bytes);
}
