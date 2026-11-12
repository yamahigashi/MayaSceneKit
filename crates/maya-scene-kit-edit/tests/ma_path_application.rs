use maya_scene_kit_edit::scene::{
    PathReplaceMode, PathReplaceOverride, PathReplaceRule, preview_replace_scene_paths,
    replace_scene_paths, stage_replace_scene_paths, stage_replace_scene_paths_with_overrides,
};

#[test]
fn preview_stage_and_save_report_actual_literal_changes_and_skips() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    let output = directory.path().join("Sample.ma");
    let original = b"//Maya ASCII 2026 scene\n// Codeset: 932\ncreateNode file -n \"Example\";\n    setAttr -l on \".ftn\" -type \"string\" \"old/old/Example.ma\";\r\ncreateNode file -n \"Sample\";\n    setAttr \".ftn\" -type \"string\" \"old/\x81?Sample.ma\";\r\ncreateNode file -n \"TestAsset\";\n    setAttr \".ftn\" -type \"string\" \"old/a\\d.ma\";\r\n";
    std::fs::write(&input, original).unwrap();
    let rules = [PathReplaceRule {
        from: "old/".into(),
        to: "asset/".into(),
        mode: PathReplaceMode::Literal,
    }];
    let preview = preview_replace_scene_paths(&input, &rules).unwrap();
    let stage = stage_replace_scene_paths(&input, &rules).unwrap();
    let saved = replace_scene_paths(&input, &output, &rules).unwrap();
    assert_eq!(preview.matched_count, 1);
    assert_eq!(preview.items.len(), 1);
    assert_eq!(stage.preview.items.len(), 3);
    assert_eq!(preview.items[0].replacement_count, 1);
    let control = &preview.items[0];
    assert!(control.skipped.is_empty());
    assert_eq!(stage.preview.items[1].replacement_count, 0);
    assert_eq!(stage.preview.items[2].replacement_count, 0);
    assert_eq!(
        stage.preview.items[1]
            .skipped
            .get(&maya_scene_kit_edit::scene::PathReplaceSkipReason::NonUtf8),
        Some(&1)
    );
    assert_eq!(
        stage.preview.items[2]
            .skipped
            .get(&maya_scene_kit_edit::scene::PathReplaceSkipReason::NonCanonicalEscape),
        Some(&1)
    );
    assert_eq!(stage.preview.matched_count, preview.matched_count);
    assert_eq!(stage.preview.applied_count, preview.applied_count);
    assert_eq!(stage.preview.items[0], preview.items[0]);
    assert_eq!(stage.changes.replacement_count, 1);
    let skipped = stage.changes.skipped.as_ref().unwrap();
    assert_eq!(skipped.non_utf8, 1);
    assert_eq!(skipped.non_canonical_escape, 1);
    assert_eq!(skipped.total(), 2);
    assert_eq!(saved.replaced_count, 1);
    assert_eq!(saved.skipped, stage.changes.skipped);
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/02/sphere.mb");
    assert!(
        stage_replace_scene_paths(binary, &[])
            .unwrap()
            .changes
            .skipped
            .is_some()
    );
    assert_eq!(std::fs::read(&input).unwrap(), original);
    assert_eq!(std::fs::read(&output).unwrap(), stage.artifact.bytes);
    assert!(
        stage
            .artifact
            .bytes
            .windows(b"asset/asset/Example.ma".len())
            .any(|w| w == b"asset/asset/Example.ma")
    );
}

#[test]
fn preview_counts_concatenated_literals_and_targeted_encoding_skips() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    std::fs::write(&input, b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\n    setAttr \".ftn\" -type \"string\" (\"old/\" + \"old/Example.ma\");\r\n").unwrap();
    let rules = [PathReplaceRule {
        from: "old/".into(),
        to: "asset/".into(),
        mode: PathReplaceMode::Literal,
    }];
    let stage = stage_replace_scene_paths(&input, &rules).unwrap();
    assert_eq!(stage.changes.replacement_count, 2);
    assert_eq!(stage.preview.matched_count, 1);
    assert_eq!(stage.preview.applied_count, 2);
    assert_eq!(stage.preview.items[0].replacement_count, 2);
    let crossing = [PathReplaceRule {
        from: "old/old".into(),
        to: "asset/Example".into(),
        mode: PathReplaceMode::Literal,
    }];
    let stage = stage_replace_scene_paths(&input, &crossing).unwrap();
    assert_eq!(stage.preview.matched_count, 0);
    assert_eq!(stage.changes.skipped.unwrap().crosses_concat_boundary, 2);

    let bytes = b"//Maya ASCII 2026 scene\n// Codeset: 932\ncreateNode file -n \"Example\";\n    setAttr -l on \".ftn\" -type \"string\" \"old/\x81?Example.ma\";\r\n";
    std::fs::write(&input, bytes).unwrap();
    let report = maya_scene_kit_observe::scene::collect_scene_paths(
        &input,
        maya_scene_kit_observe::scene::paths::PathKind::All,
    )
    .unwrap();
    let stage = stage_replace_scene_paths_with_overrides(
        &input,
        &[PathReplaceOverride {
            entry_index: 0,
            before_value: report.entries[0].value.clone(),
            after_value: "asset/Example.ma".into(),
        }],
    )
    .unwrap();
    assert_eq!(stage.artifact.bytes, bytes);
    assert_eq!(stage.preview.matched_count, 0);
    assert_eq!(stage.preview.items[0].replacement_count, 0);
    assert_eq!(stage.changes.replacement_count, 0);
    assert_eq!(stage.changes.skipped.unwrap().non_utf8, 1);
}

#[test]
fn identical_file_fingerprints_do_not_duplicate_preview_counts() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    std::fs::write(&input, b"//Maya ASCII 2026 scene\nfile -r -ns \"Example\" \"old/Sample.ma\";\nfile -r -ns \"Sample\" \"old/Sample.ma\";\n").unwrap();
    let rules = [PathReplaceRule {
        from: "old/".into(),
        to: "asset/".into(),
        mode: PathReplaceMode::Literal,
    }];
    let preview = preview_replace_scene_paths(&input, &rules).unwrap();
    assert_eq!(preview.matched_count, preview.items.len());
    assert!(preview.items.iter().all(|item| item.replacement_count == 1));
    let stage = stage_replace_scene_paths(&input, &rules).unwrap();
    assert_eq!(stage.preview, preview);
    assert_eq!(stage.changes.replacement_count, 2);
}

#[test]
fn duplicate_overrides_are_rejected_for_ascii_and_binary() {
    use maya_scene_kit_observe::scene::{collect_scene_paths, paths::PathKind};
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    std::fs::write(
        &input,
        b"//Maya ASCII 2026 scene\nfile -r \"old/Example.ma\";\n",
    )
    .unwrap();
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/mb/owner_delete/file_owner_delete.mb");
    let mut accepted = Vec::new();
    for path in [&input, &binary] {
        let report = collect_scene_paths(path, PathKind::All).unwrap();
        let before = report.entries[0].value.clone();
        let overrides = [
            PathReplaceOverride {
                entry_index: 0,
                before_value: before.clone(),
                after_value: "asset/Example.ma".into(),
            },
            PathReplaceOverride {
                entry_index: 0,
                before_value: before.clone(),
                after_value: "asset/Sample.ma".into(),
            },
        ];
        if stage_replace_scene_paths_with_overrides(path, &overrides).is_ok() {
            accepted.push(path.extension().unwrap().to_string_lossy().into_owned());
        }
    }
    assert!(
        accepted.is_empty(),
        "duplicate requests accepted: {accepted:?}"
    );
}

#[test]
fn replace_stage_preserves_mixed_literal_skip_reasons() {
    use maya_scene_kit_edit::scene::PathReplaceSkipReason;
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    std::fs::write(&input, b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" (\"asset/example/\" + \"asset\\d/file.tx\");\n").unwrap();
    let stage = stage_replace_scene_paths(
        &input,
        &[PathReplaceRule {
            from: "asset".into(),
            to: "Sample".into(),
            mode: PathReplaceMode::Literal,
        }],
    )
    .unwrap();
    assert_eq!(stage.preview.matched_count, 1);
    assert_eq!(stage.preview.applied_count, 1);
    assert_eq!(stage.preview.items.len(), 1);
    assert_eq!(stage.preview.items[0].replacement_count, 1);
    assert_eq!(
        stage.preview.items[0]
            .skipped
            .get(&PathReplaceSkipReason::NonCanonicalEscape),
        Some(&1)
    );
}

#[test]
fn replace_stage_preserves_all_skipped_entries() {
    use maya_scene_kit_edit::scene::PathReplaceSkipReason;
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    let bytes = b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" (\"asset/example/\" + \"file.tx\");\n";
    std::fs::write(&input, bytes).unwrap();
    let stage = stage_replace_scene_paths_with_overrides(
        &input,
        &[PathReplaceOverride {
            entry_index: 0,
            before_value: "asset/example/file.tx".into(),
            after_value: "asset/Sample/file.tx".into(),
        }],
    )
    .unwrap();
    assert_eq!(stage.artifact.bytes, bytes);
    assert_eq!(stage.preview.matched_count, 0);
    assert_eq!(stage.preview.applied_count, 0);
    assert_eq!(stage.preview.items.len(), 1);
    assert_eq!(
        stage.preview.items[0]
            .skipped
            .get(&PathReplaceSkipReason::CrossesConcatBoundary),
        Some(&2)
    );
}

#[test]
fn replace_stage_preserves_all_skipped_rule_entries() {
    use maya_scene_kit_edit::scene::PathReplaceSkipReason;
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    let bytes = b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset\\d/file.tx\";\n";
    std::fs::write(&input, bytes).unwrap();
    let stage = stage_replace_scene_paths(
        &input,
        &[PathReplaceRule {
            from: "asset".into(),
            to: "Sample".into(),
            mode: PathReplaceMode::Literal,
        }],
    )
    .unwrap();
    assert_eq!(stage.artifact.bytes, bytes);
    assert_eq!(stage.preview.matched_count, 0);
    assert_eq!(stage.preview.applied_count, 0);
    assert_eq!(stage.preview.items.len(), 1);
    assert_eq!(
        stage.preview.items[0]
            .skipped
            .get(&PathReplaceSkipReason::NonCanonicalEscape),
        Some(&1)
    );
}

#[test]
fn unmatched_undecodable_literals_do_not_add_staged_skip_items() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    let bytes = b"//Maya ASCII 2026 scene\n//Codeset: 932\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/\x81?file.tx\";\n";
    std::fs::write(&input, bytes).unwrap();
    let rules = [PathReplaceRule {
        from: "Sample".into(),
        to: "TestAsset".into(),
        mode: PathReplaceMode::Literal,
    }];
    let stage = stage_replace_scene_paths(&input, &rules).unwrap();
    assert_eq!(stage.artifact.bytes, bytes);
    assert_eq!(stage.changes.skipped.as_ref().unwrap().non_utf8, 1);
    assert!(stage.preview.items.is_empty());

    let bytes = b"//Maya ASCII 2026 scene\n//Codeset: 932\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" (\"asset/Sample/\" + \"example/\x81?file.tx\");\n";
    std::fs::write(&input, bytes).unwrap();
    let stage = stage_replace_scene_paths(&input, &rules).unwrap();
    assert_eq!(stage.changes.skipped.as_ref().unwrap().non_utf8, 1);
    assert_eq!(stage.preview.items.len(), 1);
    assert_eq!(stage.preview.items[0].replacement_count, 1);
    assert!(stage.preview.items[0].skipped.is_empty());
}

#[test]
fn public_rule_preview_keeps_applied_item_set() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("Example.ma");
    std::fs::write(&input, b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset\\d/file.tx\";\n").unwrap();
    let rules = [PathReplaceRule {
        from: "asset".into(),
        to: "Sample".into(),
        mode: PathReplaceMode::Literal,
    }];
    let preview = preview_replace_scene_paths(&input, &rules).unwrap();
    assert_eq!(preview.matched_count, 0);
    assert_eq!(preview.applied_count, 0);
    assert!(preview.items.is_empty());
    let stage = stage_replace_scene_paths(&input, &rules).unwrap();
    assert_eq!(stage.preview.items.len(), 1);
    assert!(!stage.preview.items[0].skipped.is_empty());
}
