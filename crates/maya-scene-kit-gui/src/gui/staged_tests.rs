use super::{
    super::{MutateBlocked, MutationRejections},
    *,
};

#[gpui::test]
fn undo_clears_previous_replace_result(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.replace_rows(vec![mutation_row(1, &path)]);
        shell
            .apply_path_override_updates(
                vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                window,
                cx,
            )
            .unwrap();
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        assert!(shell.rows[0].replace_changes.is_some());
        shell
            .apply_path_override_updates(
                vec![(0, BTreeMap::from([(0, "asset/sample/second.tx".into())]))],
                window,
                cx,
            )
            .unwrap();
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, _, cx| {
        shell.run_menu_undo(cx);
        assert!(shell.rows[0].replace_changes.is_some());
        assert_eq!(shell.rows[0].staged.overrides()[&0], "asset/sample/file.tx");
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, _, cx| {
        assert!(shell.rows[0].replace_artifact_is_current());
        assert!(shell.rows[0].replace_preview().is_some());
        shell.run_menu_redo(cx);
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, _, cx| {
        assert!(shell.rows[0].replace_artifact_is_current());
        assert_eq!(
            shell.rows[0].staged.overrides()[&0],
            "asset/sample/second.tx"
        );
        shell.run_menu_undo(cx);
        shell.run_menu_undo(cx);
        assert!(matches!(shell.rows[0].staged, Staged::None));
        assert!(shell.rows[0].replace_changes.is_none());
    });
}

#[gpui::test]
fn missing_conversion_artifact_save_reports_error(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let original = fs::read(&path).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let mut row = mutation_row(1, &path);
        row.staged = Staged::ToAscii { report: None, artifact: None, destination_source: None };
        shell.replace_rows(vec![row]);
        let job = shell.next_row_job_id;
        shell.spawn_save_jobs(vec![0], window, cx);
        assert!(matches!(&shell.rows[0].status, FileStatus::Error(message) if message.contains("missing staged artifact")));
        assert_eq!(shell.next_row_job_id, job);
        assert!(shell.rows[0].busy.is_none());
        assert!(mutation_banner(shell).contains('1'));
    });
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[gpui::test]
fn replace_menu_reports_converted_and_busy_rows(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let mut converted = mutation_row(1, &path);
        converted.staged = Staged::ToAscii {
            destination_source: None,
            report: None,
            artifact: None,
        };
        let mut busy = mutation_row(2, &path);
        busy.busy = Some((RowOperation::Analyze, 99));
        shell.replace_rows(vec![converted, busy, mutation_row(3, &path)]);
        shell.run_replace(window, cx);
        let banner = mutation_banner(shell);
        assert!(banner.contains("1 busy"));
        assert!(banner.contains("1 row(s) with staged edits"));
        assert!(banner.contains("Example.ma"));
        assert_eq!(
            shell.replace_dialog.as_ref().unwrap().captured_row_ids,
            vec![3]
        );
    });
}

fn binary_scene(path_value: &str, script: bool, owner: bool) -> Vec<u8> {
    fn chunk(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut bytes = tag.to_vec();
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    }
    fn form(kind: &[u8; 4], parts: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = kind.to_vec();
        for part in parts {
            payload.extend_from_slice(part);
        }
        chunk(b"FOR4", &payload)
    }
    let mut parts = vec![form(
        b"RTFT",
        &[
            chunk(b"CREA", b"Example\0"),
            chunk(b"STR ", format!("ftn\0\0{path_value}\0").as_bytes()),
        ],
    )];
    if script {
        parts.push(form(
            b"SCRP",
            &[
                chunk(b"CREA", b"ExampleScript\0"),
                chunk(b"STR ", b"b\0\0python(\"print('Example')\");\0"),
            ],
        ));
    }
    if owner {
        parts.push(form(
            b"RTFT",
            &[
                chunk(b"CREA", b"SampleOwner\0"),
                chunk(b"STR ", b"ftn\0\0asset/example/second.tx\0"),
            ],
        ));
    }
    parts.push(form(b"XFRM", &[chunk(b"CREA", b"ExampleKeep\0")]));
    form(b"Maya", &parts)
}

fn dialog_composition_case(cx: &mut TestAppContext, binary: bool, clean: bool, delete: bool) {
    let directory = tempdir().unwrap();
    let path = directory
        .path()
        .join(if binary { "Example.mb" } else { "Example.ma" });
    let before = "asset/example/file.tx";
    let after = "asset/example/longer_name.tx";
    let command = "python(\"print('Example')\");";
    let original = if binary {
        binary_scene(before, true, true)
    } else {
        format!("//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode file -n \"Example\";\n    setAttr \".ftn\" -type \"string\" \"{before}\";\n{command}\ncreateNode file -n \"SampleOwner\";\n    setAttr \".ftn\" -type \"string\" \"asset/example/second.tx\";\ncreateNode transform -n \"ExampleKeep\";\n").into_bytes()
    };
    fs::write(&path, &original).unwrap();
    let mut row = observed_test_row(1, &path);
    row.selected = true;
    let clean_targets = if clean {
        let target = row
            .audit_report
            .as_ref()
            .unwrap()
            .surfaces
            .iter()
            .find_map(|surface| {
                let target = clean_target_for_execution_origin(&surface.origin)?;
                match &target {
                    ExecutionCleanTarget::MbOwnerForm { form, .. } if binary && form == "SCRP" => {
                        Some(target)
                    }
                    ExecutionCleanTarget::TopLevelCommand { .. } if !binary => Some(target),
                    _ => None,
                }
            })
            .unwrap();
        BTreeSet::from([target])
    } else {
        BTreeSet::new()
    };
    let owner_targets = if delete {
        BTreeSet::from([PathOwnerDeleteTarget {
            node_type: "file".into(),
            node_name: "SampleOwner".into(),
        }])
    } else {
        BTreeSet::new()
    };
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![row]);
        shell.stage_scene_edits_for_row(
            0,
            clean_targets.clone(),
            owner_targets.clone(),
            ResultTab::Paths,
            None,
            false,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        prepare_mutation_replace_dialog(shell, window, cx);
        let replacements = &mut shell
            .replace_dialog
            .as_mut()
            .unwrap()
            .preview
            .as_mut()
            .unwrap()
            .planned_overrides[0]
            .1;
        replacements[0].after_value = after.into();
        if delete {
            replacements.push(PathReplaceOverride {
                entry_index: 1,
                before_value: "asset/example/second.tx".into(),
                after_value: "asset/sample/second.tx".into(),
            });
        }
        shell.apply_replace_dialog(window, cx);
    });
    visual_cx.run_until_parked();
    let artifact = shell.update_in(visual_cx, |shell, window, cx| {
        let row = &shell.rows[0];
        assert!(matches!(row.staged, Staged::SceneEdits { .. }));
        assert_eq!(row.staged.clean().targets, clean_targets);
        assert_eq!(row.staged.owner_delete().targets, owner_targets);
        assert_eq!(row.staged.overrides().len(), 1);
        assert_eq!(row.staged.overrides()[&0], after);
        assert_eq!(row.replace_changes.as_ref().unwrap().replacement_count, 1);
        assert_eq!(row.replace_preview().as_ref().unwrap().matched_count, 1);
        assert_eq!(
            row.staged
                .reports()
                .paths_report
                .as_ref()
                .unwrap()
                .entries
                .len(),
            if delete { 1 } else { 2 },
            "binary={binary} clean={clean} delete={delete}: {:?}",
            row.staged.reports().paths_report.as_ref().unwrap().entries
        );
        let bytes = row.staged.artifact().as_ref().unwrap().bytes.clone();
        shell.run_save_selected(window, cx);
        bytes
    });
    visual_cx.run_until_parked();
    let saved = fs::read(&path).unwrap();
    assert_eq!(saved, artifact);
    if binary {
        assert_eq!(saved, binary_scene(after, !clean, !delete));
    } else {
        let text = String::from_utf8(saved.clone()).unwrap();
        assert!(text.contains(after));
        assert_eq!(text.contains(command), !clean);
        assert_eq!(text.contains("SampleOwner"), !delete);
        assert!(text.contains("ExampleKeep"));
        if !delete {
            assert_eq!(
                text,
                String::from_utf8(original)
                    .unwrap()
                    .replace(before, after)
                    .replace(command, "")
            );
        }
    }
    shell.read_with(visual_cx, |shell, _| {
        assert!(!shell.rows[0].has_staged_edits());
        assert_eq!(
            shell.rows[0]
                .replace_changes
                .as_ref()
                .unwrap()
                .replacement_count,
            1
        );
    });
}

#[gpui::test]
fn ascii_dialog_clean_uses_original_ranges(cx: &mut TestAppContext) {
    dialog_composition_case(cx, false, true, false);
}

#[gpui::test]
fn binary_dialog_clean_uses_original_offsets(cx: &mut TestAppContext) {
    dialog_composition_case(cx, true, true, false);
}

#[gpui::test]
fn binary_dialog_owner_delete_keeps_other_paths(cx: &mut TestAppContext) {
    dialog_composition_case(cx, true, false, true);
}

#[gpui::test]
fn binary_dialog_clean_and_owner_delete_keeps_other_paths(cx: &mut TestAppContext) {
    dialog_composition_case(cx, true, true, true);
}

#[gpui::test]
fn conversion_refuses_each_staged_variant_and_succeeds_after_save(cx: &mut TestAppContext) {
    for kind in 0..3 {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.mb");
        fs::write(&path, binary_scene("asset/example/file.tx", true, false)).unwrap();
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.state = test_state(directory.path(), "");
            shell.state.workspace_auto_analyze = false;
            let mut row = observed_test_row(1, &path);
            row.selected = true;
            shell.replace_rows(vec![row]);
            match kind {
                0 => {
                    shell
                        .apply_path_override_updates(
                            vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                            window,
                            cx,
                        )
                        .unwrap();
                }
                1 => {
                    shell.stage_scene_edits_for_row(
                        0,
                        BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                            node_name: "ExampleScript".into(),
                        }]),
                        BTreeSet::new(),
                        ResultTab::Audit,
                        None,
                        false,
                        window,
                        cx,
                    );
                }
                _ => shell.run_to_ascii(window, cx),
            }
        });
        visual_cx.run_until_parked();
        let disk = fs::read(&path).unwrap();
        shell.update_in(visual_cx, |shell, window, cx| {
            assert!(shell.rows[0].has_staged_edits());
            assert!(shell.rows[0].staged.artifact().is_some());
            let before = shell.rows[0].edit_state();
            let history = (
                shell.undo_stack.len(),
                shell.next_edit_history_sequence,
                shell.state.job_history.len(),
            );
            shell.run_to_ascii(window, cx);
            assert!(shell.rows[0].edit_state().same_as(&before));
            assert_eq!(
                history,
                (
                    shell.undo_stack.len(),
                    shell.next_edit_history_sequence,
                    shell.state.job_history.len()
                )
            );
            assert!(shell.rows[0].busy.is_none());
            assert!(mutation_banner(shell).contains("staged edits"));
            shell.run_save_selected(window, cx);
        });
        assert_eq!(fs::read(&path).unwrap(), disk);
        visual_cx.run_until_parked();
        shell.update_in(visual_cx, |shell, window, cx| {
            assert!(matches!(shell.rows[0].status, FileStatus::Saved));
            assert!(!shell.rows[0].has_staged_edits());
            shell.run_to_ascii(window, cx);
        });
        visual_cx.run_until_parked();
        shell.read_with(visual_cx, |shell, _| {
            assert!(matches!(
                shell.rows[0].staged,
                Staged::ToAscii {
                    destination_source: _,
                    report: Some(_),
                    artifact: Some(_)
                }
            ));
        });
    }
}

#[gpui::test]
fn save_promotes_dispatched_scene_reports(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![mutation_row(1, &path)]);
        shell.stage_scene_edits_for_row(
            0,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScript".into(),
            }]),
            BTreeSet::new(),
            ResultTab::Audit,
            None,
            false,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows[0].analyzed_audit_mode = None;
        shell.run_save_selected(window, cx);
        assert!(shell.rows[0].busy.is_some());
        shell.rows[0].staged = Staged::None;
    });
    visual_cx.run_until_parked();
    shell.read_with(visual_cx, |shell, _| {
        assert!(matches!(shell.rows[0].status, FileStatus::Saved));
        assert_eq!(
            shell.rows[0].analyzed_audit_mode,
            Some(AuditModePreference::StrictDefault)
        );
        assert!(
            shell.rows[0]
                .dump_report
                .as_ref()
                .unwrap()
                .script_entries
                .is_empty()
        );
    });
}

#[gpui::test]
fn dialog_hydrates_missing_report_and_isolates_failed_composition(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let first = directory.path().join("Example.ma");
    let second = directory.path().join("Sample.ma");
    write_mutation_scene(&first);
    write_mutation_scene(&second);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![mutation_row(1, &first), mutation_row(2, &second)]);
        shell.stage_scene_edits_for_row(
            0,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScript".into(),
            }]),
            BTreeSet::new(),
            ResultTab::Paths,
            None,
            false,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    let previous = shell.read_with(visual_cx, |shell, _| shell.rows[0].staged.clone());
    let changed = fs::read_to_string(&first)
        .unwrap()
        .replace("asset/example/file.tx", "asset/example/changed.tx");
    fs::write(&first, &changed).unwrap();
    shell.update_in(visual_cx, |shell, window, cx| {
        prepare_mutation_replace_dialog(shell, window, cx);
        shell.rows[1].paths_report = None;
        shell.apply_replace_dialog(window, cx);
    });
    visual_cx.run_until_parked();
    shell.read_with(visual_cx, |shell, _| {
        assert!(matches!(shell.rows[0].status, FileStatus::Error(_)));
        assert!(shell.rows[0].staged.same_as(&previous));
        assert_eq!(shell.rows[0].staged.clean().targets.len(), 1);
        assert!(shell.rows[0].staged.reports().audit_report.is_some());
        assert!(shell.rows[1].paths_report.is_some());
        assert!(shell.rows[1].replace_artifact_is_current());
    });
    assert_eq!(fs::read_to_string(first).unwrap(), changed);
}

#[gpui::test]
fn dialog_skip_preview_survives_composition_history_and_save(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let original = fs::read_to_string(&path)
        .unwrap()
        .replace("asset/example/file.tx", "asset/example/file\\d.tx");
    fs::write(&path, &original).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![mutation_row(1, &path)]);
        shell.stage_scene_edits_for_row(
            0,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScript".into(),
            }]),
            BTreeSet::new(),
            ResultTab::Paths,
            None,
            false,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        prepare_mutation_replace_dialog(shell, window, cx);
        shell.apply_replace_dialog(window, cx);
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        let changes = shell.rows[0].replace_changes.clone().unwrap();
        assert_eq!(changes.skipped.as_ref().unwrap().non_canonical_escape, 1);
        assert_eq!(
            shell.rows[0]
                .replace_preview()
                .as_ref()
                .unwrap()
                .matched_count,
            0
        );
        assert!(
            shell.rows[0]
                .replace_preview()
                .as_ref()
                .unwrap()
                .items
                .is_empty()
        );
        shell.run_menu_undo(cx);
        assert!(shell.rows[0].replace_changes.is_none());
        shell.run_menu_redo(cx);
        assert_eq!(shell.rows[0].replace_changes.as_ref(), Some(&changes));
        assert_eq!(
            shell.rows[0]
                .replace_preview()
                .as_ref()
                .unwrap()
                .matched_count,
            0
        );
        shell.run_save_selected(window, cx);
    });
    visual_cx.run_until_parked();
    shell.read_with(visual_cx, |shell, _| {
        assert!(!shell.rows[0].has_staged_edits());
        assert_eq!(
            shell.rows[0]
                .replace_changes
                .as_ref()
                .unwrap()
                .skipped
                .as_ref()
                .unwrap()
                .non_canonical_escape,
            1
        );
        assert_eq!(
            shell.rows[0]
                .replace_preview()
                .as_ref()
                .unwrap()
                .matched_count,
            0
        );
    });
    let saved = fs::read_to_string(path).unwrap();
    assert!(saved.contains("asset/example/file\\d.tx"));
    assert!(!saved.contains("ExampleScript"));
}

#[gpui::test]
fn cancellation_regeneration_failure_keeps_replace_and_rejects_old_result(cx: &mut TestAppContext) {
    for delete_owner in [false, true] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.ma");
        write_mutation_scene(&path);
        let original = fs::read(&path).unwrap();
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.state = test_state(directory.path(), "");
            shell.state.workspace_auto_analyze = false;
            shell.replace_rows(vec![mutation_row(1, &path)]);
            shell
                .apply_path_override_updates(
                    vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                    window,
                    cx,
                )
                .unwrap();
        });
        visual_cx.run_until_parked();
        let revision = shell.read_with(visual_cx, |shell, _| shell.rows[0].replace_generation);
        let stale = maya_scene_kit_edit::scene::stage_replace_scene_paths_with_overrides(
            &path,
            &[PathReplaceOverride {
                entry_index: 0,
                before_value: "asset/example/file.tx".into(),
                after_value: "asset/sample/old.tx".into(),
            }],
        )
        .unwrap();
        shell.update_in(visual_cx, |shell, window, cx| {
            let clean = if delete_owner {
                BTreeSet::new()
            } else {
                BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                    node_name: "ExampleScript".into(),
                }])
            };
            let owner = if delete_owner {
                BTreeSet::from([PathOwnerDeleteTarget {
                    node_type: "file".into(),
                    node_name: "Example".into(),
                }])
            } else {
                BTreeSet::new()
            };
            shell.stage_scene_edits_for_row(
                0,
                clean,
                owner,
                ResultTab::Paths,
                None,
                false,
                window,
                cx,
            );
        });
        visual_cx.run_until_parked();
        fs::remove_file(&path).unwrap();
        let depth = shell.update_in(visual_cx, |shell, window, cx| {
            let depth = shell.undo_stack.len();
            if delete_owner {
                shell.undo_context_path_targets(vec![(1, 0)], window, cx);
            } else {
                let audit = shell
                    .audit_rows
                    .iter()
                    .find(|row| row.clean_state == AuditRowCleanState::Staged)
                    .unwrap()
                    .clone();
                shell.undo_audit_table_clean(vec![audit], window, cx);
            }
            assert!(matches!(shell.rows[0].staged, Staged::Replace { .. }));
            assert!(shell.rows[0].replace_generation > revision);
            assert!(shell.rows[0].replace_changes.is_none());
            let before = shell.rows[0].edit_state();
            shell.apply_replace_artifact_result(1, revision, Ok(stale), cx);
            assert!(shell.rows[0].edit_state().same_as(&before));
            assert_eq!(shell.undo_stack.len(), depth + 1);
            depth + 1
        });
        visual_cx.run_until_parked();
        shell.read_with(visual_cx, |shell, _| {
            assert!(matches!(shell.rows[0].status, FileStatus::Error(_)));
            assert!(matches!(
                shell.rows[0].staged,
                Staged::Replace { artifact: None, .. }
            ));
            assert_eq!(shell.rows[0].staged.overrides()[&0], "asset/sample/file.tx");
            assert_eq!(shell.undo_stack.len(), depth);
        });
        assert!(!path.exists());
        fs::write(&path, original).unwrap();
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.run_save_selected(window, cx)
        });
        visual_cx.run_until_parked();
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.contains("ExampleScript"));
        assert!(saved.contains("asset/sample/file.tx"));
    }
}

#[gpui::test]
fn failed_restage_restores_previous_edits_and_can_save(cx: &mut TestAppContext) {
    for kind in 0..3 {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.ma");
        write_mutation_scene(&path);
        let original = fs::read(&path).unwrap();
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.state = test_state(directory.path(), "");
            shell.state.workspace_auto_analyze = false;
            shell.replace_rows(vec![mutation_row(1, &path)]);
            if kind > 0 {
                shell
                    .apply_path_override_updates(
                        vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                        window,
                        cx,
                    )
                    .unwrap();
            }
        });
        visual_cx.run_until_parked();
        if kind == 2 {
            shell.update_in(visual_cx, |shell, window, cx| {
                let sequence = shell.begin_edit_transaction(&[0]);
                shell.stage_scene_edits_for_row(
                    0,
                    BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                        node_name: "ExampleScript".into(),
                    }]),
                    BTreeSet::new(),
                    ResultTab::Paths,
                    sequence,
                    false,
                    window,
                    cx,
                );
            });
            visual_cx.run_until_parked();
        }
        let (previous, depth) = shell.read_with(visual_cx, |shell, _| {
            (shell.rows[0].edit_state(), shell.undo_stack.len())
        });
        fs::remove_file(&path).unwrap();
        shell.update_in(visual_cx, |shell, window, cx| {
            let sequence = shell.begin_edit_transaction(&[0]);
            shell.stage_scene_edits_for_row(
                0,
                BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                    node_name: "SampleScript".into(),
                }]),
                BTreeSet::new(),
                ResultTab::Paths,
                sequence,
                false,
                window,
                cx,
            );
        });
        visual_cx.run_until_parked();
        shell.read_with(visual_cx, |shell, _| {
            let row = &shell.rows[0];
            assert!(
                row.staged.same_as(&previous.staged),
                "previous variant and full edit payload must survive"
            );
            assert_eq!(
                row.applied_replace_preview,
                previous.applied_replace_preview
            );
            assert_eq!(row.replace_changes, previous.replace_changes);
            assert_eq!(
                row.staged.reports().source_bytes,
                previous.staged.reports().source_bytes
            );
            assert_eq!(shell.undo_stack.len(), depth);
            assert!(matches!(&row.status, FileStatus::Error(reason) if !reason.is_empty()));
            assert!(!mutation_banner(shell).is_empty());
            assert!(
                !row.staged
                    .clean()
                    .targets
                    .contains(&ExecutionCleanTarget::ScriptNode {
                        node_name: "SampleScript".into()
                    })
            );
            if kind == 0 {
                assert!(!row.dirty());
            }
        });
        fs::write(&path, &original).unwrap();
        if kind > 0 {
            shell.update_in(visual_cx, |shell, window, cx| {
                shell.run_save_selected(window, cx)
            });
            visual_cx.run_until_parked();
            assert_eq!(
                fs::read(&path).unwrap(),
                previous.staged.artifact().as_ref().unwrap().bytes
            );
            shell.read_with(visual_cx, |shell, _| {
                assert!(matches!(shell.rows[0].status, FileStatus::Saved))
            });
        }
    }
}

#[gpui::test]
fn failed_restage_does_not_enter_undo_redo_history(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let original = fs::read(&path).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![mutation_row(1, &path)]);
        let sequence = shell.begin_edit_transaction(&[0]);
        shell.stage_scene_edits_for_row(
            0,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScript".into(),
            }]),
            BTreeSet::new(),
            ResultTab::Paths,
            sequence,
            false,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    let previous = shell.read_with(visual_cx, |shell, _| shell.rows[0].staged.clone());
    shell.update_in(visual_cx, |shell, window, cx| {
        shell
            .apply_path_override_updates(
                vec![(0, BTreeMap::from([(0, "asset/sample/failed.tx".into())]))],
                window,
                cx,
            )
            .unwrap();
        fs::remove_file(&path).unwrap();
    });
    visual_cx.run_until_parked();
    fs::write(&path, &original).unwrap();
    shell.update_in(visual_cx, |shell, window, cx| {
        shell
            .apply_path_override_updates(
                vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                window,
                cx,
            )
            .unwrap();
    });
    visual_cx.run_until_parked();
    let after = shell.read_with(visual_cx, |shell, _| shell.rows[0].staged.clone());
    shell.update_in(visual_cx, |shell, _, cx| {
        assert_eq!(shell.undo_stack.len(), 2);
        shell.run_menu_undo(cx);
        assert!(shell.rows[0].staged.same_as(&previous));
        shell.run_menu_redo(cx);
        assert!(shell.rows[0].staged.same_as(&after));
    });
}

#[gpui::test]
fn redo_cancellation_regenerates_replace_preview(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![mutation_row(1, &path)]);
        shell
            .apply_path_override_updates(
                vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                window,
                cx,
            )
            .unwrap();
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        let sequence = shell.begin_edit_transaction(&[0]);
        shell.stage_scene_edits_for_row(
            0,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScript".into(),
            }]),
            BTreeSet::new(),
            ResultTab::Paths,
            sequence,
            false,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        let audit = shell
            .audit_rows
            .iter()
            .find(|row| row.clean_state == AuditRowCleanState::Staged)
            .unwrap()
            .clone();
        shell.undo_audit_table_clean(vec![audit], window, cx);
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, _, cx| {
        shell.run_menu_undo(cx);
        assert!(matches!(shell.rows[0].staged, Staged::SceneEdits { .. }));
        shell.run_menu_redo(cx);
    });
    visual_cx.run_until_parked();
    shell.read_with(visual_cx, |shell, _| {
        assert!(shell.rows[0].replace_artifact_is_current());
        assert_eq!(
            shell.rows[0]
                .replace_preview()
                .as_ref()
                .unwrap()
                .matched_count,
            1
        );
        assert_eq!(
            shell.rows[0]
                .replace_changes
                .as_ref()
                .unwrap()
                .replacement_count,
            1
        );
    });
}

#[gpui::test]
fn replace_dialog_noop_reports_counts(cx: &mut TestAppContext) {
    for already_replaced in [false, true] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.ma");
        write_mutation_scene(&path);
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.replace_rows(vec![mutation_row(1, &path)]);
            if already_replaced {
                shell
                    .apply_path_override_updates(
                        vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                        window,
                        cx,
                    )
                    .unwrap();
            }
        });
        visual_cx.run_until_parked();
        shell.update_in(visual_cx, |shell, window, cx| {
            prepare_mutation_replace_dialog(shell, window, cx);
            if !already_replaced {
                shell
                    .replace_dialog
                    .as_mut()
                    .unwrap()
                    .preview
                    .as_mut()
                    .unwrap()
                    .planned_overrides[0]
                    .1[0]
                    .after_value = "asset/example/file.tx".into();
            }
            let before = shell.rows[0].edit_state();
            let depth = shell.undo_stack.len();
            shell.apply_replace_dialog(window, cx);
            assert!(shell.rows[0].edit_state().same_as(&before));
            assert_eq!(shell.undo_stack.len(), depth);
            let banner = mutation_banner(shell);
            assert!(banner.contains("0 row(s) changed"), "{banner}");
            assert!(banner.contains("1 skipped"), "{banner}");
        });
    }
}

#[gpui::test]
fn replace_dialog_rejects_changed_entry_identity(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.replace_rows(vec![mutation_row(1, &path)]);
        prepare_mutation_replace_dialog(shell, window, cx);
        shell.rows[0].paths_report.as_mut().unwrap().entries[0].node_name = "Sample".into();
        shell.apply_replace_dialog(window, cx);
        assert!(!shell.rows[0].dirty());
        let banner = mutation_banner(shell);
        assert!(banner.contains("0 row(s) changed"), "{banner}");
        assert!(banner.contains("1 row(s) with a stale preview"), "{banner}");
    });
}

#[gpui::test]
fn save_all_reports_busy_and_missing_artifact_together(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let original = fs::read(&path).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![mutation_row(1, &path)]);
        shell.stage_scene_edits_for_row(
            0,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScript".into(),
            }]),
            BTreeSet::new(),
            ResultTab::Paths,
            None,
            false,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        // Inject artifact loss after a successful stage to exercise Save's error boundary.
        let Staged::SceneEdits { artifact, .. } = &mut shell.rows[0].staged else {
            panic!("scene edit")
        };
        *artifact = None;
        let mut busy = mutation_row(2, &path);
        busy.staged = shell.rows[0].staged.clone();
        busy.busy = Some((RowOperation::Save, 99));
        shell.rows.push(busy);
        shell.rebuild_row_id_index();
        shell.run_save_all(window, cx);
    });
    visual_cx.simulate_prompt_answer("Save All");
    visual_cx.run_until_parked();
    shell.read_with(visual_cx, |shell, _| {
        let banner = mutation_banner(shell);
        assert!(banner.contains("1 busy"), "{banner}");
        assert!(banner.contains("1 missing artifact"), "{banner}");
        assert!(banner.contains("save is in progress"), "{banner}");
        assert!(matches!(shell.rows[0].status, FileStatus::Error(_)));
        assert!(
            shell
                .state
                .job_history
                .iter()
                .any(|job| job.failed && job.operation == "save")
        );
    });
    assert_eq!(fs::read(path).unwrap(), original);
}

fn converted_edit_refusal_case(cx: &mut TestAppContext, operation: usize) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.mb");
    fs::write(&path, binary_scene("asset/example/file.tx", true, true)).unwrap();
    let original = fs::read(&path).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        let mut row = observed_test_row(1, &path);
        row.selected = true;
        shell.replace_rows(vec![row]);
        shell.run_to_ascii(window, cx);
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        assert!(matches!(
            shell.rows[0].staged,
            Staged::ToAscii {
                artifact: Some(_),
                ..
            }
        ));
        let previous = shell.rows[0].edit_state();
        let depth = (
            shell.undo_stack.len(),
            shell.redo_stack.len(),
            shell.next_edit_history_sequence,
            shell.next_row_job_id,
        );
        match operation {
            0 => {
                shell
                    .apply_path_override_updates(
                        vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                        window,
                        cx,
                    )
                    .unwrap();
            }
            1 => shell.stage_scene_edits_for_row(
                0,
                BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                    node_name: "ExampleScript".into(),
                }]),
                BTreeSet::new(),
                ResultTab::Audit,
                None,
                false,
                window,
                cx,
            ),
            2 => shell.stage_scene_edits_for_row(
                0,
                BTreeSet::new(),
                BTreeSet::from([PathOwnerDeleteTarget {
                    node_type: "file".into(),
                    node_name: "SampleOwner".into(),
                }]),
                ResultTab::Paths,
                None,
                false,
                window,
                cx,
            ),
            _ => {
                prepare_mutation_replace_dialog(shell, window, cx);
                shell.apply_replace_dialog(window, cx);
            }
        }
        assert!(shell.rows[0].edit_state().same_as(&previous));
        assert_eq!(
            depth,
            (
                shell.undo_stack.len(),
                shell.redo_stack.len(),
                shell.next_edit_history_sequence,
                shell.next_row_job_id
            )
        );
        let banner = mutation_banner(shell);
        assert!(banner.contains("1 row(s) with staged edits"), "{banner}");
        assert!(banner.contains("0 row(s) changed"), "{banner}");
    });
    visual_cx.run_until_parked();
    assert_eq!(fs::read(path).unwrap(), original);
}

#[gpui::test]
fn converted_row_refuses_inline_with_counts(cx: &mut TestAppContext) {
    converted_edit_refusal_case(cx, 0);
}
#[gpui::test]
fn converted_row_refuses_clean_with_counts(cx: &mut TestAppContext) {
    converted_edit_refusal_case(cx, 1);
}
#[gpui::test]
fn converted_row_refuses_owner_delete_with_counts(cx: &mut TestAppContext) {
    converted_edit_refusal_case(cx, 2);
}
#[gpui::test]
fn converted_row_refuses_dialog_with_counts(cx: &mut TestAppContext) {
    converted_edit_refusal_case(cx, 3);
}

#[gpui::test]
fn rejection_summary_preserves_all_counts_and_skip_details(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, _, cx| {
        shell.status_message = None;
        shell.report_mutation_rejections(
            MutationRejections {
                missing_artifacts: 2,
                ..Default::default()
            },
            cx,
        );
        shell.report_mutation_rejections(
            MutationRejections {
                blocked: vec![
                    (
                        1,
                        MutateBlocked::Busy {
                            name: "Example".into(),
                            operation: RowOperation::Save,
                        },
                    ),
                    (
                        2,
                        MutateBlocked::Edit {
                            name: "Sample".into(),
                        },
                    ),
                    (
                        3,
                        MutateBlocked::StalePreview {
                            name: "TestScene".into(),
                        },
                    ),
                ],
                ..Default::default()
            },
            cx,
        );
        let banner = mutation_banner(shell);
        for expected in [
            "1 busy",
            "1 row(s) with staged edits",
            "1 row(s) with a stale preview",
            "2 missing artifact",
            "save is in progress",
        ] {
            assert!(banner.contains(expected), "{expected}: {banner}");
        }
        shell.status_message = Some(BannerMessage::Raw("skipped non_canonical_escape=2".into()));
        shell.report_mutation_rejections(
            MutationRejections {
                blocked: vec![(
                    1,
                    MutateBlocked::StalePreview {
                        name: "Example".into(),
                    },
                )],
                ..Default::default()
            },
            cx,
        );
        let banner = mutation_banner(shell);
        assert!(banner.contains("1 row(s) with a stale preview"), "{banner}");
        assert!(banner.contains("non_canonical_escape=2"), "{banner}");
    });
}

#[test]
fn fixture_accessors_reject_implicit_variant_changes() {
    for accessor in 0..6 {
        let mut staged = Staged::ToAscii {
            destination_source: None,
            report: None,
            artifact: None,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match accessor {
            0 => {
                test_replace_state(&mut staged);
            }
            1 => {
                test_scene_state(&mut staged);
            }
            2 => {
                let mut empty = Staged::None;
                test_artifact(&mut empty);
            }
            3 => {
                test_overrides(&mut staged);
            }
            4 => {
                test_scene_state(&mut Staged::None);
            }
            _ => {
                test_replace_state(&mut Staged::None);
            }
        }));
        assert!(
            result.is_err(),
            "fixture accessor {accessor} silently changed state"
        );
    }
}

#[test]
fn audit_clean_states_distinguish_rejection_reasons() {
    for (reason, expected) in [
        (MutateBlocked::Missing, AuditRowCleanState::Unsupported),
        (
            MutateBlocked::StalePreview {
                name: "Example".into(),
            },
            AuditRowCleanState::Unsupported,
        ),
        (
            MutateBlocked::Staged {
                name: "Example".into(),
            },
            AuditRowCleanState::Staged,
        ),
        (
            MutateBlocked::Busy {
                name: "Example".into(),
                operation: RowOperation::Save,
            },
            AuditRowCleanState::Busy,
        ),
        (
            MutateBlocked::Edit {
                name: "Example".into(),
            },
            AuditRowCleanState::BlockedByOtherDirty,
        ),
    ] {
        assert_eq!(
            super::super::helpers::audit_clean_state_for_mutation(
                AuditRowCleanState::Available,
                Err(reason)
            ),
            expected
        );
    }
}

#[gpui::test]
fn owner_deleted_dialog_matches_report_noop(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.mb");
    fs::write(&path, binary_scene("asset/example/file.tx", false, true)).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        let mut row = observed_test_row(1, &path);
        row.selected = true;
        shell.replace_rows(vec![row]);
        shell.stage_scene_edits_for_row(
            0,
            BTreeSet::new(),
            BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".into(),
                node_name: "SampleOwner".into(),
            }]),
            ResultTab::Paths,
            None,
            false,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        let previous = shell.rows[0].edit_state();
        let depth = shell.undo_stack.len();
        prepare_mutation_replace_dialog(shell, window, cx);
        let replacement = &mut shell
            .replace_dialog
            .as_mut()
            .unwrap()
            .preview
            .as_mut()
            .unwrap()
            .planned_overrides[0]
            .1[0];
        replacement.entry_index = 1;
        replacement.before_value = "asset/example/second.tx".into();
        replacement.after_value = "asset/sample/second.tx".into();
        shell.apply_replace_dialog(window, cx);
        assert!(shell.rows[0].edit_state().same_as(&previous));
        assert_eq!(shell.undo_stack.len(), depth);
        let banner = mutation_banner(shell);
        assert!(banner.contains("0 row(s) changed"), "{banner}");
        assert!(banner.contains("1 skipped"), "{banner}");
    });
}

#[gpui::test]
fn replacement_skip_completion_preserves_rejection_counts(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let first = directory.path().join("Example.ma");
    let second = directory.path().join("Sample.ma");
    for path in [&first, &second] {
        write_mutation_scene(path);
    }
    let text = fs::read_to_string(&first)
        .unwrap()
        .replace("asset/example/file.tx", "asset/example/file\\d.tx");
    fs::write(&first, &text).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![mutation_row(1, &first), mutation_row(2, &second)]);
        prepare_mutation_replace_dialog(shell, window, cx);
        shell.rows[1].replace_generation += 1;
        shell.apply_replace_dialog(window, cx);
    });
    visual_cx.run_until_parked();
    shell.read_with(visual_cx, |shell, _| {
        assert!(!shell.rows[1].dirty());
        let banner = mutation_banner(shell);
        assert!(banner.contains("1 row(s) with a stale preview"), "{banner}");
        assert!(banner.contains("non_canonical_escape=1"), "{banner}");
    });
}

fn assert_save_source_guard(
    cx: &mut TestAppContext,
    scene_edits: bool,
    history: bool,
    retry: bool,
) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let original = fs::read(&path).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.state.workspace_auto_analyze = false;
        shell.state.backup_location = BackupLocationPreference::SameDirectory;
        shell.replace_rows(vec![mutation_row(1, &path)]);
        if scene_edits {
            let sequence = shell.begin_edit_transaction(&[0]);
            shell.stage_scene_edits_for_row(
                0,
                BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                    node_name: "ExampleScript".into(),
                }]),
                BTreeSet::new(),
                ResultTab::Paths,
                sequence,
                false,
                window,
                cx,
            );
        } else {
            shell
                .apply_path_override_updates(
                    vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                    window,
                    cx,
                )
                .unwrap();
        }
    });
    visual_cx.run_until_parked();
    let expected = shell.read_with(visual_cx, |shell, _| {
        shell.rows[0]
            .staged
            .artifact()
            .as_ref()
            .unwrap()
            .bytes
            .clone()
    });
    if history {
        shell.update_in(visual_cx, |shell, _, cx| shell.run_menu_undo(cx));
    }
    let changed = String::from_utf8(original.clone())
        .unwrap()
        .replace("ExampleScript", "SampleScriptX");
    fs::write(&path, &changed).unwrap();
    if history {
        shell.update_in(visual_cx, |shell, _, cx| shell.run_menu_redo(cx));
        visual_cx.run_until_parked();
    }
    shell.update_in(visual_cx, |shell, window, cx| {
        if history {
            shell.run_context_save_from_row(1, window, cx);
        } else if scene_edits {
            shell.run_save_all(window, cx);
        } else {
            shell.run_save_selected(window, cx);
        }
    });
    if scene_edits && !history {
        visual_cx.simulate_prompt_answer("Save All");
    }
    visual_cx.run_until_parked();
    assert_eq!(fs::read(&path).unwrap(), changed.as_bytes());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    shell.read_with(visual_cx, |shell, _| {
        assert!(shell.rows[0].dirty());
        assert!(matches!(&shell.rows[0].status, FileStatus::Error(message) if message.contains("changed on disk")));
        assert!(mutation_banner(shell).contains("re-analysed"));
    });
    if retry {
        fs::write(&path, &original).unwrap();
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.run_save_selected(window, cx)
        });
        visual_cx.run_until_parked();
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert_eq!(
            fs::read(directory.path().join("Example.backup.ma")).unwrap(),
            original
        );
        shell.read_with(visual_cx, |shell, _| {
            assert!(matches!(shell.rows[0].status, FileStatus::Saved))
        });
    }
}

#[gpui::test]
fn save_refuses_changed_replace_source(cx: &mut TestAppContext) {
    assert_save_source_guard(cx, false, false, false);
}

#[gpui::test]
fn save_refuses_changed_scene_edit_source(cx: &mut TestAppContext) {
    assert_save_source_guard(cx, true, false, false);
}

#[gpui::test]
fn save_refuses_changed_source_after_redo(cx: &mut TestAppContext) {
    assert_save_source_guard(cx, true, true, false);
}

#[gpui::test]
fn save_accepts_unchanged_source_after_refusal(cx: &mut TestAppContext) {
    assert_save_source_guard(cx, false, false, true);
}

#[gpui::test]
fn changed_report_source_preserves_rows_across_edit_entrypoints(cx: &mut TestAppContext) {
    for operation in 0..4 {
        let directory = tempdir().unwrap();
        let first = directory.path().join("Example.ma");
        let second = directory.path().join("Sample.ma");
        write_mutation_scene(&first);
        write_mutation_scene(&second);
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.settings_save_disabled_path = Some(directory.path().join("settings.json"));
            shell.state = test_state(directory.path(), "");
            shell.state.workspace_auto_analyze = false;
            shell.replace_rows(vec![mutation_row(1, &first), mutation_row(2, &second)]);
            shell
                .apply_path_override_updates(
                    vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                    window,
                    cx,
                )
                .unwrap();
        });
        visual_cx.run_until_parked();
        if operation == 0 {
            shell.update_in(visual_cx, |shell, window, cx| {
                prepare_mutation_replace_dialog(shell, window, cx);
            });
            visual_cx.run_until_parked();
        }
        let previous = shell.read_with(visual_cx, |shell, _| shell.rows[0].staged.clone());
        fs::write(
            &first,
            fs::read_to_string(&first)
                .unwrap()
                .replace("ExampleScript", "SampleScript"),
        )
        .unwrap();
        shell.update_in(visual_cx, |shell, window, cx| match operation {
            0 => {
                shell.run_replace_preview(window, cx);
            }
            1 => {
                shell
                    .apply_path_override_updates(
                        vec![
                            (0, BTreeMap::from([(0, "asset/sample/next.tx".into())])),
                            (1, BTreeMap::from([(0, "asset/sample/next.tx".into())])),
                        ],
                        window,
                        cx,
                    )
                    .unwrap();
            }
            2 => {
                let revision = shell.rows[0].replace_generation;
                shell.spawn_replace_artifact_refresh(1, revision, cx);
                shell
                    .apply_path_override_updates(
                        vec![(1, BTreeMap::from([(0, "asset/sample/next.tx".into())]))],
                        window,
                        cx,
                    )
                    .unwrap();
            }
            _ => {
                for index in 0..2 {
                    shell.stage_scene_edits_for_row(
                        index,
                        BTreeSet::new(),
                        BTreeSet::from([PathOwnerDeleteTarget {
                            node_type: "file".into(),
                            node_name: "Example".into(),
                        }]),
                        ResultTab::Paths,
                        None,
                        false,
                        window,
                        cx,
                    );
                }
            }
        });
        visual_cx.run_until_parked();
        shell.read_with(visual_cx, |shell, _| {
            assert!(
                matches!(shell.rows[0].status, FileStatus::Error(_)),
                "operation {operation}, banner {}, dialog {:?}",
                mutation_banner(shell),
                shell.replace_dialog.as_ref().map(|dialog| (
                    dialog.generation,
                    dialog.is_previewing,
                    dialog.preview_signature.is_some(),
                    dialog.preview.as_ref().map(|preview| &preview.failed_files)
                ))
            );
            assert!(
                shell.rows[0].staged.same_as(&previous),
                "operation {operation}"
            );
            assert!(
                mutation_banner(shell)
                    .contains(&shell.i18n().text("banner.edit_requires_reanalysis")),
                "operation {operation}, banner {}",
                mutation_banner(shell)
            );
            assert!(
                !matches!(shell.rows[1].status, FileStatus::Error(_)),
                "operation {operation}"
            );
            if operation == 0 {
                assert_eq!(
                    shell
                        .replace_dialog
                        .as_ref()
                        .unwrap()
                        .preview
                        .as_ref()
                        .unwrap()
                        .previewable_row_ids,
                    vec![2]
                );
            } else {
                assert!(
                    shell.rows[1].staged.artifact().is_some(),
                    "operation {operation}"
                );
            }
        });
    }
}

#[gpui::test]
fn unstable_source_rejection_preserves_staged_state(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.settings_save_disabled_path = Some(directory.path().join("settings.json"));
        shell.replace_rows(vec![mutation_row(1, &path)]);
        shell
            .apply_path_override_updates(
                vec![(0, BTreeMap::from([(0, "asset/sample/file.tx".into())]))],
                window,
                cx,
            )
            .unwrap();
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, _, cx| {
        let previous = shell.rows[0].staged.clone();
        let error =
            maya_scene_kit_observe::scene::SceneToolError::SourceUnstable { path: path.clone() };
        assert!(shell.reject_changed_report_source(1, &error, cx));
        assert!(matches!(shell.rows[0].status, FileStatus::Error(_)));
        assert!(
            mutation_banner(shell).contains(&shell.i18n().text("banner.edit_requires_reanalysis"))
        );
        assert!(shell.rows[0].staged.same_as(&previous));
    });
}

#[gpui::test]
fn save_conversion_preserves_source_reports(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.mb");
    fs::write(&path, binary_scene("asset/example/file.tx", true, false)).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        let mut row = mutation_row(1, &path);
        row.selected = false;
        row.staged = Staged::ToAscii {
            destination_source: None,
            report: None,
            artifact: None,
        };
        let paths = serde_json::to_value(&row.paths_report).unwrap();
        let audit = serde_json::to_value(&row.audit_report).unwrap();
        let state = row.audit_file_state;
        let mode = row.analyzed_audit_mode;
        shell.replace_rows(vec![row]);
        shell.deliver_job_result_for_test(
            1,
            RowOperation::Save,
            RowJobResult::Save {
                promotion: SavePromotion::Unanalyzed,
                observation_error: None,
                saved_paths_report: None,
                replace_changes: None,
                replace_preview: None,
                output_path: path.with_extension("ma"),
                audit_file_state: None,
            },
            None,
            window,
            cx,
        );
        let row = &shell.rows[0];
        assert_eq!(serde_json::to_value(&row.paths_report).unwrap(), paths);
        assert_eq!(serde_json::to_value(&row.audit_report).unwrap(), audit);
        assert_eq!(row.audit_file_state, state);
        assert_eq!(row.analyzed_audit_mode, mode);
        assert!(matches!(row.staged, Staged::None));
        assert!(matches!(row.status, FileStatus::Saved));
    });
}

#[gpui::test]
fn save_changed_file_does_not_promote_reports(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let written_state = GuiFileState::read(&path).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        let mut row = mutation_row(1, &path);
        row.selected = false;
        let reports = StagedReports {
            audit_report: row.audit_report.clone(),
            dump_report: row.dump_report.clone(),
            audit_mode: Some(AuditModePreference::StrictDefault),
            audit_plan_fingerprint: Some(shell.audit_plan_fingerprint.clone()),
            ..Default::default()
        };
        let paths = row.paths_report.clone();
        shell.replace_rows(vec![row]);
        fs::write(&path, "// Example changed scene\n").unwrap();
        assert_ne!(Some(written_state), GuiFileState::read(&path).ok());
        shell.rows[0].busy = Some((RowOperation::Save, 99));
        shell.apply_job_result(
            (1, 99),
            RowOperation::Save,
            RowJobResult::Save {
                promotion: SavePromotion::SceneEdits(reports),
                observation_error: None,
                saved_paths_report: paths,
                replace_changes: None,
                replace_preview: None,
                output_path: path.clone(),
                audit_file_state: Some(written_state),
            },
            None,
            window,
            cx,
        );
        assert!(shell.rows[0].paths_report.is_none());
        assert!(shell.rows[0].dump_report.is_none());
        assert!(shell.rows[0].audit_report.is_none());
        assert!(shell.rows[0].analyzed_audit_mode.is_none());
    });
}

#[gpui::test]
fn save_observation_failure_displays_error(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        let mut row = mutation_row(1, &path);
        row.selected = false;
        shell.replace_rows(vec![row]);
        shell.deliver_job_result_for_test(
            1,
            RowOperation::Save,
            RowJobResult::Save {
                promotion: SavePromotion::Unanalyzed,
                observation_error: Some("Example observation failure".into()),
                saved_paths_report: None,
                replace_changes: None,
                replace_preview: None,
                output_path: path.clone(),
                audit_file_state: GuiFileState::read(&path).ok(),
            },
            None,
            window,
            cx,
        );
        assert!(matches!(&shell.rows[0].status, FileStatus::SavedWithWarning(message) if message.contains("Example observation failure")));
        assert!(shell.rows[0].status_label(&shell.i18n()).contains("Saved"));
        assert!(
            shell.rows[0]
                .status_label(&shell.i18n())
                .contains("Example observation failure")
        );
        shell.rows[0].selected = true;
        assert!(
            super::super::selected_row_error_lines(shell)[0]
                .contains("Example observation failure")
        );
        assert!(shell.rows[0].analyzed_audit_mode.is_none());
        shell.run_selected_auto_analysis(window, cx);
        assert!(shell.rows[0].busy.is_some());
    });
}

fn assert_ascii_save_refuses_destination_change(cx: &mut TestAppContext, binary: bool) {
    let directory = tempdir().unwrap();
    let path = directory
        .path()
        .join(if binary { "Example.mb" } else { "Example.ma" });
    if binary {
        fs::write(&path, binary_scene("asset/example/file.tx", true, false)).unwrap();
    } else {
        write_mutation_scene(&path);
    }
    let output = path.with_extension("ma");
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.replace_rows(vec![mutation_row(1, &path)]);
        shell.run_to_ascii(window, cx);
    });
    visual_cx.run_until_parked();
    fs::write(&output, "// Example external bytes\n").unwrap();
    shell.update_in(visual_cx, |shell, window, cx| {
        assert!(shell.rows[0].staged.artifact().is_some());
        shell.run_save_selected(window, cx);
    });
    visual_cx.run_until_parked();
    shell.read_with(visual_cx, |shell, _| {
        assert_eq!(fs::read(&output).unwrap(), b"// Example external bytes\n");
        assert!(shell.rows[0].staged.artifact().is_some());
        assert!(matches!(&shell.rows[0].status, FileStatus::Error(message) if message == &shell.i18n().text("banner.save_source_changed")));
    });
}

#[gpui::test]
fn ascii_save_refuses_changed_input_destination(cx: &mut TestAppContext) {
    assert_ascii_save_refuses_destination_change(cx, false);
}

#[gpui::test]
fn ascii_save_refuses_created_destination(cx: &mut TestAppContext) {
    assert_ascii_save_refuses_destination_change(cx, true);
}

#[gpui::test]
fn ascii_staging_refuses_changed_analysis_source(cx: &mut TestAppContext) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    write_mutation_scene(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(directory.path(), "");
        shell.replace_rows(vec![mutation_row(1, &path)]);
        let mut changed = fs::read(&path).unwrap();
        changed.extend_from_slice(b"\n// Example external bytes\n");
        fs::write(&path, changed).unwrap();
        shell.run_to_ascii(window, cx);
    });
    visual_cx.run_until_parked();
    shell.read_with(visual_cx, |shell, _| {
        assert!(matches!(shell.rows[0].staged, Staged::None));
        assert!(matches!(&shell.rows[0].status, FileStatus::Error(message) if message == &shell.i18n().text("banner.edit_requires_reanalysis")));
    });
}

fn ascii_content_destination_case(cx: &mut TestAppContext, extension: &str) {
    for created in [false, true] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example").with_extension(extension);
        let output = path.with_extension("ma");
        write_mutation_scene(&path);
        let original = fs::read(&path).unwrap();
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.state = test_state(directory.path(), "");
            shell.replace_rows(vec![mutation_row(1, &path)]);
            shell.run_to_ascii(window, cx);
        });
        visual_cx.run_until_parked();
        shell.update_in(visual_cx, |shell, window, cx| {
            assert!(matches!(
                &shell.rows[0].staged,
                Staged::ToAscii {
                    destination_source: None,
                    artifact: Some(_),
                    ..
                }
            ));
            if created {
                fs::write(&output, "// Example external bytes\n").unwrap();
            }
            shell.run_save_selected(window, cx);
        });
        visual_cx.run_until_parked();
        shell.read_with(visual_cx, |shell, _| {
            if created {
                assert_eq!(fs::read(&output).unwrap(), b"// Example external bytes\n");
                assert!(shell.rows[0].staged.artifact().is_some());
                assert!(matches!(&shell.rows[0].status, FileStatus::Error(message) if message == &shell.i18n().text("banner.save_source_changed")));
            } else {
                assert!(matches!(shell.rows[0].status, FileStatus::Saved));
                assert_eq!(fs::read(&output).unwrap(), original);
            }
            assert_eq!(fs::read(&path).unwrap(), original);
        });
    }
}

#[gpui::test]
fn ascii_content_mb_uses_destination_state(cx: &mut TestAppContext) {
    ascii_content_destination_case(cx, "mb");
}

#[gpui::test]
fn ascii_content_uppercase_ma_uses_destination_state(cx: &mut TestAppContext) {
    ascii_content_destination_case(cx, "MA");
}

#[gpui::test]
fn ascii_staging_requires_comparable_existing_analysis(cx: &mut TestAppContext) {
    for analysis in 0..3 {
        let directory = tempdir().unwrap();
        let path = directory.path().join("Example.ma");
        write_mutation_scene(&path);
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.state = test_state(directory.path(), "");
            let mut row = if analysis == 2 {
                test_row(1, &path)
            } else {
                mutation_row(1, &path)
            };
            row.selected = true;
            if analysis == 0 {
                row.paths_report.as_mut().unwrap().source = None;
            } else if analysis == 1 {
                row.paths_report = None;
                row.dump_report = None;
            }
            shell.replace_rows(vec![row]);
            shell.run_to_ascii(window, cx);
        });
        visual_cx.run_until_parked();
        shell.read_with(visual_cx, |shell, _| {
            if analysis == 2 {
                assert!(shell.rows[0].staged.artifact().is_some());
            } else {
                assert!(matches!(shell.rows[0].staged, Staged::None));
                assert!(matches!(&shell.rows[0].status, FileStatus::Error(message) if message == &shell.i18n().text("banner.edit_requires_reanalysis")));
            }
        });
    }
}
