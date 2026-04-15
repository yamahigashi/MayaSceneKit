use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use encoding_rs::SHIFT_JIS;
use gpui::{
    AppContext, Axis, Entity, Focusable, Modifiers, TestAppContext, VisualTestContext, point, px,
    size,
};
use gpui_component::{Root, table::ColumnSort};
use maya_scene_kit_audit::{
    audit::{build_parse_budget_blocked_audit_report, build_script_audit_plan},
    scene::{AuditOptions, AuditSeverity},
};
use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, OperationMode, PathOwnerDeletePreview, PathOwnerDeleteTarget,
    PathReplaceMode, PathReplaceOverride, PathReplacePreview, PathReplacePreviewItem,
    ValidationState,
};
use maya_scene_kit_observe::scene::{
    ExecutionLanguage, ExecutionOrigin, ExecutionSourceRange, ExecutionSurfaceKind,
    ExecutionTrigger, LoadOptions, PathKind, SceneDumpRequireKind, SceneFormat, ScenePathEntry,
    ScenePathValueStyle, ScenePathsReport, collect_scene_paths,
};
use tempfile::tempdir;

use super::{
    AuditDetailDialogState, AuditResultItemKind, AuditResultRow, AuditResultRowKey,
    AuditRowCleanState, AuditSeverityFilter, AuditSortKey, AuditTableSort,
    AutoAnalyzeParallelismPreference, AutoAnalyzePriority, AutoAnalyzeQueueState,
    BackupLocationPreference, DirtyKind, FileSortKey, FileStatus, FileTableSelectAll,
    FileTableSort, MenuAutoAnalyzeParallelism32, MenuEditRedo, MenuEditUndo,
    MenuToggleIgnoreFolderNames, PathCollectRewriteMode, PathEditKeyboardOutcome, PathFormFilter,
    PathOrderSnapshot, PathResolutionBadge, PathSortKey, PathTableSort, PathTypeFilter,
    ReplaceDialogPreviewSignature, ReplaceDialogPreviewState, ReplaceDialogSort,
    ReplaceDialogSortKey, ReplaceDialogState, RowJobResult, RowOperation, SceneRow, analyze_row,
    analyze_row_with_options, apply_path_overrides_to_report, apply_persisted_column_widths,
    audit_clean_target, audit_context_menu_state, audit_table_columns, backup_file_name,
    build_audit_clipboard_payload, build_audit_result_rows, build_audit_table_model,
    build_file_copy_payload, build_file_table_rows, build_job_history_log_lines,
    build_path_table_model, build_path_table_model_with_order_snapshot,
    clean_targets_for_removed_script_nodes, collect_scene_files_recursively,
    compute_visible_row_indices_for, default_audit_severity_filter, default_audit_sort,
    default_path_form_filter, default_path_resolution_filter, default_path_sort,
    default_path_type_filter, detect_format, filter_audit_result_rows, merge_column_widths,
    missing_path_count_for_row, next_backup_path, path_context_menu_state,
    path_edit::{
        PathCollectPlan, absolute_override_value_for_entry, collect_target_files,
        collected_path_rewrite_value, parse_path_collect_folder_input, path_collect_default_folder,
        path_collect_destination_supports_rewrite_mode, path_value_edit_supported_for_edit_targets,
        path_value_edit_supported_for_entry, resolved_target_file_paths_for_edit_targets,
        shared_workspace_root_for_targets, workspace_relative_override_value_for_entry,
        write_back_selected_scene_path,
    },
    path_edit_keyboard_outcome, path_overrides_from_replace_preview, path_table_columns,
    path_text_highlights, persisted_column_widths, reconcile_workspace_rows, render_banner_message,
    replace_dialog::render_replace_dialog_preview_rows,
    resolve_audit_clipboard_payload, resolve_audit_detail_view_model, selected_audit_notice_lines,
    selected_rows_are_parse_budget_blocked_without_paths, tokenize_search_query,
    visible_path_selection_targets, visible_selection_range_indices,
    workspace_relative_display_path, workspace_split_config,
};
use crate::{
    gui::{GuiShell, init_gui_app},
    i18n::I18n,
    menu_bar::TopMenuBar,
    model::{
        AuditModePreference, JobHistoryEntry, LocalePreference, PersistedState,
        PersistedTableColumnWidth, ResultTab, StatusFilter, SupportedLocale,
        WorkspaceLayoutPreference,
    },
};

fn test_state(root: &Path, search_query: &str) -> PersistedState {
    PersistedState {
        workspace_root: Some(root.to_path_buf()),
        locale: LocalePreference::English,
        audit_mode: AuditModePreference::StrictDefault,
        backup_location: BackupLocationPreference::BackupFolder,
        workspace_layout: WorkspaceLayoutPreference::TopBottom,
        workspace_auto_analyze: false,
        auto_analyze_parallelism: AutoAnalyzeParallelismPreference::Four,
        max_bytes: None,
        ignore_folder_names_enabled: true,
        ignored_folder_names: vec!["backup".to_string(), "autosave".to_string()],
        active_tab: ResultTab::Overview,
        status_filter: StatusFilter::All,
        file_list_findings_only: false,
        file_list_missing_only: false,
        file_list_dirty_only: false,
        search_query: search_query.to_string(),
        workspace_files: Vec::new(),
        recent_inputs: Vec::new(),
        job_history: Vec::new(),
        last_opened_input: None,
        file_table_column_widths: Vec::new(),
        path_table_column_widths: Vec::new(),
        audit_table_column_widths: Vec::new(),
    }
}

fn test_row(id: u64, path: &Path) -> SceneRow {
    SceneRow::from_path(id, path.to_path_buf()).expect("scene row")
}

fn ignore_state(enabled: bool, names: &[&str]) -> PersistedState {
    PersistedState {
        ignore_folder_names_enabled: enabled,
        ignored_folder_names: names.iter().map(|name| name.to_string()).collect(),
        ..PersistedState::default()
    }
}

fn display_audit_rows(rows: Vec<AuditResultRow>) -> Vec<super::AuditTableRow> {
    build_audit_table_model(
        &rows,
        &BTreeSet::new(),
        &BTreeSet::from([
            AuditSeverityFilter::Info,
            AuditSeverityFilter::Low,
            AuditSeverityFilter::MediumPlus,
        ]),
        false,
        false,
        "",
        default_audit_sort(),
        SupportedLocale::English,
    )
    .rows
}

fn test_audit_row(
    row_id: u64,
    item_index: usize,
    scene_name: &str,
    summary: &str,
    evidence: &[&str],
) -> AuditResultRow {
    AuditResultRow {
        key: AuditResultRowKey {
            row_id,
            item_kind: AuditResultItemKind::Finding,
            item_index,
        },
        scene_name: scene_name.to_string(),
        severity: AuditSeverity::Low,
        summary: summary.to_string(),
        code: "audit_code".to_string(),
        sink: "py_exec".to_string(),
        preview: "preview".to_string(),
        source_line: Some(3),
        evidence: evidence.iter().map(|entry| entry.to_string()).collect(),
        dirty: false,
        clean_target: Some(ExecutionCleanTarget::ScriptNode {
            node_name: "scriptNode1".to_string(),
        }),
        clean_state: AuditRowCleanState::Available,
    }
}

fn open_test_shell(cx: &mut TestAppContext) -> (Entity<GuiShell>, &mut VisualTestContext) {
    cx.update(init_gui_app);

    let shell_slot = Rc::new(RefCell::new(None));
    let shell_slot_for_build = shell_slot.clone();
    let (_, visual_cx) = cx.add_window_view(|window, cx| {
        let menu_bar = TopMenuBar::new(window, cx);
        let shell = cx.new(|cx| GuiShell::new(menu_bar, window, cx));
        shell_slot_for_build.replace(Some(shell.clone()));

        let shell_view = shell.clone();
        shell.update(cx, |shell: &mut GuiShell, cx| {
            shell.refresh_app_menus(window, cx);
            shell.bind_file_table(shell_view.clone(), cx);
            cx.focus_self(window);
        });
        Root::new(shell, window, cx)
    });

    (
        shell_slot
            .borrow()
            .clone()
            .expect("test shell should be created"),
        visual_cx,
    )
}

fn seed_file_table_selection_test_state(
    shell: &Entity<GuiShell>,
    cx: &mut TestAppContext,
) -> tempfile::TempDir {
    let dir = tempdir().expect("tmpdir");
    let keep_a = dir.path().join("keep_a.ma");
    let hide = dir.path().join("hide.mb");
    let keep_b = dir.path().join("keep_b.ma");
    fs::write(&keep_a, "").expect("write keep_a");
    fs::write(&hide, "").expect("write hide");
    fs::write(&keep_b, "").expect("write keep_b");

    shell.update(cx, |shell, cx| {
        shell.state = test_state(dir.path(), "keep");
        shell.rows = vec![
            test_row(1, &keep_a),
            test_row(2, &hide),
            test_row(3, &keep_b),
        ];
        shell.refresh_file_table(cx);
    });

    dir
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn write_literal_mel_python_scene(path: &Path) {
    fs::write(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"literalPythonReview\";\n",
            "    setAttr \".b\" -type \"string\" \"python(\\\"print('hello')\\\")\";\n",
            "    setAttr \".st\" 0;\n",
        ),
    )
    .expect("write mel python fixture");
}

fn write_top_level_python_scene(path: &Path) {
    fs::write(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "python(\"import subprocess\\nsubprocess.call(['echo', 'hi'])\");\n",
        ),
    )
    .expect("write top level python fixture");
}

fn write_path_owner_delete_scene(path: &Path) {
    fs::write(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/spec.tx\";\n",
            "createNode script -n \"cleanupScript\";\n",
            "    setAttr \".b\" -type \"string\" \"print(\\\"hello\\\")\";\n",
            "    setAttr \".st\" 0;\n",
        ),
    )
    .expect("write path owner delete fixture");
}

fn write_single_file_path_scene(path: &Path, file_value: &str) {
    fs::write(
        path,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{}\";\n",
            ),
            file_value
        ),
    )
    .expect("write single file path scene");
}

fn staged_clean_result(scene: &Path, node_name: &str) -> RowJobResult {
    RowJobResult::Clean {
        preview: maya_scene_kit_edit::scene::ExecutionCleanPreview {
            input_path: scene.to_path_buf(),
            scene_format: SceneFormat::Ma,
            operation_mode: OperationMode::Forensic,
            validation_state: ValidationState::Validated,
            cleaned_targets: vec![ExecutionCleanTarget::ScriptNode {
                node_name: node_name.to_string(),
            }],
            removed_script_nodes: vec![node_name.to_string()],
            removed_plugin_requires: Vec::new(),
        },
        artifact: maya_scene_kit_edit::scene::StagedSceneArtifact {
            input_path: scene.to_path_buf(),
            suggested_output_path: scene.to_path_buf(),
            scene_format: SceneFormat::Ma,
            operation_mode: OperationMode::Forensic,
            validation_state: ValidationState::Validated,
            bytes: format!("// cleaned {node_name}").into_bytes(),
        },
        staged_targets: vec![ExecutionCleanTarget::ScriptNode {
            node_name: node_name.to_string(),
        }],
    }
}

fn dump_script_audit_fixture() -> (SceneRow, AuditResultRowKey) {
    let path = repo_root().join("tests/02/sphere.mb");
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.audit_report = Some(result.audit_report.clone());
    row.dump_report = result.dump_report;

    let audit_row = build_audit_result_rows(std::slice::from_ref(&row), &[0])
        .into_iter()
        .find(|audit_row| audit_row.key.item_kind == AuditResultItemKind::DumpScriptNode)
        .expect("dump script row");

    (row, audit_row.key)
}

#[test]
fn detect_format_recognizes_ma_and_mb() {
    assert_eq!(
        detect_format(PathBuf::from("scene.ma").as_path()),
        Some(SceneFormat::Ma)
    );
    assert_eq!(
        detect_format(PathBuf::from("scene.mb").as_path()),
        Some(SceneFormat::Mb)
    );
    assert_eq!(detect_format(PathBuf::from("scene.txt").as_path()), None);
}

#[test]
fn path_edit_keyboard_outcome_applies_and_cancels_when_not_composing() {
    assert_eq!(
        path_edit_keyboard_outcome("enter", false),
        PathEditKeyboardOutcome::Apply
    );
    assert_eq!(
        path_edit_keyboard_outcome("escape", false),
        PathEditKeyboardOutcome::Cancel
    );
}

#[test]
fn path_edit_keyboard_outcome_suppresses_enter_and_escape_during_ime() {
    assert_eq!(
        path_edit_keyboard_outcome("enter", true),
        PathEditKeyboardOutcome::SuppressForIme
    );
    assert_eq!(
        path_edit_keyboard_outcome("escape", true),
        PathEditKeyboardOutcome::SuppressForIme
    );
    assert_eq!(
        path_edit_keyboard_outcome("tab", true),
        PathEditKeyboardOutcome::Ignore
    );
}

#[test]
fn collect_scene_files_recursively_only_keeps_supported_extensions() {
    let dir = tempdir().expect("tmpdir");
    fs::create_dir_all(dir.path().join("nested")).expect("mkdir");
    fs::write(dir.path().join("a.ma"), "").expect("write ma");
    fs::write(dir.path().join("nested").join("b.mb"), "").expect("write mb");
    fs::write(dir.path().join("c.txt"), "").expect("write txt");

    let mut out = Vec::new();
    collect_scene_files_recursively(dir.path(), &mut out, &ignore_state(false, &[]));
    out.sort();

    assert_eq!(out.len(), 2);
    assert!(out.iter().any(|path| path.ends_with("a.ma")));
    assert!(out.iter().any(|path| path.ends_with("b.mb")));
}

#[test]
fn collect_scene_files_recursively_skips_default_ignored_folders_when_enabled() {
    let dir = tempdir().expect("tmpdir");
    fs::create_dir_all(dir.path().join("backup")).expect("mkdir backup");
    fs::create_dir_all(dir.path().join("AUTOSAVE")).expect("mkdir autosave");
    fs::create_dir_all(dir.path().join("shots")).expect("mkdir shots");
    fs::write(dir.path().join("backup").join("ignored.ma"), "").expect("write ignored");
    fs::write(dir.path().join("AUTOSAVE").join("ignored.mb"), "").expect("write ignored");
    fs::write(dir.path().join("shots").join("keep.ma"), "").expect("write keep");

    let mut out = Vec::new();
    collect_scene_files_recursively(
        dir.path(),
        &mut out,
        &ignore_state(true, &["backup", "autosave"]),
    );
    out.sort();

    assert_eq!(out.len(), 1);
    assert!(out[0].ends_with("keep.ma"));
}

#[test]
fn collect_scene_files_recursively_skips_user_configured_folder_names() {
    let dir = tempdir().expect("tmpdir");
    fs::create_dir_all(dir.path().join("cache")).expect("mkdir cache");
    fs::create_dir_all(dir.path().join("shots")).expect("mkdir shots");
    fs::write(dir.path().join("cache").join("ignored.ma"), "").expect("write ignored");
    fs::write(dir.path().join("shots").join("keep.ma"), "").expect("write keep");

    let mut out = Vec::new();
    collect_scene_files_recursively(dir.path(), &mut out, &ignore_state(true, &["cache"]));
    out.sort();

    assert_eq!(out.len(), 1);
    assert!(out[0].ends_with("keep.ma"));
}

#[test]
fn collect_scene_files_recursively_does_not_skip_configured_names_when_disabled() {
    let dir = tempdir().expect("tmpdir");
    fs::create_dir_all(dir.path().join("cache")).expect("mkdir cache");
    fs::write(dir.path().join("cache").join("kept.ma"), "").expect("write kept");

    let mut out = Vec::new();
    collect_scene_files_recursively(dir.path(), &mut out, &ignore_state(false, &["cache"]));

    assert_eq!(out.len(), 1);
    assert!(out[0].ends_with("kept.ma"));
}

#[test]
fn collect_scene_files_recursively_matches_ignore_names_case_insensitively() {
    let dir = tempdir().expect("tmpdir");
    fs::create_dir_all(dir.path().join("CACHE")).expect("mkdir cache");
    fs::write(dir.path().join("CACHE").join("ignored.ma"), "").expect("write ignored");

    let mut out = Vec::new();
    collect_scene_files_recursively(dir.path(), &mut out, &ignore_state(true, &["cache"]));

    assert!(out.is_empty());
}

#[test]
fn auto_analyze_queue_prioritizes_high_before_low() {
    let mut queue = AutoAnalyzeQueueState::default();
    queue.enqueue_many([1, 2, 3], AutoAnalyzePriority::Low);
    queue.enqueue_many([4, 5], AutoAnalyzePriority::High);

    assert_eq!(queue.pop_next(), Some(4));
    assert_eq!(queue.pop_next(), Some(5));
    assert_eq!(queue.pop_next(), Some(1));
    assert_eq!(queue.pop_next(), Some(2));
    assert_eq!(queue.pop_next(), Some(3));
    assert_eq!(queue.pop_next(), None);
}

#[test]
fn auto_analyze_queue_promotes_low_entry_to_high_without_duplication() {
    let mut queue = AutoAnalyzeQueueState::default();
    queue.enqueue(7, AutoAnalyzePriority::Low);
    queue.enqueue(7, AutoAnalyzePriority::High);
    queue.enqueue(7, AutoAnalyzePriority::Low);

    assert_eq!(queue.remaining_count(), 1);
    assert_eq!(queue.pop_next(), Some(7));
    assert_eq!(queue.pop_next(), None);
}

#[test]
fn auto_analyze_queue_remaining_count_includes_in_flight() {
    let mut queue = AutoAnalyzeQueueState::default();
    queue.enqueue_many([10, 11, 12], AutoAnalyzePriority::Low);
    assert_eq!(queue.remaining_count(), 3);

    assert_eq!(queue.pop_next(), Some(10));
    assert_eq!(queue.remaining_count(), 3);

    queue.complete(10);
    assert_eq!(queue.remaining_count(), 2);
}

#[test]
fn reconcile_workspace_rows_reuses_existing_row_state_for_retained_paths() {
    let dir = tempdir().expect("tmpdir");
    let keep = dir.path().join("keep.ma");
    let add = dir.path().join("add.ma");
    fs::write(&keep, "").expect("write keep");
    fs::write(&add, "").expect("write add");

    let mut retained = test_row(7, &keep);
    retained.selected = true;
    retained.findings = 3;
    let mut next_row_id = 20;
    let rows = reconcile_workspace_rows(
        vec![retained],
        vec![keep.clone(), add.clone()],
        &mut next_row_id,
    );

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].id, 7);
    assert!(rows[0].selected);
    assert_eq!(rows[0].findings, 3);
    assert_eq!(rows[1].path, add);
    assert_eq!(rows[1].id, 20);
    assert_eq!(next_row_id, 21);
}

#[test]
fn workspace_relative_display_path_uses_workspace_root() {
    let dir = tempdir().expect("tmpdir");
    fs::create_dir_all(dir.path().join("nested")).expect("mkdir");
    let path = dir.path().join("nested").join("scene.ma");
    fs::write(&path, "").expect("write ma");

    let state = test_state(dir.path(), "");
    assert_eq!(
        workspace_relative_display_path(&path, &state),
        PathBuf::from("nested")
            .join("scene.ma")
            .display()
            .to_string()
    );
}

#[test]
fn tokenize_search_query_enforces_threshold_and_splits_terms() {
    assert!(tokenize_search_query("a").is_empty());
    assert!(tokenize_search_query(" ").is_empty());
    assert_eq!(
        tokenize_search_query("  Hero   Chair "),
        vec!["hero".to_string(), "chair".to_string()]
    );
}

#[test]
fn workspace_split_config_matches_top_bottom_layout() {
    let split = workspace_split_config(WorkspaceLayoutPreference::TopBottom);

    assert_eq!(split.group_id, "workspace-rows");
    assert_eq!(split.axis, Axis::Vertical);
    assert_eq!(split.file_size, px(420.0));
    assert_eq!(split.file_min, px(240.0));
    assert_eq!(split.result_size, px(280.0));
    assert_eq!(split.result_min, px(180.0));
}

#[test]
fn workspace_split_config_matches_left_right_layout() {
    let split = workspace_split_config(WorkspaceLayoutPreference::LeftRight);

    assert_eq!(split.group_id, "workspace-columns");
    assert_eq!(split.axis, Axis::Horizontal);
    assert_eq!(split.file_size, px(560.0));
    assert_eq!(split.file_min, px(320.0));
    assert_eq!(split.result_size, px(420.0));
    assert_eq!(split.result_min, px(260.0));
}

#[gpui::test]
fn file_table_ctrl_a_selects_only_visible_rows(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let _dir = seed_file_table_selection_test_state(&shell, visual_cx);

    visual_cx.update(|window, app| {
        shell.read(app).file_table_focus_handle.focus(window);
        shell.update(app, |shell, cx| {
            shell.on_file_table_select_all(&FileTableSelectAll, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(shell.visible_row_indices(), vec![0, 2]);
        assert_eq!(shell.selected_indices(), vec![0, 2]);
    });
}

#[gpui::test]
fn file_table_ctrl_a_toggles_to_clear_selection_when_all_visible_rows_are_selected(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let _dir = seed_file_table_selection_test_state(&shell, visual_cx);

    visual_cx.update(|window, app| {
        shell.read(app).file_table_focus_handle.focus(window);
        shell.update(app, |shell, cx| {
            shell.on_file_table_select_all(&FileTableSelectAll, window, cx);
            shell.on_file_table_select_all(&FileTableSelectAll, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(shell.visible_row_indices(), vec![0, 2]);
        assert!(shell.selected_indices().is_empty());
    });
}

#[gpui::test]
fn file_table_ctrl_a_does_not_select_rows_when_search_input_is_focused(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let _dir = seed_file_table_selection_test_state(&shell, visual_cx);

    visual_cx.update(|window, app| {
        shell
            .read(app)
            .search_input
            .read(app)
            .focus_handle(app)
            .focus(window);
        shell.update(app, |shell, cx| {
            shell.on_file_table_select_all(&FileTableSelectAll, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        assert!(shell.read(app).selected_indices().is_empty());
    });
}

#[gpui::test]
fn save_result_keeps_active_tab(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("hero.ma");
    fs::write(&scene, "//Maya ASCII 2026 scene\n").expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.dirty_kind = Some(DirtyKind::Replace);
            row.status = FileStatus::Dirty;
            shell.state.active_tab = ResultTab::Audit;
            shell.state.workspace_auto_analyze = false;
            shell.rows = vec![row];
            shell.apply_job_result(
                1,
                RowOperation::Save,
                RowJobResult::Save {
                    output_path: scene.clone(),
                },
                None,
                window,
                cx,
            );
        });
    });

    visual_cx.update(|_, app| {
        assert_eq!(shell.read(app).state.active_tab, ResultTab::Audit);
    });
}

#[gpui::test]
fn replace_then_delete_owner_save_promotes_composed_reports(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            let report = row.paths_report.clone().expect("base paths report");
            let overrides = vec![
                PathReplaceOverride {
                    entry_index: 0,
                    before_value: "textures/diffuse.tx".to_string(),
                    after_value: "textures/diffuse_replaced.tx".to_string(),
                },
                PathReplaceOverride {
                    entry_index: 1,
                    before_value: "textures/spec.tx".to_string(),
                    after_value: "textures/spec_replaced.tx".to_string(),
                },
            ];
            let staged =
                maya_scene_kit_edit::scene::stage_replace_scene_paths_with_overrides_in_report(
                    &report, &overrides,
                )
                .expect("stage replace");
            row.path_overrides = BTreeMap::from([
                (0usize, "textures/diffuse_replaced.tx".to_string()),
                (1usize, "textures/spec_replaced.tx".to_string()),
            ]);
            row.dirty_kind = Some(DirtyKind::Replace);
            row.dirty_artifact = Some(staged.artifact);
            row.replace_generation = 1;
            row.replace_artifact_generation = Some(1);
            shell.rows = vec![row];

            shell.stage_scene_edits_for_row(
                0,
                BTreeSet::new(),
                BTreeSet::from([PathOwnerDeleteTarget {
                    node_type: "file".to_string(),
                    node_name: "file1".to_string(),
                }]),
                ResultTab::Paths,
                None,
                false,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let row = &shell.rows[0];
            assert_eq!(row.dirty_kind, Some(DirtyKind::SceneEdits));
            assert_eq!(row.path_overrides.len(), 2);
            let staged_paths = row.staged_paths_report.as_ref().expect("staged paths");
            assert!(
                staged_paths
                    .entries
                    .iter()
                    .all(|entry| entry.node_name != "file1"),
                "staged paths should exclude deleted owner node",
            );
            assert!(
                staged_paths.entries.iter().any(|entry| {
                    entry.node_name == "file2" && entry.value == "textures/spec_replaced.tx"
                }),
                "staged paths should keep surviving replace override",
            );

            shell.state.workspace_auto_analyze = false;
            shell.apply_job_result(
                1,
                RowOperation::Save,
                RowJobResult::Save {
                    output_path: scene.clone(),
                },
                None,
                window,
                cx,
            );
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let row = &shell.rows[0];
        assert_eq!(row.dirty_kind, None);
        assert!(row.path_overrides.is_empty());
        assert_eq!(
            row.analyzed_audit_mode,
            Some(AuditModePreference::StrictDefault)
        );
        let saved_paths = row.paths_report.as_ref().expect("saved paths report");
        assert!(
            saved_paths
                .entries
                .iter()
                .all(|entry| entry.node_name != "file1"),
            "promoted paths report should exclude deleted owner node",
        );
        assert!(
            saved_paths.entries.iter().any(|entry| {
                entry.node_name == "file2" && entry.value == "textures/spec_replaced.tx"
            }),
            "promoted paths report should retain remaining replace override",
        );
    });
}

#[gpui::test]
fn replace_then_delete_owner_rebuilds_missing_replace_artifact(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            row.path_overrides = BTreeMap::from([
                (0usize, "textures/diffuse_replaced.tx".to_string()),
                (1usize, "textures/spec_replaced.tx".to_string()),
            ]);
            row.dirty_kind = Some(DirtyKind::Replace);
            row.replace_generation = 1;
            row.replace_artifact_generation = None;
            shell.rows = vec![row];

            shell.stage_scene_edits_for_row(
                0,
                BTreeSet::new(),
                BTreeSet::from([PathOwnerDeleteTarget {
                    node_type: "file".to_string(),
                    node_name: "file1".to_string(),
                }]),
                ResultTab::Paths,
                None,
                false,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let row = &shell.rows[0];
        assert_eq!(row.dirty_kind, Some(DirtyKind::SceneEdits));
        assert!(row.dirty_artifact.is_some());
        let staged_paths = row.staged_paths_report.as_ref().expect("staged paths");
        assert!(
            staged_paths
                .entries
                .iter()
                .all(|entry| entry.node_name != "file1"),
            "rebuilt replace bytes should still allow owner delete staging",
        );
        assert!(
            staged_paths.entries.iter().any(|entry| {
                entry.node_name == "file2" && entry.value == "textures/spec_replaced.tx"
            }),
            "rebuilt replace bytes should preserve remaining replace override",
        );
    });
}

#[gpui::test]
fn clean_result_keeps_active_audit_tab_and_marks_audit_rows_staged(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("literal_python.ma");
    write_literal_mel_python_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            let RowJobResult::Analyze(result) =
                analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze row")
            else {
                panic!("expected analyze result");
            };
            row.audit_report = Some(result.audit_report);
            row.dump_report = result.dump_report;
            shell.state.active_tab = ResultTab::Audit;
            shell.rows = vec![row];
            shell.refresh_file_table(cx);

            shell.apply_job_result(
                1,
                RowOperation::Clean,
                staged_clean_result(&scene, "literalPythonReview"),
                None,
                window,
                cx,
            );

            assert_eq!(shell.state.active_tab, ResultTab::Audit);
            assert!(shell.audit_rows.iter().any(|audit_row| {
                audit_row.clean_target
                    == Some(ExecutionCleanTarget::ScriptNode {
                        node_name: "literalPythonReview".to_string(),
                    })
                    && audit_row.clean_state == AuditRowCleanState::Staged
            }));
        });
    });
}

#[gpui::test]
fn multi_file_clean_marks_staged_audit_rows_for_each_selected_file(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let path = repo_root().join("tests/02/sphere.mb");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut first = test_row(1, &path);
            let mut second = test_row(2, &path);
            let RowJobResult::Analyze(first_result) =
                analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze first")
            else {
                panic!("expected analyze result");
            };
            let RowJobResult::Analyze(second_result) =
                analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze second")
            else {
                panic!("expected analyze result");
            };
            let first_node_name = first_result
                .dump_report
                .as_ref()
                .expect("first dump report")
                .script_entries
                .first()
                .expect("first script entry")
                .name
                .clone();
            let second_node_name = second_result
                .dump_report
                .as_ref()
                .expect("second dump report")
                .script_entries
                .first()
                .expect("second script entry")
                .name
                .clone();
            first.selected = true;
            second.selected = true;
            first.audit_report = Some(first_result.audit_report);
            first.dump_report = first_result.dump_report;
            second.audit_report = Some(second_result.audit_report);
            second.dump_report = second_result.dump_report;
            shell.state.active_tab = ResultTab::Audit;
            shell.rows = vec![first, second];
            shell.refresh_file_table(cx);

            shell.apply_job_result(
                1,
                RowOperation::Clean,
                staged_clean_result(&path, &first_node_name),
                None,
                window,
                cx,
            );
            shell.apply_job_result(
                2,
                RowOperation::Clean,
                staged_clean_result(&path, &second_node_name),
                None,
                window,
                cx,
            );

            let staged_dump_rows = shell
                .audit_all_rows
                .iter()
                .filter(|row| {
                    row.clean_target.is_some() && row.clean_state == AuditRowCleanState::Staged
                })
                .map(|row| row.key.row_id)
                .collect::<BTreeSet<_>>();

            assert_eq!(staged_dump_rows, BTreeSet::from([1, 2]));
        });
    });
}

#[gpui::test]
fn clean_undo_restores_pre_processing_status(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("hero.ma");
    fs::write(&scene, "//Maya ASCII 2026 scene\n").expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.status = FileStatus::Idle;
            shell.rows = vec![row];
            let edit_sequence = shell
                .begin_edit_transaction(&[0])
                .expect("edit transaction");
            shell.rows[0].status = FileStatus::Processing(RowOperation::Clean);
            shell.apply_job_result(
                1,
                RowOperation::Clean,
                staged_clean_result(&scene, "script1"),
                Some(edit_sequence),
                window,
                cx,
            );
            shell.run_menu_undo(cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(matches!(shell.rows[0].status, FileStatus::Idle));
    });
}

#[gpui::test]
fn edit_menu_undo_redo_actions_follow_history_availability(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("hero.ma");
    fs::write(&scene, "//Maya ASCII 2026 scene\n").expect("write scene");

    visual_cx.update(|window, app| {
        assert!(!window.is_action_available(&MenuEditUndo, app));
        assert!(!window.is_action_available(&MenuEditRedo, app));

        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.status = FileStatus::Idle;
            shell.rows = vec![row];
            let before = shell.capture_row_edit_states(&[0]);
            shell.rows[0].status = FileStatus::Dirty;
            shell.push_edit_history(before);
            shell.refresh_file_table(cx);
            cx.notify();
        });
    });

    visual_cx.update(|window, app| {
        assert!(window.is_action_available(&MenuEditUndo, app));
        assert!(!window.is_action_available(&MenuEditRedo, app));

        shell.update(app, |shell, cx| {
            shell.run_menu_undo(cx);
        });
    });

    visual_cx.update(|window, app| {
        assert!(!window.is_action_available(&MenuEditUndo, app));
        assert!(window.is_action_available(&MenuEditRedo, app));
    });
}

#[gpui::test]
fn bulk_clean_undo_restores_all_rows_after_out_of_order_completion(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("a.ma");
    let scene_b = dir.path().join("b.ma");
    fs::write(&scene_a, "//Maya ASCII 2026 scene\n").expect("write scene a");
    fs::write(&scene_b, "//Maya ASCII 2026 scene\n").expect("write scene b");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            shell.rows = vec![test_row(1, &scene_a), test_row(2, &scene_b)];
            let edit_sequence = shell
                .begin_edit_transaction(&[0, 1])
                .expect("edit transaction");
            shell.rows[0].status = FileStatus::Processing(RowOperation::Clean);
            shell.rows[1].status = FileStatus::Processing(RowOperation::Clean);

            shell.apply_job_result(
                2,
                RowOperation::Clean,
                staged_clean_result(&scene_b, "script_b"),
                Some(edit_sequence),
                window,
                cx,
            );
            assert!(shell.undo_stack.is_empty());

            shell.apply_job_result(
                1,
                RowOperation::Clean,
                staged_clean_result(&scene_a, "script_a"),
                Some(edit_sequence),
                window,
                cx,
            );

            assert_eq!(shell.undo_stack.len(), 1);
            assert_eq!(shell.undo_stack[0].transitions.len(), 2);

            shell.run_menu_undo(cx);
            assert!(matches!(shell.rows[0].status, FileStatus::Idle));
            assert!(matches!(shell.rows[1].status, FileStatus::Idle));

            shell.run_menu_redo(cx);
            assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::Clean));
            assert_eq!(shell.rows[1].dirty_kind, Some(DirtyKind::Clean));
        });
    });
}

#[gpui::test]
fn scene_edit_clean_undo_restores_findings_count_and_findings_filter(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("literal_python.ma");
    write_literal_mel_python_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            let RowJobResult::Analyze(result) =
                analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze row")
            else {
                panic!("expected analyze result");
            };
            let original_findings = result.audit_report.findings.len();
            let node_name = result
                .dump_report
                .as_ref()
                .expect("dump report")
                .script_entries
                .first()
                .expect("script entry")
                .name
                .clone();
            assert!(
                original_findings > 0,
                "fixture should produce findings before clean"
            );

            row.audit_report = Some(result.audit_report);
            row.dump_report = result.dump_report;
            row.findings = original_findings;
            shell.rows = vec![row];
            shell.refresh_file_table(cx);

            let edit_sequence = shell
                .begin_edit_transaction(&[0])
                .expect("edit transaction");
            shell.stage_scene_edits_for_row(
                0,
                BTreeSet::from([ExecutionCleanTarget::ScriptNode { node_name }]),
                BTreeSet::new(),
                ResultTab::Audit,
                Some(edit_sequence),
                false,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(shell.rows[0].findings, 0);
        assert_eq!(shell.rows[0].effective_findings_count(), 0);
    });

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let original_findings = shell.rows[0]
                .audit_report
                .as_ref()
                .expect("audit report")
                .findings
                .len();

            shell.run_menu_undo(cx);
            assert_eq!(shell.rows[0].findings, original_findings);
            assert_eq!(shell.rows[0].effective_findings_count(), original_findings);

            shell.state.file_list_findings_only = true;
            shell.refresh_file_table(cx);
            assert_eq!(shell.visible_rows, vec![0]);

            shell.run_menu_redo(cx);
            assert_eq!(shell.rows[0].findings, 0);
            assert_eq!(shell.rows[0].effective_findings_count(), 0);

            shell.refresh_file_table(cx);
            assert!(shell.visible_rows.is_empty());

            let table_rows = build_file_table_rows(
                &shell.rows,
                &[0],
                &shell.state,
                &I18n::new(SupportedLocale::English),
            );
            assert_eq!(table_rows[0].findings, "0");

            shell.refresh_app_menus(window, cx);
        });
    });
}

#[gpui::test]
fn undo_history_respects_action_order_not_completion_order(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("a.ma");
    let scene_b = dir.path().join("b.ma");
    let scene_c = dir.path().join("c.ma");
    fs::write(&scene_a, "//Maya ASCII 2026 scene\n").expect("write scene a");
    fs::write(&scene_b, "//Maya ASCII 2026 scene\n").expect("write scene b");
    fs::write(&scene_c, "//Maya ASCII 2026 scene\n").expect("write scene c");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            shell.rows = vec![
                test_row(1, &scene_a),
                test_row(2, &scene_b),
                test_row(3, &scene_c),
            ];

            let first_sequence = shell
                .begin_edit_transaction(&[0, 1])
                .expect("first sequence");
            shell.rows[0].status = FileStatus::Processing(RowOperation::Clean);
            shell.rows[1].status = FileStatus::Processing(RowOperation::Clean);

            let second_sequence = shell.begin_edit_transaction(&[2]).expect("second sequence");
            shell.rows[2].status = FileStatus::Processing(RowOperation::Clean);

            shell.apply_job_result(
                3,
                RowOperation::Clean,
                staged_clean_result(&scene_c, "script_c"),
                Some(second_sequence),
                window,
                cx,
            );
            assert!(shell.undo_stack.is_empty());

            shell.apply_job_result(
                2,
                RowOperation::Clean,
                staged_clean_result(&scene_b, "script_b"),
                Some(first_sequence),
                window,
                cx,
            );
            assert!(shell.undo_stack.is_empty());

            shell.apply_job_result(
                1,
                RowOperation::Clean,
                staged_clean_result(&scene_a, "script_a"),
                Some(first_sequence),
                window,
                cx,
            );

            assert_eq!(shell.undo_stack.len(), 2);

            shell.run_menu_undo(cx);
            assert!(matches!(shell.rows[2].status, FileStatus::Idle));
            assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::Clean));
            assert_eq!(shell.rows[1].dirty_kind, Some(DirtyKind::Clean));

            shell.run_menu_undo(cx);
            assert!(matches!(shell.rows[0].status, FileStatus::Idle));
            assert!(matches!(shell.rows[1].status, FileStatus::Idle));
        });
    });
}

#[gpui::test]
fn bulk_clean_failure_only_records_successful_subset(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("a.ma");
    let scene_b = dir.path().join("b.ma");
    fs::write(&scene_a, "//Maya ASCII 2026 scene\n").expect("write scene a");
    fs::write(&scene_b, "//Maya ASCII 2026 scene\n").expect("write scene b");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            shell.rows = vec![test_row(1, &scene_a), test_row(2, &scene_b)];
            let edit_sequence = shell
                .begin_edit_transaction(&[0, 1])
                .expect("edit transaction");
            shell.rows[0].status = FileStatus::Processing(RowOperation::Clean);
            shell.rows[1].status = FileStatus::Processing(RowOperation::Clean);

            shell.apply_job_result(
                1,
                RowOperation::Clean,
                staged_clean_result(&scene_a, "script_a"),
                Some(edit_sequence),
                window,
                cx,
            );
            shell.mark_error_by_id(
                2,
                RowOperation::Clean,
                Some(edit_sequence),
                "boom",
                window,
                cx,
            );

            assert_eq!(shell.undo_stack.len(), 1);
            assert_eq!(shell.undo_stack[0].transitions.len(), 1);
            assert_eq!(shell.undo_stack[0].transitions[0].row_id, 1);

            shell.run_menu_undo(cx);
            assert!(matches!(shell.rows[0].status, FileStatus::Idle));
            assert!(matches!(shell.rows[1].status, FileStatus::Error(_)));
        });
    });
}

#[gpui::test]
fn save_prunes_only_affected_row_history(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("a.ma");
    let scene_b = dir.path().join("b.ma");
    fs::write(&scene_a, "//Maya ASCII 2026 scene\n").expect("write scene a");
    fs::write(&scene_b, "//Maya ASCII 2026 scene\n").expect("write scene b");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            shell.rows = vec![test_row(1, &scene_a), test_row(2, &scene_b)];
            let edit_sequence = shell
                .begin_edit_transaction(&[0, 1])
                .expect("edit transaction");
            shell.rows[0].status = FileStatus::Processing(RowOperation::Clean);
            shell.rows[1].status = FileStatus::Processing(RowOperation::Clean);

            shell.apply_job_result(
                1,
                RowOperation::Clean,
                staged_clean_result(&scene_a, "script_a"),
                Some(edit_sequence),
                window,
                cx,
            );
            shell.apply_job_result(
                2,
                RowOperation::Clean,
                staged_clean_result(&scene_b, "script_b"),
                Some(edit_sequence),
                window,
                cx,
            );
            assert_eq!(shell.undo_stack.len(), 1);
            assert_eq!(shell.undo_stack[0].transitions.len(), 2);

            shell.apply_job_result(
                1,
                RowOperation::Save,
                RowJobResult::Save {
                    output_path: scene_a.clone(),
                },
                None,
                window,
                cx,
            );

            assert_eq!(shell.undo_stack.len(), 1);
            assert_eq!(shell.undo_stack[0].transitions.len(), 1);
            assert_eq!(shell.undo_stack[0].transitions[0].row_id, 2);

            shell.run_menu_undo(cx);
            assert!(matches!(shell.rows[0].status, FileStatus::Saved));
            assert!(matches!(shell.rows[1].status, FileStatus::Idle));
        });
    });
}

#[gpui::test]
fn file_table_ctrl_a_does_not_select_rows_when_path_table_is_focused(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let _dir = seed_file_table_selection_test_state(&shell, visual_cx);

    visual_cx.update(|window, app| {
        shell
            .read(app)
            .path_table
            .read(app)
            .focus_handle(app)
            .focus(window);
        shell.update(app, |shell, cx| {
            shell.on_file_table_select_all(&FileTableSelectAll, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        assert!(shell.read(app).selected_indices().is_empty());
    });
}

#[test]
fn scene_row_dirty_when_path_overrides_exist_without_artifact() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.path_overrides
        .insert(0, "textures/edited.tx".to_string());

    assert!(row.dirty());
    assert!(!row.replace_artifact_is_current());
}

#[test]
fn apply_path_overrides_to_report_updates_entry_values() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut report = collect_scene_paths(&scene, PathKind::All).expect("paths");
    let overrides = BTreeMap::from([(0usize, "textures/edited.tx".to_string())]);

    apply_path_overrides_to_report(&mut report, &overrides);

    assert_eq!(report.entries[0].value, "textures/edited.tx");
}

#[test]
fn replace_dialog_state_can_apply_only_for_matching_preview_rule() {
    let signature = ReplaceDialogPreviewSignature {
        from_value: "before".to_string(),
        to_value: "after".to_string(),
        replace_mode: PathReplaceMode::Literal,
        path_type_filter: default_path_type_filter(),
    };
    let state = ReplaceDialogState {
        captured_row_ids: vec![1, 2],
        path_targets: None,
        path_type_filter: default_path_type_filter(),
        replace_mode: PathReplaceMode::Literal,
        preview_sort: ReplaceDialogSort {
            key: ReplaceDialogSortKey::Before,
            direction: ColumnSort::Default,
        },
        is_previewing: false,
        generation: 4,
        source_cache: BTreeMap::new(),
        preview_signature: Some(signature.clone()),
        preview: Some(ReplaceDialogPreviewState {
            previewable_row_ids: vec![1],
            failed_files: Vec::new(),
            matched_count: 1,
            items: Vec::new(),
            planned_overrides: vec![(
                1,
                vec![PathReplaceOverride {
                    entry_index: 0,
                    before_value: "before".to_string(),
                    after_value: "after".to_string(),
                }],
            )],
        }),
    };

    assert!(state.can_apply(&signature));
    assert!(!state.can_apply(&ReplaceDialogPreviewSignature {
        to_value: "other".to_string(),
        ..signature.clone()
    }));
    assert!(!state.can_apply(&ReplaceDialogPreviewSignature {
        from_value: String::new(),
        ..signature
    }));
}

#[test]
fn replace_dialog_state_invalidate_preview_clears_applyability() {
    let mut state = ReplaceDialogState {
        captured_row_ids: vec![1],
        path_targets: None,
        path_type_filter: default_path_type_filter(),
        replace_mode: PathReplaceMode::Literal,
        preview_sort: ReplaceDialogSort {
            key: ReplaceDialogSortKey::Before,
            direction: ColumnSort::Default,
        },
        is_previewing: true,
        generation: 7,
        source_cache: BTreeMap::new(),
        preview_signature: Some(ReplaceDialogPreviewSignature {
            from_value: "old".to_string(),
            to_value: "new".to_string(),
            replace_mode: PathReplaceMode::Literal,
            path_type_filter: default_path_type_filter(),
        }),
        preview: Some(ReplaceDialogPreviewState {
            previewable_row_ids: vec![1],
            failed_files: Vec::new(),
            matched_count: 3,
            items: Vec::new(),
            planned_overrides: vec![(
                1,
                vec![PathReplaceOverride {
                    entry_index: 0,
                    before_value: "old".to_string(),
                    after_value: "new".to_string(),
                }],
            )],
        }),
    };

    state.invalidate_preview();

    assert_eq!(state.generation, 8);
    assert!(!state.is_previewing);
    assert!(state.preview_signature.is_none());
    assert!(state.preview.is_none());
    assert!(!state.can_apply(&ReplaceDialogPreviewSignature {
        from_value: "old".to_string(),
        to_value: "new".to_string(),
        replace_mode: PathReplaceMode::Literal,
        path_type_filter: default_path_type_filter(),
    }));
}

#[test]
fn backup_file_name_repeats_backup_suffix_before_extension() {
    assert_eq!(backup_file_name("scene.ma", 1), "scene.backup.ma");
    assert_eq!(backup_file_name("scene.ma", 2), "scene.backup.backup.ma");
    assert_eq!(backup_file_name("scene", 1), "scene.backup");
}

#[test]
fn next_backup_path_uses_backup_folder_and_skips_existing_collisions() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("scene.ma");
    let backup_dir = dir.path().join("backup");
    fs::create_dir_all(&backup_dir).expect("mkdir backup");
    fs::write(backup_dir.join("scene.backup.ma"), "older").expect("write backup");

    let path = next_backup_path(&source, BackupLocationPreference::BackupFolder);
    assert_eq!(path, backup_dir.join("scene.backup.backup.ma"));
}

#[test]
fn compute_visible_rows_matches_all_search_terms_against_relative_paths() {
    let dir = tempdir().expect("tmpdir");
    fs::create_dir_all(dir.path().join("chars")).expect("mkdir");
    fs::create_dir_all(dir.path().join("props")).expect("mkdir");
    let hero = dir.path().join("chars").join("hero.ma");
    let table = dir.path().join("props").join("table.ma");
    fs::write(&hero, "aa").expect("write hero");
    fs::write(&table, "bbb").expect("write table");

    let rows = vec![test_row(1, &hero), test_row(2, &table)];
    let state = test_state(dir.path(), "chars hero");
    let visible = compute_visible_row_indices_for(
        &rows,
        &state,
        FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![0]);
}

#[test]
fn compute_visible_rows_sorts_by_size_numerically() {
    let dir = tempdir().expect("tmpdir");
    let small = dir.path().join("small.ma");
    let large = dir.path().join("large.ma");
    fs::write(&small, "aa").expect("write small");
    fs::write(&large, "abcdefghij").expect("write large");

    let mut small_row = test_row(1, &small);
    let mut large_row = test_row(2, &large);
    small_row.modified = Some(UNIX_EPOCH + Duration::from_secs(1));
    large_row.modified = Some(UNIX_EPOCH + Duration::from_secs(2));

    let visible = compute_visible_row_indices_for(
        &[small_row, large_row],
        &test_state(dir.path(), ""),
        FileTableSort {
            key: FileSortKey::Size,
            direction: ColumnSort::Descending,
        },
    );

    assert_eq!(visible, vec![1, 0]);
}

#[test]
fn build_file_table_rows_shows_missing_count_and_blank_when_unanalyzed() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let analyzed = workspace.join("analyzed.ma");
    let unanalyzed = workspace.join("unanalyzed.ma");
    fs::write(
        &analyzed,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write analyzed");
    fs::write(&unanalyzed, "//Maya ASCII 2026 scene\n").expect("write unanalyzed");

    let mut analyzed_row = test_row(1, &analyzed);
    analyzed_row.paths_report = Some(collect_scene_paths(&analyzed, PathKind::All).expect("paths"));
    analyzed_row.refresh_path_resolution_cache();
    let unanalyzed_row = test_row(2, &unanalyzed);

    let state = test_state(workspace.as_path(), "");
    let rows = build_file_table_rows(
        &[analyzed_row, unanalyzed_row],
        &[0, 1],
        &state,
        &I18n::new(SupportedLocale::English),
    );

    assert_eq!(rows[0].missing, "1");
    assert_eq!(rows[1].missing, "");
}

#[test]
fn build_file_table_rows_prefers_report_findings_when_cached_count_is_stale() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("literal_python.ma");
    write_literal_mel_python_scene(&scene);

    let RowJobResult::Analyze(result) =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    let mut row = test_row(1, &scene);
    let findings = result.audit_report.findings.len();
    row.audit_report = Some(result.audit_report);
    row.dump_report = result.dump_report;
    row.findings = 0;

    let state = PersistedState {
        file_list_findings_only: true,
        ..test_state(dir.path(), "")
    };
    let visible = compute_visible_row_indices_for(
        std::slice::from_ref(&row),
        &state,
        FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        },
    );
    let rows = build_file_table_rows(
        &[row],
        &[0],
        &test_state(dir.path(), ""),
        &I18n::new(SupportedLocale::English),
    );

    assert_eq!(visible, vec![0]);
    assert_eq!(rows[0].findings, findings.to_string());
}

#[test]
fn build_file_table_rows_marks_scene_workspace_membership() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let outside_dir = dir.path().join("outside");
    fs::create_dir_all(&workspace).expect("mkdir workspace");
    fs::create_dir_all(&outside_dir).expect("mkdir outside");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let inside = workspace.join("inside.ma");
    let outside = outside_dir.join("outside.ma");
    fs::write(&inside, "//Maya ASCII 2026 scene\n").expect("write inside");
    fs::write(&outside, "//Maya ASCII 2026 scene\n").expect("write outside");

    let rows = build_file_table_rows(
        &[test_row(1, &inside), test_row(2, &outside)],
        &[0, 1],
        &test_state(workspace.as_path(), ""),
        &I18n::new(SupportedLocale::English),
    );

    assert!(rows[0].has_scene_workspace);
    assert!(!rows[1].has_scene_workspace);
}

#[test]
fn compute_visible_rows_sorts_workspace_members_first() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let outside_dir = dir.path().join("outside");
    fs::create_dir_all(&workspace).expect("mkdir workspace");
    fs::create_dir_all(&outside_dir).expect("mkdir outside");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let inside = workspace.join("inside.ma");
    let outside = outside_dir.join("outside.ma");
    fs::write(&inside, "//Maya ASCII 2026 scene\n").expect("write inside");
    fs::write(&outside, "//Maya ASCII 2026 scene\n").expect("write outside");

    let visible = compute_visible_row_indices_for(
        &[test_row(1, &outside), test_row(2, &inside)],
        &test_state(workspace.as_path(), ""),
        FileTableSort {
            key: FileSortKey::Workspace,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![1, 0]);
}

#[test]
fn build_job_history_log_lines_uses_app_history_entries() {
    let lines = build_job_history_log_lines(
        &I18n::new(SupportedLocale::English),
        &[JobHistoryEntry {
            operation: "save".to_string(),
            input: PathBuf::from("tests/hero.ma"),
            output: Some(PathBuf::from("tests/out/hero.ma")),
            summary: "saved".to_string(),
            failed: false,
            timestamp: Some("2026-04-02 12:00:00".to_string()),
        }],
    );

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("2026-04-02 12:00:00"));
    assert!(lines[0].contains("Saving"));
    assert!(lines[0].contains("tests/hero.ma -> tests/out/hero.ma"));
}

#[test]
fn missing_path_count_for_row_counts_only_missing_entries() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let scene = workspace.join("hero.ma");
    fs::write(workspace.join("textures/existing.tx"), "tx").expect("existing tx");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/existing.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    assert_eq!(missing_path_count_for_row(&row), Some(1));
}

#[test]
fn compute_visible_rows_sorts_by_missing_count_and_places_unanalyzed_last() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let none_missing = workspace.join("none_missing.ma");
    let one_missing = workspace.join("one_missing.ma");
    let unanalyzed = workspace.join("unanalyzed.ma");
    fs::write(workspace.join("textures/existing.tx"), "tx").expect("existing tx");
    fs::write(
        &none_missing,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/existing.tx\";\n",
        ),
    )
    .expect("write none missing");
    fs::write(
        &one_missing,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write one missing");
    fs::write(&unanalyzed, "//Maya ASCII 2026 scene\n").expect("write unanalyzed");

    let mut none_missing_row = test_row(1, &none_missing);
    none_missing_row.paths_report =
        Some(collect_scene_paths(&none_missing, PathKind::All).expect("paths"));
    none_missing_row.refresh_path_resolution_cache();
    let mut one_missing_row = test_row(2, &one_missing);
    one_missing_row.paths_report =
        Some(collect_scene_paths(&one_missing, PathKind::All).expect("paths"));
    one_missing_row.refresh_path_resolution_cache();
    let unanalyzed_row = test_row(3, &unanalyzed);

    let visible = compute_visible_row_indices_for(
        &[one_missing_row, unanalyzed_row, none_missing_row],
        &test_state(workspace.as_path(), ""),
        FileTableSort {
            key: FileSortKey::Missing,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![2, 0, 1]);
}

#[test]
fn compute_visible_rows_places_missing_modified_at_end_for_ascending_sort() {
    let dir = tempdir().expect("tmpdir");
    let older = dir.path().join("older.ma");
    let unknown = dir.path().join("unknown.ma");
    fs::write(&older, "aa").expect("write older");
    fs::write(&unknown, "bb").expect("write unknown");

    let mut older_row = test_row(1, &older);
    let mut unknown_row = test_row(2, &unknown);
    older_row.modified = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10));
    unknown_row.modified = None;

    let visible = compute_visible_row_indices_for(
        &[unknown_row, older_row],
        &test_state(dir.path(), ""),
        FileTableSort {
            key: FileSortKey::Modified,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![1, 0]);
}

#[test]
fn compute_visible_rows_filters_to_findings_only() {
    let dir = tempdir().expect("tmpdir");
    let keep = dir.path().join("keep.ma");
    let hide = dir.path().join("hide.ma");
    fs::write(&keep, "aa").expect("write keep");
    fs::write(&hide, "bb").expect("write hide");

    let mut keep_row = test_row(1, &keep);
    keep_row.findings = 2;
    let hide_row = test_row(2, &hide);

    let mut state = test_state(dir.path(), "");
    state.file_list_findings_only = true;
    let visible = compute_visible_row_indices_for(
        &[hide_row, keep_row],
        &state,
        FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![1]);
}

#[test]
fn compute_visible_rows_filters_to_missing_only() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    fs::write(workspace.join("textures/existing.tx"), "tx").expect("write existing");
    let keep = workspace.join("keep.ma");
    let hide = workspace.join("hide.ma");
    fs::write(
        &keep,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write keep");
    fs::write(
        &hide,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/existing.tx\";\n",
        ),
    )
    .expect("write hide");

    let mut keep_row = test_row(1, &keep);
    keep_row.paths_report = Some(collect_scene_paths(&keep, PathKind::All).expect("paths"));
    keep_row.refresh_path_resolution_cache();
    let mut hide_row = test_row(2, &hide);
    hide_row.paths_report = Some(collect_scene_paths(&hide, PathKind::All).expect("paths"));
    hide_row.refresh_path_resolution_cache();

    let mut state = test_state(workspace.as_path(), "");
    state.file_list_missing_only = true;
    let visible = compute_visible_row_indices_for(
        &[hide_row, keep_row],
        &state,
        FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![1]);
}

#[test]
fn compute_visible_rows_combines_findings_missing_filters_with_or_logic() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let keep = workspace.join("hero_keep.ma");
    let no_missing = workspace.join("hero_no_missing.ma");
    let no_findings = workspace.join("hero_no_findings.ma");
    fs::write(workspace.join("textures/existing.tx"), "tx").expect("write existing");
    fs::write(
        &keep,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write keep");
    fs::write(
        &no_missing,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/existing.tx\";\n",
        ),
    )
    .expect("write no_missing");
    fs::write(
        &no_findings,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write no_findings");

    let mut keep_row = test_row(1, &keep);
    keep_row.findings = 2;
    keep_row.paths_report = Some(collect_scene_paths(&keep, PathKind::All).expect("paths"));
    keep_row.refresh_path_resolution_cache();

    let mut no_missing_row = test_row(2, &no_missing);
    no_missing_row.findings = 1;
    no_missing_row.paths_report =
        Some(collect_scene_paths(&no_missing, PathKind::All).expect("paths"));
    no_missing_row.refresh_path_resolution_cache();

    let mut no_findings_row = test_row(3, &no_findings);
    no_findings_row.paths_report =
        Some(collect_scene_paths(&no_findings, PathKind::All).expect("paths"));
    no_findings_row.refresh_path_resolution_cache();

    let mut state = test_state(workspace.as_path(), "");
    state.file_list_findings_only = true;
    state.file_list_missing_only = true;
    let visible = compute_visible_row_indices_for(
        &[no_missing_row, no_findings_row, keep_row],
        &state,
        FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![2, 1, 0]);
}

#[test]
fn compute_visible_rows_combines_dirty_with_findings_missing_filters_using_or_logic() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    fs::write(workspace.join("textures/existing.tx"), "tx").expect("write existing");
    let dirty = workspace.join("dirty.ma");
    let findings = workspace.join("findings.ma");
    let missing = workspace.join("missing.ma");
    let hidden = workspace.join("hidden.ma");
    for path in [&dirty, &findings, &missing, &hidden] {
        fs::write(
            path,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"textures/existing.tx\";\n",
            ),
        )
        .expect("write scene");
    }
    fs::write(
        &missing,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write missing scene");

    let mut dirty_row = test_row(1, &dirty);
    dirty_row
        .path_overrides
        .insert(0, "textures/dirty.tx".to_string());
    let mut findings_row = test_row(2, &findings);
    findings_row.findings = 1;
    let mut missing_row = test_row(3, &missing);
    missing_row.paths_report = Some(collect_scene_paths(&missing, PathKind::All).expect("paths"));
    missing_row.refresh_path_resolution_cache();
    let hidden_row = test_row(4, &hidden);

    let mut state = test_state(workspace.as_path(), "");
    state.file_list_findings_only = true;
    state.file_list_missing_only = true;
    state.file_list_dirty_only = true;
    let visible = compute_visible_row_indices_for(
        &[dirty_row, findings_row, missing_row, hidden_row],
        &state,
        FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![0, 1, 2]);
}

#[test]
fn compute_visible_rows_combines_or_filters_with_search() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let keep = workspace.join("hero_keep.ma");
    let other = workspace.join("prop_missing.ma");
    fs::write(
        &keep,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write keep");
    fs::write(
        &other,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write other");

    let mut keep_row = test_row(1, &keep);
    keep_row.findings = 1;
    keep_row.paths_report = Some(collect_scene_paths(&keep, PathKind::All).expect("paths"));
    keep_row.refresh_path_resolution_cache();

    let mut other_row = test_row(2, &other);
    other_row.paths_report = Some(collect_scene_paths(&other, PathKind::All).expect("paths"));
    other_row.refresh_path_resolution_cache();

    let mut state = test_state(workspace.as_path(), "hero keep");
    state.file_list_findings_only = true;
    state.file_list_missing_only = true;
    let visible = compute_visible_row_indices_for(
        &[other_row, keep_row],
        &state,
        FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![1]);
}

#[test]
fn visible_selection_range_indices_only_returns_visible_rows() {
    let visible = vec![0, 2, 4, 6];
    assert_eq!(
        visible_selection_range_indices(&visible, 2, 6),
        Some(vec![2, 4, 6])
    );
    assert_eq!(
        visible_selection_range_indices(&visible, 0, 4),
        Some(vec![0, 2, 4])
    );
}

#[test]
fn visible_selection_range_indices_returns_none_for_invisible_anchor() {
    let visible = vec![0, 2, 4, 6];
    assert_eq!(visible_selection_range_indices(&visible, 1, 6), None);
    assert_eq!(visible_selection_range_indices(&visible, 0, 5), None);
}

#[test]
fn visible_path_selection_targets_only_returns_visible_rows() {
    let rows = vec![
        super::PathTableRow {
            edit_targets: vec![(1, 0)],
            captured_order: None,
            path_kind: PathTypeFilter::File,
            owner_deletable: false,
            owner_deleted: false,
            selected: false,
            scene: String::new(),
            node: String::new(),
            value: String::new(),
            value_style: None,
            dirty: false,
            resolution_badge: None,
            editable: true,
            editing: false,
            preview_only: false,
        },
        super::PathTableRow {
            edit_targets: vec![(1, 1)],
            captured_order: None,
            path_kind: PathTypeFilter::File,
            owner_deletable: false,
            owner_deleted: false,
            selected: false,
            scene: String::new(),
            node: String::new(),
            value: String::new(),
            value_style: None,
            dirty: false,
            resolution_badge: None,
            editable: true,
            editing: false,
            preview_only: false,
        },
        super::PathTableRow {
            edit_targets: vec![(2, 0)],
            captured_order: None,
            path_kind: PathTypeFilter::Reference,
            owner_deletable: false,
            owner_deleted: false,
            selected: false,
            scene: String::new(),
            node: String::new(),
            value: String::new(),
            value_style: None,
            dirty: false,
            resolution_badge: None,
            editable: true,
            editing: false,
            preview_only: false,
        },
    ];

    assert_eq!(
        visible_path_selection_targets(&rows, &vec![(1, 0)], &vec![(2, 0)]),
        Some(vec![vec![(1, 0)], vec![(1, 1)], vec![(2, 0)]])
    );
    assert_eq!(
        visible_path_selection_targets(&rows, &vec![(9, 9)], &vec![(2, 0)]),
        None
    );
}

#[test]
fn build_audit_result_rows_prefixes_the_source_file() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("top_level_python.ma");
    write_top_level_python_scene(&path);
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.audit_report = Some(result.audit_report);

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);

    assert!(!rows.is_empty());
    assert!(
        rows.iter()
            .all(|audit_row| audit_row.scene_name == "top_level_python.ma")
    );
}

#[test]
fn default_audit_severity_filter_excludes_info() {
    let filter = default_audit_severity_filter();
    assert!(!filter.contains(&AuditSeverityFilter::Info));
    assert!(filter.contains(&AuditSeverityFilter::Low));
    assert!(filter.contains(&AuditSeverityFilter::MediumPlus));
}

#[test]
fn audit_table_columns_use_localized_labels() {
    let columns = audit_table_columns(SupportedLocale::English, default_audit_sort());

    assert_eq!(columns.len(), 5);
    assert_eq!(columns[0].name.as_ref(), "Scene");
    assert_eq!(columns[1].name.as_ref(), "Severity");
    assert_eq!(columns[2].name.as_ref(), "Summary");
    assert_eq!(columns[3].name.as_ref(), "Code");
    assert_eq!(columns[4].name.as_ref(), "Sink");
}

#[test]
fn filter_audit_result_rows_keeps_only_selected_severities() {
    let rows = vec![
        AuditResultRow {
            key: AuditResultRowKey {
                row_id: 1,
                item_kind: AuditResultItemKind::Finding,
                item_index: 0,
            },
            scene_name: "a.ma".to_string(),
            severity: AuditSeverity::Info,
            summary: "info".to_string(),
            code: "info_code".to_string(),
            sink: "none".to_string(),
            preview: String::new(),
            source_line: None,
            evidence: Vec::new(),
            dirty: false,
            clean_target: None,
            clean_state: AuditRowCleanState::Unsupported,
        },
        AuditResultRow {
            key: AuditResultRowKey {
                row_id: 1,
                item_kind: AuditResultItemKind::Finding,
                item_index: 1,
            },
            scene_name: "a.ma".to_string(),
            severity: AuditSeverity::Critical,
            summary: "high".to_string(),
            code: "high_code".to_string(),
            sink: "py_exec".to_string(),
            preview: String::new(),
            source_line: None,
            evidence: Vec::new(),
            dirty: false,
            clean_target: None,
            clean_state: AuditRowCleanState::Unsupported,
        },
    ];

    let filtered = filter_audit_result_rows(&rows, &default_audit_severity_filter());

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].severity, AuditSeverity::Critical);
}

#[test]
fn build_audit_table_model_dirty_filter_combines_with_severity_filter() {
    let clean_low = test_audit_row(1, 0, "clean_low.ma", "clean low", &["node: clean"]);
    let mut dirty_low = test_audit_row(2, 0, "dirty_low.ma", "dirty low", &["node: dirty"]);
    let mut dirty_info = test_audit_row(3, 0, "dirty_info.ma", "dirty info", &["node: info"]);
    dirty_low.dirty = true;
    dirty_info.dirty = true;
    dirty_info.severity = AuditSeverity::Info;

    let model = build_audit_table_model(
        &[clean_low, dirty_low, dirty_info],
        &BTreeSet::new(),
        &BTreeSet::from([AuditSeverityFilter::Low]),
        true,
        false,
        "",
        default_audit_sort(),
        SupportedLocale::English,
    );

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].scene_name, "dirty_low.ma");
}

#[test]
fn build_audit_table_model_dedups_only_exact_matches() {
    let rows = vec![
        test_audit_row(1, 0, "first.ma", "shared summary", &["node: scriptNode1"]),
        test_audit_row(2, 0, "second.ma", "shared summary", &["node: scriptNode1"]),
        test_audit_row(3, 0, "third.ma", "shared summary", &["node: different"]),
    ];

    let model = build_audit_table_model(
        &rows,
        &BTreeSet::new(),
        &BTreeSet::from([AuditSeverityFilter::Low]),
        false,
        true,
        "",
        default_audit_sort(),
        SupportedLocale::English,
    );

    assert_eq!(model.rows.len(), 2);
    assert_eq!(
        model.rows[0].scene_names,
        vec!["first.ma".to_string(), "second.ma".to_string()]
    );
    assert_eq!(model.rows[0].row_keys.len(), 2);
    assert_eq!(model.rows[1].scene_names, vec!["third.ma".to_string()]);
}

#[test]
fn build_audit_table_model_search_matches_deduped_scene_names() {
    let rows = vec![
        test_audit_row(1, 0, "alpha.ma", "shared summary", &["node: scriptNode1"]),
        test_audit_row(2, 0, "beta.ma", "shared summary", &["node: scriptNode1"]),
    ];

    let model = build_audit_table_model(
        &rows,
        &BTreeSet::new(),
        &BTreeSet::from([AuditSeverityFilter::Low]),
        false,
        true,
        "beta",
        default_audit_sort(),
        SupportedLocale::English,
    );

    assert_eq!(model.rows.len(), 1);
    assert_eq!(
        model.rows[0].scene_names,
        vec!["alpha.ma".to_string(), "beta.ma".to_string()]
    );
}

#[test]
fn build_audit_table_model_sorts_by_summary() {
    let rows = vec![
        test_audit_row(1, 0, "first.ma", "zeta summary", &["node: scriptNode1"]),
        test_audit_row(2, 0, "second.ma", "alpha summary", &["node: scriptNode1"]),
    ];

    let model = build_audit_table_model(
        &rows,
        &BTreeSet::new(),
        &BTreeSet::from([AuditSeverityFilter::Low]),
        false,
        false,
        "",
        AuditTableSort {
            key: AuditSortKey::Summary,
            direction: ColumnSort::Ascending,
        },
        SupportedLocale::English,
    );

    assert_eq!(model.rows[0].summary, "alpha summary");
    assert_eq!(model.rows[1].summary, "zeta summary");
}

#[test]
fn build_audit_clipboard_payload_joins_preview_and_evidence() {
    let payload = build_audit_clipboard_payload(
        "print(\"hello\")",
        &["command: python".to_string(), "flag: -c".to_string()],
    );

    assert_eq!(payload, "print(\"hello\")\n\ncommand: python\nflag: -c");
}

#[test]
fn build_audit_result_rows_marks_script_node_findings_cleanable() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("mel_python_literal.ma");
    write_literal_mel_python_scene(&path);
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.audit_report = Some(result.audit_report);

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);

    assert!(
        rows.iter().any(|audit_row| {
            audit_row.clean_target
                == Some(ExecutionCleanTarget::ScriptNode {
                    node_name: "literalPythonReview".to_string(),
                })
                && audit_row.clean_state == AuditRowCleanState::Available
        }),
        "expected at least one cleanable script-node audit row"
    );
}

#[test]
fn build_audit_result_rows_marks_pending_clean_targets_as_staged() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("mel_python_literal.ma");
    write_literal_mel_python_scene(&path);
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.audit_report = Some(result.audit_report);
    row.pending_clean_targets
        .insert(ExecutionCleanTarget::ScriptNode {
            node_name: "literalPythonReview".to_string(),
        });

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);

    assert!(
        rows.iter().any(|audit_row| {
            audit_row.clean_target
                == Some(ExecutionCleanTarget::ScriptNode {
                    node_name: "literalPythonReview".to_string(),
                })
                && audit_row.clean_state == AuditRowCleanState::Staged
                && audit_row.dirty
        }),
        "expected staged targeted clean row to be marked dirty"
    );
}

#[test]
fn build_audit_table_model_marks_staged_rows_as_dirty() {
    let mut row = test_audit_row(1, 0, "scene.ma", "script literalPythonReview", &["node: a"]);
    row.clean_state = AuditRowCleanState::Staged;
    row.dirty = true;

    let table = display_audit_rows(vec![row]);

    assert_eq!(table.len(), 1);
    assert!(table[0].dirty);
    assert_eq!(table[0].clean_state, AuditRowCleanState::Staged);
}

#[test]
fn audit_context_menu_state_keeps_clean_action_visible_when_blocked_by_other_dirty() {
    let blocked_row = super::AuditTableRow {
        key: AuditResultRowKey {
            row_id: 1,
            item_kind: AuditResultItemKind::DumpScriptNode,
            item_index: 0,
        },
        row_keys: vec![AuditResultRowKey {
            row_id: 1,
            item_kind: AuditResultItemKind::DumpScriptNode,
            item_index: 0,
        }],
        selected: true,
        scene_name: "scene.ma".to_string(),
        scene_names: vec!["scene.ma".to_string()],
        severity: AuditSeverity::Info,
        summary: "script scriptNode1".to_string(),
        code: "script_node".to_string(),
        sink: "observe".to_string(),
        preview: "print".to_string(),
        source_line: None,
        evidence: vec!["node: scriptNode1".to_string()],
        dirty: false,
        clean_target: Some(ExecutionCleanTarget::ScriptNode {
            node_name: "scriptNode1".to_string(),
        }),
        clean_state: AuditRowCleanState::BlockedByOtherDirty,
    };

    let state = audit_context_menu_state(&[blocked_row]);

    assert!(!state.can_clean);
    assert!(!state.can_undo);
    assert!(state.show_disabled_clean);
}

#[test]
fn build_audit_result_rows_marks_top_level_command_findings_cleanable() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("top_level_python.ma");
    write_top_level_python_scene(&path);
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.audit_report = Some(result.audit_report);

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);
    let detail = rows.iter().find_map(|audit_row| {
        matches!(
            audit_row.clean_target,
            Some(ExecutionCleanTarget::TopLevelCommand { .. })
        )
        .then(|| resolve_audit_detail_view_model(&display_audit_rows(rows.clone()), &audit_row.key))
        .flatten()
    });

    assert!(
        detail.is_some(),
        "expected at least one cleanable top-level command detail"
    );
    assert_eq!(detail.expect("detail").source_line, Some(3));
}

#[test]
fn audit_clean_target_maps_top_level_proc_definition_to_range_delete() {
    let origin = ExecutionOrigin {
        lang: ExecutionLanguage::Mel,
        trigger: ExecutionTrigger::Unknown,
        surface_kind: ExecutionSurfaceKind::TopLevelProcDefinition,
        node_name: None,
        attr_name: None,
        source_kind: Some("proc_definition".to_string()),
        source_range: Some(ExecutionSourceRange { start: 42, end: 84 }),
        chunk_form: None,
        chunk_tag: None,
        chunk_node_offset: None,
    };

    let target = audit_clean_target(ExecutionSurfaceKind::TopLevelProcDefinition, &origin);

    assert_eq!(
        target,
        Some(ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange { start: 42, end: 84 },
        })
    );
}

#[test]
fn audit_clean_target_maps_top_level_other_statement_to_range_delete() {
    let origin = ExecutionOrigin {
        lang: ExecutionLanguage::Mel,
        trigger: ExecutionTrigger::FileOpen,
        surface_kind: ExecutionSurfaceKind::TopLevelOtherStatement,
        node_name: None,
        attr_name: None,
        source_kind: Some("top_level_other".to_string()),
        source_range: Some(ExecutionSourceRange {
            start: 120,
            end: 188,
        }),
        chunk_form: None,
        chunk_tag: None,
        chunk_node_offset: None,
    };

    let target = audit_clean_target(ExecutionSurfaceKind::TopLevelOtherStatement, &origin);

    assert_eq!(
        target,
        Some(ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange {
                start: 120,
                end: 188,
            },
        })
    );
}

#[test]
fn build_audit_result_rows_marks_file_command_callback_findings_cleanable() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("callback.ma");
    fs::write(
        &path,
        "//Maya ASCII 2026 scene\nfile -r -command \"onLoad\" \"python(\\\"import os\\\")\" \"C:/ref.ma\";\n",
    )
    .expect("write scene");
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.audit_report = Some(result.audit_report);

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);
    let audit_row = rows
        .iter()
        .find(|audit_row| {
            matches!(
                audit_row.clean_target,
                Some(ExecutionCleanTarget::FileCommandCallback { .. })
            ) && audit_row.clean_state == AuditRowCleanState::Available
        })
        .expect("expected cleanable callback audit row");
    let detail = resolve_audit_detail_view_model(&display_audit_rows(rows.clone()), &audit_row.key)
        .expect("callback detail");

    assert!(
        matches!(
            audit_row.clean_target,
            Some(ExecutionCleanTarget::FileCommandCallback { .. })
        ),
        "expected at least one cleanable file-command callback audit row"
    );
    assert_eq!(detail.source_line, Some(2));
}

#[test]
fn audit_clean_target_maps_raw_chunk_text_to_mb_owner_form() {
    let origin = ExecutionOrigin {
        lang: ExecutionLanguage::Mel,
        trigger: ExecutionTrigger::Manual,
        surface_kind: ExecutionSurfaceKind::RawChunkText,
        node_name: None,
        attr_name: None,
        source_kind: None,
        source_range: None,
        chunk_form: Some("SCRP".to_string()),
        chunk_tag: Some("STR ".to_string()),
        chunk_node_offset: Some(0xCFC),
    };

    let target = audit_clean_target(ExecutionSurfaceKind::RawChunkText, &origin);

    assert_eq!(
        target,
        Some(ExecutionCleanTarget::MbOwnerForm {
            form: "SCRP".to_string(),
            node_offset: 0xCFC,
        })
    );
}

#[test]
fn audit_clean_target_prefers_mb_owner_form_for_script_node_body() {
    let origin = ExecutionOrigin {
        lang: ExecutionLanguage::Mel,
        trigger: ExecutionTrigger::FileOpen,
        surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
        node_name: Some("uiConfigurationScriptNode".to_string()),
        attr_name: Some(".b".to_string()),
        source_kind: Some("scriptType=1,sourceType=0".to_string()),
        source_range: None,
        chunk_form: Some("SCRP".to_string()),
        chunk_tag: Some("STR ".to_string()),
        chunk_node_offset: Some(0xCFC),
    };

    let target = audit_clean_target(ExecutionSurfaceKind::ScriptNodeBody, &origin);

    assert_eq!(
        target,
        Some(ExecutionCleanTarget::MbOwnerForm {
            form: "SCRP".to_string(),
            node_offset: 0xCFC,
        })
    );
}

#[test]
fn resolve_audit_detail_view_model_returns_none_for_unknown_row_key() {
    let rows = vec![AuditResultRow {
        key: AuditResultRowKey {
            row_id: 99,
            item_kind: AuditResultItemKind::Finding,
            item_index: 0,
        },
        scene_name: "scene.ma".to_string(),
        severity: AuditSeverity::Info,
        summary: "note".to_string(),
        code: "note".to_string(),
        sink: "none".to_string(),
        preview: String::new(),
        source_line: None,
        evidence: Vec::new(),
        dirty: false,
        clean_target: None,
        clean_state: AuditRowCleanState::Unsupported,
    }];

    assert!(filter_audit_result_rows(&rows, &default_audit_severity_filter()).is_empty());
    assert!(
        resolve_audit_detail_view_model(
            &[],
            &AuditResultRowKey {
                row_id: 99,
                item_kind: AuditResultItemKind::Finding,
                item_index: 0,
            }
        )
        .is_none()
    );
}

#[test]
fn resolve_audit_clipboard_payload_uses_detail_preview_and_evidence() {
    let path = repo_root().join("tests/02/sphere.mb");
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.dump_report = result.dump_report;

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);
    let script_row = rows
        .iter()
        .find(|audit_row| audit_row.key.item_kind == AuditResultItemKind::DumpScriptNode)
        .expect("dump script row");

    let payload =
        resolve_audit_clipboard_payload(&display_audit_rows(rows.clone()), &script_row.key)
            .expect("clipboard payload");

    assert!(payload.contains("node:"));
    assert!(!payload.is_empty());
}

#[test]
fn build_audit_result_rows_show_all_dump_info_rows_for_multi_select() {
    let path = repo_root().join("tests/02/sphere.mb");
    let mut first = test_row(1, &path);
    let mut second = test_row(2, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    first.dump_report = result.dump_report.clone();
    second.dump_report = result.dump_report;

    let rows = build_audit_result_rows(&[first, second], &[0, 1]);

    assert!(
        rows.iter()
            .any(|row| row.key.item_kind == AuditResultItemKind::DumpRequire),
        "multi-select should include require rows"
    );
    assert!(
        rows.iter()
            .any(|row| row.key.item_kind == AuditResultItemKind::DumpScriptNode),
        "multi-select should include script rows"
    );
}

#[test]
fn dump_rows_include_require_and_script_previews() {
    let path = repo_root().join("tests/02/sphere.mb");
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.dump_report = result.dump_report;

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);
    let require = rows
        .iter()
        .find(|row| row.key.item_kind == AuditResultItemKind::DumpRequire)
        .expect("dump require row");
    let script = rows
        .iter()
        .find(|row| row.key.item_kind == AuditResultItemKind::DumpScriptNode)
        .expect("dump script row");

    let require_detail =
        resolve_audit_detail_view_model(&display_audit_rows(rows.clone()), &require.key)
            .expect("dump require detail");
    let script_detail =
        resolve_audit_detail_view_model(&display_audit_rows(rows.clone()), &script.key)
            .expect("dump script detail");

    assert!(!require_detail.preview.is_empty());
    assert!(!script_detail.preview.is_empty());
}

#[test]
fn dump_script_rows_are_cleanable() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("dump_script_cleanable.ma");
    fs::write(
        &path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
        ),
    )
    .expect("write scene");
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.dump_report = result.dump_report;

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);
    let script_row = rows
        .iter()
        .find(|row| row.key.item_kind == AuditResultItemKind::DumpScriptNode)
        .expect("dump script row");

    assert_eq!(
        script_row.clean_target,
        Some(ExecutionCleanTarget::ScriptNode {
            node_name: "scriptNode1".to_string(),
        })
    );
    assert_eq!(script_row.clean_state, AuditRowCleanState::Available);
}

#[test]
fn dump_script_rows_use_mb_owner_form_target_when_audit_provenance_is_available() {
    let path = repo_root().join("tests/02/sphere.mb");
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.audit_report = Some(result.audit_report);
    row.dump_report = result.dump_report;

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);
    let script_row = rows
        .iter()
        .find(|row| row.key.item_kind == AuditResultItemKind::DumpScriptNode)
        .expect("dump script row");

    assert!(matches!(
        script_row.clean_target,
        Some(ExecutionCleanTarget::MbOwnerForm {
            ref form,
            node_offset: _,
        }) if form == "SCRP"
    ));
    assert_eq!(script_row.clean_state, AuditRowCleanState::Available);
}

#[test]
fn clean_targets_for_removed_script_nodes_prefers_row_specific_mb_targets() {
    let path = repo_root().join("tests/02/sphere.mb");
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    let removed_node_name = result
        .dump_report
        .as_ref()
        .expect("dump report")
        .script_entries
        .first()
        .expect("script entry")
        .name
        .clone();
    row.audit_report = Some(result.audit_report);
    row.dump_report = result.dump_report;

    let staged_targets = clean_targets_for_removed_script_nodes(&row, &[removed_node_name]);

    assert!(staged_targets.iter().any(|target| {
        matches!(
            target,
            ExecutionCleanTarget::MbOwnerForm {
                form,
                node_offset: _,
            } if form == "SCRP"
        )
    }));
}

#[test]
fn plugin_require_rows_are_cleanable_but_maya_require_rows_are_not() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("dump_require_cleanable.ma");
    fs::write(
        &path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "requires \"pluginA\" \"1.0\";\n",
        ),
    )
    .expect("write scene");
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    assert_eq!(
        result
            .dump_report
            .as_ref()
            .expect("dump report")
            .require_entries
            .len(),
        2
    );
    assert_eq!(
        result
            .dump_report
            .as_ref()
            .expect("dump report")
            .require_entries[0]
            .kind,
        SceneDumpRequireKind::MayaVersion
    );
    assert_eq!(
        result
            .dump_report
            .as_ref()
            .expect("dump report")
            .require_entries[1]
            .kind,
        SceneDumpRequireKind::Plugin
    );
    row.dump_report = result.dump_report;

    let rows = build_audit_result_rows(std::slice::from_ref(&row), &[0]);
    let maya_row = rows
        .iter()
        .find(|audit_row| audit_row.summary == "require requires maya \"2026\";")
        .expect("maya require row");
    let plugin_row = rows
        .iter()
        .find(|audit_row| audit_row.summary == "require requires \"pluginA\" \"1.0\";")
        .expect("plugin require row");

    assert_eq!(maya_row.clean_target, None);
    assert_eq!(maya_row.clean_state, AuditRowCleanState::Unsupported);
    assert_eq!(
        plugin_row.clean_target,
        Some(ExecutionCleanTarget::PluginRequire {
            rendered: "requires \"pluginA\" \"1.0\";".to_string(),
        })
    );
    assert_eq!(plugin_row.clean_state, AuditRowCleanState::Available);
}

#[gpui::test]
fn refresh_audit_table_caches_rows_and_clears_hidden_dialog(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("top_level_python.ma");
    write_top_level_python_scene(&path);
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.selected = true;
    row.audit_report = Some(result.audit_report);
    row.dump_report = result.dump_report;

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows = vec![row];
        shell.refresh_file_table(cx);

        assert!(!shell.audit_all_rows.is_empty());
        assert!(!shell.audit_rows.is_empty());
        assert!(shell.audit_all_rows.len() > shell.audit_rows.len());
        assert_eq!(
            shell.audit_table.read(cx).delegate().rows.len(),
            shell.audit_rows.len()
        );

        let finding_key = shell
            .audit_rows
            .iter()
            .find(|row| row.severity != AuditSeverity::Info)
            .expect("finding row")
            .key
            .clone();
        shell.open_audit_detail_dialog(finding_key, window, cx);
        assert!(shell.audit_detail_dialog.is_some());

        shell.audit_severity_filter = BTreeSet::from([AuditSeverityFilter::Info]);
        shell.refresh_audit_table(cx);

        assert!(
            shell
                .audit_rows
                .iter()
                .all(|row| row.severity == AuditSeverity::Info)
        );
        assert!(shell.audit_detail_dialog.is_none());
        assert_eq!(
            shell.audit_table.read(cx).delegate().rows.len(),
            shell.audit_rows.len()
        );
    });
}

#[gpui::test]
fn audit_table_supports_multi_select(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("top_level_python.ma");
    write_top_level_python_scene(&path);
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.selected = true;
    row.audit_report = Some(result.audit_report);
    row.dump_report = result.dump_report;

    shell.update_in(visual_cx, |shell, _window, cx| {
        shell.rows = vec![row];
        shell.refresh_file_table(cx);
        shell.toggle_audit_severity(AuditSeverityFilter::Info, cx);

        let first = shell.audit_rows[0].key.clone();
        let second = shell.audit_rows[1].key.clone();

        shell.select_audit_row_by_key(first.clone(), Modifiers::default(), cx);
        shell.select_audit_row_by_key(second.clone(), Modifiers::control(), cx);

        assert_eq!(shell.selected_audit_keys.len(), 2);
        assert!(
            shell
                .audit_rows
                .iter()
                .any(|row| row.key == first && row.selected)
        );
        assert!(
            shell
                .audit_rows
                .iter()
                .any(|row| row.key == second && row.selected)
        );
    });
}

#[gpui::test]
fn audit_detail_dialog_open_populates_read_only_inputs(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let (mut row, key) = dump_script_audit_fixture();
    row.selected = true;

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows = vec![row];
        shell.refresh_file_table(cx);
        shell.toggle_audit_severity(AuditSeverityFilter::Info, cx);
        shell.open_audit_detail_dialog(key, window, cx);

        let state = shell
            .audit_detail_dialog
            .as_ref()
            .expect("audit detail state");

        assert!(!state.preview_text.is_empty());
        assert!(!state.evidence_text.is_empty());
        assert_eq!(
            state.preview_input.read(cx).value().to_string(),
            state.preview_text
        );
        assert_eq!(
            state.evidence_input.read(cx).value().to_string(),
            state.evidence_text
        );
        assert!(state.preview_input.read(cx).is_read_only());
        assert!(state.evidence_input.read(cx).is_read_only());
    });
}

#[gpui::test]
fn audit_detail_dialog_ignores_overlay_click(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let (mut row, key) = dump_script_audit_fixture();
    row.selected = true;

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows = vec![row];
        shell.refresh_file_table(cx);
        shell.toggle_audit_severity(AuditSeverityFilter::Info, cx);
        shell.open_audit_detail_dialog(key, window, cx);
        assert!(shell.audit_detail_dialog.is_some());
    });

    visual_cx.simulate_click(point(px(10.0), px(10.0)), Modifiers::default());

    shell.update_in(visual_cx, |shell, _window, _cx| {
        assert!(shell.audit_detail_dialog.is_some());
    });
}

#[gpui::test]
fn audit_detail_dialog_stays_within_resized_window(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let (mut row, key) = dump_script_audit_fixture();
    row.selected = true;

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows = vec![row];
        shell.refresh_file_table(cx);
        shell.toggle_audit_severity(AuditSeverityFilter::Info, cx);
        shell.open_audit_detail_dialog(key, window, cx);
        assert!(shell.audit_detail_dialog.is_some());
    });

    visual_cx.simulate_resize(size(px(640.0), px(420.0)));

    let close_bounds = visual_cx
        .debug_bounds("audit-detail-close")
        .expect("close button bounds");
    let body_bounds = visual_cx
        .debug_bounds("audit-detail-body")
        .expect("dialog body bounds");
    let viewport_bounds = visual_cx.update(|window, _| window.bounds());

    assert!(close_bounds.right() <= viewport_bounds.right());
    assert!(close_bounds.bottom() <= viewport_bounds.bottom());
    assert!(body_bounds.size.width > px(0.0));
    assert!(body_bounds.size.height > px(0.0));
}

#[gpui::test]
fn audit_detail_dialog_sync_refreshes_stale_input_text(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let (mut row, key) = dump_script_audit_fixture();
    row.selected = true;

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows = vec![row];
        shell.refresh_file_table(cx);
        shell.toggle_audit_severity(AuditSeverityFilter::Info, cx);
        shell.open_audit_detail_dialog(key, window, cx);

        let AuditDetailDialogState {
            preview_input,
            evidence_input,
            ..
        } = shell
            .audit_detail_dialog
            .as_ref()
            .expect("audit detail state")
            .clone();

        preview_input.update(cx, |input, cx| input.set_value("stale preview", window, cx));
        evidence_input.update(cx, |input, cx| {
            input.set_value("stale evidence", window, cx)
        });
        shell
            .audit_detail_dialog
            .as_mut()
            .expect("detail state")
            .preview_text = "stale preview".to_string();
        shell
            .audit_detail_dialog
            .as_mut()
            .expect("detail state")
            .evidence_text = "stale evidence".to_string();

        shell.sync_audit_detail_dialog_inputs(window, cx);

        let state = shell
            .audit_detail_dialog
            .as_ref()
            .expect("audit detail state");

        assert_ne!(state.preview_text, "stale preview");
        assert_ne!(state.evidence_text, "stale evidence");
        assert_eq!(
            state.preview_input.read(cx).value().to_string(),
            state.preview_text
        );
        assert_eq!(
            state.evidence_input.read(cx).value().to_string(),
            state.evidence_text
        );
    });
}

#[gpui::test]
fn replace_dialog_stays_within_resized_window(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let _dir = seed_file_table_selection_test_state(&shell, visual_cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows[0].selected = true;
        shell.rows[2].selected = true;
        shell.refresh_file_table(cx);
        shell.open_replace_dialog(window, cx);
        assert!(shell.replace_dialog.is_some());
    });

    visual_cx.simulate_resize(size(px(640.0), px(420.0)));

    let close_bounds = visual_cx
        .debug_bounds("replace-dialog-close")
        .expect("replace dialog close bounds");
    let body_bounds = visual_cx
        .debug_bounds("replace-dialog-body")
        .expect("replace dialog body bounds");
    let viewport_bounds = visual_cx.update(|window, _| window.bounds());

    assert!(close_bounds.right() <= viewport_bounds.right());
    assert!(close_bounds.bottom() <= viewport_bounds.bottom());
    assert!(body_bounds.size.width > px(0.0));
    assert!(body_bounds.size.height > px(0.0));
}

#[gpui::test]
fn replace_dialog_captures_only_selected_files(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let _dir = seed_file_table_selection_test_state(&shell, visual_cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows[0].selected = true;
        shell.rows[1].selected = false;
        shell.rows[2].selected = true;
        shell.open_replace_dialog(window, cx);

        let dialog = shell.replace_dialog.as_ref().expect("replace dialog");
        assert_eq!(dialog.captured_row_ids, vec![1, 3]);
    });
}

#[gpui::test]
fn replace_dialog_from_path_targets_replaces_only_selected_paths(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/old_a.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/old_b.tx\";\n",
        ),
    )
    .expect("write scene");

    shell.update_in(visual_cx, |shell, window, cx| {
        let mut row = test_row(1, &scene);
        row.selected = true;
        row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
        shell.rows = vec![row];

        shell.open_replace_dialog_for_path_targets(vec![(1, 1)], window, cx);
        shell
            .replace_from_input
            .update(cx, |input, cx| input.set_value("old", window, cx));
        shell
            .replace_to_input
            .update(cx, |input, cx| input.set_value("new", window, cx));
        shell.run_replace_preview(window, cx);
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let dialog = shell.replace_dialog.as_ref().expect("replace dialog");
        assert_eq!(
            dialog.path_targets,
            Some(BTreeMap::from([(1, BTreeSet::from([1]))]))
        );
        let preview = dialog.preview.as_ref().expect("preview");
        assert_eq!(preview.items.len(), 1);
        assert_eq!(preview.items[0].before_value, "textures/old_b.tx");
        assert_eq!(preview.items[0].after_value, "textures/new_b.tx");
        assert_eq!(preview.planned_overrides.len(), 1);
        assert_eq!(preview.planned_overrides[0].0, 1);
        assert_eq!(preview.planned_overrides[0].1.len(), 1);
        assert_eq!(preview.planned_overrides[0].1[0].entry_index, 1);
    });
}

#[gpui::test]
fn settings_menu_toggle_updates_ignore_folder_name_preference(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        assert!(shell.state.ignore_folder_names_enabled);
        shell.on_menu_toggle_ignore_folder_names(&MenuToggleIgnoreFolderNames, window, cx);
        assert!(!shell.state.ignore_folder_names_enabled);
    });
}

#[gpui::test]
fn settings_menu_updates_auto_analyze_parallelism_preference(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        assert_eq!(
            shell.state.auto_analyze_parallelism,
            AutoAnalyzeParallelismPreference::Four
        );
        shell.on_menu_auto_analyze_parallelism_32(&MenuAutoAnalyzeParallelism32, window, cx);
        assert_eq!(
            shell.state.auto_analyze_parallelism,
            AutoAnalyzeParallelismPreference::ThirtyTwo
        );
        assert_eq!(shell.state.auto_analyze_parallelism_limit(), 32);
    });
}

#[gpui::test]
fn max_bytes_dialog_apply_updates_preference(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        assert_eq!(shell.state.max_bytes, None);
        shell.open_max_bytes_dialog(window, cx);
        let dialog = shell.max_bytes_dialog.as_ref().expect("max bytes dialog");
        dialog
            .input
            .update(cx, |input, cx| input.set_value("4096", window, cx));

        assert!(shell.max_bytes_dialog_can_apply(cx));
        shell.apply_max_bytes_dialog(window, cx);

        assert!(shell.max_bytes_dialog.is_none());
        assert_eq!(shell.state.max_bytes, Some(4096));
    });
}

#[gpui::test]
fn max_bytes_dialog_reset_restores_default(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.max_bytes = Some(2048);
        shell.open_max_bytes_dialog(window, cx);
        shell.reset_max_bytes_dialog(window, cx);

        assert!(shell.max_bytes_dialog.is_none());
        assert_eq!(shell.state.max_bytes, None);
    });
}

#[test]
fn analyze_row_with_options_budget_exceed_returns_blocked_report() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("blocked.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"blocked\";\n",
            "    setAttr \".b\" -type \"string\" \"print(\\\"hi\\\")\";\n",
            "    setAttr \".st\" 0;\n",
        ),
    )
    .expect("write scene");

    let result = analyze_row_with_options(
        &scene,
        AuditModePreference::StrictDefault,
        &LoadOptions::default().with_max_parse_bytes(1),
    )
    .expect("analyze");

    let RowJobResult::Analyze(result) = result else {
        panic!("expected analyze result");
    };
    assert!(result.audit_report.is_parse_budget_blocked());
    assert_eq!(result.audit_report.notice_count(), 1);
    assert!(result.paths_report.is_none());
    assert!(result.dump_report.is_none());
}

#[gpui::test]
fn apply_job_result_marks_budget_blocked_rows_as_error(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("blocked.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"blocked\";\n",
            "    setAttr \".b\" -type \"string\" \"print(\\\"hi\\\")\";\n",
            "    setAttr \".st\" 0;\n",
        ),
    )
    .expect("write scene");
    let RowJobResult::Analyze(result) = analyze_row_with_options(
        &scene,
        AuditModePreference::StrictDefault,
        &LoadOptions::default().with_max_parse_bytes(1),
    )
    .expect("analyze") else {
        panic!("expected analyze result");
    };

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.rows = vec![test_row(1, &scene)];
        shell.apply_job_result(
            1,
            RowOperation::Analyze,
            RowJobResult::Analyze(result),
            None,
            window,
            cx,
        );

        assert!(matches!(
            shell.rows[0].status,
            FileStatus::Error(ref message) if message == "parse budget exceeded: max_bytes"
        ));
        assert!(
            shell.rows[0]
                .audit_report
                .as_ref()
                .is_some_and(|report| report.is_parse_budget_blocked())
        );
    });
}

#[test]
fn analyze_row_with_options_returns_blocked_report_for_mb_budget_exceed() {
    let scene = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/02/sphere.mb");

    let result = analyze_row_with_options(
        &scene,
        AuditModePreference::StrictDefault,
        &LoadOptions::default().with_max_parse_bytes(1),
    )
    .expect("analyze");

    let RowJobResult::Analyze(result) = result else {
        panic!("expected analyze result");
    };
    assert!(result.audit_report.is_parse_budget_blocked());
    assert_eq!(result.audit_report.notice_count(), 1);
    assert_eq!(
        result.audit_report.notices[0].message,
        "parse budget exceeded: max_parse_bytes"
    );
    assert!(result.paths_report.is_none());
    assert!(result.dump_report.is_none());
}

#[test]
fn analyze_row_with_options_keeps_paths_and_audit_after_cp932_prefix_line() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("cp932-prefix.ma");
    let source = concat!(
        "//Maya ASCII 2026 scene\n",
        "//Codeset: 932\n",
        "fileInfo \"comment\" \"名前名前名前\";\n",
        "createNode file -n \"file1\";\n",
        "    setAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
        "createNode script -n \"scriptNode1\";\n",
        "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
        "    setAttr \".st\" 1;\n",
        "    setAttr \".stp\" 1;\n",
    );
    let (bytes, _, _) = SHIFT_JIS.encode(source);
    fs::write(&scene, bytes.as_ref()).expect("write cp932 scene");

    let RowJobResult::Analyze(result) = analyze_row_with_options(
        &scene,
        AuditModePreference::StrictDefault,
        &LoadOptions::default(),
    )
    .expect("analyze") else {
        panic!("expected analyze result");
    };

    let paths_report = result.paths_report.expect("paths report");
    assert!(
        !paths_report.entries.is_empty(),
        "expected GUI analyze path report to be non-empty"
    );
    assert!(
        result.audit_report.surface_count > 0
            || !result.audit_report.findings.is_empty()
            || !result.audit_report.review_signals.is_empty()
            || !result.audit_report.notices.is_empty(),
        "expected GUI analyze audit report to retain observable results"
    );
}

#[gpui::test]
fn selected_audit_notice_lines_include_budget_notice(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("blocked.ma");
    fs::write(&scene, "//Maya ASCII 2026 scene\n").expect("write scene");

    shell.update_in(visual_cx, |shell, _window, _cx| {
        let plan = build_script_audit_plan(vec![], 64).expect("audit plan");
        let mut row = test_row(1, &scene);
        row.selected = true;
        row.audit_report = Some(build_parse_budget_blocked_audit_report(
            scene.clone(),
            SceneFormat::Ma,
            ValidationState::Invalid,
            &plan,
            AuditOptions::strict_default(),
            maya_scene_kit_observe::scene::MelParseBudgetLimit::MaxBytes,
            None,
        ));
        shell.rows = vec![row];

        let lines = selected_audit_notice_lines(shell, &[0]);
        assert_eq!(lines, vec!["parse budget exceeded: max_bytes".to_string()]);
    });
}

#[gpui::test]
fn selected_rows_parse_budget_blocked_without_paths_detects_blocked_selection(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("blocked.ma");
    fs::write(&scene, "//Maya ASCII 2026 scene\n").expect("write scene");

    shell.update_in(visual_cx, |shell, _window, _cx| {
        let plan = build_script_audit_plan(vec![], 64).expect("audit plan");
        let mut row = test_row(1, &scene);
        row.selected = true;
        row.audit_report = Some(build_parse_budget_blocked_audit_report(
            scene.clone(),
            SceneFormat::Ma,
            ValidationState::Invalid,
            &plan,
            AuditOptions::strict_default(),
            maya_scene_kit_observe::scene::MelParseBudgetLimit::MaxBytes,
            None,
        ));
        row.paths_report = None;
        shell.rows = vec![row];

        assert!(selected_rows_are_parse_budget_blocked_without_paths(
            shell,
            &[0]
        ));
    });
}

#[test]
fn render_analyze_completed_banner_includes_elapsed_seconds() {
    let i18n = I18n::new(SupportedLocale::English);
    let rendered = render_banner_message(
        &i18n,
        &super::BannerMessage::AnalyzeCompleted {
            name: "scene.ma".to_string(),
            elapsed: Duration::from_millis(1250),
        },
    );

    assert_eq!(rendered, "Analyzed scene.ma in 1.25s");
}

#[test]
fn render_workspace_auto_analyze_completed_banner_includes_elapsed_seconds() {
    let i18n = I18n::new(SupportedLocale::English);
    let rendered = render_banner_message(
        &i18n,
        &super::BannerMessage::WorkspaceAutoAnalyzeCompleted {
            count: 12,
            elapsed: Duration::from_millis(2500),
        },
    );

    assert_eq!(
        rendered,
        "Workspace auto analyze completed for 12 file(s) in 2.50s"
    );
}

#[gpui::test]
fn workspace_auto_analysis_dispatch_respects_parallelism_preference(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let paths: Vec<PathBuf> = (0..40)
        .map(|ix| dir.path().join(format!("scene_{ix:02}.ma")))
        .collect();
    for path in &paths {
        fs::write(path, "//Maya ASCII 2026 scene\n").expect("write scene");
    }

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(dir.path(), "");
        shell.state.workspace_auto_analyze = true;
        shell.state.auto_analyze_parallelism = AutoAnalyzeParallelismPreference::ThirtyTwo;
        shell.rows = paths
            .iter()
            .enumerate()
            .map(|(ix, path)| test_row(ix as u64 + 1, path))
            .collect();

        shell.run_workspace_auto_analysis(window, cx);

        assert_eq!(shell.auto_analyze_queue.in_flight_len(), 32);
        assert_eq!(
            shell
                .rows
                .iter()
                .filter(|row| row.status == FileStatus::Processing(RowOperation::Analyze))
                .count(),
            32
        );
        assert_eq!(shell.auto_analyze_queue.remaining_count(), 40);
    });

    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(matches!(
            shell.status_message.as_ref(),
            Some(super::BannerMessage::WorkspaceAutoAnalyzeCompleted { count, .. }) if *count == 40
        ));
    });
}

#[gpui::test]
fn ignore_folder_names_dialog_apply_updates_state_and_rescans_workspace(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let keep = dir.path().join("shots").join("keep.ma");
    let ignored = dir.path().join("cache").join("ignored.ma");
    fs::create_dir_all(keep.parent().expect("keep parent")).expect("mkdir keep");
    fs::create_dir_all(ignored.parent().expect("ignored parent")).expect("mkdir ignored");
    fs::write(&keep, "").expect("write keep");
    fs::write(&ignored, "").expect("write ignored");

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.ignore_folder_names_enabled = true;
        shell
            .state
            .set_ignored_folder_names(vec!["backup".to_string(), "autosave".to_string()]);
        shell.set_workspace_folder(dir.path().to_path_buf(), window, cx);
        assert_eq!(shell.rows.len(), 2);

        shell.open_ignore_folder_names_dialog(window, cx);
        shell
            .ignore_folder_names_dialog
            .as_mut()
            .expect("ignore dialog state")
            .draft_names
            .push("cache".to_string());

        shell.apply_ignore_folder_names_dialog(window, cx);

        assert!(shell.ignore_folder_names_dialog.is_none());
        assert_eq!(
            shell.state.ignored_folder_names,
            vec![
                "backup".to_string(),
                "autosave".to_string(),
                "cache".to_string()
            ]
        );
        assert_eq!(shell.rows.len(), 1);
        assert!(shell.rows[0].path.ends_with("keep.ma"));
    });
}

#[gpui::test]
fn ignore_folder_names_dialog_cancel_keeps_existing_state(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        let original = shell.state.ignored_folder_names.clone();
        shell.open_ignore_folder_names_dialog(window, cx);
        shell
            .ignore_folder_names_dialog
            .as_mut()
            .expect("ignore dialog state")
            .draft_names
            .push("cache".to_string());

        shell.clear_ignore_folder_names_dialog_state(cx);

        assert!(shell.ignore_folder_names_dialog.is_none());
        assert_eq!(shell.state.ignored_folder_names, original);
    });
}

#[test]
fn build_file_copy_payload_uses_all_selected_rows_when_target_is_selected() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("first.ma");
    let second = dir.path().join("second.ma");
    let third = dir.path().join("third.ma");
    fs::write(&first, "").expect("write first");
    fs::write(&second, "").expect("write second");
    fs::write(&third, "").expect("write third");

    let mut first_row = test_row(1, &first);
    first_row.selected = true;
    let mut second_row = test_row(2, &second);
    second_row.selected = true;
    let third_row = test_row(3, &third);

    let payload =
        build_file_copy_payload(&[first_row, second_row, third_row], 2).expect("copy payload");

    assert_eq!(
        payload,
        format!("{}\n{}", first.display(), second.display())
    );
}

#[test]
fn build_file_copy_payload_falls_back_to_target_row_when_not_selected() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("first.ma");
    let second = dir.path().join("second.ma");
    fs::write(&first, "").expect("write first");
    fs::write(&second, "").expect("write second");

    let mut first_row = test_row(1, &first);
    first_row.selected = true;
    let second_row = test_row(2, &second);

    let payload = build_file_copy_payload(&[first_row, second_row], 2).expect("copy payload");

    assert_eq!(payload, second.display().to_string());
}

#[test]
fn build_path_table_model_enables_scene_column_for_multi_source_selection() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("first.ma");
    let second = dir.path().join("second.ma");
    fs::write(
        &first,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "file -rdi 1 -ns \"charA\" -rfn \"charARN\" -typ \"mayaBinary\" \"shared/asset.mb\";\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"shared/asset.mb\";\n",
        ),
    )
    .expect("write first");
    fs::write(
        &second,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"before.tx\";\n",
        ),
    )
    .expect("write second");

    let mut first_row = test_row(1, &first);
    first_row.selected = true;
    first_row.paths_report = Some(collect_scene_paths(&first, PathKind::All).expect("paths"));

    let mut second_row = test_row(2, &second);
    second_row.selected = true;
    second_row.replace_preview = Some(PathReplacePreview {
        input_path: second.clone(),
        scene_format: SceneFormat::Ma,
        operation_mode: OperationMode::BestEffort,
        validation_state: ValidationState::Validated,
        matched_count: 1,
        items: vec![PathReplacePreviewItem {
            entry_index: 0,
            node_type: "file".to_string(),
            node_name: "file1".to_string(),
            attr: "ftn".to_string(),
            before_value: "before.tx".to_string(),
            after_value: "after.tx".to_string(),
            replacement_count: 1,
        }],
    });

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[first_row, second_row],
        &[0, 1],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert!(table.show_scene_column);
    assert!(!table.rows.is_empty());
    assert!(table.rows.iter().any(|row| row.preview_only));
    assert!(table.rows.iter().any(|row| row.editable));
}

#[test]
fn build_path_table_model_marks_multiple_selected_path_rows() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/spec.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));

    let selected = BTreeSet::from([vec![(1, 0)], vec![(1, 1)]]);
    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &selected,
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 2);
    assert!(table.rows.iter().all(|row| row.selected));
}

#[test]
fn path_overrides_from_replace_preview_uses_after_values_by_entry_index() {
    let preview = PathReplacePreview {
        input_path: PathBuf::from("scene.ma"),
        scene_format: SceneFormat::Ma,
        operation_mode: OperationMode::BestEffort,
        validation_state: ValidationState::Validated,
        matched_count: 2,
        items: vec![
            PathReplacePreviewItem {
                entry_index: 3,
                node_type: "file".to_string(),
                node_name: "file1".to_string(),
                attr: "ftn".to_string(),
                before_value: "before_a.tx".to_string(),
                after_value: "after_a.tx".to_string(),
                replacement_count: 1,
            },
            PathReplacePreviewItem {
                entry_index: 7,
                node_type: "reference".to_string(),
                node_name: "ref1".to_string(),
                attr: "f".to_string(),
                before_value: "before_b.mb".to_string(),
                after_value: "after_b.mb".to_string(),
                replacement_count: 1,
            },
        ],
    };

    let overrides = path_overrides_from_replace_preview(&preview);

    assert_eq!(overrides.get(&3), Some(&"after_a.tx".to_string()));
    assert_eq!(overrides.get(&7), Some(&"after_b.mb".to_string()));
    assert_eq!(overrides.len(), 2);
}

#[test]
fn replace_dialog_preview_rows_show_only_matches_when_query_exists() {
    let rows = render_replace_dialog_preview_rows(
        &ReplaceDialogPreviewState {
            previewable_row_ids: vec![1],
            failed_files: Vec::new(),
            matched_count: 1,
            items: vec![
                super::ReplaceDialogPreviewRow {
                    before_value: "match/a.tx".to_string(),
                    after_value: "match/b.tx".to_string(),
                },
                super::ReplaceDialogPreviewRow {
                    before_value: "keep.tx".to_string(),
                    after_value: "keep.tx".to_string(),
                },
            ],
            planned_overrides: Vec::new(),
        },
        &ReplaceDialogState {
            captured_row_ids: vec![1],
            path_targets: None,
            path_type_filter: default_path_type_filter(),
            replace_mode: PathReplaceMode::Literal,
            preview_sort: ReplaceDialogSort {
                key: ReplaceDialogSortKey::Before,
                direction: ColumnSort::Default,
            },
            is_previewing: false,
            generation: 1,
            source_cache: BTreeMap::new(),
            preview_signature: Some(ReplaceDialogPreviewSignature {
                from_value: "a".to_string(),
                to_value: "b".to_string(),
                replace_mode: PathReplaceMode::Literal,
                path_type_filter: default_path_type_filter(),
            }),
            preview: None,
        },
    );

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].before_value, "match/a.tx");
    assert_eq!(rows[0].after_value, "match/b.tx");
}

#[test]
fn build_path_table_model_collapses_duplicate_paths_when_dedup_enabled() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("first.ma");
    let second = dir.path().join("second.ma");
    fs::write(
        &first,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"shared/asset.mb\";\n",
        ),
    )
    .expect("write first");
    fs::write(
        &second,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"fileA\";\n",
            "    setAttr \".ftn\" -type \"string\" \"shared/asset.mb\";\n",
        ),
    )
    .expect("write second");

    let mut first_row = test_row(1, &first);
    first_row.selected = true;
    first_row.paths_report = Some(collect_scene_paths(&first, PathKind::All).expect("paths"));
    let mut second_row = test_row(2, &second);
    second_row.selected = true;
    second_row.paths_report = Some(collect_scene_paths(&second, PathKind::All).expect("paths"));

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[first_row, second_row],
        &[0, 1],
        &state,
        None,
        &BTreeSet::new(),
        true,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    let summary_rows: Vec<_> = table
        .rows
        .iter()
        .filter(|row| !row.preview_only && row.editable)
        .collect();
    assert_eq!(summary_rows.len(), 1);
    assert_eq!(summary_rows[0].edit_targets.len(), 2);
    assert_eq!(summary_rows[0].scene, "2件");
    assert_eq!(summary_rows[0].node, "2件");
    assert!(table.has_report_rows);
}

#[test]
fn build_path_table_model_filters_rows_by_search_query() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("first.ma");
    fs::write(
        &first,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"shared/asset.mb\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
        ),
    )
    .expect("write first");

    let mut row = test_row(1, &first);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&first, PathKind::All).expect("paths"));

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "diffuse",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert!(table.rows[0].value.contains("diffuse.tx"));
}

#[test]
fn build_path_table_model_marks_overridden_entries_as_dirty() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.path_overrides
        .insert(0, "textures/edited.tx".to_string());

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert!(table.rows[0].dirty);
    assert_eq!(table.rows[0].value, "textures/edited.tx");
}

#[gpui::test]
fn path_context_undo_targets_clear_all_selected_rows_in_same_file(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/spec.tx\";\n",
        ),
    )
    .expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            row.path_overrides
                .insert(0, "textures/diffuse_edited.tx".to_string());
            row.path_overrides
                .insert(1, "textures/spec_edited.tx".to_string());
            row.dirty_kind = Some(DirtyKind::Replace);
            row.status = FileStatus::Dirty;
            shell.rows = vec![row];
            shell.selected_path_rows = BTreeSet::from([vec![(1, 0)], vec![(1, 1)]]);

            let undo_targets = shell.context_undo_path_targets(&vec![(1, 0)]);
            shell.undo_path_edit_targets(undo_targets, window, cx);

            assert!(shell.rows[0].path_overrides.is_empty());
            assert_eq!(shell.rows[0].dirty_kind, None);
        });
    });
}

#[gpui::test]
fn path_context_undo_delete_owner_targets_clear_all_selected_rows_in_same_file(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            shell.rows = vec![row];
            shell.selected_path_rows = BTreeSet::from([vec![(1, 0)], vec![(1, 1)]]);

            shell.run_delete_selected_path_owner_nodes(
                vec![vec![(1, 0)], vec![(1, 1)]],
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            assert_eq!(shell.rows[0].pending_path_owner_delete_targets.len(), 2);

            let undo_targets = shell.context_undo_path_targets(&vec![(1, 0)]);
            shell.undo_context_path_targets(undo_targets, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.rows[0].pending_path_owner_delete_targets,
            BTreeSet::new(),
            "discard should clear all selected owner-delete targets",
        );
        assert_eq!(shell.rows[0].dirty_kind, None);
    });
}

#[gpui::test]
fn path_context_delete_owner_targets_only_stage_clicked_row_in_same_file(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            shell.rows = vec![row];
            shell.selected_path_rows = BTreeSet::from([vec![(1, 0)], vec![(1, 1)]]);

            let selected_rows = shell.context_delete_owner_rows(&vec![(1, 0)]);
            shell.run_delete_selected_path_owner_nodes(selected_rows, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.rows[0].pending_path_owner_delete_targets,
            BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".to_string(),
                node_name: "file1".to_string(),
            }]),
            "delete-owner context action should only stage the clicked row target",
        );
        assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::SceneEdits));
        assert!(
            shell.rows[0].dirty_artifact.is_some(),
            "single-row owner delete should still produce a saveable staged artifact",
        );
    });
}

#[gpui::test]
fn path_context_undo_delete_owner_preserves_other_scene_edits(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            shell.rows = vec![row];

            shell.stage_scene_edits_for_row(
                0,
                BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                    node_name: "cleanupScript".to_string(),
                }]),
                BTreeSet::from([
                    PathOwnerDeleteTarget {
                        node_type: "file".to_string(),
                        node_name: "file1".to_string(),
                    },
                    PathOwnerDeleteTarget {
                        node_type: "file".to_string(),
                        node_name: "file2".to_string(),
                    },
                ]),
                ResultTab::Paths,
                None,
                false,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            assert_eq!(shell.rows[0].pending_clean_targets.len(), 1);
            assert_eq!(shell.rows[0].pending_path_owner_delete_targets.len(), 2);

            let undo_targets = shell.context_undo_path_targets(&vec![(1, 0)]);
            shell.undo_context_path_targets(undo_targets, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.rows[0].pending_clean_targets,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "cleanupScript".to_string(),
            }]),
            "owner-delete undo should keep unrelated staged clean targets",
        );
        assert_eq!(
            shell.rows[0].pending_path_owner_delete_targets,
            BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".to_string(),
                node_name: "file2".to_string(),
            }]),
            "clicked owner-delete target should be the only one removed",
        );
        assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::SceneEdits));
    });
}

#[gpui::test]
fn begin_path_edit_allows_non_deleted_rows_while_scene_edits_are_staged(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            row.pending_path_owner_delete_targets = BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".to_string(),
                node_name: "file1".to_string(),
            }]);
            row.dirty_kind = Some(DirtyKind::SceneEdits);
            shell.rows = vec![row];

            shell.begin_path_edit(vec![(1, 1)], window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(shell.active_path_edit, Some(vec![(1, 1)]));
    });
}

#[gpui::test]
fn begin_path_edit_blocks_deleted_owner_rows_while_scene_edits_are_staged(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            row.pending_path_owner_delete_targets = BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".to_string(),
                node_name: "file1".to_string(),
            }]);
            row.path_owner_delete_preview = Some(PathOwnerDeletePreview {
                input_path: scene.clone(),
                scene_format: SceneFormat::Ma,
                operation_mode: OperationMode::Strict,
                validation_state: ValidationState::Validated,
                deleted_targets: vec![PathOwnerDeleteTarget {
                    node_type: "file".to_string(),
                    node_name: "file1".to_string(),
                }],
            });
            row.dirty_kind = Some(DirtyKind::SceneEdits);
            shell.rows = vec![row];

            shell.begin_path_edit(vec![(1, 0)], window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(shell.active_path_edit.is_none());
    });
}

#[gpui::test]
fn add_folder_uses_current_workspace_as_initial_directory(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            shell.state = test_state(&workspace, "");
            shell.add_folder(window, cx);
        });
    });
    visual_cx.run_until_parked();

    assert!(visual_cx.did_prompt_for_paths());
    visual_cx.simulate_path_prompt_selection(|options| {
        assert!(!options.files);
        assert!(options.directories);
        assert_eq!(
            options.initial_directory.as_deref(),
            Some(workspace.as_path())
        );
        None
    });
    visual_cx.run_until_parked();
}

#[gpui::test]
fn select_path_edit_file_uses_existing_file_parent_as_initial_directory(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let scene_dir = workspace.join("scenes");
    let texture_dir = workspace.join("sourceimages");
    fs::create_dir_all(&scene_dir).expect("create scenes");
    fs::create_dir_all(&texture_dir).expect("create textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = texture_dir.join("hero.tx");
    fs::write(&texture, "tx").expect("texture");
    let scene = scene_dir.join("scene.ma");
    write_single_file_path_scene(&scene, "sourceimages/hero.tx");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            shell.rows = vec![row];

            shell.begin_path_edit(vec![(1, 0)], window, cx);
            shell.select_path_edit_file(window, cx);
        });
    });
    visual_cx.run_until_parked();

    assert!(visual_cx.did_prompt_for_paths());
    visual_cx.simulate_path_prompt_selection(|options| {
        assert!(options.files);
        assert!(!options.directories);
        assert_eq!(
            options.initial_directory.as_deref(),
            Some(texture_dir.as_path())
        );
        None
    });
    visual_cx.run_until_parked();
    visual_cx
        .executor()
        .advance_clock(Duration::from_millis(300));
    visual_cx.run_until_parked();
}

#[gpui::test]
fn select_path_edit_file_uses_scene_workspace_when_target_file_is_missing(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let scene_dir = workspace.join("scenes");
    fs::create_dir_all(&scene_dir).expect("create scenes");
    fs::create_dir_all(workspace.join("sourceimages")).expect("create sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let scene = scene_dir.join("scene.ma");
    write_single_file_path_scene(&scene, "sourceimages/missing.tx");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            shell.rows = vec![row];

            shell.begin_path_edit(vec![(1, 0)], window, cx);
            shell.select_path_edit_file(window, cx);
        });
    });
    visual_cx.run_until_parked();

    assert!(visual_cx.did_prompt_for_paths());
    visual_cx.simulate_path_prompt_selection(|options| {
        assert_eq!(
            options.initial_directory.as_deref(),
            Some(workspace.as_path())
        );
        None
    });
    visual_cx.run_until_parked();
    visual_cx
        .executor()
        .advance_clock(Duration::from_millis(300));
    visual_cx.run_until_parked();
}

#[gpui::test]
fn select_path_edit_file_falls_back_to_os_default_without_scene_context(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_single_file_path_scene(&scene, "textures/missing.tx");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            shell.rows = vec![row];

            shell.begin_path_edit(vec![(1, 0)], window, cx);
            shell.select_path_edit_file(window, cx);
        });
    });
    visual_cx.run_until_parked();

    assert!(visual_cx.did_prompt_for_paths());
    visual_cx.simulate_path_prompt_selection(|options| {
        assert_eq!(options.initial_directory, None);
        None
    });
    visual_cx.run_until_parked();
    visual_cx
        .executor()
        .advance_clock(Duration::from_millis(300));
    visual_cx.run_until_parked();
}

#[gpui::test]
fn path_collect_folder_button_uses_input_directory_and_updates_input(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let scene_dir = workspace.join("scenes");
    let texture_dir = workspace.join("textures");
    let initial_dir = workspace.join("current-output");
    let selected_dir = workspace.join("selected-output");
    fs::create_dir_all(&scene_dir).expect("create scenes");
    fs::create_dir_all(&texture_dir).expect("create textures");
    fs::create_dir_all(&initial_dir).expect("create initial output");
    fs::create_dir_all(&selected_dir).expect("create selected output");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = texture_dir.join("hero.tx");
    fs::write(&texture, "tx").expect("texture");
    let scene = scene_dir.join("scene.ma");
    write_single_file_path_scene(&scene, "textures/hero.tx");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];

            shell.open_path_collect_dialog(
                vec![(1, 0)],
                PathCollectRewriteMode::PlainRelative,
                window,
                cx,
            );
            let dialog = shell
                .path_collect_dialog
                .as_ref()
                .expect("path collect dialog");
            dialog.folder_input.update(cx, |input, cx| {
                input.set_value(initial_dir.to_string_lossy().replace('\\', "/"), window, cx);
            });
            shell.select_path_collect_folder(window, cx);
        });
    });
    visual_cx.run_until_parked();

    assert!(visual_cx.did_prompt_for_paths());
    visual_cx.simulate_path_prompt_selection(|options| {
        assert!(!options.files);
        assert!(options.directories);
        assert_eq!(
            options.initial_directory.as_deref(),
            Some(initial_dir.as_path())
        );
        Some(vec![selected_dir.clone()])
    });
    visual_cx.run_until_parked();
    visual_cx
        .executor()
        .advance_clock(Duration::from_millis(300));
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let dialog = shell
            .path_collect_dialog
            .as_ref()
            .expect("path collect dialog");
        assert_eq!(
            dialog.folder_input.read(app).value().as_ref(),
            selected_dir.to_string_lossy().replace('\\', "/")
        );
    });
}

#[gpui::test]
fn convert_workspace_relative_preserves_owner_delete_staging_on_other_rows(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let first = workspace.join("sourceimages/first.tx");
    let second = workspace.join("sourceimages/second.tx");
    fs::write(&first, "tx").expect("write first");
    fs::write(&second, "tx").expect("write second");
    let scene = workspace.join("scene.ma");
    let first_abs = first.to_string_lossy().replace('\\', "/");
    let second_abs = second.to_string_lossy().replace('\\', "/");
    fs::write(
        &scene,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{first_abs}\";\n",
                "createNode file -n \"file2\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{second_abs}\";\n",
            ),
            first_abs = first_abs,
            second_abs = second_abs
        ),
    )
    .expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            row.pending_path_owner_delete_targets = BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".to_string(),
                node_name: "file1".to_string(),
            }]);
            row.path_owner_delete_preview = Some(PathOwnerDeletePreview {
                input_path: scene.clone(),
                scene_format: SceneFormat::Ma,
                operation_mode: OperationMode::Strict,
                validation_state: ValidationState::Validated,
                deleted_targets: vec![PathOwnerDeleteTarget {
                    node_type: "file".to_string(),
                    node_name: "file1".to_string(),
                }],
            });
            row.dirty_kind = Some(DirtyKind::SceneEdits);
            row.status = FileStatus::Dirty;
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];

            shell.convert_path_targets_to_workspace_relative(
                vec![(1, 1)],
                PathCollectRewriteMode::PlainRelative,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let row = &shell.rows[0];
        assert_eq!(row.dirty_kind, Some(DirtyKind::SceneEdits));
        assert_eq!(
            row.pending_path_owner_delete_targets,
            BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".to_string(),
                node_name: "file1".to_string(),
            }])
        );
        assert_eq!(
            row.path_overrides.get(&1),
            Some(&"sourceimages/second.tx".to_string())
        );
        assert!(row.path_owner_delete_preview.is_some());
        let staged_paths = row.staged_paths_report.as_ref().expect("staged paths");
        assert!(
            staged_paths
                .entries
                .iter()
                .all(|entry| entry.node_name != "file1"),
            "deleted owner should stay deleted in staged paths",
        );
        assert!(staged_paths.entries.iter().any(|entry| {
            entry.node_name == "file2" && entry.value == "sourceimages/second.tx"
        }));
    });
}

#[gpui::test]
fn undo_context_path_targets_keeps_owner_delete_when_undoing_other_row_override(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let first = workspace.join("sourceimages/first.tx");
    let second = workspace.join("sourceimages/second.tx");
    fs::write(&first, "tx").expect("write first");
    fs::write(&second, "tx").expect("write second");
    let scene = workspace.join("scene.ma");
    let first_abs = first.to_string_lossy().replace('\\', "/");
    let second_abs = second.to_string_lossy().replace('\\', "/");
    fs::write(
        &scene,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{first_abs}\";\n",
                "createNode file -n \"file2\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{second_abs}\";\n",
            ),
            first_abs = first_abs,
            second_abs = second_abs
        ),
    )
    .expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            row.pending_path_owner_delete_targets = BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".to_string(),
                node_name: "file1".to_string(),
            }]);
            row.path_owner_delete_preview = Some(PathOwnerDeletePreview {
                input_path: scene.clone(),
                scene_format: SceneFormat::Ma,
                operation_mode: OperationMode::Strict,
                validation_state: ValidationState::Validated,
                deleted_targets: vec![PathOwnerDeleteTarget {
                    node_type: "file".to_string(),
                    node_name: "file1".to_string(),
                }],
            });
            row.path_overrides = BTreeMap::from([(1usize, "sourceimages/second.tx".to_string())]);
            row.dirty_kind = Some(DirtyKind::SceneEdits);
            row.status = FileStatus::Dirty;
            shell.rows = vec![row];

            shell.undo_context_path_targets(vec![(1, 1)], window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let row = &shell.rows[0];
        assert!(row.path_overrides.is_empty());
        assert_eq!(row.dirty_kind, Some(DirtyKind::SceneEdits));
        assert_eq!(
            row.pending_path_owner_delete_targets,
            BTreeSet::from([PathOwnerDeleteTarget {
                node_type: "file".to_string(),
                node_name: "file1".to_string(),
            }])
        );
    });
}

#[test]
fn build_path_table_model_marks_mb_rows_without_trace_as_not_owner_deletable() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.mb");
    fs::write(&scene, "stub").expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(ScenePathsReport {
        scene_path: scene.clone(),
        scene_format: SceneFormat::Mb,
        validation_state: ValidationState::Validated,
        entries: vec![ScenePathEntry {
            node_type: "file".to_string(),
            node_name: "fileTex".to_string(),
            attr: ".ftn".to_string(),
            value: "textures/diffuse.tx".to_string(),
            meta: None,
        }],
    });

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert!(!table.rows[0].owner_deletable);
}

#[test]
fn build_path_table_model_marks_mb_rows_with_trace_as_owner_deletable() {
    let scene = repo_root().join("tests/fixtures/mb/owner_delete/file_owner_delete.mb");
    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));

    let state = test_state(repo_root().as_path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 2);
    assert!(table.rows.iter().all(|row| row.owner_deletable));
}

#[test]
fn analyze_row_keeps_mb_file_owner_rows_owner_deletable() {
    let scene = repo_root().join("tests/fixtures/mb/owner_delete/file_owner_delete.mb");
    let RowJobResult::Analyze(result) =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = result.paths_report;

    let state = test_state(repo_root().as_path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 2);
    assert!(table.rows.iter().all(|row| row.owner_deletable));
}

#[test]
fn analyze_row_keeps_connected_mb_file_owner_rows_owner_deletable() {
    let scene = repo_root().join("tests/fixtures/mb/owner_delete/connected_file_owner_delete.mb");
    let RowJobResult::Analyze(result) =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = result.paths_report;

    let state = test_state(repo_root().as_path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 2);
    assert!(table.rows.iter().all(|row| row.owner_deletable));
}

#[test]
fn build_path_table_model_marks_delete_owner_preview_targets_as_dirty() {
    let scene = repo_root().join("tests/fixtures/mb/owner_delete/file_owner_delete.mb");
    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
    row.path_owner_delete_preview = Some(PathOwnerDeletePreview {
        input_path: scene.clone(),
        scene_format: SceneFormat::Mb,
        operation_mode: OperationMode::Strict,
        validation_state: ValidationState::Validated,
        deleted_targets: vec![PathOwnerDeleteTarget {
            node_type: "file".to_string(),
            node_name: "deleteTex".to_string(),
        }],
    });
    row.dirty_kind = Some(DirtyKind::SceneEdits);

    let state = test_state(repo_root().as_path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 2);
    assert!(
        table
            .rows
            .iter()
            .any(|row| row.node == "deleteTex [file]" && row.dirty)
    );
    assert!(
        table
            .rows
            .iter()
            .any(|row| row.node == "keepTex [file]" && !row.dirty)
    );
}

#[test]
fn build_path_table_model_only_blocks_deleted_owner_rows_during_scene_edits() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
    row.pending_path_owner_delete_targets = BTreeSet::from([PathOwnerDeleteTarget {
        node_type: "file".to_string(),
        node_name: "file1".to_string(),
    }]);
    row.dirty_kind = Some(DirtyKind::SceneEdits);
    row.refresh_path_resolution_cache();

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 2);
    assert_eq!(
        table
            .rows
            .iter()
            .map(|row| (row.node.as_str(), row.editable, row.owner_deleted))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([("file1 [file]", false, true), ("file2 [file]", true, false),])
    );
}

#[test]
fn path_context_menu_state_keeps_workspace_relative_for_non_deleted_rows() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let first = workspace.join("sourceimages/first.tx");
    let second = workspace.join("sourceimages/second.tx");
    fs::write(&first, "tx").expect("write first");
    fs::write(&second, "tx").expect("write second");
    let scene = workspace.join("scene.ma");
    let first_abs = first.to_string_lossy().replace('\\', "/");
    let second_abs = second.to_string_lossy().replace('\\', "/");
    fs::write(
        &scene,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{first_abs}\";\n",
                "createNode file -n \"file2\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{second_abs}\";\n",
            ),
            first_abs = first_abs,
            second_abs = second_abs
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.pending_path_owner_delete_targets = BTreeSet::from([PathOwnerDeleteTarget {
        node_type: "file".to_string(),
        node_name: "file1".to_string(),
    }]);
    row.dirty_kind = Some(DirtyKind::SceneEdits);
    row.refresh_path_resolution_cache();

    let state = path_context_menu_state(&[row], &vec![(1, 1)]);

    assert!(state.can_convert_to_workspace_double_slash_relative);
    assert!(!state.show_disabled_convert_to_workspace_double_slash_relative);
    assert!(state.can_convert_to_plain_relative);
    assert!(!state.show_disabled_convert_to_plain_relative);
}

#[test]
fn path_value_edit_supported_for_entry_only_blocks_deleted_owner_rows() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    write_path_owner_delete_scene(&scene);

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
    row.pending_path_owner_delete_targets = BTreeSet::from([PathOwnerDeleteTarget {
        node_type: "file".to_string(),
        node_name: "file1".to_string(),
    }]);
    row.dirty_kind = Some(DirtyKind::SceneEdits);

    assert!(!path_value_edit_supported_for_entry(&row, 0));
    assert!(path_value_edit_supported_for_entry(&row, 1));
    assert!(path_value_edit_supported_for_edit_targets(
        &[row],
        &vec![(1, 1)]
    ));
}

#[test]
fn path_text_highlights_adds_visible_strikethrough_for_deleted_rows() {
    let highlights = path_text_highlights("sourceimages/hero.tx", None, true)
        .expect("owner-deleted rows should emit highlights");
    assert_eq!(highlights.len(), 1);
    assert_eq!(highlights[0].0, 0.."sourceimages/hero.tx".len());
    let strike = highlights[0]
        .1
        .strikethrough
        .expect("deleted row highlight should include strikethrough");
    assert_eq!(strike.thickness, px(1.0));
}

#[test]
fn build_path_table_model_filters_dedup_rows_by_path_value() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("hero.ma");
    let second = dir.path().join("crowd.ma");
    fs::write(
        &first,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"shared/asset.mb\";\n",
        ),
    )
    .expect("write first");
    fs::write(
        &second,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"shared/asset.mb\";\n",
        ),
    )
    .expect("write second");

    let mut first_row = test_row(1, &first);
    first_row.selected = true;
    first_row.paths_report = Some(collect_scene_paths(&first, PathKind::All).expect("paths"));
    let mut second_row = test_row(2, &second);
    second_row.selected = true;
    second_row.paths_report = Some(collect_scene_paths(&second, PathKind::All).expect("paths"));

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[first_row, second_row],
        &[0, 1],
        &state,
        None,
        &BTreeSet::new(),
        true,
        "asset.mb",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert_eq!(table.rows[0].value, "shared/asset.mb");
}

#[test]
fn build_path_table_model_keeps_single_dedup_row_labels() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("hero.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        true,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert_eq!(table.rows[0].scene, "hero.ma");
    assert_eq!(table.rows[0].node, "file1 [file]");
}

#[test]
fn build_path_table_model_sets_resolution_badges() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let scene = workspace.join("hero.ma");
    let existing = workspace.join("textures/diffuse.tx");
    fs::write(&existing, "tx").expect("texture");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 2);
    assert_eq!(
        table.rows[0].resolution_badge,
        Some(super::PathResolutionBadge::Exists)
    );
    assert_eq!(
        table.rows[1].resolution_badge,
        Some(super::PathResolutionBadge::Missing)
    );
}

#[test]
fn build_path_table_model_filters_rows_by_resolution_badge() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let scene = workspace.join("hero.ma");
    let existing = workspace.join("textures/diffuse.tx");
    fs::write(&existing, "tx").expect("texture");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/missing.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &BTreeSet::from([super::PathResolutionBadge::Missing]),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert_eq!(
        table.rows[0].resolution_badge,
        Some(super::PathResolutionBadge::Missing)
    );
}

#[test]
fn build_path_table_model_preserves_first_seen_order_when_dedup_enabled() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("order.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"fileB\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/b.tx\";\n",
            "createNode file -n \"fileA\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/a.tx\";\n",
            "createNode file -n \"fileB2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/b.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        true,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 2);
    assert_eq!(table.rows[0].value, "textures/a.tx");
    assert_eq!(table.rows[1].value, "textures/b.tx");
}

#[test]
fn build_path_table_model_splits_dedup_rows_when_resolution_differs() {
    let dir = tempdir().expect("tmpdir");
    let workspace_a = dir.path().join("workspace_a");
    let workspace_b = dir.path().join("workspace_b");
    fs::create_dir_all(workspace_a.join("shots")).expect("mkdir a shots");
    fs::create_dir_all(workspace_b.join("shots")).expect("mkdir b shots");
    fs::create_dir_all(workspace_a.join("shared")).expect("mkdir a shared");
    fs::write(workspace_a.join("workspace.mel"), "// workspace a").expect("workspace a");
    fs::write(workspace_b.join("workspace.mel"), "// workspace b").expect("workspace b");
    fs::write(workspace_a.join("shared/asset.mb"), "mb").expect("write asset");
    let first = workspace_a.join("shots/first.ma");
    let second = workspace_b.join("shots/second.ma");
    let scene_body = concat!(
        "//Maya ASCII 2026 scene\n",
        "createNode file -n \"file1\";\n",
        "    setAttr \".ftn\" -type \"string\" \"shared/asset.mb\";\n",
    );
    fs::write(&first, scene_body).expect("write first");
    fs::write(&second, scene_body).expect("write second");

    let mut first_row = test_row(1, &first);
    first_row.selected = true;
    first_row.paths_report = Some(collect_scene_paths(&first, PathKind::All).expect("paths"));
    first_row.refresh_path_resolution_cache();
    let mut second_row = test_row(2, &second);
    second_row.selected = true;
    second_row.paths_report = Some(collect_scene_paths(&second, PathKind::All).expect("paths"));
    second_row.refresh_path_resolution_cache();

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[first_row, second_row],
        &[0, 1],
        &state,
        None,
        &BTreeSet::new(),
        true,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    let rows: Vec<_> = table.rows.iter().filter(|row| !row.preview_only).collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].resolution_badge,
        Some(super::PathResolutionBadge::Exists)
    );
    assert_eq!(
        rows[1].resolution_badge,
        Some(super::PathResolutionBadge::Missing)
    );
}

#[test]
fn write_back_selected_scene_path_prefers_workspace_relative_and_preserves_double_slash() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let selected = workspace.join("sourceimages/hero.tx");
    let workspace_display = workspace.to_string_lossy().replace('\\', "/");

    assert_eq!(
        write_back_selected_scene_path(
            &selected,
            Some(&workspace),
            ScenePathValueStyle::PlainRelative,
        ),
        "sourceimages/hero.tx"
    );
    assert_eq!(
        write_back_selected_scene_path(
            &selected,
            Some(&workspace),
            ScenePathValueStyle::DoubleSlashWorkspaceRelative,
        ),
        format!("{workspace_display}//sourceimages/hero.tx")
    );
}

#[test]
fn resolved_target_file_paths_for_edit_targets_collects_existing_files() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = workspace.join("sourceimages/hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/hero.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    assert_eq!(
        resolved_target_file_paths_for_edit_targets(&[row], &vec![(1, 0)]),
        vec![texture],
    );
}

#[test]
fn workspace_relative_override_value_for_entry_converts_absolute_values_inside_workspace() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = workspace.join("sourceimages/hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scene.ma");
    let absolute = texture.to_string_lossy().replace('\\', "/");
    fs::write(
        &scene,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{absolute}\";\n",
            ),
            absolute = absolute
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    assert_eq!(
        workspace_relative_override_value_for_entry(&row, 0, PathCollectRewriteMode::PlainRelative),
        Some("sourceimages/hero.tx".to_string()),
    );
}

#[test]
fn workspace_relative_override_value_for_entry_skips_existing_relative_values() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = workspace.join("sourceimages/hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/hero.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    assert_eq!(
        workspace_relative_override_value_for_entry(&row, 0, PathCollectRewriteMode::PlainRelative),
        None
    );
}

#[test]
fn workspace_relative_override_value_for_entry_normalizes_double_slash_style_with_workspace_root() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = workspace.join("sourceimages/hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"C:/project//sourceimages/hero.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    let workspace_display = workspace.to_string_lossy().replace('\\', "/");
    assert_eq!(
        workspace_relative_override_value_for_entry(
            &row,
            0,
            PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
        ),
        Some(format!("{workspace_display}//sourceimages/hero.tx")),
    );
}

#[test]
fn absolute_override_value_for_entry_converts_workspace_relative_values() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = workspace.join("sourceimages/hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/hero.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    assert_eq!(
        absolute_override_value_for_entry(&row, 0),
        Some(texture.to_string_lossy().replace('\\', "/")),
    );
}

#[test]
fn absolute_override_value_for_entry_uses_missing_workspace_candidate() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let missing = workspace.join("sourceimages/missing.tx");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/missing.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    assert_eq!(
        absolute_override_value_for_entry(&row, 0),
        Some(missing.to_string_lossy().replace('\\', "/")),
    );
}

#[test]
fn path_collect_folder_input_defaults_and_resolves_relative_values() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");

    assert_eq!(
        path_collect_default_folder(&workspace),
        workspace.join("sourceimages")
    );
    assert_eq!(
        parse_path_collect_folder_input("sourceimages", &workspace),
        Some(workspace.join("sourceimages"))
    );
    assert_eq!(parse_path_collect_folder_input(" ", &workspace), None);
}

#[test]
fn collected_path_rewrite_value_supports_absolute_and_workspace_relative() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let destination = workspace.join("sourceimages/hero.tx");

    assert_eq!(
        collected_path_rewrite_value(&destination, &workspace, PathCollectRewriteMode::Absolute),
        destination.to_string_lossy().replace('\\', "/")
    );
    assert_eq!(
        collected_path_rewrite_value(
            &destination,
            &workspace,
            PathCollectRewriteMode::PlainRelative,
        ),
        "sourceimages/hero.tx"
    );
    assert_eq!(
        collected_path_rewrite_value(
            &destination,
            &workspace,
            PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
        ),
        format!(
            "{}//sourceimages/hero.tx",
            workspace.to_string_lossy().replace('\\', "/")
        )
    );
}

#[test]
fn path_collect_destination_validates_relative_mode_workspace_boundary() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let inside_workspace = workspace.join("sourceimages");
    let outside_workspace = dir.path().join("external");

    assert!(path_collect_destination_supports_rewrite_mode(
        &inside_workspace,
        &workspace,
        PathCollectRewriteMode::PlainRelative,
    ));
    assert!(!path_collect_destination_supports_rewrite_mode(
        &outside_workspace,
        &workspace,
        PathCollectRewriteMode::PlainRelative,
    ));
    assert!(path_collect_destination_supports_rewrite_mode(
        &inside_workspace,
        &workspace,
        PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
    ));
    assert!(!path_collect_destination_supports_rewrite_mode(
        &outside_workspace,
        &workspace,
        PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
    ));
    assert!(path_collect_destination_supports_rewrite_mode(
        &outside_workspace,
        &workspace,
        PathCollectRewriteMode::Absolute,
    ));
}

#[test]
fn collect_target_files_reuses_matching_destination_and_rejects_conflict() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("source.tx");
    let matching_destination = dir.path().join("matching/source.tx");
    let conflicting_destination = dir.path().join("conflict/source.tx");
    fs::create_dir_all(matching_destination.parent().unwrap()).expect("mkdir matching");
    fs::create_dir_all(conflicting_destination.parent().unwrap()).expect("mkdir conflict");
    fs::write(&source, "same").expect("write source");
    fs::write(&matching_destination, "same").expect("write matching");
    fs::write(&conflicting_destination, "different").expect("write conflicting");

    let reused = collect_target_files(&[PathCollectPlan {
        row_id: 1,
        entry_index: 0,
        row_index: 0,
        source_path: source.clone(),
        destination_path: matching_destination,
        next_value: "sourceimages/source.tx".to_string(),
    }])
    .expect("reuse matching destination");
    assert_eq!(reused.copied, 0);
    assert_eq!(reused.reused, 1);

    let err = collect_target_files(&[PathCollectPlan {
        row_id: 1,
        entry_index: 0,
        row_index: 0,
        source_path: source,
        destination_path: conflicting_destination,
        next_value: "sourceimages/source.tx".to_string(),
    }])
    .expect_err("conflicting destination should fail");
    assert!(err.contains("different contents"));
}

#[test]
fn collect_target_files_rejects_duplicate_basenames_with_different_contents() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("a/hero.tx");
    let second = dir.path().join("b/hero.tx");
    let destination = dir.path().join("sourceimages/hero.tx");
    fs::create_dir_all(first.parent().unwrap()).expect("mkdir first");
    fs::create_dir_all(second.parent().unwrap()).expect("mkdir second");
    fs::write(&first, "first").expect("write first");
    fs::write(&second, "second").expect("write second");

    let err = collect_target_files(&[
        PathCollectPlan {
            row_id: 1,
            entry_index: 0,
            row_index: 0,
            source_path: first,
            destination_path: destination.clone(),
            next_value: "sourceimages/hero.tx".to_string(),
        },
        PathCollectPlan {
            row_id: 1,
            entry_index: 1,
            row_index: 0,
            source_path: second,
            destination_path: destination,
            next_value: "sourceimages/hero.tx".to_string(),
        },
    ])
    .expect_err("duplicate basename conflict should fail");
    assert!(err.contains("different contents"));
}

#[test]
fn build_path_table_model_marks_double_slash_workspace_relative_rows() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = workspace.join("sourceimages/hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"C:/project//sourceimages/hero.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));

    let state = test_state(&workspace, "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        true,
        "",
        &BTreeSet::from([PathTypeFilter::File, PathTypeFilter::Reference]),
        &default_path_form_filter(),
        &BTreeSet::from([
            PathResolutionBadge::Exists,
            PathResolutionBadge::Missing,
            PathResolutionBadge::Unresolved,
        ]),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert_eq!(
        table.rows[0].value_style,
        Some(ScenePathValueStyle::DoubleSlashWorkspaceRelative)
    );
}

#[gpui::test]
fn path_dirty_filter_keeps_only_dirty_path_rows(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    fs::write(workspace.join("sourceimages/first.tx"), "first").expect("write first");
    fs::write(workspace.join("sourceimages/second.tx"), "second").expect("write second");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/first.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/second.tx\";\n",
        ),
    )
    .expect("write scene");

    visual_cx.update(|_, app| {
        shell.update(app, |shell, _| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            row.path_overrides
                .insert(1, "sourceimages/second_v2.tx".to_string());
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];
            shell.path_dirty_only = true;
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let table = shell.current_path_table_model();
        assert_eq!(table.rows.len(), 1);
        assert_eq!(table.rows[0].node, "file2 [file]");
        assert!(table.rows[0].dirty);
    });
}

#[gpui::test]
fn convert_workspace_relative_rewrites_double_slash_style_with_workspace_root(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = workspace.join("sourceimages/hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"C:/project//sourceimages/hero.tx\";\n",
        ),
    )
    .expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];

            shell.convert_path_targets_to_workspace_relative(
                vec![(1, 0)],
                PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let workspace_display = workspace.to_string_lossy().replace('\\', "/");
        assert_eq!(
            shell.rows[0].path_overrides.get(&0),
            Some(&format!("{workspace_display}//sourceimages/hero.tx")),
        );
    });
}

#[gpui::test]
fn convert_absolute_rewrites_workspace_relative_path(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = workspace.join("sourceimages/hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/hero.tx\";\n",
        ),
    )
    .expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];
            shell.path_sort = PathTableSort {
                key: PathSortKey::Node,
                direction: ColumnSort::Ascending,
            };

            shell.convert_path_targets_to_absolute(vec![(1, 0)], window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.rows[0].path_overrides.get(&0),
            Some(&texture.to_string_lossy().replace('\\', "/")),
        );
        assert!(matches!(shell.path_sort.key, PathSortKey::CapturedOrder));
        assert_eq!(shell.path_sort.direction, ColumnSort::Ascending);
        assert!(shell.path_order_snapshot.is_some());
    });
}

#[gpui::test]
fn path_mutation_preserves_pre_mutation_visible_order(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("scenes")).expect("mkdir scenes");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let a_texture = workspace.join("sourceimages/a_first.tx");
    let z_texture = workspace.join("sourceimages/z_last.tx");
    fs::write(&a_texture, "a").expect("write a texture");
    fs::write(&z_texture, "z").expect("write z texture");
    let scene = workspace.join("scenes/scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"fileZ\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/z_last.tx\";\n",
            "createNode file -n \"fileA\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/a_first.tx\";\n",
        ),
    )
    .expect("write scene");
    let z_absolute = z_texture.to_string_lossy().replace('\\', "/");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];
            shell.path_sort = PathTableSort {
                key: PathSortKey::Path,
                direction: ColumnSort::Ascending,
            };

            let before = shell.current_path_table_model();
            assert_eq!(before.rows[0].value, "sourceimages/a_first.tx");
            assert_eq!(before.rows[1].value, "sourceimages/z_last.tx");

            shell.convert_path_targets_to_absolute(vec![(1, 0)], window, cx);

            let after = shell.current_path_table_model();
            assert_eq!(after.rows[0].value, "sourceimages/a_first.tx");
            assert_eq!(after.rows[1].value, z_absolute);
            assert!(matches!(shell.path_sort.key, PathSortKey::CapturedOrder));
            assert!(shell.path_order_snapshot.is_some());

            shell.set_path_sort(PathSortKey::Path, ColumnSort::Ascending, cx);
            assert!(shell.path_order_snapshot.is_none());
        });
    });
}

#[gpui::test]
fn collect_path_targets_copies_files_and_stages_relative_paths(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let external = dir.path().join("external");
    fs::create_dir_all(&external).expect("mkdir external");
    fs::create_dir_all(workspace.join("scenes")).expect("mkdir scenes");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = external.join("hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scenes/scene.ma");
    let texture_value = texture.to_string_lossy().replace('\\', "/");
    fs::write(
        &scene,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{texture_value}\";\n",
            ),
            texture_value = texture_value
        ),
    )
    .expect("write scene");
    let destination_folder = workspace.join("sourceimages");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];

            shell.collect_path_targets_to_folder(
                vec![(1, 0)],
                destination_folder.clone(),
                PathCollectRewriteMode::PlainRelative,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.rows[0].path_overrides.get(&0),
            Some(&"sourceimages/hero.tx".to_string()),
        );
        assert_eq!(
            fs::read_to_string(destination_folder.join("hero.tx")).expect("read copied"),
            "tx"
        );
    });
}

#[gpui::test]
fn collect_path_targets_copy_only_does_not_stage_path_overrides(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let external = dir.path().join("external");
    fs::create_dir_all(&external).expect("mkdir external");
    fs::create_dir_all(workspace.join("scenes")).expect("mkdir scenes");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let texture = external.join("hero.tx");
    fs::write(&texture, "tx").expect("write texture");
    let scene = workspace.join("scenes/scene.ma");
    let texture_value = texture.to_string_lossy().replace('\\', "/");
    fs::write(
        &scene,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{texture_value}\";\n",
            ),
            texture_value = texture_value
        ),
    )
    .expect("write scene");
    let destination_folder = workspace.join("sourceimages");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];

            shell.collect_path_targets_to_folder(
                vec![(1, 0)],
                destination_folder.clone(),
                PathCollectRewriteMode::CopyOnly,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(shell.rows[0].path_overrides.is_empty());
        assert_eq!(
            fs::read_to_string(destination_folder.join("hero.tx")).expect("read copied"),
            "tx"
        );
    });
}

#[test]
fn build_path_table_model_filters_rows_by_rel_and_abs_form() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file_rel\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/rel.tx\";\n",
            "createNode file -n \"file_ws\";\n",
            "    setAttr \".ftn\" -type \"string\" \"C:/project//sourceimages/ws.tx\";\n",
            "createNode file -n \"file_abs\";\n",
            "    setAttr \".ftn\" -type \"string\" \"C:/absolute/hero.tx\";\n",
            "createNode file -n \"file_unc\";\n",
            "    setAttr \".ftn\" -type \"string\" \"//server/share/hero.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut rel_row = test_row(1, &scene);
    rel_row.selected = true;
    rel_row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    rel_row.refresh_path_resolution_cache();

    let rel_table = build_path_table_model(
        &[rel_row],
        &[0],
        &test_state(workspace.as_path(), ""),
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &BTreeSet::from([PathFormFilter::Rel]),
        &default_path_resolution_filter(),
        default_path_sort(),
    );
    let rel_values = rel_table
        .rows
        .iter()
        .map(|entry| entry.value.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        rel_values,
        BTreeSet::from(["textures/rel.tx", "C:/project//sourceimages/ws.tx"])
    );
    let mut abs_row = test_row(1, &scene);
    abs_row.selected = true;
    abs_row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    abs_row.refresh_path_resolution_cache();

    let abs_table = build_path_table_model(
        &[abs_row],
        &[0],
        &test_state(workspace.as_path(), ""),
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &BTreeSet::from([PathFormFilter::Abs]),
        &default_path_resolution_filter(),
        default_path_sort(),
    );
    let abs_values = abs_table
        .rows
        .iter()
        .map(|entry| entry.value.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        abs_values,
        BTreeSet::from(["C:/absolute/hero.tx", "//server/share/hero.tx"])
    );
}

#[test]
fn build_path_table_model_marks_preview_rows_without_value_style() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(&scene, "// scene").expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.replace_preview = Some(PathReplacePreview {
        input_path: scene,
        scene_format: SceneFormat::Ma,
        operation_mode: OperationMode::Strict,
        validation_state: ValidationState::Validated,
        matched_count: 1,
        items: vec![PathReplacePreviewItem {
            entry_index: 0,
            node_type: "file".into(),
            node_name: "file1".into(),
            attr: "ftn".into(),
            before_value: "C:/project//sourceimages/hero.tx".into(),
            after_value: "C:/project//sourceimages/hero_v2.tx".into(),
            replacement_count: 1,
        }],
    });

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        true,
        "",
        &BTreeSet::from([PathTypeFilter::File, PathTypeFilter::Reference]),
        &default_path_form_filter(),
        &BTreeSet::from([
            PathResolutionBadge::Exists,
            PathResolutionBadge::Missing,
            PathResolutionBadge::Unresolved,
        ]),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert_eq!(table.rows[0].value_style, None);
    assert!(table.rows[0].preview_only);
}

#[test]
fn build_path_table_model_filters_preview_rows_by_after_value_form() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(&workspace).expect("mkdir workspace");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let scene = workspace.join("scene.ma");
    fs::write(&scene, "// scene").expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.replace_preview = Some(PathReplacePreview {
        input_path: scene,
        scene_format: SceneFormat::Ma,
        operation_mode: OperationMode::Strict,
        validation_state: ValidationState::Validated,
        matched_count: 1,
        items: vec![PathReplacePreviewItem {
            entry_index: 0,
            node_type: "file".into(),
            node_name: "file1".into(),
            attr: "ftn".into(),
            before_value: "C:/absolute/hero.tx".into(),
            after_value: "textures/hero_v2.tx".into(),
            replacement_count: 1,
        }],
    });

    let table = build_path_table_model(
        &[row],
        &[0],
        &test_state(workspace.as_path(), ""),
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &BTreeSet::from([PathFormFilter::Rel]),
        &default_path_resolution_filter(),
        default_path_sort(),
    );

    assert_eq!(table.rows.len(), 1);
    assert!(table.rows[0].preview_only);
    assert_eq!(table.rows[0].value_style, None);
}

#[test]
fn shared_workspace_root_for_targets_returns_none_for_mixed_roots() {
    let dir = tempdir().expect("tmpdir");
    let workspace_a = dir.path().join("workspace_a");
    let workspace_b = dir.path().join("workspace_b");
    fs::create_dir_all(&workspace_a).expect("mkdir a");
    fs::create_dir_all(&workspace_b).expect("mkdir b");
    fs::write(workspace_a.join("workspace.mel"), "// workspace a").expect("workspace a");
    fs::write(workspace_b.join("workspace.mel"), "// workspace b").expect("workspace b");
    let scene_a = workspace_a.join("a.ma");
    let scene_b = workspace_b.join("b.ma");
    fs::write(&scene_a, "// scene a").expect("write a");
    fs::write(&scene_b, "// scene b").expect("write b");

    let first = test_row(1, &scene_a);
    let second = test_row(2, &scene_b);
    let targets = vec![(1, 0), (2, 0)];

    assert_eq!(
        shared_workspace_root_for_targets(&[first, second], &targets),
        None
    );
}

#[test]
fn build_path_table_model_sorts_rows_by_path_value() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"fileB\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/z_last.tx\";\n",
            "createNode file -n \"fileA\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/a_first.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));

    let state = test_state(dir.path(), "");
    let table = build_path_table_model(
        &[row],
        &[0],
        &state,
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        PathTableSort {
            key: PathSortKey::Path,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(table.rows.len(), 2);
    assert_eq!(table.rows[0].value, "textures/a_first.tx");
    assert_eq!(table.rows[1].value, "textures/z_last.tx");
}

#[test]
fn build_path_table_model_uses_captured_order_snapshot() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"fileB\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/z_last.tx\";\n",
            "createNode file -n \"fileA\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/a_first.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    let snapshot = PathOrderSnapshot {
        order_by_target: BTreeMap::from([((1, 1), 0), ((1, 0), 1)]),
    };

    let table = build_path_table_model_with_order_snapshot(
        &[row],
        &[0],
        &test_state(dir.path(), ""),
        None,
        &BTreeSet::new(),
        false,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        PathTableSort {
            key: PathSortKey::CapturedOrder,
            direction: ColumnSort::Ascending,
        },
        Some(&snapshot),
    );

    assert_eq!(table.rows.len(), 2);
    assert_eq!(table.rows[0].value, "textures/a_first.tx");
    assert_eq!(table.rows[0].captured_order, Some(0));
    assert_eq!(table.rows[1].value, "textures/z_last.tx");
    assert_eq!(table.rows[1].captured_order, Some(1));
}

#[test]
fn build_path_table_model_uses_captured_order_for_dedup_groups() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"fileSharedB\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/shared.tx\";\n",
            "createNode file -n \"fileOther\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/other.tx\";\n",
            "createNode file -n \"fileSharedC\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/shared.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    let snapshot = PathOrderSnapshot {
        order_by_target: BTreeMap::from([((1, 1), 0), ((1, 2), 1), ((1, 0), 2)]),
    };

    let table = build_path_table_model_with_order_snapshot(
        &[row],
        &[0],
        &test_state(dir.path(), ""),
        None,
        &BTreeSet::new(),
        true,
        "",
        &default_path_type_filter(),
        &default_path_form_filter(),
        &default_path_resolution_filter(),
        PathTableSort {
            key: PathSortKey::CapturedOrder,
            direction: ColumnSort::Ascending,
        },
        Some(&snapshot),
    );

    assert_eq!(table.rows.len(), 2);
    assert_eq!(table.rows[0].value, "textures/other.tx");
    assert_eq!(table.rows[0].captured_order, Some(0));
    assert_eq!(table.rows[1].value, "textures/shared.tx");
    assert_eq!(table.rows[1].captured_order, Some(1));
}

#[test]
fn merge_column_widths_preserves_existing_path_widths() {
    let mut existing = path_table_columns(false, default_path_sort());
    existing[0].width = px(70.0);
    existing[1].width = px(260.0);
    existing[2].width = px(640.0);

    let merged = merge_column_widths(&existing, path_table_columns(true, default_path_sort()));

    assert_eq!(merged[0].key.as_ref(), "kind");
    assert_eq!(merged[0].width, px(70.0));
    assert_eq!(merged[2].key.as_ref(), "node");
    assert_eq!(merged[2].width, px(260.0));
    assert_eq!(merged[3].key.as_ref(), "path");
    assert_eq!(merged[3].width, px(640.0));
}

#[test]
fn apply_persisted_column_widths_matches_by_column_key() {
    let persisted = vec![
        PersistedTableColumnWidth {
            key: "scene".to_string(),
            width_px: 410,
        },
        PersistedTableColumnWidth {
            key: "node".to_string(),
            width_px: 275,
        },
        PersistedTableColumnWidth {
            key: "path".to_string(),
            width_px: 820,
        },
    ];

    let hidden_scene =
        apply_persisted_column_widths(path_table_columns(false, default_path_sort()), &persisted);
    assert_eq!(hidden_scene[1].key.as_ref(), "node");
    assert_eq!(hidden_scene[1].width, px(275.0));
    assert_eq!(hidden_scene[2].key.as_ref(), "path");
    assert_eq!(hidden_scene[2].width, px(820.0));

    let shown_scene =
        apply_persisted_column_widths(path_table_columns(true, default_path_sort()), &persisted);
    assert_eq!(shown_scene[1].key.as_ref(), "scene");
    assert_eq!(shown_scene[1].width, px(410.0));
    assert_eq!(shown_scene[2].key.as_ref(), "node");
    assert_eq!(shown_scene[2].width, px(275.0));
    assert_eq!(shown_scene[3].key.as_ref(), "path");
    assert_eq!(shown_scene[3].width, px(820.0));
}

#[test]
fn persisted_column_widths_captures_column_keys_and_widths() {
    let mut columns = path_table_columns(false, default_path_sort());
    columns[1].width = px(255.0);
    columns[2].width = px(777.0);

    let persisted = persisted_column_widths(&columns);

    assert_eq!(
        persisted,
        vec![
            PersistedTableColumnWidth {
                key: "kind".to_string(),
                width_px: 88,
            },
            PersistedTableColumnWidth {
                key: "node".to_string(),
                width_px: 255,
            },
            PersistedTableColumnWidth {
                key: "path".to_string(),
                width_px: 777,
            },
        ]
    );
}
