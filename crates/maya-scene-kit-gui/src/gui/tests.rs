use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use encoding_rs::SHIFT_JIS;
use gpui::{
    AppContext, Axis, Entity, Focusable, Modifiers, OwnedMenuItem, TestAppContext,
    VisualTestContext, point, px, size,
};
use gpui_component::{Root, table::ColumnSort};
use maya_scene_kit_audit::{
    audit::{
        audit_script_nodes_with_options, build_parse_budget_blocked_audit_report,
        build_script_audit_plan,
    },
    scene::{
        AuditAllowlist, AuditCacheAccess, AuditCacheStore, AuditOptions, AuditSeverity,
        AuditedSceneSnapshot, fingerprint_audit_plan,
    },
};
use maya_scene_kit_edit::scene::{
    CompositeSceneEditsStageResult, ExecutionCleanTarget, OperationMode, PathOwnerDeletePreview,
    PathOwnerDeleteTarget, PathReplaceMode, PathReplaceOverride, PathReplacePreview,
    PathReplacePreviewItem, StagedSceneArtifact, ValidationState,
    clean_target_for_execution_origin,
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, ObserveCacheAccess, ObserveCacheStore, ObservedSceneSnapshot,
    collect_scene_paths,
    core::SceneFormat,
    dump::SceneDumpRequireKind,
    evidence::{
        ExecutionLanguage, ExecutionOrigin, ExecutionSourceRange, ExecutionSurfaceKind,
        ExecutionTrigger,
    },
    paths::{
        PathKind, ScenePathEntry, ScenePathResolutionStatus, ScenePathValueStyle, ScenePathsReport,
    },
};
use tempfile::tempdir;

use super::{
    AuditDetailCodeState, AuditDetailDialogState, AuditDetailField, AuditDetailFieldKind,
    AuditDetailTab, AuditResultItemKind, AuditResultRow, AuditResultRowKey, AuditRowCleanState,
    AuditSeverityFilter, AuditSortKey, AuditTableSort, AutoAnalyzeParallelismPreference,
    AutoAnalyzePriority, AutoAnalyzeQueueState, BackupLocationPreference, BannerMessage, DirtyKind,
    FileSortKey, FileStatus, FileTableSort, GuiFileState, MenuAutoAnalyzeParallelism32,
    MenuEditDeleteUiConfigurationScriptNode, MenuEditRedo, MenuEditUndo, MenuPurgeAnalysisCache,
    MenuToggleAnalysisCache, MenuToggleIgnoreFolderNames, PathCollectRewriteMode,
    PathEditKeyboardOutcome, PathFormFilter, PathOrderSnapshot, PathResolutionBadge, PathSortKey,
    PathTableSort, PathTypeFilter, ReplaceDialogPreviewSignature, ReplaceDialogPreviewState,
    ReplaceDialogSort, ReplaceDialogSortKey, ReplaceDialogState, RowJobResult, RowOperation,
    SceneRow, TableSelectAll, analyze_row, analyze_row_bytes_with_options,
    analyze_row_with_options, apply_path_overrides_to_report, apply_persisted_column_widths,
    audit_context_menu_state,
    audit_detail_dialog::OfferInput,
    audit_table_columns, backup_file_name, build_app_menus, build_audit_clipboard_payload,
    build_audit_result_rows, build_audit_table_model, build_file_copy_payload,
    build_file_operation_paths, build_file_table_rows, build_job_history_log_lines,
    build_path_table_model, build_path_table_model_with_order_snapshot,
    clean_targets_for_threat_findings, collect_scene_files_recursively,
    compute_visible_row_indices_for, default_audit_severity_filter, default_audit_sort,
    default_path_form_filter, default_path_resolution_filter, default_path_sort,
    default_path_type_filter, detect_format, exit_warning_required_for_rows,
    file_context_menu_state, filter_audit_result_rows, merge_column_widths,
    missing_path_count_for_row, next_backup_path, path_context_menu_state,
    path_edit::{
        PathCollectPlan, absolute_override_value_for_entry, collect_target_files,
        collected_path_rewrite_value, find_missing_path_file_hits, missing_path_entry_file_name,
        parse_path_collect_folder_input, path_collect_default_folder,
        path_collect_destination_supports_rewrite_mode, path_search_hit_key,
        path_value_edit_supported_for_edit_targets, path_value_edit_supported_for_entry,
        resolved_target_file_paths_for_edit_targets, shared_workspace_root_for_targets,
        workspace_relative_override_value_for_entry, write_back_selected_scene_path,
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
    default_analysis_cache_root,
    gui::{
        GuiShell,
        cache_maintenance::CacheMaintenanceFlushResult,
        cache_write::CacheWriteFlushResult,
        init_gui_app,
        plugins::{
            PluginActionScope, PluginRegistry, build_audit_plugin_context,
            build_file_plugin_context, run_plugin_action, spawn_plugin_action,
        },
    },
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
        analysis_cache_enabled: true,
        max_bytes: None,
        ignore_folder_names_enabled: true,
        ignored_folder_names: vec!["backup".to_string(), "autosave".to_string()],
        active_tab: ResultTab::Overview,
        status_filter: StatusFilter::All,
        file_list_findings_only: false,
        file_list_missing_only: false,
        file_list_no_workspace_only: false,
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

fn write_cached_scene(path: &Path) {
    fs::write(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"Example\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"Example\\\";\";\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"asset/example/file.fbx\";\n",
        ),
    )
    .expect("write cached scene");
}

fn menu_action_names(items: &[OwnedMenuItem]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            OwnedMenuItem::Action { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn sample_observed_snapshot(path_name: &str) -> ObservedSceneSnapshot {
    let dir = tempdir().expect("tmpdir");
    let scene_path = dir.path().join(path_name);
    write_cached_scene(&scene_path);
    let load_options = LoadOptions::default();
    let observation = Loader::new(load_options.clone())
        .observe_path(&scene_path)
        .expect("observe sample scene");
    ObservedSceneSnapshot::from_observation(&observation, &load_options).expect("sample snapshot")
}

fn sample_audited_snapshot(path_name: &str) -> AuditedSceneSnapshot {
    let dir = tempdir().expect("tmpdir");
    let scene_path = dir.path().join(path_name);
    write_cached_scene(&scene_path);
    let load_options = LoadOptions::default();
    let options = AuditOptions::strict_default();
    let plan = build_script_audit_plan(Vec::new(), 64).expect("build plan");
    let plan_fingerprint = fingerprint_audit_plan(&plan);
    let report = audit_script_nodes_with_options(&scene_path, &plan, &load_options, options)
        .expect("audit sample scene");
    AuditedSceneSnapshot::new(report, options, plan_fingerprint).expect("sample audit snapshot")
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
        allowed: None,
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
        provenance: vec!["node: scriptNode1".to_string(), "line: 3".to_string()],
        detail_fields: vec![
            AuditDetailField {
                kind: AuditDetailFieldKind::RuleId,
                raw: "audit_code".to_string(),
            },
            AuditDetailField {
                kind: AuditDetailFieldKind::Sink,
                raw: "py_exec".to_string(),
            },
            AuditDetailField {
                kind: AuditDetailFieldKind::Node,
                raw: "scriptNode1".to_string(),
            },
            AuditDetailField {
                kind: AuditDetailFieldKind::Line,
                raw: "3".to_string(),
            },
        ],
        source_line: Some(3),
        evidence: evidence.iter().map(|entry| entry.to_string()).collect(),
        dirty: false,
        clean_target: Some(ExecutionCleanTarget::ScriptNode {
            node_name: "scriptNode1".to_string(),
        }),
        clean_state: AuditRowCleanState::Available,
    }
}

#[test]
fn hydrate_cached_analysis_batch_restores_reports_from_disk_cache() {
    let dir = tempdir().expect("tmpdir");
    let scene_path = dir.path().join("Example.ma");
    write_cached_scene(&scene_path);

    let load_options = LoadOptions::default();
    let observation = Loader::new(load_options.clone())
        .observe_path(&scene_path)
        .expect("observe scene");
    let observe_snapshot = ObservedSceneSnapshot::from_observation(&observation, &load_options)
        .expect("observe snapshot");

    let plan = build_script_audit_plan(vec![], 64).expect("audit plan");
    let plan_fingerprint = fingerprint_audit_plan(&plan);
    let audit_options = AuditOptions::strict_default();
    let audit_report =
        audit_script_nodes_with_options(&scene_path, &plan, &load_options, audit_options)
            .expect("audit scene");
    let audit_snapshot = AuditedSceneSnapshot::new(audit_report, audit_options, plan_fingerprint)
        .expect("audit snapshot");

    let observe_root = dir.path().join("cache/observe");
    let audit_root = dir.path().join("cache/audit");
    ObserveCacheStore::new(&observe_root)
        .save(&observe_snapshot)
        .expect("save observe snapshot");
    AuditCacheStore::new(&audit_root)
        .save(&audit_snapshot)
        .expect("save audit snapshot");

    let mut row = test_row(1, &scene_path);
    let state = test_state(dir.path(), "");
    let batch = super::cache_restore::hydrate_cached_analysis_batch(
        vec![super::cache_restore::CacheHydrationInput {
            row_id: row.id,
            path: scene_path.clone(),
        }],
        load_options,
        audit_options,
        fingerprint_audit_plan(&plan),
        observe_root,
        audit_root,
    );
    let update = batch.updates.into_iter().next().expect("row update");

    if let Some(snapshot) = update.observe_snapshot {
        row.paths_report = Some(snapshot.paths_report);
        row.dump_report = Some(snapshot.dump_report);
        row.refresh_scene_workspace_root();
        row.refresh_path_resolution_cache();
    }
    if let Some(snapshot) = update.audit_snapshot {
        row.findings = snapshot.report.findings.len();
        row.set_audit_report(
            Some(snapshot.report),
            Some(GuiFileState {
                size: snapshot.file_state.size,
                modified_unix_nanos: snapshot.file_state.modified_unix_nanos,
            }),
        );
        row.analyzed_audit_mode = Some(state.audit_mode);
        row.status = FileStatus::Audited;
        row.sync_findings_count();
    }

    assert!(row.paths_report.is_some());
    assert!(row.dump_report.is_some());
    assert!(row.audit_report.is_some());
    assert_eq!(row.analyzed_audit_mode, Some(state.audit_mode));
    assert!(matches!(row.status, FileStatus::Audited));
    assert_eq!(
        row.path_resolution_cache.len(),
        row.paths_report.as_ref().expect("paths").entries.len()
    );
}

#[test]
fn hydrate_cached_analysis_batch_keeps_row_alignment_for_hits_and_misses() {
    let dir = tempdir().expect("tmpdir");
    let cached_path = dir.path().join("Example.ma");
    let missing_path = dir.path().join("Missing.ma");
    write_cached_scene(&cached_path);
    write_cached_scene(&missing_path);

    let load_options = LoadOptions::default();
    let observation = Loader::new(load_options.clone())
        .observe_path(&cached_path)
        .expect("observe scene");
    let observe_snapshot = ObservedSceneSnapshot::from_observation(&observation, &load_options)
        .expect("observe snapshot");

    let plan = build_script_audit_plan(vec![], 64).expect("audit plan");
    let plan_fingerprint = fingerprint_audit_plan(&plan);
    let audit_options = AuditOptions::strict_default();
    let audit_report =
        audit_script_nodes_with_options(&cached_path, &plan, &load_options, audit_options)
            .expect("audit scene");
    let audit_snapshot =
        AuditedSceneSnapshot::new(audit_report, audit_options, plan_fingerprint.clone())
            .expect("audit snapshot");

    let observe_root = dir.path().join("cache/observe");
    let audit_root = dir.path().join("cache/audit");
    ObserveCacheStore::new(&observe_root)
        .save(&observe_snapshot)
        .expect("save observe snapshot");
    AuditCacheStore::new(&audit_root)
        .save(&audit_snapshot)
        .expect("save audit snapshot");

    std::fs::remove_file(&missing_path).expect("remove missing scene");

    let batch = super::cache_restore::hydrate_cached_analysis_batch(
        vec![
            super::cache_restore::CacheHydrationInput {
                row_id: 41,
                path: missing_path,
            },
            super::cache_restore::CacheHydrationInput {
                row_id: 42,
                path: cached_path,
            },
        ],
        load_options,
        audit_options,
        plan_fingerprint,
        observe_root,
        audit_root,
    );

    assert_eq!(batch.processed_count, 2);
    assert_eq!(batch.updates.len(), 2);
    assert_eq!(batch.updates[0].row_id, 41);
    assert!(batch.updates[0].observe_snapshot.is_none());
    assert!(batch.updates[0].audit_snapshot.is_none());
    assert_eq!(batch.updates[1].row_id, 42);
    assert!(batch.updates[1].observe_snapshot.is_some());
    assert!(batch.updates[1].audit_snapshot.is_some());
}

fn open_test_shell(cx: &mut TestAppContext) -> (Entity<GuiShell>, &mut VisualTestContext) {
    cx.update(init_gui_app);

    let shell_slot = Rc::new(RefCell::new(None));
    let shell_slot_for_build = shell_slot.clone();
    let analysis_cache_root = unique_test_analysis_cache_root();
    let (_, visual_cx) = cx.add_window_view(|window, cx| {
        let menu_bar = TopMenuBar::new(window, cx);
        let shell = cx.new(|cx| {
            GuiShell::new_for_test(
                menu_bar,
                window,
                cx,
                PersistedState::default(),
                analysis_cache_root.clone(),
            )
        });
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

fn unique_test_analysis_cache_root() -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    let unique_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("maya-scene-kit-gui-test-cache-{nanos}-{unique_id}"))
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

fn write_ui_configuration_script_node_scene(path: &Path) {
    fs::write(
        path,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode script -n \"uiConfigurationScriptNode\";\n",
            "    setAttr \".b\" -type \"string\" \"print(\\\"ui config\\\")\";\n",
            "    setAttr \".st\" 1;\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"asset/example/file.fbx\";\n",
        ),
    )
    .expect("write uiConfigurationScriptNode fixture");
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
    let options = maya_scene_kit_edit::scene::MaterializeOptions::default()
        .with_operation_mode(OperationMode::Forensic);
    let RowJobResult::Analyze(result) =
        analyze_row(scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    let mut row = test_row(1, scene);
    row.set_audit_report(Some(result.audit_report.clone()), result.audit_file_state);
    row.dump_report = result.dump_report.clone();

    let mut clean_targets = result
        .audit_report
        .findings
        .iter()
        .filter_map(|finding| {
            let surface = result.audit_report.surface_for(finding);
            (surface.origin.node_name.as_deref() == Some(node_name))
                .then(|| clean_target_for_execution_origin(&surface.origin))
                .flatten()
        })
        .collect::<BTreeSet<_>>();
    if clean_targets.is_empty() {
        clean_targets.extend(clean_targets_for_threat_findings(&row).into_iter().filter(
            |target| {
                matches!(
                    target,
                    ExecutionCleanTarget::ScriptNode { node_name: target_name }
                        if target_name == node_name
                )
            },
        ));
    }
    if clean_targets.is_empty() {
        clean_targets.insert(ExecutionCleanTarget::ScriptNode {
            node_name: node_name.to_string(),
        });
    }

    let staged = match maya_scene_kit_edit::scene::stage_scene_edits_with_options(
        scene,
        &clean_targets.into_iter().collect::<Vec<_>>(),
        &[],
        &options,
    ) {
        Ok(staged) => staged,
        Err(_) => CompositeSceneEditsStageResult {
            preview: maya_scene_kit_edit::scene::CompositeSceneEditsPreview {
                input_path: scene.to_path_buf(),
                scene_format: SceneFormat::Ma,
                operation_mode: OperationMode::Forensic,
                validation_state: ValidationState::Validated,
                cleaned_targets: vec![ExecutionCleanTarget::ScriptNode {
                    node_name: node_name.to_string(),
                }],
                removed_script_nodes: vec![node_name.to_string()],
                removed_plugin_requires: Vec::new(),
                deleted_path_owner_targets: Vec::new(),
            },
            artifact: StagedSceneArtifact {
                input_path: scene.to_path_buf(),
                suggested_output_path: scene.to_path_buf(),
                scene_format: SceneFormat::Ma,
                operation_mode: OperationMode::Forensic,
                validation_state: ValidationState::Validated,
                bytes: fs::read(scene).unwrap_or_else(|_| {
                    format!("//Maya ASCII 2026 scene\n// cleaned {node_name}\n").into_bytes()
                }),
            },
        },
    };
    let staged_source_bytes = staged.artifact.bytes.clone();
    let analyzed = analyze_row_bytes_with_options(
        scene,
        staged.preview.scene_format,
        staged.preview.validation_state,
        staged_source_bytes.clone(),
        AuditModePreference::StrictDefault,
        &LoadOptions::default(),
        &build_script_audit_plan(vec![], 64).expect("plan"),
    )
    .expect("analyze staged bytes");
    let staged_paths_report = analyzed.paths_report.expect("staged paths");
    let staged_dump_report = analyzed.dump_report.expect("staged dump");

    RowJobResult::SceneEdits {
        audit_plan_fingerprint: analyzed.audit_plan_fingerprint,
        staged,
        audit_mode: AuditModePreference::StrictDefault,
        staged_audit_report: analyzed.audit_report,
        staged_paths_report,
        staged_dump_report,
        staged_source_bytes,
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
    row.set_audit_report(Some(result.audit_report.clone()), result.audit_file_state);
    row.dump_report = result.dump_report;

    let audit_row = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    )
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
fn auto_analyze_queue_prioritizes_high_before_viewport_before_low() {
    let mut queue = AutoAnalyzeQueueState::default();
    queue.enqueue_many([1, 2, 3], AutoAnalyzePriority::Low);
    queue.enqueue_many([6, 7], AutoAnalyzePriority::Viewport);
    queue.enqueue_many([4, 5], AutoAnalyzePriority::High);

    assert_eq!(queue.pop_next(true), Some(4));
    assert_eq!(queue.pop_next(true), Some(5));
    assert_eq!(queue.pop_next(true), Some(6));
    assert_eq!(queue.pop_next(true), Some(7));
    assert_eq!(queue.pop_next(true), Some(1));
    assert_eq!(queue.pop_next(true), Some(2));
    assert_eq!(queue.pop_next(true), Some(3));
    assert_eq!(queue.pop_next(true), None);
}

#[test]
fn auto_analyze_queue_promotes_low_entry_to_high_without_duplication() {
    let mut queue = AutoAnalyzeQueueState::default();
    queue.enqueue(7, AutoAnalyzePriority::Low);
    queue.enqueue(7, AutoAnalyzePriority::High);
    queue.enqueue(7, AutoAnalyzePriority::Low);

    assert_eq!(queue.remaining_count(), 1);
    assert_eq!(queue.pop_next(true), Some(7));
    assert_eq!(queue.pop_next(true), None);
}

#[test]
fn auto_analyze_queue_promotes_low_entry_to_viewport_without_duplication() {
    let mut queue = AutoAnalyzeQueueState::default();
    queue.enqueue(9, AutoAnalyzePriority::Low);
    queue.enqueue(9, AutoAnalyzePriority::Viewport);
    queue.enqueue(9, AutoAnalyzePriority::Low);

    assert_eq!(queue.remaining_count(), 1);
    assert_eq!(queue.pop_next(true), Some(9));
    assert_eq!(queue.pop_next(true), None);
}

#[test]
fn auto_analyze_queue_remaining_count_includes_in_flight() {
    let mut queue = AutoAnalyzeQueueState::default();
    queue.enqueue_many([10, 11, 12], AutoAnalyzePriority::Low);
    assert_eq!(queue.remaining_count(), 3);

    assert_eq!(queue.pop_next(true), Some(10));
    assert_eq!(queue.remaining_count(), 3);

    queue.complete(10);
    assert_eq!(queue.remaining_count(), 2);
}

#[test]
fn auto_analyze_queue_suppresses_low_when_requested() {
    let mut queue = AutoAnalyzeQueueState::default();
    queue.enqueue_many([1, 2], AutoAnalyzePriority::Low);
    queue.enqueue(3, AutoAnalyzePriority::Viewport);

    assert_eq!(queue.pop_next(false), Some(3));
    assert_eq!(queue.pop_next(false), None);
    assert_eq!(queue.pop_next(true), Some(1));
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
            shell.on_table_select_all(&TableSelectAll, window, cx);
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
            shell.on_table_select_all(&TableSelectAll, window, cx);
            shell.on_table_select_all(&TableSelectAll, window, cx);
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
            shell.on_table_select_all(&TableSelectAll, window, cx);
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
                    audit_file_state: None,
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
                    audit_file_state: None,
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
            row.set_audit_report(Some(result.audit_report), result.audit_file_state);
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
            assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::SceneEdits));
            assert_eq!(shell.rows[1].dirty_kind, Some(DirtyKind::SceneEdits));
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

            row.set_audit_report(Some(result.audit_report), result.audit_file_state);
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
            assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::SceneEdits));
            assert_eq!(shell.rows[1].dirty_kind, Some(DirtyKind::SceneEdits));

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
                    audit_file_state: None,
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
            shell.on_table_select_all(&TableSelectAll, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        assert!(shell.read(app).selected_indices().is_empty());
    });
}

#[gpui::test]
fn path_table_ctrl_a_selects_all_visible_path_rows_then_clears(cx: &mut TestAppContext) {
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
            shell.rows = vec![row];
            shell.selected_path_rows = BTreeSet::from([vec![(1, 0)]]);
            shell.refresh_path_table(cx);
        });
        shell.read(app).path_table_focus_handle.focus(window);
        shell.update(app, |shell, cx| {
            shell.on_table_select_all(&TableSelectAll, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.selected_path_rows,
            BTreeSet::from([vec![(1, 0)], vec![(1, 1)]])
        );
        assert_eq!(shell.selected_indices(), vec![0]);
    });

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            shell.on_table_select_all(&TableSelectAll, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(shell.selected_path_rows.is_empty());
        assert_eq!(shell.selected_indices(), vec![0]);
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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
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
fn path_resolution_cache_uses_scene_folder_fallback_after_workspace_miss() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let scene_dir = workspace.join("scenes");
    fs::create_dir_all(scene_dir.join("textures")).expect("mkdir scene textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let scene = scene_dir.join("scene.ma");
    fs::write(scene_dir.join("textures/existing.tx"), "tx").expect("existing tx");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/existing.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.refresh_scene_workspace_root();
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::All).expect("paths"));
    row.refresh_path_resolution_cache();

    assert_eq!(missing_path_count_for_row(&row), Some(0));
    assert_eq!(row.path_resolution_cache.len(), 1);
    assert_eq!(
        row.path_resolution_cache
            .get(&0)
            .map(|entry| entry.resolution.status),
        Some(ScenePathResolutionStatus::Exists)
    );
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
fn compute_visible_rows_filters_to_no_workspace_only() {
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

    let mut state = test_state(workspace.as_path(), "");
    state.file_list_no_workspace_only = true;
    let visible = compute_visible_row_indices_for(
        &[test_row(1, &inside), test_row(2, &outside)],
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
fn compute_visible_rows_combines_no_workspace_with_other_filters_using_or_logic() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let outside_dir = dir.path().join("outside");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::create_dir_all(&outside_dir).expect("mkdir outside");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    fs::write(workspace.join("textures/existing.tx"), "tx").expect("write existing");
    let findings = workspace.join("findings.ma");
    let no_workspace = outside_dir.join("outside.ma");
    let hidden = workspace.join("hidden.ma");
    for path in [&findings, &no_workspace, &hidden] {
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

    let mut findings_row = test_row(1, &findings);
    findings_row.findings = 1;
    let no_workspace_row = test_row(2, &no_workspace);
    let hidden_row = test_row(3, &hidden);

    let mut state = test_state(workspace.as_path(), "");
    state.file_list_findings_only = true;
    state.file_list_no_workspace_only = true;
    let visible = compute_visible_row_indices_for(
        &[findings_row, no_workspace_row, hidden_row],
        &state,
        FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        },
    );

    assert_eq!(visible, vec![1, 0]);
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
    state.file_list_no_workspace_only = true;
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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );

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
            allowed: None,
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
            provenance: Vec::new(),
            detail_fields: vec![
                AuditDetailField {
                    kind: AuditDetailFieldKind::RuleId,
                    raw: "info_code".to_string(),
                },
                AuditDetailField {
                    kind: AuditDetailFieldKind::Sink,
                    raw: "none".to_string(),
                },
            ],
            source_line: None,
            evidence: Vec::new(),
            dirty: false,
            clean_target: None,
            clean_state: AuditRowCleanState::Unsupported,
        },
        AuditResultRow {
            allowed: None,
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
            provenance: Vec::new(),
            detail_fields: vec![
                AuditDetailField {
                    kind: AuditDetailFieldKind::RuleId,
                    raw: "high_code".to_string(),
                },
                AuditDetailField {
                    kind: AuditDetailFieldKind::Sink,
                    raw: "py_exec".to_string(),
                },
            ],
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
        &["node: Example".to_string()],
        "print(\"hello\")",
        &["command: python".to_string(), "flag: -c".to_string()],
    );

    assert_eq!(
        payload,
        "node: Example\n\nprint(\"hello\")\n\ncommand: python\nflag: -c"
    );
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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );

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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    row.pending_clean_targets
        .insert(ExecutionCleanTarget::ScriptNode {
            node_name: "literalPythonReview".to_string(),
        });

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );

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
        allowed: None,
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
        provenance: vec!["node: scriptNode1".to_string()],
        detail_fields: vec![
            AuditDetailField {
                kind: AuditDetailFieldKind::RuleId,
                raw: "script_node".to_string(),
            },
            AuditDetailField {
                kind: AuditDetailFieldKind::Sink,
                raw: "observe".to_string(),
            },
            AuditDetailField {
                kind: AuditDetailFieldKind::Node,
                raw: "scriptNode1".to_string(),
            },
        ],
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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );
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
fn clean_targets_for_threat_findings_include_finding_backed_script_node_targets() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("literal_script_threats.ma");
    write_literal_mel_python_scene(&path);
    let mut row = test_row(1, &path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);

    let targets = clean_targets_for_threat_findings(&row);

    assert!(
        targets
            .iter()
            .all(|target| { !matches!(target, ExecutionCleanTarget::PluginRequire { .. }) }),
        "file-list threat clean should only include finding-backed execution targets",
    );
    assert!(
        targets.iter().any(|target| {
            matches!(
                target,
                ExecutionCleanTarget::ScriptNode { .. } | ExecutionCleanTarget::MbOwnerForm { .. }
            )
        }),
        "expected finding-backed script-node threat target",
    );
}

#[test]
fn file_context_menu_state_enables_clean_for_selected_finding_backed_row() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("selected_finding_target.ma");
    write_literal_mel_python_scene(&path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    let mut row = test_row(1, &path);
    row.selected = true;
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    row.paths_report = result.paths_report.clone();
    row.dump_report = result.dump_report.clone();
    row.analyzed_audit_mode = Some(result.audit_mode);

    let state = file_context_menu_state(&[row], 1, AuditModePreference::StrictDefault);

    assert!(state.can_clean);
    assert!(!state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_disables_clean_when_clicked_row_has_no_targets() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("clean_context_no_targets.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let row = test_row(1, &path);

    let state = file_context_menu_state(&[row], 1, AuditModePreference::StrictDefault);

    assert!(!state.can_clean);
    assert!(!state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_ignores_other_selected_targets_when_clicked_row_is_unselected() {
    let dir = tempdir().expect("tmpdir");
    let selected_path = dir.path().join("selected_target.ma");
    let clicked_path = dir.path().join("clicked_row.ma");
    write_literal_mel_python_scene(&selected_path);
    fs::write(&clicked_path, "//Maya ASCII 2026 scene\n").expect("write clicked");
    let RowJobResult::Analyze(result) =
        analyze_row(&selected_path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    let mut selected_row = test_row(1, &selected_path);
    selected_row.selected = true;
    selected_row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    let clicked_row = test_row(2, &clicked_path);

    let state = file_context_menu_state(
        &[selected_row, clicked_row],
        2,
        AuditModePreference::StrictDefault,
    );

    assert!(!state.can_clean);
    assert!(!state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_enables_clean_for_pending_clean_targets() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("pending_clean_target.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let mut row = test_row(1, &path);
    row.pending_clean_targets = BTreeSet::from([ExecutionCleanTarget::ScriptNode {
        node_name: "Example".to_string(),
    }]);

    let state = file_context_menu_state(&[row], 1, AuditModePreference::StrictDefault);

    assert!(!state.can_clean);
    assert!(!state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_disables_delete_ui_configuration_script_node_when_already_staged() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("pending_ui_config_target.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let mut row = test_row(1, &path);
    row.pending_clean_targets = BTreeSet::from([ExecutionCleanTarget::ScriptNode {
        node_name: "uiConfigurationScriptNode".to_string(),
    }]);

    let state = file_context_menu_state(&[row], 1, AuditModePreference::StrictDefault);

    assert!(!state.can_clean);
    assert!(!state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_enables_delete_ui_configuration_script_node_when_dump_has_node() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("ui_config_present_for_menu.ma");
    write_ui_configuration_script_node_scene(&path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    let mut row = test_row(1, &path);
    row.dump_report = result.dump_report;

    let state = file_context_menu_state(&[row], 1, AuditModePreference::StrictDefault);

    assert!(state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_disables_delete_ui_configuration_script_node_for_processing_rows() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("processing_delete_ui_config.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let mut row = test_row(1, &path);
    row.status = FileStatus::Processing(RowOperation::Analyze);

    let state = file_context_menu_state(&[row], 1, AuditModePreference::StrictDefault);

    assert!(!state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_disables_delete_actions_for_replace_rows() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("replace_context_disabled.ma");
    write_literal_mel_python_scene(&path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    let mut row = test_row(1, &path);
    row.selected = true;
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    row.dirty_kind = Some(DirtyKind::Replace);
    row.path_overrides
        .insert(0, "asset/example/edited.fbx".to_string());

    let state = file_context_menu_state(&[row], 1, AuditModePreference::StrictDefault);

    assert!(!state.can_clean);
    assert!(!state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_keeps_clean_enabled_when_selected_rows_mix_eligible_and_replace() {
    let dir = tempdir().expect("tmpdir");
    let eligible_path = dir.path().join("eligible_target.ma");
    let blocked_path = dir.path().join("blocked_target.ma");
    write_literal_mel_python_scene(&eligible_path);
    write_literal_mel_python_scene(&blocked_path);
    let RowJobResult::Analyze(result) =
        analyze_row(&eligible_path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    let mut eligible_row = test_row(1, &eligible_path);
    eligible_row.selected = true;
    eligible_row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    eligible_row.paths_report = result.paths_report.clone();
    eligible_row.dump_report = result.dump_report.clone();
    eligible_row.analyzed_audit_mode = Some(result.audit_mode);
    let mut blocked_row = test_row(2, &blocked_path);
    blocked_row.selected = true;
    blocked_row.dirty_kind = Some(DirtyKind::Replace);
    blocked_row
        .path_overrides
        .insert(0, "asset/example/edited.fbx".to_string());

    let state = file_context_menu_state(
        &[eligible_row, blocked_row],
        1,
        AuditModePreference::StrictDefault,
    );

    assert!(state.can_clean);
}

#[test]
fn file_context_menu_state_keeps_ui_configuration_delete_enabled_when_selection_has_one_match() {
    let dir = tempdir().expect("tmpdir");
    let eligible_path = dir.path().join("ui_config_match.ma");
    let blocked_path = dir.path().join("ui_config_missing.ma");
    write_ui_configuration_script_node_scene(&eligible_path);
    fs::write(&blocked_path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let RowJobResult::Analyze(result) =
        analyze_row(&eligible_path, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    let mut eligible_row = test_row(1, &eligible_path);
    eligible_row.selected = true;
    eligible_row.dump_report = result.dump_report;
    let mut blocked_row = test_row(2, &blocked_path);
    blocked_row.selected = true;

    let state = file_context_menu_state(
        &[eligible_row, blocked_row],
        1,
        AuditModePreference::StrictDefault,
    );

    assert!(state.can_delete_ui_configuration_script_node);
}

#[test]
fn file_context_menu_state_disables_delete_actions_for_to_ascii_rows() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("to_ascii_context_disabled.mb");
    fs::write(&path, "FORM").expect("write scene");
    let mut row = test_row(1, &path);
    row.selected = true;
    row.dirty_kind = Some(DirtyKind::ToAscii);
    row.dirty_artifact = Some(StagedSceneArtifact {
        input_path: path.clone(),
        suggested_output_path: dir.path().join("to_ascii_context_disabled.ma"),
        scene_format: SceneFormat::Ma,
        operation_mode: OperationMode::Forensic,
        validation_state: ValidationState::Validated,
        bytes: b"// ascii".to_vec(),
    });

    let state = file_context_menu_state(&[row], 1, AuditModePreference::StrictDefault);

    assert!(!state.can_clean);
    assert!(!state.can_delete_ui_configuration_script_node);
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
        ..ExecutionOrigin::without_chunk_address()
    };

    let target = clean_target_for_execution_origin(&origin);

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
        ..ExecutionOrigin::without_chunk_address()
    };

    let target = clean_target_for_execution_origin(&origin);

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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );
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
        ..ExecutionOrigin::without_chunk_address()
    };

    let target = clean_target_for_execution_origin(&origin);

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
        ..ExecutionOrigin::without_chunk_address()
    };

    let target = clean_target_for_execution_origin(&origin);

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
        allowed: None,
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
        provenance: Vec::new(),
        detail_fields: vec![
            AuditDetailField {
                kind: AuditDetailFieldKind::RuleId,
                raw: "note".to_string(),
            },
            AuditDetailField {
                kind: AuditDetailFieldKind::Sink,
                raw: "none".to_string(),
            },
        ],
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

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );
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

    let rows = build_audit_result_rows(
        &[first, second],
        &[0, 1],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );

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

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );
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

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );
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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    row.dump_report = result.dump_report;

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );
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

    let rows = build_audit_result_rows(
        std::slice::from_ref(&row),
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );
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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
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
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
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
        assert_eq!(
            state.code_input.read(cx).value().to_string(),
            state.preview_text
        );
        assert!(state.code_input.read(cx).is_read_only());
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

        let AuditDetailDialogState { code_input, .. } = shell
            .audit_detail_dialog
            .as_ref()
            .expect("audit detail state")
            .clone();

        code_input.update(cx, |input, cx| input.set_value("stale preview", window, cx));
        shell
            .audit_detail_dialog
            .as_mut()
            .expect("detail state")
            .preview_text = "stale preview".to_string();

        shell.sync_audit_detail_dialog_inputs(window, cx);

        let state = shell
            .audit_detail_dialog
            .as_ref()
            .expect("audit detail state");

        assert_ne!(state.preview_text, "stale preview");
        assert_eq!(
            state.code_input.read(cx).value().to_string(),
            state.preview_text
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
fn settings_menu_toggle_updates_analysis_cache_preference(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = true;
        assert!(shell.state.analysis_cache_enabled);
        shell.on_menu_toggle_analysis_cache(&MenuToggleAnalysisCache, window, cx);
        assert!(!shell.state.analysis_cache_enabled);
    });
}

#[gpui::test]
fn disabling_analysis_cache_cancels_restore_and_pending_writes(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = true;
        let observe_snapshot = sample_observed_snapshot("Example.ma");
        let observe_access = ObserveCacheAccess {
            path: observe_snapshot.file_state.path.clone(),
            file_state: observe_snapshot.file_state.clone(),
            identity: observe_snapshot.identity.clone(),
        };
        let audit_scene = tempdir().expect("tmpdir");
        let audit_path = audit_scene.path().join("Example.ma");
        write_cached_scene(&audit_path);
        let load_options = LoadOptions::default();
        let plan = build_script_audit_plan(vec![], 64).expect("plan");
        let plan_fingerprint = fingerprint_audit_plan(&plan);
        let audit_options = AuditOptions::strict_default();
        let audit_report =
            audit_script_nodes_with_options(&audit_path, &plan, &load_options, audit_options)
                .expect("audit report");
        let audit_snapshot =
            AuditedSceneSnapshot::new(audit_report, audit_options, plan_fingerprint)
                .expect("audit snapshot");
        let audit_access = AuditCacheAccess {
            path: audit_snapshot.file_state.path.clone(),
            file_state: audit_snapshot.file_state.clone(),
            identity: audit_snapshot.identity.clone(),
        };
        shell.cache_restore_state.pending.push_back(11);
        shell.cache_restore_state.in_flight = true;
        shell
            .cache_write_state
            .pending_observe_order
            .push_back("Example.ma".to_string());
        shell
            .cache_write_state
            .pending_observe
            .insert("Example.ma".to_string(), observe_snapshot);
        shell
            .cache_maintenance_state
            .pending_observe_order
            .push_back("Example.ma".to_string());
        shell
            .cache_maintenance_state
            .pending_observe
            .insert("Example.ma".to_string(), observe_access);
        shell
            .cache_maintenance_state
            .pending_audit_order
            .push_back("ExampleAudit.ma".to_string());
        shell
            .cache_maintenance_state
            .pending_audit
            .insert("ExampleAudit.ma".to_string(), audit_access);
        shell.cache_maintenance_state.pending_sweep = true;
        shell.cache_maintenance_state.in_flight = true;

        shell.on_menu_toggle_analysis_cache(&MenuToggleAnalysisCache, window, cx);

        assert!(!shell.state.analysis_cache_enabled);
        assert!(shell.cache_restore_state.pending.is_empty());
        assert!(!shell.cache_restore_state.in_flight);
        assert!(shell.cache_write_state.pending_observe.is_empty());
        assert!(shell.cache_write_state.pending_observe_order.is_empty());
        assert!(!shell.cache_write_state.debounce_pending);
        assert!(!shell.cache_write_state.in_flight);
        assert!(shell.cache_maintenance_state.pending_observe.is_empty());
        assert!(
            shell
                .cache_maintenance_state
                .pending_observe_order
                .is_empty()
        );
        assert!(shell.cache_maintenance_state.pending_audit.is_empty());
        assert!(shell.cache_maintenance_state.pending_audit_order.is_empty());
        assert!(!shell.cache_maintenance_state.pending_sweep);
        assert!(!shell.cache_maintenance_state.in_flight);
    });
}

#[gpui::test]
fn cache_writes_queue_with_idle_debounce(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = true;
        let observe_snapshot = sample_observed_snapshot("Example.ma");
        shell.enqueue_cache_writes(Some(observe_snapshot), None, window, cx);

        assert!(shell.cache_write_state.debounce_pending);
        assert!(!shell.cache_write_state.in_flight);
        assert_eq!(shell.cache_write_state.pending_observe.len(), 1);
    });
}

#[gpui::test]
fn cache_writes_stay_debounced_during_active_auto_analyze(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = true;
        shell.workspace_auto_analyze_started_at = Some(Instant::now());

        let observe_snapshot = sample_observed_snapshot("ExampleActiveAnalyze.ma");
        shell.enqueue_cache_writes(Some(observe_snapshot), None, window, cx);

        assert!(shell.cache_write_state.debounce_pending);
        assert!(!shell.cache_write_state.in_flight);
        assert_eq!(shell.cache_write_state.pending_observe.len(), 1);
    });
}

#[gpui::test]
fn cache_writes_resume_after_enqueue_during_in_flight_flush(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = true;
        shell.cache_write_state.in_flight = true;
        let stale_generation = shell.cache_write_generation;

        let observe_snapshot = sample_observed_snapshot("ExampleResume.ma");
        shell.enqueue_cache_writes(Some(observe_snapshot), None, window, cx);

        assert!(shell.cache_write_state.in_flight);
        assert!(shell.cache_write_state.debounce_pending);
        assert_eq!(shell.cache_write_state.pending_observe.len(), 1);

        shell.finish_cache_write_flush(
            stale_generation,
            CacheWriteFlushResult {
                error_count: 0,
                first_error: None,
            },
            window,
            cx,
        );

        assert!(!shell.cache_write_state.in_flight);
        assert!(shell.cache_write_state.debounce_pending);
        assert_eq!(shell.cache_write_state.pending_observe.len(), 1);
    });
}

#[gpui::test]
fn cache_maintenance_queue_with_idle_debounce(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = true;
        let snapshot = sample_observed_snapshot("Example.ma");
        let observe_access = ObserveCacheAccess {
            path: PathBuf::from("Example.ma"),
            file_state: snapshot.file_state,
            identity: snapshot.identity,
        };
        shell.enqueue_cache_accesses(Some(observe_access), None, window, cx);

        assert!(shell.cache_maintenance_state.debounce_pending);
        assert!(!shell.cache_maintenance_state.in_flight);
        assert_eq!(shell.cache_maintenance_state.pending_observe.len(), 1);
    });
}

#[gpui::test]
fn cache_maintenance_resumes_after_enqueue_during_in_flight_flush(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = true;
        shell.cache_maintenance_state.in_flight = true;
        let stale_generation = shell.cache_maintenance_generation;

        let snapshot = sample_observed_snapshot("ExampleResumeTouch.ma");
        let observe_access = ObserveCacheAccess {
            path: PathBuf::from("ExampleResumeTouch.ma"),
            file_state: snapshot.file_state,
            identity: snapshot.identity,
        };
        shell.enqueue_cache_accesses(Some(observe_access), None, window, cx);

        assert!(shell.cache_maintenance_state.in_flight);
        assert!(shell.cache_maintenance_state.debounce_pending);
        assert_eq!(shell.cache_maintenance_state.pending_observe.len(), 1);

        shell.finish_cache_maintenance_flush(
            stale_generation,
            CacheMaintenanceFlushResult {
                error_count: 0,
                first_error: None,
            },
            window,
            cx,
        );

        assert!(!shell.cache_maintenance_state.in_flight);
        assert!(shell.cache_maintenance_state.debounce_pending);
        assert_eq!(shell.cache_maintenance_state.pending_observe.len(), 1);
    });
}

#[gpui::test]
fn workspace_auto_analysis_completion_flushes_pending_cache_persistence(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = true;
        shell.workspace_auto_analyze_started_at = Some(Instant::now());

        let observe_snapshot = sample_observed_snapshot("ExampleFlush.ma");
        let observe_access = ObserveCacheAccess {
            path: observe_snapshot.file_state.path.clone(),
            file_state: observe_snapshot.file_state.clone(),
            identity: observe_snapshot.identity.clone(),
        };
        shell
            .cache_write_state
            .pending_observe_order
            .push_back("ExampleFlush.ma".to_string());
        shell
            .cache_write_state
            .pending_observe
            .insert("ExampleFlush.ma".to_string(), observe_snapshot);
        shell.cache_write_state.debounce_pending = true;
        shell
            .cache_maintenance_state
            .pending_observe_order
            .push_back("ExampleFlush.ma".to_string());
        shell
            .cache_maintenance_state
            .pending_observe
            .insert("ExampleFlush.ma".to_string(), observe_access);
        shell.cache_maintenance_state.debounce_pending = true;

        shell.maybe_finish_workspace_auto_analyze_batch(window, cx);

        assert!(shell.workspace_auto_analyze_started_at.is_none());
        assert!(shell.cache_write_state.in_flight);
        assert!(!shell.cache_write_state.debounce_pending);
        assert!(shell.cache_maintenance_state.in_flight);
        assert!(!shell.cache_maintenance_state.debounce_pending);
    });
}

#[gpui::test]
fn cache_restore_updates_queue_coalesced_refresh_for_visible_rows(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("restore_visible_scene.ma");
    write_cached_scene(&scene);
    let observe_snapshot = sample_observed_snapshot("RestoreVisible.ma");
    let audit_snapshot = sample_audited_snapshot("RestoreVisible.ma");

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(dir.path(), "");
        shell.rows = vec![test_row(1, &scene)];
        shell.rows[0].selected = true;
        shell.refresh_file_table(cx);
        shell.update_file_table_viewport_range(0..1, window, cx);

        shell.apply_cache_restore_updates(
            vec![super::cache_restore::CacheHydrationUpdate {
                row_id: 1,
                observe_snapshot: Some(observe_snapshot),
                observe_access: None,
                audit_snapshot: Some(audit_snapshot),
                audit_access: None,
            }],
            &shell.audit_plan_fingerprint.clone(),
            window,
            cx,
        );

        assert!(shell.cache_restore_refresh_state.pending_full_refresh);
        assert_eq!(
            shell.cache_restore_refresh_state.pending_completion_count,
            1
        );
        assert!(
            shell
                .cache_restore_refresh_state
                .pending_visible_row_ids
                .contains(&1)
        );
        assert!(shell.rows[0].paths_report.is_some());
        assert!(shell.rows[0].audit_report.is_some());
    });
}

#[gpui::test]
fn enabling_analysis_cache_schedules_sweep(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.analysis_cache_enabled = false;

        shell.set_analysis_cache_enabled_preference(true, window, cx);

        assert!(shell.state.analysis_cache_enabled);
        assert!(shell.cache_maintenance_state.pending_sweep);
        assert!(shell.cache_maintenance_state.debounce_pending);
    });
}

#[gpui::test]
fn purge_analysis_cache_removes_cache_directories(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        let legacy_root = default_analysis_cache_root();
        fs::create_dir_all(shell.observe_cache_root.join("aa/bb")).expect("create observe cache");
        fs::create_dir_all(shell.audit_cache_root.join("cc/dd")).expect("create audit cache");
        fs::write(shell.observe_cache_root.join("aa/bb/index.json"), "{}").expect("write observe");
        fs::write(shell.audit_cache_root.join("cc/dd/index.json"), "{}").expect("write audit");
        fs::create_dir_all(legacy_root.join("observe-v2/ee/ff")).expect("create observe v2 cache");
        fs::create_dir_all(legacy_root.join("audit-v2/gg/hh")).expect("create audit v2 cache");
        fs::write(legacy_root.join("observe-v2/ee/ff/index.json"), "{}").expect("write observe v2");
        fs::write(legacy_root.join("audit-v2/gg/hh/index.json"), "{}").expect("write audit v2");
        fs::create_dir_all(legacy_root.join("observe-v3/ii/jj")).expect("create observe v3 cache");
        fs::create_dir_all(legacy_root.join("audit-v3/kk/ll")).expect("create audit v3 cache");
        fs::write(legacy_root.join("observe-v3/ii/jj/index.json"), "{}").expect("write observe v3");
        fs::write(legacy_root.join("audit-v3/kk/ll/index.json"), "{}").expect("write audit v3");

        shell.on_menu_purge_analysis_cache(&MenuPurgeAnalysisCache, window, cx);
    });
    visual_cx.run_until_parked();
    visual_cx.simulate_prompt_answer("Purge cache");
    visual_cx.run_until_parked();
    visual_cx
        .executor()
        .advance_clock(Duration::from_millis(50));
    visual_cx.run_until_parked();

    shell.update_in(visual_cx, |shell, _window, _cx| {
        assert!(!shell.observe_cache_root.exists());
        assert!(!shell.audit_cache_root.exists());
        assert!(!default_analysis_cache_root().join("observe-v2").exists());
        assert!(!default_analysis_cache_root().join("audit-v2").exists());
        assert!(!default_analysis_cache_root().join("observe-v3").exists());
        assert!(!default_analysis_cache_root().join("audit-v3").exists());
        assert!(matches!(
            shell.status_message,
            Some(BannerMessage::CachePurged)
        ));
    });
}

#[gpui::test]
fn cancel_purge_analysis_cache_keeps_cache_directories(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        fs::create_dir_all(shell.observe_cache_root.join("aa/bb")).expect("create observe cache");
        fs::create_dir_all(shell.audit_cache_root.join("cc/dd")).expect("create audit cache");

        shell.on_menu_purge_analysis_cache(&MenuPurgeAnalysisCache, window, cx);
    });
    visual_cx.run_until_parked();
    visual_cx.simulate_prompt_answer("Cancel");
    visual_cx.run_until_parked();

    shell.update_in(visual_cx, |shell, _window, _cx| {
        assert!(shell.observe_cache_root.exists());
        assert!(shell.audit_cache_root.exists());
        assert!(!matches!(
            shell.status_message,
            Some(BannerMessage::CachePurged)
        ));
    });
}

#[gpui::test]
fn settings_menu_updates_auto_analyze_parallelism_preference(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.auto_analyze_parallelism = AutoAnalyzeParallelismPreference::Four;
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
            .update(cx, |input, cx| input.set_value("256 MB", window, cx));

        assert!(shell.max_bytes_dialog_can_apply(cx));
        shell.apply_max_bytes_dialog(window, cx);

        assert!(shell.max_bytes_dialog.is_none());
        assert_eq!(shell.state.max_bytes, Some(256 * 1024 * 1024));
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

#[gpui::test]
fn max_bytes_dialog_plain_number_defaults_to_mb(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.open_max_bytes_dialog(window, cx);
        let dialog = shell.max_bytes_dialog.as_ref().expect("max bytes dialog");
        dialog
            .input
            .update(cx, |input, cx| input.set_value("256", window, cx));

        assert!(shell.max_bytes_dialog_can_apply(cx));
        shell.apply_max_bytes_dialog(window, cx);

        assert_eq!(shell.state.max_bytes, Some(256 * 1024 * 1024));
    });
}

#[gpui::test]
fn max_bytes_dialog_reopens_with_humanized_exact_unit_value(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.max_bytes = Some(256 * 1024 * 1024);
        shell.open_max_bytes_dialog(window, cx);

        let dialog = shell.max_bytes_dialog.as_ref().expect("max bytes dialog");
        assert_eq!(dialog.input.read(cx).value(), "256 MB");
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
        &build_script_audit_plan(vec![], 64).expect("plan"),
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
        &build_script_audit_plan(vec![], 64).expect("plan"),
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
        &build_script_audit_plan(vec![], 64).expect("plan"),
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
fn analyze_row_with_options_returns_mb_reports_without_semantic_validation() {
    let scene = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/02/sphere.mb");

    let result = analyze_row_with_options(
        &scene,
        AuditModePreference::StrictDefault,
        &LoadOptions::default(),
        &build_script_audit_plan(vec![], 64).expect("plan"),
    )
    .expect("analyze");

    let RowJobResult::Analyze(result) = result else {
        panic!("expected analyze result");
    };
    assert_eq!(
        result.audit_report.validation_state,
        ValidationState::Partial
    );
    assert!(result.paths_report.is_some());
    assert!(result.dump_report.is_some());
    assert!(result.observe_snapshot.is_some());
    assert!(result.audit_snapshot.is_some());
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
        &build_script_audit_plan(vec![], 64).expect("plan"),
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

#[test]
fn analyze_row_with_options_reports_ma_render_globals_callbacks() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("render-callbacks.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "select -ne :defaultRenderGlobals;\n",
            "    setAttr \".poam\" -type \"string\" \"eval(\\\"ExampleCallback;\\\")\";\n",
            "    setAttr \".prlm\" -type \"string\" \"python(\\\"print(\\\\\\\"Example\\\\\\\")\\\")\";\n",
        ),
    )
    .expect("write scene");

    let RowJobResult::Analyze(result) = analyze_row_with_options(
        &scene,
        AuditModePreference::StrictDefault,
        &LoadOptions::default(),
        &build_script_audit_plan(vec![], 64).expect("plan"),
    )
    .expect("analyze") else {
        panic!("expected analyze result");
    };

    assert!(result.audit_report.surfaces.iter().any(|surface| {
        surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
            && surface.origin.node_name.as_deref() == Some("defaultRenderGlobals")
            && surface.origin.attr_name.as_deref() == Some(".poam")
    }));
    assert!(!result.audit_report.findings.is_empty());
}

#[test]
fn analyze_row_bytes_with_options_reports_ma_render_globals_callbacks() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("staged-render-callbacks.ma");
    let bytes = concat!(
        "//Maya ASCII 2026 scene\n",
        "select -ne :defaultRenderGlobals;\n",
        "    setAttr \".poam\" -type \"string\" \"eval(\\\"ExampleCallback;\\\")\";\n",
    )
    .as_bytes()
    .to_vec();
    fs::write(&scene, &bytes).expect("write source placeholder");

    let result = analyze_row_bytes_with_options(
        &scene,
        SceneFormat::Ma,
        ValidationState::Validated,
        bytes,
        AuditModePreference::StrictDefault,
        &LoadOptions::default(),
        &build_script_audit_plan(vec![], 64).expect("plan"),
    )
    .expect("analyze bytes");

    assert!(result.audit_report.surfaces.iter().any(|surface| {
        surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
            && surface.origin.node_name.as_deref() == Some("defaultRenderGlobals")
            && surface.origin.attr_name.as_deref() == Some(".poam")
    }));
    assert!(!result.audit_report.findings.is_empty());
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
        row.set_audit_report(
            Some(build_parse_budget_blocked_audit_report(
                scene.clone(),
                SceneFormat::Ma,
                ValidationState::Invalid,
                &plan,
                AuditOptions::strict_default(),
                maya_scene_kit_observe::scene::MelParseBudgetLimit::MaxBytes,
                None,
            )),
            None,
        );
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
        row.set_audit_report(
            Some(build_parse_budget_blocked_audit_report(
                scene.clone(),
                SceneFormat::Ma,
                ValidationState::Invalid,
                &plan,
                AuditOptions::strict_default(),
                maya_scene_kit_observe::scene::MelParseBudgetLimit::MaxBytes,
                None,
            )),
            None,
        );
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

#[test]
fn build_app_menus_removes_select_menu() {
    let menus = build_app_menus(
        &PersistedState::default(),
        &I18n::new(SupportedLocale::English),
        false,
        false,
    )
    .into_iter()
    .map(|menu| menu.owned())
    .collect::<Vec<_>>();

    assert!(
        menus.iter().all(|menu| menu.name.as_ref() != "Select"),
        "top-level Select menu should be removed",
    );
}

#[test]
fn build_app_menus_adds_exit_application_to_end_of_file_menu() {
    let menus = build_app_menus(
        &PersistedState::default(),
        &I18n::new(SupportedLocale::English),
        false,
        false,
    )
    .into_iter()
    .map(|menu| menu.owned())
    .collect::<Vec<_>>();
    let file_menu = menus
        .into_iter()
        .find(|menu| menu.name.as_ref() == "File")
        .expect("file menu");

    assert_eq!(
        menu_action_names(&file_menu.items),
        vec![
            "Select Folder".to_string(),
            "Save Selected".to_string(),
            "Save All".to_string(),
            "Exit Application".to_string(),
        ]
    );
    assert!(matches!(
        file_menu.items.last(),
        Some(OwnedMenuItem::Action { name, .. }) if name == "Exit Application"
    ));
}

#[test]
fn build_app_menus_adds_delete_ui_configuration_script_node_to_edit_menu() {
    let menus = build_app_menus(
        &PersistedState::default(),
        &I18n::new(SupportedLocale::English),
        false,
        false,
    )
    .into_iter()
    .map(|menu| menu.owned())
    .collect::<Vec<_>>();
    let edit_menu = menus
        .into_iter()
        .find(|menu| menu.name.as_ref() == "Edit")
        .expect("edit menu");

    assert!(
        menu_action_names(&edit_menu.items)
            .contains(&"Delete uiConfigurationScriptNode".to_string())
    );
}

#[test]
fn exit_warning_required_is_false_for_clean_rows() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("clean_exit_state.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let row = test_row(1, &path);

    assert!(!exit_warning_required_for_rows(&[row]));
}

#[test]
fn exit_warning_required_is_true_for_replace_rows() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("replace_exit_state.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let mut row = test_row(1, &path);
    row.dirty_kind = Some(DirtyKind::Replace);
    row.path_overrides
        .insert(0, "asset/example/edited.fbx".to_string());

    assert!(exit_warning_required_for_rows(&[row]));
}

#[test]
fn exit_warning_required_is_true_for_scene_edit_rows() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("scene_edit_exit_state.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let mut row = test_row(1, &path);
    row.dirty_kind = Some(DirtyKind::SceneEdits);
    row.dirty_artifact = Some(StagedSceneArtifact {
        input_path: path.clone(),
        suggested_output_path: path.clone(),
        scene_format: SceneFormat::Ma,
        operation_mode: OperationMode::Forensic,
        validation_state: ValidationState::Validated,
        bytes: b"// staged edit".to_vec(),
    });

    assert!(exit_warning_required_for_rows(&[row]));
}

#[test]
fn exit_warning_required_is_true_for_to_ascii_rows() {
    let dir = tempdir().expect("tmpdir");
    let source_path = dir.path().join("to_ascii_exit_state.mb");
    let output_path = dir.path().join("to_ascii_exit_state.ma");
    fs::write(&source_path, "FORM").expect("write scene");
    let mut row = test_row(1, &source_path);
    row.dirty_kind = Some(DirtyKind::ToAscii);
    row.dirty_artifact = Some(StagedSceneArtifact {
        input_path: source_path.clone(),
        suggested_output_path: output_path,
        scene_format: SceneFormat::Ma,
        operation_mode: OperationMode::Forensic,
        validation_state: ValidationState::Validated,
        bytes: b"// ascii".to_vec(),
    });

    assert!(exit_warning_required_for_rows(&[row]));
}

#[test]
fn exit_warning_required_is_true_for_path_override_rows() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("path_override_exit_state.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let mut row = test_row(1, &path);
    row.path_overrides
        .insert(1, "asset/example/override.fbx".to_string());

    assert!(exit_warning_required_for_rows(&[row]));
}

#[test]
fn exit_warning_required_is_true_for_pending_clean_rows() {
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("pending_clean_exit_state.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");
    let mut row = test_row(1, &path);
    row.pending_clean_targets = BTreeSet::from([ExecutionCleanTarget::ScriptNode {
        node_name: "Example".to_string(),
    }]);

    assert!(exit_warning_required_for_rows(&[row]));
}

#[gpui::test]
fn exit_application_closes_immediately_when_no_dirty_rows(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.on_menu_exit_application(&super::MenuExitApplication, window, cx);
    });
    visual_cx.run_until_parked();

    assert_eq!(visual_cx.windows().len(), 0);
}

#[gpui::test]
fn exit_application_cancel_keeps_window_open_when_dirty(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("dirty_cancel_exit.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");

    shell.update_in(visual_cx, |shell, window, cx| {
        let mut row = test_row(1, &path);
        row.path_overrides
            .insert(0, "asset/example/edited.fbx".to_string());
        shell.rows = vec![row];
        shell.on_menu_exit_application(&super::MenuExitApplication, window, cx);
    });
    visual_cx.run_until_parked();

    assert!(visual_cx.has_pending_prompt());
    assert_eq!(
        visual_cx.pending_prompt(),
        Some((
            "Exit Application".to_string(),
            "There are unsaved edits. Discard them and exit the application?".to_string(),
        ))
    );

    visual_cx.simulate_prompt_answer("Return to Application");
    visual_cx.run_until_parked();

    assert_eq!(visual_cx.windows().len(), 1);
}

#[gpui::test]
fn exit_application_discard_closes_window_when_dirty(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("dirty_discard_exit.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");

    shell.update_in(visual_cx, |shell, window, cx| {
        let mut row = test_row(1, &path);
        row.pending_clean_targets = BTreeSet::from([ExecutionCleanTarget::ScriptNode {
            node_name: "Example".to_string(),
        }]);
        shell.rows = vec![row];
        shell.on_menu_exit_application(&super::MenuExitApplication, window, cx);
    });
    visual_cx.run_until_parked();

    visual_cx.simulate_prompt_answer("Discard Edits and Exit");
    visual_cx.run_until_parked();

    assert_eq!(visual_cx.windows().len(), 0);
}

#[gpui::test]
fn window_close_cancel_keeps_window_open_when_dirty(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("dirty_close_cancel.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");

    shell.update_in(visual_cx, |shell, _window, _cx| {
        let mut row = test_row(1, &path);
        row.pending_clean_targets = BTreeSet::from([ExecutionCleanTarget::ScriptNode {
            node_name: "Example".to_string(),
        }]);
        shell.rows = vec![row];
    });
    visual_cx.run_until_parked();

    assert!(!visual_cx.simulate_close());
    visual_cx.run_until_parked();
    assert!(visual_cx.has_pending_prompt());

    visual_cx.simulate_prompt_answer("Return to Application");
    visual_cx.run_until_parked();

    assert_eq!(visual_cx.windows().len(), 1);
}

#[gpui::test]
fn window_close_discard_closes_window_when_dirty(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("dirty_close_discard.ma");
    fs::write(&path, "//Maya ASCII 2026 scene\n").expect("write scene");

    shell.update_in(visual_cx, |shell, _window, _cx| {
        let mut row = test_row(1, &path);
        row.dirty_artifact = Some(StagedSceneArtifact {
            input_path: path.clone(),
            suggested_output_path: path.clone(),
            scene_format: SceneFormat::Ma,
            operation_mode: OperationMode::Forensic,
            validation_state: ValidationState::Validated,
            bytes: b"// staged edit".to_vec(),
        });
        row.dirty_kind = Some(DirtyKind::SceneEdits);
        shell.rows = vec![row];
    });
    visual_cx.run_until_parked();

    assert!(!visual_cx.simulate_close());
    visual_cx.run_until_parked();
    visual_cx.simulate_prompt_answer("Discard Edits and Exit");
    visual_cx.run_until_parked();

    assert_eq!(visual_cx.windows().len(), 0);
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
fn workspace_auto_analysis_suppresses_low_priority_during_cache_restore(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let paths: Vec<PathBuf> = (0..3)
        .map(|ix| dir.path().join(format!("sample_scene_{ix:02}.ma")))
        .collect();
    for path in &paths {
        fs::write(path, "//Maya ASCII 2026 scene\n").expect("write scene");
    }

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(dir.path(), "");
        shell.state.workspace_auto_analyze = true;
        shell.state.auto_analyze_parallelism = AutoAnalyzeParallelismPreference::Four;
        shell.rows = paths
            .iter()
            .enumerate()
            .map(|(ix, path)| test_row(ix as u64 + 1, path))
            .collect();
        shell.refresh_file_table(cx);
        shell.cache_restore_state.pending = VecDeque::from([99]);

        shell.update_file_table_viewport_range(0..1, window, cx);
        shell.run_workspace_auto_analysis(window, cx);

        assert_eq!(shell.auto_analyze_queue.in_flight_len(), 1);
        assert_eq!(shell.auto_analyze_queue.pending_viewport.len(), 0);
        assert_eq!(shell.auto_analyze_queue.pending_low.len(), 2);
        assert_eq!(
            shell
                .rows
                .iter()
                .filter(|row| row.status == FileStatus::Processing(RowOperation::Analyze))
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            vec![1]
        );
    });
}

#[gpui::test]
fn selected_auto_analysis_still_dispatches_during_cache_restore(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let paths: Vec<PathBuf> = (0..3)
        .map(|ix| dir.path().join(format!("sample_click_scene_{ix:02}.ma")))
        .collect();
    for path in &paths {
        fs::write(path, "//Maya ASCII 2026 scene\n").expect("write scene");
    }

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(dir.path(), "");
        shell.state.workspace_auto_analyze = true;
        shell.state.auto_analyze_parallelism = AutoAnalyzeParallelismPreference::Four;
        shell.rows = paths
            .iter()
            .enumerate()
            .map(|(ix, path)| test_row(ix as u64 + 1, path))
            .collect();
        shell.refresh_file_table(cx);
        shell.cache_restore_state.pending = VecDeque::from([77]);

        shell.update_file_table_viewport_range(0..0, window, cx);
        shell.run_workspace_auto_analysis(window, cx);
        assert_eq!(shell.auto_analyze_queue.in_flight_len(), 0);

        shell.select_row_by_id(2, Modifiers::default(), window, cx);
        shell.run_selected_auto_analysis(window, cx);

        assert_eq!(shell.auto_analyze_queue.in_flight_len(), 1);
        assert_eq!(shell.auto_analyze_queue.pending_low.len(), 2);
        assert!(matches!(
            shell.rows[1].status,
            FileStatus::Processing(RowOperation::Analyze)
        ));
    });
}

#[gpui::test]
fn cache_restore_finish_resumes_deferred_workspace_auto_analysis(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let paths: Vec<PathBuf> = (0..3)
        .map(|ix| dir.path().join(format!("sample_resume_scene_{ix:02}.ma")))
        .collect();
    for path in &paths {
        fs::write(path, "//Maya ASCII 2026 scene\n").expect("write scene");
    }

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(dir.path(), "");
        shell.state.workspace_auto_analyze = true;
        shell.state.auto_analyze_parallelism = AutoAnalyzeParallelismPreference::Four;
        shell.rows = paths
            .iter()
            .enumerate()
            .map(|(ix, path)| test_row(ix as u64 + 1, path))
            .collect();
        shell.refresh_file_table(cx);
        shell.cache_restore_state.pending = VecDeque::from([55]);

        shell.update_file_table_viewport_range(0..1, window, cx);
        shell.run_workspace_auto_analysis(window, cx);
        assert_eq!(shell.auto_analyze_queue.in_flight_len(), 1);
        assert_eq!(shell.auto_analyze_queue.pending_low.len(), 2);

        shell.finish_progressive_cache_restore(window, cx);

        assert!(!shell.cache_restore_active());
        assert_eq!(shell.auto_analyze_queue.in_flight_len(), 3);
        assert_eq!(shell.auto_analyze_queue.pending_low.len(), 0);
    });
}

#[gpui::test]
fn analyze_result_queues_debounced_refresh_and_persist(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("queued_analyze.ma");
    write_cached_scene(&scene);
    let analyze_result =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze result");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            shell.state = test_state(dir.path(), "");
            shell.rows = vec![test_row(1, &scene)];
            shell.refresh_file_table(cx);

            shell.apply_job_result(1, RowOperation::Analyze, analyze_result, None, window, cx);

            assert!(shell.auto_analyze_refresh_state.pending_full_refresh);
            assert_eq!(shell.auto_analyze_refresh_state.pending_completion_count, 1);
            assert!(shell.persist_flush_state.dirty);
            assert!(!shell.persist_flush_state.workspace_paths_dirty);
            assert_eq!(shell.state.job_history.len(), 1);
            assert_eq!(shell.state.job_history[0].operation, "analyze");
        });
    });
}

#[gpui::test]
fn analyze_result_invalidates_path_resolution_state_for_async_refresh(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("async_path_refresh.ma");
    write_cached_scene(&scene);
    let analyze_result =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze result");
    let load_options = LoadOptions::default();
    let observation = Loader::new(load_options.clone())
        .observe_path(&scene)
        .expect("observe scene");
    let observe_snapshot = ObservedSceneSnapshot::from_observation(&observation, &load_options)
        .expect("observe snapshot");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            shell.state = test_state(dir.path(), "");
            let mut row = test_row(1, &scene);
            row.paths_report = Some(observe_snapshot.paths_report.clone());
            row.dump_report = Some(observe_snapshot.dump_report.clone());
            row.refresh_scene_workspace_root();
            row.refresh_path_resolution_cache();
            let prior_revision = row.path_resolution_revision;
            assert!(!row.path_resolution_cache.is_empty());
            shell.rows = vec![row];
            shell.refresh_file_table(cx);

            shell.apply_job_result(1, RowOperation::Analyze, analyze_result, None, window, cx);

            assert!(shell.rows[0].path_resolution_cache.is_empty());
            assert_eq!(shell.rows[0].missing_path_count(), None);
            assert!(shell.rows[0].path_resolution_revision > prior_revision);
        });
    });
}

#[test]
fn path_table_model_uses_cached_only_resolution_for_passive_render() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("cached_only_paths.ma");
    write_cached_scene(&scene);
    let load_options = LoadOptions::default();
    let observation = Loader::new(load_options.clone())
        .observe_path(&scene)
        .expect("observe scene");
    let observe_snapshot = ObservedSceneSnapshot::from_observation(&observation, &load_options)
        .expect("observe snapshot");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(observe_snapshot.paths_report);
    row.dump_report = Some(observe_snapshot.dump_report);
    row.invalidate_path_resolution_state();

    let model = build_path_table_model(
        &[row],
        &[0],
        &test_state(dir.path(), ""),
        None,
        &BTreeSet::new(),
        false,
        "",
        &BTreeSet::from([PathTypeFilter::File, PathTypeFilter::Reference]),
        &BTreeSet::from([PathFormFilter::Abs, PathFormFilter::Rel]),
        &BTreeSet::from([
            PathResolutionBadge::Exists,
            PathResolutionBadge::Missing,
            PathResolutionBadge::Unresolved,
        ]),
        default_path_sort(),
    );

    assert!(!model.rows.is_empty());
    assert!(model.rows.iter().all(|row| row.resolution_badge.is_none()));
}

#[gpui::test]
fn analyze_result_backlog_resolves_noninteractive_missing_counts(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    let scene = workspace.join("backlog_missing.ma");
    fs::write(
        &scene,
        r#"//Maya ASCII 2026 scene
createNode file -n "file1";
    setAttr ".ftn" -type "string" "textures/missing.tx";
"#,
    )
    .expect("write scene");

    let analyze_result =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze result");

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(workspace.as_path(), "excluded");
        shell.rows = vec![test_row(1, &scene)];
        shell.refresh_file_table(cx);
        shell.update_file_table_viewport_range(0..0, window, cx);
        assert!(shell.visible_rows.is_empty());

        shell.apply_job_result(1, RowOperation::Analyze, analyze_result, None, window, cx);

        assert!(shell.rows[0].display_paths_report().is_some());
        assert!(
            shell
                .path_resolution_refresh_state
                .pending_backlog_row_ids
                .contains(&1)
        );
        assert_eq!(shell.rows[0].missing_path_count(), None);
    });

    visual_cx.run_until_parked();
    visual_cx
        .executor()
        .advance_clock(Duration::from_millis(50));
    visual_cx.run_until_parked();

    shell.update_in(visual_cx, |shell, _window, _cx| {
        assert_eq!(shell.rows[0].missing_path_count(), Some(1));
        assert_eq!(shell.rows[0].path_resolution_cache.len(), 1);
        assert!(
            shell
                .path_resolution_refresh_state
                .pending_backlog_row_ids
                .is_empty()
        );
    });
}

#[gpui::test]
fn auto_analyze_completion_does_not_force_threshold_full_refresh(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("steady_refresh.ma");
    write_cached_scene(&scene);

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state = test_state(dir.path(), "");
        shell.rows = vec![test_row(1, &scene)];
        shell.refresh_file_table(cx);
        shell.update_file_table_viewport_range(0..1, window, cx);
        shell.auto_analyze_refresh_state.pending_completion_count = 63;
        shell.auto_analyze_refresh_state.pending_full_refresh = true;

        shell.queue_auto_analyze_completion_refresh(1, window, cx);

        assert!(shell.auto_analyze_refresh_state.pending_full_refresh);
        assert_eq!(
            shell.auto_analyze_refresh_state.pending_completion_count,
            64
        );
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
        assert!(shell.workspace_scan_active());
        assert!(shell.rows.is_empty());
    });
    visual_cx.run_until_parked();

    shell.update_in(visual_cx, |shell, window, cx| {
        assert_eq!(shell.rows.len(), 2);

        shell.open_ignore_folder_names_dialog(window, cx);
        shell
            .ignore_folder_names_dialog
            .as_mut()
            .expect("ignore dialog state")
            .draft_names
            .push("cache".to_string());

        shell.apply_ignore_folder_names_dialog(window, cx);
        assert!(shell.workspace_scan_active());
    });
    visual_cx.run_until_parked();

    shell.update_in(visual_cx, |shell, _, _| {
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
fn workspace_row_id_lookup_map_tracks_reload_and_clear(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("first.ma");
    let second = dir.path().join("second.mb");
    fs::write(&first, "").expect("write first");
    fs::write(&second, "").expect("write second");
    let mut first_row_id = 0;
    let mut second_row_id = 0;

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.set_workspace_folder(dir.path().to_path_buf(), window, cx);
        assert!(shell.workspace_scan_active());
    });
    visual_cx.run_until_parked();

    shell.update_in(visual_cx, |shell, window, cx| {
        first_row_id = shell
            .rows
            .iter()
            .find(|row| row.path == first)
            .map(|row| row.id)
            .expect("first row id");
        second_row_id = shell
            .rows
            .iter()
            .find(|row| row.path == second)
            .map(|row| row.id)
            .expect("second row id");
        let first_index = shell
            .rows
            .iter()
            .position(|row| row.id == first_row_id)
            .expect("first row index");
        let second_index = shell
            .rows
            .iter()
            .position(|row| row.id == second_row_id)
            .expect("second row index");

        assert_eq!(shell.index_of_row_id(first_row_id), Some(first_index));
        assert_eq!(shell.index_of_row_id(second_row_id), Some(second_index));

        fs::remove_file(&first).expect("remove first");
        shell.rescan_workspace_with_current_settings(window, cx);
        assert!(shell.workspace_scan_active());
    });
    visual_cx.run_until_parked();

    shell.update_in(visual_cx, |shell, window, cx| {
        assert_eq!(shell.rows.len(), 1);
        assert_eq!(shell.index_of_row_id(first_row_id), None);
        assert_eq!(shell.index_of_row_id(second_row_id), Some(0));

        shell.clear_workspace(window, cx);

        assert_eq!(shell.index_of_row_id(second_row_id), None);
    });
}

#[gpui::test]
fn workspace_scan_keeps_menu_state_changes_responsive(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(&scene, "").expect("write scene");

    shell.update_in(visual_cx, |shell, window, cx| {
        shell.set_workspace_folder(dir.path().to_path_buf(), window, cx);
        assert!(shell.workspace_scan_active());

        shell.set_locale_preference(LocalePreference::Japanese, window, cx);

        assert_eq!(shell.state.locale, LocalePreference::Japanese);
        assert!(shell.workspace_scan_active());
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(!shell.workspace_scan_active());
        assert_eq!(shell.rows.len(), 1);
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
fn build_file_operation_paths_uses_all_selected_rows_when_target_is_selected() {
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

    let paths = build_file_operation_paths(&[first_row, second_row, third_row], 2)
        .expect("operation paths");

    assert_eq!(paths, vec![first, second]);
}

#[test]
fn build_file_operation_paths_falls_back_to_target_row_when_not_selected() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("first.ma");
    let second = dir.path().join("second.ma");
    fs::write(&first, "").expect("write first");
    fs::write(&second, "").expect("write second");

    let mut first_row = test_row(1, &first);
    first_row.selected = true;
    let second_row = test_row(2, &second);

    let paths = build_file_operation_paths(&[first_row, second_row], 2).expect("operation paths");

    assert_eq!(paths, vec![second]);
}

#[test]
fn plugin_registry_loads_enabled_actions_for_matching_scope() {
    let dir = tempdir().expect("tmpdir");
    let plugins_dir = dir.path().join("plugins");
    fs::create_dir(&plugins_dir).expect("create plugins dir");
    fs::write(
        plugins_dir.join("sample.json"),
        r#"{
  "actions": [
    {
      "id": "example.file",
      "label": "Example File Action",
      "scopes": ["file_list"],
      "command": "example-command",
      "args": ["--mode", "file"]
    },
    {
      "id": "example.disabled",
      "label": "Disabled Action",
      "enabled": false,
      "scopes": ["file_list"],
      "command": "disabled-command"
    },
    {
      "id": "example.detail",
      "label": "Example Detail Action",
      "scopes": ["detail"],
      "command": "detail-command"
    }
  ]
}"#,
    )
    .expect("write plugin manifest");

    let registry = PluginRegistry::load_from_dir(&plugins_dir);

    let file_actions = registry.actions_for_scope(PluginActionScope::FileList);
    assert_eq!(file_actions.len(), 1);
    assert_eq!(file_actions[0].id, "example.file");
    assert_eq!(file_actions[0].args, vec!["--mode", "file"]);

    let detail_actions = registry.actions_for_scope(PluginActionScope::Detail);
    assert_eq!(detail_actions.len(), 1);
    assert_eq!(detail_actions[0].id, "example.detail");
}

#[test]
fn file_plugin_context_uses_selected_rows_when_clicked_row_is_selected() {
    let dir = tempdir().expect("tmpdir");
    let first = dir.path().join("ExampleA.ma");
    let second = dir.path().join("ExampleB.ma");
    fs::write(&first, "").expect("write first");
    fs::write(&second, "").expect("write second");

    let mut first_row = test_row(1, &first);
    first_row.selected = true;
    let mut second_row = test_row(2, &second);
    second_row.selected = true;

    let payload = build_file_plugin_context(&[first_row, second_row], 2).expect("plugin context");
    let value = serde_json::to_value(&payload).expect("serialize payload");

    assert_eq!(value["scope"], "file_list");
    assert_eq!(value["selection_count"], 2);
    assert_eq!(value["items"][0]["row_id"], 1);
    assert_eq!(value["items"][1]["row_id"], 2);
    assert_eq!(value["items"][0]["path"], first.display().to_string());
    assert_eq!(value["items"][1]["path"], second.display().to_string());
}

#[test]
fn audit_plugin_context_serializes_detail_rows() {
    let first = test_audit_row(
        1,
        0,
        "ExampleA.ma",
        "Example finding",
        &["Example evidence"],
    );
    let second = test_audit_row(
        2,
        0,
        "ExampleB.ma",
        "Another finding",
        &["Another evidence"],
    );
    let display_rows = display_audit_rows(vec![first, second]);

    let payload =
        build_audit_plugin_context(&display_rows, &display_rows[0].key).expect("plugin context");
    let value = serde_json::to_value(&payload).expect("serialize payload");

    assert_eq!(value["scope"], "detail");
    assert_eq!(value["selection_count"], 1);
    assert_eq!(value["items"][0]["scene_name"], "ExampleA.ma");
    assert_eq!(value["items"][0]["summary"], "Example finding");
    assert_eq!(value["items"][0]["evidence"][0], "Example evidence");
}

#[test]
#[cfg(unix)]
fn run_plugin_action_writes_context_to_command_stdin() {
    let dir = tempdir().expect("tmpdir");
    let output = dir.path().join("plugin-output.json");
    let action = PluginRegistry::action_for_test(
        "example.capture",
        "Capture Context",
        PluginActionScope::FileList,
        "sh",
        vec![
            "-c".to_string(),
            "cat > \"$1\"".to_string(),
            "sh".to_string(),
            output.display().to_string(),
        ],
    );
    let payload = serde_json::json!({
        "scope": "file_list",
        "selection_count": 1,
        "items": [{"row_id": 1, "path": "asset/example/Example.ma"}]
    });

    run_plugin_action(&action, &payload).expect("run plugin action");

    let captured = fs::read_to_string(&output).expect("read captured payload");
    let captured: serde_json::Value = serde_json::from_str(&captured).expect("valid json");
    assert_eq!(captured["scope"], "file_list");
    assert_eq!(captured["items"][0]["path"], "asset/example/Example.ma");
}

#[test]
#[cfg(unix)]
fn spawn_plugin_action_does_not_wait_for_slow_stdin_reader() {
    let dir = tempdir().expect("tmpdir");
    let output = dir.path().join("plugin-byte-count.txt");
    let action = PluginRegistry::action_for_test(
        "example.slow-reader",
        "Slow Reader",
        PluginActionScope::FileList,
        "sh",
        vec![
            "-c".to_string(),
            "sleep 2; wc -c > \"$1\"".to_string(),
            "sh".to_string(),
            output.display().to_string(),
        ],
    );
    let payload = serde_json::json!({
        "scope": "file_list",
        "selection_count": 1,
        "items": [{
            "row_id": 1,
            "path": "asset/example/Example.ma",
            "padding": "x".repeat(8 * 1024 * 1024)
        }]
    });

    let started = Instant::now();
    spawn_plugin_action(&action, &payload).expect("spawn plugin action");
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "plugin launch should not wait for a slow stdin reader"
    );

    let deadline = Instant::now() + Duration::from_secs(6);
    while !output.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        output.exists(),
        "plugin should eventually consume the payload"
    );
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
fn file_context_clean_stages_finding_backed_script_node_targets(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("literal_context_clean.ma");
    write_literal_mel_python_scene(&scene);
    let RowJobResult::Analyze(result) =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.set_audit_report(Some(result.audit_report.clone()), result.audit_file_state);
            row.paths_report = result.paths_report.clone();
            row.dump_report = result.dump_report.clone();
            row.analyzed_audit_mode = Some(result.audit_mode);
            shell.rows = vec![row];
            shell.rebuild_row_id_index();

            shell.run_file_context_clean_from_row(1, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(
            shell.rows[0].pending_clean_targets.iter().any(|target| {
                matches!(
                    target,
                    ExecutionCleanTarget::ScriptNode { .. }
                        | ExecutionCleanTarget::MbOwnerForm { .. }
                )
            }),
            "file-list context clean should stage finding-backed script-node targets",
        );
    });
}

#[gpui::test]
fn main_menu_clean_matches_file_context_clean_targets(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("literal_clean_parity.ma");
    write_literal_mel_python_scene(&scene);
    let RowJobResult::Analyze(result) =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.set_audit_report(Some(result.audit_report.clone()), result.audit_file_state);
            row.paths_report = result.paths_report.clone();
            row.dump_report = result.dump_report.clone();
            row.analyzed_audit_mode = Some(result.audit_mode);
            shell.rows = vec![row];
            shell.rebuild_row_id_index();
            shell.run_clean(window, cx);
        });
    });
    visual_cx.run_until_parked();

    let (menu_targets, menu_dirty_kind, menu_findings) = visual_cx.update(|_, app| {
        let shell = shell.read(app);
        (
            shell.rows[0].pending_clean_targets.clone(),
            shell.rows[0].dirty_kind,
            shell.rows[0].findings,
        )
    });

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.set_audit_report(Some(result.audit_report.clone()), result.audit_file_state);
            row.paths_report = result.paths_report.clone();
            row.dump_report = result.dump_report.clone();
            row.analyzed_audit_mode = Some(result.audit_mode);
            shell.rows = vec![row];
            shell.rebuild_row_id_index();
            shell.undo_stack.clear();
            shell.redo_stack.clear();
            shell.run_file_context_clean_from_row(1, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(shell.rows[0].pending_clean_targets, menu_targets);
        assert_eq!(shell.rows[0].dirty_kind, menu_dirty_kind);
        assert_eq!(shell.rows[0].findings, menu_findings);
        assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::SceneEdits));
    });
}

#[gpui::test]
fn file_context_clean_from_unselected_row_is_noop(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("gate_a.ma");
    let scene_b = dir.path().join("gate_b.ma");
    write_literal_mel_python_scene(&scene_a);
    write_literal_mel_python_scene(&scene_b);
    let RowJobResult::Analyze(result_a) =
        analyze_row(&scene_a, AuditModePreference::StrictDefault).expect("analyze row a")
    else {
        panic!("expected analyze result");
    };
    let RowJobResult::Analyze(result_b) =
        analyze_row(&scene_b, AuditModePreference::StrictDefault).expect("analyze row b")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row_a = test_row(1, &scene_a);
            row_a.set_audit_report(
                Some(result_a.audit_report.clone()),
                result_a.audit_file_state,
            );
            let mut row_b = test_row(2, &scene_b);
            row_b.selected = true;
            row_b.set_audit_report(
                Some(result_b.audit_report.clone()),
                result_b.audit_file_state,
            );
            shell.rows = vec![row_a, row_b];
            shell.rebuild_row_id_index();
            shell.run_file_context_clean_from_row(1, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(
            shell
                .rows
                .iter()
                .all(|row| row.pending_clean_targets.is_empty())
        );
        assert!(shell.undo_stack.is_empty());
    });
}

#[gpui::test]
fn file_context_clean_from_replace_row_is_noop(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("replace_clean_noop.ma");
    write_literal_mel_python_scene(&scene);
    let RowJobResult::Analyze(result) =
        analyze_row(&scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.set_audit_report(Some(result.audit_report.clone()), result.audit_file_state);
            row.dirty_kind = Some(DirtyKind::Replace);
            row.path_overrides
                .insert(0, "asset/example/edited.fbx".to_string());
            shell.rows = vec![row];
            shell.rebuild_row_id_index();

            shell.run_file_context_clean_from_row(1, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(shell.rows[0].pending_clean_targets.is_empty());
        assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::Replace));
        assert!(shell.undo_stack.is_empty());
    });
}

#[gpui::test]
fn file_context_clean_skips_replace_rows_in_selected_group(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let eligible_scene = dir.path().join("eligible_group_clean.ma");
    let blocked_scene = dir.path().join("blocked_group_clean.ma");
    write_literal_mel_python_scene(&eligible_scene);
    write_literal_mel_python_scene(&blocked_scene);
    let RowJobResult::Analyze(result) =
        analyze_row(&eligible_scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut eligible_row = test_row(1, &eligible_scene);
            eligible_row.selected = true;
            eligible_row
                .set_audit_report(Some(result.audit_report.clone()), result.audit_file_state);
            eligible_row.paths_report = result.paths_report.clone();
            eligible_row.dump_report = result.dump_report.clone();
            eligible_row.analyzed_audit_mode = Some(result.audit_mode);

            let mut blocked_row = test_row(2, &blocked_scene);
            blocked_row.selected = true;
            blocked_row.dirty_kind = Some(DirtyKind::Replace);
            blocked_row
                .path_overrides
                .insert(0, "asset/example/edited.fbx".to_string());

            shell.rows = vec![eligible_row, blocked_row];
            shell.rebuild_row_id_index();
            shell.run_file_context_clean_from_row(1, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(!shell.rows[0].pending_clean_targets.is_empty());
        assert!(shell.rows[1].pending_clean_targets.is_empty());
        assert_eq!(shell.rows[1].dirty_kind, Some(DirtyKind::Replace));
    });
}

#[gpui::test]
fn file_context_delete_ui_configuration_script_node_from_replace_row_is_noop(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("replace_ui_config_noop.ma");
    write_ui_configuration_script_node_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.dirty_kind = Some(DirtyKind::Replace);
            row.path_overrides
                .insert(0, "asset/example/edited.fbx".to_string());
            shell.rows = vec![row];
            shell.rebuild_row_id_index();

            shell.run_file_context_delete_ui_configuration_script_node_from_row(1, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(shell.rows[0].pending_clean_targets.is_empty());
        assert_eq!(shell.rows[0].dirty_kind, Some(DirtyKind::Replace));
        assert!(shell.undo_stack.is_empty());
    });
}

#[gpui::test]
fn file_context_delete_ui_configuration_script_node_when_already_staged_is_noop(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("ui_config_already_staged_noop.ma");
    write_ui_configuration_script_node_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            row.pending_clean_targets = BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "uiConfigurationScriptNode".to_string(),
            }]);
            row.dirty_kind = Some(DirtyKind::SceneEdits);
            shell.rows = vec![row];
            shell.rebuild_row_id_index();

            shell.run_file_context_delete_ui_configuration_script_node_from_row(1, window, cx);
        });
    });

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.rows[0].pending_clean_targets,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "uiConfigurationScriptNode".to_string(),
            }])
        );
        assert!(shell.undo_stack.is_empty());
    });
}

#[gpui::test]
fn file_context_delete_ui_configuration_script_node_skips_non_matching_selected_rows(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let eligible_scene = dir.path().join("eligible_ui_config_group.ma");
    let blocked_scene = dir.path().join("blocked_ui_config_group.ma");
    write_ui_configuration_script_node_scene(&eligible_scene);
    fs::write(&blocked_scene, "//Maya ASCII 2026 scene\n").expect("write scene");
    let RowJobResult::Analyze(result) =
        analyze_row(&eligible_scene, AuditModePreference::StrictDefault).expect("analyze row")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut eligible_row = test_row(1, &eligible_scene);
            eligible_row.selected = true;
            eligible_row.dump_report = result.dump_report.clone();

            let mut blocked_row = test_row(2, &blocked_scene);
            blocked_row.selected = true;

            shell.rows = vec![eligible_row, blocked_row];
            shell.rebuild_row_id_index();
            shell.run_file_context_delete_ui_configuration_script_node_from_row(1, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.rows[0].pending_clean_targets,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "uiConfigurationScriptNode".to_string(),
            }])
        );
        assert!(shell.rows[1].pending_clean_targets.is_empty());
    });
}

#[gpui::test]
fn file_context_undo_from_unselected_row_is_noop(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("undo_gate_a.ma");
    let scene_b = dir.path().join("undo_gate_b.ma");
    fs::write(&scene_a, "//Maya ASCII 2026 scene\n").expect("write scene a");
    fs::write(&scene_b, "//Maya ASCII 2026 scene\n").expect("write scene b");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row_a = test_row(1, &scene_a);
            row_a.dirty_artifact = Some(maya_scene_kit_edit::scene::StagedSceneArtifact {
                input_path: scene_a.clone(),
                suggested_output_path: scene_a.clone(),
                scene_format: SceneFormat::Ma,
                operation_mode: OperationMode::Forensic,
                validation_state: ValidationState::Validated,
                bytes: b"// staged a".to_vec(),
            });
            row_a.dirty_kind = Some(DirtyKind::SceneEdits);
            row_a.pending_clean_targets = BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleA".to_string(),
            }]);
            row_a.status = FileStatus::Dirty;

            let mut row_b = test_row(2, &scene_b);
            row_b.selected = true;
            row_b.dirty_artifact = Some(maya_scene_kit_edit::scene::StagedSceneArtifact {
                input_path: scene_b.clone(),
                suggested_output_path: scene_b.clone(),
                scene_format: SceneFormat::Ma,
                operation_mode: OperationMode::Forensic,
                validation_state: ValidationState::Validated,
                bytes: b"// staged b".to_vec(),
            });
            row_b.dirty_kind = Some(DirtyKind::SceneEdits);
            row_b.pending_clean_targets = BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleB".to_string(),
            }]);
            row_b.status = FileStatus::Dirty;

            shell.rows = vec![row_a, row_b];
            shell.rebuild_row_id_index();
            shell.undo_file_context_changes_from_row(1, window, cx);
            assert_eq!(
                shell.rows[0].pending_clean_targets,
                BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                    node_name: "ExampleA".to_string(),
                }])
            );
            assert_eq!(
                shell.rows[1].pending_clean_targets,
                BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                    node_name: "ExampleB".to_string(),
                }])
            );
            assert!(shell.undo_stack.is_empty());
        });
    });
}

#[gpui::test]
fn menu_delete_ui_configuration_script_node_stages_scene_edits(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("ui_configuration_menu_delete.ma");
    write_ui_configuration_script_node_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            shell.rows = vec![row];
            shell.rebuild_row_id_index();

            shell.run_delete_ui_configuration_script_node(window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        let row = &shell.rows[0];
        assert_eq!(
            row.pending_clean_targets,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "uiConfigurationScriptNode".to_string(),
            }])
        );
        assert_eq!(row.dirty_kind, Some(DirtyKind::SceneEdits));
        assert!(row.dirty_artifact.is_some());
        assert!(row.staged_audit_report.is_some());
        assert!(row.staged_paths_report.is_some());
        assert!(row.staged_dump_report.is_some());
    });
}

#[gpui::test]
fn file_context_delete_ui_configuration_script_node_from_unselected_row_targets_only_clicked_row(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("ui_config_context_a.ma");
    let scene_b = dir.path().join("ui_config_context_b.ma");
    write_ui_configuration_script_node_scene(&scene_a);
    write_ui_configuration_script_node_scene(&scene_b);
    let RowJobResult::Analyze(result_a) =
        analyze_row(&scene_a, AuditModePreference::StrictDefault).expect("analyze row a")
    else {
        panic!("expected analyze result");
    };
    let RowJobResult::Analyze(result_b) =
        analyze_row(&scene_b, AuditModePreference::StrictDefault).expect("analyze row b")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row_a = test_row(1, &scene_a);
            row_a.selected = true;
            row_a.dump_report = result_a.dump_report.clone();
            let mut row_b = test_row(2, &scene_b);
            row_b.dump_report = result_b.dump_report.clone();
            shell.rows = vec![row_a, row_b];
            shell.rebuild_row_id_index();

            shell.run_file_context_delete_ui_configuration_script_node_from_row(2, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(shell.rows[0].pending_clean_targets.is_empty());
        assert_eq!(
            shell.rows[1].pending_clean_targets,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "uiConfigurationScriptNode".to_string(),
            }])
        );
    });
}

#[gpui::test]
fn file_context_delete_ui_configuration_script_node_from_selected_row_targets_selected_rows(
    cx: &mut TestAppContext,
) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("ui_config_context_selected_a.ma");
    let scene_b = dir.path().join("ui_config_context_selected_b.ma");
    write_ui_configuration_script_node_scene(&scene_a);
    write_ui_configuration_script_node_scene(&scene_b);
    let RowJobResult::Analyze(result_a) =
        analyze_row(&scene_a, AuditModePreference::StrictDefault).expect("analyze row a")
    else {
        panic!("expected analyze result");
    };
    let RowJobResult::Analyze(result_b) =
        analyze_row(&scene_b, AuditModePreference::StrictDefault).expect("analyze row b")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row_a = test_row(1, &scene_a);
            row_a.selected = true;
            row_a.dump_report = result_a.dump_report.clone();
            let mut row_b = test_row(2, &scene_b);
            row_b.selected = true;
            row_b.dump_report = result_b.dump_report.clone();
            shell.rows = vec![row_a, row_b];
            shell.rebuild_row_id_index();

            shell.run_file_context_delete_ui_configuration_script_node_from_row(2, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        for row in &shell.rows {
            assert_eq!(
                row.pending_clean_targets,
                BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                    node_name: "uiConfigurationScriptNode".to_string(),
                }])
            );
            assert_eq!(row.dirty_kind, Some(DirtyKind::SceneEdits));
        }
    });
}

#[gpui::test]
fn file_context_delete_ui_configuration_script_node_skips_processing_rows(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene_a = dir.path().join("ui_config_processing_a.ma");
    let scene_b = dir.path().join("ui_config_processing_b.ma");
    write_ui_configuration_script_node_scene(&scene_a);
    write_ui_configuration_script_node_scene(&scene_b);
    let RowJobResult::Analyze(result_a) =
        analyze_row(&scene_a, AuditModePreference::StrictDefault).expect("analyze row a")
    else {
        panic!("expected analyze result");
    };
    let RowJobResult::Analyze(result_b) =
        analyze_row(&scene_b, AuditModePreference::StrictDefault).expect("analyze row b")
    else {
        panic!("expected analyze result");
    };

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row_a = test_row(1, &scene_a);
            row_a.selected = true;
            row_a.dump_report = result_a.dump_report.clone();
            let mut row_b = test_row(2, &scene_b);
            row_b.selected = true;
            row_b.dump_report = result_b.dump_report.clone();
            row_b.status = FileStatus::Processing(RowOperation::Analyze);
            shell.rows = vec![row_a, row_b];
            shell.rebuild_row_id_index();

            shell.run_file_context_delete_ui_configuration_script_node_from_row(1, window, cx);
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(
            shell.rows[0].pending_clean_targets,
            BTreeSet::from([ExecutionCleanTarget::ScriptNode {
                node_name: "uiConfigurationScriptNode".to_string(),
            }])
        );
        assert!(shell.rows[1].pending_clean_targets.is_empty());
    });
}

#[gpui::test]
fn menu_delete_ui_configuration_script_node_is_noop_during_workspace_scan(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("ui_config_scan_gate.ma");
    write_ui_configuration_script_node_scene(&scene);

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.selected = true;
            shell.rows = vec![row];
            shell.rebuild_row_id_index();
            shell.workspace_scan_state.in_flight = true;

            shell.on_menu_edit_delete_ui_configuration_script_node(
                &MenuEditDeleteUiConfigurationScriptNode,
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert!(shell.rows[0].pending_clean_targets.is_empty());
        assert!(shell.undo_stack.is_empty());
        assert!(shell.workspace_scan_active());
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
fn path_context_menu_state_enables_search_for_mixed_missing_selection() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    fs::write(workspace.join("sourceimages/exists.tx"), "tx").expect("write existing");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/exists.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/missing.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
    row.refresh_path_resolution_cache();

    let state = path_context_menu_state(&[row], &vec![(1, 0), (1, 1)]);

    assert!(state.can_search_missing_files);
    assert!(!state.show_disabled_search_missing_files);
}

#[test]
fn path_context_menu_state_disables_search_for_non_editable_missing_targets() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
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
    row.selected = true;
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
    row.pending_path_owner_delete_targets = BTreeSet::from([PathOwnerDeleteTarget {
        node_type: "file".to_string(),
        node_name: "file1".to_string(),
    }]);
    row.dirty_kind = Some(DirtyKind::SceneEdits);
    row.refresh_path_resolution_cache();

    let state = path_context_menu_state(&[row], &vec![(1, 0)]);

    assert!(!state.can_search_missing_files);
    assert!(state.show_disabled_search_missing_files);
}

#[test]
fn path_context_menu_state_disables_search_for_processing_missing_targets() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
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
    row.selected = true;
    row.status = FileStatus::Processing(RowOperation::Analyze);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
    row.refresh_path_resolution_cache();

    let state = path_context_menu_state(&[row], &vec![(1, 0)]);

    assert!(!state.can_search_missing_files);
    assert!(state.show_disabled_search_missing_files);
}

#[test]
fn path_context_menu_state_search_skips_processing_targets_when_editable_missing_exists() {
    let dir = tempdir().expect("tmpdir");
    let first_scene = dir.path().join("first.ma");
    let second_scene = dir.path().join("second.ma");
    let scene_body = concat!(
        "//Maya ASCII 2026 scene\n",
        "createNode file -n \"file1\";\n",
        "    setAttr \".ftn\" -type \"string\" \"sourceimages/missing.tx\";\n",
    );
    fs::write(&first_scene, scene_body).expect("write first scene");
    fs::write(&second_scene, scene_body).expect("write second scene");

    let mut first_row = test_row(1, &first_scene);
    first_row.selected = true;
    first_row.paths_report =
        Some(collect_scene_paths(&first_scene, PathKind::File).expect("paths"));
    first_row.refresh_path_resolution_cache();
    let mut second_row = test_row(2, &second_scene);
    second_row.selected = true;
    second_row.status = FileStatus::Processing(RowOperation::Analyze);
    second_row.paths_report =
        Some(collect_scene_paths(&second_scene, PathKind::File).expect("paths"));
    second_row.refresh_path_resolution_cache();

    let state = path_context_menu_state(&[first_row, second_row], &vec![(1, 0), (2, 0)]);

    assert!(state.can_search_missing_files);
    assert!(!state.show_disabled_search_missing_files);
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
fn missing_path_entry_file_name_extracts_basename_for_missing_entries() {
    let dir = tempdir().expect("tmpdir");
    let scene = dir.path().join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages\\\\nested\\\\missing.tx\";\n",
        ),
    )
    .expect("write scene");

    let mut row = test_row(1, &scene);
    row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
    row.refresh_path_resolution_cache();

    assert_eq!(
        missing_path_entry_file_name(&row, 0),
        Some("missing.tx".to_string())
    );
}

#[test]
fn find_missing_path_file_hits_uses_breadth_first_sorted_first_hit() {
    let dir = tempdir().expect("tmpdir");
    let root = dir.path();
    fs::create_dir_all(root.join("b_folder")).expect("mkdir b");
    fs::create_dir_all(root.join("a_folder/deeper")).expect("mkdir a");
    fs::write(root.join("b_folder/TestAsset.tx"), "b").expect("write b");
    fs::write(root.join("a_folder/TestAsset.tx"), "a").expect("write a");
    fs::write(root.join("a_folder/deeper/TestAsset.tx"), "deep").expect("write deep");

    let hits = find_missing_path_file_hits(
        root,
        &BTreeSet::from(["TestAsset.tx".to_string()]),
        &ignore_state(false, &[]),
    );

    assert_eq!(
        hits.get(&path_search_hit_key("TestAsset.tx")),
        Some(&root.join("a_folder/TestAsset.tx"))
    );
}

#[test]
fn find_missing_path_file_hits_skips_ignored_folders() {
    let dir = tempdir().expect("tmpdir");
    let root = dir.path();
    fs::create_dir_all(root.join("backup")).expect("mkdir backup");
    fs::create_dir_all(root.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(root.join("backup/Sample.tx"), "ignored").expect("write ignored");
    fs::write(root.join("sourceimages/Sample.tx"), "kept").expect("write kept");

    let hits = find_missing_path_file_hits(
        root,
        &BTreeSet::from(["Sample.tx".to_string()]),
        &ignore_state(true, &["backup"]),
    );

    assert_eq!(
        hits.get(&path_search_hit_key("Sample.tx")),
        Some(&root.join("sourceimages/Sample.tx"))
    );
}

#[test]
fn find_missing_path_file_hits_matches_case_insensitively_and_multiple_targets() {
    let dir = tempdir().expect("tmpdir");
    let root = dir.path();
    fs::create_dir_all(root.join("sourceimages")).expect("mkdir sourceimages");
    fs::write(root.join("sourceimages/sample_diffuse.TX"), "diffuse").expect("write diffuse");
    fs::write(root.join("sourceimages/Sample_Normal.tx"), "normal").expect("write normal");

    let hits = find_missing_path_file_hits(
        root,
        &BTreeSet::from([
            "SAMPLE_DIFFUSE.tx".to_string(),
            "sample_normal.TX".to_string(),
        ]),
        &ignore_state(false, &[]),
    );

    assert_eq!(
        hits.get(&path_search_hit_key("SAMPLE_DIFFUSE.tx")),
        Some(&root.join("sourceimages/sample_diffuse.TX"))
    );
    assert_eq!(
        hits.get(&path_search_hit_key("sample_normal.TX")),
        Some(&root.join("sourceimages/Sample_Normal.tx"))
    );
}

#[test]
fn find_missing_path_file_hits_returns_empty_for_no_hits() {
    let dir = tempdir().expect("tmpdir");
    fs::create_dir_all(dir.path().join("sourceimages")).expect("mkdir sourceimages");

    let hits = find_missing_path_file_hits(
        dir.path(),
        &BTreeSet::from(["Missing.tx".to_string()]),
        &ignore_state(false, &[]),
    );

    assert!(hits.is_empty());
}

#[test]
fn search_write_back_preserves_plain_relative_values_inside_workspace() {
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let found = workspace.join("sourceimages/Sample.tx");
    fs::create_dir_all(found.parent().expect("parent")).expect("mkdir sourceimages");
    fs::write(&found, "tx").expect("write found");

    assert_eq!(
        write_back_selected_scene_path(
            &found,
            Some(&workspace),
            ScenePathValueStyle::PlainRelative,
        ),
        "sourceimages/Sample.tx"
    );
}

#[gpui::test]
fn search_missing_path_write_back_preserves_entry_value_styles(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let recovered = workspace.join("recovered");
    let plain_hit = recovered.join("SamplePlain.tx");
    let double_slash_hit = recovered.join("SampleWorkspace.tx");
    fs::create_dir_all(&recovered).expect("mkdir recovered");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    fs::write(&plain_hit, "plain").expect("write plain");
    fs::write(&double_slash_hit, "workspace").expect("write workspace");
    let workspace_display = workspace.to_string_lossy().replace('\\', "/");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"sourceimages/SamplePlain.tx\";\n",
                "createNode file -n \"file2\";\n",
                "    setAttr \".ftn\" -type \"string\" \"{workspace_display}//sourceimages/SampleWorkspace.tx\";\n",
            ),
            workspace_display = workspace_display
        ),
    )
    .expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];
            let targets = shell.missing_path_search_targets(&vec![(1, 0), (1, 1)]);
            let hits = BTreeMap::from([
                (path_search_hit_key("SamplePlain.tx"), plain_hit.clone()),
                (
                    path_search_hit_key("SampleWorkspace.tx"),
                    double_slash_hit.clone(),
                ),
            ]);

            shell.apply_missing_path_file_hits(
                targets,
                workspace.clone(),
                hits,
                Duration::from_secs(0),
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
            Some(&"recovered/SamplePlain.tx".to_string())
        );
        assert_eq!(
            shell.rows[0].path_overrides.get(&1),
            Some(&format!(
                "{workspace_display}//recovered/SampleWorkspace.tx"
            ))
        );
    });
}

#[gpui::test]
fn search_missing_path_write_back_skips_rows_that_disappeared(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let recovered = workspace.join("recovered");
    let first_hit = recovered.join("SampleFirst.tx");
    let second_hit = recovered.join("SampleSecond.tx");
    fs::create_dir_all(&recovered).expect("mkdir recovered");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    fs::write(&first_hit, "first").expect("write first");
    fs::write(&second_hit, "second").expect("write second");
    let first_scene = workspace.join("first.ma");
    let second_scene = workspace.join("second.ma");
    fs::write(
        &first_scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/SampleFirst.tx\";\n",
        ),
    )
    .expect("write first scene");
    fs::write(
        &second_scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/SampleSecond.tx\";\n",
        ),
    )
    .expect("write second scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut first_row = test_row(1, &first_scene);
            first_row.paths_report =
                Some(collect_scene_paths(&first_scene, PathKind::File).expect("paths"));
            first_row.refresh_path_resolution_cache();
            let mut second_row = test_row(2, &second_scene);
            second_row.paths_report =
                Some(collect_scene_paths(&second_scene, PathKind::File).expect("paths"));
            second_row.refresh_path_resolution_cache();
            shell.rows = vec![first_row, second_row];
            let targets = shell.missing_path_search_targets(&vec![(1, 0), (2, 0)]);
            shell.rows.retain(|row| row.id == 1);
            let hits = BTreeMap::from([
                (path_search_hit_key("SampleFirst.tx"), first_hit.clone()),
                (path_search_hit_key("SampleSecond.tx"), second_hit.clone()),
            ]);

            shell.apply_missing_path_file_hits(
                targets,
                workspace.clone(),
                hits,
                Duration::from_secs(0),
                window,
                cx,
            );
        });
    });
    visual_cx.run_until_parked();

    visual_cx.update(|_, app| {
        let shell = shell.read(app);
        assert_eq!(shell.rows.len(), 1);
        assert_eq!(
            shell.rows[0].path_overrides.get(&0),
            Some(&"recovered/SampleFirst.tx".to_string())
        );
    });
}

#[gpui::test]
fn search_missing_path_write_back_skips_targets_whose_value_changed(cx: &mut TestAppContext) {
    let (shell, visual_cx) = open_test_shell(cx);
    let dir = tempdir().expect("tmpdir");
    let workspace = dir.path().join("workspace");
    let recovered = workspace.join("recovered");
    let hit = recovered.join("Sample.tx");
    fs::create_dir_all(&recovered).expect("mkdir recovered");
    fs::write(workspace.join("workspace.mel"), "// workspace").expect("workspace");
    fs::write(&hit, "tx").expect("write hit");
    let scene = workspace.join("scene.ma");
    fs::write(
        &scene,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"sourceimages/Sample.tx\";\n",
        ),
    )
    .expect("write scene");

    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut row = test_row(1, &scene);
            row.paths_report = Some(collect_scene_paths(&scene, PathKind::File).expect("paths"));
            row.refresh_path_resolution_cache();
            shell.rows = vec![row];
            let targets = shell.missing_path_search_targets(&vec![(1, 0)]);
            shell.rows[0]
                .path_overrides
                .insert(0, "sourceimages/SampleChanged.tx".to_string());
            let hits = BTreeMap::from([(path_search_hit_key("Sample.tx"), hit.clone())]);

            shell.apply_missing_path_file_hits(
                targets,
                workspace.clone(),
                hits,
                Duration::from_secs(0),
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
            Some(&"sourceimages/SampleChanged.tx".to_string())
        );
    });
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
fn collect_target_files_reuses_self_copy_without_destination_read() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("source.tx");
    fs::write(&source, "same").expect("write source");

    let reused = collect_target_files(&[PathCollectPlan {
        row_id: 1,
        entry_index: 0,
        row_index: 0,
        source_path: source.clone(),
        destination_path: source,
        next_value: "source.tx".to_string(),
    }])
    .expect("reuse self copy");
    assert_eq!(reused.copied, 0);
    assert_eq!(reused.reused, 1);
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

#[gpui::test]
fn audit_detail_tabs_select_one_panel_and_reset_on_reopen(cx: &mut TestAppContext) {
    use gpui_component::WindowExt;

    let (shell, visual_cx) = open_test_shell(cx);
    let mut row = test_audit_row(1, 0, "TestScene.ma", "Example", &[]);
    row.preview = r"Example\n\t".to_string();
    let key = row.key.clone();
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.locale = LocalePreference::English;
        shell.audit_rows = display_audit_rows(vec![row]);
        shell.open_audit_detail_dialog(key.clone(), window, cx);
        let state = shell.audit_detail_dialog.as_ref().expect("dialog state");
        assert_eq!(state.active_tab, AuditDetailTab::Code);
        assert_eq!(state.code_input.read(cx).value().as_ref(), r"Example\n\t");
    });
    let assert_panel = |visual_cx: &mut VisualTestContext, selected| {
        let (rows, state) = shell.update_in(visual_cx, |shell, _, _| {
            (
                shell.audit_rows.clone(),
                shell.audit_detail_dialog.clone().unwrap(),
            )
        });
        // GPUI retains debug bounds between frames, so inspect each selection in a fresh window.
        let (snapshot, snapshot_cx) = open_test_shell(visual_cx);
        snapshot.update_in(snapshot_cx, |shell, window, cx| {
            shell.state.locale = LocalePreference::English;
            shell.audit_rows = rows;
            shell.open_audit_detail_dialog(state.key, window, cx);
            shell.audit_detail_dialog.as_mut().unwrap().active_tab = state.active_tab;
            cx.notify();
        });
        for (index, selector) in ["audit-detail-panel-code", "audit-detail-panel-details"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                snapshot_cx.debug_bounds(selector).is_some(),
                index == selected,
                "{selector}"
            );
        }
    };
    assert_panel(visual_cx, 0);
    let tabs = visual_cx
        .debug_bounds("audit-detail-tabs")
        .expect("tab bounds");
    visual_cx.simulate_click(
        point(tabs.left() + px(90.0), tabs.center().y),
        Modifiers::default(),
    );
    shell.update_in(visual_cx, |shell, window, cx| {
        assert_eq!(
            shell.audit_detail_dialog.as_ref().unwrap().active_tab,
            AuditDetailTab::Details
        );
        shell.sync_audit_detail_dialog_inputs(window, cx);
        assert_eq!(
            shell.audit_detail_dialog.as_ref().unwrap().active_tab,
            AuditDetailTab::Details
        );
    });
    assert_panel(visual_cx, 1);
    let close = visual_cx
        .debug_bounds("audit-detail-close")
        .expect("close bounds");
    visual_cx.simulate_click(close.center(), Modifiers::default());
    shell.update_in(visual_cx, |shell, window, cx| {
        assert!(shell.audit_detail_dialog.is_none());
        assert!(!window.has_active_dialog(cx));
        shell.audit_rows[0].preview.clear();
        shell.open_audit_detail_dialog(key, window, cx);
        let state = shell.audit_detail_dialog.as_ref().expect("reopened dialog");
        assert_eq!(state.active_tab, AuditDetailTab::Code);
        assert_eq!(state.code_input.read(cx).value().as_ref(), "-");
        let detail = resolve_audit_detail_view_model(&shell.audit_rows, &state.key).unwrap();
        assert_eq!(
            super::audit_detail_dialog::audit_detail_preview_text(&detail),
            "-"
        );
    });
    assert_panel(visual_cx, 0);
}

#[test]
fn audit_detail_fields_preserve_origin_order_source_line_and_representative() {
    use AuditDetailFieldKind::*;

    use super::helpers::build_audit_detail_fields;
    let fields = |pairs: &[(AuditDetailFieldKind, &str)]| {
        pairs
            .iter()
            .map(|(kind, raw)| AuditDetailField {
                kind: *kind,
                raw: (*raw).to_string(),
            })
            .collect::<Vec<_>>()
    };
    let dir = tempdir().expect("tmpdir");
    let path = dir.path().join("TestScene.ma");
    let prefix = "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n";
    fs::write(&path, format!("{prefix}python(\"import subprocess\\nsubprocess.call(['echo', 'Example'])\");\ncreateNode script -n \"ExampleScriptNode\";\nsetAttr \".b\" -type \"string\" \"print(1)\";\nsetAttr \".st\" 2;\nsetAttr \".stp\" 1;\n")).expect("write synthetic scene");
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).expect("analyze")
    else {
        panic!("expected analysis");
    };
    let finding = result
        .audit_report
        .findings
        .iter()
        .find(|finding| {
            result.audit_report.surface_for(finding).origin.surface_kind
                == ExecutionSurfaceKind::TopLevelCommand
        })
        .expect("top-level finding");
    let origin = ExecutionOrigin {
        lang: ExecutionLanguage::Python,
        trigger: ExecutionTrigger::GuiOpenClose,
        surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
        node_name: Some("ExampleScriptNode".to_string()),
        attr_name: Some(".b".to_string()),
        source_kind: Some("scriptType=2,sourceType=1".to_string()),
        ..ExecutionOrigin::without_chunk_address()
    };
    let expected = fields(&[
        (RuleId, finding.code.as_str()),
        (Sink, finding.sink.as_str()),
        (Node, "ExampleScriptNode"),
        (Attribute, ".b"),
        (Surface, "script_node_body"),
        (Trigger, "gui_open_close"),
        (Language, "python"),
        (Source, "scriptType=2,sourceType=1"),
        (Line, "3"),
    ]);
    assert_eq!(
        build_audit_detail_fields(
            finding.code.as_str(),
            finding.sink.as_str(),
            &origin,
            Some(3),
            None,
            &AuditAllowlist::default(),
            &I18n::new(SupportedLocale::English),
        ),
        expected
    );
    let mut optional_origin = origin.clone();
    optional_origin.node_name = None;
    optional_origin.attr_name = None;
    optional_origin.source_kind = None;
    assert_eq!(
        build_audit_detail_fields(
            "Example",
            "Example",
            &optional_origin,
            None,
            None,
            &AuditAllowlist::default(),
            &I18n::new(SupportedLocale::English),
        ),
        fields(&[
            (RuleId, "Example"),
            (Sink, "Example"),
            (Surface, "script_node_body"),
            (Trigger, "gui_open_close"),
            (Language, "python"),
        ])
    );
    optional_origin.node_name = Some(String::new());
    optional_origin.attr_name = Some(String::new());
    optional_origin.source_kind = Some(String::new());
    assert_eq!(
        build_audit_detail_fields(
            "Example",
            "Example",
            &optional_origin,
            None,
            None,
            &AuditAllowlist::default(),
            &I18n::new(SupportedLocale::English),
        ),
        fields(&[
            (RuleId, "Example"),
            (Sink, "Example"),
            (Node, ""),
            (Attribute, ""),
            (Surface, "script_node_body"),
            (Trigger, "gui_open_close"),
            (Language, "python"),
            (Source, ""),
        ])
    );
    assert_eq!(
        result
            .audit_report
            .surface_for(finding)
            .origin
            .source_range
            .unwrap()
            .start,
        prefix.len()
    );
    let finding_index = result
        .audit_report
        .findings
        .iter()
        .position(|item| std::ptr::eq(item, finding))
        .unwrap();
    let mut scene_row = test_row(1, &path);
    scene_row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    scene_row.dump_report = result.dump_report;
    let rows = build_audit_result_rows(
        &[scene_row],
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    );
    let finding_row = rows
        .iter()
        .find(|row| {
            row.key.item_kind == AuditResultItemKind::Finding && row.key.item_index == finding_index
        })
        .unwrap();
    assert_eq!(finding_row.source_line, Some(3));
    assert!(finding_row.provenance.contains(&"line: 3".to_string()));
    assert_eq!(
        finding_row
            .detail_fields
            .iter()
            .find(|field| field.kind == Line)
            .unwrap()
            .raw,
        "3"
    );
    let require = rows
        .iter()
        .find(|row| row.key.item_kind == AuditResultItemKind::DumpRequire)
        .expect("require row");
    assert_eq!(
        require.detail_fields,
        fields(&[(RuleId, "require"), (Sink, "observe")])
    );
    let script = rows
        .iter()
        .find(|row| row.key.item_kind == AuditResultItemKind::DumpScriptNode)
        .expect("script row");
    assert_eq!(
        script.detail_fields,
        fields(&[
            (RuleId, "script_node"),
            (Sink, "observe"),
            (Node, "ExampleScriptNode")
        ])
    );
    let table = display_audit_rows(rows.clone());
    for row in &rows {
        assert_eq!(
            resolve_audit_detail_view_model(&table, &row.key)
                .unwrap()
                .detail_fields,
            row.detail_fields
        );
    }
    let mut first = test_audit_row(1, 0, "ExampleA.ma", "Example", &[]);
    first.detail_fields = expected.clone();
    let mut second = first.clone();
    second.key.row_id = 2;
    second.scene_name = "ExampleB.ma".to_string();
    second
        .detail_fields
        .iter_mut()
        .find(|field| field.kind == Language)
        .unwrap()
        .raw = "mel".to_string();
    let keys = vec![first.key.clone(), second.key.clone()];
    let dedup = build_audit_table_model(
        &[first, second],
        &BTreeSet::new(),
        &default_audit_severity_filter(),
        false,
        false,
        true,
        "",
        default_audit_sort(),
        SupportedLocale::English,
    );
    assert_eq!(dedup.rows.len(), 1);
    assert_eq!(dedup.rows[0].row_keys, keys);
    assert_eq!(dedup.rows[0].detail_fields, expected);
    assert_eq!(
        resolve_audit_detail_view_model(&dedup.rows, &keys[0])
            .unwrap()
            .detail_fields,
        expected
    );
    assert!(resolve_audit_detail_view_model(&dedup.rows, &keys[1]).is_none());
}

#[test]
fn audit_detail_values_translate_only_complete_known_values() {
    use AuditDetailFieldKind::*;

    use super::audit_detail_dialog::audit_detail_field_display;
    let en = I18n::new(SupportedLocale::English);
    let ja = I18n::new(SupportedLocale::Japanese);
    let surface = vec![AuditDetailField {
        kind: Surface,
        raw: "script_node_body".to_string(),
    }];
    let display = |kind, raw: &str, i18n: &I18n| {
        audit_detail_field_display(
            &AuditDetailField {
                kind,
                raw: raw.to_string(),
            },
            &surface,
            i18n,
        )
    };
    assert_eq!(
        display(Trigger, "gui_open_close", &ja),
        "GUI でシーンを開くとき／閉じるとき (gui_open_close)"
    );
    assert_eq!(
        display(Trigger, "gui_open_close", &en),
        "On GUI scene open/close (gui_open_close)"
    );
    assert_eq!(display(Trigger, "unknown", &ja), "不明 (unknown)");
    assert_eq!(display(Trigger, "example_trigger", &ja), "example_trigger");
    assert_eq!(
        display(Source, "scriptType=2,sourceType=1", &en),
        "GUI Open/Close / Python (scriptType=2,sourceType=1)"
    );
    assert_eq!(
        display(Source, "scriptType=2", &en),
        "GUI Open/Close (scriptType=2)"
    );
    assert_eq!(
        display(Source, "sourceType=1", &en),
        "Python (sourceType=1)"
    );
    for raw in [
        "custom",
        "scriptType=99",
        "scriptType=2,sourceType=99",
        "scriptType=02",
        "scriptType=+2",
        "scriptType=-2",
        "scriptType=２",
        "scriptType= 2",
        " scriptType=2",
        "scriptType=2 ",
        "scriptType=",
        "sourceType=",
        "sourceType=1,scriptType=2",
        "scriptType=2,sourceType=1,sourceType=0",
        "scriptType=2,sourceType=",
        "",
    ] {
        assert_eq!(display(Source, raw, &en), raw);
    }
    for (raw, expected) in [
        (".b", "before script (.b)"),
        ("b", "before script (b)"),
        (".a", "after script (.a)"),
        ("a", "after script (a)"),
        ("Example", "Example"),
        ("", ""),
    ] {
        assert_eq!(display(Attribute, raw, &en), expected);
    }
    let callback = vec![AuditDetailField {
        kind: Surface,
        raw: "node_attr_callback".to_string(),
    }];
    let attribute = AuditDetailField {
        kind: Attribute,
        raw: ".b".to_string(),
    };
    assert_eq!(audit_detail_field_display(&attribute, &callback, &en), ".b");
    assert_eq!(audit_detail_field_display(&attribute, &[], &en), ".b");
    for kind in [RuleId, Sink, Node, Line, Surface, Trigger, Language] {
        assert_eq!(display(kind, "", &en), "");
    }
    let key = format!("audit_value.trigger.{}", "gui_open_close");
    assert_eq!(
        ja.try_text(&key),
        Some("GUI でシーンを開くとき／閉じるとき".to_string())
    );
    assert_eq!(
        ja.try_text(&format!("audit_value.trigger.{}", "example_missing")),
        None
    );
}

#[test]
fn audit_detail_evidence_filters_entries_without_changing_copy_payload() {
    use super::audit_detail_dialog::audit_detail_evidence_text;
    let mut row = test_audit_row(
        1,
        0,
        "ExampleA.ma",
        "Example",
        &["node_name: ExampleScriptNode", "command: example"],
    );
    row.provenance = vec!["node: ExampleScriptNode".to_string()];
    row.preview = "Example preview".to_string();
    let table = display_audit_rows(vec![row]);
    let mut detail = resolve_audit_detail_view_model(&table, &table[0].key).unwrap();
    assert_eq!(audit_detail_evidence_text(&detail), "command: example");
    let expected = "node: ExampleScriptNode\n\nExample preview\n\nnode_name: ExampleScriptNode\ncommand: example";
    assert_eq!(
        build_audit_clipboard_payload(&detail.provenance, &detail.preview, &detail.evidence),
        expected
    );
    assert_eq!(
        resolve_audit_clipboard_payload(&table, &table[0].key).as_deref(),
        Some(expected)
    );
    detail.evidence = vec!["node_name: ExampleScriptNode".to_string()];
    assert_eq!(audit_detail_evidence_text(&detail), "-");
    detail.scene_names = vec!["ExampleA.ma".to_string(), "ExampleB.ma".to_string()];
    assert_eq!(
        audit_detail_evidence_text(&detail),
        "scenes:\nExampleA.ma\nExampleB.ma\n-"
    );
    detail.evidence.clear();
    assert_eq!(
        audit_detail_evidence_text(&detail),
        "scenes:\nExampleA.ma\nExampleB.ma\n-"
    );
    detail.scene_names.truncate(1);
    assert_eq!(audit_detail_evidence_text(&detail), "-");
    for entry in [
        "node: ExampleScriptNode",
        " node_name: ExampleScriptNode",
        "node_name:",
        "Example\nnode_name: ExampleScriptNode",
    ] {
        detail.evidence = vec![entry.to_string()];
        assert_eq!(audit_detail_evidence_text(&detail), entry);
    }
    detail.evidence = vec!["node_name: ExampleScriptNode\ncommand: example".to_string()];
    assert_eq!(audit_detail_evidence_text(&detail), "-");
}

#[test]
fn audit_detail_header_facts_follow_locale_and_omit_unknown_trigger() {
    use AuditDetailFieldKind::*;

    use super::audit_detail_dialog::audit_detail_header_facts;
    let en = I18n::new(SupportedLocale::English);
    let ja = I18n::new(SupportedLocale::Japanese);
    let node = AuditDetailField {
        kind: Node,
        raw: "ExampleScriptNode".to_string(),
    };
    let trigger = AuditDetailField {
        kind: Trigger,
        raw: "gui_open_close".to_string(),
    };
    let fields = vec![trigger.clone(), node.clone()];
    assert_eq!(
        audit_detail_header_facts(&fields, &ja).as_deref(),
        Some(
            "ノード: ExampleScriptNode  |  実行契機: GUI でシーンを開くとき／閉じるとき (gui_open_close)"
        )
    );
    assert_eq!(
        audit_detail_header_facts(&fields, &en).as_deref(),
        Some("Node: ExampleScriptNode  |  Trigger: On GUI scene open/close (gui_open_close)")
    );
    assert_eq!(
        audit_detail_header_facts(&[node], &ja).as_deref(),
        Some("ノード: ExampleScriptNode")
    );
    assert_eq!(
        audit_detail_header_facts(&[trigger], &en).as_deref(),
        Some("Trigger: On GUI scene open/close (gui_open_close)")
    );
    assert_eq!(audit_detail_header_facts(&[], &ja), None);
    assert_eq!(
        audit_detail_header_facts(
            &[
                AuditDetailField {
                    kind: RuleId,
                    raw: "require".to_string()
                },
                AuditDetailField {
                    kind: Sink,
                    raw: "observe".to_string()
                }
            ],
            &ja
        ),
        None
    );
    assert_eq!(
        audit_detail_header_facts(
            &[AuditDetailField {
                kind: Node,
                raw: String::new()
            }],
            &ja
        )
        .as_deref(),
        Some("ノード: ")
    );
    assert_eq!(
        audit_detail_header_facts(
            &[AuditDetailField {
                kind: Trigger,
                raw: "unknown".to_string()
            }],
            &ja
        ),
        None
    );
}

#[test]
fn audit_detail_surface_text_matching_is_unique_and_preserves_origin_identity() {
    use maya_scene_kit_observe::scene::execution::ExecutionSurface;

    use super::audit_detail_dialog::{AuditSurfaceMatch, match_audit_surface_text};

    let origin = ExecutionOrigin {
        lang: ExecutionLanguage::Python,
        surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
        node_name: Some("ExampleScriptNode".to_string()),
        source_kind: Some("scriptType=1,sourceType=1".to_string()),
        ..ExecutionOrigin::without_chunk_address()
    };
    let surface = ExecutionSurface {
        origin: origin.clone(),
        text: "print('Example')".into(),
        preview: String::new(),
    };
    let single = std::slice::from_ref(&surface);
    assert_eq!(
        match_audit_surface_text(&origin, false, single),
        AuditSurfaceMatch::Found(Box::new(super::audit_detail_dialog::FoundSurface {
            catalog_index: 0,
            origin: origin.clone(),
            text: surface.text.clone()
        }))
    );
    let mut derived = origin.clone();
    derived.lang = ExecutionLanguage::Mel;
    derived.source_kind = Some("Example literal".to_string());
    assert_eq!(
        match_audit_surface_text(&derived, true, single),
        AuditSurfaceMatch::Found(Box::new(super::audit_detail_dialog::FoundSurface {
            catalog_index: 0,
            origin: origin.clone(),
            text: surface.text.clone()
        }))
    );
    let mut other_node = derived.clone();
    other_node.node_name = Some("ExampleOtherNode".to_string());
    assert_eq!(
        match_audit_surface_text(&other_node, true, single),
        AuditSurfaceMatch::NotFound
    );
    let mut other_language = origin.clone();
    other_language.lang = ExecutionLanguage::Mel;
    assert_eq!(
        match_audit_surface_text(&other_language, false, single),
        AuditSurfaceMatch::NotFound
    );
    assert_eq!(
        match_audit_surface_text(&origin, false, &[]),
        AuditSurfaceMatch::NotFound
    );
    assert_eq!(
        match_audit_surface_text(&origin, false, &[surface.clone(), surface.clone()]),
        AuditSurfaceMatch::Ambiguous
    );

    let mut parent = surface.clone();
    parent.text = r#"maya.mel.eval("python(\"print('Example')\")")"#.into();
    let mut bridge = surface;
    bridge.origin.lang = ExecutionLanguage::Mel;
    bridge.origin.source_kind = Some("python->maya.mel.eval literal bridge".to_string());
    bridge.text = r#"python("print('Example')")"#.into();
    assert_eq!(
        match_audit_surface_text(&derived, true, &[parent, bridge]),
        AuditSurfaceMatch::Ambiguous
    );
}

fn audit_detail_code_test_row(path: &Path) -> SceneRow {
    let body = "import subprocess\nsubprocess.call(['echo', 'Example'])\r\nprint('Example')";
    let encoded = body.replace('\r', "\\r").replace('\n', "\\n");
    fs::write(path, format!("//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"ExampleScriptNode\";\n    setAttr \".b\" -type \"string\" \"{encoded}\";\n    setAttr \".st\" 1;\n    setAttr \".stp\" 1;\n")).unwrap();
    let RowJobResult::Analyze(result) =
        analyze_row(path, AuditModePreference::StrictDefault).unwrap()
    else {
        panic!("expected analysis");
    };
    let mut row = test_row(1, path);
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    row.dump_report = result.dump_report;
    row
}

fn prepare_audit_detail_code_test(
    shell: &mut GuiShell,
    row: SceneRow,
    kind: AuditResultItemKind,
) -> AuditResultRowKey {
    shell.replace_rows(vec![row]);
    shell.audit_rows = display_audit_rows(build_audit_result_rows(
        &shell.rows,
        &[0],
        &AuditAllowlist::default(),
        &I18n::new(SupportedLocale::English),
    ));
    shell
        .audit_rows
        .iter()
        .flat_map(|row| &row.row_keys)
        .find(|key| key.item_kind == kind)
        .unwrap()
        .clone()
}

#[gpui::test]
fn audit_detail_code_loads_full_text_and_sync_preserves_it(cx: &mut TestAppContext) {
    use super::audit_detail_dialog::load_audit_surface_text;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    assert_eq!(
        row.audit_file_state,
        Some(GuiFileState::read(&path).unwrap())
    );
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::Finding);
        shell.open_audit_detail_dialog(key.clone(), window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        let AuditDetailCodeState::Loading { request } = state.code else {
            panic!("expected loading");
        };
        let target = state.code_target.clone().unwrap();
        assert_eq!(
            target.origin.node_name.as_deref(),
            Some("ExampleScriptNode")
        );
        let result = load_audit_surface_text(
            &path,
            &shell.scene_load_options(),
            &target,
            &OfferInput::from(shell.rows[0].display_audit_report().unwrap()),
        );
        shell.apply_audit_detail_code_result(&key, request, result, window, cx);
        let expected =
            "import subprocess\nsubprocess.call(['echo', 'Example'])\r\nprint('Example')";
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert_eq!(state.code, audit_detail_expected_loaded(&shell.rows[0]));
        assert_eq!(
            state.code_input.read(cx).value().as_bytes(),
            expected.as_bytes()
        );
        assert_eq!(state.code_text, expected);
        assert_eq!(
            shell.audit_detail_code_clipboard_text(cx).as_deref(),
            Some(expected)
        );
        let preview = state.preview_text.clone();
        shell.audit_detail_dialog.as_mut().unwrap().active_tab = AuditDetailTab::Details;
        shell.sync_audit_detail_dialog_inputs(window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert_eq!(
            state.code_input.read(cx).value().as_bytes(),
            expected.as_bytes()
        );
        assert_eq!(state.preview_text, preview);
        assert_eq!(state.code_text, expected);
        assert_eq!(state.active_tab, AuditDetailTab::Details);
    });
}

#[gpui::test]
fn audit_detail_code_missing_file_opens_asynchronously_then_fails(cx: &mut TestAppContext) {
    use super::audit_detail_dialog::{
        audit_detail_code_note_key, load_audit_surface_text_for_file_state,
    };
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    fs::remove_file(&path).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::Finding);
        shell.open_audit_detail_dialog(key.clone(), window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        let AuditDetailCodeState::Loading { request } = state.code else {
            panic!("open must only spawn the load");
        };
        let preview = state.preview_text.clone();
        let result = load_audit_surface_text_for_file_state(
            &path,
            &shell.scene_load_options(),
            state.code_target.as_ref().unwrap(),
            shell.rows[0].audit_file_state,
            &OfferInput::from(shell.rows[0].display_audit_report().unwrap()),
        );
        shell.apply_audit_detail_code_result(&key, request, result, window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert!(matches!(&state.code, AuditDetailCodeState::Failed { error } if !error.is_empty()));
        assert_eq!(state.code_input.read(cx).value().as_ref(), preview);
        assert_eq!(
            audit_detail_code_note_key(&state.code),
            Some("audit_detail.code_load_failed")
        );
    });
}

#[gpui::test]
fn audit_detail_code_drops_results_from_an_old_request(cx: &mut TestAppContext) {
    use gpui_component::WindowExt;

    use super::audit_detail_dialog::load_audit_surface_text;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::Finding);
        shell.open_audit_detail_dialog(key.clone(), window, cx);
        let old = shell.audit_detail_dialog.as_ref().unwrap().clone();
        let AuditDetailCodeState::Loading { request } = old.code else {
            panic!("expected loading");
        };
        let result = load_audit_surface_text(
            &path,
            &shell.scene_load_options(),
            old.code_target.as_ref().unwrap(),
            &OfferInput::from(shell.rows[0].display_audit_report().unwrap()),
        );
        shell.clear_audit_detail_dialog_state(cx);
        window.close_dialog(cx);
        shell.open_audit_detail_dialog(key.clone(), window, cx);
        let current = shell.audit_detail_dialog.as_ref().unwrap().clone();
        assert_ne!(current.code, old.code);
        shell.apply_audit_detail_code_result(&key, request, result, window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert_eq!(state.code, current.code);
        assert_eq!(state.code_text, current.code_text);
        assert_eq!(
            state.code_input.read(cx).value().as_ref(),
            current.code_text.as_ref()
        );
    });
}

#[gpui::test]
fn audit_detail_code_dump_script_uses_preview_without_loading(cx: &mut TestAppContext) {
    use super::audit_detail_dialog::audit_detail_code_note_key;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::DumpScriptNode);
        let preview = resolve_audit_detail_view_model(&shell.audit_rows, &key)
            .unwrap()
            .preview;
        let request = shell.audit_detail_code_request;
        shell.open_audit_detail_dialog(key, window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert_eq!(state.code, AuditDetailCodeState::NotApplicable);
        assert_eq!(shell.audit_detail_code_request, request);
        assert_eq!(state.code_input.read(cx).value().as_ref(), preview);
        assert_eq!(
            shell.audit_detail_code_clipboard_text(cx).as_deref(),
            Some(preview.as_str())
        );
        assert_eq!(audit_detail_code_note_key(&state.code), None);
    });
}

#[gpui::test]
fn audit_detail_code_changed_file_keeps_preview(cx: &mut TestAppContext) {
    use super::audit_detail_dialog::{
        audit_detail_code_note_key, load_audit_surface_text_for_file_state,
    };
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    fs::write(&path, "//Maya ASCII 2026 scene\n").unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::Finding);
        shell.open_audit_detail_dialog(key.clone(), window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        let AuditDetailCodeState::Loading { request } = state.code else {
            panic!("expected loading");
        };
        let preview = state.preview_text.clone();
        let result = load_audit_surface_text_for_file_state(
            &path,
            &shell.scene_load_options(),
            state.code_target.as_ref().unwrap(),
            shell.rows[0].audit_file_state,
            &OfferInput::from(shell.rows[0].display_audit_report().unwrap()),
        );
        shell.apply_audit_detail_code_result(&key, request, result, window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert_eq!(state.code, AuditDetailCodeState::FileChanged);
        assert_eq!(state.code_input.read(cx).value().as_ref(), preview);
        assert_eq!(
            audit_detail_code_note_key(&state.code),
            Some("audit_detail.code_file_changed")
        );
    });
}

#[gpui::test]
fn audit_detail_code_generation_change_invalidates_loaded_text(cx: &mut TestAppContext) {
    use super::audit_detail_dialog::load_audit_surface_text;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::Finding);
        shell.open_audit_detail_dialog(key.clone(), window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        let AuditDetailCodeState::Loading { request } = state.code else {
            panic!("expected loading");
        };
        let result = load_audit_surface_text(
            &path,
            &shell.scene_load_options(),
            state.code_target.as_ref().unwrap(),
            &OfferInput::from(shell.rows[0].display_audit_report().unwrap()),
        );
        shell.apply_audit_detail_code_result(&key, request, result, window, cx);
        assert_eq!(
            shell.audit_detail_dialog.as_ref().unwrap().code,
            audit_detail_expected_loaded(&shell.rows[0])
        );
        let row = &mut shell.rows[0];
        row.set_audit_report(row.audit_report.clone(), row.audit_file_state);
        shell.sync_audit_detail_dialog_inputs(window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert_eq!(state.code, AuditDetailCodeState::Unavailable);
        assert_eq!(
            state.code_input.read(cx).value().as_ref(),
            state.preview_text
        );
        assert_eq!(state.code_text, state.preview_text);
    });
}

fn audit_detail_fix_target(row: &SceneRow) -> super::AuditDetailCodeTarget {
    let report = row.display_audit_report().unwrap();
    let finding = report
        .findings
        .iter()
        .find(|finding| {
            report.surface_for(finding).origin.node_name.as_deref() == Some("ExampleScriptNode")
        })
        .unwrap();
    super::AuditDetailCodeTarget {
        origin: report.surface_for(finding).origin.clone(),
        derived: false,
    }
}

fn audit_detail_expected_loaded(row: &SceneRow) -> AuditDetailCodeState {
    let origin = audit_detail_fix_target(row).origin;
    let text = "import subprocess\nsubprocess.call(['echo', 'Example'])\r\nprint('Example')";
    AuditDetailCodeState::Loaded {
        derived: false,
        allow: Box::new(super::AuditAllowMaterial {
            hash: maya_scene_kit_audit::scene::allowlist_surface_hash(&origin, text),
            root_origin: origin,
            offered_codes: vec!["python_subprocess".to_string()],
        }),
    }
}

#[test]
fn audit_detail_fix_equal_file_state_loads_full_text() {
    use super::audit_detail_dialog::load_audit_surface_text_for_file_state;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let result = load_audit_surface_text_for_file_state(
        &path,
        &LoadOptions::default(),
        &audit_detail_fix_target(&row),
        row.audit_file_state,
        &OfferInput::from(row.display_audit_report().unwrap()),
    );
    assert_eq!(result.state, audit_detail_expected_loaded(&row));
    assert_eq!(
        result.text.as_deref(),
        Some("import subprocess\nsubprocess.call(['echo', 'Example'])\r\nprint('Example')")
    );
}

#[gpui::test]
fn audit_detail_fix_spawned_missing_file_applies_failure(cx: &mut TestAppContext) {
    use super::audit_detail_dialog::audit_detail_code_note_key;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    fs::remove_file(&path).unwrap();
    let (shell, visual_cx) = open_test_shell(cx);
    let preview = shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::Finding);
        shell.open_audit_detail_dialog(key, window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert!(matches!(state.code, AuditDetailCodeState::Loading { .. }));
        state.preview_text.clone()
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, _, cx| {
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert!(
            matches!(&state.code, AuditDetailCodeState::Failed { error } if !error.is_empty()),
            "spawned result was not applied: {:?}",
            state.code
        );
        assert_eq!(state.code_input.read(cx).value().as_ref(), preview);
        assert_eq!(
            audit_detail_code_note_key(&state.code),
            Some("audit_detail.code_load_failed")
        );
    });
}

#[gpui::test]
fn audit_detail_fix_analysis_apply_records_file_state(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let result = analyze_row(&path, AuditModePreference::StrictDefault).unwrap();
    let expected = Some(GuiFileState::read(&path).unwrap());
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.replace_rows(vec![row]);
        let generation = shell.rows[0].audit_generation;
        shell.apply_job_result(1, RowOperation::Analyze, result, None, window, cx);
        assert_eq!(shell.rows[0].audit_file_state, expected);
        assert!(shell.rows[0].audit_generation > generation);
    });
}

#[gpui::test]
fn audit_detail_fix_save_promotion_records_file_state(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let mut row = audit_detail_code_test_row(&path);
    row.dirty_kind = Some(DirtyKind::SceneEdits);
    row.staged_audit_report = row.audit_report.clone();
    row.staged_audit_plan_fingerprint = Some(fingerprint_audit_plan(
        &build_script_audit_plan(vec![], 64).expect("plan"),
    ));
    let saved = format!("{}// Example\n", fs::read_to_string(&path).unwrap());
    fs::write(&path, saved).unwrap();
    let expected = Some(GuiFileState::read(&path).unwrap());
    assert_ne!(row.audit_file_state, expected);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.state.workspace_auto_analyze = false;
        shell.replace_rows(vec![row]);
        let generation = shell.rows[0].audit_generation;
        shell.apply_job_result(
            1,
            RowOperation::Save,
            RowJobResult::Save {
                output_path: path.clone(),
                audit_file_state: expected,
            },
            None,
            window,
            cx,
        );
        assert_eq!(shell.rows[0].audit_file_state, expected);
        assert!(shell.rows[0].audit_generation > generation);
        assert!(shell.rows[0].staged_audit_report.is_none());
    });
}

#[gpui::test]
fn audit_detail_fix_cache_restore_records_file_state(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let RowJobResult::Analyze(result) =
        analyze_row(&path, AuditModePreference::StrictDefault).unwrap()
    else {
        panic!("expected analysis");
    };
    let snapshot = result.audit_snapshot.unwrap();
    let expected = Some(GuiFileState {
        size: snapshot.file_state.size,
        modified_unix_nanos: snapshot.file_state.modified_unix_nanos,
    });
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.replace_rows(vec![row]);
        let generation = shell.rows[0].audit_generation;
        shell.apply_cache_restore_updates(
            vec![super::cache_restore::CacheHydrationUpdate {
                row_id: 1,
                observe_snapshot: None,
                observe_access: None,
                audit_snapshot: Some(snapshot),
                audit_access: None,
            }],
            &shell.audit_plan_fingerprint.clone(),
            window,
            cx,
        );
        assert_eq!(shell.rows[0].audit_file_state, expected);
        assert!(shell.rows[0].audit_generation > generation);
    });
}

#[gpui::test]
fn audit_detail_fix_dedup_only_blocks_findings(cx: &mut TestAppContext) {
    use gpui_component::WindowExt;

    use super::audit_detail_dialog::audit_detail_code_note_key;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let mut other = test_row(2, &path);
    other.set_audit_report(row.audit_report.clone(), row.audit_file_state);
    other.dump_report = row.dump_report.clone();
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.replace_rows(vec![row, other]);
        let mut severities = default_audit_severity_filter();
        severities.insert(AuditSeverityFilter::Info);
        shell.audit_rows = build_audit_table_model(
            &build_audit_result_rows(
                &shell.rows,
                &[0, 1],
                &AuditAllowlist::default(),
                &I18n::new(SupportedLocale::English),
            ),
            &BTreeSet::new(),
            &severities,
            false,
            false,
            true,
            "",
            default_audit_sort(),
            SupportedLocale::English,
        )
        .rows;
        for kind in [
            AuditResultItemKind::Finding,
            AuditResultItemKind::DumpScriptNode,
            AuditResultItemKind::DumpRequire,
        ] {
            let audit_row = shell
                .audit_rows
                .iter()
                .find(|row| row.key.item_kind == kind)
                .unwrap();
            assert!(audit_row.row_keys.len() > 1);
            let key = audit_row.key.clone();
            let request = shell.audit_detail_code_request;
            shell.open_audit_detail_dialog(key, window, cx);
            let expected = if kind == AuditResultItemKind::Finding {
                AuditDetailCodeState::Unavailable
            } else {
                AuditDetailCodeState::NotApplicable
            };
            let state = shell.audit_detail_dialog.as_ref().unwrap();
            assert_eq!(state.code, expected);
            assert_eq!(shell.audit_detail_code_request, request);
            let note = if kind == AuditResultItemKind::Finding {
                Some("audit_detail.code_unavailable")
            } else {
                None
            };
            assert_eq!(audit_detail_code_note_key(&state.code), note);
            if kind != AuditResultItemKind::Finding {
                let row = &mut shell.rows[0];
                row.set_audit_report(row.audit_report.clone(), row.audit_file_state);
                shell.sync_audit_detail_dialog_inputs(window, cx);
                let state = shell.audit_detail_dialog.as_ref().unwrap();
                assert_eq!(state.code, AuditDetailCodeState::NotApplicable);
                assert_eq!(audit_detail_code_note_key(&state.code), None);
            }
            shell.clear_audit_detail_dialog_state(cx);
            window.close_dialog(cx);
        }
    });
}

#[gpui::test]
fn audit_detail_fix_loading_generation_rejects_old_result(cx: &mut TestAppContext) {
    use maya_scene_kit_observe::scene::execution::ExecutionSurface;

    use super::audit_detail_dialog::audit_surface_code_result;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::Finding);
        shell.open_audit_detail_dialog(key.clone(), window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        let AuditDetailCodeState::Loading { request } = state.code else {
            panic!("expected loading");
        };
        let target = state.code_target.clone().unwrap();
        let result = audit_surface_code_result(
            &target,
            &[ExecutionSurface {
                origin: target.origin.clone(),
                text: "Example full text".into(),
                preview: String::new(),
            }],
            &OfferInput::default(),
        );
        assert!(matches!(
            &result.state,
            AuditDetailCodeState::Loaded { allow, .. } if allow.offered_codes.is_empty()
        ));
        let row = &mut shell.rows[0];
        row.set_audit_report(row.audit_report.clone(), row.audit_file_state);
        shell
            .audit_rows
            .iter_mut()
            .find(|row| row.key == key)
            .unwrap()
            .preview = "Example current preview".to_string();
        shell.apply_audit_detail_code_result(&key, request, result, window, cx);
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert_eq!(state.code, AuditDetailCodeState::Unavailable);
        assert_eq!(
            state.code_input.read(cx).value().as_ref(),
            "Example current preview"
        );
        assert_eq!(state.code_text, "Example current preview");
    });
}

#[test]
fn audit_detail_fix_missing_file_state_does_not_load() {
    use super::audit_detail_dialog::load_audit_surface_text_for_file_state;
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let result = load_audit_surface_text_for_file_state(
        &path,
        &LoadOptions::default(),
        &audit_detail_fix_target(&row),
        None,
        &OfferInput::from(row.display_audit_report().unwrap()),
    );
    assert_eq!(result.state, AuditDetailCodeState::FileChanged);
    assert!(result.text.is_none());
}

fn audit_detail_fix_assert_too_large(text: String, offers: &OfferInput) {
    use maya_scene_kit_observe::scene::execution::ExecutionSurface;

    use super::audit_detail_dialog::{audit_detail_code_note_key, audit_surface_code_result};
    let target = super::AuditDetailCodeTarget {
        origin: ExecutionOrigin::without_chunk_address(),
        derived: false,
    };
    let result = audit_surface_code_result(
        &target,
        &[ExecutionSurface {
            origin: target.origin.clone(),
            text: text.into(),
            preview: String::new(),
        }],
        offers,
    );
    assert_eq!(result.state, AuditDetailCodeState::TooLarge);
    assert!(result.text.is_none());
    assert_eq!(
        audit_detail_code_note_key(&result.state),
        Some("audit_detail.code_too_large")
    );
}

#[test]
fn audit_detail_fix_total_text_limit() {
    let text = format!("{}E", "E\n".repeat(1024 * 1024));
    assert_eq!(text.len(), 2 * 1024 * 1024 + 1);
    audit_detail_fix_assert_too_large(text, &OfferInput::default());
}

#[test]
fn audit_detail_fix_single_line_limit() {
    audit_detail_fix_assert_too_large("E".repeat(65537), &OfferInput::default());
}

#[gpui::test]
fn audit_detail_fix_unmatched_results_preserve_preview(cx: &mut TestAppContext) {
    use gpui_component::WindowExt;
    use maya_scene_kit_observe::scene::execution::ExecutionSurface;

    use super::audit_detail_dialog::{audit_detail_code_note_key, audit_surface_code_result};
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let row = audit_detail_code_test_row(&path);
    let (shell, visual_cx) = open_test_shell(cx);
    shell.update_in(visual_cx, |shell, window, cx| {
        let key = prepare_audit_detail_code_test(shell, row, AuditResultItemKind::Finding);
        for (count, expected, note) in [
            (
                0,
                AuditDetailCodeState::NotFound,
                "audit_detail.code_not_found",
            ),
            (
                2,
                AuditDetailCodeState::Ambiguous,
                "audit_detail.code_ambiguous",
            ),
        ] {
            shell.open_audit_detail_dialog(key.clone(), window, cx);
            let state = shell.audit_detail_dialog.as_ref().unwrap();
            let AuditDetailCodeState::Loading { request } = state.code else {
                panic!("expected loading");
            };
            let preview = state.preview_text.clone();
            let target = state.code_target.clone().unwrap();
            let surfaces = vec![
                ExecutionSurface {
                    origin: target.origin.clone(),
                    text: "Example full text".into(),
                    preview: String::new()
                };
                count
            ];
            let result = audit_surface_code_result(&target, &surfaces, &OfferInput::default());
            shell.apply_audit_detail_code_result(&key, request, result, window, cx);
            let state = shell.audit_detail_dialog.as_ref().unwrap();
            assert_eq!(state.code, expected);
            assert_eq!(state.code_input.read(cx).value().as_ref(), preview);
            assert_eq!(state.code_text, preview);
            assert_eq!(audit_detail_code_note_key(&state.code), Some(note));
            shell.clear_audit_detail_dialog_state(cx);
            window.close_dialog(cx);
        }
    });
}

mod allowlist_tests {
    use std::sync::Arc;

    use maya_scene_kit_audit::scene::{
        AllowlistSource, AuditAllowRef, AuditDisposition, AuditFindingCode, allowlist_surface_hash,
    };
    use serde_json::json;

    use super::*;
    use crate::gui::{
        AnalyzeRowResult, ScriptAuditPlan, allowlist_error_text, gui_audit_plan,
        helpers::{build_audit_detail_fields, searchable_text_for_audit_row},
    };

    const SCENE: &str = concat!(
        "//Maya ASCII 2026 scene\n",
        "requires maya \"2026\";\n",
        "createNode script -n \"ExampleScriptNode\";\n",
        "\tsetAttr \".b\" -type \"string\" \"exec \\\"Example\\\"\";\n",
        "\tsetAttr \".st\" 1;\n",
    );
    const HASH: &str = "sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20";

    fn list_json(reason: &str) -> String {
        json!({"version":1,"entries":[{
            "hash":HASH,"codes":["mel_exec"],"label":"Example","reason":reason
        }]})
        .to_string()
    }

    fn example_allowlist() -> AuditAllowlist {
        AuditAllowlist::from_json(&list_json("Example reason"), AllowlistSource::App).unwrap()
    }

    fn analyze(path: &Path, plan: &ScriptAuditPlan) -> AnalyzeRowResult {
        let RowJobResult::Analyze(result) = analyze_row_with_options(
            path,
            AuditModePreference::StrictDefault,
            &LoadOptions::default(),
            plan,
        )
        .unwrap() else {
            panic!("expected analysis");
        };
        result
    }

    fn current_row(id: u64, path: &Path, plan: &ScriptAuditPlan) -> SceneRow {
        let result = analyze(path, plan);
        let mut row = test_row(id, path);
        row.set_audit_report(Some(result.audit_report), result.audit_file_state);
        row.audit_plan_fingerprint = Some(result.audit_plan_fingerprint);
        row.paths_report = result.paths_report;
        row.dump_report = result.dump_report;
        row.analyzed_audit_mode = Some(result.audit_mode);
        row.status = FileStatus::Audited;
        row.sync_findings_count();
        row
    }

    fn model(rows: &[AuditResultRow], show: bool, dedup: bool) -> super::super::AuditTableModel {
        build_audit_table_model(
            rows,
            &BTreeSet::new(),
            &default_audit_severity_filter(),
            false,
            show,
            dedup,
            "",
            default_audit_sort(),
            SupportedLocale::English,
        )
    }

    #[gpui::test]
    fn allowed_analysis_preserves_disposition_and_counts_only_threats(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("TestScene.ma");
        fs::write(&path, SCENE).unwrap();
        let allowlist = example_allowlist();
        let plan = gui_audit_plan(allowlist.clone()).unwrap();
        let path_result = analyze(&path, &plan);
        let bytes_result = analyze_row_bytes_with_options(
            &path,
            SceneFormat::Ma,
            ValidationState::Validated,
            SCENE.as_bytes().to_vec(),
            AuditModePreference::StrictDefault,
            &LoadOptions::default(),
            &plan,
        )
        .unwrap();
        for result in [&path_result, &bytes_result] {
            let report = &result.audit_report;
            assert_eq!(report.finding_count(), 1);
            assert_eq!(report.allowed_finding_count(), 1);
            assert_eq!(report.disposition, AuditDisposition::Review);
            assert_eq!(
                report.findings[0].allowed_by,
                Some(AuditAllowRef {
                    hash: HASH.parse().unwrap(),
                    source: AllowlistSource::App,
                })
            );
            let origin = &report.surface_for(&report.findings[0]).origin;
            assert_eq!(origin.lang, ExecutionLanguage::Mel);
            assert_eq!(origin.surface_kind, ExecutionSurfaceKind::ScriptNodeBody);
            assert_eq!(origin.attr_name.as_deref(), Some(".b"));
            assert_eq!(origin.trigger, ExecutionTrigger::FileOpen);
            assert_eq!(origin.source_kind.as_deref(), Some("scriptType=1"));
            let observation = Loader::new(LoadOptions::default())
                .observe_analysis_path(&path)
                .unwrap();
            let surfaces = observation.execution_surfaces(64).unwrap();
            let observed = surfaces
                .iter()
                .find(|surface| surface.origin.node_name.as_deref() == Some("ExampleScriptNode"))
                .unwrap();
            assert_eq!(observed.text.as_ref(), "exec \"Example\"");
            assert_eq!(
                allowlist_surface_hash(origin, "exec \"Example\"").to_string(),
                HASH
            );
            assert_eq!(result.audit_plan_fingerprint, fingerprint_audit_plan(&plan));
        }
        let empty = gui_audit_plan(AuditAllowlist::default()).unwrap();
        let control = analyze(&path, &empty);
        assert_eq!(control.audit_report.allowed_finding_count(), 0);
        assert_eq!(control.audit_report.finding_count(), 1);
        assert_eq!(
            control.audit_report.disposition,
            AuditDisposition::DenyMalicious
        );
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.audit_allowlist = allowlist;
            shell.audit_plan = Arc::new(plan);
            shell.audit_plan_fingerprint = fingerprint_audit_plan(&shell.audit_plan);
            shell.replace_rows(vec![test_row(1, &path)]);
            for result in [path_result, bytes_result] {
                shell.apply_job_result(
                    1,
                    RowOperation::Analyze,
                    RowJobResult::Analyze(result),
                    None,
                    window,
                    cx,
                );
                assert_eq!(shell.rows[0].findings, 0);
                assert_eq!(shell.rows[0].effective_findings_count(), 0);
                assert!(shell.rows[0].analysis_current_for(AuditModePreference::StrictDefault));
            }
            shell.apply_job_result(
                1,
                RowOperation::Analyze,
                RowJobResult::Analyze(control),
                None,
                window,
                cx,
            );
            assert_eq!(shell.rows[0].findings, 1);
        });
    }

    #[gpui::test]
    fn allowed_rows_toggle_caps_dedup_and_close_hidden_details(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("TestScene.ma");
        fs::write(&path, SCENE).unwrap();
        let allowlist = example_allowlist();
        let plan = gui_audit_plan(allowlist.clone()).unwrap();
        let mut row = current_row(1, &path, &plan);
        row.selected = true;
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            assert!(!shell.audit_show_allowed);
            shell.audit_allowlist = allowlist;
            shell.replace_rows(vec![row]);
            shell.refresh_audit_table(cx);
            let findings = |shell: &GuiShell| {
                shell
                    .audit_rows
                    .iter()
                    .filter(|row| row.key.item_kind == AuditResultItemKind::Finding)
                    .count()
            };
            assert_eq!(findings(shell), 0);
            assert_eq!(shell.audit_allowed_total, 1);
            assert_eq!(
                shell.i18n().format(
                    "audit_table.show_allowed",
                    &[("count", shell.audit_allowed_total.to_string())]
                ),
                "Show allowed (1)"
            );
            shell.toggle_audit_show_allowed(cx);
            assert_eq!(findings(shell), 1);
            let finding = shell
                .audit_rows
                .iter()
                .find(|row| row.key.item_kind == AuditResultItemKind::Finding)
                .unwrap()
                .clone();
            assert_eq!(finding.allowed, Some(AllowlistSource::App));
            assert_eq!(finding.key.item_index, 0);
            shell.selected_audit_keys.insert(finding.key.clone());
            shell.open_audit_detail_dialog(finding.key, window, cx);
            assert!(shell.audit_detail_dialog.is_some());
            shell.toggle_audit_show_allowed(cx);
            assert!(shell.audit_detail_dialog.is_none());
            assert!(shell.selected_audit_keys.is_empty());
            let report = shell.rows[0].audit_report.as_mut().unwrap();
            let finding = report.findings[0].clone();
            report.findings = vec![finding; 18];
            report.findings[17].allowed_by = None;
            shell.refresh_audit_table(cx);
            assert_eq!(shell.audit_allowed_total, 17);
            assert_eq!(
                shell.i18n().format(
                    "audit_table.show_allowed",
                    &[("count", shell.audit_allowed_total.to_string())]
                ),
                "Show allowed (17)"
            );
            assert_eq!(findings(shell), 1);
            assert_eq!(
                shell
                    .audit_rows
                    .iter()
                    .find(|row| row.key.item_kind == AuditResultItemKind::Finding)
                    .unwrap()
                    .key
                    .item_index,
                17
            );
            shell.toggle_audit_show_allowed(cx);
            let indices = shell
                .audit_rows
                .iter()
                .filter(|row| row.key.item_kind == AuditResultItemKind::Finding)
                .map(|row| row.key.item_index)
                .collect::<BTreeSet<_>>();
            assert_eq!(indices, (0..16).chain([17]).collect());
        });
        let first = test_audit_row(1, 0, "TestScene", "Example", &["Example"]);
        let mut second = first.clone();
        second.key.item_index = 1;
        second.allowed = Some(AllowlistSource::App);
        let mixed = model(&[first.clone(), second.clone()], true, true);
        assert_eq!(mixed.rows.len(), 2);
        assert_eq!(mixed.rows[0].summary, mixed.rows[1].summary);
        assert_eq!(
            searchable_text_for_audit_row(&mixed.rows[0], SupportedLocale::English),
            searchable_text_for_audit_row(&mixed.rows[1], SupportedLocale::English)
        );
        let clipboard = |row: &super::super::AuditTableRow| {
            build_audit_clipboard_payload(&row.provenance, &row.preview, &row.evidence)
        };
        assert_eq!(clipboard(&mixed.rows[0]), clipboard(&mixed.rows[1]));
        second.allowed = None;
        assert_eq!(model(&[first.clone(), second], true, true).rows.len(), 1);
        let allowed_with = |item_index: usize, hash: &str| {
            let mut row = first.clone();
            row.key.item_index = item_index;
            row.allowed = Some(AllowlistSource::App);
            row.detail_fields.insert(
                0,
                AuditDetailField {
                    kind: AuditDetailFieldKind::AllowHash,
                    raw: hash.to_string(),
                },
            );
            row
        };
        let h1 = format!("sha256:{}", "11".repeat(32));
        let h2 = format!("sha256:{}", "22".repeat(32));
        assert_eq!(
            model(&[allowed_with(2, &h1), allowed_with(3, &h2)], true, true)
                .rows
                .len(),
            2
        );
        assert_eq!(
            model(&[allowed_with(2, &h1), allowed_with(3, &h1)], true, true)
                .rows
                .len(),
            1
        );
    }

    #[gpui::test]
    fn allowed_cleaning_uses_unallowed_targets_and_rejects_stale_files(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("TestScene.ma");
        fs::write(&path, SCENE).unwrap();
        let allowlist = example_allowlist();
        let plan = gui_audit_plan(allowlist.clone()).unwrap();
        let mut row = current_row(1, &path, &plan);
        assert!(
            !file_context_menu_state(
                std::slice::from_ref(&row),
                1,
                AuditModePreference::StrictDefault
            )
            .can_clean
        );
        let rows = build_audit_result_rows(
            std::slice::from_ref(&row),
            &[0],
            &allowlist,
            &I18n::new(SupportedLocale::English),
        );
        let allowed = model(&rows, true, false)
            .rows
            .into_iter()
            .find(|row| row.key.item_kind == AuditResultItemKind::Finding)
            .unwrap();
        assert_eq!(allowed.clean_state, AuditRowCleanState::Available);
        assert!(audit_context_menu_state(&[allowed]).can_clean);
        let report = row.audit_report.as_mut().unwrap();
        let mut surface = report.surface_for(&report.findings[0]).clone();
        surface.origin.node_name = Some("SampleScriptNode".into());
        let surface_index = report.surfaces.len();
        report.surfaces.push(surface);
        let mut allowed = report.findings[0].clone();
        allowed.surface_index = surface_index;
        let mut threat = allowed.clone();
        threat.allowed_by = None;
        report.findings.extend([allowed, threat]);
        assert_eq!(
            clean_targets_for_threat_findings(&row),
            vec![ExecutionCleanTarget::ScriptNode {
                node_name: "SampleScriptNode".into()
            }]
        );
        assert!(
            file_context_menu_state(
                std::slice::from_ref(&row),
                1,
                AuditModePreference::StrictDefault
            )
            .can_clean
        );
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, _, _| {
            shell.replace_rows(vec![row]);
            assert_eq!(shell.file_threat_clean_targets_by_row(vec![0]).len(), 1);
            shell.rows[0]
                .pending_clean_targets
                .insert(ExecutionCleanTarget::ScriptNode {
                    node_name: "ExampleScriptNode".into(),
                });
            let pending = shell.rows[0].pending_clean_targets.clone();
            shell.rows[0].mark_analysis_stale();
            assert!(shell.file_threat_clean_targets_by_row(vec![0]).is_empty());
            assert!(!file_context_menu_state(&shell.rows, 1, shell.state.audit_mode).can_clean);
            assert_eq!(shell.rows[0].pending_clean_targets, pending);
        });
    }

    fn open_shell_with_allowlist_paths(
        cx: &mut TestAppContext,
        app: PathBuf,
        user: PathBuf,
        cache: PathBuf,
    ) -> (Entity<GuiShell>, &mut VisualTestContext) {
        cx.update(init_gui_app);
        let slot = Rc::new(RefCell::new(None));
        let built = slot.clone();
        let (_, visual_cx) = cx.add_window_view(|window, cx| {
            let menu_bar = TopMenuBar::new(window, cx);
            let shell = cx.new(|cx| {
                GuiShell::new_with_state_and_cache_root(
                    menu_bar,
                    window,
                    cx,
                    PersistedState::default(),
                    cache,
                    None,
                    Some(app),
                    Some(user),
                )
            });
            built.replace(Some(shell.clone()));
            Root::new(shell, window, cx)
        });
        let shell = slot.borrow().clone().unwrap();
        (shell, visual_cx)
    }

    #[gpui::test]
    fn allowlist_errors_remain_visible_after_scan_and_analysis(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let app = dir.path().join("ExampleApp/allowlist.json");
        let user = dir.path().join("ExampleUser/allowlist.json");
        {
            let (shell, visual_cx) = open_shell_with_allowlist_paths(
                cx,
                app.clone(),
                user.clone(),
                dir.path().join("ExampleCache"),
            );
            shell.update_in(visual_cx, |shell, _, _| {
                assert_eq!(shell.audit_allowlist.len_entries(), 0);
                assert!(shell.allowlist_load_errors.is_empty());
                assert!(
                    allowlist_error_text(&shell.allowlist_load_errors, &shell.i18n()).is_none()
                );
                assert!(shell.status_message.is_none());
                assert_eq!(
                    shell.i18n().format(
                        "audit_table.show_allowed",
                        &[("count", shell.audit_allowed_total.to_string())]
                    ),
                    "Show allowed (0)"
                );
            });
        }
        fs::create_dir_all(app.parent().unwrap()).unwrap();
        fs::create_dir_all(user.parent().unwrap()).unwrap();
        let hash = format!("sha256:{}", "11".repeat(32));
        fs::write(
            &app,
            json!({"version":1,"entries":[{"hash":hash,"codes":["mel_exec"],
            "label":"Example","preview":"Example preview","reason":"Example reason",
            "added_at":"2026-11-07","added_by":"Example"}]})
            .to_string(),
        )
        .unwrap();
        fs::write(&user, "{").unwrap();
        let root = dir.path().join("ExampleWorkspace");
        fs::create_dir(&root).unwrap();
        let path = root.join("TestScene.ma");
        fs::write(&path, SCENE).unwrap();
        let error = AuditAllowlist::from_json("{", AllowlistSource::User)
            .unwrap_err()
            .to_string();
        let (shell, visual_cx) =
            open_shell_with_allowlist_paths(cx, app, user.clone(), dir.path().join("SampleCache"));
        let check_error = |shell: &GuiShell| {
            assert_eq!(shell.audit_allowlist.len_entries(), 1);
            assert_eq!(shell.allowlist_load_errors.len(), 1);
            let text = allowlist_error_text(&shell.allowlist_load_errors, &shell.i18n()).unwrap();
            assert!(text.contains(user.to_str().unwrap()));
            assert!(text.contains(&error));
        };
        shell.update_in(visual_cx, |shell, window, cx| {
            check_error(shell);
            shell.set_workspace_folder(root, window, cx);
            assert!(shell.workspace_scan_active());
            check_error(shell);
        });
        visual_cx.run_until_parked();
        shell.update_in(visual_cx, |shell, window, cx| {
            assert!(!shell.workspace_scan_active());
            check_error(shell);
            let id = shell.rows[0].id;
            let result = analyze(&path, &shell.audit_plan);
            shell.apply_job_result(
                id,
                RowOperation::Analyze,
                RowJobResult::Analyze(result),
                None,
                window,
                cx,
            );
            assert!(matches!(
                shell.status_message,
                Some(BannerMessage::AnalyzeCompleted { .. })
            ));
            check_error(shell);
            assert!(shell.rows[0].analysis_current_for(shell.state.audit_mode));
        });
    }

    #[gpui::test]
    fn undo_restoring_a_report_from_another_plan_leaves_the_row_stale(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("TestScene.ma");
        fs::write(&path, SCENE).unwrap();
        let old_plan = gui_audit_plan(example_allowlist()).unwrap();
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, _, cx| {
            shell.state.workspace_auto_analyze = false;
            shell.state.analysis_cache_enabled = false;
            let current = current_row(1, &path, &shell.audit_plan);
            let old = current_row(1, &path, &old_plan);
            let entry = super::super::GuiEditHistoryEntry {
                transitions: vec![super::super::RowEditTransition {
                    row_id: 1,
                    before: old.edit_state(),
                    after: current.edit_state(),
                }],
            };
            shell.replace_rows(vec![current]);
            shell.apply_edit_history_entry(&entry, true, cx);
            assert!(shell.rows[0].analysis_current_for(AuditModePreference::StrictDefault));
            shell.apply_edit_history_entry(&entry, false, cx);
            assert!(shell.rows[0].audit_report.is_some());
            assert!(!shell.rows[0].analysis_current_for(AuditModePreference::StrictDefault));
            assert!(shell.file_threat_clean_targets_by_row(vec![0]).is_empty());
        });
    }

    #[gpui::test]
    fn reload_preserves_edits_and_rejects_old_job_and_cache_plans(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("TestScene.ma");
        fs::write(&path, SCENE).unwrap();
        let list_path = dir.path().join("allowlist.json");
        let empty_plan = gui_audit_plan(AuditAllowlist::default()).unwrap();
        let old_fingerprint = fingerprint_audit_plan(&empty_plan);
        let old_analyze = analyze(&path, &empty_plan);
        let old_snapshot = old_analyze.audit_snapshot.clone().unwrap();
        let old_staged = staged_clean_result(&path, "ExampleScriptNode");
        let mut dirty = current_row(2, &path, &empty_plan);
        let RowJobResult::SceneEdits {
            staged,
            staged_source_bytes,
            ..
        } = staged_clean_result(&path, "ExampleScriptNode")
        else {
            panic!("expected staged edits");
        };
        dirty.dirty_artifact = Some(staged.artifact);
        dirty.staged_source_bytes = Some(staged_source_bytes);
        dirty.staged_audit_report = dirty.audit_report.clone();
        dirty.staged_audit_mode = Some(AuditModePreference::StrictDefault);
        dirty.staged_audit_plan_fingerprint = Some(old_fingerprint.clone());
        dirty.dirty_kind = Some(DirtyKind::SceneEdits);
        dirty
            .pending_clean_targets
            .insert(ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScriptNode".into(),
            });
        dirty
            .path_overrides
            .insert(0, "asset/example/file.fbx".into());
        let saved_artifact = dirty.dirty_artifact.clone();
        let saved_bytes = dirty.staged_source_bytes.clone();
        let saved_targets = dirty.pending_clean_targets.clone();
        let saved_overrides = dirty.path_overrides.clone();
        let (shell, visual_cx) = open_test_shell(cx);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.state.workspace_auto_analyze = false;
            shell.state.analysis_cache_enabled = false;
            shell.app_allowlist_path = Some(list_path.clone());
            shell.replace_rows(vec![current_row(1, &path, &empty_plan), dirty, test_row(3, &path)]);
            fs::write(&list_path, list_json("Example reason")).unwrap();
            shell.workspace_scan_state.in_flight = true;
            let generation = shell.cache_restore_generation;
            let selected_generation = shell.selected_auto_analyze_generation;
            shell.reload_allowlists(window, cx);
            assert_eq!(shell.cache_restore_generation, generation);
            assert_eq!(shell.selected_auto_analyze_generation, selected_generation);
            assert!(!shell.rows[0].analysis_current_for(AuditModePreference::StrictDefault));
            assert!(!shell.rows[1].analysis_current_for(AuditModePreference::StrictDefault));
            assert_eq!(shell.rows[1].staged_audit_mode, None);
            assert_eq!(shell.rows[1].dirty_artifact, saved_artifact);
            assert_eq!(shell.rows[1].staged_source_bytes, saved_bytes);
            assert_eq!(shell.rows[1].pending_clean_targets, saved_targets);
            assert_eq!(shell.rows[1].path_overrides, saved_overrides);
            assert!(matches!(shell.status_message, Some(BannerMessage::AllowlistsReloaded { count: 1, stale_rows: 2 })));
            let banner = render_banner_message(&shell.i18n(), shell.status_message.as_ref().unwrap());
            assert_eq!(banner, "Reloaded allowlists: 1 entries 2 file(s) need re-audit; files with unsaved edits update after saving");
            shell.workspace_scan_state.in_flight = false;
            shell.rows[0] = current_row(1, &path, &shell.audit_plan);
            shell.rows[0].selected = true;
            shell.audit_show_allowed = true;
            let fingerprint = shell.audit_plan_fingerprint.clone();
            shell.reload_allowlists(window, cx);
            assert!(shell.rows[0].analysis_current_for(AuditModePreference::StrictDefault));
            assert_eq!(shell.audit_plan_fingerprint, fingerprint);
            assert!(matches!(shell.status_message, Some(BannerMessage::AllowlistsReloaded { count: 1, stale_rows: 0 })));
            fs::write(&list_path, list_json("Sample reason")).unwrap();
            shell.reload_allowlists(window, cx);
            assert_eq!(shell.audit_plan_fingerprint, fingerprint);
            assert!(shell.rows[0].analysis_current_for(AuditModePreference::StrictDefault));
            let finding = shell.audit_rows.iter().find(|row| row.key.item_kind == AuditResultItemKind::Finding).unwrap();
            assert_eq!(finding.detail_fields[0].raw, "Sample reason (Distributed (app))");
            shell.rows[0].selected = false;
            shell.file_table_viewport_range = 0..0;
            shell.apply_job_result(1, RowOperation::Analyze, RowJobResult::Analyze(old_analyze), None, window, cx);
            assert!(shell.rows[0].audit_report.is_some());
            assert!(!shell.rows[0].analysis_current_for(AuditModePreference::StrictDefault));
            shell.apply_job_result(2, RowOperation::Clean, old_staged, None, window, cx);
            assert!(shell.rows[1].dirty_artifact.is_some());
            assert_eq!(shell.rows[1].staged_audit_plan_fingerprint.as_deref(), Some(old_fingerprint.as_str()));
            assert_eq!(shell.rows[1].staged_audit_mode, None);
            assert!(!shell.rows[1].analysis_current_for(AuditModePreference::StrictDefault));
            let edit_state = shell.rows[1].edit_state();
            shell.rows[1].apply_edit_state(&edit_state);
            assert_eq!(shell.rows[1].staged_audit_plan_fingerprint.as_deref(), Some(old_fingerprint.as_str()));
            let audit_generation = shell.rows[1].audit_generation;
            shell.apply_job_result(2, RowOperation::Save, RowJobResult::Save {
                output_path: path.clone(), audit_file_state: GuiFileState::read(&path).ok(),
            }, None, window, cx);
            assert_eq!(shell.rows[1].audit_generation, audit_generation);
            assert!(!shell.rows[1].analysis_current_for(AuditModePreference::StrictDefault));
            assert!(shell.rows[1].dirty_artifact.is_none());
            assert!(shell.rows[1].staged_audit_plan_fingerprint.is_none());
            let generation = shell.rows[2].audit_generation;
            shell.apply_cache_restore_updates(vec![super::super::cache_restore::CacheHydrationUpdate {
                row_id: 3, observe_snapshot: None, observe_access: None,
                audit_snapshot: Some(old_snapshot), audit_access: None,
            }], &old_fingerprint, window, cx);
            assert_eq!(shell.rows[2].audit_generation, generation);
            assert!(shell.rows[2].audit_report.is_none());
            // Reload starts a new cache-restore generation, so the in-flight batch with a cache hit is dropped.
            let cached = analyze(&path, &shell.audit_plan);
            AuditCacheStore::new(&shell.audit_cache_root)
                .save(&cached.audit_snapshot.unwrap()).unwrap();
            ObserveCacheStore::new(&shell.observe_cache_root)
                .save(&cached.observe_snapshot.unwrap()).unwrap();
            shell.state.analysis_cache_enabled = true;
            shell.start_progressive_cache_restore(window, cx);
            let generation = shell.cache_restore_generation;
            fs::write(&list_path, "{\"version\":1,\"entries\":[]}").unwrap();
            shell.reload_allowlists(window, cx);
            assert_ne!(shell.cache_restore_generation, generation);
            shell.cancel_progressive_cache_restore();
        });
    }

    #[test]
    fn allowed_details_preserve_metadata_source_and_localized_fallbacks() {
        use AuditDetailFieldKind::{AllowHash, Allowed, RuleId};
        let hash = format!("sha256:{}", "11".repeat(32));
        let origin = ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            attr_name: Some(".b".into()),
            trigger: ExecutionTrigger::FileOpen,
            ..ExecutionOrigin::without_chunk_address()
        };
        let list = |reason: Option<&str>, label: Option<&str>, source| {
            AuditAllowlist::from_json(
            &json!({"version":1,"entries":[{"hash":hash,"codes":["mel_exec"],"reason":reason,"label":label}]}).to_string(), source,
        ).unwrap()
        };
        let allowed = AuditAllowRef {
            hash: hash.parse().unwrap(),
            source: AllowlistSource::App,
        };
        for (locale, app_source, user_source) in [
            (SupportedLocale::English, "Distributed (app)", "User (user)"),
            (
                SupportedLocale::Japanese,
                "管理者配布 (app)",
                "ユーザー (user)",
            ),
            (SupportedLocale::Chinese, "管理员分发 (app)", "用户 (user)"),
        ] {
            let i18n = I18n::new(locale);
            let fields = build_audit_detail_fields(
                "mel_exec",
                "mel_exec",
                &origin,
                Some(4),
                Some(&allowed),
                &list(
                    Some("Example reason"),
                    Some("Example"),
                    AllowlistSource::App,
                ),
                &i18n,
            );
            assert_eq!(
                [fields[0].kind, fields[1].kind, fields[2].kind],
                [Allowed, AllowHash, RuleId]
            );
            assert_eq!(fields[0].raw, format!("Example reason ({app_source})"));
            assert_eq!(fields[1].raw, hash);
            let user_ref = AuditAllowRef {
                source: AllowlistSource::User,
                ..allowed.clone()
            };
            for (reason, label, value) in [
                (None, Some("Example"), "Example"),
                (None, None, "-"),
                (Some("  "), Some("Example"), "Example"),
            ] {
                let fields = build_audit_detail_fields(
                    "mel_exec",
                    "mel_exec",
                    &origin,
                    Some(4),
                    Some(&user_ref),
                    &list(reason, label, AllowlistSource::User),
                    &i18n,
                );
                assert_eq!(fields[0].raw, format!("{value} ({user_source})"));
            }
            let plain = build_audit_detail_fields(
                "mel_exec",
                "mel_exec",
                &origin,
                Some(4),
                None,
                &AuditAllowlist::default(),
                &i18n,
            );
            assert_eq!(&fields[2..], plain);
        }
        let merged = AuditAllowlist::merge([
            list(
                Some("Example reason"),
                Some("Example"),
                AllowlistSource::App,
            ),
            AuditAllowlist::from_json(
                &json!({"version":1,"entries":[{"hash":hash,"codes":["mel_eval"]}]}).to_string(),
                AllowlistSource::User,
            )
            .unwrap(),
        ]);
        let user_ref = AuditAllowRef {
            source: AllowlistSource::User,
            ..allowed
        };
        let fields = build_audit_detail_fields(
            AuditFindingCode::MelEval.as_str(),
            "mel_eval",
            &origin,
            None,
            Some(&user_ref),
            &merged,
            &I18n::new(SupportedLocale::English),
        );
        assert_eq!(fields[0].raw, "Example reason (User (user))");
        let dir = tempdir().unwrap();
        let path = dir.path().join("TestScene.ma");
        fs::write(&path, SCENE).unwrap();
        let empty = gui_audit_plan(AuditAllowlist::default()).unwrap();
        let plain_row = current_row(1, &path, &empty);
        let allowed_row = current_row(1, &path, &gui_audit_plan(example_allowlist()).unwrap());
        let i18n = I18n::new(SupportedLocale::English);
        let plain = build_audit_result_rows(&[plain_row], &[0], &AuditAllowlist::default(), &i18n);
        let allowed = build_audit_result_rows(&[allowed_row], &[0], &example_allowlist(), &i18n);
        for (plain, allowed) in plain.iter().zip(&allowed) {
            assert_eq!(
                build_audit_clipboard_payload(&plain.provenance, &plain.preview, &plain.evidence),
                build_audit_clipboard_payload(
                    &allowed.provenance,
                    &allowed.preview,
                    &allowed.evidence
                )
            );
            if plain.key.item_kind != AuditResultItemKind::Finding {
                assert_eq!(plain.detail_fields, allowed.detail_fields);
            } else {
                assert_eq!(plain.detail_fields, allowed.detail_fields[2..]);
            }
        }
    }
}

#[gpui::test]
fn path_override_failure_preserves_history(cx: &mut TestAppContext) {
    check_path_override_failure(cx, false);
}

#[gpui::test]
fn path_override_failure_preserves_pending_transaction(cx: &mut TestAppContext) {
    check_path_override_failure(cx, true);
}

fn check_path_override_failure(cx: &mut TestAppContext, pending: bool) {
    let (shell, visual_cx) = open_test_shell(cx);
    visual_cx.update(|window, app| {
        shell.update(app, |shell, cx| {
            let mut first = SceneRow::new_unloaded_row(1);
            first.paths_report = Some(super::ScenePathsReport {
                entries: Vec::new(),
                scene_path: "asset/example/TestScene.ma".into(),
                scene_format: maya_scene_kit_observe::scene::SceneFormat::Ma,
                validation_state: maya_scene_kit_observe::scene::ValidationState::Validated,
            });
            first
                .path_overrides
                .insert(0, "asset/example/Example.tx".into());
            first
                .pending_path_owner_delete_targets
                .insert(PathOwnerDeleteTarget {
                    node_type: "file".into(),
                    node_name: "Example".into(),
                });
            shell.rows = vec![first, SceneRow::new_unloaded_row(2)];
            if pending {
                shell.begin_edit_transaction(&[1]);
            }
            let transactions = shell.pending_edit_transactions.len();
            let sequence = shell.next_edit_history_sequence;
            let commit_sequence = shell.next_edit_history_commit_sequence;
            let undo = shell.undo_stack.len();
            let redo = shell.redo_stack.len();
            let overrides = shell.rows[0].path_overrides.clone();
            let generation = shell.rows[0].replace_generation;
            shell.undo_path_edit_targets(vec![(1, 0), (2, 0)], window, cx);
            assert_eq!(shell.rows[0].path_overrides, overrides);
            assert_eq!(shell.rows[0].replace_generation, generation);
            assert_eq!(shell.pending_edit_transactions.len(), transactions);
            assert_eq!(shell.next_edit_history_sequence, sequence);
            assert_eq!(shell.next_edit_history_commit_sequence, commit_sequence);
            assert_eq!(shell.undo_stack.len(), undo);
            assert_eq!(shell.redo_stack.len(), redo);
        });
    });
}
