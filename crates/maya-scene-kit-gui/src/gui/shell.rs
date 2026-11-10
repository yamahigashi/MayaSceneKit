use maya_scene_kit_edit::scene::{MaterializeOptions, OperationMode};

use super::*;

impl GuiShell {
    pub(super) fn startup_banner_message(&self) -> Option<&BannerMessage> {
        self.startup_banner.as_ref().map(|(_, message)| message)
    }

    pub(super) fn dismiss_startup_banner(&mut self) {
        self.startup_banner = None;
    }

    fn show_startup_banner(&mut self, importance: StartupBannerImportance, message: BannerMessage) {
        if self
            .startup_banner
            .as_ref()
            .is_none_or(|(current, _)| importance >= *current)
        {
            self.startup_banner = Some((importance, message));
        }
    }

    pub(super) fn new(menu_bar: TopMenuBar, window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self::new_with_loaded_settings(menu_bar, window, cx, load_persisted_state())
    }

    pub(super) fn new_with_loaded_settings(
        menu_bar: TopMenuBar,
        window: &mut Window,
        cx: &mut Context<Self>,
        loaded: crate::persistence::LoadedSettings,
    ) -> Self {
        let mut shell = Self::new_with_state_and_cache_root(
            menu_bar,
            window,
            cx,
            loaded.state,
            default_analysis_cache_root(),
            Some(default_plugin_dir_from_state_path(&default_state_path())),
            app_allowlist_path(std::env::current_exe().ok().as_deref()),
            user_allowlist_path(&default_state_path()),
        );
        shell.apply_settings_recovery(loaded.recovery.as_ref());
        shell
    }

    pub(super) fn apply_settings_recovery(
        &mut self,
        recovery: Option<&crate::persistence::SettingsRecovery>,
    ) {
        if let Some(recovery) = recovery {
            let mut message = recovery.banner(&self.i18n());
            if let Some(root) = self
                .state
                .workspace_root
                .as_ref()
                .filter(|root| !root.is_dir())
            {
                message.push('\n');
                message.push_str(&self.i18n().format(
                    "banner.workspace_unavailable",
                    &[("path", root.display().to_string())],
                ));
            }
            let importance = if recovery.saving_disabled {
                self.settings_save_disabled_path = Some(recovery.path.clone());
                self.cancel_persist_flush();
                StartupBannerImportance::Error
            } else {
                StartupBannerImportance::Warning
            };
            self.show_startup_banner(importance, BannerMessage::Raw(message));
        }
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        menu_bar: TopMenuBar,
        window: &mut Window,
        cx: &mut Context<Self>,
        state: PersistedState,
        analysis_cache_root: PathBuf,
    ) -> Self {
        Self::new_with_state_and_cache_root(
            menu_bar,
            window,
            cx,
            state,
            analysis_cache_root,
            None,
            None,
            None,
        )
    }

    pub(super) fn new_with_state_and_cache_root(
        menu_bar: TopMenuBar,
        window: &mut Window,
        cx: &mut Context<Self>,
        mut state: PersistedState,
        analysis_cache_root: PathBuf,
        plugin_dir: Option<PathBuf>,
        app_allowlist_path: Option<PathBuf>,
        user_allowlist_path: Option<PathBuf>,
    ) -> Self {
        let loaded = load_allowlists(
            app_allowlist_path.as_deref(),
            user_allowlist_path.as_deref(),
        );
        let audit_plan = Arc::new(
            gui_audit_plan(loaded.allowlist.clone())
                .expect("building an audit plan with no custom rules cannot fail"),
        );
        let audit_plan_fingerprint = fingerprint_audit_plan(&audit_plan);
        state.normalize_ignore_folder_settings();
        state.active_tab = ResultTab::Overview;
        let i18n = I18n::new(state.locale.resolve());
        let search_query = state.search_query.clone();
        let search_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(i18n.text("placeholder.search"))
                .default_value(search_query)
        });
        let path_search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n.text("placeholder.path_search"))
        });
        let audit_search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n.text("placeholder.audit_search"))
        });
        let path_edit_input = cx
            .new(|cx| InputState::new(window, cx).placeholder(i18n.text("placeholder.scene_path")));
        let replace_from_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n.text("placeholder.replace_from"))
        });
        let replace_to_input = cx
            .new(|cx| InputState::new(window, cx).placeholder(i18n.text("placeholder.replace_to")));
        let path_edit_focus_handle = path_edit_input.read(cx).focus_handle(cx);
        let mut next_row_id = 1u64;
        let observe_cache_root = analysis_cache_root.join("observe-v4");
        let audit_cache_root = analysis_cache_root.join("audit-v4");
        let plugin_registry = plugin_dir
            .as_ref()
            .map(|dir| PluginRegistry::load_from_dir(dir))
            .unwrap_or_default();
        let rows = load_rows_from_state(&state, &mut next_row_id);
        let row_id_to_index = rows
            .iter()
            .enumerate()
            .map(|(index, row)| (row.id, index))
            .collect();
        let file_sort = FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        };
        let path_sort = default_path_sort();
        let audit_sort = default_audit_sort();
        let visible_rows = compute_visible_row_indices_for(&rows, &state, file_sort);
        let table_rows = build_file_table_rows(&rows, &visible_rows, &state, &i18n);
        let file_table = cx.new(|cx| {
            TableState::new(
                FileTableDelegate::new(
                    table_rows,
                    i18n.locale(),
                    file_sort,
                    &state.file_table_column_widths,
                ),
                window,
                cx,
            )
            .col_resizable(true)
            .sortable(true)
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
        });
        let file_table_focus_handle = file_table.read(cx).focus_handle(cx);
        let path_table = cx.new(|cx| {
            TableState::new(
                PathTableDelegate::new(
                    Vec::new(),
                    i18n.locale(),
                    path_sort,
                    false,
                    &state.path_table_column_widths,
                ),
                window,
                cx,
            )
            .col_resizable(true)
            .sortable(true)
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
        });
        let audit_table = cx.new(|cx| {
            TableState::new(
                AuditTableDelegate::new(
                    Vec::new(),
                    i18n.locale(),
                    audit_sort,
                    &state.audit_table_column_widths,
                ),
                window,
                cx,
            )
            .col_resizable(true)
            .sortable(true)
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
        });
        let replace_preview_table = cx.new(|cx| {
            TableState::new(
                ReplacePreviewTableDelegate::new(
                    i18n.locale(),
                    ReplaceDialogSort {
                        key: ReplaceDialogSortKey::Before,
                        direction: ColumnSort::Default,
                    },
                ),
                window,
                cx,
            )
            .col_resizable(true)
            .sortable(false)
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
        });
        let path_table_focus_handle = path_table.read(cx).focus_handle(cx);
        let view = cx.entity();
        let close_view = view.clone();
        window.on_window_should_close(cx, move |window, cx| {
            close_view.update(cx, |shell, cx| shell.on_window_should_close(window, cx))
        });
        let path_edit_view = view.clone();
        let path_table_view = view.clone();
        let subscriptions = vec![
            cx.subscribe(
                &replace_preview_table,
                |_: &mut Self, table, event: &TableEvent, cx| {
                    if let TableEvent::ColumnWidthsChanged(widths) = event {
                        let widths = widths.clone();
                        table.update(cx, |table, _| table.delegate_mut().apply_widths(&widths));
                    }
                },
            ),
            cx.subscribe(&search_input, |this: &mut Self, _, ev: &InputEvent, cx| {
                if matches!(ev, InputEvent::Change) {
                    this.apply_search_query(cx);
                }
            }),
            cx.subscribe(
                &path_search_input,
                |this: &mut Self, _, ev: &InputEvent, cx| {
                    if matches!(ev, InputEvent::Change) {
                        this.apply_path_search_query(cx);
                    }
                },
            ),
            cx.subscribe(
                &audit_search_input,
                |this: &mut Self, _, ev: &InputEvent, cx| {
                    if matches!(ev, InputEvent::Change) {
                        this.apply_audit_search_query(cx);
                    }
                },
            ),
            cx.subscribe_in(
                &path_edit_input,
                window,
                |this: &mut Self, _, ev: &InputEvent, window, cx| {
                    if matches!(ev, InputEvent::PressEnter { secondary: false })
                        && matches!(
                            this.path_edit_keyboard_outcome("enter", window, cx),
                            PathEditKeyboardOutcome::Apply
                        )
                    {
                        this.apply_path_edit(window, cx);
                    }
                },
            ),
            cx.subscribe(
                &replace_from_input,
                |this: &mut Self, _, ev: &InputEvent, cx| {
                    if matches!(ev, InputEvent::Change) {
                        this.on_replace_dialog_inputs_changed(cx);
                    }
                },
            ),
            cx.subscribe(
                &replace_to_input,
                |this: &mut Self, _, ev: &InputEvent, cx| {
                    if matches!(ev, InputEvent::Change) {
                        this.on_replace_dialog_inputs_changed(cx);
                    }
                },
            ),
            cx.on_focus_out(
                &path_edit_focus_handle,
                window,
                move |this, _event, window, cx| {
                    if this.active_path_edit.is_none() {
                        return;
                    }
                    let view = path_edit_view.clone();
                    window.defer(cx, move |_window, cx| {
                        view.update(cx, |shell, cx| {
                            if shell.active_path_edit.is_some() {
                                shell.cancel_path_edit_state(cx);
                            }
                        });
                    });
                },
            ),
            cx.on_focus_out(
                &path_table_focus_handle,
                window,
                move |this, _event, window, cx| {
                    if this.active_path_edit.is_some() || this.selected_path_rows.is_empty() {
                        return;
                    }
                    let view = path_table_view.clone();
                    window.defer(cx, move |_window, cx| {
                        view.update(cx, |shell, cx| {
                            if shell.suppress_next_path_focus_out_clear {
                                shell.suppress_next_path_focus_out_clear = false;
                                return;
                            }
                            if shell.active_path_edit.is_none() {
                                shell.selected_path_rows.clear();
                                shell.path_selection_anchor = None;
                                shell.path_table.update(cx, |table, cx| {
                                    table.clear_selection(cx);
                                });
                                shell.refresh_path_table(cx);
                                cx.notify();
                            }
                        });
                    });
                },
            ),
        ];

        let mut shell = Self {
            audit_allowlist: loaded.allowlist,
            allowlist_load_errors: loaded.errors,
            allowlist_manager: None,
            audit_plan,
            audit_plan_fingerprint,
            app_allowlist_path,
            user_allowlist_path,
            audit_show_allowed: false,
            audit_allowed_total: 0,
            state,
            rows,
            row_id_to_index,
            visible_rows,
            menu_bar,
            focus_handle: cx.focus_handle(),
            search_input,
            path_search_input,
            audit_search_input,
            path_edit_input,
            replace_from_input,
            replace_to_input,
            file_table,
            file_table_focus_handle,
            path_table,
            path_table_focus_handle,
            path_table_summary: PathTableSummary::default(),
            audit_table,
            replace_preview_table,
            audit_all_rows: Vec::new(),
            audit_rows: Vec::new(),
            file_sort,
            path_sort,
            path_order_snapshot: None,
            audit_sort,
            next_row_id,
            selection_anchor: None,
            selected_auto_analyze_generation: 0,
            workspace_auto_analyze_generation: 0,
            file_dialog_block_generation: 0,
            auto_analyze_queue: AutoAnalyzeQueueState::default(),
            file_dialog_ui_blocked: false,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            next_row_job_id: 1,
            audit_refresh_batch_depth: 0,
            mutation_banner_depth: 0,
            audit_refresh_pending: false,
            #[cfg(test)]
            audit_refresh_count: 0,
            next_edit_history_sequence: 0,
            next_edit_history_commit_sequence: 0,
            pending_edit_transactions: BTreeMap::new(),
            completed_edit_history: BTreeMap::new(),
            workspace_auto_analyze_started_at: None,
            file_table_viewport_range: 0..0,
            workspace_scan_state: WorkspaceScanState::default(),
            cache_restore_generation: 0,
            cache_restore_state: CacheRestoreState::default(),
            cache_write_generation: 0,
            cache_write_state: CacheWriteState::default(),
            cache_maintenance_generation: 0,
            cache_maintenance_state: CacheMaintenanceState::default(),
            cache_restore_refresh_state: CacheRestoreRefreshState::default(),
            auto_analyze_refresh_state: AutoAnalyzeRefreshState::default(),
            path_resolution_refresh_state: PathResolutionRefreshState::default(),
            persist_flush_state: PersistFlushState::default(),
            active_path_edit: None,
            path_search_in_flight: false,
            selected_path_rows: BTreeSet::new(),
            path_selection_anchor: None,
            suppress_next_path_focus_out_clear: false,
            path_table_dedup: false,
            path_dirty_only: false,
            path_search_query: String::new(),
            audit_table_dedup: false,
            audit_dirty_only: false,
            audit_search_query: String::new(),
            selected_audit_keys: BTreeSet::new(),
            audit_selection_anchor: None,
            path_type_filter: default_path_type_filter(),
            path_form_filter: default_path_form_filter(),
            path_resolution_filter: default_path_resolution_filter(),
            audit_severity_filter: default_audit_severity_filter(),
            audit_detail_dialog: None,
            audit_detail_code_request: 0,
            audit_detail_allow_request: 0,
            audit_allow_in_flight: false,
            plugin_registry,
            status_message: None,
            startup_banner: None,
            settings_save_disabled_path: None,
            settings_save_skip_logged: false,
            max_bytes_dialog: None,
            ignore_folder_names_dialog: None,
            replace_dialog: None,
            path_collect_dialog: None,
            observe_cache_root,
            audit_cache_root,
            exit_confirmation_pending: false,
            bypass_next_exit_warning: false,
            _subscriptions: subscriptions,
        };
        if let Some(root) = shell.state.workspace_root_path() {
            if root.is_dir() {
                shell.rescan_workspace_with_current_settings(window, cx);
            } else {
                shell.show_startup_banner(
                    StartupBannerImportance::Warning,
                    BannerMessage::Raw(shell.i18n().format(
                        "banner.workspace_unavailable",
                        &[("path", root.display().to_string())],
                    )),
                );
            }
        } else {
            shell.start_progressive_cache_restore(window, cx);
        }
        shell
    }

    pub(super) fn bind_file_table(&mut self, view: Entity<Self>, cx: &mut Context<Self>) {
        let file_table_focus_handle = self.file_table_focus_handle.clone();
        self.file_table.update(cx, |table, cx| {
            table.delegate_mut().set_view(view.clone());
            table
                .delegate_mut()
                .set_focus_handle(file_table_focus_handle.clone());
            table.refresh(cx);
        });
        self.path_table.update(cx, |table, cx| {
            table.delegate_mut().set_view(view.clone());
            table.refresh(cx);
        });
        self.audit_table.update(cx, |table, cx| {
            table.delegate_mut().set_view(view.clone());
            table.refresh(cx);
        });
        self.replace_preview_table.update(cx, |table, cx| {
            table.delegate_mut().set_view(view);
            table.refresh(cx);
        });
    }

    pub(super) fn locale(&self) -> SupportedLocale {
        self.state.locale.resolve()
    }

    pub(super) fn i18n(&self) -> I18n {
        I18n::new(self.locale())
    }

    pub(super) fn scene_load_options(&self) -> LoadOptions {
        let mut options = LoadOptions::default();
        if let Some(max_bytes) = self.state.max_bytes {
            options = options.with_max_parse_bytes(max_bytes);
        }
        options
    }

    pub(super) fn scene_materialize_options(&self, mode: OperationMode) -> MaterializeOptions {
        MaterializeOptions::new(self.scene_load_options()).with_operation_mode(mode)
    }

    pub(super) fn cache_restore_active(&self) -> bool {
        self.cache_restore_state.in_flight || !self.cache_restore_state.pending.is_empty()
    }

    pub(super) fn workspace_scan_active(&self) -> bool {
        self.workspace_scan_state.in_flight
    }

    pub(super) fn cache_restore_message(&self, i18n: &I18n) -> Option<String> {
        self.cache_restore_active().then(|| {
            i18n.format(
                "banner.cache_restore_in_progress",
                &[
                    (
                        "completed",
                        self.cache_restore_state.completed_count.to_string(),
                    ),
                    ("total", self.cache_restore_state.total_count.to_string()),
                ],
            )
        })
    }

    pub(super) fn workspace_scan_message(&self, i18n: &I18n) -> Option<String> {
        self.workspace_scan_active()
            .then(|| i18n.text("banner.workspace_scan_in_progress"))
    }

    pub(super) fn backup_location_label(&self, i18n: &I18n) -> String {
        backup_location_label(i18n, self.state.backup_location)
    }
}
