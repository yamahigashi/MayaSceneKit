use super::*;
use std::{fs, io};

struct WorkspaceScanResult {
    root: PathBuf,
    files: Vec<DiscoveredSceneFile>,
    kind: WorkspaceScanKind,
}

#[derive(Clone, Copy)]
enum ExitRequestKind {
    Application,
}

pub(super) fn exit_warning_required_for_rows(rows: &[SceneRow]) -> bool {
    rows.iter().any(SceneRow::dirty)
}

impl GuiShell {
    pub(super) fn request_exit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.exit_confirmation_pending {
            return;
        }
        if self.exit_warning_required() {
            self.confirm_exit_request(ExitRequestKind::Application, window, cx);
            return;
        }

        self.complete_exit_request(window);
        cx.notify();
    }

    pub(super) fn on_window_should_close(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.bypass_next_exit_warning {
            self.bypass_next_exit_warning = false;
            return true;
        }

        self.request_exit(window, cx);
        false
    }

    pub(super) fn exit_warning_required(&self) -> bool {
        exit_warning_required_for_rows(&self.rows)
    }

    fn confirm_exit_request(
        &mut self,
        kind: ExitRequestKind,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.exit_confirmation_pending = true;
        let i18n = self.i18n();
        let response = window.prompt(
            PromptLevel::Warning,
            &i18n.text("dialog.confirm_exit_application_title"),
            Some(&i18n.text("dialog.confirm_exit_application_description")),
            &[
                PromptButton::cancel(i18n.text("action.return_to_application")),
                PromptButton::ok(i18n.text("action.discard_edits_and_exit")),
            ],
            cx,
        );
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let mut async_cx = cx.clone();
                async move {
                    let answer = response.await.ok();
                    let _ = async_cx.update_window_entity(
                        &view,
                        move |shell: &mut GuiShell,
                              window: &mut Window,
                              cx: &mut Context<GuiShell>| {
                            shell.exit_confirmation_pending = false;
                            if answer != Some(1) {
                                cx.notify();
                                return;
                            }
                            match kind {
                                ExitRequestKind::Application => shell.complete_exit_request(window),
                            }
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    fn complete_exit_request(&mut self, window: &mut Window) {
        self.bypass_next_exit_warning = true;
        window.remove_window();
    }

    pub(super) fn confirm_purge_analysis_cache(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let i18n = self.i18n();
        let response = window.prompt(
            PromptLevel::Warning,
            &i18n.text("dialog.confirm_purge_analysis_cache_title"),
            Some(&i18n.text("dialog.confirm_purge_analysis_cache_description")),
            &[
                PromptButton::cancel(i18n.text("action.cancel")),
                PromptButton::ok(i18n.text("settings.purge_analysis_cache")),
            ],
            cx,
        );
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let mut async_cx = cx.clone();
                async move {
                    let Ok(answer) = response.await else {
                        return;
                    };
                    if answer != 1 {
                        return;
                    }
                    let _ = async_cx.update_window_entity(
                        &view,
                        move |shell: &mut GuiShell,
                              window: &mut Window,
                              cx: &mut Context<GuiShell>| {
                            shell.purge_analysis_cache(window, cx);
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn set_file_table_column_widths(&mut self, widths: Vec<PersistedTableColumnWidth>) {
        if self.state.file_table_column_widths == widths {
            return;
        }
        self.state.file_table_column_widths = widths;
        self.persist();
    }

    pub(super) fn set_path_table_column_widths(&mut self, widths: Vec<PersistedTableColumnWidth>) {
        if self.state.path_table_column_widths == widths {
            return;
        }
        self.state.path_table_column_widths = widths;
        self.persist();
    }

    pub(super) fn set_audit_table_column_widths(&mut self, widths: Vec<PersistedTableColumnWidth>) {
        if self.state.audit_table_column_widths == widths {
            return;
        }
        self.state.audit_table_column_widths = widths;
        self.persist();
    }

    pub(super) fn refresh_app_menus(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let menus = build_app_menus(
            &self.state,
            &self.i18n(),
            !self.undo_stack.is_empty(),
            !self.redo_stack.is_empty(),
        );
        cx.set_menus(menus);
        let menu_bar = self.menu_bar.clone();
        let action_context = self.focus_handle.clone();
        window.defer(cx, move |window, cx| {
            if let TopMenuBar::Windows(menu_bar) = &menu_bar {
                menu_bar.update(cx, |menu_bar, cx| {
                    menu_bar.reload_from_app(window, action_context.clone(), cx);
                });
            }
        });
    }

    pub(super) fn persist(&mut self) {
        self.flush_persist_now(true);
    }

    pub(super) fn add_recent_input(&mut self, path: &Path, was_directory: bool) {
        let input = RecentInput {
            path: path.to_path_buf(),
            was_directory,
        };
        self.state
            .recent_inputs
            .retain(|entry| entry.path != input.path);
        self.state.recent_inputs.insert(0, input.clone());
        self.state.recent_inputs.truncate(MAX_RECENT_FOLDERS);
        self.state.last_opened_input = Some(input);
    }

    pub(super) fn open_recent_folder(
        &mut self,
        index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(folder) = self
            .state
            .recent_folders(MAX_RECENT_FOLDERS)
            .get(index)
            .cloned()
        else {
            return;
        };

        if !folder.is_dir() {
            self.status_message = Some(BannerMessage::Raw(format!(
                "Recent folder not found: {}",
                folder.display()
            )));
            return;
        }

        self.set_workspace_folder(folder, window, cx);
    }

    pub(super) fn remove_recent_folder_by_display(
        &mut self,
        display: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(folder) = self
            .state
            .remove_recent_folder_by_display(display, MAX_RECENT_FOLDERS)
        else {
            return;
        };

        self.status_message = Some(BannerMessage::Raw(format!(
            "Removed recent folder: {}",
            folder.display()
        )));
        self.refresh_app_menus(window, cx);
        self.persist();
        cx.notify();
    }

    pub(super) fn add_folder(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let response = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            initial_directory: self
                .state
                .workspace_root_path()
                .filter(|path| path.is_dir()),
            prompt: Some(self.i18n().text("action.select_folder").into()),
        });
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let mut async_cx = cx.clone();
                async move {
                    match response.await {
                        Ok(Ok(Some(paths))) => {
                            let folder = paths.into_iter().next();
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    if let Some(folder) = folder {
                                        shell.set_workspace_folder(folder, window, cx);
                                    }
                                },
                            );
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(err)) => {
                            let message = err.to_string();
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell, _, cx: &mut Context<GuiShell>| {
                                    shell.status_message = Some(BannerMessage::Raw(message));
                                    cx.notify();
                                },
                            );
                        }
                        Err(err) => {
                            let message = format!("Folder selection failed: {err}");
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell, _, cx: &mut Context<GuiShell>| {
                                    shell.status_message = Some(BannerMessage::Raw(message));
                                    cx.notify();
                                },
                            );
                        }
                    }
                }
            })
            .detach();
    }

    pub(super) fn set_workspace_folder(
        &mut self,
        folder: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.start_workspace_scan(folder, WorkspaceScanKind::ReplaceAll, true, window, cx);
    }

    pub(super) fn clear_workspace(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.cancel_workspace_scan();
        self.cancel_progressive_cache_restore();
        self.clear_rows();
        self.visible_rows.clear();
        self.file_table_viewport_range = 0..0;
        self.clear_edit_history();
        self.cancel_all_auto_analysis();
        self.selection_anchor = None;
        self.active_path_edit = None;
        self.selected_path_rows.clear();
        self.path_selection_anchor = None;
        self.state.set_workspace_root(None);
        self.status_message = Some(BannerMessage::WorkspaceCleared);
        self.refresh_app_menus(window, cx);
        self.refresh_file_table(cx);
        self.refresh_path_table(cx);
        self.persist();
    }

    pub(super) fn rescan_workspace_with_current_settings(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(root) = self.state.workspace_root_path() else {
            self.refresh_app_menus(window, cx);
            self.persist();
            return;
        };
        self.start_workspace_scan(root, WorkspaceScanKind::Rescan, false, window, cx);
    }

    pub(super) fn cancel_workspace_scan(&mut self) {
        self.workspace_scan_state.generation = self.workspace_scan_state.generation.wrapping_add(1);
        self.workspace_scan_state.in_flight = false;
        self.workspace_scan_state.kind = WorkspaceScanKind::ReplaceAll;
    }

    fn start_workspace_scan(
        &mut self,
        root: PathBuf,
        kind: WorkspaceScanKind,
        add_recent_input: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.cancel_workspace_scan();
        self.cancel_progressive_cache_restore();
        self.cancel_all_auto_analysis();
        self.workspace_scan_state.in_flight = true;
        self.workspace_scan_state.kind = kind;
        let generation = self.workspace_scan_state.generation;
        self.state.set_workspace_root(Some(root.clone()));
        if add_recent_input {
            self.add_recent_input(&root, true);
        }
        self.status_message = Some(BannerMessage::Raw(
            self.i18n().text("banner.workspace_scan_in_progress"),
        ));
        self.refresh_app_menus(window, cx);
        self.persist();
        cx.notify();

        let state = self.state.clone();
        let view = cx.entity();
        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    let root_for_scan = root.clone();
                    let result = executor
                        .spawn(async move {
                            WorkspaceScanResult {
                                files: discover_workspace_scene_files(&root_for_scan, &state),
                                root: root_for_scan,
                                kind,
                            }
                        })
                        .await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        move |shell: &mut GuiShell,
                              window: &mut Window,
                              cx: &mut Context<GuiShell>| {
                            if shell.workspace_scan_state.generation != generation {
                                return;
                            }
                            shell.apply_workspace_scan_result(result, window, cx);
                        },
                    );
                }
            })
            .detach();
    }

    fn apply_workspace_scan_result(
        &mut self,
        result: WorkspaceScanResult,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.workspace_scan_state.in_flight = false;
        self.workspace_scan_state.kind = result.kind;
        match result.kind {
            WorkspaceScanKind::ReplaceAll => {
                let rows = build_rows_from_discovered_files(result.files, &mut self.next_row_id);
                self.replace_rows(rows);
                self.clear_selection();
                self.clear_edit_history();
                self.selection_anchor = None;
                self.active_path_edit = None;
                self.selected_path_rows.clear();
                self.path_selection_anchor = None;
                self.status_message = Some(BannerMessage::WorkspaceLoaded {
                    count: self.rows.len(),
                    path: result.root,
                });
            }
            WorkspaceScanKind::Rescan => {
                let existing_rows = std::mem::take(&mut self.rows);
                let rows = reconcile_workspace_rows_from_discovered_files(
                    existing_rows,
                    result.files,
                    &mut self.next_row_id,
                );
                self.replace_rows(rows);
                self.clear_edit_history();
                self.selection_anchor = self.rows.iter().position(|row| row.selected);
                self.active_path_edit = None;
                self.selected_path_rows.clear();
                self.path_selection_anchor = None;
                self.status_message = None;
            }
        }
        self.refresh_file_table(cx);
        self.refresh_app_menus(window, cx);
        self.schedule_cache_sweep(window, cx);
        self.schedule_periodic_cache_sweep(window, cx);
        self.start_progressive_cache_restore(window, cx);
        self.schedule_workspace_auto_analysis_if_enabled(window, cx);
        self.persist();
        cx.notify();
    }

    pub(super) fn set_locale_preference(
        &mut self,
        locale: LocalePreference,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.state.locale = locale;
        let i18n = self.i18n();
        self.search_input.update(cx, |input, cx| {
            input.set_placeholder(i18n.text("placeholder.search"), window, cx);
        });
        self.path_search_input.update(cx, |input, cx| {
            input.set_placeholder(i18n.text("placeholder.path_search"), window, cx);
        });
        self.audit_search_input.update(cx, |input, cx| {
            input.set_placeholder(i18n.text("placeholder.audit_search"), window, cx);
        });
        self.path_edit_input.update(cx, |input, cx| {
            input.set_placeholder(i18n.text("placeholder.scene_path"), window, cx);
        });
        self.refresh_app_menus(window, cx);
        self.refresh_file_table(cx);
        self.persist();
    }

    pub(super) fn set_backup_location_preference(
        &mut self,
        backup_location: BackupLocationPreference,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.state.backup_location = backup_location;
        self.refresh_app_menus(window, cx);
        self.persist();
    }

    pub(super) fn set_workspace_layout_preference(
        &mut self,
        layout: WorkspaceLayoutPreference,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.state.workspace_layout == layout {
            return;
        }
        self.state.workspace_layout = layout;
        self.refresh_app_menus(window, cx);
        self.persist();
        cx.notify();
    }

    pub(super) fn set_auto_analyze_parallelism_preference(
        &mut self,
        parallelism: AutoAnalyzeParallelismPreference,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.state.auto_analyze_parallelism == parallelism {
            return;
        }
        self.state.auto_analyze_parallelism = parallelism;
        self.refresh_app_menus(window, cx);
        self.persist();
        self.dispatch_auto_analyze_jobs(window, cx);
        cx.notify();
    }

    pub(super) fn set_analysis_cache_enabled_preference(
        &mut self,
        enabled: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.state.analysis_cache_enabled == enabled {
            return;
        }
        self.state.analysis_cache_enabled = enabled;
        self.cancel_progressive_cache_restore();
        self.cancel_cache_writes();
        self.cancel_cache_maintenance();
        self.refresh_app_menus(window, cx);
        self.persist();
        if enabled {
            self.schedule_cache_sweep(window, cx);
            self.schedule_periodic_cache_sweep(window, cx);
            self.start_progressive_cache_restore(window, cx);
        }
        cx.notify();
    }

    pub(super) fn purge_analysis_cache(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.cancel_progressive_cache_restore();
        self.cancel_cache_writes();
        self.cancel_cache_maintenance();
        let legacy_root = default_analysis_cache_root();
        let cache_roots = [
            self.observe_cache_root.clone(),
            self.audit_cache_root.clone(),
            legacy_root.join("observe"),
            legacy_root.join("audit"),
            legacy_root.join("observe-v2"),
            legacy_root.join("audit-v2"),
            legacy_root.join("observe-v3"),
            legacy_root.join("audit-v3"),
            legacy_root.join("observe-v4"),
            legacy_root.join("audit-v4"),
        ];
        let purge_result = cache_roots
            .into_iter()
            .try_fold((), |(), root| purge_cache_dir(&root));
        match purge_result {
            Ok(()) => {
                self.status_message = Some(BannerMessage::CachePurged);
                self.refresh_app_menus(window, cx);
                cx.notify();
            }
            Err(err) => {
                self.status_message = Some(BannerMessage::PersistFailed(err.to_string()));
                cx.notify();
            }
        }
    }

    pub(super) fn set_ignore_folder_names_enabled_preference(
        &mut self,
        ignore_folder_names_enabled: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.state.ignore_folder_names_enabled == ignore_folder_names_enabled {
            return;
        }
        self.state.ignore_folder_names_enabled = ignore_folder_names_enabled;
        self.cancel_all_auto_analysis();
        self.rescan_workspace_with_current_settings(window, cx);
    }

    pub(super) fn set_max_bytes_preference(
        &mut self,
        max_bytes: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.state.max_bytes == max_bytes {
            return;
        }
        self.state.max_bytes = max_bytes;
        self.refresh_app_menus(window, cx);
        self.persist();
        if self.state.workspace_auto_analyze {
            self.cancel_all_auto_analysis();
            self.schedule_workspace_auto_analysis(window, cx);
        }
        cx.notify();
    }

    pub(super) fn apply_ignored_folder_names(
        &mut self,
        ignored_folder_names: Vec<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.state.ignored_folder_names == ignored_folder_names {
            self.refresh_app_menus(window, cx);
            self.persist();
            return;
        }
        self.state.set_ignored_folder_names(ignored_folder_names);
        if self.state.ignore_folder_names_enabled {
            self.cancel_all_auto_analysis();
            self.rescan_workspace_with_current_settings(window, cx);
            return;
        }
        self.refresh_app_menus(window, cx);
        self.persist();
        cx.notify();
    }

    pub(super) fn set_file_sort(
        &mut self,
        key: FileSortKey,
        direction: ColumnSort,
        cx: &mut Context<Self>,
    ) {
        self.file_sort = FileTableSort { key, direction };
        self.refresh_file_table(cx);
    }

    pub(super) fn set_path_sort(
        &mut self,
        key: PathSortKey,
        direction: ColumnSort,
        cx: &mut Context<Self>,
    ) {
        self.path_order_snapshot = None;
        self.path_sort = PathTableSort { key, direction };
        self.refresh_path_table(cx);
    }

    pub(super) fn set_audit_sort(
        &mut self,
        key: AuditSortKey,
        direction: ColumnSort,
        cx: &mut Context<Self>,
    ) {
        self.audit_sort = AuditTableSort { key, direction };
        self.refresh_audit_table(cx);
    }

    pub(super) fn workspace_caption(&self, i18n: &I18n) -> String {
        match self.state.workspace_root_path() {
            Some(path) => i18n.format(
                "workspace.caption.folder",
                &[("path", path.display().to_string())],
            ),
            None => i18n.text("workspace.caption.empty"),
        }
    }

    pub(super) fn window_title(&self, i18n: &I18n) -> String {
        let selected = self.selected_indices().len();
        let dirty = self.ready_dirty_indices().len();
        let workspace = self
            .state
            .workspace_root_path()
            .and_then(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| i18n.text("window.no_workspace"));

        i18n.format(
            "window.title",
            &[
                ("workspace", workspace),
                ("selected", selected.to_string()),
                ("dirty", dirty.to_string()),
            ],
        )
    }

    pub(super) fn refresh_visible_rows(&mut self) {
        self.visible_rows =
            compute_visible_row_indices_for(&self.rows, &self.state, self.file_sort);
    }

    pub(super) fn refresh_audit_table(&mut self, cx: &mut Context<Self>) {
        let selected = self.selected_indices();
        self.audit_all_rows = build_audit_result_rows(&self.rows, &selected);
        let mut audit_model = self.current_audit_table_model();
        let visible_keys = audit_model
            .rows
            .iter()
            .map(|row| row.key.clone())
            .collect::<BTreeSet<_>>();
        let selected_len = self.selected_audit_keys.len();
        self.selected_audit_keys
            .retain(|key| visible_keys.contains(key));
        if self
            .audit_selection_anchor
            .as_ref()
            .is_some_and(|key| !visible_keys.contains(key))
        {
            self.audit_selection_anchor = None;
        }
        if self.selected_audit_keys.len() != selected_len {
            audit_model = self.current_audit_table_model();
        }
        self.audit_rows = audit_model.rows;

        if self
            .audit_detail_dialog
            .as_ref()
            .is_some_and(|dialog| !self.audit_rows.iter().any(|row| row.key == dialog.key))
        {
            self.audit_detail_dialog = None;
        }

        let i18n = self.i18n();
        let audit_rows = self.audit_rows.clone();
        self.audit_table.update(cx, |table, cx| {
            table
                .delegate_mut()
                .sync(audit_rows, i18n.locale(), self.audit_sort);
            table.clear_selection(cx);
            table.refresh(cx);
        });
    }

    pub(super) fn refresh_file_table(&mut self, cx: &mut Context<Self>) {
        self.refresh_visible_rows();
        self.refresh_file_table_from_current_visible_rows(cx);
        self.refresh_audit_table(cx);
        self.refresh_path_table(cx);
    }

    pub(super) fn refresh_file_table_from_current_visible_rows(&mut self, cx: &mut Context<Self>) {
        let i18n = self.i18n();
        let file_sort = self.file_sort;
        let table_rows = build_file_table_rows(&self.rows, &self.visible_rows, &self.state, &i18n);
        self.file_table.update(cx, |table, cx| {
            table
                .delegate_mut()
                .sync(table_rows, i18n.locale(), file_sort);
            table.clear_selection(cx);
            table.refresh(cx);
        });
    }

    pub(super) fn patch_visible_file_rows(
        &mut self,
        row_ids: &BTreeSet<u64>,
        cx: &mut Context<Self>,
    ) -> bool {
        if row_ids.is_empty() {
            return false;
        }
        let i18n = self.i18n();
        let mut patched_rows = Vec::new();
        for row_id in row_ids {
            let Some(index) = self.index_of_row_id(*row_id) else {
                continue;
            };
            let Some(visible_index) = self.visible_position_for_row_index(index) else {
                continue;
            };
            let Some(row) = self.rows.get(index) else {
                continue;
            };
            patched_rows.push((
                visible_index,
                build_single_file_table_row(row, &self.state, &i18n),
            ));
        }
        if patched_rows.is_empty() {
            return false;
        }
        self.file_table.update(cx, |table, cx| {
            table
                .delegate_mut()
                .replace_rows(patched_rows, i18n.locale(), self.file_sort);
            table.refresh(cx);
        });
        true
    }
}

fn purge_cache_dir(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}
