use super::*;
use std::{fs, io};

impl GuiShell {
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
        self.state.normalize_ignore_folder_settings();
        self.state.set_workspace_root(
            self.state
                .workspace_root_path()
                .filter(|path| path.exists()),
        );
        self.state
            .replace_workspace_paths(self.rows.iter().map(|row| row.path.clone()));
        if let Err(err) = save_persisted_state(&self.state) {
            self.status_message = Some(BannerMessage::PersistFailed(err.to_string()));
        }
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
        self.cancel_progressive_cache_restore();
        let mut files = Vec::new();
        collect_scene_files_recursively(&folder, &mut files, &self.state);
        let rows = build_rows_from_paths(files, &mut self.next_row_id);
        self.replace_rows(rows);
        self.clear_selection();
        self.clear_edit_history();
        self.cancel_all_auto_analysis();
        self.selection_anchor = None;
        self.active_path_edit = None;
        self.selected_path_rows.clear();
        self.path_selection_anchor = None;
        self.state.set_workspace_root(Some(folder.clone()));
        self.add_recent_input(&folder, true);
        self.status_message = Some(BannerMessage::WorkspaceLoaded {
            count: self.rows.len(),
            path: folder,
        });
        self.refresh_app_menus(window, cx);
        self.refresh_file_table(cx);
        self.refresh_path_table(cx);
        self.start_progressive_cache_restore(window, cx);
        self.schedule_workspace_auto_analysis_if_enabled(window, cx);
        self.persist();
    }

    pub(super) fn clear_workspace(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.cancel_progressive_cache_restore();
        self.clear_rows();
        self.visible_rows.clear();
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
        self.cancel_progressive_cache_restore();
        let Some(root) = self.state.workspace_root_path() else {
            self.refresh_app_menus(window, cx);
            self.persist();
            return;
        };
        let mut files = Vec::new();
        collect_scene_files_recursively(&root, &mut files, &self.state);
        let existing_rows = std::mem::take(&mut self.rows);
        let rows = reconcile_workspace_rows(existing_rows, files, &mut self.next_row_id);
        self.replace_rows(rows);
        self.clear_edit_history();
        self.selection_anchor = self.rows.iter().position(|row| row.selected);
        self.active_path_edit = None;
        self.selected_path_rows.clear();
        self.path_selection_anchor = None;
        self.refresh_file_table(cx);
        self.refresh_path_table(cx);
        self.refresh_app_menus(window, cx);
        self.start_progressive_cache_restore(window, cx);
        self.schedule_workspace_auto_analysis_if_enabled(window, cx);
        self.persist();
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
            self.start_progressive_cache_restore(window, cx);
        }
        cx.notify();
    }

    pub(super) fn purge_analysis_cache(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.cancel_progressive_cache_restore();
        self.cancel_cache_writes();
        self.cancel_cache_maintenance();
        match purge_cache_dir(&self.observe_cache_root)
            .and_then(|()| purge_cache_dir(&self.audit_cache_root))
        {
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
        self.refresh_audit_table(cx);
        self.refresh_path_table(cx);
    }
}

fn purge_cache_dir(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}
