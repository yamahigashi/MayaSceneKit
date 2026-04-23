use super::*;

impl GuiShell {
    pub(super) fn on_menu_select_folder(
        &mut self,
        _: &MenuSelectFolder,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.add_folder(window, cx);
    }

    pub(super) fn on_menu_save_selected(
        &mut self,
        _: &MenuSaveSelected,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.workspace_scan_active() {
            return;
        }
        self.run_save_selected(window, cx);
    }

    pub(super) fn on_menu_save_all(
        &mut self,
        _: &MenuSaveAll,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.workspace_scan_active() {
            return;
        }
        self.run_save_all(window, cx);
    }

    pub(super) fn on_menu_edit_clean(
        &mut self,
        _: &MenuEditClean,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.workspace_scan_active() {
            return;
        }
        self.run_clean(window, cx);
    }

    pub(super) fn on_menu_edit_delete_ui_configuration_script_node(
        &mut self,
        _: &MenuEditDeleteUiConfigurationScriptNode,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.workspace_scan_active() {
            return;
        }
        self.run_delete_ui_configuration_script_node(window, cx);
    }

    pub(super) fn on_menu_edit_undo(
        &mut self,
        _: &MenuEditUndo,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.run_menu_undo(cx);
        self.refresh_app_menus(window, cx);
    }

    pub(super) fn on_menu_edit_redo(
        &mut self,
        _: &MenuEditRedo,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.run_menu_redo(cx);
        self.refresh_app_menus(window, cx);
    }

    pub(super) fn on_menu_edit_replace(
        &mut self,
        _: &MenuEditReplace,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.workspace_scan_active() {
            return;
        }
        self.run_replace(window, cx);
    }

    pub(super) fn on_menu_edit_to_ascii(
        &mut self,
        _: &MenuEditToAscii,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.workspace_scan_active() {
            return;
        }
        self.run_to_ascii(window, cx);
    }

    pub(super) fn on_menu_exit_application(
        &mut self,
        _: &MenuExitApplication,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.request_exit(window, cx);
    }

    pub(super) fn on_menu_clear_workspace(
        &mut self,
        _: &MenuClearWorkspace,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.clear_workspace(window, cx);
    }

    pub(super) fn on_file_table_select_all(
        &mut self,
        _: &FileTableSelectAll,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.workspace_scan_active() {
            return;
        }
        let focused = self.file_table_focus_handle.contains_focused(window, cx);
        if !focused {
            return;
        }
        window.prevent_default();
        let visible_indices = self.visible_row_indices();
        let all_visible_selected = !visible_indices.is_empty()
            && visible_indices
                .iter()
                .all(|&index| self.rows.get(index).is_some_and(|row| row.selected));
        if all_visible_selected {
            self.clear_selection();
            self.refresh_file_table(cx);
            cx.notify();
            return;
        }
        self.select_visible(window, cx);
        cx.notify();
    }

    pub(super) fn on_menu_recent_folder_unavailable(
        &mut self,
        _: &MenuRecentFolderUnavailable,
        _: &mut Window,
        _: &mut Context<Self>,
    ) {
    }

    pub(super) fn on_menu_recent_folder_0(
        &mut self,
        _: &MenuRecentFolder0,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(0, window, cx);
    }

    pub(super) fn on_menu_recent_folder_1(
        &mut self,
        _: &MenuRecentFolder1,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(1, window, cx);
    }

    pub(super) fn on_menu_recent_folder_2(
        &mut self,
        _: &MenuRecentFolder2,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(2, window, cx);
    }

    pub(super) fn on_menu_recent_folder_3(
        &mut self,
        _: &MenuRecentFolder3,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(3, window, cx);
    }

    pub(super) fn on_menu_recent_folder_4(
        &mut self,
        _: &MenuRecentFolder4,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(4, window, cx);
    }

    pub(super) fn on_menu_recent_folder_5(
        &mut self,
        _: &MenuRecentFolder5,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(5, window, cx);
    }

    pub(super) fn on_menu_recent_folder_6(
        &mut self,
        _: &MenuRecentFolder6,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(6, window, cx);
    }

    pub(super) fn on_menu_recent_folder_7(
        &mut self,
        _: &MenuRecentFolder7,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(7, window, cx);
    }

    pub(super) fn on_menu_recent_folder_8(
        &mut self,
        _: &MenuRecentFolder8,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(8, window, cx);
    }

    pub(super) fn on_menu_recent_folder_9(
        &mut self,
        _: &MenuRecentFolder9,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_recent_folder(9, window, cx);
    }

    pub(super) fn on_menu_remove_recent_folder_by_path(
        &mut self,
        action: &MenuRemoveRecentFolderByPath,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.remove_recent_folder_by_display(&action.path, window, cx);
    }

    pub(super) fn on_menu_locale_english(
        &mut self,
        _: &MenuLocaleEnglish,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_locale_preference(LocalePreference::English, window, cx);
    }

    pub(super) fn on_menu_locale_japanese(
        &mut self,
        _: &MenuLocaleJapanese,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_locale_preference(LocalePreference::Japanese, window, cx);
    }

    pub(super) fn on_menu_locale_chinese(
        &mut self,
        _: &MenuLocaleChinese,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_locale_preference(LocalePreference::Chinese, window, cx);
    }

    pub(super) fn on_menu_backup_location_same_directory(
        &mut self,
        _: &MenuBackupLocationSameDirectory,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_backup_location_preference(BackupLocationPreference::SameDirectory, window, cx);
    }

    pub(super) fn on_menu_backup_location_backup_folder(
        &mut self,
        _: &MenuBackupLocationBackupFolder,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_backup_location_preference(BackupLocationPreference::BackupFolder, window, cx);
    }

    pub(super) fn on_menu_layout_vertical_split(
        &mut self,
        _: &MenuLayoutVerticalSplit,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_workspace_layout_preference(WorkspaceLayoutPreference::LeftRight, window, cx);
    }

    pub(super) fn on_menu_layout_horizontal_split(
        &mut self,
        _: &MenuLayoutHorizontalSplit,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_workspace_layout_preference(WorkspaceLayoutPreference::TopBottom, window, cx);
    }

    pub(super) fn on_menu_auto_analyze_parallelism_1(
        &mut self,
        _: &MenuAutoAnalyzeParallelism1,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_auto_analyze_parallelism_preference(
            AutoAnalyzeParallelismPreference::One,
            window,
            cx,
        );
    }

    pub(super) fn on_menu_auto_analyze_parallelism_2(
        &mut self,
        _: &MenuAutoAnalyzeParallelism2,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_auto_analyze_parallelism_preference(
            AutoAnalyzeParallelismPreference::Two,
            window,
            cx,
        );
    }

    pub(super) fn on_menu_auto_analyze_parallelism_4(
        &mut self,
        _: &MenuAutoAnalyzeParallelism4,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_auto_analyze_parallelism_preference(
            AutoAnalyzeParallelismPreference::Four,
            window,
            cx,
        );
    }

    pub(super) fn on_menu_auto_analyze_parallelism_8(
        &mut self,
        _: &MenuAutoAnalyzeParallelism8,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_auto_analyze_parallelism_preference(
            AutoAnalyzeParallelismPreference::Eight,
            window,
            cx,
        );
    }

    pub(super) fn on_menu_auto_analyze_parallelism_16(
        &mut self,
        _: &MenuAutoAnalyzeParallelism16,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_auto_analyze_parallelism_preference(
            AutoAnalyzeParallelismPreference::Sixteen,
            window,
            cx,
        );
    }

    pub(super) fn on_menu_auto_analyze_parallelism_32(
        &mut self,
        _: &MenuAutoAnalyzeParallelism32,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_auto_analyze_parallelism_preference(
            AutoAnalyzeParallelismPreference::ThirtyTwo,
            window,
            cx,
        );
    }

    pub(super) fn on_menu_toggle_analysis_cache(
        &mut self,
        _: &MenuToggleAnalysisCache,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_analysis_cache_enabled_preference(!self.state.analysis_cache_enabled, window, cx);
    }

    pub(super) fn on_menu_purge_analysis_cache(
        &mut self,
        _: &MenuPurgeAnalysisCache,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.confirm_purge_analysis_cache(window, cx);
    }

    pub(super) fn on_menu_edit_max_bytes(
        &mut self,
        _: &MenuEditMaxBytes,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_max_bytes_dialog(window, cx);
    }

    pub(super) fn on_menu_toggle_ignore_folder_names(
        &mut self,
        _: &MenuToggleIgnoreFolderNames,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_ignore_folder_names_enabled_preference(
            !self.state.ignore_folder_names_enabled,
            window,
            cx,
        );
    }

    pub(super) fn on_menu_edit_ignored_folder_names(
        &mut self,
        _: &MenuEditIgnoredFolderNames,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_ignore_folder_names_dialog(window, cx);
    }
}
