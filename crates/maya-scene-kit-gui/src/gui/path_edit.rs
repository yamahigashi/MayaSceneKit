use super::*;
use maya_scene_kit_edit::scene::OperationMode;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

impl GuiShell {
    pub(super) fn capture_path_order_snapshot(&self) -> Option<PathOrderSnapshot> {
        let model = self.current_path_table_model();
        let mut order_by_target = BTreeMap::new();
        for (row_ix, row) in model.rows.iter().enumerate() {
            for target in &row.edit_targets {
                order_by_target.entry(*target).or_insert(row_ix);
            }
        }
        (!order_by_target.is_empty()).then_some(PathOrderSnapshot { order_by_target })
    }

    pub(super) fn preserve_path_order_after_path_mutation(
        &mut self,
        snapshot: Option<PathOrderSnapshot>,
    ) {
        self.path_order_snapshot = snapshot;
        self.path_sort = PathTableSort {
            key: PathSortKey::CapturedOrder,
            direction: ColumnSort::Ascending,
        };
    }

    pub(super) fn current_path_value(&self, row: &SceneRow, entry_index: usize) -> Option<String> {
        let report = row.display_paths_report()?;
        let entry = report.entries.get(entry_index)?;
        Some(
            row.path_overrides
                .get(&entry_index)
                .cloned()
                .unwrap_or_else(|| entry.value.clone()),
        )
    }

    fn active_path_edit_value_style(&self, edit_targets: &PathEditTargets) -> ScenePathValueStyle {
        let Some((row_id, entry_index)) = edit_targets.first().copied() else {
            return ScenePathValueStyle::PlainRelative;
        };
        let Some(row_index) = self.index_of_row_id(row_id) else {
            return ScenePathValueStyle::PlainRelative;
        };
        let Some(value) = self.current_path_value(&self.rows[row_index], entry_index) else {
            return ScenePathValueStyle::PlainRelative;
        };
        resolve_scene_path_value(&value, self.rows[row_index].scene_workspace_root.as_deref()).style
    }

    fn apply_selected_path_edit_file(
        &mut self,
        edit_targets: PathEditTargets,
        selected_path: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !path_value_edit_supported_for_edit_targets(&self.rows, &edit_targets) {
            return;
        }
        let shared_workspace_root = shared_workspace_root_for_targets(&self.rows, &edit_targets);
        let value_style = self.active_path_edit_value_style(&edit_targets);
        let next_value = write_back_selected_scene_path(
            &selected_path,
            shared_workspace_root.as_deref(),
            value_style,
        );
        let edit_targets = normalize_path_edit_targets(edit_targets);
        let mut row_targets: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();

        for (row_id, entry_index) in &edit_targets {
            let Some(row_index) = self.index_of_row_id(*row_id) else {
                return;
            };
            row_targets
                .entry(row_index)
                .or_default()
                .insert(*entry_index);
        }

        let mut planned_edits = Vec::<(usize, BTreeMap<usize, String>)>::new();
        for (row_index, entry_indices) in row_targets {
            let mut next_overrides = self.rows[row_index].path_overrides.clone();
            for entry_index in entry_indices {
                let Some(current_value) =
                    self.current_path_value(&self.rows[row_index], entry_index)
                else {
                    return;
                };
                if next_value == current_value {
                    next_overrides.remove(&entry_index);
                } else {
                    next_overrides.insert(entry_index, next_value.clone());
                }
            }
            planned_edits.push((row_index, next_overrides));
        }

        if self
            .apply_path_override_updates(planned_edits, window, cx)
            .is_err()
        {
            return;
        }

        self.cancel_path_edit(window, cx);
        self.refresh_file_table(cx);
        self.persist();
    }

    fn open_path_edit_file_dialog(
        &mut self,
        edit_targets: PathEditTargets,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if edit_targets.is_empty() {
            return;
        }
        let prompt = self.i18n().text("action.select_file");
        let initial_directory = self.path_edit_initial_directory(&edit_targets);
        let response = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            initial_directory,
            prompt: Some(prompt.into()),
        });
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let mut async_cx = cx.clone();
                async move {
                    match response.await {
                        Ok(Ok(Some(paths))) => {
                            let selected_path = paths.into_iter().next();
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    if let Some(selected_path) = selected_path {
                                        shell.apply_selected_path_edit_file(
                                            edit_targets.clone(),
                                            selected_path,
                                            window,
                                            cx,
                                        );
                                    }
                                    shell.schedule_file_dialog_ui_unblock(window, cx);
                                },
                            );
                        }
                        Ok(Ok(None)) => {
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    shell.schedule_file_dialog_ui_unblock(window, cx);
                                },
                            );
                        }
                        Ok(Err(err)) => {
                            let message = err.to_string();
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    shell.status_message = Some(BannerMessage::Raw(message));
                                    shell.schedule_file_dialog_ui_unblock(window, cx);
                                    cx.notify();
                                },
                            );
                        }
                        Err(err) => {
                            let message = err.to_string();
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    shell.status_message = Some(BannerMessage::Raw(message));
                                    shell.schedule_file_dialog_ui_unblock(window, cx);
                                    cx.notify();
                                },
                            );
                        }
                    }
                }
            })
            .detach();
    }

    fn path_edit_initial_directory(&self, edit_targets: &PathEditTargets) -> Option<PathBuf> {
        let (row_id, entry_index) = edit_targets.first().copied()?;
        let row_index = self.index_of_row_id(row_id)?;
        let row = self.rows.get(row_index)?;
        let value = self.current_path_value(row, entry_index)?;
        let resolution = row
            .path_resolution(entry_index, &value)
            .cloned()
            .or_else(|| row.path_resolution_fallback(entry_index, &value));

        resolution
            .and_then(|resolution| {
                resolution
                    .resolved_path
                    .filter(|path| path.is_file())
                    .and_then(|path| path.parent().map(Path::to_path_buf))
            })
            .or_else(|| {
                row.scene_workspace_root
                    .clone()
                    .filter(|path| path.is_dir())
            })
    }

    pub(super) fn select_path_edit_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(edit_targets) = self.active_path_edit.clone() else {
            return;
        };
        if !path_value_edit_supported_for_edit_targets(&self.rows, &edit_targets) {
            return;
        }
        let view = cx.entity();
        self.begin_file_dialog_ui_block(cx);
        window.defer(cx, move |window, cx| {
            view.update(cx, |shell, cx| {
                shell.open_path_edit_file_dialog(edit_targets.clone(), window, cx);
            });
        });
    }

    pub(super) fn spawn_replace_artifact_refresh(
        &mut self,
        row_id: u64,
        revision: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(index) = self.index_of_row_id(row_id) else {
            return;
        };
        let Some(row) = self.rows.get(index) else {
            return;
        };
        let Some(report) = row.display_paths_report().cloned() else {
            return;
        };
        let Some(overrides) = replace_overrides_for_row(row) else {
            return;
        };
        if overrides.is_empty() {
            return;
        }

        let options = self.scene_materialize_options(OperationMode::Forensic);
        let view = cx.entity();
        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    let result = executor
                        .spawn(async move {
                            stage_replace_scene_paths_with_overrides_in_report_with_options(
                                &report, &overrides, &options,
                            )
                            .map_err(|err| err.to_string())
                        })
                        .await;

                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, _window: &mut Window, cx: &mut Context<GuiShell>| {
                            let Some(row_index) = shell.index_of_row_id(row_id) else {
                                return;
                            };
                            let Some(row) = shell.rows.get_mut(row_index) else {
                                return;
                            };
                            if row.replace_generation != revision
                                || row.dirty_kind != Some(DirtyKind::Replace)
                                || row.path_overrides.is_empty()
                            {
                                return;
                            }
                            match result {
                                Ok(staged) => {
                                    row.dirty_artifact = Some(staged.artifact);
                                    row.replace_artifact_generation = Some(revision);
                                }
                                Err(err) => {
                                    row.dirty_artifact = None;
                                    row.replace_artifact_generation = None;
                                    shell.status_message = Some(BannerMessage::Raw(err));
                                }
                            }
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn context_path_targets(&self, edit_targets: &PathEditTargets) -> PathEditTargets {
        if self.selected_path_rows.contains(edit_targets) {
            normalize_path_edit_targets(
                self.selected_path_rows
                    .iter()
                    .flat_map(|targets| targets.iter().copied())
                    .collect(),
            )
        } else {
            normalize_path_edit_targets(edit_targets.clone())
        }
    }

    pub(super) fn context_undo_path_targets(
        &self,
        edit_targets: &PathEditTargets,
    ) -> PathEditTargets {
        self.context_path_targets(edit_targets)
    }

    pub(super) fn context_delete_owner_rows(
        &self,
        edit_targets: &PathEditTargets,
    ) -> Vec<PathEditTargets> {
        let edit_targets = normalize_path_edit_targets(edit_targets.clone());
        if edit_targets.is_empty() {
            Vec::new()
        } else {
            vec![edit_targets]
        }
    }

    pub(super) fn undo_context_path_targets(
        &mut self,
        edit_targets: PathEditTargets,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }

        let mut replace_targets = Vec::new();
        let mut delete_targets_by_row = BTreeMap::<usize, BTreeSet<PathOwnerDeleteTarget>>::new();
        for (row_id, entry_index) in edit_targets {
            let Some(row_index) = self.index_of_row_id(row_id) else {
                continue;
            };
            if self.rows[row_index].is_processing() {
                return;
            }

            match self.rows[row_index].dirty_kind {
                Some(DirtyKind::SceneEdits) => {
                    if let Some(target) =
                        path_owner_delete_target_for_entry(&self.rows[row_index], entry_index)
                            .filter(|target| {
                                self.rows[row_index]
                                    .pending_path_owner_delete_targets
                                    .contains(target)
                            })
                    {
                        delete_targets_by_row
                            .entry(row_index)
                            .or_default()
                            .insert(target);
                    } else if self.rows[row_index]
                        .path_overrides
                        .contains_key(&entry_index)
                    {
                        replace_targets.push((row_id, entry_index));
                    }
                }
                _ => replace_targets.push((row_id, entry_index)),
            }
        }

        if !replace_targets.is_empty() {
            self.undo_path_edit_targets(replace_targets, window, cx);
        }
        if !delete_targets_by_row.is_empty() {
            self.undo_staged_path_owner_delete_targets(delete_targets_by_row, window, cx);
        }
    }

    pub(super) fn copy_path_target_files_to_clipboard(
        &mut self,
        edit_targets: PathEditTargets,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let resolved_paths = resolved_target_file_paths_for_edit_targets(&self.rows, &edit_targets);
        if resolved_paths.is_empty() {
            return;
        }

        let view = cx.entity();
        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    let result =
                        executor
                            .spawn(async move {
                                copy_file_drop_paths_to_system_clipboard(&resolved_paths)
                            })
                            .await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        move |shell: &mut GuiShell,
                              _window: &mut Window,
                              cx: &mut Context<GuiShell>| {
                            if let Err(err) = result {
                                shell.status_message = Some(BannerMessage::Raw(err));
                            }
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn convert_path_targets_to_workspace_relative(
        &mut self,
        edit_targets: PathEditTargets,
        rewrite_mode: PathCollectRewriteMode,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }
        if !path_value_edit_supported_for_edit_targets(&self.rows, &edit_targets) {
            return;
        }

        let mut row_targets: BTreeMap<usize, BTreeMap<usize, String>> = BTreeMap::new();
        for (row_id, entry_index) in edit_targets {
            let Some(row_index) = self.index_of_row_id(row_id) else {
                continue;
            };
            if self.rows[row_index].is_processing() {
                continue;
            }
            let Some(next_value) = workspace_relative_override_value_for_entry(
                &self.rows[row_index],
                entry_index,
                rewrite_mode,
            ) else {
                continue;
            };
            row_targets
                .entry(row_index)
                .or_default()
                .insert(entry_index, next_value);
        }
        if row_targets.is_empty() {
            return;
        }

        let planned_edits = row_targets
            .into_iter()
            .map(|(row_index, overrides)| {
                let mut next_overrides = self.rows[row_index].path_overrides.clone();
                for (entry_index, next_value) in overrides {
                    next_overrides.insert(entry_index, next_value);
                }
                (row_index, next_overrides)
            })
            .collect::<Vec<_>>();

        if let Err(err) = self.apply_path_override_updates(planned_edits, window, cx) {
            self.status_message = Some(BannerMessage::InlinePathEditFailed(err));
            return;
        }
        self.refresh_file_table(cx);
        self.persist();
        cx.notify();
    }

    pub(super) fn convert_path_targets_to_absolute(
        &mut self,
        edit_targets: PathEditTargets,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }
        if !path_value_edit_supported_for_edit_targets(&self.rows, &edit_targets) {
            return;
        }

        let mut row_targets: BTreeMap<usize, BTreeMap<usize, String>> = BTreeMap::new();
        for (row_id, entry_index) in edit_targets {
            let Some(row_index) = self.index_of_row_id(row_id) else {
                continue;
            };
            if self.rows[row_index].is_processing() {
                continue;
            }
            let Some(next_value) =
                absolute_override_value_for_entry(&self.rows[row_index], entry_index)
            else {
                continue;
            };
            row_targets
                .entry(row_index)
                .or_default()
                .insert(entry_index, next_value);
        }
        if row_targets.is_empty() {
            return;
        }

        let planned_edits = row_targets
            .into_iter()
            .map(|(row_index, overrides)| {
                let mut next_overrides = self.rows[row_index].path_overrides.clone();
                for (entry_index, next_value) in overrides {
                    next_overrides.insert(entry_index, next_value);
                }
                (row_index, next_overrides)
            })
            .collect::<Vec<_>>();

        if let Err(err) = self.apply_path_override_updates(planned_edits, window, cx) {
            self.status_message = Some(BannerMessage::InlinePathEditFailed(err));
            return;
        }
        self.refresh_file_table(cx);
        self.persist();
        cx.notify();
    }

    pub(super) fn collect_path_targets_to_folder(
        &mut self,
        edit_targets: PathEditTargets,
        destination_folder: PathBuf,
        rewrite_mode: PathCollectRewriteMode,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }
        let Some(workspace_root) = shared_workspace_root_for_targets(&self.rows, &edit_targets)
        else {
            self.status_message = Some(BannerMessage::Raw(
                self.i18n().text("banner.path_collect_requires_workspace"),
            ));
            cx.notify();
            return;
        };
        if !path_collect_destination_supports_rewrite_mode(
            &destination_folder,
            &workspace_root,
            rewrite_mode,
        ) {
            self.status_message = Some(BannerMessage::Raw(
                self.i18n().text("banner.path_collect_folder_invalid"),
            ));
            cx.notify();
            return;
        }
        let can_collect = match rewrite_mode {
            PathCollectRewriteMode::CopyOnly => {
                path_file_collect_supported_for_edit_targets(&self.rows, &edit_targets)
            }
            _ => path_collect_supported_for_edit_targets(&self.rows, &edit_targets),
        };
        if !can_collect {
            return;
        }

        let mut plans = Vec::new();
        for (row_id, entry_index) in edit_targets {
            let Some(row_index) = self.index_of_row_id(row_id) else {
                continue;
            };
            let Some(source_path) =
                resolved_target_file_path_for_entry(&self.rows[row_index], entry_index)
            else {
                continue;
            };
            let Some(file_name) = source_path.file_name() else {
                self.status_message = Some(BannerMessage::Raw(format!(
                    "path has no file name: {}",
                    source_path.display()
                )));
                cx.notify();
                return;
            };
            let destination_path = destination_folder.join(file_name);
            let next_value =
                collected_path_rewrite_value(&destination_path, &workspace_root, rewrite_mode);
            plans.push(PathCollectPlan {
                row_id,
                entry_index,
                row_index,
                source_path,
                destination_path,
                next_value,
            });
        }

        if plans.is_empty() {
            return;
        }

        let result = match collect_target_files(&plans) {
            Ok(result) => result,
            Err(err) => {
                self.status_message = Some(BannerMessage::Raw(err));
                cx.notify();
                return;
            }
        };

        if rewrite_mode == PathCollectRewriteMode::CopyOnly {
            self.record_job(
                "path-collect",
                workspace_root,
                Some(destination_folder),
                format!("{} file(s) copied, {} reused", result.copied, result.reused),
                false,
            );
            self.persist();
            cx.notify();
            return;
        }

        let mut row_targets: BTreeMap<usize, Vec<&PathCollectPlan>> = BTreeMap::new();
        for plan in &plans {
            row_targets.entry(plan.row_index).or_default().push(plan);
        }

        let mut planned_edits = Vec::new();
        for (row_index, row_plans) in row_targets {
            let mut next_overrides = self.rows[row_index].path_overrides.clone();
            for plan in row_plans {
                let Some(current_value) =
                    self.current_path_value(&self.rows[row_index], plan.entry_index)
                else {
                    continue;
                };
                if plan.next_value == current_value {
                    next_overrides.remove(&plan.entry_index);
                } else {
                    next_overrides.insert(plan.entry_index, plan.next_value.clone());
                }
            }
            planned_edits.push((row_index, next_overrides));
        }

        let planned_edits = planned_edits
            .into_iter()
            .filter(|(row_index, next_overrides)| {
                self.rows[*row_index].path_overrides != *next_overrides
            })
            .collect::<Vec<_>>();

        if planned_edits.is_empty() {
            self.record_job(
                "path-collect",
                workspace_root,
                Some(destination_folder),
                format!("{} file(s) copied, {} reused", result.copied, result.reused),
                false,
            );
            self.persist();
            cx.notify();
            return;
        }

        if let Err(err) = self.apply_path_override_updates(planned_edits, window, cx) {
            self.status_message = Some(BannerMessage::InlinePathEditFailed(err));
            return;
        }

        self.record_job(
            "path-collect",
            workspace_root,
            Some(destination_folder),
            format!(
                "{} file(s) copied, {} reused, {} path(s) staged",
                result.copied,
                result.reused,
                plans.len()
            ),
            false,
        );
        self.refresh_file_table(cx);
        self.persist();
        cx.notify();
    }

    pub(super) fn current_path_table_model(&self) -> PathTableModel {
        let mut model = build_path_table_model_with_order_snapshot(
            &self.rows,
            &self.selected_indices(),
            &self.state,
            self.active_path_edit.clone(),
            &self.selected_path_rows,
            self.path_table_dedup,
            &self.path_search_query,
            &self.path_type_filter,
            &self.path_form_filter,
            &self.path_resolution_filter,
            self.path_sort,
            self.path_order_snapshot.as_ref(),
        );
        if self.path_dirty_only {
            model.rows.retain(|row| row.dirty);
        }
        model
    }

    pub(super) fn current_audit_table_model(&self) -> AuditTableModel {
        build_audit_table_model(
            &self.audit_all_rows,
            &self.selected_audit_keys,
            &self.audit_severity_filter,
            self.audit_dirty_only,
            self.audit_table_dedup,
            &self.audit_search_query,
            self.audit_sort,
            self.locale(),
        )
    }

    pub(super) fn refresh_path_table(&mut self, cx: &mut Context<Self>) {
        let i18n = self.i18n();
        let path_table = self.current_path_table_model();
        let visible_targets = path_table
            .rows
            .iter()
            .map(|row| row.edit_targets.clone())
            .filter(|targets| !targets.is_empty())
            .collect::<BTreeSet<_>>();
        self.selected_path_rows
            .retain(|targets| visible_targets.contains(targets));
        if self
            .path_selection_anchor
            .as_ref()
            .is_some_and(|targets| !visible_targets.contains(targets))
        {
            self.path_selection_anchor = None;
        }
        self.path_table.update(cx, |table, cx| {
            table.delegate_mut().sync(
                path_table.rows,
                i18n.locale(),
                path_table.show_scene_column,
                self.path_sort,
            );
            table.refresh(cx);
        });
    }

    pub(super) fn begin_path_edit(
        &mut self,
        edit_targets: PathEditTargets,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }

        let (first_row_id, first_entry_index) = edit_targets[0];
        let Some(primary_row_index) = self.index_of_row_id(first_row_id) else {
            return;
        };
        let Some(primary_value) =
            self.current_path_value(&self.rows[primary_row_index], first_entry_index)
        else {
            return;
        };

        for (row_id, entry_index) in &edit_targets {
            let Some(row_index) = self.index_of_row_id(*row_id) else {
                return;
            };
            let Some(row) = self.rows.get(row_index) else {
                return;
            };
            if !row.selected || !path_value_edit_supported_for_entry(row, *entry_index) {
                return;
            }
            let Some(_report) = row.display_paths_report() else {
                return;
            };
            let Some(current_value) = self.current_path_value(row, *entry_index) else {
                return;
            };
            if current_value != primary_value {
                return;
            }
        }

        self.path_edit_input
            .update(cx, |input, cx| input.set_value(primary_value, window, cx));
        let focus_handle = self.path_edit_input.read(cx).focus_handle(cx);
        focus_handle.focus(window);
        self.active_path_edit = Some(edit_targets);
        self.refresh_path_table(cx);
        cx.notify();
    }

    pub(super) fn select_path_row(
        &mut self,
        edit_targets: PathEditTargets,
        modifiers: Modifiers,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }

        let path_table = self.current_path_table_model();
        let toggle = modifiers.control || modifiers.platform;
        let extend = modifiers.shift;

        self.active_path_edit = None;

        if extend {
            let anchor = self
                .path_selection_anchor
                .clone()
                .filter(|anchor| {
                    path_table
                        .rows
                        .iter()
                        .any(|row| &row.edit_targets == anchor)
                })
                .unwrap_or_else(|| edit_targets.clone());
            let Some(range_targets) =
                visible_path_selection_targets(&path_table.rows, &anchor, &edit_targets)
            else {
                return;
            };
            if !toggle {
                self.selected_path_rows.clear();
            }
            self.selected_path_rows.extend(range_targets);
            self.path_selection_anchor = Some(anchor);
            self.refresh_path_table(cx);
            cx.notify();
            return;
        }

        if toggle {
            if !self.selected_path_rows.insert(edit_targets.clone()) {
                self.selected_path_rows.remove(&edit_targets);
            }
            self.path_selection_anchor = Some(edit_targets);
            self.refresh_path_table(cx);
            cx.notify();
            return;
        }

        self.selected_path_rows.clear();
        self.selected_path_rows.insert(edit_targets.clone());
        self.path_selection_anchor = Some(edit_targets);
        self.refresh_path_table(cx);
        cx.notify();
    }

    pub(super) fn cancel_path_edit_state(&mut self, cx: &mut Context<Self>) {
        self.active_path_edit = None;
        self.selected_path_rows.clear();
        self.path_selection_anchor = None;
        self.refresh_path_table(cx);
        cx.notify();
    }

    pub(super) fn cancel_path_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.cancel_path_edit_state(cx);
        self.path_edit_input
            .update(cx, |input, cx| input.set_value("", window, cx));
    }

    pub(super) fn path_edit_keyboard_outcome(
        &mut self,
        key: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> PathEditKeyboardOutcome {
        let has_marked_text = self.path_edit_input.update(cx, |input, cx| {
            input.marked_text_range(window, cx).is_some()
        });
        path_edit_keyboard_outcome(key, has_marked_text)
    }

    pub(super) fn apply_path_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(edit_targets) = self.active_path_edit.clone() else {
            return;
        };
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            self.cancel_path_edit(window, cx);
            return;
        }

        let new_value = self.path_edit_input.read(cx).value().to_string();
        let mut row_targets: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();

        for (row_id, entry_index) in &edit_targets {
            let Some(row_index) = self.index_of_row_id(*row_id) else {
                self.cancel_path_edit(window, cx);
                return;
            };
            let Some(row) = self.rows.get(row_index) else {
                self.cancel_path_edit(window, cx);
                return;
            };
            if !row.selected || !path_value_edit_supported_for_entry(row, *entry_index) {
                self.cancel_path_edit(window, cx);
                return;
            }
            let Some(report) = row.display_paths_report() else {
                self.cancel_path_edit(window, cx);
                return;
            };
            let Some(_entry) = report.entries.get(*entry_index) else {
                self.cancel_path_edit(window, cx);
                return;
            };
            row_targets
                .entry(row_index)
                .or_default()
                .insert(*entry_index);
        }

        let mut planned_edits = Vec::<(usize, BTreeMap<usize, String>)>::new();
        for (row_index, entry_indices) in row_targets {
            let Some(_report) = self.rows[row_index].display_paths_report() else {
                self.cancel_path_edit(window, cx);
                return;
            };

            let mut next_overrides = self.rows[row_index].path_overrides.clone();
            for entry_index in entry_indices {
                let Some(current_value) =
                    self.current_path_value(&self.rows[row_index], entry_index)
                else {
                    self.cancel_path_edit(window, cx);
                    return;
                };
                if new_value == current_value {
                    next_overrides.remove(&entry_index);
                } else {
                    next_overrides.insert(entry_index, new_value.clone());
                }
            }

            planned_edits.push((row_index, next_overrides));
        }

        if self
            .apply_path_override_updates(planned_edits, window, cx)
            .is_err()
        {
            self.cancel_path_edit(window, cx);
            return;
        }

        self.cancel_path_edit(window, cx);
        self.refresh_file_table(cx);
        self.persist();
    }

    fn apply_path_override_updates(
        &mut self,
        planned_edits: Vec<(usize, BTreeMap<usize, String>)>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Result<(), String> {
        let path_order_snapshot = self.capture_path_order_snapshot();
        let row_indices = planned_edits
            .iter()
            .map(|(row_index, _)| *row_index)
            .collect::<Vec<_>>();
        let requires_scene_edit_restaging = planned_edits.iter().any(|(row_index, _)| {
            let row = &self.rows[*row_index];
            row.scene_edits_are_staged()
                || !row.pending_clean_targets.is_empty()
                || !row.pending_path_owner_delete_targets.is_empty()
        });
        let before =
            (!requires_scene_edit_restaging).then(|| self.capture_row_edit_states(&row_indices));
        let edit_sequence = if requires_scene_edit_restaging {
            self.begin_edit_transaction(&row_indices)
        } else {
            None
        };
        let mut inline_job_records = Vec::new();
        for (row_index, next_overrides) in planned_edits {
            let Some(report) = self.rows[row_index].display_paths_report() else {
                return Err("missing path report for override update".to_string());
            };
            let staged_overrides = next_overrides
                .iter()
                .filter_map(|(ix, after_value)| {
                    report.entries.get(*ix).map(|entry| PathReplaceOverride {
                        entry_index: *ix,
                        before_value: entry.value.clone(),
                        after_value: after_value.clone(),
                    })
                })
                .collect::<Vec<_>>();
            let preview = if staged_overrides.is_empty() {
                None
            } else {
                let options = self.scene_materialize_options(OperationMode::Forensic);
                Some(
                    preview_replace_scene_paths_with_overrides_in_report_with_options(
                        report,
                        &staged_overrides,
                        &options,
                    )
                    .map_err(|err| err.to_string())?,
                )
            };

            let row_id = self.rows[row_index].id;
            let row_path = self.rows[row_index].path.clone();
            let mut revision = None;
            let mut summary = "cleared".to_string();
            let pending_clean_targets = self.rows[row_index].pending_clean_targets.clone();
            let pending_path_owner_delete_targets = self.rows[row_index]
                .pending_path_owner_delete_targets
                .clone();
            let restage_scene_edits = self.rows[row_index].scene_edits_are_staged()
                || !pending_clean_targets.is_empty()
                || !pending_path_owner_delete_targets.is_empty();
            let row = &mut self.rows[row_index];
            row.path_overrides = next_overrides;
            row.replace_generation = row.replace_generation.wrapping_add(1);
            row.replace_artifact_generation = None;
            if restage_scene_edits {
                row.replace_preview = None;
                summary = if row.path_overrides.is_empty() {
                    "scene edits restaged".to_string()
                } else {
                    format!("{} composite path edit(s) staged", row.path_overrides.len())
                };
            } else {
                row.dirty_artifact = None;
                row.staged_audit_mode = None;
                row.staged_audit_report = None;
                row.staged_paths_report = None;
                row.staged_dump_report = None;
                row.staged_source_bytes = None;
                row.pending_clean_targets.clear();
                row.pending_path_owner_delete_targets.clear();
                row.clean_preview = None;
                row.path_owner_delete_preview = None;
                match preview {
                    Some(preview) => {
                        let matched = preview.matched_count;
                        row.dirty_kind = Some(DirtyKind::Replace);
                        row.replace_preview = Some(preview);
                        row.status = FileStatus::Dirty;
                        summary = format!("{matched} match(es) staged");
                        revision = Some(row.replace_generation);
                    }
                    None => {
                        row.dirty_kind = None;
                        row.replace_preview = None;
                        row.status = if row.paths_report.is_some() {
                            FileStatus::Audited
                        } else {
                            FileStatus::Idle
                        };
                    }
                }
                row.sync_findings_count();
            }
            self.refresh_row_path_resolution_state(row_index);
            if restage_scene_edits {
                self.stage_scene_edits_for_row(
                    row_index,
                    pending_clean_targets,
                    pending_path_owner_delete_targets,
                    ResultTab::Paths,
                    edit_sequence,
                    false,
                    window,
                    cx,
                );
            } else {
                inline_job_records.push((row_path, summary, false));
                if let Some(revision) = revision {
                    self.spawn_replace_artifact_refresh(row_id, revision, window, cx);
                }
                if let Some(edit_sequence) = edit_sequence {
                    self.complete_edit_transaction_success(edit_sequence, row_id);
                }
            }
        }

        for (row_path, summary, failed) in inline_job_records {
            self.record_job("replace-inline", row_path, None, summary, failed);
        }
        if let Some(before) = before {
            self.push_edit_history(before);
        }
        self.preserve_path_order_after_path_mutation(path_order_snapshot);
        self.refresh_app_menus(window, cx);

        Ok(())
    }

    pub(super) fn undo_path_edit_targets(
        &mut self,
        edit_targets: PathEditTargets,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }

        let mut row_targets: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (row_id, entry_index) in edit_targets {
            let Some(row_index) = self.index_of_row_id(row_id) else {
                return;
            };
            if self.rows[row_index].is_processing() {
                return;
            }
            row_targets
                .entry(row_index)
                .or_default()
                .insert(entry_index);
        }

        let mut planned_edits = Vec::new();
        for (row_index, entry_indices) in row_targets {
            let mut next_overrides = self.rows[row_index].path_overrides.clone();
            for entry_index in entry_indices {
                next_overrides.remove(&entry_index);
            }
            planned_edits.push((row_index, next_overrides));
        }

        if let Err(err) = self.apply_path_override_updates(planned_edits, window, cx) {
            self.status_message = Some(BannerMessage::InlinePathEditFailed(err));
            return;
        }
        self.refresh_file_table(cx);
        self.persist();
        cx.notify();
    }

    fn undo_staged_path_owner_delete_targets(
        &mut self,
        targets_by_row: BTreeMap<usize, BTreeSet<PathOwnerDeleteTarget>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if targets_by_row.is_empty() {
            return;
        }

        let row_indices = targets_by_row.keys().copied().collect::<Vec<_>>();
        let edit_sequence = self.begin_edit_transaction(&row_indices);
        for (row_index, targets) in targets_by_row {
            let mut next_path_owner_delete_targets = self.rows[row_index]
                .pending_path_owner_delete_targets
                .clone();
            for target in targets {
                next_path_owner_delete_targets.remove(&target);
            }

            let next_clean_targets = self.rows[row_index].pending_clean_targets.clone();
            if next_clean_targets.is_empty() && next_path_owner_delete_targets.is_empty() {
                self.clear_clean_state_for_row(row_index, true, edit_sequence, cx);
            } else {
                self.stage_scene_edits_for_row(
                    row_index,
                    next_clean_targets,
                    next_path_owner_delete_targets,
                    ResultTab::Paths,
                    edit_sequence,
                    true,
                    window,
                    cx,
                );
            }
        }
    }

    pub(super) fn undo_row_changes_for_ids(
        &mut self,
        row_ids: Vec<u64>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let row_indices = row_ids
            .into_iter()
            .filter_map(|row_id| self.index_of_row_id(row_id))
            .filter(|row_index| {
                self.rows
                    .get(*row_index)
                    .is_some_and(|row| row.dirty() && !row.is_processing())
            })
            .collect::<Vec<_>>();
        if row_indices.is_empty() {
            return;
        }

        let before = self.capture_row_edit_states(&row_indices);
        for row_index in row_indices {
            let row_path = self.rows[row_index].path.clone();
            if !self.rows[row_index].path_overrides.is_empty() {
                let row = &mut self.rows[row_index];
                row.path_overrides.clear();
                row.dirty_artifact = None;
                row.dirty_kind = None;
                row.clean_preview = None;
                row.replace_preview = None;
                row.ascii_report = None;
                row.path_owner_delete_preview = None;
                row.pending_clean_targets.clear();
                row.pending_path_owner_delete_targets.clear();
                row.staged_audit_mode = None;
                row.staged_audit_report = None;
                row.staged_paths_report = None;
                row.staged_dump_report = None;
                row.staged_source_bytes = None;
                row.replace_artifact_generation = None;
                row.status = if row.audit_report.is_some()
                    || row.paths_report.is_some()
                    || row.dump_report.is_some()
                {
                    FileStatus::Audited
                } else {
                    FileStatus::Idle
                };
                row.sync_findings_count();
                self.refresh_row_path_resolution_state(row_index);
            } else {
                let row = &mut self.rows[row_index];
                row.dirty_artifact = None;
                row.dirty_kind = None;
                row.clean_preview = None;
                row.replace_preview = None;
                row.ascii_report = None;
                row.path_owner_delete_preview = None;
                row.pending_clean_targets.clear();
                row.pending_path_owner_delete_targets.clear();
                row.staged_audit_mode = None;
                row.staged_audit_report = None;
                row.staged_paths_report = None;
                row.staged_dump_report = None;
                row.staged_source_bytes = None;
                row.replace_artifact_generation = None;
                row.status = if row.audit_report.is_some()
                    || row.paths_report.is_some()
                    || row.dump_report.is_some()
                {
                    FileStatus::Audited
                } else {
                    FileStatus::Idle
                };
                row.sync_findings_count();
                self.refresh_row_path_resolution_state(row_index);
            }
            self.record_job("undo", row_path, None, "cleared".to_string(), false);
        }

        self.push_edit_history(before);
        self.refresh_app_menus(_window, cx);
        self.refresh_file_table(cx);
        self.persist();
        cx.notify();
    }

    fn clear_clean_state_for_row(
        &mut self,
        row_index: usize,
        record_undo: bool,
        edit_sequence: Option<u64>,
        cx: &mut Context<Self>,
    ) {
        let row_id = self.rows[row_index].id;
        let row_path = self.rows[row_index].path.clone();
        self.clear_staged_scene_edits_for_row(row_index);
        if record_undo {
            self.record_job("undo", row_path, None, "cleared".to_string(), false);
        }
        if let Some(edit_sequence) = edit_sequence {
            self.complete_edit_transaction_success(edit_sequence, row_id);
        }
        self.refresh_file_table(cx);
        self.persist();
        cx.notify();
    }

    fn clear_staged_scene_edits_for_row(&mut self, row_index: usize) {
        let row = &mut self.rows[row_index];
        row.dirty_artifact = None;
        row.clean_preview = None;
        row.path_owner_delete_preview = None;
        row.pending_clean_targets.clear();
        row.pending_path_owner_delete_targets.clear();
        row.staged_audit_mode = None;
        row.staged_audit_report = None;
        row.staged_paths_report = None;
        row.staged_dump_report = None;
        row.staged_source_bytes = None;
        if matches!(
            row.dirty_kind,
            Some(DirtyKind::SceneEdits | DirtyKind::Clean)
        ) {
            row.dirty_kind = None;
        }
        row.status = if row.audit_report.is_some()
            || row.paths_report.is_some()
            || row.dump_report.is_some()
        {
            FileStatus::Audited
        } else {
            FileStatus::Idle
        };
        row.sync_findings_count();
    }

    pub(super) fn stage_scene_edits_for_row(
        &mut self,
        row_index: usize,
        clean_targets: BTreeSet<ExecutionCleanTarget>,
        path_owner_delete_targets: BTreeSet<PathOwnerDeleteTarget>,
        target_tab: ResultTab,
        edit_sequence: Option<u64>,
        record_empty_success: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if clean_targets.is_empty() && path_owner_delete_targets.is_empty() {
            self.clear_staged_scene_edits_for_row(row_index);
            if let Some(edit_sequence) = edit_sequence {
                let row_id = self.rows[row_index].id;
                self.complete_edit_transaction_success(edit_sequence, row_id);
            }
            if record_empty_success {
                let row_path = self.rows[row_index].path.clone();
                self.record_job("undo", row_path, None, "cleared".to_string(), false);
            }
            self.refresh_file_table(cx);
            self.persist();
            cx.notify();
            return;
        }

        let row_id = self.rows[row_index].id;
        let audit_mode = self.rows[row_index]
            .analyzed_audit_mode
            .unwrap_or(AuditModePreference::StrictDefault);
        let base_report = self.rows[row_index].display_paths_report().cloned();
        let path_overrides = self.rows[row_index].path_overrides.clone();
        let replace_artifact = self.rows[row_index].dirty_artifact.clone();
        let replace_artifact_current = self.rows[row_index].replace_artifact_is_current();
        let clean_targets = clean_targets.into_iter().collect::<Vec<_>>();
        let path_owner_delete_targets = path_owner_delete_targets.into_iter().collect::<Vec<_>>();
        let materialize_options = self.scene_materialize_options(OperationMode::Forensic);
        let load_options = self.scene_load_options();
        self.spawn_row_job(
            row_id,
            if clean_targets.is_empty() {
                RowOperation::DeleteOwnerNodes
            } else {
                RowOperation::Clean
            },
            Some(target_tab),
            edit_sequence,
            window,
            cx,
            move |path| {
                let staged = if path_overrides.is_empty() {
                    stage_scene_edits_with_options(
                        &path,
                        &clean_targets,
                        &path_owner_delete_targets,
                        &materialize_options,
                    )
                    .map_err(|err| err.to_string())?
                } else {
                    let base_report = base_report
                        .clone()
                        .ok_or_else(|| "missing path report for scene edits".to_string())?;
                    let replace_overrides =
                        replace_overrides_for_row_from_map(&base_report, &path_overrides)?;
                    let replace_bytes = if replace_artifact_current {
                        replace_artifact
                            .clone()
                            .ok_or_else(|| {
                                "missing staged replace artifact for scene edits".to_string()
                            })?
                            .bytes
                    } else {
                        stage_replace_scene_paths_with_overrides_in_report_with_options(
                            &base_report,
                            &replace_overrides,
                            &materialize_options,
                        )
                        .map_err(|err| err.to_string())?
                        .artifact
                        .bytes
                    };
                    let observation = Loader::new(load_options.clone())
                        .observe_bytes(
                            &path,
                            base_report.scene_format,
                            base_report.validation_state,
                            replace_bytes.clone(),
                        )
                        .map_err(|err| err.to_string())?;
                    let current_report = ScenePathsReport {
                        scene_path: observation.scene_path().to_path_buf(),
                        scene_format: observation.scene_format(),
                        validation_state: observation.validation_state(),
                        entries: observation
                            .scene_paths(PathKind::All)
                            .map_err(|err| err.to_string())?,
                    };
                    stage_scene_edits_in_report_with_bytes_with_options(
                        &current_report,
                        &replace_bytes,
                        &clean_targets,
                        &path_owner_delete_targets,
                        &materialize_options,
                    )
                    .map_err(|err| err.to_string())?
                };
                let staged_source_bytes = staged.artifact.bytes.clone();
                let analyzed = analyze_row_bytes_with_options(
                    &path,
                    staged.preview.scene_format,
                    staged.preview.validation_state,
                    staged_source_bytes.clone(),
                    audit_mode,
                    &load_options,
                )?;
                let staged_paths_report = analyzed.paths_report.ok_or_else(|| {
                    "parse budget exceeded while rebuilding path preview".to_string()
                })?;
                let staged_dump_report = analyzed.dump_report.ok_or_else(|| {
                    "parse budget exceeded while rebuilding dump preview".to_string()
                })?;
                Ok(RowJobResult::SceneEdits {
                    staged,
                    audit_mode,
                    staged_audit_report: analyzed.audit_report,
                    staged_paths_report,
                    staged_dump_report,
                    staged_source_bytes,
                })
            },
        );
    }

    fn stage_clean_targets_for_row(
        &mut self,
        row_index: usize,
        targets: BTreeSet<ExecutionCleanTarget>,
        target_tab: ResultTab,
        edit_sequence: Option<u64>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let path_owner_delete_targets = self.rows[row_index]
            .pending_path_owner_delete_targets
            .clone();
        if targets.is_empty() && path_owner_delete_targets.is_empty() {
            self.clear_clean_state_for_row(row_index, false, edit_sequence, cx);
            return;
        }
        self.stage_scene_edits_for_row(
            row_index,
            targets,
            path_owner_delete_targets,
            target_tab,
            edit_sequence,
            false,
            window,
            cx,
        );
    }

    pub(super) fn run_audit_row_clean(
        &mut self,
        row_keys: Vec<AuditResultRowKey>,
        target: ExecutionCleanTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.run_audit_key_targets(row_keys, target, AuditRowCleanState::Available, window, cx);
    }

    pub(super) fn undo_audit_row_clean(
        &mut self,
        row_keys: Vec<AuditResultRowKey>,
        target: ExecutionCleanTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.run_audit_key_targets(row_keys, target, AuditRowCleanState::Staged, window, cx);
    }

    fn audit_targets_by_row(
        &self,
        rows: &[AuditTableRow],
        state: AuditRowCleanState,
    ) -> BTreeMap<usize, BTreeSet<ExecutionCleanTarget>> {
        let mut by_row = BTreeMap::<usize, BTreeSet<ExecutionCleanTarget>>::new();
        for row in rows {
            if row.clean_state != state {
                continue;
            }
            let Some(target) = row.clean_target.clone() else {
                continue;
            };
            for key in &row.row_keys {
                let Some(row_index) = self.index_of_row_id(key.row_id) else {
                    continue;
                };
                by_row.entry(row_index).or_default().insert(target.clone());
            }
        }
        by_row
    }

    fn run_audit_key_targets(
        &mut self,
        row_keys: Vec<AuditResultRowKey>,
        target: ExecutionCleanTarget,
        state: AuditRowCleanState,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let rows = vec![AuditTableRow {
            key: row_keys.first().cloned().unwrap_or(AuditResultRowKey {
                row_id: 0,
                item_kind: AuditResultItemKind::Finding,
                item_index: 0,
            }),
            row_keys,
            selected: false,
            scene_name: String::new(),
            scene_names: Vec::new(),
            severity: AuditSeverity::Info,
            summary: String::new(),
            code: String::new(),
            sink: String::new(),
            preview: String::new(),
            source_line: None,
            evidence: Vec::new(),
            dirty: state == AuditRowCleanState::Staged,
            clean_target: Some(target),
            clean_state: state,
        }];
        match state {
            AuditRowCleanState::Available => self.run_audit_table_clean(rows, window, cx),
            AuditRowCleanState::Staged => self.undo_audit_table_clean(rows, window, cx),
            AuditRowCleanState::Unsupported | AuditRowCleanState::BlockedByOtherDirty => {}
        }
    }

    pub(super) fn run_audit_table_clean(
        &mut self,
        rows: Vec<AuditTableRow>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let targets_by_row = self.audit_targets_by_row(&rows, AuditRowCleanState::Available);
        let row_indices = targets_by_row.keys().copied().collect::<Vec<_>>();
        let edit_sequence = self.begin_edit_transaction(&row_indices);
        for (row_index, targets) in targets_by_row {
            let mut next_targets = self.rows[row_index].pending_clean_targets.clone();
            next_targets.extend(targets);
            self.stage_clean_targets_for_row(
                row_index,
                next_targets,
                ResultTab::Audit,
                edit_sequence,
                window,
                cx,
            );
        }
    }

    pub(super) fn undo_audit_table_clean(
        &mut self,
        rows: Vec<AuditTableRow>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let targets_by_row = self.audit_targets_by_row(&rows, AuditRowCleanState::Staged);
        let row_indices = targets_by_row.keys().copied().collect::<Vec<_>>();
        let edit_sequence = self.begin_edit_transaction(&row_indices);
        for (row_index, targets) in targets_by_row {
            let mut next_targets = self.rows[row_index].pending_clean_targets.clone();
            for target in targets {
                next_targets.remove(&target);
            }
            if next_targets.is_empty() {
                let path_owner_delete_targets = self.rows[row_index]
                    .pending_path_owner_delete_targets
                    .clone();
                if path_owner_delete_targets.is_empty() {
                    self.clear_clean_state_for_row(row_index, true, edit_sequence, cx);
                } else {
                    self.stage_scene_edits_for_row(
                        row_index,
                        next_targets,
                        path_owner_delete_targets,
                        ResultTab::Audit,
                        edit_sequence,
                        true,
                        window,
                        cx,
                    );
                }
            } else {
                self.stage_clean_targets_for_row(
                    row_index,
                    next_targets,
                    ResultTab::Audit,
                    edit_sequence,
                    window,
                    cx,
                );
            }
        }
    }

    pub(super) fn seed_replace_dialog_source_cache(
        &self,
    ) -> BTreeMap<u64, ReplaceDialogSourceCacheEntry> {
        self.ready_selected_indices()
            .into_iter()
            .filter_map(|index| {
                let row = self.rows.get(index)?;
                let report = row.display_paths_report().cloned()?;
                Some((
                    row.id,
                    ReplaceDialogSourceCacheEntry {
                        report,
                        base_overrides: row.path_overrides.clone(),
                    },
                ))
            })
            .collect()
    }

    pub(super) fn toggle_path_table_dedup(&mut self, cx: &mut Context<Self>) {
        self.path_table_dedup = !self.path_table_dedup;
        self.refresh_path_table(cx);
    }

    pub(super) fn toggle_path_dirty_filter(&mut self, cx: &mut Context<Self>) {
        self.path_dirty_only = !self.path_dirty_only;
        self.refresh_path_table(cx);
    }

    pub(super) fn toggle_audit_table_dedup(&mut self, cx: &mut Context<Self>) {
        self.audit_table_dedup = !self.audit_table_dedup;
        self.refresh_audit_table(cx);
    }

    pub(super) fn toggle_audit_dirty_filter(&mut self, cx: &mut Context<Self>) {
        self.audit_dirty_only = !self.audit_dirty_only;
        self.refresh_audit_table(cx);
    }

    pub(super) fn toggle_path_type_filter(
        &mut self,
        filter: PathTypeFilter,
        cx: &mut Context<Self>,
    ) {
        if !self.path_type_filter.insert(filter) {
            self.path_type_filter.remove(&filter);
        }
        self.refresh_path_table(cx);
    }

    pub(super) fn toggle_path_form_filter(
        &mut self,
        filter: PathFormFilter,
        cx: &mut Context<Self>,
    ) {
        if !self.path_form_filter.insert(filter) {
            self.path_form_filter.remove(&filter);
        }
        self.refresh_path_table(cx);
    }

    pub(super) fn toggle_path_resolution_filter(
        &mut self,
        filter: PathResolutionBadge,
        cx: &mut Context<Self>,
    ) {
        if !self.path_resolution_filter.insert(filter) {
            self.path_resolution_filter.remove(&filter);
        }
        self.refresh_path_table(cx);
    }

    pub(super) fn toggle_audit_severity(
        &mut self,
        severity: AuditSeverityFilter,
        cx: &mut Context<Self>,
    ) {
        if !self.audit_severity_filter.insert(severity) {
            self.audit_severity_filter.remove(&severity);
        }
        self.refresh_audit_table(cx);
    }

    pub(super) fn run_delete_selected_path_owner_nodes(
        &mut self,
        selected_rows: Vec<PathEditTargets>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let mut targets_by_row = BTreeMap::<usize, BTreeSet<PathOwnerDeleteTarget>>::new();
        for edit_targets in selected_rows {
            for (row_id, entry_index) in edit_targets {
                let Some(row_index) = self.index_of_row_id(row_id) else {
                    continue;
                };
                let Some(row) = self.rows.get(row_index) else {
                    continue;
                };
                if row.is_processing() {
                    continue;
                }
                let Some(report) = row.display_paths_report() else {
                    continue;
                };
                let Some(entry) = report.entries.get(entry_index) else {
                    continue;
                };
                if !super::helpers::path_owner_delete_supported_for_entry(row, entry_index) {
                    continue;
                }
                targets_by_row
                    .entry(row_index)
                    .or_default()
                    .insert(PathOwnerDeleteTarget {
                        node_type: entry.node_type.clone(),
                        node_name: entry.node_name.clone(),
                    });
            }
        }

        let row_indices = targets_by_row.keys().copied().collect::<Vec<_>>();
        let edit_sequence = self.begin_edit_transaction(&row_indices);
        for (row_index, targets) in targets_by_row {
            if targets.is_empty() {
                continue;
            }
            let mut next_targets = self.rows[row_index]
                .pending_path_owner_delete_targets
                .clone();
            next_targets.extend(targets);
            self.stage_scene_edits_for_row(
                row_index,
                self.rows[row_index].pending_clean_targets.clone(),
                next_targets,
                ResultTab::Paths,
                edit_sequence,
                false,
                window,
                cx,
            );
        }
    }
}

fn replace_overrides_for_row_from_map(
    report: &ScenePathsReport,
    overrides: &BTreeMap<usize, String>,
) -> Result<Vec<PathReplaceOverride>, String> {
    overrides
        .iter()
        .map(|(entry_index, after_value)| {
            let entry = report
                .entries
                .get(*entry_index)
                .ok_or_else(|| format!("missing path entry {entry_index} for replace override"))?;
            Ok(PathReplaceOverride {
                entry_index: *entry_index,
                before_value: entry.value.clone(),
                after_value: after_value.clone(),
            })
        })
        .collect()
}

pub(super) fn normalize_path_edit_targets(mut targets: PathEditTargets) -> PathEditTargets {
    targets.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    targets.dedup();
    targets
}

pub(super) fn path_edit_targets_id(targets: &PathEditTargets) -> String {
    if targets.is_empty() {
        "none".to_string()
    } else {
        targets
            .iter()
            .map(|(row_id, entry_index)| format!("{row_id}-{entry_index}"))
            .collect::<Vec<_>>()
            .join("|")
    }
}

pub(super) fn scene_path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(super) fn write_back_selected_scene_path(
    selected_path: &Path,
    workspace_root: Option<&Path>,
    value_style: ScenePathValueStyle,
) -> String {
    if let Some(workspace_root) = workspace_root {
        if let Ok(relative) = selected_path.strip_prefix(workspace_root) {
            let relative = scene_path_string(relative);
            if !relative.is_empty() {
                return match value_style {
                    ScenePathValueStyle::DoubleSlashWorkspaceRelative => {
                        format!(
                            "{}//{}",
                            scene_path_string(workspace_root),
                            relative.trim_start_matches('/')
                        )
                    }
                    _ => relative,
                };
            }
        }
    }
    scene_path_string(selected_path)
}

pub(super) fn shared_workspace_root_for_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> Option<PathBuf> {
    let (first_row_id, _) = *edit_targets.first()?;
    let first_root = rows
        .iter()
        .find(|row| row.id == first_row_id)
        .and_then(|row| row.scene_workspace_root.clone())?;

    edit_targets
        .iter()
        .all(|(row_id, _)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .and_then(|row| row.scene_workspace_root.as_ref())
                == Some(&first_root)
        })
        .then_some(first_root)
}

pub(super) fn resolved_target_file_paths_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> Vec<PathBuf> {
    let mut resolved_paths = BTreeSet::new();

    for (row_id, entry_index) in edit_targets {
        let Some(row) = rows.iter().find(|row| row.id == *row_id) else {
            continue;
        };
        let Some(path) = resolved_target_file_path_for_entry(row, *entry_index) else {
            continue;
        };
        resolved_paths.insert(path);
    }

    resolved_paths.into_iter().collect()
}

pub(super) fn path_owner_delete_supported_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> bool {
    !edit_targets.is_empty()
        && edit_targets.iter().all(|(row_id, entry_index)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .is_some_and(|row| {
                    super::helpers::path_owner_delete_supported_for_entry(row, *entry_index)
                })
        })
}

fn path_owner_delete_target_for_entry(
    row: &SceneRow,
    entry_index: usize,
) -> Option<PathOwnerDeleteTarget> {
    let report = row.display_paths_report()?;
    let entry = report.entries.get(entry_index)?;
    Some(PathOwnerDeleteTarget {
        node_type: entry.node_type.clone(),
        node_name: entry.node_name.clone(),
    })
}

pub(super) fn path_owner_delete_staged_for_entry(row: &SceneRow, entry_index: usize) -> bool {
    let Some(target) = path_owner_delete_target_for_entry(row, entry_index) else {
        return false;
    };
    row.pending_path_owner_delete_targets.contains(&target)
        || row
            .path_owner_delete_preview
            .as_ref()
            .is_some_and(|preview| preview.deleted_targets.contains(&target))
}

pub(super) fn path_value_edit_supported_for_entry(row: &SceneRow, entry_index: usize) -> bool {
    row.display_paths_report()
        .and_then(|report| report.entries.get(entry_index))
        .is_some()
        && !row.is_processing()
        && !path_owner_delete_staged_for_entry(row, entry_index)
}

pub(super) fn path_value_edit_supported_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> bool {
    !edit_targets.is_empty()
        && edit_targets.iter().all(|(row_id, entry_index)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .is_some_and(|row| path_value_edit_supported_for_entry(row, *entry_index))
        })
}

pub(super) fn workspace_relative_override_value_for_entry(
    row: &SceneRow,
    entry_index: usize,
    rewrite_mode: PathCollectRewriteMode,
) -> Option<String> {
    let workspace_root = row.scene_workspace_root.as_deref()?;
    let current_value = effective_path_value_for_entry(row, entry_index)?;
    let fallback = row.path_resolution_fallback(entry_index, &current_value);
    let resolution = row
        .path_resolution(entry_index, &current_value)
        .or(fallback.as_ref())?;
    let resolved_path = resolution.resolved_path.as_deref()?;
    resolved_path.strip_prefix(workspace_root).ok()?;

    let value_style = path_collect_rewrite_value_style(rewrite_mode)?;
    let next_value =
        write_back_selected_scene_path(resolved_path, Some(workspace_root), value_style);
    (next_value != current_value).then_some(next_value)
}

pub(super) fn absolute_override_value_for_entry(
    row: &SceneRow,
    entry_index: usize,
) -> Option<String> {
    let current_value = effective_path_value_for_entry(row, entry_index)?;
    let fallback = row.path_resolution_fallback(entry_index, &current_value);
    let resolution = row
        .path_resolution(entry_index, &current_value)
        .or(fallback.as_ref())?;
    let resolved_path = resolution.resolved_path.as_deref()?;
    let next_value = scene_path_string(resolved_path);
    (next_value != current_value).then_some(next_value)
}

pub(super) fn path_collect_supported_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> bool {
    path_file_collect_supported_for_edit_targets(rows, edit_targets)
        && path_value_edit_supported_for_edit_targets(rows, edit_targets)
}

pub(super) fn path_file_collect_supported_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> bool {
    shared_workspace_root_for_targets(rows, edit_targets).is_some()
        && !edit_targets.is_empty()
        && edit_targets.iter().all(|(row_id, entry_index)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .and_then(|row| resolved_target_file_path_for_entry(row, *entry_index))
                .is_some()
        })
}

pub(super) fn path_collect_default_folder(workspace_root: &Path) -> PathBuf {
    workspace_root.join("sourceimages")
}

pub(super) fn parse_path_collect_folder_input(
    input: &str,
    workspace_root: &Path,
) -> Option<PathBuf> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(workspace_root.join(path))
    }
}

pub(super) fn collected_path_rewrite_value(
    destination_path: &Path,
    workspace_root: &Path,
    rewrite_mode: PathCollectRewriteMode,
) -> String {
    match rewrite_mode {
        PathCollectRewriteMode::CopyOnly => scene_path_string(destination_path),
        PathCollectRewriteMode::Absolute => scene_path_string(destination_path),
        PathCollectRewriteMode::WorkspaceDoubleSlashRelative => write_back_selected_scene_path(
            destination_path,
            Some(workspace_root),
            ScenePathValueStyle::DoubleSlashWorkspaceRelative,
        ),
        PathCollectRewriteMode::PlainRelative => write_back_selected_scene_path(
            destination_path,
            Some(workspace_root),
            ScenePathValueStyle::PlainRelative,
        ),
    }
}

pub(super) fn path_collect_destination_supports_rewrite_mode(
    destination_folder: &Path,
    workspace_root: &Path,
    rewrite_mode: PathCollectRewriteMode,
) -> bool {
    match rewrite_mode {
        PathCollectRewriteMode::CopyOnly => true,
        PathCollectRewriteMode::Absolute => true,
        PathCollectRewriteMode::WorkspaceDoubleSlashRelative
        | PathCollectRewriteMode::PlainRelative => {
            destination_folder.strip_prefix(workspace_root).is_ok()
        }
    }
}

fn path_collect_rewrite_value_style(
    rewrite_mode: PathCollectRewriteMode,
) -> Option<ScenePathValueStyle> {
    match rewrite_mode {
        PathCollectRewriteMode::CopyOnly => None,
        PathCollectRewriteMode::Absolute => None,
        PathCollectRewriteMode::WorkspaceDoubleSlashRelative => {
            Some(ScenePathValueStyle::DoubleSlashWorkspaceRelative)
        }
        PathCollectRewriteMode::PlainRelative => Some(ScenePathValueStyle::PlainRelative),
    }
}

pub(super) fn collect_target_files(plans: &[PathCollectPlan]) -> Result<PathCollectResult, String> {
    let mut by_destination = BTreeMap::<PathBuf, BTreeSet<PathBuf>>::new();
    for plan in plans {
        by_destination
            .entry(plan.destination_path.clone())
            .or_default()
            .insert(plan.source_path.clone());
    }

    let mut copied = 0usize;
    let mut reused = 0usize;
    for (destination_path, source_paths) in by_destination {
        let Some(source_path) = source_paths.iter().next().cloned() else {
            continue;
        };
        if !source_path.is_file() {
            return Err(format!(
                "source file is unavailable: {}",
                source_path.display()
            ));
        }

        let source_bytes = fs::read(&source_path)
            .map_err(|err| format!("failed to read {}: {err}", source_path.display()))?;
        for other_source in source_paths.iter().skip(1) {
            if !other_source.is_file() {
                return Err(format!(
                    "source file is unavailable: {}",
                    other_source.display()
                ));
            }
            let other_bytes = fs::read(other_source)
                .map_err(|err| format!("failed to read {}: {err}", other_source.display()))?;
            if other_bytes != source_bytes {
                return Err(format!(
                    "multiple source files map to {} with different contents",
                    destination_path.display()
                ));
            }
        }

        if destination_path.exists() {
            let destination_bytes = fs::read(&destination_path)
                .map_err(|err| format!("failed to read {}: {err}", destination_path.display()))?;
            if destination_bytes != source_bytes {
                return Err(format!(
                    "destination already exists with different contents: {}",
                    destination_path.display()
                ));
            }
            reused += 1;
            continue;
        }

        if source_path == destination_path {
            reused += 1;
            continue;
        }

        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        fs::copy(&source_path, &destination_path).map_err(|err| {
            format!(
                "failed to copy {} to {}: {err}",
                source_path.display(),
                destination_path.display()
            )
        })?;
        copied += 1;
    }

    Ok(PathCollectResult { copied, reused })
}

pub(super) fn resolved_target_file_path_for_entry(
    row: &SceneRow,
    entry_index: usize,
) -> Option<PathBuf> {
    let current_value = effective_path_value_for_entry(row, entry_index)?;
    let resolution = row
        .path_resolution(entry_index, &current_value)
        .cloned()
        .or_else(|| row.path_resolution_fallback(entry_index, &current_value))?;
    let resolved_path = resolution.resolved_path?;
    resolved_path.is_file().then_some(resolved_path)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PathCollectPlan {
    pub row_id: u64,
    pub entry_index: usize,
    pub row_index: usize,
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub next_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PathCollectResult {
    pub copied: usize,
    pub reused: usize,
}

fn effective_path_value_for_entry(row: &SceneRow, entry_index: usize) -> Option<String> {
    let report = row.display_paths_report()?;
    let entry = report.entries.get(entry_index)?;
    Some(
        row.path_overrides
            .get(&entry_index)
            .cloned()
            .unwrap_or_else(|| entry.value.clone()),
    )
}

fn copy_file_drop_paths_to_system_clipboard(paths: &[PathBuf]) -> Result<(), String> {
    if paths.is_empty() {
        return Err("no resolved files to copy".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        let path_literals = paths
            .iter()
            .map(|path| format!("'{}'", path.to_string_lossy().replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(", ");
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; \
             $paths = New-Object System.Collections.Specialized.StringCollection; \
             @({}) | ForEach-Object {{ [void]$paths.Add($_) }}; \
             [System.Windows.Forms.Clipboard]::SetFileDropList($paths)",
            path_literals
        );
        let output = std::process::Command::new("powershell.exe")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-STA",
                "-Command",
                script.as_str(),
            ])
            .output()
            .map_err(|err| format!("failed to copy file to clipboard: {err}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(if stderr.is_empty() {
                "failed to copy file to clipboard".to_string()
            } else {
                format!("failed to copy file to clipboard: {stderr}")
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = paths;
        Err("copy file to clipboard is only supported on Windows".to_string())
    }
}
