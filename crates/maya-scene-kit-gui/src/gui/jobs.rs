use maya_scene_kit_edit::scene::OperationMode;

use super::*;

impl GuiShell {
    pub(super) fn rebuild_row_id_index(&mut self) {
        self.row_id_to_index = self
            .rows
            .iter()
            .enumerate()
            .map(|(index, row)| (row.id, index))
            .collect();
    }

    pub(super) fn replace_rows(&mut self, rows: Vec<SceneRow>) {
        self.rows = rows;
        self.rebuild_row_id_index();
    }

    pub(super) fn clear_rows(&mut self) {
        self.rows.clear();
        self.row_id_to_index.clear();
    }

    pub(super) fn capture_row_edit_states(
        &self,
        row_indices: &[usize],
    ) -> Vec<(u64, SceneRowEditState)> {
        row_indices
            .iter()
            .filter_map(|row_index| {
                self.rows
                    .get(*row_index)
                    .map(|row| (row.id, row.edit_state()))
            })
            .collect()
    }

    fn next_edit_history_sequence(&mut self) -> u64 {
        let sequence = self.next_edit_history_sequence;
        self.next_edit_history_sequence = self.next_edit_history_sequence.wrapping_add(1);
        sequence
    }

    fn build_edit_history_entry(
        &self,
        before: Vec<(u64, SceneRowEditState)>,
    ) -> Option<GuiEditHistoryEntry> {
        let mut transitions = Vec::new();
        for (row_id, before_state) in before {
            let Some(row_index) = self.index_of_row_id(row_id) else {
                continue;
            };
            let after_state = self.rows[row_index].edit_state();
            if !after_state.same_as(&before_state) {
                transitions.push(RowEditTransition {
                    row_id,
                    before: before_state,
                    after: after_state,
                });
            }
        }
        (!transitions.is_empty()).then_some(GuiEditHistoryEntry { transitions })
    }

    fn queue_completed_edit_history(&mut self, sequence: u64, entry: Option<GuiEditHistoryEntry>) {
        self.completed_edit_history.insert(sequence, entry);
        self.flush_completed_edit_history();
    }

    fn flush_completed_edit_history(&mut self) {
        while let Some(entry) = self
            .completed_edit_history
            .remove(&self.next_edit_history_commit_sequence)
        {
            if let Some(entry) = entry {
                self.undo_stack.push(entry);
                self.redo_stack.clear();
            }
            self.next_edit_history_commit_sequence =
                self.next_edit_history_commit_sequence.wrapping_add(1);
        }
    }

    pub(super) fn push_edit_history(&mut self, before: Vec<(u64, SceneRowEditState)>) {
        let sequence = self.next_edit_history_sequence();
        let entry = self.build_edit_history_entry(before);
        self.queue_completed_edit_history(sequence, entry);
    }

    pub(super) fn begin_edit_transaction(&mut self, row_indices: &[usize]) -> Option<u64> {
        let before = self.capture_row_edit_states(row_indices);
        if before.is_empty() {
            return None;
        }
        let row_ids = before.iter().map(|(row_id, _)| *row_id).collect::<Vec<_>>();
        let remaining_row_ids = row_ids.iter().copied().collect::<BTreeSet<_>>();
        let before_states = before.into_iter().collect::<BTreeMap<_, _>>();
        let sequence = self.next_edit_history_sequence();
        self.pending_edit_transactions.insert(
            sequence,
            PendingEditTransaction {
                row_ids,
                before_states,
                successful_after_states: BTreeMap::new(),
                remaining_row_ids,
            },
        );
        Some(sequence)
    }

    fn finalize_edit_transaction(&mut self, sequence: u64) {
        let Some(transaction) = self.pending_edit_transactions.remove(&sequence) else {
            return;
        };
        let mut transitions = Vec::new();
        for row_id in transaction.row_ids {
            let Some(before) = transaction.before_states.get(&row_id) else {
                continue;
            };
            let Some(after) = transaction.successful_after_states.get(&row_id) else {
                continue;
            };
            if !after.same_as(before) {
                transitions.push(RowEditTransition {
                    row_id,
                    before: before.clone(),
                    after: after.clone(),
                });
            }
        }
        let entry = (!transitions.is_empty()).then_some(GuiEditHistoryEntry { transitions });
        self.queue_completed_edit_history(sequence, entry);
    }

    pub(super) fn complete_edit_transaction_success(&mut self, sequence: u64, row_id: u64) {
        let Some(row_index) = self.index_of_row_id(row_id) else {
            self.complete_edit_transaction_failure(sequence, row_id);
            return;
        };
        let after_state = self.rows[row_index].edit_state();
        let Some(transaction) = self.pending_edit_transactions.get_mut(&sequence) else {
            return;
        };
        transaction
            .successful_after_states
            .insert(row_id, after_state);
        transaction.remaining_row_ids.remove(&row_id);
        if transaction.remaining_row_ids.is_empty() {
            self.finalize_edit_transaction(sequence);
        }
    }

    pub(super) fn complete_edit_transaction_failure(&mut self, sequence: u64, row_id: u64) {
        let Some(transaction) = self.pending_edit_transactions.get_mut(&sequence) else {
            return;
        };
        transaction.successful_after_states.remove(&row_id);
        transaction.remaining_row_ids.remove(&row_id);
        if transaction.remaining_row_ids.is_empty() {
            self.finalize_edit_transaction(sequence);
        }
    }

    pub(super) fn prune_edit_history_for_row_ids(&mut self, row_ids: &[u64]) {
        if row_ids.is_empty() {
            return;
        }
        let affected = row_ids.iter().copied().collect::<BTreeSet<_>>();
        for stack in [&mut self.undo_stack, &mut self.redo_stack] {
            for entry in stack.iter_mut() {
                entry
                    .transitions
                    .retain(|transition| !affected.contains(&transition.row_id));
            }
            stack.retain(|entry| !entry.transitions.is_empty());
        }
        for entry in self.completed_edit_history.values_mut() {
            let should_clear = if let Some(history_entry) = entry.as_mut() {
                history_entry
                    .transitions
                    .retain(|transition| !affected.contains(&transition.row_id));
                history_entry.transitions.is_empty()
            } else {
                false
            };
            if should_clear {
                *entry = None;
            }
        }
        let mut transactions_to_finalize = Vec::new();
        for (sequence, transaction) in &mut self.pending_edit_transactions {
            transaction
                .row_ids
                .retain(|row_id| !affected.contains(row_id));
            for row_id in &affected {
                transaction.before_states.remove(row_id);
                transaction.successful_after_states.remove(row_id);
                transaction.remaining_row_ids.remove(row_id);
            }
            if transaction.remaining_row_ids.is_empty() {
                transactions_to_finalize.push(*sequence);
            }
        }
        for sequence in transactions_to_finalize {
            self.finalize_edit_transaction(sequence);
        }
        self.flush_completed_edit_history();
    }

    pub(super) fn clear_edit_history(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.pending_edit_transactions.clear();
        self.completed_edit_history.clear();
        self.next_edit_history_sequence = 0;
        self.next_edit_history_commit_sequence = 0;
    }

    fn apply_edit_history_entry(
        &mut self,
        entry: &GuiEditHistoryEntry,
        restore_after: bool,
        cx: &mut Context<Self>,
    ) {
        for transition in &entry.transitions {
            let Some(row_index) = self.index_of_row_id(transition.row_id) else {
                continue;
            };
            let state = if restore_after {
                &transition.after
            } else {
                &transition.before
            };
            self.rows[row_index].apply_edit_state(state);
            self.refresh_row_path_resolution_state(row_index);
        }
        self.refresh_file_table(cx);
        self.persist();
        cx.notify();
    }

    pub(super) fn run_menu_undo(&mut self, cx: &mut Context<Self>) {
        let Some(entry) = self.undo_stack.pop() else {
            self.status_message = Some(BannerMessage::NothingToUndo);
            cx.notify();
            return;
        };
        self.apply_edit_history_entry(&entry, false, cx);
        self.redo_stack.push(entry);
    }

    pub(super) fn run_menu_redo(&mut self, cx: &mut Context<Self>) {
        let Some(entry) = self.redo_stack.pop() else {
            self.status_message = Some(BannerMessage::NothingToRedo);
            cx.notify();
            return;
        };
        self.apply_edit_history_entry(&entry, true, cx);
        self.undo_stack.push(entry);
    }

    pub(super) fn begin_file_dialog_ui_block(&mut self, cx: &mut Context<Self>) {
        self.file_dialog_block_generation = self.file_dialog_block_generation.wrapping_add(1);
        self.file_dialog_ui_blocked = true;
        cx.notify();
    }

    pub(super) fn schedule_file_dialog_ui_unblock(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let generation = self.file_dialog_block_generation;
        let view = cx.entity();
        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    executor.timer(FILE_DIALOG_UI_BLOCK_RELEASE_DELAY).await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, _, cx: &mut Context<GuiShell>| {
                            if shell.file_dialog_block_generation != generation {
                                return;
                            }
                            shell.file_dialog_ui_blocked = false;
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    fn begin_save_ui_block(&mut self, count: usize, cx: &mut Context<Self>) {
        if count == 0 {
            return;
        }
        self.save_jobs_in_flight = self.save_jobs_in_flight.saturating_add(count);
        cx.notify();
    }

    fn complete_save_ui_block(&mut self, cx: &mut Context<Self>) {
        self.save_jobs_in_flight = self.save_jobs_in_flight.saturating_sub(1);
        cx.notify();
    }

    pub(super) fn refresh_row_path_resolution_state(&mut self, row_index: usize) {
        let Some(row) = self.rows.get_mut(row_index) else {
            return;
        };
        row.refresh_scene_workspace_root();
        row.refresh_path_resolution_cache();
    }

    pub(super) fn visible_row_indices(&self) -> Vec<usize> {
        self.visible_rows.clone()
    }

    pub(super) fn selected_indices(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter_map(|(ix, row)| row.selected.then_some(ix))
            .collect()
    }

    pub(super) fn ready_selected_indices(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter_map(|(ix, row)| (row.selected && !row.is_processing()).then_some(ix))
            .collect()
    }

    pub(super) fn audit_visible_position_for_key(&self, key: &AuditResultRowKey) -> Option<usize> {
        self.audit_rows.iter().position(|row| &row.key == key)
    }

    pub(super) fn ready_dirty_indices(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter_map(|(ix, row)| (row.dirty() && !row.is_processing()).then_some(ix))
            .collect()
    }

    pub(super) fn selected_ready_dirty_indices(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter_map(|(ix, row)| {
                (row.selected && row.dirty() && !row.is_processing()).then_some(ix)
            })
            .collect()
    }

    pub(super) fn save_target_path_for_row(&self, index: usize) -> Option<PathBuf> {
        let row = self.rows.get(index)?;
        match row.dirty_kind? {
            DirtyKind::Replace => Some(row.path.clone()),
            DirtyKind::SceneEdits => row
                .dirty_artifact
                .as_ref()
                .map(|artifact| artifact.input_path.clone()),
            DirtyKind::ToAscii => row
                .dirty_artifact
                .as_ref()
                .map(|artifact| artifact.suggested_output_path.clone()),
        }
    }

    pub(super) fn confirm_save_all(
        &mut self,
        targets: Vec<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let i18n = self.i18n();
        let message = i18n.text("dialog.confirm_save_all_title");
        let detail = i18n.format(
            "dialog.confirm_save_all_description",
            &[
                ("count", targets.len().to_string()),
                ("backup_location", self.backup_location_label(&i18n)),
            ],
        );
        let response = window.prompt(
            PromptLevel::Warning,
            &message,
            Some(&detail),
            &[
                PromptButton::cancel(i18n.text("action.cancel")),
                PromptButton::ok(i18n.text("action.save_all")),
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
                            shell.spawn_save_jobs(targets, window, cx);
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn index_of_row_id(&self, id: u64) -> Option<usize> {
        self.row_id_to_index
            .get(&id)
            .copied()
            .filter(|index| self.rows.get(*index).is_some_and(|row| row.id == id))
            .or_else(|| self.rows.iter().position(|row| row.id == id))
    }

    pub(super) fn visible_position_for_row_index(&self, index: usize) -> Option<usize> {
        self.visible_rows
            .iter()
            .position(|visible| *visible == index)
    }

    pub(super) fn select_row_by_id(
        &mut self,
        id: u64,
        modifiers: Modifiers,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(index) = self.index_of_row_id(id) else {
            return;
        };

        let toggle = modifiers.control || modifiers.platform;
        let extend = modifiers.shift;

        if extend {
            let anchor = self
                .selection_anchor
                .filter(|anchor| self.visible_position_for_row_index(*anchor).is_some())
                .unwrap_or(index);
            let Some(range_indices) =
                visible_selection_range_indices(&self.visible_rows, anchor, index)
            else {
                return;
            };
            if !toggle {
                self.clear_selection();
            }
            for row_index in &range_indices {
                self.rows[*row_index].selected = true;
            }
            self.selection_anchor = Some(anchor);
            self.active_path_edit = None;
            self.selected_path_rows.clear();
            self.path_selection_anchor = None;
            for row_index in &range_indices {
                self.prioritize_cache_restore_for_row(self.rows[*row_index].id);
            }
            self.refresh_file_table(cx);
            self.schedule_selected_auto_analysis(window, cx);
            self.schedule_selected_path_resolution_refresh(window, cx);
            return;
        }

        if toggle {
            self.rows[index].selected = !self.rows[index].selected;
            self.selection_anchor = Some(index);
            self.active_path_edit = None;
            self.selected_path_rows.clear();
            self.path_selection_anchor = None;
            if self.rows[index].selected {
                self.prioritize_cache_restore_for_row(self.rows[index].id);
            }
            self.refresh_file_table(cx);
            self.schedule_selected_auto_analysis(window, cx);
            self.schedule_selected_path_resolution_refresh(window, cx);
            return;
        }

        let already_single = self.rows[index].selected && self.selected_indices().len() == 1;
        self.clear_selection();
        self.rows[index].selected = true;
        self.selection_anchor = Some(index);
        if already_single {
            self.selection_anchor = Some(index);
        }
        self.active_path_edit = None;
        self.selected_path_rows.clear();
        self.path_selection_anchor = None;
        self.prioritize_cache_restore_for_row(self.rows[index].id);
        self.refresh_file_table(cx);
        self.schedule_selected_auto_analysis(window, cx);
        self.schedule_selected_path_resolution_refresh(window, cx);
    }

    pub(super) fn clear_selection(&mut self) {
        for row in &mut self.rows {
            row.selected = false;
        }
        self.selection_anchor = None;
        self.cancel_selected_auto_analysis();
        self.selected_path_rows.clear();
        self.path_selection_anchor = None;
    }

    pub(super) fn replace_audit_selection(
        &mut self,
        key: AuditResultRowKey,
        cx: &mut Context<Self>,
    ) {
        self.selected_audit_keys.clear();
        self.selected_audit_keys.insert(key.clone());
        self.audit_selection_anchor = Some(key);
        self.refresh_audit_table(cx);
    }

    pub(super) fn select_audit_row_by_key(
        &mut self,
        key: AuditResultRowKey,
        modifiers: Modifiers,
        cx: &mut Context<Self>,
    ) {
        let Some(index) = self.audit_visible_position_for_key(&key) else {
            return;
        };

        let toggle = modifiers.control || modifiers.platform;
        let extend = modifiers.shift;

        if extend {
            let anchor = self
                .audit_selection_anchor
                .clone()
                .filter(|anchor| self.audit_visible_position_for_key(anchor).is_some())
                .unwrap_or_else(|| key.clone());
            let Some(range_keys) = visible_audit_selection_keys(&self.audit_rows, &anchor, &key)
            else {
                return;
            };
            if !toggle {
                self.selected_audit_keys.clear();
            }
            self.selected_audit_keys.extend(range_keys);
            self.audit_selection_anchor = Some(anchor);
            self.refresh_audit_table(cx);
            return;
        }

        if toggle {
            if !self.selected_audit_keys.insert(key.clone()) {
                self.selected_audit_keys.remove(&key);
            }
            self.audit_selection_anchor = Some(key);
            self.refresh_audit_table(cx);
            return;
        }

        let already_single =
            self.selected_audit_keys.contains(&key) && self.selected_audit_keys.len() == 1;
        self.selected_audit_keys.clear();
        self.selected_audit_keys.insert(key.clone());
        self.audit_selection_anchor = Some(key.clone());
        if already_single {
            self.audit_selection_anchor = Some(key);
        }
        let _ = index;
        self.refresh_audit_table(cx);
    }

    pub(super) fn select_visible(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let indices = self.visible_row_indices();
        for index in indices {
            self.rows[index].selected = true;
        }
        if self.selection_anchor.is_none() {
            self.selection_anchor = self.visible_row_indices().first().copied();
        }
        self.active_path_edit = None;
        self.selected_path_rows.clear();
        self.path_selection_anchor = None;
        for index in self.visible_row_indices() {
            self.prioritize_cache_restore_for_row(self.rows[index].id);
        }
        self.refresh_file_table(cx);
        self.schedule_selected_auto_analysis(window, cx);
        self.schedule_selected_path_resolution_refresh(window, cx);
    }

    pub(super) fn record_job(
        &mut self,
        operation: &str,
        input: PathBuf,
        output: Option<PathBuf>,
        summary: String,
        failed: bool,
    ) {
        self.push_job_history_entry(operation, input, output, summary, failed);
        self.persist();
    }

    fn push_job_history_entry(
        &mut self,
        operation: &str,
        input: PathBuf,
        output: Option<PathBuf>,
        summary: String,
        failed: bool,
    ) {
        self.state.job_history.insert(
            0,
            JobHistoryEntry {
                operation: operation.to_string(),
                input,
                output,
                summary,
                failed,
                timestamp: Some(self.i18n().format_timestamp(Local::now())),
            },
        );
        self.state.job_history.truncate(24);
    }

    fn record_auto_analyze_job(&mut self, input: PathBuf, summary: String, failed: bool) {
        self.push_job_history_entry("analyze", input, None, summary, failed);
    }

    pub(super) fn mark_error(
        &mut self,
        index: usize,
        operation: RowOperation,
        edit_sequence: Option<u64>,
        error: impl ToString,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let message = error.to_string();
        if matches!(operation, RowOperation::Save) {
            self.complete_save_ui_block(cx);
        }
        let row_id = self.rows[index].id;
        self.rows[index].status = FileStatus::Error(message.clone());
        if matches!(operation, RowOperation::Analyze) {
            self.record_auto_analyze_job(self.rows[index].path.clone(), message, true);
            self.queue_auto_analyze_completion_refresh(row_id, window, cx);
            self.schedule_persist_flush(window, cx, false);
        } else {
            self.refresh_file_table(cx);
            self.record_job(
                operation_key(operation),
                self.rows[index].path.clone(),
                None,
                message,
                true,
            );
        }
        if let Some(edit_sequence) = edit_sequence {
            self.complete_edit_transaction_failure(edit_sequence, row_id);
        }
    }

    pub(super) fn mark_error_by_id(
        &mut self,
        row_id: u64,
        operation: RowOperation,
        edit_sequence: Option<u64>,
        error: impl ToString,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(index) = self.index_of_row_id(row_id) {
            self.mark_error(index, operation, edit_sequence, error, window, cx);
        }
    }

    pub(super) fn apply_job_result(
        &mut self,
        row_id: u64,
        operation: RowOperation,
        result: RowJobResult,
        edit_sequence: Option<u64>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(index) = self.index_of_row_id(row_id) else {
            return;
        };

        match result {
            RowJobResult::Analyze(result) => {
                let AnalyzeRowResult {
                    audit_report,
                    paths_report,
                    dump_report,
                    observe_snapshot,
                    audit_snapshot,
                    audit_mode,
                    elapsed,
                } = result;
                self.prune_edit_history_for_row_ids(&[row_id]);
                let findings = audit_report.findings.len();
                let path_count = paths_report
                    .as_ref()
                    .map_or(0, |report| report.entries.len());
                let require_count = dump_report
                    .as_ref()
                    .map_or(0, |report| report.requires.len());
                let script_count = dump_report
                    .as_ref()
                    .map_or(0, |report| report.script_entries.len());
                let row_status = if audit_report.is_parse_budget_blocked() {
                    FileStatus::Error(
                        audit_report
                            .notices
                            .first()
                            .map(|notice| notice.message.clone())
                            .unwrap_or_else(|| "parse budget exceeded".to_string()),
                    )
                } else {
                    FileStatus::Audited
                };
                self.rows[index].findings = findings;
                self.rows[index].audit_report = Some(audit_report);
                self.rows[index].paths_report = paths_report;
                self.rows[index].dump_report = dump_report;
                self.rows[index].analyzed_audit_mode = Some(audit_mode);
                self.rows[index].pending_clean_targets.clear();
                self.rows[index].path_overrides.clear();
                self.rows[index].replace_preview = None;
                self.rows[index].path_owner_delete_preview = None;
                self.rows[index].pending_path_owner_delete_targets.clear();
                self.rows[index].staged_audit_mode = None;
                self.rows[index].staged_audit_report = None;
                self.rows[index].staged_paths_report = None;
                self.rows[index].staged_dump_report = None;
                self.rows[index].staged_source_bytes = None;
                self.rows[index].dirty_artifact = None;
                self.rows[index].clean_preview = None;
                self.rows[index].ascii_report = None;
                self.rows[index].dirty_kind = None;
                self.rows[index].replace_artifact_generation = None;
                self.rows[index].status = row_status;
                self.rows[index].sync_findings_count();
                self.rows[index].invalidate_path_resolution_state();
                self.queue_path_resolution_backlog_for_row_id(row_id, window, cx);
                self.status_message = Some(BannerMessage::AnalyzeCompleted {
                    name: self.rows[index].name.clone(),
                    elapsed,
                });
                self.record_auto_analyze_job(
                    self.rows[index].path.clone(),
                    format!(
                        "{findings} finding(s), {path_count} path(s), {require_count} require(s), {script_count} script node(s)"
                    ),
                    false,
                );
                self.enqueue_cache_writes(observe_snapshot, audit_snapshot, window, cx);
            }
            RowJobResult::SceneEdits {
                staged,
                audit_mode,
                staged_audit_report,
                staged_paths_report,
                staged_dump_report,
                staged_source_bytes,
            } => {
                let cleaned = staged.preview.cleaned_targets.len();
                let deleted = staged.preview.deleted_path_owner_targets.len();
                self.rows[index].findings = staged_audit_report.findings.len();
                self.rows[index].dirty_artifact = Some(staged.artifact);
                self.rows[index].dirty_kind = Some(DirtyKind::SceneEdits);
                self.rows[index].clean_preview = Some(ExecutionCleanPreview {
                    input_path: staged.preview.input_path.clone(),
                    scene_format: staged.preview.scene_format,
                    operation_mode: staged.preview.operation_mode,
                    validation_state: staged.preview.validation_state,
                    cleaned_targets: staged.preview.cleaned_targets.clone(),
                    removed_script_nodes: staged.preview.removed_script_nodes.clone(),
                    removed_plugin_requires: staged.preview.removed_plugin_requires.clone(),
                });
                self.rows[index].path_owner_delete_preview = Some(PathOwnerDeletePreview {
                    input_path: staged.preview.input_path.clone(),
                    scene_format: staged.preview.scene_format,
                    operation_mode: staged.preview.operation_mode,
                    validation_state: staged.preview.validation_state,
                    deleted_targets: staged.preview.deleted_path_owner_targets.clone(),
                });
                self.rows[index].pending_clean_targets =
                    staged.preview.cleaned_targets.iter().cloned().collect();
                self.rows[index].pending_path_owner_delete_targets = staged
                    .preview
                    .deleted_path_owner_targets
                    .iter()
                    .cloned()
                    .collect();
                self.rows[index].staged_audit_mode = Some(audit_mode);
                self.rows[index].staged_audit_report = Some(staged_audit_report);
                self.rows[index].staged_paths_report = Some(staged_paths_report);
                self.rows[index].staged_dump_report = Some(staged_dump_report);
                self.rows[index].staged_source_bytes = Some(staged_source_bytes);
                self.rows[index].replace_preview = None;
                self.rows[index].ascii_report = None;
                self.rows[index].replace_artifact_generation = None;
                self.rows[index].status = FileStatus::Dirty;
                self.rows[index].sync_findings_count();
                self.refresh_row_path_resolution_state(index);
                self.record_job(
                    operation_key(operation),
                    self.rows[index].path.clone(),
                    None,
                    format!("{cleaned} clean target(s), {deleted} owner node(s) staged"),
                    false,
                );
                if let Some(edit_sequence) = edit_sequence {
                    self.complete_edit_transaction_success(edit_sequence, row_id);
                }
            }
            RowJobResult::ToAscii { report, artifact } => {
                self.rows[index].dirty_artifact = Some(artifact);
                self.rows[index].dirty_kind = Some(DirtyKind::ToAscii);
                self.rows[index].ascii_report = Some(report);
                self.rows[index].path_owner_delete_preview = None;
                self.rows[index].staged_audit_mode = None;
                self.rows[index].status = FileStatus::Dirty;
                self.record_job(
                    operation_key(operation),
                    self.rows[index].path.clone(),
                    None,
                    "staged".to_string(),
                    false,
                );
                if let Some(edit_sequence) = edit_sequence {
                    self.complete_edit_transaction_success(edit_sequence, row_id);
                }
            }
            RowJobResult::Save { output_path } => {
                self.prune_edit_history_for_row_ids(&[row_id]);
                self.complete_save_ui_block(cx);
                let dirty_kind = self.rows[index].dirty_kind;
                if dirty_kind == Some(DirtyKind::Replace) {
                    let overrides = self.rows[index].path_overrides.clone();
                    if let Some(report) = self.rows[index].paths_report.as_mut() {
                        apply_path_overrides_to_report(report, &overrides);
                    }
                } else if dirty_kind == Some(DirtyKind::SceneEdits) {
                    if let Some(report) = self.rows[index].staged_audit_report.take() {
                        self.rows[index].audit_report = Some(report);
                    }
                    if let Some(report) = self.rows[index].staged_paths_report.take() {
                        self.rows[index].paths_report = Some(report);
                    }
                    if let Some(report) = self.rows[index].staged_dump_report.take() {
                        self.rows[index].dump_report = Some(report);
                    }
                    if let Some(audit_mode) = self.rows[index].staged_audit_mode.take() {
                        self.rows[index].analyzed_audit_mode = Some(audit_mode);
                    }
                }
                self.rows[index].dirty_artifact = None;
                self.rows[index].replace_artifact_generation = None;
                self.rows[index].dirty_kind = None;
                self.rows[index].pending_clean_targets.clear();
                self.rows[index].pending_path_owner_delete_targets.clear();
                self.rows[index].path_overrides.clear();
                self.rows[index].replace_preview = None;
                self.rows[index].path_owner_delete_preview = None;
                self.rows[index].staged_audit_mode = None;
                self.rows[index].staged_audit_report = None;
                self.rows[index].staged_paths_report = None;
                self.rows[index].staged_dump_report = None;
                self.rows[index].staged_source_bytes = None;
                self.rows[index].clean_preview = None;
                self.rows[index].ascii_report = None;
                if dirty_kind != Some(DirtyKind::SceneEdits) {
                    self.rows[index].mark_analysis_stale();
                }
                self.rows[index].sync_findings_count();
                self.rows[index].status = FileStatus::Saved;
                self.refresh_row_path_resolution_state(index);
                self.record_job(
                    operation_key(operation),
                    self.rows[index].path.clone(),
                    Some(output_path),
                    "saved".to_string(),
                    false,
                );
                if self.rows[index].selected {
                    self.schedule_selected_auto_analysis(window, cx);
                }
                self.schedule_workspace_auto_analysis_if_enabled(window, cx);
            }
        }

        if matches!(operation, RowOperation::Analyze) {
            self.queue_auto_analyze_completion_refresh(row_id, window, cx);
            self.schedule_persist_flush(window, cx, false);
        } else {
            self.refresh_file_table(cx);
            self.refresh_app_menus(window, cx);
            self.persist();
        }
    }

    pub(super) fn spawn_row_job(
        &mut self,
        row_id: u64,
        operation: RowOperation,
        target_tab: Option<ResultTab>,
        edit_sequence: Option<u64>,
        window: &mut Window,
        cx: &mut Context<Self>,
        job: impl FnOnce(PathBuf) -> Result<RowJobResult, String> + Send + 'static,
    ) {
        let Some(index) = self.index_of_row_id(row_id) else {
            return;
        };

        self.rows[index].status = FileStatus::Processing(operation);
        let path = self.rows[index].path.clone();
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    let result = executor.spawn(async move { job(path) }).await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, window: &mut Window, cx: &mut Context<GuiShell>| {
                            match result {
                                Ok(result) => shell.apply_job_result(
                                    row_id,
                                    operation,
                                    result,
                                    edit_sequence,
                                    window,
                                    cx,
                                ),
                                Err(err) => shell.mark_error_by_id(
                                    row_id,
                                    operation,
                                    edit_sequence,
                                    err,
                                    window,
                                    cx,
                                ),
                            }
                            if let Some(target_tab) = target_tab {
                                shell.set_tab(target_tab, window, cx);
                            }
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn run_clean(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let targets_by_row = self.file_threat_clean_targets_by_row(self.ready_selected_indices());
        if !bulk_enabled(targets_by_row.len()) {
            self.status_message = Some(BannerMessage::SelectFilesFirst);
            return;
        }

        self.stage_file_threat_targets(targets_by_row, window, cx);
    }

    pub(super) fn run_file_context_clean_from_row(
        &mut self,
        row_id: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(row_indices) = self.selected_ready_indices_if_clicked_row_selected(row_id) else {
            return;
        };
        let targets_by_row = self.file_threat_clean_targets_by_row(row_indices);
        if !bulk_enabled(targets_by_row.len()) {
            return;
        }

        self.stage_file_threat_targets(targets_by_row, window, cx);
    }

    pub(super) fn undo_file_context_changes_from_row(
        &mut self,
        row_id: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(row_indices) = self.selected_ready_dirty_indices_if_clicked_row_selected(row_id)
        else {
            return;
        };
        let row_ids = row_indices
            .into_iter()
            .filter_map(|row_index| self.rows.get(row_index).map(|row| row.id))
            .collect::<Vec<_>>();
        self.undo_row_changes_for_ids(row_ids, window, cx);
    }

    fn stage_file_threat_targets(
        &mut self,
        targets_by_row: Vec<(usize, BTreeSet<ExecutionCleanTarget>)>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let row_indices = targets_by_row
            .iter()
            .map(|(row_index, _)| *row_index)
            .collect::<Vec<_>>();
        let edit_sequence = self.begin_edit_transaction(&row_indices);
        for (row_index, targets) in targets_by_row {
            self.stage_clean_targets_for_row(
                row_index,
                targets,
                ResultTab::Audit,
                edit_sequence,
                window,
                cx,
            );
        }
    }

    fn file_threat_clean_targets_by_row(
        &self,
        row_indices: Vec<usize>,
    ) -> Vec<(usize, BTreeSet<ExecutionCleanTarget>)> {
        row_indices
            .into_iter()
            .filter_map(|row_index| {
                let mut next_targets = self.rows[row_index].pending_clean_targets.clone();
                next_targets.extend(clean_targets_for_threat_findings(&self.rows[row_index]));
                (!next_targets.is_empty()).then_some((row_index, next_targets))
            })
            .collect()
    }

    fn selected_ready_indices_if_clicked_row_selected(&self, row_id: u64) -> Option<Vec<usize>> {
        let row_index = self.index_of_row_id(row_id)?;
        self.rows
            .get(row_index)
            .is_some_and(|row| row.selected)
            .then(|| self.ready_selected_indices())
    }

    fn selected_ready_dirty_indices_if_clicked_row_selected(
        &self,
        row_id: u64,
    ) -> Option<Vec<usize>> {
        let row_index = self.index_of_row_id(row_id)?;
        self.rows
            .get(row_index)
            .is_some_and(|row| row.selected)
            .then(|| self.selected_ready_dirty_indices())
    }

    pub(super) fn run_to_ascii(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let selected = self.ready_selected_indices();
        if !bulk_enabled(selected.len()) {
            self.status_message = Some(BannerMessage::SelectFilesFirst);
            return;
        }

        let edit_sequence = self.begin_edit_transaction(&selected);
        for index in selected {
            let row_id = self.rows[index].id;
            let options = self.scene_materialize_options(OperationMode::Forensic);
            self.spawn_row_job(
                row_id,
                RowOperation::ToAscii,
                Some(ResultTab::Overview),
                edit_sequence,
                window,
                cx,
                move |path| {
                    let staged = stage_maya_ascii_with_options(&path, &options)
                        .map_err(|err| err.to_string())?;
                    Ok(RowJobResult::ToAscii {
                        report: staged.report,
                        artifact: staged.artifact,
                    })
                },
            );
        }
    }

    pub(super) fn run_replace(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.open_replace_dialog(window, cx);
    }

    pub(super) fn run_save_selected(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let targets = self.selected_ready_dirty_indices();
        if !save_enabled(targets.len()) {
            self.status_message = Some(BannerMessage::NothingSelectedDirtyToSave);
            return;
        }
        self.spawn_save_jobs(targets, window, cx);
    }

    pub(super) fn run_save_all(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let targets = self.ready_dirty_indices();
        if !save_enabled(targets.len()) {
            self.status_message = Some(BannerMessage::NothingDirtyToSave);
            return;
        }
        self.confirm_save_all(targets, window, cx);
    }

    pub(super) fn run_context_save_from_row(
        &mut self,
        row_id: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(index) = self.index_of_row_id(row_id) else {
            return;
        };
        let targets = if self.rows[index].selected {
            self.selected_ready_dirty_indices()
        } else if self.rows[index].dirty() && !self.rows[index].is_processing() {
            vec![index]
        } else {
            Vec::new()
        };
        if !save_enabled(targets.len()) {
            self.status_message = Some(BannerMessage::NothingSelectedDirtyToSave);
            return;
        }
        self.spawn_save_jobs(targets, window, cx);
    }

    pub(super) fn spawn_save_jobs(
        &mut self,
        targets: Vec<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let backup_location = self.state.backup_location;
        for index in targets {
            let Some(path) = self.save_target_path_for_row(index) else {
                continue;
            };
            let row_id = self.rows[index].id;
            let row = &self.rows[index];
            let dirty_kind = row.dirty_kind;
            let artifact = row.dirty_artifact.clone();
            let artifact_current = row.replace_artifact_is_current();
            let report = row.paths_report.clone();
            let overrides = replace_overrides_for_row(row).unwrap_or_default();
            let options = self.scene_materialize_options(OperationMode::Forensic);
            self.spawn_row_job(
                row_id,
                RowOperation::Save,
                None,
                None,
                window,
                cx,
                move |_input_path| {
                    let artifact = match dirty_kind {
                        Some(DirtyKind::Replace) => {
                            if artifact_current {
                                artifact
                                    .ok_or_else(|| "missing staged replace artifact".to_string())?
                            } else {
                                let report = report
                                    .ok_or_else(|| "missing path report for save".to_string())?;
                                stage_replace_scene_paths_with_overrides_in_report_with_options(
                                    &report, &overrides, &options,
                                )
                                .map_err(|err| err.to_string())?
                                .artifact
                            }
                        }
                        Some(DirtyKind::SceneEdits) | Some(DirtyKind::ToAscii) => artifact
                            .ok_or_else(|| "missing staged artifact for save".to_string())?,
                        None => return Err("missing dirty kind for save".to_string()),
                    };
                    save_staged_artifact_with_backup(&artifact, &path, backup_location)
                        .map_err(|err| err.to_string())?;
                    Ok(RowJobResult::Save { output_path: path })
                },
            );
            self.begin_save_ui_block(1, cx);
        }
    }
}
