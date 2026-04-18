use std::ops::Range;

use super::*;

const AUTO_ANALYZE_VISIBLE_REFRESH_DEBOUNCE: Duration = Duration::from_millis(33);
const AUTO_ANALYZE_FULL_REFRESH_DEBOUNCE: Duration = Duration::from_millis(250);
const AUTO_ANALYZE_FULL_REFRESH_THRESHOLD: usize = 64;

impl GuiShell {
    pub(super) fn toggle_workspace_auto_analyze(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.state.workspace_auto_analyze = !self.state.workspace_auto_analyze;
        self.refresh_app_menus(window, cx);
        if self.state.workspace_auto_analyze {
            self.schedule_workspace_auto_analysis(window, cx);
        } else {
            self.cancel_workspace_auto_analysis();
        }
        self.persist();
    }

    pub(super) fn apply_search_query(&mut self, cx: &mut Context<Self>) {
        self.state.search_query = self.search_input.read(cx).value().to_string();
        self.refresh_file_table(cx);
        self.persist();
    }

    pub(super) fn toggle_file_list_findings_filter(&mut self, cx: &mut Context<Self>) {
        self.state.file_list_findings_only = !self.state.file_list_findings_only;
        self.refresh_file_table(cx);
        self.persist();
    }

    pub(super) fn toggle_file_list_missing_filter(&mut self, cx: &mut Context<Self>) {
        self.state.file_list_missing_only = !self.state.file_list_missing_only;
        self.refresh_file_table(cx);
        self.persist();
    }

    pub(super) fn toggle_file_list_dirty_filter(&mut self, cx: &mut Context<Self>) {
        self.state.file_list_dirty_only = !self.state.file_list_dirty_only;
        self.refresh_file_table(cx);
        self.persist();
    }

    pub(super) fn apply_path_search_query(&mut self, cx: &mut Context<Self>) {
        self.path_search_query = self.path_search_input.read(cx).value().to_string();
        self.refresh_path_table(cx);
    }

    pub(super) fn apply_audit_search_query(&mut self, cx: &mut Context<Self>) {
        self.audit_search_query = self.audit_search_input.read(cx).value().to_string();
        self.refresh_audit_table(cx);
    }

    pub(super) fn set_tab(&mut self, tab: ResultTab, cx: &mut Context<Self>) {
        self.state.active_tab = tab;
        self.refresh_file_table(cx);
        self.persist();
    }

    fn can_auto_analyze_row(&self, row: &SceneRow, audit_mode: AuditModePreference) -> bool {
        !row.is_processing()
            && !row.dirty()
            && !row.analysis_current_for(audit_mode)
            && !matches!(row.status, FileStatus::Error(_))
    }

    fn auto_analyze_candidate_row_ids(
        &self,
        priority: AutoAnalyzePriority,
        audit_mode: AuditModePreference,
    ) -> Vec<u64> {
        match priority {
            AutoAnalyzePriority::High => self
                .rows
                .iter()
                .filter(|row| row.selected)
                .filter(|row| self.can_auto_analyze_row(row, audit_mode))
                .map(|row| row.id)
                .collect(),
            AutoAnalyzePriority::Viewport => self.viewport_auto_analyze_row_ids(audit_mode),
            AutoAnalyzePriority::Low => self
                .rows
                .iter()
                .filter(|row| self.can_auto_analyze_row(row, audit_mode))
                .map(|row| row.id)
                .collect(),
        }
    }

    fn viewport_auto_analyze_row_ids(&self, audit_mode: AuditModePreference) -> Vec<u64> {
        let end = self
            .file_table_viewport_range
            .end
            .min(self.visible_rows.len());
        let start = self.file_table_viewport_range.start.min(end);
        self.visible_rows[start..end]
            .iter()
            .filter_map(|row_ix| self.rows.get(*row_ix))
            .filter(|row| self.can_auto_analyze_row(row, audit_mode))
            .map(|row| row.id)
            .collect()
    }

    pub(super) fn update_file_table_viewport_range(
        &mut self,
        visible_range: Range<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let end = visible_range.end.min(self.visible_rows.len());
        let start = visible_range.start.min(end);
        let visible_range = start..end;
        if self.file_table_viewport_range == visible_range {
            return;
        }
        self.file_table_viewport_range = visible_range;
        if self.state.workspace_auto_analyze && self.cache_restore_active() {
            self.sync_viewport_auto_analyze(window, cx);
        }
    }

    pub(super) fn sync_viewport_auto_analyze(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let audit_mode = self.state.audit_mode;
        let targets = self.viewport_auto_analyze_row_ids(audit_mode);
        self.auto_analyze_queue.replace_pending_viewport(targets);
        self.dispatch_auto_analyze_jobs(window, cx);
    }

    pub(super) fn cancel_selected_auto_analysis(&mut self) {
        self.selected_auto_analyze_generation =
            self.selected_auto_analyze_generation.wrapping_add(1);
        self.auto_analyze_queue.clear_pending_high();
    }

    pub(super) fn cancel_workspace_auto_analysis(&mut self) {
        self.workspace_auto_analyze_generation =
            self.workspace_auto_analyze_generation.wrapping_add(1);
        self.auto_analyze_queue.clear_pending_low();
        self.auto_analyze_queue.pending_viewport.clear();
        self.workspace_auto_analyze_started_at = None;
    }

    pub(super) fn cancel_all_auto_analysis(&mut self) {
        self.selected_auto_analyze_generation =
            self.selected_auto_analyze_generation.wrapping_add(1);
        self.workspace_auto_analyze_generation =
            self.workspace_auto_analyze_generation.wrapping_add(1);
        self.auto_analyze_queue.reset();
        self.workspace_auto_analyze_started_at = None;
        self.cancel_auto_analyze_refresh();
    }

    pub(super) fn schedule_selected_auto_analysis(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.selected_auto_analyze_generation =
            self.selected_auto_analyze_generation.wrapping_add(1);
        let generation = self.selected_auto_analyze_generation;
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    executor.timer(AUTO_ANALYZE_DEBOUNCE).await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, window: &mut Window, cx: &mut Context<GuiShell>| {
                            if shell.selected_auto_analyze_generation != generation {
                                return;
                            }
                            shell.run_selected_auto_analysis(window, cx);
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn run_selected_auto_analysis(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let audit_mode = self.state.audit_mode;
        let targets = self.auto_analyze_candidate_row_ids(AutoAnalyzePriority::High, audit_mode);
        self.auto_analyze_queue
            .enqueue_many(targets, AutoAnalyzePriority::High);
        self.dispatch_auto_analyze_jobs(window, cx);
    }

    pub(super) fn schedule_workspace_auto_analysis_if_enabled(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.state.workspace_auto_analyze {
            self.schedule_workspace_auto_analysis(window, cx);
        } else {
            self.cancel_workspace_auto_analysis();
        }
    }

    pub(super) fn schedule_workspace_auto_analysis(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.state.workspace_auto_analyze || self.rows.is_empty() {
            return;
        }
        self.workspace_auto_analyze_generation =
            self.workspace_auto_analyze_generation.wrapping_add(1);
        let generation = self.workspace_auto_analyze_generation;
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    executor.timer(AUTO_ANALYZE_DEBOUNCE).await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, window: &mut Window, cx: &mut Context<GuiShell>| {
                            if shell.workspace_auto_analyze_generation != generation
                                || !shell.state.workspace_auto_analyze
                            {
                                return;
                            }
                            shell.run_workspace_auto_analysis(window, cx);
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn run_workspace_auto_analysis(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let audit_mode = self.state.audit_mode;
        let targets = self.auto_analyze_candidate_row_ids(AutoAnalyzePriority::Low, audit_mode);
        if !targets.is_empty() && self.workspace_auto_analyze_started_at.is_none() {
            self.workspace_auto_analyze_started_at = Some(Instant::now());
        }
        self.auto_analyze_queue
            .enqueue_many(targets, AutoAnalyzePriority::Low);
        if self.cache_restore_active() {
            self.sync_viewport_auto_analyze(window, cx);
            return;
        }
        self.dispatch_auto_analyze_jobs(window, cx);
    }

    pub(super) fn dispatch_auto_analyze_jobs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let audit_mode = self.state.audit_mode;
        let allow_low_priority = !self.cache_restore_active();
        while self.auto_analyze_queue.in_flight_len() < self.state.auto_analyze_parallelism_limit()
        {
            let Some(row_id) = self.auto_analyze_queue.pop_next(allow_low_priority) else {
                break;
            };
            let Some(index) = self.index_of_row_id(row_id) else {
                self.auto_analyze_queue.complete(row_id);
                continue;
            };
            if !self.can_auto_analyze_row(&self.rows[index], audit_mode) {
                self.auto_analyze_queue.complete(row_id);
                continue;
            }
            let generation = self.auto_analyze_queue.generation;
            self.spawn_auto_analyze_job(row_id, generation, window, cx, audit_mode);
        }
    }

    fn spawn_auto_analyze_job(
        &mut self,
        row_id: u64,
        generation: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
        audit_mode: AuditModePreference,
    ) {
        let Some(index) = self.index_of_row_id(row_id) else {
            self.auto_analyze_queue.complete(row_id);
            return;
        };
        self.rows[index].status = FileStatus::Processing(RowOperation::Analyze);
        let path = self.rows[index].path.clone();
        let load_options = self.scene_load_options();
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    let result =
                        executor
                            .spawn(async move {
                                analyze_row_with_options(&path, audit_mode, &load_options)
                            })
                            .await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, window: &mut Window, cx: &mut Context<GuiShell>| {
                            shell.finish_auto_analyze_job(row_id, generation, result, window, cx);
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    fn finish_auto_analyze_job(
        &mut self,
        row_id: u64,
        generation: u64,
        result: Result<RowJobResult, String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.auto_analyze_queue.generation == generation {
            self.auto_analyze_queue.complete(row_id);
        }
        match result {
            Ok(result) => {
                self.apply_job_result(row_id, RowOperation::Analyze, result, None, window, cx)
            }
            Err(err) => self.mark_error_by_id(row_id, RowOperation::Analyze, None, err, window, cx),
        }
        if self.auto_analyze_queue.generation == generation {
            self.dispatch_auto_analyze_jobs(window, cx);
            self.maybe_finish_workspace_auto_analyze_batch(cx);
        }
    }

    fn maybe_finish_workspace_auto_analyze_batch(&mut self, cx: &mut Context<Self>) {
        let Some(started_at) = self.workspace_auto_analyze_started_at else {
            return;
        };
        let queue_idle = self.auto_analyze_queue.pending_high.is_empty()
            && self.auto_analyze_queue.pending_viewport.is_empty()
            && self.auto_analyze_queue.pending_low.is_empty()
            && self.auto_analyze_queue.in_flight.is_empty();
        if !queue_idle {
            return;
        }
        let remaining =
            self.auto_analyze_candidate_row_ids(AutoAnalyzePriority::Low, self.state.audit_mode);
        if !remaining.is_empty() {
            return;
        }
        self.flush_pending_auto_analyze_refresh(cx);
        self.flush_persist_now(false);
        self.workspace_auto_analyze_started_at = None;
        self.status_message = Some(BannerMessage::WorkspaceAutoAnalyzeCompleted {
            count: self.rows.len(),
            elapsed: started_at.elapsed(),
        });
    }

    pub(super) fn queue_auto_analyze_completion_refresh(
        &mut self,
        row_id: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(index) = self.index_of_row_id(row_id) else {
            return;
        };

        if self.rows[index].selected {
            self.refresh_selected_result_tables(cx);
        }

        if self.visible_position_for_row_index(index).is_some() {
            self.auto_analyze_refresh_state
                .pending_visible_row_ids
                .insert(row_id);
            self.schedule_auto_analyze_visible_refresh(window, cx);
        }

        self.auto_analyze_refresh_state.pending_full_refresh = true;
        self.auto_analyze_refresh_state.pending_completion_count += 1;
        if self.auto_analyze_refresh_state.pending_completion_count
            >= AUTO_ANALYZE_FULL_REFRESH_THRESHOLD
        {
            self.flush_auto_analyze_full_refresh(cx);
            return;
        }
        self.schedule_auto_analyze_full_refresh(window, cx);
    }

    fn cancel_auto_analyze_refresh(&mut self) {
        self.auto_analyze_refresh_state.visible_generation = self
            .auto_analyze_refresh_state
            .visible_generation
            .wrapping_add(1);
        self.auto_analyze_refresh_state.full_generation = self
            .auto_analyze_refresh_state
            .full_generation
            .wrapping_add(1);
        self.auto_analyze_refresh_state
            .pending_visible_row_ids
            .clear();
        self.auto_analyze_refresh_state.pending_full_refresh = false;
        self.auto_analyze_refresh_state.pending_completion_count = 0;
    }

    fn schedule_auto_analyze_visible_refresh(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.auto_analyze_refresh_state.visible_generation = self
            .auto_analyze_refresh_state
            .visible_generation
            .wrapping_add(1);
        let generation = self.auto_analyze_refresh_state.visible_generation;
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    executor.timer(AUTO_ANALYZE_VISIBLE_REFRESH_DEBOUNCE).await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, _window: &mut Window, cx: &mut Context<GuiShell>| {
                            if shell.auto_analyze_refresh_state.visible_generation != generation {
                                return;
                            }
                            shell.flush_auto_analyze_visible_refresh(cx);
                        },
                    );
                }
            })
            .detach();
    }

    fn schedule_auto_analyze_full_refresh(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.auto_analyze_refresh_state.full_generation = self
            .auto_analyze_refresh_state
            .full_generation
            .wrapping_add(1);
        let generation = self.auto_analyze_refresh_state.full_generation;
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    executor.timer(AUTO_ANALYZE_FULL_REFRESH_DEBOUNCE).await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, _window: &mut Window, cx: &mut Context<GuiShell>| {
                            if shell.auto_analyze_refresh_state.full_generation != generation {
                                return;
                            }
                            shell.flush_auto_analyze_full_refresh(cx);
                        },
                    );
                }
            })
            .detach();
    }

    fn flush_auto_analyze_visible_refresh(&mut self, cx: &mut Context<Self>) {
        let row_ids = std::mem::take(&mut self.auto_analyze_refresh_state.pending_visible_row_ids);
        if row_ids.is_empty() {
            return;
        }
        let mut patched_any = false;
        for row_id in row_ids {
            patched_any |= self.patch_visible_file_row(row_id, cx);
        }
        if !patched_any && self.auto_analyze_refresh_state.pending_full_refresh {
            self.flush_auto_analyze_full_refresh(cx);
        }
    }

    fn flush_auto_analyze_full_refresh(&mut self, cx: &mut Context<Self>) {
        if !self.auto_analyze_refresh_state.pending_full_refresh {
            return;
        }
        self.auto_analyze_refresh_state.pending_full_refresh = false;
        self.auto_analyze_refresh_state.pending_completion_count = 0;
        self.auto_analyze_refresh_state
            .pending_visible_row_ids
            .clear();
        self.refresh_file_table(cx);
    }

    fn flush_pending_auto_analyze_refresh(&mut self, cx: &mut Context<Self>) {
        if !self.auto_analyze_refresh_state.pending_full_refresh
            && self
                .auto_analyze_refresh_state
                .pending_visible_row_ids
                .is_empty()
        {
            return;
        }
        self.auto_analyze_refresh_state.visible_generation = self
            .auto_analyze_refresh_state
            .visible_generation
            .wrapping_add(1);
        self.auto_analyze_refresh_state.full_generation = self
            .auto_analyze_refresh_state
            .full_generation
            .wrapping_add(1);
        self.auto_analyze_refresh_state
            .pending_visible_row_ids
            .clear();
        self.auto_analyze_refresh_state.pending_full_refresh = false;
        self.auto_analyze_refresh_state.pending_completion_count = 0;
        self.refresh_file_table(cx);
    }
}
