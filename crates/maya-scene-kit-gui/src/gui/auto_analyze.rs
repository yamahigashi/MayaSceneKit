use super::*;

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
        self.rows
            .iter()
            .filter(|row| match priority {
                AutoAnalyzePriority::High => row.selected,
                AutoAnalyzePriority::Low => true,
            })
            .filter(|row| self.can_auto_analyze_row(row, audit_mode))
            .map(|row| row.id)
            .collect()
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
        self.workspace_auto_analyze_started_at = None;
    }

    pub(super) fn cancel_all_auto_analysis(&mut self) {
        self.selected_auto_analyze_generation =
            self.selected_auto_analyze_generation.wrapping_add(1);
        self.workspace_auto_analyze_generation =
            self.workspace_auto_analyze_generation.wrapping_add(1);
        self.auto_analyze_queue.reset();
        self.workspace_auto_analyze_started_at = None;
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
        self.dispatch_auto_analyze_jobs(window, cx);
    }

    pub(super) fn dispatch_auto_analyze_jobs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let audit_mode = self.state.audit_mode;
        while self.auto_analyze_queue.in_flight_len() < self.state.auto_analyze_parallelism_limit()
        {
            let Some(row_id) = self.auto_analyze_queue.pop_next() else {
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
            self.maybe_finish_workspace_auto_analyze_batch();
        }
    }

    fn maybe_finish_workspace_auto_analyze_batch(&mut self) {
        let Some(started_at) = self.workspace_auto_analyze_started_at else {
            return;
        };
        let queue_idle = self.auto_analyze_queue.pending_high.is_empty()
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
        self.workspace_auto_analyze_started_at = None;
        self.status_message = Some(BannerMessage::WorkspaceAutoAnalyzeCompleted {
            count: self.rows.len(),
            elapsed: started_at.elapsed(),
        });
    }
}
