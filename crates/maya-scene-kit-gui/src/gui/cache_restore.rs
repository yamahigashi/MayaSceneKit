use super::*;

const CACHE_RESTORE_BATCH_SIZE: usize = 32;
const CACHE_RESTORE_VISIBLE_REFRESH_DEBOUNCE: Duration = Duration::from_millis(33);
const CACHE_RESTORE_FULL_REFRESH_DEBOUNCE: Duration = Duration::from_millis(1500);
const CACHE_RESTORE_PROGRESS_NOTIFY_INTERVAL: usize = CACHE_RESTORE_BATCH_SIZE * 8;

#[derive(Clone)]
pub(super) struct CacheHydrationInput {
    pub(super) row_id: u64,
    pub(super) path: PathBuf,
}

pub(super) struct CacheHydrationUpdate {
    pub(super) row_id: u64,
    pub(super) observe_snapshot: Option<ObservedSceneSnapshot>,
    pub(super) observe_access: Option<ObserveCacheAccess>,
    pub(super) audit_snapshot: Option<AuditedSceneSnapshot>,
    pub(super) audit_access: Option<AuditCacheAccess>,
}

pub(super) struct CacheHydrationBatchResult {
    pub(super) processed_count: usize,
    pub(super) updates: Vec<CacheHydrationUpdate>,
}

pub(super) fn hydrate_cached_analysis_batch(
    rows: Vec<CacheHydrationInput>,
    load_options: LoadOptions,
    audit_options: AuditOptions,
    plan_fingerprint: String,
    observe_cache_root: PathBuf,
    audit_cache_root: PathBuf,
) -> CacheHydrationBatchResult {
    let observe_store = ObserveCacheStore::new(observe_cache_root);
    let audit_store = AuditCacheStore::new(audit_cache_root);
    let paths = rows.iter().map(|row| row.path.clone()).collect::<Vec<_>>();
    let observe_hits = observe_store
        .load_many_by_path_if_fresh_with_access(&paths, &load_options, 64)
        .unwrap_or_else(|_| (0..rows.len()).map(|_| Ok(None)).collect());
    let audit_hits = audit_store
        .load_many_by_path_if_fresh_with_access(&paths, audit_options, &plan_fingerprint)
        .unwrap_or_else(|_| (0..rows.len()).map(|_| Ok(None)).collect());

    let updates = rows
        .into_iter()
        .zip(observe_hits)
        .zip(audit_hits)
        .map(|((row, observe_hit), audit_hit)| {
            let observe_hit = observe_hit.ok().flatten();
            let audit_hit = audit_hit.ok().flatten();
            CacheHydrationUpdate {
                row_id: row.row_id,
                observe_snapshot: observe_hit.as_ref().map(|hit| hit.snapshot.clone()),
                observe_access: observe_hit.map(|hit| hit.access),
                audit_snapshot: audit_hit.as_ref().map(|hit| hit.snapshot.clone()),
                audit_access: audit_hit.map(|hit| hit.access),
            }
        })
        .collect::<Vec<_>>();

    CacheHydrationBatchResult {
        processed_count: updates.len(),
        updates,
    }
}

impl GuiShell {
    pub(super) fn start_progressive_cache_restore(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.state.analysis_cache_enabled {
            self.finish_progressive_cache_restore(window, cx);
            return;
        }
        self.cache_restore_generation = self.cache_restore_generation.wrapping_add(1);
        self.cancel_cache_restore_refresh();
        self.cache_restore_state = CacheRestoreState {
            pending: self.build_cache_restore_queue(),
            total_count: 0,
            completed_count: 0,
            in_flight: false,
        };
        self.cache_restore_state.total_count = self.cache_restore_state.pending.len();

        if self.cache_restore_state.total_count == 0 {
            self.finish_progressive_cache_restore(window, cx);
            return;
        }

        if self.state.workspace_auto_analyze {
            self.sync_viewport_auto_analyze(window, cx);
        }
        self.dispatch_progressive_cache_restore(window, cx);
        cx.notify();
    }

    pub(super) fn cancel_progressive_cache_restore(&mut self) {
        self.cache_restore_generation = self.cache_restore_generation.wrapping_add(1);
        self.cache_restore_state = CacheRestoreState::default();
        self.cancel_cache_restore_refresh();
    }

    pub(super) fn prioritize_cache_restore_for_row(&mut self, row_id: u64) {
        if !self.cache_restore_active() {
            return;
        }
        let Some(position) = self
            .cache_restore_state
            .pending
            .iter()
            .position(|pending| *pending == row_id)
        else {
            return;
        };
        let Some(row_id) = self.cache_restore_state.pending.remove(position) else {
            return;
        };
        self.cache_restore_state.pending.push_front(row_id);
    }

    fn build_cache_restore_queue(&self) -> VecDeque<u64> {
        let mut queue = VecDeque::new();
        let mut seen = BTreeSet::new();
        let audit_mode = self.state.audit_mode;

        let mut push_row = |row: &SceneRow| {
            if !row_needs_cache_restore(row, audit_mode) || !seen.insert(row.id) {
                return;
            }
            queue.push_back(row.id);
        };

        for row in self.rows.iter().filter(|row| row.selected) {
            push_row(row);
        }
        for visible_index in &self.visible_rows {
            if let Some(row) = self.rows.get(*visible_index) {
                push_row(row);
            }
        }
        for row in &self.rows {
            push_row(row);
        }

        queue
    }

    fn next_cache_restore_batch(&mut self) -> Vec<CacheHydrationInput> {
        let mut batch = Vec::new();
        let audit_mode = self.state.audit_mode;
        while batch.len() < CACHE_RESTORE_BATCH_SIZE {
            let Some(row_id) = self.cache_restore_state.pending.pop_front() else {
                break;
            };
            let Some(index) = self.index_of_row_id(row_id) else {
                continue;
            };
            let row = &self.rows[index];
            if !row_needs_cache_restore(row, audit_mode) {
                continue;
            }
            batch.push(CacheHydrationInput {
                row_id,
                path: row.path.clone(),
            });
        }
        batch
    }

    fn dispatch_progressive_cache_restore(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.cache_restore_state.in_flight {
            return;
        }

        let batch = self.next_cache_restore_batch();
        if batch.is_empty() {
            self.finish_progressive_cache_restore(window, cx);
            return;
        }

        self.cache_restore_state.in_flight = true;
        let generation = self.cache_restore_generation;
        let load_options = self.scene_load_options();
        let audit_options = audit_options_from_preference(self.state.audit_mode);
        let plan_fingerprint = gui_audit_plan()
            .map(|plan| fingerprint_audit_plan(&plan))
            .unwrap_or_default();
        let observe_cache_root = self.observe_cache_root.clone();
        let audit_cache_root = self.audit_cache_root.clone();
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    let result = executor
                        .spawn(async move {
                            hydrate_cached_analysis_batch(
                                batch,
                                load_options,
                                audit_options,
                                plan_fingerprint,
                                observe_cache_root,
                                audit_cache_root,
                            )
                        })
                        .await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        move |shell: &mut GuiShell,
                              window: &mut Window,
                              cx: &mut Context<GuiShell>| {
                            if shell.cache_restore_generation != generation {
                                return;
                            }
                            shell.cache_restore_state.in_flight = false;
                            shell.cache_restore_state.completed_count += result.processed_count;
                            shell.apply_cache_restore_updates(result.updates, window, cx);
                            shell.dispatch_progressive_cache_restore(window, cx);
                            if shell.should_notify_cache_restore_progress() {
                                cx.notify();
                            }
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn apply_cache_restore_updates(
        &mut self,
        updates: Vec<CacheHydrationUpdate>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let mut changed_row_ids = BTreeSet::new();
        for update in updates {
            let observe_access = update.observe_access.clone();
            let audit_access = update.audit_access.clone();
            let Some(index) = self.index_of_row_id(update.row_id) else {
                continue;
            };
            let row = &mut self.rows[index];
            if row.is_processing() || row.dirty() {
                continue;
            }

            if let Some(snapshot) = update.observe_snapshot {
                if row.paths_report.is_none() || row.dump_report.is_none() {
                    row.paths_report = Some(snapshot.paths_report);
                    row.dump_report = Some(snapshot.dump_report);
                    row.invalidate_path_resolution_state();
                    changed_row_ids.insert(update.row_id);
                }
            }

            if let Some(snapshot) = update.audit_snapshot {
                if !row.analysis_current_for(self.state.audit_mode) {
                    let findings = snapshot.report.findings.len();
                    let parse_budget_blocked = snapshot.report.is_parse_budget_blocked();
                    let blocked_message = snapshot
                        .report
                        .notices
                        .first()
                        .map(|notice| notice.message.clone())
                        .unwrap_or_else(|| "parse budget exceeded".to_string());
                    row.findings = findings;
                    row.audit_report = Some(snapshot.report);
                    row.analyzed_audit_mode = Some(self.state.audit_mode);
                    row.status = if parse_budget_blocked {
                        FileStatus::Error(blocked_message)
                    } else {
                        FileStatus::Audited
                    };
                    row.sync_findings_count();
                    changed_row_ids.insert(update.row_id);
                }
            }

            self.enqueue_cache_accesses(observe_access, audit_access, window, cx);
        }

        if !changed_row_ids.is_empty() {
            self.queue_cache_restore_refresh(changed_row_ids, window, cx);
        }
    }

    pub(super) fn finish_progressive_cache_restore(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.cache_restore_state = CacheRestoreState::default();
        self.flush_pending_cache_restore_refresh(cx);
        if self.state.workspace_auto_analyze {
            self.run_workspace_auto_analysis(window, cx);
        }
        cx.notify();
    }

    fn queue_cache_restore_refresh(
        &mut self,
        row_ids: BTreeSet<u64>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let row_ids = row_ids.into_iter().collect::<Vec<_>>();
        for row_id in &row_ids {
            if let Some(index) = self.index_of_row_id(*row_id) {
                if self.visible_position_for_row_index(index).is_some() {
                    self.cache_restore_refresh_state
                        .pending_visible_row_ids
                        .insert(*row_id);
                }
                self.cache_restore_refresh_state.pending_full_refresh = true;
                self.cache_restore_refresh_state.pending_completion_count += 1;
            }
        }
        self.queue_path_resolution_backlog_for_row_ids(row_ids.iter().copied(), window, cx);
        if !self
            .cache_restore_refresh_state
            .pending_visible_row_ids
            .is_empty()
        {
            self.schedule_cache_restore_visible_refresh(window, cx);
        }
        self.schedule_cache_restore_full_refresh(window, cx);
    }

    fn cancel_cache_restore_refresh(&mut self) {
        self.cache_restore_refresh_state.visible_generation = self
            .cache_restore_refresh_state
            .visible_generation
            .wrapping_add(1);
        self.cache_restore_refresh_state.full_generation = self
            .cache_restore_refresh_state
            .full_generation
            .wrapping_add(1);
        self.cache_restore_refresh_state
            .pending_visible_row_ids
            .clear();
        self.cache_restore_refresh_state.pending_full_refresh = false;
        self.cache_restore_refresh_state.pending_completion_count = 0;
    }

    fn schedule_cache_restore_visible_refresh(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.cache_restore_refresh_state.visible_generation = self
            .cache_restore_refresh_state
            .visible_generation
            .wrapping_add(1);
        let generation = self.cache_restore_refresh_state.visible_generation;
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    executor.timer(CACHE_RESTORE_VISIBLE_REFRESH_DEBOUNCE).await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, _window: &mut Window, cx: &mut Context<GuiShell>| {
                            if shell.cache_restore_refresh_state.visible_generation != generation {
                                return;
                            }
                            shell.flush_cache_restore_visible_refresh(cx);
                        },
                    );
                }
            })
            .detach();
    }

    fn schedule_cache_restore_full_refresh(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.cache_restore_refresh_state.pending_full_refresh {
            return;
        }
        self.cache_restore_refresh_state.full_generation = self
            .cache_restore_refresh_state
            .full_generation
            .wrapping_add(1);
        let generation = self.cache_restore_refresh_state.full_generation;
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    executor.timer(CACHE_RESTORE_FULL_REFRESH_DEBOUNCE).await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, _window: &mut Window, cx: &mut Context<GuiShell>| {
                            if shell.cache_restore_refresh_state.full_generation != generation {
                                return;
                            }
                            shell.flush_cache_restore_full_refresh(cx);
                        },
                    );
                }
            })
            .detach();
    }

    fn flush_cache_restore_visible_refresh(&mut self, cx: &mut Context<Self>) {
        let row_ids = std::mem::take(&mut self.cache_restore_refresh_state.pending_visible_row_ids);
        if row_ids.is_empty() {
            return;
        }
        let patched_any = self.patch_visible_file_rows(&row_ids, cx);
        if !patched_any
            && self.cache_restore_refresh_state.pending_full_refresh
            && !self.cache_restore_active()
        {
            self.flush_cache_restore_full_refresh(cx);
        }
    }

    fn flush_cache_restore_full_refresh(&mut self, cx: &mut Context<Self>) {
        if !self.cache_restore_refresh_state.pending_full_refresh {
            return;
        }
        self.cache_restore_refresh_state.pending_full_refresh = false;
        self.cache_restore_refresh_state.pending_completion_count = 0;
        self.cache_restore_refresh_state
            .pending_visible_row_ids
            .clear();
        self.refresh_file_table(cx);
    }

    fn flush_pending_cache_restore_refresh(&mut self, cx: &mut Context<Self>) {
        if !self.cache_restore_refresh_state.pending_full_refresh
            && self
                .cache_restore_refresh_state
                .pending_visible_row_ids
                .is_empty()
        {
            return;
        }
        self.cache_restore_refresh_state.visible_generation = self
            .cache_restore_refresh_state
            .visible_generation
            .wrapping_add(1);
        self.cache_restore_refresh_state.full_generation = self
            .cache_restore_refresh_state
            .full_generation
            .wrapping_add(1);
        self.cache_restore_refresh_state
            .pending_visible_row_ids
            .clear();
        self.cache_restore_refresh_state.pending_full_refresh = false;
        self.cache_restore_refresh_state.pending_completion_count = 0;
        self.refresh_file_table(cx);
    }

    fn should_notify_cache_restore_progress(&self) -> bool {
        self.cache_restore_state.completed_count >= self.cache_restore_state.total_count
            || self
                .cache_restore_state
                .completed_count
                % CACHE_RESTORE_PROGRESS_NOTIFY_INTERVAL
                == 0
    }
}

fn row_needs_cache_restore(row: &SceneRow, audit_mode: AuditModePreference) -> bool {
    !row.is_processing()
        && !row.dirty()
        && (row.paths_report.is_none()
            || row.dump_report.is_none()
            || !row.analysis_current_for(audit_mode))
}
