use super::*;

const CACHE_RESTORE_BATCH_SIZE: usize = 32;

#[derive(Clone)]
pub(super) struct CacheHydrationInput {
    pub(super) row_id: u64,
    pub(super) path: PathBuf,
}

pub(super) struct CacheHydrationUpdate {
    pub(super) row_id: u64,
    pub(super) observe_snapshot: Option<ObservedSceneSnapshot>,
    pub(super) audit_snapshot: Option<AuditedSceneSnapshot>,
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
    let updates = rows
        .into_iter()
        .map(|row| CacheHydrationUpdate {
            row_id: row.row_id,
            observe_snapshot: observe_store
                .load_by_path_if_fresh(&row.path, &load_options, 64)
                .ok()
                .flatten(),
            audit_snapshot: audit_store
                .load_by_path_if_fresh(&row.path, audit_options, &plan_fingerprint)
                .ok()
                .flatten(),
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

        self.dispatch_progressive_cache_restore(window, cx);
        cx.notify();
    }

    pub(super) fn cancel_progressive_cache_restore(&mut self) {
        self.cache_restore_generation = self.cache_restore_generation.wrapping_add(1);
        self.cache_restore_state = CacheRestoreState::default();
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

    fn dispatch_progressive_cache_restore(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
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
                        move |shell: &mut GuiShell, window: &mut Window, cx: &mut Context<GuiShell>| {
                            if shell.cache_restore_generation != generation {
                                return;
                            }
                            shell.cache_restore_state.in_flight = false;
                            shell.cache_restore_state.completed_count += result.processed_count;
                            shell.apply_cache_restore_updates(result.updates, cx);
                            shell.dispatch_progressive_cache_restore(window, cx);
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    fn apply_cache_restore_updates(
        &mut self,
        updates: Vec<CacheHydrationUpdate>,
        cx: &mut Context<Self>,
    ) {
        let mut changed = false;
        for update in updates {
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
                    row.refresh_scene_workspace_root();
                    row.refresh_path_resolution_cache();
                    changed = true;
                }
            }

            if let Some(snapshot) = update.audit_snapshot {
                if !row.analysis_current_for(self.state.audit_mode) {
                    row.findings = snapshot.report.findings.len();
                    row.audit_report = Some(snapshot.report.clone());
                    row.analyzed_audit_mode = Some(self.state.audit_mode);
                    row.status = if snapshot.report.is_parse_budget_blocked() {
                        FileStatus::Error(
                            snapshot
                                .report
                                .notices
                                .first()
                                .map(|notice| notice.message.clone())
                                .unwrap_or_else(|| "parse budget exceeded".to_string()),
                        )
                    } else {
                        FileStatus::Audited
                    };
                    row.sync_findings_count();
                    changed = true;
                }
            }
        }

        if changed {
            self.refresh_file_table(cx);
        }
    }

    fn finish_progressive_cache_restore(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.cache_restore_state = CacheRestoreState::default();
        cx.notify();
    }
}

fn row_needs_cache_restore(row: &SceneRow, audit_mode: AuditModePreference) -> bool {
    !row.is_processing()
        && !row.dirty()
        && (row.paths_report.is_none()
            || row.dump_report.is_none()
            || !row.analysis_current_for(audit_mode))
}
