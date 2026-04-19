use super::*;

const CACHE_WRITE_DEBOUNCE: Duration = Duration::from_secs(1);
const CACHE_WRITE_AUTO_ANALYZE_DEBOUNCE: Duration = Duration::from_secs(3);
const CACHE_WRITE_BATCH_SIZE: usize = 256;
const CACHE_WRITE_IMMEDIATE_THRESHOLD: usize = 2048;

struct CacheWriteBatch {
    observe: Vec<ObservedSceneSnapshot>,
    audit: Vec<AuditedSceneSnapshot>,
}

pub(super) struct CacheWriteFlushResult {
    pub(super) error_count: usize,
    pub(super) first_error: Option<String>,
}

impl GuiShell {
    pub(super) fn cancel_cache_writes(&mut self) {
        self.cache_write_generation = self.cache_write_generation.wrapping_add(1);
        self.cache_write_state = CacheWriteState::default();
    }

    pub(super) fn enqueue_cache_writes(
        &mut self,
        observe_snapshot: Option<ObservedSceneSnapshot>,
        audit_snapshot: Option<AuditedSceneSnapshot>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.state.analysis_cache_enabled {
            return;
        }
        if let Some(snapshot) = observe_snapshot {
            self.enqueue_observe_cache_write(snapshot);
        }
        if let Some(snapshot) = audit_snapshot {
            self.enqueue_audit_cache_write(snapshot);
        }
        self.schedule_cache_write_flush(
            window,
            cx,
            self.cache_write_should_debounce(),
            self.cache_write_flush_delay(),
        );
    }

    fn enqueue_observe_cache_write(&mut self, snapshot: ObservedSceneSnapshot) {
        let key = cache_write_key(&snapshot.file_state.path);
        if !self.cache_write_state.pending_observe.contains_key(&key) {
            self.cache_write_state
                .pending_observe_order
                .push_back(key.clone());
        }
        self.cache_write_state.pending_observe.insert(key, snapshot);
    }

    fn enqueue_audit_cache_write(&mut self, snapshot: AuditedSceneSnapshot) {
        let key = cache_write_key(&snapshot.file_state.path);
        if !self.cache_write_state.pending_audit.contains_key(&key) {
            self.cache_write_state
                .pending_audit_order
                .push_back(key.clone());
        }
        self.cache_write_state.pending_audit.insert(key, snapshot);
    }

    pub(super) fn flush_cache_writes_now(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.cache_write_has_pending() || self.cache_write_state.in_flight {
            return;
        }
        self.cache_write_state.debounce_generation =
            self.cache_write_state.debounce_generation.wrapping_add(1);
        self.cache_write_state.debounce_pending = false;
        self.schedule_cache_write_flush(window, cx, false, CACHE_WRITE_DEBOUNCE);
    }

    fn cache_write_should_debounce(&self) -> bool {
        self.cache_persistence_backpressure_active()
            || self.pending_cache_write_count() < CACHE_WRITE_IMMEDIATE_THRESHOLD
    }

    fn cache_write_flush_delay(&self) -> Duration {
        if self.cache_persistence_backpressure_active() {
            CACHE_WRITE_AUTO_ANALYZE_DEBOUNCE
        } else {
            CACHE_WRITE_DEBOUNCE
        }
    }

    pub(super) fn cache_persistence_backpressure_active(&self) -> bool {
        self.workspace_auto_analyze_started_at.is_some()
            || self.auto_analyze_queue.remaining_count() > 0
    }

    fn schedule_cache_write_flush(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        debounced: bool,
        delay: Duration,
    ) {
        if !self.cache_write_has_pending() {
            return;
        }

        let cancel_generation = self.cache_write_generation;
        let observe_cache_root = self.observe_cache_root.clone();
        let audit_cache_root = self.audit_cache_root.clone();
        let view = cx.entity();
        let debounce_generation = if debounced {
            self.cache_write_state.debounce_generation =
                self.cache_write_state.debounce_generation.wrapping_add(1);
            Some(self.cache_write_state.debounce_generation)
        } else {
            None
        };

        if debounced {
            self.cache_write_state.debounce_pending = true;
            if self.cache_write_state.in_flight {
                return;
            }
        } else if self.cache_write_state.in_flight || self.cache_write_state.debounce_pending {
            return;
        }

        self.cache_write_state.in_flight = !debounced;

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    if debounced {
                        executor.timer(delay).await;
                    }

                    let batch = async_cx
                        .update_window_entity(
                            &view,
                            |shell: &mut GuiShell,
                             _window: &mut Window,
                             _cx: &mut Context<GuiShell>| {
                                shell
                                    .begin_cache_write_flush(cancel_generation, debounce_generation)
                            },
                        )
                        .ok()
                        .flatten();

                    let Some(batch) = batch else {
                        return;
                    };

                    let result = executor
                        .spawn(async move {
                            flush_cache_write_batch(batch, observe_cache_root, audit_cache_root)
                        })
                        .await;

                    let _ = async_cx.update_window_entity(
                        &view,
                        move |shell: &mut GuiShell,
                              window: &mut Window,
                              cx: &mut Context<GuiShell>| {
                            shell.finish_cache_write_flush(cancel_generation, result, window, cx);
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    fn begin_cache_write_flush(
        &mut self,
        cancel_generation: u64,
        debounce_generation: Option<u64>,
    ) -> Option<CacheWriteBatch> {
        if self.cache_write_generation != cancel_generation {
            return None;
        }
        if let Some(debounce_generation) = debounce_generation {
            if self.cache_write_state.debounce_generation != debounce_generation {
                return None;
            }
            self.cache_write_state.debounce_pending = false;
            if !self.cache_write_has_pending() || self.cache_write_state.in_flight {
                return None;
            }
            self.cache_write_state.in_flight = true;
        }
        Some(self.take_cache_write_batch())
    }

    pub(super) fn finish_cache_write_flush(
        &mut self,
        cancel_generation: u64,
        result: CacheWriteFlushResult,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.cache_write_generation != cancel_generation {
            return;
        }
        self.cache_write_state.in_flight = false;
        self.record_cache_write_flush_result(result);
        if self.cache_write_has_pending() {
            self.schedule_cache_write_flush(
                window,
                cx,
                self.cache_write_should_debounce(),
                self.cache_write_flush_delay(),
            );
        } else {
            self.finish_cache_write_cycle();
        }
    }

    fn take_cache_write_batch(&mut self) -> CacheWriteBatch {
        CacheWriteBatch {
            observe: take_pending_snapshots(
                &mut self.cache_write_state.pending_observe_order,
                &mut self.cache_write_state.pending_observe,
                CACHE_WRITE_BATCH_SIZE,
            ),
            audit: take_pending_snapshots(
                &mut self.cache_write_state.pending_audit_order,
                &mut self.cache_write_state.pending_audit,
                CACHE_WRITE_BATCH_SIZE,
            ),
        }
    }

    fn cache_write_has_pending(&self) -> bool {
        !self.cache_write_state.pending_observe.is_empty()
            || !self.cache_write_state.pending_audit.is_empty()
    }

    fn pending_cache_write_count(&self) -> usize {
        self.cache_write_state.pending_observe.len() + self.cache_write_state.pending_audit.len()
    }

    fn record_cache_write_flush_result(&mut self, result: CacheWriteFlushResult) {
        if result.error_count == 0 {
            return;
        }
        self.cache_write_state.error_count += result.error_count;
        if self.cache_write_state.first_error.is_none() {
            self.cache_write_state.first_error = result.first_error;
        }
    }

    fn finish_cache_write_cycle(&mut self) {
        if self.cache_write_state.error_count == 0 {
            return;
        }
        let error_count = self.cache_write_state.error_count;
        let first_error = self
            .cache_write_state
            .first_error
            .take()
            .unwrap_or_else(|| "cache persistence failed".to_string());
        self.cache_write_state.error_count = 0;
        let detail = if error_count == 1 {
            first_error
        } else {
            format!("{first_error} ({error_count} failures)")
        };
        self.status_message = Some(BannerMessage::PersistFailed(detail));
    }
}

fn take_pending_snapshots<T: Clone>(
    order: &mut VecDeque<String>,
    map: &mut BTreeMap<String, T>,
    limit: usize,
) -> Vec<T> {
    let mut snapshots = Vec::new();
    while snapshots.len() < limit {
        let Some(key) = order.pop_front() else {
            break;
        };
        let Some(snapshot) = map.remove(&key) else {
            continue;
        };
        snapshots.push(snapshot);
    }
    snapshots
}

fn flush_cache_write_batch(
    batch: CacheWriteBatch,
    observe_cache_root: PathBuf,
    audit_cache_root: PathBuf,
) -> CacheWriteFlushResult {
    let mut error_count = 0usize;
    let mut first_error = None;

    if !batch.observe.is_empty() {
        if let Err(err) = ObserveCacheStore::new(observe_cache_root).save_batch(&batch.observe) {
            error_count += batch.observe.len();
            first_error.get_or_insert_with(|| err.to_string());
        }
    }

    if !batch.audit.is_empty() {
        if let Err(err) = AuditCacheStore::new(audit_cache_root).save_batch(&batch.audit) {
            error_count += batch.audit.len();
            first_error.get_or_insert_with(|| err.to_string());
        }
    }

    CacheWriteFlushResult {
        error_count,
        first_error,
    }
}

fn cache_write_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::take_pending_snapshots;
    use std::collections::{BTreeMap, VecDeque};

    #[test]
    fn take_pending_snapshots_preserves_latest_per_key() {
        let mut order = VecDeque::from(["a".to_string(), "b".to_string()]);
        let mut map = BTreeMap::from([("a".to_string(), 3usize), ("b".to_string(), 2usize)]);

        let batch = take_pending_snapshots(&mut order, &mut map, 64);

        assert_eq!(batch, vec![3, 2]);
        assert!(order.is_empty());
        assert!(map.is_empty());
    }
}
