use super::*;

const CACHE_MAINTENANCE_DEBOUNCE: Duration = Duration::from_secs(2);
const CACHE_MAINTENANCE_TOUCH_THRESHOLD: usize = 1000;

struct CacheMaintenanceBatch {
    observe: Vec<ObserveCacheAccess>,
    audit: Vec<AuditCacheAccess>,
    sweep: bool,
}

struct CacheMaintenanceFlushResult {
    error_count: usize,
    first_error: Option<String>,
}

impl GuiShell {
    pub(super) fn cancel_cache_maintenance(&mut self) {
        self.cache_maintenance_generation = self.cache_maintenance_generation.wrapping_add(1);
        self.cache_maintenance_state = CacheMaintenanceState::default();
    }

    pub(super) fn enqueue_cache_accesses(
        &mut self,
        observe_access: Option<ObserveCacheAccess>,
        audit_access: Option<AuditCacheAccess>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.state.analysis_cache_enabled {
            return;
        }
        if let Some(access) = observe_access {
            self.enqueue_observe_cache_access(access);
        }
        if let Some(access) = audit_access {
            self.enqueue_audit_cache_access(access);
        }
        let debounced = self.pending_cache_access_count() < CACHE_MAINTENANCE_TOUCH_THRESHOLD;
        self.schedule_cache_maintenance(window, cx, debounced);
    }

    pub(super) fn request_cache_sweep(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.state.analysis_cache_enabled {
            return;
        }
        self.cache_maintenance_state.pending_sweep = true;
        self.schedule_cache_maintenance(window, cx, true);
    }

    fn enqueue_observe_cache_access(&mut self, access: ObserveCacheAccess) {
        let key = cache_maintenance_key(&access.path);
        if !self
            .cache_maintenance_state
            .pending_observe
            .contains_key(&key)
        {
            self.cache_maintenance_state
                .pending_observe_order
                .push_back(key.clone());
        }
        self.cache_maintenance_state
            .pending_observe
            .insert(key, access);
    }

    fn enqueue_audit_cache_access(&mut self, access: AuditCacheAccess) {
        let key = cache_maintenance_key(&access.path);
        if !self
            .cache_maintenance_state
            .pending_audit
            .contains_key(&key)
        {
            self.cache_maintenance_state
                .pending_audit_order
                .push_back(key.clone());
        }
        self.cache_maintenance_state
            .pending_audit
            .insert(key, access);
    }

    fn schedule_cache_maintenance(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        debounced: bool,
    ) {
        if self.cache_maintenance_state.in_flight || !self.cache_maintenance_has_pending() {
            return;
        }

        self.cache_maintenance_state.in_flight = true;
        self.cache_maintenance_generation = self.cache_maintenance_generation.wrapping_add(1);
        let generation = self.cache_maintenance_generation;
        let observe_cache_root = self.observe_cache_root.clone();
        let audit_cache_root = self.audit_cache_root.clone();
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    if debounced {
                        executor.timer(CACHE_MAINTENANCE_DEBOUNCE).await;
                    }

                    let batch = async_cx
                        .update_window_entity(
                            &view,
                            |shell: &mut GuiShell,
                             _window: &mut Window,
                             _cx: &mut Context<GuiShell>| {
                                if shell.cache_maintenance_generation != generation {
                                    return None;
                                }
                                Some(shell.take_cache_maintenance_batch())
                            },
                        )
                        .ok()
                        .flatten();

                    let Some(batch) = batch else {
                        return;
                    };

                    let result = executor
                        .spawn(async move {
                            flush_cache_maintenance_batch(
                                batch,
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
                            if shell.cache_maintenance_generation != generation {
                                return;
                            }
                            shell.cache_maintenance_state.in_flight = false;
                            shell.record_cache_maintenance_flush_result(result);
                            if shell.cache_maintenance_has_pending() {
                                shell.schedule_cache_maintenance(window, cx, false);
                            } else {
                                shell.finish_cache_maintenance_cycle();
                            }
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    fn take_cache_maintenance_batch(&mut self) -> CacheMaintenanceBatch {
        let sweep = self.cache_maintenance_state.pending_sweep;
        self.cache_maintenance_state.pending_sweep = false;
        CacheMaintenanceBatch {
            observe: take_pending_accesses(
                &mut self.cache_maintenance_state.pending_observe_order,
                &mut self.cache_maintenance_state.pending_observe,
            ),
            audit: take_pending_accesses(
                &mut self.cache_maintenance_state.pending_audit_order,
                &mut self.cache_maintenance_state.pending_audit,
            ),
            sweep,
        }
    }

    fn cache_maintenance_has_pending(&self) -> bool {
        self.cache_maintenance_state.pending_sweep
            || !self.cache_maintenance_state.pending_observe.is_empty()
            || !self.cache_maintenance_state.pending_audit.is_empty()
    }

    fn pending_cache_access_count(&self) -> usize {
        self.cache_maintenance_state.pending_observe.len()
            + self.cache_maintenance_state.pending_audit.len()
    }

    fn record_cache_maintenance_flush_result(&mut self, result: CacheMaintenanceFlushResult) {
        if result.error_count == 0 {
            return;
        }
        self.cache_maintenance_state.error_count += result.error_count;
        if self.cache_maintenance_state.first_error.is_none() {
            self.cache_maintenance_state.first_error = result.first_error;
        }
    }

    fn finish_cache_maintenance_cycle(&mut self) {
        if self.cache_maintenance_state.error_count == 0 {
            return;
        }
        let error_count = self.cache_maintenance_state.error_count;
        let first_error = self
            .cache_maintenance_state
            .first_error
            .take()
            .unwrap_or_else(|| "cache maintenance failed".to_string());
        self.cache_maintenance_state.error_count = 0;
        let detail = if error_count == 1 {
            first_error
        } else {
            format!("{first_error} ({error_count} failures)")
        };
        self.status_message = Some(BannerMessage::PersistFailed(detail));
    }
}

fn take_pending_accesses<T: Clone>(
    order: &mut VecDeque<String>,
    map: &mut BTreeMap<String, T>,
) -> Vec<T> {
    let mut accesses = Vec::with_capacity(map.len());
    while let Some(key) = order.pop_front() {
        let Some(access) = map.remove(&key) else {
            continue;
        };
        accesses.push(access);
    }
    accesses
}

fn flush_cache_maintenance_batch(
    batch: CacheMaintenanceBatch,
    observe_cache_root: PathBuf,
    audit_cache_root: PathBuf,
) -> CacheMaintenanceFlushResult {
    let mut error_count = 0usize;
    let mut first_error = None;
    let now = SystemTime::now();

    if batch.sweep || !batch.observe.is_empty() {
        if let Err(err) =
            ObserveCacheStore::new(observe_cache_root).apply_maintenance(&batch.observe, now)
        {
            error_count += batch.observe.len().max(1);
            first_error.get_or_insert_with(|| err.to_string());
        }
    }

    if batch.sweep || !batch.audit.is_empty() {
        if let Err(err) =
            AuditCacheStore::new(audit_cache_root).apply_maintenance(&batch.audit, now)
        {
            error_count += batch.audit.len().max(1);
            first_error.get_or_insert_with(|| err.to_string());
        }
    }

    CacheMaintenanceFlushResult {
        error_count,
        first_error,
    }
}

fn cache_maintenance_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::take_pending_accesses;
    use std::collections::{BTreeMap, VecDeque};

    #[test]
    fn take_pending_accesses_preserves_latest_per_key() {
        let mut order = VecDeque::from(["a".to_string(), "b".to_string()]);
        let mut map = BTreeMap::from([("a".to_string(), 3usize), ("b".to_string(), 2usize)]);

        let batch = take_pending_accesses(&mut order, &mut map);

        assert_eq!(batch, vec![3, 2]);
        assert!(order.is_empty());
        assert!(map.is_empty());
    }
}
