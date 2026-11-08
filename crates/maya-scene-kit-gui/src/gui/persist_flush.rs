use super::*;

const PERSIST_FLUSH_DEBOUNCE: Duration = Duration::from_millis(250);

impl PersistFlushState {
    fn cancel(&mut self) {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("persist generation exhausted");
        self.in_flight = false;
        self.dirty = false;
        self.workspace_paths_dirty = false;
    }
}

impl GuiShell {
    pub(super) fn cancel_persist_flush(&mut self) {
        self.persist_flush_state.cancel();
    }

    pub(super) fn schedule_persist_flush(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        workspace_paths_dirty: bool,
    ) {
        self.persist_flush_state.dirty = true;
        self.persist_flush_state.workspace_paths_dirty |= workspace_paths_dirty;
        if self.persist_flush_state.in_flight {
            return;
        }

        self.persist_flush_state.in_flight = true;
        self.persist_flush_state.generation = self
            .persist_flush_state
            .generation
            .checked_add(1)
            .expect("persist generation exhausted");
        let generation = self.persist_flush_state.generation;
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    executor.timer(PERSIST_FLUSH_DEBOUNCE).await;

                    let persist_state = async_cx
                        .update_window_entity(
                            &view,
                            |shell: &mut GuiShell,
                             _window: &mut Window,
                             _cx: &mut Context<GuiShell>| {
                                if shell.persist_flush_state.generation != generation
                                    || !shell.persist_flush_state.dirty
                                {
                                    return None;
                                }

                                let workspace_paths_dirty =
                                    shell.persist_flush_state.workspace_paths_dirty;
                                shell.persist_flush_state.dirty = false;
                                shell.persist_flush_state.workspace_paths_dirty = false;
                                Some((
                                    shell.prepared_persisted_state(workspace_paths_dirty),
                                    next_persist_save_sequence(),
                                ))
                            },
                        )
                        .ok()
                        .flatten();

                    let Some((persist_state, sequence)) = persist_state else {
                        return;
                    };

                    let result = executor
                        .spawn(async move { save_persisted_state(&persist_state, sequence) })
                        .await;

                    let _ = async_cx.update_window_entity(
                        &view,
                        move |shell: &mut GuiShell,
                              window: &mut Window,
                              cx: &mut Context<GuiShell>| {
                            if shell.persist_flush_state.generation != generation {
                                return;
                            }

                            shell.persist_flush_state.in_flight = false;
                            if let Err(err) = result {
                                shell.status_message =
                                    Some(BannerMessage::PersistFailed(err.to_string()));
                            }
                            if shell.persist_flush_state.dirty {
                                shell.schedule_persist_flush(
                                    window,
                                    cx,
                                    shell.persist_flush_state.workspace_paths_dirty,
                                );
                            }
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn flush_persist_now(&mut self, workspace_paths_dirty: bool) {
        self.cancel_persist_flush();
        let state = self.prepared_persisted_state(workspace_paths_dirty);
        let sequence = next_persist_save_sequence();
        if let Err(err) = save_persisted_state(&state, sequence) {
            self.status_message = Some(BannerMessage::PersistFailed(err.to_string()));
        }
    }

    pub(super) fn prepared_persisted_state(&self, workspace_paths_dirty: bool) -> PersistedState {
        let mut state = self.state.clone();
        state.normalize_ignore_folder_settings();
        state.set_workspace_root(state.workspace_root_path().filter(|path| path.exists()));
        if workspace_paths_dirty {
            state.replace_workspace_paths(self.rows.iter().map(|row| row.path.clone()));
        }
        state
    }
}

#[cfg(test)]
mod tests {
    use super::PersistFlushState;

    #[test]
    fn cancel_preserves_and_increments_generation() {
        let mut state = PersistFlushState {
            generation: 7,
            in_flight: true,
            dirty: true,
            workspace_paths_dirty: true,
        };
        state.cancel();
        assert_eq!(state.generation, 8);
        assert!(!state.in_flight);
        assert!(!state.dirty);
        assert!(!state.workspace_paths_dirty);
        state.cancel();
        assert_eq!(state.generation, 9);
    }
}
