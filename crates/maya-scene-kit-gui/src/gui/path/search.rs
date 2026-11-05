use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use super::{
    super::*,
    helpers::{
        effective_path_value_for_entry, missing_path_entry_file_name,
        path_value_edit_supported_for_entry, shared_workspace_root_for_targets,
        write_back_selected_scene_path,
    },
    normalize_path_edit_targets,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gui) struct MissingPathSearchTarget {
    row_id: u64,
    entry_index: usize,
    before_value: String,
    file_name: String,
}

pub(in crate::gui) fn path_search_hit_key(file_name: &str) -> String {
    file_name.to_ascii_lowercase()
}

pub(in crate::gui) fn find_missing_path_file_hits(
    root: &Path,
    wanted_file_names: &BTreeSet<String>,
    state: &PersistedState,
) -> BTreeMap<String, PathBuf> {
    if wanted_file_names.is_empty() || !root.is_dir() {
        return BTreeMap::new();
    }

    let wanted = wanted_file_names
        .iter()
        .map(|name| (path_search_hit_key(name), name.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut hits = BTreeMap::new();
    let mut visited_dirs = BTreeSet::new();
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);

    while let Some((dir, depth)) = queue.pop_front() {
        if depth > 128 {
            continue;
        }
        let canonical_dir = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if !visited_dirs.insert(canonical_dir) {
            continue;
        }

        let Ok(read_dir) = fs::read_dir(&dir) else {
            continue;
        };
        let mut entries = read_dir.filter_map(Result::ok).collect::<Vec<_>>();
        entries.sort_by(|a, b| {
            a.file_name()
                .to_string_lossy()
                .cmp(&b.file_name().to_string_lossy())
        });

        for entry in entries {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };

            if file_type.is_file() {
                let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                let key = path_search_hit_key(file_name);
                if wanted.contains_key(&key) {
                    hits.entry(key).or_insert(path);
                    if hits.len() == wanted.len() {
                        return hits;
                    }
                }
                continue;
            }

            if file_type.is_dir() || path.is_dir() {
                if should_ignore_workspace_directory(&path, state) {
                    continue;
                }
                queue.push_back((path, depth + 1));
            }
        }
    }

    hits
}

impl GuiShell {
    pub(in crate::gui) fn search_missing_path_files(
        &mut self,
        edit_targets: PathEditTargets,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.path_search_in_flight {
            self.status_message = Some(BannerMessage::Raw(
                self.i18n().text("banner.path_search_in_progress"),
            ));
            cx.notify();
            return;
        }

        let search_targets = self.missing_path_search_targets(&edit_targets);
        if search_targets.is_empty() {
            return;
        }

        let initial_directory = self.path_search_initial_directory(&edit_targets, &search_targets);
        let response = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            initial_directory,
            prompt: Some(self.i18n().text("action.search_missing_files").into()),
        });
        let view = cx.entity();
        self.begin_file_dialog_ui_block(cx);

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    match response.await {
                        Ok(Ok(Some(paths))) => {
                            let selected_folder = paths.into_iter().next();
                            let Some(selected_folder) = selected_folder else {
                                let _ = async_cx.update_window_entity(
                                    &view,
                                    |shell: &mut GuiShell,
                                     window: &mut Window,
                                     cx: &mut Context<GuiShell>| {
                                        shell.schedule_file_dialog_ui_unblock(window, cx);
                                    },
                                );
                                return;
                            };

                            let state = async_cx
                                .update_window_entity(
                                    &view,
                                    |shell: &mut GuiShell,
                                     window: &mut Window,
                                     cx: &mut Context<GuiShell>| {
                                        if shell.path_search_in_flight {
                                            shell.schedule_file_dialog_ui_unblock(window, cx);
                                            return None;
                                        }
                                        shell.path_search_in_flight = true;
                                        shell.status_message = Some(BannerMessage::Raw(
                                            shell.i18n().text("banner.path_search_in_progress"),
                                        ));
                                        shell.schedule_file_dialog_ui_unblock(window, cx);
                                        cx.notify();
                                        Some(shell.state.clone())
                                    },
                                )
                                .ok()
                                .flatten();

                            let Some(state) = state else {
                                return;
                            };
                            let wanted = search_targets
                                .iter()
                                .map(|target| target.file_name.clone())
                                .collect::<BTreeSet<_>>();
                            let started_at = Instant::now();
                            let hits = executor
                                .spawn({
                                    let selected_folder = selected_folder.clone();
                                    async move {
                                        find_missing_path_file_hits(
                                            &selected_folder,
                                            &wanted,
                                            &state,
                                        )
                                    }
                                })
                                .await;
                            let elapsed = started_at.elapsed();

                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    shell.path_search_in_flight = false;
                                    shell.apply_missing_path_file_hits(
                                        search_targets.clone(),
                                        selected_folder,
                                        hits,
                                        elapsed,
                                        window,
                                        cx,
                                    );
                                },
                            );
                        }
                        Ok(Ok(None)) => {
                            let _ = async_cx.update_window_entity(
                                &view,
                                |shell: &mut GuiShell,
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
                            let message = format!("Folder selection failed: {err}");
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

    pub(in crate::gui) fn missing_path_search_targets(
        &self,
        edit_targets: &PathEditTargets,
    ) -> Vec<MissingPathSearchTarget> {
        normalize_path_edit_targets(edit_targets.clone())
            .into_iter()
            .filter_map(|(row_id, entry_index)| {
                let row = self.rows.iter().find(|row| row.id == row_id)?;
                if !path_value_edit_supported_for_entry(row, entry_index) {
                    return None;
                }
                Some(MissingPathSearchTarget {
                    row_id,
                    entry_index,
                    before_value: effective_path_value_for_entry(row, entry_index)?,
                    file_name: missing_path_entry_file_name(row, entry_index)?,
                })
            })
            .collect()
    }

    fn path_search_initial_directory(
        &self,
        edit_targets: &PathEditTargets,
        search_targets: &[MissingPathSearchTarget],
    ) -> Option<PathBuf> {
        shared_workspace_root_for_targets(&self.rows, edit_targets)
            .or_else(|| {
                let target_edit_targets = search_targets
                    .iter()
                    .map(|target| (target.row_id, target.entry_index))
                    .collect::<Vec<_>>();
                shared_workspace_root_for_targets(&self.rows, &target_edit_targets)
            })
            .filter(|path| path.is_dir())
            .or_else(|| {
                search_targets
                    .first()
                    .and_then(|target| self.index_of_row_id(target.row_id))
                    .and_then(|row_index| self.rows.get(row_index))
                    .and_then(|row| row.path.parent().map(Path::to_path_buf))
                    .filter(|path| path.is_dir())
            })
    }

    pub(in crate::gui) fn apply_missing_path_file_hits(
        &mut self,
        targets: Vec<MissingPathSearchTarget>,
        search_root: PathBuf,
        hits: BTreeMap<String, PathBuf>,
        elapsed: Duration,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let total = targets.len();
        if total == 0 {
            return;
        }

        let mut row_targets = BTreeMap::<usize, BTreeMap<usize, String>>::new();
        for target in targets {
            let Some(hit) = hits.get(&path_search_hit_key(&target.file_name)) else {
                continue;
            };
            let Some(row_index) = self.index_of_row_id(target.row_id) else {
                continue;
            };
            let Some(row) = self.rows.get(row_index) else {
                continue;
            };
            if !path_value_edit_supported_for_entry(row, target.entry_index) {
                continue;
            }
            let Some(current_value) = effective_path_value_for_entry(row, target.entry_index)
            else {
                continue;
            };
            if current_value != target.before_value {
                continue;
            }
            if missing_path_entry_file_name(row, target.entry_index).as_deref()
                != Some(target.file_name.as_str())
            {
                continue;
            }

            let value_style = path_value_style_for_entry(row, target.entry_index, &current_value);
            let next_value = write_back_selected_scene_path(
                hit,
                row.scene_workspace_root.as_deref(),
                value_style,
            );
            if next_value == current_value {
                continue;
            }
            row_targets
                .entry(row_index)
                .or_default()
                .insert(target.entry_index, next_value);
        }

        let found = row_targets.values().map(BTreeMap::len).sum::<usize>();
        if row_targets.is_empty() {
            self.status_message = Some(BannerMessage::Raw(self.i18n().format(
                "banner.path_search_no_hits",
                &[("total", total.to_string())],
            )));
            self.record_job(
                "path-search",
                search_root,
                None,
                format!(
                    "0/{total} path(s) staged in {}",
                    format_elapsed_seconds(elapsed)
                ),
                false,
            );
            self.persist();
            cx.notify();
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
            .filter(|(row_index, next_overrides)| {
                self.rows[*row_index].path_overrides != *next_overrides
            })
            .collect::<Vec<_>>();

        if planned_edits.is_empty() {
            self.status_message = Some(BannerMessage::Raw(self.i18n().format(
                "banner.path_search_no_hits",
                &[("total", total.to_string())],
            )));
            self.record_job(
                "path-search",
                search_root,
                None,
                format!(
                    "0/{total} path(s) staged in {}",
                    format_elapsed_seconds(elapsed)
                ),
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

        self.status_message = Some(BannerMessage::Raw(self.i18n().format(
            "banner.path_search_completed",
            &[("found", found.to_string()), ("total", total.to_string())],
        )));
        self.record_job(
            "path-search",
            search_root,
            None,
            format!(
                "{found}/{total} path(s) staged in {}",
                format_elapsed_seconds(elapsed)
            ),
            false,
        );
        self.refresh_file_table(cx);
        self.persist();
        cx.notify();
    }
}

fn path_value_style_for_entry(
    row: &SceneRow,
    entry_index: usize,
    current_value: &str,
) -> ScenePathValueStyle {
    row.path_resolution(entry_index, current_value)
        .map(|resolution| resolution.style)
        .or_else(|| {
            row.path_resolution_fallback(entry_index, current_value)
                .map(|resolution| resolution.style)
        })
        .unwrap_or_else(|| infer_scene_path_value_style(current_value))
}
