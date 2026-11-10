use maya_scene_kit_edit::scene::OperationMode;

use super::*;

const REPLACE_DIALOG_HORIZONTAL_MARGIN: Pixels = px(48.0);
const REPLACE_DIALOG_VERTICAL_MARGIN: Pixels = px(96.0);
const REPLACE_DIALOG_PREVIEW_MAX_HEIGHT: Pixels = px(320.0);
const REPLACE_PREVIEW_TABLE_ROW_HEIGHT: Pixels = px(32.0);

struct ReplaceDialogLayout {
    width: Pixels,
    max_height: Pixels,
    preview_max_height: Pixels,
}

impl GuiShell {
    pub(super) fn replace_dialog_current_rule(&self, cx: &App) -> (String, String) {
        (
            self.replace_from_input.read(cx).value().to_string(),
            self.replace_to_input.read(cx).value().to_string(),
        )
    }

    pub(super) fn replace_dialog_current_signature(
        &self,
        cx: &App,
    ) -> Option<ReplaceDialogPreviewSignature> {
        let dialog = self.replace_dialog.as_ref()?;
        let (from_value, to_value) = self.replace_dialog_current_rule(cx);
        Some(ReplaceDialogPreviewSignature {
            from_value,
            to_value,
            replace_mode: dialog.replace_mode,
            path_type_filter: dialog.path_type_filter.clone(),
        })
    }

    pub(super) fn replace_dialog_preview_needs_refresh(&self, cx: &App) -> bool {
        let Some(dialog) = self.replace_dialog.as_ref() else {
            return false;
        };
        if dialog.is_previewing {
            return false;
        }
        let Some(signature) = self.replace_dialog_current_signature(cx) else {
            return false;
        };
        dialog.preview_signature.as_ref() != Some(&signature)
    }

    pub(super) fn replace_dialog_can_apply(&self, cx: &App) -> bool {
        let Some(signature) = self.replace_dialog_current_signature(cx) else {
            return false;
        };
        self.replace_dialog
            .as_ref()
            .is_some_and(|dialog| dialog.can_apply(&signature))
    }

    pub(super) fn on_replace_dialog_inputs_changed(&mut self, cx: &mut Context<Self>) {
        if let Some(dialog) = self.replace_dialog.as_mut() {
            dialog.invalidate_preview();
            cx.notify();
        }
    }

    pub(super) fn clear_replace_dialog_state(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.replace_dialog = None;
        self.replace_from_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.replace_to_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        cx.notify();
    }

    pub(super) fn open_replace_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let row_ids = self.row_ids_for_indices(&self.selected_indices());
        self.with_mutation_targets(row_ids, RowMutation::PathEdit, cx, |shell, indices, cx| {
            let captured = shell.row_ids_for_indices(&indices);
            shell.open_replace_dialog_for_rows(captured, None, window, cx);
        });
    }

    pub(super) fn open_replace_dialog_for_path_targets(
        &mut self,
        edit_targets: PathEditTargets,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = super::path_edit::normalize_path_edit_targets(edit_targets);
        let mut path_targets = BTreeMap::<u64, BTreeSet<usize>>::new();
        for (row_id, entry_index) in edit_targets {
            path_targets.entry(row_id).or_default().insert(entry_index);
        }
        let captured_row_ids = path_targets.keys().copied().collect::<Vec<_>>();
        self.open_replace_dialog_for_rows(captured_row_ids, Some(path_targets), window, cx);
    }

    fn open_replace_dialog_for_rows(
        &mut self,
        captured_row_ids: Vec<u64>,
        path_targets: Option<BTreeMap<u64, BTreeSet<usize>>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !bulk_enabled(captured_row_ids.len()) {
            self.status_message = Some(BannerMessage::SelectFilesFirst);
            cx.notify();
            return;
        }
        if self.replace_dialog.is_some() {
            if window.has_active_dialog(cx) {
                return;
            }
            self.replace_dialog = None;
        }
        if window.has_active_dialog(cx) {
            return;
        }

        self.replace_from_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.replace_to_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.replace_dialog = Some(ReplaceDialogState {
            captured_generations: captured_row_ids
                .iter()
                .filter_map(|id| {
                    self.index_of_row_id(*id)
                        .map(|index| (*id, self.rows[index].replace_generation))
                })
                .collect(),
            captured_row_ids,
            path_targets,
            path_type_filter: default_path_type_filter(),
            replace_mode: PathReplaceMode::Literal,
            preview_sort: ReplaceDialogSort {
                key: ReplaceDialogSortKey::Before,
                direction: ColumnSort::Default,
            },
            is_previewing: false,
            generation: 0,
            source_cache: self.seed_replace_dialog_source_cache(),
            preview_signature: None,
            preview: None,
        });
        self.sync_replace_preview_table(cx);
        let view = cx.entity();
        window.open_dialog(cx, move |dialog, window, cx| {
            build_replace_dialog(dialog, view.clone(), window, cx)
        });
        cx.notify();
    }

    pub(super) fn run_replace_preview(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(signature) = self.replace_dialog_current_signature(cx) else {
            return;
        };
        let Some((captured_row_ids, path_targets, existing_cache)) =
            self.replace_dialog.as_ref().map(|dialog| {
                (
                    dialog.captured_row_ids.clone(),
                    dialog.path_targets.clone(),
                    dialog.source_cache.clone(),
                )
            })
        else {
            return;
        };
        let generation = {
            let Some(dialog_state) = self.replace_dialog.as_mut() else {
                return;
            };
            let generation = dialog_state.generation.saturating_add(1);
            dialog_state.generation = generation;
            dialog_state.is_previewing = true;
            dialog_state.preview_signature = None;
            generation
        };

        let targets = captured_row_ids
            .iter()
            .filter_map(|row_id| {
                let index = self.index_of_row_id(*row_id)?;
                let row = self.rows.get(index)?;
                Some((
                    *row_id,
                    row.path.clone(),
                    workspace_relative_display_path(&row.path, &self.state),
                    path_targets
                        .as_ref()
                        .and_then(|targets| targets.get(row_id).cloned()),
                    existing_cache.get(row_id).cloned(),
                ))
            })
            .collect::<Vec<_>>();
        let rules = vec![PathReplaceRule {
            from: signature.from_value.clone(),
            to: signature.to_value.clone(),
            mode: signature.replace_mode,
        }];
        let load_options = self.scene_load_options();
        let materialize_options = self.scene_materialize_options(OperationMode::Forensic);
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    let outcome = executor
                        .spawn(async move {
                            let mut previewable_row_ids = Vec::new();
                            let mut failed_files = Vec::new();
                            let mut matched_count = 0usize;
                            let mut items = Vec::new();
                            let mut planned_overrides = Vec::new();
                            let mut resolved_cache = BTreeMap::new();

                            for (row_id, path, scene_name, row_path_targets, cached_entry) in
                                targets
                            {
                                let cache_entry = match cached_entry {
                                    Some(entry) => entry,
                                    None => match collect_scene_paths_with_options(
                                        &path,
                                        PathKind::All,
                                        &load_options,
                                    ) {
                                        Ok(report) => ReplaceDialogSourceCacheEntry {
                                            report,
                                            base_overrides: BTreeMap::new(),
                                        },
                                        Err(err) => {
                                            failed_files.push(format!("{scene_name}: {err}"));
                                            continue;
                                        }
                                    },
                                };

                                let mut effective_report = cache_entry.report.clone();
                                for (entry_index, value) in &cache_entry.base_overrides {
                                    if let Some(entry) =
                                        effective_report.entries.get_mut(*entry_index)
                                    {
                                        entry.value = value.clone();
                                    }
                                }

                                match preview_replace_scene_path_candidates_in_report_with_options(
                                    &effective_report,
                                    &rules,
                                    &materialize_options,
                                ) {
                                    Ok(preview) => {
                                        previewable_row_ids.push(row_id);
                                        let mut row_overrides = Vec::new();
                                        for item in preview.items {
                                            if row_path_targets.as_ref().is_some_and(|targets| {
                                                !targets.contains(&item.entry_index)
                                            }) {
                                                continue;
                                            }
                                            let path_kind =
                                                path_type_for_node_type(&item.node_type);
                                            if !signature.path_type_filter.contains(&path_kind) {
                                                continue;
                                            }
                                            matched_count += item.replacement_count;
                                            if item.replacement_count > 0 {
                                                let Some(original_entry) = cache_entry
                                                    .report
                                                    .entries
                                                    .get(item.entry_index)
                                                else {
                                                    continue;
                                                };
                                                row_overrides.push(PathReplaceOverride {
                                                    entry_index: item.entry_index,
                                                    before_value: original_entry.value.clone(),
                                                    after_value: item.after_value.clone(),
                                                });
                                            }
                                            items.push(ReplaceDialogPreviewRow {
                                                before_value: item.before_value,
                                                after_value: item.after_value,
                                            });
                                        }
                                        planned_overrides.push((row_id, row_overrides));
                                        resolved_cache.insert(row_id, cache_entry);
                                    }
                                    Err(err) => {
                                        failed_files.push(format!("{scene_name}: {err}"));
                                    }
                                }
                            }

                            (
                                generation,
                                signature.clone(),
                                resolved_cache,
                                ReplaceDialogPreviewState {
                                    previewable_row_ids,
                                    failed_files,
                                    matched_count,
                                    items,
                                    planned_overrides,
                                },
                            )
                        })
                        .await;

                    let _ = async_cx.update_window_entity(
                        &view,
                        |shell: &mut GuiShell, _window: &mut Window, cx: &mut Context<GuiShell>| {
                            let Some(dialog) = shell.replace_dialog.as_mut() else {
                                return;
                            };
                            if dialog.generation != outcome.0 {
                                return;
                            }
                            dialog.is_previewing = false;
                            dialog.preview_signature = Some(outcome.1.clone());
                            dialog.source_cache.extend(outcome.2.clone());
                            dialog.preview = Some(outcome.3.clone());
                            shell.sync_replace_preview_table(cx);
                            cx.notify();
                        },
                    );
                }
            })
            .detach();

        cx.notify();
    }

    pub(super) fn apply_replace_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(signature) = self.replace_dialog_current_signature(cx) else {
            return;
        };
        let Some(dialog_state) = self.replace_dialog.as_ref() else {
            return;
        };
        if !dialog_state.can_apply(&signature) {
            return;
        }

        let previous_banner = if self.mutation_banner_depth == 0 {
            self.status_message.take()
        } else {
            None
        };
        let planned_overrides = dialog_state
            .preview
            .as_ref()
            .map(|preview| preview.planned_overrides.clone())
            .unwrap_or_default();
        let source_cache = dialog_state.source_cache.clone();
        let generations = dialog_state.captured_generations.clone();
        let (indices, mut rejected) = self.mutation_targets(
            planned_overrides
                .iter()
                .filter(|(_, overrides)| !overrides.is_empty())
                .map(|(id, _)| *id),
            RowMutation::PathEdit,
        );
        let accepted = self
            .row_ids_for_indices(&indices)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut planned_edits = Vec::new();
        for (row_id, overrides) in planned_overrides {
            if overrides.is_empty() {
                rejected.skipped += 1;
                continue;
            }
            if !accepted.contains(&row_id) {
                continue;
            }
            let Some(index) = self.index_of_row_id(row_id) else {
                continue;
            };
            let Some(cached) = source_cache.get(&row_id) else {
                rejected.skipped += 1;
                continue;
            };
            let row = &self.rows[index];
            let same_report = row.paths_report.as_ref().is_none_or(|report| {
                report.entries.len() == cached.report.entries.len()
                    && report.source == cached.report.source
                    && overrides.iter().all(|replacement| {
                        let index = replacement.entry_index;
                        match (report.entries.get(index), cached.report.entries.get(index)) {
                            (Some(current), Some(original)) => {
                                current.value == original.value
                                    && current.node_type == original.node_type
                                    && current.node_name == original.node_name
                                    && current.attr == original.attr
                            }
                            _ => false,
                        }
                    })
            });
            if generations.get(&row_id) != Some(&row.replace_generation) || !same_report {
                rejected.blocked.push((
                    row_id,
                    MutateBlocked::StalePreview {
                        name: row.name.clone(),
                    },
                ));
                continue;
            }
            let mut merged = row.staged.overrides().clone();
            for replacement in overrides {
                let Some(entry) = cached.report.entries.get(replacement.entry_index) else {
                    continue;
                };
                let target = PathOwnerDeleteTarget {
                    node_type: entry.node_type.clone(),
                    node_name: entry.node_name.clone(),
                };
                if row.staged.owner_delete().targets.contains(&target) {
                    continue;
                }
                if replacement.after_value == entry.value {
                    merged.remove(&replacement.entry_index);
                } else {
                    merged.insert(replacement.entry_index, replacement.after_value);
                }
            }
            if &merged == row.staged.overrides() {
                rejected.skipped += 1;
                continue;
            }
            let replacements = merged
                .iter()
                .filter_map(|(index, value)| {
                    cached
                        .report
                        .entries
                        .get(*index)
                        .map(|entry| PathReplaceOverride {
                            entry_index: *index,
                            before_value: entry.value.clone(),
                            after_value: value.clone(),
                        })
                })
                .collect::<Vec<_>>();
            let options = self.scene_materialize_options(OperationMode::Forensic);
            if let Err(error) = preview_replace_scene_paths_with_overrides_in_report_with_options(
                &cached.report,
                &replacements,
                &options,
            ) {
                self.report_edit_detail(error.to_string());
                rejected.skipped += 1;
                continue;
            }
            if self.rows[index].paths_report.is_none() {
                self.rows[index].paths_report = Some(cached.report.clone());
            }
            planned_edits.push((index, merged));
        }
        let mut applied = planned_edits.len();
        if applied > 0 {
            if self
                .apply_path_override_updates(planned_edits, window, cx)
                .is_err()
            {
                rejected.skipped += applied;
                applied = 0;
            }
            self.clear_replace_dialog_state(window, cx);
            window.close_dialog(cx);
            self.set_tab(ResultTab::Paths, window, cx);
        }
        rejected.changed = Some(applied);
        self.report_replace_rejections(rejected, applied, cx);
        if self.status_message.is_none() {
            self.status_message = previous_banner;
        }
        self.refresh_file_table(cx);
        cx.notify();
    }

    fn report_replace_rejections(
        &mut self,
        rejected: MutationRejections,
        applied: usize,
        cx: &mut Context<Self>,
    ) {
        if let Some(skipped) = rejected.banner() {
            let summary = format!(
                "{} file(s) staged; {}",
                applied,
                render_banner_message(&self.i18n(), &skipped)
            );
            self.record_job(
                operation_key(RowOperation::Replace),
                self.state.workspace_root_path().unwrap_or_default(),
                None,
                summary,
                false,
            );
        }
        self.report_mutation_rejections(rejected, cx);
    }

    pub(super) fn toggle_replace_dialog_path_type_filter(
        &mut self,
        filter: PathTypeFilter,
        cx: &mut Context<Self>,
    ) {
        let Some(dialog) = self.replace_dialog.as_mut() else {
            return;
        };
        if !dialog.path_type_filter.insert(filter) {
            dialog.path_type_filter.remove(&filter);
        }
        dialog.invalidate_preview();
        cx.notify();
    }

    pub(super) fn set_replace_dialog_mode(
        &mut self,
        mode: PathReplaceMode,
        cx: &mut Context<Self>,
    ) {
        let Some(dialog) = self.replace_dialog.as_mut() else {
            return;
        };
        if dialog.replace_mode == mode {
            return;
        }
        dialog.replace_mode = mode;
        dialog.invalidate_preview();
        cx.notify();
    }

    pub(super) fn toggle_replace_dialog_preview_sort(
        &mut self,
        key: ReplaceDialogSortKey,
        cx: &mut Context<Self>,
    ) {
        let Some(dialog) = self.replace_dialog.as_mut() else {
            return;
        };
        dialog.preview_sort = if dialog.preview_sort.key == key {
            let next_direction = match dialog.preview_sort.direction {
                ColumnSort::Default => ColumnSort::Ascending,
                ColumnSort::Ascending => ColumnSort::Descending,
                ColumnSort::Descending => ColumnSort::Default,
            };
            ReplaceDialogSort {
                key,
                direction: next_direction,
            }
        } else {
            ReplaceDialogSort {
                key,
                direction: ColumnSort::Ascending,
            }
        };
        self.sync_replace_preview_table(cx);
        cx.notify();
    }

    pub(super) fn sync_replace_preview_table(&mut self, cx: &mut Context<Self>) {
        let Some(dialog) = self.replace_dialog.as_ref() else {
            return;
        };
        let rows = dialog
            .preview
            .as_ref()
            .map(|preview| render_replace_dialog_preview_rows(preview, dialog))
            .unwrap_or_default();
        let sort = dialog.preview_sort;
        let locale = self.i18n().locale();
        self.replace_preview_table.update(cx, |table, cx| {
            if table.delegate_mut().sync(rows, locale, sort) {
                table.refresh(cx);
            }
            cx.notify();
        });
    }
}

fn build_replace_dialog(
    dialog: Dialog,
    view: Entity<GuiShell>,
    window: &mut Window,
    cx: &mut App,
) -> Dialog {
    let needs_refresh = {
        let shell = view.read(cx);
        shell.replace_dialog_preview_needs_refresh(cx)
    };
    if needs_refresh {
        let view = view.clone();
        window.defer(cx, move |window, cx| {
            view.update(cx, |shell, cx| shell.run_replace_preview(window, cx));
        });
    }
    let shell = view.read(cx);
    let i18n = shell.i18n();
    let dialog_state = shell.replace_dialog.as_ref();
    let selected_count = dialog_state
        .map(|state| state.captured_row_ids.len())
        .unwrap_or_default();
    let layout = replace_dialog_layout(window);
    let preview_refreshing = dialog_state
        .is_some_and(|state| state.preview.is_some() && state.preview_signature.is_none());
    let summary = if let Some(dialog_state) = dialog_state {
        if let Some(preview) = dialog_state.preview.as_ref() {
            i18n.format(
                "dialog.replace_summary",
                &[
                    ("selected", selected_count.to_string()),
                    ("previewable", preview.previewable_row_ids.len().to_string()),
                    ("matched", preview.matched_count.to_string()),
                    ("failed", preview.failed_files.len().to_string()),
                ],
            )
        } else if dialog_state.is_previewing {
            i18n.text("dialog.replace_previewing")
        } else {
            i18n.format(
                "dialog.replace_selected_files",
                &[("count", selected_count.to_string())],
            )
        }
    } else {
        i18n.text("dialog.replace_selected_files_empty")
    };

    let mut dialog = dialog
        .title(i18n.text("dialog.replace_path_title"))
        .width(layout.width)
        .max_h(layout.max_height)
        .overlay_closable(false)
        .on_cancel({
            let view = view.clone();
            move |_, window, cx| {
                view.update(cx, |shell, cx| shell.clear_replace_dialog_state(window, cx));
                true
            }
        })
        .footer({
            let view = view.clone();
            move |_, _, _, cx| {
                let shell = view.read(cx);
                let i18n = shell.i18n();
                let can_apply = shell.replace_dialog_can_apply(cx);
                vec![
                    div()
                        .debug_selector(|| "replace-dialog-close".to_string())
                        .child(
                            Button::new("replace-cancel")
                                .label(i18n.text("action.cancel"))
                                .ghost()
                                .on_click({
                                    let view = view.clone();
                                    move |_, window, cx| {
                                        view.update(cx, |shell, cx| {
                                            shell.clear_replace_dialog_state(window, cx);
                                        });
                                        window.close_dialog(cx);
                                    }
                                }),
                        )
                        .into_any_element(),
                    Button::new("replace-apply")
                        .label(i18n.text("action.apply"))
                        .disabled(!can_apply)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| shell.apply_replace_dialog(window, cx));
                            }
                        })
                        .into_any_element(),
                ]
            }
        });

    dialog = dialog.child(
        div()
            .debug_selector(|| "replace-dialog-body".to_string())
            .w_full()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child(i18n.text("dialog.replace_hint")),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .items_end()
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(MUTED))
                                    .child(i18n.text("label.before")),
                            )
                            .child(
                                Input::new(&shell.replace_from_input)
                                    .small()
                                    .cleanable(true),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(MUTED))
                                    .child(i18n.text("label.after")),
                            )
                            .child(Input::new(&shell.replace_to_input).small().cleanable(true)),
                    ),
            )
            .child(
                div().flex().flex_wrap().gap_2().children(
                    [PathTypeFilter::Reference, PathTypeFilter::File]
                        .into_iter()
                        .map(|filter| {
                            let selected = dialog_state
                                .is_some_and(|state| state.path_type_filter.contains(&filter));
                            replace_dialog_path_type_filter_button(
                                path_type_filter_label(&i18n, filter),
                                filter,
                                selected,
                                view.clone(),
                            )
                            .into_any_element()
                        }),
                ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child(i18n.text("label.replace_mode")),
                    )
                    .child(
                        RadioGroup::horizontal("replace-mode")
                            .selected_index(dialog_state.map(|state| {
                                if state.replace_mode == PathReplaceMode::Literal {
                                    0
                                } else {
                                    1
                                }
                            }))
                            .gap_x_3()
                            .child(
                                Radio::new("replace-mode-literal")
                                    .label(i18n.text("label.replace_mode_literal"))
                                    .on_click({
                                        let view = view.clone();
                                        move |checked, _, cx| {
                                            if !*checked {
                                                return;
                                            }
                                            view.update(cx, |shell, cx| {
                                                shell.set_replace_dialog_mode(
                                                    PathReplaceMode::Literal,
                                                    cx,
                                                )
                                            });
                                        }
                                    }),
                            )
                            .child(
                                Radio::new("replace-mode-regex")
                                    .label(i18n.text("label.replace_mode_regex"))
                                    .on_click({
                                        let view = view.clone();
                                        move |checked, _, cx| {
                                            if !*checked {
                                                return;
                                            }
                                            view.update(cx, |shell, cx| {
                                                shell.set_replace_dialog_mode(
                                                    PathReplaceMode::Regex,
                                                    cx,
                                                )
                                            });
                                        }
                                    }),
                            ),
                    ),
            )
            .child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(PANEL_ALT_BG))
                    .px_3()
                    .py_2()
                    .text_sm()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(summary)
                    .when(preview_refreshing, |this| {
                        this.child(Spinner::new().with_size(px(12.0)))
                    }),
            )
            .child(render_replace_dialog_preview(
                dialog_state,
                &i18n,
                selected_count,
                view.clone(),
                layout.preview_max_height,
                cx,
            )),
    );

    dialog
}

fn replace_dialog_layout(window: &Window) -> ReplaceDialogLayout {
    let window_paddings = gpui_component::window_paddings(window);
    let viewport = window.viewport_size()
        - size(
            window_paddings.left + window_paddings.right,
            window_paddings.top + window_paddings.bottom,
        );
    let available_width =
        clamp_replace_dialog_dimension(viewport.width, REPLACE_DIALOG_HORIZONTAL_MARGIN);
    let available_height =
        clamp_replace_dialog_dimension(viewport.height, REPLACE_DIALOG_VERTICAL_MARGIN);

    ReplaceDialogLayout {
        width: available_width,
        max_height: available_height,
        preview_max_height: REPLACE_DIALOG_PREVIEW_MAX_HEIGHT.min(available_height),
    }
}

fn clamp_replace_dialog_dimension(viewport: Pixels, margin: Pixels) -> Pixels {
    if viewport > margin {
        viewport - margin
    } else {
        viewport.max(px(0.0))
    }
}

fn render_replace_dialog_preview(
    dialog_state: Option<&ReplaceDialogState>,
    i18n: &I18n,
    selected_count: usize,
    view: Entity<GuiShell>,
    preview_max_height: Pixels,
    cx: &App,
) -> AnyElement {
    let Some(dialog_state) = dialog_state else {
        return div()
            .text_sm()
            .text_color(rgb(MUTED))
            .child(i18n.text("dialog.replace_selected_files_empty"))
            .into_any_element();
    };
    if dialog_state.is_previewing && dialog_state.preview.is_none() {
        return div()
            .flex()
            .items_center()
            .gap_3()
            .child(Spinner::new().with_size(px(16.0)))
            .child(i18n.text("dialog.replace_previewing"))
            .into_any_element();
    }
    let Some(preview) = dialog_state.preview.as_ref() else {
        return div()
            .text_sm()
            .text_color(rgb(MUTED))
            .child(i18n.text("dialog.replace_preview_hint"))
            .into_any_element();
    };

    let row_count = view
        .read(cx)
        .replace_preview_table
        .read(cx)
        .delegate()
        .row_count();
    let content = if row_count == 0 {
        div()
            .rounded_md()
            .border_1()
            .border_color(rgb(BORDER))
            .bg(rgb(PANEL_ALT_BG))
            .px_3()
            .py_3()
            .text_sm()
            .child(i18n.text("dialog.replace_no_matches"))
            .into_any_element()
    } else {
        // The table virtualizes rows itself; it only needs a bounded height.
        let table_height = (REPLACE_PREVIEW_TABLE_ROW_HEIGHT * (row_count + 1) as f32 + px(2.0))
            .min(preview_max_height);

        div()
            .rounded_md()
            .border_1()
            .border_color(rgb(BORDER))
            .w_full()
            .h(table_height)
            .min_h_0()
            .overflow_hidden()
            .child(Table::new(&view.read(cx).replace_preview_table).scrollbar_visible(true, true))
            .into_any_element()
    };

    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(content)
        .when(!preview.failed_files.is_empty(), |this| {
            this.child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(WARN_SOFT))
                    .px_3()
                    .py_3()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::BOLD)
                            .child(i18n.format(
                                "dialog.replace_failed_files",
                                &[("count", preview.failed_files.len().to_string())],
                            )),
                    )
                    .children(
                        preview
                            .failed_files
                            .iter()
                            .map(|line| div().text_sm().text_color(rgb(TEXT)).child(line.clone())),
                    ),
            )
        })
        .when(
            preview.items.is_empty() && preview.failed_files.len() == selected_count,
            |this| {
                this.child(
                    div()
                        .text_sm()
                        .text_color(rgb(MUTED))
                        .child(i18n.text("dialog.replace_apply_blocked_all_failed")),
                )
            },
        )
        .into_any_element()
}

fn replace_dialog_path_type_filter_button(
    label: String,
    filter: PathTypeFilter,
    selected: bool,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let (background, foreground) = if selected {
        match filter {
            PathTypeFilter::Reference => (ACCENT_SOFT, ACCENT),
            PathTypeFilter::File => (WARN_SOFT, 0x8a6116),
        }
    } else {
        (PANEL_BG, MUTED)
    };
    let border = if selected { foreground } else { BORDER };

    div()
        .px_2()
        .py_1()
        .rounded_sm()
        .border_1()
        .border_color(rgb(border))
        .bg(rgb(background))
        .text_sm()
        .text_color(rgb(foreground))
        .flex()
        .items_center()
        .gap_1()
        .child(Icon::new(path_type_icon(filter)).small())
        .child(label)
        .on_mouse_down(MouseButton::Left, |_, _, cx| {
            cx.stop_propagation();
        })
        .on_mouse_up(MouseButton::Left, move |_, _, cx| {
            view.update(cx, |shell, cx| {
                shell.toggle_replace_dialog_path_type_filter(filter, cx);
                cx.notify();
            });
        })
}

pub(super) fn render_replace_dialog_preview_rows(
    preview: &ReplaceDialogPreviewState,
    dialog_state: &ReplaceDialogState,
) -> Vec<ReplaceDialogPreviewRow> {
    let mut seen = BTreeSet::new();
    let mut rows = preview
        .items
        .iter()
        .filter(|item| seen.insert((item.before_value.clone(), item.after_value.clone())))
        .cloned()
        .collect::<Vec<_>>();

    if !matches!(dialog_state.preview_sort.direction, ColumnSort::Default) {
        rows.sort_by(|left, right| {
            let ordering = match dialog_state.preview_sort.key {
                ReplaceDialogSortKey::Before => left.before_value.cmp(&right.before_value),
                ReplaceDialogSortKey::After => left.after_value.cmp(&right.after_value),
            }
            .then_with(|| left.before_value.cmp(&right.before_value))
            .then_with(|| left.after_value.cmp(&right.after_value));

            match dialog_state.preview_sort.direction {
                ColumnSort::Ascending => ordering,
                ColumnSort::Descending => ordering.reverse(),
                ColumnSort::Default => std::cmp::Ordering::Equal,
            }
        });
    }

    rows
}
