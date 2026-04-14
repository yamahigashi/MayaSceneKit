use super::*;
use maya_scene_kit_edit::scene::OperationMode;

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
        let captured_row_ids = self
            .ready_selected_indices()
            .into_iter()
            .filter_map(|index| self.rows.get(index).map(|row| row.id))
            .collect::<Vec<_>>();
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
            captured_row_ids,
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
        let Some((captured_row_ids, existing_cache)) = self
            .replace_dialog
            .as_ref()
            .map(|dialog| (dialog.captured_row_ids.clone(), dialog.source_cache.clone()))
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
            dialog_state.preview = None;
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

                            for (row_id, path, scene_name, cached_entry) in targets {
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

        let planned_overrides = dialog_state
            .preview
            .as_ref()
            .map(|preview| preview.planned_overrides.clone())
            .unwrap_or_default();
        let source_cache = dialog_state.source_cache.clone();
        let target_indices = planned_overrides
            .iter()
            .filter_map(|(row_id, overrides)| {
                (!overrides.is_empty())
                    .then(|| self.index_of_row_id(*row_id))
                    .flatten()
            })
            .collect::<Vec<_>>();
        let before = self.capture_row_edit_states(&target_indices);

        for (row_id, overrides) in planned_overrides {
            if overrides.is_empty() {
                continue;
            }
            let Some(index) = self.index_of_row_id(row_id) else {
                continue;
            };
            let Some(source_cache_entry) = source_cache.get(&row_id).cloned() else {
                continue;
            };
            let options = self.scene_materialize_options(OperationMode::Forensic);
            let preview = match preview_replace_scene_paths_with_overrides_in_report_with_options(
                &source_cache_entry.report,
                &overrides,
                &options,
            ) {
                Ok(preview) => preview,
                Err(err) => {
                    self.status_message = Some(BannerMessage::Raw(err.to_string()));
                    continue;
                }
            };
            let overrides_by_entry = path_overrides_from_replace_preview(&preview);
            let matched = preview.matched_count;
            let row_path = self.rows[index].path.clone();
            let mut revision = None;
            if let Some(row) = self.rows.get_mut(index) {
                row.paths_report = Some(source_cache_entry.report.clone());
                row.path_overrides = overrides_by_entry;
                row.dirty_kind = Some(DirtyKind::Replace);
                row.replace_preview = Some(preview);
                row.dirty_artifact = None;
                row.path_owner_delete_preview = None;
                row.replace_generation = row.replace_generation.wrapping_add(1);
                row.replace_artifact_generation = None;
                row.status = FileStatus::Dirty;
                revision = Some(row.replace_generation);
            }
            self.refresh_row_path_resolution_state(index);
            self.record_job(
                operation_key(RowOperation::Replace),
                row_path,
                None,
                format!("{matched} match(es) staged"),
                false,
            );
            if let Some(revision) = revision {
                self.spawn_replace_artifact_refresh(row_id, revision, window, cx);
            }
        }
        self.push_edit_history(before);
        self.refresh_app_menus(window, cx);

        self.clear_replace_dialog_state(window, cx);
        window.close_dialog(cx);
        self.set_tab(ResultTab::Paths, cx);
        cx.notify();
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
        cx.notify();
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
    let dialog_state = shell.replace_dialog.clone();
    let selected_count = dialog_state
        .as_ref()
        .map(|state| state.captured_row_ids.len())
        .unwrap_or_default();
    let summary = if let Some(dialog_state) = dialog_state.as_ref() {
        if dialog_state.is_previewing {
            i18n.text("dialog.replace_previewing")
        } else if let Some(preview) = dialog_state.preview.as_ref() {
            i18n.format(
                "dialog.replace_summary",
                &[
                    ("selected", selected_count.to_string()),
                    ("previewable", preview.previewable_row_ids.len().to_string()),
                    ("matched", preview.matched_count.to_string()),
                    ("failed", preview.failed_files.len().to_string()),
                ],
            )
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
        .width(px(860.0))
        .max_w(px(960.0))
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
                        })
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
            .w_full()
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
                                .as_ref()
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
                            .selected_index(dialog_state.as_ref().map(|state| {
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
                    .child(summary),
            )
            .child(render_replace_dialog_preview(
                dialog_state.as_ref(),
                &i18n,
                selected_count,
                view.clone(),
            )),
    );

    dialog
}

fn render_replace_dialog_preview(
    dialog_state: Option<&ReplaceDialogState>,
    i18n: &I18n,
    selected_count: usize,
    view: Entity<GuiShell>,
) -> AnyElement {
    let Some(dialog_state) = dialog_state else {
        return div()
            .text_sm()
            .text_color(rgb(MUTED))
            .child(i18n.text("dialog.replace_selected_files_empty"))
            .into_any_element();
    };
    if dialog_state.is_previewing {
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

    let rendered_items = render_replace_dialog_preview_rows(preview, dialog_state);
    let content = if rendered_items.is_empty() {
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
        div()
            .rounded_md()
            .border_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .px_3()
                    .py_2()
                    .border_b_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(PANEL_ALT_BG))
                    .flex()
                    .gap_3()
                    .text_sm()
                    .font_weight(FontWeight::BOLD)
                    .child(render_replace_preview_sort_header(
                        i18n.text("label.before"),
                        ReplaceDialogSortKey::Before,
                        dialog_state.preview_sort,
                        view.clone(),
                    ))
                    .child(render_replace_preview_sort_header(
                        i18n.text("label.after"),
                        ReplaceDialogSortKey::After,
                        dialog_state.preview_sort,
                        view.clone(),
                    )),
            )
            .child(div().max_h(px(320.0)).overflow_y_scrollbar().children(
                rendered_items.into_iter().map(|item| {
                    div()
                        .px_3()
                        .py_2()
                        .border_b_1()
                        .border_color(rgb(BORDER))
                        .flex()
                        .gap_3()
                        .text_sm()
                        .child(div().flex_1().truncate().child(item.before_value.clone()))
                        .child(div().flex_1().truncate().child(item.after_value.clone()))
                }),
            ))
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
    let filter_to_matches_only = dialog_state
        .preview_signature
        .as_ref()
        .is_some_and(|signature| !signature.from_value.trim().is_empty());
    let mut seen = BTreeSet::new();
    let mut rows = preview
        .items
        .iter()
        .filter(|item| !filter_to_matches_only || item.before_value != item.after_value)
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

fn render_replace_preview_sort_header(
    label: String,
    key: ReplaceDialogSortKey,
    sort: ReplaceDialogSort,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let indicator = if sort.key == key {
        match sort.direction {
            ColumnSort::Ascending => " ↑",
            ColumnSort::Descending => " ↓",
            ColumnSort::Default => "",
        }
    } else {
        ""
    };

    div()
        .flex_1()
        .flex()
        .items_center()
        .gap_1()
        .cursor_pointer()
        .child(format!("{label}{indicator}"))
        .on_mouse_down(MouseButton::Left, |_, _, cx| {
            cx.stop_propagation();
        })
        .on_mouse_up(MouseButton::Left, move |_, _, cx| {
            view.update(cx, |shell, cx| {
                shell.toggle_replace_dialog_preview_sort(key, cx)
            });
        })
}
