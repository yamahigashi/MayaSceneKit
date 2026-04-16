use gpui_component::menu::PopupMenu;

use super::*;

impl PathTableDelegate {
    pub(in crate::gui) fn new(
        rows: Vec<PathTableRow>,
        locale: SupportedLocale,
        sort: PathTableSort,
        show_scene_column: bool,
        persisted_widths: &[PersistedTableColumnWidth],
    ) -> Self {
        Self {
            view: None,
            locale,
            rows,
            show_scene_column,
            sort,
            columns: apply_persisted_column_widths(
                path_table_columns(show_scene_column, sort),
                persisted_widths,
            ),
        }
    }

    pub(in crate::gui) fn set_view(&mut self, view: Entity<GuiShell>) {
        self.view = Some(view);
    }

    pub(in crate::gui) fn apply_widths(&mut self, widths: &[Pixels]) {
        for (column, width) in self.columns.iter_mut().zip(widths.iter().copied()) {
            column.width = width;
        }
    }

    pub(in crate::gui) fn persisted_column_widths(&self) -> Vec<PersistedTableColumnWidth> {
        persisted_column_widths(&self.columns)
    }

    pub(in crate::gui) fn sync(
        &mut self,
        rows: Vec<PathTableRow>,
        locale: SupportedLocale,
        show_scene_column: bool,
        sort: PathTableSort,
    ) {
        self.rows = rows;
        self.locale = locale;
        if self.show_scene_column != show_scene_column {
            self.columns =
                merge_column_widths(&self.columns, path_table_columns(show_scene_column, sort));
        } else {
            update_path_sort_columns(&mut self.columns, show_scene_column, sort);
        }
        self.show_scene_column = show_scene_column;
        self.sort = sort;
    }

    fn kind_column_ix(&self) -> usize {
        0
    }

    fn scene_column_ix(&self) -> Option<usize> {
        self.show_scene_column.then_some(1)
    }

    fn node_column_ix(&self) -> usize {
        if self.show_scene_column { 2 } else { 1 }
    }

    fn path_column_ix(&self) -> usize {
        if self.show_scene_column { 3 } else { 2 }
    }

    fn update_sort_columns(&mut self, active_col_ix: usize, sort: ColumnSort) {
        for (col_ix, column) in self.columns.iter_mut().enumerate() {
            if col_ix == active_col_ix {
                if column.sort.is_some() {
                    column.sort = Some(sort);
                }
            } else if column.sort.is_some() {
                column.sort = Some(ColumnSort::Default);
            }
        }
    }
}

impl TableDelegate for PathTableDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> &Column {
        &self.columns[col_ix]
    }

    fn perform_sort(
        &mut self,
        col_ix: usize,
        sort: ColumnSort,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        let Some(key) = path_sort_key_for_col_ix(col_ix, self.show_scene_column) else {
            return;
        };
        let sort = match sort {
            ColumnSort::Default => ColumnSort::Ascending,
            other => other,
        };
        self.update_sort_columns(col_ix, sort);
        if let Some(view) = self.view.clone() {
            cx.defer(move |cx| {
                view.update(cx, |shell, cx| shell.set_path_sort(key, sort, cx));
            });
        }
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let row = &self.rows[row_ix];
        let mut tr = div().id(("path-row", row_ix)).bg(rgb(if row.selected {
            ACCENT_SOFT
        } else if row.dirty {
            WARN_SOFT
        } else {
            PANEL_BG
        }));

        if let Some(view) = self.view.clone().filter(|_| !row.edit_targets.is_empty()) {
            let edit_targets = row.edit_targets.clone();
            tr = tr.on_mouse_up(MouseButton::Left, move |event, _, cx| {
                view.update(cx, |shell, cx| {
                    shell.select_path_row(edit_targets.clone(), event.modifiers, cx);
                });
            });
        }

        tr
    }

    fn render_th(
        &mut self,
        col_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let i18n = I18n::new(self.locale);
        let label = match col_ix {
            ix if ix == self.kind_column_ix() => String::new(),
            ix if self.scene_column_ix() == Some(ix) => i18n.text("table.scene"),
            ix if ix == self.node_column_ix() => i18n.text("table.node"),
            ix if ix == self.path_column_ix() => i18n.text("table.path"),
            _ => String::new(),
        };
        let mut th = div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .px_2()
            .py_2()
            .text_sm()
            .text_color(rgb(MUTED));
        if col_ix == self.kind_column_ix() {
            th = th.child(Icon::new(IconName::Frame).small());
        } else {
            th = th
                .justify_start()
                .child(div().min_w_0().truncate().child(label));
        }
        let Some(key) = path_sort_key_for_col_ix(col_ix, self.show_scene_column) else {
            return th.into_any_element();
        };
        let Some(view) = self.view.clone() else {
            return th.into_any_element();
        };
        let show_scene_column = self.show_scene_column;
        th.cursor_pointer()
            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .on_mouse_up(MouseButton::Left, move |_, window, cx| {
                cx.stop_propagation();
                view.update(cx, |shell, cx| {
                    let sort =
                        next_path_sort_for_col_ix(col_ix, show_scene_column, shell.path_sort);
                    shell.set_path_sort(key, sort, cx);
                    cx.focus_self(window);
                    cx.notify();
                });
            })
            .into_any_element()
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let row = self.rows[row_ix].clone();
        let view = self.view.clone();
        match col_ix {
            ix if ix == self.kind_column_ix() => {
                let mut cell = div()
                    .size_full()
                    .px_2()
                    .py_1()
                    .flex()
                    .items_center()
                    .justify_start()
                    .gap_1()
                    .child(path_kind_badge(row.path_kind));
                if let Some(indicator) = path_resolution_badge_indicator(row.resolution_badge) {
                    cell = cell.child(indicator);
                }
                cell.into_any_element()
            }
            ix if self.scene_column_ix() == Some(ix) => {
                path_table_cell(row.scene, None, false).into_any_element()
            }
            ix if ix == self.node_column_ix() => {
                path_table_cell(row.node, None, false).into_any_element()
            }
            ix if ix == self.path_column_ix() => {
                if row.editing && row.editable {
                    if let Some(view) = view.clone() {
                        let input = view.read(cx).path_edit_input.clone();
                        let i18n = I18n::new(self.locale);
                        let action_suffix = path_edit_targets_id(&row.edit_targets);
                        let input_focus_handle = input.read(cx).focus_handle(cx);
                        div()
                            .size_full()
                            .px_2()
                            .py_2()
                            .flex()
                            .items_center()
                            .gap_2()
                            .capture_key_down({
                                let view = view.clone();
                                move |event, window, cx| {
                                    let outcome = view.update(cx, |shell, cx| {
                                        shell.path_edit_keyboard_outcome(
                                            &event.keystroke.key,
                                            window,
                                            cx,
                                        )
                                    });
                                    if outcome == PathEditKeyboardOutcome::SuppressForIme {
                                        cx.stop_propagation();
                                    }
                                }
                            })
                            .on_key_down({
                                let view = view.clone();
                                move |event, window, cx| {
                                    if view.update(cx, |shell, cx| {
                                        shell.path_edit_keyboard_outcome(
                                            &event.keystroke.key,
                                            window,
                                            cx,
                                        )
                                    }) != PathEditKeyboardOutcome::Cancel
                                    {
                                        return;
                                    }
                                    cx.stop_propagation();
                                    view.update(cx, |shell, cx| {
                                        shell.cancel_path_edit(window, cx);
                                    });
                                }
                            })
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                        cx.stop_propagation();
                                    })
                                    .on_mouse_up(MouseButton::Left, move |_, window, cx| {
                                        cx.stop_propagation();
                                        input_focus_handle.focus(window);
                                    })
                                    .child(Input::new(&input).small()),
                            )
                            .child(action_button(
                                format!("path-select-file-{action_suffix}"),
                                i18n.text("action.select_file"),
                                true,
                                move |shell, window, cx| shell.select_path_edit_file(window, cx),
                                view.clone(),
                            ))
                            .child(action_button(
                                format!("path-apply-{action_suffix}"),
                                i18n.text("action.apply"),
                                true,
                                move |shell, window, cx| shell.apply_path_edit(window, cx),
                                view.clone(),
                            ))
                            .child(action_button(
                                format!("path-cancel-{action_suffix}"),
                                i18n.text("action.cancel"),
                                true,
                                move |shell, window, cx| shell.cancel_path_edit(window, cx),
                                view,
                            ))
                            .into_any_element()
                    } else {
                        path_table_cell(row.value, row.value_style, row.owner_deleted)
                            .into_any_element()
                    }
                } else if row.preview_only {
                    div()
                        .size_full()
                        .px_2()
                        .py_2()
                        .flex()
                        .gap_2()
                        .items_center()
                        .child(path_table_text(
                            row.value,
                            row.value_style,
                            row.owner_deleted,
                        ))
                        .child(badge(
                            &I18n::new(self.locale).text("label.preview"),
                            PANEL_ALT_BG,
                            MUTED,
                        ))
                        .into_any_element()
                } else if row.editable && !row.edit_targets.is_empty() {
                    if let Some(view) = view.clone() {
                        let edit_targets = row.edit_targets.clone();
                        let selected = row.selected;
                        let view = view.clone();
                        let content = path_table_value_cell(
                            row.value,
                            row.value_style,
                            row.dirty,
                            row.owner_deleted,
                            row.resolution_badge,
                            self.locale,
                        );
                        content
                            .on_mouse_up(MouseButton::Left, move |event, window, cx| {
                                if event.modifiers.shift
                                    || event.modifiers.control
                                    || event.modifiers.platform
                                {
                                    return;
                                }
                                if !selected {
                                    return;
                                }
                                cx.stop_propagation();
                                view.update(cx, |shell, cx| {
                                    if shell.selected_path_rows.len() != 1 {
                                        return;
                                    }
                                    shell.begin_path_edit(edit_targets.clone(), window, cx);
                                });
                            })
                            .into_any_element()
                    } else {
                        path_table_value_cell(
                            row.value,
                            row.value_style,
                            row.dirty,
                            row.owner_deleted,
                            row.resolution_badge,
                            self.locale,
                        )
                        .into_any_element()
                    }
                } else {
                    path_table_value_cell(
                        row.value,
                        row.value_style,
                        row.dirty,
                        row.owner_deleted,
                        row.resolution_badge,
                        self.locale,
                    )
                    .into_any_element()
                }
            }
            _ => path_table_cell(String::new(), None, false).into_any_element(),
        }
    }

    fn context_menu(
        &mut self,
        row_ix: usize,
        menu: PopupMenu,
        window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> PopupMenu {
        let Some(row) = self.rows.get(row_ix).cloned() else {
            return menu;
        };
        let Some(view) = self.view.clone() else {
            return menu;
        };
        if !row.edit_targets.is_empty() {
            let view = view.clone();
            let edit_targets = row.edit_targets.clone();
            window.defer(cx, move |_window, cx| {
                view.update(cx, |shell, cx| {
                    shell.suppress_next_path_focus_out_clear = true;
                    if !shell.selected_path_rows.contains(&edit_targets) {
                        shell.select_path_row(edit_targets.clone(), Modifiers::default(), cx);
                    }
                });
            });
        }

        let copy_label = I18n::new(self.locale).text("action.copy_path_name");
        let copy_file_label = I18n::new(self.locale).text("action.copy_file");
        let convert_absolute_label = I18n::new(self.locale).text("action.convert_to_absolute");
        let convert_workspace_double_slash_relative_label =
            I18n::new(self.locale).text("action.convert_to_workspace_double_slash_relative");
        let convert_plain_relative_label =
            I18n::new(self.locale).text("action.convert_to_plain_relative");
        let collect_absolute_label =
            I18n::new(self.locale).text("action.collect_files_to_absolute");
        let collect_to_folder_label = I18n::new(self.locale).text("action.collect_files_to_folder");
        let collect_workspace_double_slash_relative_label =
            I18n::new(self.locale).text("action.collect_files_to_workspace_double_slash_relative");
        let collect_plain_relative_label =
            I18n::new(self.locale).text("action.collect_files_to_plain_relative");
        let replace_label = I18n::new(self.locale).text("action.replace_path");
        let undo_label = I18n::new(self.locale).text("action.discard_changes");
        let delete_owner_label = I18n::new(self.locale).text("action.delete_owner_nodes");
        let edit_targets = row.edit_targets.clone();

        if edit_targets.is_empty() {
            return menu.item(PopupMenuItem::new(copy_label).on_click({
                let copied_path = row.value.clone();
                move |_, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(copied_path.clone()));
                }
            }));
        }

        let selected_targets =
            view.update(cx, |shell, _| shell.context_path_targets(&edit_targets));
        let has_copyable_file = view.update(cx, |shell, _| {
            !resolved_target_file_paths_for_edit_targets(&shell.rows, &selected_targets).is_empty()
        });
        let path_menu_state = view.update(cx, |shell, _| {
            path_context_menu_state(&shell.rows, &selected_targets)
        });
        let has_dirty_context_targets = view.update(cx, |shell, _| {
            selected_targets.iter().any(|(row_id, entry_index)| {
                shell
                    .rows
                    .iter()
                    .find(|row| row.id == *row_id)
                    .is_some_and(|row| {
                        row.path_overrides.contains_key(entry_index)
                            || path_owner_delete_staged_for_entry(row, *entry_index)
                    })
            })
        });
        let can_delete_owner_targets = row.owner_deletable
            && view.update(cx, |shell, _| {
                path_owner_delete_supported_for_edit_targets(&shell.rows, &selected_targets)
            });

        let menu = menu
            .item(PopupMenuItem::new(copy_label).on_click({
                let copied_path = row.value.clone();
                move |_, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(copied_path.clone()));
                }
            }))
            .item(PopupMenuItem::new(replace_label).on_click({
                let view = view.clone();
                let edit_targets = edit_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        let selected_targets = shell.context_path_targets(&edit_targets);
                        shell.open_replace_dialog_for_path_targets(selected_targets, window, cx);
                    });
                }
            }))
            .separator();

        let menu = if path_menu_state.can_convert_to_absolute {
            menu.item(PopupMenuItem::new(convert_absolute_label).on_click({
                let view = view.clone();
                let selected_targets = selected_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        shell.convert_path_targets_to_absolute(
                            selected_targets.clone(),
                            window,
                            cx,
                        );
                    });
                }
            }))
        } else if path_menu_state.show_disabled_convert_to_absolute {
            menu.item(PopupMenuItem::new(convert_absolute_label).disabled(true))
        } else {
            menu
        };
        let menu = if path_menu_state.can_convert_to_workspace_double_slash_relative {
            menu.item(
                PopupMenuItem::new(convert_workspace_double_slash_relative_label).on_click({
                    let view = view.clone();
                    let selected_targets = selected_targets.clone();
                    move |_, window, cx| {
                        view.update(cx, |shell, cx| {
                            shell.convert_path_targets_to_workspace_relative(
                                selected_targets.clone(),
                                PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
                                window,
                                cx,
                            );
                        });
                    }
                }),
            )
        } else if path_menu_state.show_disabled_convert_to_workspace_double_slash_relative {
            menu.item(
                PopupMenuItem::new(convert_workspace_double_slash_relative_label).disabled(true),
            )
        } else {
            menu
        };
        let menu = if path_menu_state.can_convert_to_plain_relative {
            menu.item(PopupMenuItem::new(convert_plain_relative_label).on_click({
                let view = view.clone();
                let selected_targets = selected_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        shell.convert_path_targets_to_workspace_relative(
                            selected_targets.clone(),
                            PathCollectRewriteMode::PlainRelative,
                            window,
                            cx,
                        );
                    });
                }
            }))
        } else if path_menu_state.show_disabled_convert_to_plain_relative {
            menu.item(PopupMenuItem::new(convert_plain_relative_label).disabled(true))
        } else {
            menu
        };
        let menu = menu.separator();
        let menu = if has_copyable_file {
            menu.item(PopupMenuItem::new(copy_file_label).on_click({
                let view = view.clone();
                let edit_targets = edit_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        let selected_targets = shell.context_path_targets(&edit_targets);
                        shell.copy_path_target_files_to_clipboard(selected_targets, window, cx);
                    });
                }
            }))
        } else {
            menu
        };
        let menu = if path_menu_state.can_collect_files_to_folder {
            menu.item(PopupMenuItem::new(collect_to_folder_label).on_click({
                let view = view.clone();
                let selected_targets = selected_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        shell.open_path_collect_dialog(
                            selected_targets.clone(),
                            PathCollectRewriteMode::CopyOnly,
                            window,
                            cx,
                        );
                    });
                }
            }))
        } else if path_menu_state.show_disabled_collect_files_to_folder {
            menu.item(PopupMenuItem::new(collect_to_folder_label).disabled(true))
        } else {
            menu
        };
        let menu = menu.separator();
        let menu = if path_menu_state.can_collect_files {
            menu.item(PopupMenuItem::new(collect_absolute_label).on_click({
                let view = view.clone();
                let selected_targets = selected_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        shell.open_path_collect_dialog(
                            selected_targets.clone(),
                            PathCollectRewriteMode::Absolute,
                            window,
                            cx,
                        );
                    });
                }
            }))
            .item(
                PopupMenuItem::new(collect_workspace_double_slash_relative_label).on_click({
                    let view = view.clone();
                    let selected_targets = selected_targets.clone();
                    move |_, window, cx| {
                        view.update(cx, |shell, cx| {
                            shell.open_path_collect_dialog(
                                selected_targets.clone(),
                                PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
                                window,
                                cx,
                            );
                        });
                    }
                }),
            )
            .item(PopupMenuItem::new(collect_plain_relative_label).on_click({
                let view = view.clone();
                let selected_targets = selected_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        shell.open_path_collect_dialog(
                            selected_targets.clone(),
                            PathCollectRewriteMode::PlainRelative,
                            window,
                            cx,
                        );
                    });
                }
            }))
        } else if path_menu_state.show_disabled_collect_files {
            menu.item(PopupMenuItem::new(collect_absolute_label).disabled(true))
                .item(
                    PopupMenuItem::new(collect_workspace_double_slash_relative_label)
                        .disabled(true),
                )
                .item(PopupMenuItem::new(collect_plain_relative_label).disabled(true))
        } else {
            menu
        };

        let menu = if has_dirty_context_targets || can_delete_owner_targets {
            menu.separator()
        } else {
            menu
        };
        let menu = if has_dirty_context_targets {
            menu.item(PopupMenuItem::new(undo_label).on_click({
                let view = view.clone();
                let edit_targets = edit_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        let undo_targets = shell.context_undo_path_targets(&edit_targets);
                        shell.undo_context_path_targets(undo_targets, window, cx);
                    });
                }
            }))
        } else {
            menu
        };
        if !can_delete_owner_targets {
            return menu;
        }
        menu.item(PopupMenuItem::new(delete_owner_label).on_click({
            let edit_targets = edit_targets.clone();
            move |_, window, cx| {
                view.update(cx, |shell, cx| {
                    let selected_rows = shell.context_delete_owner_rows(&edit_targets);
                    shell.run_delete_selected_path_owner_nodes(selected_rows, window, cx);
                });
            }
        }))
    }
}

fn path_table_value_cell(
    value: String,
    value_style: Option<ScenePathValueStyle>,
    dirty: bool,
    owner_deleted: bool,
    _resolution_badge: Option<PathResolutionBadge>,
    locale: SupportedLocale,
) -> Div {
    let mut cell = path_table_cell(value, value_style, owner_deleted);
    let i18n = I18n::new(locale);
    if dirty {
        cell = cell.child(badge(&i18n.text("label.dirty"), WARN_SOFT, 0x8a6116));
    }
    cell
}

fn path_resolution_badge_indicator(
    badge_kind: Option<PathResolutionBadge>,
) -> Option<impl IntoElement> {
    match badge_kind? {
        PathResolutionBadge::Exists => {
            Some(icon_badge(AppIconName::BadgeCheck, SUCCESS_SOFT, 0x256c2c))
        }
        PathResolutionBadge::Missing => Some(icon_badge(
            AppIconName::FileQuestionMark,
            ERROR_SOFT,
            0x8a3a32,
        )),
        PathResolutionBadge::Unresolved => None,
    }
}
