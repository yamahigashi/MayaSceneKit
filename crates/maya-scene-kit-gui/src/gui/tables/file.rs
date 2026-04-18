use std::ops::Range;

use gpui_component::menu::PopupMenu;

use super::*;

impl FileTableDelegate {
    pub(in crate::gui) fn new(
        rows: Vec<FileTableRow>,
        locale: SupportedLocale,
        sort: FileTableSort,
        persisted_widths: &[PersistedTableColumnWidth],
    ) -> Self {
        let mut this = Self {
            view: None,
            focus_handle: None,
            locale,
            rows,
            columns: vec![
                Column::new("marker", "").width(px(40.0)).resizable(false),
                Column::new("name", "Name")
                    .width(px(620.0))
                    .fixed_left()
                    .sort(if sort.key == FileSortKey::Name {
                        sort.direction
                    } else {
                        ColumnSort::Default
                    }),
                Column::new("status", "Status").width(px(170.0)).sortable(),
                Column::new("findings", "Findings")
                    .width(px(96.0))
                    .sortable(),
                Column::new("missing", "Missing").width(px(96.0)).sortable(),
                Column::new("workspace", "Workspace")
                    .width(px(110.0))
                    .resizable(true)
                    .sort(if sort.key == FileSortKey::Workspace {
                        sort.direction
                    } else {
                        ColumnSort::Default
                    }),
                Column::new("size", "Size").width(px(120.0)).sortable(),
                Column::new("modified", "Modified").width(px(190.0)).sort(
                    if sort.key == FileSortKey::Modified {
                        sort.direction
                    } else {
                        ColumnSort::Default
                    },
                ),
            ],
        };
        this.columns = apply_persisted_column_widths(this.columns, persisted_widths);
        update_file_sort_columns(&mut this.columns, sort);
        this
    }

    pub(in crate::gui) fn set_view(&mut self, view: Entity<GuiShell>) {
        self.view = Some(view);
    }

    pub(in crate::gui) fn set_focus_handle(&mut self, focus_handle: FocusHandle) {
        self.focus_handle = Some(focus_handle);
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
        rows: Vec<FileTableRow>,
        locale: SupportedLocale,
        sort: FileTableSort,
    ) {
        self.rows = rows;
        self.locale = locale;
        update_file_sort_columns(&mut self.columns, sort);
    }

    pub(in crate::gui) fn replace_row(
        &mut self,
        row_ix: usize,
        row: FileTableRow,
        locale: SupportedLocale,
        sort: FileTableSort,
    ) {
        let Some(existing) = self.rows.get_mut(row_ix) else {
            return;
        };
        *existing = row;
        self.locale = locale;
        update_file_sort_columns(&mut self.columns, sort);
    }

    pub(super) fn update_sort_columns(&mut self, active_col_ix: usize, sort: ColumnSort) {
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

fn update_file_sort_columns(columns: &mut [Column], sort: FileTableSort) {
    let active_col_ix = match sort.key {
        FileSortKey::Name => 1,
        FileSortKey::Status => 2,
        FileSortKey::Findings => 3,
        FileSortKey::Missing => 4,
        FileSortKey::Workspace => 5,
        FileSortKey::Size => 6,
        FileSortKey::Modified => 7,
    };
    for (col_ix, column) in columns.iter_mut().enumerate() {
        if column.sort.is_none() {
            continue;
        }
        if col_ix == active_col_ix {
            column.sort = Some(sort.direction);
        } else {
            column.sort = Some(ColumnSort::Default);
        }
    }
}

impl TableDelegate for FileTableDelegate {
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
        let Some(key) = file_sort_key_for_col_ix(col_ix) else {
            return;
        };
        let sort = match sort {
            ColumnSort::Default => ColumnSort::Ascending,
            other => other,
        };
        self.update_sort_columns(col_ix, sort);
        if let Some(view) = self.view.clone() {
            cx.defer(move |cx| {
                view.update(cx, |shell, cx| shell.set_file_sort(key, sort, cx));
            });
        }
    }

    fn visible_rows_changed(
        &mut self,
        visible_range: Range<usize>,
        window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        let Some(view) = self.view.clone() else {
            return;
        };
        let visible_range_for_update = visible_range.clone();
        window.defer(cx, move |window, cx| {
            view.update(cx, |shell, cx| {
                shell.update_file_table_viewport_range(
                    visible_range_for_update.clone(),
                    window,
                    cx,
                );
            });
        });
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let row = &self.rows[row_ix];
        let focus_handle = self.focus_handle.clone();
        let mut tr = div()
            .id(("row", row_ix))
            .bg(rgb(if row.selected { ACCENT_SOFT } else { row.tone }))
            .when(row.is_processing, |this| this.text_color(rgb(MUTED)));

        if let Some(view) = self.view.clone() {
            let row_id = row.id;
            tr = tr
                .on_mouse_down(MouseButton::Left, |_, _, cx| {
                    cx.stop_propagation();
                })
                .on_mouse_up(MouseButton::Left, move |event, window, cx| {
                    cx.stop_propagation();
                    view.update(cx, |shell, cx| {
                        shell.select_row_by_id(row_id, event.modifiers, window, cx);
                        cx.notify();
                    });
                    if let Some(focus_handle) = focus_handle.as_ref() {
                        focus_handle.focus(window);
                    }
                });
        }

        tr
    }

    fn render_th(
        &mut self,
        col_ix: usize,
        _: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let i18n = I18n::new(self.locale);
        let focus_handle = self.focus_handle.clone();
        let label = match col_ix {
            0 => String::new(),
            1 => i18n.text("table.name"),
            2 => i18n.text("table.status"),
            3 => i18n.text("table.file_list_findings"),
            4 => i18n.text("table.missing"),
            5 => i18n.text("table.workspace"),
            6 => i18n.text("table.size"),
            7 => i18n.text("table.modified"),
            _ => String::new(),
        };
        let cell = div()
            .size_full()
            .flex()
            .items_center()
            .min_w_0()
            .text_sm()
            .text_color(rgb(MUTED))
            .child(div().min_w_0().truncate().child(label));
        let Some(key) = file_sort_key_for_col_ix(col_ix) else {
            return cell.into_any_element();
        };
        let Some(view) = self.view.clone() else {
            return cell.into_any_element();
        };
        cell.cursor_pointer()
            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .on_mouse_up(MouseButton::Left, move |_, window, cx| {
                cx.stop_propagation();
                view.update(cx, |shell, cx| {
                    let sort = next_file_sort_for_col_ix(col_ix, shell.file_sort);
                    shell.set_file_sort(key, sort, cx);
                    cx.notify();
                });
                if let Some(focus_handle) = focus_handle.as_ref() {
                    focus_handle.focus(window);
                }
            })
            .into_any_element()
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let row = self.rows[row_ix].clone();
        let view = self.view.clone();
        let focus_handle = self.focus_handle.clone();
        let mut cell = file_table_cell_container();

        cell = match col_ix {
            0 => {
                if row.is_processing {
                    cell.child(
                        div().w_full().flex().justify_center().child(
                            Spinner::new()
                                .with_size(gpui_component::Size::Small)
                                .color(rgb(MUTED).into()),
                        ),
                    )
                } else {
                    cell.child(badge(
                        if row.selected { "●" } else { "○" },
                        PANEL_BG,
                        ACCENT,
                    ))
                }
            }
            1 => cell.child(file_table_text_cell(row.name)),
            2 => cell.child(file_table_text_cell(row.status)),
            3 => cell.child(file_table_text_cell(row.findings)),
            4 => cell.child(file_table_text_cell(row.missing)),
            5 => {
                if row.has_scene_workspace {
                    cell.child(
                        div()
                            .w_full()
                            .flex()
                            .justify_center()
                            .text_sm()
                            .text_color(rgb(0x256c2c))
                            .child("✓"),
                    )
                } else {
                    cell.child(String::new())
                }
            }
            6 => cell.child(file_table_text_cell(row.size)),
            7 => cell.child(file_table_muted_text_cell(row.modified)),
            _ => cell.child(String::new()),
        };

        if let Some(view) = view {
            let select_view = view.clone();
            cell.on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .on_mouse_up(MouseButton::Left, move |event, window, cx| {
                cx.stop_propagation();
                select_view.update(cx, |shell, cx| {
                    shell.select_row_by_id(row.id, event.modifiers, window, cx);
                    cx.notify();
                });
                if let Some(focus_handle) = focus_handle.as_ref() {
                    focus_handle.focus(window);
                }
            })
            .into_any_element()
        } else {
            cell.into_any_element()
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
        if !row.selected {
            let view = view.clone();
            let row_id = row.id;
            window.defer(cx, move |window, cx| {
                view.update(cx, |shell, cx| {
                    shell.select_row_by_id(row_id, Modifiers::default(), window, cx);
                    cx.notify();
                });
            });
        }

        let i18n = I18n::new(self.locale);
        let copy_label = i18n.text("action.copy_path");
        let clean_label = i18n.text("action.clean_file_context");
        let replace_label = i18n.text("action.replace_path");
        let save_label = i18n.text("action.save");
        let undo_label = i18n.text("action.undo_all_changes");
        let menu = menu.item(PopupMenuItem::new(copy_label).on_click({
            let view = view.clone();
            let row_id = row.id;
            move |_, _, cx| {
                let Some(copied_path) = build_file_copy_payload(&view.read(cx).rows, row_id) else {
                    return;
                };
                cx.write_to_clipboard(ClipboardItem::new_string(copied_path));
            }
        }));
        let menu = menu.item(PopupMenuItem::new(clean_label).on_click({
            let view = view.clone();
            move |_, window, cx| {
                view.update(cx, |shell, cx| {
                    shell.run_file_context_clean(window, cx);
                });
            }
        }));
        let menu = menu.item(PopupMenuItem::new(replace_label).on_click({
            let view = view.clone();
            move |_, window, cx| {
                view.update(cx, |shell, cx| {
                    shell.run_replace(window, cx);
                });
            }
        }));
        if !row.dirty {
            return menu;
        }

        menu.item(PopupMenuItem::new(save_label).on_click({
            let view = view.clone();
            move |_, window, cx| {
                view.update(cx, |shell, cx| {
                    shell.run_context_save_from_row(row.id, window, cx);
                });
            }
        }))
        .item(
            PopupMenuItem::new(undo_label).on_click(move |_, window, cx| {
                view.update(cx, |shell, cx| {
                    let row_ids = if shell
                        .index_of_row_id(row.id)
                        .and_then(|row_index| shell.rows.get(row_index))
                        .is_some_and(|selected_row| selected_row.selected)
                    {
                        shell
                            .selected_ready_dirty_indices()
                            .into_iter()
                            .filter_map(|row_index| shell.rows.get(row_index).map(|row| row.id))
                            .collect::<Vec<_>>()
                    } else {
                        vec![row.id]
                    };
                    shell.undo_row_changes_for_ids(row_ids, window, cx);
                });
            }),
        )
    }
}
