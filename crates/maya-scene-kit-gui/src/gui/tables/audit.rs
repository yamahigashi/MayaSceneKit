use gpui_component::menu::PopupMenu;

use super::*;

impl AuditTableDelegate {
    pub(in crate::gui) fn new(
        rows: Vec<AuditTableRow>,
        locale: SupportedLocale,
        sort: AuditTableSort,
        persisted_widths: &[PersistedTableColumnWidth],
    ) -> Self {
        Self {
            view: None,
            locale,
            rows,
            sort,
            columns: apply_persisted_column_widths(
                audit_table_columns(locale, sort),
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
        rows: Vec<AuditTableRow>,
        locale: SupportedLocale,
        sort: AuditTableSort,
    ) {
        self.rows = rows;
        self.locale = locale;
        self.sort = sort;
        self.columns = merge_column_widths(&self.columns, audit_table_columns(locale, sort));
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

impl TableDelegate for AuditTableDelegate {
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
        let Some(key) = audit_sort_key_for_col_ix(col_ix) else {
            return;
        };
        let sort = match sort {
            ColumnSort::Default => ColumnSort::Ascending,
            other => other,
        };
        self.update_sort_columns(col_ix, sort);
        if let Some(view) = self.view.clone() {
            cx.defer(move |cx| {
                view.update(cx, |shell, cx| shell.set_audit_sort(key, sort, cx));
            });
        }
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let row = &self.rows[row_ix];
        let row_bg = if row.selected {
            ACCENT_SOFT
        } else if row.clean_state == AuditRowCleanState::Staged {
            WARN_SOFT
        } else {
            PANEL_ALT_BG
        };
        let mut tr = div()
            .id(("audit-row", row_ix))
            .bg(rgb(row_bg))
            .when(row.clean_state == AuditRowCleanState::Staged, |this| {
                this.opacity(0.72)
            });

        if let Some(view) = self.view.clone() {
            let key = row.key.clone();
            tr = tr
                .on_mouse_down(MouseButton::Left, |_, _, cx| {
                    cx.stop_propagation();
                })
                .on_mouse_up(MouseButton::Left, move |event, _, cx| {
                    cx.stop_propagation();
                    view.update(cx, |shell, cx| {
                        shell.select_audit_row_by_key(key.clone(), event.modifiers, cx);
                    });
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
        let label = match col_ix {
            0 => i18n.text("table.scene"),
            1 => i18n.text("table.severity"),
            2 => i18n.text("table.summary"),
            3 => i18n.text("table.code"),
            4 => i18n.text("table.sink"),
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
        let Some(key) = audit_sort_key_for_col_ix(col_ix) else {
            return cell.into_any_element();
        };
        let Some(view) = self.view.clone() else {
            return cell.into_any_element();
        };
        cell.cursor_pointer()
            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .on_mouse_up(MouseButton::Left, move |_, _, cx| {
                cx.stop_propagation();
                view.update(cx, |shell, cx| {
                    let sort = next_audit_sort_for_col_ix(col_ix, shell.audit_sort);
                    shell.set_audit_sort(key, sort, cx);
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
        _cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let row = self.rows[row_ix].clone();
        let view = self.view.clone();
        let (badge_bg, badge_fg) = {
            let (_, badge_bg, badge_fg) = audit_severity_colors(row.severity);
            (badge_bg, badge_fg)
        };

        match col_ix {
            0 => audit_table_text_cell(row.scene_name).into_any_element(),
            1 => file_table_cell_container()
                .child(badge(
                    &severity_label(&I18n::new(self.locale), row.severity),
                    badge_bg,
                    badge_fg,
                ))
                .into_any_element(),
            2 => {
                let mut content = div()
                    .size_full()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(file_table_text_cell(row.summary.clone()));
                if row.dirty {
                    content = content.child(badge(
                        &I18n::new(self.locale).text("label.dirty"),
                        WARN_SOFT,
                        0x8a6116,
                    ));
                }
                let Some(view) = view else {
                    return content.into_any_element();
                };
                let detail_button = div()
                    .flex_none()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| {
                        cx.stop_propagation();
                    })
                    .on_mouse_up(MouseButton::Left, |_, _, cx| {
                        cx.stop_propagation();
                    })
                    .child(action_button(
                        format!(
                            "audit-detail-{}-{:?}-{}",
                            row.key.row_id, row.key.item_kind, row.key.item_index
                        ),
                        I18n::new(self.locale).text("action.detail"),
                        true,
                        move |shell, window, cx| {
                            shell.open_audit_detail_dialog(row.key.clone(), window, cx);
                        },
                        view,
                    ));
                content.child(detail_button).into_any_element()
            }
            3 => audit_table_muted_text_cell(row.code).into_any_element(),
            4 => audit_table_muted_text_cell(row.sink).into_any_element(),
            _ => audit_table_text_cell(String::new()).into_any_element(),
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
            let key = row.key.clone();
            let view = view.clone();
            window.defer(cx, move |_, cx| {
                view.update(cx, |shell, cx| {
                    shell.replace_audit_selection(key.clone(), cx);
                });
            });
        }
        let i18n = I18n::new(self.locale);
        let copy_label = i18n.text("action.copy_source_text");
        let clean_label = i18n.text("action.clean_audit_context");
        let undo_label = i18n.text("action.discard_changes");
        let row_key = row.key.clone();
        let action_rows = if row.selected {
            self.rows
                .iter()
                .filter(|entry| entry.selected)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            vec![row.clone()]
        };
        let menu = menu.item(PopupMenuItem::new(copy_label).on_click({
            let view = view.clone();
            move |_, _, cx| {
                let Some(payload) =
                    resolve_audit_clipboard_payload(&view.read(cx).audit_rows, &row_key)
                else {
                    return;
                };
                cx.write_to_clipboard(ClipboardItem::new_string(payload));
            }
        }));
        let mut menu = menu;
        let clean_state = audit_context_menu_state(&action_rows);
        if clean_state.can_clean {
            menu = menu.item(PopupMenuItem::new(clean_label).on_click({
                let view = view.clone();
                let action_rows = action_rows.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        shell.run_audit_table_clean(action_rows.clone(), window, cx);
                    });
                }
            }));
        } else if clean_state.show_disabled_clean {
            menu = menu.item(PopupMenuItem::new(clean_label).disabled(true));
        }
        if clean_state.can_undo {
            menu = menu.item(PopupMenuItem::new(undo_label).on_click({
                let view = view.clone();
                let action_rows = action_rows.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        shell.undo_audit_table_clean(action_rows.clone(), window, cx);
                    });
                }
            }));
        }
        menu
    }
}
