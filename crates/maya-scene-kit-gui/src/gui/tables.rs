use gpui_component::menu::PopupMenu;

use super::{
    path_edit::{
        absolute_override_value_for_entry, path_collect_supported_for_edit_targets,
        path_edit_targets_id, path_owner_delete_supported_for_edit_targets,
        resolved_target_file_paths_for_edit_targets, workspace_relative_override_value_for_entry,
    },
    *,
};

const WORKSPACE_PATH_PREFIX_MUTED: u32 = 0xa3a19e;

impl FileTableDelegate {
    pub(super) fn new(
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

    pub(super) fn set_view(&mut self, view: Entity<GuiShell>) {
        self.view = Some(view);
    }

    pub(super) fn set_focus_handle(&mut self, focus_handle: FocusHandle) {
        self.focus_handle = Some(focus_handle);
    }

    pub(super) fn apply_widths(&mut self, widths: &[Pixels]) {
        for (column, width) in self.columns.iter_mut().zip(widths.iter().copied()) {
            column.width = width;
        }
    }

    pub(super) fn persisted_column_widths(&self) -> Vec<PersistedTableColumnWidth> {
        persisted_column_widths(&self.columns)
    }

    pub(super) fn sync(
        &mut self,
        rows: Vec<FileTableRow>,
        locale: SupportedLocale,
        sort: FileTableSort,
    ) {
        self.rows = rows;
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

impl AuditTableDelegate {
    pub(super) fn new(
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

    pub(super) fn set_view(&mut self, view: Entity<GuiShell>) {
        self.view = Some(view);
    }

    pub(super) fn apply_widths(&mut self, widths: &[Pixels]) {
        for (column, width) in self.columns.iter_mut().zip(widths.iter().copied()) {
            column.width = width;
        }
    }

    pub(super) fn persisted_column_widths(&self) -> Vec<PersistedTableColumnWidth> {
        persisted_column_widths(&self.columns)
    }

    pub(super) fn sync(
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AuditContextMenuState {
    pub can_clean: bool,
    pub can_undo: bool,
    pub show_disabled_clean: bool,
}

pub(super) fn audit_context_menu_state(rows: &[AuditTableRow]) -> AuditContextMenuState {
    let can_clean = rows
        .iter()
        .any(|entry| entry.clean_state == AuditRowCleanState::Available);
    let can_undo = rows
        .iter()
        .any(|entry| entry.clean_state == AuditRowCleanState::Staged);
    let show_disabled_clean = !can_clean
        && rows
            .iter()
            .any(|entry| entry.clean_state == AuditRowCleanState::BlockedByOtherDirty);

    AuditContextMenuState {
        can_clean,
        can_undo,
        show_disabled_clean,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PathContextMenuState {
    pub can_convert_to_absolute: bool,
    pub show_disabled_convert_to_absolute: bool,
    pub can_convert_to_workspace_double_slash_relative: bool,
    pub show_disabled_convert_to_workspace_double_slash_relative: bool,
    pub can_convert_to_plain_relative: bool,
    pub show_disabled_convert_to_plain_relative: bool,
    pub can_collect_files: bool,
    pub show_disabled_collect_files: bool,
}

pub(super) fn path_context_menu_state(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> PathContextMenuState {
    let has_workspace_double_slash_relative_target =
        edit_targets.iter().any(|(row_id, entry_index)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .and_then(|row| {
                    workspace_relative_override_value_for_entry(
                        row,
                        *entry_index,
                        PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
                    )
                })
                .is_some()
        });
    let has_plain_relative_target = edit_targets.iter().any(|(row_id, entry_index)| {
        rows.iter()
            .find(|row| row.id == *row_id)
            .and_then(|row| {
                workspace_relative_override_value_for_entry(
                    row,
                    *entry_index,
                    PathCollectRewriteMode::PlainRelative,
                )
            })
            .is_some()
    });
    let has_absolute_target = edit_targets.iter().any(|(row_id, entry_index)| {
        rows.iter()
            .find(|row| row.id == *row_id)
            .and_then(|row| absolute_override_value_for_entry(row, *entry_index))
            .is_some()
    });
    let has_collectable_file_target = edit_targets.iter().any(|(row_id, entry_index)| {
        rows.iter()
            .find(|row| row.id == *row_id)
            .and_then(|row| {
                super::path_edit::resolved_target_file_path_for_entry(row, *entry_index)
            })
            .is_some()
    });
    let can_edit_path_values =
        super::path_edit::path_value_edit_supported_for_edit_targets(rows, edit_targets);
    let can_collect_files = path_collect_supported_for_edit_targets(rows, edit_targets);

    PathContextMenuState {
        can_convert_to_absolute: has_absolute_target && can_edit_path_values,
        show_disabled_convert_to_absolute: has_absolute_target && !can_edit_path_values,
        can_convert_to_workspace_double_slash_relative: has_workspace_double_slash_relative_target
            && can_edit_path_values,
        show_disabled_convert_to_workspace_double_slash_relative:
            has_workspace_double_slash_relative_target && !can_edit_path_values,
        can_convert_to_plain_relative: has_plain_relative_target && can_edit_path_values,
        show_disabled_convert_to_plain_relative: has_plain_relative_target && !can_edit_path_values,
        can_collect_files,
        show_disabled_collect_files: has_collectable_file_target && !can_collect_files,
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
                    shell.run_clean(window, cx);
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

impl PathTableDelegate {
    pub(super) fn new(
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

    pub(super) fn set_view(&mut self, view: Entity<GuiShell>) {
        self.view = Some(view);
    }

    pub(super) fn apply_widths(&mut self, widths: &[Pixels]) {
        for (column, width) in self.columns.iter_mut().zip(widths.iter().copied()) {
            column.width = width;
        }
    }

    pub(super) fn persisted_column_widths(&self) -> Vec<PersistedTableColumnWidth> {
        persisted_column_widths(&self.columns)
    }

    pub(super) fn sync(
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
        let collect_workspace_double_slash_relative_label =
            I18n::new(self.locale).text("action.collect_files_to_workspace_double_slash_relative");
        let collect_plain_relative_label =
            I18n::new(self.locale).text("action.collect_files_to_plain_relative");
        let replace_label = I18n::new(self.locale).text("action.replace_path");
        let undo_label = I18n::new(self.locale).text("action.discard_changes");
        let delete_owner_label = I18n::new(self.locale).text("action.delete_owner_nodes");
        let edit_targets = row.edit_targets.clone();
        let menu = menu.item(PopupMenuItem::new(copy_label).on_click({
            let copied_path = row.value.clone();
            move |_, _, cx| {
                cx.write_to_clipboard(ClipboardItem::new_string(copied_path.clone()));
            }
        }));
        let menu = menu.item(PopupMenuItem::new(replace_label).on_click({
            let view = view.clone();
            let edit_targets = edit_targets.clone();
            move |_, window, cx| {
                view.update(cx, |shell, cx| {
                    let selected_targets = shell.context_path_targets(&edit_targets);
                    shell.open_replace_dialog_for_path_targets(selected_targets, window, cx);
                });
            }
        }));
        if edit_targets.is_empty() {
            return menu;
        }
        let selected_targets =
            view.update(cx, |shell, _| shell.context_path_targets(&edit_targets));
        let has_copyable_file = view.update(cx, |shell, _| {
            !resolved_target_file_paths_for_edit_targets(&shell.rows, &edit_targets).is_empty()
        });
        let path_menu_state = view.update(cx, |shell, _| {
            path_context_menu_state(&shell.rows, &selected_targets)
        });
        let can_delete_owner_targets = row.owner_deletable
            && view.update(cx, |shell, _| {
                path_owner_delete_supported_for_edit_targets(&shell.rows, &selected_targets)
            });
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
        if !row.dirty {
            if !can_delete_owner_targets {
                return menu;
            }
            return menu.item(PopupMenuItem::new(delete_owner_label).on_click({
                let view = view.clone();
                let edit_targets = edit_targets.clone();
                move |_, window, cx| {
                    view.update(cx, |shell, cx| {
                        let selected_rows = if shell.selected_path_rows.contains(&edit_targets) {
                            shell.selected_path_rows.iter().cloned().collect::<Vec<_>>()
                        } else {
                            vec![edit_targets.clone()]
                        };
                        shell.run_delete_selected_path_owner_nodes(selected_rows, window, cx);
                    });
                }
            }));
        }

        let menu = menu.item(PopupMenuItem::new(undo_label).on_click({
            let view = view.clone();
            let edit_targets = edit_targets.clone();
            move |_, window, cx| {
                view.update(cx, |shell, cx| {
                    let undo_targets = shell.context_undo_path_targets(&edit_targets);
                    shell.undo_context_path_targets(undo_targets, window, cx);
                });
            }
        }));
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

pub(super) fn path_table_columns(show_scene_column: bool, sort: PathTableSort) -> Vec<Column> {
    let mut columns = Vec::new();
    columns.push(
        Column::new("kind", "")
            .width(px(88.0))
            .resizable(false)
            .sortable(),
    );
    if show_scene_column {
        columns.push(
            Column::new("scene", "Scene")
                .width(px(300.0))
                .resizable(true)
                .sortable()
                .sort(if sort.key == PathSortKey::Scene {
                    sort.direction
                } else {
                    ColumnSort::Default
                }),
        );
    }
    columns.push(
        Column::new("node", "Node")
            .width(px(220.0))
            .resizable(true)
            .sortable()
            .sort(if sort.key == PathSortKey::Node {
                sort.direction
            } else {
                ColumnSort::Default
            }),
    );
    columns.push(
        Column::new("path", "Path")
            .width(px(700.0))
            .resizable(true)
            .sortable()
            .sort(if sort.key == PathSortKey::Path {
                sort.direction
            } else {
                ColumnSort::Default
            }),
    );
    columns
}

pub(super) fn merge_column_widths(existing: &[Column], mut next: Vec<Column>) -> Vec<Column> {
    let widths_by_key = existing
        .iter()
        .map(|column| (column.key.clone(), column.width))
        .collect::<BTreeMap<_, _>>();
    for column in &mut next {
        if let Some(width) = widths_by_key.get(&column.key) {
            column.width = *width;
        }
    }
    next
}

pub(super) fn apply_persisted_column_widths(
    mut columns: Vec<Column>,
    persisted_widths: &[PersistedTableColumnWidth],
) -> Vec<Column> {
    let widths_by_key = persisted_widths
        .iter()
        .map(|width| (width.key.as_str(), px(width.width_px as f32)))
        .collect::<BTreeMap<_, _>>();
    for column in &mut columns {
        if let Some(width) = widths_by_key.get(column.key.as_ref()) {
            column.width = *width;
        }
    }
    columns
}

pub(super) fn persisted_column_widths(columns: &[Column]) -> Vec<PersistedTableColumnWidth> {
    columns
        .iter()
        .map(|column| PersistedTableColumnWidth {
            key: column.key.to_string(),
            width_px: u32::from(column.width),
        })
        .collect()
}

pub(super) fn update_path_sort_columns(
    columns: &mut [Column],
    show_scene_column: bool,
    sort: PathTableSort,
) {
    for (col_ix, column) in columns.iter_mut().enumerate() {
        let Some(key) = path_sort_key_for_col_ix(col_ix, show_scene_column) else {
            continue;
        };
        if column.sort.is_some() {
            column.sort = Some(if key == sort.key {
                sort.direction
            } else {
                ColumnSort::Default
            });
        }
    }
}

pub(super) fn file_table_cell_container() -> Div {
    div().size_full().flex().items_center().min_w_0()
}

pub(super) fn audit_table_columns(locale: SupportedLocale, sort: AuditTableSort) -> Vec<Column> {
    let i18n = I18n::new(locale);
    vec![
        Column::new("scene", i18n.text("table.scene"))
            .width(px(220.0))
            .sort(if sort.key == AuditSortKey::Scene {
                sort.direction
            } else {
                ColumnSort::Default
            }),
        Column::new("severity", i18n.text("table.severity"))
            .width(px(130.0))
            .sort(if sort.key == AuditSortKey::Severity {
                sort.direction
            } else {
                ColumnSort::Default
            }),
        Column::new("summary", i18n.text("table.summary"))
            .width(px(560.0))
            .sort(if sort.key == AuditSortKey::Summary {
                sort.direction
            } else {
                ColumnSort::Default
            }),
        Column::new("code", i18n.text("table.code"))
            .width(px(160.0))
            .sort(if sort.key == AuditSortKey::Code {
                sort.direction
            } else {
                ColumnSort::Default
            }),
        Column::new("sink", i18n.text("table.sink"))
            .width(px(160.0))
            .sort(if sort.key == AuditSortKey::Sink {
                sort.direction
            } else {
                ColumnSort::Default
            }),
    ]
}

pub(super) fn audit_table_text_cell(text: String) -> Div {
    file_table_text_cell(text)
}

pub(super) fn audit_table_muted_text_cell(text: String) -> Div {
    file_table_text_cell(text).text_color(rgb(MUTED))
}

pub(super) fn file_table_text_cell(text: String) -> Div {
    div()
        .flex_1()
        .min_w_0()
        .text_sm()
        .overflow_hidden()
        .whitespace_nowrap()
        .truncate()
        .child(text)
}

pub(super) fn file_table_muted_text_cell(text: String) -> Div {
    file_table_text_cell(text).text_color(rgb(MUTED))
}

pub(super) fn path_table_cell(
    text: String,
    value_style: Option<ScenePathValueStyle>,
    owner_deleted: bool,
) -> Div {
    div()
        .size_full()
        .flex()
        .items_center()
        .min_w_0()
        .child(path_table_text(text, value_style, owner_deleted))
}

pub(super) fn path_table_text(
    text: String,
    value_style: Option<ScenePathValueStyle>,
    owner_deleted: bool,
) -> Div {
    let highlights = path_text_highlights(&text, value_style, owner_deleted);
    div()
        .flex_1()
        .min_w_0()
        .text_sm()
        .when(owner_deleted, |this| this.text_color(rgb(MUTED)))
        .overflow_hidden()
        .whitespace_nowrap()
        .truncate()
        .child(
            StyledText::new(text).when_some(highlights, |this, highlights| {
                this.with_highlights(highlights)
            }),
        )
}

pub(super) fn path_text_highlights(
    text: &str,
    value_style: Option<ScenePathValueStyle>,
    owner_deleted: bool,
) -> Option<Vec<(std::ops::Range<usize>, HighlightStyle)>> {
    let workspace_highlights = workspace_prefix_highlights(text, value_style);
    let owner_deleted_highlights = owner_deleted.then(|| {
        vec![(
            0..text.len(),
            HighlightStyle {
                strikethrough: Some(StrikethroughStyle {
                    thickness: px(1.0),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]
    });
    match (workspace_highlights, owner_deleted_highlights) {
        (None, None) => None,
        (Some(highlights), None) | (None, Some(highlights)) => Some(highlights),
        (Some(base), Some(overlay)) => Some(gpui::combine_highlights(base, overlay).collect()),
    }
}

fn workspace_prefix_highlights(
    text: &str,
    value_style: Option<ScenePathValueStyle>,
) -> Option<Vec<(std::ops::Range<usize>, HighlightStyle)>> {
    if value_style != Some(ScenePathValueStyle::DoubleSlashWorkspaceRelative) {
        return None;
    }
    let (prefix, _suffix) = text.split_once("//")?;
    if prefix.is_empty() {
        return None;
    }
    let separator_start = prefix.len();
    let separator_end = separator_start + 2;
    Some(vec![
        (
            0..prefix.len(),
            HighlightStyle {
                color: Some(rgb(WORKSPACE_PATH_PREFIX_MUTED).into()),
                ..Default::default()
            },
        ),
        (
            separator_start..separator_end,
            HighlightStyle {
                font_weight: Some(FontWeight::BOLD),
                ..Default::default()
            },
        ),
    ])
}
