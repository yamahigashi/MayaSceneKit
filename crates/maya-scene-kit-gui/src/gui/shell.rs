use super::*;
use maya_scene_kit_edit::scene::{MaterializeOptions, OperationMode};

impl GuiShell {
    pub(super) fn new(menu_bar: TopMenuBar, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut state = load_persisted_state().unwrap_or_default();
        state.normalize_ignore_folder_settings();
        state.active_tab = ResultTab::Overview;
        let i18n = I18n::new(state.locale.resolve());
        let search_query = state.search_query.clone();
        let search_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(i18n.text("placeholder.search"))
                .default_value(search_query)
        });
        let path_search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n.text("placeholder.path_search"))
        });
        let audit_search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n.text("placeholder.audit_search"))
        });
        let path_edit_input = cx
            .new(|cx| InputState::new(window, cx).placeholder(i18n.text("placeholder.scene_path")));
        let replace_from_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n.text("placeholder.replace_from"))
        });
        let replace_to_input = cx
            .new(|cx| InputState::new(window, cx).placeholder(i18n.text("placeholder.replace_to")));
        let path_edit_focus_handle = path_edit_input.read(cx).focus_handle(cx);
        let mut next_row_id = 1u64;
        let rows = load_rows_from_state(&state, &mut next_row_id);
        let file_sort = FileTableSort {
            key: FileSortKey::Name,
            direction: ColumnSort::Ascending,
        };
        let path_sort = default_path_sort();
        let audit_sort = default_audit_sort();
        let visible_rows = compute_visible_row_indices_for(&rows, &state, file_sort);
        let table_rows = build_file_table_rows(&rows, &visible_rows, &state, &i18n);
        let file_table = cx.new(|cx| {
            TableState::new(
                FileTableDelegate::new(
                    table_rows,
                    i18n.locale(),
                    file_sort,
                    &state.file_table_column_widths,
                ),
                window,
                cx,
            )
            .col_resizable(true)
            .sortable(true)
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
        });
        let file_table_focus_handle = file_table.read(cx).focus_handle(cx);
        let path_table = cx.new(|cx| {
            TableState::new(
                PathTableDelegate::new(
                    Vec::new(),
                    i18n.locale(),
                    path_sort,
                    false,
                    &state.path_table_column_widths,
                ),
                window,
                cx,
            )
            .col_resizable(true)
            .sortable(true)
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
        });
        let audit_table = cx.new(|cx| {
            TableState::new(
                AuditTableDelegate::new(
                    Vec::new(),
                    i18n.locale(),
                    audit_sort,
                    &state.audit_table_column_widths,
                ),
                window,
                cx,
            )
            .col_resizable(true)
            .sortable(true)
            .col_movable(false)
            .col_selectable(false)
            .row_selectable(false)
        });
        let path_table_focus_handle = path_table.read(cx).focus_handle(cx);
        let view = cx.entity();
        let path_edit_view = view.clone();
        let path_table_view = view.clone();
        let subscriptions = vec![
            cx.subscribe(&search_input, |this: &mut Self, _, ev: &InputEvent, cx| {
                if matches!(ev, InputEvent::Change) {
                    this.apply_search_query(cx);
                }
            }),
            cx.subscribe(
                &path_search_input,
                |this: &mut Self, _, ev: &InputEvent, cx| {
                    if matches!(ev, InputEvent::Change) {
                        this.apply_path_search_query(cx);
                    }
                },
            ),
            cx.subscribe(
                &audit_search_input,
                |this: &mut Self, _, ev: &InputEvent, cx| {
                    if matches!(ev, InputEvent::Change) {
                        this.apply_audit_search_query(cx);
                    }
                },
            ),
            cx.subscribe_in(
                &path_edit_input,
                window,
                |this: &mut Self, _, ev: &InputEvent, window, cx| {
                    if matches!(ev, InputEvent::PressEnter { secondary: false })
                        && matches!(
                            this.path_edit_keyboard_outcome("enter", window, cx),
                            PathEditKeyboardOutcome::Apply
                        )
                    {
                        this.apply_path_edit(window, cx);
                    }
                },
            ),
            cx.subscribe(
                &replace_from_input,
                |this: &mut Self, _, ev: &InputEvent, cx| {
                    if matches!(ev, InputEvent::Change) {
                        this.on_replace_dialog_inputs_changed(cx);
                    }
                },
            ),
            cx.subscribe(
                &replace_to_input,
                |this: &mut Self, _, ev: &InputEvent, cx| {
                    if matches!(ev, InputEvent::Change) {
                        this.on_replace_dialog_inputs_changed(cx);
                    }
                },
            ),
            cx.on_focus_out(
                &path_edit_focus_handle,
                window,
                move |this, _event, window, cx| {
                    if this.active_path_edit.is_none() {
                        return;
                    }
                    let view = path_edit_view.clone();
                    window.defer(cx, move |_window, cx| {
                        view.update(cx, |shell, cx| {
                            if shell.active_path_edit.is_some() {
                                shell.cancel_path_edit_state(cx);
                            }
                        });
                    });
                },
            ),
            cx.on_focus_out(
                &path_table_focus_handle,
                window,
                move |this, _event, window, cx| {
                    if this.active_path_edit.is_some() || this.selected_path_rows.is_empty() {
                        return;
                    }
                    let view = path_table_view.clone();
                    window.defer(cx, move |_window, cx| {
                        view.update(cx, |shell, cx| {
                            if shell.suppress_next_path_focus_out_clear {
                                shell.suppress_next_path_focus_out_clear = false;
                                return;
                            }
                            if shell.active_path_edit.is_none() {
                                shell.selected_path_rows.clear();
                                shell.path_selection_anchor = None;
                                shell.path_table.update(cx, |table, cx| {
                                    table.clear_selection(cx);
                                });
                                shell.refresh_path_table(cx);
                                cx.notify();
                            }
                        });
                    });
                },
            ),
        ];

        Self {
            state,
            rows,
            visible_rows,
            menu_bar,
            focus_handle: cx.focus_handle(),
            search_input,
            path_search_input,
            audit_search_input,
            path_edit_input,
            replace_from_input,
            replace_to_input,
            file_table,
            file_table_focus_handle,
            path_table,
            audit_table,
            audit_all_rows: Vec::new(),
            audit_rows: Vec::new(),
            file_sort,
            path_sort,
            path_order_snapshot: None,
            audit_sort,
            next_row_id,
            selection_anchor: None,
            selected_auto_analyze_generation: 0,
            workspace_auto_analyze_generation: 0,
            file_dialog_block_generation: 0,
            auto_analyze_queue: AutoAnalyzeQueueState::default(),
            file_dialog_ui_blocked: false,
            save_jobs_in_flight: 0,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            next_edit_history_sequence: 0,
            next_edit_history_commit_sequence: 0,
            pending_edit_transactions: BTreeMap::new(),
            completed_edit_history: BTreeMap::new(),
            workspace_auto_analyze_started_at: None,
            active_path_edit: None,
            selected_path_rows: BTreeSet::new(),
            path_selection_anchor: None,
            suppress_next_path_focus_out_clear: false,
            path_table_dedup: false,
            path_dirty_only: false,
            path_search_query: String::new(),
            audit_table_dedup: false,
            audit_dirty_only: false,
            audit_search_query: String::new(),
            selected_audit_keys: BTreeSet::new(),
            audit_selection_anchor: None,
            path_type_filter: default_path_type_filter(),
            path_form_filter: default_path_form_filter(),
            path_resolution_filter: default_path_resolution_filter(),
            audit_severity_filter: default_audit_severity_filter(),
            audit_detail_dialog: None,
            status_message: None,
            max_bytes_dialog: None,
            ignore_folder_names_dialog: None,
            replace_dialog: None,
            path_collect_dialog: None,
            _subscriptions: subscriptions,
        }
    }

    pub(super) fn bind_file_table(&mut self, view: Entity<Self>, cx: &mut Context<Self>) {
        let file_table_focus_handle = self.file_table_focus_handle.clone();
        self.file_table.update(cx, |table, cx| {
            table.delegate_mut().set_view(view.clone());
            table
                .delegate_mut()
                .set_focus_handle(file_table_focus_handle.clone());
            table.refresh(cx);
        });
        self.path_table.update(cx, |table, cx| {
            table.delegate_mut().set_view(view.clone());
            table.refresh(cx);
        });
        self.audit_table.update(cx, |table, cx| {
            table.delegate_mut().set_view(view);
            table.refresh(cx);
        });
    }

    pub(super) fn locale(&self) -> SupportedLocale {
        self.state.locale.resolve()
    }

    pub(super) fn i18n(&self) -> I18n {
        I18n::new(self.locale())
    }

    pub(super) fn scene_load_options(&self) -> LoadOptions {
        let mut options = LoadOptions::default();
        if let Some(max_bytes) = self.state.max_bytes {
            options = options.with_max_parse_bytes(max_bytes);
        }
        options
    }

    pub(super) fn scene_materialize_options(&self, mode: OperationMode) -> MaterializeOptions {
        MaterializeOptions::new(self.scene_load_options()).with_operation_mode(mode)
    }

    pub(super) fn backup_location_label(&self, i18n: &I18n) -> String {
        backup_location_label(i18n, self.state.backup_location)
    }
}
