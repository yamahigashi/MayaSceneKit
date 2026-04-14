use super::*;

impl GuiShell {
    pub(super) fn render_file_table(&self, view: Entity<Self>) -> impl IntoElement {
        let i18n = self.i18n();
        section_panel()
            .size_full()
            .flex_1()
            .min_w_0()
            .overflow_hidden()
            .child(file_panel_header(
                &i18n,
                &self.workspace_caption(&i18n),
                &self.search_input,
                self.state.file_list_findings_only,
                self.state.file_list_missing_only,
                self.state.workspace_auto_analyze,
                view.clone(),
            ))
            .child(
                div().flex_1().min_h_0().child(
                    div()
                        .key_context(FILE_TABLE_CONTEXT)
                        .track_focus(&self.file_table_focus_handle)
                        .size_full()
                        .child(Table::new(&self.file_table).scrollbar_visible(true, false)),
                ),
            )
    }

    pub(super) fn render_result_panel(&self, view: Entity<Self>) -> impl IntoElement {
        let i18n = self.i18n();
        let active_ix = tab_index(self.state.active_tab);
        let tab_view = view.clone();
        section_panel()
            .size_full()
            .flex_1()
            .min_w_0()
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .min_w_0()
                    .child(
                        TabBar::new("result-tabs")
                            .underline()
                            .selected_index(active_ix)
                            .on_click(move |ix, _window, cx| {
                                tab_view.update(cx, |shell, cx| {
                                    shell.set_tab(result_tab_for_index(*ix), cx);
                                    cx.notify();
                                });
                            })
                            .children([
                                Tab::new().label(i18n.text("tab.overview")),
                                Tab::new().label(i18n.text("tab.audit")),
                                Tab::new().label(i18n.text("tab.paths")),
                                Tab::new().label(i18n.text("tab.log")),
                            ]),
                    )
                    .when(self.state.active_tab == ResultTab::Audit, |this| {
                        this.child(render_audit_filter_bar(self, &i18n, view.clone()))
                    })
                    .when(self.state.active_tab == ResultTab::Paths, |this| {
                        this.child(render_paths_filter_bar(self, &i18n, view.clone()))
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .overflow_hidden()
                    .child(result_content(self, &i18n, view)),
            )
    }
}
impl Render for GuiShell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity();
        let i18n = self.i18n();
        window.set_window_title(&self.window_title(&i18n));

        div()
            .size_full()
            .relative()
            .flex()
            .flex_col()
            .track_focus(&self.focus_handle)
            .bg(rgb(ROOT_BG))
            .text_color(rgb(TEXT))
            .on_action(cx.listener(Self::on_menu_select_folder))
            .on_action(cx.listener(Self::on_menu_recent_folder_unavailable))
            .on_action(cx.listener(Self::on_menu_recent_folder_0))
            .on_action(cx.listener(Self::on_menu_recent_folder_1))
            .on_action(cx.listener(Self::on_menu_recent_folder_2))
            .on_action(cx.listener(Self::on_menu_recent_folder_3))
            .on_action(cx.listener(Self::on_menu_recent_folder_4))
            .on_action(cx.listener(Self::on_menu_recent_folder_5))
            .on_action(cx.listener(Self::on_menu_recent_folder_6))
            .on_action(cx.listener(Self::on_menu_recent_folder_7))
            .on_action(cx.listener(Self::on_menu_recent_folder_8))
            .on_action(cx.listener(Self::on_menu_recent_folder_9))
            .on_action(cx.listener(Self::on_menu_remove_recent_folder_by_path))
            .on_action(cx.listener(Self::on_menu_save_selected))
            .on_action(cx.listener(Self::on_menu_save_all))
            .when(!self.undo_stack.is_empty(), |this| {
                this.on_action(cx.listener(Self::on_menu_edit_undo))
            })
            .when(!self.redo_stack.is_empty(), |this| {
                this.on_action(cx.listener(Self::on_menu_edit_redo))
            })
            .on_action(cx.listener(Self::on_menu_edit_clean))
            .on_action(cx.listener(Self::on_menu_edit_replace))
            .on_action(cx.listener(Self::on_menu_edit_to_ascii))
            .on_action(cx.listener(Self::on_menu_clear_workspace))
            .on_action(cx.listener(Self::on_menu_select_visible))
            .on_action(cx.listener(Self::on_file_table_select_all))
            .on_action(cx.listener(Self::on_menu_clear_selection))
            .on_action(cx.listener(Self::on_menu_locale_english))
            .on_action(cx.listener(Self::on_menu_locale_chinese))
            .on_action(cx.listener(Self::on_menu_locale_japanese))
            .on_action(cx.listener(Self::on_menu_backup_location_same_directory))
            .on_action(cx.listener(Self::on_menu_backup_location_backup_folder))
            .on_action(cx.listener(Self::on_menu_layout_vertical_split))
            .on_action(cx.listener(Self::on_menu_layout_horizontal_split))
            .on_action(cx.listener(Self::on_menu_auto_analyze_parallelism_1))
            .on_action(cx.listener(Self::on_menu_auto_analyze_parallelism_2))
            .on_action(cx.listener(Self::on_menu_auto_analyze_parallelism_4))
            .on_action(cx.listener(Self::on_menu_auto_analyze_parallelism_8))
            .on_action(cx.listener(Self::on_menu_auto_analyze_parallelism_16))
            .on_action(cx.listener(Self::on_menu_auto_analyze_parallelism_32))
            .on_action(cx.listener(Self::on_menu_edit_max_bytes))
            .on_action(cx.listener(Self::on_menu_toggle_ignore_folder_names))
            .on_action(cx.listener(Self::on_menu_edit_ignored_folder_names))
            .when(cfg!(target_os = "windows"), |this| {
                this.child(
                    div()
                        .px_2()
                        .py_1()
                        .border_b_1()
                        .border_color(rgb(BORDER))
                        .bg(rgb(0xf7f7f7))
                        .child(render_menu_strip(
                            self.menu_bar.element(),
                            render_global_processing_indicator(self, &i18n),
                        )),
                )
            })
            .when(
                cfg!(not(target_os = "windows")) && !cfg!(target_os = "macos"),
                |this| {
                    this.child(
                        div()
                            .px_4()
                            .pt_3()
                            .child(section_bar().child(render_menu_strip(
                                self.menu_bar.element(),
                                render_global_processing_indicator(self, &i18n),
                            ))),
                    )
                },
            )
            .child(div().flex_1().min_h_0().p_4().child({
                let split = workspace_split_config(self.state.workspace_layout);
                let file_panel = resizable_panel()
                    .size(split.file_size)
                    .size_range(split.file_min..Pixels::MAX)
                    .child(self.render_file_table(view.clone()));
                let result_panel = resizable_panel()
                    .size(split.result_size)
                    .size_range(split.result_min..Pixels::MAX)
                    .child(self.render_result_panel(view.clone()));
                match split.axis {
                    Axis::Vertical => v_resizable(split.group_id)
                        .child(file_panel)
                        .child(result_panel)
                        .into_any_element(),
                    Axis::Horizontal => h_resizable(split.group_id)
                        .child(file_panel)
                        .child(result_panel)
                        .into_any_element(),
                }
            }))
            .child(
                div().px_4().pb_3().text_sm().text_color(rgb(MUTED)).child(
                    self.status_message
                        .as_ref()
                        .map(|message| render_banner_message(&i18n, message))
                        .unwrap_or_else(|| i18n.text("banner.default_hint")),
                ),
            )
            .when(self.file_dialog_ui_blocked, |this| {
                this.child(
                    div()
                        .id("file-dialog-ui-block")
                        .absolute()
                        .top_0()
                        .left_0()
                        .right_0()
                        .bottom_0()
                        .occlude()
                        .bg(rgba(0xfffcf780)),
                )
            })
            .when(self.save_jobs_in_flight > 0, |this| {
                this.child(
                    div()
                        .id("save-ui-block")
                        .absolute()
                        .top_0()
                        .left_0()
                        .right_0()
                        .bottom_0()
                        .occlude()
                        .bg(rgba(0xfffcf7c8))
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(
                            div()
                                .px_4()
                                .py_3()
                                .rounded_md()
                                .border_1()
                                .border_color(rgb(BORDER))
                                .bg(rgb(PANEL_BG))
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(Spinner::new().with_size(px(16.0)))
                                .child(self.i18n().text("file_status.processing.save")),
                        ),
                )
            })
    }
}

impl Focusable for GuiShell {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

fn section_bar() -> Div {
    div()
        .px_4()
        .py_3()
        .flex()
        .flex_wrap()
        .items_center()
        .justify_between()
        .gap_3()
        .border_b_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL_BG))
}

fn render_menu_strip(menu: impl IntoElement, indicator: impl IntoElement) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(div().flex_1().min_w_0().child(menu))
        .child(indicator)
}

fn render_global_processing_indicator(shell: &GuiShell, i18n: &I18n) -> AnyElement {
    let auto_remaining_count = shell.auto_analyze_queue.remaining_count();
    let row_processing_count = shell.rows.iter().filter(|row| row.is_processing()).count();
    let dialog_previewing = shell
        .replace_dialog
        .as_ref()
        .is_some_and(|dialog| dialog.is_previewing);
    if auto_remaining_count == 0 && row_processing_count == 0 && !dialog_previewing {
        return div().into_any_element();
    }
    let label = if auto_remaining_count > 0 {
        i18n.format(
            "status.remaining_count",
            &[("count", auto_remaining_count.to_string())],
        )
    } else if row_processing_count > 0 {
        i18n.format(
            "status.processing_count",
            &[("count", row_processing_count.to_string())],
        )
    } else {
        i18n.text("status.working")
    };
    div()
        .flex()
        .items_center()
        .gap_2()
        .text_sm()
        .text_color(rgb(MUTED))
        .child(Spinner::new().with_size(px(14.0)))
        .child(label)
        .into_any_element()
}

fn auto_analyze_toggle_button(
    label: String,
    enabled: bool,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let (background, foreground, border) = if enabled {
        (ACCENT_SOFT, ACCENT, ACCENT)
    } else {
        (PANEL_BG, MUTED, BORDER)
    };
    div()
        .px_2()
        .py_1()
        .rounded_sm()
        .border_1()
        .border_color(rgb(border))
        .bg(rgb(background))
        .text_sm()
        .text_color(rgb(foreground))
        .child(label)
        .on_mouse_down(MouseButton::Left, |_, _, cx| {
            cx.stop_propagation();
        })
        .on_mouse_up(MouseButton::Left, move |_, window, cx| {
            view.update(cx, |shell, cx| {
                shell.toggle_workspace_auto_analyze(window, cx);
                cx.notify();
            });
        })
}

fn file_list_filter_button(
    label: String,
    selected: bool,
    active_background: u32,
    active_foreground: u32,
    on_click: impl Fn(&mut GuiShell, &mut Context<GuiShell>) + 'static,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let background = if selected {
        active_background
    } else {
        PANEL_BG
    };
    let foreground = if selected { active_foreground } else { MUTED };
    let border = if selected { active_foreground } else { BORDER };

    div()
        .px_2()
        .py_1()
        .rounded_sm()
        .border_1()
        .border_color(rgb(border))
        .bg(rgb(background))
        .text_sm()
        .text_color(rgb(foreground))
        .child(label)
        .on_mouse_down(MouseButton::Left, |_, _, cx| {
            cx.stop_propagation();
        })
        .on_mouse_up(MouseButton::Left, move |_, _, cx| {
            view.update(cx, |shell, cx| {
                on_click(shell, cx);
                cx.notify();
            });
        })
}

fn file_panel_header(
    i18n: &I18n,
    caption: &str,
    search_input: &Entity<InputState>,
    findings_only: bool,
    missing_only: bool,
    auto_analyze_enabled: bool,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    div()
        .flex()
        .items_end()
        .justify_between()
        .gap_3()
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .min_w_0()
                .child(
                    div()
                        .font_weight(FontWeight::BOLD)
                        .child(i18n.text("panel.files")),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(MUTED))
                        .truncate()
                        .child(caption.to_string()),
                ),
        )
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap_2()
                .child(auto_analyze_toggle_button(
                    i18n.text("label.auto_analyze"),
                    auto_analyze_enabled,
                    view.clone(),
                ))
                .child(div().text_sm().text_color(rgb(MUTED)).child("|"))
                .child(file_list_filter_button(
                    i18n.text("label.file_list_findings"),
                    findings_only,
                    WARN_SOFT,
                    0x8a6116,
                    move |shell, cx| {
                        shell.toggle_file_list_findings_filter(cx);
                    },
                    view.clone(),
                ))
                .child(file_list_filter_button(
                    i18n.text("label.path_missing"),
                    missing_only,
                    ERROR_SOFT,
                    0x8a3a32,
                    move |shell, cx| {
                        shell.toggle_file_list_missing_filter(cx);
                    },
                    view,
                ))
                .child(
                    Input::new(search_input)
                        .small()
                        .w(px(220.0))
                        .cleanable(true),
                ),
        )
}

pub(super) fn section_panel() -> Div {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .rounded_lg()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL_BG))
}
