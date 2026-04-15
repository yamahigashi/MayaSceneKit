use super::{render::section_panel, *};

pub(super) fn result_content(
    shell: &GuiShell,
    i18n: &I18n,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    div()
        .size_full()
        .min_w_0()
        .child(match shell.state.active_tab {
            ResultTab::Overview => result_overview(shell, i18n).into_any_element(),
            ResultTab::Audit => result_audit(shell, i18n, view).into_any_element(),
            ResultTab::Paths => result_paths(shell, i18n).into_any_element(),
            ResultTab::Log => result_log(shell, i18n).into_any_element(),
        })
}

pub(super) fn render_audit_filter_bar(
    shell: &GuiShell,
    i18n: &I18n,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let count_label = i18n.format(
        "log.audit",
        &[("count", shell.audit_rows.len().to_string())],
    );
    let dedup_label = if shell.audit_table_dedup {
        i18n.text("audit_table.show_all")
    } else {
        i18n.text("audit_table.dedup")
    };

    div()
        .flex()
        .items_center()
        .justify_end()
        .gap_2()
        .child(div().text_sm().text_color(rgb(MUTED)).child(count_label))
        .children(
            [
                AuditSeverityFilter::MediumPlus,
                AuditSeverityFilter::Low,
                AuditSeverityFilter::Info,
            ]
            .into_iter()
            .map(|filter| {
                let selected = shell.audit_severity_filter.contains(&filter);
                audit_filter_button(
                    audit_filter_label(i18n, filter),
                    filter,
                    selected,
                    view.clone(),
                )
            }),
        )
        .child(dirty_filter_button(
            i18n.text("label.dirty"),
            shell.audit_dirty_only,
            move |shell, cx| shell.toggle_audit_dirty_filter(cx),
            view.clone(),
        ))
        .child(action_button(
            "audit-table-dedup",
            dedup_label,
            true,
            move |shell, _, cx| {
                shell.toggle_audit_table_dedup(cx);
                cx.notify();
            },
            view.clone(),
        ))
        .child(
            Input::new(&shell.audit_search_input)
                .small()
                .w(px(240.0))
                .cleanable(true),
        )
}

pub(super) fn render_paths_filter_bar(
    shell: &GuiShell,
    i18n: &I18n,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let model = shell.current_path_table_model();
    let dedup_label = if shell.path_table_dedup {
        i18n.text("path_table.show_all")
    } else {
        i18n.text("path_table.dedup")
    };
    let count_label = i18n.format("log.paths", &[("count", model.rows.len().to_string())]);

    div()
        .flex()
        .items_center()
        .justify_end()
        .gap_2()
        .child(div().text_sm().text_color(rgb(MUTED)).child(count_label))
        .children(
            [PathTypeFilter::Reference, PathTypeFilter::File]
                .into_iter()
                .map(|filter| {
                    let selected = shell.path_type_filter.contains(&filter);
                    path_type_filter_button(
                        path_type_filter_label(i18n, filter),
                        filter,
                        selected,
                        view.clone(),
                    )
                }),
        )
        .children(
            [PathFormFilter::Rel, PathFormFilter::Abs]
                .into_iter()
                .map(|filter| {
                    let selected = shell.path_form_filter.contains(&filter);
                    path_form_filter_button(
                        path_form_filter_label(i18n, filter),
                        filter,
                        selected,
                        view.clone(),
                    )
                }),
        )
        .children(
            [PathResolutionBadge::Exists, PathResolutionBadge::Missing]
                .into_iter()
                .map(|filter| {
                    let selected = shell.path_resolution_filter.contains(&filter);
                    path_resolution_filter_button(
                        path_resolution_filter_label(i18n, filter),
                        filter,
                        selected,
                        view.clone(),
                    )
                }),
        )
        .child(dirty_filter_button(
            i18n.text("label.dirty"),
            shell.path_dirty_only,
            move |shell, cx| shell.toggle_path_dirty_filter(cx),
            view.clone(),
        ))
        .child(action_button(
            "path-table-dedup",
            dedup_label,
            true,
            move |shell, _, cx| {
                shell.toggle_path_table_dedup(cx);
                cx.notify();
            },
            view,
        ))
        .child(
            Input::new(&shell.path_search_input)
                .small()
                .w(px(240.0))
                .cleanable(true),
        )
}

pub(super) fn result_overview(shell: &GuiShell, i18n: &I18n) -> AnyElement {
    if shell.rows.is_empty() {
        return body_text(i18n.text("empty.overview")).into_any_element();
    }
    let dirty = shell.rows.iter().filter(|row| row.dirty()).count();
    let findings = shell
        .rows
        .iter()
        .map(SceneRow::effective_findings_count)
        .sum::<usize>();
    div()
        .flex()
        .gap_3()
        .child(metric_card(
            i18n,
            &i18n.text("label.files"),
            &shell.rows.len().to_string(),
        ))
        .child(metric_card(
            i18n,
            &i18n.text("label.dirty"),
            &dirty.to_string(),
        ))
        .child(metric_card(
            i18n,
            &i18n.text("label.findings"),
            &findings.to_string(),
        ))
        .into_any_element()
}

pub(super) fn result_audit(shell: &GuiShell, i18n: &I18n, _view: Entity<GuiShell>) -> AnyElement {
    let selected = shell.selected_indices();
    if selected.is_empty() {
        return body_text(i18n.text("empty.audit.none")).into_any_element();
    }
    let notice_lines = selected_audit_notice_lines(shell, &selected);
    let notice_panel =
        (!notice_lines.is_empty()).then(|| render_audit_notice_panel(i18n, notice_lines));
    if !shell.audit_rows.is_empty() {
        return div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .children(notice_panel)
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .size_full()
                    .child(Table::new(&shell.audit_table).scrollbar_visible(true, false)),
            )
            .into_any_element();
    }
    if let Some(panel) = notice_panel {
        return div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel)
            .into_any_element();
    }
    if shell.audit_all_rows.is_empty() {
        return body_text(i18n.text("empty.audit.run")).into_any_element();
    }
    body_text(i18n.text("empty.audit.filtered")).into_any_element()
}

pub(super) fn result_paths(shell: &GuiShell, i18n: &I18n) -> AnyElement {
    let selected = shell.selected_indices();
    if selected.is_empty() {
        return body_text(i18n.text("empty.paths.none")).into_any_element();
    }
    let model = shell.current_path_table_model();
    if !model.rows.is_empty() || model.has_report_rows {
        return div()
            .size_full()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .size_full()
                    .child(Table::new(&shell.path_table).scrollbar_visible(true, false)),
            )
            .into_any_element();
    }
    if selected_rows_are_parse_budget_blocked_without_paths(shell, &selected) {
        return body_text(i18n.text("empty.paths.parse_budget_blocked")).into_any_element();
    }
    body_text(i18n.text("empty.paths.run")).into_any_element()
}

pub(super) fn result_log(shell: &GuiShell, i18n: &I18n) -> AnyElement {
    let lines = build_job_history_log_lines(i18n, &shell.state.job_history);
    if lines.is_empty() {
        return body_text(i18n.text("empty.log")).into_any_element();
    }
    list_panel(lines).into_any_element()
}

pub(super) fn metric_card(i18n: &I18n, title: &str, value: &str) -> impl IntoElement {
    section_panel()
        .w(px(180.0))
        .child(
            div()
                .text_sm()
                .text_color(rgb(MUTED))
                .child(title.to_string()),
        )
        .child(
            div()
                .text_xl()
                .font_weight(FontWeight::BOLD)
                .child(value.to_string()),
        )
        .child(
            div()
                .text_sm()
                .text_color(rgb(MUTED))
                .child(i18n.text("metric.workspace")),
        )
}

pub(super) fn list_panel(lines: Vec<String>) -> impl IntoElement {
    div()
        .size_full()
        .min_w_0()
        .min_h_0()
        .overflow_y_scrollbar()
        .child(
            div()
                .size_full()
                .min_w_0()
                .flex()
                .flex_col()
                .gap_2()
                .children(lines.into_iter().map(scrollable_list_line)),
        )
}

pub(super) fn body_text(text: String) -> impl IntoElement {
    div().min_w_0().text_sm().text_color(rgb(MUTED)).child(text)
}

pub(super) fn selected_audit_notice_lines(shell: &GuiShell, selected: &[usize]) -> Vec<String> {
    let multiple = selected.len() > 1;
    selected
        .iter()
        .filter_map(|&index| shell.rows.get(index))
        .flat_map(|row| {
            row.display_audit_report()
                .into_iter()
                .flat_map(move |report| report.notices.iter().map(move |notice| (row, notice)))
        })
        .map(|(row, notice)| {
            if multiple {
                format!("{}: {}", row.name, notice.message)
            } else {
                notice.message.clone()
            }
        })
        .collect()
}

fn render_audit_notice_panel(i18n: &I18n, lines: Vec<String>) -> impl IntoElement {
    section_panel()
        .child(
            div()
                .text_sm()
                .font_weight(FontWeight::BOLD)
                .child(i18n.text("label.audit_notices")),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .children(lines.into_iter().map(scrollable_list_line)),
        )
}

pub(super) fn selected_rows_are_parse_budget_blocked_without_paths(
    shell: &GuiShell,
    selected: &[usize],
) -> bool {
    selected
        .iter()
        .filter_map(|&index| shell.rows.get(index))
        .any(|row| {
            row.display_audit_report()
                .is_some_and(|report| report.is_parse_budget_blocked())
                && row.display_paths_report().is_none()
        })
}

pub(super) fn scrollable_list_line(line: String) -> impl IntoElement {
    div()
        .min_w_0()
        .p_2()
        .rounded_sm()
        .bg(rgb(PANEL_ALT_BG))
        .text_sm()
        .child(line)
}

pub(super) fn audit_filter_button(
    label: String,
    filter: AuditSeverityFilter,
    selected: bool,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let (_, badge_bg, badge_fg) = audit_filter_colors(filter);
    let background = if selected { badge_bg } else { PANEL_BG };
    let foreground = if selected { badge_fg } else { MUTED };
    let border = if selected { badge_bg } else { BORDER };

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
                shell.toggle_audit_severity(filter, cx);
                cx.notify();
            });
        })
}

pub(super) fn dirty_filter_button(
    label: String,
    selected: bool,
    on_click: impl Fn(&mut GuiShell, &mut Context<GuiShell>) + 'static,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let background = if selected { WARN_SOFT } else { PANEL_BG };
    let foreground = if selected { 0x8a6116 } else { MUTED };
    let border = if selected { 0x8a6116 } else { BORDER };

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

pub(super) fn path_type_filter_button(
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
                shell.toggle_path_type_filter(filter, cx);
                cx.notify();
            });
        })
}

pub(super) fn path_resolution_filter_button(
    label: String,
    filter: PathResolutionBadge,
    selected: bool,
    view: Entity<GuiShell>,
) -> AnyElement {
    let Some(icon) = path_resolution_icon(filter) else {
        return div().into_any_element();
    };
    let (active_background, active_foreground) = match filter {
        PathResolutionBadge::Exists => (SUCCESS_SOFT, 0x256c2c),
        PathResolutionBadge::Missing => (ERROR_SOFT, 0x8a3a32),
        PathResolutionBadge::Unresolved => (PANEL_ALT_BG, MUTED),
    };
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
        .flex()
        .items_center()
        .gap_1()
        .child(Icon::new(icon).small())
        .child(label)
        .on_mouse_down(MouseButton::Left, |_, _, cx| {
            cx.stop_propagation();
        })
        .on_mouse_up(MouseButton::Left, move |_, _, cx| {
            view.update(cx, |shell, cx| {
                shell.toggle_path_resolution_filter(filter, cx);
                cx.notify();
            });
        })
        .into_any_element()
}

pub(super) fn path_form_filter_button(
    label: String,
    filter: PathFormFilter,
    selected: bool,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let (background, foreground) = if selected {
        match filter {
            PathFormFilter::Rel => (ACCENT_SOFT, ACCENT),
            PathFormFilter::Abs => (PANEL_ALT_BG, TEXT),
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
        .child(label)
        .on_mouse_down(MouseButton::Left, |_, _, cx| {
            cx.stop_propagation();
        })
        .on_mouse_up(MouseButton::Left, move |_, _, cx| {
            view.update(cx, |shell, cx| {
                shell.toggle_path_form_filter(filter, cx);
                cx.notify();
            });
        })
}
