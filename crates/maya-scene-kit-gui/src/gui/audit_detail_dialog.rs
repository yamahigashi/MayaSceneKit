use super::*;

const AUDIT_DETAIL_PREVIEW_HEIGHT: Pixels = px(320.0);
const AUDIT_DETAIL_EVIDENCE_HEIGHT: Pixels = px(180.0);
const AUDIT_DETAIL_DIALOG_WIDTH: Pixels = px(960.0);
const AUDIT_DETAIL_DIALOG_MAX_WIDTH: Pixels = px(1040.0);
const AUDIT_DETAIL_DIALOG_HORIZONTAL_MARGIN: Pixels = px(48.0);
const AUDIT_DETAIL_DIALOG_VERTICAL_MARGIN: Pixels = px(96.0);

struct AuditDetailDialogLayout {
    width: Pixels,
    max_width: Pixels,
    max_height: Pixels,
}

impl GuiShell {
    pub(super) fn open_audit_detail_dialog(
        &mut self,
        key: AuditResultRowKey,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if window.has_active_dialog(cx) {
            return;
        }

        let detail = resolve_audit_detail_view_model(&self.audit_rows, &key);
        let preview_text = detail
            .as_ref()
            .map(audit_detail_preview_text)
            .unwrap_or_default();
        let evidence_text = detail
            .as_ref()
            .map(audit_detail_evidence_text)
            .unwrap_or_default();
        let preview_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .default_value(preview_text.clone())
                .read_only(true)
        });
        let evidence_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .default_value(evidence_text.clone())
                .read_only(true)
        });

        self.audit_detail_dialog = Some(AuditDetailDialogState {
            key,
            preview_input,
            preview_text,
            evidence_input,
            evidence_text,
        });

        let view = cx.entity();
        window.open_dialog(cx, move |dialog, window, cx| {
            build_audit_detail_dialog(dialog, view.clone(), window, cx)
        });
        cx.notify();
    }

    pub(super) fn clear_audit_detail_dialog_state(&mut self, cx: &mut Context<Self>) {
        self.audit_detail_dialog = None;
        cx.notify();
    }

    pub(super) fn sync_audit_detail_dialog_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(dialog_state) = self.audit_detail_dialog.as_mut() else {
            return;
        };
        let Some(detail) = resolve_audit_detail_view_model(&self.audit_rows, &dialog_state.key)
        else {
            return;
        };

        let preview_text = audit_detail_preview_text(&detail);
        if dialog_state.preview_text != preview_text {
            dialog_state.preview_input.update(cx, |input, cx| {
                input.set_value(preview_text.clone(), window, cx);
                input.set_read_only(true, window, cx);
            });
            dialog_state.preview_text = preview_text;
        }

        let evidence_text = audit_detail_evidence_text(&detail);
        if dialog_state.evidence_text != evidence_text {
            dialog_state.evidence_input.update(cx, |input, cx| {
                input.set_value(evidence_text.clone(), window, cx);
                input.set_read_only(true, window, cx);
            });
            dialog_state.evidence_text = evidence_text;
        }
    }
}

fn build_audit_detail_dialog(
    dialog: Dialog,
    view: Entity<GuiShell>,
    window: &mut Window,
    cx: &mut App,
) -> Dialog {
    view.update(cx, |shell, cx| {
        shell.sync_audit_detail_dialog_inputs(window, cx);
    });

    let shell = view.read(cx);
    let i18n = shell.i18n();
    let dialog_state = shell.audit_detail_dialog.clone();
    let detail = dialog_state
        .as_ref()
        .and_then(|state| resolve_audit_detail_view_model(&shell.audit_rows, &state.key));
    let layout = audit_detail_dialog_layout(window);

    dialog
        .title(i18n.text("dialog.audit_detail_title"))
        .width(layout.width)
        .max_w(layout.max_width)
        .max_h(layout.max_height)
        .overlay_closable(false)
        .on_cancel({
            let view = view.clone();
            move |_, _, cx| {
                view.update(cx, |shell, cx| shell.clear_audit_detail_dialog_state(cx));
                true
            }
        })
        .footer({
            let view = view.clone();
            move |_, _, _, cx| {
                let shell = view.read(cx);
                let i18n = shell.i18n();
                let detail_state = shell.audit_detail_dialog.clone();
                let detail = detail_state.as_ref().and_then(|state| {
                    resolve_audit_detail_view_model(&shell.audit_rows, &state.key)
                });
                let mut buttons = Vec::new();
                if let Some(detail) = detail.as_ref() {
                    match (detail.clean_state, detail.clean_target.clone()) {
                        (AuditRowCleanState::Available, Some(target)) => buttons.push(
                            Button::new("audit-detail-clean")
                                .label(i18n.text("action.clean"))
                                .on_click({
                                    let view = view.clone();
                                    let row_keys = detail.row_keys.clone();
                                    move |_, window, cx| {
                                        view.update(cx, |shell, cx| {
                                            shell.run_audit_row_clean(
                                                row_keys.clone(),
                                                target.clone(),
                                                window,
                                                cx,
                                            );
                                        });
                                    }
                                })
                                .into_any_element(),
                        ),
                        (AuditRowCleanState::Staged, Some(target)) => buttons.push(
                            Button::new("audit-detail-undo")
                                .label(i18n.text("action.undo"))
                                .on_click({
                                    let view = view.clone();
                                    let row_keys = detail.row_keys.clone();
                                    move |_, window, cx| {
                                        view.update(cx, |shell, cx| {
                                            shell.undo_audit_row_clean(
                                                row_keys.clone(),
                                                target.clone(),
                                                window,
                                                cx,
                                            );
                                        });
                                    }
                                })
                                .into_any_element(),
                        ),
                        _ => {}
                    }
                }
                buttons.push(
                    Button::new("audit-detail-copy")
                        .label(i18n.text("action.copy_source_text"))
                        .disabled(detail.is_none())
                        .on_click({
                            let view = view.clone();
                            move |_, _, cx| {
                                let shell = view.read(cx);
                                let Some(state) = shell.audit_detail_dialog.as_ref() else {
                                    return;
                                };
                                let Some(payload) =
                                    resolve_audit_clipboard_payload(&shell.audit_rows, &state.key)
                                else {
                                    return;
                                };
                                cx.write_to_clipboard(ClipboardItem::new_string(payload));
                            }
                        })
                        .into_any_element(),
                );
                buttons.push(
                    div()
                        .debug_selector(|| "audit-detail-close".to_string())
                        .child(
                            Button::new("audit-detail-close")
                                .label(i18n.text("action.cancel"))
                                .ghost()
                                .on_click({
                                    let view = view.clone();
                                    move |_, window, cx| {
                                        view.update(cx, |shell, cx| {
                                            shell.clear_audit_detail_dialog_state(cx)
                                        });
                                        window.close_dialog(cx);
                                    }
                                }),
                        )
                        .into_any_element(),
                );
                buttons
            }
        })
        .child(render_audit_detail_dialog_body(
            detail.as_ref(),
            dialog_state.as_ref(),
            &i18n,
        ))
}

fn render_audit_detail_dialog_body(
    detail: Option<&AuditDetailViewModel>,
    dialog_state: Option<&AuditDetailDialogState>,
    i18n: &I18n,
) -> AnyElement {
    let Some(detail) = detail else {
        return div()
            .w_full()
            .text_sm()
            .text_color(rgb(MUTED))
            .child(i18n.text("dialog.audit_detail_unavailable"))
            .into_any_element();
    };
    let Some(dialog_state) = dialog_state else {
        return div()
            .w_full()
            .text_sm()
            .text_color(rgb(MUTED))
            .child(i18n.text("dialog.audit_detail_unavailable"))
            .into_any_element();
    };

    let (_, badge_bg, badge_fg) = audit_severity_colors(detail.severity);
    let meta = format!("{}  |  {}", detail.code, detail.sink);

    div()
        .debug_selector(|| "audit-detail-body".to_string())
        .w_full()
        .min_h_0()
        .flex()
        .flex_col()
        .gap_3()
        .child(
            div()
                .rounded_md()
                .border_1()
                .border_color(rgb(BORDER))
                .bg(rgb(PANEL_ALT_BG))
                .px_3()
                .py_3()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .min_w_0()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .flex_1()
                                .gap_2()
                                .min_w_0()
                                .child(badge(&detail.scene_name, PANEL_BG, MUTED))
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .overflow_hidden()
                                        .whitespace_nowrap()
                                        .truncate()
                                        .text_sm()
                                        .font_weight(FontWeight::BOLD)
                                        .child(detail.summary.clone()),
                                ),
                        )
                        .child(badge(
                            &severity_label(i18n, detail.severity),
                            badge_bg,
                            badge_fg,
                        )),
                )
                .child(div().text_sm().text_color(rgb(MUTED)).child(meta))
                .children(
                    detail
                        .provenance
                        .iter()
                        .cloned()
                        .map(|line| div().text_sm().text_color(rgb(MUTED)).child(line)),
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
                        .font_weight(FontWeight::BOLD)
                        .child(i18n.text("label.preview")),
                )
                .child(render_audit_detail_text_panel(
                    &dialog_state.preview_input,
                    AUDIT_DETAIL_PREVIEW_HEIGHT,
                )),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::BOLD)
                        .child(i18n.text("label.evidence")),
                )
                .child(render_audit_detail_text_panel(
                    &dialog_state.evidence_input,
                    AUDIT_DETAIL_EVIDENCE_HEIGHT,
                )),
        )
        .into_any_element()
}

fn audit_detail_dialog_layout(window: &Window) -> AuditDetailDialogLayout {
    let window_paddings = gpui_component::window_paddings(window);
    let viewport = window.viewport_size()
        - size(
            window_paddings.left + window_paddings.right,
            window_paddings.top + window_paddings.bottom,
        );
    let available_width =
        clamp_dialog_dimension(viewport.width, AUDIT_DETAIL_DIALOG_HORIZONTAL_MARGIN);
    let available_height =
        clamp_dialog_dimension(viewport.height, AUDIT_DETAIL_DIALOG_VERTICAL_MARGIN);

    AuditDetailDialogLayout {
        width: AUDIT_DETAIL_DIALOG_WIDTH.min(available_width),
        max_width: AUDIT_DETAIL_DIALOG_MAX_WIDTH.min(available_width),
        max_height: available_height,
    }
}

fn clamp_dialog_dimension(viewport: Pixels, margin: Pixels) -> Pixels {
    if viewport > margin {
        viewport - margin
    } else {
        viewport.max(px(0.0))
    }
}

fn render_audit_detail_text_panel(input: &Entity<InputState>, height: Pixels) -> AnyElement {
    div()
        .h(height)
        .min_h(height)
        .min_w_0()
        .rounded_md()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL_BG))
        .overflow_hidden()
        .child(
            Input::new(input)
                .h_full()
                .appearance(false)
                .bordered(false)
                .focus_bordered(false),
        )
        .into_any_element()
}

fn audit_detail_preview_text(detail: &AuditDetailViewModel) -> String {
    if detail.preview.is_empty() {
        "-".to_string()
    } else {
        detail.preview.clone()
    }
}

fn audit_detail_evidence_text(detail: &AuditDetailViewModel) -> String {
    let mut lines = Vec::new();
    if detail.scene_names.len() > 1 {
        lines.push("scenes:".to_string());
        lines.extend(detail.scene_names.iter().cloned());
    }
    lines.extend(detail.evidence.iter().cloned());

    if lines.is_empty() {
        "-".to_string()
    } else {
        lines.join("\n")
    }
}
