use super::*;

pub(super) fn parse_max_bytes_input(input: &str) -> Option<Option<usize>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some(None);
    }
    match trimmed.parse::<usize>() {
        Ok(value) if value > 0 => Some(Some(value)),
        _ => None,
    }
}

impl GuiShell {
    pub(super) fn open_max_bytes_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.max_bytes_dialog.is_some() {
            if window.has_active_dialog(cx) {
                return;
            }
            self.max_bytes_dialog = None;
        }
        if window.has_active_dialog(cx) {
            return;
        }

        let i18n = self.i18n();
        let default_value = self
            .state
            .max_bytes
            .map(|value| value.to_string())
            .unwrap_or_default();
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(i18n.text("placeholder.max_bytes"))
                .default_value(default_value)
        });
        self.max_bytes_dialog = Some(MaxBytesDialogState { input });

        let view = cx.entity();
        window.open_dialog(cx, move |dialog, window, cx| {
            build_max_bytes_dialog(dialog, view.clone(), window, cx)
        });
        cx.notify();
    }

    pub(super) fn clear_max_bytes_dialog_state(&mut self, cx: &mut Context<Self>) {
        self.max_bytes_dialog = None;
        cx.notify();
    }

    pub(super) fn max_bytes_dialog_can_apply(&self, cx: &App) -> bool {
        self.max_bytes_dialog
            .as_ref()
            .is_some_and(|dialog| dialog.can_apply(&self.state, cx))
    }

    pub(super) fn apply_max_bytes_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(dialog) = self.max_bytes_dialog.as_ref() else {
            return;
        };
        let Some(max_bytes) = dialog.parsed_value(cx) else {
            self.status_message = Some(BannerMessage::Raw(
                self.i18n().text("dialog.max_bytes_invalid"),
            ));
            cx.notify();
            return;
        };
        self.clear_max_bytes_dialog_state(cx);
        self.set_max_bytes_preference(max_bytes, window, cx);
    }

    pub(super) fn reset_max_bytes_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.clear_max_bytes_dialog_state(cx);
        self.set_max_bytes_preference(None, window, cx);
    }
}

fn build_max_bytes_dialog(
    dialog: Dialog,
    view: Entity<GuiShell>,
    _: &mut Window,
    cx: &mut App,
) -> Dialog {
    let shell = view.read(cx);
    let i18n = shell.i18n();
    let dialog_state = shell.max_bytes_dialog.clone();
    let reset_enabled = shell.state.max_bytes.is_some();

    dialog
        .title(i18n.text("dialog.max_bytes_title"))
        .width(px(520.0))
        .max_w(px(560.0))
        .overlay_closable(false)
        .on_cancel({
            let view = view.clone();
            move |_, _, cx| {
                view.update(cx, |shell, cx| shell.clear_max_bytes_dialog_state(cx));
                true
            }
        })
        .footer({
            let view = view.clone();
            move |_, _, _, cx| {
                let shell = view.read(cx);
                let i18n = shell.i18n();
                let can_apply = shell.max_bytes_dialog_can_apply(cx);
                let reset_enabled = shell.state.max_bytes.is_some();
                vec![
                    Button::new("max-bytes-cancel")
                        .label(i18n.text("action.cancel"))
                        .ghost()
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| {
                                    shell.clear_max_bytes_dialog_state(cx);
                                });
                                window.close_dialog(cx);
                            }
                        })
                        .into_any_element(),
                    Button::new("max-bytes-reset")
                        .label(i18n.text("action.reset"))
                        .ghost()
                        .disabled(!reset_enabled)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| {
                                    shell.reset_max_bytes_dialog(window, cx);
                                });
                                window.close_dialog(cx);
                            }
                        })
                        .into_any_element(),
                    Button::new("max-bytes-apply")
                        .label(i18n.text("action.apply"))
                        .disabled(!can_apply)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| {
                                    shell.apply_max_bytes_dialog(window, cx);
                                });
                                window.close_dialog(cx);
                            }
                        })
                        .into_any_element(),
                ]
            }
        })
        .child(
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(MUTED))
                        .child(i18n.text("dialog.max_bytes_hint")),
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
                                .child(i18n.text("settings.max_bytes")),
                        )
                        .when_some(dialog_state.as_ref(), |this, dialog_state| {
                            this.child(Input::new(&dialog_state.input).small().cleanable(true))
                        }),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(MUTED))
                        .child(if reset_enabled {
                            i18n.format(
                                "dialog.max_bytes_current",
                                &[(
                                    "value",
                                    shell
                                        .state
                                        .max_bytes
                                        .map(|value| value.to_string())
                                        .unwrap_or_default(),
                                )],
                            )
                        } else {
                            i18n.text("dialog.max_bytes_default")
                        }),
                ),
        )
}
