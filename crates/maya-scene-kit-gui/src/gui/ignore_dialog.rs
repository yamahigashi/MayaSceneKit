use super::*;

impl GuiShell {
    pub(super) fn open_ignore_folder_names_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.ignore_folder_names_dialog.is_some() {
            if window.has_active_dialog(cx) {
                return;
            }
            self.ignore_folder_names_dialog = None;
        }
        if window.has_active_dialog(cx) {
            return;
        }

        let i18n = self.i18n();
        let name_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n.text("placeholder.ignored_folder_name"))
        });
        self.ignore_folder_names_dialog = Some(IgnoreFolderNamesDialogState {
            draft_names: self.state.ignored_folder_names.clone(),
            name_input,
        });

        let view = cx.entity();
        window.open_dialog(cx, move |dialog, window, cx| {
            build_ignore_folder_names_dialog(dialog, view.clone(), window, cx)
        });
        cx.notify();
    }

    pub(super) fn clear_ignore_folder_names_dialog_state(&mut self, cx: &mut Context<Self>) {
        self.ignore_folder_names_dialog = None;
        cx.notify();
    }

    pub(super) fn ignore_folder_names_dialog_can_apply(&self) -> bool {
        self.ignore_folder_names_dialog
            .as_ref()
            .is_some_and(|dialog| dialog.can_apply(&self.state))
    }

    pub(super) fn add_ignore_folder_name_from_dialog_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(raw_name) = self
            .ignore_folder_names_dialog
            .as_ref()
            .map(|dialog| dialog.name_input.read(cx).value().to_string())
        else {
            return;
        };
        let Some(name) = normalize_ignored_folder_name(&raw_name) else {
            self.status_message = Some(BannerMessage::Raw(
                self.i18n().text("banner.ignore_folder_name_invalid"),
            ));
            cx.notify();
            return;
        };
        if self
            .ignore_folder_names_dialog
            .as_ref()
            .is_some_and(|dialog| {
                dialog
                    .draft_names
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(&name))
            })
        {
            self.status_message = Some(BannerMessage::Raw(
                self.i18n()
                    .format("banner.ignore_folder_name_duplicate", &[("name", name)]),
            ));
            cx.notify();
            return;
        }

        let Some(dialog) = self.ignore_folder_names_dialog.as_mut() else {
            return;
        };
        dialog.draft_names.push(name);
        dialog
            .name_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        cx.notify();
    }

    pub(super) fn remove_ignore_folder_name_from_dialog(
        &mut self,
        name: &str,
        cx: &mut Context<Self>,
    ) {
        let Some(dialog) = self.ignore_folder_names_dialog.as_mut() else {
            return;
        };
        let before_len = dialog.draft_names.len();
        dialog
            .draft_names
            .retain(|existing| !existing.eq_ignore_ascii_case(name));
        if dialog.draft_names.len() != before_len {
            cx.notify();
        }
    }

    pub(super) fn apply_ignore_folder_names_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(dialog) = self.ignore_folder_names_dialog.as_ref() else {
            return;
        };
        let draft_names = dialog.draft_names.clone();
        self.clear_ignore_folder_names_dialog_state(cx);
        self.apply_ignored_folder_names(draft_names, window, cx);
    }
}

fn build_ignore_folder_names_dialog(
    dialog: Dialog,
    view: Entity<GuiShell>,
    _: &mut Window,
    cx: &mut App,
) -> Dialog {
    let shell = view.read(cx);
    let i18n = shell.i18n();
    let dialog_state = shell.ignore_folder_names_dialog.clone();
    let configured_names = dialog_state
        .as_ref()
        .map(|state| state.draft_names.clone())
        .unwrap_or_default();

    dialog
        .title(i18n.text("dialog.ignore_folder_names_title"))
        .width(px(720.0))
        .max_w(px(780.0))
        .overlay_closable(false)
        .on_cancel({
            let view = view.clone();
            move |_, _, cx| {
                view.update(cx, |shell, cx| shell.clear_ignore_folder_names_dialog_state(cx));
                true
            }
        })
        .footer({
            let view = view.clone();
            move |_, _, _, cx| {
                let shell = view.read(cx);
                let i18n = shell.i18n();
                let can_apply = shell.ignore_folder_names_dialog_can_apply();
                vec![
                    Button::new("ignore-folders-cancel")
                        .label(i18n.text("action.cancel"))
                        .ghost()
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| {
                                    shell.clear_ignore_folder_names_dialog_state(cx);
                                });
                                window.close_dialog(cx);
                            }
                        })
                        .into_any_element(),
                    Button::new("ignore-folders-apply")
                        .label(i18n.text("action.apply"))
                        .disabled(!can_apply)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| {
                                    shell.apply_ignore_folder_names_dialog(window, cx);
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
                        .child(i18n.text("dialog.ignore_folder_names_hint")),
                )
                .when_some(dialog_state.as_ref(), |this, dialog_state| {
                    this.child(
                        div()
                            .flex()
                            .items_end()
                            .gap_3()
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
                                            .child(i18n.text("label.ignored_folder_names")),
                                    )
                                    .child(
                                        Input::new(&dialog_state.name_input)
                                            .small()
                                            .cleanable(true),
                                    ),
                            )
                            .child(
                                Button::new("ignore-folders-add")
                                    .label(i18n.text("action.add"))
                                    .small()
                                    .on_click({
                                        let view = view.clone();
                                        move |_, window, cx| {
                                            view.update(cx, |shell, cx| {
                                                shell.add_ignore_folder_name_from_dialog_input(
                                                    window, cx,
                                                );
                                            });
                                        }
                                    }),
                            ),
                    )
                })
                .child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(BORDER))
                        .bg(rgb(PANEL_BG))
                        .child(
                            if configured_names.is_empty() {
                                div()
                                    .px_3()
                                    .py_4()
                                    .text_sm()
                                    .text_color(rgb(MUTED))
                                    .child(i18n.text("dialog.ignore_folder_names_empty"))
                                    .into_any_element()
                            } else {
                                div()
                                    .max_h(px(280.0))
                                    .overflow_y_scrollbar()
                                    .children(configured_names.into_iter().enumerate().map(
                                        |(ix, name)| {
                                            let remove_name = name.clone();
                                            div()
                                                .id(("ignore-folder-name-row", ix))
                                                .px_3()
                                                .py_2()
                                                .border_b_1()
                                                .border_color(rgb(BORDER))
                                                .flex()
                                                .items_center()
                                                .justify_between()
                                                .gap_3()
                                                .child(div().flex_1().text_sm().child(name))
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "ignore-folder-remove-{ix}"
                                                    )))
                                                    .label(i18n.text("action.remove"))
                                                    .small()
                                                    .ghost()
                                                    .on_click({
                                                        let view = view.clone();
                                                        move |_, _, cx| {
                                                            view.update(cx, |shell, cx| {
                                                                shell.remove_ignore_folder_name_from_dialog(
                                                                    &remove_name,
                                                                    cx,
                                                                );
                                                            });
                                                        }
                                                    }),
                                                )
                                        },
                                    ))
                                    .into_any_element()
                            },
                        ),
                ),
        )
}
