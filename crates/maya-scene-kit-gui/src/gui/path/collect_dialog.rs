use super::{
    super::*, normalize_path_edit_targets, parse_path_collect_folder_input,
    path_collect_default_folder, path_collect_destination_supports_rewrite_mode,
    path_collect_supported_for_edit_targets, path_file_collect_supported_for_edit_targets,
    scene_path_string, shared_workspace_root_for_targets,
};

impl GuiShell {
    pub(in crate::gui) fn open_path_collect_dialog(
        &mut self,
        edit_targets: PathEditTargets,
        rewrite_mode: PathCollectRewriteMode,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }
        let can_collect = match rewrite_mode {
            PathCollectRewriteMode::CopyOnly => {
                path_file_collect_supported_for_edit_targets(&self.rows, &edit_targets)
            }
            _ => path_collect_supported_for_edit_targets(&self.rows, &edit_targets),
        };
        if !can_collect {
            return;
        }
        let Some(workspace_root) = shared_workspace_root_for_targets(&self.rows, &edit_targets)
        else {
            return;
        };

        if self.path_collect_dialog.is_some() {
            if window.has_active_dialog(cx) {
                return;
            }
            self.path_collect_dialog = None;
        }
        if window.has_active_dialog(cx) {
            return;
        }

        let default_folder = path_collect_default_folder(&workspace_root);
        let placeholder = self.i18n().text("placeholder.path_collect_folder");
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(placeholder)
                .default_value(scene_path_string(&default_folder))
        });
        self.path_collect_dialog = Some(PathCollectDialogState {
            edit_targets,
            rewrite_mode,
            workspace_root,
            folder_input: input,
        });

        let view = cx.entity();
        window.open_dialog(cx, move |dialog, window, cx| {
            build_path_collect_dialog(dialog, view.clone(), window, cx)
        });
        cx.notify();
    }

    pub(in crate::gui) fn clear_path_collect_dialog_state(&mut self, cx: &mut Context<Self>) {
        self.path_collect_dialog = None;
        cx.notify();
    }

    pub(in crate::gui) fn path_collect_dialog_destination_path(&self, cx: &App) -> Option<PathBuf> {
        let dialog = self.path_collect_dialog.as_ref()?;
        let input_value = dialog.folder_input.read(cx).value();
        let destination =
            parse_path_collect_folder_input(input_value.as_ref(), dialog.workspace_root.as_path())?;
        path_collect_destination_supports_rewrite_mode(
            &destination,
            &dialog.workspace_root,
            dialog.rewrite_mode,
        )
        .then_some(destination)
    }

    pub(in crate::gui) fn path_collect_dialog_initial_directory(
        &self,
        cx: &App,
    ) -> Option<PathBuf> {
        let dialog = self.path_collect_dialog.as_ref()?;
        let input_value = dialog.folder_input.read(cx).value();
        parse_path_collect_folder_input(input_value.as_ref(), dialog.workspace_root.as_path())
            .filter(|path| path.is_dir())
            .or_else(|| {
                dialog
                    .workspace_root
                    .is_dir()
                    .then(|| dialog.workspace_root.clone())
            })
    }

    pub(in crate::gui) fn path_collect_dialog_can_apply(&self, cx: &App) -> bool {
        self.path_collect_dialog_destination_path(cx).is_some()
    }

    fn open_path_collect_folder_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.path_collect_dialog.is_none() {
            self.schedule_file_dialog_ui_unblock(window, cx);
            return;
        }

        let response = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            initial_directory: self.path_collect_dialog_initial_directory(cx),
            prompt: Some(self.i18n().text("action.select_folder").into()),
        });
        let view = cx.entity();

        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let mut async_cx = cx.clone();
                async move {
                    match response.await {
                        Ok(Ok(Some(paths))) => {
                            let selected_folder = paths.into_iter().next();
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    if let (Some(dialog), Some(selected_folder)) =
                                        (&shell.path_collect_dialog, selected_folder)
                                    {
                                        let value = scene_path_string(&selected_folder);
                                        dialog.folder_input.update(cx, |input, cx| {
                                            input.set_value(value, window, cx);
                                        });
                                    }
                                    shell.schedule_file_dialog_ui_unblock(window, cx);
                                    cx.notify();
                                },
                            );
                        }
                        Ok(Ok(None)) => {
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    shell.schedule_file_dialog_ui_unblock(window, cx);
                                },
                            );
                        }
                        Ok(Err(err)) => {
                            let message = err.to_string();
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    shell.status_message = Some(BannerMessage::Raw(message));
                                    shell.schedule_file_dialog_ui_unblock(window, cx);
                                    cx.notify();
                                },
                            );
                        }
                        Err(err) => {
                            let message = format!("Folder selection failed: {err}");
                            let _ = async_cx.update_window_entity(
                                &view,
                                move |shell: &mut GuiShell,
                                      window: &mut Window,
                                      cx: &mut Context<GuiShell>| {
                                    shell.status_message = Some(BannerMessage::Raw(message));
                                    shell.schedule_file_dialog_ui_unblock(window, cx);
                                    cx.notify();
                                },
                            );
                        }
                    }
                }
            })
            .detach();
    }

    pub(in crate::gui) fn select_path_collect_folder(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.path_collect_dialog.is_none() {
            return;
        }
        let view = cx.entity();
        self.begin_file_dialog_ui_block(cx);
        window.defer(cx, move |window, cx| {
            view.update(cx, |shell, cx| {
                shell.open_path_collect_folder_dialog(window, cx);
            });
        });
    }

    pub(in crate::gui) fn apply_path_collect_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(dialog) = self.path_collect_dialog.clone() else {
            return;
        };
        let Some(destination_folder) = self.path_collect_dialog_destination_path(cx) else {
            self.status_message = Some(BannerMessage::Raw(
                self.i18n().text("banner.path_collect_folder_invalid"),
            ));
            cx.notify();
            return;
        };

        self.clear_path_collect_dialog_state(cx);
        self.collect_path_targets_to_folder(
            dialog.edit_targets,
            destination_folder,
            dialog.rewrite_mode,
            window,
            cx,
        );
    }
}

fn build_path_collect_dialog(
    dialog: Dialog,
    view: Entity<GuiShell>,
    _: &mut Window,
    cx: &mut App,
) -> Dialog {
    let shell = view.read(cx);
    let i18n = shell.i18n();
    let dialog_state = shell.path_collect_dialog.clone();
    let can_apply = shell.path_collect_dialog_can_apply(cx);
    let title = dialog_state
        .as_ref()
        .map(|state| match state.rewrite_mode {
            PathCollectRewriteMode::CopyOnly => i18n.text("dialog.path_collect_copy_only_title"),
            PathCollectRewriteMode::Absolute => i18n.text("dialog.path_collect_absolute_title"),
            PathCollectRewriteMode::WorkspaceDoubleSlashRelative => {
                i18n.text("dialog.path_collect_workspace_double_slash_relative_title")
            }
            PathCollectRewriteMode::PlainRelative => {
                i18n.text("dialog.path_collect_plain_relative_title")
            }
        })
        .unwrap_or_else(|| i18n.text("dialog.path_collect_absolute_title"));

    dialog
        .title(title)
        .width(px(720.0))
        .max_w(px(780.0))
        .overlay_closable(false)
        .on_cancel({
            let view = view.clone();
            move |_, _, cx| {
                view.update(cx, |shell, cx| shell.clear_path_collect_dialog_state(cx));
                true
            }
        })
        .footer({
            let view = view.clone();
            move |_, _, _, cx| {
                let shell = view.read(cx);
                let i18n = shell.i18n();
                let can_apply = shell.path_collect_dialog_can_apply(cx);
                vec![
                    Button::new("path-collect-cancel")
                        .label(i18n.text("action.cancel"))
                        .ghost()
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| {
                                    shell.clear_path_collect_dialog_state(cx);
                                });
                                window.close_dialog(cx);
                            }
                        })
                        .into_any_element(),
                    Button::new("path-collect-apply")
                        .label(i18n.text("action.apply"))
                        .disabled(!can_apply)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| {
                                    shell.apply_path_collect_dialog(window, cx);
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
                        .child(i18n.text("dialog.path_collect_hint")),
                )
                .when_some(dialog_state.as_ref(), |this, dialog_state| {
                    this.child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(MUTED))
                                    .child(i18n.text("label.folder")),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .child(
                                        div().flex_1().child(
                                            Input::new(&dialog_state.folder_input)
                                                .small()
                                                .cleanable(true),
                                        ),
                                    )
                                    .child(
                                        Button::new("path-collect-select-folder")
                                            .label(i18n.text("action.select_folder"))
                                            .small()
                                            .on_click({
                                                let view = view.clone();
                                                move |_, window, cx| {
                                                    view.update(cx, |shell, cx| {
                                                        shell
                                                            .select_path_collect_folder(window, cx);
                                                    });
                                                }
                                            }),
                                    ),
                            ),
                    )
                })
                .when_some(
                    dialog_state.as_ref().map(|state| {
                        scene_path_string(&path_collect_default_folder(&state.workspace_root))
                    }),
                    |this, default_folder| {
                        this.child(div().text_sm().text_color(rgb(MUTED)).child(i18n.format(
                            "dialog.path_collect_default_folder",
                            &[("path", default_folder)],
                        )))
                    },
                )
                .when(!can_apply, |this| {
                    this.child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x8a3a32))
                            .child(i18n.text("banner.path_collect_folder_invalid")),
                    )
                }),
        )
}
