use super::*;
use crate::persistence::{
    RemoveAllowlistEntryError, read_allowlist_document, remove_user_allowlist_entry,
};
use gpui_component::{ActiveTheme as _, tag::Tag, tooltip::Tooltip};

fn load_allowlist_manager_layer(
    path: Option<&Path>,
    source: AllowlistSource,
) -> AllowlistManagerLayer {
    AllowlistManagerLayer {
        path: path.map(Path::to_path_buf),
        document: path.map_or_else(
            || {
                Ok(UserAllowlistDocument {
                    version: 1,
                    entries: Vec::new(),
                })
            },
            |path| read_allowlist_document(path, source),
        ),
    }
}

impl GuiShell {
    pub(super) fn open_allowlist_manager_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.allowlist_manager.is_some() {
            if window.has_active_dialog(cx) {
                return;
            }
            self.allowlist_manager = None;
        }
        if window.has_active_dialog(cx) {
            return;
        }
        self.refresh_allowlist_manager_data(cx);
        let view = cx.entity();
        window.open_dialog(cx, move |dialog, window, cx| {
            build_allowlist_manager_dialog(dialog, view.clone(), window, cx)
        });
        cx.notify();
    }

    pub(super) fn clear_allowlist_manager_dialog_state(&mut self, cx: &mut Context<Self>) {
        self.allowlist_manager = None;
        cx.notify();
    }

    pub(super) fn refresh_allowlist_manager_data(&mut self, cx: &mut Context<Self>) {
        let selected = self
            .allowlist_manager
            .as_ref()
            .map_or(AllowlistManagerTab::User, |state| state.selected);
        self.allowlist_manager = Some(AllowlistManagerState {
            app: load_allowlist_manager_layer(
                self.app_allowlist_path.as_deref(),
                AllowlistSource::App,
            ),
            user: load_allowlist_manager_layer(
                self.user_allowlist_path.as_deref(),
                AllowlistSource::User,
            ),
            pending_remove: None,
            selected,
        });
        cx.notify();
    }

    fn select_allowlist_manager_tab(
        &mut self,
        selected: AllowlistManagerTab,
        cx: &mut Context<Self>,
    ) {
        if let Some(state) = self.allowlist_manager.as_mut()
            && state.selected != selected
        {
            state.selected = selected;
            state.pending_remove = None;
            cx.notify();
        }
    }

    fn open_allowlist_manager_folder(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(state) = &self.allowlist_manager else {
            return;
        };
        let layer = match state.selected {
            AllowlistManagerTab::User => &state.user,
            AllowlistManagerTab::App => &state.app,
        };
        let Some(path) = layer.path.clone() else {
            return;
        };
        let view = cx.entity();
        window
            .spawn(cx, move |cx: &mut AsyncWindowContext| {
                let executor = cx.background_executor().clone();
                let mut async_cx = cx.clone();
                async move {
                    let result =
                        executor
                            .spawn(async move {
                                path::reveal_allowlist_path_in_system_file_manager(&path)
                            })
                            .await;
                    let _ = async_cx.update_window_entity(
                        &view,
                        move |shell: &mut GuiShell, _, cx: &mut Context<GuiShell>| {
                            if let Err(error) = result {
                                shell.status_message = Some(BannerMessage::Raw(error));
                            }
                            cx.notify();
                        },
                    );
                }
            })
            .detach();
    }

    pub(super) fn begin_allowlist_entry_removal(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(state) = self.allowlist_manager.as_mut() else {
            return;
        };
        if state.user.path.is_none() {
            return;
        }
        let Ok(document) = &state.user.document else {
            return;
        };
        let Some(expected) = document.entries.get(index) else {
            return;
        };
        state.pending_remove = Some(PendingAllowlistRemoval {
            index,
            expected: expected.clone(),
        });
        cx.notify();
    }

    pub(super) fn cancel_allowlist_entry_removal(&mut self, cx: &mut Context<Self>) {
        if let Some(state) = self.allowlist_manager.as_mut() {
            state.pending_remove = None;
            cx.notify();
        }
    }

    pub(super) fn confirm_allowlist_entry_removal(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.audit_allow_in_flight {
            return;
        }
        let Some(state) = &self.allowlist_manager else {
            return;
        };
        let Some(pending) = &state.pending_remove else {
            return;
        };
        let Some(path) = state.user.path.clone() else {
            return;
        };
        if state.user.document.is_err() {
            return;
        }
        let label = pending.expected.label.clone().unwrap_or_else(|| "-".into());
        let result = remove_user_allowlist_entry(&path, pending.index, &pending.expected);
        self.reload_allowlists(window, cx);
        self.refresh_allowlist_manager_data(cx);
        self.status_message = Some(match result {
            Ok(()) => BannerMessage::AllowlistRemoved { label },
            Err(RemoveAllowlistEntryError::FileChanged) => BannerMessage::AllowlistFileChanged,
            Err(RemoveAllowlistEntryError::Read(error)) => {
                BannerMessage::AllowlistReadFailed { path, error }
            }
            Err(RemoveAllowlistEntryError::Write(error)) => {
                BannerMessage::AllowlistWriteFailed { path, error }
            }
        });
        cx.notify();
    }
}

fn build_allowlist_manager_dialog(
    dialog: Dialog,
    view: Entity<GuiShell>,
    window: &mut Window,
    cx: &mut App,
) -> Dialog {
    let shell = view.read(cx);
    let i18n = shell.i18n();
    let state = shell.allowlist_manager.clone();
    let paddings = gpui_component::window_paddings(window);
    let viewport = window.viewport_size()
        - size(
            paddings.left + paddings.right,
            paddings.top + paddings.bottom,
        );
    let max_height = (viewport.height * 0.70).max(px(0.0));
    let list_max = (max_height - px(160.0)).max(px(0.0));
    dialog
        .title(i18n.text("dialog.allowlist_manager_title"))
        .width(px(720.0))
        .max_w(px(780.0))
        .max_h(max_height)
        .overlay_closable(false)
        .on_ok({
            let view = view.clone();
            move |_, _, cx| {
                view.update(cx, |shell, cx| {
                    shell.clear_allowlist_manager_dialog_state(cx)
                });
                true
            }
        })
        .on_cancel({
            let view = view.clone();
            move |_, _, cx| {
                view.update(cx, |shell, cx| {
                    shell.clear_allowlist_manager_dialog_state(cx)
                });
                true
            }
        })
        .footer({
            let view = view.clone();
            move |_, _, _, cx| {
                vec![
                    Button::new("allowlist-manager-close")
                        .debug_selector(|| "allowlist-manager-close".into())
                        .label(view.read(cx).i18n().text("action.close"))
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| {
                                view.update(cx, |shell, cx| {
                                    shell.clear_allowlist_manager_dialog_state(cx)
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
                .id("allowlist-manager")
                .debug_selector(|| "allowlist-manager".into())
                .w_full()
                .flex()
                .flex_col()
                .gap_2()
                .when_some(state.as_ref(), |this, state| {
                    let tab_view = view.clone();
                    let (layer, source, selected_index) = match state.selected {
                        AllowlistManagerTab::User => (&state.user, AllowlistSource::User, 0),
                        AllowlistManagerTab::App => (&state.app, AllowlistSource::App, 1),
                    };
                    this.child(
                        TabBar::new("allowlist-manager-tabs")
                            .underline()
                            .flex_shrink_0()
                            .selected_index(selected_index)
                            .on_click(move |index, _, cx| {
                                let tab = match index {
                                    0 => AllowlistManagerTab::User,
                                    1 => AllowlistManagerTab::App,
                                    _ => return,
                                };
                                tab_view.update(cx, |shell, cx| {
                                    shell.select_allowlist_manager_tab(tab, cx)
                                });
                            })
                            .children([
                                Tab::new()
                                    .debug_selector(|| "allowlist-manager-tab-user".into())
                                    .child(div().id("allowlist-manager-tab-user").child(
                                        allowlist_manager_tab_label(
                                            &state.user,
                                            AllowlistSource::User,
                                            &i18n,
                                        ),
                                    )),
                                Tab::new()
                                    .debug_selector(|| "allowlist-manager-tab-app".into())
                                    .child(div().id("allowlist-manager-tab-app").child(
                                        allowlist_manager_tab_label(
                                            &state.app,
                                            AllowlistSource::App,
                                            &i18n,
                                        ),
                                    )),
                            ]),
                    )
                    .child(render_allowlist_manager_section(
                        layer,
                        source,
                        state,
                        view.clone(),
                        &i18n,
                        cx,
                        list_max,
                    ))
                }),
        )
}

fn allowlist_manager_tab_label(
    layer: &AllowlistManagerLayer,
    source: AllowlistSource,
    i18n: &I18n,
) -> String {
    let title = i18n.text(match source {
        AllowlistSource::App => "allowlist_manager.app",
        AllowlistSource::User => "allowlist_manager.user",
    });
    if layer.path.is_none() {
        return format!("{title} 0");
    }
    match &layer.document {
        Ok(document) => format!("{title} {}", document.entries.len()),
        Err(_) => title,
    }
}

fn allowlist_manager_path_text(layer: &AllowlistManagerLayer, i18n: &I18n) -> String {
    layer
        .path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| i18n.text("allowlist_manager.path_unavailable"))
}

fn allowlist_manager_error_text(layer: &AllowlistManagerLayer, i18n: &I18n) -> Option<String> {
    layer
        .document
        .as_ref()
        .err()
        .map(|error| format!("{}\n{error}", allowlist_manager_path_text(layer, i18n)))
}

fn render_allowlist_manager_section(
    layer: &AllowlistManagerLayer,
    source: AllowlistSource,
    state: &AllowlistManagerState,
    view: Entity<GuiShell>,
    i18n: &I18n,
    cx: &App,
    list_max: Pixels,
) -> AnyElement {
    let name = match source {
        AllowlistSource::App => "app",
        AllowlistSource::User => "user",
    };
    let id = format!("allowlist-{name}-section");
    let path_text = allowlist_manager_path_text(layer, i18n);
    let tooltip_text = path_text.clone();
    let header = div()
        .flex()
        .flex_shrink_0()
        .items_center()
        .gap_2()
        .child(
            div()
                .id("allowlist-manager-path")
                .flex_1()
                .min_w_0()
                .text_sm()
                .text_color(rgb(MUTED))
                .truncate()
                .tooltip(move |window, cx| Tooltip::new(tooltip_text.clone()).build(window, cx))
                .child(path_text),
        )
        .when(layer.path.is_some(), |this| {
            let view = view.clone();
            this.child(
                Button::new("allowlist-manager-open-folder")
                    .debug_selector(|| "allowlist-manager-open-folder".into())
                    .small()
                    .flex_shrink_0()
                    .label(i18n.text("allowlist_manager.open_folder"))
                    .on_click(move |_, window, cx| {
                        view.update(cx, |shell, cx| {
                            shell.open_allowlist_manager_folder(window, cx)
                        })
                    }),
            )
        });
    let mut list = div()
        .id("allowlist-manager-list")
        .debug_selector(|| "allowlist-manager-list".into())
        .max_h(list_max)
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .gap_3();
    if let Some(error) = allowlist_manager_error_text(layer, i18n) {
        let id = format!("allowlist-{name}-error");
        list = list.child(
            div()
                .id(SharedString::from(id.clone()))
                .debug_selector(move || id.clone())
                .flex()
                .items_start()
                .gap_2()
                .flex_shrink_0()
                .rounded_md()
                .p_3()
                .bg(rgb(ERROR_SOFT))
                .text_color(rgb(TEXT))
                .child(Icon::new(IconName::TriangleAlert).small())
                .child(div().child(error)),
        );
    } else if let Ok(document) = &layer.document {
        if document.entries.is_empty() {
            let id = format!("allowlist-{name}-empty");
            let key = match source {
                AllowlistSource::User => "allowlist_manager.empty_user",
                AllowlistSource::App => "allowlist_manager.empty",
            };
            list = list.child(
                div()
                    .id(SharedString::from(id.clone()))
                    .debug_selector(move || id.clone())
                    .flex()
                    .flex_shrink_0()
                    .items_center()
                    .justify_center()
                    .text_color(rgb(MUTED))
                    .child(i18n.text(key)),
            );
        }
        for (index, entry) in document.entries.iter().enumerate() {
            list = list.child(render_allowlist_manager_entry(
                entry,
                index,
                source,
                state,
                view.clone(),
                i18n,
                cx,
            ));
        }
    }
    div()
        .id(SharedString::from(id.clone()))
        .debug_selector(move || id.clone())
        .flex()
        .flex_col()
        .gap_2()
        .child(header)
        .when(source == AllowlistSource::App, |this| {
            this.child(
                div()
                    .flex_shrink_0()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child(i18n.text("allowlist_manager.read_only")),
            )
        })
        .child(list)
        .into_any_element()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AllowlistManagerEntryPresentation {
    node: String,
    attribute: Option<String>,
    codes: Vec<(String, bool)>,
    reason: Option<String>,
    preview: Option<String>,
    metadata: Vec<String>,
    short_hash: String,
    full_hash: String,
}

fn allowlist_manager_entry_presentation(
    entry: &UserAllowlistEntry,
    source: AllowlistSource,
    state: &AllowlistManagerState,
    i18n: &I18n,
) -> AllowlistManagerEntryPresentation {
    let label = entry.label.as_deref().unwrap_or("-");
    let (node, attribute) = label
        .split_once(' ')
        .map_or((label.to_owned(), None), |(node, attribute)| {
            (node.to_owned(), Some(attribute.to_owned()))
        });
    let codes = entry
        .codes
        .iter()
        .map(|code| {
            let also_app = source == AllowlistSource::User
                && state.app.path.is_some()
                && state.app.document.as_ref().is_ok_and(|app| {
                    app.entries
                        .iter()
                        .any(|app| app.hash == entry.hash && app.codes.contains(code))
                });
            (code.clone(), also_app)
        })
        .collect();
    let metadata = entry
        .added_at
        .as_ref()
        .map(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .map(|time| i18n.format_timestamp(time.with_timezone(&Local)))
                .unwrap_or_else(|_| value.clone())
        })
        .into_iter()
        .chain(entry.added_by.clone())
        .collect();
    let full_hash = entry.hash.to_string();
    let short_hash = format!("{}…", &full_hash["sha256:".len().."sha256:".len() + 8]);
    AllowlistManagerEntryPresentation {
        node,
        attribute,
        codes,
        reason: entry
            .reason
            .as_ref()
            .map(|reason| i18n.format("allowlist_manager.reason", &[("reason", reason.clone())])),
        preview: entry.preview.as_ref().map(|preview| {
            preview
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(120)
                .collect()
        }),
        metadata,
        short_hash,
        full_hash,
    }
}

fn allowlist_manager_entry_footer_text(presentation: &AllowlistManagerEntryPresentation) -> String {
    presentation
        .metadata
        .iter()
        .chain(std::iter::once(&presentation.short_hash))
        .cloned()
        .collect::<Vec<_>>()
        .join(" · ")
}

fn allowlist_manager_entry_is_pending(
    state: &AllowlistManagerState,
    source: AllowlistSource,
    index: usize,
) -> bool {
    source == AllowlistSource::User
        && state
            .pending_remove
            .as_ref()
            .is_some_and(|pending| pending.index == index)
}

fn render_allowlist_manager_entry(
    entry: &UserAllowlistEntry,
    index: usize,
    source: AllowlistSource,
    state: &AllowlistManagerState,
    view: Entity<GuiShell>,
    i18n: &I18n,
    cx: &App,
) -> AnyElement {
    let name = match source {
        AllowlistSource::App => "app",
        AllowlistSource::User => "user",
    };
    let id = format!("allowlist-{name}-entry-{index}");
    let presentation = allowlist_manager_entry_presentation(entry, source, state, i18n);
    let pending = allowlist_manager_entry_is_pending(state, source, index);
    let mut metadata_text = allowlist_manager_entry_footer_text(&presentation);
    metadata_text.truncate(metadata_text.len() - presentation.short_hash.len());
    let full_hash = presentation.full_hash.clone();
    let copy_id = format!("allowlist-{name}-copy-hash-{index}");
    let row_one = div()
        .flex()
        .items_center()
        .justify_between()
        .gap_2()
        .child(
            div()
                .flex()
                .flex_1()
                .items_baseline()
                .gap_1()
                .min_w_0()
                .overflow_hidden()
                .truncate()
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(TEXT))
                        .whitespace_nowrap()
                        .child(presentation.node),
                )
                .children(presentation.attribute.map(|attribute| {
                    div()
                        .text_color(rgb(MUTED))
                        .whitespace_nowrap()
                        .child(attribute)
                })),
        )
        .when(source == AllowlistSource::User && !pending, |this| {
            this.child(div().flex_shrink_0().child(AllowlistRemovalControls {
                view: view.clone(),
                index,
                pending,
            }))
        });
    div()
        .id(SharedString::from(id.clone()))
        .debug_selector(move || id.clone())
        .flex()
        .flex_col()
        .flex_shrink_0()
        .gap_2()
        .p_3()
        .rounded_md()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL_BG))
        .min_w_0()
        .when(pending, |this| {
            this.bg(rgb(ERROR_SOFT)).border_color(cx.theme().danger)
        })
        .child(row_one)
        .when(pending, |this| {
            this.child(div().child(i18n.text("allowlist_manager.remove_warning")))
                .child(AllowlistRemovalControls {
                    view: view.clone(),
                    index,
                    pending,
                })
        })
        .child(
            div().flex().flex_wrap().gap_1().children(
                presentation
                    .codes
                    .into_iter()
                    .enumerate()
                    .map(|(n, (code, also_app))| {
                        let code_id = format!("allowlist-{name}-code-{index}-{n}");
                        let marker_id = format!("allowlist-{name}-also-app-{index}-{n}");
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .child(
                                div().debug_selector(move || code_id.clone()).child(
                                    Tag::custom(
                                        rgb(PANEL_BG).into(),
                                        rgb(TEXT).into(),
                                        rgb(BORDER).into(),
                                    )
                                    .small()
                                    .outline()
                                    .child(code),
                                ),
                            )
                            .when(also_app, |this| {
                                this.child(
                                    div().debug_selector(move || marker_id.clone()).child(
                                        Tag::custom(
                                            rgb(ACCENT_SOFT).into(),
                                            rgb(ACCENT).into(),
                                            rgb(ACCENT).into(),
                                        )
                                        .small()
                                        .outline()
                                        .child(i18n.text("allowlist_manager.also_app_tag")),
                                    ),
                                )
                            })
                    }),
            ),
        )
        .children(
            presentation
                .reason
                .map(|reason| div().text_color(rgb(TEXT)).child(reason)),
        )
        .children(presentation.preview.map(|preview| {
            // Text truncation caches its first measurement, so the line must sit in a row
            // where the measured width is the final one.
            div()
                .flex()
                .bg(rgb(PANEL_ALT_BG))
                .rounded_md()
                .px_2()
                .py_1()
                .min_w_0()
                .child(div().flex_1().min_w_0().truncate().child(preview))
        }))
        .child(
            div()
                .flex()
                .items_center()
                .gap_1()
                .text_sm()
                .text_color(rgb(MUTED))
                .min_w_0()
                .whitespace_nowrap()
                .overflow_hidden()
                .when(!metadata_text.is_empty(), |this| {
                    this.child(
                        div()
                            .min_w_0()
                            .truncate()
                            .whitespace_nowrap()
                            .child(metadata_text),
                    )
                })
                .child(
                    div()
                        .id(SharedString::from(format!("allowlist-{name}-hash-{index}")))
                        .flex_shrink_0()
                        .whitespace_nowrap()
                        .tooltip(move |window, cx| {
                            Tooltip::new(full_hash.clone()).build(window, cx)
                        })
                        .child(presentation.short_hash),
                )
                .child(
                    Button::new(SharedString::from(copy_id.clone()))
                        .debug_selector(move || copy_id.clone())
                        .small()
                        .ghost()
                        .flex_shrink_0()
                        .icon(IconName::Copy)
                        .tooltip(i18n.text("allowlist_manager.copy_hash"))
                        .on_click(move |_, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(
                                presentation.full_hash.clone(),
                            ));
                        }),
                ),
        )
        .into_any_element()
}

#[derive(IntoElement)]
struct AllowlistRemovalControls {
    view: Entity<GuiShell>,
    index: usize,
    pending: bool,
}

impl RenderOnce for AllowlistRemovalControls {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let shell = self.view.read(cx);
        let i18n = shell.i18n();
        let busy = shell.audit_allow_in_flight;
        let mut buttons = div().flex().items_center().gap_2();
        for action in if self.pending {
            &["confirm", "cancel"][..]
        } else {
            &["remove"][..]
        } {
            let action = *action;
            let index = self.index;
            let id = format!("allowlist-user-{action}-{index}");
            let view = self.view.clone();
            let key = match action {
                "confirm" => "allowlist_manager.confirm_remove",
                "cancel" => "action.cancel",
                _ => "action.remove",
            };
            buttons = buttons.child(
                Button::new(SharedString::from(id.clone()))
                    .debug_selector(move || id.clone())
                    .small()
                    .when(action == "remove", |this| this.danger().outline())
                    .when(action == "confirm", |this| this.danger())
                    .label(i18n.text(key))
                    .disabled(action == "confirm" && busy)
                    .on_click(move |_, window, cx| {
                        view.update(cx, |shell, cx| match action {
                            "confirm" => shell.confirm_allowlist_entry_removal(window, cx),
                            "cancel" => shell.cancel_allowlist_entry_removal(cx),
                            _ => shell.begin_allowlist_entry_removal(index, cx),
                        });
                    }),
            );
            if action == "confirm" && busy {
                let id = format!("allowlist-user-busy-{index}");
                buttons = buttons.child(
                    div()
                        .debug_selector(move || id.clone())
                        .text_sm()
                        .text_color(rgb(MUTED))
                        .child(i18n.text("allowlist_manager.busy")),
                );
            }
        }
        buttons
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::test;

    use super::*;
    use maya_scene_kit_audit::scene::{AuditDisposition, AuditFindingCode};
    use std::{cell::RefCell, rc::Rc};
    use tempfile::tempdir;
    const A0: &str = concat!(
        r#"{"hash":"sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20","#,
        r#""codes":["mel_exec"],"#,
        r#""label":"ExampleApp"}"#,
    );
    const A1: &str = concat!(
        r#"{"hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
        r#""codes":["mel_python"],"#,
        r#""label":"Sample"}"#,
    );
    const U0: &str = concat!(
        r#"{"hash":"sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20","#,
        r#""codes":["mel_exec","#,
        r#""mel_python"],"#,
        r#""label":"ExampleScriptNode","#,
        r#""preview":"Example preview\nSample preview","#,
        r#""reason":"Example reason","#,
        r#""added_at":"2026-11-07T09:30:00Z","#,
        r#""added_by":"Example"}"#,
    );
    const U1: &str = concat!(
        r#"{"hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","#,
        r#""codes":["mel_eval"]}"#,
    );
    const OTHER_HASH: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const E0: &str = "{\n  \"version\": 1,\n  \"entries\": []\n}\n";
    fn document_json(records: &[&str]) -> String {
        format!("{{\"version\":1,\"entries\":[{}]}}\n", records.join(","))
    }
    const SCENE: &str = concat!(
        "//Maya ASCII 2026 scene\n",
        "requires maya \"2026\";\n",
        "createNode script -n \"ExampleScriptNode\";\n",
        "\tsetAttr \".b\" -type \"string\" \"exec \\\"Example\\\"\";\n",
        "\tsetAttr \".st\" 1;\n",
    );
    const HASH: &str = "sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20";
    fn current_row(path: &Path, plan: &ScriptAuditPlan) -> SceneRow {
        let RowJobResult::Analyze(result) = analyze_row_with_options(
            path,
            AuditModePreference::StrictDefault,
            &LoadOptions::default(),
            plan,
        )
        .unwrap() else {
            panic!("expected analysis");
        };
        let mut row = SceneRow::from_path(1, path.to_path_buf()).unwrap();
        row.set_audit_report(Some(result.audit_report), result.audit_file_state);
        row.audit_plan_fingerprint = Some(result.audit_plan_fingerprint);
        row.paths_report = result.paths_report;
        row.dump_report = result.dump_report;
        row.analyzed_audit_mode = Some(result.audit_mode);
        row.status = FileStatus::Audited;
        row.selected = true;
        row.sync_findings_count();
        row
    }

    fn open_shell<'a>(
        cx: &'a mut TestAppContext,
        dir: &Path,
        user_path: &Path,
    ) -> (Entity<GuiShell>, &'a mut VisualTestContext) {
        cx.update(init_gui_app);
        let slot = Rc::new(RefCell::new(None));
        let built = slot.clone();
        let (_, visual_cx) = cx.add_window_view(|window, cx| {
            let menu_bar = TopMenuBar::new(window, cx);
            let shell = cx.new(|cx| {
                GuiShell::new_with_state_and_cache_root(
                    menu_bar,
                    window,
                    cx,
                    PersistedState {
                        locale: crate::model::LocalePreference::English,
                        analysis_cache_enabled: false,
                        ..PersistedState::default()
                    },
                    dir.join("ExampleCache"),
                    None,
                    Some(dir.join("ExampleApp/allowlist.json")),
                    Some(user_path.to_path_buf()),
                )
            });
            built.replace(Some(shell.clone()));
            Root::new(shell, window, cx)
        });
        let shell = slot.borrow().clone().unwrap();
        (shell, visual_cx)
    }

    fn write_document(path: &Path, records: &[&str]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, document_json(records)).unwrap();
    }

    fn click(visual_cx: &mut VisualTestContext, selector: &'static str) {
        let list = visual_cx.debug_bounds("allowlist-manager-list").unwrap();
        let bounds = visual_cx.debug_bounds(selector).expect(selector);
        if !list.contains(&bounds.center())
            && (selector.starts_with("allowlist-user-") || selector.starts_with("allowlist-app-"))
        {
            visual_cx.simulate_event(ScrollWheelEvent {
                position: list.center(),
                delta: ScrollDelta::Pixels(point(px(0.0), list.center().y - bounds.center().y)),
                modifiers: Modifiers::default(),
                touch_phase: TouchPhase::Moved,
            });
        }
        let bounds = visual_cx.debug_bounds(selector).expect(selector);
        visual_cx.simulate_click(bounds.center(), Modifiers::default());
    }

    fn assert_confirmation_controls(
        shell: &Entity<GuiShell>,
        visual_cx: &mut VisualTestContext,
        dir: &Path,
        user: &Path,
        pending: Option<usize>,
    ) {
        let (state, busy) = shell.update_in(visual_cx, |shell, _, _| {
            (shell.allowlist_manager.clone(), shell.audit_allow_in_flight)
        });
        // GPUI retains debug bounds between frames; inspect absence in a fresh window.
        let (snapshot, snapshot_cx) = open_shell(visual_cx, dir, user);
        snapshot.update_in(snapshot_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            shell.allowlist_manager = state;
            shell.audit_allow_in_flight = busy;
            cx.notify();
        });
        for (index, remove, confirm, cancel, busy_note) in [
            (
                0,
                "allowlist-user-remove-0",
                "allowlist-user-confirm-0",
                "allowlist-user-cancel-0",
                "allowlist-user-busy-0",
            ),
            (
                1,
                "allowlist-user-remove-1",
                "allowlist-user-confirm-1",
                "allowlist-user-cancel-1",
                "allowlist-user-busy-1",
            ),
        ] {
            assert_eq!(
                snapshot_cx.debug_bounds(remove).is_some(),
                pending != Some(index)
            );
            assert_eq!(
                snapshot_cx.debug_bounds(confirm).is_some(),
                pending == Some(index)
            );
            assert_eq!(
                snapshot_cx.debug_bounds(cancel).is_some(),
                pending == Some(index)
            );
            assert_eq!(
                snapshot_cx.debug_bounds(busy_note).is_some(),
                busy && pending == Some(index)
            );
        }
    }

    #[gpui::test]
    fn allowlist_manager_opens_from_menu_and_displays_layers(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let app = dir.path().join("ExampleApp/allowlist.json");
        let user = dir.path().join("ExampleUser/allowlist.json");
        write_document(&app, &[A0, A1]);
        write_document(&user, &[U0, U1]);
        let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
        shell.update_in(visual_cx, |shell, window, cx| {
            let fingerprint = shell.audit_plan_fingerprint.clone();
            let plan = shell.audit_plan.clone();
            let banner = shell
                .status_message
                .as_ref()
                .map(|message| render_banner_message(&shell.i18n(), message));
            shell.on_menu_manage_allowlists(&MenuManageAllowlists, window, cx);
            assert_eq!(shell.audit_plan_fingerprint, fingerprint);
            assert!(Arc::ptr_eq(&shell.audit_plan, &plan));
            assert_eq!(
                shell
                    .status_message
                    .as_ref()
                    .map(|message| render_banner_message(&shell.i18n(), message)),
                banner
            );
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert_eq!(
                allowlist_manager_tab_label(&state.app, AllowlistSource::App, &shell.i18n()),
                "App 2"
            );
            assert_eq!(
                allowlist_manager_path_text(&state.app, &shell.i18n()),
                app.display().to_string()
            );
            assert_eq!(
                shell.i18n().text("allowlist_manager.read_only"),
                "Read-only. Distributed with the application."
            );
            assert_eq!(
                allowlist_manager_tab_label(&state.user, AllowlistSource::User, &shell.i18n()),
                "User 2"
            );
            assert_eq!(
                allowlist_manager_path_text(&state.user, &shell.i18n()),
                user.display().to_string()
            );
            for (layer, source, labels) in [
                (&state.app, AllowlistSource::App, ["ExampleApp", "Sample"]),
                (
                    &state.user,
                    AllowlistSource::User,
                    ["ExampleScriptNode", "-"],
                ),
            ] {
                let document = layer.document.as_ref().unwrap();
                assert_eq!(
                    document
                        .entries
                        .iter()
                        .map(|entry| allowlist_manager_entry_presentation(
                            entry,
                            source,
                            state,
                            &shell.i18n()
                        )
                        .node)
                        .collect::<Vec<_>>(),
                    labels
                );
            }
            let user_entries = &state.user.document.as_ref().unwrap().entries;
            let local_time = shell.i18n().format_timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-11-07T09:30:00Z")
                    .unwrap()
                    .with_timezone(&Local),
            );
            assert_eq!(
                allowlist_manager_entry_presentation(
                    &user_entries[0],
                    AllowlistSource::User,
                    state,
                    &shell.i18n()
                ),
                AllowlistManagerEntryPresentation {
                    node: "ExampleScriptNode".into(),
                    attribute: None,
                    codes: vec![("mel_exec".into(), true), ("mel_python".into(), false)],
                    reason: Some("Reason: Example reason".into()),
                    preview: Some("Example preview".into()),
                    metadata: vec![local_time, "Example".into()],
                    short_hash: "79a04cad…".into(),
                    full_hash: HASH.into(),
                }
            );
            assert_eq!(
                allowlist_manager_entry_presentation(
                    &user_entries[1],
                    AllowlistSource::User,
                    state,
                    &shell.i18n()
                ),
                AllowlistManagerEntryPresentation {
                    node: "-".into(),
                    attribute: None,
                    codes: vec![("mel_eval".into(), false)],
                    reason: None,
                    preview: None,
                    metadata: vec![],
                    short_hash: "11111111…".into(),
                    full_hash: OTHER_HASH.into(),
                }
            );
            for (locale, expected) in [
                (SupportedLocale::Japanese, "App にも登録"),
                (SupportedLocale::Chinese, "App 中也有"),
            ] {
                let i18n = I18n::new(locale);
                assert_eq!(
                    allowlist_manager_entry_presentation(
                        &user_entries[0],
                        AllowlistSource::User,
                        state,
                        &i18n
                    )
                    .codes,
                    vec![("mel_exec".into(), true), ("mel_python".into(), false)]
                );
                assert_eq!(i18n.text("allowlist_manager.also_app_tag"), expected);
            }
            let menus = build_app_menus(&shell.state, &shell.i18n(), false, false);
            let settings = menus
                .into_iter()
                .map(|menu| menu.owned())
                .find(|menu| menu.name == shell.i18n().text("menu.settings"))
                .unwrap();
            let find_action = |id| {
                settings
                    .items
                    .iter()
                    .position(|item| match item {
                        OwnedMenuItem::Action { action, .. } => action.as_any().type_id() == id,
                        _ => false,
                    })
                    .unwrap()
            };
            let reload = find_action(std::any::TypeId::of::<MenuReloadAllowlists>());
            let manage = find_action(std::any::TypeId::of::<MenuManageAllowlists>());
            let max_bytes = find_action(std::any::TypeId::of::<MenuEditMaxBytes>());
            assert_eq!((manage, max_bytes), (reload + 1, reload + 2));
            let OwnedMenuItem::Action { name, .. } = &settings.items[manage] else {
                panic!("expected Manage action");
            };
            assert_eq!(name, &shell.i18n().text("settings.manage_allowlists"));
            shell.begin_allowlist_entry_removal(0, cx);
            let pending = shell
                .allowlist_manager
                .as_ref()
                .unwrap()
                .pending_remove
                .clone();
            shell.open_allowlist_manager_dialog(window, cx);
            assert_eq!(
                shell.allowlist_manager.as_ref().unwrap().pending_remove,
                pending
            );
            assert_eq!(
                shell
                    .allowlist_manager
                    .as_ref()
                    .unwrap()
                    .user
                    .document
                    .as_ref()
                    .unwrap()
                    .entries
                    .len(),
                2
            );
        });
        assert!(
            visual_cx
                .debug_bounds("allowlist-manager-tab-user")
                .unwrap()
                .left()
                < visual_cx
                    .debug_bounds("allowlist-manager-tab-app")
                    .unwrap()
                    .left()
        );
        assert!(
            visual_cx
                .debug_bounds("allowlist-user-entry-0")
                .unwrap()
                .top()
                < visual_cx
                    .debug_bounds("allowlist-user-entry-1")
                    .unwrap()
                    .top()
        );
        click(visual_cx, "allowlist-manager-tab-app");
        assert!(
            visual_cx
                .debug_bounds("allowlist-app-entry-0")
                .unwrap()
                .top()
                < visual_cx
                    .debug_bounds("allowlist-app-entry-1")
                    .unwrap()
                    .top()
        );
        for selector in [
            "allowlist-app-remove-0",
            "allowlist-app-confirm-0",
            "allowlist-app-cancel-0",
            "allowlist-app-remove-1",
        ] {
            assert!(visual_cx.debug_bounds(selector).is_none());
        }
        click(visual_cx, "allowlist-manager-tab-user");
        shell.update_in(visual_cx, |shell, _, cx| {
            shell.cancel_allowlist_entry_removal(cx)
        });
        assert!(visual_cx.debug_bounds("allowlist-user-remove-0").is_some());
        assert!(visual_cx.debug_bounds("allowlist-user-remove-1").is_some());
        click(visual_cx, "allowlist-manager-close");
        shell.update_in(visual_cx, |shell, _, _| {
            assert!(shell.allowlist_manager.is_none())
        });
        let long = U0.replace(
            "Example preview\\nSample preview",
            &("例".repeat(121) + "\\nSample"),
        );
        write_document(&user, &[&long, U1]);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            let state = shell.allowlist_manager.as_ref().unwrap();
            let entry = &state.user.document.as_ref().unwrap().entries[0];
            assert_eq!(
                allowlist_manager_entry_presentation(
                    entry,
                    AllowlistSource::User,
                    state,
                    &shell.i18n()
                )
                .preview,
                Some("例".repeat(120))
            );
        });
        click(visual_cx, "allowlist-manager-close");
        fs::write(&user, "{").unwrap();
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert!(state.user.document.is_err());
            assert_eq!(
                allowlist_manager_tab_label(&state.user, AllowlistSource::User, &shell.i18n()),
                "User"
            );
            assert_eq!(
                allowlist_manager_path_text(&state.user, &shell.i18n()),
                user.display().to_string()
            );
            assert_eq!(state.app.document.as_ref().unwrap().entries.len(), 2);
        });
        assert!(visual_cx.debug_bounds("allowlist-user-error").is_some());
        let (snapshot, snapshot_cx) = open_shell(visual_cx, dir.path(), &user);
        snapshot.update_in(snapshot_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx)
        });
        assert!(snapshot_cx.debug_bounds("allowlist-user-error").is_some());
        assert!(
            snapshot_cx
                .debug_bounds("allowlist-user-remove-0")
                .is_none()
        );
        assert!(
            snapshot_cx
                .debug_bounds("allowlist-user-confirm-0")
                .is_none()
        );
        snapshot_cx.simulate_keystrokes("escape");
        snapshot.update_in(snapshot_cx, |shell, window, cx| {
            assert!(shell.allowlist_manager.is_none());
            assert!(!window.has_active_dialog(cx));
            shell.open_allowlist_manager_dialog(window, cx);
            assert!(window.has_active_dialog(cx));
        });
        snapshot_cx.run_until_parked();
        snapshot_cx.simulate_keystrokes("enter");
        snapshot.update_in(snapshot_cx, |shell, window, cx| {
            assert!(shell.allowlist_manager.is_none());
            assert!(!window.has_active_dialog(cx));
        });
        fs::write(&app, "{").unwrap();
        write_document(&user, &[U0, U1]);
        snapshot.update_in(snapshot_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert!(state.app.document.is_err());
            assert_eq!(
                allowlist_manager_tab_label(&state.app, AllowlistSource::App, &shell.i18n()),
                "App"
            );
            assert_eq!(
                allowlist_manager_path_text(&state.app, &shell.i18n()),
                app.display().to_string()
            );
            let entry = &state.user.document.as_ref().unwrap().entries[0];
            assert_eq!(
                allowlist_manager_entry_presentation(
                    entry,
                    AllowlistSource::User,
                    state,
                    &shell.i18n()
                )
                .codes,
                vec![("mel_exec".into(), false), ("mel_python".into(), false)]
            );
        });
        click(snapshot_cx, "allowlist-manager-tab-app");
        assert!(snapshot_cx.debug_bounds("allowlist-app-error").is_some());
    }

    #[gpui::test]
    fn allowlist_manager_confirmation_is_inline(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let user = dir.path().join("ExampleUser/allowlist.json");
        let input = document_json(&[U0, U1]);
        write_document(&user, &[U0, U1]);
        let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx)
        });
        for (selector, pending, record) in [
            ("allowlist-user-remove-0", Some(0), Some(U0)),
            ("allowlist-user-remove-1", Some(1), Some(U1)),
            ("allowlist-user-cancel-1", None, None),
        ] {
            click(visual_cx, selector);
            if pending == Some(0) {
                assert!(visual_cx.debug_bounds("allowlist-user-confirm-0").is_some());
            }
            shell.update_in(visual_cx, |shell, _, _| {
                assert_eq!(
                    shell.allowlist_manager.as_ref().unwrap().pending_remove,
                    pending.map(|index| PendingAllowlistRemoval {
                        index,
                        expected: serde_json::from_str(record.unwrap()).unwrap()
                    })
                );
            });
            assert_eq!(fs::read(&user).unwrap(), input.as_bytes());
            assert_confirmation_controls(&shell, visual_cx, dir.path(), &user, pending);
        }
        click(visual_cx, "allowlist-user-remove-0");
        let (plan, banner, pending) = shell.update_in(visual_cx, |shell, _, cx| {
            shell.audit_allow_in_flight = true;
            cx.notify();
            (
                shell.audit_plan.clone(),
                shell
                    .status_message
                    .as_ref()
                    .map(|message| render_banner_message(&shell.i18n(), message)),
                shell
                    .allowlist_manager
                    .as_ref()
                    .unwrap()
                    .pending_remove
                    .clone(),
            )
        });
        click(visual_cx, "allowlist-user-confirm-0");
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.confirm_allowlist_entry_removal(window, cx);
            assert_eq!(
                shell.allowlist_manager.as_ref().unwrap().pending_remove,
                pending
            );
            assert!(Arc::ptr_eq(&shell.audit_plan, &plan));
            assert_eq!(
                shell
                    .status_message
                    .as_ref()
                    .map(|message| render_banner_message(&shell.i18n(), message)),
                banner
            );
            assert_eq!(fs::read(&user).unwrap(), input.as_bytes());
            shell.audit_allow_in_flight = false;
            cx.notify();
        });
        click(visual_cx, "allowlist-user-confirm-0");
        shell.update_in(visual_cx, |shell, _, _| {
            assert!(matches!(
                shell.status_message,
                Some(BannerMessage::AllowlistRemoved { .. })
            ))
        });
        let key = AuditResultRowKey {
            row_id: 1,
            item_kind: AuditResultItemKind::Finding,
            item_index: 0,
        };
        for result in [
            Ok(1),
            Err(AllowAddError::WriteFailed {
                path: user.clone(),
                error: "Example error".into(),
            }),
        ] {
            write_document(&user, &[U0]);
            shell.update_in(visual_cx, |shell, _, cx| {
                shell.refresh_allowlist_manager_data(cx);
                shell.begin_allowlist_entry_removal(0, cx);
            });
            write_document(&user, &[U1]);
            shell.update_in(visual_cx, |shell, window, cx| {
                let plan = shell.audit_plan.clone();
                shell.apply_audit_allow_result(&key, 1, result.clone(), window, cx);
                assert!(!Arc::ptr_eq(&shell.audit_plan, &plan));
                let state = shell.allowlist_manager.as_ref().unwrap();
                assert!(state.pending_remove.is_none());
                assert_eq!(
                    state.user.document.as_ref().unwrap().entries,
                    vec![serde_json::from_str::<UserAllowlistEntry>(U1).unwrap()]
                );
                assert!(match result {
                    Ok(_) => matches!(
                        shell.status_message,
                        Some(BannerMessage::AllowlistAdded { count: 1 })
                    ),
                    Err(_) => matches!(
                        shell.status_message,
                        Some(BannerMessage::AllowlistWriteFailed { .. })
                    ),
                });
            });
        }
        write_document(&user, &[U0]);
        shell.update_in(visual_cx, |shell, _, cx| {
            shell.refresh_allowlist_manager_data(cx);
            shell.begin_allowlist_entry_removal(0, cx);
            assert!(
                shell
                    .allowlist_manager
                    .as_ref()
                    .unwrap()
                    .pending_remove
                    .is_some()
            );
        });
        write_document(&user, &[U1]);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.on_menu_reload_allowlists(&MenuReloadAllowlists, window, cx);
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert!(state.pending_remove.is_none());
            assert_eq!(
                state.user.document.as_ref().unwrap().entries,
                vec![serde_json::from_str::<UserAllowlistEntry>(U1).unwrap()]
            );
            for case in 0..3 {
                match case {
                    0 => assert!(
                        shell
                            .allowlist_manager
                            .as_ref()
                            .unwrap()
                            .pending_remove
                            .is_none()
                    ),
                    1 => {
                        shell.begin_allowlist_entry_removal(0, cx);
                        let state = shell.allowlist_manager.as_mut().unwrap();
                        assert!(state.pending_remove.is_some());
                        state.user.document = Err("Example read error".into());
                    }
                    _ => shell.allowlist_manager = None,
                }
                let bytes = fs::read(&user).unwrap();
                let banner = |shell: &GuiShell| {
                    let Some(BannerMessage::AllowlistsReloaded { count, stale_rows }) =
                        &shell.status_message
                    else {
                        panic!("expected reload banner");
                    };
                    (*count, *stale_rows)
                };
                let original_banner = banner(shell);
                let plan = shell.audit_plan.clone();
                let state = shell.allowlist_manager.clone();
                shell.confirm_allowlist_entry_removal(window, cx);
                assert_eq!(fs::read(&user).unwrap(), bytes);
                assert_eq!(banner(shell), original_banner);
                assert!(Arc::ptr_eq(&shell.audit_plan, &plan));
                match (&shell.allowlist_manager, &state) {
                    (Some(actual), Some(expected)) => {
                        assert_eq!(actual.app.path, expected.app.path);
                        assert_eq!(actual.app.document, expected.app.document);
                        assert_eq!(actual.user.path, expected.user.path);
                        assert_eq!(actual.user.document, expected.user.document);
                        assert_eq!(actual.pending_remove, expected.pending_remove);
                    }
                    (None, None) => {}
                    _ => panic!("manager state changed"),
                }
            }
        });
    }
    #[gpui::test]
    fn allowlist_manager_removal_reloads_and_reaudits(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("TestScene.ma");
        let user = dir.path().join("ExampleUser/allowlist.json");
        fs::write(&path, SCENE).unwrap();
        write_document(&user, &[U0]);
        let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
        let observed = Rc::new(RefCell::new(false));
        shell.update_in(visual_cx, |shell, window, cx| {
            assert!(!shell.workspace_scan_active());
            assert!(!shell.state.analysis_cache_enabled);
            let row = current_row(&path, &shell.audit_plan);
            let report = row.display_audit_report().unwrap();
            assert_eq!(report.finding_count(), 1);
            assert_eq!(report.findings[0].code, AuditFindingCode::MelExec);
            assert_eq!(report.allowed_finding_count(), 1);
            assert_eq!(
                report.findings[0].allowed_by,
                Some(AuditAllowRef {
                    hash: HASH.parse().unwrap(),
                    source: AllowlistSource::User
                })
            );
            assert_eq!(row.effective_findings_count(), 0);
            assert_eq!(report.disposition, AuditDisposition::Review);
            shell.replace_rows(vec![row]);
            shell.refresh_file_table(cx);
            shell.refresh_audit_table(cx);
            shell.open_allowlist_manager_dialog(window, cx);
            shell.begin_allowlist_entry_removal(0, cx);
            let old_plan = shell.audit_plan.clone();
            let fingerprint = shell.audit_plan_fingerprint.clone();
            let observed = observed.clone();
            cx.observe_self(move |shell, _| {
                let row = &shell.rows[0];
                if row.analysis_current_for(shell.state.audit_mode) {
                    let report = row.display_audit_report().unwrap();
                    if report.allowed_finding_count() == 0 {
                        assert_eq!(report.finding_count(), 1);
                        assert_eq!(report.findings[0].allowed_by, None);
                        assert_eq!(row.effective_findings_count(), 1);
                        assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
                        *observed.borrow_mut() = true;
                    }
                }
            })
            .detach();
            shell.confirm_allowlist_entry_removal(window, cx);
            assert_eq!(fs::read(&user).unwrap(), E0.as_bytes());
            assert!(!Arc::ptr_eq(&shell.audit_plan, &old_plan));
            assert_ne!(shell.audit_plan_fingerprint, fingerprint);
            assert!(!shell.rows[0].analysis_current_for(shell.state.audit_mode));
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert!(state.pending_remove.is_none());
            assert!(state.user.document.as_ref().unwrap().entries.is_empty());
            let Some(message @ BannerMessage::AllowlistRemoved { label }) = &shell.status_message
            else {
                panic!("expected removal banner");
            };
            assert_eq!(label, "ExampleScriptNode");
            assert_eq!(
                render_banner_message(&shell.i18n(), message),
                "Removed from the allowlist: ExampleScriptNode"
            );
        });
        visual_cx.run_until_parked();
        visual_cx.executor().advance_clock(AUTO_ANALYZE_DEBOUNCE);
        visual_cx.run_until_parked();
        assert!(
            *observed.borrow(),
            "normal scheduler must apply the re-audit"
        );
        shell.update_in(visual_cx, |shell, _, _| {
            let row = &shell.rows[0];
            assert!(row.analysis_current_for(shell.state.audit_mode));
            let report = row.display_audit_report().unwrap();
            assert_eq!(report.finding_count(), 1);
            assert_eq!(report.allowed_finding_count(), 0);
            assert_eq!(report.findings[0].allowed_by, None);
            assert_eq!(row.effective_findings_count(), 1);
            assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
        });
        for (locale, prefix) in [
            (SupportedLocale::English, "Removed from the allowlist: "),
            (SupportedLocale::Japanese, "許可リストから削除しました: "),
            (SupportedLocale::Chinese, "已从允许列表删除："),
        ] {
            for label in ["ExampleScriptNode", "-"] {
                assert_eq!(
                    render_banner_message(
                        &I18n::new(locale),
                        &BannerMessage::AllowlistRemoved {
                            label: label.into()
                        }
                    ),
                    format!("{prefix}{label}")
                );
            }
        }
        assert!(!dir.path().join("ExampleApp/allowlist.json").exists());
    }

    #[gpui::test]
    fn allowlist_manager_refreshes_after_removal_failure(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let user = dir.path().join("ExampleUser/allowlist.json");
        let app = dir.path().join("ExampleApp/allowlist.json");
        write_document(&user, &[U0]);
        let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
        let (old_plan, fingerprint) = shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            shell.begin_allowlist_entry_removal(0, cx);
            (
                shell.audit_plan.clone(),
                shell.audit_plan_fingerprint.clone(),
            )
        });
        write_document(&user, &[U1]);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.confirm_allowlist_entry_removal(window, cx);
            assert!(!Arc::ptr_eq(&shell.audit_plan, &old_plan));
            assert_ne!(shell.audit_plan_fingerprint, fingerprint);
            assert_eq!(fs::read(&user).unwrap(), document_json(&[U1]).as_bytes());
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert!(state.pending_remove.is_none());
            assert_eq!(
                state.user.document.as_ref().unwrap().entries,
                vec![serde_json::from_str::<UserAllowlistEntry>(U1).unwrap()]
            );
            assert!(state.app.document.as_ref().unwrap().entries.is_empty());
            assert!(matches!(
                shell.status_message,
                Some(BannerMessage::AllowlistFileChanged)
            ));
            assert_eq!(
                render_banner_message(&shell.i18n(), shell.status_message.as_ref().unwrap()),
                "The allowlist file changed. The list was refreshed."
            );
            shell.begin_allowlist_entry_removal(0, cx);
        });
        fs::remove_file(&user).unwrap();
        fs::create_dir(&user).unwrap();
        // Changing the other layer makes its refresh observable after the failed removal.
        write_document(&app, &[A0]);
        shell.update_in(visual_cx, |shell, window, cx| {
            let plan = shell.audit_plan.clone();
            shell.confirm_allowlist_entry_removal(window, cx);
            assert!(!Arc::ptr_eq(&shell.audit_plan, &plan));
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert!(state.pending_remove.is_none());
            assert!(state.user.document.is_err());
            assert_eq!(
                state.app.document.as_ref().unwrap().entries,
                vec![serde_json::from_str::<UserAllowlistEntry>(A0).unwrap()]
            );
            let Some(message @ BannerMessage::AllowlistReadFailed { path, error }) =
                &shell.status_message
            else {
                panic!("expected read failure");
            };
            assert_eq!(path, &user);
            assert!(!error.is_empty());
            assert_eq!(
                render_banner_message(&shell.i18n(), message),
                format!("Could not load allowlist {}: {error}", user.display())
            );
        });
        assert!(fs::read_dir(&user).unwrap().next().is_none());
        for (locale, read, write) in [
            (
                SupportedLocale::English,
                "Could not load allowlist ExampleUser/allowlist.json: Example error",
                "Could not write allowlist ExampleUser/allowlist.json: Example error",
            ),
            (
                SupportedLocale::Japanese,
                "許可リストを読み込めませんでした: ExampleUser/allowlist.json: Example error",
                "許可リストに書き込めませんでした: ExampleUser/allowlist.json: Example error",
            ),
            (
                SupportedLocale::Chinese,
                "无法加载允许列表 ExampleUser/allowlist.json: Example error",
                "无法写入允许列表 ExampleUser/allowlist.json: Example error",
            ),
        ] {
            let i18n = I18n::new(locale);
            assert_eq!(
                render_banner_message(
                    &i18n,
                    &BannerMessage::AllowlistReadFailed {
                        path: "ExampleUser/allowlist.json".into(),
                        error: "Example error".into()
                    }
                ),
                read
            );
            assert_eq!(
                render_banner_message(
                    &i18n,
                    &BannerMessage::AllowlistWriteFailed {
                        path: "ExampleUser/allowlist.json".into(),
                        error: "Example error".into()
                    }
                ),
                write
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            struct RestoreMode(PathBuf);
            impl Drop for RestoreMode {
                fn drop(&mut self) {
                    fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755)).unwrap();
                }
            }
            fs::remove_dir(&user).unwrap();
            write_document(&user, &[U0]);
            fs::remove_file(&app).unwrap();
            let (plan, fingerprint) = shell.update_in(visual_cx, |shell, window, cx| {
                shell.on_menu_reload_allowlists(&MenuReloadAllowlists, window, cx);
                shell.begin_allowlist_entry_removal(0, cx);
                (
                    shell.audit_plan.clone(),
                    shell.audit_plan_fingerprint.clone(),
                )
            });
            let parent = user.parent().unwrap();
            let _restore = RestoreMode(parent.to_path_buf());
            fs::set_permissions(parent, fs::Permissions::from_mode(0o555)).unwrap();
            if tempfile::NamedTempFile::new_in(parent).is_ok() {
                eprintln!(
                    "Unix Write case skipped: parent mode 0o555 still permits temporary files"
                );
                return;
            }
            shell.update_in(visual_cx, |shell, window, cx| {
                shell.confirm_allowlist_entry_removal(window, cx);
                assert!(!Arc::ptr_eq(&shell.audit_plan, &plan));
                assert_eq!(shell.audit_plan_fingerprint, fingerprint);
                let state = shell.allowlist_manager.as_ref().unwrap();
                assert!(state.pending_remove.is_none());
                assert!(state.app.document.as_ref().unwrap().entries.is_empty());
                assert_eq!(
                    state.user.document.as_ref().unwrap().entries,
                    vec![serde_json::from_str::<UserAllowlistEntry>(U0).unwrap()]
                );
                let Some(message @ BannerMessage::AllowlistWriteFailed { path, error }) =
                    &shell.status_message
                else {
                    panic!("expected write failure");
                };
                assert_eq!(path, &user);
                assert!(!error.is_empty());
                assert_eq!(
                    render_banner_message(&shell.i18n(), message),
                    format!("Could not write allowlist {}: {error}", user.display())
                );
            });
            assert_eq!(fs::read(&user).unwrap(), document_json(&[U0]).as_bytes());
        }
    }

    #[gpui::test]
    fn allowlist_manager_tabs_preserve_selection(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let app = dir.path().join("ExampleApp/allowlist.json");
        let user = dir.path().join("ExampleUser/allowlist.json");
        write_document(&app, &[A0, A1]);
        write_document(&user, &[U0, U1]);
        let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert_eq!(state.selected, AllowlistManagerTab::User);
            assert_eq!(
                allowlist_manager_tab_label(&state.user, AllowlistSource::User, &shell.i18n()),
                "User 2"
            );
            assert_eq!(
                allowlist_manager_tab_label(&state.app, AllowlistSource::App, &shell.i18n()),
                "App 2"
            );
        });
        assert!(visual_cx.debug_bounds("allowlist-user-section").is_some());
        assert!(visual_cx.debug_bounds("allowlist-app-section").is_none());
        click(visual_cx, "allowlist-user-remove-0");
        shell.update_in(visual_cx, |shell, _, _| {
            let pending = shell
                .allowlist_manager
                .as_ref()
                .unwrap()
                .pending_remove
                .as_ref()
                .unwrap();
            assert_eq!(pending.index, 0);
        });
        click(visual_cx, "allowlist-manager-tab-app");
        let state = shell.update_in(visual_cx, |shell, _, _| {
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert_eq!(state.selected, AllowlistManagerTab::App);
            assert!(state.pending_remove.is_none());
            let entries = &state.app.document.as_ref().unwrap().entries;
            assert_eq!(entries[0].label.as_deref(), Some("ExampleApp"));
            assert_eq!(entries[1].label.as_deref(), Some("Sample"));
            state.clone()
        });
        let (snapshot, snapshot_cx) = open_shell(visual_cx, dir.path(), &user);
        snapshot.update_in(snapshot_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            shell.allowlist_manager = Some(state);
            cx.notify();
        });
        assert!(snapshot_cx.debug_bounds("allowlist-app-section").is_some());
        assert!(snapshot_cx.debug_bounds("allowlist-user-section").is_none());
        for selector in ["allowlist-app-entry-0", "allowlist-app-entry-1"] {
            assert!(snapshot_cx.debug_bounds(selector).is_some());
        }
        for selector in [
            "allowlist-user-remove-0",
            "allowlist-user-confirm-0",
            "allowlist-user-cancel-0",
            "allowlist-user-remove-1",
            "allowlist-user-confirm-1",
            "allowlist-user-cancel-1",
        ] {
            assert!(snapshot_cx.debug_bounds(selector).is_none());
        }
        click(visual_cx, "allowlist-manager-tab-user");
        assert_confirmation_controls(&shell, visual_cx, dir.path(), &user, None);
        assert!(visual_cx.debug_bounds("allowlist-user-remove-0").is_some());
        assert!(visual_cx.debug_bounds("allowlist-user-remove-1").is_some());
        click(visual_cx, "allowlist-user-remove-0");
        click(visual_cx, "allowlist-user-confirm-0");
        shell.update_in(visual_cx, |shell, _, _| {
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert_eq!(state.selected, AllowlistManagerTab::User);
            assert_eq!(
                allowlist_manager_tab_label(&state.user, AllowlistSource::User, &shell.i18n()),
                "User 1"
            );
        });
        click(visual_cx, "allowlist-manager-tab-app");
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.refresh_allowlist_manager_data(cx);
            assert_eq!(
                shell.allowlist_manager.as_ref().unwrap().selected,
                AllowlistManagerTab::App
            );
            shell.begin_allowlist_entry_removal(0, cx);
            shell.confirm_allowlist_entry_removal(window, cx);
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert_eq!(state.selected, AllowlistManagerTab::App);
            assert!(state.pending_remove.is_none());
            assert_eq!(
                allowlist_manager_tab_label(&state.user, AllowlistSource::User, &shell.i18n()),
                "User 0"
            );
        });
        click(visual_cx, "allowlist-manager-close");
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            assert_eq!(
                shell.allowlist_manager.as_ref().unwrap().selected,
                AllowlistManagerTab::User
            );
        });
    }

    #[gpui::test]
    fn allowlist_manager_entry_presentation_and_copy(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let app = dir.path().join("ExampleApp/allowlist.json");
        let user = dir.path().join("ExampleUser/allowlist.json");
        let v = U0
            .replace("ExampleScriptNode", "ExampleScriptNode .b")
            .replace(r#""added_by":"Example""#, r#""added_by":"ExampleUser""#);
        let w = v.replace("2026-11-07T09:30:00Z", "Example invalid timestamp");
        write_document(&app, &[A0, A1]);
        write_document(&user, &[&v, U1, &w]);
        let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            let state = shell.allowlist_manager.as_ref().unwrap();
            let entries = &state.user.document.as_ref().unwrap().entries;
            let i18n = shell.i18n();
            let local = i18n.format_timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-11-07T09:30:00Z")
                    .unwrap()
                    .with_timezone(&Local),
            );
            let presentation = allowlist_manager_entry_presentation(
                &entries[0],
                AllowlistSource::User,
                state,
                &i18n,
            );
            assert_eq!(presentation.node, "ExampleScriptNode");
            assert_eq!(presentation.attribute.as_deref(), Some(".b"));
            assert_eq!(
                presentation.codes,
                vec![("mel_exec".into(), true), ("mel_python".into(), false)]
            );
            assert_eq!(
                presentation.reason.as_deref(),
                Some("Reason: Example reason")
            );
            assert_eq!(presentation.preview.as_deref(), Some("Example preview"));
            assert_eq!(
                presentation.metadata,
                vec![local.clone(), "ExampleUser".into()]
            );
            assert_eq!(presentation.short_hash, "79a04cad…");
            assert_eq!(presentation.full_hash, HASH);
            assert_eq!(
                allowlist_manager_entry_footer_text(&presentation),
                format!("{local} · ExampleUser · 79a04cad…")
            );
            let raw = allowlist_manager_entry_presentation(
                &entries[2],
                AllowlistSource::User,
                state,
                &i18n,
            );
            assert_eq!(raw.metadata, ["Example invalid timestamp", "ExampleUser"]);
            assert_eq!(
                allowlist_manager_entry_footer_text(&raw),
                "Example invalid timestamp · ExampleUser · 79a04cad…"
            );
            let missing = allowlist_manager_entry_presentation(
                &entries[1],
                AllowlistSource::User,
                state,
                &i18n,
            );
            assert_eq!(missing.node, "-");
            assert_eq!(missing.attribute, None);
            assert_eq!(missing.metadata, Vec::<String>::new());
            assert_eq!(missing.codes, vec![("mel_eval".into(), false)]);
            assert_eq!(allowlist_manager_entry_footer_text(&missing), "11111111…");
            for (label, attribute) in [
                ("ExampleScriptNode", None),
                ("ExampleScriptNode .b Example", Some(".b Example")),
            ] {
                let mut entry = entries[0].clone();
                entry.label = Some(label.into());
                let value = allowlist_manager_entry_presentation(
                    &entry,
                    AllowlistSource::User,
                    state,
                    &i18n,
                );
                assert_eq!(value.node, "ExampleScriptNode");
                assert_eq!(value.attribute.as_deref(), attribute);
            }
            for (added_at, added_by, expected) in [
                (
                    None,
                    Some("ExampleUser".into()),
                    "ExampleUser · 79a04cad…".to_string(),
                ),
                (
                    Some("2026-11-07T09:30:00Z".into()),
                    None,
                    format!("{local} · 79a04cad…"),
                ),
                (None, None, "79a04cad…".to_string()),
            ] {
                let mut entry = entries[0].clone();
                entry.added_at = added_at;
                entry.added_by = added_by;
                assert_eq!(
                    allowlist_manager_entry_footer_text(&allowlist_manager_entry_presentation(
                        &entry,
                        AllowlistSource::User,
                        state,
                        &i18n,
                    )),
                    expected
                );
            }
        });
        for selector in [
            "allowlist-user-code-0-0",
            "allowlist-user-code-0-1",
            "allowlist-user-also-app-0-0",
            "allowlist-user-code-1-0",
            "allowlist-user-code-2-0",
            "allowlist-user-code-2-1",
            "allowlist-user-also-app-2-0",
        ] {
            assert!(visual_cx.debug_bounds(selector).is_some(), "{selector}");
        }
        for selector in [
            "allowlist-user-code-0-2",
            "allowlist-user-also-app-0-1",
            "allowlist-user-also-app-1-0",
            "allowlist-user-code-1-1",
            "allowlist-user-also-app-2-1",
        ] {
            assert!(visual_cx.debug_bounds(selector).is_none(), "{selector}");
        }
        click(visual_cx, "allowlist-user-copy-hash-0");
        assert_eq!(
            visual_cx.update(|_, cx| cx.read_from_clipboard().and_then(|item| item.text())),
            Some(HASH.to_owned())
        );
        click(visual_cx, "allowlist-manager-tab-app");
        assert!(
            visual_cx
                .debug_bounds("allowlist-app-also-app-0-0")
                .is_none()
        );
        assert!(
            visual_cx
                .debug_bounds("allowlist-app-also-app-1-0")
                .is_none()
        );
        click(visual_cx, "allowlist-app-copy-hash-1");
        assert_eq!(
            visual_cx.update(|_, cx| cx.read_from_clipboard().and_then(|item| item.text())),
            Some(OTHER_HASH.to_owned())
        );
        for no_path in [false, true] {
            let (snapshot, snapshot_cx) = open_shell(visual_cx, dir.path(), &user);
            snapshot.update_in(snapshot_cx, |shell, window, cx| {
                shell.open_allowlist_manager_dialog(window, cx);
                if no_path {
                    shell.app_allowlist_path = None;
                    shell.refresh_allowlist_manager_data(cx);
                } else {
                    shell.allowlist_manager.as_mut().unwrap().app.document =
                        Err("Example read error".into());
                }
                let state = shell.allowlist_manager.as_ref().unwrap();
                let entry = &state.user.document.as_ref().unwrap().entries[0];
                assert_eq!(
                    allowlist_manager_entry_presentation(
                        entry,
                        AllowlistSource::User,
                        state,
                        &shell.i18n()
                    )
                    .codes,
                    vec![("mel_exec".into(), false), ("mel_python".into(), false)]
                );
                cx.notify();
            });
            for selector in [
                "allowlist-user-also-app-0-0",
                "allowlist-user-also-app-0-1",
                "allowlist-user-also-app-1-0",
                "allowlist-user-also-app-2-0",
            ] {
                assert!(snapshot_cx.debug_bounds(selector).is_none(), "{selector}");
            }
        }
    }

    #[gpui::test]
    fn allowlist_manager_pending_card_presentation(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let user = dir.path().join("ExampleUser/allowlist.json");
        let app = dir.path().join("ExampleApp/allowlist.json");
        write_document(&user, &[U0, U1]);
        write_document(&app, &[A0, A1]);
        let input = fs::read(&user).unwrap();
        let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
        });
        for (selector, pending) in [
            ("allowlist-user-remove-0", Some(0)),
            ("allowlist-user-remove-1", Some(1)),
            ("allowlist-user-cancel-1", None),
        ] {
            click(visual_cx, selector);
            shell.update_in(visual_cx, |shell, _, _| {
                let state = shell.allowlist_manager.as_ref().unwrap();
                for index in 0..2 {
                    assert_eq!(
                        allowlist_manager_entry_is_pending(state, AllowlistSource::User, index),
                        pending == Some(index)
                    );
                    assert!(!allowlist_manager_entry_is_pending(
                        state,
                        AllowlistSource::App,
                        index
                    ));
                }
                assert_eq!(
                    shell.i18n().text("allowlist_manager.remove_warning"),
                    concat!(
                        "Removing this entry stops allowing its codes unless another entry also ",
                        "lists them. Affected files are re-audited."
                    )
                );
            });
            assert_confirmation_controls(&shell, visual_cx, dir.path(), &user, pending);
            assert_eq!(fs::read(&user).unwrap(), input);
        }
        click(visual_cx, "allowlist-user-remove-0");
        let mut state = shell.update_in(visual_cx, |shell, _, cx| {
            shell.audit_allow_in_flight = true;
            assert_eq!(
                shell.i18n().text("allowlist_manager.busy"),
                "An allowlist addition is in progress."
            );
            cx.notify();
            shell.allowlist_manager.clone().unwrap()
        });
        click(visual_cx, "allowlist-user-confirm-0");
        shell.update_in(visual_cx, |shell, _, _| {
            assert_eq!(
                shell.allowlist_manager.as_ref().unwrap().pending_remove,
                state.pending_remove
            );
        });
        assert_eq!(fs::read(&user).unwrap(), input);
        click(visual_cx, "allowlist-user-remove-1");
        assert_confirmation_controls(&shell, visual_cx, dir.path(), &user, Some(1));
        assert_eq!(fs::read(&user).unwrap(), input);
        click(visual_cx, "allowlist-user-cancel-1");
        assert_confirmation_controls(&shell, visual_cx, dir.path(), &user, None);
        assert_eq!(fs::read(&user).unwrap(), input);
        state.selected = AllowlistManagerTab::App;
        let (snapshot, snapshot_cx) = open_shell(visual_cx, dir.path(), &user);
        snapshot.update_in(snapshot_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            shell.allowlist_manager = Some(state);
            cx.notify();
        });
        for selector in [
            "allowlist-user-remove-0",
            "allowlist-user-confirm-0",
            "allowlist-user-cancel-0",
            "allowlist-user-remove-1",
            "allowlist-user-confirm-1",
            "allowlist-user-cancel-1",
        ] {
            assert!(snapshot_cx.debug_bounds(selector).is_none(), "{selector}");
        }
    }

    #[gpui::test]
    fn allowlist_manager_empty_and_error_presentation(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let app = dir.path().join("ExampleApp/allowlist.json");
        let user = dir.path().join("ExampleUser/allowlist.json");
        write_document(&app, &[]);
        write_document(&user, &[]);
        let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
        shell.update_in(visual_cx, |shell, window, cx| {
            shell.open_allowlist_manager_dialog(window, cx);
            let state = shell.allowlist_manager.as_ref().unwrap();
            assert_eq!(
                allowlist_manager_tab_label(&state.user, AllowlistSource::User, &shell.i18n()),
                "User 0"
            );
            assert_eq!(
                allowlist_manager_tab_label(&state.app, AllowlistSource::App, &shell.i18n()),
                "App 0"
            );
            assert_eq!(
                shell.i18n().text("allowlist_manager.empty_user"),
                "No entries. Use \"Allow this threat…\" in the audit details to add one."
            );
            assert_eq!(
                allowlist_manager_error_text(&state.user, &shell.i18n()),
                None
            );
        });
        assert!(visual_cx.debug_bounds("allowlist-user-empty").is_some());
        click(visual_cx, "allowlist-manager-tab-app");
        assert!(visual_cx.debug_bounds("allowlist-app-empty").is_some());
        shell.update_in(visual_cx, |shell, _, _| {
            assert_eq!(shell.i18n().text("allowlist_manager.empty"), "No entries");
        });
        for (selected, source, path, label, error_id, entry_id, remove_id, confirm_id) in [
            (
                AllowlistManagerTab::User,
                AllowlistSource::User,
                &user,
                "User",
                "allowlist-user-error",
                "allowlist-user-entry-0",
                "allowlist-user-remove-0",
                "allowlist-user-confirm-0",
            ),
            (
                AllowlistManagerTab::App,
                AllowlistSource::App,
                &app,
                "App",
                "allowlist-app-error",
                "allowlist-app-entry-0",
                "allowlist-app-remove-0",
                "allowlist-app-confirm-0",
            ),
        ] {
            let (snapshot, snapshot_cx) = open_shell(visual_cx, dir.path(), &user);
            snapshot.update_in(snapshot_cx, |shell, window, cx| {
                shell.open_allowlist_manager_dialog(window, cx);
                let i18n = shell.i18n();
                let state = shell.allowlist_manager.as_mut().unwrap();
                state.selected = selected;
                let layer = match selected {
                    AllowlistManagerTab::User => &mut state.user,
                    AllowlistManagerTab::App => &mut state.app,
                };
                layer.document = Err("Example read error".into());
                assert_eq!(allowlist_manager_tab_label(layer, source, &i18n), label);
                assert_eq!(
                    allowlist_manager_error_text(layer, &i18n),
                    Some(format!("{}\nExample read error", path.display()))
                );
                cx.notify();
            });
            assert!(snapshot_cx.debug_bounds(error_id).is_some());
            assert!(snapshot_cx.debug_bounds(entry_id).is_none());
            assert!(snapshot_cx.debug_bounds(remove_id).is_none());
            assert!(snapshot_cx.debug_bounds(confirm_id).is_none());
        }
        for (selected, source, label) in [
            (AllowlistManagerTab::User, AllowlistSource::User, "User 0"),
            (AllowlistManagerTab::App, AllowlistSource::App, "App 0"),
        ] {
            let (snapshot, snapshot_cx) = open_shell(visual_cx, dir.path(), &user);
            snapshot.update_in(snapshot_cx, |shell, window, cx| {
                shell.open_allowlist_manager_dialog(window, cx);
                match selected {
                    AllowlistManagerTab::User => shell.user_allowlist_path = None,
                    AllowlistManagerTab::App => shell.app_allowlist_path = None,
                }
                shell.select_allowlist_manager_tab(selected, cx);
                shell.refresh_allowlist_manager_data(cx);
                let state = shell.allowlist_manager.as_ref().unwrap();
                let layer = match selected {
                    AllowlistManagerTab::User => &state.user,
                    AllowlistManagerTab::App => &state.app,
                };
                assert!(layer.path.is_none());
                assert!(layer.document.as_ref().unwrap().entries.is_empty());
                assert_eq!(
                    allowlist_manager_tab_label(layer, source, &shell.i18n()),
                    label
                );
                assert_eq!(
                    allowlist_manager_path_text(layer, &shell.i18n()),
                    "Path not available"
                );
            });
        }
    }

    #[gpui::test]
    fn allowlist_manager_open_folder_availability(cx: &mut TestAppContext) {
        let dir = tempdir().unwrap();
        let app = dir.path().join("ExampleApp/allowlist.json");
        let user = dir.path().join("ExampleUser/allowlist.json");
        write_document(&app, &[A0]);
        write_document(&user, &[U0]);
        for selected in [AllowlistManagerTab::User, AllowlistManagerTab::App] {
            for case in 0..4 {
                let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
                shell.update_in(visual_cx, |shell, window, cx| {
                    shell.open_allowlist_manager_dialog(window, cx);
                    let target = match selected {
                        AllowlistManagerTab::User => &mut shell.user_allowlist_path,
                        AllowlistManagerTab::App => &mut shell.app_allowlist_path,
                    };
                    match case {
                        0 => *target = None,
                        2 => *target = Some(dir.path().join("ExampleUser/ExampleMissing.json")),
                        _ => {}
                    }
                    shell.select_allowlist_manager_tab(selected, cx);
                    shell.refresh_allowlist_manager_data(cx);
                    let state = shell.allowlist_manager.as_mut().unwrap();
                    let (layer, other) = match selected {
                        AllowlistManagerTab::User => (&mut state.user, &state.app),
                        AllowlistManagerTab::App => (&mut state.app, &state.user),
                    };
                    assert!(other.path.is_some());
                    if case == 3 {
                        layer.document = Err("Example read error".into());
                    }
                    assert_eq!(layer.path.is_some(), case != 0);
                    shell.status_message = None;
                    cx.notify();
                });
                assert_eq!(
                    visual_cx
                        .debug_bounds("allowlist-manager-open-folder")
                        .is_some(),
                    case != 0
                );
                #[cfg(not(target_os = "windows"))]
                if case != 0 {
                    click(visual_cx, "allowlist-manager-open-folder");
                    visual_cx.run_until_parked();
                    shell.update_in(visual_cx, |shell, _, _| {
                        let Some(BannerMessage::Raw(error)) = &shell.status_message else {
                            panic!("expected reveal error");
                        };
                        assert_eq!(
                            error,
                            "reveal file in Explorer is only supported on Windows"
                        );
                    });
                }
            }
        }
    }

    #[test]
    fn allowlist_manager_visual_catalog_texts() {
        let expected = [
            (
                "allowlist_manager.read_only",
                [
                    "Read-only. Distributed with the application.",
                    "読み取り専用です。アプリケーションとともに配布されます。",
                    "只读。随应用程序分发。",
                ],
            ),
            (
                "allowlist_manager.open_folder",
                ["Open folder", "フォルダーを開く", "打开文件夹"],
            ),
            (
                "allowlist_manager.also_app_tag",
                ["also app", "App にも登録", "App 中也有"],
            ),
            (
                "allowlist_manager.remove_warning",
                [
                    concat!(
                        "Removing this entry stops allowing its codes unless another entry also ",
                        "lists them. Affected files are re-audited."
                    ),
                    concat!(
                        "この登録を削除すると、他の登録にもある場合を除き、",
                        "そのコードは許可されなくなります。影響するファイルは再監査されます。"
                    ),
                    concat!(
                        "删除此条目后，除非其他条目也列出这些代码，否则它们将不再被允许。",
                        "受影响的文件将重新审核。"
                    ),
                ],
            ),
            (
                "allowlist_manager.empty_user",
                [
                    "No entries. Use \"Allow this threat…\" in the audit details to add one.",
                    "登録はありません。監査詳細の「この脅威を許可…」から追加できます。",
                    "没有条目。请在审核详情中使用“允许此威胁…”添加。",
                ],
            ),
            (
                "allowlist_manager.copy_hash",
                ["Copy hash", "ハッシュをコピー", "复制哈希"],
            ),
        ];
        for (index, text) in [
            include_str!("../../locales/en.json"),
            include_str!("../../locales/ja.json"),
            include_str!("../../locales/cn.json"),
        ]
        .into_iter()
        .enumerate()
        {
            let catalog: serde_json::Value = serde_json::from_str(text).unwrap();
            let mut previous = text.find("\"allowlist_manager.busy\"").unwrap();
            for (key, values) in expected {
                assert_eq!(
                    catalog.get(key).and_then(serde_json::Value::as_str),
                    Some(values[index])
                );
                let position = text.find(&format!("\"{key}\"")).unwrap();
                assert!(position > previous, "{key}");
                previous = position;
            }
            assert_eq!(catalog.get("allowlist_manager.app").unwrap(), "App");
            assert_eq!(
                catalog.get("allowlist_manager.path_unavailable").unwrap(),
                ["Path not available", "パスを取得できません", "路径不可用"][index]
            );
            for key in [
                "allowlist_manager.entry_count",
                "allowlist_manager.added_at",
                "allowlist_manager.added_by",
                "allowlist_manager.also_app",
            ] {
                assert_eq!(catalog.get(key), None, "{key}");
            }
        }
    }

    #[test]
    fn allowlist_manager_catalog_texts() {
        let expected = [
            (
                "settings.manage_allowlists",
                ["Manage allowlists…", "許可リストを管理…", "管理允许列表…"],
            ),
            (
                "dialog.allowlist_manager_title",
                ["Manage allowlists", "許可リストの管理", "管理允许列表"],
            ),
            ("allowlist_manager.app", ["App", "App", "App"]),
            ("allowlist_manager.user", ["User", "ユーザー", "用户"]),
            (
                "allowlist_manager.path_unavailable",
                ["Path not available", "パスを取得できません", "路径不可用"],
            ),
            (
                "allowlist_manager.empty",
                ["No entries", "登録はありません", "没有条目"],
            ),
            (
                "allowlist_manager.reason",
                ["Reason: {reason}", "理由: {reason}", "原因：{reason}"],
            ),
            (
                "allowlist_manager.confirm_remove",
                ["Confirm removal", "削除を確定", "确认删除"],
            ),
            (
                "banner.allowlist_removed",
                [
                    "Removed from the allowlist: {label}",
                    "許可リストから削除しました: {label}",
                    "已从允许列表删除：{label}",
                ],
            ),
            (
                "banner.allowlist_file_changed",
                [
                    "The allowlist file changed. The list was refreshed.",
                    "許可リストのファイルが変更されました。一覧を更新しました。",
                    "允许列表文件已更改，列表已刷新。",
                ],
            ),
            (
                "allowlist_manager.busy",
                [
                    "An allowlist addition is in progress.",
                    "許可リストへの追加を処理中です。",
                    "正在添加到允许列表。",
                ],
            ),
        ];
        for (index, catalog) in [
            include_str!("../../locales/en.json"),
            include_str!("../../locales/ja.json"),
            include_str!("../../locales/cn.json"),
        ]
        .into_iter()
        .enumerate()
        {
            let catalog: serde_json::Value = serde_json::from_str(catalog).unwrap();
            for (key, values) in expected {
                assert_eq!(
                    catalog.get(key).and_then(serde_json::Value::as_str),
                    Some(values[index]),
                    "{key}"
                );
            }
        }
    }
}
