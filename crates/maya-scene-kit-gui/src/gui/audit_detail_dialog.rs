use super::*;
use maya_scene_kit_audit::scene::AuditSurfaceDerivation;
use maya_scene_kit_observe::scene::{evidence::ExecutionLanguage, execution::ExecutionSurface};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AuditSurfaceMatch {
    Found(Arc<str>),
    NotFound,
    Ambiguous,
}

pub(super) struct AuditDetailCodeResult {
    pub(super) state: AuditDetailCodeState,
    pub(super) text: Option<Arc<str>>,
}

impl AuditDetailCodeResult {
    fn fallback(state: AuditDetailCodeState) -> Self {
        Self { state, text: None }
    }
}

pub(super) fn match_audit_surface_text(
    target: &ExecutionOrigin,
    derived: bool,
    surfaces: &[ExecutionSurface],
) -> AuditSurfaceMatch {
    let normalized = |origin: &ExecutionOrigin| {
        let mut origin = origin.clone();
        if derived {
            origin.lang = ExecutionLanguage::Unknown;
            origin.source_kind = None;
        }
        origin
    };
    let target = normalized(target);
    let mut matches = surfaces
        .iter()
        .filter(|surface| normalized(&surface.origin) == target);
    match (matches.next(), matches.next()) {
        (Some(surface), None) => AuditSurfaceMatch::Found(surface.text.clone()),
        (None, _) => AuditSurfaceMatch::NotFound,
        _ => AuditSurfaceMatch::Ambiguous,
    }
}

pub(super) fn load_audit_surface_text(
    path: &Path,
    options: &LoadOptions,
    target: &AuditDetailCodeTarget,
) -> AuditDetailCodeResult {
    let catalog = Loader::new(options.clone())
        .observe_analysis_path(path)
        .and_then(|observation| observation.observed_execution_catalog_with_digests(0, false));
    let catalog = match catalog {
        Ok(catalog) => catalog,
        Err(error) => {
            return AuditDetailCodeResult::fallback(AuditDetailCodeState::Failed {
                error: error.to_string(),
            });
        }
    };
    let surfaces = catalog
        .surfaces
        .into_iter()
        .map(|entry| entry.surface)
        .collect::<Vec<_>>();
    audit_surface_code_result(target, &surfaces)
}

pub(super) fn audit_surface_code_result(
    target: &AuditDetailCodeTarget,
    surfaces: &[ExecutionSurface],
) -> AuditDetailCodeResult {
    match match_audit_surface_text(&target.origin, target.derived, surfaces) {
        AuditSurfaceMatch::Found(text) => {
            if text.len() > 2 * 1024 * 1024
                || text
                    .as_bytes()
                    .split(|byte| *byte == b'\n')
                    .any(|line| line.len() > 65536)
            {
                AuditDetailCodeResult::fallback(AuditDetailCodeState::TooLarge)
            } else {
                AuditDetailCodeResult {
                    state: AuditDetailCodeState::Loaded {
                        derived: target.derived,
                    },
                    text: Some(text),
                }
            }
        }
        AuditSurfaceMatch::NotFound => {
            AuditDetailCodeResult::fallback(AuditDetailCodeState::NotFound)
        }
        AuditSurfaceMatch::Ambiguous => {
            AuditDetailCodeResult::fallback(AuditDetailCodeState::Ambiguous)
        }
    }
}

pub(super) fn load_audit_surface_text_for_file_state(
    path: &Path,
    options: &LoadOptions,
    target: &AuditDetailCodeTarget,
    file_state: Option<GuiFileState>,
) -> AuditDetailCodeResult {
    let Some(expected) = file_state else {
        return AuditDetailCodeResult::fallback(AuditDetailCodeState::FileChanged);
    };
    match GuiFileState::read(path) {
        Ok(current) if current == expected => {
            let result = load_audit_surface_text(path, options, target);
            // The file can be replaced between the metadata check and the read.
            match GuiFileState::read(path) {
                Ok(after) if after == expected => result,
                _ => AuditDetailCodeResult::fallback(AuditDetailCodeState::FileChanged),
            }
        }
        Ok(_) => AuditDetailCodeResult::fallback(AuditDetailCodeState::FileChanged),
        Err(error) => AuditDetailCodeResult::fallback(AuditDetailCodeState::Failed {
            error: error.to_string(),
        }),
    }
}

pub(super) fn audit_detail_code_note_key(state: &AuditDetailCodeState) -> Option<&'static str> {
    Some(match state {
        AuditDetailCodeState::Loading { .. } => "audit_detail.code_loading",
        AuditDetailCodeState::Loaded { derived: true } => "audit_detail.code_derived_parent",
        AuditDetailCodeState::NotFound => "audit_detail.code_not_found",
        AuditDetailCodeState::Ambiguous => "audit_detail.code_ambiguous",
        AuditDetailCodeState::Failed { .. } => "audit_detail.code_load_failed",
        AuditDetailCodeState::Unavailable => "audit_detail.code_unavailable",
        AuditDetailCodeState::FileChanged => "audit_detail.code_file_changed",
        AuditDetailCodeState::TooLarge => "audit_detail.code_too_large",
        AuditDetailCodeState::NotApplicable | AuditDetailCodeState::Loaded { derived: false } => {
            return None;
        }
    })
}

const AUDIT_DETAIL_TAB_PANEL_HEIGHT: Pixels = px(420.0);
const AUDIT_DETAIL_DIALOG_CHROME_HEIGHT: Pixels = px(300.0);
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
        let code_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .default_value(preview_text.clone())
                .read_only(true)
        });

        let code_target = self.resolve_audit_detail_code_target(&key);
        let row = self
            .index_of_row_id(key.row_id)
            .and_then(|index| self.rows.get(index));
        let code_generation = row.map_or(0, |row| row.audit_generation);
        let load = row
            .zip(code_target.clone())
            .filter(|_| {
                detail
                    .as_ref()
                    .is_some_and(|detail| detail.row_keys.len() == 1)
            })
            .map(|(row, target)| (row.path.clone(), row.audit_file_state, target));
        let code = if key.item_kind != AuditResultItemKind::Finding {
            AuditDetailCodeState::NotApplicable
        } else if load.is_some() {
            self.audit_detail_code_request += 1;
            AuditDetailCodeState::Loading {
                request: self.audit_detail_code_request,
            }
        } else {
            AuditDetailCodeState::Unavailable
        };
        self.audit_detail_dialog = Some(AuditDetailDialogState {
            key: key.clone(),
            active_tab: AuditDetailTab::Code,
            code_input,
            code_text: preview_text.clone().into(),
            preview_text,
            code,
            code_target,
            code_generation,
        });

        if let Some((path, file_state, target)) = load {
            let options = self.scene_load_options();
            let request = self.audit_detail_code_request;
            let view = cx.entity();
            window
                .spawn(cx, move |cx: &mut AsyncWindowContext| {
                    let executor = cx.background_executor().clone();
                    let mut async_cx = cx.clone();
                    async move {
                        let result = executor
                            .spawn(async move {
                                load_audit_surface_text_for_file_state(
                                    &path, &options, &target, file_state,
                                )
                            })
                            .await;
                        let _ = async_cx.update_window_entity(
                            &view,
                            move |shell: &mut GuiShell,
                                  window: &mut Window,
                                  cx: &mut Context<GuiShell>| {
                                shell.apply_audit_detail_code_result(
                                    &key, request, result, window, cx,
                                );
                            },
                        );
                    }
                })
                .detach();
        }

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

    fn resolve_audit_detail_code_target(
        &self,
        key: &AuditResultRowKey,
    ) -> Option<AuditDetailCodeTarget> {
        if key.item_kind != AuditResultItemKind::Finding {
            return None;
        }
        let row = self.rows.get(self.index_of_row_id(key.row_id)?)?;
        let report = row.display_audit_report()?;
        let finding = report.findings.get(key.item_index)?;
        let surface = report.surfaces.get(finding.surface_index)?;
        Some(AuditDetailCodeTarget {
            origin: surface.origin.clone(),
            derived: surface.derivation != AuditSurfaceDerivation::Observed,
        })
    }

    fn audit_detail_code_identity_is_current(&self, state: &AuditDetailDialogState) -> bool {
        state.code_target.is_some()
            && self.resolve_audit_detail_code_target(&state.key) == state.code_target
    }

    pub(super) fn audit_detail_code_copy_enabled(&self) -> bool {
        self.audit_detail_dialog.as_ref().is_some_and(|state| {
            (matches!(state.code, AuditDetailCodeState::Loaded { .. })
                || state.key.item_kind == AuditResultItemKind::DumpScriptNode)
                && !state.code_text.is_empty()
                && state.code_text.as_ref() != "-"
        })
    }

    pub(super) fn audit_detail_code_clipboard_text(&self, cx: &App) -> Option<String> {
        if !self.audit_detail_code_copy_enabled() {
            return None;
        }
        let state = self.audit_detail_dialog.as_ref()?;
        Some(state.code_input.read(cx).value().to_string())
    }

    pub(super) fn apply_audit_detail_code_result(
        &mut self,
        key: &AuditResultRowKey,
        request: u64,
        result: AuditDetailCodeResult,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(state) = self.audit_detail_dialog.as_ref() else {
            return;
        };
        if &state.key != key || state.code != (AuditDetailCodeState::Loading { request }) {
            return;
        }
        self.sync_audit_detail_dialog_inputs(window, cx);
        let state = self.audit_detail_dialog.as_mut().unwrap();
        if state.code != (AuditDetailCodeState::Loading { request }) {
            cx.notify();
            return;
        }
        state.code = result.state;
        if let Some(text) = result.text {
            state.code_input.update(cx, |input, cx| {
                input.set_value(text.to_string(), window, cx)
            });
            state.code_text = state.code_input.read(cx).value();
        }
        cx.notify();
    }

    pub(super) fn sync_audit_detail_dialog_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(state) = self.audit_detail_dialog.as_ref() else {
            return;
        };
        let detail = resolve_audit_detail_view_model(&self.audit_rows, &state.key);
        let generation_changed = self
            .index_of_row_id(state.key.row_id)
            .and_then(|index| self.rows.get(index))
            .is_some_and(|row| row.audit_generation != state.code_generation);
        let invalid = state.key.item_kind == AuditResultItemKind::Finding
            && (generation_changed
                || detail
                    .as_ref()
                    .is_some_and(|detail| detail.row_keys.len() > 1)
                || detail.is_none()
                || !self.audit_detail_code_identity_is_current(state));
        let preview_text = detail
            .as_ref()
            .map(audit_detail_preview_text)
            .unwrap_or_else(|| "-".to_string());
        let state = self.audit_detail_dialog.as_mut().unwrap();
        if invalid {
            state.code = AuditDetailCodeState::Unavailable;
        } else if matches!(state.code, AuditDetailCodeState::Loaded { .. }) {
            return;
        }
        if state.preview_text != preview_text
            || (invalid && state.code_text.as_ref() != preview_text.as_str())
        {
            state.code_input.update(cx, |input, cx| {
                input.set_value(preview_text.clone(), window, cx);
                input.set_read_only(true, window, cx);
            });
            state.code_text = state.code_input.read(cx).value();
            state.preview_text = preview_text;
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
                let detail_state = shell.audit_detail_dialog.as_ref();
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
                    Button::new("audit-detail-copy-code")
                        .label(i18n.text("action.copy_code"))
                        .disabled(!shell.audit_detail_code_copy_enabled())
                        .on_click({
                            let view = view.clone();
                            move |_, _, cx| {
                                if let Some(text) =
                                    view.read(cx).audit_detail_code_clipboard_text(cx)
                                {
                                    cx.write_to_clipboard(ClipboardItem::new_string(text));
                                }
                            }
                        })
                        .into_any_element(),
                );
                buttons.push(
                    Button::new("audit-detail-copy")
                        .label(i18n.text("action.copy_details"))
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
                                .label(i18n.text("action.close"))
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
            view,
            px(160.0).max(
                AUDIT_DETAIL_TAB_PANEL_HEIGHT
                    .min(layout.max_height - AUDIT_DETAIL_DIALOG_CHROME_HEIGHT),
            ),
            &i18n,
        ))
}

fn render_audit_detail_dialog_body(
    detail: Option<&AuditDetailViewModel>,
    dialog_state: Option<&AuditDetailDialogState>,
    view: Entity<GuiShell>,
    panel_height: Pixels,
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
    let facts = audit_detail_header_facts(&detail.detail_fields, i18n);
    let evidence_text = Some(audit_detail_evidence_text(detail)).filter(|text| text != "-");
    let selected_index = match dialog_state.active_tab {
        AuditDetailTab::Code => 0,
        AuditDetailTab::Details => 1,
    };

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
                .children(facts.map(|facts| {
                    // Text truncation caches its first measurement, so the line must sit in a row
                    // where the measured width is the final one (same layout as the summary).
                    div().flex().min_w_0().child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .truncate()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child(facts),
                    )
                })),
        )
        .child(
            div()
                .debug_selector(|| "audit-detail-tabs".to_string())
                .child(
                    TabBar::new("audit-detail-tabs")
                        .underline()
                        .selected_index(selected_index)
                        .on_click(move |ix, _, cx| {
                            let tab = match ix {
                                0 => AuditDetailTab::Code,
                                1 => AuditDetailTab::Details,
                                _ => return,
                            };
                            view.update(cx, |shell, cx| {
                                if let Some(state) = shell.audit_detail_dialog.as_mut() {
                                    state.active_tab = tab;
                                    cx.notify();
                                }
                            });
                        })
                        .children([
                            Tab::new().label(i18n.text("tab.audit_detail_code")),
                            Tab::new().label(i18n.text("tab.audit_detail_details")),
                        ]),
                ),
        )
        .child(match dialog_state.active_tab {
            AuditDetailTab::Code => div()
                .debug_selector(|| "audit-detail-panel-code".to_string())
                .children(audit_detail_code_note_key(&dialog_state.code).map(|key| {
                    let text = match &dialog_state.code {
                        AuditDetailCodeState::Failed { error } => {
                            i18n.format(key, &[("error", error.clone())])
                        }
                        _ => i18n.text(key),
                    };
                    div().text_sm().text_color(rgb(MUTED)).child(text)
                }))
                .child(render_audit_detail_text_panel(
                    &dialog_state.code_input,
                    panel_height,
                ))
                .into_any_element(),
            AuditDetailTab::Details => div()
                .id("audit-detail-fields")
                .debug_selector(|| "audit-detail-panel-details".to_string())
                .h(panel_height)
                .min_h(panel_height)
                .overflow_y_scrollbar()
                .when(
                    detail.detail_fields.is_empty() && evidence_text.is_none(),
                    |this| this.child("-"),
                )
                .children(
                    detail
                        .detail_fields
                        .iter()
                        .map(|field| {
                            (
                                audit_detail_field_label(field.kind, i18n),
                                audit_detail_field_display(field, &detail.detail_fields, i18n),
                            )
                        })
                        .chain(evidence_text.map(|text| (i18n.text("label.evidence"), text)))
                        .map(|(label, value)| {
                            div()
                                .flex()
                                .gap_3()
                                .text_sm()
                                .child(div().w(px(200.0)).flex_shrink_0().child(label))
                                .child(div().flex_1().min_w_0().child(value))
                        }),
                )
                .into_any_element(),
        })
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

pub(super) fn audit_detail_preview_text(detail: &AuditDetailViewModel) -> String {
    if detail.preview.is_empty() {
        "-".to_string()
    } else {
        detail.preview.clone()
    }
}

pub(super) fn audit_detail_evidence_text(detail: &AuditDetailViewModel) -> String {
    let mut lines = Vec::new();
    if detail.scene_names.len() > 1 {
        lines.push("scenes:".to_string());
        lines.extend(detail.scene_names.iter().cloned());
    }
    let evidence = detail
        .evidence
        .iter()
        .filter(|entry| !entry.starts_with("node_name: "))
        .cloned()
        .collect::<Vec<_>>();
    if evidence.is_empty() {
        lines.push("-".to_string());
    } else {
        lines.extend(evidence);
    }

    lines.join("\n")
}

pub(super) fn audit_detail_field_label(field: AuditDetailFieldKind, i18n: &I18n) -> String {
    use AuditDetailFieldKind::*;
    i18n.text(match field {
        RuleId => "label.audit_detail.rule_id",
        Sink => "label.audit_detail.sink",
        Node => "label.audit_detail.node",
        Attribute => "label.audit_detail.attribute",
        Surface => "label.audit_detail.surface",
        Trigger => "label.audit_detail.trigger",
        Language => "label.audit_detail.language",
        Source => "label.audit_detail.source",
        Line => "label.audit_detail.line",
    })
}

pub(super) fn audit_detail_field_display(
    field: &AuditDetailField,
    fields: &[AuditDetailField],
    i18n: &I18n,
) -> String {
    use AuditDetailFieldKind::*;
    let raw = &field.raw;
    let translated = match field.kind {
        Surface => i18n.try_text(&format!("audit_value.surface.{raw}")),
        Trigger => i18n.try_text(&format!("audit_value.trigger.{raw}")),
        Language => i18n.try_text(&format!("audit_value.language.{raw}")),
        Attribute
            if fields
                .iter()
                .any(|field| field.kind == Surface && field.raw == "script_node_body") =>
        {
            match raw.as_str() {
                ".b" | "b" => i18n.try_text("audit_value.attribute.before"),
                ".a" | "a" => i18n.try_text("audit_value.attribute.after"),
                _ => None,
            }
        }
        Source => {
            let lookup_number = |part: &str, prefix: &str, key_prefix: &str| {
                let number = part.strip_prefix(prefix)?;
                if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                i18n.try_text(&format!("audit_value.{key_prefix}.{number}"))
            };
            if let Some((script, source)) = raw.split_once(',') {
                lookup_number(script, "scriptType=", "script_type")
                    .zip(lookup_number(source, "sourceType=", "source_type"))
                    .map(|(script, source)| format!("{script} / {source}"))
            } else {
                lookup_number(raw, "scriptType=", "script_type")
                    .or_else(|| lookup_number(raw, "sourceType=", "source_type"))
            }
        }
        _ => None,
    };
    translated.map_or_else(|| raw.clone(), |translated| format!("{translated} ({raw})"))
}

pub(super) fn audit_detail_header_facts(
    fields: &[AuditDetailField],
    i18n: &I18n,
) -> Option<String> {
    let facts = [AuditDetailFieldKind::Node, AuditDetailFieldKind::Trigger]
        .into_iter()
        .filter_map(|kind| fields.iter().find(|field| field.kind == kind))
        .filter(|field| field.kind != AuditDetailFieldKind::Trigger || field.raw != "unknown")
        .map(|field| {
            format!(
                "{}: {}",
                audit_detail_field_label(field.kind, i18n),
                audit_detail_field_display(field, fields, i18n)
            )
        })
        .collect::<Vec<_>>();
    if facts.is_empty() {
        None
    } else {
        Some(facts.join("  |  "))
    }
}
