use super::{super::*, helpers::normalize_path_edit_targets};

impl GuiShell {
    pub(in crate::gui) fn capture_path_order_snapshot(&self) -> Option<PathOrderSnapshot> {
        let model = self.current_path_table_model();
        let mut order_by_target = BTreeMap::new();
        for (row_ix, row) in model.rows.iter().enumerate() {
            for target in &row.edit_targets {
                order_by_target.entry(*target).or_insert(row_ix);
            }
        }
        (!order_by_target.is_empty()).then_some(PathOrderSnapshot { order_by_target })
    }

    pub(in crate::gui) fn preserve_path_order_after_path_mutation(
        &mut self,
        snapshot: Option<PathOrderSnapshot>,
    ) {
        self.path_order_snapshot = snapshot;
        self.path_sort = PathTableSort {
            key: PathSortKey::CapturedOrder,
            direction: ColumnSort::Ascending,
        };
    }

    pub(in crate::gui) fn current_path_table_model(&self) -> PathTableModel {
        let mut model = build_path_table_model_with_order_snapshot(
            &self.rows,
            &self.selected_indices(),
            &self.state,
            self.active_path_edit.clone(),
            &self.selected_path_rows,
            self.path_table_dedup,
            &self.path_search_query,
            &self.path_type_filter,
            &self.path_form_filter,
            &self.path_resolution_filter,
            self.path_sort,
            self.path_order_snapshot.as_ref(),
        );
        if self.path_dirty_only {
            model.rows.retain(|row| row.dirty);
        }
        model
    }

    pub(in crate::gui) fn current_audit_table_model(&self) -> AuditTableModel {
        build_audit_table_model(
            &self.audit_all_rows,
            &self.selected_audit_keys,
            &self.audit_severity_filter,
            self.audit_dirty_only,
            self.audit_table_dedup,
            &self.audit_search_query,
            self.audit_sort,
            self.locale(),
        )
    }

    pub(in crate::gui) fn refresh_path_table(&mut self, cx: &mut Context<Self>) {
        let i18n = self.i18n();
        let path_table = self.current_path_table_model();
        let path_table_summary = PathTableSummary {
            row_count: path_table.rows.len(),
            has_report_rows: path_table.has_report_rows,
        };
        let visible_targets = path_table
            .rows
            .iter()
            .map(|row| row.edit_targets.clone())
            .filter(|targets| !targets.is_empty())
            .collect::<BTreeSet<_>>();
        self.selected_path_rows
            .retain(|targets| visible_targets.contains(targets));
        if self
            .path_selection_anchor
            .as_ref()
            .is_some_and(|targets| !visible_targets.contains(targets))
        {
            self.path_selection_anchor = None;
        }
        self.path_table_summary = path_table_summary;
        self.path_table.update(cx, |table, cx| {
            table.delegate_mut().sync(
                path_table.rows,
                i18n.locale(),
                path_table.show_scene_column,
                self.path_sort,
            );
            table.refresh(cx);
        });
    }

    pub(in crate::gui) fn select_path_row(
        &mut self,
        edit_targets: PathEditTargets,
        modifiers: Modifiers,
        cx: &mut Context<Self>,
    ) {
        let edit_targets = normalize_path_edit_targets(edit_targets);
        if edit_targets.is_empty() {
            return;
        }

        let path_table = self.current_path_table_model();
        let toggle = modifiers.control || modifiers.platform;
        let extend = modifiers.shift;

        self.active_path_edit = None;

        if extend {
            let anchor = self
                .path_selection_anchor
                .clone()
                .filter(|anchor| {
                    path_table
                        .rows
                        .iter()
                        .any(|row| &row.edit_targets == anchor)
                })
                .unwrap_or_else(|| edit_targets.clone());
            let Some(range_targets) =
                visible_path_selection_targets(&path_table.rows, &anchor, &edit_targets)
            else {
                return;
            };
            if !toggle {
                self.selected_path_rows.clear();
            }
            self.selected_path_rows.extend(range_targets);
            self.path_selection_anchor = Some(anchor);
            self.refresh_path_table(cx);
            cx.notify();
            return;
        }

        if toggle {
            if !self.selected_path_rows.insert(edit_targets.clone()) {
                self.selected_path_rows.remove(&edit_targets);
            }
            self.path_selection_anchor = Some(edit_targets);
            self.refresh_path_table(cx);
            cx.notify();
            return;
        }

        self.selected_path_rows.clear();
        self.selected_path_rows.insert(edit_targets.clone());
        self.path_selection_anchor = Some(edit_targets);
        self.refresh_path_table(cx);
        cx.notify();
    }

    pub(in crate::gui) fn toggle_path_table_dedup(&mut self, cx: &mut Context<Self>) {
        self.path_table_dedup = !self.path_table_dedup;
        self.refresh_path_table(cx);
    }

    pub(in crate::gui) fn toggle_path_dirty_filter(&mut self, cx: &mut Context<Self>) {
        self.path_dirty_only = !self.path_dirty_only;
        self.refresh_path_table(cx);
    }

    pub(in crate::gui) fn toggle_audit_table_dedup(&mut self, cx: &mut Context<Self>) {
        self.audit_table_dedup = !self.audit_table_dedup;
        self.refresh_audit_table(cx);
    }

    pub(in crate::gui) fn toggle_audit_dirty_filter(&mut self, cx: &mut Context<Self>) {
        self.audit_dirty_only = !self.audit_dirty_only;
        self.refresh_audit_table(cx);
    }

    pub(in crate::gui) fn toggle_path_type_filter(
        &mut self,
        filter: PathTypeFilter,
        cx: &mut Context<Self>,
    ) {
        if !self.path_type_filter.insert(filter) {
            self.path_type_filter.remove(&filter);
        }
        self.refresh_path_table(cx);
    }

    pub(in crate::gui) fn toggle_path_form_filter(
        &mut self,
        filter: PathFormFilter,
        cx: &mut Context<Self>,
    ) {
        if !self.path_form_filter.insert(filter) {
            self.path_form_filter.remove(&filter);
        }
        self.refresh_path_table(cx);
    }

    pub(in crate::gui) fn toggle_path_resolution_filter(
        &mut self,
        filter: PathResolutionBadge,
        cx: &mut Context<Self>,
    ) {
        if !self.path_resolution_filter.insert(filter) {
            self.path_resolution_filter.remove(&filter);
        }
        self.refresh_path_table(cx);
    }

    pub(in crate::gui) fn toggle_audit_severity(
        &mut self,
        severity: AuditSeverityFilter,
        cx: &mut Context<Self>,
    ) {
        if !self.audit_severity_filter.insert(severity) {
            self.audit_severity_filter.remove(&severity);
        }
        self.refresh_audit_table(cx);
    }
}
