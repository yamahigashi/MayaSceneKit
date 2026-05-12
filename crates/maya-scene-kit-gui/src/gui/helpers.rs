use maya_scene_kit_observe::scene::scripts::ScriptNodeEntry;

use super::{path_edit::normalize_path_edit_targets, *};

pub(super) fn build_audit_result_rows(
    rows: &[SceneRow],
    selected: &[usize],
) -> Vec<AuditResultRow> {
    let mut out = Vec::new();
    for &index in selected {
        let Some(row) = rows.get(index) else {
            continue;
        };
        if let Some(report) = row.display_audit_report() {
            for (finding_index, finding) in report
                .findings
                .iter()
                .enumerate()
                .take(AUDIT_RESULTS_PER_FILE)
            {
                let surface = report.surface_for(finding);
                let clean_target = clean_target_for_execution_origin(&surface.origin);
                let clean_state = audit_row_clean_state(row, clean_target.as_ref());
                let dirty = audit_item_dirty(row, clean_target.as_ref());
                out.push(AuditResultRow {
                    key: AuditResultRowKey {
                        row_id: row.id,
                        item_kind: AuditResultItemKind::Finding,
                        item_index: finding_index,
                    },
                    scene_name: row.name.clone(),
                    severity: finding.severity,
                    summary: render_audit_finding_detail(&finding.detail),
                    code: finding.code.as_str().to_string(),
                    sink: finding.sink.as_str().to_string(),
                    preview: report.finding_preview(finding).to_string(),
                    provenance: audit_provenance_lines(
                        &surface.origin,
                        audit_source_line(row, &surface.origin),
                    ),
                    source_line: audit_source_line(row, &surface.origin),
                    evidence: finding.evidence.iter().map(render_audit_evidence).collect(),
                    dirty,
                    clean_target,
                    clean_state,
                });
            }
        }
        if let Some(dump_report) = row.display_dump_report() {
            out.extend(build_dump_info_rows(row, dump_report));
        }
    }
    out
}

pub(super) fn clean_targets_for_threat_findings(row: &SceneRow) -> Vec<ExecutionCleanTarget> {
    let Some(report) = row.display_audit_report() else {
        return Vec::new();
    };
    let mut targets = BTreeSet::<ExecutionCleanTarget>::new();
    for finding in &report.findings {
        let surface = report.surface_for(finding);
        if let Some(target) = clean_target_for_execution_origin(&surface.origin) {
            targets.insert(target);
        }
    }
    targets.into_iter().collect()
}

fn build_dump_info_rows(row: &SceneRow, report: &SceneDumpReport) -> Vec<AuditResultRow> {
    let mut rows = Vec::new();
    for (require_index, require) in report.require_entries.iter().enumerate() {
        let clean_target = dump_require_clean_target(require);
        let clean_state = audit_row_clean_state(row, clean_target.as_ref());
        rows.push(AuditResultRow {
            key: AuditResultRowKey {
                row_id: row.id,
                item_kind: AuditResultItemKind::DumpRequire,
                item_index: require_index,
            },
            scene_name: row.name.clone(),
            severity: AuditSeverity::Info,
            summary: format!("require {}", require.rendered),
            code: "require".to_string(),
            sink: "observe".to_string(),
            preview: require.rendered.clone(),
            provenance: Vec::new(),
            source_line: None,
            evidence: Vec::new(),
            dirty: audit_item_dirty(row, clean_target.as_ref()),
            clean_target: clean_target.clone(),
            clean_state,
        });
    }
    for (script_index, entry) in report.script_entries.iter().enumerate() {
        let clean_target = dump_script_clean_target(row, entry);
        let clean_state = audit_row_clean_state(row, clean_target.as_ref());
        rows.push(AuditResultRow {
            key: AuditResultRowKey {
                row_id: row.id,
                item_kind: AuditResultItemKind::DumpScriptNode,
                item_index: script_index,
            },
            scene_name: row.name.clone(),
            severity: AuditSeverity::Info,
            summary: format!("script {}", entry.name),
            code: "script_node".to_string(),
            sink: "observe".to_string(),
            preview: entry.body.trim_end_matches('\n').to_string(),
            provenance: vec![format!("node: {}", entry.name)],
            source_line: None,
            evidence: vec![format!("node: {}", entry.name)],
            dirty: audit_item_dirty(row, clean_target.as_ref()),
            clean_target: clean_target.clone(),
            clean_state,
        });
    }

    rows
}

fn dump_script_clean_target(
    row: &SceneRow,
    entry: &ScriptNodeEntry,
) -> Option<ExecutionCleanTarget> {
    row.display_audit_report()
        .as_ref()
        .and_then(|report| {
            report
                .surfaces
                .iter()
                .find(|surface| {
                    surface.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody
                        && surface.origin.node_name.as_deref() == Some(entry.name.as_str())
                })
                .and_then(|surface| clean_target_for_execution_origin(&surface.origin))
        })
        .or_else(|| dump_script_mb_owner_form_target(row, entry))
        .or_else(|| {
            Some(ExecutionCleanTarget::ScriptNode {
                node_name: entry.name.clone(),
            })
        })
}

fn dump_script_mb_owner_form_target(
    row: &SceneRow,
    entry: &ScriptNodeEntry,
) -> Option<ExecutionCleanTarget> {
    let body = entry.body.trim_end_matches('\n').trim();
    collect_raw_chunks(&row.path)
        .ok()?
        .into_iter()
        .find(|chunk| {
            if chunk.trace_form != "SCRP" {
                return false;
            }
            let payload_text = String::from_utf8_lossy(&chunk.payload);
            payload_text.contains(&entry.name) || (!body.is_empty() && payload_text.contains(body))
        })
        .map(|chunk| ExecutionCleanTarget::MbOwnerForm {
            form: chunk.trace_form,
            node_offset: chunk.trace_node_offset,
        })
}

fn dump_require_clean_target(require: &SceneDumpRequireEntry) -> Option<ExecutionCleanTarget> {
    match require.kind {
        SceneDumpRequireKind::MayaVersion => None,
        SceneDumpRequireKind::Plugin => Some(ExecutionCleanTarget::PluginRequire {
            rendered: require.rendered.clone(),
        }),
    }
}

fn audit_row_clean_state(
    row: &SceneRow,
    clean_target: Option<&ExecutionCleanTarget>,
) -> AuditRowCleanState {
    match clean_target {
        None => AuditRowCleanState::Unsupported,
        Some(target) if row.pending_clean_targets.contains(target) => AuditRowCleanState::Staged,
        Some(_)
            if row.is_processing()
                || matches!(
                    row.dirty_kind,
                    Some(DirtyKind::Replace | DirtyKind::ToAscii)
                ) =>
        {
            AuditRowCleanState::BlockedByOtherDirty
        }
        Some(_) => AuditRowCleanState::Available,
    }
}

fn audit_item_dirty(row: &SceneRow, clean_target: Option<&ExecutionCleanTarget>) -> bool {
    clean_target.is_some_and(|target| row.pending_clean_targets.contains(target))
}

fn audit_source_line(row: &SceneRow, origin: &ExecutionOrigin) -> Option<usize> {
    let source_range = origin.source_range?;
    let bytes = fs::read(&row.path).ok()?;
    if source_range.start > bytes.len() {
        return None;
    }
    Some(
        bytes[..source_range.start]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1,
    )
}

fn audit_provenance_lines(origin: &ExecutionOrigin, source_line: Option<usize>) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(node_name) = origin.node_name.as_deref() {
        lines.push(format!("node: {node_name}"));
    }
    if let Some(attr_name) = origin.attr_name.as_deref() {
        lines.push(format!("attribute: {attr_name}"));
    }
    lines.push(format!("surface: {}", origin.surface_kind.as_str()));
    lines.push(format!("trigger: {}", origin.trigger.as_str()));
    if let Some(source_kind) = origin.source_kind.as_deref() {
        lines.push(format!("source: {source_kind}"));
    }
    if let Some(source_line) = source_line {
        lines.push(format!("line: {source_line}"));
    }
    lines
}

pub(super) fn build_audit_table_model(
    rows: &[AuditResultRow],
    selected_keys: &BTreeSet<AuditResultRowKey>,
    filter: &BTreeSet<AuditSeverityFilter>,
    dirty_only: bool,
    dedup: bool,
    search_query: &str,
    sort: AuditTableSort,
    locale: SupportedLocale,
) -> AuditTableModel {
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct AuditDedupKey {
        severity_rank: u8,
        summary: String,
        code: String,
        sink: String,
        preview: String,
        provenance: Vec<String>,
        source_line: Option<usize>,
        evidence: Vec<String>,
        clean_target: Option<ExecutionCleanTarget>,
        clean_state: AuditRowCleanState,
    }

    struct DedupAuditGroup {
        row_keys: Vec<AuditResultRowKey>,
        scene_names: BTreeSet<String>,
        row: AuditResultRow,
    }

    let filtered = filter_audit_result_rows(rows, filter)
        .into_iter()
        .filter(|row| !dirty_only || row.dirty)
        .collect::<Vec<_>>();
    let mut display_rows = Vec::new();
    if dedup {
        let mut groups = Vec::<DedupAuditGroup>::new();
        let mut group_indices = BTreeMap::<AuditDedupKey, usize>::new();
        for row in filtered {
            let group_key = AuditDedupKey {
                severity_rank: audit_severity_rank(row.severity),
                summary: row.summary.clone(),
                code: row.code.clone(),
                sink: row.sink.clone(),
                preview: row.preview.clone(),
                provenance: row.provenance.clone(),
                source_line: row.source_line,
                evidence: row.evidence.clone(),
                clean_target: row.clean_target.clone(),
                clean_state: row.clean_state,
            };
            let group_ix = *group_indices.entry(group_key).or_insert_with(|| {
                groups.push(DedupAuditGroup {
                    row_keys: Vec::new(),
                    scene_names: BTreeSet::new(),
                    row: row.clone(),
                });
                groups.len() - 1
            });
            let group = &mut groups[group_ix];
            group.row_keys.push(row.key.clone());
            group.scene_names.insert(row.scene_name.clone());
            group.row.dirty |= row.dirty;
        }

        let i18n = I18n::new(locale);
        for group in groups {
            let scene_names = group.scene_names.into_iter().collect::<Vec<_>>();
            let scene_name = if scene_names.len() == 1 {
                scene_names[0].clone()
            } else {
                i18n.format(
                    "audit_table.scenes_count",
                    &[("count", scene_names.len().to_string())],
                )
            };
            display_rows.push(AuditTableRow {
                key: group.row.key.clone(),
                row_keys: group.row_keys,
                selected: selected_keys.contains(&group.row.key),
                scene_name,
                scene_names,
                severity: group.row.severity,
                summary: group.row.summary,
                code: group.row.code,
                sink: group.row.sink,
                preview: group.row.preview,
                provenance: group.row.provenance,
                source_line: group.row.source_line,
                evidence: group.row.evidence,
                dirty: group.row.dirty,
                clean_target: group.row.clean_target,
                clean_state: group.row.clean_state,
            });
        }
    } else {
        display_rows = filtered
            .into_iter()
            .map(|row| AuditTableRow {
                key: row.key.clone(),
                row_keys: vec![row.key.clone()],
                selected: selected_keys.contains(&row.key),
                scene_name: row.scene_name.clone(),
                scene_names: vec![row.scene_name.clone()],
                severity: row.severity,
                summary: row.summary,
                code: row.code,
                sink: row.sink,
                preview: row.preview,
                provenance: row.provenance,
                source_line: row.source_line,
                evidence: row.evidence,
                dirty: row.dirty,
                clean_target: row.clean_target,
                clean_state: row.clean_state,
            })
            .collect();
    }

    let tokens = tokenize_search_query(search_query);
    display_rows
        .retain(|row| matches_search_tokens(searchable_text_for_audit_row(row, locale), &tokens));
    sort_audit_rows(&mut display_rows, sort);

    AuditTableModel { rows: display_rows }
}

pub(super) fn resolve_audit_detail_view_model(
    rows: &[AuditTableRow],
    key: &AuditResultRowKey,
) -> Option<AuditDetailViewModel> {
    let row = rows.iter().find(|row| &row.key == key)?;
    Some(AuditDetailViewModel {
        key: row.key.clone(),
        row_keys: row.row_keys.clone(),
        scene_name: row.scene_name.clone(),
        scene_names: row.scene_names.clone(),
        severity: row.severity,
        summary: row.summary.clone(),
        code: row.code.clone(),
        sink: row.sink.clone(),
        preview: row.preview.clone(),
        provenance: row.provenance.clone(),
        source_line: row.source_line,
        evidence: row.evidence.clone(),
        clean_target: row.clean_target.clone(),
        clean_state: row.clean_state,
    })
}

pub(super) fn resolve_audit_clipboard_payload(
    rows: &[AuditTableRow],
    key: &AuditResultRowKey,
) -> Option<String> {
    let detail = resolve_audit_detail_view_model(rows, key)?;
    Some(build_audit_clipboard_payload(
        &detail.provenance,
        &detail.preview,
        &detail.evidence,
    ))
}

pub(super) fn build_job_history_log_lines(i18n: &I18n, entries: &[JobHistoryEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| {
            let operation = operation_label_for_job_history(i18n, &entry.operation);
            let timestamp = entry.timestamp.clone().unwrap_or_else(|| "-".to_string());
            let path_text = match entry.output.as_ref() {
                Some(output) => format!("{} -> {}", entry.input.display(), output.display()),
                None => entry.input.display().to_string(),
            };
            format!(
                "{timestamp} | {operation} | {path_text} | {}",
                entry.summary
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn build_path_table_model(
    rows: &[SceneRow],
    selected: &[usize],
    state: &PersistedState,
    active_path_edit: Option<PathEditTargets>,
    selected_path_rows: &BTreeSet<PathEditTargets>,
    dedup: bool,
    search_query: &str,
    path_type_filter: &BTreeSet<PathTypeFilter>,
    path_form_filter: &BTreeSet<PathFormFilter>,
    path_resolution_filter: &BTreeSet<PathResolutionBadge>,
    sort: PathTableSort,
) -> PathTableModel {
    build_path_table_model_with_order_snapshot(
        rows,
        selected,
        state,
        active_path_edit,
        selected_path_rows,
        dedup,
        search_query,
        path_type_filter,
        path_form_filter,
        path_resolution_filter,
        sort,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_path_table_model_with_order_snapshot(
    rows: &[SceneRow],
    selected: &[usize],
    state: &PersistedState,
    active_path_edit: Option<PathEditTargets>,
    selected_path_rows: &BTreeSet<PathEditTargets>,
    dedup: bool,
    search_query: &str,
    path_type_filter: &BTreeSet<PathTypeFilter>,
    path_form_filter: &BTreeSet<PathFormFilter>,
    path_resolution_filter: &BTreeSet<PathResolutionBadge>,
    sort: PathTableSort,
    order_snapshot: Option<&PathOrderSnapshot>,
) -> PathTableModel {
    struct DedupPathGroup {
        kind: PathTypeFilter,
        edit_targets: PathEditTargets,
        first_scene: String,
        first_node: String,
        scene_names: BTreeSet<String>,
        node_names: BTreeSet<String>,
        value: String,
        value_style: Option<ScenePathValueStyle>,
        dirty: bool,
        resolution_badge: Option<PathResolutionBadge>,
        owner_deletable: bool,
        owner_deleted: bool,
        editable: bool,
    }

    let mut path_rows = Vec::new();
    let mut contributing_sources = 0usize;
    let mut has_report_rows = false;
    let active_path_edit = normalize_path_edit_targets(active_path_edit.unwrap_or_default());
    let selected_path_rows = selected_path_rows
        .iter()
        .cloned()
        .map(normalize_path_edit_targets)
        .collect::<BTreeSet<_>>();
    let mut group_order = Vec::<DedupPathGroup>::new();
    let mut group_indices = BTreeMap::<
        (
            PathTypeFilter,
            String,
            Option<PathResolutionBadge>,
            Option<PathBuf>,
        ),
        usize,
    >::new();

    let normalized_query = search_query.trim().to_ascii_lowercase();
    let matches_query = |value: &str| {
        if normalized_query.is_empty() {
            return true;
        }
        let value = value.to_ascii_lowercase();
        value.contains(&normalized_query)
    };

    for &index in selected {
        let Some(row) = rows.get(index) else {
            continue;
        };
        let scene = workspace_relative_display_path(&row.path, state);
        let mut contributed = false;

        if let Some(report) = row.display_paths_report() {
            has_report_rows = true;
            contributed = true;
            for (entry_index, entry) in report.entries.iter().enumerate() {
                let path_kind = path_type_for_node_type(&entry.node_type);
                if !path_type_filter.contains(&path_kind) {
                    continue;
                }
                let value = row
                    .path_overrides
                    .get(&entry_index)
                    .cloned()
                    .unwrap_or_else(|| entry.value.clone());
                let is_dirty = row.path_overrides.contains_key(&entry_index)
                    || path_owner_delete_dirty_for_entry(row, entry_index);
                let resolution = row.path_resolution(entry_index, &value).cloned();
                let value_style = resolution
                    .as_ref()
                    .map(|resolution| resolution.style)
                    .unwrap_or_else(|| infer_scene_path_value_style(&value));
                let path_form = path_form_for_style(value_style);
                let resolution_badge =
                    resolution
                        .as_ref()
                        .map(|resolution| match resolution.status {
                            ScenePathResolutionStatus::Exists => PathResolutionBadge::Exists,
                            ScenePathResolutionStatus::Missing => PathResolutionBadge::Missing,
                            ScenePathResolutionStatus::Unresolved => {
                                PathResolutionBadge::Unresolved
                            }
                        });
                if !resolution_badge
                    .map(|badge| path_resolution_filter.contains(&badge))
                    .unwrap_or(true)
                {
                    continue;
                }
                if !path_form_filter.contains(&path_form) {
                    continue;
                }
                if dedup {
                    let group_key = (
                        path_kind,
                        value.clone(),
                        resolution_badge,
                        resolution
                            .as_ref()
                            .and_then(|resolution| resolution.resolved_path.clone()),
                    );
                    let node = format!("{} [{}]", entry.node_name, entry.node_type);
                    let group_ix = *group_indices.entry(group_key).or_insert_with(|| {
                        group_order.push(DedupPathGroup {
                            kind: path_kind,
                            edit_targets: Vec::new(),
                            first_scene: scene.clone(),
                            first_node: node.clone(),
                            scene_names: BTreeSet::new(),
                            node_names: BTreeSet::new(),
                            value: value.clone(),
                            value_style: Some(value_style),
                            dirty: false,
                            resolution_badge,
                            owner_deletable: true,
                            owner_deleted: false,
                            editable: super::path_edit::path_value_edit_supported_for_entry(
                                row,
                                entry_index,
                            ),
                        });
                        group_order.len() - 1
                    });
                    let group = &mut group_order[group_ix];
                    group.scene_names.insert(scene.clone());
                    group.node_names.insert(node);
                    group.dirty |= is_dirty;
                    group.owner_deletable &=
                        path_owner_delete_supported_for_entry(row, entry_index);
                    group.owner_deleted |=
                        super::path_edit::path_owner_delete_staged_for_entry(row, entry_index);
                    group.editable &=
                        super::path_edit::path_value_edit_supported_for_entry(row, entry_index);
                    group.edit_targets.push((row.id, entry_index));
                } else {
                    let node = format!("{} [{}]", entry.node_name, entry.node_type);
                    if !matches_query(&value) {
                        continue;
                    }
                    let edit_targets = vec![(row.id, entry_index)];
                    path_rows.push(PathTableRow {
                        edit_targets: edit_targets.clone(),
                        captured_order: path_order_for_targets(order_snapshot, &edit_targets),
                        path_kind,
                        owner_deletable: path_owner_delete_supported_for_entry(row, entry_index),
                        owner_deleted: super::path_edit::path_owner_delete_staged_for_entry(
                            row,
                            entry_index,
                        ),
                        selected: selected_path_rows.contains(&edit_targets),
                        scene: scene.clone(),
                        node,
                        value,
                        value_style: Some(value_style),
                        dirty: is_dirty,
                        resolution_badge,
                        editable: super::path_edit::path_value_edit_supported_for_entry(
                            row,
                            entry_index,
                        ),
                        editing: active_path_edit == edit_targets,
                        preview_only: false,
                    });
                }
            }
        } else if let Some(preview) = row.replace_preview.as_ref() {
            if !preview.items.is_empty() {
                contributed = true;
            }
            for item in &preview.items {
                let path_kind = path_type_for_node_type(&item.node_type);
                if !path_type_filter.contains(&path_kind) {
                    continue;
                }
                let path_form =
                    path_form_for_style(infer_scene_path_value_style(&item.after_value));
                if !path_form_filter.contains(&path_form) {
                    continue;
                }
                let node = format!("{} [{}]", item.node_name, item.node_type);
                let value = format!("{} -> {}", item.before_value, item.after_value);
                if !matches_query(&value) {
                    continue;
                }
                path_rows.push(PathTableRow {
                    edit_targets: Vec::new(),
                    captured_order: None,
                    path_kind,
                    owner_deletable: false,
                    owner_deleted: false,
                    selected: false,
                    scene: scene.clone(),
                    node,
                    value,
                    value_style: None,
                    dirty: false,
                    resolution_badge: None,
                    editable: false,
                    editing: false,
                    preview_only: true,
                });
            }
        }

        if contributed {
            contributing_sources += 1;
        }
    }

    if dedup {
        for mut group in group_order {
            if group.edit_targets.is_empty() {
                continue;
            }
            let edit_targets = normalize_path_edit_targets(std::mem::take(&mut group.edit_targets));
            let scene_count = group.scene_names.len();
            let node_count = group.node_names.len();
            let scene = if scene_count == 1 {
                group.first_scene.clone()
            } else {
                format!("{scene_count}件")
            };
            let node = if node_count == 1 {
                group.first_node.clone()
            } else {
                format!("{node_count}件")
            };
            if !matches_query(&group.value) {
                continue;
            }
            path_rows.push(PathTableRow {
                edit_targets: edit_targets.clone(),
                captured_order: path_order_for_targets(order_snapshot, &edit_targets),
                path_kind: group.kind,
                owner_deletable: group.owner_deletable,
                owner_deleted: group.owner_deleted,
                selected: selected_path_rows.contains(&edit_targets),
                scene,
                node,
                value: group.value.clone(),
                value_style: group.value_style,
                dirty: group.dirty,
                resolution_badge: group.resolution_badge,
                editable: group.editable,
                editing: active_path_edit == edit_targets,
                preview_only: false,
            });
        }
    }

    sort_path_rows(&mut path_rows, sort);

    PathTableModel {
        rows: path_rows,
        has_report_rows,
        show_scene_column: contributing_sources > 1,
    }
}

fn path_order_for_targets(
    snapshot: Option<&PathOrderSnapshot>,
    edit_targets: &PathEditTargets,
) -> Option<usize> {
    let snapshot = snapshot?;
    edit_targets
        .iter()
        .filter_map(|target| snapshot.order_by_target.get(target).copied())
        .min()
}

pub(super) fn path_owner_delete_supported_for_entry(row: &SceneRow, entry_index: usize) -> bool {
    let Some(report) = row.display_paths_report() else {
        return false;
    };
    let Some(entry) = report.entries.get(entry_index) else {
        return false;
    };

    match report.scene_format {
        SceneFormat::Ma => true,
        SceneFormat::Mb => entry
            .meta
            .as_ref()
            .is_some_and(|meta| meta.trace_form.is_some() && meta.trace_node_offset.is_some()),
        SceneFormat::Unknown => false,
    }
}

fn path_owner_delete_dirty_for_entry(row: &SceneRow, entry_index: usize) -> bool {
    let Some(report) = row.display_paths_report() else {
        return false;
    };
    let Some(entry) = report.entries.get(entry_index) else {
        return false;
    };
    row.pending_path_owner_delete_targets
        .iter()
        .any(|target| target.node_type == entry.node_type && target.node_name == entry.node_name)
        || row
            .path_owner_delete_preview
            .as_ref()
            .is_some_and(|preview| {
                preview.deleted_targets.iter().any(|target| {
                    target.node_type == entry.node_type && target.node_name == entry.node_name
                })
            })
}

pub(super) fn path_overrides_from_replace_preview(
    preview: &PathReplacePreview,
) -> BTreeMap<usize, String> {
    preview
        .items
        .iter()
        .map(|item| (item.entry_index, item.after_value.clone()))
        .collect()
}

pub(super) fn replace_overrides_for_row(row: &SceneRow) -> Option<Vec<PathReplaceOverride>> {
    let report = row.display_paths_report()?;
    Some(
        row.path_overrides
            .iter()
            .filter_map(|(entry_index, after_value)| {
                report
                    .entries
                    .get(*entry_index)
                    .map(|entry| PathReplaceOverride {
                        entry_index: *entry_index,
                        before_value: entry.value.clone(),
                        after_value: after_value.clone(),
                    })
            })
            .collect(),
    )
}

pub(super) fn apply_path_overrides_to_report(
    report: &mut ScenePathsReport,
    overrides: &BTreeMap<usize, String>,
) {
    for (entry_index, value) in overrides {
        if let Some(entry) = report.entries.get_mut(*entry_index) {
            entry.value = value.clone();
        }
    }
}

pub(super) fn default_audit_severity_filter() -> BTreeSet<AuditSeverityFilter> {
    BTreeSet::from([AuditSeverityFilter::Low, AuditSeverityFilter::MediumPlus])
}

pub(super) fn default_audit_sort() -> AuditTableSort {
    AuditTableSort {
        key: AuditSortKey::Scene,
        direction: ColumnSort::Default,
    }
}

pub(super) fn default_path_type_filter() -> BTreeSet<PathTypeFilter> {
    BTreeSet::from([PathTypeFilter::Reference, PathTypeFilter::File])
}

pub(super) fn default_path_form_filter() -> BTreeSet<PathFormFilter> {
    BTreeSet::from([PathFormFilter::Rel, PathFormFilter::Abs])
}

pub(super) fn default_path_resolution_filter() -> BTreeSet<PathResolutionBadge> {
    BTreeSet::from([
        PathResolutionBadge::Exists,
        PathResolutionBadge::Missing,
        PathResolutionBadge::Unresolved,
    ])
}

pub(super) fn default_path_sort() -> PathTableSort {
    PathTableSort {
        key: PathSortKey::Path,
        direction: ColumnSort::Ascending,
    }
}

pub(super) fn path_type_for_node_type(node_type: &str) -> PathTypeFilter {
    if node_type == "reference" {
        PathTypeFilter::Reference
    } else {
        PathTypeFilter::File
    }
}

pub(super) fn infer_scene_path_value_style(value: &str) -> ScenePathValueStyle {
    if value.starts_with("//") || value.starts_with("\\\\") {
        return ScenePathValueStyle::UncAbsolute;
    }
    if value.contains("//") {
        return ScenePathValueStyle::DoubleSlashWorkspaceRelative;
    }
    if value.starts_with("\\") {
        return ScenePathValueStyle::UncAbsolute;
    }
    if value.contains(':') || value.starts_with('/') {
        return ScenePathValueStyle::Absolute;
    }
    ScenePathValueStyle::PlainRelative
}

pub(super) fn path_form_for_style(style: ScenePathValueStyle) -> PathFormFilter {
    match style {
        ScenePathValueStyle::PlainRelative | ScenePathValueStyle::DoubleSlashWorkspaceRelative => {
            PathFormFilter::Rel
        }
        ScenePathValueStyle::Absolute | ScenePathValueStyle::UncAbsolute => PathFormFilter::Abs,
    }
}

pub(super) fn filter_audit_result_rows(
    rows: &[AuditResultRow],
    filter: &BTreeSet<AuditSeverityFilter>,
) -> Vec<AuditResultRow> {
    rows.iter()
        .filter(|row| {
            filter
                .iter()
                .any(|group| audit_filter_matches(*group, row.severity))
        })
        .cloned()
        .collect()
}

pub(super) fn searchable_text_for_audit_row(
    row: &AuditTableRow,
    locale: SupportedLocale,
) -> String {
    let i18n = I18n::new(locale);
    format!(
        "{} {} {} {} {}",
        row.scene_names.join(" "),
        severity_label(&i18n, row.severity),
        row.summary,
        row.code,
        row.sink
    )
    .to_ascii_lowercase()
}

pub(super) fn audit_filter_matches(filter: AuditSeverityFilter, severity: AuditSeverity) -> bool {
    match filter {
        AuditSeverityFilter::Info => severity == AuditSeverity::Info,
        AuditSeverityFilter::Low => severity == AuditSeverity::Low,
        AuditSeverityFilter::MediumPlus => matches!(
            severity,
            AuditSeverity::Medium | AuditSeverity::High | AuditSeverity::Critical
        ),
    }
}

pub(super) fn render_audit_evidence(evidence: &AuditEvidence) -> String {
    match evidence {
        AuditEvidence::FreeText { value } => value.clone(),
        AuditEvidence::KeyValue { key, value } => format!("{}: {}", key.as_str(), value),
    }
}

pub(super) fn build_audit_clipboard_payload(
    provenance: &[String],
    preview: &str,
    evidence: &[String],
) -> String {
    let preview = preview.trim();
    let provenance_lines = provenance
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    let evidence_lines = evidence
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();

    let mut sections = Vec::new();
    if !provenance_lines.is_empty() {
        sections.push(provenance_lines.join("\n"));
    }
    if !preview.is_empty() {
        sections.push(preview.to_string());
    }
    if !evidence_lines.is_empty() {
        sections.push(evidence_lines.join("\n"));
    }
    sections.join("\n\n")
}

pub(super) fn save_staged_artifact_with_backup(
    artifact: &StagedSceneArtifact,
    output_path: &Path,
    backup_location: BackupLocationPreference,
) -> Result<PathBuf, io::Error> {
    if output_path.exists() {
        let backup_path = next_backup_path(output_path, backup_location);
        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(output_path, &backup_path)?;
    }

    save_staged_artifact(artifact, output_path).map_err(io::Error::other)
}

pub(super) fn next_backup_path(path: &Path, backup_location: BackupLocationPreference) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("scene");
    let backup_parent = match backup_location {
        BackupLocationPreference::SameDirectory => parent.to_path_buf(),
        BackupLocationPreference::BackupFolder => parent.join("backup"),
    };

    let mut candidate = backup_parent.join(backup_file_name(file_name, 1));
    let mut depth = 2usize;
    while candidate.exists() {
        candidate = backup_parent.join(backup_file_name(file_name, depth));
        depth += 1;
    }
    candidate
}

pub(super) fn backup_file_name(file_name: &str, depth: usize) -> String {
    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(file_name);
    let ext = path.extension().and_then(|value| value.to_str());
    let suffix = ".backup".repeat(depth);
    match ext {
        Some(ext) if !ext.is_empty() => format!("{stem}{suffix}.{ext}"),
        _ => format!("{stem}{suffix}"),
    }
}

pub(super) fn tab_index(tab: ResultTab) -> usize {
    match tab {
        ResultTab::Overview => 0,
        ResultTab::Audit => 1,
        ResultTab::Paths => 2,
        ResultTab::Log => 3,
    }
}

pub(super) fn result_tab_for_index(index: usize) -> ResultTab {
    match index {
        1 => ResultTab::Audit,
        2 => ResultTab::Paths,
        3 => ResultTab::Log,
        _ => ResultTab::Overview,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct WorkspaceSplitConfig {
    pub group_id: &'static str,
    pub axis: Axis,
    pub file_size: Pixels,
    pub file_min: Pixels,
    pub result_size: Pixels,
    pub result_min: Pixels,
}

pub(super) fn workspace_split_config(layout: WorkspaceLayoutPreference) -> WorkspaceSplitConfig {
    match layout {
        WorkspaceLayoutPreference::TopBottom => WorkspaceSplitConfig {
            group_id: "workspace-rows",
            axis: Axis::Vertical,
            file_size: px(420.0),
            file_min: px(240.0),
            result_size: px(280.0),
            result_min: px(180.0),
        },
        WorkspaceLayoutPreference::LeftRight => WorkspaceSplitConfig {
            group_id: "workspace-columns",
            axis: Axis::Horizontal,
            file_size: px(560.0),
            file_min: px(320.0),
            result_size: px(420.0),
            result_min: px(260.0),
        },
    }
}

pub(super) fn detect_format(path: &Path) -> Option<SceneFormat> {
    let ext = path.extension()?.to_str()?;
    if ext.eq_ignore_ascii_case("ma") {
        return Some(SceneFormat::Ma);
    }
    if ext.eq_ignore_ascii_case("mb") {
        return Some(SceneFormat::Mb);
    }
    None
}

pub(super) fn compute_visible_row_indices_for(
    state_rows: &[SceneRow],
    state: &PersistedState,
    sort: FileTableSort,
) -> Vec<usize> {
    let tokens = tokenize_search_query(&state.search_query);
    let mut visible_rows = state_rows
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            row.status.filter_matches(state.status_filter)
                && file_list_filters_match(row, state)
                && matches_search_tokens(searchable_text_for_row(row, state), &tokens)
        })
        .map(|(ix, _)| ix)
        .collect::<Vec<_>>();
    visible_rows.sort_by(|left, right| {
        compare_rows_for_sort(&state_rows[*left], &state_rows[*right], state, sort)
    });
    visible_rows
}

fn file_list_filters_match(row: &SceneRow, state: &PersistedState) -> bool {
    let findings_match = row.effective_findings_count() > 0;
    let missing_match = missing_path_count_for_row(row).is_some_and(|count| count > 0);
    let no_workspace_match = row.scene_workspace_root.is_none();
    let dirty_match = row.dirty();

    if !state.file_list_findings_only
        && !state.file_list_missing_only
        && !state.file_list_no_workspace_only
        && !state.file_list_dirty_only
    {
        return true;
    }

    (state.file_list_findings_only && findings_match)
        || (state.file_list_missing_only && missing_match)
        || (state.file_list_no_workspace_only && no_workspace_match)
        || (state.file_list_dirty_only && dirty_match)
}

pub(super) fn build_file_copy_payload(rows: &[SceneRow], row_id: u64) -> Option<String> {
    let paths = build_file_operation_paths(rows, row_id)?;

    Some(
        paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

pub(super) fn build_file_operation_paths(rows: &[SceneRow], row_id: u64) -> Option<Vec<PathBuf>> {
    let target = rows.iter().find(|row| row.id == row_id)?;
    if target.selected {
        let selected_paths = rows
            .iter()
            .filter(|row| row.selected)
            .map(|row| row.path.clone())
            .collect::<Vec<_>>();
        if !selected_paths.is_empty() {
            return Some(selected_paths);
        }
    }

    Some(vec![target.path.clone()])
}

pub(super) fn build_file_table_rows(
    rows: &[SceneRow],
    visible_rows: &[usize],
    state: &PersistedState,
    i18n: &I18n,
) -> Vec<FileTableRow> {
    visible_rows
        .iter()
        .filter_map(|index| rows.get(*index))
        .map(|row| build_single_file_table_row(row, state, i18n))
        .collect()
}

pub(super) fn build_single_file_table_row(
    row: &SceneRow,
    state: &PersistedState,
    i18n: &I18n,
) -> FileTableRow {
    FileTableRow {
        id: row.id,
        selected: row.selected,
        dirty: row.dirty(),
        is_processing: row.is_processing(),
        tone: row.status.tone(),
        name: workspace_relative_display_path(&row.path, state),
        has_scene_workspace: row.scene_workspace_root.is_some(),
        status: row.status.label(i18n),
        findings: row.effective_findings_count().to_string(),
        missing: missing_path_count_for_row(row)
            .map(|count| count.to_string())
            .unwrap_or_default(),
        size: i18n.format_bytes(row.size),
        modified: i18n.format_modified(row.modified),
    }
}

pub(super) fn missing_path_count_for_row(row: &SceneRow) -> Option<usize> {
    row.missing_path_count()
}

pub(super) fn searchable_text_for_row(row: &SceneRow, state: &PersistedState) -> String {
    format!(
        "{} {} {}",
        row.name,
        workspace_relative_display_path(&row.path, state),
        row.path.display()
    )
    .to_ascii_lowercase()
}

pub(super) fn tokenize_search_query(query: &str) -> Vec<String> {
    let lowered = query.trim().to_ascii_lowercase();
    let non_whitespace_len = lowered.chars().filter(|ch| !ch.is_whitespace()).count();
    if non_whitespace_len < 2 {
        return Vec::new();
    }
    lowered
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

pub(super) fn matches_search_tokens(haystack: String, tokens: &[String]) -> bool {
    tokens.is_empty() || tokens.iter().all(|token| haystack.contains(token))
}

pub(super) fn workspace_relative_display_path(path: &Path, state: &PersistedState) -> String {
    state
        .workspace_root_path()
        .and_then(|root| {
            path.strip_prefix(root)
                .ok()
                .map(|value| value.to_path_buf())
        })
        .unwrap_or_else(|| path.to_path_buf())
        .display()
        .to_string()
}

pub(super) fn file_sort_key_for_col_ix(col_ix: usize) -> Option<FileSortKey> {
    match col_ix {
        1 => Some(FileSortKey::Name),
        2 => Some(FileSortKey::Status),
        3 => Some(FileSortKey::Findings),
        4 => Some(FileSortKey::Missing),
        5 => Some(FileSortKey::Workspace),
        6 => Some(FileSortKey::Size),
        7 => Some(FileSortKey::Modified),
        _ => None,
    }
}

pub(super) fn audit_sort_key_for_col_ix(col_ix: usize) -> Option<AuditSortKey> {
    match col_ix {
        0 => Some(AuditSortKey::Scene),
        1 => Some(AuditSortKey::Severity),
        2 => Some(AuditSortKey::Summary),
        3 => Some(AuditSortKey::Code),
        4 => Some(AuditSortKey::Sink),
        _ => None,
    }
}

pub(super) fn next_column_sort(sort: ColumnSort) -> ColumnSort {
    match sort {
        ColumnSort::Ascending => ColumnSort::Descending,
        ColumnSort::Descending => ColumnSort::Ascending,
        ColumnSort::Default => ColumnSort::Ascending,
    }
}

pub(super) fn next_file_sort_for_col_ix(col_ix: usize, current: FileTableSort) -> ColumnSort {
    match file_sort_key_for_col_ix(col_ix) {
        Some(key) if key == current.key => next_column_sort(current.direction),
        Some(_) => ColumnSort::Ascending,
        None => ColumnSort::Default,
    }
}

pub(super) fn next_audit_sort_for_col_ix(col_ix: usize, current: AuditTableSort) -> ColumnSort {
    match audit_sort_key_for_col_ix(col_ix) {
        Some(key) if key == current.key => next_column_sort(current.direction),
        Some(_) => ColumnSort::Ascending,
        None => ColumnSort::Default,
    }
}

pub(super) fn path_sort_key_for_col_ix(
    col_ix: usize,
    show_scene_column: bool,
) -> Option<PathSortKey> {
    match (show_scene_column, col_ix) {
        (_, 0) => Some(PathSortKey::Kind),
        (true, 1) => Some(PathSortKey::Scene),
        (true, 2) | (false, 1) => Some(PathSortKey::Node),
        (true, 3) | (false, 2) => Some(PathSortKey::Path),
        _ => None,
    }
}

pub(super) fn next_path_sort_for_col_ix(
    col_ix: usize,
    show_scene_column: bool,
    current: PathTableSort,
) -> ColumnSort {
    match path_sort_key_for_col_ix(col_ix, show_scene_column) {
        Some(key) if key == current.key => next_column_sort(current.direction),
        Some(_) => ColumnSort::Ascending,
        None => ColumnSort::Default,
    }
}

pub(super) fn visible_selection_range_indices(
    visible_rows: &[usize],
    anchor: usize,
    clicked: usize,
) -> Option<Vec<usize>> {
    let anchor_visible_ix = visible_rows.iter().position(|row_ix| *row_ix == anchor)?;
    let clicked_visible_ix = visible_rows.iter().position(|row_ix| *row_ix == clicked)?;
    let (start, end) = if anchor_visible_ix <= clicked_visible_ix {
        (anchor_visible_ix, clicked_visible_ix)
    } else {
        (clicked_visible_ix, anchor_visible_ix)
    };
    Some(visible_rows[start..=end].to_vec())
}

pub(super) fn visible_audit_selection_keys(
    rows: &[AuditTableRow],
    anchor: &AuditResultRowKey,
    clicked: &AuditResultRowKey,
) -> Option<Vec<AuditResultRowKey>> {
    let anchor_ix = rows.iter().position(|row| &row.key == anchor)?;
    let clicked_ix = rows.iter().position(|row| &row.key == clicked)?;
    let (start, end) = if anchor_ix <= clicked_ix {
        (anchor_ix, clicked_ix)
    } else {
        (clicked_ix, anchor_ix)
    };
    Some(
        rows[start..=end]
            .iter()
            .map(|row| row.key.clone())
            .collect(),
    )
}

pub(super) fn visible_path_selection_targets(
    rows: &[PathTableRow],
    anchor: &PathEditTargets,
    clicked: &PathEditTargets,
) -> Option<Vec<PathEditTargets>> {
    let anchor_ix = rows.iter().position(|row| &row.edit_targets == anchor)?;
    let clicked_ix = rows.iter().position(|row| &row.edit_targets == clicked)?;
    let (start, end) = if anchor_ix <= clicked_ix {
        (anchor_ix, clicked_ix)
    } else {
        (clicked_ix, anchor_ix)
    };
    Some(
        rows[start..=end]
            .iter()
            .filter(|row| !row.edit_targets.is_empty())
            .map(|row| row.edit_targets.clone())
            .collect(),
    )
}

pub(super) fn compare_rows_for_sort(
    left: &SceneRow,
    right: &SceneRow,
    state: &PersistedState,
    sort: FileTableSort,
) -> std::cmp::Ordering {
    let locale_i18n = I18n::new(state.locale.resolve());
    let ordering = match sort.key {
        FileSortKey::Name => workspace_relative_display_path(&left.path, state)
            .cmp(&workspace_relative_display_path(&right.path, state)),
        FileSortKey::Workspace => left
            .scene_workspace_root
            .is_none()
            .cmp(&right.scene_workspace_root.is_none())
            .then_with(|| left.path.cmp(&right.path)),
        FileSortKey::Status => left
            .status
            .label(&locale_i18n)
            .cmp(&right.status.label(&locale_i18n)),
        FileSortKey::Findings => left
            .effective_findings_count()
            .cmp(&right.effective_findings_count())
            .then_with(|| left.path.cmp(&right.path)),
        FileSortKey::Missing => missing_path_count_for_row(left)
            .map(|count| (false, count))
            .unwrap_or((true, 0))
            .cmp(
                &missing_path_count_for_row(right)
                    .map(|count| (false, count))
                    .unwrap_or((true, 0)),
            )
            .then_with(|| left.path.cmp(&right.path)),
        FileSortKey::Size => left
            .size
            .cmp(&right.size)
            .then_with(|| left.path.cmp(&right.path)),
        FileSortKey::Modified => modified_sort_key(left.modified)
            .cmp(&modified_sort_key(right.modified))
            .then_with(|| left.path.cmp(&right.path)),
    };

    match sort.direction {
        ColumnSort::Ascending => ordering,
        ColumnSort::Descending => ordering.reverse(),
        ColumnSort::Default => workspace_relative_display_path(&left.path, state)
            .cmp(&workspace_relative_display_path(&right.path, state)),
    }
}

pub(super) fn sort_path_rows(rows: &mut [PathTableRow], sort: PathTableSort) {
    if matches!(sort.key, PathSortKey::CapturedOrder) {
        rows.sort_by(|left, right| compare_path_rows_for_sort(left, right, sort));
        return;
    }
    if matches!(sort.direction, ColumnSort::Default) {
        return;
    }

    rows.sort_by(|left, right| compare_path_rows_for_sort(left, right, sort));
}

pub(super) fn sort_audit_rows(rows: &mut [AuditTableRow], sort: AuditTableSort) {
    if matches!(sort.direction, ColumnSort::Default) {
        return;
    }

    rows.sort_by(|left, right| compare_audit_rows_for_sort(left, right, sort));
}

pub(super) fn compare_path_rows_for_sort(
    left: &PathTableRow,
    right: &PathTableRow,
    sort: PathTableSort,
) -> std::cmp::Ordering {
    let ordering = match sort.key {
        PathSortKey::Kind => left.path_kind.cmp(&right.path_kind),
        PathSortKey::Scene => left.scene.cmp(&right.scene),
        PathSortKey::Node => left.node.cmp(&right.node),
        PathSortKey::Path => left.value.cmp(&right.value),
        PathSortKey::CapturedOrder => {
            return compare_captured_path_order(left, right, sort.direction);
        }
    };
    let ordering = ordering
        .then_with(|| left.scene.cmp(&right.scene))
        .then_with(|| left.node.cmp(&right.node))
        .then_with(|| left.value.cmp(&right.value));

    match sort.direction {
        ColumnSort::Ascending => ordering,
        ColumnSort::Descending => ordering.reverse(),
        ColumnSort::Default => std::cmp::Ordering::Equal,
    }
}

fn compare_captured_path_order(
    left: &PathTableRow,
    right: &PathTableRow,
    direction: ColumnSort,
) -> std::cmp::Ordering {
    let ordering = match (left.captured_order, right.captured_order) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    };
    match direction {
        ColumnSort::Ascending => ordering,
        ColumnSort::Descending => ordering.reverse(),
        ColumnSort::Default => std::cmp::Ordering::Equal,
    }
}

pub(super) fn compare_audit_rows_for_sort(
    left: &AuditTableRow,
    right: &AuditTableRow,
    sort: AuditTableSort,
) -> std::cmp::Ordering {
    let ordering = match sort.key {
        AuditSortKey::Scene => left
            .scene_names
            .cmp(&right.scene_names)
            .then_with(|| left.scene_name.cmp(&right.scene_name)),
        AuditSortKey::Severity => {
            audit_severity_rank(left.severity).cmp(&audit_severity_rank(right.severity))
        }
        AuditSortKey::Summary => left.summary.cmp(&right.summary),
        AuditSortKey::Code => left.code.cmp(&right.code),
        AuditSortKey::Sink => left.sink.cmp(&right.sink),
    }
    .then_with(|| left.key.cmp(&right.key));

    match sort.direction {
        ColumnSort::Ascending => ordering,
        ColumnSort::Descending => ordering.reverse(),
        ColumnSort::Default => std::cmp::Ordering::Equal,
    }
}

pub(super) fn modified_sort_key(modified: Option<SystemTime>) -> (bool, Option<SystemTime>) {
    (modified.is_none(), modified)
}

pub(super) fn audit_severity_rank(severity: AuditSeverity) -> u8 {
    match severity {
        AuditSeverity::Info => 0,
        AuditSeverity::Low => 1,
        AuditSeverity::Medium => 2,
        AuditSeverity::High => 3,
        AuditSeverity::Critical => 4,
    }
}

pub(super) fn build_rows_from_paths(paths: Vec<PathBuf>, next_row_id: &mut u64) -> Vec<SceneRow> {
    let mut rows = Vec::new();
    for path in paths {
        if let Some(row) = SceneRow::from_path(*next_row_id, path) {
            rows.push(row);
            *next_row_id += 1;
        }
    }
    rows
}

pub(super) fn build_rows_from_discovered_files(
    files: Vec<DiscoveredSceneFile>,
    next_row_id: &mut u64,
) -> Vec<SceneRow> {
    let mut rows = Vec::new();
    for file in files {
        rows.push(SceneRow::from_discovered_file(*next_row_id, file));
        *next_row_id += 1;
    }
    rows
}

#[cfg(test)]
pub(super) fn reconcile_workspace_rows(
    existing_rows: Vec<SceneRow>,
    paths: Vec<PathBuf>,
    next_row_id: &mut u64,
) -> Vec<SceneRow> {
    let mut rows_by_path = existing_rows
        .into_iter()
        .map(|row| (row.path.clone(), row))
        .collect::<BTreeMap<_, _>>();
    let mut rows = Vec::new();
    for path in paths {
        if let Some(row) = rows_by_path.remove(&path) {
            rows.push(row);
        } else if let Some(row) = SceneRow::from_path(*next_row_id, path) {
            rows.push(row);
            *next_row_id += 1;
        }
    }
    rows
}

pub(super) fn reconcile_workspace_rows_from_discovered_files(
    existing_rows: Vec<SceneRow>,
    files: Vec<DiscoveredSceneFile>,
    next_row_id: &mut u64,
) -> Vec<SceneRow> {
    let mut rows_by_path = existing_rows
        .into_iter()
        .map(|row| (row.path.clone(), row))
        .collect::<BTreeMap<_, _>>();
    let mut rows = Vec::new();
    for file in files {
        if let Some(row) = rows_by_path.remove(&file.path) {
            rows.push(row);
        } else {
            rows.push(SceneRow::from_discovered_file(*next_row_id, file));
            *next_row_id += 1;
        }
    }
    rows
}

pub(super) fn load_rows_from_state(state: &PersistedState, next_row_id: &mut u64) -> Vec<SceneRow> {
    if state.workspace_root_path().is_some() {
        return Vec::new();
    }

    build_rows_from_paths(state.workspace_paths(), next_row_id)
}

pub(super) fn should_ignore_workspace_directory(path: &Path, state: &PersistedState) -> bool {
    state.ignore_folder_names_enabled
        && path
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(normalize_ignored_folder_name)
            .is_some_and(|name| {
                state
                    .ignored_folder_names
                    .iter()
                    .filter_map(|entry| normalize_ignored_folder_name(entry))
                    .any(|entry| entry.eq_ignore_ascii_case(&name))
            })
}

#[cfg(test)]
pub(super) fn collect_scene_files_recursively(
    path: &Path,
    out: &mut Vec<PathBuf>,
    state: &PersistedState,
) {
    let Ok(read_dir) = fs::read_dir(path) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if should_ignore_workspace_directory(&path, state) {
                continue;
            }
            collect_scene_files_recursively(&path, out, state);
        } else if detect_format(&path).is_some() {
            out.push(path);
        }
    }
}

pub(super) fn discover_workspace_scene_files(
    path: &Path,
    state: &PersistedState,
) -> Vec<DiscoveredSceneFile> {
    let mut out = Vec::new();
    discover_workspace_scene_files_recursively(path, &mut out, state);
    out
}

fn discover_workspace_scene_files_recursively(
    path: &Path,
    out: &mut Vec<DiscoveredSceneFile>,
    state: &PersistedState,
) {
    let Ok(read_dir) = fs::read_dir(path) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if should_ignore_workspace_directory(&path, state) {
                continue;
            }
            discover_workspace_scene_files_recursively(&path, out, state);
            continue;
        }
        if detect_format(&path).is_none() {
            continue;
        }
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        out.push(DiscoveredSceneFile {
            name: path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("scene")
                .to_string(),
            size: metadata.len(),
            modified: metadata.modified().ok(),
            scene_workspace_root: find_scene_workspace_root(&path),
            path,
        });
    }
}

#[cfg(test)]
pub(super) fn analyze_row(
    path: &Path,
    audit_mode: AuditModePreference,
) -> Result<RowJobResult, String> {
    analyze_row_with_options(path, audit_mode, &LoadOptions::default())
}

pub(super) fn analyze_row_with_options(
    path: &Path,
    audit_mode: AuditModePreference,
    load_options: &LoadOptions,
) -> Result<RowJobResult, String> {
    let started_at = Instant::now();
    match Loader::new(load_options.clone()).observe_analysis_path(path) {
        Ok(observation) => {
            analyze_observation(&observation, audit_mode, load_options, started_at.elapsed())
        }
        Err(
            maya_scene_kit_observe::scene::SceneToolError::MelParseBudgetExceeded { .. }
            | maya_scene_kit_observe::scene::SceneToolError::MbParseBudgetExceeded { .. },
        ) => {
            let plan = gui_audit_plan().map_err(|err| err.to_string())?;
            let options = audit_options_from_preference(audit_mode);
            let audit_report = audit_script_nodes_with_options(path, &plan, load_options, options)
                .map_err(|err| err.to_string())?;
            let audit_snapshot = AuditedSceneSnapshot::new(
                audit_report.clone(),
                options,
                fingerprint_audit_plan(&plan),
            )
            .map_err(|err| err.to_string())?;
            Ok(RowJobResult::Analyze(AnalyzeRowResult {
                audit_report,
                paths_report: None,
                dump_report: None,
                observe_snapshot: None,
                audit_snapshot: Some(audit_snapshot),
                audit_mode,
                elapsed: started_at.elapsed(),
            }))
        }
        Err(err) => Err(err.to_string()),
    }
}

pub(super) fn analyze_row_bytes_with_options(
    path: &Path,
    scene_format: SceneFormat,
    validation_state: ValidationState,
    bytes: Vec<u8>,
    audit_mode: AuditModePreference,
    load_options: &LoadOptions,
) -> Result<AnalyzeRowResult, String> {
    let started_at = Instant::now();
    match Loader::new(load_options.clone()).observe_analysis_bytes(
        path,
        scene_format,
        validation_state,
        bytes,
    ) {
        Ok(observation) => {
            analyze_observation_result(&observation, audit_mode, load_options, started_at.elapsed())
        }
        Err(maya_scene_kit_observe::scene::SceneToolError::MelParseBudgetExceeded { limit }) => {
            let plan = gui_audit_plan().map_err(|err| err.to_string())?;
            let options = audit_options_from_preference(audit_mode);
            let audit_report = build_parse_budget_blocked_audit_report(
                path.to_path_buf(),
                scene_format,
                ValidationState::Invalid,
                &plan,
                options,
                limit,
                None,
            );
            Ok(AnalyzeRowResult {
                audit_report: audit_report.clone(),
                paths_report: None,
                dump_report: None,
                observe_snapshot: None,
                audit_snapshot: Some(
                    AuditedSceneSnapshot::new(audit_report, options, fingerprint_audit_plan(&plan))
                        .map_err(|err| err.to_string())?,
                ),
                audit_mode,
                elapsed: started_at.elapsed(),
            })
        }
        Err(maya_scene_kit_observe::scene::SceneToolError::MbParseBudgetExceeded { limit }) => {
            let plan = gui_audit_plan().map_err(|err| err.to_string())?;
            let options = audit_options_from_preference(audit_mode);
            let audit_report = build_parse_budget_blocked_audit_report(
                path.to_path_buf(),
                scene_format,
                ValidationState::Invalid,
                &plan,
                options,
                limit,
                None,
            );
            Ok(AnalyzeRowResult {
                audit_report: audit_report.clone(),
                paths_report: None,
                dump_report: None,
                observe_snapshot: None,
                audit_snapshot: Some(
                    AuditedSceneSnapshot::new(audit_report, options, fingerprint_audit_plan(&plan))
                        .map_err(|err| err.to_string())?,
                ),
                audit_mode,
                elapsed: started_at.elapsed(),
            })
        }
        Err(err) => Err(err.to_string()),
    }
}

fn analyze_observation(
    observation: &maya_scene_kit_observe::scene::ObservationBundle,
    audit_mode: AuditModePreference,
    load_options: &LoadOptions,
    elapsed: Duration,
) -> Result<RowJobResult, String> {
    Ok(RowJobResult::Analyze(analyze_observation_result(
        observation,
        audit_mode,
        load_options,
        elapsed,
    )?))
}

fn analyze_observation_result(
    observation: &maya_scene_kit_observe::scene::ObservationBundle,
    audit_mode: AuditModePreference,
    load_options: &LoadOptions,
    elapsed: Duration,
) -> Result<AnalyzeRowResult, String> {
    let observe_snapshot = ObservedSceneSnapshot::from_observation(observation, load_options)
        .map_err(|err| err.to_string())?;
    let dump_report = observation
        .scene_dump_report()
        .map_err(|err| err.to_string())?;
    let paths_report = ScenePathsReport {
        scene_path: observation.scene_path().to_path_buf(),
        scene_format: observation.scene_format(),
        validation_state: observation.validation_state(),
        entries: observation
            .scene_paths(PathKind::All)
            .map_err(|err| err.to_string())?,
    };
    let plan = gui_audit_plan().map_err(|err| err.to_string())?;
    let options = audit_options_from_preference(audit_mode);
    let audit_report =
        audit_observation(observation, &plan, options).map_err(|err| err.to_string())?;
    let audit_snapshot =
        AuditedSceneSnapshot::new(audit_report.clone(), options, fingerprint_audit_plan(&plan))
            .map_err(|err| err.to_string())?;

    Ok(AnalyzeRowResult {
        audit_report,
        paths_report: Some(paths_report),
        dump_report: Some(dump_report),
        observe_snapshot: Some(observe_snapshot),
        audit_snapshot: Some(audit_snapshot),
        audit_mode,
        elapsed,
    })
}

pub(super) fn gui_audit_plan() -> Result<
    maya_scene_kit_audit::audit::ScriptAuditPlan,
    maya_scene_kit_observe::scene::SceneToolError,
> {
    build_script_audit_plan(vec![], 64)
}

pub(super) fn audit_options_from_preference(audit_mode: AuditModePreference) -> AuditOptions {
    match audit_mode {
        AuditModePreference::StrictDefault => AuditOptions::strict_default(),
        AuditModePreference::HardenedUntrusted => AuditOptions::hardened_untrusted(),
    }
}

pub(super) fn operation_key(operation: RowOperation) -> &'static str {
    match operation {
        RowOperation::Analyze => "analyze",
        RowOperation::Clean => "clean",
        RowOperation::DeleteOwnerNodes => "delete-owner-nodes",
        RowOperation::Replace => "replace",
        RowOperation::ToAscii => "to-ascii",
        RowOperation::Save => "save",
    }
}

pub(super) fn operation_label(i18n: &I18n, operation: RowOperation) -> String {
    match operation {
        RowOperation::Analyze => i18n.text("file_status.processing.analyze"),
        RowOperation::Clean => i18n.text("file_status.processing.clean"),
        RowOperation::DeleteOwnerNodes => i18n.text("file_status.processing.delete_owner_nodes"),
        RowOperation::Replace => i18n.text("file_status.processing.replace"),
        RowOperation::ToAscii => i18n.text("file_status.processing.to_ascii"),
        RowOperation::Save => i18n.text("file_status.processing.save"),
    }
}

pub(super) fn operation_label_for_job_history(i18n: &I18n, operation: &str) -> String {
    match operation {
        "analyze" => operation_label(i18n, RowOperation::Analyze),
        "clean" => operation_label(i18n, RowOperation::Clean),
        "delete-owner-nodes" => operation_label(i18n, RowOperation::DeleteOwnerNodes),
        "replace" => operation_label(i18n, RowOperation::Replace),
        "to-ascii" => operation_label(i18n, RowOperation::ToAscii),
        "save" => operation_label(i18n, RowOperation::Save),
        "path-collect" => i18n.text("log.path_collect"),
        other => other.to_string(),
    }
}

pub(super) fn format_elapsed_seconds(elapsed: Duration) -> String {
    format!("{:.2}s", elapsed.as_secs_f64())
}

pub(super) fn render_banner_message(i18n: &I18n, message: &BannerMessage) -> String {
    match message {
        BannerMessage::PersistFailed(error) => {
            i18n.format("banner.persist_failed", &[("error", error.clone())])
        }
        BannerMessage::CachePurged => i18n.text("banner.cache_purged"),
        BannerMessage::WorkspaceLoaded { count, path } => i18n.format(
            "banner.workspace_loaded",
            &[
                ("count", count.to_string()),
                ("path", path.display().to_string()),
            ],
        ),
        BannerMessage::AnalyzeCompleted { name, elapsed } => i18n.format(
            "banner.analyze_completed",
            &[
                ("name", name.clone()),
                ("elapsed", format_elapsed_seconds(*elapsed)),
            ],
        ),
        BannerMessage::WorkspaceAutoAnalyzeCompleted { count, elapsed } => i18n.format(
            "banner.workspace_auto_analyze_completed",
            &[
                ("count", count.to_string()),
                ("elapsed", format_elapsed_seconds(*elapsed)),
            ],
        ),
        BannerMessage::WorkspaceCleared => i18n.text("banner.workspace_cleared"),
        BannerMessage::InlinePathEditFailed(error) => i18n.format(
            "banner.inline_path_edit_failed",
            &[("error", error.clone())],
        ),
        BannerMessage::SelectFilesFirst => i18n.text("banner.select_files_first"),
        BannerMessage::Raw(message) => message.clone(),
        BannerMessage::NothingDirtyToSave => i18n.text("banner.nothing_dirty_to_save"),
        BannerMessage::NothingSelectedDirtyToSave => {
            i18n.text("banner.nothing_selected_dirty_to_save")
        }
        BannerMessage::NothingToUndo => i18n.text("banner.nothing_to_undo"),
        BannerMessage::NothingToRedo => i18n.text("banner.nothing_to_redo"),
    }
}

pub(super) fn render_audit_finding_detail(detail: &AuditFindingDetail) -> String {
    match detail {
        AuditFindingDetail::Static { value } => match value {
            StaticAuditFindingDetail::CustomRuleMatch => {
                "custom audit rule matched execution surface".to_string()
            }
            _ => value.message().to_string(),
        },
        AuditFindingDetail::SourceKindCapability { message } => message.clone(),
        AuditFindingDetail::CustomRuleMatch => {
            "custom audit rule matched execution surface".to_string()
        }
        AuditFindingDetail::FreeText { message } => message.clone(),
    }
}

pub(super) fn checked_menu_item(selected: bool, label: String, action: impl Action) -> MenuItem {
    MenuItem::action_checked(label, selected, action)
}

pub(super) fn backup_location_label(i18n: &I18n, location: BackupLocationPreference) -> String {
    match location {
        BackupLocationPreference::SameDirectory => i18n.text("backup_location.same_directory"),
        BackupLocationPreference::BackupFolder => i18n.text("backup_location.backup_folder"),
    }
}

pub(super) fn workspace_layout_label(i18n: &I18n, layout: WorkspaceLayoutPreference) -> String {
    match layout {
        WorkspaceLayoutPreference::TopBottom => i18n.text("layout.horizontal_split"),
        WorkspaceLayoutPreference::LeftRight => i18n.text("layout.vertical_split"),
    }
}

pub(super) fn auto_analyze_parallelism_menu_label(i18n: &I18n) -> String {
    i18n.text("menu.auto_analyze_parallelism")
}

pub(super) fn ignore_folder_names_label(i18n: &I18n) -> String {
    i18n.text("settings.ignore_special_folders")
}

pub(super) fn edit_ignored_folder_names_label(i18n: &I18n) -> String {
    i18n.text("settings.edit_ignored_folder_names")
}

pub(super) fn edit_max_bytes_label(i18n: &I18n) -> String {
    i18n.text("settings.max_bytes")
}

pub(super) fn build_app_menus(
    state: &PersistedState,
    i18n: &I18n,
    can_undo: bool,
    can_redo: bool,
) -> Vec<Menu> {
    let selected_locale = state.locale.resolve();

    vec![
        Menu {
            name: i18n.text("menu.file").into(),
            items: vec![
                MenuItem::action(i18n.text("action.select_folder"), MenuSelectFolder),
                MenuItem::submenu(Menu {
                    name: i18n.text("menu.recent_folder").into(),
                    items: recent_folder_menu_items(state, i18n),
                }),
                MenuItem::separator(),
                MenuItem::action(i18n.text("action.save_selected"), MenuSaveSelected),
                MenuItem::action(i18n.text("action.save_all"), MenuSaveAll),
                MenuItem::separator(),
                MenuItem::action(i18n.text("action.exit_application"), MenuExitApplication),
            ],
        },
        Menu {
            name: i18n.text("menu.edit").into(),
            items: vec![
                if can_undo {
                    MenuItem::os_action(i18n.text("action.undo"), MenuEditUndo, OsAction::Undo)
                } else {
                    MenuItem::os_action(
                        i18n.text("action.undo"),
                        MenuEditUndoUnavailable,
                        OsAction::Undo,
                    )
                },
                if can_redo {
                    MenuItem::os_action(i18n.text("action.redo"), MenuEditRedo, OsAction::Redo)
                } else {
                    MenuItem::os_action(
                        i18n.text("action.redo"),
                        MenuEditRedoUnavailable,
                        OsAction::Redo,
                    )
                },
                MenuItem::separator(),
                MenuItem::action(i18n.text("action.clean"), MenuEditClean),
                MenuItem::action(
                    i18n.text("action.delete_ui_configuration_script_node"),
                    MenuEditDeleteUiConfigurationScriptNode,
                ),
                MenuItem::action(i18n.text("action.replace_path"), MenuEditReplace),
                MenuItem::action(i18n.text("action.to_ascii"), MenuEditToAscii),
            ],
        },
        Menu {
            name: i18n.text("menu.settings").into(),
            items: vec![
                MenuItem::submenu(Menu {
                    name: i18n.text("menu.language").into(),
                    items: vec![
                        checked_menu_item(
                            selected_locale == SupportedLocale::English,
                            i18n.text("locale.english"),
                            MenuLocaleEnglish,
                        ),
                        checked_menu_item(
                            selected_locale == SupportedLocale::Japanese,
                            i18n.text("locale.japanese"),
                            MenuLocaleJapanese,
                        ),
                        checked_menu_item(
                            selected_locale == SupportedLocale::Chinese,
                            i18n.text("locale.chinese"),
                            MenuLocaleChinese,
                        ),
                    ],
                }),
                MenuItem::submenu(Menu {
                    name: i18n.text("menu.backup_location").into(),
                    items: vec![
                        checked_menu_item(
                            state.backup_location == BackupLocationPreference::BackupFolder,
                            i18n.text("backup_location.backup_folder"),
                            MenuBackupLocationBackupFolder,
                        ),
                        checked_menu_item(
                            state.backup_location == BackupLocationPreference::SameDirectory,
                            i18n.text("backup_location.same_directory"),
                            MenuBackupLocationSameDirectory,
                        ),
                    ],
                }),
                MenuItem::submenu(Menu {
                    name: i18n.text("menu.layout").into(),
                    items: vec![
                        checked_menu_item(
                            state.workspace_layout == WorkspaceLayoutPreference::LeftRight,
                            workspace_layout_label(i18n, WorkspaceLayoutPreference::LeftRight),
                            MenuLayoutVerticalSplit,
                        ),
                        checked_menu_item(
                            state.workspace_layout == WorkspaceLayoutPreference::TopBottom,
                            workspace_layout_label(i18n, WorkspaceLayoutPreference::TopBottom),
                            MenuLayoutHorizontalSplit,
                        ),
                    ],
                }),
                MenuItem::submenu(Menu {
                    name: auto_analyze_parallelism_menu_label(i18n).into(),
                    items: vec![
                        checked_menu_item(
                            state.auto_analyze_parallelism == AutoAnalyzeParallelismPreference::One,
                            AutoAnalyzeParallelismPreference::One.limit().to_string(),
                            MenuAutoAnalyzeParallelism1,
                        ),
                        checked_menu_item(
                            state.auto_analyze_parallelism == AutoAnalyzeParallelismPreference::Two,
                            AutoAnalyzeParallelismPreference::Two.limit().to_string(),
                            MenuAutoAnalyzeParallelism2,
                        ),
                        checked_menu_item(
                            state.auto_analyze_parallelism
                                == AutoAnalyzeParallelismPreference::Four,
                            AutoAnalyzeParallelismPreference::Four.limit().to_string(),
                            MenuAutoAnalyzeParallelism4,
                        ),
                        checked_menu_item(
                            state.auto_analyze_parallelism
                                == AutoAnalyzeParallelismPreference::Eight,
                            AutoAnalyzeParallelismPreference::Eight.limit().to_string(),
                            MenuAutoAnalyzeParallelism8,
                        ),
                        checked_menu_item(
                            state.auto_analyze_parallelism
                                == AutoAnalyzeParallelismPreference::Sixteen,
                            AutoAnalyzeParallelismPreference::Sixteen
                                .limit()
                                .to_string(),
                            MenuAutoAnalyzeParallelism16,
                        ),
                        checked_menu_item(
                            state.auto_analyze_parallelism
                                == AutoAnalyzeParallelismPreference::ThirtyTwo,
                            AutoAnalyzeParallelismPreference::ThirtyTwo
                                .limit()
                                .to_string(),
                            MenuAutoAnalyzeParallelism32,
                        ),
                    ],
                }),
                MenuItem::separator(),
                checked_menu_item(
                    state.analysis_cache_enabled,
                    i18n.text("settings.analysis_cache_enabled"),
                    MenuToggleAnalysisCache,
                ),
                MenuItem::action(
                    i18n.text("settings.purge_analysis_cache"),
                    MenuPurgeAnalysisCache,
                ),
                MenuItem::action(edit_max_bytes_label(i18n), MenuEditMaxBytes),
                checked_menu_item(
                    state.ignore_folder_names_enabled,
                    ignore_folder_names_label(i18n),
                    MenuToggleIgnoreFolderNames,
                ),
                MenuItem::action(
                    edit_ignored_folder_names_label(i18n),
                    MenuEditIgnoredFolderNames,
                ),
            ],
        },
    ]
}

pub(super) fn recent_folder_menu_items(state: &PersistedState, i18n: &I18n) -> Vec<MenuItem> {
    let recent = state.recent_folders(MAX_RECENT_FOLDERS);
    if recent.is_empty() {
        return vec![MenuItem::action(
            i18n.text("menu.recent_folder.empty"),
            MenuRecentFolderUnavailable,
        )];
    }

    recent
        .into_iter()
        .enumerate()
        .map(|(index, path)| recent_folder_menu_item(index, path.display().to_string()))
        .collect()
}

pub(super) fn recent_folder_menu_item(index: usize, label: String) -> MenuItem {
    match index {
        0 => MenuItem::action(label, MenuRecentFolder0),
        1 => MenuItem::action(label, MenuRecentFolder1),
        2 => MenuItem::action(label, MenuRecentFolder2),
        3 => MenuItem::action(label, MenuRecentFolder3),
        4 => MenuItem::action(label, MenuRecentFolder4),
        5 => MenuItem::action(label, MenuRecentFolder5),
        6 => MenuItem::action(label, MenuRecentFolder6),
        7 => MenuItem::action(label, MenuRecentFolder7),
        8 => MenuItem::action(label, MenuRecentFolder8),
        9 => MenuItem::action(label, MenuRecentFolder9),
        _ => MenuItem::action(label, MenuRecentFolderUnavailable),
    }
}

pub(super) fn action_button(
    id: impl Into<String>,
    label: impl Into<String>,
    enabled: bool,
    action: impl Fn(&mut GuiShell, &mut Window, &mut Context<GuiShell>) + 'static,
    view: Entity<GuiShell>,
) -> impl IntoElement {
    let id = id.into();
    let label = label.into();
    Button::new(SharedString::from(id))
        .label(label)
        .small()
        .disabled(!enabled)
        .on_click(move |_, window, cx| {
            view.update(cx, |shell, cx| {
                action(shell, window, cx);
                cx.notify();
            });
        })
}
