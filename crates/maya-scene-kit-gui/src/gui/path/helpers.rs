use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use super::super::*;

pub(in crate::gui) fn replace_overrides_for_row_from_map(
    report: &ScenePathsReport,
    overrides: &BTreeMap<usize, String>,
) -> Result<Vec<PathReplaceOverride>, String> {
    overrides
        .iter()
        .map(|(entry_index, after_value)| {
            let entry = report
                .entries
                .get(*entry_index)
                .ok_or_else(|| format!("missing path entry {entry_index} for replace override"))?;
            Ok(PathReplaceOverride {
                entry_index: *entry_index,
                before_value: entry.value.clone(),
                after_value: after_value.clone(),
            })
        })
        .collect()
}

pub(in crate::gui) fn normalize_path_edit_targets(mut targets: PathEditTargets) -> PathEditTargets {
    targets.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    targets.dedup();
    targets
}

pub(in crate::gui) fn path_edit_targets_id(targets: &PathEditTargets) -> String {
    if targets.is_empty() {
        "none".to_string()
    } else {
        targets
            .iter()
            .map(|(row_id, entry_index)| format!("{row_id}-{entry_index}"))
            .collect::<Vec<_>>()
            .join("|")
    }
}

pub(in crate::gui) fn scene_path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(in crate::gui) fn write_back_selected_scene_path(
    selected_path: &Path,
    workspace_root: Option<&Path>,
    value_style: ScenePathValueStyle,
) -> String {
    if let Some(workspace_root) = workspace_root {
        if let Ok(relative) = selected_path.strip_prefix(workspace_root) {
            let relative = scene_path_string(relative);
            if !relative.is_empty() {
                return match value_style {
                    ScenePathValueStyle::DoubleSlashWorkspaceRelative => {
                        format!(
                            "{}//{}",
                            scene_path_string(workspace_root),
                            relative.trim_start_matches('/')
                        )
                    }
                    _ => relative,
                };
            }
        }
    }
    scene_path_string(selected_path)
}

pub(in crate::gui) fn shared_workspace_root_for_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> Option<PathBuf> {
    let (first_row_id, _) = *edit_targets.first()?;
    let first_root = rows
        .iter()
        .find(|row| row.id == first_row_id)
        .and_then(|row| row.scene_workspace_root.clone())?;

    edit_targets
        .iter()
        .all(|(row_id, _)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .and_then(|row| row.scene_workspace_root.as_ref())
                == Some(&first_root)
        })
        .then_some(first_root)
}

pub(in crate::gui) fn resolved_target_file_paths_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> Vec<PathBuf> {
    let mut resolved_paths = BTreeSet::new();

    for (row_id, entry_index) in edit_targets {
        let Some(row) = rows.iter().find(|row| row.id == *row_id) else {
            continue;
        };
        let Some(path) = resolved_target_file_path_for_entry(row, *entry_index) else {
            continue;
        };
        resolved_paths.insert(path);
    }

    resolved_paths.into_iter().collect()
}

pub(in crate::gui) fn path_owner_delete_supported_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> bool {
    !edit_targets.is_empty()
        && edit_targets.iter().all(|(row_id, entry_index)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .is_some_and(|row| {
                    super::super::helpers::path_owner_delete_supported_for_entry(row, *entry_index)
                })
        })
}

pub(super) fn path_owner_delete_target_for_entry(
    row: &SceneRow,
    entry_index: usize,
) -> Option<PathOwnerDeleteTarget> {
    let report = row.display_paths_report()?;
    let entry = report.entries.get(entry_index)?;
    Some(PathOwnerDeleteTarget {
        node_type: entry.node_type.clone(),
        node_name: entry.node_name.clone(),
    })
}

pub(in crate::gui) fn path_owner_delete_staged_for_entry(
    row: &SceneRow,
    entry_index: usize,
) -> bool {
    let Some(target) = path_owner_delete_target_for_entry(row, entry_index) else {
        return false;
    };
    row.pending_path_owner_delete_targets.contains(&target)
        || row
            .path_owner_delete_preview
            .as_ref()
            .is_some_and(|preview| preview.deleted_targets.contains(&target))
}

pub(in crate::gui) fn path_value_edit_supported_for_entry(
    row: &SceneRow,
    entry_index: usize,
) -> bool {
    row.display_paths_report()
        .and_then(|report| report.entries.get(entry_index))
        .is_some()
        && !row.is_processing()
        && !path_owner_delete_staged_for_entry(row, entry_index)
}

pub(in crate::gui) fn path_value_edit_supported_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> bool {
    !edit_targets.is_empty()
        && edit_targets.iter().all(|(row_id, entry_index)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .is_some_and(|row| path_value_edit_supported_for_entry(row, *entry_index))
        })
}

pub(in crate::gui) fn workspace_relative_override_value_for_entry(
    row: &SceneRow,
    entry_index: usize,
    rewrite_mode: PathCollectRewriteMode,
) -> Option<String> {
    let workspace_root = row.scene_workspace_root.as_deref()?;
    let current_value = effective_path_value_for_entry(row, entry_index)?;
    let fallback = row.path_resolution_fallback(entry_index, &current_value);
    let resolution = row
        .path_resolution(entry_index, &current_value)
        .or(fallback.as_ref())?;
    let resolved_path = resolution.resolved_path.as_deref()?;
    resolved_path.strip_prefix(workspace_root).ok()?;

    let value_style = path_collect_rewrite_value_style(rewrite_mode)?;
    let next_value =
        write_back_selected_scene_path(resolved_path, Some(workspace_root), value_style);
    (next_value != current_value).then_some(next_value)
}

pub(in crate::gui) fn absolute_override_value_for_entry(
    row: &SceneRow,
    entry_index: usize,
) -> Option<String> {
    let current_value = effective_path_value_for_entry(row, entry_index)?;
    let fallback = row.path_resolution_fallback(entry_index, &current_value);
    let resolution = row
        .path_resolution(entry_index, &current_value)
        .or(fallback.as_ref())?;
    let resolved_path = resolution.resolved_path.as_deref()?;
    let next_value = scene_path_string(resolved_path);
    (next_value != current_value).then_some(next_value)
}

fn path_collect_rewrite_value_style(
    rewrite_mode: PathCollectRewriteMode,
) -> Option<ScenePathValueStyle> {
    match rewrite_mode {
        PathCollectRewriteMode::CopyOnly => None,
        PathCollectRewriteMode::Absolute => None,
        PathCollectRewriteMode::WorkspaceDoubleSlashRelative => {
            Some(ScenePathValueStyle::DoubleSlashWorkspaceRelative)
        }
        PathCollectRewriteMode::PlainRelative => Some(ScenePathValueStyle::PlainRelative),
    }
}

pub(in crate::gui) fn resolved_target_file_path_for_entry(
    row: &SceneRow,
    entry_index: usize,
) -> Option<PathBuf> {
    let current_value = effective_path_value_for_entry(row, entry_index)?;
    let resolution = row
        .path_resolution(entry_index, &current_value)
        .cloned()
        .or_else(|| row.path_resolution_fallback(entry_index, &current_value))?;
    let resolved_path = resolution.resolved_path?;
    resolved_path.is_file().then_some(resolved_path)
}

fn effective_path_value_for_entry(row: &SceneRow, entry_index: usize) -> Option<String> {
    let report = row.display_paths_report()?;
    let entry = report.entries.get(entry_index)?;
    Some(
        row.path_overrides
            .get(&entry_index)
            .cloned()
            .unwrap_or_else(|| entry.value.clone()),
    )
}
