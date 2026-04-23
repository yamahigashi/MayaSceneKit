use std::collections::BTreeMap;

use super::super::{
    AuditRowCleanState, AuditTableRow, ExecutionCleanTarget, PathCollectRewriteMode,
    PathEditTargets, SceneRow, clean_targets_for_threat_findings,
    path_edit::{
        absolute_override_value_for_entry, path_value_edit_supported_for_entry,
        resolved_target_file_path_for_entry, workspace_relative_override_value_for_entry,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::gui) struct AuditContextMenuState {
    pub can_clean: bool,
    pub can_undo: bool,
    pub show_disabled_clean: bool,
}

pub(in crate::gui) fn audit_context_menu_state(rows: &[AuditTableRow]) -> AuditContextMenuState {
    let can_clean = rows
        .iter()
        .any(|entry| entry.clean_state == AuditRowCleanState::Available);
    let can_undo = rows
        .iter()
        .any(|entry| entry.clean_state == AuditRowCleanState::Staged);
    let show_disabled_clean = !can_clean
        && rows
            .iter()
            .any(|entry| entry.clean_state == AuditRowCleanState::BlockedByOtherDirty);

    AuditContextMenuState {
        can_clean,
        can_undo,
        show_disabled_clean,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::gui) struct FileContextMenuState {
    pub can_clean: bool,
    pub can_delete_ui_configuration_script_node: bool,
}

pub(in crate::gui) fn file_context_menu_state(
    rows: &[SceneRow],
    row_id: u64,
) -> FileContextMenuState {
    let Some(row_index) = rows.iter().position(|row| row.id == row_id) else {
        return FileContextMenuState {
            can_clean: false,
            can_delete_ui_configuration_script_node: false,
        };
    };
    let selected = rows[row_index].selected;
    let can_delete_ui_configuration_script_node = !rows[row_index].is_processing();
    let can_clean = rows
        .iter()
        .enumerate()
        .filter(|(index, row)| {
            if row.is_processing() {
                return false;
            }
            if selected {
                row.selected
            } else {
                *index == row_index
            }
        })
        .any(|(_, row)| file_context_clean_targets(row).next().is_some());

    FileContextMenuState {
        can_clean,
        can_delete_ui_configuration_script_node,
    }
}

fn file_context_clean_targets(row: &SceneRow) -> impl Iterator<Item = ExecutionCleanTarget> + '_ {
    row.pending_clean_targets
        .iter()
        .cloned()
        .chain(clean_targets_for_threat_findings(row))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::gui) struct PathContextMenuState {
    pub can_convert_to_absolute: bool,
    pub show_disabled_convert_to_absolute: bool,
    pub can_convert_to_workspace_double_slash_relative: bool,
    pub show_disabled_convert_to_workspace_double_slash_relative: bool,
    pub can_convert_to_plain_relative: bool,
    pub show_disabled_convert_to_plain_relative: bool,
    pub can_collect_files_to_folder: bool,
    pub show_disabled_collect_files_to_folder: bool,
    pub can_collect_files: bool,
    pub show_disabled_collect_files: bool,
}

pub(in crate::gui) fn path_context_menu_state(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> PathContextMenuState {
    let row_by_id = rows
        .iter()
        .map(|row| (row.id, row))
        .collect::<BTreeMap<_, _>>();
    let has_targets = !edit_targets.is_empty();
    let first_workspace_root = edit_targets
        .first()
        .and_then(|(row_id, _)| row_by_id.get(row_id))
        .and_then(|row| row.scene_workspace_root.as_ref());
    let mut all_targets_editable = has_targets;
    let mut all_targets_collectable_files = has_targets;
    let mut shared_workspace_root = has_targets && first_workspace_root.is_some();
    let mut has_workspace_double_slash_relative_target = false;
    let mut has_plain_relative_target = false;
    let mut has_absolute_target = false;
    let mut has_collectable_file_target = false;
    for (row_id, entry_index) in edit_targets {
        let Some(row) = row_by_id.get(row_id).copied() else {
            all_targets_editable = false;
            all_targets_collectable_files = false;
            shared_workspace_root = false;
            continue;
        };
        has_workspace_double_slash_relative_target |= workspace_relative_override_value_for_entry(
            row,
            *entry_index,
            PathCollectRewriteMode::WorkspaceDoubleSlashRelative,
        )
        .is_some();
        has_plain_relative_target |= workspace_relative_override_value_for_entry(
            row,
            *entry_index,
            PathCollectRewriteMode::PlainRelative,
        )
        .is_some();
        has_absolute_target |= absolute_override_value_for_entry(row, *entry_index).is_some();
        let has_resolved_file = resolved_target_file_path_for_entry(row, *entry_index).is_some();
        has_collectable_file_target |= has_resolved_file;
        all_targets_collectable_files &= has_resolved_file;
        all_targets_editable &= path_value_edit_supported_for_entry(row, *entry_index);
        shared_workspace_root &= row.scene_workspace_root.as_ref() == first_workspace_root;
    }
    let can_edit_path_values = all_targets_editable;
    let can_collect_files_to_folder = shared_workspace_root && all_targets_collectable_files;
    let can_collect_files = can_collect_files_to_folder && can_edit_path_values;

    PathContextMenuState {
        can_convert_to_absolute: has_absolute_target && can_edit_path_values,
        show_disabled_convert_to_absolute: has_absolute_target && !can_edit_path_values,
        can_convert_to_workspace_double_slash_relative: has_workspace_double_slash_relative_target
            && can_edit_path_values,
        show_disabled_convert_to_workspace_double_slash_relative:
            has_workspace_double_slash_relative_target && !can_edit_path_values,
        can_convert_to_plain_relative: has_plain_relative_target && can_edit_path_values,
        show_disabled_convert_to_plain_relative: has_plain_relative_target && !can_edit_path_values,
        can_collect_files_to_folder,
        show_disabled_collect_files_to_folder: has_collectable_file_target
            && !can_collect_files_to_folder,
        can_collect_files,
        show_disabled_collect_files: has_collectable_file_target && !can_collect_files,
    }
}
