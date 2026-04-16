use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use super::super::*;
use super::helpers::{
    path_value_edit_supported_for_edit_targets, resolved_target_file_path_for_entry,
    scene_path_string, shared_workspace_root_for_targets, write_back_selected_scene_path,
};

pub(in crate::gui) fn path_collect_supported_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> bool {
    path_file_collect_supported_for_edit_targets(rows, edit_targets)
        && path_value_edit_supported_for_edit_targets(rows, edit_targets)
}

pub(in crate::gui) fn path_file_collect_supported_for_edit_targets(
    rows: &[SceneRow],
    edit_targets: &PathEditTargets,
) -> bool {
    shared_workspace_root_for_targets(rows, edit_targets).is_some()
        && !edit_targets.is_empty()
        && edit_targets.iter().all(|(row_id, entry_index)| {
            rows.iter()
                .find(|row| row.id == *row_id)
                .and_then(|row| resolved_target_file_path_for_entry(row, *entry_index))
                .is_some()
        })
}

pub(in crate::gui) fn path_collect_default_folder(workspace_root: &Path) -> PathBuf {
    workspace_root.join("sourceimages")
}

pub(in crate::gui) fn parse_path_collect_folder_input(
    input: &str,
    workspace_root: &Path,
) -> Option<PathBuf> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(workspace_root.join(path))
    }
}

pub(in crate::gui) fn collected_path_rewrite_value(
    destination_path: &Path,
    workspace_root: &Path,
    rewrite_mode: PathCollectRewriteMode,
) -> String {
    match rewrite_mode {
        PathCollectRewriteMode::CopyOnly => scene_path_string(destination_path),
        PathCollectRewriteMode::Absolute => scene_path_string(destination_path),
        PathCollectRewriteMode::WorkspaceDoubleSlashRelative => write_back_selected_scene_path(
            destination_path,
            Some(workspace_root),
            ScenePathValueStyle::DoubleSlashWorkspaceRelative,
        ),
        PathCollectRewriteMode::PlainRelative => write_back_selected_scene_path(
            destination_path,
            Some(workspace_root),
            ScenePathValueStyle::PlainRelative,
        ),
    }
}

pub(in crate::gui) fn path_collect_destination_supports_rewrite_mode(
    destination_folder: &Path,
    workspace_root: &Path,
    rewrite_mode: PathCollectRewriteMode,
) -> bool {
    match rewrite_mode {
        PathCollectRewriteMode::CopyOnly => true,
        PathCollectRewriteMode::Absolute => true,
        PathCollectRewriteMode::WorkspaceDoubleSlashRelative
        | PathCollectRewriteMode::PlainRelative => {
            destination_folder.strip_prefix(workspace_root).is_ok()
        }
    }
}

pub(in crate::gui) fn collect_target_files(
    plans: &[PathCollectPlan],
) -> Result<PathCollectResult, String> {
    let mut by_destination = BTreeMap::<PathBuf, BTreeSet<PathBuf>>::new();
    for plan in plans {
        by_destination
            .entry(plan.destination_path.clone())
            .or_default()
            .insert(plan.source_path.clone());
    }

    let mut copied = 0usize;
    let mut reused = 0usize;
    for (destination_path, source_paths) in by_destination {
        let Some(source_path) = source_paths.iter().next().cloned() else {
            continue;
        };
        if !source_path.is_file() {
            return Err(format!(
                "source file is unavailable: {}",
                source_path.display()
            ));
        }

        let source_bytes = fs::read(&source_path)
            .map_err(|err| format!("failed to read {}: {err}", source_path.display()))?;
        for other_source in source_paths.iter().skip(1) {
            if !other_source.is_file() {
                return Err(format!(
                    "source file is unavailable: {}",
                    other_source.display()
                ));
            }
            let other_bytes = fs::read(other_source)
                .map_err(|err| format!("failed to read {}: {err}", other_source.display()))?;
            if other_bytes != source_bytes {
                return Err(format!(
                    "multiple source files map to {} with different contents",
                    destination_path.display()
                ));
            }
        }

        if source_path == destination_path {
            reused += 1;
            continue;
        }

        if destination_path.exists() {
            let destination_bytes = fs::read(&destination_path)
                .map_err(|err| format!("failed to read {}: {err}", destination_path.display()))?;
            if destination_bytes != source_bytes {
                return Err(format!(
                    "destination already exists with different contents: {}",
                    destination_path.display()
                ));
            }
            reused += 1;
            continue;
        }

        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        fs::copy(&source_path, &destination_path).map_err(|err| {
            format!(
                "failed to copy {} to {}: {err}",
                source_path.display(),
                destination_path.display()
            )
        })?;
        copied += 1;
    }

    Ok(PathCollectResult { copied, reused })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gui) struct PathCollectPlan {
    pub row_id: u64,
    pub entry_index: usize,
    pub row_index: usize,
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub next_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gui) struct PathCollectResult {
    pub copied: usize,
    pub reused: usize,
}
