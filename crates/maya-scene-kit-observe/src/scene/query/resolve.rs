use std::path::{Path, PathBuf};

use crate::scene::paths::{
    ScenePathResolution, ScenePathResolutionStatus, ScenePathValueStyle,
};

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn classify_scene_path_value_style(value: &str) -> ScenePathValueStyle {
    if value.starts_with("//") || value.starts_with("\\\\") {
        return ScenePathValueStyle::UncAbsolute;
    }
    if value.contains("//") {
        return ScenePathValueStyle::DoubleSlashWorkspaceRelative;
    }
    if Path::new(value).is_absolute() || has_windows_drive_prefix(value) {
        return ScenePathValueStyle::Absolute;
    }
    ScenePathValueStyle::PlainRelative
}

fn workspace_relative_suffix(value: &str) -> Option<&str> {
    let (_prefix, suffix) = value.split_once("//")?;
    let suffix = suffix.trim_start_matches('/');
    (!suffix.is_empty()).then_some(suffix)
}

pub fn find_scene_workspace_root(scene_path: impl AsRef<Path>) -> Option<PathBuf> {
    let mut current = scene_path.as_ref().parent()?;
    loop {
        if current.join("workspace.mel").is_file() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

pub fn resolve_scene_path_value(
    raw_value: &str,
    workspace_root: Option<&Path>,
) -> ScenePathResolution {
    let style = classify_scene_path_value_style(raw_value);
    let resolved_path = match style {
        ScenePathValueStyle::PlainRelative => workspace_root.and_then(|workspace_root| {
            let trimmed = raw_value.trim_start_matches('/');
            (!trimmed.is_empty()).then(|| workspace_root.join(trimmed))
        }),
        ScenePathValueStyle::Absolute | ScenePathValueStyle::UncAbsolute => {
            Some(PathBuf::from(raw_value))
        }
        ScenePathValueStyle::DoubleSlashWorkspaceRelative => {
            workspace_root.and_then(|workspace_root| {
                workspace_relative_suffix(raw_value).map(|suffix| workspace_root.join(suffix))
            })
        }
    };

    let status = match resolved_path.as_ref() {
        Some(path) if path.is_file() => ScenePathResolutionStatus::Exists,
        Some(_) => ScenePathResolutionStatus::Missing,
        None => ScenePathResolutionStatus::Unresolved,
    };

    ScenePathResolution {
        style,
        resolved_path,
        status,
    }
}
