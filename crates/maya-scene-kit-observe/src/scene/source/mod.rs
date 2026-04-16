pub(crate) mod loader;
pub(crate) mod ma;

pub use self::loader::{LoadOptions, Loader, ObservationBundle};
pub(crate) use self::loader::{MaObservationData, ObservationData};
use std::path::Path;

use crate::scene::{PathKind, SceneFormat, SceneToolError};

pub fn detect_scene_format(path: impl AsRef<Path>) -> Result<SceneFormat, SceneToolError> {
    crate::scene::ops::detect_scene_format(path)
}

pub fn check_script_nodes(
    path: impl AsRef<Path>,
) -> Result<crate::scene::ScriptNodeReport, SceneToolError> {
    check_script_nodes_with_options(path, &LoadOptions::default())
}

pub fn check_script_nodes_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<crate::scene::ScriptNodeReport, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path(path)?;
    let entries = observation.script_node_entries()?;
    Ok(crate::scene::ScriptNodeReport {
        scene_path: observation.scene_path().to_path_buf(),
        scene_format: observation.scene_format(),
        validation_state: observation.validation_state(),
        nodes: entries.into_iter().map(|entry| entry.name).collect(),
    })
}

pub fn collect_script_node_entries(
    path: impl AsRef<Path>,
) -> Result<crate::scene::ScriptNodeEntriesReport, SceneToolError> {
    collect_script_node_entries_with_options(path, &LoadOptions::default())
}

pub fn collect_script_node_entries_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<crate::scene::ScriptNodeEntriesReport, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path(path)?;
    Ok(crate::scene::ScriptNodeEntriesReport {
        scene_path: observation.scene_path().to_path_buf(),
        scene_format: observation.scene_format(),
        validation_state: observation.validation_state(),
        entries: observation.script_node_entries()?,
    })
}

pub fn collect_scene_dump(
    path: impl AsRef<Path>,
) -> Result<crate::scene::SceneDumpReport, SceneToolError> {
    collect_scene_dump_with_options(path, &LoadOptions::default())
}

pub fn collect_scene_dump_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<crate::scene::SceneDumpReport, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path_without_retained_ma_bytes(path)?;
    observation.scene_dump_report()
}

pub fn collect_scene_paths(
    path: impl AsRef<Path>,
    kind: PathKind,
) -> Result<crate::scene::ScenePathsReport, SceneToolError> {
    collect_scene_paths_with_options(path, kind, &LoadOptions::default())
}

pub fn collect_scene_paths_with_options(
    path: impl AsRef<Path>,
    kind: PathKind,
    options: &LoadOptions,
) -> Result<crate::scene::ScenePathsReport, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path_without_retained_ma_bytes(path)?;
    Ok(crate::scene::ScenePathsReport {
        scene_path: observation.scene_path().to_path_buf(),
        scene_format: observation.scene_format(),
        validation_state: observation.validation_state(),
        entries: observation.scene_paths(kind)?,
    })
}
