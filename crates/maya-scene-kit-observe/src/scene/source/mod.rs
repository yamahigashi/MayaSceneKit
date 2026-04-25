pub(crate) mod loader;
pub(crate) mod ma;
pub(crate) mod mb;

use std::path::Path;

pub use self::loader::{ExecutionObservationBundle, LoadOptions, Loader, ObservationBundle};
pub(crate) use self::loader::{MaObservationData, ObservationData};
use crate::scene::{
    SceneToolError,
    core::SceneFormat,
    dump::SceneDumpReport,
    paths::{PathKind, ScenePathsReport},
    scripts::{ScriptNodeEntriesReport, ScriptNodeReport},
};

pub fn detect_scene_format(path: impl AsRef<Path>) -> Result<SceneFormat, SceneToolError> {
    crate::scene::ops::detect_scene_format(path)
}

pub fn check_script_nodes(path: impl AsRef<Path>) -> Result<ScriptNodeReport, SceneToolError> {
    check_script_nodes_with_options(path, &LoadOptions::default())
}

pub fn check_script_nodes_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<ScriptNodeReport, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path(path)?;
    let entries = observation.script_node_entries()?;
    Ok(ScriptNodeReport {
        scene_path: observation.scene_path().to_path_buf(),
        scene_format: observation.scene_format(),
        validation_state: observation.validation_state(),
        nodes: entries.into_iter().map(|entry| entry.name).collect(),
    })
}

pub fn collect_script_node_entries(
    path: impl AsRef<Path>,
) -> Result<ScriptNodeEntriesReport, SceneToolError> {
    collect_script_node_entries_with_options(path, &LoadOptions::default())
}

pub fn collect_script_node_entries_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<ScriptNodeEntriesReport, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path(path)?;
    Ok(ScriptNodeEntriesReport {
        scene_path: observation.scene_path().to_path_buf(),
        scene_format: observation.scene_format(),
        validation_state: observation.validation_state(),
        entries: observation.script_node_entries()?,
    })
}

pub fn collect_scene_dump(path: impl AsRef<Path>) -> Result<SceneDumpReport, SceneToolError> {
    collect_scene_dump_with_options(path, &LoadOptions::default())
}

pub fn collect_scene_dump_with_options(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<SceneDumpReport, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path_without_retained_ma_bytes(path)?;
    observation.scene_dump_report()
}

pub fn collect_scene_paths(
    path: impl AsRef<Path>,
    kind: PathKind,
) -> Result<ScenePathsReport, SceneToolError> {
    collect_scene_paths_with_options(path, kind, &LoadOptions::default())
}

pub fn collect_scene_paths_with_options(
    path: impl AsRef<Path>,
    kind: PathKind,
    options: &LoadOptions,
) -> Result<ScenePathsReport, SceneToolError> {
    let observation = Loader::new(options.clone()).observe_path_without_retained_ma_bytes(path)?;
    Ok(ScenePathsReport {
        scene_path: observation.scene_path().to_path_buf(),
        scene_format: observation.scene_format(),
        validation_state: observation.validation_state(),
        entries: observation.scene_paths(kind)?,
    })
}
