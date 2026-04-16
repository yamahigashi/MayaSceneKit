use std::path::PathBuf;

use maya_scene_kit_observe::scene::evidence::ExecutionSourceRange;

use super::{OperationMode, SceneFormat, ValidationState, staging::StagedSceneArtifact};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutionCleanTarget {
    ScriptNode { node_name: String },
    PluginRequire { rendered: String },
    TopLevelCommand { source_range: ExecutionSourceRange },
    FileCommandCallback { source_range: ExecutionSourceRange },
    MbOwnerForm { form: String, node_offset: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionCleanPreview {
    pub input_path: PathBuf,
    pub scene_format: SceneFormat,
    pub operation_mode: OperationMode,
    pub validation_state: ValidationState,
    pub cleaned_targets: Vec<ExecutionCleanTarget>,
    pub removed_script_nodes: Vec<String>,
    pub removed_plugin_requires: Vec<String>,
}

impl ExecutionCleanPreview {
    pub fn cleaned_count(&self) -> usize {
        self.cleaned_targets.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionCleanStageResult {
    pub preview: ExecutionCleanPreview,
    pub artifact: StagedSceneArtifact,
}

#[derive(Debug, Clone)]
pub struct ExecutionCleanResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub scene_format: SceneFormat,
    pub operation_mode: OperationMode,
    pub validation_state: ValidationState,
    pub cleaned_targets: Vec<ExecutionCleanTarget>,
    pub removed_script_nodes: Vec<String>,
    pub removed_plugin_requires: Vec<String>,
}

impl ExecutionCleanResult {
    pub fn cleaned_count(&self) -> usize {
        self.cleaned_targets.len()
    }
}
