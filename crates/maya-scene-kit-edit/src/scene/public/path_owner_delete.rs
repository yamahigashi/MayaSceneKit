use std::path::PathBuf;

use super::{OperationMode, SceneFormat, ValidationState, staging::StagedSceneArtifact};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathOwnerDeleteTarget {
    pub node_type: String,
    pub node_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathOwnerDeletePreview {
    pub input_path: PathBuf,
    pub scene_format: SceneFormat,
    pub operation_mode: OperationMode,
    pub validation_state: ValidationState,
    pub deleted_targets: Vec<PathOwnerDeleteTarget>,
}

impl PathOwnerDeletePreview {
    pub fn deleted_count(&self) -> usize {
        self.deleted_targets.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathOwnerDeleteStageResult {
    pub preview: PathOwnerDeletePreview,
    pub artifact: StagedSceneArtifact,
}
