use std::path::PathBuf;

use super::{
    OperationMode, PathOwnerDeleteTarget, SceneFormat, StagedSceneArtifact, ValidationState,
    clean::ExecutionCleanTarget,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeSceneEditsPreview {
    pub input_path: PathBuf,
    pub scene_format: SceneFormat,
    pub operation_mode: OperationMode,
    pub validation_state: ValidationState,
    pub cleaned_targets: Vec<ExecutionCleanTarget>,
    pub removed_script_nodes: Vec<String>,
    pub removed_plugin_requires: Vec<String>,
    pub deleted_path_owner_targets: Vec<PathOwnerDeleteTarget>,
}

impl CompositeSceneEditsPreview {
    pub fn has_clean_targets(&self) -> bool {
        !self.cleaned_targets.is_empty()
    }

    pub fn has_deleted_path_owner_targets(&self) -> bool {
        !self.deleted_path_owner_targets.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeSceneEditsStageResult {
    pub preview: CompositeSceneEditsPreview,
    pub artifact: StagedSceneArtifact,
}
