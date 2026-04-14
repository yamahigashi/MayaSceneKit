use std::path::PathBuf;

use super::{OperationMode, SceneFormat, ValidationState, staging::StagedSceneArtifact};

/// Result of removing script nodes from a scene.
#[derive(Debug, Clone)]
pub struct ScriptNodeCleanResult {
    /// Original scene path.
    pub input_path: PathBuf,
    /// Output scene path.
    pub output_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Operation policy used for the write.
    pub operation_mode: OperationMode,
    /// Integrity state associated with the write path.
    pub validation_state: ValidationState,
    /// Removed node names.
    pub removed_nodes: Vec<String>,
}

impl ScriptNodeCleanResult {
    /// Returns the number of removed script nodes.
    pub fn removed_count(&self) -> usize {
        self.removed_nodes.len()
    }
}

/// Non-destructive preview of a script-node cleanup operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptNodeCleanPreview {
    /// Source scene path.
    pub input_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Operation policy selected for the preview.
    pub operation_mode: OperationMode,
    /// Integrity state associated with the preview path.
    pub validation_state: ValidationState,
    /// Script node names that would be removed.
    pub removed_nodes: Vec<String>,
}

impl ScriptNodeCleanPreview {
    /// Returns the number of script nodes that would be removed.
    pub fn removed_count(&self) -> usize {
        self.removed_nodes.len()
    }
}

/// Non-destructive staged cleanup result owned by the edit layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptNodeCleanStageResult {
    /// Preview data for the cleanup operation.
    pub preview: ScriptNodeCleanPreview,
    /// Staged output bytes that can be saved later.
    pub artifact: StagedSceneArtifact,
}
