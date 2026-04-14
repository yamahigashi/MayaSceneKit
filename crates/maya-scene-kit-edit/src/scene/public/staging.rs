use std::path::PathBuf;

use super::{OperationMode, SceneFormat, ValidationState};

/// In-memory staged output owned by the edit layer until the caller persists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedSceneArtifact {
    /// Original scene path used to build the artifact.
    pub input_path: PathBuf,
    /// Suggested destination path for the staged bytes.
    pub suggested_output_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Operation policy used to build the artifact.
    pub operation_mode: OperationMode,
    /// Integrity state associated with the staged bytes.
    pub validation_state: ValidationState,
    /// Materialized output bytes.
    pub bytes: Vec<u8>,
}
