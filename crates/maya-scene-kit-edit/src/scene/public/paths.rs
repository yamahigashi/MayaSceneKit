use std::path::PathBuf;

use super::{OperationMode, SceneFormat, ValidationState, staging::StagedSceneArtifact};

/// Path replacement matching mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathReplaceMode {
    /// Replace plain substring matches.
    #[default]
    Literal,
    /// Replace matches using Rust regex syntax.
    Regex,
}

/// One path replacement rule.
#[derive(Debug, Clone)]
pub struct PathReplaceRule {
    /// Path prefix or exact value to replace.
    pub from: String,
    /// Replacement value.
    pub to: String,
    /// Matching mode used for this rule.
    pub mode: PathReplaceMode,
}

/// One targeted path override keyed by collected entry order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathReplaceOverride {
    /// Zero-based index into `collect_scene_paths(PathKind::All).entries`.
    pub entry_index: usize,
    /// Original value expected at that entry.
    pub before_value: String,
    /// Replacement value for that entry only.
    pub after_value: String,
}

/// Result of rewriting scene paths.
#[derive(Debug, Clone)]
pub struct PathReplaceResult {
    /// Original scene path.
    pub input_path: PathBuf,
    /// Output scene path.
    pub output_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Operation policy used for the write.
    pub operation_mode: OperationMode,
    /// Integrity state associated with the rewrite path.
    pub validation_state: ValidationState,
    /// Number of rewritten paths.
    pub replaced_count: usize,
}

/// One planned path replacement preview row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathReplacePreviewItem {
    /// Zero-based index into `collect_scene_paths(PathKind::All).entries`.
    pub entry_index: usize,
    /// Node type that owns the path.
    pub node_type: String,
    /// Node name that owns the path.
    pub node_name: String,
    /// Attribute path or shorthand.
    pub attr: String,
    /// Original value.
    pub before_value: String,
    /// Rewritten value.
    pub after_value: String,
    /// Number of replacements that would be applied to this value.
    pub replacement_count: usize,
}

/// One candidate preview row, including unchanged values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathReplaceCandidateItem {
    /// Zero-based index into `collect_scene_paths(PathKind::All).entries`.
    pub entry_index: usize,
    /// Node type that owns the path.
    pub node_type: String,
    /// Node name that owns the path.
    pub node_name: String,
    /// Attribute path or shorthand.
    pub attr: String,
    /// Original value.
    pub before_value: String,
    /// Rewritten value.
    pub after_value: String,
    /// Number of replacements that would be applied to this value.
    pub replacement_count: usize,
}

/// Non-destructive preview of a path rewrite operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathReplacePreview {
    /// Source scene path.
    pub input_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Operation policy selected for the preview.
    pub operation_mode: OperationMode,
    /// Integrity state associated with the preview path.
    pub validation_state: ValidationState,
    /// Number of replacements that would be applied.
    pub matched_count: usize,
    /// Expandable before/after details for affected values.
    pub items: Vec<PathReplacePreviewItem>,
}

/// Non-destructive preview of all candidate paths for a rewrite operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathReplaceCandidatePreview {
    /// Source scene path.
    pub input_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Operation policy selected for the preview.
    pub operation_mode: OperationMode,
    /// Integrity state associated with the preview path.
    pub validation_state: ValidationState,
    /// Number of replacements that would be applied.
    pub matched_count: usize,
    /// Expandable before/after details for all candidate values.
    pub items: Vec<PathReplaceCandidateItem>,
}

/// Non-destructive staged rewrite result owned by the edit layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathReplaceStageResult {
    /// Expandable before/after details for affected values.
    pub preview: PathReplacePreview,
    /// Staged output bytes that can be saved later.
    pub artifact: StagedSceneArtifact,
}
