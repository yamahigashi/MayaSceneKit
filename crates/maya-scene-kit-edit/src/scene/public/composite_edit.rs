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
    pub changes: SceneEditChanges,
    pub preview: CompositeSceneEditsPreview,
    pub artifact: StagedSceneArtifact,
}

#[derive(Debug, Clone)]
pub struct SceneEditPlan {
    pub report: maya_scene_kit_observe::scene::paths::ScenePathsReport,
    pub clean_source: Option<maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>,
    pub intents: Vec<SceneEditIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SceneEditIntent {
    Path(super::PathReplaceOverride),
    Clean(ExecutionCleanTarget),
    DeleteOwner(PathOwnerDeleteTarget),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SceneEditLocator {
    MaRange {
        start: usize,
        end: usize,
    },
    MbForm {
        form: String,
        node_offset: usize,
    },
    MbRecord {
        form: String,
        node_offset: usize,
        chunk_start: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SceneEditStatus {
    Applied,
    Covered,
    Superseded,
    Unchanged,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SceneEditChange {
    pub intent: SceneEditIntent,
    pub locator: SceneEditLocator,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
    pub status: SceneEditStatus,
    pub reason: String,
    pub superseded_by: Option<SceneEditLocator>,
    pub covered_by: Option<SceneEditLocator>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenePathOutcome {
    Replaced,
    Superseded,
    Mixed,
    Unchanged,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenePathEntryChange {
    pub entry_index: usize,
    pub outcome: ScenePathOutcome,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SceneEditChanges {
    pub records: Vec<SceneEditChange>,
    pub path_entries: Vec<ScenePathEntryChange>,
    pub path_replacements: super::PathReplaceChanges,
    pub superseded_path_override_count: usize,
    pub physical_deletion_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SceneEditError {
    #[error("missing {source_kind} observation fingerprint")]
    MissingSource { source_kind: &'static str },
    #[error("{source_kind} observation fingerprint does not match the original bytes")]
    SourceMismatch { source_kind: &'static str },
    #[error("source length changed: expected {expected}, found {actual}")]
    SourceLengthMismatch { expected: usize, actual: usize },
    #[error("scene edit plans require an unfiltered PathKind::All report")]
    FilteredReport,
    #[error("duplicate path override for entry {entry_index}")]
    DuplicateOverride { entry_index: usize },
    #[error("invalid scene edit target: {reason}")]
    InvalidTarget { reason: String },
    #[error("scene edit ranges overlap: {first:?} and {second:?}")]
    Overlap {
        first: SceneEditLocator,
        second: SceneEditLocator,
    },
    #[error("no effective edits; skipped: {skipped:?}")]
    NoEffectiveEdits { skipped: Vec<SceneEditChange> },
    #[error(transparent)]
    Binary(#[from] maya_scene_kit_formats::mb::rewrite::MbPlanError),
    #[error(transparent)]
    Path(#[from] maya_scene_kit_formats::ma::rewrite::MaPathReplaceError),
    #[error(transparent)]
    Source(#[from] super::super::SceneToolError),
}
