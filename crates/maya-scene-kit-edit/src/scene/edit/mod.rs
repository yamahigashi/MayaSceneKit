use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use maya_scene_kit_formats::ma::{
    requires, rewrite, scripts, types::PathReplaceRule as MaPathReplaceRule,
};
use maya_scene_kit_observe::scene::{
    LoadOptions, MelParseBudget, collect_scene_paths_with_options,
    evidence::ExecutionSourceRange,
    paths::{PathKind, ScenePathsReport},
};
use regex::Regex;

use crate::{
    mb::{
        MbPathReplaceRule, parse_file, remove_plugin_requires_from_mb,
        remove_raw_script_nodes_from_mb,
    },
    scene::{
        CompositeSceneEditsPreview, CompositeSceneEditsStageResult, ExecutionCleanPreview,
        ExecutionCleanResult, ExecutionCleanStageResult, ExecutionCleanTarget,
        MayaAsciiConversionReport, MayaAsciiStageResult, OperationMode, PathOwnerDeletePreview,
        PathOwnerDeleteStageResult, PathOwnerDeleteTarget, PathReplaceCandidateItem,
        PathReplaceCandidatePreview, PathReplaceMode, PathReplaceOverride, PathReplacePreview,
        PathReplacePreviewItem, PathReplaceResult, PathReplaceRule, PathReplaceStageResult,
        RawChunkDump, SceneFormat, SceneToolError, ScriptNodeCleanPreview, ScriptNodeCleanResult,
        ScriptNodeCleanStageResult, StagedSceneArtifact, ValidationState,
        io::write::write_bytes_atomic, ops, public::map, recover::collect_raw_chunk_records,
    },
};

mod clean;
mod composite;
mod materialize;
mod path_owner_delete;
mod paths;
mod preview;
mod replace_rules;
mod stage;

pub use self::paths::collect_raw_chunks;

#[derive(Debug, Clone)]
pub struct MaterializeOptions {
    load_options: LoadOptions,
    embed_output_metadata: bool,
    operation_mode: OperationMode,
}

impl Default for MaterializeOptions {
    fn default() -> Self {
        Self {
            load_options: LoadOptions::default(),
            embed_output_metadata: false,
            operation_mode: OperationMode::BestEffort,
        }
    }
}

impl MaterializeOptions {
    pub fn new(load_options: LoadOptions) -> Self {
        Self {
            load_options,
            ..Self::default()
        }
    }

    pub fn with_schema_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.load_options = self.load_options.with_schema_root(path);
        self
    }

    pub fn with_chunk_schema_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.load_options = self.load_options.with_chunk_schema_root(path);
        self
    }

    pub fn with_addattr_schema_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.load_options = self.load_options.with_addattr_schema_path(path);
        self
    }

    pub fn with_structural_attr_schema_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.load_options = self.load_options.with_structural_attr_schema_path(path);
        self
    }

    pub fn with_refedit_schema_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.load_options = self.load_options.with_refedit_schema_path(path);
        self
    }

    pub fn with_additional_node_info_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.load_options = self.load_options.with_additional_node_info_paths(paths);
        self
    }

    pub fn with_mel_parse_budget(mut self, budget: MelParseBudget) -> Self {
        self.load_options = self.load_options.with_mel_parse_budget(budget);
        self
    }

    pub fn with_max_parse_bytes(mut self, max_bytes: usize) -> Self {
        self.load_options = self.load_options.with_max_parse_bytes(max_bytes);
        self
    }

    pub fn with_embed_output_metadata(mut self, enabled: bool) -> Self {
        self.embed_output_metadata = enabled;
        self
    }

    pub fn with_operation_mode(mut self, mode: OperationMode) -> Self {
        self.operation_mode = mode;
        self
    }

    pub fn load_options(&self) -> &LoadOptions {
        &self.load_options
    }

    fn reject_if_not_forensic(&self) -> Result<(), SceneToolError> {
        if self.operation_mode == OperationMode::Forensic {
            return Ok(());
        }
        Err(SceneToolError::RejectedByMode {
            mode: self.operation_mode,
            validation_state: ValidationState::Unsupported,
            issue_count: 0,
            unknown_count: 0,
        })
    }
}

pub struct Materializer {
    options: MaterializeOptions,
}

impl Materializer {
    pub fn new(options: MaterializeOptions) -> Self {
        Self { options }
    }
}

pub struct PatchPlanner {
    options: MaterializeOptions,
}

impl PatchPlanner {
    pub fn new(options: MaterializeOptions) -> Self {
        Self { options }
    }
}
