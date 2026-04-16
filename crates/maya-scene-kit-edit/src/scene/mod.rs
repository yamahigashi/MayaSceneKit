mod edit;
mod emit;
mod error;
mod io;
pub(crate) mod ir;
mod ops;
pub(crate) mod public {
    mod clean;
    mod composite_edit;
    pub(crate) mod map;

    mod conversion;
    mod core;
    mod path_owner_delete;
    mod paths;
    mod scripts;
    mod staging;

    pub use self::{
        clean::{
            ExecutionCleanPreview, ExecutionCleanResult, ExecutionCleanStageResult,
            ExecutionCleanTarget,
        },
        composite_edit::{CompositeSceneEditsPreview, CompositeSceneEditsStageResult},
        conversion::{
            Confidence, DecodeAttemptResult, DecodeQuality, DecodeQualityDistributionEntry,
            IssueKind, MayaAsciiConversionReport, MayaAsciiDecodeAttempt, MayaAsciiIssue,
            MayaAsciiStageResult, RawChunkDump, SemanticProvenance, UnknownInventoryEntry,
        },
        core::{AsciiDecodePolicy, OperationMode, SceneFormat, ValidationState},
        path_owner_delete::{
            PathOwnerDeletePreview, PathOwnerDeleteStageResult, PathOwnerDeleteTarget,
        },
        paths::{
            PathReplaceCandidateItem, PathReplaceCandidatePreview, PathReplaceMode,
            PathReplaceOverride, PathReplacePreview, PathReplacePreviewItem, PathReplaceResult,
            PathReplaceRule, PathReplaceStageResult,
        },
        scripts::{ScriptNodeCleanPreview, ScriptNodeCleanResult, ScriptNodeCleanStageResult},
        staging::StagedSceneArtifact,
    };
}
mod recover;

use std::path::{Path, PathBuf};

pub use self::{
    edit::{MaterializeOptions, Materializer, PatchPlanner, collect_raw_chunks},
    error::SceneToolError,
    io::write::write_output_bytes_atomic,
    public::{
        AsciiDecodePolicy, CompositeSceneEditsPreview, CompositeSceneEditsStageResult, Confidence,
        DecodeAttemptResult, DecodeQuality, DecodeQualityDistributionEntry, ExecutionCleanPreview,
        ExecutionCleanResult, ExecutionCleanStageResult, ExecutionCleanTarget, IssueKind,
        MayaAsciiConversionReport, MayaAsciiDecodeAttempt, MayaAsciiIssue, MayaAsciiStageResult,
        OperationMode, PathOwnerDeletePreview, PathOwnerDeleteStageResult, PathOwnerDeleteTarget,
        PathReplaceCandidateItem, PathReplaceCandidatePreview, PathReplaceMode,
        PathReplaceOverride, PathReplacePreview, PathReplacePreviewItem, PathReplaceResult,
        PathReplaceRule, PathReplaceStageResult, RawChunkDump, SceneFormat, ScriptNodeCleanPreview,
        ScriptNodeCleanResult, ScriptNodeCleanStageResult, SemanticProvenance, StagedSceneArtifact,
        UnknownInventoryEntry, ValidationState,
    },
};

pub fn configure_additional_node_info_paths(paths: &[PathBuf]) -> Result<(), SceneToolError> {
    maya_scene_kit_observe::scene::recovery::validate_additional_node_info_paths(
        &maya_scene_kit_observe::scene::LoadOptions::default()
            .with_additional_node_info_paths(paths.to_vec()),
    )
}

pub fn convert_to_maya_ascii(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<PathBuf, SceneToolError> {
    Ok(convert_to_maya_ascii_with_report(input_path, output_path)?.output_path)
}

pub fn convert_to_maya_ascii_with_report(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<MayaAsciiConversionReport, SceneToolError> {
    convert_to_maya_ascii_with_report_and_options(
        input_path,
        output_path,
        &MaterializeOptions::default(),
    )
}

pub fn convert_to_maya_ascii_with_options(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    options: &MaterializeOptions,
) -> Result<PathBuf, SceneToolError> {
    Ok(
        convert_to_maya_ascii_with_report_and_options(input_path, output_path, options)?
            .output_path,
    )
}

pub fn convert_to_maya_ascii_with_report_and_options(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    options: &MaterializeOptions,
) -> Result<MayaAsciiConversionReport, SceneToolError> {
    Materializer::new(options.clone()).convert_to_maya_ascii_with_report(input_path, output_path)
}

pub fn stage_maya_ascii_with_options(
    input_path: impl AsRef<Path>,
    options: &MaterializeOptions,
) -> Result<MayaAsciiStageResult, SceneToolError> {
    Materializer::new(options.clone()).stage_maya_ascii(input_path)
}

pub fn stage_maya_ascii(
    input_path: impl AsRef<Path>,
) -> Result<MayaAsciiStageResult, SceneToolError> {
    stage_maya_ascii_with_options(input_path, &MaterializeOptions::default())
}

pub fn replace_scene_paths_with_options(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
    options: &MaterializeOptions,
) -> Result<PathReplaceResult, SceneToolError> {
    PatchPlanner::new(options.clone()).replace_scene_paths(input_path, output_path, rules)
}

pub fn preview_replace_scene_paths_with_options(
    input_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
    options: &MaterializeOptions,
) -> Result<PathReplacePreview, SceneToolError> {
    PatchPlanner::new(options.clone()).preview_replace_scene_paths(input_path, rules)
}

pub fn preview_replace_scene_paths(
    input_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
) -> Result<PathReplacePreview, SceneToolError> {
    preview_replace_scene_paths_with_options(
        input_path,
        rules,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn preview_replace_scene_path_candidates_with_options(
    input_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
    options: &MaterializeOptions,
) -> Result<PathReplaceCandidatePreview, SceneToolError> {
    PatchPlanner::new(options.clone()).preview_replace_scene_path_candidates(input_path, rules)
}

pub fn preview_replace_scene_path_candidates(
    input_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
) -> Result<PathReplaceCandidatePreview, SceneToolError> {
    preview_replace_scene_path_candidates_with_options(
        input_path,
        rules,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn preview_replace_scene_path_candidates_in_report_with_options(
    report: &maya_scene_kit_observe::scene::paths::ScenePathsReport,
    rules: &[PathReplaceRule],
    options: &MaterializeOptions,
) -> Result<PathReplaceCandidatePreview, SceneToolError> {
    PatchPlanner::new(options.clone())
        .preview_replace_scene_path_candidates_in_report(report, rules)
}

pub fn preview_replace_scene_path_candidates_in_report(
    report: &maya_scene_kit_observe::scene::paths::ScenePathsReport,
    rules: &[PathReplaceRule],
) -> Result<PathReplaceCandidatePreview, SceneToolError> {
    preview_replace_scene_path_candidates_in_report_with_options(
        report,
        rules,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_replace_scene_paths_with_options(
    input_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
    options: &MaterializeOptions,
) -> Result<PathReplaceStageResult, SceneToolError> {
    PatchPlanner::new(options.clone()).stage_replace_scene_paths(input_path, rules)
}

pub fn stage_replace_scene_paths(
    input_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
) -> Result<PathReplaceStageResult, SceneToolError> {
    stage_replace_scene_paths_with_options(
        input_path,
        rules,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn preview_replace_scene_paths_with_overrides_with_options(
    input_path: impl AsRef<Path>,
    overrides: &[PathReplaceOverride],
    options: &MaterializeOptions,
) -> Result<PathReplacePreview, SceneToolError> {
    PatchPlanner::new(options.clone())
        .preview_replace_scene_paths_with_overrides(input_path, overrides)
}

pub fn preview_replace_scene_paths_with_overrides(
    input_path: impl AsRef<Path>,
    overrides: &[PathReplaceOverride],
) -> Result<PathReplacePreview, SceneToolError> {
    preview_replace_scene_paths_with_overrides_with_options(
        input_path,
        overrides,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn preview_replace_scene_paths_with_overrides_in_report_with_options(
    report: &maya_scene_kit_observe::scene::paths::ScenePathsReport,
    overrides: &[PathReplaceOverride],
    options: &MaterializeOptions,
) -> Result<PathReplacePreview, SceneToolError> {
    PatchPlanner::new(options.clone())
        .preview_replace_scene_paths_with_overrides_in_report(report, overrides)
}

pub fn preview_replace_scene_paths_with_overrides_in_report(
    report: &maya_scene_kit_observe::scene::paths::ScenePathsReport,
    overrides: &[PathReplaceOverride],
) -> Result<PathReplacePreview, SceneToolError> {
    preview_replace_scene_paths_with_overrides_in_report_with_options(
        report,
        overrides,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_replace_scene_paths_with_overrides_with_options(
    input_path: impl AsRef<Path>,
    overrides: &[PathReplaceOverride],
    options: &MaterializeOptions,
) -> Result<PathReplaceStageResult, SceneToolError> {
    PatchPlanner::new(options.clone())
        .stage_replace_scene_paths_with_overrides(input_path, overrides)
}

pub fn stage_replace_scene_paths_with_overrides(
    input_path: impl AsRef<Path>,
    overrides: &[PathReplaceOverride],
) -> Result<PathReplaceStageResult, SceneToolError> {
    stage_replace_scene_paths_with_overrides_with_options(
        input_path,
        overrides,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_replace_scene_paths_with_overrides_in_report_with_options(
    report: &maya_scene_kit_observe::scene::paths::ScenePathsReport,
    overrides: &[PathReplaceOverride],
    options: &MaterializeOptions,
) -> Result<PathReplaceStageResult, SceneToolError> {
    PatchPlanner::new(options.clone())
        .stage_replace_scene_paths_with_overrides_in_report(report, overrides)
}

pub fn stage_replace_scene_paths_with_overrides_in_report(
    report: &maya_scene_kit_observe::scene::paths::ScenePathsReport,
    overrides: &[PathReplaceOverride],
) -> Result<PathReplaceStageResult, SceneToolError> {
    stage_replace_scene_paths_with_overrides_in_report_with_options(
        report,
        overrides,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn preview_delete_path_owner_nodes_with_options(
    input_path: impl AsRef<Path>,
    targets: &[PathOwnerDeleteTarget],
    options: &MaterializeOptions,
) -> Result<PathOwnerDeletePreview, SceneToolError> {
    PatchPlanner::new(options.clone()).preview_delete_path_owner_nodes(input_path, targets)
}

pub fn preview_delete_path_owner_nodes(
    input_path: impl AsRef<Path>,
    targets: &[PathOwnerDeleteTarget],
) -> Result<PathOwnerDeletePreview, SceneToolError> {
    preview_delete_path_owner_nodes_with_options(
        input_path,
        targets,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_delete_path_owner_nodes_with_options(
    input_path: impl AsRef<Path>,
    targets: &[PathOwnerDeleteTarget],
    options: &MaterializeOptions,
) -> Result<PathOwnerDeleteStageResult, SceneToolError> {
    PatchPlanner::new(options.clone()).stage_delete_path_owner_nodes(input_path, targets)
}

pub fn stage_delete_path_owner_nodes(
    input_path: impl AsRef<Path>,
    targets: &[PathOwnerDeleteTarget],
) -> Result<PathOwnerDeleteStageResult, SceneToolError> {
    stage_delete_path_owner_nodes_with_options(
        input_path,
        targets,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_scene_edits_with_options(
    input_path: impl AsRef<Path>,
    clean_targets: &[ExecutionCleanTarget],
    path_owner_delete_targets: &[PathOwnerDeleteTarget],
    options: &MaterializeOptions,
) -> Result<CompositeSceneEditsStageResult, SceneToolError> {
    PatchPlanner::new(options.clone()).stage_scene_edits(
        input_path,
        clean_targets,
        path_owner_delete_targets,
    )
}

pub fn stage_scene_edits(
    input_path: impl AsRef<Path>,
    clean_targets: &[ExecutionCleanTarget],
    path_owner_delete_targets: &[PathOwnerDeleteTarget],
) -> Result<CompositeSceneEditsStageResult, SceneToolError> {
    stage_scene_edits_with_options(
        input_path,
        clean_targets,
        path_owner_delete_targets,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_scene_edits_in_report_with_bytes_with_options(
    report: &maya_scene_kit_observe::scene::paths::ScenePathsReport,
    bytes: &[u8],
    clean_targets: &[ExecutionCleanTarget],
    path_owner_delete_targets: &[PathOwnerDeleteTarget],
    options: &MaterializeOptions,
) -> Result<CompositeSceneEditsStageResult, SceneToolError> {
    PatchPlanner::new(options.clone()).stage_scene_edits_in_report_with_bytes(
        report,
        bytes,
        clean_targets,
        path_owner_delete_targets,
    )
}

pub fn stage_scene_edits_in_report_with_bytes(
    report: &maya_scene_kit_observe::scene::paths::ScenePathsReport,
    bytes: &[u8],
    clean_targets: &[ExecutionCleanTarget],
    path_owner_delete_targets: &[PathOwnerDeleteTarget],
) -> Result<CompositeSceneEditsStageResult, SceneToolError> {
    stage_scene_edits_in_report_with_bytes_with_options(
        report,
        bytes,
        clean_targets,
        path_owner_delete_targets,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn replace_scene_paths(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
) -> Result<PathReplaceResult, SceneToolError> {
    replace_scene_paths_with_options(
        input_path,
        output_path,
        rules,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn clean_execution_targets_with_options(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    targets: &[ExecutionCleanTarget],
    options: &MaterializeOptions,
) -> Result<ExecutionCleanResult, SceneToolError> {
    PatchPlanner::new(options.clone()).clean_execution_targets(input_path, output_path, targets)
}

pub fn clean_execution_targets(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    targets: &[ExecutionCleanTarget],
) -> Result<ExecutionCleanResult, SceneToolError> {
    clean_execution_targets_with_options(
        input_path,
        output_path,
        targets,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn preview_clean_execution_targets_with_options(
    input_path: impl AsRef<Path>,
    targets: &[ExecutionCleanTarget],
    options: &MaterializeOptions,
) -> Result<ExecutionCleanPreview, SceneToolError> {
    PatchPlanner::new(options.clone()).preview_clean_execution_targets(input_path, targets)
}

pub fn preview_clean_execution_targets(
    input_path: impl AsRef<Path>,
    targets: &[ExecutionCleanTarget],
) -> Result<ExecutionCleanPreview, SceneToolError> {
    preview_clean_execution_targets_with_options(
        input_path,
        targets,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_clean_execution_targets_with_options(
    input_path: impl AsRef<Path>,
    targets: &[ExecutionCleanTarget],
    options: &MaterializeOptions,
) -> Result<ExecutionCleanStageResult, SceneToolError> {
    PatchPlanner::new(options.clone()).stage_clean_execution_targets(input_path, targets)
}

pub fn stage_clean_execution_targets(
    input_path: impl AsRef<Path>,
    targets: &[ExecutionCleanTarget],
) -> Result<ExecutionCleanStageResult, SceneToolError> {
    stage_clean_execution_targets_with_options(
        input_path,
        targets,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn remove_script_nodes_with_options(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    options: &MaterializeOptions,
) -> Result<ScriptNodeCleanResult, SceneToolError> {
    PatchPlanner::new(options.clone()).remove_script_nodes(input_path, output_path)
}

pub fn preview_remove_script_nodes_with_options(
    input_path: impl AsRef<Path>,
    options: &MaterializeOptions,
) -> Result<ScriptNodeCleanPreview, SceneToolError> {
    PatchPlanner::new(options.clone()).preview_remove_script_nodes(input_path)
}

pub fn preview_remove_script_nodes(
    input_path: impl AsRef<Path>,
) -> Result<ScriptNodeCleanPreview, SceneToolError> {
    preview_remove_script_nodes_with_options(
        input_path,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn preview_remove_script_nodes_by_name_with_options(
    input_path: impl AsRef<Path>,
    node_names: &[String],
    options: &MaterializeOptions,
) -> Result<ScriptNodeCleanPreview, SceneToolError> {
    let targets = node_names
        .iter()
        .cloned()
        .map(|node_name| ExecutionCleanTarget::ScriptNode { node_name })
        .collect::<Vec<_>>();
    let preview = preview_clean_execution_targets_with_options(input_path, &targets, options)?;
    Ok(ScriptNodeCleanPreview {
        input_path: preview.input_path,
        scene_format: preview.scene_format,
        operation_mode: preview.operation_mode,
        validation_state: preview.validation_state,
        removed_nodes: preview.removed_script_nodes,
    })
}

pub fn preview_remove_script_nodes_by_name(
    input_path: impl AsRef<Path>,
    node_names: &[String],
) -> Result<ScriptNodeCleanPreview, SceneToolError> {
    preview_remove_script_nodes_by_name_with_options(
        input_path,
        node_names,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_remove_script_nodes_with_options(
    input_path: impl AsRef<Path>,
    options: &MaterializeOptions,
) -> Result<ScriptNodeCleanStageResult, SceneToolError> {
    PatchPlanner::new(options.clone()).stage_remove_script_nodes(input_path)
}

pub fn stage_remove_script_nodes(
    input_path: impl AsRef<Path>,
) -> Result<ScriptNodeCleanStageResult, SceneToolError> {
    stage_remove_script_nodes_with_options(
        input_path,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn stage_remove_script_nodes_by_name_with_options(
    input_path: impl AsRef<Path>,
    node_names: &[String],
    options: &MaterializeOptions,
) -> Result<ScriptNodeCleanStageResult, SceneToolError> {
    let targets = node_names
        .iter()
        .cloned()
        .map(|node_name| ExecutionCleanTarget::ScriptNode { node_name })
        .collect::<Vec<_>>();
    let staged = stage_clean_execution_targets_with_options(input_path, &targets, options)?;
    Ok(ScriptNodeCleanStageResult {
        preview: ScriptNodeCleanPreview {
            input_path: staged.preview.input_path,
            scene_format: staged.preview.scene_format,
            operation_mode: staged.preview.operation_mode,
            validation_state: staged.preview.validation_state,
            removed_nodes: staged.preview.removed_script_nodes,
        },
        artifact: staged.artifact,
    })
}

pub fn stage_remove_script_nodes_by_name(
    input_path: impl AsRef<Path>,
    node_names: &[String],
) -> Result<ScriptNodeCleanStageResult, SceneToolError> {
    stage_remove_script_nodes_by_name_with_options(
        input_path,
        node_names,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn remove_script_nodes(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<ScriptNodeCleanResult, SceneToolError> {
    remove_script_nodes_with_options(
        input_path,
        output_path,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn remove_script_nodes_by_name_with_options(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    node_names: &[String],
    options: &MaterializeOptions,
) -> Result<ScriptNodeCleanResult, SceneToolError> {
    let targets = node_names
        .iter()
        .cloned()
        .map(|node_name| ExecutionCleanTarget::ScriptNode { node_name })
        .collect::<Vec<_>>();
    let result = clean_execution_targets_with_options(input_path, output_path, &targets, options)?;
    Ok(ScriptNodeCleanResult {
        input_path: result.input_path,
        output_path: result.output_path,
        scene_format: result.scene_format,
        operation_mode: result.operation_mode,
        validation_state: result.validation_state,
        removed_nodes: result.removed_script_nodes,
    })
}

pub fn remove_script_nodes_by_name(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    node_names: &[String],
) -> Result<ScriptNodeCleanResult, SceneToolError> {
    remove_script_nodes_by_name_with_options(
        input_path,
        output_path,
        node_names,
        &MaterializeOptions::default().with_operation_mode(OperationMode::Forensic),
    )
}

pub fn save_staged_artifact(
    artifact: &StagedSceneArtifact,
    output_path: impl AsRef<Path>,
) -> Result<PathBuf, SceneToolError> {
    let dst = output_path.as_ref();
    write_output_bytes_atomic(dst, &artifact.bytes)?;
    Ok(dst.to_path_buf())
}
