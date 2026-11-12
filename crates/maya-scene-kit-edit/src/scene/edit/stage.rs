use super::*;

impl PatchPlanner {
    pub fn replace_scene_paths(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        rules: &[PathReplaceRule],
    ) -> Result<PathReplaceResult, SceneToolError> {
        let dst = output_path.as_ref();
        let staged = self.stage_replace_scene_paths(input_path, rules)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        write_bytes_atomic(dst, &staged.artifact.bytes)?;
        Ok(PathReplaceResult {
            input_path: staged.preview.input_path.clone(),
            output_path: dst.to_path_buf(),
            scene_format: staged.preview.scene_format,
            operation_mode: staged.preview.operation_mode,
            validation_state: staged.preview.validation_state,
            replaced_count: staged.changes.replacement_count,
            skipped: staged.changes.skipped,
        })
    }

    pub fn stage_replace_scene_paths(
        &self,
        input_path: impl AsRef<Path>,
        rules: &[PathReplaceRule],
    ) -> Result<PathReplaceStageResult, SceneToolError> {
        let report = self.collect_scene_paths_report(input_path.as_ref())?;
        let applied = self.apply_path_rules_in_path(&input_path, rules)?;
        let preview = super::preview::staged_path_preview(
            self.path_candidate_preview_from_application(&report, &applied),
        );
        Ok(PathReplaceStageResult {
            changes: applied.changes.summary,
            artifact: StagedSceneArtifact {
                input_path: preview.input_path.clone(),
                suggested_output_path: super::replace_rules::suggested_path_output(
                    &preview.input_path,
                    "_rewritten",
                    None,
                ),
                scene_format: preview.scene_format,
                operation_mode: preview.operation_mode,
                validation_state: preview.validation_state,
                bytes: applied.bytes,
            },
            preview,
        })
    }

    pub fn stage_replace_scene_paths_with_overrides(
        &self,
        input_path: impl AsRef<Path>,
        overrides: &[PathReplaceOverride],
    ) -> Result<PathReplaceStageResult, SceneToolError> {
        let src = input_path.as_ref();
        let report = self.collect_scene_paths_report(src)?;
        self.stage_replace_scene_paths_with_overrides_in_report(&report, overrides)
    }

    pub fn stage_replace_scene_paths_with_overrides_in_report(
        &self,
        report: &ScenePathsReport,
        overrides: &[PathReplaceOverride],
    ) -> Result<PathReplaceStageResult, SceneToolError> {
        let targets = super::replace_rules::resolve_targeted_overrides(report, overrides)?;
        let applied = self.apply_path_overrides_in_report(report, &targets)?;
        let preview = self.path_override_preview_from_application(report, &targets, &applied);
        Ok(PathReplaceStageResult {
            changes: applied.changes.summary,
            artifact: StagedSceneArtifact {
                input_path: preview.input_path.clone(),
                suggested_output_path: super::replace_rules::suggested_path_output(
                    &preview.input_path,
                    "_rewritten",
                    None,
                ),
                scene_format: preview.scene_format,
                operation_mode: preview.operation_mode,
                validation_state: preview.validation_state,
                bytes: applied.bytes,
            },
            preview,
        })
    }

    pub fn remove_script_nodes(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<ScriptNodeCleanResult, SceneToolError> {
        let dst = output_path.as_ref();
        let staged = self.stage_remove_script_nodes(input_path)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        write_bytes_atomic(dst, &staged.artifact.bytes)?;
        Ok(ScriptNodeCleanResult {
            changes: staged.changes,
            input_path: staged.preview.input_path.clone(),
            output_path: dst.to_path_buf(),
            scene_format: staged.preview.scene_format,
            operation_mode: staged.preview.operation_mode,
            validation_state: staged.preview.validation_state,
            removed_nodes: staged.preview.removed_nodes.clone(),
        })
    }

    pub fn remove_script_nodes_by_name(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        node_names: &[String],
    ) -> Result<ScriptNodeCleanResult, SceneToolError> {
        let dst = output_path.as_ref();
        let staged = self.stage_remove_script_nodes_by_name(input_path, node_names)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        write_bytes_atomic(dst, &staged.artifact.bytes)?;
        Ok(ScriptNodeCleanResult {
            changes: staged.changes,
            input_path: staged.preview.input_path.clone(),
            output_path: dst.to_path_buf(),
            scene_format: staged.preview.scene_format,
            operation_mode: staged.preview.operation_mode,
            validation_state: staged.preview.validation_state,
            removed_nodes: staged.preview.removed_nodes.clone(),
        })
    }

    pub fn stage_remove_script_nodes(
        &self,
        input_path: impl AsRef<Path>,
    ) -> Result<ScriptNodeCleanStageResult, SceneToolError> {
        let src = input_path.as_ref();
        let (format, applied) = self.apply_script_clean_in_path(src)?;
        let preview = self.script_preview_from_application(src, format, &applied);
        let bytes = applied.bytes;
        let changes = applied.changes.scene;
        Ok(ScriptNodeCleanStageResult {
            changes,
            artifact: StagedSceneArtifact {
                input_path: preview.input_path.clone(),
                suggested_output_path: super::replace_rules::suggested_path_output(
                    &preview.input_path,
                    "_clean",
                    None,
                ),
                scene_format: preview.scene_format,
                operation_mode: preview.operation_mode,
                validation_state: preview.validation_state,
                bytes,
            },
            preview,
        })
    }

    pub fn stage_remove_script_nodes_by_name(
        &self,
        input_path: impl AsRef<Path>,
        node_names: &[String],
    ) -> Result<ScriptNodeCleanStageResult, SceneToolError> {
        let src = input_path.as_ref();
        let targets = node_names
            .iter()
            .cloned()
            .map(|node_name| ExecutionCleanTarget::ScriptNode { node_name })
            .collect::<Vec<_>>();
        let (format, applied) = self.apply_execution_clean_in_path(src, &targets)?;
        let preview = self.script_preview_from_application(src, format, &applied);
        let bytes = applied.bytes;
        let changes = applied.changes.scene;
        Ok(ScriptNodeCleanStageResult {
            changes,
            artifact: StagedSceneArtifact {
                input_path: preview.input_path.clone(),
                suggested_output_path: super::replace_rules::suggested_path_output(
                    &preview.input_path,
                    "_clean",
                    None,
                ),
                scene_format: preview.scene_format,
                operation_mode: preview.operation_mode,
                validation_state: preview.validation_state,
                bytes,
            },
            preview,
        })
    }

    pub fn clean_execution_targets(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        targets: &[ExecutionCleanTarget],
    ) -> Result<ExecutionCleanResult, SceneToolError> {
        let dst = output_path.as_ref();
        let staged = self.stage_clean_execution_targets(input_path, targets)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        write_bytes_atomic(dst, &staged.artifact.bytes)?;
        Ok(ExecutionCleanResult {
            changes: staged.changes,
            input_path: staged.preview.input_path.clone(),
            output_path: dst.to_path_buf(),
            scene_format: staged.preview.scene_format,
            operation_mode: staged.preview.operation_mode,
            validation_state: staged.preview.validation_state,
            cleaned_targets: staged.preview.cleaned_targets.clone(),
            removed_script_nodes: staged.preview.removed_script_nodes.clone(),
            removed_plugin_requires: staged.preview.removed_plugin_requires.clone(),
        })
    }

    pub fn stage_clean_execution_targets(
        &self,
        input_path: impl AsRef<Path>,
        targets: &[ExecutionCleanTarget],
    ) -> Result<ExecutionCleanStageResult, SceneToolError> {
        let src = input_path.as_ref();
        let (format, applied) = self.apply_execution_clean_in_path(src, targets)?;
        let preview = self.clean_preview_from_application(src, format, &applied);
        let bytes = applied.bytes;
        let changes = applied.changes.scene;
        Ok(ExecutionCleanStageResult {
            changes,
            artifact: StagedSceneArtifact {
                input_path: preview.input_path.clone(),
                suggested_output_path: super::replace_rules::suggested_path_output(
                    &preview.input_path,
                    "_clean",
                    None,
                ),
                scene_format: preview.scene_format,
                operation_mode: preview.operation_mode,
                validation_state: preview.validation_state,
                bytes,
            },
            preview,
        })
    }
}
