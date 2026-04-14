use super::*;

impl PatchPlanner {
    pub fn stage_scene_edits_in_report_with_bytes(
        &self,
        report: &ScenePathsReport,
        bytes: &[u8],
        clean_targets: &[ExecutionCleanTarget],
        path_owner_delete_targets: &[PathOwnerDeleteTarget],
    ) -> Result<CompositeSceneEditsStageResult, SceneToolError> {
        let src = report.scene_path.as_path();
        let scene_format = report.scene_format;
        let validation_state = report.validation_state;

        let mut bytes = bytes.to_vec();
        let mut path_preview = None;
        if !path_owner_delete_targets.is_empty() {
            let preview =
                self.preview_delete_path_owner_nodes_in_report(report, path_owner_delete_targets)?;
            bytes = self.materialize_deleted_path_owner_nodes_bytes_in_report_and_bytes(
                report,
                &preview.deleted_targets,
                &bytes,
            )?;
            path_preview = Some(preview);
        }

        let mut clean_preview = None;
        if !clean_targets.is_empty() {
            let preview = self.preview_clean_execution_targets_in_bytes(
                src,
                scene_format,
                validation_state,
                &bytes,
                clean_targets,
            )?;
            bytes = self.materialize_execution_clean_scene_bytes_in_bytes(
                src,
                scene_format,
                &bytes,
                &preview.cleaned_targets,
            )?;
            clean_preview = Some(preview);
        }

        if clean_preview.is_none() && path_preview.is_none() {
            return Err(SceneToolError::Message(format!(
                "no scene edits staged for {}",
                src.display()
            )));
        }

        let preview = CompositeSceneEditsPreview {
            input_path: src.to_path_buf(),
            scene_format,
            operation_mode: self.options.operation_mode,
            validation_state,
            cleaned_targets: clean_preview
                .as_ref()
                .map(|preview| preview.cleaned_targets.clone())
                .unwrap_or_default(),
            removed_script_nodes: clean_preview
                .as_ref()
                .map(|preview| preview.removed_script_nodes.clone())
                .unwrap_or_default(),
            removed_plugin_requires: clean_preview
                .as_ref()
                .map(|preview| preview.removed_plugin_requires.clone())
                .unwrap_or_default(),
            deleted_path_owner_targets: path_preview
                .as_ref()
                .map(|preview| preview.deleted_targets.clone())
                .unwrap_or_default(),
        };

        let suggested_suffix = match (
            preview.has_clean_targets(),
            preview.has_deleted_path_owner_targets(),
        ) {
            (true, true) => "_edited",
            (true, false) => "_clean",
            (false, true) => "_node-removed",
            (false, false) => unreachable!("checked above"),
        };

        Ok(CompositeSceneEditsStageResult {
            artifact: StagedSceneArtifact {
                input_path: preview.input_path.clone(),
                suggested_output_path: super::replace_rules::suggested_path_output(
                    &preview.input_path,
                    suggested_suffix,
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

    pub fn stage_scene_edits(
        &self,
        input_path: impl AsRef<Path>,
        clean_targets: &[ExecutionCleanTarget],
        path_owner_delete_targets: &[PathOwnerDeleteTarget],
    ) -> Result<CompositeSceneEditsStageResult, SceneToolError> {
        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;
        let validation_state = if scene_format == SceneFormat::Mb {
            let report = self.collect_scene_paths_report(src)?;
            report.validation_state
        } else {
            ValidationState::CopiedUnvalidated
        };

        let mut bytes = fs::read(src)?;
        let mut path_preview = None;
        if !path_owner_delete_targets.is_empty() {
            let report = self.collect_scene_paths_report(src)?;
            let preview =
                self.preview_delete_path_owner_nodes_in_report(&report, path_owner_delete_targets)?;
            bytes = self.materialize_deleted_path_owner_nodes_bytes_in_report(
                &report,
                &preview.deleted_targets,
            )?;
            path_preview = Some(preview);
        }

        let mut clean_preview = None;
        if !clean_targets.is_empty() {
            let preview = self.preview_clean_execution_targets_in_bytes(
                src,
                scene_format,
                validation_state,
                &bytes,
                clean_targets,
            )?;
            bytes = self.materialize_execution_clean_scene_bytes_in_bytes(
                src,
                scene_format,
                &bytes,
                &preview.cleaned_targets,
            )?;
            clean_preview = Some(preview);
        }

        if clean_preview.is_none() && path_preview.is_none() {
            return Err(SceneToolError::Message(format!(
                "no scene edits staged for {}",
                src.display()
            )));
        }

        let preview = CompositeSceneEditsPreview {
            input_path: src.to_path_buf(),
            scene_format,
            operation_mode: self.options.operation_mode,
            validation_state,
            cleaned_targets: clean_preview
                .as_ref()
                .map(|preview| preview.cleaned_targets.clone())
                .unwrap_or_default(),
            removed_script_nodes: clean_preview
                .as_ref()
                .map(|preview| preview.removed_script_nodes.clone())
                .unwrap_or_default(),
            removed_plugin_requires: clean_preview
                .as_ref()
                .map(|preview| preview.removed_plugin_requires.clone())
                .unwrap_or_default(),
            deleted_path_owner_targets: path_preview
                .as_ref()
                .map(|preview| preview.deleted_targets.clone())
                .unwrap_or_default(),
        };

        let suggested_suffix = match (
            preview.has_clean_targets(),
            preview.has_deleted_path_owner_targets(),
        ) {
            (true, true) => "_edited",
            (true, false) => "_clean",
            (false, true) => "_node-removed",
            (false, false) => unreachable!("checked above"),
        };

        Ok(CompositeSceneEditsStageResult {
            artifact: StagedSceneArtifact {
                input_path: preview.input_path.clone(),
                suggested_output_path: super::replace_rules::suggested_path_output(
                    &preview.input_path,
                    suggested_suffix,
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
