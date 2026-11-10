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

        let mb = if scene_format == SceneFormat::Mb {
            Some(crate::mb::parse_bytes(bytes.to_vec())?)
        } else {
            None
        };
        let path_preview = if path_owner_delete_targets.is_empty() {
            None
        } else {
            Some(self.preview_delete_path_owner_nodes_in_report(report, path_owner_delete_targets)?)
        };
        let clean_preview = if clean_targets.is_empty() {
            None
        } else {
            Some(self.preview_clean_execution_targets_with_root(
                src,
                scene_format,
                validation_state,
                bytes,
                clean_targets,
                mb.as_ref().map(|mb| mb.root()),
            )?)
        };

        if clean_preview.is_none() && path_preview.is_none() {
            return Err(SceneToolError::Message(format!(
                "no scene edits staged for {}",
                src.display()
            )));
        }

        let accepted_clean = clean_preview
            .as_ref()
            .map(|preview| preview.cleaned_targets.as_slice())
            .unwrap_or_default();
        let accepted_owners = path_preview
            .as_ref()
            .map(|preview| preview.deleted_targets.as_slice())
            .unwrap_or_default();
        let bytes = if let Some(mb) = mb {
            let (mut forms, requires) =
                super::clean::collect_mb_clean_targets(mb.data(), mb.root(), accepted_clean)?;
            forms.extend(super::path_owner_delete::resolve_mb_path_owner_forms(
                report,
                accepted_owners,
            ));
            let forms = forms
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            crate::mb::remove_root_forms_and_plugin_requires_from_mb(
                mb.data(),
                mb.root(),
                &forms,
                crate::mb::MbNameSelection::Only(&requires),
            )
            .map_err(super::clean::mb_rewrite_error)?
            .0
        } else if scene_format == SceneFormat::Ma {
            let cleaned = if accepted_clean.is_empty() {
                bytes.to_vec()
            } else {
                self.materialize_execution_clean_scene_bytes_in_bytes(
                    src,
                    scene_format,
                    bytes,
                    accepted_clean,
                )?
            };
            let owners = accepted_owners
                .iter()
                .map(|target| (target.node_type.clone(), target.node_name.clone()))
                .collect::<Vec<_>>();
            rewrite::remove_path_owner_nodes_from_ma(&cleaned, &owners).0
        } else {
            return Err(super::materialize::unsupported_scene_format(
                src,
                scene_format,
            ));
        };

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
        let mut report = if scene_format == SceneFormat::Mb || !path_owner_delete_targets.is_empty()
        {
            self.collect_scene_paths_report(src)?
        } else {
            ScenePathsReport {
                scene_path: src.to_path_buf(),
                scene_format,
                validation_state: ValidationState::CopiedUnvalidated,
                entries: Vec::new(),
            }
        };
        if scene_format != SceneFormat::Mb {
            report.validation_state = ValidationState::CopiedUnvalidated;
        }
        let bytes = fs::read(src)?;
        self.stage_scene_edits_in_report_with_bytes(
            &report,
            &bytes,
            clean_targets,
            path_owner_delete_targets,
        )
    }
}
