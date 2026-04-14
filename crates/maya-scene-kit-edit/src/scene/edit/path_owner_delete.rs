use super::*;
use crate::scene::edit::materialize::unsupported_scene_format;

impl PatchPlanner {
    pub fn preview_delete_path_owner_nodes(
        &self,
        input_path: impl AsRef<Path>,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<PathOwnerDeletePreview, SceneToolError> {
        let src = input_path.as_ref();
        let report = self.collect_scene_paths_report(src)?;
        self.preview_delete_path_owner_nodes_in_report(&report, targets)
    }

    pub fn preview_delete_path_owner_nodes_in_report(
        &self,
        report: &ScenePathsReport,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<PathOwnerDeletePreview, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let normalized = normalize_path_owner_delete_targets(targets)?;
        let deleted_targets = resolve_path_owner_delete_targets(report, &normalized);
        if deleted_targets.is_empty() {
            return Err(SceneToolError::Message(format!(
                "no matching path owner nodes found in {}",
                report.scene_path.display()
            )));
        }

        Ok(PathOwnerDeletePreview {
            input_path: report.scene_path.clone(),
            scene_format: report.scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: report.validation_state,
            deleted_targets,
        })
    }

    pub fn stage_delete_path_owner_nodes(
        &self,
        input_path: impl AsRef<Path>,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<PathOwnerDeleteStageResult, SceneToolError> {
        let src = input_path.as_ref();
        let report = self.collect_scene_paths_report(src)?;
        self.stage_delete_path_owner_nodes_in_report(&report, targets)
    }

    pub fn stage_delete_path_owner_nodes_in_report(
        &self,
        report: &ScenePathsReport,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<PathOwnerDeleteStageResult, SceneToolError> {
        let preview = self.preview_delete_path_owner_nodes_in_report(report, targets)?;
        let bytes = self.materialize_deleted_path_owner_nodes_bytes_in_report(
            report,
            &preview.deleted_targets,
        )?;
        Ok(PathOwnerDeleteStageResult {
            artifact: StagedSceneArtifact {
                input_path: preview.input_path.clone(),
                suggested_output_path: super::replace_rules::suggested_path_output(
                    &preview.input_path,
                    "_node-removed",
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

    pub(super) fn materialize_deleted_path_owner_nodes_bytes_in_report(
        &self,
        report: &ScenePathsReport,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<Vec<u8>, SceneToolError> {
        let original = fs::read(report.scene_path.as_path())?;
        self.materialize_deleted_path_owner_nodes_bytes_in_report_and_bytes(
            report, targets, &original,
        )
    }

    pub(super) fn materialize_deleted_path_owner_nodes_bytes_in_report_and_bytes(
        &self,
        report: &ScenePathsReport,
        targets: &[PathOwnerDeleteTarget],
        bytes: &[u8],
    ) -> Result<Vec<u8>, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let src = report.scene_path.as_path();

        if report.scene_format == SceneFormat::Ma {
            let ma_targets = targets
                .iter()
                .map(|target| (target.node_type.clone(), target.node_name.clone()))
                .collect::<Vec<_>>();
            let (rewritten, removed) = rewrite::remove_path_owner_nodes_from_ma(bytes, &ma_targets);
            if removed.is_empty() {
                return Err(SceneToolError::Message(format!(
                    "no matching path owner nodes found in {}",
                    src.display()
                )));
            }
            return Ok(rewritten);
        }

        if report.scene_format == SceneFormat::Mb {
            let mb = crate::mb::parse_bytes(bytes.to_vec())?;
            let owner_forms = resolve_mb_path_owner_forms(report, targets);
            if owner_forms.is_empty() {
                return Err(SceneToolError::Message(format!(
                    "no matching path owner forms found in {}",
                    src.display()
                )));
            }
            let (rewritten, removed) =
                crate::mb::remove_root_forms_from_mb_by_locator(&mb.data, &mb.root, &owner_forms);
            if removed.is_empty() {
                return Err(SceneToolError::Message(format!(
                    "no matching path owner forms found in {}",
                    src.display()
                )));
            }
            return Ok(rewritten);
        }

        Err(unsupported_scene_format(src, report.scene_format))
    }
}

fn normalize_path_owner_delete_targets(
    targets: &[PathOwnerDeleteTarget],
) -> Result<Vec<PathOwnerDeleteTarget>, SceneToolError> {
    let normalized = targets
        .iter()
        .filter_map(|target| {
            let node_type = target.node_type.trim();
            let node_name = target.node_name.trim();
            (!node_type.is_empty() && !node_name.is_empty()).then(|| PathOwnerDeleteTarget {
                node_type: node_type.to_string(),
                node_name: node_name.to_string(),
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return Err(SceneToolError::Message(
            "path owner delete requires at least one valid target".to_string(),
        ));
    }
    Ok(normalized)
}

fn resolve_path_owner_delete_targets(
    report: &ScenePathsReport,
    requested: &[PathOwnerDeleteTarget],
) -> Vec<PathOwnerDeleteTarget> {
    if report.scene_format == SceneFormat::Mb {
        return resolve_mb_path_owner_targets(report, requested);
    }

    let requested = requested
        .iter()
        .cloned()
        .collect::<BTreeSet<PathOwnerDeleteTarget>>();
    report
        .entries
        .iter()
        .filter_map(|entry| {
            let target = PathOwnerDeleteTarget {
                node_type: entry.node_type.clone(),
                node_name: entry.node_name.clone(),
            };
            requested.contains(&target).then_some(target)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn resolve_mb_path_owner_targets(
    report: &ScenePathsReport,
    requested: &[PathOwnerDeleteTarget],
) -> Vec<PathOwnerDeleteTarget> {
    let requested = requested
        .iter()
        .cloned()
        .collect::<BTreeSet<PathOwnerDeleteTarget>>();
    report
        .entries
        .iter()
        .filter_map(|entry| {
            let target = PathOwnerDeleteTarget {
                node_type: entry.node_type.clone(),
                node_name: entry.node_name.clone(),
            };
            if !requested.contains(&target) {
                return None;
            }
            let meta = entry.meta.as_ref()?;
            meta.trace_form.as_ref()?;
            meta.trace_node_offset?;
            Some(target)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn resolve_mb_path_owner_forms(
    report: &ScenePathsReport,
    requested: &[PathOwnerDeleteTarget],
) -> Vec<(String, usize)> {
    let requested = requested
        .iter()
        .cloned()
        .collect::<BTreeSet<PathOwnerDeleteTarget>>();
    report
        .entries
        .iter()
        .filter_map(|entry| {
            let target = PathOwnerDeleteTarget {
                node_type: entry.node_type.clone(),
                node_name: entry.node_name.clone(),
            };
            if !requested.contains(&target) {
                return None;
            }
            let meta = entry.meta.as_ref()?;
            Some((meta.trace_form.clone()?, meta.trace_node_offset?))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
