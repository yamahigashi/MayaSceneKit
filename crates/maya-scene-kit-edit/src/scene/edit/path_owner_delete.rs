use super::{
    application::{
        Applied, change, deleted_owners, form_locator, normalized_away, range_locator, summarize,
    },
    *,
};
use crate::scene::{
    SceneEditChanges, SceneEditIntent, edit::materialize::unsupported_scene_format,
};

impl PatchPlanner {
    pub fn preview_delete_path_owner_nodes(
        &self,
        input_path: impl AsRef<Path>,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<PathOwnerDeletePreview, SceneToolError> {
        let report = self.collect_scene_paths_report(input_path.as_ref())?;
        self.preview_delete_path_owner_nodes_in_report(&report, targets)
    }

    pub fn preview_delete_path_owner_nodes_in_report(
        &self,
        report: &ScenePathsReport,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<PathOwnerDeletePreview, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let applied =
            apply_owner_deletion(super::paths::read_report_source(report)?, report, targets)?;
        Ok(self.owner_preview_from_application(report, &applied.changes))
    }

    pub fn stage_delete_path_owner_nodes(
        &self,
        input_path: impl AsRef<Path>,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<PathOwnerDeleteStageResult, SceneToolError> {
        let report = self.collect_scene_paths_report(input_path.as_ref())?;
        self.stage_delete_path_owner_nodes_in_report(&report, targets)
    }

    pub fn stage_delete_path_owner_nodes_in_report(
        &self,
        report: &ScenePathsReport,
        targets: &[PathOwnerDeleteTarget],
    ) -> Result<PathOwnerDeleteStageResult, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let applied =
            apply_owner_deletion(super::paths::read_report_source(report)?, report, targets)?;
        let preview = self.owner_preview_from_application(report, &applied.changes);
        Ok(PathOwnerDeleteStageResult {
            changes: applied.changes,
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
                bytes: applied.bytes,
            },
            preview,
        })
    }

    fn owner_preview_from_application(
        &self,
        report: &ScenePathsReport,
        changes: &SceneEditChanges,
    ) -> PathOwnerDeletePreview {
        PathOwnerDeletePreview {
            input_path: report.scene_path.clone(),
            scene_format: report.scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: report.validation_state,
            deleted_targets: deleted_owners(changes),
        }
    }
}

fn apply_owner_deletion(
    bytes: Vec<u8>,
    report: &ScenePathsReport,
    requested: &[PathOwnerDeleteTarget],
) -> Result<Applied<SceneEditChanges>, SceneToolError> {
    let targets = normalize_path_owner_delete_targets(requested)?;
    let resolved = resolve_path_owner_delete_targets(report, &targets);
    let missing = |target: &PathOwnerDeleteTarget| {
        SceneToolError::Message(format!(
            "no matching path owner node {target:?} found in {}",
            report.scene_path.display()
        ))
    };
    for target in &targets {
        if !resolved.contains(target) {
            return Err(missing(target));
        }
    }
    let mut changes = SceneEditChanges::default();
    let output = if report.scene_format == SceneFormat::Ma {
        let pairs = targets
            .iter()
            .map(|target| (target.node_type.clone(), target.node_name.clone()))
            .collect::<Vec<_>>();
        let (output, removed) = rewrite::remove_path_owner_nodes_from_ma(&bytes, &pairs);
        for target in &targets {
            if !removed.contains(&(target.node_type.clone(), target.node_name.clone())) {
                return Err(missing(target));
            }
        }
        for (range, (node_type, node_name)) in
            rewrite::collect_path_owner_ranges_from_ma(&bytes, &pairs)
        {
            changes.records.push(change(
                &SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
                    node_type,
                    node_name,
                }),
                range_locator(&range),
                bytes[range].to_vec(),
                Vec::new(),
            ));
        }
        output
    } else if report.scene_format == SceneFormat::Mb {
        let mb = crate::mb::parse_bytes(bytes)?;
        let forms = resolve_mb_path_owner_forms(report, &targets);
        for target in &targets {
            let actual = crate::mb::rewrite::locate_mb_path_owner_forms(
                mb.data(),
                mb.root(),
                &target.node_type,
                &target.node_name,
            )
            .map_err(|error| SceneToolError::Message(error.to_string()))?;
            let requested_forms = resolve_mb_path_owner_forms(report, std::slice::from_ref(target));
            if requested_forms.is_empty()
                || requested_forms.iter().any(|form| !actual.contains(form))
            {
                return Err(missing(target));
            }
        }
        let (output, removed) =
            crate::mb::remove_root_forms_from_mb_by_locator(mb.data(), mb.root(), &forms)
                .map_err(super::clean::mb_rewrite_error)?;
        if forms.iter().any(|form| !removed.contains(form)) {
            return Err(SceneToolError::Message(
                "requested MB owner form was not removed".into(),
            ));
        }
        for target in &targets {
            for (form, offset) in resolve_mb_path_owner_forms(report, std::slice::from_ref(target))
            {
                let child = mb
                    .root()
                    .children()
                    .iter()
                    .find(|child| child.offset() == offset)
                    .expect("validated owner form");
                changes.records.push(change(
                    &SceneEditIntent::DeleteOwner(target.clone()),
                    form_locator(&form, offset),
                    mb.data()[child.offset()..child.payload_end()].to_vec(),
                    Vec::new(),
                ));
            }
        }
        output
    } else {
        return Err(unsupported_scene_format(
            &report.scene_path,
            report.scene_format,
        ));
    };
    let mut seen = BTreeSet::new();
    for target in requested {
        let normalized = PathOwnerDeleteTarget {
            node_type: target.node_type.trim().into(),
            node_name: target.node_name.trim().into(),
        };
        if normalized.node_type.is_empty()
            || normalized.node_name.is_empty()
            || !seen.insert(normalized)
        {
            changes
                .records
                .push(normalized_away(SceneEditIntent::DeleteOwner(
                    target.clone(),
                )));
        }
    }
    summarize(&mut changes);
    Ok(Applied {
        bytes: output,
        changes,
    })
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
    if targets.is_empty() {
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

pub(super) fn resolve_mb_path_owner_forms(
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
