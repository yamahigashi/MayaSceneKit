use maya_scene_kit_observe::scene::Loader;

use super::{
    application::{
        Applied, absorbed, change, cleaned_targets, form_locator, normalized_away, range_locator,
        record_locator, summarize,
    },
    *,
};
use crate::scene::{
    SceneEditChange, SceneEditChanges, SceneEditIntent, SceneEditLocator, SceneEditStatus,
    edit::materialize::unsupported_scene_format,
};

pub(super) struct CleanChanges {
    pub scene: SceneEditChanges,
    pub removed_script_nodes: Vec<String>,
    pub removed_plugin_requires: Vec<String>,
}

impl PatchPlanner {
    pub(super) fn apply_script_clean_in_path(
        &self,
        input_path: &Path,
    ) -> Result<(SceneFormat, Applied<CleanChanges>), SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let loader = Loader::new(self.options.load_options().clone());
        let observation = super::source::read_stable(input_path, || {
            let observation = loader.observe_script_owners_path(input_path)?;
            let stability = observation.source_read_stability();
            Ok((observation, stability))
        })?;
        let format = observation.scene_format();
        let bytes = observation.bytes();
        let script_origins = observation.origins();
        let mut scene = SceneEditChanges::default();
        let (output, removed_script_nodes) = if format == SceneFormat::Ma {
            let mut ranges = scripts::collect_script_node_ranges_from_ma(bytes, &[]);
            let names = script_origins
                .iter()
                .filter_map(|origin| origin.node_name.clone())
                .filter(|name| !ranges.iter().any(|(_, existing)| existing == name))
                .collect::<Vec<_>>();
            ranges.extend(
                rewrite::collect_named_node_owner_ranges_from_ma(bytes, &names)
                    .into_iter()
                    .filter(|(_, (node_type, _))| node_type != "script")
                    .map(|(range, (_, name))| (range, name)),
            );
            ranges.sort_by_key(|(range, _)| range.start);
            let mut edits = Vec::with_capacity(ranges.len());
            let mut names = Vec::with_capacity(ranges.len());
            for (range, name) in ranges {
                names.push(name.clone());
                edits.push(rewrite::MaByteEdit {
                    range: range.clone(),
                    bytes: Vec::new(),
                });
                scene.records.push(change(
                    &SceneEditIntent::Clean(ExecutionCleanTarget::ScriptNode { node_name: name }),
                    range_locator(&range),
                    bytes[range].to_vec(),
                    Vec::new(),
                ));
            }
            (rewrite::apply_ma_byte_edits(bytes, &mut edits), names)
        } else if format == SceneFormat::Mb {
            let mb = observation.binary().expect("binary script owner source");
            let (mut forms, mut names) =
                crate::mb::paths::locate_raw_script_node_forms_in_mb_by_name(
                    mb.data(),
                    mb.root(),
                    crate::mb::MbNameSelection::All,
                )
                .value;
            for origin in script_origins {
                if let (Some(form), Some(offset), Some(name)) = (
                    origin.chunk_form.clone(),
                    origin.chunk_node_offset,
                    origin.node_name.clone(),
                ) {
                    let locator = (form, offset);
                    if !forms.contains(&locator) {
                        forms.push(locator);
                        names.push(name);
                    }
                }
            }
            let (output, removed) =
                crate::mb::remove_root_forms_from_mb_by_locator(mb.data(), mb.root(), &forms)
                    .map_err(mb_rewrite_error)?;
            if forms.iter().any(|form| !removed.contains(form)) {
                return Err(SceneToolError::Message(
                    "requested script owner was not removed".into(),
                ));
            }
            for ((form, offset), name) in forms.into_iter().zip(names.iter().cloned()) {
                scene.records.push(binary_form_change(
                    mb.data(),
                    mb.root(),
                    &ExecutionCleanTarget::ScriptNode { node_name: name },
                    &form,
                    offset,
                )?);
            }
            (output, names)
        } else {
            return Err(unsupported_scene_format(input_path, format));
        };
        summarize(&mut scene);
        Ok((
            format,
            Applied {
                bytes: output,
                changes: CleanChanges {
                    scene,
                    removed_script_nodes,
                    removed_plugin_requires: Vec::new(),
                },
            },
        ))
    }

    pub(super) fn apply_execution_clean_in_path(
        &self,
        input_path: &Path,
        targets: &[ExecutionCleanTarget],
    ) -> Result<(SceneFormat, Applied<CleanChanges>), SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let (observation, bytes) =
            super::source::read_scene_edit_source(input_path, self.options.load_options())?;
        let format = observation.scene_format();
        let applied = apply_execution_clean(bytes, input_path, format, targets)?;
        Ok((format, applied))
    }

    pub(super) fn clean_preview_from_application(
        &self,
        input_path: &Path,
        scene_format: SceneFormat,
        applied: &Applied<CleanChanges>,
    ) -> ExecutionCleanPreview {
        ExecutionCleanPreview {
            input_path: input_path.to_path_buf(),
            scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: ValidationState::CopiedUnvalidated,
            cleaned_targets: cleaned_targets(&applied.changes.scene),
            removed_script_nodes: applied.changes.removed_script_nodes.clone(),
            removed_plugin_requires: applied.changes.removed_plugin_requires.clone(),
        }
    }

    pub(super) fn script_preview_from_application(
        &self,
        input_path: &Path,
        scene_format: SceneFormat,
        applied: &Applied<CleanChanges>,
    ) -> ScriptNodeCleanPreview {
        ScriptNodeCleanPreview {
            input_path: input_path.to_path_buf(),
            scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: ValidationState::CopiedUnvalidated,
            removed_nodes: applied.changes.removed_script_nodes.clone(),
        }
    }
}

fn missing_target(path: &Path, target: &ExecutionCleanTarget) -> SceneToolError {
    SceneToolError::Message(format!(
        "no matching execution clean target {target:?} found in {}",
        path.display()
    ))
}

fn ascii_clean_records(
    bytes: &[u8],
    path: &Path,
    targets: &[ExecutionCleanTarget],
) -> Result<Vec<SceneEditChange>, SceneToolError> {
    let mut records = Vec::new();
    for target in targets {
        let ranges = match target {
            ExecutionCleanTarget::ScriptNode { node_name } => {
                scripts::collect_script_node_ranges_from_ma(bytes, std::slice::from_ref(node_name))
                    .into_iter()
                    .map(|(range, _)| range)
                    .collect::<Vec<_>>()
            }
            ExecutionCleanTarget::PluginRequire { rendered } => {
                requires::collect_plugin_require_ranges_from_ma(
                    bytes,
                    std::slice::from_ref(rendered),
                )
                .into_iter()
                .map(|(range, _)| range)
                .collect()
            }
            ExecutionCleanTarget::TopLevelCommand { source_range } => {
                if !rewrite::ma_range_has_bytes(bytes, source_range.start, source_range.end) {
                    return Err(missing_target(path, target));
                }
                std::iter::once(source_range.start..source_range.end).collect()
            }
            ExecutionCleanTarget::FileCommandCallback { source_range } => {
                if !rewrite::ma_file_command_callback_present(
                    bytes,
                    source_range.start,
                    source_range.end,
                ) {
                    return Err(missing_target(path, target));
                }
                std::iter::once(source_range.start..source_range.end).collect()
            }
            _ => {
                return Err(unsupported_execution_clean_target(
                    path,
                    SceneFormat::Ma,
                    target,
                ));
            }
        };
        if ranges.is_empty() {
            return Err(missing_target(path, target));
        }
        for range in ranges {
            records.push(change(
                &SceneEditIntent::Clean(target.clone()),
                range_locator(&range),
                bytes[range].to_vec(),
                Vec::new(),
            ));
        }
    }
    Ok(records)
}

fn binary_form_change(
    bytes: &[u8],
    root: &crate::mb::Chunk,
    target: &ExecutionCleanTarget,
    form: &str,
    offset: usize,
) -> Result<SceneEditChange, SceneToolError> {
    let child = root
        .children()
        .iter()
        .find(|child| {
            child.offset() == offset && child.form_type().is_some_and(|value| value == form)
        })
        .ok_or_else(|| {
            SceneToolError::Message(format!(
                "requested original MB form does not exist: {form} at {offset}"
            ))
        })?;
    Ok(change(
        &SceneEditIntent::Clean(target.clone()),
        form_locator(form, offset),
        bytes[child.offset()..child.payload_end()].to_vec(),
        Vec::new(),
    ))
}

fn binary_clean_records(
    bytes: &[u8],
    root: &crate::mb::Chunk,
    path: &Path,
    targets: &[ExecutionCleanTarget],
) -> Result<Vec<SceneEditChange>, SceneToolError> {
    let mut records = Vec::new();
    for target in targets {
        match target {
            ExecutionCleanTarget::PluginRequire { rendered } => {
                let found = crate::mb::rewrite::collect_mb_plugin_require_records(
                    bytes,
                    root,
                    std::slice::from_ref(rendered),
                )
                .map_err(mb_rewrite_error)?;
                if found.is_empty() {
                    return Err(missing_target(path, target));
                }
                for (locator, before) in found {
                    records.push(change(
                        &SceneEditIntent::Clean(target.clone()),
                        record_locator(&locator),
                        before,
                        Vec::new(),
                    ));
                }
            }
            ExecutionCleanTarget::ScriptNode { .. } | ExecutionCleanTarget::MbOwnerForm { .. } => {
                let (forms, _) =
                    collect_mb_clean_targets(bytes, root, std::slice::from_ref(target))?;
                if forms.is_empty() {
                    return Err(missing_target(path, target));
                }
                for (form, offset) in forms {
                    records.push(binary_form_change(bytes, root, target, &form, offset)?);
                }
            }
            _ => {
                return Err(unsupported_execution_clean_target(
                    path,
                    SceneFormat::Mb,
                    target,
                ));
            }
        }
    }
    Ok(records)
}

fn mark_previously_consumed(record: &mut SceneEditChange) {
    record.status = SceneEditStatus::Covered;
    record.reason = "present in original source; consumed by preceding edits".into();
    record.after.clear();
}

fn reconcile_named_removals(records: &mut [SceneEditChange], removed: &[String], scripts: bool) {
    let mut remaining = std::collections::BTreeMap::<String, usize>::new();
    for name in removed {
        *remaining.entry(name.clone()).or_default() += 1;
    }
    for record in records {
        let name = match &record.intent {
            SceneEditIntent::Clean(ExecutionCleanTarget::ScriptNode { node_name }) if scripts => {
                node_name
            }
            SceneEditIntent::Clean(ExecutionCleanTarget::PluginRequire { rendered })
                if !scripts =>
            {
                rendered
            }
            _ => continue,
        };
        let count = remaining.entry(name.clone()).or_default();
        if record.status == SceneEditStatus::Applied && *count > 0 {
            *count -= 1;
        } else {
            mark_previously_consumed(record);
        }
    }
}

fn normalize_outcomes(records: &mut [SceneEditChange]) {
    let mut order = (0..records.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| match &records[*index].locator {
        SceneEditLocator::MaRange { start, end } => (*start, std::cmp::Reverse(*end)),
        SceneEditLocator::MbForm { node_offset, .. } => {
            (*node_offset, std::cmp::Reverse(usize::MAX))
        }
        SceneEditLocator::MbRecord {
            node_offset,
            chunk_start,
            ..
        } => (
            *node_offset,
            std::cmp::Reverse(usize::MAX - 1 - chunk_start),
        ),
        SceneEditLocator::Unresolved => (usize::MAX, std::cmp::Reverse(0)),
    });
    let mut kept: Vec<usize> = Vec::new();
    for index in order {
        if records[index].status != SceneEditStatus::Applied {
            continue;
        }
        let covering = kept.iter().find(|outer| {
            if matches!(
                records[**outer].intent,
                SceneEditIntent::Clean(ExecutionCleanTarget::FileCommandCallback { .. })
            ) {
                return false;
            }
            match (&records[**outer].locator, &records[index].locator) {
                (
                    SceneEditLocator::MaRange { start: a, end: b },
                    SceneEditLocator::MaRange { start: c, end: d },
                ) => a <= c && d <= b,
                (
                    SceneEditLocator::MbForm {
                        form: a,
                        node_offset: b,
                    },
                    SceneEditLocator::MbForm {
                        form: c,
                        node_offset: d,
                    }
                    | SceneEditLocator::MbRecord {
                        form: c,
                        node_offset: d,
                        ..
                    },
                ) => a == c && b == d,
                (a, b) => a == b,
            }
        });
        if let Some(outer) = covering {
            let locator = records[*outer].locator.clone();
            absorbed(&mut records[index], &locator, true);
        } else {
            kept.push(index);
        }
    }
}

fn apply_execution_clean(
    bytes: Vec<u8>,
    path: &Path,
    format: SceneFormat,
    requested: &[ExecutionCleanTarget],
) -> Result<Applied<CleanChanges>, SceneToolError> {
    let targets = normalize_execution_clean_targets(requested)?;
    let (output, mut records, mut removed_script_nodes, mut removed_plugin_requires) = if format
        == SceneFormat::Ma
    {
        let mut records = ascii_clean_records(&bytes, path, &targets)?;
        let edits = targets.iter().filter_map(ma_range_edit).collect::<Vec<_>>();
        let normalized =
            rewrite::normalize_ma_range_edits(bytes.len(), &edits).map_err(ma_range_edit_error)?;
        let mut range_edits = Vec::new();
        for edit in &normalized {
            let (replacement, count) = rewrite::apply_ma_range_edits(
                &bytes[edit.start..edit.end],
                &[rewrite::MaRangeEdit {
                    start: 0,
                    end: edit.end - edit.start,
                    kind: edit.kind,
                }],
            )
            .map_err(ma_range_edit_error)?;
            if count != 1 {
                return Err(SceneToolError::Message(
                    "requested MA range was not applied".into(),
                ));
            }
            range_edits.push(rewrite::MaByteEdit {
                range: edit.start..edit.end,
                bytes: replacement,
            });
        }
        let mut output = rewrite::apply_ma_byte_edits(&bytes, &mut range_edits);
        for record in &mut records {
            if let SceneEditIntent::Clean(target) = &record.intent {
                if let Some(edit) = ma_range_edit(target) {
                    if !normalized.contains(&edit) {
                        let outer = normalized
                            .iter()
                            .find(|outer| outer.start <= edit.start && edit.end <= outer.end)
                            .expect("normalized range coverage");
                        absorbed(record, &range_locator(&(outer.start..outer.end)), true);
                    } else {
                        record.after.clone_from(
                            &range_edits
                                .iter()
                                .find(|applied| applied.range == (edit.start..edit.end))
                                .expect("applied range")
                                .bytes,
                        );
                    }
                } else if let SceneEditLocator::MaRange { start, .. } = record.locator {
                    if let Some(outer) = normalized.iter().find(|outer| {
                        outer.kind == rewrite::MaRangeEditKind::RemoveCommand
                            && outer.start <= start
                            && start < outer.end
                    }) {
                        absorbed(record, &range_locator(&(outer.start..outer.end)), true);
                    }
                }
            }
        }
        let scripts = targets
            .iter()
            .filter_map(|target| match target {
                ExecutionCleanTarget::ScriptNode { node_name } => Some(node_name.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let removed_scripts = if scripts.is_empty() {
            Vec::new()
        } else {
            let (rewritten, removed) =
                scripts::remove_raw_script_nodes_from_ma_by_name(&output, &scripts);
            output = rewritten;
            removed
        };
        reconcile_named_removals(&mut records, &removed_scripts, true);
        let requires = targets
            .iter()
            .filter_map(|target| match target {
                ExecutionCleanTarget::PluginRequire { rendered } => Some(rendered.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let removed_requires = if requires.is_empty() {
            Vec::new()
        } else {
            let (rewritten, removed) = requires::remove_plugin_requires_from_ma(&output, &requires);
            output = rewritten;
            removed
        };
        reconcile_named_removals(&mut records, &removed_requires, false);
        (output, records, removed_scripts, removed_requires)
    } else if format == SceneFormat::Mb {
        let mb = crate::mb::parse_bytes(bytes)?;
        crate::mb::rewrite::require_complete_mb_sections(mb.data(), mb.root())
            .map_err(mb_rewrite_error)?;
        let mut records = binary_clean_records(mb.data(), mb.root(), path, &targets)?;
        let forms = records
            .iter()
            .filter_map(|record| match &record.locator {
                SceneEditLocator::MbForm { form, node_offset } => {
                    Some((form.clone(), *node_offset))
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let requires = targets
            .iter()
            .filter_map(|target| match target {
                ExecutionCleanTarget::PluginRequire { rendered } => Some(rendered.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let (output, removed_forms, removed_requires) =
            crate::mb::remove_root_forms_and_plugin_requires_from_mb(
                mb.data(),
                mb.root(),
                &forms,
                crate::mb::MbNameSelection::Only(&requires),
            )
            .map_err(mb_rewrite_error)?;
        if forms.iter().any(|form| !removed_forms.contains(form)) {
            return Err(SceneToolError::Message(
                "requested MB form was not removed".into(),
            ));
        }
        let mut removed_scripts = Vec::new();
        for record in &mut records {
            if let SceneEditLocator::MbRecord {
                form, node_offset, ..
            } = &record.locator
            {
                if removed_forms.contains(&(form.clone(), *node_offset)) {
                    let outer = form_locator(form, *node_offset);
                    absorbed(record, &outer, true);
                }
            }
            if let SceneEditIntent::Clean(ExecutionCleanTarget::ScriptNode { node_name }) =
                &record.intent
            {
                removed_scripts.push(node_name.clone());
            }
        }
        (output, records, removed_scripts, removed_requires)
    } else {
        return Err(unsupported_scene_format(path, format));
    };
    normalize_outcomes(&mut records);
    if format == SceneFormat::Mb {
        removed_script_nodes = records
            .iter()
            .filter_map(|record| {
                if record.status != SceneEditStatus::Applied {
                    return None;
                }
                match &record.intent {
                    SceneEditIntent::Clean(ExecutionCleanTarget::ScriptNode { node_name }) => {
                        Some(node_name.clone())
                    }
                    _ => None,
                }
            })
            .collect();
    }
    let mut seen = BTreeSet::new();
    for target in requested {
        let normalized = normalized_target(target);
        if normalized
            .as_ref()
            .is_none_or(|target| !seen.insert(target.clone()))
        {
            records.push(normalized_away(SceneEditIntent::Clean(target.clone())));
        }
    }
    removed_script_nodes.sort();
    removed_plugin_requires.sort();
    let mut scene = SceneEditChanges {
        records,
        ..Default::default()
    };
    summarize(&mut scene);
    Ok(Applied {
        bytes: output,
        changes: CleanChanges {
            scene,
            removed_script_nodes,
            removed_plugin_requires,
        },
    })
}

fn normalized_target(target: &ExecutionCleanTarget) -> Option<ExecutionCleanTarget> {
    match target {
        ExecutionCleanTarget::ScriptNode { node_name } => {
            let node_name = node_name.trim();
            (!node_name.is_empty()).then(|| ExecutionCleanTarget::ScriptNode {
                node_name: node_name.to_string(),
            })
        }
        ExecutionCleanTarget::PluginRequire { rendered } => {
            let rendered = rendered.trim();
            (!rendered.is_empty()).then(|| ExecutionCleanTarget::PluginRequire {
                rendered: rendered.to_string(),
            })
        }
        ExecutionCleanTarget::TopLevelCommand { source_range } => valid_execution_source_range(
            source_range,
        )
        .then_some(ExecutionCleanTarget::TopLevelCommand {
            source_range: *source_range,
        }),
        ExecutionCleanTarget::FileCommandCallback { source_range } => valid_execution_source_range(
            source_range,
        )
        .then_some(ExecutionCleanTarget::FileCommandCallback {
            source_range: *source_range,
        }),
        ExecutionCleanTarget::MbOwnerForm { form, node_offset } => {
            let form = form.trim();
            (!form.is_empty()).then(|| ExecutionCleanTarget::MbOwnerForm {
                form: form.to_string(),
                node_offset: *node_offset,
            })
        }
    }
}

pub(super) fn normalize_execution_clean_targets(
    targets: &[ExecutionCleanTarget],
) -> Result<Vec<ExecutionCleanTarget>, SceneToolError> {
    if targets.is_empty() {
        return Err(SceneToolError::Message(
            "execution clean requires at least one valid target".into(),
        ));
    }
    let normalized = targets
        .iter()
        .filter_map(normalized_target)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    Ok(normalized)
}

fn valid_execution_source_range(source_range: &ExecutionSourceRange) -> bool {
    source_range.start < source_range.end
}

pub(super) fn unsupported_execution_clean_target(
    path: &Path,
    detected: SceneFormat,
    target: &ExecutionCleanTarget,
) -> SceneToolError {
    SceneToolError::Message(format!(
        "execution clean target {target:?} is unsupported for {detected:?} scene {}",
        path.display()
    ))
}

pub(super) fn ma_range_edit(target: &ExecutionCleanTarget) -> Option<rewrite::MaRangeEdit> {
    let (source_range, kind) = match target {
        ExecutionCleanTarget::TopLevelCommand { source_range } => {
            (source_range, rewrite::MaRangeEditKind::RemoveCommand)
        }
        ExecutionCleanTarget::FileCommandCallback { source_range } => (
            source_range,
            rewrite::MaRangeEditKind::StripFileCommandCallback,
        ),
        _ => return None,
    };
    Some(rewrite::MaRangeEdit {
        start: source_range.start,
        end: source_range.end,
        kind,
    })
}

pub(super) fn ma_range_edit_error(error: rewrite::MaRangeEditError) -> SceneToolError {
    SceneToolError::Message(match error {
        rewrite::MaRangeEditError::Overlap { first, second } => format!(
            "execution clean ranges overlap: {}..{} and {}..{}",
            first.start, first.end, second.start, second.end
        ),
        rewrite::MaRangeEditError::CallbackParse(error) => error.to_string(),
    })
}

type MbCleanTargets = (Vec<(String, usize)>, Vec<String>);

pub(super) fn collect_mb_clean_targets(
    data: &[u8],
    root: &crate::mb::Chunk,
    targets: &[ExecutionCleanTarget],
) -> Result<MbCleanTargets, SceneToolError> {
    crate::mb::rewrite::require_complete_mb_sections(data, root).map_err(mb_rewrite_error)?;
    let script_nodes = targets
        .iter()
        .filter_map(|target| match target {
            ExecutionCleanTarget::ScriptNode { node_name } => Some(node_name.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut owner_form_targets = if script_nodes.is_empty() {
        Vec::new()
    } else {
        crate::mb::paths::locate_raw_script_node_forms_in_mb_by_name(
            data,
            root,
            crate::mb::MbNameSelection::Only(&script_nodes),
        )
        .value
        .0
    };
    owner_form_targets.extend(targets.iter().filter_map(|target| match target {
        ExecutionCleanTarget::MbOwnerForm { form, node_offset } => {
            Some((form.clone(), *node_offset))
        }
        _ => None,
    }));
    let owner_form_targets = owner_form_targets
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let plugin_requires = targets
        .iter()
        .filter_map(|target| match target {
            ExecutionCleanTarget::PluginRequire { rendered } => Some(rendered.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    Ok((owner_form_targets, plugin_requires))
}

pub(super) fn mb_rewrite_error(error: crate::mb::MbRewriteError) -> SceneToolError {
    SceneToolError::Message(error.to_string())
}
