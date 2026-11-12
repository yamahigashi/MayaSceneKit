use std::{collections::BTreeMap, ops::Range};

use maya_scene_kit_formats::mb::rewrite as binary;
use sha2::{Digest, Sha256};

use super::{
    application::{
        Applied, absorbed, change, cleaned_targets, deleted_owners, form_locator, path_skip_counts,
        range_locator, record_locator, summarize,
    },
    *,
};
use crate::scene::{
    SceneEditChanges, SceneEditError, SceneEditIntent, SceneEditLocator, SceneEditPlan,
    SceneEditStatus,
};

impl PatchPlanner {
    pub fn stage_scene_edit_plan(
        &self,
        plan: &SceneEditPlan,
        bytes: &[u8],
    ) -> Result<CompositeSceneEditsStageResult, SceneEditError> {
        let Applied {
            bytes: output,
            changes,
        } = self.apply_scene_edit_plan(plan, bytes)?;
        let cleaned_targets = cleaned_targets(&changes);
        let deleted_path_owner_targets = deleted_owners(&changes);
        let preview = CompositeSceneEditsPreview {
            input_path: plan.report.scene_path.clone(),
            scene_format: plan.report.scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: if plan.report.scene_format == SceneFormat::Ma {
                ValidationState::CopiedUnvalidated
            } else {
                plan.report.validation_state
            },
            removed_script_nodes: cleaned_targets
                .iter()
                .filter_map(|target| match target {
                    ExecutionCleanTarget::ScriptNode { node_name } => Some(node_name.clone()),
                    _ => None,
                })
                .collect(),
            removed_plugin_requires: cleaned_targets
                .iter()
                .filter_map(|target| match target {
                    ExecutionCleanTarget::PluginRequire { rendered } => Some(rendered.clone()),
                    _ => None,
                })
                .collect(),
            cleaned_targets,
            deleted_path_owner_targets,
        };
        let suffix = match (
            preview.has_clean_targets(),
            preview.has_deleted_path_owner_targets(),
            changes.path_replacements.replacement_count > 0,
        ) {
            (true, false, false) => "_clean",
            (false, true, false) => "_node-removed",
            _ => "_edited",
        };
        let artifact = StagedSceneArtifact {
            input_path: preview.input_path.clone(),
            suggested_output_path: super::replace_rules::suggested_path_output(
                &preview.input_path,
                suffix,
                None,
            ),
            scene_format: preview.scene_format,
            operation_mode: preview.operation_mode,
            validation_state: preview.validation_state,
            bytes: output,
        };
        Ok(CompositeSceneEditsStageResult {
            preview,
            artifact,
            changes,
        })
    }

    fn apply_scene_edit_plan(
        &self,
        plan: &SceneEditPlan,
        bytes: &[u8],
    ) -> Result<Applied<SceneEditChanges>, SceneEditError> {
        let mb = if plan.report.scene_format == SceneFormat::Mb {
            let mb = crate::mb::parse_bytes(bytes.to_vec()).map_err(SceneToolError::from)?;
            binary::require_complete_mb_sections(mb.data(), mb.root())
                .map_err(binary::MbPlanError::from)?;
            Some(mb)
        } else {
            None
        };
        validate_source(plan, bytes)?;
        self.options.reject_if_not_forensic()?;
        let mut intents = plan.intents.clone();
        intents.sort();
        validate_overrides(&plan.report, &intents)?;
        let (output, mut changes) = match plan.report.scene_format {
            SceneFormat::Ma => apply_ascii(plan, bytes, &intents, self.options.load_options())?,
            SceneFormat::Mb => apply_binary(plan, bytes, mb.as_ref().unwrap().root(), &intents)?,
            other => {
                return Err(super::materialize::unsupported_scene_format(
                    &plan.report.scene_path,
                    other,
                )
                .into());
            }
        };
        if output == bytes {
            return Err(SceneEditError::NoEffectiveEdits {
                skipped: changes
                    .records
                    .into_iter()
                    .filter(|record| record.status == SceneEditStatus::Skipped)
                    .collect(),
            });
        }
        summarize(&mut changes);
        Ok(Applied {
            bytes: output,
            changes,
        })
    }

    pub fn stage_scene_edits(
        &self,
        input_path: impl AsRef<Path>,
        clean_source: Option<&maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>,
        clean_targets: &[ExecutionCleanTarget],
        owners: &[PathOwnerDeleteTarget],
    ) -> Result<CompositeSceneEditsStageResult, SceneEditError> {
        let (observation, bytes) = super::source::read_scene_edit_source(
            input_path.as_ref(),
            self.options.load_options(),
        )?;
        let plan = SceneEditPlan {
            report: observation.scene_paths_report(PathKind::All)?,
            clean_source: clean_source.cloned(),
            intents: clean_targets
                .iter()
                .cloned()
                .map(SceneEditIntent::Clean)
                .chain(owners.iter().cloned().map(SceneEditIntent::DeleteOwner))
                .collect(),
        };
        self.stage_scene_edit_plan(&plan, &bytes)
    }
}

fn invalid(reason: impl Into<String>) -> SceneEditError {
    SceneEditError::InvalidTarget {
        reason: reason.into(),
    }
}

fn validate_source(plan: &SceneEditPlan, bytes: &[u8]) -> Result<(), SceneEditError> {
    let source = plan
        .report
        .source
        .as_ref()
        .ok_or(SceneEditError::MissingSource {
            source_kind: "path",
        })?;
    if source.sha256.is_empty() {
        return Err(SceneEditError::MissingSource {
            source_kind: "path",
        });
    }
    if source.byte_len != bytes.len() {
        return Err(SceneEditError::SourceLengthMismatch {
            expected: source.byte_len,
            actual: bytes.len(),
        });
    }
    let digest = format!("{:x}", Sha256::digest(bytes));
    if source.sha256 != digest {
        return Err(SceneEditError::SourceMismatch {
            source_kind: "path",
        });
    }
    if plan
        .intents
        .iter()
        .any(|intent| matches!(intent, SceneEditIntent::Clean(_)))
    {
        let clean = plan
            .clean_source
            .as_ref()
            .filter(|source| !source.sha256.is_empty())
            .ok_or(SceneEditError::MissingSource {
                source_kind: "clean",
            })?;
        if clean.byte_len != bytes.len() {
            return Err(SceneEditError::SourceLengthMismatch {
                expected: clean.byte_len,
                actual: bytes.len(),
            });
        }
        if clean.sha256 != digest {
            return Err(SceneEditError::SourceMismatch {
                source_kind: "clean",
            });
        }
    }
    if plan.report.kind != Some(PathKind::All) {
        return Err(SceneEditError::FilteredReport);
    }
    Ok(())
}

fn validate_overrides(
    report: &ScenePathsReport,
    intents: &[SceneEditIntent],
) -> Result<(), SceneEditError> {
    let mut seen = BTreeSet::new();
    for intent in intents {
        if let SceneEditIntent::Path(value) = intent {
            if !seen.insert(value.entry_index) {
                return Err(SceneEditError::DuplicateOverride {
                    entry_index: value.entry_index,
                });
            }
            let entry = report
                .entries
                .get(value.entry_index)
                .ok_or_else(|| invalid("path entry index is out of range"))?;
            if entry.value != value.before_value {
                return Err(invalid("path before_value does not match the report"));
            }
        }
    }
    Ok(())
}

fn path_overrides(intents: &[SceneEditIntent]) -> BTreeMap<usize, &PathReplaceOverride> {
    intents
        .iter()
        .filter_map(|intent| match intent {
            SceneEditIntent::Path(value) => Some((value.entry_index, value)),
            _ => None,
        })
        .collect()
}

fn contains(outer: &Range<usize>, inner: &Range<usize>) -> bool {
    outer.start <= inner.start
        && inner.end <= outer.end
        && (inner.start != inner.end || inner.start < outer.end)
}
fn intersects(a: &Range<usize>, b: &Range<usize>) -> bool {
    if a.is_empty() {
        return contains(b, a);
    }
    if b.is_empty() {
        return contains(a, b);
    }
    a.start < b.end && b.start < a.end
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AsciiKind {
    Delete,
    Callback,
}
struct AsciiEdit {
    range: Range<usize>,
    kind: AsciiKind,
    records: Vec<usize>,
    bytes: Vec<u8>,
}

fn push_ascii(
    edits: &mut Vec<AsciiEdit>,
    changes: &mut SceneEditChanges,
    source: &[u8],
    intent: &SceneEditIntent,
    range: Range<usize>,
    kind: AsciiKind,
    commands: Option<&rewrite::MaCommandRanges>,
) -> Result<(), SceneEditError> {
    let before = source
        .get(range.clone())
        .filter(|_| !range.is_empty())
        .ok_or_else(|| invalid("invalid original MA range"))?;
    if !before.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(invalid("MA target has no source bytes"));
    }
    if matches!(
        intent,
        SceneEditIntent::Clean(
            ExecutionCleanTarget::TopLevelCommand { .. }
                | ExecutionCleanTarget::FileCommandCallback { .. }
        )
    ) && !commands.is_some_and(|commands| commands.contains(source, range.clone()))
    {
        return Err(invalid("MA target must identify a whole original command"));
    }
    if kind == AsciiKind::Callback
        && !commands
            .and_then(|commands| commands.file_command_without_callback(before))
            .is_some_and(|(_, changed)| changed)
    {
        return Err(invalid("file callback does not match the original command"));
    }
    let record = changes.records.len();
    changes.records.push(change(
        intent,
        range_locator(&range),
        before.to_vec(),
        Vec::new(),
    ));
    edits.push(AsciiEdit {
        range,
        kind,
        records: vec![record],
        bytes: Vec::new(),
    });
    Ok(())
}

fn normalize_ascii(
    mut edits: Vec<AsciiEdit>,
    changes: &mut SceneEditChanges,
) -> Result<Vec<AsciiEdit>, SceneEditError> {
    edits.sort_by_key(|edit| {
        (
            edit.range.start,
            std::cmp::Reverse(edit.range.end),
            edit.kind != AsciiKind::Delete,
        )
    });
    let mut kept: Vec<AsciiEdit> = Vec::new();
    for edit in edits {
        if let Some(outer) = kept
            .iter_mut()
            .find(|outer| intersects(&outer.range, &edit.range))
        {
            if outer.range == edit.range && outer.kind == edit.kind {
                outer.records.extend(edit.records);
            } else if outer.kind == AsciiKind::Delete && contains(&outer.range, &edit.range) {
                for index in edit.records {
                    absorbed(
                        &mut changes.records[index],
                        &range_locator(&outer.range),
                        edit.kind == AsciiKind::Delete,
                    );
                }
            } else {
                return Err(SceneEditError::Overlap {
                    first: range_locator(&outer.range),
                    second: range_locator(&edit.range),
                });
            }
        } else {
            kept.push(edit);
        }
    }
    Ok(kept)
}

fn apply_ascii(
    plan: &SceneEditPlan,
    bytes: &[u8],
    intents: &[SceneEditIntent],
    load_options: &LoadOptions,
) -> Result<(Vec<u8>, SceneEditChanges), SceneEditError> {
    let mut changes = SceneEditChanges::default();
    changes.path_replacements.skipped = Some(Box::default());
    let mut edits = Vec::new();
    let commands = intents
        .iter()
        .any(|intent| {
            matches!(
                intent,
                SceneEditIntent::Clean(
                    ExecutionCleanTarget::TopLevelCommand { .. }
                        | ExecutionCleanTarget::FileCommandCallback { .. }
                )
            )
        })
        .then(|| rewrite::collect_ma_command_ranges(bytes));
    let mut script_owners = if intents.iter().any(|intent| {
        matches!(
            intent,
            SceneEditIntent::Clean(ExecutionCleanTarget::ScriptNode { .. })
        )
    }) {
        super::clean::collect_script_owner_ranges_from_ma(bytes, std::iter::empty())
    } else {
        Vec::new()
    };
    if intents.iter().any(|intent| {
        matches!(intent, SceneEditIntent::Clean(ExecutionCleanTarget::ScriptNode { node_name })
            if !node_name.trim().is_empty() && !script_owners.iter().any(|(_, name)| name == node_name))
    }) {
        let observation = maya_scene_kit_observe::scene::Loader::new(load_options.clone())
            .observe_execution_bytes(
                &plan.report.scene_path,
                SceneFormat::Ma,
                plan.report.validation_state,
                bytes.to_vec(),
            )?;
        let catalog = observation.observed_execution_catalog_with_digests(0, false)?;
        script_owners = super::clean::collect_script_owner_ranges_from_ma(
            bytes,
            catalog.surfaces.iter().filter_map(|surface| {
                let origin = &surface.surface.origin;
                (origin.surface_kind == maya_scene_kit_observe::scene::evidence::ExecutionSurfaceKind::ScriptNodeBody)
                    .then_some(origin.node_name.as_deref())
                    .flatten()
            }),
        );
    }
    let mut owner_locations = BTreeMap::<PathOwnerDeleteTarget, Vec<Range<usize>>>::new();
    for intent in intents {
        match intent {
            SceneEditIntent::Path(_) => {}
            SceneEditIntent::Clean(target) => {
                let ranges = match target {
                    ExecutionCleanTarget::TopLevelCommand { source_range }
                    | ExecutionCleanTarget::FileCommandCallback { source_range } => {
                        std::iter::once(source_range.start..source_range.end).collect::<Vec<_>>()
                    }
                    ExecutionCleanTarget::ScriptNode { node_name } => {
                        if node_name.trim().is_empty() {
                            return Err(invalid("empty script node target"));
                        }
                        script_owners
                            .iter()
                            .filter(|(_, name)| name == node_name)
                            .map(|(range, _)| range.clone())
                            .collect()
                    }
                    ExecutionCleanTarget::PluginRequire { rendered } => {
                        if rendered.trim().is_empty() {
                            return Err(invalid("empty requires target"));
                        }
                        requires::collect_plugin_require_ranges_from_ma(
                            bytes,
                            std::slice::from_ref(rendered),
                        )
                        .into_iter()
                        .map(|(range, _)| range)
                        .collect()
                    }
                    _ => return Err(invalid("MB form target supplied for MA")),
                };
                if ranges.is_empty() {
                    return Err(invalid(format!(
                        "requested deletion was not found: {target:?}"
                    )));
                }
                let kind = if matches!(target, ExecutionCleanTarget::FileCommandCallback { .. }) {
                    AsciiKind::Callback
                } else {
                    AsciiKind::Delete
                };
                for range in ranges {
                    push_ascii(
                        &mut edits,
                        &mut changes,
                        bytes,
                        intent,
                        range,
                        kind,
                        commands.as_ref(),
                    )?;
                }
            }
            SceneEditIntent::DeleteOwner(owner) => {
                let targets = [(owner.node_type.clone(), owner.node_name.clone())];
                let ranges = rewrite::collect_path_owner_ranges_from_ma(bytes, &targets);
                if ranges.is_empty() {
                    return Err(invalid(format!("requested owner was not found: {owner:?}")));
                }
                for (range, _) in ranges {
                    owner_locations
                        .entry(owner.clone())
                        .or_default()
                        .push(range.clone());
                    push_ascii(
                        &mut edits,
                        &mut changes,
                        bytes,
                        intent,
                        range,
                        AsciiKind::Delete,
                        commands.as_ref(),
                    )?;
                }
            }
        }
    }
    let mut edits = normalize_ascii(edits, &mut changes)?;
    let overrides = path_overrides(intents);
    let candidates =
        rewrite::collect_ma_path_candidates(bytes, &overrides.keys().copied().collect::<Vec<_>>())?;
    **changes.path_replacements.skipped.as_mut().unwrap() = candidates.skipped;
    let mut path_edits = Vec::new();
    for candidate in candidates.candidates {
        let value = overrides[&candidate.entry_index];
        let entry = &plan.report.entries[candidate.entry_index];
        if candidate.entry().node_name != entry.node_name
            || candidate.entry().node_type != entry.node_type
            || candidate.entry().attr != entry.attr
            || candidate.entry().value != entry.value
        {
            return Err(invalid(
                "path report does not identify the original MA value",
            ));
        }
        let owner = PathOwnerDeleteTarget {
            node_type: entry.node_type.clone(),
            node_name: entry.node_name.clone(),
        };
        let mut deletions = Vec::new();
        for range in candidate.ranges() {
            let owner_deletion = owner_locations
                .get(&owner)
                .and_then(|ranges| ranges.iter().find(|deleted| contains(deleted, range)));
            let mut deletion = owner_deletion.map(range_locator);
            for edit in edits.iter().filter(|_| owner_deletion.is_none()) {
                if !intersects(&edit.range, range) {
                    continue;
                }
                if !contains(&edit.range, range) {
                    return Err(SceneEditError::Overlap {
                        first: range_locator(&edit.range),
                        second: range_locator(range),
                    });
                }
                if edit.kind == AsciiKind::Delete {
                    deletion = Some(range_locator(&edit.range));
                }
            }
            deletions.push(deletion);
        }
        let intent = SceneEditIntent::Path(value.clone());
        if deletions.iter().all(Option::is_some) {
            for (range, deletion) in candidate.ranges().iter().zip(deletions) {
                let mut record = change(
                    &intent,
                    range_locator(range),
                    bytes[range.clone()].to_vec(),
                    Vec::new(),
                );
                absorbed(&mut record, &deletion.unwrap(), false);
                changes.records.push(record);
            }
            continue;
        }
        let excluded = candidate
            .ranges()
            .iter()
            .zip(&deletions)
            .filter_map(|(range, deletion)| deletion.as_ref().map(|_| range.clone()))
            .collect::<Vec<_>>();
        let applied = rewrite::plan_ma_path_value(bytes, &candidate, &value.after_value, &excluded);
        add_skips(
            changes.path_replacements.skipped.as_mut().unwrap(),
            &applied.skipped,
        );
        for (range, deletion) in candidate.ranges().iter().zip(deletions) {
            let replacement = applied.edits.iter().find(|edit| edit.range == *range);
            let mut record = change(
                &intent,
                range_locator(range),
                bytes[range.clone()].to_vec(),
                replacement
                    .map_or_else(|| bytes[range.clone()].to_vec(), |edit| edit.bytes.clone()),
            );
            if let Some(deletion) = deletion {
                absorbed(&mut record, &deletion, false);
            } else if let Some(replacement) = replacement {
                path_edits.push(replacement.clone());
            } else {
                let skipped = applied
                    .skipped_ranges
                    .iter()
                    .find(|skip| skip.range == *range);
                record.status = if skipped.is_some() {
                    SceneEditStatus::Skipped
                } else {
                    SceneEditStatus::Unchanged
                };
                record.reason = if let Some(skipped) = skipped {
                    record.path_skips = path_skip_counts(&skipped.skipped);
                    format!("path encoding or literal boundary: {:?}", skipped.skipped)
                } else {
                    "value unchanged".into()
                };
            }
            changes.records.push(record);
        }
    }
    for edit in &mut edits {
        if edit.kind != AsciiKind::Callback {
            continue;
        }
        let mut local = path_edits
            .iter()
            .filter(|path| contains(&edit.range, &path.range))
            .map(|path| rewrite::MaByteEdit {
                range: path.range.start - edit.range.start..path.range.end - edit.range.start,
                bytes: path.bytes.clone(),
            })
            .collect::<Vec<_>>();
        path_edits.retain(|path| !contains(&edit.range, &path.range));
        let command = rewrite::apply_ma_byte_edits(&bytes[edit.range.clone()], &mut local);
        let (rewritten, changed) = commands
            .as_ref()
            .and_then(|commands| commands.file_command_without_callback(&command))
            .ok_or_else(|| invalid("callback command did not resolve"))?;
        if !changed {
            return Err(invalid("callback removal was not applied"));
        }
        edit.bytes = rewritten;
        for &record in &edit.records {
            changes.records[record].after.clone_from(&edit.bytes);
        }
    }
    changes.physical_deletion_count = edits
        .iter()
        .filter(|edit| edit.kind == AsciiKind::Delete)
        .count();
    path_edits.extend(edits.into_iter().map(|edit| rewrite::MaByteEdit {
        range: edit.range,
        bytes: edit.bytes,
    }));
    if path_edits.is_empty() {
        return Err(SceneEditError::NoEffectiveEdits {
            skipped: changes
                .records
                .into_iter()
                .filter(|record| record.status == SceneEditStatus::Skipped)
                .collect(),
        });
    }
    Ok((
        rewrite::apply_ma_byte_edits(bytes, &mut path_edits),
        changes,
    ))
}

fn add_skips(
    to: &mut maya_scene_kit_formats::PathReplaceSkips,
    from: &maya_scene_kit_formats::PathReplaceSkips,
) {
    to.non_utf8 += from.non_utf8;
    to.non_canonical_escape += from.non_canonical_escape;
    to.unrepresentable += from.unrepresentable;
    to.crosses_concat_boundary += from.crosses_concat_boundary;
}

fn apply_binary(
    plan: &SceneEditPlan,
    bytes: &[u8],
    root: &crate::mb::Chunk,
    intents: &[SceneEditIntent],
) -> Result<(Vec<u8>, SceneEditChanges), SceneEditError> {
    let mut changes = SceneEditChanges::default();
    changes.path_replacements.skipped =
        Some(Box::new(maya_scene_kit_formats::PathReplaceSkips::binary()));
    let mut physical = binary::MbOriginalEdits::default();
    for intent in intents {
        let forms = match intent {
            SceneEditIntent::Clean(ExecutionCleanTarget::PluginRequire { rendered }) => {
                if rendered.trim().is_empty() {
                    return Err(invalid("empty requires target"));
                }
                let records = binary::collect_mb_plugin_require_records(
                    bytes,
                    root,
                    std::slice::from_ref(rendered),
                )
                .map_err(binary::MbPlanError::from)?;
                if records.is_empty() {
                    return Err(invalid(format!(
                        "requested require was not found: {rendered}"
                    )));
                }
                for (locator, before) in records {
                    changes.records.push(change(
                        intent,
                        record_locator(&locator),
                        before,
                        Vec::new(),
                    ));
                    physical.removed_records.push(locator);
                }
                continue;
            }
            SceneEditIntent::Clean(target) => {
                if !matches!(
                    target,
                    ExecutionCleanTarget::ScriptNode { .. }
                        | ExecutionCleanTarget::MbOwnerForm { .. }
                ) {
                    return Err(invalid("MA target supplied for MB"));
                }
                super::clean::collect_mb_clean_targets(bytes, root, std::slice::from_ref(target))?.0
            }
            SceneEditIntent::DeleteOwner(owner) => {
                let requested = super::path_owner_delete::resolve_mb_path_owner_forms(
                    &plan.report,
                    std::slice::from_ref(owner),
                );
                let actual = binary::locate_mb_path_owner_forms(
                    bytes,
                    root,
                    &owner.node_type,
                    &owner.node_name,
                )?;
                if requested.iter().any(|form| !actual.contains(form)) {
                    return Err(invalid(
                        "MB owner locator does not match the original owner",
                    ));
                }
                requested
            }
            SceneEditIntent::Path(_) => continue,
        };
        if forms.is_empty() {
            return Err(invalid(format!(
                "requested deletion was not found: {intent:?}"
            )));
        }
        for (form, offset) in forms {
            let child = root
                .children()
                .iter()
                .find(|child| {
                    child.offset() == offset
                        && child
                            .form_type()
                            .is_some_and(|value| value == form.as_str())
                })
                .ok_or_else(|| invalid("requested original MB form does not exist"))?;
            changes.records.push(change(
                intent,
                form_locator(&form, offset),
                bytes[child.offset()..child.payload_end()].to_vec(),
                Vec::new(),
            ));
            physical.removed_forms.push((form, offset));
        }
    }
    physical.removed_forms.sort();
    physical.removed_forms.dedup();
    for record in &mut changes.records {
        if let SceneEditLocator::MbRecord {
            form, node_offset, ..
        } = &record.locator
            && physical
                .removed_forms
                .contains(&(form.clone(), *node_offset))
        {
            absorbed(record, &form_locator(form, *node_offset), true);
        }
    }
    physical.removed_records.retain(|record| {
        !physical
            .removed_forms
            .contains(&(record.form.clone(), record.node_offset))
    });
    physical.removed_records.sort();
    physical.removed_records.dedup();
    let overrides = path_overrides(intents);
    if !overrides.is_empty() {
        let candidates = binary::collect_mb_path_candidates(
            bytes,
            root,
            &overrides.keys().copied().collect::<Vec<_>>(),
        )?;
        for candidate in candidates {
            let value = overrides[&candidate.entry_index];
            let entry = &plan.report.entries[candidate.entry_index];
            if candidate.entry.node_name != entry.node_name
                || candidate.entry.node_type != entry.node_type
                || candidate.entry.attr != entry.attr
                || candidate.entry.value != entry.value
            {
                return Err(invalid(
                    "path report does not identify the original MB value",
                ));
            }
            let intent = SceneEditIntent::Path(value.clone());
            let mut record = change(
                &intent,
                record_locator(&candidate.locator),
                candidate.before.clone(),
                candidate.before.clone(),
            );
            if physical.removed_forms.contains(&(
                candidate.locator.form.clone(),
                candidate.locator.node_offset,
            )) {
                absorbed(
                    &mut record,
                    &form_locator(&candidate.locator.form, candidate.locator.node_offset),
                    false,
                );
            } else {
                let (edit, status) =
                    binary::plan_mb_path_value(bytes, root, &candidate, &value.after_value)?;
                if let Some(edit) = edit {
                    record.after.clone_from(&edit.bytes);
                    physical.rewritten_records.push(edit);
                } else if status == binary::MbPathStatus::Unchanged {
                    record.status = SceneEditStatus::Unchanged;
                    record.reason = "payload unchanged".into();
                } else {
                    record.status = SceneEditStatus::Skipped;
                    record.reason = match status {
                        binary::MbPathStatus::Undecodable => "undecodable",
                        binary::MbPathStatus::PayloadRejected => "payload_rejected",
                        _ => unreachable!(),
                    }
                    .into();
                    let skipped = changes.path_replacements.skipped.get_or_insert_with(|| {
                        Box::new(maya_scene_kit_formats::PathReplaceSkips::binary())
                    });
                    let reason = if status == binary::MbPathStatus::Undecodable {
                        skipped.non_utf8 += 1;
                        crate::scene::PathReplaceSkipReason::NonUtf8
                    } else {
                        *skipped.payload_rejected.as_mut().unwrap() += 1;
                        crate::scene::PathReplaceSkipReason::PayloadRejected
                    };
                    record.path_skips.insert(reason, 1);
                }
            }
            changes.records.push(record);
        }
    }
    changes.physical_deletion_count = physical.removed_forms.len() + physical.removed_records.len();
    if changes.physical_deletion_count == 0 && physical.rewritten_records.is_empty() {
        return Err(SceneEditError::NoEffectiveEdits {
            skipped: changes
                .records
                .into_iter()
                .filter(|record| record.status == SceneEditStatus::Skipped)
                .collect(),
        });
    }
    binary::validate_mb_original_edits(&physical)?;
    Ok((
        binary::apply_mb_original_edits(bytes, root, &physical)?,
        changes,
    ))
}
