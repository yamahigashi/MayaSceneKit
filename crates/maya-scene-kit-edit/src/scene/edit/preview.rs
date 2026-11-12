use std::collections::BTreeMap;

use super::*;
use crate::scene::PathReplaceSkipReason;

impl PatchPlanner {
    pub fn preview_replace_scene_paths(
        &self,
        input_path: impl AsRef<Path>,
        rules: &[PathReplaceRule],
    ) -> Result<PathReplacePreview, SceneToolError> {
        let preview = self.preview_replace_scene_path_candidates(input_path, rules)?;
        Ok(matched_path_preview(preview))
    }

    pub fn preview_replace_scene_path_candidates(
        &self,
        input_path: impl AsRef<Path>,
        rules: &[PathReplaceRule],
    ) -> Result<PathReplaceCandidatePreview, SceneToolError> {
        let src = input_path.as_ref();
        let report = self.collect_scene_paths_report(src)?;
        self.preview_replace_scene_path_candidates_in_report(&report, rules)
    }

    pub fn preview_replace_scene_path_candidates_in_report(
        &self,
        report: &ScenePathsReport,
        rules: &[PathReplaceRule],
    ) -> Result<PathReplaceCandidatePreview, SceneToolError> {
        self.options.reject_if_not_forensic()?;

        let applied = self.apply_path_rules_in_report(report, rules)?;
        Ok(self.path_candidate_preview_from_application(report, &applied))
    }

    pub(super) fn path_candidate_preview_from_application(
        &self,
        report: &ScenePathsReport,
        applied: &super::paths::AppliedPathReplacement,
    ) -> PathReplaceCandidatePreview {
        let mut changes = MaPreviewChanges::new(&applied.changes.paths);
        let items: Vec<_> = report
            .entries
            .iter()
            .enumerate()
            .map(|(entry_index, entry)| {
                let (after_value, replacement_count, skipped) =
                    if report.scene_format == SceneFormat::Mb {
                        mb_preview_change(applied, entry_index, &entry.value)
                    } else {
                        changes.take(entry)
                    };
                PathReplaceCandidateItem {
                    skipped,
                    entry_index,
                    node_type: entry.node_type.clone(),
                    node_name: entry.node_name.clone(),
                    attr: entry.attr.clone(),
                    before_value: entry.value.clone(),
                    after_value,
                    replacement_count,
                }
            })
            .collect();
        PathReplaceCandidatePreview {
            input_path: report.scene_path.clone(),
            scene_format: report.scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: report.validation_state,
            matched_count: items
                .iter()
                .filter(|item| item.replacement_count > 0)
                .count(),
            applied_count: applied.changes.summary.replacement_count,
            items,
        }
    }

    pub fn preview_replace_scene_paths_with_overrides(
        &self,
        input_path: impl AsRef<Path>,
        overrides: &[PathReplaceOverride],
    ) -> Result<PathReplacePreview, SceneToolError> {
        let src = input_path.as_ref();
        let report = self.collect_scene_paths_report(src)?;
        self.preview_replace_scene_paths_with_overrides_in_report(&report, overrides)
    }

    pub fn preview_replace_scene_paths_with_overrides_in_report(
        &self,
        report: &ScenePathsReport,
        overrides: &[PathReplaceOverride],
    ) -> Result<PathReplacePreview, SceneToolError> {
        self.options.reject_if_not_forensic()?;

        let targets = super::replace_rules::resolve_targeted_overrides(report, overrides)?;
        let applied = self.apply_path_overrides_in_report(report, &targets)?;
        Ok(self.path_override_preview_from_application(report, &targets, &applied))
    }

    pub(super) fn path_override_preview_from_application(
        &self,
        report: &ScenePathsReport,
        targets: &[super::replace_rules::ResolvedPathOverride],
        applied: &super::paths::AppliedPathReplacement,
    ) -> PathReplacePreview {
        let mut changes = MaPreviewChanges::new(&applied.changes.paths);
        let items: Vec<_> = targets
            .iter()
            .map(|target| {
                let (after_value, replacement_count, skipped) =
                    if report.scene_format == SceneFormat::Mb {
                        mb_preview_change(applied, target.entry_index, &target.entry.value)
                    } else {
                        changes.take(&target.entry)
                    };
                PathReplacePreviewItem {
                    skipped,
                    entry_index: target.entry_index,
                    node_type: target.entry.node_type.clone(),
                    node_name: target.entry.node_name.clone(),
                    attr: target.entry.attr.clone(),
                    before_value: target.entry.value.clone(),
                    after_value,
                    replacement_count,
                }
            })
            .collect();
        PathReplacePreview {
            input_path: report.scene_path.clone(),
            scene_format: report.scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: report.validation_state,
            matched_count: items
                .iter()
                .filter(|item| item.replacement_count > 0)
                .count(),
            applied_count: applied.changes.summary.replacement_count,
            items,
        }
    }

    pub fn preview_remove_script_nodes(
        &self,
        input_path: impl AsRef<Path>,
    ) -> Result<ScriptNodeCleanPreview, SceneToolError> {
        let src = input_path.as_ref();
        let (format, applied) = self.apply_script_clean_in_path(src)?;
        Ok(self.script_preview_from_application(src, format, &applied))
    }

    pub fn preview_remove_script_nodes_by_name(
        &self,
        input_path: impl AsRef<Path>,
        node_names: &[String],
    ) -> Result<ScriptNodeCleanPreview, SceneToolError> {
        let targets = node_names
            .iter()
            .cloned()
            .map(|node_name| ExecutionCleanTarget::ScriptNode { node_name })
            .collect::<Vec<_>>();
        let src = input_path.as_ref();
        let (format, applied) = self.apply_execution_clean_in_path(src, &targets)?;
        Ok(self.script_preview_from_application(src, format, &applied))
    }

    pub fn preview_clean_execution_targets(
        &self,
        input_path: impl AsRef<Path>,
        targets: &[ExecutionCleanTarget],
    ) -> Result<ExecutionCleanPreview, SceneToolError> {
        let src = input_path.as_ref();
        let (format, applied) = self.apply_execution_clean_in_path(src, targets)?;
        Ok(self.clean_preview_from_application(src, format, &applied))
    }
}

pub(super) fn matched_path_preview(mut preview: PathReplaceCandidatePreview) -> PathReplacePreview {
    preview.items.retain(|item| item.replacement_count > 0);
    staged_path_preview(preview)
}

pub(super) fn staged_path_preview(preview: PathReplaceCandidatePreview) -> PathReplacePreview {
    let items = preview
        .items
        .into_iter()
        .filter(|item| item.replacement_count > 0 || !item.skipped.is_empty())
        .map(|item| PathReplacePreviewItem {
            skipped: item.skipped,
            entry_index: item.entry_index,
            node_type: item.node_type,
            node_name: item.node_name,
            attr: item.attr,
            before_value: item.before_value,
            after_value: item.after_value,
            replacement_count: item.replacement_count,
        })
        .collect();
    PathReplacePreview {
        input_path: preview.input_path,
        scene_format: preview.scene_format,
        operation_mode: preview.operation_mode,
        validation_state: preview.validation_state,
        matched_count: preview.matched_count,
        applied_count: preview.applied_count,
        items,
    }
}

type PathFingerprint<'a> = (&'a str, &'a str, &'a str, &'a str);

struct MaPreviewChanges<'a> {
    entries: std::collections::HashMap<
        PathFingerprint<'a>,
        std::collections::VecDeque<&'a rewrite::MaPathReplaceChange>,
    >,
}

impl<'a> MaPreviewChanges<'a> {
    fn new(changes: &'a [rewrite::MaPathReplaceChange]) -> Self {
        let mut entries: std::collections::HashMap<_, std::collections::VecDeque<_>> =
            std::collections::HashMap::new();
        for change in changes {
            if let Some(entry) = &change.entry {
                entries
                    .entry((
                        entry.node_type.as_str(),
                        entry.node_name.as_str(),
                        entry.attr.as_str(),
                        entry.value.as_str(),
                    ))
                    .or_default()
                    .push_back(change);
            }
        }
        Self { entries }
    }

    fn take(
        &mut self,
        entry: &'a maya_scene_kit_observe::scene::paths::ScenePathEntry,
    ) -> (String, usize, BTreeMap<PathReplaceSkipReason, usize>) {
        self.entries
            .get_mut(&(
                entry.node_type.as_str(),
                entry.node_name.as_str(),
                entry.attr.as_str(),
                entry.value.as_str(),
            ))
            .and_then(std::collections::VecDeque::pop_front)
            .map_or_else(
                || (entry.value.clone(), 0, Default::default()),
                |change| {
                    let mut skipped = BTreeMap::new();
                    for range in change
                        .skipped_ranges
                        .iter()
                        .filter(|range| range.replacement_requested)
                    {
                        for (reason, count) in super::application::path_skip_counts(&range.skipped)
                        {
                            *skipped.entry(reason).or_default() += count;
                        }
                    }
                    (
                        change.after_value.clone(),
                        change.replacement_count,
                        skipped,
                    )
                },
            )
    }
}

fn mb_preview_change(
    applied: &super::paths::AppliedPathReplacement,
    entry_index: usize,
    before: &str,
) -> (String, usize, BTreeMap<PathReplaceSkipReason, usize>) {
    let mut after = before.to_owned();
    let mut count = 0;
    let mut skipped = BTreeMap::new();
    for change in &applied.changes.mb_paths {
        if change.entry_index != Some(entry_index) || !change.replacement_requested {
            continue;
        }
        use crate::mb::rewrite::MbPathStatus;
        let reason = match change.status {
            MbPathStatus::Applied => {
                count += 1;
                if let Some(value) = &change.after_value {
                    after.clone_from(value);
                }
                None
            }
            MbPathStatus::Unchanged => None,
            MbPathStatus::Undecodable => Some(PathReplaceSkipReason::NonUtf8),
            MbPathStatus::PayloadRejected => Some(PathReplaceSkipReason::PayloadRejected),
            MbPathStatus::UnmatchedLocator => Some(PathReplaceSkipReason::UnmatchedLocator),
            MbPathStatus::DuplicateRequest => Some(PathReplaceSkipReason::DuplicateRequest),
        };
        if let Some(reason) = reason {
            *skipped.entry(reason).or_default() += 1;
        }
    }
    (after, count, skipped)
}
