use super::*;
use crate::scene::edit::materialize::unsupported_scene_format;

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

        let compiled_rules = super::replace_rules::CompiledPreviewReplaceRules::compile(rules)?;
        let applied = Some(self.materialize_replaced_scene_bytes(&report.scene_path, rules)?);
        Ok(self.path_candidate_preview_from_application(report, &compiled_rules, applied.as_ref()))
    }

    pub(super) fn path_candidate_preview_from_application(
        &self,
        report: &ScenePathsReport,
        compiled_rules: &super::replace_rules::CompiledPreviewReplaceRules,
        applied: Option<&super::paths::AppliedPathReplacement>,
    ) -> PathReplaceCandidatePreview {
        let mut changes =
            MaPreviewChanges::new(applied.map_or(&[], |result| result.paths.as_slice()));
        let items: Vec<_> = report
            .entries
            .iter()
            .enumerate()
            .map(|(entry_index, entry)| {
                let (after_value, replacement_count) = if report.scene_format == SceneFormat::Mb {
                    mb_preview_change(applied.unwrap(), entry_index, &entry.value)
                } else if applied.is_some() {
                    changes.take(entry)
                } else {
                    compiled_rules.apply(&entry.value)
                };
                PathReplaceCandidateItem {
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
            applied_count: applied.map_or(0, |result| result.changes.replacement_count),
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
        let applied = Some(
            self.materialize_replaced_scene_bytes_from_overrides_in_report(report, overrides)?,
        );
        Ok(self.path_override_preview_from_application(report, &targets, applied.as_ref()))
    }

    pub(super) fn path_override_preview_from_application(
        &self,
        report: &ScenePathsReport,
        targets: &[super::replace_rules::ResolvedPathOverride],
        applied: Option<&super::paths::AppliedPathReplacement>,
    ) -> PathReplacePreview {
        let mut changes =
            MaPreviewChanges::new(applied.map_or(&[], |result| result.paths.as_slice()));
        let items: Vec<_> = targets
            .iter()
            .map(|target| {
                let (after_value, replacement_count) = if report.scene_format == SceneFormat::Mb {
                    mb_preview_change(applied.unwrap(), target.entry_index, &target.entry.value)
                } else if applied.is_some() {
                    changes.take(&target.entry)
                } else {
                    (
                        target.after_value.clone(),
                        usize::from(target.entry.value != target.after_value),
                    )
                };
                PathReplacePreviewItem {
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
            applied_count: applied.map_or(0, |result| result.changes.replacement_count),
            items,
        }
    }

    pub fn preview_remove_script_nodes(
        &self,
        input_path: impl AsRef<Path>,
    ) -> Result<ScriptNodeCleanPreview, SceneToolError> {
        self.options.reject_if_not_forensic()?;

        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;
        let removed_nodes = if scene_format == SceneFormat::Ma {
            let original = fs::read(src)?;
            let (_, removed_names) = scripts::remove_raw_script_nodes_from_ma(&original);
            removed_names
        } else if scene_format == SceneFormat::Mb {
            let mb = parse_file(src)?;
            let (_, removed_names) = remove_raw_script_nodes_from_mb(mb.data(), mb.root())
                .map_err(super::clean::mb_rewrite_error)?;
            removed_names
        } else {
            return Err(unsupported_scene_format(src, scene_format));
        };

        Ok(ScriptNodeCleanPreview {
            input_path: src.to_path_buf(),
            scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: ValidationState::CopiedUnvalidated,
            removed_nodes,
        })
    }

    pub fn preview_remove_script_nodes_by_name(
        &self,
        input_path: impl AsRef<Path>,
        node_names: &[String],
    ) -> Result<ScriptNodeCleanPreview, SceneToolError> {
        self.options.reject_if_not_forensic()?;

        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;
        let normalized = super::clean::normalize_clean_target_names(node_names)?;
        let removed_nodes = if scene_format == SceneFormat::Ma {
            let original = fs::read(src)?;
            let (_, removed_names) =
                scripts::remove_raw_script_nodes_from_ma_by_name(&original, &normalized);
            removed_names
        } else if scene_format == SceneFormat::Mb {
            let mb = parse_file(src)?;
            let (_, removed_names) = crate::mb::paths::remove_raw_script_nodes_from_mb_by_name(
                mb.data(),
                mb.root(),
                &normalized,
            )
            .map_err(super::clean::mb_rewrite_error)?;
            removed_names
        } else {
            return Err(unsupported_scene_format(src, scene_format));
        };

        if removed_nodes.is_empty() {
            return Err(SceneToolError::Message(format!(
                "no matching script nodes found for targeted clean in {}",
                src.display()
            )));
        }

        Ok(ScriptNodeCleanPreview {
            input_path: src.to_path_buf(),
            scene_format,
            operation_mode: self.options.operation_mode,
            validation_state: ValidationState::CopiedUnvalidated,
            removed_nodes,
        })
    }

    pub fn preview_clean_execution_targets(
        &self,
        input_path: impl AsRef<Path>,
        targets: &[ExecutionCleanTarget],
    ) -> Result<ExecutionCleanPreview, SceneToolError> {
        self.options.reject_if_not_forensic()?;

        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;
        let bytes = fs::read(src)?;
        self.preview_clean_execution_targets_in_bytes(
            src,
            scene_format,
            ValidationState::CopiedUnvalidated,
            &bytes,
            targets,
        )
    }

    pub(super) fn preview_clean_execution_targets_in_bytes(
        &self,
        input_path: &Path,
        scene_format: SceneFormat,
        validation_state: ValidationState,
        bytes: &[u8],
        targets: &[ExecutionCleanTarget],
    ) -> Result<ExecutionCleanPreview, SceneToolError> {
        let mb = if scene_format == SceneFormat::Mb {
            Some(crate::mb::parse_bytes(bytes.to_vec())?)
        } else {
            None
        };
        self.preview_clean_execution_targets_with_root(
            input_path,
            scene_format,
            validation_state,
            bytes,
            targets,
            mb.as_ref().map(|mb| mb.root()),
        )
    }

    pub(super) fn preview_clean_execution_targets_with_root(
        &self,
        input_path: &Path,
        scene_format: SceneFormat,
        validation_state: ValidationState,
        bytes: &[u8],
        targets: &[ExecutionCleanTarget],
        mb_root: Option<&crate::mb::Chunk>,
    ) -> Result<ExecutionCleanPreview, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let normalized = super::clean::normalize_execution_clean_targets(targets)?;
        if normalized.is_empty() {
            return Err(SceneToolError::Message(format!(
                "no execution clean targets provided for {}",
                input_path.display()
            )));
        }

        let mut cleaned_targets = Vec::new();
        let mut removed_script_nodes = Vec::new();
        let mut removed_plugin_requires = Vec::new();

        for target in normalized {
            match &target {
                ExecutionCleanTarget::ScriptNode { node_name } => {
                    let names = vec![node_name.clone()];
                    let removed_names = if scene_format == SceneFormat::Ma {
                        let (_, removed_names) =
                            scripts::remove_raw_script_nodes_from_ma_by_name(bytes, &names);
                        removed_names
                    } else if scene_format == SceneFormat::Mb {
                        let root = mb_root.expect("mb root");
                        let (_, removed_names) =
                            crate::mb::paths::remove_raw_script_nodes_from_mb_by_name(
                                bytes, root, &names,
                            )
                            .map_err(super::clean::mb_rewrite_error)?;
                        removed_names
                    } else {
                        return Err(unsupported_scene_format(input_path, scene_format));
                    };
                    if !removed_names.is_empty() {
                        cleaned_targets.push(target.clone());
                        removed_script_nodes.extend(removed_names);
                    }
                }
                ExecutionCleanTarget::PluginRequire { rendered } => {
                    let rendered_targets = vec![rendered.clone()];
                    let removed = if scene_format == SceneFormat::Ma {
                        let (_, removed) =
                            requires::remove_plugin_requires_from_ma(bytes, &rendered_targets);
                        removed
                    } else if scene_format == SceneFormat::Mb {
                        let root = mb_root.expect("mb root");
                        let (_, removed) =
                            remove_plugin_requires_from_mb(bytes, root, &rendered_targets)
                                .map_err(super::clean::mb_rewrite_error)?;
                        removed
                    } else {
                        return Err(unsupported_scene_format(input_path, scene_format));
                    };
                    if !removed.is_empty() {
                        cleaned_targets.push(target.clone());
                        removed_plugin_requires.extend(removed);
                    }
                }
                ExecutionCleanTarget::TopLevelCommand { source_range } => {
                    if scene_format != SceneFormat::Ma {
                        return Err(super::clean::unsupported_execution_clean_target(
                            input_path,
                            scene_format,
                            &target,
                        ));
                    }
                    if rewrite::ma_range_has_bytes(bytes, source_range.start, source_range.end) {
                        cleaned_targets.push(target.clone());
                    }
                }
                ExecutionCleanTarget::FileCommandCallback { source_range } => {
                    if scene_format != SceneFormat::Ma {
                        return Err(super::clean::unsupported_execution_clean_target(
                            input_path,
                            scene_format,
                            &target,
                        ));
                    }
                    if rewrite::ma_file_command_callback_present(
                        bytes,
                        source_range.start,
                        source_range.end,
                    ) {
                        cleaned_targets.push(target.clone());
                    }
                }
                ExecutionCleanTarget::MbOwnerForm { form, node_offset } => {
                    if scene_format != SceneFormat::Mb {
                        return Err(super::clean::unsupported_execution_clean_target(
                            input_path,
                            scene_format,
                            &target,
                        ));
                    }
                    let root = mb_root.expect("mb root");
                    if super::clean::mb_root_form_present(root, form, *node_offset)? {
                        cleaned_targets.push(target.clone());
                    }
                }
            }
        }

        if scene_format == SceneFormat::Ma {
            let edits = cleaned_targets
                .iter()
                .filter_map(super::clean::ma_range_edit)
                .collect::<Vec<_>>();
            let normalized = rewrite::normalize_ma_range_edits(bytes.len(), &edits)
                .map_err(super::clean::ma_range_edit_error)?;
            cleaned_targets.retain(|target| {
                super::clean::ma_range_edit(target).is_none_or(|edit| normalized.contains(&edit))
            });
        }

        if cleaned_targets.is_empty() {
            return Err(SceneToolError::Message(format!(
                "no matching execution clean targets found in {}",
                input_path.display()
            )));
        }

        Ok(ExecutionCleanPreview {
            input_path: input_path.to_path_buf(),
            scene_format,
            operation_mode: self.options.operation_mode,
            validation_state,
            cleaned_targets,
            removed_script_nodes,
            removed_plugin_requires,
        })
    }
}

pub(super) fn matched_path_preview(preview: PathReplaceCandidatePreview) -> PathReplacePreview {
    let items = preview
        .items
        .into_iter()
        .filter(|item| item.replacement_count > 0)
        .map(|item| PathReplacePreviewItem {
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
    ) -> (String, usize) {
        self.entries
            .get_mut(&(
                entry.node_type.as_str(),
                entry.node_name.as_str(),
                entry.attr.as_str(),
                entry.value.as_str(),
            ))
            .and_then(std::collections::VecDeque::pop_front)
            .map_or_else(
                || (entry.value.clone(), 0),
                |change| (change.after_value.clone(), change.replacement_count),
            )
    }
}

fn mb_preview_change(
    applied: &super::paths::AppliedPathReplacement,
    entry_index: usize,
    before: &str,
) -> (String, usize) {
    let mut after = before.to_owned();
    let mut count = 0;
    for change in &applied.mb_paths {
        if change.entry_index == Some(entry_index)
            && change.status == crate::mb::rewrite::MbPathStatus::Applied
        {
            count += 1;
            if let Some(value) = &change.after_value {
                after.clone_from(value);
            }
        }
    }
    (after, count)
}
