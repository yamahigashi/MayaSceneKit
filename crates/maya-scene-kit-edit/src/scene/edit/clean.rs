use super::*;
use crate::scene::edit::materialize::unsupported_scene_format;

impl PatchPlanner {
    pub(super) fn materialize_clean_scene_bytes(
        &self,
        input_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;

        if scene_format == SceneFormat::Ma {
            let original = fs::read(src)?;
            let (cleaned, _) = scripts::remove_raw_script_nodes_from_ma(&original);
            return Ok(cleaned);
        }

        if scene_format == SceneFormat::Mb {
            let mb = parse_file(src)?;
            let (cleaned, _) = remove_raw_script_nodes_from_mb(&mb.data, &mb.root);
            return Ok(cleaned);
        }

        Err(unsupported_scene_format(src, scene_format))
    }

    pub(super) fn materialize_clean_scene_bytes_by_name(
        &self,
        input_path: impl AsRef<Path>,
        node_names: &[String],
    ) -> Result<Vec<u8>, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;

        if scene_format == SceneFormat::Ma {
            let original = fs::read(src)?;
            let (cleaned, _) =
                scripts::remove_raw_script_nodes_from_ma_by_name(&original, node_names);
            return Ok(cleaned);
        }

        if scene_format == SceneFormat::Mb {
            let mb = parse_file(src)?;
            let (cleaned, _) = crate::mb::paths::remove_raw_script_nodes_from_mb_by_name(
                &mb.data, &mb.root, node_names,
            );
            return Ok(cleaned);
        }

        Err(unsupported_scene_format(src, scene_format))
    }

    pub(super) fn materialize_execution_clean_scene_bytes(
        &self,
        input_path: impl AsRef<Path>,
        targets: &[ExecutionCleanTarget],
    ) -> Result<Vec<u8>, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;
        let bytes = fs::read(src)?;
        self.materialize_execution_clean_scene_bytes_in_bytes(src, scene_format, &bytes, targets)
    }

    pub(super) fn materialize_execution_clean_scene_bytes_in_bytes(
        &self,
        input_path: &Path,
        scene_format: SceneFormat,
        bytes: &[u8],
        targets: &[ExecutionCleanTarget],
    ) -> Result<Vec<u8>, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let normalized = normalize_execution_clean_targets(targets)?;

        if scene_format == SceneFormat::Ma {
            let mut bytes = bytes.to_vec();
            let script_nodes = normalized
                .iter()
                .filter_map(|target| match target {
                    ExecutionCleanTarget::ScriptNode { node_name } => Some(node_name.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if !script_nodes.is_empty() {
                let (cleaned, _) =
                    scripts::remove_raw_script_nodes_from_ma_by_name(&bytes, &script_nodes);
                bytes = cleaned;
            }

            let plugin_requires = normalized
                .iter()
                .filter_map(|target| match target {
                    ExecutionCleanTarget::PluginRequire { rendered } => Some(rendered.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if !plugin_requires.is_empty() {
                let (cleaned, _) =
                    requires::remove_plugin_requires_from_ma(&bytes, &plugin_requires);
                bytes = cleaned;
            }

            let top_level_ranges = normalized
                .iter()
                .filter_map(|target| match target {
                    ExecutionCleanTarget::TopLevelCommand { source_range } => {
                        Some((source_range.start, source_range.end))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            if !top_level_ranges.is_empty() {
                let (cleaned, _) =
                    rewrite::remove_top_level_commands_from_ma(&bytes, &top_level_ranges);
                bytes = cleaned;
            }

            let callback_ranges = normalized
                .iter()
                .filter_map(|target| match target {
                    ExecutionCleanTarget::FileCommandCallback { source_range } => {
                        Some((source_range.start, source_range.end))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            if !callback_ranges.is_empty() {
                let (cleaned, _) =
                    rewrite::remove_file_command_callbacks_from_ma(&bytes, &callback_ranges)
                        .map_err(|err| SceneToolError::Message(err.to_string()))?;
                bytes = cleaned;
            }

            return Ok(bytes);
        }

        if scene_format == SceneFormat::Mb {
            let mb = crate::mb::parse_bytes(bytes.to_vec())?;
            let script_nodes = normalized
                .iter()
                .filter_map(|target| match target {
                    ExecutionCleanTarget::ScriptNode { node_name } => Some(node_name.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let (mut owner_form_targets, _) =
                crate::mb::paths::locate_raw_script_node_forms_in_mb_by_name(
                    &mb.data,
                    &mb.root,
                    &script_nodes,
                );
            owner_form_targets.extend(normalized.iter().filter_map(|target| match target {
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
            let plugin_requires = normalized
                .iter()
                .filter_map(|target| match target {
                    ExecutionCleanTarget::PluginRequire { rendered } => Some(rendered.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if owner_form_targets.is_empty() && plugin_requires.is_empty() {
                return Err(SceneToolError::Message(format!(
                    "execution clean targets are unsupported for MB scenes: {}",
                    input_path.display()
                )));
            }

            let (cleaned, _, removed_requires) =
                crate::mb::remove_root_forms_and_plugin_requires_from_mb(
                    &mb.data,
                    &mb.root,
                    &owner_form_targets,
                    &plugin_requires,
                );
            if cleaned.as_slice() == mb.data.as_ref()
                && removed_requires.is_empty()
                && owner_form_targets.is_empty()
            {
                return Err(SceneToolError::Message(format!(
                    "execution clean targets are unsupported for MB scenes: {}",
                    input_path.display()
                )));
            }
            return Ok(cleaned);
        }

        Err(unsupported_scene_format(input_path, scene_format))
    }
}

pub(super) fn normalize_clean_target_names(
    node_names: &[String],
) -> Result<Vec<String>, SceneToolError> {
    let normalized = node_names
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return Err(SceneToolError::Message(
            "targeted clean requires at least one script node name".to_string(),
        ));
    }
    Ok(normalized)
}

pub(super) fn normalize_execution_clean_targets(
    targets: &[ExecutionCleanTarget],
) -> Result<Vec<ExecutionCleanTarget>, SceneToolError> {
    let mut normalized = targets
        .iter()
        .filter_map(|target| match target {
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
            ExecutionCleanTarget::FileCommandCallback { source_range } => {
                valid_execution_source_range(source_range).then_some(
                    ExecutionCleanTarget::FileCommandCallback {
                        source_range: *source_range,
                    },
                )
            }
            ExecutionCleanTarget::MbOwnerForm { form, node_offset } => {
                let form = form.trim();
                (!form.is_empty()).then(|| ExecutionCleanTarget::MbOwnerForm {
                    form: form.to_string(),
                    node_offset: *node_offset,
                })
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if normalized.is_empty() {
        return Err(SceneToolError::Message(
            "execution clean requires at least one valid target".to_string(),
        ));
    }

    let destructive_ranges = normalized
        .iter()
        .filter_map(|target| match target {
            ExecutionCleanTarget::TopLevelCommand { source_range } => Some(*source_range),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    normalized.retain(|target| match target {
        ExecutionCleanTarget::FileCommandCallback { source_range } => {
            !destructive_ranges.contains(source_range)
        }
        _ => true,
    });

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

pub(super) fn mb_root_form_present(
    root: &crate::mb::Chunk,
    form: &str,
    node_offset: usize,
) -> bool {
    root.children
        .iter()
        .any(|child| child.offset == node_offset && child.form_type.as_deref() == Some(form))
}
