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
            let (cleaned, _) = remove_raw_script_nodes_from_mb(mb.data(), mb.root())
                .map_err(super::clean::mb_rewrite_error)?;
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
                mb.data(),
                mb.root(),
                node_names,
            )
            .map_err(super::clean::mb_rewrite_error)?;
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
            let edits = normalized
                .iter()
                .filter_map(ma_range_edit)
                .collect::<Vec<_>>();
            let (mut bytes, _) =
                rewrite::apply_ma_range_edits(bytes, &edits).map_err(ma_range_edit_error)?;
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

            return Ok(bytes);
        }

        if scene_format == SceneFormat::Mb {
            let mb = crate::mb::parse_bytes(bytes.to_vec())?;
            let (owner_form_targets, plugin_requires) =
                collect_mb_clean_targets(mb.data(), mb.root(), &normalized)?;
            if owner_form_targets.is_empty() && plugin_requires.is_empty() {
                return Err(SceneToolError::Message(format!(
                    "execution clean targets are unsupported for MB scenes: {}",
                    input_path.display()
                )));
            }

            let (cleaned, _, removed_requires) =
                crate::mb::remove_root_forms_and_plugin_requires_from_mb(
                    mb.data(),
                    mb.root(),
                    &owner_form_targets,
                    crate::mb::MbNameSelection::Only(&plugin_requires),
                )
                .map_err(super::clean::mb_rewrite_error)?;
            if cleaned.as_slice() == mb.data()
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
    let normalized = targets
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
) -> Result<bool, SceneToolError> {
    crate::mb::require_complete_mb_tree(root).map_err(mb_rewrite_error)?;
    Ok(root.children().iter().any(|child| {
        let rendered = child.form_type().map(|f| f.to_string());
        child.offset() == node_offset && rendered.as_deref() == Some(form)
    }))
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
