use super::*;
use crate::scene::edit::materialize::unsupported_scene_format;

pub(super) struct AppliedPathReplacement {
    pub bytes: Vec<u8>,
    pub changes: crate::scene::PathReplaceChanges,
    pub paths: Vec<rewrite::MaPathReplaceChange>,
}

impl From<rewrite::MaPathReplaceResult> for AppliedPathReplacement {
    fn from(result: rewrite::MaPathReplaceResult) -> Self {
        Self {
            bytes: result.bytes,
            changes: crate::scene::PathReplaceChanges {
                replacement_count: result.replacement_count,
                skipped: Some(result.skipped),
            },
            paths: result.paths,
        }
    }
}

pub(super) fn ma_replace_error(error: rewrite::MaPathReplaceError) -> SceneToolError {
    SceneToolError::Message(error.to_string())
}

impl PatchPlanner {
    pub(super) fn collect_scene_paths_report(
        &self,
        src: &Path,
    ) -> Result<ScenePathsReport, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        collect_scene_paths_with_options(src, PathKind::All, self.options.load_options())
    }

    pub(super) fn materialize_replaced_scene_bytes(
        &self,
        input_path: impl AsRef<Path>,
        rules: &[PathReplaceRule],
    ) -> Result<AppliedPathReplacement, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;

        if scene_format == SceneFormat::Ma {
            let original = fs::read(src)?;
            let ma_rules = super::replace_rules::ma_replace_rules(rules);
            return rewrite::replace_raw_scene_paths_in_ma(&original, &ma_rules)
                .map(Into::into)
                .map_err(ma_replace_error);
        }

        if scene_format == SceneFormat::Mb {
            let mb = parse_file(src)?;
            let mb_rules = rules
                .iter()
                .map(|rule| MbPathReplaceRule {
                    from: rule.from.clone(),
                    to: rule.to.clone(),
                    mode: match rule.mode {
                        PathReplaceMode::Literal => {
                            maya_scene_kit_formats::ma::types::PathReplaceMode::Literal
                        }
                        PathReplaceMode::Regex => {
                            maya_scene_kit_formats::ma::types::PathReplaceMode::Regex
                        }
                    },
                })
                .collect::<Vec<_>>();
            let (rewritten, replacement_count) =
                crate::mb::replace_scene_paths_in_mb(mb.data(), mb.root(), &mb_rules)
                    .map_err(super::clean::mb_rewrite_error)?;
            return Ok(AppliedPathReplacement {
                bytes: rewritten,
                changes: crate::scene::PathReplaceChanges {
                    replacement_count,
                    skipped: None,
                },
                paths: Vec::new(),
            });
        }

        Err(unsupported_scene_format(src, scene_format))
    }

    pub(super) fn materialize_replaced_scene_bytes_from_overrides_in_report(
        &self,
        report: &ScenePathsReport,
        overrides: &[PathReplaceOverride],
    ) -> Result<AppliedPathReplacement, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let src = report.scene_path.as_path();
        let targets = super::replace_rules::resolve_targeted_overrides(report, overrides)?;
        let indexed_replacements = targets
            .iter()
            .map(|target| (target.entry_index, target.after_value.clone()))
            .collect::<Vec<_>>();

        if report.scene_format == SceneFormat::Ma {
            let original = fs::read(src)?;
            return rewrite::replace_raw_scene_paths_in_ma_by_index(
                &original,
                &indexed_replacements,
            )
            .map(Into::into)
            .map_err(ma_replace_error);
        }

        if report.scene_format == SceneFormat::Mb {
            let mb = parse_file(src)?;
            let (rewritten, replacement_count) =
                crate::mb::rewrite::replace_scene_paths_in_mb_by_index(
                    mb.data(),
                    mb.root(),
                    &indexed_replacements,
                )
                .map_err(super::clean::mb_rewrite_error)?;
            return Ok(AppliedPathReplacement {
                bytes: rewritten,
                changes: crate::scene::PathReplaceChanges {
                    replacement_count,
                    skipped: None,
                },
                paths: Vec::new(),
            });
        }

        Err(unsupported_scene_format(src, report.scene_format))
    }
}

pub fn collect_raw_chunks(path: impl AsRef<Path>) -> Result<Vec<RawChunkDump>, SceneToolError> {
    let scene_path = path.as_ref();
    let scene_format = ops::detect_scene_format(scene_path)?;
    if scene_format != SceneFormat::Mb {
        return Ok(vec![]);
    }
    let mb = parse_file(scene_path)?;
    Ok(collect_raw_chunk_records(&mb)
        .0
        .into_iter()
        .map(|raw| {
            let payload = raw.payload(mb.data()).to_vec();
            RawChunkDump {
                trace_form: raw.chunk_ref.form,
                trace_tag: raw.chunk_ref.tag,
                trace_node_offset: raw.chunk_ref.node_offset,
                trace_chunk_aux: raw.chunk_ref.chunk_aux,
                trace_child_alignment: raw.chunk_ref.child_alignment,
                trace_child_header_size: raw.chunk_ref.child_header_size,
                payload,
            }
        })
        .collect())
}
