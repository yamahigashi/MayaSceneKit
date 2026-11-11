use sha2::{Digest, Sha256};

use super::{application::Applied, *};
use crate::scene::edit::materialize::unsupported_scene_format;

pub(super) fn read_report_source(report: &ScenePathsReport) -> Result<Vec<u8>, SceneToolError> {
    let source = report
        .source
        .as_ref()
        .filter(|source| !source.sha256.is_empty())
        .ok_or_else(|| SceneToolError::Message("paths report has no source fingerprint".into()))?;
    let bytes = fs::read(&report.scene_path)?;
    if source.byte_len != bytes.len() || source.sha256 != format!("{:x}", Sha256::digest(&bytes)) {
        return Err(SceneToolError::SourceChanged {
            path: report.scene_path.clone(),
        });
    }
    Ok(bytes)
}

pub(super) struct PathApplicationChanges {
    pub summary: crate::scene::PathReplaceChanges,
    pub paths: Vec<rewrite::MaPathReplaceChange>,
    pub mb_paths: Vec<crate::mb::rewrite::MbPathChange>,
}

pub(super) type AppliedPathReplacement = Applied<PathApplicationChanges>;

enum PathPlan<'a> {
    Rules(&'a [PathReplaceRule]),
    Overrides(&'a [(usize, String)]),
}

impl From<rewrite::MaPathReplaceResult> for AppliedPathReplacement {
    fn from(result: rewrite::MaPathReplaceResult) -> Self {
        Self {
            bytes: result.bytes,
            changes: PathApplicationChanges {
                summary: crate::scene::PathReplaceChanges {
                    replacement_count: result.replacement_count,
                    skipped: Some(Box::new(result.skipped)),
                },
                paths: result.paths,
                mb_paths: Vec::new(),
            },
        }
    }
}

pub(super) fn ma_replace_error(error: rewrite::MaPathReplaceError) -> SceneToolError {
    SceneToolError::Message(error.to_string())
}

fn apply_paths(
    bytes: Vec<u8>,
    input_path: &Path,
    format: SceneFormat,
    plan: PathPlan<'_>,
) -> Result<AppliedPathReplacement, SceneToolError> {
    if let PathPlan::Rules(rules) = &plan {
        super::replace_rules::validate_replace_rules(rules)?;
    }
    if format == SceneFormat::Ma {
        return match plan {
            PathPlan::Rules(rules) => rewrite::replace_raw_scene_paths_in_ma(
                &bytes,
                &super::replace_rules::ma_replace_rules(rules),
            ),
            PathPlan::Overrides(overrides) => {
                rewrite::replace_raw_scene_paths_in_ma_by_index(&bytes, overrides)
            }
        }
        .map(Into::into)
        .map_err(ma_replace_error);
    }
    if format == SceneFormat::Mb {
        let mb = crate::mb::parse_bytes(bytes)?;
        let (bytes, changes) = match plan {
            PathPlan::Rules(rules) => {
                let rules = super::replace_rules::ma_replace_rules(rules)
                    .into_iter()
                    .map(|rule| MbPathReplaceRule {
                        from: rule.from,
                        to: rule.to,
                        mode: rule.mode,
                    })
                    .collect::<Vec<_>>();
                crate::mb::replace_scene_paths_in_mb(mb.data(), mb.root(), &rules)
            }
            PathPlan::Overrides(overrides) => {
                crate::mb::rewrite::replace_scene_paths_in_mb_by_index(
                    mb.data(),
                    mb.root(),
                    overrides,
                )
            }
        }
        .map_err(super::clean::mb_rewrite_error)?;
        return Ok(Applied {
            bytes,
            changes: PathApplicationChanges {
                summary: crate::scene::PathReplaceChanges {
                    replacement_count: changes.replacement_count,
                    skipped: Some(Box::new(changes.skipped)),
                },
                paths: Vec::new(),
                mb_paths: changes.paths,
            },
        });
    }
    Err(unsupported_scene_format(input_path, format))
}

impl PatchPlanner {
    pub(super) fn collect_scene_paths_report(
        &self,
        src: &Path,
    ) -> Result<ScenePathsReport, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        collect_scene_paths_with_options(src, PathKind::All, self.options.load_options())
    }

    pub(super) fn apply_path_rules_in_path(
        &self,
        input_path: impl AsRef<Path>,
        rules: &[PathReplaceRule],
    ) -> Result<AppliedPathReplacement, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let src = input_path.as_ref();
        let format = ops::detect_scene_format(src)?;
        let bytes = fs::read(src)?;
        apply_paths(bytes, src, format, PathPlan::Rules(rules))
    }

    pub(super) fn apply_path_rules_in_report(
        &self,
        report: &ScenePathsReport,
        rules: &[PathReplaceRule],
    ) -> Result<AppliedPathReplacement, SceneToolError> {
        let bytes = read_report_source(report)?;
        apply_paths(
            bytes,
            &report.scene_path,
            report.scene_format,
            PathPlan::Rules(rules),
        )
    }

    pub(super) fn apply_path_overrides_in_report(
        &self,
        report: &ScenePathsReport,
        targets: &[super::replace_rules::ResolvedPathOverride],
    ) -> Result<AppliedPathReplacement, SceneToolError> {
        self.options.reject_if_not_forensic()?;
        let overrides = targets
            .iter()
            .map(|target| (target.entry_index, target.after_value.clone()))
            .collect::<Vec<_>>();
        let bytes = read_report_source(report)?;
        apply_paths(
            bytes,
            &report.scene_path,
            report.scene_format,
            PathPlan::Overrides(&overrides),
        )
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
