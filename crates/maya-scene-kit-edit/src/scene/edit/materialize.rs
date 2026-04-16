use super::*;

impl Materializer {
    pub fn configure_additional_node_info_paths(
        &self,
        paths: &[PathBuf],
    ) -> Result<(), SceneToolError> {
        maya_scene_kit_observe::scene::recovery::validate_additional_node_info_paths(
            &self
                .options
                .clone()
                .with_additional_node_info_paths(paths.to_vec())
                .load_options,
        )
    }

    pub fn convert_to_maya_ascii_with_report(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<MayaAsciiConversionReport, SceneToolError> {
        let staged = self.stage_maya_ascii(input_path)?;
        let dst = output_path.as_ref();
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        write_bytes_atomic(dst, &staged.artifact.bytes)?;
        let mut report = staged.report;
        report.output_path = dst.to_path_buf();
        Ok(report)
    }

    pub fn stage_maya_ascii(
        &self,
        input_path: impl AsRef<Path>,
    ) -> Result<MayaAsciiStageResult, SceneToolError> {
        let src = input_path.as_ref();
        let scene_format = ops::detect_scene_format(src)?;
        let suggested_output_path = suggested_ascii_output_path(src);

        if scene_format == SceneFormat::Ma {
            let bytes = fs::read(src)?;
            let report = finalize_state(
                MayaAsciiConversionReport {
                    output_path: suggested_output_path.clone(),
                    scene_format,
                    operation_mode: self.options.operation_mode,
                    validation_state: ValidationState::CopiedUnvalidated,
                    issues: vec![],
                    raw_chunks: vec![],
                    unknown_inventory: vec![],
                    decode_quality_distribution: vec![],
                    raw_chunk_count: 0,
                    raw_payload_size_total: 0,
                    unknown_payload_size_total: 0,
                    unknown_payload_size_ratio: 0.0,
                },
                self.options.operation_mode,
            )?;
            return Ok(MayaAsciiStageResult {
                artifact: StagedSceneArtifact {
                    input_path: src.to_path_buf(),
                    suggested_output_path,
                    scene_format,
                    operation_mode: self.options.operation_mode,
                    validation_state: report.validation_state,
                    bytes,
                },
                report,
            });
        }

        if scene_format == SceneFormat::Mb {
            let output_name = suggested_output_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let recovery = maya_scene_kit_observe::scene::recovery::recover_mb_scene(
                src,
                self.options.load_options(),
            )?;
            let result = ops::render_best_effort_ma(ops::BestEffortRenderData {
                metadata: recovery.header,
                scene_model: recovery.scene,
                forensics: recovery.forensics,
                issues: recovery.issues,
                source_path: src,
                output_name: output_name.as_ref(),
                angular_attrs_by_node: recovery.angular_attrs_by_node,
                embed_metadata: self.options.embed_output_metadata,
            });
            let issues = map::map_node_recovery_issues(result.issues);
            let unknown_inventory = map::build_unknown_inventory(&issues);
            let unknown_payload_size_total = unknown_inventory
                .iter()
                .map(|entry| entry.payload_size_sum)
                .sum::<usize>();
            let unknown_payload_size_ratio = if result.raw_payload_size_total == 0 {
                0.0
            } else {
                unknown_payload_size_total as f64 / result.raw_payload_size_total as f64
            };
            let validation_state = if !unknown_inventory.is_empty() {
                ValidationState::Unsupported
            } else if !issues.is_empty() {
                ValidationState::Partial
            } else {
                ValidationState::Validated
            };
            let decode_quality_distribution = result
                .decode_quality_distribution
                .into_iter()
                .map(map::to_public_decode_quality_entry)
                .collect();
            let bytes = result.maya_ascii.into_bytes();
            let report = finalize_state(
                MayaAsciiConversionReport {
                    output_path: suggested_output_path.clone(),
                    scene_format,
                    operation_mode: self.options.operation_mode,
                    validation_state,
                    issues,
                    raw_chunks: result.raw_chunks,
                    unknown_inventory,
                    decode_quality_distribution,
                    raw_chunk_count: result.raw_chunk_count,
                    raw_payload_size_total: result.raw_payload_size_total,
                    unknown_payload_size_total,
                    unknown_payload_size_ratio,
                },
                self.options.operation_mode,
            )?;
            return Ok(MayaAsciiStageResult {
                artifact: StagedSceneArtifact {
                    input_path: src.to_path_buf(),
                    suggested_output_path,
                    scene_format,
                    operation_mode: self.options.operation_mode,
                    validation_state: report.validation_state,
                    bytes,
                },
                report,
            });
        }

        Err(unsupported_scene_format(src, scene_format))
    }
}

fn finalize_state(
    report: MayaAsciiConversionReport,
    mode: OperationMode,
) -> Result<MayaAsciiConversionReport, SceneToolError> {
    if mode.allows_state(report.validation_state) {
        Ok(report)
    } else {
        Err(SceneToolError::RejectedByMode {
            mode,
            validation_state: report.validation_state,
            issue_count: report.issues.len(),
            unknown_count: report.unknown_inventory.len(),
        })
    }
}

fn suggested_ascii_output_path(input_path: &Path) -> PathBuf {
    input_path.with_extension("ma")
}

pub(super) fn unsupported_scene_format(path: &Path, detected: SceneFormat) -> SceneToolError {
    SceneToolError::UnsupportedSceneFormat {
        path: path.to_path_buf(),
        detected,
    }
}
