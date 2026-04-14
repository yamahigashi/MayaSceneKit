use std::{fs, path::PathBuf};

use super::super::{
    fs::{CliOutputError, write_output_bytes},
    issues_artifacts::attach_unknown_payload_blobs_to_issues,
    output_contracts::build_to_ascii_issues_json,
    runtime_context::materialize_options,
};
use crate::scene::{OperationMode, SceneToolError, convert_to_maya_ascii_with_report_and_options};

pub(crate) fn run_to_ascii(
    input: &PathBuf,
    output: &PathBuf,
    issues_json: Option<&PathBuf>,
    node_info_paths: &[PathBuf],
    max_bytes: Option<usize>,
    embed_metadata: bool,
    write_unknown_blobs: bool,
    mode: OperationMode,
) -> i32 {
    let options = materialize_options(node_info_paths, max_bytes)
        .with_embed_output_metadata(embed_metadata)
        .with_operation_mode(mode);
    match convert_to_maya_ascii_with_report_and_options(input, output, &options) {
        Ok(mut report) => {
            println!(
                "written={} format={} mode={} state={}",
                report.output_path.display(),
                report.scene_format,
                report.operation_mode,
                report.validation_state,
            );
            if let Some(path) = issues_json {
                if let Some(parent) = path.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        eprintln!("error: {e}");
                        return 2;
                    }
                }
                if write_unknown_blobs {
                    attach_unknown_payload_blobs_to_issues(
                        path,
                        &report.raw_chunks,
                        &mut report.issues,
                    );
                }
                let payload = build_to_ascii_issues_json(input, &report);
                match serde_json::to_vec_pretty(&payload) {
                    Ok(bytes) => {
                        if let Err(e) = write_output_bytes(path, &bytes) {
                            eprintln!("error: {e}");
                            return match e {
                                CliOutputError::Scene(SceneToolError::Io(_)) => 2,
                                _ => 1,
                            };
                        }
                        println!("issues_json={}", path.display());
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        return 2;
                    }
                }
            }
            0
        }
        Err(SceneToolError::Io(e)) => {
            eprintln!("error: {e}");
            2
        }
        Err(e) => {
            eprintln!("scene error: {e}");
            1
        }
    }
}
