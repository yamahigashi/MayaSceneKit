use std::path::PathBuf;

use crate::{
    cli::runtime_context::materialize_options,
    scene::{OperationMode, SceneToolError, remove_script_nodes_with_options},
};

pub(crate) fn run_script_clean(
    input: &PathBuf,
    output: &PathBuf,
    node_info_paths: &[PathBuf],
    max_bytes: Option<usize>,
) -> i32 {
    let options = materialize_options(node_info_paths, max_bytes)
        .with_operation_mode(OperationMode::Forensic);
    match remove_script_nodes_with_options(input, output, &options) {
        Ok(result) => {
            println!(
                "written={} format={} mode={} state={} removed={}",
                result.output_path.display(),
                result.scene_format,
                result.operation_mode,
                result.validation_state,
                result.removed_count()
            );
            for name in result.removed_nodes {
                println!("- {name}");
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
