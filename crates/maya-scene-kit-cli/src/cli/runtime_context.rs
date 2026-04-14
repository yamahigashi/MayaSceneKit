use std::path::PathBuf;

use crate::scene::{LoadOptions, MaterializeOptions};

pub(crate) fn load_options(node_info_paths: &[PathBuf], max_bytes: Option<usize>) -> LoadOptions {
    let mut options = LoadOptions::default();
    if !node_info_paths.is_empty() {
        options = options.with_additional_node_info_paths(node_info_paths.to_vec());
    }
    if let Some(max_bytes) = max_bytes {
        options = options.with_max_parse_bytes(max_bytes);
    }
    options
}

pub(crate) fn materialize_options(
    node_info_paths: &[PathBuf],
    max_bytes: Option<usize>,
) -> MaterializeOptions {
    MaterializeOptions::new(load_options(node_info_paths, max_bytes))
}
