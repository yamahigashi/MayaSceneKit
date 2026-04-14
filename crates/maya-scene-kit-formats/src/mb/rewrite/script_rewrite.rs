use super::super::Chunk;
use super::super::scripts;

pub(crate) fn remove_script_nodes_from_mb(data: &[u8], root: &Chunk) -> (Vec<u8>, Vec<String>) {
    scripts::remove_script_nodes_from_mb(data, root)
}
