use super::{Chunk, MayaBinaryFile, paths};

pub(crate) fn scan_script_nodes_in_mb(data: &[u8], root: &Chunk) -> Vec<String> {
    paths::scan_raw_script_nodes_in_mb(data, root)
}

pub(crate) fn extract_script_entries_from_mb(mb: &MayaBinaryFile) -> Vec<(String, String)> {
    paths::extract_raw_script_entries_from_mb(mb)
}

pub(crate) fn remove_script_nodes_from_mb(data: &[u8], root: &Chunk) -> (Vec<u8>, Vec<String>) {
    paths::remove_raw_script_nodes_from_mb(data, root)
}
