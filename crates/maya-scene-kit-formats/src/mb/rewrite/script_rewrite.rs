use super::super::{Chunk, scripts};

pub(crate) fn remove_script_nodes_from_mb(
    data: &[u8],
    root: &Chunk,
) -> Result<(Vec<u8>, Vec<String>), crate::mb::MbRewriteError> {
    scripts::remove_script_nodes_from_mb(data, root)
}
