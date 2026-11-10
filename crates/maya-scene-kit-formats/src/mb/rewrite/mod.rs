mod attr_payload;
mod path_rewrite;

pub(crate) use maya_mb::{encode_chunk, encode_root_chunk};

pub(crate) use self::attr_payload::rewrite_attr_payload_string_preserving_shape;
pub use self::path_rewrite::{
    MbPathReplaceRule, replace_scene_paths_in_mb, replace_scene_paths_in_mb_by_index,
    replace_scene_paths_in_mb_by_index_cow, replace_scene_paths_in_mb_cow,
};

#[derive(Debug, Clone)]
pub struct MbRewriteError {
    pub completeness: crate::mb::MbCompleteness,
}

impl std::fmt::Display for MbRewriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot rewrite incomplete Maya Binary tree: {}",
            self.completeness
        )
    }
}

impl std::error::Error for MbRewriteError {}

pub fn require_complete_mb_tree(root: &crate::mb::Chunk) -> Result<(), MbRewriteError> {
    match root.completeness() {
        crate::mb::MbCompleteness::Complete => Ok(()),
        completeness => Err(MbRewriteError { completeness }),
    }
}

pub(crate) fn child_span_end(root: &crate::mb::Chunk, child: &crate::mb::Chunk) -> usize {
    let alignment = root
        .child_layout()
        .map_or(1, |layout| layout.alignment_usize());
    let padding = (alignment - child.size() % alignment) % alignment;
    child
        .payload_end()
        .saturating_add(padding)
        .min(root.payload_end())
}
