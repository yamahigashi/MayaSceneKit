// The IFF chunk layer lives in `maya-mb`; this module re-exports it and owns the
// Maya-semantic `.mb` helpers built on top of it.
mod head;
pub mod paths;
pub mod rewrite;

pub use maya_mb::{
    BudgetContext, ByteSpan, Chunk, ChunkLayout, EncodeError, FourCC, FourCCParseError,
    HeaderFormat, LayoutHints, MayaBinaryFile, MayaBinaryParseError, MbChildren, MbCompleteness,
    MbParseBudget, MbParseBudgetLimit, MbTruncationReason, ReadField, SectionChunk, parse_bytes,
    parse_bytes_with_budget, parse_file, parse_file_with_budget, parse_section_chunks_with_hints,
    resolve_section_layout_hints, visit_group_chunks_with_layout,
    visit_group_chunks_with_layout_with_budget, walk_group_chunks_with_layout,
    walk_group_chunks_with_layout_with_budget,
};

pub(crate) use self::rewrite::encode_root_chunk;
pub use self::{
    head::{
        HeadMetadata, MbRequiresEntry, MbRootFormsAndRequiresRemoval, extract_head_metadata,
        remove_plugin_requires_from_mb, remove_root_forms_and_plugin_requires_from_mb,
        render_requires_entry,
    },
    paths::{
        MbNameSelection, MbRootFormRemoval, collect_rtft_owner_traces_from_mb,
        decode_best_effort_script_text, extract_raw_script_entries_from_mb,
        remove_raw_script_nodes_from_mb, remove_root_forms_from_mb_by_locator,
        scan_raw_script_nodes_in_mb,
    },
    rewrite::{
        MbPathReplaceRule, MbRewriteError, replace_scene_paths_in_mb,
        replace_scene_paths_in_mb_cow, require_complete_mb_tree,
    },
};
