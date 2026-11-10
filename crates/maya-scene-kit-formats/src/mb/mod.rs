// The IFF chunk layer lives in `maya-mb`; this module re-exports it and owns the
// Maya-semantic `.mb` helpers built on top of it.
mod head;
pub mod paths;
pub mod rewrite;

pub use maya_mb::{
    BudgetContext, ByteSpan, Chunk, ChunkLayout, EncodeError, FourCC, FourCCParseError,
    HeaderFormat, LayoutHints, MayaBinaryFile, MayaBinaryParseError, MbChildren, MbCompleteness,
    MbParseBudget, MbParseBudgetLimit, MbSectionScanState, MbTruncationReason, MbWalkResult,
    ReadField, SectionChunk, parse_bytes, parse_bytes_with_budget, parse_file,
    parse_file_with_budget, parse_section_chunks_with_hints,
    parse_section_chunks_with_hints_with_budget, resolve_section_layout_hints,
    visit_group_chunks_with_layout, visit_group_chunks_with_layout_with_budget,
    walk_group_chunks_with_layout, walk_group_chunks_with_layout_with_budget,
};

pub(crate) use self::rewrite::encode_root_chunk;
pub use self::{
    head::{
        HeadMetadata, MbRequiresEntry, MbRootFormsAndRequiresRemoval, extract_head_metadata,
        extract_head_metadata_with_budget, remove_plugin_requires_from_mb,
        remove_root_forms_and_plugin_requires_from_mb, render_requires_entry,
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

/// Checks root child sections using the raw walk's layout rules and bounded budget.
pub(crate) fn scan_root_sections(
    data: &[u8],
    root: &Chunk,
    budget: &MbParseBudget,
) -> MbSectionScanState {
    root.scan_root_sections(data, budget)
        .unwrap_or(MbSectionScanState::Stopped)
}

#[derive(Debug, Clone)]
pub struct MbSectionScan<T> {
    pub value: T,
    pub state: MbSectionScanState,
}
