pub mod parser;

pub(crate) mod defaults;
mod head;
pub(crate) mod layout;
pub mod paths;
mod raw_walk;
pub mod rewrite;
pub(crate) mod section;

pub use self::{
    super::byte_span::ByteSpan,
    head::{
        HeadMetadata, MbRequiresEntry, extract_head_metadata, remove_plugin_requires_from_mb,
        remove_root_forms_and_plugin_requires_from_mb, render_requires_entry,
    },
    layout::resolve_section_layout_hints,
    parser::{
        Chunk, MayaBinaryFile, MayaBinaryParseError, MbParseBudget, MbParseBudgetLimit,
        parse_bytes, parse_bytes_with_budget, parse_file, parse_file_with_budget,
    },
    paths::{
        collect_rtft_owner_traces_from_mb, decode_best_effort_script_text,
        remove_raw_script_nodes_from_mb, remove_root_forms_from_mb_by_locator,
    },
    raw_walk::{walk_group_chunks_with_layout, walk_group_chunks_with_layout_with_budget},
    rewrite::{MbPathReplaceRule, replace_scene_paths_in_mb},
    section::parse_section_chunks_with_hints,
};
pub(crate) use self::{
    layout::is_group_chunk_tag,
    rewrite::encode_root_chunk,
    section::{ParsedSection, SectionChunk, parse_section_chunks_full_with_hints},
};
