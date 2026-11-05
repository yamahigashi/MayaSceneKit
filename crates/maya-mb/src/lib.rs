//! Low-level Autodesk Maya Binary (`.mb`) IFF chunk reading, walking, and encoding.
//!
//! This crate knows the chunk container layout (FOR4/FOR8, CAT, LIS groups, header widths,
//! alignment) but nothing about Maya node or attribute semantics.

mod byte_span;
mod chunk_encode;
mod defaults;
mod fourcc;
mod layout;
mod parser;
mod raw_walk;
mod section;

pub(crate) use self::layout::is_group_chunk_tag;
pub use self::{
    byte_span::ByteSpan,
    chunk_encode::{EncodeError, encode_chunk, encode_root_chunk},
    fourcc::{FourCC, FourCCParseError},
    layout::{ChunkLayout, LayoutHints, resolve_section_layout_hints},
    parser::{
        BudgetContext, Chunk, MayaBinaryFile, MayaBinaryParseError, MbParseBudget,
        MbParseBudgetLimit, ReadField, parse_bytes, parse_bytes_with_budget, parse_file,
        parse_file_with_budget,
    },
    raw_walk::{
        visit_group_chunks_with_layout, visit_group_chunks_with_layout_with_budget,
        walk_group_chunks_with_layout, walk_group_chunks_with_layout_with_budget,
    },
    section::{HeaderFormat, ParsedSection, SectionChunk, parse_section_chunks_with_hints},
};
