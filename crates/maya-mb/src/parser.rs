use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use thiserror::Error;

use crate::{
    ChunkLayout, FourCC, HeaderFormat,
    layout::{
        EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE, is_group_chunk_tag,
        resolve_parser_group_layout,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbParseBudgetLimit {
    MaxDepth,
    MaxChildrenPerGroup,
    MaxTotalChunks,
    MaxParseBytes,
}

impl MbParseBudgetLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxDepth => "max_depth",
            Self::MaxChildrenPerGroup => "max_children_per_group",
            Self::MaxTotalChunks => "max_total_chunks",
            Self::MaxParseBytes => "max_parse_bytes",
        }
    }
}

impl std::fmt::Display for MbParseBudgetLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The primitive field that a truncated read attempted to decode.
///
/// Matches outside this crate require a wildcard arm. The unit variants remain
/// constructible outside this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadField {
    /// A four-byte chunk or form tag.
    Tag,
    /// A big-endian 32-bit unsigned integer.
    U32,
    /// A big-endian 64-bit unsigned integer.
    U64,
}

/// Diagnostic values for a parse or walk budget failure.
///
/// Matches outside this crate require a wildcard arm and `..` in named-field
/// patterns. Named-field variants cannot be constructed outside this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BudgetContext {
    /// Input size exceeded the byte budget.
    #[non_exhaustive]
    InputBytes {
        /// Observed input size in bytes.
        size: usize,
        /// Configured maximum input size in bytes.
        maximum: usize,
        /// Whether the size was checked after loading the bytes.
        after_read: bool,
    },
    /// The total-chunk budget prevented claiming the root.
    #[non_exhaustive]
    RootClaim {
        /// Configured maximum number of chunks.
        maximum: usize,
    },
    /// A semantic walk exceeded its depth budget.
    #[non_exhaustive]
    Depth {
        /// Depth of the group whose contents would be walked.
        depth: usize,
        /// Configured maximum depth.
        maximum: usize,
    },
    /// A semantic walk exceeded a group's child budget.
    #[non_exhaustive]
    Children {
        /// Depth of the group containing the children.
        depth: usize,
        /// Configured maximum number of children per group.
        maximum: usize,
    },
    /// A semantic walk exhausted its total-chunk budget.
    #[non_exhaustive]
    TotalChunks {
        /// Configured maximum number of chunks.
        maximum: usize,
    },
}

/// A Maya Binary container parse, walk, or input failure.
///
/// Matches outside this crate require a wildcard arm and `..` in named-field
/// patterns. Named-field variants cannot be constructed outside this crate.
/// The tuple variant [`Self::Io`] remains constructible outside this crate;
/// cloning it shares the original I/O error.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum MayaBinaryParseError {
    /// The input cannot hold the smallest stream header.
    #[non_exhaustive]
    #[error("File is too small to be a Maya Binary stream.")]
    StreamTooShort {
        /// Actual input size in bytes.
        actual: usize,
        /// Minimum stream size in bytes.
        minimum: usize,
    },
    /// The root tag is neither FOR4 nor FOR8.
    #[non_exhaustive]
    #[error("Unexpected root chunk '{tag}'.")]
    UnexpectedRoot {
        /// Observed root tag.
        tag: FourCC,
    },
    /// Bytes remain after the root chunk.
    #[non_exhaustive]
    #[error("Trailing bytes after root chunk: next=0x{next:X}, size=0x{len:X}")]
    TrailingBytes {
        /// Offset immediately after the root chunk.
        next: usize,
        /// Input size in bytes.
        len: usize,
    },
    /// A chunk header extends beyond its container.
    #[non_exhaustive]
    #[error("Chunk header exceeds container: offset=0x{offset:X}, limit=0x{limit:X}")]
    HeaderOutOfBounds {
        /// Chunk header offset.
        offset: usize,
        /// Required header size in bytes.
        header_size: usize,
        /// Exclusive container end offset.
        limit: usize,
    },
    /// Adding the payload size to its offset overflowed.
    #[non_exhaustive]
    #[error("Chunk payload overflow for '{tag}' at 0x{offset:X}: size=0x{size:X}")]
    PayloadOverflow {
        /// Chunk tag.
        tag: FourCC,
        /// Chunk header offset.
        offset: usize,
        /// Declared payload size in bytes.
        size: usize,
    },
    /// A payload extends beyond its container.
    #[non_exhaustive]
    #[error(
        "Chunk payload exceeds container for '{tag}' at 0x{offset:X}: payload_end=0x{payload_end:X}, limit=0x{limit:X}"
    )]
    PayloadOutOfBounds {
        /// Chunk tag.
        tag: FourCC,
        /// Chunk header offset.
        offset: usize,
        /// Exclusive payload end offset.
        payload_end: usize,
        /// Exclusive container end offset.
        limit: usize,
    },
    /// A group payload cannot hold its form tag.
    #[non_exhaustive]
    #[error("Group '{tag}' at 0x{offset:X} has size < 4.")]
    GroupTooShort {
        /// Group chunk tag.
        tag: FourCC,
        /// Chunk header offset.
        offset: usize,
        /// Declared payload size in bytes.
        size: usize,
    },
    /// Adding the aligned payload size to its offset overflowed.
    #[non_exhaustive]
    #[error(
        "Alignment overflow for '{tag}' at 0x{offset:X}: payload_offset=0x{payload_offset:X}, aligned_size=0x{aligned_size:X}"
    )]
    AlignmentOverflow {
        /// Chunk tag.
        tag: FourCC,
        /// Chunk header offset.
        offset: usize,
        /// Start of the payload.
        payload_offset: usize,
        /// Payload size rounded to the sibling alignment.
        aligned_size: usize,
    },
    /// The aligned end of a chunk extends beyond its container.
    #[non_exhaustive]
    #[error("Alignment overflow for '{tag}' at 0x{offset:X}: next=0x{next:X}, limit=0x{limit:X}")]
    AlignedEndOutOfBounds {
        /// Chunk tag.
        tag: FourCC,
        /// Chunk header offset.
        offset: usize,
        /// Aligned end offset of the chunk.
        next: usize,
        /// Exclusive container end offset.
        limit: usize,
    },
    /// A primitive field could not be read in full.
    #[non_exhaustive]
    #[error("Missing {} at 0x{offset:X}", match .field { ReadField::Tag => "4-byte tag", ReadField::U32 => "u32", ReadField::U64 => "u64" })]
    TruncatedRead {
        /// Start offset of the attempted read.
        offset: usize,
        /// Required number of bytes.
        width: usize,
        /// Primitive field being decoded.
        field: ReadField,
    },
    /// A complete child parse ended at an unexpected offset.
    #[non_exhaustive]
    #[error("Children ended at 0x{actual:X} but expected 0x{expected:X}")]
    ChildrenEndMismatch {
        /// Offset reached by the child parser.
        actual: usize,
        /// Expected exclusive container end offset.
        expected: usize,
    },
    /// A configured parsing or walking budget was exceeded.
    #[non_exhaustive]
    #[error("{}", budget_text(.context))]
    BudgetExceeded {
        /// Budget responsible for the failure.
        limit: MbParseBudgetLimit,
        /// Diagnostic values at the failure site.
        context: BudgetContext,
    },
    /// The original input I/O error, shared across clones.
    #[error(transparent)]
    Io(Arc<std::io::Error>),
}

fn budget_text(context: &BudgetContext) -> String {
    match context {
        BudgetContext::InputBytes {
            size,
            maximum,
            after_read,
        } => {
            if *after_read {
                format!(
                    "Maya Binary file exceeds parse budget after read: size={size} limit={maximum}"
                )
            } else {
                format!("Maya Binary file exceeds parse budget: size={size} limit={maximum}")
            }
        }
        BudgetContext::RootClaim { .. } => {
            "Maya Binary parse budget exhausted before the root chunk.".to_string()
        }
        BudgetContext::Depth { depth, maximum } => {
            format!(
                "Maya Binary semantic walk exceeded depth budget: depth={depth} limit={maximum}"
            )
        }
        BudgetContext::Children { depth, maximum } => {
            format!(
                "Maya Binary semantic walk exceeded child budget: depth={depth} limit={maximum}"
            )
        }
        BudgetContext::TotalChunks { maximum } => {
            format!("Maya Binary semantic walk exceeded total chunk budget: limit={maximum}")
        }
    }
}

impl From<std::io::Error> for MayaBinaryParseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(Arc::new(value))
    }
}

impl MayaBinaryParseError {
    /// Returns the budget responsible for this error, if any.
    pub fn budget_limit(&self) -> Option<MbParseBudgetLimit> {
        match self {
            Self::BudgetExceeded { limit, .. } => Some(*limit),
            Self::StreamTooShort { .. }
            | Self::UnexpectedRoot { .. }
            | Self::TrailingBytes { .. }
            | Self::HeaderOutOfBounds { .. }
            | Self::PayloadOverflow { .. }
            | Self::PayloadOutOfBounds { .. }
            | Self::GroupTooShort { .. }
            | Self::AlignmentOverflow { .. }
            | Self::AlignedEndOutOfBounds { .. }
            | Self::TruncatedRead { .. }
            | Self::ChildrenEndMismatch { .. }
            | Self::Io(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbParseBudget {
    pub max_depth: usize,
    pub max_children_per_group: usize,
    pub max_total_chunks: usize,
    pub max_parse_bytes: usize,
}

impl Default for MbParseBudget {
    fn default() -> Self {
        Self {
            max_depth: 128,
            max_children_per_group: 100_000,
            max_total_chunks: 1_000_000,
            max_parse_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// A parsed chunk whose fields cannot be constructed or modified externally.
#[derive(Debug, Clone)]
pub struct Chunk {
    tag: FourCC,
    offset: usize,
    aux: u32,
    size: usize,
    payload_offset: usize,
    payload_end: usize,
    form_type: Option<FourCC>,
    /// Resolved layout of group children, even when expansion is skipped.
    /// Leaves have no child layout; FOR8/Maya children use alignment 4.
    child_layout: Option<ChunkLayout>,
    children_parsed: bool,
    children: Vec<Chunk>,
}

impl Chunk {
    /// The original chunk tag.
    pub fn tag(&self) -> FourCC {
        self.tag
    }

    /// The header start as an absolute byte offset from [`MayaBinaryFile::data`].
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The auxiliary header value.
    pub fn aux(&self) -> u32 {
        self.aux
    }

    /// The payload length in bytes, excluding the header and sibling padding.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The payload start as an absolute byte offset from [`MayaBinaryFile::data`].
    /// A group payload includes its four-byte form type.
    pub fn payload_offset(&self) -> usize {
        self.payload_offset
    }

    /// The exclusive payload end as an absolute byte offset from [`MayaBinaryFile::data`].
    /// A group payload includes its four-byte form type.
    pub fn payload_end(&self) -> usize {
        self.payload_end
    }

    /// The form type of a group, or `None` for a leaf.
    pub fn form_type(&self) -> Option<FourCC> {
        self.form_type
    }

    /// The resolved layout of group children, even when expansion is skipped.
    /// This describes child placement, not this chunk's header or sibling alignment.
    pub fn child_layout(&self) -> Option<ChunkLayout> {
        self.child_layout
    }

    /// Returns the parsed direct children in their original order.
    pub fn children(&self) -> &[Chunk] {
        &self.children
    }

    /// Whether the direct child sequence was parsed to its end.
    /// Leaves, skipped expansion, partial prefixes, and absorbed child errors
    /// return false. Unexpanded descendants do not prevent a complete parent;
    /// an empty group can be complete.
    pub fn children_complete(&self) -> bool {
        self.children_parsed
    }

    /// Returns this chunk's own header width, independently of child layout
    /// and sibling alignment.
    pub fn header_format(&self) -> HeaderFormat {
        if self
            .payload_offset
            .checked_sub(self.offset)
            .unwrap_or_default()
            == FOUR_BYTE_HEADER_SIZE
        {
            HeaderFormat::FourByte
        } else {
            HeaderFormat::EightByte
        }
    }

    pub fn is_group(&self) -> bool {
        self.tag.is_group()
    }
}

/// Parsed bytes and their chunk tree, constructed through the parse functions.
/// The bytes and tree cannot be replaced or modified externally.
#[derive(Debug, Clone)]
pub struct MayaBinaryFile {
    path: Option<PathBuf>,
    data: Arc<[u8]>,
    root: Chunk,
}

impl MayaBinaryFile {
    /// Returns the source path metadata, if supplied.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns the complete parsed buffer, the origin of chunk byte offsets.
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Returns the shared parsed buffer without copying its bytes.
    pub fn data_arc(&self) -> &Arc<[u8]> {
        &self.data
    }

    /// Returns the parsed root chunk.
    pub fn root(&self) -> &Chunk {
        &self.root
    }

    /// Sets source path metadata without changing the parsed bytes or tree.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn payload<'a>(&'a self, chunk: &Chunk) -> &'a [u8] {
        &self.data[chunk.payload_offset..chunk.payload_end]
    }

    pub fn walk(&self) -> Vec<&Chunk> {
        let mut out = Vec::new();
        let mut stack = vec![&self.root];
        while let Some(node) = stack.pop() {
            out.push(node);
            for child in node.children.iter().rev() {
                stack.push(child);
            }
        }
        out
    }
}

pub fn parse_file(path: impl AsRef<Path>) -> Result<MayaBinaryFile, MayaBinaryParseError> {
    parse_file_with_budget(path, &MbParseBudget::default())
}

pub fn parse_bytes(data: impl Into<Vec<u8>>) -> Result<MayaBinaryFile, MayaBinaryParseError> {
    parse_bytes_with_budget(data, &MbParseBudget::default())
}

pub fn parse_file_with_budget(
    path: impl AsRef<Path>,
    budget: &MbParseBudget,
) -> Result<MayaBinaryFile, MayaBinaryParseError> {
    let p = path.as_ref();
    let file_size = fs::metadata(p)?.len() as usize;
    if file_size > budget.max_parse_bytes {
        return Err(MayaBinaryParseError::BudgetExceeded {
            limit: MbParseBudgetLimit::MaxParseBytes,
            context: BudgetContext::InputBytes {
                size: file_size,
                maximum: budget.max_parse_bytes,
                after_read: false,
            },
        });
    }
    let data: Arc<[u8]> = fs::read(p)?.into();
    if data.len() > budget.max_parse_bytes {
        return Err(MayaBinaryParseError::BudgetExceeded {
            limit: MbParseBudgetLimit::MaxParseBytes,
            context: BudgetContext::InputBytes {
                size: data.len(),
                maximum: budget.max_parse_bytes,
                after_read: true,
            },
        });
    }
    let root = parse_stream(&data, budget)?;
    Ok(MayaBinaryFile {
        path: Some(p.to_path_buf()),
        data,
        root,
    })
}

pub fn parse_bytes_with_budget(
    data: impl Into<Vec<u8>>,
    budget: &MbParseBudget,
) -> Result<MayaBinaryFile, MayaBinaryParseError> {
    let data: Arc<[u8]> = data.into().into();
    if data.len() > budget.max_parse_bytes {
        return Err(MayaBinaryParseError::BudgetExceeded {
            limit: MbParseBudgetLimit::MaxParseBytes,
            context: BudgetContext::InputBytes {
                size: data.len(),
                maximum: budget.max_parse_bytes,
                after_read: true,
            },
        });
    }
    let root = parse_stream(&data, budget)?;
    Ok(MayaBinaryFile {
        path: None,
        data,
        root,
    })
}

#[derive(Debug, Clone, Copy)]
struct ParseBudgetState<'a> {
    budget: &'a MbParseBudget,
    total_chunks: usize,
}

impl<'a> ParseBudgetState<'a> {
    fn new(budget: &'a MbParseBudget) -> Self {
        Self {
            budget,
            total_chunks: 0,
        }
    }

    fn claim_chunk(&mut self) -> bool {
        if self.total_chunks >= self.budget.max_total_chunks {
            return false;
        }
        self.total_chunks += 1;
        true
    }
}

#[derive(Debug)]
enum ParseChunkStatus {
    Parsed((Chunk, usize)),
    BudgetExhausted,
}

#[derive(Debug)]
struct ParseChildrenResult {
    children: Vec<Chunk>,
    complete: bool,
}

fn parse_stream(data: &[u8], budget: &MbParseBudget) -> Result<Chunk, MayaBinaryParseError> {
    if data.len() < 8 {
        return Err(MayaBinaryParseError::StreamTooShort {
            actual: data.len(),
            minimum: 8,
        });
    }
    let root_tag = read_tag(data, 0)?;
    let root_format = match root_tag.as_ascii() {
        Some("FOR4") => HeaderFormat::FourByte,
        Some("FOR8") => HeaderFormat::EightByte,
        _ => {
            return Err(MayaBinaryParseError::UnexpectedRoot { tag: root_tag });
        }
    };
    let mut state = ParseBudgetState::new(budget);
    let ParseChunkStatus::Parsed((root, next)) =
        parse_chunk(data, 0, data.len(), 1, 0, root_format, &mut state)?
    else {
        return Err(MayaBinaryParseError::BudgetExceeded {
            limit: MbParseBudgetLimit::MaxTotalChunks,
            context: BudgetContext::RootClaim {
                maximum: budget.max_total_chunks,
            },
        });
    };
    if root.tag != "FOR4" && root.tag != "FOR8" {
        return Err(MayaBinaryParseError::UnexpectedRoot { tag: root.tag });
    }
    if next != data.len() {
        return Err(MayaBinaryParseError::TrailingBytes {
            next,
            len: data.len(),
        });
    }
    Ok(root)
}

fn parse_chunk(
    data: &[u8],
    offset: usize,
    limit: usize,
    sibling_alignment: usize,
    depth: usize,
    header_format: HeaderFormat,
    state: &mut ParseBudgetState<'_>,
) -> Result<ParseChunkStatus, MayaBinaryParseError> {
    if !state.claim_chunk() {
        return Ok(ParseChunkStatus::BudgetExhausted);
    }
    let hdr_size = header_format.header_size();
    if offset + hdr_size > limit {
        return Err(MayaBinaryParseError::HeaderOutOfBounds {
            offset,
            header_size: hdr_size,
            limit,
        });
    }

    let tag = read_tag(data, offset)?;
    let (aux, size, payload_offset) = match header_format {
        HeaderFormat::FourByte => (
            0,
            read_u32be(data, offset + 4)? as usize,
            offset + FOUR_BYTE_HEADER_SIZE,
        ),
        HeaderFormat::EightByte => (
            read_u32be(data, offset + 4)?,
            read_u64be(data, offset + 8)? as usize,
            offset + EIGHT_BYTE_HEADER_SIZE,
        ),
    };
    let payload_end = payload_offset
        .checked_add(size)
        .ok_or(MayaBinaryParseError::PayloadOverflow { tag, offset, size })?;
    if payload_end > limit {
        return Err(MayaBinaryParseError::PayloadOutOfBounds {
            tag,
            offset,
            payload_end,
            limit,
        });
    }

    let mut form_type = None;
    let mut children_parsed = false;
    let mut children = Vec::new();

    let mut child_layout = None;
    if is_group_chunk_tag(tag) {
        if size < 4 {
            return Err(MayaBinaryParseError::GroupTooShort { tag, offset, size });
        }
        form_type = Some(read_tag(data, payload_offset)?);
        let preferred_layout = resolve_parser_group_layout(tag, form_type, header_format);
        child_layout = Some(preferred_layout);

        if should_expand_group(depth, state.budget) {
            if let Ok(parsed) = parse_children_with_format(
                data,
                payload_offset + 4,
                payload_end,
                depth + 1,
                preferred_layout.alignment_usize(),
                preferred_layout.header_format(),
                state,
            ) {
                children = parsed.children;
                children_parsed = parsed.complete;
            }
        }
    }

    let aligned_size = align(size, sibling_alignment);
    let next_offset = payload_offset.checked_add(aligned_size).ok_or(
        MayaBinaryParseError::AlignmentOverflow {
            tag,
            offset,
            payload_offset,
            aligned_size,
        },
    )?;
    if next_offset > limit {
        return Err(MayaBinaryParseError::AlignedEndOutOfBounds {
            tag,
            offset,
            next: next_offset,
            limit,
        });
    }

    Ok(ParseChunkStatus::Parsed((
        Chunk {
            tag,
            offset,
            aux,
            size,
            payload_offset,
            payload_end,
            form_type,
            child_layout,
            children_parsed,
            children,
        },
        next_offset,
    )))
}

fn should_expand_group(depth: usize, budget: &MbParseBudget) -> bool {
    depth < budget.max_depth
}

fn align(offset: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return offset;
    }
    let rem = offset % alignment;
    if rem == 0 {
        offset
    } else {
        offset + (alignment - rem)
    }
}

fn read_tag(data: &[u8], offset: usize) -> Result<FourCC, MayaBinaryParseError> {
    let raw = data
        .get(offset..offset + 4)
        .ok_or(MayaBinaryParseError::TruncatedRead {
            offset,
            width: 4,
            field: ReadField::Tag,
        })?;
    Ok(FourCC::new(
        raw.try_into().expect("slice is 4 bytes by construction"),
    ))
}

fn read_u32be(data: &[u8], offset: usize) -> Result<u32, MayaBinaryParseError> {
    let raw = data
        .get(offset..offset + 4)
        .ok_or(MayaBinaryParseError::TruncatedRead {
            offset,
            width: 4,
            field: ReadField::U32,
        })?;
    let mut a = [0u8; 4];
    a.copy_from_slice(raw);
    Ok(u32::from_be_bytes(a))
}

fn read_u64be(data: &[u8], offset: usize) -> Result<u64, MayaBinaryParseError> {
    let raw = data
        .get(offset..offset + 8)
        .ok_or(MayaBinaryParseError::TruncatedRead {
            offset,
            width: 8,
            field: ReadField::U64,
        })?;
    let mut a = [0u8; 8];
    a.copy_from_slice(raw);
    Ok(u64::from_be_bytes(a))
}

fn parse_children_with_format(
    data: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    sibling_alignment: usize,
    header_format: HeaderFormat,
    state: &mut ParseBudgetState<'_>,
) -> Result<ParseChildrenResult, MayaBinaryParseError> {
    let mut children = Vec::new();
    let mut cursor = start;
    let mut complete = true;
    while cursor < end {
        if children.len() >= state.budget.max_children_per_group {
            complete = false;
            break;
        }
        match parse_chunk(
            data,
            cursor,
            end,
            sibling_alignment,
            depth,
            header_format,
            state,
        )? {
            ParseChunkStatus::Parsed((child, next_cursor)) => {
                children.push(child);
                cursor = next_cursor;
            }
            ParseChunkStatus::BudgetExhausted => {
                complete = false;
                break;
            }
        }
    }
    if complete && cursor != end {
        return Err(MayaBinaryParseError::ChildrenEndMismatch {
            actual: cursor,
            expected: end,
        });
    }
    Ok(ParseChildrenResult { children, complete })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_chunk_accessors_match_for4_bytes() {
        let data = b"FOR4\0\0\0\x10TESTDATA\0\0\0\x03abc\0";
        let parsed = parse_bytes(data.to_vec()).unwrap();
        let root = parsed.root();
        assert_eq!(root.tag(), FourCC::new(*b"FOR4"));
        assert_eq!(root.aux(), 0);
        assert_eq!(root.size(), 16);
        assert_eq!(root.offset(), 0);
        assert_eq!(root.payload_offset(), 8);
        assert_eq!(root.payload_end(), 24);
        assert_eq!(root.form_type(), Some(FourCC::new(*b"TEST")));
        assert_eq!(
            root.child_layout(),
            Some(ChunkLayout::new(
                std::num::NonZeroUsize::new(4).unwrap(),
                HeaderFormat::FourByte,
            ))
        );
        assert_eq!(root.children().len(), 1);
        assert!(root.children_complete());
        assert_eq!(root.header_format(), HeaderFormat::FourByte);
        assert_eq!(parsed.payload(root), &data[8..24]);

        let leaf = &root.children()[0];
        assert_eq!(leaf.tag(), FourCC::new(*b"DATA"));
        assert_eq!(leaf.aux(), 0);
        assert_eq!(leaf.size(), 3);
        assert_eq!(leaf.offset(), 12);
        assert_eq!(leaf.payload_offset(), 20);
        assert_eq!(leaf.payload_end(), 23);
        assert_eq!(leaf.form_type(), None);
        assert_eq!(leaf.child_layout(), None);
        assert_eq!(leaf.children().len(), 0);
        assert!(!leaf.children_complete());
        assert_eq!(leaf.header_format(), HeaderFormat::FourByte);
        assert_eq!(parsed.payload(leaf), b"abc");
    }

    #[test]
    fn public_chunk_aux_accessors_preserve_for8_values() {
        let mut data = b"FOR8\x01\x02\x03\x04\0\0\0\0\0\0\0\x1cTEST".to_vec();
        data.extend_from_slice(b"DATA\x55\x66\x77\x88\0\0\0\0\0\0\0\x01A\0\0\0\0\0\0\0");
        let parsed = parse_bytes(data).unwrap();
        let root = parsed.root();
        assert_eq!(root.header_format(), HeaderFormat::EightByte);
        assert_eq!(root.aux(), 0x01020304);
        assert!(root.children_complete());
        assert_eq!(root.children().len(), 1);
        let child = &root.children()[0];
        assert_eq!(child.header_format(), HeaderFormat::EightByte);
        assert_eq!(child.aux(), 0x55667788);
        assert_eq!(parsed.payload(child), b"A");
    }

    #[test]
    fn with_path_preserves_bytes_arc_and_chunk_getters() {
        let data = b"FOR4\0\0\0\x10TESTDATA\0\0\0\x04Test";
        let parsed = parse_bytes(data.to_vec()).unwrap();
        assert_eq!(parsed.path(), None);
        let original_arc = Arc::clone(parsed.data_arc());
        let chunk_getters = |file: &MayaBinaryFile| {
            file.walk()
                .into_iter()
                .map(|chunk| {
                    (
                        chunk.tag(),
                        chunk.aux(),
                        chunk.size(),
                        chunk.offset(),
                        chunk.payload_offset(),
                        chunk.payload_end(),
                        chunk.form_type(),
                        chunk.child_layout(),
                        chunk.children().len(),
                        chunk.children_complete(),
                        chunk.header_format(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let original_chunks = chunk_getters(&parsed);
        let path = Path::new("asset/example/scene.mb");
        let parsed = parsed.with_path(path);
        assert_eq!(parsed.path(), Some(path));
        assert_eq!(parsed.data(), data);
        assert!(Arc::ptr_eq(parsed.data_arc(), &original_arc));
        assert_eq!(chunk_getters(&parsed), original_chunks);

        let replacement = Path::new("asset/example/sample.mb");
        let parsed = parsed.with_path(replacement);
        assert_eq!(parsed.path(), Some(replacement));
        assert_eq!(parsed.data(), data);
        assert!(Arc::ptr_eq(parsed.data_arc(), &original_arc));
        assert_eq!(chunk_getters(&parsed), original_chunks);
    }

    #[test]
    fn file_byte_budget_before_read_preserves_context() {
        let path = std::env::temp_dir().join(format!(
            "maya-mb-{}-file-byte-budget-before-read.mb",
            std::process::id()
        ));
        fs::write(&path, b"FOR8").unwrap();
        let error = parse_file_with_budget(
            &path,
            &MbParseBudget {
                max_parse_bytes: 2,
                ..MbParseBudget::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::BudgetExceeded {
                limit: MbParseBudgetLimit::MaxParseBytes,
                context: BudgetContext::InputBytes {
                    size: 4,
                    maximum: 2,
                    after_read: false
                }
            }
        ));
        assert_eq!(
            error.budget_limit(),
            Some(MbParseBudgetLimit::MaxParseBytes)
        );
        assert_eq!(
            error.to_string(),
            "Maya Binary file exceeds parse budget: size=4 limit=2"
        );
        let _ = fs::remove_file(path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_byte_budget_after_read_preserves_context() {
        // Procfs reports zero metadata length while supplying bytes on read.
        let error = parse_file_with_budget(
            "/proc/self/status",
            &MbParseBudget {
                max_parse_bytes: 10,
                ..MbParseBudget::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::BudgetExceeded {
                limit: MbParseBudgetLimit::MaxParseBytes,
                context: BudgetContext::InputBytes {
                    size,
                    maximum: 10,
                    after_read: true
                }
            } if size > 10
        ));
        let display = error.to_string();
        assert!(display.starts_with("Maya Binary file exceeds parse budget after read: size="));
        assert!(display.ends_with("limit=10"));
    }

    #[test]
    fn private_payload_out_of_bounds_preserves_nonzero_offset() {
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(b"DATA\0\0\0\x04");
        let budget = MbParseBudget::default();
        let error = parse_chunk(
            &bytes,
            8,
            bytes.len(),
            4,
            0,
            HeaderFormat::FourByte,
            &mut ParseBudgetState::new(&budget),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::PayloadOutOfBounds {
                tag,
                offset: 8,
                payload_end: 20,
                limit: 16
            } if tag == FourCC::new(*b"DATA")
        ));
        assert_eq!(
            error.to_string(),
            "Chunk payload exceeds container for 'DATA' at 0x8: payload_end=0x14, limit=0x10"
        );
    }

    #[test]
    fn private_group_too_short_preserves_nonzero_offset() {
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(b"FOR8");
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&2u64.to_be_bytes());
        bytes.extend_from_slice(b"TE");
        let budget = MbParseBudget::default();
        let error = parse_chunk(
            &bytes,
            8,
            bytes.len(),
            4,
            0,
            HeaderFormat::EightByte,
            &mut ParseBudgetState::new(&budget),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::GroupTooShort {
                tag,
                offset: 8,
                size: 2
            } if tag == FourCC::new(*b"FOR8")
        ));
        assert_eq!(error.to_string(), "Group 'FOR8' at 0x8 has size < 4.");
    }

    #[test]
    fn root_group_too_short_preserves_context() {
        let mut bytes = b"FOR8".to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&2u64.to_be_bytes());
        bytes.extend_from_slice(b"TE");
        let error = parse_bytes(bytes).unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::GroupTooShort {
                tag,
                offset: 0,
                size: 2
            } if tag == FourCC::new(*b"FOR8")
        ));
        assert_eq!(error.to_string(), "Group 'FOR8' at 0x0 has size < 4.");
    }

    #[test]
    fn file_read_io_preserves_display_and_has_no_budget_limit() {
        let path = std::env::temp_dir();
        let expected = fs::read(&path).unwrap_err();
        let error = parse_file(&path).unwrap_err();
        assert!(matches!(error, MayaBinaryParseError::Io(_)));
        assert_eq!(error.to_string(), expected.to_string());
        assert_eq!(error.budget_limit(), None);
    }

    fn structured_errors() -> Vec<(MayaBinaryParseError, &'static str)> {
        let tag = FourCC::new(*b"DATA");
        vec![
            (
                MayaBinaryParseError::StreamTooShort {
                    actual: 4,
                    minimum: 8,
                },
                "File is too small to be a Maya Binary stream.",
            ),
            (
                MayaBinaryParseError::UnexpectedRoot { tag },
                "Unexpected root chunk 'DATA'.",
            ),
            (
                MayaBinaryParseError::UnexpectedRoot {
                    tag: FourCC::new([0, 1, 0x7f, 0xff]),
                },
                "Unexpected root chunk '[00017FFF]'.",
            ),
            (
                MayaBinaryParseError::TrailingBytes {
                    next: 0xab,
                    len: 0xcd,
                },
                "Trailing bytes after root chunk: next=0xAB, size=0xCD",
            ),
            (
                MayaBinaryParseError::HeaderOutOfBounds {
                    offset: 0xab,
                    header_size: 16,
                    limit: 0xcd,
                },
                "Chunk header exceeds container: offset=0xAB, limit=0xCD",
            ),
            (
                MayaBinaryParseError::PayloadOverflow {
                    tag,
                    offset: 0xab,
                    size: 0xef,
                },
                "Chunk payload overflow for 'DATA' at 0xAB: size=0xEF",
            ),
            (
                MayaBinaryParseError::PayloadOutOfBounds {
                    tag,
                    offset: 0xab,
                    payload_end: 0xef,
                    limit: 0xcd,
                },
                "Chunk payload exceeds container for 'DATA' at 0xAB: payload_end=0xEF, limit=0xCD",
            ),
            (
                MayaBinaryParseError::GroupTooShort {
                    tag: FourCC::new(*b"FOR8"),
                    offset: 0xab,
                    size: 0,
                },
                "Group 'FOR8' at 0xAB has size < 4.",
            ),
            (
                MayaBinaryParseError::AlignmentOverflow {
                    tag,
                    offset: 0xab,
                    payload_offset: 0xbb,
                    aligned_size: 0xef,
                },
                "Alignment overflow for 'DATA' at 0xAB: payload_offset=0xBB, aligned_size=0xEF",
            ),
            (
                MayaBinaryParseError::AlignedEndOutOfBounds {
                    tag,
                    offset: 0xab,
                    next: 0xef,
                    limit: 0xcd,
                },
                "Alignment overflow for 'DATA' at 0xAB: next=0xEF, limit=0xCD",
            ),
            (
                MayaBinaryParseError::TruncatedRead {
                    offset: 0xab,
                    width: 4,
                    field: ReadField::Tag,
                },
                "Missing 4-byte tag at 0xAB",
            ),
            (
                MayaBinaryParseError::TruncatedRead {
                    offset: 0xab,
                    width: 4,
                    field: ReadField::U32,
                },
                "Missing u32 at 0xAB",
            ),
            (
                MayaBinaryParseError::TruncatedRead {
                    offset: 0xab,
                    width: 8,
                    field: ReadField::U64,
                },
                "Missing u64 at 0xAB",
            ),
            (
                MayaBinaryParseError::ChildrenEndMismatch {
                    actual: 0xab,
                    expected: 0xcd,
                },
                "Children ended at 0xAB but expected 0xCD",
            ),
        ]
    }

    #[test]
    fn structured_error_display_preserves_messages() {
        for (error, expected) in structured_errors() {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn parse_failures_preserve_variants_and_fields() {
        for len in 0..8 {
            let error = parse_bytes(vec![0; len]).unwrap_err();
            assert!(
                matches!(error, MayaBinaryParseError::StreamTooShort { actual, minimum: 8 } if actual == len)
            );
            assert_eq!(
                error.to_string(),
                "File is too small to be a Maya Binary stream."
            );
        }
        for (bytes, expected) in [
            (*b"TEST\0\0\0\0", "Unexpected root chunk 'TEST'."),
            (
                [0, 1, 0x7f, 0xff, 0, 0, 0, 0],
                "Unexpected root chunk '[00017FFF]'.",
            ),
        ] {
            let error = parse_bytes(bytes).unwrap_err();
            assert!(
                matches!(error, MayaBinaryParseError::UnexpectedRoot { tag } if tag.as_bytes() == &bytes[..4])
            );
            assert_eq!(error.to_string(), expected);
        }
        for len in 8..16 {
            let mut bytes = b"FOR8".to_vec();
            bytes.resize(len, 0);
            let error = parse_bytes(bytes).unwrap_err();
            assert!(
                matches!(error, MayaBinaryParseError::HeaderOutOfBounds { offset: 0, header_size: 16, limit } if limit == len)
            );
            assert_eq!(
                error.to_string(),
                format!("Chunk header exceeds container: offset=0x0, limit=0x{len:X}")
            );
        }
        let error = parse_bytes(b"FOR4\0\0\0\x04TEST\0".to_vec()).unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::TrailingBytes { next: 12, len: 13 }
        ));
        assert_eq!(
            error.to_string(),
            "Trailing bytes after root chunk: next=0xC, size=0xD"
        );

        #[cfg(target_pointer_width = "64")]
        {
            let error = parse_bytes(*b"FOR8\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff").unwrap_err();
            assert!(
                matches!(error, MayaBinaryParseError::PayloadOverflow { tag, offset: 0, size: usize::MAX } if tag == "FOR8")
            );
            assert_eq!(
                error.to_string(),
                "Chunk payload overflow for 'FOR8' at 0x0: size=0xFFFFFFFFFFFFFFFF"
            );
            let error = parse_bytes(*b"FOR8\0\0\0\0\0\0\0\x01\0\0\0\x10").unwrap_err();
            assert!(
                matches!(error, MayaBinaryParseError::PayloadOutOfBounds { tag, offset: 0, payload_end: 0x100000020, limit: 16 } if tag == "FOR8")
            );
            assert_eq!(
                error.to_string(),
                "Chunk payload exceeds container for 'FOR8' at 0x0: payload_end=0x100000020, limit=0x10"
            );
        }
        let error = parse_bytes(*b"FOR8\0\0\0\0\0\0\0\0\0\0\0\0").unwrap_err();
        assert!(
            matches!(error, MayaBinaryParseError::GroupTooShort { tag, offset: 0, size: 0 } if tag == "FOR8")
        );
        assert_eq!(error.to_string(), "Group 'FOR8' at 0x0 has size < 4.");
    }

    #[test]
    fn private_read_and_alignment_errors_preserve_contract() {
        let data = [0; 0xac];
        for (error, expected_field, expected_width, expected_text) in [
            (
                read_tag(&data, 0xab).unwrap_err(),
                ReadField::Tag,
                4,
                "Missing 4-byte tag at 0xAB",
            ),
            (
                read_u32be(&data, 0xab).unwrap_err(),
                ReadField::U32,
                4,
                "Missing u32 at 0xAB",
            ),
            (
                read_u64be(&data, 0xab).unwrap_err(),
                ReadField::U64,
                8,
                "Missing u64 at 0xAB",
            ),
        ] {
            assert!(
                matches!(error, MayaBinaryParseError::TruncatedRead { offset: 0xab, width, field } if width == expected_width && field == expected_field)
            );
            assert_eq!(error.to_string(), expected_text);
        }
        // Calling the private chunk parser bypasses the public parser's child-error absorption.
        let bytes = b"DATA\0\0\0\x01\0";
        let budget = MbParseBudget::default();
        let error = parse_chunk(
            bytes,
            0,
            bytes.len(),
            4,
            0,
            HeaderFormat::FourByte,
            &mut ParseBudgetState::new(&budget),
        )
        .unwrap_err();
        assert!(
            matches!(error, MayaBinaryParseError::AlignedEndOutOfBounds { tag, offset: 0, next: 12, limit: 9 } if tag == "DATA")
        );
        assert_eq!(
            error.to_string(),
            "Alignment overflow for 'DATA' at 0x0: next=0xC, limit=0x9"
        );
    }

    #[test]
    fn budget_context_preserves_messages_and_limits() {
        for (limit, context, expected) in [
            (
                MbParseBudgetLimit::MaxParseBytes,
                BudgetContext::InputBytes {
                    size: 12,
                    maximum: 8,
                    after_read: false,
                },
                "Maya Binary file exceeds parse budget: size=12 limit=8",
            ),
            (
                MbParseBudgetLimit::MaxParseBytes,
                BudgetContext::InputBytes {
                    size: 12,
                    maximum: 8,
                    after_read: true,
                },
                "Maya Binary file exceeds parse budget after read: size=12 limit=8",
            ),
            (
                MbParseBudgetLimit::MaxTotalChunks,
                BudgetContext::RootClaim { maximum: 0 },
                "Maya Binary parse budget exhausted before the root chunk.",
            ),
            (
                MbParseBudgetLimit::MaxDepth,
                BudgetContext::Depth {
                    depth: 3,
                    maximum: 2,
                },
                "Maya Binary semantic walk exceeded depth budget: depth=3 limit=2",
            ),
            (
                MbParseBudgetLimit::MaxChildrenPerGroup,
                BudgetContext::Children {
                    depth: 3,
                    maximum: 2,
                },
                "Maya Binary semantic walk exceeded child budget: depth=3 limit=2",
            ),
            (
                MbParseBudgetLimit::MaxTotalChunks,
                BudgetContext::TotalChunks { maximum: 2 },
                "Maya Binary semantic walk exceeded total chunk budget: limit=2",
            ),
        ] {
            let error = MayaBinaryParseError::BudgetExceeded { limit, context };
            for actual in [&error, &error.clone()] {
                assert_eq!(actual.to_string(), expected);
                assert_eq!(actual.budget_limit(), Some(limit));
                assert!(
                    matches!(actual, MayaBinaryParseError::BudgetExceeded { limit: actual_limit, context: actual_context } if *actual_limit == limit && *actual_context == context)
                );
            }
        }
        for (error, _) in structured_errors() {
            assert_eq!(error.budget_limit(), None);
            assert_eq!(error.clone().budget_limit(), None);
        }
        assert_eq!(
            MayaBinaryParseError::from(std::io::Error::other("Example")).budget_limit(),
            None
        );
    }

    #[test]
    fn parse_budget_order_and_partial_children_are_preserved() {
        let error = parse_bytes_with_budget(
            b"FOR8".to_vec(),
            &MbParseBudget {
                max_parse_bytes: 3,
                ..MbParseBudget::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::BudgetExceeded {
                limit: MbParseBudgetLimit::MaxParseBytes,
                context: BudgetContext::InputBytes {
                    size: 4,
                    maximum: 3,
                    after_read: true
                }
            }
        ));
        assert_eq!(
            error.to_string(),
            "Maya Binary file exceeds parse budget after read: size=4 limit=3"
        );
        let error = parse_bytes_with_budget(
            b"FOR4\0\0\0\x04TEST".to_vec(),
            &MbParseBudget {
                max_total_chunks: 0,
                ..MbParseBudget::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::BudgetExceeded {
                limit: MbParseBudgetLimit::MaxTotalChunks,
                context: BudgetContext::RootClaim { maximum: 0 }
            }
        ));
        assert_eq!(
            error.to_string(),
            "Maya Binary parse budget exhausted before the root chunk."
        );

        let malformed = parse_bytes(b"FOR4\0\0\0\x0cTESTDATA\0\0\0\x04".to_vec()).unwrap();
        assert!(!malformed.root.children_parsed);
        assert!(malformed.root.children.is_empty());

        let nested = b"FOR4\0\0\0\x18TESTFOR4\0\0\0\x0cTESTDATA\0\0\0\0";
        let parsed = parse_bytes_with_budget(
            nested.to_vec(),
            &MbParseBudget {
                max_depth: 1,
                ..MbParseBudget::default()
            },
        )
        .unwrap();
        assert!(parsed.root.children_parsed);
        assert_eq!(parsed.root.children.len(), 1);
        assert_eq!(parsed.root.children[0].tag, "FOR4");
        assert!(!parsed.root.children[0].children_parsed);
        assert!(parsed.root.children[0].children.is_empty());

        let siblings = b"FOR4\0\0\0\x14TESTDATA\0\0\0\0DATA\0\0\0\0";
        for budget in [
            MbParseBudget {
                max_children_per_group: 1,
                ..MbParseBudget::default()
            },
            MbParseBudget {
                max_total_chunks: 2,
                ..MbParseBudget::default()
            },
        ] {
            let parsed = parse_bytes_with_budget(siblings.to_vec(), &budget).unwrap();
            assert!(!parsed.root.children_parsed);
            assert_eq!(parsed.root.children.len(), 1);
            assert_eq!(parsed.root.children[0].tag, "DATA");
            assert_eq!(parsed.root.children[0].offset, 12);
        }
    }

    #[test]
    fn io_clone_shares_original_error() {
        #[derive(Debug)]
        struct ExampleError;
        impl std::fmt::Display for ExampleError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("Example")
            }
        }
        impl std::error::Error for ExampleError {}

        for original in [
            std::io::Error::from_raw_os_error(2),
            std::io::Error::other(ExampleError),
        ] {
            let expected_text = original.to_string();
            let expected_kind = original.kind();
            let expected_code = original.raw_os_error();
            let error = MayaBinaryParseError::from(original);
            let cloned = error.clone();
            let (MayaBinaryParseError::Io(first), MayaBinaryParseError::Io(second)) =
                (&error, &cloned)
            else {
                panic!("expected shared I/O errors");
            };
            assert!(Arc::ptr_eq(first, second));
            for actual in [first, second] {
                assert_eq!(actual.kind(), expected_kind);
                assert_eq!(actual.raw_os_error(), expected_code);
                assert_eq!(actual.to_string(), expected_text);
            }
            assert_eq!(error.to_string(), expected_text);
            assert_eq!(cloned.to_string(), expected_text);
        }
    }

    #[test]
    fn child_layout_is_retained_when_child_payload_is_missing() {
        let parsed = parse_bytes(b"FOR4\0\0\0\x0cTESTDATA\0\0\0\x04".to_vec()).unwrap();

        assert!(!parsed.root.children_parsed);
        assert!(parsed.root.children.is_empty());
        let layout = parsed.root.child_layout.expect("group child layout");
        assert_eq!(layout.alignment_usize(), 4);
        assert_eq!(layout.header_format(), HeaderFormat::FourByte);
    }

    #[test]
    fn nested_for8_child_layout_inherits_four_byte_header() {
        let data = b"FOR4\0\0\0\x20TESTFOR8\0\0\0\x14TESTDATA\0\0\0\x01X\0\0\0\0\0\0\0";
        let parsed = parse_bytes(data.to_vec()).unwrap();

        assert!(parsed.root.children_parsed);
        assert_eq!(parsed.root.children.len(), 1);
        let nested = &parsed.root.children[0];
        assert_eq!(nested.tag, "FOR8");
        assert_eq!(nested.form_type, Some(FourCC::new(*b"TEST")));
        let layout = nested.child_layout.expect("nested group child layout");
        assert_eq!(layout.header_format(), HeaderFormat::FourByte);
        assert_eq!(layout.alignment_usize(), 8);
        assert!(nested.children_parsed);
        assert_eq!(nested.children.len(), 1);
        assert_eq!(nested.children[0].tag, "DATA");
        assert_eq!(parsed.payload(&nested.children[0]), b"X");
    }

    #[test]
    fn child_layout_is_set_before_expansion() {
        use std::num::NonZeroUsize;

        use crate::encode_chunk;
        for (tag, form, alignment, header) in [
            (*b"FOR4", *b"TEST", 4, HeaderFormat::FourByte),
            (*b"FOR8", *b"Maya", 4, HeaderFormat::EightByte),
            (*b"FOR8", *b"TEST", 8, HeaderFormat::EightByte),
        ] {
            let layout = ChunkLayout::new(NonZeroUsize::new(alignment).unwrap(), header);
            let leaf_bytes = encode_chunk(FourCC::new(*b"DATA"), 0x11, b"X", layout).unwrap();
            let mut payload = form.to_vec();
            payload.extend_from_slice(&leaf_bytes);
            let data = encode_chunk(
                FourCC::new(tag),
                0x22,
                &payload,
                ChunkLayout::new(NonZeroUsize::new(1).unwrap(), header),
            )
            .unwrap();
            for max_depth in [0, 2] {
                let file = parse_bytes_with_budget(
                    data.clone(),
                    &MbParseBudget {
                        max_depth,
                        ..MbParseBudget::default()
                    },
                )
                .unwrap();
                let root = &file.root;
                let header_size = header.header_size();
                assert_eq!(root.tag, FourCC::new(tag));
                assert_eq!(root.offset, 0);
                assert_eq!(
                    root.aux,
                    if header == HeaderFormat::FourByte {
                        0
                    } else {
                        0x22
                    }
                );
                assert_eq!(root.size, payload.len());
                assert_eq!(root.payload_offset, header_size);
                assert_eq!(root.payload_end, data.len());
                assert_eq!(root.form_type, Some(FourCC::new(form)));
                assert_eq!(root.child_layout, Some(layout));
                assert_eq!(root.children_parsed, max_depth != 0);
                assert_eq!(root.children.len(), usize::from(max_depth != 0));
                assert_eq!(file.payload(root), payload);
                if max_depth != 0 {
                    let leaf = &root.children[0];
                    assert_eq!(leaf.tag, "DATA");
                    assert_eq!(leaf.offset, header_size + 4);
                    assert_eq!(
                        leaf.aux,
                        if header == HeaderFormat::FourByte {
                            0
                        } else {
                            0x11
                        }
                    );
                    assert_eq!(leaf.size, 1);
                    assert_eq!(leaf.payload_offset, header_size * 2 + 4);
                    assert_eq!(leaf.payload_end, header_size * 2 + 5);
                    assert_eq!(leaf.form_type, None);
                    assert_eq!(leaf.child_layout, None);
                    assert!(!leaf.children_parsed);
                    assert!(leaf.children.is_empty());
                    assert_eq!(file.payload(leaf), b"X");
                }
            }
        }
    }
}
