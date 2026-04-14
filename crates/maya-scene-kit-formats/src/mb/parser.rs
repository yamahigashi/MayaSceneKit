use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use thiserror::Error;

use crate::mb::layout::{
    EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE, header_size_to_width, is_group_chunk_tag,
    resolve_parser_group_layout,
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

#[derive(Debug, Error)]
pub enum MayaBinaryParseError {
    #[error("{message}")]
    BudgetExceeded {
        limit: MbParseBudgetLimit,
        message: String,
    },
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Clone for MayaBinaryParseError {
    fn clone(&self) -> Self {
        match self {
            Self::BudgetExceeded { limit, message } => Self::BudgetExceeded {
                limit: *limit,
                message: message.clone(),
            },
            Self::Message(message) => Self::Message(message.clone()),
            Self::Io(err) => Self::Io(std::io::Error::new(err.kind(), err.to_string())),
        }
    }
}

impl MayaBinaryParseError {
    pub fn budget_limit(&self) -> Option<MbParseBudgetLimit> {
        match self {
            Self::BudgetExceeded { limit, .. } => Some(*limit),
            Self::Message(_) | Self::Io(_) => None,
        }
    }

    pub(crate) fn max_parse_bytes_exceeded(size: usize, limit: usize, after_read: bool) -> Self {
        let message = if after_read {
            format!("Maya Binary file exceeds parse budget after read: size={size} limit={limit}")
        } else {
            format!("Maya Binary file exceeds parse budget: size={size} limit={limit}")
        };
        Self::BudgetExceeded {
            limit: MbParseBudgetLimit::MaxParseBytes,
            message,
        }
    }

    pub(crate) fn semantic_walk_budget_exceeded(
        limit: MbParseBudgetLimit,
        message: String,
    ) -> Self {
        Self::BudgetExceeded { limit, message }
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

#[derive(Debug, Clone)]
pub struct Chunk {
    pub tag: String,
    pub offset: usize,
    pub aux: u32,
    pub size: usize,
    pub payload_offset: usize,
    pub payload_end: usize,
    pub form_type: Option<String>,
    pub child_alignment: Option<usize>,
    pub child_header_size: Option<usize>,
    pub children_parsed: bool,
    pub children: Vec<Chunk>,
}

impl Chunk {
    pub fn is_group(&self) -> bool {
        is_group_chunk_tag(self.tag.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct MayaBinaryFile {
    pub path: Option<PathBuf>,
    pub data: Arc<[u8]>,
    pub root: Chunk,
}

impl MayaBinaryFile {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkHeaderFormat {
    FourByte,
    EightByte,
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
        return Err(MayaBinaryParseError::max_parse_bytes_exceeded(
            file_size,
            budget.max_parse_bytes,
            false,
        ));
    }
    let data: Arc<[u8]> = fs::read(p)?.into();
    if data.len() > budget.max_parse_bytes {
        return Err(MayaBinaryParseError::max_parse_bytes_exceeded(
            data.len(),
            budget.max_parse_bytes,
            true,
        ));
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
        return Err(MayaBinaryParseError::max_parse_bytes_exceeded(
            data.len(),
            budget.max_parse_bytes,
            true,
        ));
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
        return Err(MayaBinaryParseError::Message(
            "File is too small to be a Maya Binary stream.".to_string(),
        ));
    }
    let root_tag = read_tag(data, 0)?;
    let root_format = match root_tag.as_str() {
        "FOR4" => ChunkHeaderFormat::FourByte,
        "FOR8" => ChunkHeaderFormat::EightByte,
        _ => {
            return Err(MayaBinaryParseError::Message(format!(
                "Unexpected root chunk '{root_tag}'."
            )));
        }
    };
    let mut state = ParseBudgetState::new(budget);
    let ParseChunkStatus::Parsed((root, next)) =
        parse_chunk(data, 0, data.len(), 1, 0, root_format, &mut state)?
    else {
        return Err(MayaBinaryParseError::semantic_walk_budget_exceeded(
            MbParseBudgetLimit::MaxTotalChunks,
            "Maya Binary parse budget exhausted before the root chunk.".to_string(),
        ));
    };
    if root.tag != "FOR4" && root.tag != "FOR8" {
        return Err(MayaBinaryParseError::Message(format!(
            "Unexpected root chunk '{}'.",
            root.tag
        )));
    }
    if next != data.len() {
        return Err(MayaBinaryParseError::Message(format!(
            "Trailing bytes after root chunk: next=0x{next:X}, size=0x{:X}",
            data.len()
        )));
    }
    Ok(root)
}

fn parse_chunk(
    data: &[u8],
    offset: usize,
    limit: usize,
    sibling_alignment: usize,
    depth: usize,
    header_format: ChunkHeaderFormat,
    state: &mut ParseBudgetState<'_>,
) -> Result<ParseChunkStatus, MayaBinaryParseError> {
    if !state.claim_chunk() {
        return Ok(ParseChunkStatus::BudgetExhausted);
    }
    let hdr_size = header_size(header_format);
    if offset + hdr_size > limit {
        return Err(MayaBinaryParseError::Message(format!(
            "Chunk header exceeds container: offset=0x{offset:X}, limit=0x{limit:X}"
        )));
    }

    let tag = read_tag(data, offset)?;
    let (aux, size, payload_offset) = match header_format {
        ChunkHeaderFormat::FourByte => (
            0,
            read_u32be(data, offset + 4)? as usize,
            offset + FOUR_BYTE_HEADER_SIZE,
        ),
        ChunkHeaderFormat::EightByte => (
            read_u32be(data, offset + 4)?,
            read_u64be(data, offset + 8)? as usize,
            offset + EIGHT_BYTE_HEADER_SIZE,
        ),
    };
    let payload_end = payload_offset.checked_add(size).ok_or_else(|| {
        MayaBinaryParseError::Message(format!(
            "Chunk payload overflow for '{tag}' at 0x{offset:X}: size=0x{size:X}"
        ))
    })?;
    if payload_end > limit {
        return Err(MayaBinaryParseError::Message(format!(
            "Chunk payload exceeds container for '{tag}' at 0x{offset:X}: payload_end=0x{payload_end:X}, limit=0x{limit:X}"
        )));
    }

    let mut form_type = None;
    let mut children_parsed = false;
    let mut children = Vec::new();

    let mut child_alignment_resolved: Option<usize> = None;
    let mut child_header_size_resolved: Option<usize> = None;
    if is_group_chunk_tag(&tag) {
        if size < 4 {
            return Err(MayaBinaryParseError::Message(format!(
                "Group '{tag}' at 0x{offset:X} has size < 4."
            )));
        }
        form_type = Some(read_tag(data, payload_offset)?);
        let (preferred_alignment, preferred_header_size) =
            resolve_parser_group_layout(&tag, form_type.as_deref(), header_size(header_format));
        let preferred_header =
            header_format_from_size(preferred_header_size).unwrap_or(header_format);
        child_alignment_resolved = Some(preferred_alignment);
        child_header_size_resolved = Some(preferred_header_size);

        if should_expand_group(depth, state.budget) {
            if let Ok(parsed) = parse_children_with_format(
                data,
                payload_offset + 4,
                payload_end,
                depth + 1,
                preferred_alignment,
                preferred_header,
                state,
            ) {
                children = parsed.children;
                children_parsed = parsed.complete;
            }
        }
    }

    let aligned_size = align(size, sibling_alignment);
    let next_offset = payload_offset.checked_add(aligned_size).ok_or_else(|| {
        MayaBinaryParseError::Message(format!(
            "Alignment overflow for '{tag}' at 0x{offset:X}: payload_offset=0x{payload_offset:X}, aligned_size=0x{aligned_size:X}"
        ))
    })?;
    if next_offset > limit {
        return Err(MayaBinaryParseError::Message(format!(
            "Alignment overflow for '{tag}' at 0x{offset:X}: next=0x{next_offset:X}, limit=0x{limit:X}"
        )));
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
            child_alignment: child_alignment_resolved,
            child_header_size: child_header_size_resolved,
            children_parsed,
            children,
        },
        next_offset,
    )))
}

fn header_size(header_format: ChunkHeaderFormat) -> usize {
    match header_format {
        ChunkHeaderFormat::FourByte => FOUR_BYTE_HEADER_SIZE,
        ChunkHeaderFormat::EightByte => EIGHT_BYTE_HEADER_SIZE,
    }
}

fn header_format_from_size(size: usize) -> Option<ChunkHeaderFormat> {
    match header_size_to_width(size) {
        Some(4) => Some(ChunkHeaderFormat::FourByte),
        Some(8) => Some(ChunkHeaderFormat::EightByte),
        _ => None,
    }
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

fn read_tag(data: &[u8], offset: usize) -> Result<String, MayaBinaryParseError> {
    let raw = data.get(offset..offset + 4).ok_or_else(|| {
        MayaBinaryParseError::Message(format!("Missing 4-byte tag at 0x{offset:X}"))
    })?;
    if raw.iter().all(|b| (32..=126).contains(b)) {
        return Ok(raw.iter().map(|b| *b as char).collect());
    }
    Ok(format!(
        "[{:02X}{:02X}{:02X}{:02X}]",
        raw[0], raw[1], raw[2], raw[3]
    ))
}

fn read_u32be(data: &[u8], offset: usize) -> Result<u32, MayaBinaryParseError> {
    let raw = data
        .get(offset..offset + 4)
        .ok_or_else(|| MayaBinaryParseError::Message(format!("Missing u32 at 0x{offset:X}")))?;
    let mut a = [0u8; 4];
    a.copy_from_slice(raw);
    Ok(u32::from_be_bytes(a))
}

fn read_u64be(data: &[u8], offset: usize) -> Result<u64, MayaBinaryParseError> {
    let raw = data
        .get(offset..offset + 8)
        .ok_or_else(|| MayaBinaryParseError::Message(format!("Missing u64 at 0x{offset:X}")))?;
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
    header_format: ChunkHeaderFormat,
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
        return Err(MayaBinaryParseError::Message(format!(
            "Children ended at 0x{cursor:X} but expected 0x{end:X}"
        )));
    }
    Ok(ParseChildrenResult { children, complete })
}
