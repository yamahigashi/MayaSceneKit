use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MayaBinaryParseError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
    pub children_parsed: bool,
    pub children: Vec<Chunk>,
}

impl Chunk {
    pub fn is_group(&self) -> bool {
        matches!(
            self.tag.as_str(),
            "FOR4" | "FOR8" | "CAT4" | "CAT8" | "LIS4" | "LIS8"
        )
    }
}

#[derive(Debug, Clone)]
pub struct MayaBinaryFile {
    pub path: Option<PathBuf>,
    pub data: Vec<u8>,
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

pub fn parse_file(path: impl AsRef<Path>) -> Result<MayaBinaryFile, MayaBinaryParseError> {
    let p = path.as_ref();
    let data = fs::read(p)?;
    let root = parse_stream(&data)?;
    Ok(MayaBinaryFile {
        path: Some(p.to_path_buf()),
        data,
        root,
    })
}

fn parse_stream(data: &[u8]) -> Result<Chunk, MayaBinaryParseError> {
    if data.len() < 16 {
        return Err(MayaBinaryParseError::Message(
            "File is too small to be a Maya Binary stream.".to_string(),
        ));
    }
    let (root, next) = parse_chunk(data, 0, data.len(), 1, 0)?;
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
) -> Result<(Chunk, usize), MayaBinaryParseError> {
    if offset + 16 > limit {
        return Err(MayaBinaryParseError::Message(format!(
            "Chunk header exceeds container: offset=0x{offset:X}, limit=0x{limit:X}"
        )));
    }

    let tag = read_tag(data, offset)?;
    let aux = read_u32be(data, offset + 4)?;
    let size = read_u64be(data, offset + 8)? as usize;
    let payload_offset = offset + 16;
    let payload_end = payload_offset + size;
    if payload_end > limit {
        return Err(MayaBinaryParseError::Message(format!(
            "Chunk payload exceeds container for '{tag}' at 0x{offset:X}: payload_end=0x{payload_end:X}, limit=0x{limit:X}"
        )));
    }

    let mut form_type = None;
    let mut children_parsed = false;
    let mut children = Vec::new();

    if is_group_tag(&tag) {
        if size < 4 {
            return Err(MayaBinaryParseError::Message(format!(
                "Group '{tag}' at 0x{offset:X} has size < 4."
            )));
        }
        form_type = Some(read_tag(data, payload_offset)?);
        if should_expand_group(depth, form_type.as_deref()) {
            let child_alignment = child_alignment(&tag, form_type.as_deref());
            let mut cursor = payload_offset + 4;
            while cursor < payload_end {
                let (child, next_cursor) =
                    parse_chunk(data, cursor, payload_end, child_alignment, depth + 1)?;
                children.push(child);
                cursor = next_cursor;
            }
            if cursor != payload_end {
                return Err(MayaBinaryParseError::Message(format!(
                    "Children of '{tag}' at 0x{offset:X} ended at 0x{cursor:X} but expected 0x{payload_end:X}"
                )));
            }
            children_parsed = true;
        }
    }

    let next_offset = payload_offset + align(size, sibling_alignment);
    if next_offset > limit {
        return Err(MayaBinaryParseError::Message(format!(
            "Alignment overflow for '{tag}' at 0x{offset:X}: next=0x{next_offset:X}, limit=0x{limit:X}"
        )));
    }

    Ok((
        Chunk {
            tag,
            offset,
            aux,
            size,
            payload_offset,
            payload_end,
            form_type,
            children_parsed,
            children,
        },
        next_offset,
    ))
}

fn should_expand_group(depth: usize, form_type: Option<&str>) -> bool {
    if depth == 0 {
        return true;
    }
    depth == 1 && form_type == Some("HEAD")
}

fn child_alignment(tag: &str, form_type: Option<&str>) -> usize {
    if tag.ends_with('8') {
        if form_type == Some("Maya") {
            return 4;
        }
        return 8;
    }
    4
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
    Ok(raw
        .iter()
        .map(|b| {
            if (32..=126).contains(b) {
                *b as char
            } else {
                '.'
            }
        })
        .collect())
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

fn is_group_tag(tag: &str) -> bool {
    matches!(tag, "FOR4" | "FOR8" | "CAT4" | "CAT8" | "LIS4" | "LIS8")
}
