use crate::mb::{
    ByteSpan,
    defaults::{default_alignment_for_header_size, default_header_size_for_alignment},
    layout::{EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionHeaderFormat {
    FourByte,
    EightByte,
}

impl SectionHeaderFormat {
    fn from_header_size(header_size: Option<usize>) -> Option<Self> {
        match header_size {
            Some(FOUR_BYTE_HEADER_SIZE) => Some(SectionHeaderFormat::FourByte),
            Some(EIGHT_BYTE_HEADER_SIZE) => Some(SectionHeaderFormat::EightByte),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SectionLayout {
    pub(crate) alignment: usize,
    pub(crate) header_format: SectionHeaderFormat,
    pub(crate) consumed: usize,
}

#[derive(Debug, Clone)]
pub struct SectionChunk {
    pub tag: String,
    pub aux: u32,
    pub payload_span: ByteSpan,
    pub chunk_start: usize,
    pub chunk_end: usize,
}

impl SectionChunk {
    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        self.payload_span.slice(data)
    }

    pub(crate) fn offset_spans(&mut self, base: usize) {
        self.payload_span = self.payload_span.offset(base);
    }
}

#[derive(Debug, Clone)]
pub struct ParsedSection {
    pub chunks: Vec<SectionChunk>,
    pub(crate) layout: SectionLayout,
    pub tail_span: ByteSpan,
}

impl ParsedSection {
    pub fn tail<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        self.tail_span.slice(data)
    }
}

pub fn parse_section_chunks_with_hints(
    data: &[u8],
    alignment_hint: Option<usize>,
    header_size_hint: Option<usize>,
) -> ParsedSection {
    parse_section_chunks_full_with_hints(data, alignment_hint, header_size_hint)
}

pub(crate) fn parse_section_chunks_full_with_hints(
    data: &[u8],
    alignment_hint: Option<usize>,
    header_size_hint: Option<usize>,
) -> ParsedSection {
    if let Some(alignment) = normalize_alignment(alignment_hint) {
        let header_format = SectionHeaderFormat::from_header_size(header_size_hint)
            .unwrap_or_else(|| default_header_format_for_alignment(alignment));
        return parse_section_chunks_with_layout(data, alignment, header_format);
    }
    if let Some(header_format) = SectionHeaderFormat::from_header_size(header_size_hint) {
        let alignment = default_alignment_for_header_format(header_format);
        return parse_section_chunks_with_layout(data, alignment, header_format);
    }

    ParsedSection {
        chunks: Vec::new(),
        layout: SectionLayout {
            alignment: 0,
            header_format: SectionHeaderFormat::EightByte,
            consumed: 0,
        },
        tail_span: ByteSpan::new(0, data.len()),
    }
}

fn parse_section_chunks_with_layout(
    data: &[u8],
    alignment: usize,
    header_format: SectionHeaderFormat,
) -> ParsedSection {
    let mut chunks = Vec::new();
    let mut cursor = 0usize;
    let data_len = data.len();
    let header_size = section_header_size(header_format);
    let size_offset = match header_format {
        SectionHeaderFormat::FourByte => 4,
        SectionHeaderFormat::EightByte => 8,
    };

    while cursor + header_size <= data_len {
        let tag_bytes = &data[cursor..cursor + 4];
        if !tag_bytes.iter().all(|b| (32..=126).contains(b)) {
            break;
        }
        let aux = if header_format == SectionHeaderFormat::EightByte {
            u32::from_be_bytes(data[cursor + 4..cursor + 8].try_into().unwrap())
        } else {
            0
        };
        let size = match header_format {
            SectionHeaderFormat::FourByte => u32::from_be_bytes(
                data[cursor + size_offset..cursor + size_offset + 4]
                    .try_into()
                    .unwrap(),
            ) as usize,
            SectionHeaderFormat::EightByte => u64::from_be_bytes(
                data[cursor + size_offset..cursor + size_offset + 8]
                    .try_into()
                    .unwrap(),
            ) as usize,
        };
        let payload_start = cursor + header_size;
        let Some(payload_end) = payload_start.checked_add(size) else {
            break;
        };
        if payload_end > data_len {
            break;
        }

        let step = align(header_size + size, alignment);
        let Some(mut next_cursor) = cursor.checked_add(step) else {
            break;
        };
        if next_cursor <= cursor {
            break;
        }
        if next_cursor > data_len {
            next_cursor = payload_end;
        }

        chunks.push(SectionChunk {
            tag: String::from_utf8_lossy(tag_bytes).to_string(),
            aux,
            payload_span: ByteSpan::new(payload_start, payload_end),
            chunk_start: cursor,
            chunk_end: next_cursor,
        });
        cursor = next_cursor;
    }

    ParsedSection {
        chunks,
        layout: SectionLayout {
            alignment,
            header_format,
            consumed: cursor,
        },
        tail_span: ByteSpan::new(cursor, data_len),
    }
}

fn section_header_size(header_format: SectionHeaderFormat) -> usize {
    match header_format {
        SectionHeaderFormat::FourByte => FOUR_BYTE_HEADER_SIZE,
        SectionHeaderFormat::EightByte => EIGHT_BYTE_HEADER_SIZE,
    }
}

fn normalize_alignment(alignment_hint: Option<usize>) -> Option<usize> {
    match alignment_hint {
        Some(0) | None => None,
        Some(alignment) => Some(alignment),
    }
}

fn default_header_format_for_alignment(alignment: usize) -> SectionHeaderFormat {
    if default_header_size_for_alignment(alignment) == EIGHT_BYTE_HEADER_SIZE {
        SectionHeaderFormat::EightByte
    } else {
        SectionHeaderFormat::FourByte
    }
}

fn default_alignment_for_header_format(header_format: SectionHeaderFormat) -> usize {
    default_alignment_for_header_size(section_header_size(header_format))
}

fn align(v: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return v;
    }
    let rem = v % alignment;
    if rem == 0 { v } else { v + (alignment - rem) }
}
