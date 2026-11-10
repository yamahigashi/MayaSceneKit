use crate::{
    ByteSpan, ChunkLayout, FourCC, LayoutHints,
    defaults::{
        EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE, default_alignment_for_header_format,
        default_header_format_for_alignment,
    },
};

/// The size-field width of a chunk header, independent of its alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderFormat {
    /// Four-byte size field in an 8-byte header.
    FourByte,
    /// Eight-byte size field in a 16-byte header, including FOR8/Maya.
    EightByte,
}

impl HeaderFormat {
    /// Returns the full header size, including tag and auxiliary fields.
    pub const fn header_size(self) -> usize {
        match self {
            HeaderFormat::FourByte => FOUR_BYTE_HEADER_SIZE,
            HeaderFormat::EightByte => EIGHT_BYTE_HEADER_SIZE,
        }
    }
    /// Accepts only full header sizes 8 and 16.
    pub const fn from_header_size(header_size: usize) -> Option<Self> {
        match header_size {
            FOUR_BYTE_HEADER_SIZE => Some(HeaderFormat::FourByte),
            EIGHT_BYTE_HEADER_SIZE => Some(HeaderFormat::EightByte),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SectionLayout {
    pub(crate) alignment: usize,
    pub(crate) header_format: HeaderFormat,
    pub(crate) consumed: usize,
}

/// A section parse result whose fields cannot be constructed or modified externally.
#[derive(Debug, Clone)]
pub struct SectionChunk {
    pub(crate) tag: FourCC,
    pub(crate) aux: u32,
    pub(crate) payload_span: ByteSpan,
    pub(crate) chunk_start: usize,
    pub(crate) chunk_end: usize,
}

impl SectionChunk {
    /// The original chunk tag.
    pub fn tag(&self) -> FourCC {
        self.tag
    }

    /// The auxiliary header value.
    pub fn aux(&self) -> u32 {
        self.aux
    }

    /// The payload span relative to the section buffer supplied to the parser.
    /// Raw walks and visits adjust this span to their top-level input buffer.
    /// It is file-absolute only when the caller adds the file base.
    pub fn payload_span(&self) -> ByteSpan {
        self.payload_span
    }

    /// The header start relative to the section buffer that directly scanned this chunk.
    /// Nested raw walks do not adjust this offset to the parent buffer.
    pub fn chunk_start(&self) -> usize {
        self.chunk_start
    }

    /// The exclusive consumed end, including existing padding, relative to the
    /// section buffer that directly scanned this chunk. Nested raw walks do
    /// not adjust this offset to the parent buffer.
    pub fn chunk_end(&self) -> usize {
        self.chunk_end
    }

    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        self.payload_span.slice(data)
    }

    pub(crate) fn offset_spans(&mut self, base: usize) {
        self.payload_span = self.payload_span.offset(base);
    }
}

/// A section parse result whose fields cannot be constructed or modified externally.
#[derive(Debug, Clone)]
pub struct ParsedSection {
    pub(crate) chunks: Vec<SectionChunk>,
    pub(crate) layout: SectionLayout,
    pub(crate) tail_span: ByteSpan,
}

impl ParsedSection {
    /// Returns the scanned chunks in their original order.
    pub fn chunks(&self) -> &[SectionChunk] {
        &self.chunks
    }

    /// Consumes the section and returns its scanned chunks in original order.
    pub fn into_chunks(self) -> Vec<SectionChunk> {
        self.chunks
    }

    /// Returns the unscanned tail's half-open span relative to the section input.
    /// With unspecified layout hints, this is the entire input buffer.
    pub fn tail_span(&self) -> ByteSpan {
        self.tail_span
    }

    pub fn tail<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        self.tail_span.slice(data)
    }
}

/// Scans a section using independent layout hints.
/// With neither hint specified, returns the whole input as tail. A missing
/// component is derived from the supplied nonzero alignment or header format.
pub fn parse_section_chunks_with_hints(data: &[u8], hints: LayoutHints) -> ParsedSection {
    if let Some(alignment) = hints.alignment() {
        let header_format = hints
            .header_format()
            .unwrap_or_else(|| default_header_format_for_alignment(alignment));
        return parse_section_chunks_with_layout(data, ChunkLayout::new(alignment, header_format));
    }
    if let Some(header_format) = hints.header_format() {
        let alignment = default_alignment_for_header_format(header_format);
        return parse_section_chunks_with_layout(data, ChunkLayout::new(alignment, header_format));
    }

    ParsedSection {
        chunks: Vec::new(),
        layout: SectionLayout {
            alignment: 0,
            header_format: HeaderFormat::EightByte,
            consumed: 0,
        },
        tail_span: ByteSpan::new(0, data.len()),
    }
}

fn parse_section_chunks_with_layout(data: &[u8], layout: ChunkLayout) -> ParsedSection {
    let alignment = layout.alignment_usize();
    let header_format = layout.header_format();
    let mut chunks = Vec::new();
    let mut cursor = 0usize;
    let data_len = data.len();
    let header_size = header_format.header_size();
    let size_offset = match header_format {
        HeaderFormat::FourByte => 4,
        HeaderFormat::EightByte => 8,
    };

    while cursor + header_size <= data_len {
        let tag_bytes = &data[cursor..cursor + 4];
        if !tag_bytes.iter().all(|b| (32..=126).contains(b)) {
            break;
        }
        let aux = if header_format == HeaderFormat::EightByte {
            u32::from_be_bytes(data[cursor + 4..cursor + 8].try_into().unwrap())
        } else {
            0
        };
        let size = match header_format {
            HeaderFormat::FourByte => u32::from_be_bytes(
                data[cursor + size_offset..cursor + size_offset + 4]
                    .try_into()
                    .unwrap(),
            ) as usize,
            HeaderFormat::EightByte => u64::from_be_bytes(
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
            if payload_end != data_len {
                break;
            }
            next_cursor = payload_end;
        }

        chunks.push(SectionChunk {
            tag: FourCC::new(
                tag_bytes
                    .try_into()
                    .expect("slice is 4 bytes by construction"),
            ),
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

fn align(v: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return v;
    }
    let rem = v % alignment;
    if rem == 0 { v } else { v + (alignment - rem) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_section_accessors_preserve_chunks_and_tail() {
        let mut data = b"DATA\x11\x22\x33\x44\0\0\0\0\0\0\0\x01A\0\0\0\0\0\0\0".to_vec();
        data.extend_from_slice(b"TEST\x55\x66\x77\x88\0\0\0\0\0\0\0\x02BC\0\0\0\0\0\0");
        data.extend_from_slice(b"end");
        let parsed = parse_section_chunks_with_hints(
            &data,
            LayoutHints::new().with_header_format(HeaderFormat::EightByte),
        );
        let chunk_getters = |chunk: &SectionChunk| {
            (
                chunk.tag(),
                chunk.aux(),
                chunk.payload_span(),
                chunk.chunk_start(),
                chunk.chunk_end(),
            )
        };
        let borrowed = parsed
            .chunks()
            .iter()
            .map(chunk_getters)
            .collect::<Vec<_>>();
        assert_eq!(
            borrowed,
            vec![
                (
                    FourCC::new(*b"DATA"),
                    0x11223344,
                    ByteSpan::new(16, 17),
                    0,
                    24
                ),
                (
                    FourCC::new(*b"TEST"),
                    0x55667788,
                    ByteSpan::new(40, 42),
                    24,
                    48
                ),
            ]
        );
        let tail_span = parsed.tail_span();
        assert_eq!(tail_span, ByteSpan::new(48, 51));
        assert_eq!(parsed.tail(&data), tail_span.slice(&data));
        assert_eq!(parsed.tail(&data), b"end");
        let owned = parsed.into_chunks();
        assert_eq!(
            owned.iter().map(chunk_getters).collect::<Vec<_>>(),
            borrowed
        );
    }

    #[test]
    fn header_format_numeric_boundary() {
        const FOUR: Option<HeaderFormat> = HeaderFormat::from_header_size(8);
        const EIGHT: Option<HeaderFormat> = HeaderFormat::from_header_size(16);
        const FOUR_SIZE: usize = HeaderFormat::FourByte.header_size();
        const EIGHT_SIZE: usize = HeaderFormat::EightByte.header_size();
        assert_eq!(FOUR, Some(HeaderFormat::FourByte));
        assert_eq!(EIGHT, Some(HeaderFormat::EightByte));
        assert_eq!(FOUR_SIZE, 8);
        assert_eq!(EIGHT_SIZE, 16);
        assert_eq!(FOUR.unwrap().header_size(), 8);
        assert_eq!(EIGHT.unwrap().header_size(), 16);
        for size in [0, 12, 20, 24, usize::MAX] {
            assert_eq!(HeaderFormat::from_header_size(size), None);
        }
    }

    #[test]
    fn section_hints_preserve_scan_and_tail() {
        let data = b"DATA\0\0\0\x01X\0\0\0";
        let unspecified = parse_section_chunks_with_hints(data, LayoutHints::default());
        assert!(unspecified.chunks.is_empty());
        assert_eq!(unspecified.tail_span, ByteSpan::new(0, 12));
        assert_eq!(unspecified.tail(data), data);
        assert_eq!(unspecified.layout.alignment, 0);
        assert_eq!(unspecified.layout.consumed, 0);
        assert_eq!(unspecified.layout.header_format, HeaderFormat::EightByte);

        for hints in [
            LayoutHints::new().with_header_format(HeaderFormat::FourByte),
            LayoutHints::from_numeric(Some(0), Some(8)),
        ] {
            let parsed = parse_section_chunks_with_hints(data, hints);
            assert_eq!(parsed.chunks.len(), 1);
            let chunk = &parsed.chunks[0];
            assert_eq!(chunk.tag, "DATA");
            assert_eq!(chunk.aux, 0);
            assert_eq!(chunk.payload_span, ByteSpan::new(8, 9));
            assert_eq!((chunk.chunk_start, chunk.chunk_end), (0, 12));
            assert_eq!(parsed.layout.alignment, 4);
            assert_eq!(parsed.layout.header_format, HeaderFormat::FourByte);
            assert_eq!(parsed.layout.consumed, 12);
            assert_eq!(parsed.tail_span, ByteSpan::new(12, 12));
        }
        for hints in [
            LayoutHints::from_numeric(Some(3), None),
            LayoutHints::from_numeric(Some(3), Some(24)),
        ] {
            let parsed = parse_section_chunks_with_hints(data, hints);
            assert_eq!(parsed.chunks.len(), 1);
            let chunk = &parsed.chunks[0];
            assert_eq!(chunk.payload_span, ByteSpan::new(8, 9));
            assert_eq!((chunk.chunk_start, chunk.chunk_end), (0, 9));
            assert_eq!(parsed.layout.alignment, 3);
            assert_eq!(parsed.layout.header_format, HeaderFormat::FourByte);
            assert_eq!(parsed.layout.consumed, 9);
            assert_eq!(parsed.tail_span, ByteSpan::new(9, 12));
            assert_eq!(parsed.tail(data), &[0, 0, 0]);
        }
        for malformed in [
            b"\x00ABC\0\0\0\0".as_slice(),
            b"DATA\0\0\0",
            b"DATA\0\0\0\x09X",
        ] {
            let hints = LayoutHints::new().with_header_format(HeaderFormat::FourByte);
            let parsed = parse_section_chunks_with_hints(malformed, hints);
            assert!(parsed.chunks.is_empty());
            assert_eq!(parsed.tail_span, ByteSpan::new(0, malformed.len()));
            let mut after_chunk = data.to_vec();
            after_chunk.extend_from_slice(malformed);
            let parsed = parse_section_chunks_with_hints(&after_chunk, hints);
            assert_eq!(parsed.chunks.len(), 1);
            assert_eq!(parsed.layout.consumed, 12);
            assert_eq!(parsed.tail_span, ByteSpan::new(12, after_chunk.len()));
            assert_eq!(parsed.tail(&after_chunk), malformed);
        }
    }
}
