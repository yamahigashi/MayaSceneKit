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

    /// Returns whether every input byte was consumed.
    pub fn state(&self) -> MbSectionScanState {
        MbSectionScanState::from_tail(self.tail_span.len())
    }

    /// Consumes both the scanned prefix and its completion state.
    pub fn into_parts(self) -> (Vec<SectionChunk>, MbSectionScanState) {
        let state = self.state();
        (self.chunks, state)
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

/// Completion of a bounded section scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[must_use = "inspect the section scan state before accepting a partial result"]
pub enum MbSectionScanState {
    #[default]
    Complete,
    Stopped,
}

impl MbSectionScanState {
    pub fn merge(&mut self, other: Self) {
        if other == Self::Stopped {
            *self = other;
        }
    }

    fn from_tail(len: usize) -> Self {
        if len == 0 {
            Self::Complete
        } else {
            Self::Stopped
        }
    }
}

pub(crate) fn accept_chunk_tag(raw: &[u8]) -> Option<FourCC> {
    Some(FourCC::new(raw.get(..4)?.try_into().ok()?))
}

/// Scans a section with the default parsing budget.
pub fn parse_section_chunks_with_hints(data: &[u8], hints: LayoutHints) -> ParsedSection {
    parse_section_chunks_with_hints_with_budget(data, hints, &crate::MbParseBudget::default())
}

/// Scans a bounded prefix, leaving unconsumed bytes in the tail.
pub fn parse_section_chunks_with_hints_with_budget(
    data: &[u8],
    hints: LayoutHints,
    budget: &crate::MbParseBudget,
) -> ParsedSection {
    let mut cursor = SectionCursor::new(data, hints);
    let mut chunks = Vec::new();
    if data.len() <= budget.max_parse_bytes {
        while chunks.len() < budget.max_children_per_group && chunks.len() < budget.max_total_chunks
        {
            let Some(chunk) = cursor.next() else {
                break;
            };
            chunks.push(chunk);
        }
    }
    ParsedSection {
        chunks,
        layout: SectionLayout {
            alignment: cursor.layout.map_or(0, |l| l.alignment_usize()),
            header_format: cursor
                .layout
                .map_or(HeaderFormat::EightByte, |l| l.header_format()),
            consumed: cursor.offset,
        },
        tail_span: ByteSpan::new(cursor.offset, data.len()),
    }
}

pub(crate) struct SectionCursor<'a> {
    data: &'a [u8],
    layout: Option<ChunkLayout>,
    offset: usize,
}

impl<'a> SectionCursor<'a> {
    pub(crate) fn new(data: &'a [u8], hints: LayoutHints) -> Self {
        let layout = if let Some(alignment) = hints.alignment() {
            Some(ChunkLayout::new(
                alignment,
                hints
                    .header_format()
                    .unwrap_or_else(|| default_header_format_for_alignment(alignment)),
            ))
        } else {
            hints
                .header_format()
                .map(|header| ChunkLayout::new(default_alignment_for_header_format(header), header))
        };
        Self {
            data,
            layout,
            offset: 0,
        }
    }

    pub(crate) fn state(&self) -> MbSectionScanState {
        MbSectionScanState::from_tail(self.data.len() - self.offset)
    }

    pub(crate) fn next(&mut self) -> Option<SectionChunk> {
        let chunk = parse_section_chunks_with_layout(self.data, self.offset, self.layout?)?;
        self.offset = chunk.chunk_end;
        Some(chunk)
    }
}

fn parse_section_chunks_with_layout(
    data: &[u8],
    cursor: usize,
    layout: ChunkLayout,
) -> Option<SectionChunk> {
    let header_format = layout.header_format();
    let header_size = header_format.header_size();
    let payload_start = cursor.checked_add(header_size)?;
    let header = data.get(cursor..payload_start)?;
    let tag = accept_chunk_tag(header)?;
    let (aux, size) = match header_format {
        HeaderFormat::FourByte => (
            0,
            u32::from_be_bytes(header[4..8].try_into().ok()?) as usize,
        ),
        HeaderFormat::EightByte => (
            u32::from_be_bytes(header[4..8].try_into().ok()?),
            u64::from_be_bytes(header[8..16].try_into().ok()?) as usize,
        ),
    };
    let payload_end = payload_start.checked_add(size)?;
    if payload_end > data.len() {
        return None;
    }
    let length = header_size.checked_add(size)?;
    let alignment = layout.alignment_usize();
    let padding = (alignment - length % alignment) % alignment;
    let mut chunk_end = cursor.checked_add(length.checked_add(padding)?)?;
    if chunk_end > data.len() {
        if payload_end != data.len() {
            return None;
        }
        chunk_end = payload_end;
    }
    Some(SectionChunk {
        tag,
        aux,
        payload_span: ByteSpan::new(payload_start, payload_end),
        chunk_start: cursor,
        chunk_end,
    })
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
        let (owned, state) = parsed.into_parts();
        assert_eq!(state, MbSectionScanState::Stopped);
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
            assert_eq!(parsed.state(), MbSectionScanState::Complete);
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
            assert_eq!(parsed.state(), MbSectionScanState::Stopped);
        }
        let hints = LayoutHints::new().with_header_format(HeaderFormat::FourByte);
        let nonprintable = b"\x00ABC\0\0\0\0";
        for prefix in [&[][..], data.as_slice()] {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(nonprintable);
            let parsed = parse_section_chunks_with_hints(&bytes, hints);
            assert_eq!(parsed.chunks().len(), if prefix.is_empty() { 1 } else { 2 });
            assert_eq!(
                parsed.chunks().last().unwrap().tag(),
                FourCC::new([0, 65, 66, 67])
            );
            assert_eq!(parsed.layout.consumed, bytes.len());
            assert_eq!(parsed.tail_span(), ByteSpan::new(bytes.len(), bytes.len()));
            assert_eq!(parsed.state(), MbSectionScanState::Complete);
        }
        assert_eq!(unspecified.state(), MbSectionScanState::Stopped);
        assert_eq!(
            parse_section_chunks_with_hints(&[], LayoutHints::default()).state(),
            MbSectionScanState::Complete
        );
        for malformed in [b"DATA\0\0\0".as_slice(), b"DATA\0\0\0\x09X"] {
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
            assert_eq!(parsed.state(), MbSectionScanState::Stopped);
        }
    }
}
