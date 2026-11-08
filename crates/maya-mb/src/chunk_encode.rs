use std::collections::HashSet;

use crate::{Chunk, ChunkLayout, FourCC, HeaderFormat, ParsedSection, SectionChunk};

/// A rejected chunk encoding or section rewrite.
/// Arithmetic overflow concerns `usize` lengths, not allocation failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// The payload cannot fit a four-byte size field.
    #[error("four-byte payload length {payload_len} exceeds u32::MAX")]
    PayloadTooLarge { payload_len: usize },
    /// A header, padding, or total output length overflowed `usize`.
    #[error("encoded length arithmetic overflow")]
    LengthOverflow,
    /// The same chunk was requested more than once.
    #[error("duplicate rewrite for chunk index {index}")]
    DuplicateRewrite { index: usize },
    /// A rewrite refers to a chunk outside the parsed section.
    #[error("rewrite index {index} is outside section with {chunk_count} chunks")]
    RewriteIndexOutOfRange { index: usize, chunk_count: usize },
    /// A parsed span is reversed or outside the supplied source.
    #[error("section span {start}..{end} is outside source buffer of length {source_len}")]
    SourceMismatch {
        start: usize,
        end: usize,
        source_len: usize,
    },
}

/// Encodes a chunk and zero pads to its nonzero alignment.
/// Header width is independent of alignment, as with FOR8/Maya.
/// Auxiliary bytes are written only for eight-byte size fields.
/// Returns an error for an oversized four-byte payload or length arithmetic overflow.
pub fn encode_chunk(
    tag: FourCC,
    aux: u32,
    payload: &[u8],
    layout: ChunkLayout,
) -> Result<Vec<u8>, EncodeError> {
    let len = encoded_chunk_len(
        layout.header_format(),
        payload.len(),
        layout.alignment_usize(),
    )?;
    let mut out = Vec::with_capacity(len);
    append_chunk_header(&mut out, tag, aux, payload.len(), layout.header_format())?;
    out.extend_from_slice(payload);
    out.resize(len, 0);
    Ok(out)
}

/// Encodes a root's tag, auxiliary value, and header width with a new payload.
/// No trailing padding is appended. Length errors are checked before encoding.
pub fn encode_root_chunk(root: &Chunk, payload: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let len = encoded_chunk_len(root.header_format(), payload.len(), 1)?;
    let mut out = Vec::with_capacity(len);
    append_chunk_header(
        &mut out,
        root.tag(),
        root.aux(),
        payload.len(),
        root.header_format(),
    )?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// Appends an unpadded header after validating all lengths.
pub(crate) fn append_chunk_header(
    out: &mut Vec<u8>,
    tag: FourCC,
    aux: u32,
    payload_len: usize,
    header_format: HeaderFormat,
) -> Result<(), EncodeError> {
    encoded_chunk_len(header_format, payload_len, 1)?;
    out.len()
        .checked_add(header_format.header_size())
        .ok_or(EncodeError::LengthOverflow)?;
    out.extend_from_slice(tag.as_bytes());
    match header_format {
        HeaderFormat::FourByte => out.extend_from_slice(&(payload_len as u32).to_be_bytes()),
        HeaderFormat::EightByte => {
            out.extend_from_slice(&aux.to_be_bytes());
            out.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }
    }
    Ok(())
}

fn encoded_chunk_len(
    header_format: HeaderFormat,
    payload_len: usize,
    alignment: usize,
) -> Result<usize, EncodeError> {
    if header_format == HeaderFormat::FourByte {
        u32::try_from(payload_len).map_err(|_| EncodeError::PayloadTooLarge { payload_len })?;
    }
    let n = header_format
        .header_size()
        .checked_add(payload_len)
        .ok_or(EncodeError::LengthOverflow)?;
    align_len(n, alignment).ok_or(EncodeError::LengthOverflow)
}

fn align_len(n: usize, alignment: usize) -> Option<usize> {
    let alignment = alignment.max(1);
    let remainder = n % alignment;
    let pad = if remainder == 0 {
        0
    } else {
        alignment.checked_sub(remainder)?
    };
    n.checked_add(pad)
}

fn padding_is_complete(
    chunk: &SectionChunk,
    header_format: HeaderFormat,
    alignment: usize,
) -> bool {
    let complete_len = (|| {
        let len = chunk
            .payload_span
            .end
            .checked_sub(chunk.payload_span.start)?;
        let n = header_format.header_size().checked_add(len)?;
        let pad = align_len(n, alignment)?.checked_sub(n)?;
        n.checked_add(pad)
    })();
    complete_len.is_some()
        && chunk.chunk_end.checked_sub(chunk.chunk_start) == complete_len
        && chunk.chunk_start.checked_add(header_format.header_size())
            == Some(chunk.payload_span.start)
}

fn add_span_len(total: usize, start: usize, end: usize) -> Result<usize, EncodeError> {
    end.checked_sub(start)
        .and_then(|len| total.checked_add(len))
        .ok_or(EncodeError::LengthOverflow)
}

impl ParsedSection {
    /// Checks whether this index exists and this payload length can be encoded
    /// with the section's header width and alignment (zero alignment means one).
    /// This does not check allocation, source spans, or the total section length.
    pub fn can_encode_payload(&self, index: usize, len: usize) -> bool {
        self.chunks.get(index).is_some()
            && encoded_chunk_len(self.layout.header_format, len, self.layout.alignment).is_ok()
    }

    /// Rewrites selected chunk payloads using offsets relative to the buffer parsed
    /// into this section. Source validation checks bounds only, not buffer identity
    /// or header contents; rewritten headers always use the parsed tag and auxiliary value.
    ///
    /// Before copying or encoding, checks chunk and payload spans in section order,
    /// then consumed and tail spans, then all indices in input order, then duplicate
    /// indices in input order, then payload sizes in section order and total output length.
    /// Invalid spans return `SourceMismatch`; out-of-range and duplicate indices return
    /// their respective errors. Encoding failures return no partial output, including
    /// `PayloadTooLarge` and `LengthOverflow` instead of truncating or overflowing lengths.
    ///
    /// Same-length rewrites preserve complete original padding, including nonzero bytes.
    /// Incomplete padding or changed payload lengths produce zero padding. Unspecified
    /// chunks, gaps, the remainder before the consumed end, and the tail are copied.
    /// With no rewrites, parser-produced sections reproduce the consumed prefix followed
    /// by the tail, excluding any source suffix after the original tail end.
    pub fn rewrite_payloads(
        &self,
        source: &[u8],
        rewrites: &[(usize, &[u8])],
    ) -> Result<Vec<u8>, EncodeError> {
        let check_span = |start, end| {
            source
                .get(start..end)
                .ok_or(EncodeError::SourceMismatch {
                    start,
                    end,
                    source_len: source.len(),
                })
                .map(|_| ())
        };
        for chunk in &self.chunks {
            check_span(chunk.chunk_start, chunk.chunk_end)?;
            check_span(chunk.payload_span.start, chunk.payload_span.end)?;
        }
        check_span(0, self.layout.consumed)?;
        check_span(self.tail_span.start, self.tail_span.end)?;
        for &(index, _) in rewrites {
            if self.chunks.get(index).is_none() {
                return Err(EncodeError::RewriteIndexOutOfRange {
                    index,
                    chunk_count: self.chunks.len(),
                });
            }
        }
        let mut seen = HashSet::new();
        for &(index, _) in rewrites {
            if !seen.insert(index) {
                return Err(EncodeError::DuplicateRewrite { index });
            }
        }
        let mut slots = vec![None; self.chunks.len()];
        for &(index, payload) in rewrites {
            slots[index] = Some(payload);
        }
        let lengths = self
            .chunks
            .iter()
            .zip(&slots)
            .map(|(chunk, payload)| match payload {
                Some(payload) => encoded_chunk_len(
                    self.layout.header_format,
                    payload.len(),
                    self.layout.alignment,
                ),
                None => Ok(chunk.chunk_end - chunk.chunk_start),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut total = 0;
        let mut cursor = 0;
        for (chunk, len) in self.chunks.iter().zip(&lengths) {
            if chunk.chunk_start > cursor {
                total = add_span_len(total, cursor, chunk.chunk_start)?;
            }
            total = add_span_len(total, 0, *len)?;
            cursor = chunk.chunk_end;
        }
        if cursor < self.layout.consumed {
            total = add_span_len(total, cursor, self.layout.consumed)?;
        }
        total = add_span_len(total, self.tail_span.start, self.tail_span.end)?;

        let mut out = Vec::with_capacity(total);
        cursor = 0;
        for ((chunk, payload), len) in self.chunks.iter().zip(slots).zip(lengths) {
            if chunk.chunk_start > cursor {
                out.extend_from_slice(&source[cursor..chunk.chunk_start]);
            }
            if let Some(payload) = payload {
                let end = out.len() + len;
                append_chunk_header(
                    &mut out,
                    chunk.tag,
                    chunk.aux,
                    payload.len(),
                    self.layout.header_format,
                )?;
                out.extend_from_slice(payload);
                if chunk.payload_span.end.checked_sub(chunk.payload_span.start)
                    == Some(payload.len())
                    && padding_is_complete(chunk, self.layout.header_format, self.layout.alignment)
                {
                    out.extend_from_slice(&source[chunk.payload_span.end..chunk.chunk_end]);
                } else {
                    out.resize(end, 0);
                }
            } else {
                out.extend_from_slice(&source[chunk.chunk_start..chunk.chunk_end]);
            }
            cursor = chunk.chunk_end;
        }
        if cursor < self.layout.consumed {
            out.extend_from_slice(&source[cursor..self.layout.consumed]);
        }
        out.extend_from_slice(&source[self.tail_span.start..self.tail_span.end]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::encode_chunk;
    use crate::{ChunkLayout, FourCC, HeaderFormat, parse_bytes};

    #[test]
    fn encode_chunk_preserves_non_printable_tag_bytes() {
        let encoded = encode_chunk(
            FourCC::new([0x00, 0x01, 0x7F, 0xFF]),
            0,
            &[0x12, 0x34],
            ChunkLayout::new(
                NonZeroUsize::new(4).expect("nonzero alignment"),
                HeaderFormat::FourByte,
            ),
        )
        .unwrap();
        assert_eq!(&encoded[..4], &[0x00, 0x01, 0x7F, 0xFF]);
    }

    #[test]
    fn parse_bytes_preserves_non_printable_child_tag() {
        let mut stream = Vec::new();
        stream.extend_from_slice(b"FOR4");
        stream.extend_from_slice(&16u32.to_be_bytes());
        stream.extend_from_slice(b"TEST");
        stream.extend_from_slice(&[0x00, 0x01, 0x7F, 0xFF]);
        stream.extend_from_slice(&2u32.to_be_bytes());
        stream.extend_from_slice(&[0x12, 0x34, 0x00, 0x00]);

        let parsed = parse_bytes(stream).unwrap();
        assert_eq!(parsed.root().children().len(), 1);
        let child = &parsed.root().children()[0];
        assert_eq!(child.tag().as_bytes(), &[0x00, 0x01, 0x7F, 0xFF]);
        assert_eq!(child.tag().to_string(), "[00017FFF]");
    }

    #[test]
    fn typed_layout_preserves_padding_and_tail() {
        use crate::{
            ByteSpan, LayoutHints, ParsedSection, SectionChunk, parse_section_chunks_with_hints,
            section::SectionLayout,
        };
        for (alignment, format, expected) in [
            (
                4,
                HeaderFormat::FourByte,
                b"DATA\0\0\0\x01X\0\0\0".as_slice(),
            ),
            (3, HeaderFormat::FourByte, b"DATA\0\0\0\x01X".as_slice()),
            (
                4,
                HeaderFormat::EightByte,
                b"DATA\0\0\0\x11\0\0\0\0\0\0\0\x01X\0\0\0".as_slice(),
            ),
        ] {
            let encoded = encode_chunk(
                FourCC::new(*b"DATA"),
                0x11,
                b"X",
                ChunkLayout::new(NonZeroUsize::new(alignment).unwrap(), format),
            )
            .unwrap();
            assert_eq!(encoded, expected);
        }
        let inner = b"\xAA\xBBDATA\0\0\0\x01X\xCC\xDD\xEE\x12\x34TEST";
        let parsed = ParsedSection {
            chunks: vec![SectionChunk {
                tag: FourCC::new(*b"DATA"),
                aux: 0,
                payload_span: ByteSpan::new(10, 11),
                chunk_start: 2,
                chunk_end: 14,
            }],
            layout: SectionLayout {
                alignment: 4,
                header_format: HeaderFormat::FourByte,
                consumed: 16,
            },
            tail_span: ByteSpan::new(16, inner.len()),
        };
        assert_eq!(parsed.rewrite_payloads(inner, &[]).unwrap(), inner);
        assert_eq!(
            parsed
                .rewrite_payloads(inner, &[(0, b"Example".as_slice())])
                .unwrap(),
            b"\xAA\xBBDATA\0\0\0\x07Example\0\x12\x34TEST",
        );

        let mut unspecified = parse_section_chunks_with_hints(inner, LayoutHints::default());
        assert_eq!(unspecified.rewrite_payloads(inner, &[]).unwrap(), inner);
        unspecified.chunks.push(SectionChunk {
            tag: FourCC::new(*b"DATA"),
            aux: 0x11,
            payload_span: ByteSpan::new(0, 0),
            chunk_start: 0,
            chunk_end: 0,
        });
        let mut expected = b"DATA\0\0\0\x11\0\0\0\0\0\0\0\x01X".to_vec();
        expected.extend_from_slice(inner);
        assert_eq!(
            unspecified
                .rewrite_payloads(inner, &[(0, b"X".as_slice())])
                .unwrap(),
            expected,
        );
    }

    fn four_section(data: &[u8]) -> crate::ParsedSection {
        crate::parse_section_chunks_with_hints(
            data,
            crate::LayoutHints::new().with_header_format(HeaderFormat::FourByte),
        )
    }

    #[test]
    fn encode_error_traits_and_display() {
        use super::EncodeError;
        fn check_traits<T: Clone + PartialEq + Eq + std::error::Error>(_: &T) {}
        for (error, message) in [
            (
                EncodeError::PayloadTooLarge { payload_len: 42 },
                "four-byte payload length 42 exceeds u32::MAX",
            ),
            (
                EncodeError::LengthOverflow,
                "encoded length arithmetic overflow",
            ),
            (
                EncodeError::DuplicateRewrite { index: 2 },
                "duplicate rewrite for chunk index 2",
            ),
            (
                EncodeError::RewriteIndexOutOfRange {
                    index: 4,
                    chunk_count: 3,
                },
                "rewrite index 4 is outside section with 3 chunks",
            ),
            (
                EncodeError::SourceMismatch {
                    start: 3,
                    end: 9,
                    source_len: 8,
                },
                "section span 3..9 is outside source buffer of length 8",
            ),
        ] {
            check_traits(&error);
            assert_eq!(error.clone(), error);
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn four_byte_payload_size_boundary() {
        use super::{EncodeError, encoded_chunk_len};
        let limit = u32::MAX as usize;
        assert_eq!(
            encoded_chunk_len(HeaderFormat::FourByte, limit, 1),
            Ok(limit + 8)
        );
        assert_eq!(
            encoded_chunk_len(HeaderFormat::FourByte, limit + 1, 1),
            Err(EncodeError::PayloadTooLarge {
                payload_len: limit + 1
            })
        );
        let section = four_section(b"DATA\0\0\0\x01X\0\0\0");
        assert!(section.can_encode_payload(0, limit));
        assert!(!section.can_encode_payload(0, limit + 1));
        assert!(!section.can_encode_payload(1, 0));
    }

    #[test]
    fn header_length_overflow() {
        assert_eq!(
            super::encoded_chunk_len(HeaderFormat::EightByte, usize::MAX, 1),
            Err(super::EncodeError::LengthOverflow)
        );
    }

    #[test]
    fn alignment_length_overflow() {
        assert_eq!(
            super::encoded_chunk_len(HeaderFormat::EightByte, usize::MAX - 16, 2),
            Err(super::EncodeError::LengthOverflow)
        );
    }

    #[test]
    fn section_total_length_overflow() {
        assert_eq!(
            super::add_span_len(usize::MAX - 1, 2, 4),
            Err(super::EncodeError::LengthOverflow)
        );
        assert_eq!(super::add_span_len(usize::MAX - 1, 2, 3), Ok(usize::MAX));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn four_byte_payload_error_precedes_arithmetic_overflow() {
        assert_eq!(
            super::encoded_chunk_len(HeaderFormat::FourByte, usize::MAX, usize::MAX),
            Err(super::EncodeError::PayloadTooLarge {
                payload_len: usize::MAX
            })
        );
    }

    #[test]
    fn encoder_bytes_cover_width_alignment_and_payload_boundaries() {
        let tag = FourCC::new([0, 1, 0x7f, 0xff]);
        for (format, alignment, lengths) in [
            (HeaderFormat::FourByte, 1, [8, 9, 11, 12, 15, 16]),
            (HeaderFormat::FourByte, 3, [9, 9, 12, 12, 15, 18]),
            (HeaderFormat::FourByte, 4, [8, 12, 12, 12, 16, 16]),
            (HeaderFormat::FourByte, 8, [8, 16, 16, 16, 16, 16]),
            (HeaderFormat::EightByte, 1, [16, 17, 19, 20, 23, 24]),
            (HeaderFormat::EightByte, 3, [18, 18, 21, 21, 24, 24]),
            (HeaderFormat::EightByte, 4, [16, 20, 20, 20, 24, 24]),
            (HeaderFormat::EightByte, 8, [16, 24, 24, 24, 24, 24]),
        ] {
            for (payload_len, expected_len) in [0, 1, 3, 4, 7, 8].into_iter().zip(lengths) {
                let payload = &b"ExampleX"[..payload_len];
                let mut expected = vec![0, 1, 0x7f, 0xff];
                match format {
                    HeaderFormat::FourByte => {
                        expected.extend_from_slice(&[0, 0, 0, payload_len as u8])
                    }
                    HeaderFormat::EightByte => expected.extend_from_slice(&[
                        0x11,
                        0x22,
                        0x33,
                        0x44,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        payload_len as u8,
                    ]),
                }
                expected.extend_from_slice(payload);
                expected.resize(expected_len, 0);
                assert_eq!(
                    encode_chunk(
                        tag,
                        0x11223344,
                        payload,
                        ChunkLayout::new(NonZeroUsize::new(alignment).unwrap(), format)
                    )
                    .unwrap(),
                    expected
                );
            }
        }
        for (source, expected) in [
            (
                b"FOR4\0\0\0\x04Maya".as_slice(),
                b"FOR4\0\0\0\x07Example".as_slice(),
            ),
            (
                b"FOR8\x11\x22\x33\x44\0\0\0\0\0\0\0\x04Maya",
                b"FOR8\x11\x22\x33\x44\0\0\0\0\0\0\0\x07Example",
            ),
        ] {
            let parsed = parse_bytes(source.to_vec()).unwrap();
            assert_eq!(
                super::encode_root_chunk(parsed.root(), b"Example").unwrap(),
                expected
            );
        }
    }

    #[test]
    fn complete_padding_survives_same_length_rewrites_only() {
        let source = b"DATA\0\0\0\x01X\xA1\xB2\xC3";
        let parsed = four_section(source);
        let rewritten = parsed.rewrite_payloads(source, &[(0, b"Y")]).unwrap();
        let old = b"DATA\0\0\0\x01Y\0\0\0";
        assert_eq!(rewritten, b"DATA\0\0\0\x01Y\xA1\xB2\xC3");
        assert_eq!(&rewritten[..9], &old[..9]);
        assert_eq!(
            rewritten
                .iter()
                .zip(old)
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(|(i, _)| i)
                .collect::<Vec<_>>(),
            [9, 10, 11]
        );
        assert_eq!(
            parsed.rewrite_payloads(source, &[(0, b"X")]).unwrap(),
            source
        );
        assert_eq!(
            parsed.rewrite_payloads(source, &[(0, b"YZ")]).unwrap(),
            b"DATA\0\0\0\x02YZ\0\0"
        );
    }

    #[test]
    fn padding_completeness_boundaries() {
        use crate::{ByteSpan, ParsedSection, SectionChunk, section::SectionLayout};
        for format in [HeaderFormat::FourByte, HeaderFormat::EightByte] {
            for alignment in [0, 1, 3, 4, 8] {
                for start in [0, 2] {
                    let layout =
                        ChunkLayout::new(NonZeroUsize::new(alignment.max(1)).unwrap(), format);
                    let original =
                        encode_chunk(FourCC::new(*b"DATA"), 0x11223344, b"X", layout).unwrap();
                    let h = format.header_size();
                    let mut source = vec![0xAA; start];
                    source.extend_from_slice(&original);
                    source[start + h + 1..].fill(0xCC);
                    source.extend_from_slice(b"Sample");
                    let parsed = ParsedSection {
                        chunks: vec![SectionChunk {
                            tag: FourCC::new(*b"DATA"),
                            aux: 0x11223344,
                            payload_span: ByteSpan::new(start + h, start + h + 1),
                            chunk_start: start,
                            chunk_end: start + original.len(),
                        }],
                        layout: SectionLayout {
                            alignment,
                            header_format: format,
                            consumed: start + original.len(),
                        },
                        tail_span: ByteSpan::new(start + original.len(), source.len()),
                    };
                    assert!(super::padding_is_complete(
                        &parsed.chunks[0],
                        format,
                        alignment
                    ));
                    let mut expected = source.clone();
                    expected[start + h] = b'Y';
                    assert_eq!(
                        parsed.rewrite_payloads(&source, &[(0, b"Y")]).unwrap(),
                        expected
                    );
                    for defect in 0..3 {
                        let mut incomplete = parsed.clone();
                        match defect {
                            0 => incomplete.chunks[0].chunk_end -= 1,
                            1 => incomplete.chunks[0].chunk_end += 1,
                            _ => {
                                incomplete.chunks[0].payload_span =
                                    ByteSpan::new(source.len() - 1, source.len())
                            }
                        }
                        assert!(!super::padding_is_complete(
                            &incomplete.chunks[0],
                            format,
                            alignment
                        ));
                        let mut expected = source[..start].to_vec();
                        expected.extend_from_slice(
                            &encode_chunk(FourCC::new(*b"DATA"), 0x11223344, b"Y", layout).unwrap(),
                        );
                        let cursor = incomplete.chunks[0].chunk_end;
                        if cursor < incomplete.layout.consumed {
                            expected.extend_from_slice(&source[cursor..incomplete.layout.consumed]);
                        }
                        expected.extend_from_slice(
                            &source[incomplete.tail_span.start..incomplete.tail_span.end],
                        );
                        assert_eq!(
                            incomplete.rewrite_payloads(&source, &[(0, b"Y")]).unwrap(),
                            expected
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn duplicate_rewrite_reports_first_repeated_index() {
        let source = b"DATA\0\0\0\x01X\0\0\0TEST\0\0\0\x01X\0\0\0";
        assert_eq!(
            four_section(source)
                .rewrite_payloads(source, &[(1, b"Y"), (0, b"Y"), (1, b"Z"), (0, b"Z")]),
            Err(super::EncodeError::DuplicateRewrite { index: 1 })
        );
    }

    #[test]
    fn out_of_range_rewrites_cover_boundary_huge_and_tail_only() {
        let source = b"DATA\0\0\0\x01X\0\0\0";
        let parsed = four_section(source);
        for index in [parsed.chunks.len(), usize::MAX] {
            assert_eq!(
                parsed.rewrite_payloads(source, &[(index, b"Y")]),
                Err(super::EncodeError::RewriteIndexOutOfRange {
                    index,
                    chunk_count: 1
                })
            );
        }
        assert_eq!(
            four_section(b"end").rewrite_payloads(b"end", &[(0, b"Y")]),
            Err(super::EncodeError::RewriteIndexOutOfRange {
                index: 0,
                chunk_count: 0
            })
        );
    }

    #[test]
    fn source_shorter_than_chunk_reports_exact_span() {
        let source = b"DATA\0\0\0\x01X\0\0\0";
        assert_eq!(
            four_section(source).rewrite_payloads(&source[..11], &[]),
            Err(super::EncodeError::SourceMismatch {
                start: 0,
                end: 12,
                source_len: 11
            })
        );
    }

    #[test]
    fn invalid_payload_consumed_tail_and_reversed_spans() {
        use crate::ByteSpan;
        let source = b"DATA\0\0\0\x01X\0\0\0";
        for (case, start, end) in [
            (0, 8, 13),
            (1, 0, 13),
            (2, 12, 13),
            (3, 9, 8),
            (4, 12, 0),
            (5, 12, 11),
        ] {
            let mut parsed = four_section(source);
            match case {
                0 | 3 => parsed.chunks[0].payload_span = ByteSpan::new(start, end),
                1 => parsed.layout.consumed = end,
                2 | 5 => parsed.tail_span = ByteSpan::new(start, end),
                _ => {
                    parsed.chunks[0].chunk_start = start;
                    parsed.chunks[0].chunk_end = end;
                }
            }
            assert_eq!(
                parsed.rewrite_payloads(source, &[]),
                Err(super::EncodeError::SourceMismatch {
                    start,
                    end,
                    source_len: 12
                })
            );
        }
    }

    #[test]
    fn rewrite_validation_order_and_unsorted_unique_indices() {
        use super::EncodeError;
        let source = b"DATA\0\0\0\x01X\0\0\0TEST\0\0\0\x01X\0\0\0";
        let parsed = four_section(source);
        let invalid = [
            (0, b"Y".as_slice()),
            (0, b"Y".as_slice()),
            (2, b"Y".as_slice()),
        ];
        assert_eq!(
            parsed.rewrite_payloads(&source[..23], &invalid),
            Err(EncodeError::SourceMismatch {
                start: 12,
                end: 24,
                source_len: 23
            })
        );
        assert_eq!(
            parsed.rewrite_payloads(source, &invalid),
            Err(EncodeError::RewriteIndexOutOfRange {
                index: 2,
                chunk_count: 2
            })
        );
        assert_eq!(
            parsed.rewrite_payloads(source, &invalid[..2]),
            Err(EncodeError::DuplicateRewrite { index: 0 })
        );
        assert_eq!(
            parsed
                .rewrite_payloads(source, &[(1, b"Z"), (0, b"Y")])
                .unwrap(),
            b"DATA\0\0\0\x01Y\0\0\0TEST\0\0\0\x01Z\0\0\0"
        );
        let mut malformed = parsed.clone();
        malformed.chunks[0].payload_span.end = 25;
        malformed.chunks[1].chunk_end = 26;
        malformed.layout.consumed = 27;
        malformed.tail_span.end = 28;
        assert_eq!(
            malformed.rewrite_payloads(source, &invalid),
            Err(EncodeError::SourceMismatch {
                start: 8,
                end: 25,
                source_len: 24
            })
        );
    }

    #[test]
    fn empty_rewrites_copy_gaps_tail_and_backward_cursor() {
        use crate::{
            ByteSpan, LayoutHints, ParsedSection, SectionChunk, parse_section_chunks_with_hints,
            section::SectionLayout,
        };
        for source in [b"DATA\0\0\0\x01X\xAA\xBB\xCCend".as_slice(), b"end", b""] {
            for hints in [
                LayoutHints::default(),
                LayoutHints::new().with_header_format(HeaderFormat::FourByte),
            ] {
                let parsed = parse_section_chunks_with_hints(source, hints);
                assert_eq!(parsed.rewrite_payloads(source, &[]).unwrap(), source);
                let mut longer = source.to_vec();
                longer.extend_from_slice(b"Sample");
                assert_eq!(parsed.rewrite_payloads(&longer, &[]).unwrap(), source);
            }
        }
        let source = b"0123456789ABCDEF";
        let parsed = ParsedSection {
            chunks: [(2, 4), (6, 8), (3, 5)]
                .into_iter()
                .map(|(start, end)| SectionChunk {
                    tag: FourCC::new(*b"DATA"),
                    aux: 0,
                    payload_span: ByteSpan::new(start, start),
                    chunk_start: start,
                    chunk_end: end,
                })
                .collect(),
            layout: SectionLayout {
                alignment: 4,
                header_format: HeaderFormat::FourByte,
                consumed: 12,
            },
            tail_span: ByteSpan::new(12, 14),
        };
        assert_eq!(
            parsed.rewrite_payloads(source, &[]).unwrap(),
            b"012345673456789ABCD"
        );
        let empty = ParsedSection {
            chunks: vec![],
            ..parsed
        };
        assert_eq!(
            empty.rewrite_payloads(source, &[]).unwrap(),
            b"0123456789ABCD"
        );
    }

    #[test]
    fn alternate_source_regenerates_only_rewritten_headers() {
        let original = b"DATA\0\0\0\x01X\xAA\xBB\xCCDATA\0\0\0\x01X\0\0\0";
        let alternate = b"TEST\0\0\0\x01X\xDD\xEE\xFFTEST\0\0\0\x01X\0\0\0";
        let parsed = four_section(original);
        assert_eq!(
            parsed.rewrite_payloads(alternate, &[(0, b"X")]).unwrap(),
            b"DATA\0\0\0\x01X\xDD\xEE\xFFTEST\0\0\0\x01X\0\0\0"
        );
    }
}
