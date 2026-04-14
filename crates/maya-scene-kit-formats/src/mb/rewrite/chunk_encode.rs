use crate::mb::{Chunk, ParsedSection, section::SectionHeaderFormat};

pub(crate) fn encode_chunk(
    tag: &str,
    aux: u32,
    payload: &[u8],
    alignment: usize,
    header_format: SectionHeaderFormat,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    append_chunk_header(&mut out, tag, aux, payload.len(), header_format)?;
    out.extend_from_slice(payload);
    let pad = align_len(out.len(), alignment) - out.len();
    out.resize(out.len() + pad, 0);
    Some(out)
}

pub(crate) fn encode_root_chunk(root: &Chunk, payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    append_chunk_header(
        &mut out,
        root.tag.as_str(),
        root.aux,
        payload.len(),
        chunk_header_format_from_chunk(root),
    )?;
    out.extend_from_slice(payload);
    Some(out)
}

pub(crate) fn append_chunk_header(
    out: &mut Vec<u8>,
    tag: &str,
    aux: u32,
    payload_len: usize,
    header_format: SectionHeaderFormat,
) -> Option<()> {
    out.extend_from_slice(tag.as_bytes());
    match header_format {
        SectionHeaderFormat::FourByte => {
            let size = u32::try_from(payload_len).ok()?;
            out.extend_from_slice(&size.to_be_bytes());
        }
        SectionHeaderFormat::EightByte => {
            out.extend_from_slice(&aux.to_be_bytes());
            out.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }
    }
    Some(())
}

pub(crate) fn chunk_header_format_from_chunk(chunk: &Chunk) -> SectionHeaderFormat {
    if chunk
        .payload_offset
        .checked_sub(chunk.offset)
        .unwrap_or_default()
        == 8
    {
        SectionHeaderFormat::FourByte
    } else {
        SectionHeaderFormat::EightByte
    }
}

pub(crate) fn rewrite_attr_payload_string_preserving_shape(
    payload: &[u8],
    _kind: u8,
    new_value: &str,
) -> Option<Vec<u8>> {
    let attr_end = payload.iter().position(|b| *b == 0)?;
    let value_start = attr_end.checked_add(2)?;
    if value_start > payload.len() {
        return None;
    }

    let value_part = &payload[value_start..];
    let value_end_rel = value_part.iter().position(|b| *b == 0);
    let (value_end, has_nul) = match value_end_rel {
        Some(rel) => (value_start + rel, true),
        None => (payload.len(), false),
    };
    let tail_start = if has_nul { value_end + 1 } else { value_end };

    let mut out = Vec::new();
    out.extend_from_slice(&payload[..value_start]);
    out.extend_from_slice(new_value.as_bytes());
    if has_nul {
        out.push(0);
    }
    out.extend_from_slice(&payload[tail_start..]);
    Some(out)
}

pub(crate) fn rebuild_section_with_payload_rewrites(
    inner: &[u8],
    parsed: &ParsedSection,
    rewritten_payloads: &[(usize, Vec<u8>)],
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = 0usize;

    for (idx, chunk) in parsed.chunks.iter().enumerate() {
        if chunk.chunk_start > cursor {
            out.extend_from_slice(&inner[cursor..chunk.chunk_start]);
        }
        if let Some((_, payload)) = rewritten_payloads.iter().find(|(target, _)| *target == idx) {
            if let Some(encoded) = encode_chunk(
                &chunk.tag,
                chunk.aux,
                payload,
                parsed.layout.alignment,
                parsed.layout.header_format,
            ) {
                out.extend_from_slice(&encoded);
            } else {
                out.extend_from_slice(&inner[chunk.chunk_start..chunk.chunk_end]);
            }
        } else {
            out.extend_from_slice(&inner[chunk.chunk_start..chunk.chunk_end]);
        }
        cursor = chunk.chunk_end;
    }

    if cursor < parsed.layout.consumed {
        out.extend_from_slice(&inner[cursor..parsed.layout.consumed]);
    }
    out.extend_from_slice(parsed.tail(inner));
    out
}

fn align_len(v: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return v;
    }
    let rem = v % alignment;
    if rem == 0 { v } else { v + (alignment - rem) }
}
