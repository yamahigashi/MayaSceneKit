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
