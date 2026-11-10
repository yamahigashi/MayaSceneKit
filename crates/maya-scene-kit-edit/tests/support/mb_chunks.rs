pub(crate) fn build_mb_chunk_with_alignment(
    tag: &str,
    payload: &[u8],
    sibling_alignment: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    while (out.len() - 16) % sibling_alignment != 0 {
        out.push(0);
    }
    out
}

pub(crate) fn build_mb_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
    build_mb_chunk_with_alignment(tag, payload, 8)
}

pub(crate) fn build_mb_form_with_alignment(
    form: &str,
    children: &[Vec<u8>],
    sibling_alignment: usize,
) -> Vec<u8> {
    let mut payload = form.as_bytes().to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    build_mb_chunk_with_alignment("FOR8", &payload, sibling_alignment)
}

pub(crate) fn build_mb_root(children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = b"Maya".to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"FOR8");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}
