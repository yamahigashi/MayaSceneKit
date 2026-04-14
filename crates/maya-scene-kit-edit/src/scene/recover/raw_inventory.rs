use crate::{
    mb::{MayaBinaryFile, resolve_section_layout_hints, walk_group_chunks_with_layout},
    scene::ir::{ChunkRef, RawChunkRecord},
};

pub(crate) fn collect_raw_chunk_records(mb: &MayaBinaryFile) -> Vec<RawChunkRecord> {
    let mut raw_chunks = Vec::new();

    for child in &mb.root.children {
        let form = child.form_type.clone().unwrap_or_default();
        let (child_alignment, child_header_size) = resolve_section_layout_hints(
            &child.tag,
            child.form_type.as_deref(),
            child.child_alignment,
            child.child_header_size,
        );
        let payload = &mb.data[child.payload_offset..child.payload_end];
        let inner_data = if payload.len() >= 4 {
            &payload[4..]
        } else {
            &[]
        };
        for chunk in walk_group_chunks_with_layout(inner_data, child_alignment, child_header_size) {
            raw_chunks.push(RawChunkRecord {
                chunk_ref: ChunkRef {
                    form: form.clone(),
                    tag: chunk.tag,
                    node_offset: child.offset,
                    parent_tag: Some(child.tag.clone()),
                    chunk_aux: Some(chunk.aux),
                    child_alignment,
                    child_header_size,
                    payload_size: chunk.payload_span.len(),
                },
                payload_span: chunk.payload_span.offset(child.payload_offset + 4),
            });
        }
    }

    raw_chunks
}
