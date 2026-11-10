use std::sync::Arc;

use crate::{
    mb::{
        LayoutHints, MayaBinaryFile, MayaBinaryParseError, MbParseBudget, SectionChunk,
        resolve_section_layout_hints, visit_group_chunks_with_layout,
        visit_group_chunks_with_layout_with_budget,
    },
    scene::{
        decode::dispatcher::DecoderDispatcher,
        ir::{ChunkRef, DecodedChunkRecord, DecodedEvent, RawChunkRecord, StringInterner},
        schema::SchemaRegistry,
    },
};

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn collect_raw_chunk_records(
    mb: &MayaBinaryFile,
) -> (Vec<RawChunkRecord>, crate::mb::MbSectionScanState) {
    collect_raw_chunk_records_inner(mb, None).expect("unbudgeted raw inventory should not fail")
}

pub(crate) fn collect_raw_chunk_records_with_budget(
    mb: &MayaBinaryFile,
    budget: &MbParseBudget,
) -> Result<(Vec<RawChunkRecord>, crate::mb::MbSectionScanState), MayaBinaryParseError> {
    collect_raw_chunk_records_inner(mb, Some(budget))
}

fn collect_raw_chunk_records_inner(
    mb: &MayaBinaryFile,
    budget: Option<&MbParseBudget>,
) -> Result<(Vec<RawChunkRecord>, crate::mb::MbSectionScanState), MayaBinaryParseError> {
    let mut raw_chunks = Vec::new();
    let mut state = crate::mb::MbSectionScanState::Complete;

    for child in mb.root().children() {
        if !child.is_group() {
            continue;
        }
        let form = child.form_type().map(|f| f.to_string()).unwrap_or_default();
        let hints = resolve_section_layout_hints(
            child.tag(),
            child.form_type(),
            child
                .child_layout()
                .map_or_else(LayoutHints::new, LayoutHints::from),
        );
        let child_alignment = hints.alignment().map(|a| a.get());
        let child_header_size = hints.header_format().map(|f| f.header_size());
        let payload = &mb.data()[child.payload_offset()..child.payload_end()];
        let inner_data = if payload.len() >= 4 {
            &payload[4..]
        } else {
            &[]
        };
        let mut push_raw_chunk = |chunk: SectionChunk| {
            raw_chunks.push(RawChunkRecord {
                chunk_ref: ChunkRef {
                    form: form.clone(),
                    tag: chunk.tag().to_string(),
                    node_offset: child.offset(),
                    parent_tag: Some(child.tag().to_string()),
                    chunk_aux: Some(chunk.aux()),
                    child_alignment,
                    child_header_size,
                    payload_size: chunk.payload_span().len(),
                },
                payload_span: chunk.payload_span().offset(child.payload_offset() + 4),
            });
        };
        state.merge(match budget {
            Some(budget) => visit_group_chunks_with_layout_with_budget(
                inner_data,
                hints,
                2,
                budget,
                &mut push_raw_chunk,
            )?,
            None => visit_group_chunks_with_layout(inner_data, hints, &mut push_raw_chunk),
        });
    }

    Ok((raw_chunks, state))
}

pub(crate) fn collect_decoded_chunk_records(
    raw_chunks: &[RawChunkRecord],
    raw_source: &[u8],
    registry: Arc<SchemaRegistry>,
) -> Vec<DecodedChunkRecord> {
    let dispatcher = DecoderDispatcher::new(registry);
    let mut interner = StringInterner::default();
    let mut decoded = Vec::with_capacity(raw_chunks.len());

    for raw in raw_chunks {
        let mut dispatch = dispatcher.decode_with_quality(
            &raw.chunk_ref.form,
            &raw.chunk_ref.tag,
            raw.payload(raw_source),
            raw.chunk_ref.node_offset,
            raw.chunk_ref.chunk_aux,
            raw.chunk_ref.child_alignment,
            raw.chunk_ref.child_header_size,
            Some(raw.chunk_ref.form.as_str()),
            raw.chunk_ref.parent_tag.as_deref(),
        );
        intern_decoded_events(&mut dispatch.events, &mut interner);
        decoded.push(DecodedChunkRecord {
            chunk_ref: raw.chunk_ref.clone(),
            events: dispatch.events,
            quality: dispatch.quality,
        });
    }

    decoded
}

fn intern_decoded_events(events: &mut [DecodedEvent], interner: &mut StringInterner) {
    for event in events {
        match event {
            DecodedEvent::Relationship { kind, .. } => {
                *kind = interner.intern(kind.as_ref());
            }
            DecodedEvent::RefEdit { attr_name, .. } => {
                *attr_name = interner.intern(attr_name.as_ref());
            }
            DecodedEvent::ReferenceFile {
                reference_node,
                namespace,
                file_type,
                ..
            } => {
                *reference_node = interner.intern(reference_node.as_ref());
                if let Some(namespace) = namespace {
                    *namespace = interner.intern(namespace.as_ref());
                }
                if let Some(file_type) = file_type {
                    *file_type = interner.intern(file_type.as_ref());
                }
            }
            _ => {}
        }
    }
}
