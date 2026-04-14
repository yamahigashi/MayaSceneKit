use maya_scene_kit_formats::mb::ByteSpan;

use super::ChunkRef;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawChunkRecord {
    pub(crate) chunk_ref: ChunkRef,
    pub(crate) payload_span: ByteSpan,
}

impl RawChunkRecord {
    pub(crate) fn payload<'a>(&self, source: &'a [u8]) -> &'a [u8] {
        self.payload_span.slice(source)
    }
}
