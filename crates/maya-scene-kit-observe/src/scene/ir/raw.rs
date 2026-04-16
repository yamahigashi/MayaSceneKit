use std::sync::Arc;

use maya_scene_kit_formats::mb::ByteSpan;

use super::{ChunkRef, DecodeQualityRecord, DecodedEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawChunkRecord {
    pub chunk_ref: ChunkRef,
    pub payload_span: ByteSpan,
}

impl RawChunkRecord {
    pub fn payload<'a>(&self, source: &'a [u8]) -> &'a [u8] {
        self.payload_span.slice(source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedChunkRecord {
    pub chunk_ref: ChunkRef,
    pub events: Vec<DecodedEvent>,
    pub quality: super::SchemaDecodeAttemptResult,
}

#[derive(Debug, Clone, Default)]
pub struct SceneArtifacts {
    pub raw_source: Arc<[u8]>,
    pub raw_chunks: Vec<RawChunkRecord>,
    pub decode_qualities: Vec<DecodeQualityRecord>,
}
