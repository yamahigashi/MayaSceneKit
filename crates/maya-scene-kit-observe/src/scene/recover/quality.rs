use crate::scene::ir::{DecodeQualityRecord, DecodedChunkRecord};

pub(crate) fn collect_decode_quality_records(
    decoded_chunks: &[DecodedChunkRecord],
) -> Vec<DecodeQualityRecord> {
    decoded_chunks
        .iter()
        .map(|decoded| DecodeQualityRecord {
            chunk_ref: decoded.chunk_ref.clone(),
            quality: decoded.quality.clone(),
        })
        .collect()
}
