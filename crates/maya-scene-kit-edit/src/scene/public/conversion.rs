use std::path::PathBuf;

use serde::Serialize;

use super::{OperationMode, SceneFormat, ValidationState, staging::StagedSceneArtifact};

/// Result of one schema decoder attempt for a recovered chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeAttemptResult {
    /// Exact schema match.
    Exact,
    /// Partial schema match.
    Partial,
    /// Decoder examined the chunk but passed.
    Pass,
    /// Decoder failed to decode the chunk.
    Failed,
}

/// One recorded decoder attempt for an issue.
#[derive(Debug, Clone)]
pub struct MayaAsciiDecodeAttempt {
    /// Decoder identifier.
    pub decoder_id: String,
    /// Decoder outcome.
    pub result: DecodeAttemptResult,
    /// Optional failure or pass reason.
    pub reason: Option<String>,
}

/// Raw chunk payload captured for issue artifacts and reporting.
#[derive(Debug, Clone)]
pub struct RawChunkDump {
    /// Chunk form.
    pub trace_form: String,
    /// Chunk tag.
    pub trace_tag: String,
    /// Node offset of the chunk.
    pub trace_node_offset: usize,
    /// Optional chunk aux value.
    pub trace_chunk_aux: Option<u32>,
    /// Optional child alignment hint.
    pub trace_child_alignment: Option<usize>,
    /// Optional child header size hint.
    pub trace_child_header_size: Option<usize>,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
}

/// High-level issue kind produced during canonical recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    /// Information was inferred rather than directly decoded.
    Inferred,
    /// The payload is unsupported by the current recovery logic.
    Unsupported,
}

/// Confidence assigned to a recovered value or issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Directly decoded from canonical data.
    Exact,
    /// Inferred from partial evidence.
    Inferred,
    /// Confidence could not be determined.
    Unknown,
}

/// Semantic fallback that produced an inferred value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticProvenance {
    /// Node name suffix was used to infer semantics.
    NodeNameSuffixInference,
    /// Reference namespace was missing.
    MissingReferenceNamespace,
    /// Reference file type was missing.
    MissingReferenceFileType,
    /// Nested reference include path fallback was used.
    NestedReferenceIncludePath,
}

/// One issue emitted during MB-to-MA recovery or reporting.
#[derive(Debug, Clone)]
pub struct MayaAsciiIssue {
    /// Recovered node type.
    pub node_type: String,
    /// Recovered node name.
    pub node_name: String,
    /// Issue classification.
    pub kind: IssueKind,
    /// Confidence level for the recovered value.
    pub confidence: Confidence,
    /// Attribute or synthetic slot associated with the issue.
    pub attr_name: String,
    /// Optional human-readable reason.
    pub reason: Option<String>,
    /// Semantic fallback that produced the issue.
    pub semantic_provenance: Option<SemanticProvenance>,
    /// Optional value kind marker in hex.
    pub value_kind_hex: Option<String>,
    /// Raw payload size in bytes.
    pub payload_size: Option<usize>,
    /// Payload digest when computed.
    pub payload_digest_hex: Option<String>,
    /// Short payload preview in hex.
    pub payload_preview_hex: Option<String>,
    /// Full payload rendered inline in hex when small enough.
    pub payload_inline_hex: Option<String>,
    /// External blob reference when payload was materialized separately.
    pub payload_blob_ref: Option<String>,
    /// Unknown refedit tail offset.
    pub refedit_unknown_tail_offset: Option<usize>,
    /// Unknown refedit tail opcode in hex.
    pub refedit_unknown_tail_opcode_hex: Option<String>,
    /// Unknown refedit tail payload size.
    pub refedit_unknown_tail_payload_size: Option<usize>,
    /// Unknown refedit tail payload preview in hex.
    pub refedit_unknown_tail_payload_preview_hex: Option<String>,
    /// Decoder attempts recorded for the payload.
    pub decoder_attempts: Vec<MayaAsciiDecodeAttempt>,
    /// Raw chunk form when provenance is available.
    pub trace_form: Option<String>,
    /// Raw chunk tag when provenance is available.
    pub trace_tag: Option<String>,
    /// Raw chunk node offset when provenance is available.
    pub trace_node_offset: Option<usize>,
    /// Raw chunk aux value when provenance is available.
    pub trace_chunk_aux: Option<u32>,
    /// Raw child alignment hint when provenance is available.
    pub trace_child_alignment: Option<usize>,
    /// Raw child header size hint when provenance is available.
    pub trace_child_header_size: Option<usize>,
}

/// Aggregated unknown-chunk inventory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownInventoryEntry {
    /// Raw chunk form.
    pub trace_form: Option<String>,
    /// Raw chunk tag.
    pub trace_tag: Option<String>,
    /// Raw chunk aux value.
    pub trace_chunk_aux: Option<u32>,
    /// Number of occurrences.
    pub count: usize,
    /// Sum of raw payload sizes.
    pub payload_size_sum: usize,
}

/// Quality bucket for recovered decode coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeQuality {
    /// Fully decoded.
    Exact,
    /// Partially decoded.
    Partial,
    /// Examined but passed through.
    Pass,
    /// Failed to decode.
    Failed,
}

/// Aggregate conversion report returned by MB-to-MA conversion APIs.
#[derive(Debug, Clone)]
pub struct MayaAsciiConversionReport {
    /// Output Maya ASCII path.
    pub output_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Operation policy used for the conversion.
    pub operation_mode: OperationMode,
    /// Integrity summary for the recovered scene.
    pub validation_state: ValidationState,
    /// Issues emitted during recovery.
    pub issues: Vec<MayaAsciiIssue>,
    /// Raw chunks captured for reporting.
    pub raw_chunks: Vec<RawChunkDump>,
    /// Aggregated unknown inventory.
    pub unknown_inventory: Vec<UnknownInventoryEntry>,
    /// Decode quality histogram by form and tag.
    pub decode_quality_distribution: Vec<DecodeQualityDistributionEntry>,
    /// Count of raw chunks seen during conversion.
    pub raw_chunk_count: usize,
    /// Total raw payload size in bytes.
    pub raw_payload_size_total: usize,
    /// Total unknown payload size in bytes.
    pub unknown_payload_size_total: usize,
    /// Ratio of unknown payload bytes to total raw payload bytes.
    pub unknown_payload_size_ratio: f64,
}

/// Non-destructive staged conversion result owned by the edit layer.
#[derive(Debug, Clone)]
pub struct MayaAsciiStageResult {
    /// Report for the staged conversion output.
    pub report: MayaAsciiConversionReport,
    /// Staged output bytes that can be saved later.
    pub artifact: StagedSceneArtifact,
}

/// One decode-quality histogram row.
#[derive(Debug, Clone)]
pub struct DecodeQualityDistributionEntry {
    /// Quality bucket.
    pub quality: DecodeQuality,
    /// Chunk form.
    pub form: String,
    /// Chunk tag.
    pub tag: String,
    /// Number of matching chunks.
    pub count: usize,
}
