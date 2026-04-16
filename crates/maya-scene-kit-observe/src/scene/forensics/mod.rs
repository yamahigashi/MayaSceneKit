#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Exact,
    Inferred,
    Unknown,
}

impl From<crate::scene::ir::Confidence> for Confidence {
    fn from(value: crate::scene::ir::Confidence) -> Self {
        match value {
            crate::scene::ir::Confidence::Exact => Self::Exact,
            crate::scene::ir::Confidence::Inferred => Self::Inferred,
            crate::scene::ir::Confidence::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    pub form: String,
    pub tag: String,
    pub node_offset: usize,
    pub parent_tag: Option<String>,
    pub chunk_aux: Option<u32>,
    pub child_alignment: Option<usize>,
    pub child_header_size: Option<usize>,
    pub payload_size: usize,
}

impl From<crate::scene::ir::ChunkRef> for ChunkRef {
    fn from(value: crate::scene::ir::ChunkRef) -> Self {
        Self {
            form: value.form,
            tag: value.tag,
            node_offset: value.node_offset,
            parent_tag: value.parent_tag,
            chunk_aux: value.chunk_aux,
            child_alignment: value.child_alignment,
            child_header_size: value.child_header_size,
            payload_size: value.payload_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkTrace {
    pub form: String,
    pub tag: String,
    pub node_offset: usize,
    pub chunk_aux: Option<u32>,
    pub child_alignment: Option<usize>,
    pub child_header_size: Option<usize>,
}

impl From<crate::scene::ir::ChunkTrace> for ChunkTrace {
    fn from(value: crate::scene::ir::ChunkTrace) -> Self {
        Self {
            form: value.form,
            tag: value.tag,
            node_offset: value.node_offset,
            chunk_aux: value.chunk_aux,
            child_alignment: value.child_alignment,
            child_header_size: value.child_header_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawChunkRecord {
    pub chunk_ref: ChunkRef,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaDecodeAttemptResult {
    Exact,
    Partial,
    Pass,
    Failed,
}

impl From<crate::scene::ir::SchemaDecodeAttemptResult> for SchemaDecodeAttemptResult {
    fn from(value: crate::scene::ir::SchemaDecodeAttemptResult) -> Self {
        match value {
            crate::scene::ir::SchemaDecodeAttemptResult::Exact => Self::Exact,
            crate::scene::ir::SchemaDecodeAttemptResult::Partial => Self::Partial,
            crate::scene::ir::SchemaDecodeAttemptResult::Pass => Self::Pass,
            crate::scene::ir::SchemaDecodeAttemptResult::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeQualityRecord {
    pub chunk_ref: ChunkRef,
    pub quality: SchemaDecodeAttemptResult,
}

impl From<crate::scene::ir::DecodeQualityRecord> for DecodeQualityRecord {
    fn from(value: crate::scene::ir::DecodeQualityRecord) -> Self {
        Self {
            chunk_ref: value.chunk_ref.into(),
            quality: value.quality.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDecodeAttempt {
    pub decoder_id: String,
    pub result: SchemaDecodeAttemptResult,
    pub reason: Option<String>,
}

impl From<crate::scene::ir::SchemaDecodeAttempt> for SchemaDecodeAttempt {
    fn from(value: crate::scene::ir::SchemaDecodeAttempt) -> Self {
        Self {
            decoder_id: value.decoder_id,
            result: value.result.into(),
            reason: value.reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryIssueKind {
    Inferred,
    Unsupported,
}

impl From<crate::scene::ir::RecoveryIssueKind> for RecoveryIssueKind {
    fn from(value: crate::scene::ir::RecoveryIssueKind) -> Self {
        match value {
            crate::scene::ir::RecoveryIssueKind::Inferred => Self::Inferred,
            crate::scene::ir::RecoveryIssueKind::Unsupported => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticProvenance {
    NodeNameSuffixInference,
    MissingReferenceNamespace,
    MissingReferenceFileType,
    NestedReferenceIncludePath,
}

impl From<crate::scene::ir::SemanticProvenance> for SemanticProvenance {
    fn from(value: crate::scene::ir::SemanticProvenance) -> Self {
        match value {
            crate::scene::ir::SemanticProvenance::NodeNameSuffixInference => {
                Self::NodeNameSuffixInference
            }
            crate::scene::ir::SemanticProvenance::MissingReferenceNamespace => {
                Self::MissingReferenceNamespace
            }
            crate::scene::ir::SemanticProvenance::MissingReferenceFileType => {
                Self::MissingReferenceFileType
            }
            crate::scene::ir::SemanticProvenance::NestedReferenceIncludePath => {
                Self::NestedReferenceIncludePath
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryIssue {
    pub kind: RecoveryIssueKind,
    pub confidence: Confidence,
    pub attr_name: String,
    pub reason: Option<String>,
    pub semantic_provenance: Option<SemanticProvenance>,
    pub value_kind_hex: Option<String>,
    pub payload_size: Option<usize>,
    pub payload_digest_hex: Option<String>,
    pub payload_preview_hex: Option<String>,
    pub payload_inline_hex: Option<String>,
    pub refedit_unknown_tail_offset: Option<usize>,
    pub refedit_unknown_tail_opcode_hex: Option<String>,
    pub refedit_unknown_tail_payload_size: Option<usize>,
    pub refedit_unknown_tail_payload_preview_hex: Option<String>,
    pub decoder_attempts: Vec<SchemaDecodeAttempt>,
    pub trace: Option<ChunkTrace>,
}

impl From<crate::scene::ir::RecoveryIssue> for RecoveryIssue {
    fn from(value: crate::scene::ir::RecoveryIssue) -> Self {
        Self {
            kind: value.kind.into(),
            confidence: value.confidence.into(),
            attr_name: value.attr_name,
            reason: value.reason,
            semantic_provenance: value.semantic_provenance.map(Into::into),
            value_kind_hex: value.value_kind_hex,
            payload_size: value.payload_size,
            payload_digest_hex: value.payload_digest_hex,
            payload_preview_hex: value.payload_preview_hex,
            payload_inline_hex: value.payload_inline_hex,
            refedit_unknown_tail_offset: value.refedit_unknown_tail_offset,
            refedit_unknown_tail_opcode_hex: value.refedit_unknown_tail_opcode_hex,
            refedit_unknown_tail_payload_size: value.refedit_unknown_tail_payload_size,
            refedit_unknown_tail_payload_preview_hex: value.refedit_unknown_tail_payload_preview_hex,
            decoder_attempts: value
                .decoder_attempts
                .into_iter()
                .map(Into::into)
                .collect(),
            trace: value.trace.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecoveryIssue {
    pub node_type: String,
    pub node_name: String,
    pub issue: RecoveryIssue,
}

impl From<crate::scene::ir::NodeRecoveryIssue> for NodeRecoveryIssue {
    fn from(value: crate::scene::ir::NodeRecoveryIssue) -> Self {
        Self {
            node_type: value.node_type,
            node_name: value.node_name,
            issue: value.issue.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TypeIdResolverStatus {
    Provided,
    #[default]
    LoadedDefault,
    DefaultLoadFailed {
        message: String,
    },
}

impl From<crate::scene::ir::TypeIdResolverStatus> for TypeIdResolverStatus {
    fn from(value: crate::scene::ir::TypeIdResolverStatus) -> Self {
        match value {
            crate::scene::ir::TypeIdResolverStatus::Provided => Self::Provided,
            crate::scene::ir::TypeIdResolverStatus::LoadedDefault => Self::LoadedDefault,
            crate::scene::ir::TypeIdResolverStatus::DefaultLoadFailed { message } => {
                Self::DefaultLoadFailed { message }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryForensics {
    pub raw_chunks: Vec<RawChunkRecord>,
    pub decode_qualities: Vec<DecodeQualityRecord>,
    pub typeid_resolver_status: TypeIdResolverStatus,
}
