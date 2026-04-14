use std::fmt::Write as _;

use super::{ChunkRef, ChunkTrace, Confidence, RefEditUnknownTail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryIssueKind {
    Inferred,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticProvenance {
    NodeNameSuffixInference,
    MissingReferenceNamespace,
    MissingReferenceFileType,
    NestedReferenceIncludePath,
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

#[derive(Debug, Clone)]
pub struct NodeRecoveryIssue {
    pub node_type: String,
    pub node_name: String,
    pub issue: RecoveryIssue,
}

impl RecoveryIssue {
    pub fn inferred_analysis(attr_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            kind: RecoveryIssueKind::Inferred,
            confidence: Confidence::Inferred,
            attr_name: attr_name.into(),
            reason: Some(reason.into()),
            semantic_provenance: None,
            value_kind_hex: None,
            payload_size: None,
            payload_digest_hex: None,
            payload_preview_hex: None,
            payload_inline_hex: None,
            refedit_unknown_tail_offset: None,
            refedit_unknown_tail_opcode_hex: None,
            refedit_unknown_tail_payload_size: None,
            refedit_unknown_tail_payload_preview_hex: None,
            decoder_attempts: vec![],
            trace: None,
        }
    }

    pub fn inferred_analysis_with_provenance(
        attr_name: impl Into<String>,
        reason: impl Into<String>,
        semantic_provenance: SemanticProvenance,
    ) -> Self {
        let mut issue = Self::inferred_analysis(attr_name, reason);
        issue.semantic_provenance = Some(semantic_provenance);
        issue
    }

    pub fn inferred_refedit_unknown_tail(
        attr_name: impl Into<String>,
        tail: &RefEditUnknownTail,
    ) -> Self {
        let preview_len = tail.payload.len().min(48);
        let mut preview_hex = String::with_capacity(preview_len * 2);
        for byte in &tail.payload[..preview_len] {
            write!(&mut preview_hex, "{byte:02X}").expect("write hex");
        }
        Self {
            kind: RecoveryIssueKind::Inferred,
            confidence: Confidence::Inferred,
            attr_name: attr_name.into(),
            reason: Some("reference edit contains unknown opcode tail".to_string()),
            semantic_provenance: None,
            value_kind_hex: None,
            payload_size: None,
            payload_digest_hex: None,
            payload_preview_hex: None,
            payload_inline_hex: None,
            refedit_unknown_tail_offset: Some(tail.start_offset),
            refedit_unknown_tail_opcode_hex: Some(format!("0x{:02X}", tail.opcode)),
            refedit_unknown_tail_payload_size: Some(tail.payload.len()),
            refedit_unknown_tail_payload_preview_hex: Some(preview_hex),
            decoder_attempts: vec![],
            trace: None,
        }
    }

    pub fn to_decode_note(&self) -> String {
        let mut parts: Vec<String> = vec![];
        match self.kind {
            RecoveryIssueKind::Inferred => parts.push("inferred".to_string()),
            RecoveryIssueKind::Unsupported => parts.push("unsupported".to_string()),
        }
        parts.push(format!("attr={}", self.attr_name));

        if let Some(reason) = &self.reason {
            parts.push(format!("reason={reason}"));
        }
        if let Some(provenance) = self.semantic_provenance {
            let label = match provenance {
                SemanticProvenance::NodeNameSuffixInference => "node_name_suffix_inference",
                SemanticProvenance::MissingReferenceNamespace => "missing_reference_namespace",
                SemanticProvenance::MissingReferenceFileType => "missing_reference_file_type",
                SemanticProvenance::NestedReferenceIncludePath => "nested_reference_include_path",
            };
            parts.push(format!("semantic_provenance={label}"));
        }
        if let Some(kind_hex) = &self.value_kind_hex {
            parts.push(format!("kind={kind_hex}"));
        }
        if let Some(payload) = self.payload_size {
            parts.push(format!("payload={payload}"));
        }
        if let Some(d) = &self.payload_digest_hex {
            parts.push(format!("digest={d}"));
        }
        if let Some(offset) = self.refedit_unknown_tail_offset {
            parts.push(format!("refedit_unknown_tail_offset={offset}"));
        }
        if let Some(opcode_hex) = &self.refedit_unknown_tail_opcode_hex {
            parts.push(format!("refedit_unknown_tail_opcode={opcode_hex}"));
        }
        if let Some(size) = self.refedit_unknown_tail_payload_size {
            parts.push(format!("refedit_unknown_tail_bytes={size}"));
        }
        if !self.decoder_attempts.is_empty() {
            let attempts = self
                .decoder_attempts
                .iter()
                .map(|attempt| {
                    let result = match attempt.result {
                        SchemaDecodeAttemptResult::Exact => "exact",
                        SchemaDecodeAttemptResult::Partial => "partial",
                        SchemaDecodeAttemptResult::Pass => "pass",
                        SchemaDecodeAttemptResult::Failed => "failed",
                    };
                    match &attempt.reason {
                        Some(reason) => format!("{}:{result}({reason})", attempt.decoder_id),
                        None => format!("{}:{result}", attempt.decoder_id),
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            parts.push(format!("attempts={attempts}"));
        }
        if let Some(trace) = &self.trace {
            if let Some(aux) = trace.chunk_aux {
                parts.push(format!(
                    "trace={}:{}@0x{:X}/aux=0x{:08X}",
                    trace.form, trace.tag, trace.node_offset, aux
                ));
            } else {
                parts.push(format!(
                    "trace={}:{}@0x{:X}",
                    trace.form, trace.tag, trace.node_offset
                ));
            }
        }

        parts.join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownEvent {
    pub reason: String,
    pub payload_size: usize,
    pub payload_digest_hex: String,
    pub payload_preview_hex: String,
    pub payload_inline_hex: Option<String>,
    pub decoder_attempts: Vec<SchemaDecodeAttempt>,
    pub trace: ChunkTrace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaDecodeAttemptResult {
    Exact,
    Partial,
    Pass,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDecodeAttempt {
    pub decoder_id: String,
    pub result: SchemaDecodeAttemptResult,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeQualityRecord {
    pub chunk_ref: ChunkRef,
    pub quality: SchemaDecodeAttemptResult,
}

#[cfg(test)]
mod tests {
    use super::{RecoveryIssue, RefEditUnknownTail, SemanticProvenance};

    #[test]
    fn inferred_refedit_unknown_tail_sets_structured_fields() {
        let tail = RefEditUnknownTail {
            start_offset: 42,
            opcode: 0xAB,
            payload: b"\xABhello".to_vec(),
        };
        let issue = RecoveryIssue::inferred_refedit_unknown_tail(".ed", &tail);
        assert_eq!(
            issue.reason.as_deref(),
            Some("reference edit contains unknown opcode tail")
        );
        assert_eq!(issue.refedit_unknown_tail_offset, Some(42));
        assert_eq!(
            issue.refedit_unknown_tail_opcode_hex.as_deref(),
            Some("0xAB")
        );
        assert_eq!(issue.refedit_unknown_tail_payload_size, Some(6));
        assert_eq!(
            issue.refedit_unknown_tail_payload_preview_hex.as_deref(),
            Some("AB68656C6C6F")
        );
    }

    #[test]
    fn inferred_analysis_with_provenance_sets_structured_source() {
        let issue = RecoveryIssue::inferred_analysis_with_provenance(
            "<CREA>",
            "node type inferred from name suffix",
            SemanticProvenance::NodeNameSuffixInference,
        );
        assert_eq!(
            issue.semantic_provenance,
            Some(SemanticProvenance::NodeNameSuffixInference)
        );
        assert!(
            issue
                .to_decode_note()
                .contains("semantic_provenance=node_name_suffix_inference")
        );
    }
}
