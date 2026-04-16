use maya_scene_kit_observe::scene::{
    forensics::{
        Confidence as InternalConfidence, NodeRecoveryIssue, RecoveryIssueKind,
        SchemaDecodeAttemptResult, SemanticProvenance as InternalSemanticProvenance,
    },
};

use super::{
    Confidence, DecodeAttemptResult, DecodeQuality, DecodeQualityDistributionEntry, IssueKind,
    MayaAsciiDecodeAttempt, MayaAsciiIssue, SemanticProvenance, UnknownInventoryEntry,
};
use crate::scene::ops;

pub(crate) fn map_node_recovery_issues(issues: Vec<NodeRecoveryIssue>) -> Vec<MayaAsciiIssue> {
    issues
        .into_iter()
        .map(|i| {
            let trace_form = i.issue.trace.as_ref().map(|t| t.form.clone());
            let trace_tag = i.issue.trace.as_ref().map(|t| t.tag.clone());
            let trace_node_offset = i.issue.trace.as_ref().map(|t| t.node_offset);
            let trace_chunk_aux = i.issue.trace.as_ref().and_then(|t| t.chunk_aux);
            let trace_child_alignment = i.issue.trace.as_ref().and_then(|t| t.child_alignment);
            let trace_child_header_size = i.issue.trace.as_ref().and_then(|t| t.child_header_size);

            MayaAsciiIssue {
                node_type: i.node_type,
                node_name: i.node_name,
                kind: match i.issue.kind {
                    RecoveryIssueKind::Inferred => IssueKind::Inferred,
                    RecoveryIssueKind::Unsupported => IssueKind::Unsupported,
                },
                confidence: match i.issue.confidence {
                    InternalConfidence::Exact => Confidence::Exact,
                    InternalConfidence::Inferred => Confidence::Inferred,
                    InternalConfidence::Unknown => Confidence::Unknown,
                },
                attr_name: i.issue.attr_name,
                reason: i.issue.reason,
                semantic_provenance: i.issue.semantic_provenance.map(
                    |provenance| match provenance {
                        InternalSemanticProvenance::NodeNameSuffixInference => {
                            SemanticProvenance::NodeNameSuffixInference
                        }
                        InternalSemanticProvenance::MissingReferenceNamespace => {
                            SemanticProvenance::MissingReferenceNamespace
                        }
                        InternalSemanticProvenance::MissingReferenceFileType => {
                            SemanticProvenance::MissingReferenceFileType
                        }
                        InternalSemanticProvenance::NestedReferenceIncludePath => {
                            SemanticProvenance::NestedReferenceIncludePath
                        }
                    },
                ),
                value_kind_hex: i.issue.value_kind_hex,
                payload_size: i.issue.payload_size,
                payload_digest_hex: i.issue.payload_digest_hex,
                payload_preview_hex: i.issue.payload_preview_hex,
                payload_inline_hex: i.issue.payload_inline_hex,
                payload_blob_ref: None,
                refedit_unknown_tail_offset: i.issue.refedit_unknown_tail_offset,
                refedit_unknown_tail_opcode_hex: i.issue.refedit_unknown_tail_opcode_hex,
                refedit_unknown_tail_payload_size: i.issue.refedit_unknown_tail_payload_size,
                refedit_unknown_tail_payload_preview_hex: i
                    .issue
                    .refedit_unknown_tail_payload_preview_hex,
                decoder_attempts: i
                    .issue
                    .decoder_attempts
                    .into_iter()
                    .map(|attempt| MayaAsciiDecodeAttempt {
                        decoder_id: attempt.decoder_id,
                        result: match attempt.result {
                            SchemaDecodeAttemptResult::Exact => DecodeAttemptResult::Exact,
                            SchemaDecodeAttemptResult::Partial => DecodeAttemptResult::Partial,
                            SchemaDecodeAttemptResult::Pass => DecodeAttemptResult::Pass,
                            SchemaDecodeAttemptResult::Failed => DecodeAttemptResult::Failed,
                        },
                        reason: attempt.reason,
                    })
                    .collect(),
                trace_form,
                trace_tag,
                trace_node_offset,
                trace_chunk_aux,
                trace_child_alignment,
                trace_child_header_size,
            }
        })
        .collect()
}

pub(crate) fn build_unknown_inventory(issues: &[MayaAsciiIssue]) -> Vec<UnknownInventoryEntry> {
    type UnknownKey = (Option<String>, Option<String>, Option<u32>);
    type UnknownStats = (usize, usize);

    let mut grouped: std::collections::BTreeMap<UnknownKey, UnknownStats> =
        std::collections::BTreeMap::new();

    for issue in issues {
        if issue.kind != IssueKind::Unsupported || issue.attr_name != "<unknown-chunk>" {
            continue;
        }
        let entry = grouped
            .entry((
                issue.trace_form.clone(),
                issue.trace_tag.clone(),
                issue.trace_chunk_aux,
            ))
            .or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(issue.payload_size.unwrap_or(0));
    }

    grouped
        .into_iter()
        .map(
            |((trace_form, trace_tag, trace_chunk_aux), (count, payload_size_sum))| {
                UnknownInventoryEntry {
                    trace_form,
                    trace_tag,
                    trace_chunk_aux,
                    count,
                    payload_size_sum,
                }
            },
        )
        .collect()
}

pub(in crate::scene) fn to_public_decode_quality_entry(
    entry: ops::DecodeQualityDistributionEntry,
) -> DecodeQualityDistributionEntry {
    DecodeQualityDistributionEntry {
        quality: entry.quality,
        form: entry.form,
        tag: entry.tag,
        count: entry.count,
    }
}

pub(crate) fn map_decode_quality(result: SchemaDecodeAttemptResult) -> DecodeQuality {
    match result {
        SchemaDecodeAttemptResult::Exact => DecodeQuality::Exact,
        SchemaDecodeAttemptResult::Partial => DecodeQuality::Partial,
        SchemaDecodeAttemptResult::Pass => DecodeQuality::Pass,
        SchemaDecodeAttemptResult::Failed => DecodeQuality::Failed,
    }
}
