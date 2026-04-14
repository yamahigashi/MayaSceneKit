use std::path::Path;

use serde_json::{Value, json};

use crate::scene::{MayaAsciiConversionReport, PathKind};

pub(crate) const JSON_CONTRACT_VERSION: u32 = 4;

pub(crate) fn scene_path_kind_label(kind: PathKind) -> &'static str {
    match kind {
        PathKind::All => "all",
        PathKind::File => "file",
        PathKind::Reference => "reference",
    }
}

pub(crate) fn unknown_blob_dir_name(stem: &str) -> String {
    format!("{stem}.unknown_blobs")
}

pub(crate) fn build_to_ascii_issues_json(
    input: &Path,
    report: &MayaAsciiConversionReport,
) -> Value {
    json!({
        "contract_version": JSON_CONTRACT_VERSION,
        "source": input,
        "output": report.output_path,
        "scene_format": report.scene_format,
        "operation_mode": report.operation_mode,
        "validation_state": report.validation_state,
        "raw_chunk_count": report.raw_chunk_count,
        "raw_payload_size_total": report.raw_payload_size_total,
        "issue_count": report.issues.len(),
        "unknown_payload_size_total": report.unknown_payload_size_total,
        "unknown_payload_size_ratio": report.unknown_payload_size_ratio,
        "decode_quality_distribution": report.decode_quality_distribution.iter().map(|entry| {
            json!({
                "quality": entry.quality,
                "form": entry.form,
                "tag": entry.tag,
                "count": entry.count,
            })
        }).collect::<Vec<_>>(),
        "unknown_inventory": report.unknown_inventory.iter().map(|entry| {
            json!({
                "trace_form": entry.trace_form,
                "trace_tag": entry.trace_tag,
                "trace_chunk_aux": entry.trace_chunk_aux,
                "count": entry.count,
                "payload_size_sum": entry.payload_size_sum,
            })
        }).collect::<Vec<_>>(),
        "issues": report.issues.iter().map(|issue| {
            json!({
                "node_type": issue.node_type,
                "node_name": issue.node_name,
                "kind": issue.kind,
                "confidence": issue.confidence,
                "attr_name": issue.attr_name,
                "reason": issue.reason,
                "value_kind_hex": issue.value_kind_hex,
                "payload_size": issue.payload_size,
                "payload_digest_hex": issue.payload_digest_hex,
                "payload_preview_hex": issue.payload_preview_hex,
                "payload_inline_hex": issue.payload_inline_hex,
                "payload_blob_ref": issue.payload_blob_ref,
                "refedit_unknown_tail_offset": issue.refedit_unknown_tail_offset,
                "refedit_unknown_tail_opcode_hex": issue.refedit_unknown_tail_opcode_hex,
                "refedit_unknown_tail_payload_size": issue.refedit_unknown_tail_payload_size,
                "refedit_unknown_tail_payload_preview_hex": issue.refedit_unknown_tail_payload_preview_hex,
                "decoder_attempts": issue.decoder_attempts.iter().map(|attempt| {
                    json!({
                        "decoder_id": attempt.decoder_id,
                        "result": attempt.result,
                        "reason": attempt.reason,
                    })
                }).collect::<Vec<_>>(),
                "trace_form": issue.trace_form,
                "trace_tag": issue.trace_tag,
                "trace_node_offset": issue.trace_node_offset,
                "trace_chunk_aux": issue.trace_chunk_aux,
                "trace_child_alignment": issue.trace_child_alignment,
                "trace_child_header_size": issue.trace_child_header_size,
            })
        }).collect::<Vec<_>>(),
    })
}
