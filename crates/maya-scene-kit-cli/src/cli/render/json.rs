use serde_json::json;

use super::text::{render_audit_evidence, render_audit_finding_detail, render_audit_review_detail};
use crate::scene::{AuditFinding, AuditNotice, AuditReport, AuditReviewSignal};

pub(in crate::cli) fn render_audit_hit_json(
    scene_path: &str,
    report: &AuditReport,
    hit: &AuditFinding,
) -> serde_json::Value {
    let surface = report.surface_for(hit);
    let preview = report.finding_preview(hit);
    let mut value = json!({
        "path": scene_path,
        "scene_format": report.scene_format.as_str(),
        "finding_id": hit.code.as_str(),
        "severity": hit.severity.as_str(),
        "sink": hit.sink.as_str(),
        "rule": hit.rule,
        "message": render_audit_finding_detail(&hit.detail),
        "evidence": hit.evidence.iter().map(render_audit_evidence).collect::<Vec<_>>(),
        "preview": if preview.is_empty() { None } else { Some(preview.to_string()) },
        "origin": render_execution_origin_json(&surface.origin)
    });
    if let Some(allowed) = &hit.allowed_by {
        value["allowed_by"] = json!(allowed);
    }
    value
}

pub(in crate::cli) fn render_review_signal_json(
    scene_path: &str,
    report: &AuditReport,
    review: &AuditReviewSignal,
) -> serde_json::Value {
    let surface = report.surface_for_review(review);
    let preview = report.review_preview(review);
    json!({
        "path": scene_path,
        "scene_format": report.scene_format.as_str(),
        "review_id": review.code.as_str(),
        "message": render_audit_review_detail(&review.detail),
        "evidence": review.evidence.iter().map(render_audit_evidence).collect::<Vec<_>>(),
        "preview": if preview.is_empty() { None } else { Some(preview.to_string()) },
        "origin": render_execution_origin_json(&surface.origin)
    })
}

pub(in crate::cli) fn render_audit_notice_json(
    scene_path: &str,
    report: &AuditReport,
    notice: &AuditNotice,
) -> serde_json::Value {
    json!({
        "path": scene_path,
        "scene_format": report.scene_format.as_str(),
        "notice_id": notice.code.as_str(),
        "severity": notice.severity.as_str(),
        "message": notice.message,
    })
}

pub(in crate::cli) fn render_execution_origin_json(
    origin: &crate::scene::ExecutionOrigin,
) -> serde_json::Value {
    let mut value = json!({
        "lang": origin.lang.as_str(),
        "trigger": origin.trigger.as_str(),
        "surface_kind": origin.surface_kind.as_str(),
        "node_name": origin.node_name.clone(),
        "attr_name": origin.attr_name.clone(),
        "source_kind": origin.source_kind.clone(),
        "chunk_form": origin.chunk_form.clone(),
        "chunk_tag": origin.chunk_tag.clone(),
        "chunk_node_offset": origin.chunk_node_offset,
        "chunk_aux": origin.chunk_aux,
        "chunk_payload_offset": origin.chunk_payload_offset,
        "chunk_payload_size": origin.chunk_payload_size,
        "chunk_child_alignment": origin.chunk_child_alignment,
        "chunk_child_header_size": origin.chunk_child_header_size,
    });
    if origin.overwritten {
        value["overwritten"] = json!(true);
        value["assignment_index"] = json!(origin.assignment_index);
    }
    value
}
