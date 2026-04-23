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
    json!({
        "path": scene_path,
        "scene_format": report.scene_format.as_str(),
        "finding_id": hit.code.as_str(),
        "severity": hit.severity.as_str(),
        "sink": hit.sink.as_str(),
        "rule": hit.rule,
        "message": render_audit_finding_detail(&hit.detail),
        "evidence": hit.evidence.iter().map(render_audit_evidence).collect::<Vec<_>>(),
        "preview": if preview.is_empty() { None } else { Some(preview.to_string()) },
        "origin": {
            "lang": surface.origin.lang.as_str(),
            "trigger": surface.origin.trigger.as_str(),
            "surface_kind": surface.origin.surface_kind.as_str(),
            "node_name": surface.origin.node_name.clone(),
            "attr_name": surface.origin.attr_name.clone(),
            "source_kind": surface.origin.source_kind.clone(),
            "chunk_form": surface.origin.chunk_form.clone(),
            "chunk_tag": surface.origin.chunk_tag.clone(),
            "chunk_node_offset": surface.origin.chunk_node_offset,
            "chunk_aux": surface.origin.chunk_aux,
            "chunk_payload_offset": surface.origin.chunk_payload_offset,
            "chunk_payload_size": surface.origin.chunk_payload_size,
            "chunk_child_alignment": surface.origin.chunk_child_alignment,
            "chunk_child_header_size": surface.origin.chunk_child_header_size,
        }
    })
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
        "origin": {
            "lang": surface.origin.lang.as_str(),
            "trigger": surface.origin.trigger.as_str(),
            "surface_kind": surface.origin.surface_kind.as_str(),
            "node_name": surface.origin.node_name.clone(),
            "attr_name": surface.origin.attr_name.clone(),
            "source_kind": surface.origin.source_kind.clone(),
            "chunk_form": surface.origin.chunk_form.clone(),
            "chunk_tag": surface.origin.chunk_tag.clone(),
            "chunk_node_offset": surface.origin.chunk_node_offset,
            "chunk_aux": surface.origin.chunk_aux,
            "chunk_payload_offset": surface.origin.chunk_payload_offset,
            "chunk_payload_size": surface.origin.chunk_payload_size,
            "chunk_child_alignment": surface.origin.chunk_child_alignment,
            "chunk_child_header_size": surface.origin.chunk_child_header_size,
        }
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
