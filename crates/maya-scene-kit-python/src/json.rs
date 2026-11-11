use maya_scene_kit_audit::scene::{
    AuditFinding, AuditGraphReport, AuditNotice, AuditReport, AuditReviewSignal, AuditSurface,
};
use maya_scene_kit_edit::scene::{
    DecodeQualityDistributionEntry, MayaAsciiConversionReport, MayaAsciiDecodeAttempt,
    MayaAsciiIssue, PathReplacePreview, PathReplacePreviewItem, PathReplaceResult, RawChunkDump,
    ScriptNodeCleanPreview, ScriptNodeCleanResult, UnknownInventoryEntry,
};
use maya_scene_kit_observe::scene::{
    inspect::{MbInspectNode, MbInspectReport},
    paths::{ScenePathEntry, ScenePathMeta, ScenePathsReport},
    scripts::ScriptNodeEntriesReport,
};
use serde_json::{Value, json};

pub(crate) fn inspect_report(report: &MbInspectReport) -> Value {
    json!({
        "scene_path": report.scene_path.to_string_lossy(),
        "scene_format": report.scene_format,
        "root": inspect_node(&report.root),
    })
}

pub(crate) fn scene_paths_report(report: &ScenePathsReport) -> Value {
    json!({
        "scene_path": report.scene_path.to_string_lossy(),
        "scene_format": report.scene_format,
        "validation_state": report.validation_state,
        "count": report.count(),
        "entries": report.entries.iter().map(scene_path_entry).collect::<Vec<_>>(),
    })
}

pub(crate) fn script_entries_report(report: &ScriptNodeEntriesReport) -> Value {
    json!({
        "scene_path": report.scene_path.to_string_lossy(),
        "scene_format": report.scene_format,
        "validation_state": report.validation_state,
        "count": report.entries.len(),
        "entries": report.entries.iter().map(|entry| {
            json!({
                "name": entry.name,
                "body": entry.body,
            })
        }).collect::<Vec<_>>(),
    })
}

pub(crate) fn audit_report(report: &AuditReport) -> Value {
    json!({
        "scene_path": report.scene_path.to_string_lossy(),
        "scene_format": report.scene_format,
        "profile": report.profile.as_str(),
        "validation_state": report.validation_state,
        "surface_count": report.surface_count,
        "coverage_state": report.coverage_state.as_str(),
        "coverage_issues": report.coverage_issues,
        "blocked_on_uncertainty": report.blocked_on_uncertainty,
        "disposition": report.disposition.as_str(),
        "effective_rules": report.effective_rules,
        "unit_summaries": report.unit_summaries,
        "dependency_facts": report.dependency_facts,
        "unknown_semantics": report.unknown_semantics,
        "digests": report.digests,
        "notices": report.notices.iter().map(audit_notice).collect::<Vec<_>>(),
        "surfaces": report.surfaces.iter().map(audit_surface).collect::<Vec<_>>(),
        "review_signals": report.review_signals.iter().map(audit_review_signal).collect::<Vec<_>>(),
        "findings": report.findings.iter().map(audit_finding).collect::<Vec<_>>(),
        "notice_count": report.notice_count(),
        "finding_count": report.finding_count(),
        "allowed_finding_count": report.allowed_finding_count(),
        "review_signal_count": report.review_signal_count(),
    })
}

pub(crate) fn audit_graph_report(report: &AuditGraphReport) -> Value {
    let root_report = report
        .roots
        .first()
        .and_then(|root| root.report_index)
        .and_then(|index| report.reports.get(index));
    let blocked_on_uncertainty = !report.traversal_issues.is_empty()
        || report
            .reports
            .iter()
            .any(|scene_report| scene_report.blocked_on_uncertainty);
    let surface_count = report
        .reports
        .iter()
        .map(|scene_report| scene_report.surface_count)
        .sum::<usize>();
    let coverage_issues = report
        .reports
        .iter()
        .flat_map(|scene_report| scene_report.coverage_issues.iter())
        .collect::<Vec<_>>();
    let notices = report
        .reports
        .iter()
        .flat_map(|scene_report| scene_report.notices.iter().map(audit_notice))
        .collect::<Vec<_>>();
    let review_signals = report
        .reports
        .iter()
        .flat_map(|scene_report| scene_report.review_signals.iter().map(audit_review_signal))
        .collect::<Vec<_>>();
    let findings = report
        .reports
        .iter()
        .flat_map(|scene_report| scene_report.findings.iter().map(audit_finding))
        .collect::<Vec<_>>();

    json!({
        "scene_path": report.roots.first().map(|root| root.path.to_string_lossy()),
        "profile": root_report.map(|scene_report| scene_report.profile.as_str()),
        "validation_state": root_report.map(|scene_report| &scene_report.validation_state),
        "coverage_state": root_report.map(|scene_report| scene_report.coverage_state.as_str()),
        "coverage_issues": coverage_issues,
        "blocked_on_uncertainty": blocked_on_uncertainty,
        "disposition": report.disposition.as_str(),
        "root_count": report.roots.len(),
        "scene_count": report.reports.len(),
        "edge_count": report.edges.len(),
        "traversal_issue_count": report.traversal_issues.len(),
        "surface_count": surface_count,
        "finding_count": report.finding_count(),
        "allowed_finding_count": report.allowed_finding_count(),
        "review_signal_count": report.review_signal_count(),
        "notice_count": report.notice_count(),
        "notices": notices,
        "review_signals": review_signals,
        "findings": findings,
        "roots": report.roots.iter().map(|root| json!({
            "path": root.path.to_string_lossy(),
            "identity": root.identity,
            "report_index": root.report_index,
            "issue_index": root.issue_index,
        })).collect::<Vec<_>>(),
        "edges": report.edges.iter().map(|edge| json!({
            "source_identity": edge.source_identity,
            "source_path": edge.source_path.to_string_lossy(),
            "raw_target": edge.raw_target,
            "resolved_path": edge.resolved_path.as_ref().map(|path| path.to_string_lossy()),
            "resolution_status": edge.resolution_status,
            "target_identity": edge.target_identity,
            "target_report_index": edge.target_report_index,
            "issue_index": edge.issue_index,
        })).collect::<Vec<_>>(),
        "traversal_issues": report.traversal_issues.iter().map(|issue| json!({
            "kind": issue.kind,
            "scene_path": issue.scene_path.as_ref().map(|path| path.to_string_lossy()),
            "source_path": issue.source_path.as_ref().map(|path| path.to_string_lossy()),
            "raw_target": issue.raw_target,
            "message": issue.message,
        })).collect::<Vec<_>>(),
        "reports": report.reports.iter().map(audit_report).collect::<Vec<_>>(),
        "root_report": root_report.map(audit_report),
    })
}

pub(crate) fn script_node_clean_preview(preview: &ScriptNodeCleanPreview) -> Value {
    json!({
        "input_path": preview.input_path.to_string_lossy(),
        "scene_format": preview.scene_format,
        "operation_mode": preview.operation_mode,
        "validation_state": preview.validation_state,
        "removed_nodes": preview.removed_nodes,
        "removed_count": preview.removed_count(),
    })
}

pub(crate) fn script_node_clean_result(result: &ScriptNodeCleanResult) -> Value {
    json!({
        "input_path": result.input_path.to_string_lossy(),
        "output_path": result.output_path.to_string_lossy(),
        "scene_format": result.scene_format,
        "operation_mode": result.operation_mode,
        "validation_state": result.validation_state,
        "removed_nodes": result.removed_nodes,
        "removed_count": result.removed_count(),
    })
}

pub(crate) fn path_replace_preview(preview: &PathReplacePreview) -> Value {
    json!({
        "input_path": preview.input_path.to_string_lossy(),
        "scene_format": preview.scene_format,
        "operation_mode": preview.operation_mode,
        "validation_state": preview.validation_state,
        "matched_count": preview.matched_count,
        "applied_count": preview.applied_count,
        "items": preview.items.iter().map(path_replace_preview_item).collect::<Vec<_>>(),
    })
}

pub(crate) fn path_replace_result(result: &PathReplaceResult) -> Value {
    json!({
        "input_path": result.input_path.to_string_lossy(),
        "output_path": result.output_path.to_string_lossy(),
        "scene_format": result.scene_format,
        "operation_mode": result.operation_mode,
        "validation_state": result.validation_state,
        "replaced_count": result.replaced_count,
        "skipped": result.skipped,
    })
}

pub(crate) fn maya_ascii_conversion_report(report: &MayaAsciiConversionReport) -> Value {
    json!({
        "output_path": report.output_path.to_string_lossy(),
        "scene_format": report.scene_format,
        "operation_mode": report.operation_mode,
        "validation_state": report.validation_state,
        "raw_chunk_count": report.raw_chunk_count,
        "raw_payload_size_total": report.raw_payload_size_total,
        "unknown_payload_size_total": report.unknown_payload_size_total,
        "unknown_payload_size_ratio": report.unknown_payload_size_ratio,
        "issues": report.issues.iter().map(maya_ascii_issue).collect::<Vec<_>>(),
        "raw_chunks": report.raw_chunks.iter().map(raw_chunk_dump).collect::<Vec<_>>(),
        "unknown_inventory": report.unknown_inventory.iter().map(unknown_inventory_entry).collect::<Vec<_>>(),
        "decode_quality_distribution": report.decode_quality_distribution.iter().map(decode_quality_distribution_entry).collect::<Vec<_>>(),
    })
}

fn inspect_node(node: &MbInspectNode) -> Value {
    json!({
        "tag": node.tag,
        "offset": node.offset,
        "aux": node.aux,
        "size": node.size,
        "payload_offset": node.payload_offset,
        "payload_end": node.payload_end,
        "child_alignment": node.child_alignment,
        "child_header_size": node.child_header_size,
        "form_type": node.form_type,
        "opaque": node.opaque,
        "payload_preview": node.payload_preview,
        "children": node.children.iter().map(inspect_node).collect::<Vec<_>>(),
    })
}

fn scene_path_entry(entry: &ScenePathEntry) -> Value {
    json!({
        "node_type": entry.node_type,
        "node_name": entry.node_name,
        "attr": entry.attr,
        "value": entry.value,
        "meta": entry.meta.as_ref().map(scene_path_meta),
    })
}

fn scene_path_meta(meta: &ScenePathMeta) -> Value {
    json!({
        "origin": meta.origin,
        "short_name": meta.short_name,
        "reference_node": meta.reference_node,
        "format_hint": meta.format_hint,
        "reference_options": meta.reference_options,
        "color_space": meta.color_space,
        "raw_fields": meta.raw_fields,
        "trace_form": meta.trace_form,
        "trace_tag": meta.trace_tag,
        "trace_node_offset": meta.trace_node_offset,
        "trace_child_alignment": meta.trace_child_alignment,
        "trace_child_header_size": meta.trace_child_header_size,
    })
}

fn audit_surface(surface: &AuditSurface) -> Value {
    json!({
        "origin": surface.origin,
        "preview": surface.preview,
        "derivation": surface.derivation.as_str(),
    })
}

fn audit_finding(finding: &AuditFinding) -> Value {
    json!({
        "code": finding.code.as_str(),
        "severity": finding.severity.as_str(),
        "surface_index": finding.surface_index,
        "sink": finding.sink.as_str(),
        "rule": finding.rule,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "preview_override": finding.preview_override.clone(),
        "allowed_by": finding.allowed_by,
    })
}

fn audit_review_signal(review: &AuditReviewSignal) -> Value {
    json!({
        "code": review.code.as_str(),
        "surface_index": review.surface_index,
        "detail": review.detail,
        "evidence": review.evidence,
        "preview_override": review.preview_override.clone(),
    })
}

fn audit_notice(notice: &AuditNotice) -> Value {
    json!({
        "code": notice.code.as_str(),
        "severity": notice.severity.as_str(),
        "message": notice.message,
    })
}

fn path_replace_preview_item(item: &PathReplacePreviewItem) -> Value {
    json!({
        "node_type": item.node_type,
        "node_name": item.node_name,
        "attr": item.attr,
        "before_value": item.before_value,
        "after_value": item.after_value,
        "replacement_count": item.replacement_count,
    })
}

fn maya_ascii_issue(issue: &MayaAsciiIssue) -> Value {
    json!({
        "node_type": issue.node_type,
        "node_name": issue.node_name,
        "kind": issue.kind,
        "confidence": issue.confidence,
        "attr_name": issue.attr_name,
        "reason": issue.reason,
        "semantic_provenance": issue.semantic_provenance,
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
        "decoder_attempts": issue.decoder_attempts.iter().map(maya_ascii_decode_attempt).collect::<Vec<_>>(),
        "trace_form": issue.trace_form,
        "trace_tag": issue.trace_tag,
        "trace_node_offset": issue.trace_node_offset,
        "trace_chunk_aux": issue.trace_chunk_aux,
        "trace_child_alignment": issue.trace_child_alignment,
        "trace_child_header_size": issue.trace_child_header_size,
    })
}

fn maya_ascii_decode_attempt(attempt: &MayaAsciiDecodeAttempt) -> Value {
    json!({
        "decoder_id": attempt.decoder_id,
        "result": attempt.result,
        "reason": attempt.reason,
    })
}

fn raw_chunk_dump(chunk: &RawChunkDump) -> Value {
    json!({
        "trace_form": chunk.trace_form,
        "trace_tag": chunk.trace_tag,
        "trace_node_offset": chunk.trace_node_offset,
        "trace_chunk_aux": chunk.trace_chunk_aux,
        "trace_child_alignment": chunk.trace_child_alignment,
        "trace_child_header_size": chunk.trace_child_header_size,
        "payload_size": chunk.payload.len(),
    })
}

fn unknown_inventory_entry(entry: &UnknownInventoryEntry) -> Value {
    json!({
        "trace_form": entry.trace_form,
        "trace_tag": entry.trace_tag,
        "trace_chunk_aux": entry.trace_chunk_aux,
        "count": entry.count,
        "payload_size_sum": entry.payload_size_sum,
    })
}

fn decode_quality_distribution_entry(entry: &DecodeQualityDistributionEntry) -> Value {
    json!({
        "quality": entry.quality,
        "form": entry.form,
        "tag": entry.tag,
        "count": entry.count,
    })
}

#[cfg(test)]
mod path_replace_tests {
    #[test]
    fn path_replace_json_preserves_skip_counts_and_unknown_binary_detection() {
        use maya_scene_kit_edit::scene::{PathReplaceMode, PathReplaceRule, replace_scene_paths};
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("Example.ma");
        let output = directory.path().join("Sample.ma");
        let prefix = b"//Maya ASCII 2026 scene\n// Codeset: 932\ncreateNode file -n \"Example\";\n    setAttr \".ftn\" -type \"string\" \"old/\x81?Example.ma\";\n";
        std::fs::write(
            &input,
            [prefix.as_slice(), b"file -r \"unfinished"].concat(),
        )
        .unwrap();
        let result = replace_scene_paths(
            &input,
            &output,
            &[PathReplaceRule {
                from: "old/".into(),
                to: "asset/".into(),
                mode: PathReplaceMode::Literal,
            }],
        )
        .unwrap();
        let value = super::path_replace_result(&result);
        assert_eq!(value["replaced_count"], 0);
        assert_eq!(value["skipped"]["non_utf8"], 1);
        assert_eq!(value["skipped"]["non_canonical_escape"], 0);
        assert_eq!(value["skipped"]["unrepresentable"], 0);
        assert_eq!(value["skipped"]["crosses_concat_boundary"], 0);
        assert_eq!(value["skipped"]["unterminated_tail"], 1);
        assert_eq!(value["skipped"]["unterminated_tail_from"], prefix.len());
        let binary =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/02/sphere.mb");
        let result = replace_scene_paths(binary, directory.path().join("Sample.mb"), &[]).unwrap();
        let value = super::path_replace_result(&result);
        assert_eq!(value["skipped"]["non_utf8"], 0);
        assert_eq!(value["skipped"]["payload_rejected"], 0);
        assert!(value["skipped"]["non_canonical_escape"].is_null());
        assert!(value["skipped"]["unterminated_tail_from"].is_null());
    }
}

#[cfg(all(test, unix))]
mod graph_path_tests {
    use super::*;

    fn graph() -> AuditGraphReport {
        serde_json::from_value(json!({
            "roots": [{"path": "asset/example/Example.ma", "identity": "Example", "report_index": null, "issue_index": 0}],
            "reports": [],
            "edges": [{"source_identity": "Example", "source_path": "asset/example/Example.ma", "raw_target": "Sample.ma", "resolved_path": "asset/example/Sample.ma", "resolution_status": "Missing", "target_identity": null, "target_report_index": null, "issue_index": 0}],
            "traversal_issues": [{"kind": "missing_reference", "scene_path": "asset/example/Sample.ma", "source_path": "asset/example/Example.ma", "raw_target": "Sample.ma", "message": "Example missing reference"}],
            "disposition": "allow"
        })).unwrap()
    }

    #[test]
    fn graph_paths_render_lossily_and_preserve_utf8_json() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

        let report = graph();
        let expected = json!({
            "scene_path": "asset/example/Example.ma",
            "profile": null, "validation_state": null, "coverage_state": null,
            "coverage_issues": [], "blocked_on_uncertainty": true, "disposition": "allow",
            "root_count": 1, "scene_count": 0, "edge_count": 1, "traversal_issue_count": 1,
            "surface_count": 0, "finding_count": 0, "allowed_finding_count": 0,
            "review_signal_count": 0, "notice_count": 0, "notices": [],
            "review_signals": [], "findings": [], "roots": report.roots,
            "edges": report.edges, "traversal_issues": report.traversal_issues,
            "reports": [], "root_report": null
        });
        assert_eq!(
            audit_graph_report(&report).to_string(),
            expected.to_string()
        );

        let invalid = PathBuf::from(OsString::from_vec(b"asset/example/\xff.ma".to_vec()));
        let pointers = [
            "/roots/0/path",
            "/edges/0/source_path",
            "/edges/0/resolved_path",
            "/traversal_issues/0/scene_path",
            "/traversal_issues/0/source_path",
        ];
        let mut panics = Vec::new();
        for (index, pointer) in pointers.iter().enumerate() {
            let mut report = graph();
            match index {
                0 => report.roots[0].path = invalid.clone(),
                1 => report.edges[0].source_path = invalid.clone(),
                2 => report.edges[0].resolved_path = Some(invalid.clone()),
                3 => report.traversal_issues[0].scene_path = Some(invalid.clone()),
                4 => report.traversal_issues[0].source_path = Some(invalid.clone()),
                _ => unreachable!(),
            }
            match std::panic::catch_unwind(|| audit_graph_report(&report)) {
                Ok(value) => {
                    assert_eq!(value.pointer(pointer).unwrap(), "asset/example/�.ma");
                    if index == 0 {
                        assert_eq!(value["scene_path"], "asset/example/�.ma");
                    }
                }
                Err(_) => panics.push(*pointer),
            }
        }
        assert!(panics.is_empty(), "path rendering panicked: {panics:?}");
    }
}

#[cfg(test)]
mod audit_key_tests {
    use std::collections::BTreeSet;

    use maya_scene_kit_audit::scene::{ExecutionLanguage, audit_source_text};
    use maya_scene_kit_observe::scene::evidence::{
        ExecutionCoverageIssue, ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind,
    };

    use super::*;

    fn populated_report() -> AuditReport {
        let mut report = audit_source_text(
            "import os\nos.system('echo Example')",
            ExecutionLanguage::Python,
        )
        .unwrap();
        report.scene_path = "asset/example/Example.ma".into();
        report.coverage_issues.push(ExecutionCoverageIssue {
            kind: ExecutionCoverageIssueKind::TopLevelDiagnostics,
            detail: ExecutionCoverageIssueDetail::TopLevelDiagnostics {
                diagnostic: "Example diagnostic".into(),
            },
            origin: None,
            preview: "Example".into(),
        });
        report.digests.scene_sha256 = "0".repeat(64);
        report.digests.schema_bundle_sha256 = Some("1".repeat(64));
        report.digests.policy_bundle_sha256 = Some("2".repeat(64));
        assert!(!report.findings.is_empty());
        assert!(!report.coverage_issues.is_empty());
        assert!(!report.digests.scene_sha256.is_empty());
        report
    }

    fn assert_keys(rendered: Value, serialized: Value, extra_keys: &[&str]) {
        let actual = rendered
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut expected = serialized
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        expected.extend(extra_keys.iter().copied());
        assert_eq!(actual, expected);
    }

    #[test]
    fn audit_notice_keys_include_all_serde_fields() {
        let notice = AuditNotice::parse_budget_exceeded(1);
        assert_keys(
            audit_notice(&notice),
            serde_json::to_value(&notice).unwrap(),
            &[],
        );
    }

    #[test]
    fn audit_surface_keys_include_all_serde_fields() {
        let report = populated_report();
        let surface = &report.surfaces[0];
        assert_keys(
            audit_surface(surface),
            serde_json::to_value(surface).unwrap(),
            &[],
        );
    }

    #[test]
    fn audit_finding_keys_include_all_serde_fields() {
        use maya_scene_kit_audit::scene::{AllowlistSource, AuditAllowRef};

        let mut report = populated_report();
        let finding = &mut report.findings[0];
        finding.allowed_by = Some(AuditAllowRef {
            hash: format!("sha256:{}", "0".repeat(64)).parse().unwrap(),
            source: AllowlistSource::User,
        });
        let serialized = serde_json::to_value(&*finding).unwrap();
        assert!(serialized["allowed_by"].is_object());
        assert_keys(audit_finding(finding), serialized, &[]);
    }

    #[test]
    fn audit_review_signal_keys_include_all_serde_fields() {
        use maya_scene_kit_audit::scene::{AuditReviewCode, AuditReviewDetail};

        let signal = AuditReviewSignal {
            code: AuditReviewCode::PythonMayaUncertain,
            surface_index: 0,
            detail: AuditReviewDetail::FreeText {
                message: "Example review".into(),
            },
            evidence: vec![],
            preview_override: Some("Example".into()),
        };
        assert_keys(
            audit_review_signal(&signal),
            serde_json::to_value(&signal).unwrap(),
            &[],
        );
    }

    #[test]
    fn audit_report_keys_include_all_serde_fields() {
        let report = populated_report();
        assert_keys(
            audit_report(&report),
            serde_json::to_value(&report).unwrap(),
            &[
                "notice_count",
                "finding_count",
                "allowed_finding_count",
                "review_signal_count",
            ],
        );
    }

    #[test]
    fn audit_graph_report_keys_include_all_serde_fields() {
        let scene_report = populated_report();
        let report = AuditGraphReport {
            roots: vec![maya_scene_kit_audit::scene::AuditGraphRoot {
                path: "asset/example/Example.ma".into(),
                identity: Some("Example".into()),
                report_index: Some(0),
                issue_index: None,
            }],
            disposition: scene_report.disposition,
            reports: vec![scene_report],
            edges: vec![],
            traversal_issues: vec![],
        };
        assert_keys(
            audit_graph_report(&report),
            serde_json::to_value(&report).unwrap(),
            &[
                "scene_path",
                "profile",
                "validation_state",
                "coverage_state",
                "coverage_issues",
                "blocked_on_uncertainty",
                "root_count",
                "scene_count",
                "edge_count",
                "traversal_issue_count",
                "surface_count",
                "finding_count",
                "allowed_finding_count",
                "review_signal_count",
                "notice_count",
                "notices",
                "review_signals",
                "findings",
                "root_report",
            ],
        );
    }
}
