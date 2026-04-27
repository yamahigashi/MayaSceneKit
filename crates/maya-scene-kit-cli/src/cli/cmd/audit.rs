use std::{
    collections::BTreeMap,
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use serde_json::json;

use super::super::{
    fs::collect_scene_files,
    output_contracts::JSON_CONTRACT_VERSION,
    render::{
        json::{render_audit_hit_json, render_audit_notice_json, render_review_signal_json},
        text::{
            group_audit_hit_indexes, group_review_signal_indexes, render_audit_notice_text,
            render_coverage_issue_detail, render_dependency_fact_detail, render_execution_reason,
            render_grouped_audit_hit_text, render_grouped_review_signal_text,
            render_unit_summary_text,
        },
    },
    runtime_context::load_options,
};
use crate::scene::{
    AuditOptions, AuditReport, ExecutionCoverageIssue, SceneToolError,
    audit_reference_graph_roots_with_options_and_digests, build_script_audit_plan,
};

pub(crate) struct ScriptAuditArgs<'a> {
    pub(crate) input: &'a Path,
    pub(crate) inline_rules: Vec<String>,
    pub(crate) json_output: bool,
    pub(crate) summary_only: bool,
    pub(crate) max_preview: usize,
    pub(crate) node_info_paths: &'a [PathBuf],
    pub(crate) max_bytes: Option<usize>,
}

pub(crate) fn run_script_audit(args: ScriptAuditArgs<'_>) -> i32 {
    let ScriptAuditArgs {
        input,
        inline_rules,
        json_output,
        summary_only,
        max_preview,
        node_info_paths,
        max_bytes,
    } = args;

    let plan = match build_script_audit_plan(inline_rules, max_preview) {
        Ok(plan) => plan,
        Err(SceneToolError::Config(err)) | Err(SceneToolError::Message(err)) => {
            eprintln!("error: {err}");
            return 2;
        }
        Err(err) => {
            eprintln!("scene error: {err}");
            return 1;
        }
    };
    let load_options = load_options(node_info_paths, max_bytes);

    let files = match collect_scene_files(input) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => {
            eprintln!("error: no .ma/.mb files found: {}", input.display());
            return 2;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let audit_options = AuditOptions::strict_default();
    let graph_report = audit_reference_graph_roots_with_options_and_digests(
        files.iter().map(PathBuf::as_path),
        &plan,
        &load_options,
        audit_options,
        false,
    );
    if graph_report.reports.is_empty()
        && graph_report
            .traversal_issues
            .iter()
            .any(|issue| issue.kind == crate::scene::AuditTraversalIssueKind::LoadFailed)
    {
        for issue in &graph_report.traversal_issues {
            eprintln!("scene error: {}", issue.message);
        }
        return 1;
    }

    if json_output {
        let mut file_summaries = Vec::new();
        for report in &graph_report.reports {
            let file_hit_count = report.finding_count();
            let file_review_count = report.review_signal_count();
            let file_notice_count = report.notice_count();
            let scene_path = report.scene_path.to_string_lossy();
            file_summaries.push((
                scene_path.clone().into_owned(),
                report.scene_format,
                file_hit_count,
                file_review_count,
                file_notice_count,
                report.surface_count,
                report.validation_state,
                report.coverage_state,
                report.coverage_issues.len(),
                report.blocked_on_uncertainty,
                report.disposition,
            ));
        }

        let reports = &graph_report.reports;
        let all_hit_count = reports
            .iter()
            .map(|report| report.findings.len())
            .sum::<usize>();
        let all_review_count = reports
            .iter()
            .map(|report| report.review_signals.len())
            .sum::<usize>();
        let all_notice_count = reports
            .iter()
            .map(|report| report.notices.len())
            .sum::<usize>();
        let doc = json!({
            "contract_version": JSON_CONTRACT_VERSION,
            "input": input.display().to_string(),
            "profile": audit_options.profile.as_str(),
            "graph": {
                "root_count": graph_report.roots.len(),
                "scene_count": graph_report.reports.len(),
                "edge_count": graph_report.edges.len(),
                "traversal_issue_count": graph_report.traversal_issues.len(),
                "disposition": graph_report.disposition.as_str(),
                "roots": &graph_report.roots,
                "edges": &graph_report.edges,
                "traversal_issues": &graph_report.traversal_issues,
            },
            "files": file_summaries.iter().map(|(path, format, hit_count, review_count, notice_count, surface_count, validation_state, coverage_state, coverage_issue_count, blocked_on_uncertainty, disposition)| json!({
                "path": path,
                "scene_format": format.as_str(),
                "finding_count": hit_count,
                "review_signal_count": review_count,
                "notice_count": notice_count,
                "disposition": disposition.as_str(),
                "surface_count": surface_count,
                "validation_state": validation_state,
                "coverage_state": coverage_state.as_str(),
                "coverage_issue_count": coverage_issue_count,
                "blocked_on_uncertainty": blocked_on_uncertainty,
            })).collect::<Vec<_>>(),
            "unit_summaries": reports
                .iter()
                .flat_map(|report| {
                    let scene_path = report.scene_path.to_string_lossy();
                    report.unit_summaries.iter().map(move |summary| {
                        json!({
                            "path": scene_path.as_ref(),
                            "effect": summary.effect.as_str(),
                            "semantic_class": summary.semantic_class.as_str(),
                            "certainty": summary.certainty.as_str(),
                            "preview": summary.preview,
                            "reasons": summary.reasons.iter().map(render_execution_reason).collect::<Vec<_>>(),
                            "origin": {
                                "lang": summary.origin.lang.as_str(),
                                "trigger": summary.origin.trigger.as_str(),
                                "surface_kind": summary.origin.surface_kind.as_str(),
                                "node_name": summary.origin.node_name.clone(),
                                "attr_name": summary.origin.attr_name.clone(),
                                "source_kind": summary.origin.source_kind.clone(),
                                "chunk_form": summary.origin.chunk_form.clone(),
                                "chunk_tag": summary.origin.chunk_tag.clone(),
                                "chunk_node_offset": summary.origin.chunk_node_offset,
                                "chunk_aux": summary.origin.chunk_aux,
                                "chunk_payload_offset": summary.origin.chunk_payload_offset,
                                "chunk_payload_size": summary.origin.chunk_payload_size,
                                "chunk_child_alignment": summary.origin.chunk_child_alignment,
                                "chunk_child_header_size": summary.origin.chunk_child_header_size,
                            }
                        })
                    })
                })
                .collect::<Vec<_>>(),
            "dependency_facts": reports
                .iter()
                .flat_map(|report| {
                    let scene_path = report.scene_path.to_string_lossy();
                    report.dependency_facts.iter().map(move |fact| {
                        json!({
                            "path": scene_path.as_ref(),
                            "kind": fact.kind.as_str(),
                            "risk": fact.risk.as_str(),
                            "target": fact.target,
                            "message": render_dependency_fact_detail(&fact.detail),
                            "origin": fact.origin.as_ref().map(|origin| json!({
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
                            })),
                        })
                    })
                })
                .collect::<Vec<_>>(),
            "finding_count": all_hit_count,
            "review_signal_count": all_review_count,
            "notice_count": all_notice_count,
            "coverage_issue_count": reports
                .iter()
                .map(|report| report.coverage_issues.len())
                .sum::<usize>(),
            "notices": reports
                .iter()
                .flat_map(|report| {
                    let scene_path = report.scene_path.to_string_lossy();
                    report
                        .notices
                        .iter()
                        .map(move |notice| render_audit_notice_json(scene_path.as_ref(), report, notice))
                })
                .collect::<Vec<_>>(),
            "review_signals": reports
                .iter()
                .flat_map(|report| {
                    let scene_path = report.scene_path.to_string_lossy();
                    report
                        .review_signals
                        .iter()
                        .map(move |review| render_review_signal_json(scene_path.as_ref(), report, review))
                })
                .collect::<Vec<_>>(),
            "hits": reports
                .iter()
                .flat_map(|report| {
                    let scene_path = report.scene_path.to_string_lossy();
                    report
                        .findings
                        .iter()
                        .map(move |hit| render_audit_hit_json(scene_path.as_ref(), report, hit))
                })
                .collect::<Vec<_>>(),
            "coverage_issues": reports
                .iter()
                .flat_map(|report| {
                    let scene_path = report.scene_path.to_string_lossy();
                    report.coverage_issues.iter().map(move |issue| {
                        json!({
                            "path": scene_path.as_ref(),
                            "scene_format": report.scene_format.as_str(),
                            "coverage_state": report.coverage_state.as_str(),
                            "kind": issue.kind.as_str(),
                            "message": render_coverage_issue_detail(&issue.detail),
                            "preview": if issue.preview.is_empty() { None } else { Some(issue.preview.clone()) },
                            "origin": issue.origin.as_ref().map(|origin| json!({
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
                            })),
                        })
                    })
                })
                .collect::<Vec<_>>(),
            "coverage_issue_groups": reports
                .iter()
                .flat_map(|report| {
                    let scene_path = report.scene_path.to_string_lossy();
                    grouped_coverage_issues(report).into_iter().map(move |group| {
                        let issue = group.issue;
                        json!({
                            "path": scene_path.as_ref(),
                            "scene_format": report.scene_format.as_str(),
                            "coverage_state": report.coverage_state.as_str(),
                            "kind": issue.kind.as_str(),
                            "message": group.message,
                            "count": group.count,
                            "preview": if issue.preview.is_empty() { None } else { Some(issue.preview.clone()) },
                            "origin": issue.origin.as_ref().map(|origin| json!({
                                "lang": origin.lang.as_str(),
                                "trigger": origin.trigger.as_str(),
                                "surface_kind": origin.surface_kind.as_str(),
                                "node_name": null,
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
                            })),
                        })
                    })
                })
                .collect::<Vec<_>>(),
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: failed to render json: {e}");
                return 1;
            }
        }

        match graph_report.disposition {
            crate::scene::AuditDisposition::Allow
            | crate::scene::AuditDisposition::AllowWithNotice => 0,
            crate::scene::AuditDisposition::Review => 20,
            crate::scene::AuditDisposition::DenyMalicious => 10,
            crate::scene::AuditDisposition::DenyUncertain => 11,
        }
    } else {
        let stdout = io::stdout();
        let mut output = io::BufWriter::with_capacity(256 * 1024, stdout.lock());
        let mut total_findings = 0usize;

        for report in &graph_report.reports {
            let file_hit_count = report.finding_count();
            let file_review_count = report.review_signal_count();
            let file_notice_count = report.notice_count();
            let scene_path = report.scene_path.to_string_lossy();

            let _ = writeln!(
                output,
                "path={} format={} profile={} state={} coverage_state={} coverage_issues={} blocked_on_uncertainty={} disposition={} findings={} reviews={} notices={} surfaces={}",
                scene_path.as_ref(),
                report.scene_format.as_str(),
                audit_options.profile.as_str(),
                report.validation_state,
                report.coverage_state.as_str(),
                report.coverage_issues.len(),
                report.blocked_on_uncertainty,
                report.disposition.as_str(),
                file_hit_count,
                file_review_count,
                file_notice_count,
                report.surface_count,
            );

            total_findings += report.findings.len();

            if summary_only {
                continue;
            }

            for summary in &report.unit_summaries {
                let _ = writeln!(
                    output,
                    "{}",
                    render_unit_summary_text(scene_path.as_ref(), summary)
                );
            }
            for notice in &report.notices {
                let _ = writeln!(
                    output,
                    "{}",
                    render_audit_notice_text(scene_path.as_ref(), notice)
                );
            }
            for (review_index, count) in group_review_signal_indexes(report) {
                let review = &report.review_signals[review_index];
                let _ = writeln!(
                    output,
                    "{}",
                    render_grouped_review_signal_text(scene_path.as_ref(), report, review, count)
                );
            }
            for (hit_index, count) in group_audit_hit_indexes(report) {
                let hit = &report.findings[hit_index];
                let _ = writeln!(
                    output,
                    "{}",
                    render_grouped_audit_hit_text(scene_path.as_ref(), report, hit, count)
                );
            }
            for fact in &report.dependency_facts {
                let _ = writeln!(
                    output,
                    "- dependency path={} kind={} risk={} target=\"{}\" msg=\"{}\"",
                    scene_path.as_ref(),
                    fact.kind.as_str(),
                    fact.risk.as_str(),
                    fact.target,
                    render_dependency_fact_detail(&fact.detail),
                );
            }
            for group in grouped_coverage_issues(report) {
                let issue = group.issue;
                let _ = writeln!(
                    output,
                    "- coverage path={} gate=block coverage_state={} kind={} count={} msg=\"{}\" preview=\"{}\"",
                    scene_path.as_ref(),
                    report.coverage_state.as_str(),
                    issue.kind.as_str(),
                    group.count,
                    group.message,
                    issue.preview,
                );
            }
        }
        for issue in &graph_report.traversal_issues {
            let _ = writeln!(
                output,
                "- reference_graph_issue kind={:?} scene_path={} source_path={} target=\"{}\" msg=\"{}\"",
                issue.kind,
                issue
                    .scene_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
                issue
                    .source_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
                issue.raw_target.as_deref().unwrap_or(""),
                issue.message,
            );
        }
        let _ = writeln!(output, "total_findings={total_findings}");

        match graph_report.disposition {
            crate::scene::AuditDisposition::Allow
            | crate::scene::AuditDisposition::AllowWithNotice => 0,
            crate::scene::AuditDisposition::Review => 20,
            crate::scene::AuditDisposition::DenyMalicious => 10,
            crate::scene::AuditDisposition::DenyUncertain => 11,
        }
    }
}

struct GroupedCoverageIssue<'a> {
    issue: &'a ExecutionCoverageIssue,
    message: String,
    count: usize,
}

fn grouped_coverage_issues(report: &AuditReport) -> Vec<GroupedCoverageIssue<'_>> {
    let mut groups = Vec::<GroupedCoverageIssue<'_>>::new();
    let mut index_by_key = BTreeMap::<String, usize>::new();
    for issue in &report.coverage_issues {
        let message = render_coverage_issue_detail(&issue.detail);
        let key = coverage_issue_group_key(issue, &message);
        if let Some(index) = index_by_key.get(&key).copied() {
            groups[index].count += 1;
        } else {
            index_by_key.insert(key, groups.len());
            groups.push(GroupedCoverageIssue {
                issue,
                message,
                count: 1,
            });
        }
    }
    groups
}

fn coverage_issue_group_key(issue: &ExecutionCoverageIssue, message: &str) -> String {
    let origin = issue.origin.as_ref();
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}",
        issue.kind.as_str(),
        message,
        origin.map(|value| value.lang.as_str()).unwrap_or(""),
        origin
            .map(|value| value.surface_kind.as_str())
            .unwrap_or(""),
        origin
            .and_then(|value| value.attr_name.as_deref())
            .unwrap_or(""),
        origin
            .and_then(|value| value.source_kind.as_deref())
            .unwrap_or(""),
    )
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tempfile::tempdir;

    use super::{ScriptAuditArgs, grouped_coverage_issues, run_script_audit};
    use crate::scene::{
        AuditDisposition, AuditProfile, AuditReport, ExecutionCoverageIssue,
        ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind, ExecutionCoverageState,
        ExecutionLanguage, ExecutionOrigin, ExecutionSurfaceKind, ExecutionTrigger, SceneDigestSet,
        SceneFormat, ValidationState,
    };

    #[test]
    fn run_script_audit_budget_exceed_returns_review_exit_code() {
        let dir = tempdir().expect("tmpdir");
        let source = dir.path().join("blocked.ma");
        fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"blocked\";\n",
                "    setAttr \".b\" -type \"string\" \"print(\\\"hi\\\")\";\n",
                "    setAttr \".st\" 0;\n",
            ),
        )
        .expect("write scene");

        let code = run_script_audit(ScriptAuditArgs {
            input: &source,
            inline_rules: Vec::new(),
            json_output: true,
            summary_only: false,
            max_preview: 64,
            node_info_paths: &[],
            max_bytes: Some(1),
        });

        assert_eq!(code, 20);
    }

    #[test]
    fn coverage_issue_grouping_ignores_node_names() {
        let origin = |node_name: &str| ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::TimeChanged,
            surface_kind: ExecutionSurfaceKind::NodeAttrCallback,
            node_name: Some(node_name.to_string()),
            attr_name: Some(".ixp".to_string()),
            source_range: None,
            source_kind: Some("internalExpression".to_string()),
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        };
        let issue = |node_name: &str| ExecutionCoverageIssue {
            kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
            detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
                diagnostic: "unexpected token while parsing item".to_string(),
            },
            origin: Some(origin(node_name)),
            preview: String::new(),
        };
        let report = AuditReport {
            scene_path: PathBuf::from("example.ma"),
            scene_format: SceneFormat::Ma,
            profile: AuditProfile::StrictDefault,
            validation_state: ValidationState::Validated,
            effective_rules: Vec::new(),
            surface_count: 2,
            coverage_state: ExecutionCoverageState::Incomplete,
            coverage_issues: vec![issue("ExampleExpressionA"), issue("ExampleExpressionB")],
            blocked_on_uncertainty: true,
            disposition: AuditDisposition::Review,
            unit_summaries: Vec::new(),
            dependency_facts: Vec::new(),
            unknown_semantics: Vec::new(),
            digests: SceneDigestSet {
                scene_sha256: String::new(),
                schema_bundle_sha256: None,
                policy_bundle_sha256: None,
            },
            notices: Vec::new(),
            surfaces: Vec::new(),
            review_signals: Vec::new(),
            findings: Vec::new(),
        };

        let groups = grouped_coverage_issues(&report);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 2);
    }
}
