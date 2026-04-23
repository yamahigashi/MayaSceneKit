use std::collections::HashMap;

use crate::scene::{
    AuditEvidence, AuditFinding, AuditFindingDetail, AuditNotice, AuditReport, AuditReviewDetail,
    AuditReviewSignal, DependencyFactDetail, ExecutionCoverageIssueDetail, ExecutionEffectClass,
    ExecutionOrigin, ExecutionReason, ExecutionReasonTemplate, ExecutionUnitSummary,
    StaticAuditFindingDetail, StaticAuditReviewDetail, StaticExecutionReason,
};

pub(in crate::cli) fn render_unit_summary_text(
    scene_path: &str,
    summary: &ExecutionUnitSummary,
) -> String {
    format!(
        "- unit path={} trigger={} lang={} effect={} semantic_class={} certainty={} reason=\"{}\"",
        scene_path,
        summary.origin.trigger.as_str(),
        summary.origin.lang.as_str(),
        summary.effect.as_str(),
        summary.semantic_class.as_str(),
        summary.certainty.as_str(),
        summarize_unit_reason(summary),
    )
}

pub(in crate::cli) fn summarize_unit_reason(summary: &ExecutionUnitSummary) -> String {
    let Some(primary_reason) = summary
        .reasons
        .iter()
        .find(|reason| reason_matches_effect(summary.effect, reason))
        .or_else(|| summary.reasons.first())
    else {
        return "-".to_string();
    };

    let extra_count = summary.reasons.len().saturating_sub(1);
    if extra_count == 0 {
        render_execution_reason(primary_reason)
    } else {
        format!(
            "{} (+{extra_count} more reasons)",
            render_execution_reason(primary_reason)
        )
    }
}

#[cfg(test)]
pub(in crate::cli) fn render_audit_hit_text(report: &AuditReport, hit: &AuditFinding) -> String {
    let scene_path = report.scene_path.display().to_string();
    render_grouped_audit_hit_text(&scene_path, report, hit, 1)
}

pub(in crate::cli) fn render_grouped_audit_hit_text(
    scene_path: &str,
    report: &AuditReport,
    hit: &AuditFinding,
    count: usize,
) -> String {
    let surface = report.surface_for(hit);
    let preview = report.finding_preview(hit);
    let mut parts = vec!["- finding".to_string(), format!("path={scene_path}")];
    if count > 1 {
        parts.push(format!("count={count}"));
    }
    parts.extend([
        format!("severity={}", hit.severity.as_str()),
        format!("sink={}", hit.sink.as_str()),
        format!("finding_id={}", hit.code.as_str()),
        format!(
            "node={}",
            surface.origin.node_name.as_deref().unwrap_or("-")
        ),
        format!(
            "attr={}",
            surface.origin.attr_name.as_deref().unwrap_or("-")
        ),
    ]);
    parts.extend(render_chunk_address_fields(&surface.origin));
    parts.push(format!(
        "msg=\"{}\"",
        render_audit_finding_detail(&hit.detail)
    ));
    if !hit.evidence.is_empty() {
        parts.push(format!(
            "evidence=\"{}\"",
            hit.evidence
                .iter()
                .map(render_audit_evidence)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if !preview.is_empty() {
        parts.push(format!("preview=\"{}\"", preview));
    }
    parts.join(" ")
}

pub(in crate::cli) fn render_grouped_review_signal_text(
    scene_path: &str,
    report: &AuditReport,
    review: &AuditReviewSignal,
    count: usize,
) -> String {
    let surface = report.surface_for_review(review);
    let preview = report.review_preview(review);
    let mut parts = vec!["- review".to_string(), format!("path={scene_path}")];
    if count > 1 {
        parts.push(format!("count={count}"));
    }
    parts.extend([
        format!("review_id={}", review.code.as_str()),
        format!(
            "node={}",
            surface.origin.node_name.as_deref().unwrap_or("-")
        ),
        format!(
            "attr={}",
            surface.origin.attr_name.as_deref().unwrap_or("-")
        ),
    ]);
    parts.extend(render_chunk_address_fields(&surface.origin));
    parts.push(format!(
        "msg=\"{}\"",
        render_audit_review_detail(&review.detail)
    ));
    if !review.evidence.is_empty() {
        parts.push(format!(
            "evidence=\"{}\"",
            review
                .evidence
                .iter()
                .map(render_audit_evidence)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if !preview.is_empty() {
        parts.push(format!("preview=\"{}\"", preview));
    }
    parts.join(" ")
}

fn render_chunk_address_fields(origin: &ExecutionOrigin) -> Vec<String> {
    let mut fields = vec![format!(
        "chunk={}:{}@{}",
        origin.chunk_form.as_deref().unwrap_or("-"),
        origin.chunk_tag.as_deref().unwrap_or("-"),
        origin
            .chunk_node_offset
            .map(|value| value.to_string())
            .as_deref()
            .unwrap_or("-")
    )];
    let Some(owner_offset) = origin.chunk_node_offset else {
        return fields;
    };
    let Some(payload_offset) = origin.chunk_payload_offset else {
        return fields;
    };
    let payload_size = origin.chunk_payload_size.unwrap_or_default();
    let payload_end = payload_offset.saturating_add(payload_size);
    fields.push(format!("addr=0x{owner_offset:08X}"));
    fields.push(format!(
        "payload=0x{payload_offset:08X}..0x{payload_end:08X}"
    ));
    if let Some(aux) = origin.chunk_aux {
        fields.push(format!("aux=0x{aux:08X}"));
    }
    fields
}

pub(in crate::cli) fn render_audit_notice_text(scene_path: &str, notice: &AuditNotice) -> String {
    format!(
        "- notice path={scene_path} severity={} notice_id={} msg=\"{}\"",
        notice.severity.as_str(),
        notice.code.as_str(),
        notice.message,
    )
}

pub(in crate::cli) fn group_audit_hit_indexes(report: &AuditReport) -> Vec<(usize, usize)> {
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut indexes: HashMap<GroupedAuditHitKey<'_>, usize> = HashMap::new();

    for (hit_index, hit) in report.findings.iter().enumerate() {
        let surface = report.surface_for(hit);
        let preview = report.finding_preview(hit);
        let key = GroupedAuditHitKey {
            finding_id: hit.code.as_str(),
            severity: hit.severity.as_str(),
            sink: hit.sink.as_str(),
            message: render_audit_finding_detail(&hit.detail),
            evidence: hit
                .evidence
                .iter()
                .map(render_audit_evidence)
                .collect::<Vec<_>>(),
            lang: surface.origin.lang.as_str(),
            trigger: surface.origin.trigger.as_str(),
            surface_kind: surface.origin.surface_kind.as_str(),
            node_name: surface.origin.node_name.as_deref(),
            attr_name: surface.origin.attr_name.as_deref(),
            chunk_form: surface.origin.chunk_form.as_deref(),
            chunk_tag: surface.origin.chunk_tag.as_deref(),
            chunk_node_offset: surface.origin.chunk_node_offset,
            chunk_payload_offset: surface.origin.chunk_payload_offset,
            chunk_payload_size: surface.origin.chunk_payload_size,
            preview,
        };
        if let Some(group_index) = indexes.get(&key).copied() {
            groups[group_index].1 += 1;
        } else {
            indexes.insert(key, groups.len());
            groups.push((hit_index, 1usize));
        }
    }

    groups
}

pub(in crate::cli) fn group_review_signal_indexes(report: &AuditReport) -> Vec<(usize, usize)> {
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut indexes: HashMap<GroupedReviewSignalKey<'_>, usize> = HashMap::new();

    for (review_index, review) in report.review_signals.iter().enumerate() {
        let surface = report.surface_for_review(review);
        let preview = report.review_preview(review);
        let key = GroupedReviewSignalKey {
            review_id: review.code.as_str(),
            message: render_audit_review_detail(&review.detail),
            evidence: review
                .evidence
                .iter()
                .map(render_audit_evidence)
                .collect::<Vec<_>>(),
            lang: surface.origin.lang.as_str(),
            trigger: surface.origin.trigger.as_str(),
            surface_kind: surface.origin.surface_kind.as_str(),
            node_name: surface.origin.node_name.as_deref(),
            attr_name: surface.origin.attr_name.as_deref(),
            chunk_form: surface.origin.chunk_form.as_deref(),
            chunk_tag: surface.origin.chunk_tag.as_deref(),
            chunk_node_offset: surface.origin.chunk_node_offset,
            chunk_payload_offset: surface.origin.chunk_payload_offset,
            chunk_payload_size: surface.origin.chunk_payload_size,
            preview,
        };
        if let Some(group_index) = indexes.get(&key).copied() {
            groups[group_index].1 += 1;
        } else {
            indexes.insert(key, groups.len());
            groups.push((review_index, 1usize));
        }
    }

    groups
}

fn reason_matches_effect(effect: ExecutionEffectClass, reason: &ExecutionReason) -> bool {
    match effect {
        ExecutionEffectClass::HookRegistration => matches!(
            reason,
            ExecutionReason::FlagOnCommand { .. }
                | ExecutionReason::Named {
                    template: ExecutionReasonTemplate::HookLikeMelCommandDetected,
                    ..
                }
        ),
        ExecutionEffectClass::DynamicEvaluation => matches!(
            reason,
            ExecutionReason::Named {
                template: ExecutionReasonTemplate::DynamicMelCommandDetected
                    | ExecutionReasonTemplate::DynamicPythonCallDetected,
                ..
            }
        ),
        ExecutionEffectClass::ExternalDependency => matches!(
            reason,
            ExecutionReason::Named {
                template: ExecutionReasonTemplate::ExternalDependencyMelCommandDetected
                    | ExecutionReasonTemplate::ExternalPythonCapabilityDetected
                    | ExecutionReasonTemplate::PythonImportDetected
                    | ExecutionReasonTemplate::PythonImportFromDetected,
                ..
            }
        ),
        ExecutionEffectClass::SceneMutation => matches!(
            reason,
            ExecutionReason::Named {
                template: ExecutionReasonTemplate::SceneMutatingMelCommandDetected,
                ..
            }
        ),
        ExecutionEffectClass::UIImpact => matches!(
            reason,
            ExecutionReason::Named {
                template: ExecutionReasonTemplate::UiImpactingMelCommandDetected,
                ..
            } | ExecutionReason::Static {
                value: StaticExecutionReason::PythonRaiseDetected
            }
        ),
        ExecutionEffectClass::SceneReadOnly => matches!(
            reason,
            ExecutionReason::Named {
                template: ExecutionReasonTemplate::ReadOnlyMelCommandDetected,
                ..
            } | ExecutionReason::Static {
                value: StaticExecutionReason::ReadOnlyMelOptionVarQueryDetected
            }
        ),
        ExecutionEffectClass::DiagnosticOutput => matches!(
            reason,
            ExecutionReason::Static {
                value: StaticExecutionReason::DiagnosticMelOutputDetected
                    | StaticExecutionReason::PythonPrintDetected
            }
        ),
        ExecutionEffectClass::Unknown => matches!(
            reason,
            ExecutionReason::Static {
                value: StaticExecutionReason::SurfaceLanguageUnknown
                    | StaticExecutionReason::NormalizedMelFactsUnavailable
                    | StaticExecutionReason::MelDiagnosticsPreventProvenEffectSummary
                    | StaticExecutionReason::PythonParseFailurePreventsProvenEffectSummary
                    | StaticExecutionReason::UnresolvedPythonCallTargetDetected
            } | ExecutionReason::Named {
                template: ExecutionReasonTemplate::UnclassifiedMelCommandDetected
                    | ExecutionReasonTemplate::UnclassifiedPythonCallDetected,
                ..
            }
        ),
        ExecutionEffectClass::PureComputation => matches!(
            reason,
            ExecutionReason::Static {
                value: StaticExecutionReason::NoMelCommandInvocationDetected
                    | StaticExecutionReason::PythonUnitEmpty
                    | StaticExecutionReason::NoSideEffectingPythonConstructsDetected
            }
        ),
    }
}

pub(in crate::cli) fn render_execution_reason(reason: &ExecutionReason) -> String {
    match reason {
        ExecutionReason::Static { value } => match value {
            StaticExecutionReason::SurfaceLanguageUnknown => {
                "surface language is unknown".to_string()
            }
            StaticExecutionReason::NormalizedMelFactsUnavailable => {
                "normalized MEL facts are unavailable".to_string()
            }
            StaticExecutionReason::MelDiagnosticsPreventProvenEffectSummary => {
                "MEL diagnostics prevent a proven effect summary".to_string()
            }
            StaticExecutionReason::NoMelCommandInvocationDetected => {
                "no MEL command invocation detected".to_string()
            }
            StaticExecutionReason::ExecutionUnitBodyEmpty => {
                "execution unit body is empty".to_string()
            }
            StaticExecutionReason::DiagnosticMelOutputDetected => {
                "diagnostic MEL output detected".to_string()
            }
            StaticExecutionReason::PythonParseFailurePreventsProvenEffectSummary => {
                "Python parse failure prevents a proven effect summary".to_string()
            }
            StaticExecutionReason::PythonRaiseDetected => "Python raise detected".to_string(),
            StaticExecutionReason::UnresolvedPythonCallTargetDetected => {
                "unresolved Python call target detected".to_string()
            }
            StaticExecutionReason::PythonUnitEmpty => "Python unit is empty".to_string(),
            StaticExecutionReason::NoSideEffectingPythonConstructsDetected => {
                "no side-effecting Python constructs detected".to_string()
            }
            StaticExecutionReason::PythonPrintDetected => "Python print detected".to_string(),
            StaticExecutionReason::ReadOnlyMelOptionVarQueryDetected => {
                "read-only MEL optionVar query detected".to_string()
            }
        },
        ExecutionReason::Named { template, value } => match template {
            ExecutionReasonTemplate::DynamicMelCommandDetected => {
                format!("dynamic MEL command `{value}` detected")
            }
            ExecutionReasonTemplate::HookLikeMelCommandDetected => {
                format!("hook-like MEL command `{value}` detected")
            }
            ExecutionReasonTemplate::ExternalDependencyMelCommandDetected => {
                format!("external-dependency MEL command `{value}` detected")
            }
            ExecutionReasonTemplate::SceneMutatingMelCommandDetected => {
                format!("scene-mutating MEL command `{value}` detected")
            }
            ExecutionReasonTemplate::UiImpactingMelCommandDetected => {
                format!("ui-impacting MEL command `{value}` detected")
            }
            ExecutionReasonTemplate::ReadOnlyMelCommandDetected => {
                format!("read-only MEL command `{value}` detected")
            }
            ExecutionReasonTemplate::UnclassifiedMelCommandDetected => {
                format!("unclassified MEL command `{value}` detected")
            }
            ExecutionReasonTemplate::DynamicPythonCallDetected => {
                format!("dynamic Python call `{value}` detected")
            }
            ExecutionReasonTemplate::ExternalPythonCapabilityDetected => {
                format!("external Python capability `{value}` detected")
            }
            ExecutionReasonTemplate::UnclassifiedPythonCallDetected => {
                format!("unclassified Python call `{value}` detected")
            }
            ExecutionReasonTemplate::PythonImportDetected => {
                format!("Python import `{value}` detected")
            }
            ExecutionReasonTemplate::PythonImportFromDetected => {
                format!("Python import-from `{value}` detected")
            }
        },
        ExecutionReason::FlagOnCommand {
            flag_name,
            command_name,
        } => format!("flag `{flag_name}` on command `{command_name}` detected"),
    }
}

pub(in crate::cli) fn render_dependency_fact_detail(detail: &DependencyFactDetail) -> String {
    match detail {
        DependencyFactDetail::Require => "scene declares a Maya require dependency".to_string(),
        DependencyFactDetail::ScenePath { node_type, attr } => {
            format!("scene path extracted from {node_type} {attr}")
        }
        DependencyFactDetail::MelDependencyObserved { command_name } => {
            format!("MEL `{command_name}` dependency observed")
        }
        DependencyFactDetail::FileCommandCallbackObserved => {
            "file -command callback observed".to_string()
        }
    }
}

pub(in crate::cli) fn render_coverage_issue_detail(
    detail: &ExecutionCoverageIssueDetail,
) -> String {
    match detail {
        ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic } => {
            format!("top-level MEL diagnostics present: {diagnostic}")
        }
        ExecutionCoverageIssueDetail::SurfaceDiagnostics { diagnostic } => {
            format!("surface MEL diagnostics present: {diagnostic}")
        }
        ExecutionCoverageIssueDetail::UnsupportedProcDefinition { is_global } => {
            if *is_global {
                "top-level global proc definition is not modeled as an execution unit".to_string()
            } else {
                "top-level proc definition is not modeled as an execution unit".to_string()
            }
        }
        ExecutionCoverageIssueDetail::UnsupportedTopLevelStatement => {
            "top-level MEL statement outside the supported command model was observed".to_string()
        }
    }
}

pub(in crate::cli) fn render_audit_finding_detail(detail: &AuditFindingDetail) -> String {
    match detail {
        AuditFindingDetail::Static { value } => match value {
            StaticAuditFindingDetail::CustomRuleMatch => {
                "custom audit rule matched execution surface".to_string()
            }
            _ => value.message().to_string(),
        },
        AuditFindingDetail::SourceKindCapability { message } => message.clone(),
        AuditFindingDetail::CustomRuleMatch => {
            "custom audit rule matched execution surface".to_string()
        }
        AuditFindingDetail::FreeText { message } => message.clone(),
    }
}

pub(in crate::cli) fn render_audit_review_detail(detail: &AuditReviewDetail) -> String {
    match detail {
        AuditReviewDetail::Static { value } => match value {
            StaticAuditReviewDetail::MelCallbackBodyDetected => value.message().to_string(),
            StaticAuditReviewDetail::MelCallbackProcReferenceDetected => {
                value.message().to_string()
            }
            StaticAuditReviewDetail::MelBodyAssemblyWithoutSinkDetected => {
                value.message().to_string()
            }
        },
        AuditReviewDetail::FreeText { message } => message.clone(),
    }
}

pub(in crate::cli) fn render_audit_evidence(evidence: &AuditEvidence) -> String {
    match evidence {
        AuditEvidence::FreeText { value } => value.clone(),
        AuditEvidence::KeyValue { key, value } => format!("{}={value}", key.as_str()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GroupedAuditHitKey<'a> {
    finding_id: &'a str,
    severity: &'a str,
    sink: &'a str,
    message: String,
    evidence: Vec<String>,
    lang: &'a str,
    trigger: &'a str,
    surface_kind: &'a str,
    node_name: Option<&'a str>,
    attr_name: Option<&'a str>,
    chunk_form: Option<&'a str>,
    chunk_tag: Option<&'a str>,
    chunk_node_offset: Option<usize>,
    chunk_payload_offset: Option<usize>,
    chunk_payload_size: Option<usize>,
    preview: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GroupedReviewSignalKey<'a> {
    review_id: &'a str,
    message: String,
    evidence: Vec<String>,
    lang: &'a str,
    trigger: &'a str,
    surface_kind: &'a str,
    node_name: Option<&'a str>,
    attr_name: Option<&'a str>,
    chunk_form: Option<&'a str>,
    chunk_tag: Option<&'a str>,
    chunk_node_offset: Option<usize>,
    chunk_payload_offset: Option<usize>,
    chunk_payload_size: Option<usize>,
    preview: &'a str,
}
