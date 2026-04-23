pub(super) use super::super::policy::{preview_window, severity_for_trigger, snippet};
use super::AnalysisSurface;
use crate::scene::{
    AuditEvidence, AuditEvidenceKey, AuditFinding, AuditFindingCode, AuditFindingDetail,
    AuditReviewCode, AuditReviewDetail, AuditReviewSignal, AuditSeverity, AuditSinkKind,
    StaticAuditFindingDetail, StaticAuditReviewDetail,
};

pub(super) fn capability_finding(
    surface_index: usize,
    surface: &AnalysisSurface,
    id: &str,
    sink: AuditSinkKind,
    message: &str,
) -> AuditFinding {
    build_finding(
        surface_index,
        surface,
        id,
        severity_for_trigger(AuditSeverity::High, surface.origin.trigger),
        sink,
        None,
        message,
        vec![AuditEvidence::FreeText {
            value: surface.origin.source_kind.clone().unwrap_or_default(),
        }],
        None,
    )
}

pub(super) fn dynamic_exec_finding(
    surface_index: usize,
    surface: &AnalysisSurface,
    id: &str,
    sink: AuditSinkKind,
    message: &str,
) -> AuditFinding {
    build_finding(
        surface_index,
        surface,
        id,
        severity_for_trigger(AuditSeverity::High, surface.origin.trigger),
        sink,
        None,
        message,
        vec![AuditEvidence::FreeText {
            value: "body reaches execution hook".to_string(),
        }],
        None,
    )
}

pub(super) fn build_finding(
    surface_index: usize,
    surface: &AnalysisSurface,
    finding_id: &str,
    severity: AuditSeverity,
    sink: AuditSinkKind,
    rule: Option<String>,
    message: &str,
    mut evidence: Vec<AuditEvidence>,
    preview_override: Option<String>,
) -> AuditFinding {
    prepend_node_name_evidence(&mut evidence, surface);
    AuditFinding {
        code: audit_finding_code(finding_id),
        severity,
        surface_index,
        sink,
        rule,
        detail: audit_finding_detail(finding_id, message),
        evidence,
        preview_override,
    }
}

pub(super) fn build_review_signal(
    surface: &AnalysisSurface,
    surface_index: usize,
    review_id: &str,
    message: &str,
    mut evidence: Vec<AuditEvidence>,
    preview_override: Option<String>,
) -> AuditReviewSignal {
    prepend_node_name_evidence(&mut evidence, surface);
    AuditReviewSignal {
        code: audit_review_code(review_id),
        surface_index,
        detail: audit_review_detail(review_id, message),
        evidence,
        preview_override,
    }
}

fn prepend_node_name_evidence(evidence: &mut Vec<AuditEvidence>, surface: &AnalysisSurface) {
    let Some(node_name) = surface.origin.node_name.as_deref() else {
        return;
    };
    if evidence.iter().any(|entry| {
        matches!(
            entry,
            AuditEvidence::KeyValue {
                key: AuditEvidenceKey::NodeName,
                ..
            }
        )
    }) {
        return;
    }
    evidence.insert(
        0,
        AuditEvidence::KeyValue {
            key: AuditEvidenceKey::NodeName,
            value: node_name.to_string(),
        },
    );
}

fn audit_finding_code(finding_id: &str) -> AuditFindingCode {
    match finding_id {
        "command_port" => AuditFindingCode::CommandPort,
        "custom_rule_match" => AuditFindingCode::CustomRuleMatch,
        "mel_callback_flag" => AuditFindingCode::MelCallbackFlag,
        "mel_eval" => AuditFindingCode::MelEval,
        "mel_evaldeferred" => AuditFindingCode::MelEvalDeferred,
        "mel_parse_diagnostics" => AuditFindingCode::MelParseDiagnostics,
        "mel_python" => AuditFindingCode::MelPython,
        "mel_scriptjob" => AuditFindingCode::MelScriptjob,
        "obfuscation_markers" => AuditFindingCode::ObfuscationMarkers,
        "python_body_assembly" => AuditFindingCode::PythonBodyAssembly,
        "python_pycompile" => AuditFindingCode::PythonCompile,
        "python_ctypes" => AuditFindingCode::PythonCtypes,
        "python_pyeval" => AuditFindingCode::PythonEval,
        "python_pyexec" => AuditFindingCode::PythonExec,
        "python_pyimport" => AuditFindingCode::PythonImport,
        "python_parse_failure" => AuditFindingCode::PythonParseFailure,
        "python_socket" => AuditFindingCode::PythonSocket,
        "python_subprocess" => AuditFindingCode::PythonSubprocess,
        "python_unresolved_call_target" => AuditFindingCode::PythonUnresolvedCallTarget,
        "unknown_execution_language" => AuditFindingCode::UnknownExecutionLanguage,
        "unknown_execution_trigger" => AuditFindingCode::UnknownExecutionTrigger,
        _ => panic!("unhandled finding id: {finding_id}"),
    }
}

fn audit_review_code(review_id: &str) -> AuditReviewCode {
    match review_id {
        "mel_callback_body" => AuditReviewCode::MelCallbackBody,
        "mel_callback_proc_reference" => AuditReviewCode::MelCallbackProcReference,
        "mel_body_assembly_without_sink" => AuditReviewCode::MelBodyAssemblyWithoutSink,
        _ => panic!("unhandled review id: {review_id}"),
    }
}

fn audit_finding_detail(finding_id: &str, message: &str) -> AuditFindingDetail {
    let static_detail = match finding_id {
        "command_port" => Some(StaticAuditFindingDetail::CommandPortOpensCommandSocket),
        "custom_rule_match" => Some(StaticAuditFindingDetail::CustomRuleMatch),
        "mel_callback_flag" => Some(StaticAuditFindingDetail::ScriptBearingMelCallbackFlagDetected),
        "mel_eval" if message == "eval fixed-literal body detected" => {
            Some(StaticAuditFindingDetail::EvalFixedLiteralBodyDetected)
        }
        "mel_eval" if message == "dynamic or assembled eval body detected" => {
            Some(StaticAuditFindingDetail::DynamicOrAssembledEvalBodyDetected)
        }
        "mel_evaldeferred" if message == "evalDeferred fixed-literal body detected" => {
            Some(StaticAuditFindingDetail::EvalDeferredFixedLiteralBodyDetected)
        }
        "mel_evaldeferred" if message == "dynamic or assembled evalDeferred body detected" => {
            Some(StaticAuditFindingDetail::DynamicOrAssembledEvalDeferredBodyDetected)
        }
        "mel_parse_diagnostics" => Some(StaticAuditFindingDetail::MelParseDiagnosticsPresent),
        "mel_python"
            if message == "MEL -> python(...) fixed-literal bridge is not auto-allowed" =>
        {
            Some(StaticAuditFindingDetail::MelPythonLiteralBridgeNotAutoAllowed)
        }
        "mel_python" if message == "dynamic or assembled MEL -> python(...) bridge detected" => {
            Some(StaticAuditFindingDetail::DynamicOrAssembledMelPythonBridgeDetected)
        }
        "mel_scriptjob" => Some(StaticAuditFindingDetail::ScriptJobHookDetected),
        "python_body_assembly" => Some(StaticAuditFindingDetail::PythonBodyAssemblyMarkersDetected),
        "python_pycompile" => Some(StaticAuditFindingDetail::PythonCompileDetected),
        "python_ctypes" => Some(StaticAuditFindingDetail::CtypesCapabilityDetected),
        "python_pyeval" => Some(StaticAuditFindingDetail::PythonEvalDetected),
        "python_pyexec" => Some(StaticAuditFindingDetail::PythonExecDetected),
        "python_parse_failure" => Some(StaticAuditFindingDetail::PythonParseFailed),
        "python_socket" => Some(StaticAuditFindingDetail::SocketCapabilityDetected),
        "python_subprocess" => Some(StaticAuditFindingDetail::SubprocessCapabilityDetected),
        "python_unresolved_call_target" => {
            Some(StaticAuditFindingDetail::PythonCallTargetCouldNotBeResolved)
        }
        "unknown_execution_language" => {
            Some(StaticAuditFindingDetail::ExecutionSurfaceLanguageCouldNotBeInferred)
        }
        "unknown_execution_trigger" => {
            Some(StaticAuditFindingDetail::ExecutionSurfaceTriggerCouldNotBeInferred)
        }
        _ => None,
    };

    static_detail
        .map(|value| AuditFindingDetail::Static { value })
        .unwrap_or_else(|| AuditFindingDetail::FreeText {
            message: message.to_string(),
        })
}

fn audit_review_detail(review_id: &str, message: &str) -> AuditReviewDetail {
    let static_detail = match review_id {
        "mel_callback_body" => Some(StaticAuditReviewDetail::MelCallbackBodyDetected),
        "mel_callback_proc_reference" => {
            Some(StaticAuditReviewDetail::MelCallbackProcReferenceDetected)
        }
        "mel_body_assembly_without_sink" => {
            Some(StaticAuditReviewDetail::MelBodyAssemblyWithoutSinkDetected)
        }
        _ => None,
    };

    static_detail
        .map(|value| AuditReviewDetail::Static { value })
        .unwrap_or_else(|| AuditReviewDetail::FreeText {
            message: message.to_string(),
        })
}
