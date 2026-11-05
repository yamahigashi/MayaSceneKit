use super::{
    AnalysisSurface, SurfaceAnalysis,
    builders::{build_finding, build_review_signal, capability_finding, severity_for_trigger},
};
use crate::{
    audit::lower_python::{
        MayaCall, MayaKind, PythonBodyArgKind, PythonCallKind, PythonCapabilityKind, PythonSignal,
        collect_python_signals,
    },
    scene::{AuditEvidence, AuditSeverity, AuditSinkKind},
};

pub(super) fn analyze_python_surface_impl(
    surface_index: usize,
    surface: &AnalysisSurface,
) -> SurfaceAnalysis {
    let mut analysis = SurfaceAnalysis::default();

    for signal in collect_python_signals(&surface.text) {
        match signal {
            PythonSignal::Call { kind, first_arg } => {
                let (sink, message) = match kind {
                    PythonCallKind::Exec => (AuditSinkKind::PyExec, "Python exec detected"),
                    PythonCallKind::Eval => (AuditSinkKind::PyEval, "Python eval detected"),
                    PythonCallKind::Compile => {
                        (AuditSinkKind::PyCompile, "Python compile detected")
                    }
                    PythonCallKind::Import => {
                        (AuditSinkKind::PyImport, "dynamic Python import detected")
                    }
                };
                let severity = match kind {
                    PythonCallKind::Import => AuditSeverity::High,
                    PythonCallKind::Exec | PythonCallKind::Eval | PythonCallKind::Compile => {
                        AuditSeverity::Critical
                    }
                };
                let evidence = if kind == PythonCallKind::Import {
                    vec![AuditEvidence::FreeText {
                        value: "__import__".to_string(),
                    }]
                } else {
                    match first_arg {
                        PythonBodyArgKind::Literal => vec![AuditEvidence::FreeText {
                            value: "fixed literal body".to_string(),
                        }],
                        PythonBodyArgKind::Dynamic => vec![AuditEvidence::FreeText {
                            value: "dynamic or assembled body".to_string(),
                        }],
                        PythonBodyArgKind::Assembled { markers } => {
                            let mut evidence = vec![AuditEvidence::FreeText {
                                value: "dynamic or assembled body".to_string(),
                            }];
                            evidence.extend(
                                markers
                                    .into_iter()
                                    .map(|value| AuditEvidence::FreeText { value }),
                            );
                            evidence
                        }
                    }
                };
                analysis.findings.push(build_finding(
                    surface_index,
                    surface,
                    &format!("python_{sink:?}").to_ascii_lowercase(),
                    severity_for_trigger(severity, surface.origin.trigger),
                    sink,
                    None,
                    message,
                    evidence,
                    None,
                ));
            }
            PythonSignal::HardMarker { markers } => {
                analysis.findings.push(build_finding(
                    surface_index,
                    surface,
                    "python_body_assembly",
                    severity_for_trigger(AuditSeverity::Critical, surface.origin.trigger),
                    AuditSinkKind::None,
                    None,
                    "Python body-assembly / obfuscation markers detected",
                    markers
                        .into_iter()
                        .map(|value| AuditEvidence::FreeText { value })
                        .collect::<Vec<_>>(),
                    None,
                ));
            }
            PythonSignal::MayaUncertain { message } => {
                record_maya_uncertainty(surface_index, surface, message, Vec::new(), &mut analysis)
            }
            PythonSignal::Maya(call) => {
                analyze_maya_call(surface_index, surface, call, &mut analysis)
            }
            PythonSignal::Capability(kind) => {
                let (id, sink, message, severity) = match kind {
                    PythonCapabilityKind::Subprocess => (
                        "python_subprocess",
                        AuditSinkKind::PySubprocess,
                        "subprocess capability detected",
                        AuditSeverity::High,
                    ),
                    PythonCapabilityKind::Socket => (
                        "python_socket",
                        AuditSinkKind::PySocket,
                        "socket capability detected",
                        AuditSeverity::High,
                    ),
                    PythonCapabilityKind::Ctypes => (
                        "python_ctypes",
                        AuditSinkKind::PyCtypes,
                        "ctypes / native library capability detected",
                        AuditSeverity::High,
                    ),
                    PythonCapabilityKind::FileOpen => (
                        "python_file_open",
                        AuditSinkKind::PyFileOpen,
                        "Python file open capability detected",
                        AuditSeverity::Critical,
                    ),
                    PythonCapabilityKind::FileWrite => (
                        "python_file_write",
                        AuditSinkKind::PyFileWrite,
                        "Python file write capability detected",
                        AuditSeverity::Critical,
                    ),
                };
                let mut finding = capability_finding(surface_index, surface, id, sink, message);
                finding.severity = severity_for_trigger(severity, surface.origin.trigger);
                analysis.findings.push(finding);
            }
            PythonSignal::AutorunPersistenceMarker { marker } => {
                analysis.findings.push(build_finding(
                    surface_index,
                    surface,
                    "python_autorun_persistence_marker",
                    severity_for_trigger(AuditSeverity::Critical, surface.origin.trigger),
                    AuditSinkKind::PyAutorunPersistence,
                    None,
                    "Python autorun persistence marker detected",
                    vec![AuditEvidence::FreeText { value: marker }],
                    None,
                ));
            }
            PythonSignal::UnresolvedCallTarget { message } => {
                analysis.findings.push(build_finding(
                    surface_index,
                    surface,
                    "python_unresolved_call_target",
                    severity_for_trigger(AuditSeverity::High, surface.origin.trigger),
                    AuditSinkKind::None,
                    None,
                    "Python call target could not be resolved without executing dynamic dispatch",
                    vec![AuditEvidence::FreeText { value: message }],
                    None,
                ));
            }
            PythonSignal::ParseFailure { message } => {
                analysis.findings.push(build_finding(
                    surface_index,
                    surface,
                    "python_parse_failure",
                    severity_for_trigger(AuditSeverity::Medium, surface.origin.trigger),
                    AuditSinkKind::None,
                    None,
                    "Python parse failed; audit blocked on unresolved Python semantics",
                    vec![AuditEvidence::FreeText { value: message }],
                    None,
                ));
            }
        }
    }

    analysis
}

fn analyze_maya_call(
    surface_index: usize,
    surface: &AnalysisSurface,
    call: MayaCall,
    analysis: &mut SurfaceAnalysis,
) {
    use crate::scene::AuditEvidenceKey;

    let (id, sink) = match call.kind {
        MayaKind::File => ("python_maya_file", AuditSinkKind::PyMayaFile),
        MayaKind::SysFile => ("python_file_write", AuditSinkKind::PyFileWrite),
        MayaKind::ScriptJob => ("python_maya_script_job", AuditSinkKind::PyMayaScriptJob),
        MayaKind::CommandPort => ("python_maya_command_port", AuditSinkKind::PySocket),
        MayaKind::ScriptNode => ("python_maya_script_node", AuditSinkKind::PyMayaScriptNode),
        MayaKind::LoadPlugin => ("python_maya_load_plugin", AuditSinkKind::PyMayaLoadPlugin),
        MayaKind::EvalDeferred => (
            "python_maya_eval_deferred",
            AuditSinkKind::PyMayaEvalDeferred,
        ),
        MayaKind::Callback => ("python_maya_callback", AuditSinkKind::PyMayaCallback),
    };
    let mut evidence = vec![AuditEvidence::KeyValue {
        key: AuditEvidenceKey::Command,
        value: call.target.clone(),
    }];
    evidence.extend(call.flags.into_iter().map(|value| AuditEvidence::KeyValue {
        key: AuditEvidenceKey::Flag,
        value,
    }));
    evidence.extend(
        call.operations
            .iter()
            .map(|operation| AuditEvidence::FreeText {
                value: format!("operation={operation}"),
            }),
    );
    if !call.operations.is_empty() {
        let severity = if call.critical {
            AuditSeverity::Critical
        } else {
            AuditSeverity::High
        };
        analysis.findings.push(build_finding(
            surface_index,
            surface,
            id,
            severity_for_trigger(severity, surface.origin.trigger),
            sink,
            None,
            "Python Maya capability detected",
            evidence.clone(),
            None,
        ));
    }
    if !call.uncertainty.is_empty() {
        let reason = format!("{}: {}", call.target, call.uncertainty.join("; "));
        record_maya_uncertainty(surface_index, surface, reason, evidence, analysis);
    }
}

fn record_maya_uncertainty(
    surface_index: usize,
    surface: &AnalysisSurface,
    reason: String,
    mut evidence: Vec<AuditEvidence>,
    analysis: &mut SurfaceAnalysis,
) {
    use crate::scene::UnknownSemanticFact;
    use maya_scene_kit_observe::scene::evidence::UnknownSemanticDetail;

    evidence.push(AuditEvidence::FreeText {
        value: reason.clone(),
    });
    analysis.review_signals.push(build_review_signal(
        surface,
        surface_index,
        "python_maya_uncertain",
        "Python Maya semantics require review",
        evidence,
        None,
    ));
    analysis.unknown_semantics.push(UnknownSemanticFact {
        origin: surface.origin.clone(),
        detail: UnknownSemanticDetail::GenericUncertain,
        preview: reason,
    });
}
