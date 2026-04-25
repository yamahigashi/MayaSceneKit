use super::{
    AnalysisSurface, SurfaceAnalysis,
    builders::{build_finding, capability_finding, severity_for_trigger},
};
use crate::{
    audit::lower_python::{
        PythonBodyArgKind, PythonCallKind, PythonCapabilityKind, PythonSignal,
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
                if let PythonBodyArgKind::Assembled { markers } = &first_arg {
                    analysis.findings.push(build_finding(
                        surface_index,
                        surface,
                        "python_body_assembly",
                        severity_for_trigger(AuditSeverity::Critical, surface.origin.trigger),
                        AuditSinkKind::None,
                        None,
                        "Python body-assembly / obfuscation markers detected",
                        markers
                            .iter()
                            .cloned()
                            .map(|value| AuditEvidence::FreeText { value })
                            .collect::<Vec<_>>(),
                        None,
                    ));
                }
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
                        PythonBodyArgKind::Dynamic | PythonBodyArgKind::Assembled { .. } => {
                            vec![AuditEvidence::FreeText {
                                value: "dynamic or assembled body".to_string(),
                            }]
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
            PythonSignal::Capability(kind) => {
                let (id, sink, message) = match kind {
                    PythonCapabilityKind::Subprocess => (
                        "python_subprocess",
                        AuditSinkKind::PySubprocess,
                        "subprocess capability detected",
                    ),
                    PythonCapabilityKind::Socket => (
                        "python_socket",
                        AuditSinkKind::PySocket,
                        "socket capability detected",
                    ),
                    PythonCapabilityKind::Ctypes => (
                        "python_ctypes",
                        AuditSinkKind::PyCtypes,
                        "ctypes / native library capability detected",
                    ),
                };
                analysis.findings.push(capability_finding(
                    surface_index,
                    surface,
                    id,
                    sink,
                    message,
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

    let obfuscation = super::text_scan::scan_strong_obfuscation_markers(&surface.text);
    if !obfuscation.is_empty() {
        analysis.findings.push(build_finding(
            surface_index,
            surface,
            "python_body_assembly",
            severity_for_trigger(AuditSeverity::Critical, surface.origin.trigger),
            AuditSinkKind::None,
            None,
            "Python body-assembly / obfuscation markers detected",
            obfuscation
                .into_iter()
                .map(|value| AuditEvidence::FreeText { value })
                .collect::<Vec<_>>(),
            None,
        ));
    }

    analysis
}
