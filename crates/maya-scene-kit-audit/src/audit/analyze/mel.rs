use std::{collections::HashMap, sync::Arc};

use maya_scene_kit_observe::scene::execution::{MelResolvedStringKind, MelSinkArgKind};

use super::{
    AnalysisSurface, SurfaceAnalysis,
    builders::{
        build_finding, build_review_signal, capability_finding, dynamic_exec_finding,
        preview_window, severity_for_trigger,
    },
    callback_flags::analyze_callback_flags,
    text_scan::{MelSinkWordHits, MelTextScan},
};
use crate::scene::{
    AuditEvidence, AuditEvidenceKey, AuditFinding, AuditSeverity, AuditSinkKind, ExecutionLanguage,
    execution::{MelSurfaceCall, MelSurfaceFacts},
};

pub(super) fn analyze_mel_surface_impl(
    surface_index: usize,
    surface: &AnalysisSurface,
    mel_surface_facts_cache: &mut HashMap<Arc<str>, Arc<MelSurfaceFacts>>,
) -> SurfaceAnalysis {
    let mut analysis = SurfaceAnalysis::default();
    let mut text_scan = MelTextScan::new(&surface.text);
    let mut sink_word_hits = None;
    let mel_sink_calls = surface
        .mel
        .as_deref()
        .map(MelSinkCalls::from_facts)
        .unwrap_or_default();

    if let Some(mel) = &surface.mel {
        let callback_analysis = analyze_callback_flags(
            surface_index,
            surface,
            mel,
            mel_surface_facts_cache,
            &mut analysis.derived_surfaces,
        );
        analysis.findings.extend(callback_analysis.findings);
        analysis
            .review_signals
            .extend(callback_analysis.review_signals);

        analysis.findings.extend(analyze_mel_sink(
            surface_index,
            surface,
            mel,
            MelSinkArgKind::Python,
            "python",
            AuditSinkKind::MelPython,
            |kind| match kind {
                MelResolvedStringKind::Literal => (
                    AuditSeverity::Medium,
                    "MEL -> python(...) fixed-literal bridge is not auto-allowed",
                ),
                _ => (
                    AuditSeverity::High,
                    "dynamic or assembled MEL -> python(...) bridge detected",
                ),
            },
            true,
            &mut analysis.derived_surfaces,
        ));
        analysis.findings.extend(analyze_mel_sink(
            surface_index,
            surface,
            mel,
            MelSinkArgKind::EvalDeferred,
            "evalDeferred",
            AuditSinkKind::MelEvalDeferred,
            |kind| match kind {
                MelResolvedStringKind::Literal => (
                    AuditSeverity::High,
                    "evalDeferred fixed-literal body detected",
                ),
                _ => (
                    AuditSeverity::High,
                    "dynamic or assembled evalDeferred body detected",
                ),
            },
            false,
            &mut analysis.derived_surfaces,
        ));
        analysis.findings.extend(analyze_mel_sink(
            surface_index,
            surface,
            mel,
            MelSinkArgKind::Eval,
            "eval",
            AuditSinkKind::MelEval,
            |kind| match kind {
                MelResolvedStringKind::Literal => {
                    (AuditSeverity::Medium, "eval fixed-literal body detected")
                }
                _ => (
                    AuditSeverity::High,
                    "dynamic or assembled eval body detected",
                ),
            },
            false,
            &mut analysis.derived_surfaces,
        ));

        for code_like in &mel.code_like_value_facts {
            analysis.review_signals.push(build_review_signal(
                surface,
                surface_index,
                "mel_body_assembly_without_sink",
                "assembled MEL body reconstructs code-like text in execution context without a proven execution sink",
                vec![
                    AuditEvidence::FreeText {
                        value: "assembled body".to_string(),
                    },
                    AuditEvidence::FreeText {
                        value: super::builders::snippet(code_like.rendered_text.as_ref()),
                    },
                ],
                Some(super::builders::snippet(code_like.rendered_text.as_ref())),
            ));
        }

        if mel
            .sink_arg_facts
            .iter()
            .any(|fact| fact.sink_kind == MelSinkArgKind::ScriptJobPayload)
        {
            analysis.findings.push(dynamic_exec_finding(
                surface_index,
                surface,
                "mel_scriptjob",
                AuditSinkKind::MelScriptJob,
                "scriptJob hook detected",
            ));
        }
    }

    if let Some(exec_call) = mel_sink_calls.exec {
        analysis
            .findings
            .push(mel_exec_finding(surface_index, surface, exec_call));
    }

    if has_mel_call_or_word(
        surface,
        mel_sink_calls.command_port,
        "commandPort",
        &mut sink_word_hits,
        &mut text_scan,
    ) {
        analysis.findings.push(capability_finding(
            surface_index,
            surface,
            "command_port",
            AuditSinkKind::MelCommandPort,
            "commandPort opens a command socket",
        ));
    }

    analysis
}

fn mel_exec_finding(
    surface_index: usize,
    surface: &AnalysisSurface,
    call: &MelSurfaceCall,
) -> AuditFinding {
    let mut evidence = vec![AuditEvidence::KeyValue {
        key: AuditEvidenceKey::Command,
        value: call.name.to_string(),
    }];
    let preview_override = call
        .literal_first_arg
        .as_deref()
        .map(super::builders::snippet)
        .filter(|preview| !preview.is_empty());
    if let Some(arg) = call.literal_first_arg.as_deref() {
        evidence.push(AuditEvidence::FreeText {
            value: format!("fixed literal command: {}", super::builders::snippet(arg)),
        });
    } else if call.dynamic {
        evidence.push(AuditEvidence::FreeText {
            value: "dynamic or unresolved command".to_string(),
        });
    }

    build_finding(
        surface_index,
        surface,
        "mel_exec",
        severity_for_trigger(AuditSeverity::High, surface.origin.trigger),
        AuditSinkKind::MelExec,
        None,
        "MEL exec command detected",
        evidence,
        preview_override,
    )
}

fn analyze_mel_sink<F>(
    surface_index: usize,
    surface: &AnalysisSurface,
    mel: &MelSurfaceFacts,
    sink_kind: MelSinkArgKind,
    sink_name: &str,
    sink: AuditSinkKind,
    policy: F,
    bridge_python: bool,
    derived_surfaces: &mut Vec<AnalysisSurface>,
) -> Vec<AuditFinding>
where
    F: Fn(MelResolvedStringKind) -> (AuditSeverity, &'static str),
{
    let Some(fact) = mel
        .sink_arg_facts
        .iter()
        .find(|fact| fact.sink_kind == sink_kind)
    else {
        return Vec::new();
    };

    let (severity, message) = policy(fact.resolved_kind);
    let mut evidence = Vec::new();
    match fact.resolved_kind {
        MelResolvedStringKind::Literal => {
            evidence.push(AuditEvidence::FreeText {
                value: "fixed literal body".to_string(),
            });
        }
        MelResolvedStringKind::AssembledLiteral => {
            evidence.push(AuditEvidence::FreeText {
                value: "assembled body".to_string(),
            });
            evidence.extend(fact.markers.iter().map(|marker| AuditEvidence::FreeText {
                value: marker.as_str().to_string(),
            }));
        }
        MelResolvedStringKind::Dynamic
        | MelResolvedStringKind::Unknown
        | MelResolvedStringKind::ProcReference => {
            evidence.push(AuditEvidence::FreeText {
                value: "dynamic or assembled body".to_string(),
            });
        }
    }
    if let Some(body) = fact.rendered_text.as_deref() {
        evidence.push(AuditEvidence::FreeText {
            value: super::builders::snippet(body),
        });
    }

    let preview_override = fact
        .rendered_text
        .as_deref()
        .map(super::builders::snippet)
        .filter(|preview| !preview.is_empty());

    let findings = vec![build_finding(
        surface_index,
        surface,
        &format!("mel_{}", sink_name.to_ascii_lowercase()),
        severity_for_trigger(severity, surface.origin.trigger),
        sink,
        None,
        message,
        evidence,
        preview_override,
    )];

    if bridge_python && fact.resolved_kind == MelResolvedStringKind::Literal {
        if let Some(body) = fact.rendered_text.as_deref() {
            let mut bridged_origin = surface.origin.clone();
            bridged_origin.lang = ExecutionLanguage::Python;
            bridged_origin.source_kind = Some("mel->python literal bridge".to_string());
            derived_surfaces.push(AnalysisSurface {
                preview: preview_window(body, 0, body.len().min(24), surface.preview.len().max(16)),
                text: Arc::from(body),
                origin: bridged_origin,
                derivation: crate::scene::AuditSurfaceDerivation::MelPythonLiteralBridge,
                mel: None,
            });
        }
    }

    findings
}

#[cfg(test)]
pub(super) fn find_mel_call<'a>(
    surface: &'a AnalysisSurface,
    sink_name: &str,
) -> Option<&'a MelSurfaceCall> {
    surface
        .mel
        .as_ref()?
        .calls
        .iter()
        .find(|call| call.name.eq_ignore_ascii_case(sink_name))
}

fn has_mel_call_or_word(
    surface: &AnalysisSurface,
    parser_call: Option<&MelSurfaceCall>,
    sink_name: &str,
    sink_word_hits: &mut Option<MelSinkWordHits>,
    text_scan: &mut MelTextScan<'_>,
) -> bool {
    parser_call.is_some()
        || ensure_sink_word_hits(surface, sink_word_hits, text_scan).contains(sink_name)
}

fn ensure_sink_word_hits<'a>(
    _surface: &'a AnalysisSurface,
    sink_word_hits: &'a mut Option<MelSinkWordHits>,
    text_scan: &'a mut MelTextScan<'_>,
) -> MelSinkWordHits {
    *sink_word_hits.get_or_insert_with(|| text_scan.sink_word_hits())
}

#[derive(Debug, Clone, Copy, Default)]
struct MelSinkCalls<'a> {
    command_port: Option<&'a MelSurfaceCall>,
    exec: Option<&'a MelSurfaceCall>,
}

impl<'a> MelSinkCalls<'a> {
    fn from_facts(facts: &'a MelSurfaceFacts) -> Self {
        let mut calls = Self::default();
        for call in &facts.calls {
            if calls.command_port.is_none() && call.name.eq_ignore_ascii_case("commandPort") {
                calls.command_port = Some(call);
            } else if calls.exec.is_none() && call.name.eq_ignore_ascii_case("exec") {
                calls.exec = Some(call);
            }
            if calls.command_port.is_some() && calls.exec.is_some() {
                break;
            }
        }
        calls
    }
}
