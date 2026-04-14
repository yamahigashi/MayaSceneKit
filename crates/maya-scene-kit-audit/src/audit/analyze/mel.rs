use std::{collections::HashMap, sync::Arc};

use super::{
    AnalysisSurface, SurfaceAnalysis,
    builders::{
        build_finding, capability_finding, dynamic_exec_finding, preview_window,
        severity_for_trigger,
    },
    callback_flags::analyze_callback_flags,
    text_scan::{
        MelSinkWordHits, MelTextScan, extract_mel_literal_call_body,
        obfuscation_marker_base_severity,
    },
};
use crate::scene::{
    AuditEvidence, AuditFinding, AuditSeverity, AuditSinkKind, ExecutionLanguage,
    observe::{MelSurfaceCall, MelSurfaceFacts},
};

pub(super) fn analyze_mel_surface_impl(
    surface_index: usize,
    surface: &AnalysisSurface,
    mel_surface_facts_cache: &mut HashMap<Arc<str>, Arc<MelSurfaceFacts>>,
) -> SurfaceAnalysis {
    let mut analysis = SurfaceAnalysis::default();
    let mut text_scan = MelTextScan::new(&surface.text);
    let mel_sink_calls = surface
        .mel
        .as_deref()
        .map(MelSinkCalls::from_facts)
        .unwrap_or_default();
    let mut sink_word_hits = None;
    if let Some(mel) = &surface.mel {
        if !mel.diagnostics.is_empty() {
            analysis.findings.push(build_finding(
                surface_index,
                surface,
                "mel_parse_diagnostics",
                severity_for_trigger(AuditSeverity::High, surface.origin.trigger),
                AuditSinkKind::None,
                None,
                "MEL parse diagnostics present; audit blocked on unresolved MEL semantics",
                mel.diagnostics
                    .iter()
                    .take(3)
                    .map(|diagnostic| AuditEvidence::FreeText {
                        value: diagnostic.message.to_string(),
                    })
                    .collect(),
            ));
        }
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
    }
    let obfuscation = text_scan.obfuscation_markers();
    if !obfuscation.is_empty() {
        let severity = severity_for_trigger(
            obfuscation_marker_base_severity(&obfuscation),
            surface.origin.trigger,
        );
        analysis.findings.push(build_finding(
            surface_index,
            surface,
            "obfuscation_markers",
            severity,
            AuditSinkKind::None,
            None,
            "body-assembly / obfuscation markers detected in execution context",
            obfuscation
                .into_iter()
                .map(|value| AuditEvidence::FreeText { value })
                .collect::<Vec<_>>(),
        ));
    }

    analysis.findings.extend(analyze_mel_sink(
        surface_index,
        surface,
        "python",
        mel_sink_calls.python,
        AuditSinkKind::MelPython,
        |literal| {
            if literal {
                (
                    AuditSeverity::Medium,
                    "MEL -> python(...) fixed-literal bridge is not auto-allowed",
                )
            } else {
                (
                    AuditSeverity::High,
                    "dynamic or assembled MEL -> python(...) bridge detected",
                )
            }
        },
        true,
        &mut sink_word_hits,
        &mut text_scan,
        &mut analysis.derived_surfaces,
    ));
    analysis.findings.extend(analyze_mel_sink(
        surface_index,
        surface,
        "evalDeferred",
        mel_sink_calls.eval_deferred,
        AuditSinkKind::MelEvalDeferred,
        |literal| {
            if literal {
                (
                    AuditSeverity::High,
                    "evalDeferred fixed-literal body detected",
                )
            } else {
                (
                    AuditSeverity::High,
                    "dynamic or assembled evalDeferred body detected",
                )
            }
        },
        false,
        &mut sink_word_hits,
        &mut text_scan,
        &mut analysis.derived_surfaces,
    ));
    analysis.findings.extend(analyze_mel_sink(
        surface_index,
        surface,
        "eval",
        mel_sink_calls.eval,
        AuditSinkKind::MelEval,
        |literal| {
            if literal {
                (AuditSeverity::Medium, "eval fixed-literal body detected")
            } else {
                (
                    AuditSeverity::High,
                    "dynamic or assembled eval body detected",
                )
            }
        },
        false,
        &mut sink_word_hits,
        &mut text_scan,
        &mut analysis.derived_surfaces,
    ));

    if has_mel_call_or_word(
        surface,
        mel_sink_calls.script_job,
        "scriptJob",
        &mut sink_word_hits,
        &mut text_scan,
    ) {
        analysis.findings.push(dynamic_exec_finding(
            surface_index,
            surface,
            "mel_scriptjob",
            AuditSinkKind::MelScriptJob,
            "scriptJob hook detected",
        ));
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

fn analyze_mel_sink<F>(
    surface_index: usize,
    surface: &AnalysisSurface,
    sink_name: &str,
    parser_call: Option<&MelSurfaceCall>,
    sink: AuditSinkKind,
    policy: F,
    bridge_python: bool,
    sink_word_hits: &mut Option<MelSinkWordHits>,
    text_scan: &mut MelTextScan<'_>,
    derived_surfaces: &mut Vec<AnalysisSurface>,
) -> Vec<AuditFinding>
where
    F: Fn(bool) -> (AuditSeverity, &'static str),
{
    let mut findings = Vec::new();
    let regex_hit = parser_call.is_none()
        && ensure_sink_word_hits(surface, sink_word_hits, text_scan).contains(sink_name);
    if parser_call.is_none() && !regex_hit {
        return findings;
    }

    let literal = parser_call
        .and_then(|call| call.literal_first_arg.as_deref().map(str::to_string))
        .or_else(|| extract_mel_literal_call_body(&surface.text, sink_name));
    let (severity, message) = policy(literal.is_some());
    let mut evidence = Vec::new();
    if let Some(body) = literal.as_deref() {
        evidence.push(AuditEvidence::FreeText {
            value: "fixed literal body".to_string(),
        });
        evidence.push(AuditEvidence::FreeText {
            value: super::builders::snippet(body),
        });
    } else {
        evidence.push(AuditEvidence::FreeText {
            value: "dynamic or assembled body".to_string(),
        });
    }
    findings.push(build_finding(
        surface_index,
        surface,
        &format!("mel_{}", sink_name.to_ascii_lowercase()),
        severity_for_trigger(severity, surface.origin.trigger),
        sink,
        None,
        message,
        evidence,
    ));

    if bridge_python {
        if let Some(body) = literal {
            let mut bridged_origin = surface.origin.clone();
            bridged_origin.lang = ExecutionLanguage::Python;
            bridged_origin.source_kind = Some("mel->python literal bridge".to_string());
            derived_surfaces.push(AnalysisSurface {
                preview: preview_window(
                    &body,
                    0,
                    body.len().min(24),
                    surface.preview.len().max(16),
                ),
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
    python: Option<&'a MelSurfaceCall>,
    eval_deferred: Option<&'a MelSurfaceCall>,
    eval: Option<&'a MelSurfaceCall>,
    script_job: Option<&'a MelSurfaceCall>,
    command_port: Option<&'a MelSurfaceCall>,
}

impl<'a> MelSinkCalls<'a> {
    fn from_facts(facts: &'a MelSurfaceFacts) -> Self {
        let mut calls = Self::default();
        for call in &facts.calls {
            if calls.python.is_none() && call.name.eq_ignore_ascii_case("python") {
                calls.python = Some(call);
            }
            if calls.eval_deferred.is_none() && call.name.eq_ignore_ascii_case("evalDeferred") {
                calls.eval_deferred = Some(call);
            }
            if calls.eval.is_none() && call.name.eq_ignore_ascii_case("eval") {
                calls.eval = Some(call);
            }
            if calls.script_job.is_none() && call.name.eq_ignore_ascii_case("scriptJob") {
                calls.script_job = Some(call);
            }
            if calls.command_port.is_none() && call.name.eq_ignore_ascii_case("commandPort") {
                calls.command_port = Some(call);
            }
            if calls.is_complete() {
                break;
            }
        }
        calls
    }

    fn is_complete(&self) -> bool {
        self.python.is_some()
            && self.eval_deferred.is_some()
            && self.eval.is_some()
            && self.script_job.is_some()
            && self.command_port.is_some()
    }
}
