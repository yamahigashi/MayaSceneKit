use std::{collections::HashMap, sync::Arc};

use maya_scene_kit_observe::scene::execution::{
    MelResolvedStringKind, MelSinkArgFact, MelSinkArgKind,
};

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
    ExecutionSurfaceKind,
    execution::{MelSurfaceCall, MelSurfaceFacts},
};

const MEL_SINK_PREVIEW_LINES_BEFORE: usize = 30;
const MEL_SINK_PREVIEW_LINES_AFTER: usize = 10;
const MEL_SINK_PREVIEW_MAX_BYTES: usize = 12 * 1024;
const MEL_SINK_PREVIEW_PREFIX_OMISSION: &str = "[... omitted before ...] ";
const MEL_SINK_PREVIEW_SUFFIX_OMISSION: &str = " [... omitted after ...]";

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
            mel_sink_calls.python,
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
            mel_sink_calls.eval_deferred,
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
            mel_sink_calls.eval,
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
    parser_call: Option<&MelSurfaceCall>,
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
        return analyze_mel_parser_sink(
            surface_index,
            surface,
            parser_call,
            sink_name,
            sink,
            policy,
            bridge_python,
            derived_surfaces,
        );
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

    let preview_override = mel_sink_preview_override(surface, fact);

    let findings = if bridge_python && is_expression_literal_python_bridge(surface, fact) {
        Vec::new()
    } else {
        vec![build_finding(
            surface_index,
            surface,
            &format!("mel_{}", sink_name.to_ascii_lowercase()),
            severity_for_trigger(severity, surface.origin.trigger),
            sink,
            None,
            message,
            evidence,
            preview_override,
        )]
    };

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

fn analyze_mel_parser_sink<F>(
    surface_index: usize,
    surface: &AnalysisSurface,
    parser_call: Option<&MelSurfaceCall>,
    sink_name: &str,
    sink: AuditSinkKind,
    policy: F,
    bridge_python: bool,
    derived_surfaces: &mut Vec<AnalysisSurface>,
) -> Vec<AuditFinding>
where
    F: Fn(MelResolvedStringKind) -> (AuditSeverity, &'static str),
{
    let Some(call) = parser_call else {
        return Vec::new();
    };
    let resolved_kind = if call.literal_first_arg.is_some() {
        MelResolvedStringKind::Literal
    } else if call.dynamic {
        MelResolvedStringKind::Dynamic
    } else {
        MelResolvedStringKind::Unknown
    };
    let (severity, message) = policy(resolved_kind);
    let mut evidence = Vec::new();
    if let Some(body) = call.literal_first_arg.as_deref() {
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
    let preview_override = call
        .literal_first_arg
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

    if bridge_python && resolved_kind == MelResolvedStringKind::Literal {
        if let Some(body) = call.literal_first_arg.as_deref() {
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

fn is_expression_literal_python_bridge(surface: &AnalysisSurface, fact: &MelSinkArgFact) -> bool {
    fact.resolved_kind == MelResolvedStringKind::Literal
        && is_direct_literal_sink_arg(surface.text.as_ref(), fact)
        && surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
        && matches!(
            surface.origin.source_kind.as_deref(),
            Some("expression" | "internalExpression")
        )
}

fn mel_sink_preview_override(surface: &AnalysisSurface, fact: &MelSinkArgFact) -> Option<String> {
    if fact.resolved_kind == MelResolvedStringKind::Literal {
        return fact
            .rendered_text
            .as_deref()
            .map(super::builders::snippet)
            .filter(|preview| !preview.is_empty());
    }

    let start = fact
        .command_name
        .as_deref()
        .and_then(|command_name| {
            let search_end = clamp_char_boundary(surface.text.as_ref(), fact.span.start);
            surface.text[..search_end].rfind(command_name)
        })
        .unwrap_or(fact.span.start);
    let preview = mel_sink_line_preview(surface.text.as_ref(), start);
    (!preview.is_empty()).then_some(preview)
}

fn clamp_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

pub(super) fn mel_sink_line_preview(text: &str, sink_position: usize) -> String {
    if text.is_empty() {
        return String::new();
    }

    let sink_position = clamp_char_boundary(text, sink_position);
    let sink_line_start = line_start_at_or_before(text, sink_position);
    let (window_start, omitted_before) =
        line_start_before(text, sink_line_start, MEL_SINK_PREVIEW_LINES_BEFORE);
    let (window_end, omitted_after) =
        line_end_after(text, sink_line_start, MEL_SINK_PREVIEW_LINES_AFTER);

    let mut preview = String::new();
    if omitted_before {
        preview.push_str(MEL_SINK_PREVIEW_PREFIX_OMISSION);
    }
    preview.push_str(&normalize_mel_sink_preview_text(
        &text[window_start..window_end],
    ));
    if omitted_after {
        while preview.ends_with('\n') {
            preview.pop();
        }
        preview.push_str(MEL_SINK_PREVIEW_SUFFIX_OMISSION);
    }
    truncate_mel_sink_preview(preview)
}

fn line_start_at_or_before(text: &str, position: usize) -> usize {
    text[..position].rfind('\n').map_or(0, |index| index + 1)
}

fn line_start_before(text: &str, mut line_start: usize, lines_before: usize) -> (usize, bool) {
    for _ in 0..lines_before {
        if line_start == 0 {
            return (0, false);
        }
        line_start = text[..line_start - 1]
            .rfind('\n')
            .map_or(0, |index| index + 1);
    }
    (line_start, line_start > 0)
}

fn line_end_after(text: &str, line_start: usize, lines_after: usize) -> (usize, bool) {
    let mut end = line_end_inclusive(text, line_start);
    for _ in 0..lines_after {
        if end >= text.len() {
            return (text.len(), false);
        }
        end = line_end_inclusive(text, end);
    }
    (end, end < text.len())
}

fn line_end_inclusive(text: &str, line_start: usize) -> usize {
    text[line_start..]
        .find('\n')
        .map_or(text.len(), |offset| line_start + offset + 1)
}

fn normalize_mel_sink_preview_text(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\t', "    ")
}

fn truncate_mel_sink_preview(mut preview: String) -> String {
    if preview.len() <= MEL_SINK_PREVIEW_MAX_BYTES {
        return preview;
    }

    let marker = MEL_SINK_PREVIEW_SUFFIX_OMISSION;
    let limit = MEL_SINK_PREVIEW_MAX_BYTES.saturating_sub(marker.len());
    let truncate_at = clamp_char_boundary(&preview, limit);
    preview.truncate(truncate_at);
    preview.push_str(marker);
    preview
}

fn is_direct_literal_sink_arg(source_text: &str, fact: &MelSinkArgFact) -> bool {
    source_text
        .get(fact.span.start..fact.span.end)
        .map(str::trim_start)
        .is_some_and(|text| text.starts_with('"') || text.starts_with('\''))
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
    command_port: Option<&'a MelSurfaceCall>,
    exec: Option<&'a MelSurfaceCall>,
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
            if calls.command_port.is_none() && call.name.eq_ignore_ascii_case("commandPort") {
                calls.command_port = Some(call);
            }
            if calls.exec.is_none() && call.name.eq_ignore_ascii_case("exec") {
                calls.exec = Some(call);
            }
            if calls.is_complete() {
                break;
            }
        }
        calls
    }

    fn is_complete(self) -> bool {
        self.python.is_some()
            && self.eval_deferred.is_some()
            && self.eval.is_some()
            && self.command_port.is_some()
            && self.exec.is_some()
    }
}
