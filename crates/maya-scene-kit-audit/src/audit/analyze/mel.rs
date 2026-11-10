use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use maya_scene_kit_observe::scene::execution::{
    MelResolvedStringKind, MelSinkArgFact, MelSinkArgKind, MelSurfaceNormalizedCommand,
    MelSurfaceNormalizedItem,
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
        analyze_dangerous_commands(surface_index, surface, mel, &mut analysis);
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

        let findings = analyze_mel_sink(
            surface_index,
            surface,
            mel,
            &mel_sink_calls.python,
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
            &mut analysis,
        );
        analysis.findings.extend(findings);
        let findings = analyze_mel_sink(
            surface_index,
            surface,
            mel,
            &mel_sink_calls.eval_deferred,
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
            &mut analysis,
        );
        analysis.findings.extend(findings);
        let findings = analyze_mel_sink(
            surface_index,
            surface,
            mel,
            &mel_sink_calls.eval,
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
            &mut analysis,
        );
        analysis.findings.extend(findings);

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

fn analyze_dangerous_commands(
    surface_index: usize,
    surface: &AnalysisSurface,
    facts: &MelSurfaceFacts,
    analysis: &mut SurfaceAnalysis,
) {
    let mut seen = HashSet::new();
    for call in &facts.calls {
        let name = call.name.to_ascii_lowercase();
        let (code, sink, severity) = match name.as_str() {
            "system" => ("mel_system", AuditSinkKind::MelSystem, AuditSeverity::High),
            "popen" => ("mel_popen", AuditSinkKind::MelPopen, AuditSeverity::High),
            "fopen" => (
                "mel_file_open",
                AuditSinkKind::MelFileOpen,
                AuditSeverity::Critical,
            ),
            "fprint" | "fwrite" => (
                "mel_file_write",
                AuditSinkKind::MelFileWrite,
                AuditSeverity::Critical,
            ),
            "evalecho" => (
                "mel_evalecho",
                AuditSinkKind::MelEvalEcho,
                AuditSeverity::Critical,
            ),
            "callpython" => (
                "mel_callpython",
                AuditSinkKind::MelCallPython,
                AuditSeverity::Critical,
            ),
            "source" => ("mel_source", AuditSinkKind::MelSource, AuditSeverity::High),
            "loadplugin" => (
                "mel_loadplugin",
                AuditSinkKind::MelLoadPlugin,
                AuditSeverity::High,
            ),
            "sysfile" => (
                "mel_sysfile",
                AuditSinkKind::MelSysFile,
                AuditSeverity::Critical,
            ),
            _ => continue,
        };
        if !seen.insert((call.span_start, call.span_end, name.clone())) {
            continue;
        }
        if name == "fopen" || name == "sysfile" {
            let command = facts.normalized_commands.iter().find(|command| {
                command.span_start == call.span_start
                    && command.schema_name.eq_ignore_ascii_case(&name)
            });
            let args = command
                .map(normalized_arguments)
                .unwrap_or_else(|| function_arguments(surface, call));
            if name == "fopen" && matches!(args.get(1), Some(Some("r" | "rb"))) {
                continue;
            }
            if name == "sysfile" && !sysfile_may_modify(command, &args, surface.text.as_ref()) {
                continue;
            }
        }
        analysis.findings.push(build_finding(
            surface_index,
            surface,
            code,
            severity_for_trigger(severity, surface.origin.trigger),
            sink,
            None,
            "MEL capability detected",
            vec![AuditEvidence::KeyValue {
                key: AuditEvidenceKey::Command,
                value: call.name.to_string(),
            }],
            surface
                .text
                .get(call.span_start..call.span_end)
                .map(super::builders::snippet),
        ));
    }
}

fn normalized_arguments(command: &MelSurfaceNormalizedCommand) -> Vec<Option<&str>> {
    command
        .items
        .iter()
        .filter_map(|item| match item {
            MelSurfaceNormalizedItem::Positional(arg) => Some(arg.literal.as_deref()),
            MelSurfaceNormalizedItem::Flag(_) => None,
        })
        .collect()
}

fn sysfile_may_modify(
    command: Option<&MelSurfaceNormalizedCommand>,
    args: &[Option<&str>],
    source: &str,
) -> bool {
    let mut flags = Vec::new();
    if let Some(command) = command {
        for item in &command.items {
            if let MelSurfaceNormalizedItem::Flag(flag) = item {
                flags.push(Some(flag.preferred_name(source).trim_start_matches('-')));
            }
        }
    } else {
        for arg in args {
            match arg {
                Some(value) if value.starts_with('-') => {
                    flags.push(Some(value.trim_start_matches('-')))
                }
                None => flags.push(None),
                _ => {}
            }
        }
    }
    if flags.is_empty() {
        return true;
    }
    flags
        .into_iter()
        .any(|flag| !matches!(flag, Some("exists" | "ex" | "query" | "q")))
}

// Function-call facts expose only the first argument. Inspect remaining literal
// arguments within the proven call span; expressions stay unresolved.
fn function_arguments<'a>(
    surface: &'a AnalysisSurface,
    call: &MelSurfaceCall,
) -> Vec<Option<&'a str>> {
    let Some(text) = surface.text.get(call.span_start..call.span_end) else {
        return Vec::new();
    };
    let Some(tail) = text.get(call.name.len()..) else {
        return Vec::new();
    };
    let tail = trim_mel_trivia(tail);
    if !tail.starts_with('(') {
        return Vec::new();
    }
    let open = text.len() - tail.len();
    let bytes = text.as_bytes();
    let mut args = Vec::new();
    let mut start = open + 1;
    let mut index = start;
    let mut depth = 0usize;
    let mut quote = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = quote {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == delimiter {
                quote = None;
            }
        } else if byte == b'"' || byte == b'\'' {
            quote = Some(byte);
        } else if bytes[index..].starts_with(b"//") {
            index += bytes[index..]
                .iter()
                .position(|&b| b == b'\n')
                .unwrap_or(bytes.len() - index);
            continue;
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            index += 2;
            continue;
        } else if matches!(byte, b'(' | b'[' | b'{') {
            depth += 1;
        } else if matches!(byte, b')' | b']' | b'}') {
            if depth == 0 {
                args.push(plain_literal(&text[start..index]));
                break;
            }
            depth -= 1;
        } else if byte == b',' && depth == 0 {
            args.push(plain_literal(&text[start..index]));
            start = index + 1;
        }
        index += 1;
    }
    args
}

fn trim_mel_trivia(mut text: &str) -> &str {
    loop {
        text = text.trim_start();
        if text.starts_with("//") {
            text = text.find('\n').map_or("", |end| &text[end + 1..]);
        } else if let Some(comment) = text.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else {
                return text;
            };
            text = &comment[end + 2..];
        } else {
            return text;
        }
    }
}

fn plain_literal(text: &str) -> Option<&str> {
    let text = trim_mel_trivia(text);
    let quote = *text.as_bytes().first()?;
    if !matches!(quote, b'"' | b'\'') {
        return None;
    }
    let end = text[1..]
        .bytes()
        .position(|byte| byte == quote || byte == b'\\')?
        + 1;
    if text.as_bytes()[end] != quote || !trim_mel_trivia(&text[end + 1..]).is_empty() {
        return None;
    }
    Some(&text[1..end])
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
    parser_calls: &[&MelSurfaceCall],
    sink_kind: MelSinkArgKind,
    sink_name: &str,
    sink: AuditSinkKind,
    policy: F,
    analysis: &mut SurfaceAnalysis,
) -> Vec<AuditFinding>
where
    F: Fn(MelResolvedStringKind) -> (AuditSeverity, &'static str),
{
    let bridge_python = sink_kind == MelSinkArgKind::Python;
    let mut findings = Vec::with_capacity(parser_calls.len());
    let mut literals = LiteralSinkCache::default();
    analysis.derived_surfaces.reserve(parser_calls.len());
    let facts = mel
        .sink_arg_facts
        .iter()
        .filter(|fact| fact.sink_kind == sink_kind)
        .collect::<Vec<_>>();
    let owners = match_sink_calls(parser_calls, &facts);
    let mut covered_calls = vec![false; parser_calls.len()];
    for (fact, owner) in facts.into_iter().zip(owners) {
        let position = if let Some(index) = owner {
            covered_calls[index] = true;
            let call = parser_calls[index];
            (call.span_start, call.span_end)
        } else {
            (fact.span.start, fact.span.end)
        };
        let literal = (fact.resolved_kind == MelResolvedStringKind::Literal)
            .then_some(fact.rendered_text.as_deref())
            .flatten();
        let suppressed = bridge_python && is_expression_literal_python_bridge(surface, fact);
        findings.extend(
            literals.analyze(literal, suppressed, position, analysis, |analysis| {
                analyze_mel_sink_fact(
                    surface_index,
                    surface,
                    fact,
                    position,
                    sink_name,
                    sink,
                    &policy,
                    bridge_python,
                    analysis,
                )
            }),
        );
    }
    for (call, covered) in parser_calls.iter().zip(covered_calls) {
        if !covered {
            findings.extend(literals.analyze(
                call.literal_first_arg.as_deref(),
                false,
                (call.span_start, call.span_end),
                analysis,
                |analysis| {
                    analyze_mel_parser_sink(
                        surface_index,
                        surface,
                        Some(call),
                        sink_name,
                        sink,
                        &policy,
                        bridge_python,
                        analysis,
                    )
                },
            ));
        }
    }
    findings
}

#[derive(Default)]
struct LiteralSinkCache<'a> {
    entries: HashMap<(&'a str, bool), (Option<AuditFinding>, usize)>,
}

impl<'a> LiteralSinkCache<'a> {
    fn analyze(
        &mut self,
        body: Option<&'a str>,
        suppressed: bool,
        position: (usize, usize),
        analysis: &mut SurfaceAnalysis,
        analyze: impl FnOnce(&mut SurfaceAnalysis) -> Option<AuditFinding>,
    ) -> Option<AuditFinding> {
        let Some(body) = body else {
            return analyze(analysis);
        };
        if let Some((finding, index)) = self.entries.get(&(body, suppressed)) {
            let mut derived = analysis.derived_surfaces[*index].clone();
            derived.parent_position = Some(position);
            analysis.derived_surfaces.push(derived);
            return finding.clone();
        }
        let index = analysis.derived_surfaces.len();
        let finding = analyze(analysis);
        self.entries
            .insert((body, suppressed), (finding.clone(), index));
        finding
    }
}

fn match_sink_calls(calls: &[&MelSurfaceCall], facts: &[&MelSinkArgFact]) -> Vec<Option<usize>> {
    let mut call_order = (0..calls.len()).collect::<Vec<_>>();
    call_order
        .sort_unstable_by_key(|&index| (calls[index].span_start, Reverse(calls[index].span_end)));
    let mut fact_order = (0..facts.len()).collect::<Vec<_>>();
    fact_order.sort_unstable_by_key(|&index| facts[index].span.start);
    let mut active: Vec<usize> = Vec::new();
    let mut next_call = 0;
    let mut owners = vec![None; facts.len()];
    for fact_index in fact_order {
        let fact = facts[fact_index];
        while next_call < call_order.len()
            && calls[call_order[next_call]].span_start < fact.span.start
        {
            let index = call_order[next_call];
            while active
                .last()
                .is_some_and(|&previous| calls[previous].span_end <= calls[index].span_start)
            {
                active.pop();
            }
            active.push(index);
            next_call += 1;
        }
        while active
            .last()
            .is_some_and(|&index| calls[index].span_end <= fact.span.start)
        {
            active.pop();
        }
        // Parser call spans are nested or disjoint, so enclosing ends decrease along the stack.
        let enclosing = active.partition_point(|&index| calls[index].span_end >= fact.span.end);
        owners[fact_index] = enclosing.checked_sub(1).map(|index| active[index]);
    }
    owners
}

fn analyze_mel_sink_fact<F>(
    surface_index: usize,
    surface: &AnalysisSurface,
    fact: &MelSinkArgFact,
    position: (usize, usize),
    sink_name: &str,
    sink: AuditSinkKind,
    policy: F,
    bridge_python: bool,
    analysis: &mut SurfaceAnalysis,
) -> Option<AuditFinding>
where
    F: Fn(MelResolvedStringKind) -> (AuditSeverity, &'static str),
{
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
        None
    } else {
        Some(build_finding(
            surface_index,
            surface,
            &format!("mel_{}", sink_name.to_ascii_lowercase()),
            severity_for_trigger(severity, surface.origin.trigger),
            sink,
            None,
            message,
            evidence,
            preview_override,
        ))
    };

    if fact.resolved_kind == MelResolvedStringKind::Literal {
        if let Some(body) = fact.rendered_text.as_deref() {
            derive_literal_sink_body(surface, body, sink_name, bridge_python, position, analysis);
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
    analysis: &mut SurfaceAnalysis,
) -> Option<AuditFinding>
where
    F: Fn(MelResolvedStringKind) -> (AuditSeverity, &'static str),
{
    let call = parser_call?;
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

    let findings = Some(build_finding(
        surface_index,
        surface,
        &format!("mel_{}", sink_name.to_ascii_lowercase()),
        severity_for_trigger(severity, surface.origin.trigger),
        sink,
        None,
        message,
        evidence,
        preview_override,
    ));

    if resolved_kind == MelResolvedStringKind::Literal {
        if let Some(body) = call.literal_first_arg.as_deref() {
            derive_literal_sink_body(
                surface,
                body,
                sink_name,
                bridge_python,
                (call.span_start, call.span_end),
                analysis,
            );
        }
    }

    findings
}

fn derive_literal_sink_body(
    surface: &AnalysisSurface,
    body: &str,
    sink_name: &str,
    bridge_python: bool,
    position: (usize, usize),
    analysis: &mut SurfaceAnalysis,
) {
    let mut origin = surface.origin.clone();
    origin.lang = if bridge_python {
        ExecutionLanguage::Python
    } else {
        ExecutionLanguage::Mel
    };
    origin.source_kind = Some(if bridge_python {
        "mel->python literal bridge".to_string()
    } else {
        format!("mel {sink_name} literal body")
    });
    let preview = preview_window(body, 0, body.len().min(24), surface.preview.len().max(16));
    let depth = surface.literal_eval_depth + usize::from(!bridge_python);
    let text: Arc<str> = Arc::from(body);
    analysis.derived_surfaces.push(AnalysisSurface {
        root_index: surface.root_index,
        literal_eval_depth: depth,
        parent_position: Some(position),
        text,
        preview,
        origin,
        derivation: if bridge_python {
            crate::scene::AuditSurfaceDerivation::MelPythonLiteralBridge
        } else {
            crate::scene::AuditSurfaceDerivation::MelCallbackLiteral
        },
        mel: None,
    });
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

#[derive(Debug, Clone, Default)]
struct MelSinkCalls<'a> {
    python: Vec<&'a MelSurfaceCall>,
    eval_deferred: Vec<&'a MelSurfaceCall>,
    eval: Vec<&'a MelSurfaceCall>,
    command_port: Option<&'a MelSurfaceCall>,
    exec: Option<&'a MelSurfaceCall>,
}

impl<'a> MelSinkCalls<'a> {
    fn from_facts(facts: &'a MelSurfaceFacts) -> Self {
        let mut calls = Self::default();
        let mut seen = HashSet::new();
        for call in &facts.calls {
            let sink_calls = if call.name.eq_ignore_ascii_case("python") {
                Some((MelSinkArgKind::Python, &mut calls.python))
            } else if call.name.eq_ignore_ascii_case("evalDeferred") {
                Some((MelSinkArgKind::EvalDeferred, &mut calls.eval_deferred))
            } else if call.name.eq_ignore_ascii_case("eval") {
                Some((MelSinkArgKind::Eval, &mut calls.eval))
            } else {
                None
            };
            if let Some((kind, sink_calls)) = sink_calls {
                if seen.insert((kind, call.span_start, call.span_end)) {
                    sink_calls.push(call);
                }
            }
            if calls.command_port.is_none() && call.name.eq_ignore_ascii_case("commandPort") {
                calls.command_port = Some(call);
            }
            if calls.exec.is_none() && call.name.eq_ignore_ascii_case("exec") {
                calls.exec = Some(call);
            }
        }
        calls
    }
}

#[cfg(test)]
mod allowlist_root_tests {
    use maya_scene_kit_observe::scene::execution::collect_mel_surface_facts;

    use super::*;
    use crate::scene::{AuditSurfaceDerivation, ExecutionOrigin, ExecutionTrigger};

    #[test]
    fn allowlist_root_survives_literal_callback_and_parser_fallback() {
        let body = "python(\"exec('print(1)')\")";
        let mut surface = AnalysisSurface {
            root_index: 0,
            literal_eval_depth: 0,
            parent_position: None,
            text: Arc::from(body),
            preview: body.into(),
            origin: ExecutionOrigin {
                lang: ExecutionLanguage::Mel,
                trigger: ExecutionTrigger::FileOpen,
                ..ExecutionOrigin::without_chunk_address()
            },
            derivation: AuditSurfaceDerivation::Observed,
            mel: None,
        };
        let call = MelSurfaceCall {
            name: "python".into(),
            surface_kind: crate::scene::execution::MelSurfaceCallSurfaceKind::Function,
            captured: false,
            literal_first_arg: Some("exec('print(1)')".into()),
            dynamic: false,
            span_start: 0,
            span_end: body.len(),
        };
        let mut analysis = SurfaceAnalysis::default();
        let findings = analyze_mel_parser_sink(
            0,
            &surface,
            Some(&call),
            "python",
            AuditSinkKind::MelPython,
            |_| (AuditSeverity::Medium, "Example"),
            true,
            &mut analysis,
        );
        let derived = analysis.derived_surfaces;
        assert!(findings.is_some());
        assert_eq!(derived.len(), 1);
        assert_eq!(derived[0].root_index, 0);
        assert_eq!(derived[0].text.as_ref(), "exec('print(1)')");
        surface.mel = Some(Arc::new(collect_mel_surface_facts(body)));
        let normal = analyze_mel_surface_impl(0, &surface, &mut HashMap::new());
        assert_eq!(normal.derived_surfaces.len(), 1);
        assert_eq!(normal.derived_surfaces[0].root_index, derived[0].root_index);
        let callback = "button -command \"python(\\\"exec('print(1)')\\\")\";";
        surface.text = Arc::from(callback);
        surface.mel = Some(Arc::new(collect_mel_surface_facts(callback)));
        let callback_analysis = analyze_mel_surface_impl(0, &surface, &mut HashMap::new());
        assert!(!callback_analysis.review_signals.is_empty());
        let callback_surface = callback_analysis
            .derived_surfaces
            .iter()
            .find(|s| s.derivation == AuditSurfaceDerivation::MelCallbackLiteral)
            .unwrap();
        assert_eq!(callback_surface.root_index, 0);
        let python = analyze_mel_surface_impl(1, callback_surface, &mut HashMap::new());
        assert_eq!(python.derived_surfaces.len(), 1);
        assert_eq!(python.derived_surfaces[0].root_index, 0);
    }
}
