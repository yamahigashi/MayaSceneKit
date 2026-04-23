use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use maya_scene_kit_observe::scene::execution::{
    MelResolvedStringKind, MelSinkArgKind, collect_mel_surface_facts_shared,
};

use super::{
    AnalysisSurface,
    builders::{build_finding, build_review_signal, preview_window, severity_for_trigger, snippet},
};
use crate::scene::{
    AuditEvidence, AuditEvidenceKey, AuditReviewSignal, AuditSeverity, AuditSinkKind,
    AuditSurfaceDerivation, ExecutionLanguage, execution::MelSurfaceFacts,
};

#[derive(Debug, Default)]
pub(super) struct CallbackFlagAnalysis {
    pub(super) findings: Vec<crate::scene::AuditFinding>,
    pub(super) review_signals: Vec<AuditReviewSignal>,
}

pub(super) fn analyze_callback_flags(
    surface_index: usize,
    surface: &AnalysisSurface,
    mel: &MelSurfaceFacts,
    mel_surface_facts_cache: &mut HashMap<Arc<str>, Arc<MelSurfaceFacts>>,
    derived_surfaces: &mut Vec<AnalysisSurface>,
) -> CallbackFlagAnalysis {
    let mut analysis = CallbackFlagAnalysis::default();
    let mut seen_payloads = HashSet::new();

    for fact in mel
        .sink_arg_facts
        .iter()
        .filter(|fact| fact.sink_kind == MelSinkArgKind::CallbackFlag)
    {
        let Some(command_name) = fact.command_name.as_deref() else {
            continue;
        };
        let Some(flag_name) = fact.flag_name.as_deref() else {
            continue;
        };
        let Some(body) = fact.rendered_text.as_deref().map(str::trim) else {
            continue;
        };
        if body.is_empty() || is_empty_callback_placeholder(body) {
            continue;
        }
        if !seen_payloads.insert((command_name, flag_name, body, fact.resolved_kind)) {
            continue;
        }

        let evidence = vec![
            AuditEvidence::KeyValue {
                key: AuditEvidenceKey::Command,
                value: command_name.to_string(),
            },
            AuditEvidence::KeyValue {
                key: AuditEvidenceKey::Flag,
                value: flag_name.to_string(),
            },
            AuditEvidence::KeyValue {
                key: AuditEvidenceKey::CallbackTarget,
                value: body.to_string(),
            },
        ];
        let preview_override = Some(snippet(body));

        match fact.resolved_kind {
            MelResolvedStringKind::ProcReference => {
                analysis.review_signals.push(build_review_signal(
                    surface,
                    surface_index,
                    "mel_callback_proc_reference",
                    "MEL callback flag references a proc name; offline behavior remains runtime-dependent",
                    evidence,
                    preview_override,
                ));
            }
            MelResolvedStringKind::Literal | MelResolvedStringKind::AssembledLiteral => {
                analysis.findings.push(build_finding(
                    surface_index,
                    surface,
                    "mel_callback_flag",
                    severity_for_trigger(AuditSeverity::High, surface.origin.trigger),
                    AuditSinkKind::None,
                    None,
                    "script-bearing MEL callback flag detected",
                    evidence.clone(),
                    preview_override.clone(),
                ));
                analysis.review_signals.push(build_review_signal(
                    surface,
                    surface_index,
                    "mel_callback_body",
                    "MEL callback flag embeds inline script body; derived sink findings determine deny behavior",
                    evidence.clone(),
                    preview_override.clone(),
                ));

                let body: Arc<str> = Arc::from(body);
                let mut derived_origin = surface.origin.clone();
                derived_origin.lang = ExecutionLanguage::Mel;
                derived_origin.source_kind =
                    Some(format!("mel callback flag {command_name}.{flag_name}"));
                let mel = collect_cached_mel_surface_facts(mel_surface_facts_cache, &body);
                derived_surfaces.push(AnalysisSurface {
                    preview: preview_window(
                        &body,
                        0,
                        body.len().min(24),
                        surface.preview.len().max(16),
                    ),
                    text: body,
                    origin: derived_origin,
                    derivation: AuditSurfaceDerivation::MelCallbackLiteral,
                    mel: Some(mel),
                });
            }
            MelResolvedStringKind::Dynamic | MelResolvedStringKind::Unknown => {
                analysis.findings.push(build_finding(
                    surface_index,
                    surface,
                    "mel_callback_flag",
                    severity_for_trigger(AuditSeverity::High, surface.origin.trigger),
                    AuditSinkKind::None,
                    None,
                    "script-bearing MEL callback flag detected",
                    evidence,
                    preview_override,
                ));
            }
        }
    }

    analysis
}

fn is_empty_callback_placeholder(text: &str) -> bool {
    let trimmed = text.trim();
    let Some(inner) = trimmed
        .strip_prefix('{')
        .and_then(|text| text.strip_suffix('}'))
    else {
        return false;
    };
    inner.trim().is_empty()
}

fn collect_cached_mel_surface_facts(
    cache: &mut HashMap<Arc<str>, Arc<MelSurfaceFacts>>,
    source: &Arc<str>,
) -> Arc<MelSurfaceFacts> {
    if let Some(facts) = cache.get(source.as_ref()) {
        return Arc::clone(facts);
    }

    let facts = Arc::new(collect_mel_surface_facts_shared(Arc::clone(source)));
    cache.insert(Arc::clone(source), Arc::clone(&facts));
    facts
}
