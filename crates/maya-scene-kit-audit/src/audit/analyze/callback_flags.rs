use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use maya_scene_kit_observe::scene::execution::{
    MelSurfaceNormalizedArg, MelSurfaceNormalizedItem, collect_mel_surface_facts_shared,
};

use super::{
    AnalysisSurface,
    builders::{build_review_signal, preview_window},
};
use crate::scene::{
    AuditEvidence, AuditEvidenceKey, AuditReviewSignal, AuditSurfaceDerivation, ExecutionLanguage,
    execution::MelSurfaceFacts,
};

#[derive(Debug, Default)]
pub(super) struct CallbackFlagAnalysis {
    pub(super) findings: Vec<crate::scene::AuditFinding>,
    pub(super) review_signals: Vec<AuditReviewSignal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CallbackPayloadKind {
    ProcReference,
    ExecutableBody,
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

    for command in &mel.normalized_commands {
        for item in &command.items {
            let MelSurfaceNormalizedItem::Flag(flag) = item else {
                continue;
            };
            let mut script_args = flag.iter_script_args();
            let Some(first_arg) = script_args.next() else {
                continue;
            };

            let flag_name = flag.preferred_name(mel.source_text.as_ref());
            for arg in std::iter::once(first_arg).chain(script_args) {
                let Some((body, payload_kind)) =
                    classify_callback_arg(arg, mel.source_text.as_ref())
                else {
                    continue;
                };
                let key = (command.schema_name.as_ref(), flag_name, body, payload_kind);
                if !seen_payloads.insert(key) {
                    continue;
                }
                let evidence = vec![
                    AuditEvidence::KeyValue {
                        key: AuditEvidenceKey::Command,
                        value: command.schema_name.to_string(),
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

                match payload_kind {
                    CallbackPayloadKind::ProcReference => {
                        analysis.review_signals.push(build_review_signal(
                            surface_index,
                            "mel_callback_proc_reference",
                            "MEL callback flag references a proc name; offline behavior remains runtime-dependent",
                            evidence,
                        ));
                    }
                    CallbackPayloadKind::ExecutableBody => {
                        analysis.review_signals.push(build_review_signal(
                            surface_index,
                            "mel_callback_body",
                            "MEL callback flag embeds inline script body; derived sink findings determine deny behavior",
                            evidence.clone(),
                        ));

                        let body: Arc<str> = Arc::from(body);
                        let mut derived_origin = surface.origin.clone();
                        derived_origin.lang = ExecutionLanguage::Mel;
                        derived_origin.source_kind = Some(format!(
                            "mel callback flag {}.{}",
                            command.schema_name, flag_name
                        ));
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
                }
            }
        }
    }

    analysis
}

fn classify_callback_arg<'a>(
    arg: &'a MelSurfaceNormalizedArg,
    source_text: &'a str,
) -> Option<(&'a str, CallbackPayloadKind)> {
    let body = arg.literal.as_deref().map(str::trim).or_else(|| {
        let trimmed = arg.text(source_text).trim();
        (!trimmed.is_empty()).then_some(trimmed)
    })?;
    if body.is_empty() || is_empty_callback_placeholder(body) {
        return None;
    }
    let payload_kind = match arg.literal.as_deref() {
        Some(literal) if !arg.dynamic && is_bare_callback_identifier(literal) => {
            CallbackPayloadKind::ProcReference
        }
        _ => CallbackPayloadKind::ExecutableBody,
    };
    Some((body, payload_kind))
}

fn is_bare_callback_identifier(text: &str) -> bool {
    let mut chars = text.trim().chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !matches!(first, 'a'..='z' | 'A'..='Z' | '_') {
        return false;
    }
    chars.all(|ch| matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_'))
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
