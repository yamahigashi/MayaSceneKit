use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use maya_scene_kit_formats::mel::{MelParseBudget, mel_parse_budget_limit_from_message};
use rustpython_parser::ast;

use super::{
    MelResolvedStringKind, MelSinkArgFact, MelSinkArgKind, MelSurfaceFacts,
    ObservedExecutionCatalog, ObservedExecutionSurface, dependency,
    effect_registry::{
        classify_mel_command, classify_mel_command_with_semantics, classify_python_call_target,
        effect_rank,
    },
    mel_surface,
    python_source::{
        PythonParseBudgetLimit, check_python_parse_budget_with_max_bytes,
        collect_static_maya_mel_eval_payloads, is_maya_mel_eval_call, parse_python_compat_suite,
        static_string_expr, with_python_analysis,
    },
    python_walk::{
        PythonAstVisitor, PythonBody, PythonWalkPoint,
        bindings::{BodyBindings, enter_body_bindings, leave_body_bindings},
        walk_expr, walk_stmt, walk_suite,
    },
    surfaces,
};
use crate::scene::{
    DependencyFact, EffectCertainty, ExecutionCoverageIssue, ExecutionCoverageIssueDetail,
    ExecutionCoverageIssueKind, ExecutionCoverageState, ExecutionEffectClass, ExecutionLanguage,
    ExecutionOrigin, ExecutionReason, ExecutionReasonTemplate, ExecutionSemanticClass,
    ExecutionSurfaceKind, ExecutionTrigger, ExecutionUnitSummary, SceneDigestSet, SceneFormat,
    SceneToolError, StaticExecutionReason, UnknownSemanticDetail, UnknownSemanticFact,
    source::{ObservationBundle, ObservationData},
};

const CHANGED_DURING_READ: &str = "scene file changed while it was being read";

#[derive(Debug, Clone)]
pub(crate) struct ObservedExecutionCore {
    pub(super) python_max_body_bytes: usize,
    pub(super) surfaces: Vec<ObservedExecutionSurfaceCore>,
    pub(super) unit_summaries: Vec<ExecutionUnitSummaryCore>,
    pub(super) dependency_facts: Vec<DependencyFact>,
    pub(super) unknown_semantics: Vec<UnknownSemanticFactCore>,
    pub(super) coverage_state: ExecutionCoverageState,
    pub(super) coverage_issues: Vec<surfaces::ExecutionCoverageIssueRecord>,
}

#[derive(Debug, Clone)]
pub(crate) struct ObservedExecutionSurfaceCore {
    pub(super) python_parse_budget_limit: Option<PythonParseBudgetLimit>,
    pub(super) text: Arc<str>,
    pub(super) origin: ExecutionOrigin,
    pub(super) mel: Option<Arc<MelSurfaceFacts>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutionUnitSummaryCore {
    pub(super) origin: ExecutionOrigin,
    pub(super) effect: ExecutionEffectClass,
    pub(super) semantic_class: ExecutionSemanticClass,
    pub(super) certainty: EffectCertainty,
    pub(super) preview: surfaces::PreviewWindowSpec,
    pub(super) reasons: Vec<ExecutionReason>,
}

#[derive(Debug, Clone)]
pub(crate) struct UnknownSemanticFactCore {
    pub(super) origin: ExecutionOrigin,
    pub(super) detail: UnknownSemanticDetail,
    pub(super) preview: surfaces::PreviewWindowSpec,
}

pub(crate) fn build_observed_execution_core(
    observation: &ObservationBundle,
) -> Result<ObservedExecutionCore, SceneToolError> {
    let mut coverage = match &observation.data {
        ObservationData::Ma { data } => {
            let semantics = data.node_execution_semantics()?;
            surfaces::collect_execution_coverage_from_ma_parts(
                data.script_entries(),
                data.execution_node_attr_values()?,
                data.execution_connections()?,
                data.top_level(),
                semantics.as_ref(),
            )
        }
        ObservationData::Mb { session } => {
            surfaces::collect_execution_coverage_from_mb_with_budget(
                &session.mb,
                &session.completeness,
                session.section_state(),
                session.budget(),
                session.schema_context()?.registry(),
                session
                    .schema_context()?
                    .node_execution_semantics()?
                    .as_ref(),
            )
        }
    }?;

    if observation.source_snapshot().identity.stability()
        == crate::scene::source::snapshot::ReadStability::Unstable
    {
        let diagnostic = CHANGED_DURING_READ;
        coverage
            .coverage_issues
            .push(surfaces::ExecutionCoverageIssueRecord {
                kind: ExecutionCoverageIssueKind::TopLevelDiagnostics,
                detail: ExecutionCoverageIssueDetail::TopLevelDiagnostics {
                    diagnostic: diagnostic.into(),
                },
                origin: None,
                preview: surfaces::PreviewWindowSpec::new(
                    Arc::from(diagnostic),
                    0,
                    diagnostic.len(),
                ),
            });
    }

    let mut core = build_execution_core(coverage, observation.mel_parse_budget())?;
    let mut dependency_facts = dependency::collect_scene_dependency_facts(observation)?;
    dependency_facts.append(&mut core.dependency_facts);
    core.dependency_facts = dependency_facts;
    Ok(core)
}

pub fn observe_source_text(
    source: &str,
    language: ExecutionLanguage,
) -> Result<ObservedExecutionCatalog, SceneToolError> {
    if language == ExecutionLanguage::Unknown {
        return Err(SceneToolError::Config(
            "source language must be python or mel".to_string(),
        ));
    }
    let origin = ExecutionOrigin {
        lang: language,
        trigger: ExecutionTrigger::Manual,
        surface_kind: ExecutionSurfaceKind::RawChunkText,
        source_kind: Some("standalone_source_text".to_string()),
        ..ExecutionOrigin::without_chunk_address()
    };
    let coverage = surfaces::ExecutionCoverageCollection {
        surfaces: vec![surfaces::ExecutionSurfaceRecord {
            text: Arc::from(source),
            origin,
            requires_mel_modeling: true,
        }],
        coverage_issues: Vec::new(),
    };
    let mut core = build_execution_core(coverage, &MelParseBudget::default())?;
    if let Some(summary) = core.unit_summaries.first()
        && summary.reasons.iter().any(|reason| {
            matches!(
                reason,
                ExecutionReason::Static {
                    value: StaticExecutionReason::PythonParseFailurePreventsProvenEffectSummary
                }
            )
        })
    {
        core.coverage_issues
            .push(surfaces::ExecutionCoverageIssueRecord {
                kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
                detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
                    diagnostic: "Python parse failed".to_string(),
                },
                origin: Some(summary.origin.clone()),
                preview: summary.preview.clone(),
            });
        core.coverage_state = ExecutionCoverageState::Incomplete;
    }
    Ok(materialize_observed_execution_catalog(
        &core,
        96,
        SceneDigestSet {
            scene_sha256: String::new(),
            schema_bundle_sha256: None,
            policy_bundle_sha256: None,
        },
    ))
}

fn python_budget_issue(
    surface: &surfaces::ExecutionSurfaceRecord,
    limit: PythonParseBudgetLimit,
) -> surfaces::ExecutionCoverageIssueRecord {
    surfaces::ExecutionCoverageIssueRecord {
        kind: ExecutionCoverageIssueKind::PythonParseBudgetExceeded,
        detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
            diagnostic: format!("parse budget exceeded: {limit}"),
        },
        origin: Some(surface.origin.clone()),
        preview: surface_preview_spec(&surface.text),
    }
}

fn python_surface_analysis_result<T>(
    result: std::io::Result<T>,
    surface: &surfaces::ExecutionSurfaceRecord,
    issues: &mut Vec<surfaces::ExecutionCoverageIssueRecord>,
) -> Option<T> {
    result
        .map_err(|error| {
            issues.push(surfaces::ExecutionCoverageIssueRecord {
                kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
                detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
                    diagnostic: format!("Python analysis unavailable: {error}"),
                },
                origin: Some(surface.origin.clone()),
                preview: surface_preview_spec(&surface.text),
            });
        })
        .ok()
}

fn build_execution_core(
    mut coverage: surfaces::ExecutionCoverageCollection,
    mel_parse_budget: &MelParseBudget,
) -> Result<ObservedExecutionCore, SceneToolError> {
    let surface_capacity = coverage.surfaces.len();
    let mut mel_surface_facts_cache = HashMap::with_capacity(surface_capacity);
    let mut observed = Vec::with_capacity(surface_capacity);
    let mut unit_summaries = Vec::with_capacity(surface_capacity);
    let mut unknown_semantics = Vec::with_capacity(surface_capacity);
    let mut pending_surfaces = VecDeque::from(coverage.surfaces);
    while let Some(surface) = pending_surfaces.pop_front() {
        if surface.origin.lang == ExecutionLanguage::Python
            && let Err(limit) =
                check_python_parse_budget_with_max_bytes(&surface.text, mel_parse_budget.max_bytes)
        {
            coverage
                .coverage_issues
                .push(python_budget_issue(&surface, limit));
            observed.push(ObservedExecutionSurfaceCore {
                text: surface.text,
                origin: surface.origin,
                mel: None,
                python_parse_budget_limit: Some(limit),
            });
            continue;
        }
        let should_model =
            surface.requires_mel_modeling || should_model_as_execution_unit(&surface.origin);
        let mel = match surface.origin.lang {
            ExecutionLanguage::Python => None,
            ExecutionLanguage::Mel | ExecutionLanguage::Unknown if should_model => {
                let syntax = mel_surface_syntax_for_origin(&surface.origin);
                Some(mel_surface::collect_cached_mel_surface_facts(
                    &mut mel_surface_facts_cache,
                    &surface.text,
                    syntax,
                    mel_parse_budget,
                ))
            }
            ExecutionLanguage::Mel | ExecutionLanguage::Unknown => None,
        };

        if let Some(limit) = mel.as_deref().and_then(|facts| {
            facts.diagnostics.iter().find_map(|diagnostic| {
                (diagnostic.stage == mel_surface::MelSurfaceDiagnosticStage::Parse)
                    .then_some(())
                    .and_then(|_| mel_parse_budget_limit_from_message(diagnostic.message.as_ref()))
            })
        }) {
            return Err(SceneToolError::MelParseBudgetExceeded { limit });
        }

        if let Some(mel) = mel.as_deref() {
            for fact in &mel.sink_arg_facts {
                if fact.sink_kind == MelSinkArgKind::Python
                    && let Some(body) = fact.rendered_text.as_deref()
                {
                    if let Err(limit) =
                        check_python_parse_budget_with_max_bytes(body, mel_parse_budget.max_bytes)
                    {
                        coverage
                            .coverage_issues
                            .push(python_budget_issue(&surface, limit));
                    }
                }
            }
            if !mel.diagnostics.is_empty() {
                coverage
                    .coverage_issues
                    .push(surface_diagnostic_issue(&surface, mel));
            }
        }

        let summarize = || {
            summarize_execution_unit(
                &surface.origin,
                &surface.text,
                mel.as_deref(),
                mel_parse_budget.max_bytes,
            )
        };
        let (summary, payloads) = if surface.origin.lang == ExecutionLanguage::Python {
            python_surface_analysis_result(
                with_python_analysis(&surface.text, |text| {
                    (
                        summarize(),
                        collect_static_maya_mel_eval_payloads(text, mel_parse_budget.max_bytes),
                    )
                }),
                &surface,
                &mut coverage.coverage_issues,
            )
            .unwrap_or_default()
        } else {
            (summarize(), Vec::new())
        };
        if let Some((summary, unknown)) = summary {
            if let Some(unknown) = unknown {
                unknown_semantics.push(UnknownSemanticFactCore {
                    origin: surface.origin.clone(),
                    detail: unknown,
                    preview: surface_preview_spec(&surface.text),
                });
            }
            unit_summaries.push(summary);
        }

        for payload in payloads {
            let mut origin = surface.origin.clone();
            origin.lang = ExecutionLanguage::Mel;
            origin.source_kind = Some("python->maya.mel.eval literal bridge".to_string());
            pending_surfaces.push_back(surfaces::ExecutionSurfaceRecord {
                text: Arc::from(payload),
                origin,
                requires_mel_modeling: true,
            });
        }

        observed.push(ObservedExecutionSurfaceCore {
            python_parse_budget_limit: None,
            text: surface.text,
            origin: surface.origin,
            mel,
        });
    }

    let coverage_state = derive_coverage_state(SceneFormat::Unknown, &coverage.coverage_issues);
    let dependency_facts = dependency::collect_surface_dependency_facts(&observed);

    Ok(ObservedExecutionCore {
        python_max_body_bytes: mel_parse_budget.max_bytes,
        surfaces: observed,
        unit_summaries,
        dependency_facts,
        unknown_semantics,
        coverage_state,
        coverage_issues: coverage.coverage_issues,
    })
}

fn mel_surface_syntax_for_origin(origin: &ExecutionOrigin) -> mel_surface::MelSurfaceSyntax {
    match origin.source_kind.as_deref() {
        Some("expression" | "internalExpression") => mel_surface::MelSurfaceSyntax::Expression,
        _ => mel_surface::MelSurfaceSyntax::Mel,
    }
}

pub(crate) fn materialize_observed_execution_catalog(
    core: &ObservedExecutionCore,
    max_preview: usize,
    digests: SceneDigestSet,
) -> ObservedExecutionCatalog {
    ObservedExecutionCatalog {
        python_max_body_bytes: core.python_max_body_bytes,
        surfaces: core
            .surfaces
            .iter()
            .map(|surface| materialize_observed_execution_surface(surface, max_preview))
            .collect(),
        unit_summaries: core
            .unit_summaries
            .iter()
            .map(|summary| materialize_execution_unit_summary(summary, max_preview))
            .collect(),
        dependency_facts: core.dependency_facts.clone(),
        unknown_semantics: core
            .unknown_semantics
            .iter()
            .map(|fact| materialize_unknown_semantic_fact(fact, max_preview))
            .collect(),
        digests,
        coverage_state: core.coverage_state,
        coverage_issues: core
            .coverage_issues
            .iter()
            .map(|issue| materialize_coverage_issue(issue, max_preview))
            .collect(),
    }
}

pub(crate) fn derive_coverage_state(
    _scene_format: SceneFormat,
    coverage_issues: &[surfaces::ExecutionCoverageIssueRecord],
) -> ExecutionCoverageState {
    if coverage_issues
        .iter()
        .any(|issue| issue.kind == ExecutionCoverageIssueKind::UnsupportedCoverage)
    {
        return ExecutionCoverageState::Unsupported;
    }
    if coverage_issues.is_empty() {
        ExecutionCoverageState::Complete
    } else {
        ExecutionCoverageState::Incomplete
    }
}

pub(crate) fn build_scene_digests(
    observation: &ObservationBundle,
) -> Result<SceneDigestSet, SceneToolError> {
    Ok(SceneDigestSet {
        scene_sha256: observation.source_snapshot().sha256()?.to_owned(),
        schema_bundle_sha256: match &observation.data {
            ObservationData::Ma { data } => data
                .schema_context
                .as_ref()
                .map(|context| context.schema_bundle_sha256().to_owned()),
            ObservationData::Mb { session } => {
                Some(session.schema_context()?.schema_bundle_sha256().to_owned())
            }
        },
        policy_bundle_sha256: None,
    })
}

fn summarize_mel_surface(
    origin: &ExecutionOrigin,
    mel: Option<&MelSurfaceFacts>,
    text: &str,
    python_max_body_bytes: usize,
) -> (
    ExecutionEffectClass,
    ExecutionSemanticClass,
    EffectCertainty,
    Vec<ExecutionReason>,
) {
    let Some(mel) = mel else {
        return (
            ExecutionEffectClass::Unknown,
            ExecutionSemanticClass::UnknownWrite,
            EffectCertainty::Uncertain,
            vec![ExecutionReason::Static {
                value: StaticExecutionReason::NormalizedMelFactsUnavailable,
            }],
        );
    };

    if !mel.diagnostics.is_empty() {
        return (
            ExecutionEffectClass::Unknown,
            ExecutionSemanticClass::UnknownWrite,
            EffectCertainty::Uncertain,
            vec![ExecutionReason::Static {
                value: StaticExecutionReason::MelDiagnosticsPreventProvenEffectSummary,
            }],
        );
    }

    if mel.calls.is_empty() && mel.normalized_commands.is_empty() {
        return (
            ExecutionEffectClass::PureComputation,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            vec![ExecutionReason::Static {
                value: StaticExecutionReason::NoMelCommandInvocationDetected,
            }],
        );
    }

    let mut effect = ExecutionEffectClass::PureComputation;
    let mut semantic_class = ExecutionSemanticClass::General;
    let mut certainty = EffectCertainty::Proven;
    let reason_capacity = if !mel.normalized_commands.is_empty() {
        mel.normalized_commands.len()
    } else {
        mel.calls.len()
    };
    let mut reasons = Vec::with_capacity(reason_capacity + usize::from(text.trim().is_empty()));
    let expression_python_bridge = is_expression_node_attr_surface(origin);
    let mut consumed_sink_args = vec![false; mel.sink_arg_facts.len()];

    if !mel.normalized_commands.is_empty() {
        for command in &mel.normalized_commands {
            let name = command.schema_name.as_ref();
            let expression_bridge_summary = if name.eq_ignore_ascii_case("python") {
                expression_literal_python_bridge_summary(
                    expression_python_bridge,
                    python_max_body_bytes,
                    mel,
                    &mut consumed_sink_args,
                    command.span_start,
                    command.span_end,
                )
            } else {
                None
            };
            let (call_effect, call_semantic_class, call_certainty, mut call_reasons) =
                expression_bridge_summary.unwrap_or_else(|| {
                    classify_mel_command_with_semantics(mel.source_text.as_ref(), command, name)
                        .map(|rule| {
                            (
                                rule.effect,
                                rule.semantic_class,
                                rule.certainty,
                                vec![rule.reason(name)],
                            )
                        })
                        .unwrap_or_else(|| {
                            (
                                ExecutionEffectClass::Unknown,
                                ExecutionSemanticClass::UnknownWrite,
                                EffectCertainty::Uncertain,
                                vec![ExecutionReason::Named {
                                    template:
                                        ExecutionReasonTemplate::UnclassifiedMelCommandDetected,
                                    value: name.to_string(),
                                }],
                            )
                        })
                });

            if effect_rank(call_effect) > effect_rank(effect)
                || (call_effect == effect
                    && semantic_rank(call_semantic_class) > semantic_rank(semantic_class))
            {
                effect = call_effect;
                semantic_class = call_semantic_class;
            }
            if call_certainty == EffectCertainty::Uncertain {
                certainty = EffectCertainty::Uncertain;
            }
            reasons.append(&mut call_reasons);
        }
    } else {
        for call in &mel.calls {
            let name = call.name.as_ref();
            let expression_bridge_summary = if name.eq_ignore_ascii_case("python") {
                expression_literal_python_bridge_summary(
                    expression_python_bridge,
                    python_max_body_bytes,
                    mel,
                    &mut consumed_sink_args,
                    call.span_start,
                    call.span_end,
                )
            } else {
                None
            };
            let (call_effect, call_semantic_class, call_certainty, mut call_reasons) =
                expression_bridge_summary.unwrap_or_else(|| {
                    classify_mel_command(name)
                        .map(|rule| {
                            (
                                rule.effect,
                                rule.semantic_class,
                                rule.certainty,
                                vec![rule.reason(name)],
                            )
                        })
                        .unwrap_or_else(|| {
                            (
                                ExecutionEffectClass::Unknown,
                                ExecutionSemanticClass::UnknownWrite,
                                EffectCertainty::Uncertain,
                                vec![ExecutionReason::Named {
                                    template:
                                        ExecutionReasonTemplate::UnclassifiedMelCommandDetected,
                                    value: name.to_string(),
                                }],
                            )
                        })
                });

            if effect_rank(call_effect) > effect_rank(effect)
                || (call_effect == effect
                    && semantic_rank(call_semantic_class) > semantic_rank(semantic_class))
            {
                effect = call_effect;
                semantic_class = call_semantic_class;
            }
            if call_certainty == EffectCertainty::Uncertain {
                certainty = EffectCertainty::Uncertain;
            }
            reasons.append(&mut call_reasons);
        }
    }

    if text.trim().is_empty() {
        reasons.push(ExecutionReason::Static {
            value: StaticExecutionReason::ExecutionUnitBodyEmpty,
        });
    }

    (effect, semantic_class, certainty, reasons)
}

fn expression_literal_python_bridge_summary(
    expression_python_bridge: bool,
    python_max_body_bytes: usize,
    mel: &MelSurfaceFacts,
    consumed_sink_args: &mut [bool],
    command_start: usize,
    command_end: usize,
) -> Option<(
    ExecutionEffectClass,
    ExecutionSemanticClass,
    EffectCertainty,
    Vec<ExecutionReason>,
)> {
    if !expression_python_bridge {
        return None;
    }
    let (index, fact) =
        literal_python_sink_arg_in_command(mel, consumed_sink_args, command_start, command_end)?;
    consumed_sink_args[index] = true;
    check_python_parse_budget_with_max_bytes(
        fact.rendered_text.as_deref().unwrap_or_default(),
        python_max_body_bytes,
    )
    .ok()?;
    let (effect, semantic_class, certainty, reasons) = summarize_python_surface(
        fact.rendered_text.as_deref().unwrap_or_default(),
        python_max_body_bytes,
    );
    Some((effect, semantic_class, certainty, reasons))
}

fn literal_python_sink_arg_in_command<'a>(
    mel: &'a MelSurfaceFacts,
    consumed_sink_args: &[bool],
    command_start: usize,
    command_end: usize,
) -> Option<(usize, &'a MelSinkArgFact)> {
    mel.sink_arg_facts.iter().enumerate().find(|(index, fact)| {
        !consumed_sink_args[*index]
            && fact.sink_kind == MelSinkArgKind::Python
            && fact.resolved_kind == MelResolvedStringKind::Literal
            && fact.rendered_text.is_some()
            && is_direct_literal_sink_arg(mel.source_text.as_ref(), fact)
            && fact.span.start >= command_start
            && fact.span.end <= command_end
    })
}

fn is_direct_literal_sink_arg(source_text: &str, fact: &MelSinkArgFact) -> bool {
    source_text
        .get(fact.span.start..fact.span.end)
        .map(str::trim_start)
        .is_some_and(|text| text.starts_with('"') || text.starts_with('\''))
}

fn is_expression_node_attr_surface(origin: &ExecutionOrigin) -> bool {
    origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
        && matches!(
            origin.source_kind.as_deref(),
            Some("expression" | "internalExpression")
        )
}

type PythonEffectSummary = (
    ExecutionEffectClass,
    ExecutionSemanticClass,
    EffectCertainty,
    Vec<ExecutionReason>,
);

fn summarize_python_surface(text: &str, python_max_body_bytes: usize) -> PythonEffectSummary {
    python_summary_result(with_python_analysis(text, |text| {
        let program = parse_python_compat_suite(text, python_max_body_bytes)?;
        let mut visitor = PythonEffectVisitor::default();
        walk_suite(&mut visitor, &program);
        Some(visitor.finish())
    }))
}

fn python_summary_result(
    result: std::io::Result<Option<PythonEffectSummary>>,
) -> PythonEffectSummary {
    result.ok().flatten().unwrap_or_else(|| {
        (
            ExecutionEffectClass::Unknown,
            ExecutionSemanticClass::UnknownWrite,
            EffectCertainty::Uncertain,
            vec![ExecutionReason::Static {
                value: StaticExecutionReason::PythonParseFailurePreventsProvenEffectSummary,
            }],
        )
    })
}

fn materialize_observed_execution_surface(
    surface: &ObservedExecutionSurfaceCore,
    max_preview: usize,
) -> ObservedExecutionSurface {
    ObservedExecutionSurface {
        python_parse_budget_limit: surface.python_parse_budget_limit,
        surface: surfaces::ExecutionSurface {
            text: Arc::clone(&surface.text),
            origin: surface.origin.clone(),
            preview: render_preview(&surface_preview_spec(&surface.text), max_preview),
        },
        mel: surface.mel.clone(),
    }
}

fn materialize_execution_unit_summary(
    summary: &ExecutionUnitSummaryCore,
    max_preview: usize,
) -> ExecutionUnitSummary {
    ExecutionUnitSummary {
        origin: summary.origin.clone(),
        effect: summary.effect,
        semantic_class: summary.semantic_class,
        certainty: summary.certainty,
        preview: render_preview(&summary.preview, max_preview),
        reasons: summary.reasons.clone(),
    }
}

fn materialize_unknown_semantic_fact(
    fact: &UnknownSemanticFactCore,
    max_preview: usize,
) -> UnknownSemanticFact {
    UnknownSemanticFact {
        origin: fact.origin.clone(),
        detail: fact.detail.clone(),
        preview: render_preview(&fact.preview, max_preview),
    }
}

fn materialize_coverage_issue(
    issue: &surfaces::ExecutionCoverageIssueRecord,
    max_preview: usize,
) -> ExecutionCoverageIssue {
    ExecutionCoverageIssue {
        kind: issue.kind,
        detail: issue.detail.clone(),
        origin: issue.origin.clone(),
        preview: match &issue.detail {
            ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic }
                if diagnostic == CHANGED_DURING_READ && issue.origin.is_none() =>
            {
                diagnostic.clone()
            }
            _ => render_preview(&issue.preview, max_preview),
        },
    }
}

fn render_preview(preview: &surfaces::PreviewWindowSpec, max_preview: usize) -> String {
    surfaces::preview_window(
        preview.text.as_ref(),
        preview.start,
        preview.end,
        max_preview,
    )
}

fn surface_preview_spec(text: &Arc<str>) -> surfaces::PreviewWindowSpec {
    surfaces::PreviewWindowSpec::prefix(Arc::clone(text))
}

fn surface_diagnostic_issue(
    surface: &surfaces::ExecutionSurfaceRecord,
    facts: &MelSurfaceFacts,
) -> surfaces::ExecutionCoverageIssueRecord {
    let (start, end) = facts
        .diagnostics
        .first()
        .map(|diagnostic| (diagnostic.span_start, diagnostic.span_end))
        .unwrap_or((0, surface.text.len()));
    surfaces::ExecutionCoverageIssueRecord {
        kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
        detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
            diagnostic: facts
                .diagnostics
                .first()
                .map(|diagnostic| diagnostic.message.to_string())
                .unwrap_or_else(|| "surface diagnostics present".to_string()),
        },
        origin: Some(surface.origin.clone()),
        preview: surfaces::PreviewWindowSpec::new(Arc::clone(&surface.text), start, end),
    }
}

fn summarize_execution_unit(
    origin: &ExecutionOrigin,
    text: &Arc<str>,
    mel: Option<&MelSurfaceFacts>,
    python_max_body_bytes: usize,
) -> Option<(ExecutionUnitSummaryCore, Option<UnknownSemanticDetail>)> {
    if !should_model_as_execution_unit(origin) {
        return None;
    }

    let (effect, semantic_class, certainty, reasons) = match origin.lang {
        ExecutionLanguage::Python => summarize_python_surface(text, python_max_body_bytes),
        ExecutionLanguage::Mel => summarize_mel_surface(origin, mel, text, python_max_body_bytes),
        ExecutionLanguage::Unknown => (
            ExecutionEffectClass::Unknown,
            ExecutionSemanticClass::UnknownWrite,
            EffectCertainty::Uncertain,
            vec![ExecutionReason::Static {
                value: StaticExecutionReason::SurfaceLanguageUnknown,
            }],
        ),
    };

    let unknown = (certainty == EffectCertainty::Uncertain).then(|| {
        reasons
            .first()
            .cloned()
            .map(|reason| UnknownSemanticDetail::PrimaryReason { reason })
            .unwrap_or(UnknownSemanticDetail::GenericUncertain)
    });

    Some((
        ExecutionUnitSummaryCore {
            origin: origin.clone(),
            effect,
            semantic_class,
            certainty,
            preview: surface_preview_spec(text),
            reasons,
        },
        unknown,
    ))
}

fn should_model_as_execution_unit(origin: &ExecutionOrigin) -> bool {
    use crate::scene::evidence::ExecutionSurfaceKind;

    match origin.surface_kind {
        ExecutionSurfaceKind::ScriptNodeBody
        | ExecutionSurfaceKind::FileCommandCallback
        | ExecutionSurfaceKind::NodeAttrCallback
        | ExecutionSurfaceKind::RawChunkText => true,
        ExecutionSurfaceKind::TopLevelProcDefinition
        | ExecutionSurfaceKind::TopLevelOtherStatement => false,
        ExecutionSurfaceKind::TopLevelCommand => matches!(
            origin.source_kind.as_deref(),
            Some(
                "python"
                    | "eval"
                    | "evalDeferred"
                    | "exec"
                    | "scriptJob"
                    | "source"
                    | "loadPlugin"
                    | "commandPort"
                    | "print"
                    | "warning"
                    | "error"
                    | "confirmDialog"
                    | "headsUpMessage"
            )
        ),
    }
}

struct PythonEffectVisitor {
    module_aliases: BodyBindings,
    string_values: BodyBindings,
    effect: ExecutionEffectClass,
    semantic_class: ExecutionSemanticClass,
    certainty: EffectCertainty,
    reasons: Vec<ExecutionReason>,
    saw_any_stmt: bool,
}

impl Default for PythonEffectVisitor {
    fn default() -> Self {
        Self {
            module_aliases: BodyBindings::default(),
            string_values: BodyBindings::default(),
            effect: ExecutionEffectClass::PureComputation,
            semantic_class: ExecutionSemanticClass::General,
            certainty: EffectCertainty::Proven,
            reasons: Vec::new(),
            saw_any_stmt: false,
        }
    }
}

impl PythonAstVisitor for PythonEffectVisitor {
    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        self.saw_any_stmt = true;
        self.record_statement(stmt);
        walk_stmt(self, stmt);
        self.record_assignment(stmt);
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        if let ast::Expr::Call(call) = expr {
            self.record_call(call);
        }
        walk_expr(self, expr);
    }

    fn enter_body(&mut self, body: PythonBody<'_>) {
        enter_body_bindings(body, &mut self.module_aliases, &mut self.string_values);
    }

    fn leave_body(&mut self, _body: PythonBody<'_>) {
        leave_body_bindings(&mut self.module_aliases, &mut self.string_values, true);
    }

    fn at_point(&mut self, point: PythonWalkPoint<'_>) {
        match point {
            PythonWalkPoint::AfterForIter(target) | PythonWalkPoint::AfterDeleteTarget(target) => {
                self.clear_string_target(target);
            }
            PythonWalkPoint::AfterWithVars(item) => {
                if let Some(target) = &item.optional_vars {
                    self.clear_string_target(target);
                }
            }
            PythonWalkPoint::BeforeHandlerBody(_) | PythonWalkPoint::AfterComprehensionIter(_) => {}
        }
    }
}

impl PythonEffectVisitor {
    fn record_statement(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::Import(import) => {
                for alias in &import.names {
                    let local_name = alias
                        .asname
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| {
                            alias
                                .name
                                .as_str()
                                .split('.')
                                .next()
                                .unwrap_or(alias.name.as_str())
                                .to_string()
                        });
                    self.module_aliases
                        .insert(local_name, Some(alias.name.as_str().to_string()));
                    self.raise(
                        ExecutionEffectClass::ExternalDependency,
                        ExecutionSemanticClass::DependencyWrite,
                        EffectCertainty::Proven,
                        ExecutionReason::Named {
                            template: ExecutionReasonTemplate::PythonImportDetected,
                            value: alias.name.to_string(),
                        },
                    );
                }
            }
            ast::Stmt::ImportFrom(import) => {
                let module = import.module.as_deref().unwrap_or("<relative>");
                for alias in &import.names {
                    let local_name = alias
                        .asname
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| alias.name.to_string());
                    self.module_aliases
                        .insert(local_name, Some(format!("{module}.{}", alias.name)));
                }
                self.raise(
                    ExecutionEffectClass::ExternalDependency,
                    ExecutionSemanticClass::DependencyWrite,
                    EffectCertainty::Proven,
                    ExecutionReason::Named {
                        template: ExecutionReasonTemplate::PythonImportFromDetected,
                        value: module.to_string(),
                    },
                );
            }
            ast::Stmt::Raise(_) => {
                self.raise(
                    ExecutionEffectClass::UIImpact,
                    ExecutionSemanticClass::General,
                    EffectCertainty::Proven,
                    ExecutionReason::Static {
                        value: StaticExecutionReason::PythonRaiseDetected,
                    },
                );
            }
            _ => {}
        }
    }

    fn record_assignment(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::Assign(stmt) => {
                let string_value = static_string_expr(&stmt.value, &self.string_values);
                for target in &stmt.targets {
                    self.record_string_target(target, string_value.clone());
                }
            }
            ast::Stmt::AnnAssign(stmt) => {
                if let Some(expr) = &stmt.value {
                    self.record_string_target(
                        &stmt.target,
                        static_string_expr(expr, &self.string_values),
                    );
                } else {
                    self.clear_string_target(&stmt.target);
                }
            }
            ast::Stmt::AugAssign(stmt) => {
                self.clear_string_target(&stmt.target);
            }
            _ => {}
        }
    }

    fn record_call(&mut self, call: &ast::ExprCall) {
        if is_maya_mel_eval_call(&call.func, &self.module_aliases) {
            if call.args.is_empty()
                || call
                    .args
                    .first()
                    .and_then(|arg| static_string_expr(arg, &self.string_values))
                    .is_none()
            {
                self.raise(
                    ExecutionEffectClass::Unknown,
                    ExecutionSemanticClass::UnknownWrite,
                    EffectCertainty::Uncertain,
                    ExecutionReason::Static {
                        value: StaticExecutionReason::UnresolvedPythonCallTargetDetected,
                    },
                );
            }
            return;
        }
        let name = call_target_name(&call.func);
        match name {
            Some(name) => {
                if let Some(rule) = classify_python_call_target(&name) {
                    self.raise(
                        rule.effect,
                        rule.semantic_class,
                        rule.certainty,
                        rule.reason(&name),
                    );
                } else {
                    self.raise(
                        ExecutionEffectClass::Unknown,
                        ExecutionSemanticClass::UnknownWrite,
                        EffectCertainty::Uncertain,
                        ExecutionReason::Named {
                            template: ExecutionReasonTemplate::UnclassifiedPythonCallDetected,
                            value: name,
                        },
                    );
                }
            }
            None => self.raise(
                ExecutionEffectClass::Unknown,
                ExecutionSemanticClass::UnknownWrite,
                EffectCertainty::Uncertain,
                ExecutionReason::Static {
                    value: StaticExecutionReason::UnresolvedPythonCallTargetDetected,
                },
            ),
        }
    }

    fn raise(
        &mut self,
        effect: ExecutionEffectClass,
        semantic_class: ExecutionSemanticClass,
        certainty: EffectCertainty,
        reason: ExecutionReason,
    ) {
        if effect_rank(effect) > effect_rank(self.effect)
            || (effect == self.effect
                && semantic_rank(semantic_class) > semantic_rank(self.semantic_class))
        {
            self.effect = effect;
            self.semantic_class = semantic_class;
        }
        if certainty == EffectCertainty::Uncertain {
            self.certainty = EffectCertainty::Uncertain;
        }
        self.reasons.push(reason);
    }

    fn record_string_target(&mut self, target: &ast::Expr, value: Option<String>) {
        match target {
            ast::Expr::Name(name) => {
                self.string_values.insert(name.id.to_string(), value);
            }
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.clear_string_target(elt);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.clear_string_target(elt);
                }
            }
            ast::Expr::Starred(expr) => self.clear_string_target(&expr.value),
            _ => {}
        }
    }

    fn clear_string_target(&mut self, target: &ast::Expr) {
        match target {
            ast::Expr::Name(name) => {
                self.string_values.insert(name.id.to_string(), None);
            }
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.clear_string_target(elt);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.clear_string_target(elt);
                }
            }
            ast::Expr::Starred(expr) => self.clear_string_target(&expr.value),
            _ => {}
        }
    }

    fn finish(
        mut self,
    ) -> (
        ExecutionEffectClass,
        ExecutionSemanticClass,
        EffectCertainty,
        Vec<ExecutionReason>,
    ) {
        if !self.saw_any_stmt {
            return (
                ExecutionEffectClass::PureComputation,
                ExecutionSemanticClass::General,
                EffectCertainty::Proven,
                vec![ExecutionReason::Static {
                    value: StaticExecutionReason::PythonUnitEmpty,
                }],
            );
        }
        if self.reasons.is_empty() {
            self.reasons.push(ExecutionReason::Static {
                value: StaticExecutionReason::NoSideEffectingPythonConstructsDetected,
            });
        }
        (
            self.effect,
            self.semantic_class,
            self.certainty,
            self.reasons,
        )
    }
}

fn call_target_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Name(name) => Some(name.id.to_string()),
        ast::Expr::Attribute(attr) => {
            let mut base = call_target_name(&attr.value)?;
            base.push('.');
            base.push_str(attr.attr.as_str());
            Some(base)
        }
        _ => None,
    }
}

fn semantic_rank(class: ExecutionSemanticClass) -> u8 {
    match class {
        ExecutionSemanticClass::General => 0,
        ExecutionSemanticClass::OperationalConfigWrite => 1,
        ExecutionSemanticClass::SceneDataWrite => 2,
        ExecutionSemanticClass::DependencyWrite => 3,
        ExecutionSemanticClass::ScriptBearingWrite => 4,
        ExecutionSemanticClass::UnknownWrite => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::summarize_python_surface;
    use crate::scene::{EffectCertainty, ExecutionEffectClass};

    #[test]
    fn python_spawn_failure_reports_surface_coverage_gap() {
        let surface = super::surfaces::ExecutionSurfaceRecord {
            text: std::sync::Arc::from("print('Example')"),
            origin: super::ExecutionOrigin {
                lang: super::ExecutionLanguage::Python,
                ..super::ExecutionOrigin::without_chunk_address()
            },
            requires_mel_modeling: true,
        };
        let mut issues = Vec::new();
        assert!(
            super::python_surface_analysis_result::<()>(
                Err(std::io::Error::other("Example spawn failure")),
                &surface,
                &mut issues,
            )
            .is_none()
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].kind,
            super::ExecutionCoverageIssueKind::SurfaceDiagnostics
        );
        assert!(
            matches!(&issues[0].detail, super::ExecutionCoverageIssueDetail::SurfaceDiagnostics { diagnostic } if diagnostic.contains("Example spawn failure"))
        );
        assert_eq!(issues[0].origin, Some(surface.origin));
    }

    #[test]
    fn python_spawn_failure_leaves_summary_uncertain() {
        let result =
            super::python_summary_result(Err(std::io::Error::other("Example spawn failure")));
        assert_eq!(result.0, ExecutionEffectClass::Unknown);
        assert_eq!(result.2, EffectCertainty::Uncertain);
        assert!(matches!(
            result.3.as_slice(),
            [super::ExecutionReason::Static {
                value: super::StaticExecutionReason::PythonParseFailurePreventsProvenEffectSummary,
            }]
        ));
    }

    #[test]
    fn python_summary_uses_the_supplied_byte_budget() {
        let source = "print('Example')";
        assert_eq!(
            summarize_python_surface(source, 8).0,
            ExecutionEffectClass::Unknown
        );
        assert_eq!(
            summarize_python_surface(source, 128).0,
            ExecutionEffectClass::DiagnosticOutput
        );
    }

    #[test]
    fn python_body_budget_preserves_catalog_surfaces() {
        use std::sync::Arc;

        use maya_scene_kit_formats::mel::MelParseBudget;

        use super::{build_execution_core, surfaces};
        use crate::scene::{ExecutionLanguage, ExecutionOrigin};

        let surface = |text: &str| surfaces::ExecutionSurfaceRecord {
            text: Arc::from(text),
            origin: ExecutionOrigin {
                lang: ExecutionLanguage::Python,
                ..ExecutionOrigin::without_chunk_address()
            },
            requires_mel_modeling: true,
        };
        let core = build_execution_core(
            surfaces::ExecutionCoverageCollection {
                surfaces: vec![surface("import os; os.system('Example')"), surface("pass")],
                coverage_issues: Vec::new(),
            },
            &MelParseBudget {
                max_bytes: 8,
                ..MelParseBudget::default()
            },
        )
        .expect("catalog retains skipped Python");
        assert_eq!(core.surfaces.len(), 2);
        assert_eq!(
            core.surfaces[0].text.as_ref(),
            "import os; os.system('Example')"
        );
        assert_eq!(core.coverage_issues.len(), 1);
        assert!(matches!(&core.coverage_issues[0].detail,
            super::ExecutionCoverageIssueDetail::SurfaceDiagnostics { diagnostic }
                if diagnostic == "parse budget exceeded: python_max_body_bytes"));
    }

    #[test]
    fn execution_core_uses_session_completeness() {
        use super::{ExecutionCoverageIssueDetail, ObservationData, build_observed_execution_core};
        use crate::scene::{LoadOptions, Loader, SceneFormat, ValidationState};

        let mut bytes = b"FOR4".to_vec();
        bytes.extend_from_slice(&12u32.to_be_bytes());
        bytes.extend_from_slice(b"MayaDATA");
        bytes.extend_from_slice(&100u32.to_be_bytes());
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                std::path::Path::new("Example.mb"),
                SceneFormat::Mb,
                ValidationState::Validated,
                bytes,
            )
            .unwrap();
        let ObservationData::Mb { session } = &observation.data else {
            panic!("expected MB");
        };
        let expected = session.completeness.to_string();
        assert!(matches!(
            session.completeness,
            crate::mb::MbCompleteness::Truncated { .. }
        ));
        let core = build_observed_execution_core(&observation).unwrap();
        assert_eq!(core.coverage_issues.len(), 1);
        let ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason } =
            &core.coverage_issues[0].detail
        else {
            panic!("unexpected issue");
        };
        assert_eq!(
            reason,
            &format!(
                "MB chunk tree {expected}; reasons=[{}]",
                match &session.completeness {
                    crate::mb::MbCompleteness::Truncated { first_reason, .. } =>
                        first_reason.to_string(),
                    _ => unreachable!(),
                }
            )
        );
    }

    #[test]
    fn python_summary_uses_compat_normalization_for_python2_print() {
        let (_effect, _semantic_class, certainty, reasons) = summarize_python_surface(
            "print u'Example message'\n",
            crate::scene::MelParseBudget::default().max_bytes,
        );

        assert_eq!(certainty, EffectCertainty::Proven);
        assert!(reasons.iter().all(|reason| {
            !format!("{reason:?}").contains("PythonParseFailurePreventsProvenEffectSummary")
        }));
    }

    #[test]
    fn python_summary_does_not_treat_static_maya_mel_eval_as_unknown_python_call() {
        let (effect, _semantic_class, certainty, reasons) = summarize_python_surface(
            "import maya.mel as mm\ncmd = 'set' + 'Project \"asset/example\";'\nmm.eval(cmd)\n",
            crate::scene::MelParseBudget::default().max_bytes,
        );

        assert_eq!(effect, ExecutionEffectClass::ExternalDependency);
        assert_eq!(certainty, EffectCertainty::Proven);
        assert!(
            reasons.iter().all(|reason| {
                !format!("{reason:?}").contains("UnclassifiedPythonCallDetected")
            })
        );
    }

    #[test]
    fn python_summary_keeps_dynamic_maya_mel_eval_uncertain() {
        let (_effect, _semantic_class, certainty, _reasons) = summarize_python_surface(
            "import maya.mel as mm\nmm.eval(build_command())\n",
            crate::scene::MelParseBudget::default().max_bytes,
        );

        assert_eq!(certainty, EffectCertainty::Uncertain);
    }
}

#[cfg(test)]
#[path = "python_walk/observe_tests.rs"]
mod walk_tests;
