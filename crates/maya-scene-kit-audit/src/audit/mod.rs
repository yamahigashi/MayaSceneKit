mod analyze;
mod lower_python;
mod policy;
mod rules;

use std::{
    collections::HashMap,
    fmt::Display,
    path::{Path, PathBuf},
    sync::Arc,
};

use maya_scene_kit_observe::scene::detect_scene_format;

pub use self::rules::ScriptAuditPlan;
use crate::scene::{
    AuditDisposition, AuditEvidence, AuditFinding, AuditFindingCode, AuditFindingDetail,
    AuditNotice, AuditOptions, AuditProfile, AuditReport, AuditSeverity, AuditSinkKind,
    DependencyFact, DependencyRiskClass, EffectCertainty, ExecutionCoverageState,
    ExecutionEffectClass, ExecutionLanguage, ExecutionSemanticClass, ExecutionUnitSummary,
    LoadOptions, Loader, ObservationBundle, SceneDigestSet, SceneFormat, SceneToolError,
    StaticAuditFindingDetail, ValidationState, execution::ObservedExecutionCatalog,
};

pub fn build_script_audit_plan(
    inline_rules: Vec<String>,
    max_preview: usize,
) -> Result<ScriptAuditPlan, SceneToolError> {
    rules::build_script_audit_plan(inline_rules, max_preview)
}

pub fn build_parse_budget_blocked_audit_report(
    scene_path: impl Into<PathBuf>,
    scene_format: SceneFormat,
    validation_state: ValidationState,
    plan: &ScriptAuditPlan,
    options: AuditOptions,
    limit: impl Display,
    digests: Option<SceneDigestSet>,
) -> AuditReport {
    let blocked_on_uncertainty = true;
    AuditReport {
        scene_path: scene_path.into(),
        scene_format,
        profile: options.profile,
        validation_state,
        effective_rules: plan.effective_rules.clone(),
        surface_count: 0,
        coverage_state: ExecutionCoverageState::Incomplete,
        coverage_issues: Vec::new(),
        blocked_on_uncertainty,
        disposition: determine_disposition(
            options.profile,
            &[],
            &[],
            blocked_on_uncertainty,
            false,
            false,
        ),
        unit_summaries: Vec::new(),
        dependency_facts: Vec::new(),
        unknown_semantics: Vec::new(),
        digests: digests.unwrap_or_else(empty_scene_digests),
        notices: vec![AuditNotice::parse_budget_exceeded(limit)],
        surfaces: Vec::new(),
        review_signals: Vec::new(),
        findings: Vec::new(),
    }
}

pub fn audit_observation(
    observation: &ObservationBundle,
    plan: &ScriptAuditPlan,
    options: AuditOptions,
) -> Result<AuditReport, SceneToolError> {
    audit_observation_with_digests(observation, plan, options, true)
}

pub fn audit_observation_with_digests(
    observation: &ObservationBundle,
    plan: &ScriptAuditPlan,
    options: AuditOptions,
    include_digests: bool,
) -> Result<AuditReport, SceneToolError> {
    let scene_path = observation.scene_path().to_path_buf();
    let scene_format = observation.scene_format();
    let validation_state = observation.validation_state();
    let ObservedExecutionCatalog {
        surfaces: observed_surfaces,
        unit_summaries,
        dependency_facts,
        unknown_semantics,
        digests: observed_digests,
        coverage_state,
        coverage_issues,
    } = match observation.observed_execution_catalog_with_digests(plan.max_preview, include_digests)
    {
        Ok(catalog) => catalog,
        Err(SceneToolError::MelParseBudgetExceeded { limit }) => {
            let digests = if include_digests {
                Some(observation.scene_digests(0)?)
            } else {
                None
            };
            return Ok(build_parse_budget_blocked_audit_report(
                scene_path,
                scene_format,
                validation_state,
                plan,
                options,
                limit,
                digests,
            ));
        }
        Err(SceneToolError::MbParseBudgetExceeded { limit }) => {
            let digests = if include_digests {
                Some(observation.scene_digests(0)?)
            } else {
                None
            };
            return Ok(build_parse_budget_blocked_audit_report(
                scene_path,
                scene_format,
                validation_state,
                plan,
                options,
                limit,
                digests,
            ));
        }
        Err(err) => return Err(err),
    };
    let surface_count = observed_surfaces.len();
    let mut mel_surface_facts_cache = HashMap::<Arc<str>, Arc<_>>::with_capacity(surface_count);
    let has_custom_rules = !plan.rules.is_empty();
    let mut surfaces = observed_surfaces
        .into_iter()
        .map(analyze::AnalysisSurface::observed)
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    let mut review_signals = Vec::new();
    let mut surface_index = 0usize;

    while surface_index < surfaces.len() {
        let analysis = {
            let surface = &surfaces[surface_index];
            findings.extend(surface_uncertainty_findings(surface_index, surface));
            if has_custom_rules {
                findings.extend(analyze::findings_for_custom_rules(
                    surface_index,
                    surface,
                    &plan.rules,
                ));
            }
            match surface.origin.lang {
                ExecutionLanguage::Python => {
                    analyze::analyze_python_surface(surface_index, surface)
                }
                ExecutionLanguage::Mel | ExecutionLanguage::Unknown => {
                    analyze::analyze_mel_surface(
                        surface_index,
                        surface,
                        &mut mel_surface_facts_cache,
                    )
                }
            }
        };
        findings.extend(analysis.findings);
        review_signals.extend(analysis.review_signals);
        surfaces.extend(analysis.derived_surfaces);
        surfaces[surface_index].discard_analysis_state();
        surface_index += 1;
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.code.as_str().cmp(b.code.as_str()))
            .then_with(|| a.detail.sort_key().cmp(b.detail.sort_key()))
            .then_with(|| a.surface_index.cmp(&b.surface_index))
    });
    review_signals.sort_by(|a, b| {
        a.code
            .as_str()
            .cmp(b.code.as_str())
            .then_with(|| a.detail.sort_key().cmp(b.detail.sort_key()))
            .then_with(|| a.surface_index.cmp(&b.surface_index))
    });

    let over_budget = unit_summaries.len() > options.budgets.max_units
        || dependency_facts.len() > options.budgets.max_dependencies;
    let blocked_on_uncertainty = matches!(
        validation_state,
        ValidationState::Invalid
            | ValidationState::Unsupported
            | ValidationState::CopiedUnvalidated
    ) || coverage_state != ExecutionCoverageState::Complete
        || !coverage_issues.is_empty()
        || !unknown_semantics.is_empty()
        || over_budget;
    let disposition = determine_disposition(
        options.profile,
        &unit_summaries,
        &dependency_facts,
        blocked_on_uncertainty,
        !review_signals.is_empty(),
        !findings.is_empty(),
    );
    let digests = if include_digests {
        observed_digests
    } else {
        SceneDigestSet {
            scene_sha256: String::new(),
            schema_bundle_sha256: None,
            policy_bundle_sha256: None,
        }
    };
    Ok(AuditReport {
        scene_path,
        scene_format,
        profile: options.profile,
        validation_state,
        effective_rules: plan.effective_rules.clone(),
        surface_count,
        coverage_state,
        coverage_issues,
        blocked_on_uncertainty,
        disposition,
        unit_summaries,
        dependency_facts,
        unknown_semantics,
        digests,
        notices: Vec::new(),
        surfaces: surfaces
            .into_iter()
            .map(analyze::AnalysisSurface::into_public)
            .collect(),
        review_signals,
        findings,
    })
}

pub fn audit_script_nodes_with_options(
    path: impl AsRef<Path>,
    plan: &ScriptAuditPlan,
    load_options: &LoadOptions,
    options: AuditOptions,
) -> Result<AuditReport, SceneToolError> {
    audit_script_nodes_with_options_and_digests(path, plan, load_options, options, true)
}

pub fn audit_script_nodes_with_options_and_digests(
    path: impl AsRef<Path>,
    plan: &ScriptAuditPlan,
    load_options: &LoadOptions,
    options: AuditOptions,
    include_digests: bool,
) -> Result<AuditReport, SceneToolError> {
    let path = path.as_ref();
    let loader = Loader::new(load_options.clone());
    let observation = match loader.observe_path(path) {
        Ok(observation) => observation,
        Err(SceneToolError::MelParseBudgetExceeded { limit }) => {
            let scene_format = detect_scene_format(path)?;
            return Ok(build_parse_budget_blocked_audit_report(
                path.to_path_buf(),
                scene_format,
                ValidationState::Invalid,
                plan,
                options,
                limit,
                None,
            ));
        }
        Err(SceneToolError::MbParseBudgetExceeded { limit }) => {
            let scene_format = detect_scene_format(path)?;
            return Ok(build_parse_budget_blocked_audit_report(
                path.to_path_buf(),
                scene_format,
                ValidationState::Invalid,
                plan,
                options,
                limit,
                None,
            ));
        }
        Err(err) => return Err(err),
    };
    audit_observation_with_digests(&observation, plan, options, include_digests)
}

pub fn audit_script_nodes(
    path: impl AsRef<Path>,
    plan: &ScriptAuditPlan,
) -> Result<AuditReport, SceneToolError> {
    audit_script_nodes_with_options(
        path,
        plan,
        &LoadOptions::default(),
        AuditOptions::strict_default(),
    )
}

fn determine_disposition(
    profile: AuditProfile,
    unit_summaries: &[ExecutionUnitSummary],
    dependency_facts: &[DependencyFact],
    blocked_on_uncertainty: bool,
    has_review_signals: bool,
    has_findings: bool,
) -> AuditDisposition {
    let mut disposition = if unit_summaries.is_empty() {
        AuditDisposition::Allow
    } else {
        AuditDisposition::AllowWithNotice
    };

    for summary in unit_summaries {
        disposition = max_disposition(disposition, disposition_for_unit(profile, summary));
    }
    for fact in dependency_facts {
        disposition = max_disposition(disposition, disposition_for_dependency(profile, fact));
    }
    if blocked_on_uncertainty {
        disposition = max_disposition(
            disposition,
            match profile {
                AuditProfile::StrictDefault => AuditDisposition::Review,
                AuditProfile::HardenedUntrusted => AuditDisposition::DenyUncertain,
            },
        );
    }
    if has_review_signals {
        disposition = max_disposition(
            disposition,
            match profile {
                AuditProfile::StrictDefault => AuditDisposition::Review,
                AuditProfile::HardenedUntrusted => AuditDisposition::DenyUncertain,
            },
        );
    }
    if has_findings {
        disposition = max_disposition(disposition, AuditDisposition::DenyMalicious);
    }

    disposition
}

fn empty_scene_digests() -> SceneDigestSet {
    SceneDigestSet {
        scene_sha256: String::new(),
        schema_bundle_sha256: None,
        policy_bundle_sha256: None,
    }
}

fn disposition_for_unit(profile: AuditProfile, summary: &ExecutionUnitSummary) -> AuditDisposition {
    if summary.certainty == EffectCertainty::Uncertain {
        return match profile {
            AuditProfile::StrictDefault => AuditDisposition::Review,
            AuditProfile::HardenedUntrusted => AuditDisposition::DenyUncertain,
        };
    }

    match summary.effect {
        ExecutionEffectClass::PureComputation | ExecutionEffectClass::DiagnosticOutput => {
            AuditDisposition::AllowWithNotice
        }
        ExecutionEffectClass::SceneReadOnly | ExecutionEffectClass::UIImpact => {
            AuditDisposition::Review
        }
        ExecutionEffectClass::SceneMutation => match summary.semantic_class {
            ExecutionSemanticClass::OperationalConfigWrite
            | ExecutionSemanticClass::SceneDataWrite => AuditDisposition::Allow,
            ExecutionSemanticClass::ScriptBearingWrite
            | ExecutionSemanticClass::DependencyWrite => AuditDisposition::DenyMalicious,
            ExecutionSemanticClass::UnknownWrite | ExecutionSemanticClass::General => match profile
            {
                AuditProfile::StrictDefault => AuditDisposition::Review,
                AuditProfile::HardenedUntrusted => AuditDisposition::DenyUncertain,
            },
        },
        ExecutionEffectClass::ExternalDependency => match profile {
            AuditProfile::StrictDefault => AuditDisposition::Review,
            AuditProfile::HardenedUntrusted => AuditDisposition::DenyUncertain,
        },
        ExecutionEffectClass::DynamicEvaluation | ExecutionEffectClass::HookRegistration => {
            AuditDisposition::DenyMalicious
        }
        ExecutionEffectClass::Unknown => match profile {
            AuditProfile::StrictDefault => AuditDisposition::Review,
            AuditProfile::HardenedUntrusted => AuditDisposition::DenyUncertain,
        },
    }
}

fn disposition_for_dependency(profile: AuditProfile, fact: &DependencyFact) -> AuditDisposition {
    match fact.risk {
        DependencyRiskClass::Informational => AuditDisposition::Allow,
        DependencyRiskClass::Review => AuditDisposition::Review,
        DependencyRiskClass::Uncertain => match profile {
            AuditProfile::StrictDefault => AuditDisposition::Review,
            AuditProfile::HardenedUntrusted => AuditDisposition::DenyUncertain,
        },
    }
}

fn disposition_rank(disposition: AuditDisposition) -> u8 {
    match disposition {
        AuditDisposition::Allow => 0,
        AuditDisposition::AllowWithNotice => 1,
        AuditDisposition::Review => 2,
        AuditDisposition::DenyUncertain => 3,
        AuditDisposition::DenyMalicious => 4,
    }
}

fn max_disposition(lhs: AuditDisposition, rhs: AuditDisposition) -> AuditDisposition {
    if disposition_rank(rhs) > disposition_rank(lhs) {
        rhs
    } else {
        lhs
    }
}

fn surface_uncertainty_findings(
    surface_index: usize,
    surface: &analyze::AnalysisSurface,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    if surface.origin.lang == ExecutionLanguage::Unknown {
        findings.push(AuditFinding {
            code: AuditFindingCode::UnknownExecutionLanguage,
            severity: AuditSeverity::High,
            surface_index,
            sink: AuditSinkKind::None,
            rule: None,
            detail: AuditFindingDetail::Static {
                value: StaticAuditFindingDetail::ExecutionSurfaceLanguageCouldNotBeInferred,
            },
            evidence: vec![AuditEvidence::FreeText {
                value: surface.origin.source_kind.clone().unwrap_or_default(),
            }],
        });
    }
    if surface.origin.trigger == crate::scene::ExecutionTrigger::Unknown {
        findings.push(AuditFinding {
            code: AuditFindingCode::UnknownExecutionTrigger,
            severity: AuditSeverity::High,
            surface_index,
            sink: AuditSinkKind::None,
            rule: None,
            detail: AuditFindingDetail::Static {
                value: StaticAuditFindingDetail::ExecutionSurfaceTriggerCouldNotBeInferred,
            },
            evidence: vec![AuditEvidence::FreeText {
                value: surface.origin.source_kind.clone().unwrap_or_default(),
            }],
        });
    }
    findings
}
