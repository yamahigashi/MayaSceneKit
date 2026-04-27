use std::{collections::HashMap, sync::Arc};

use maya_scene_kit_formats::mel::mel_parse_budget_limit_from_message;
use rustpython_parser::{Parse, ast};
use sha2::{Digest, Sha256};

use super::{
    MelSurfaceFacts, ObservedExecutionCatalog, ObservedExecutionSurface, dependency,
    effect_registry::{
        classify_mel_command, classify_mel_command_with_semantics, classify_python_call_target,
        effect_rank,
    },
    mel_surface, surfaces,
};
use crate::scene::{
    DependencyFact, EffectCertainty, ExecutionCoverageIssue, ExecutionCoverageIssueDetail,
    ExecutionCoverageIssueKind, ExecutionCoverageState, ExecutionEffectClass, ExecutionLanguage,
    ExecutionOrigin, ExecutionReason, ExecutionReasonTemplate, ExecutionSemanticClass,
    ExecutionUnitSummary, SceneDigestSet, SceneFormat, SceneToolError, StaticExecutionReason,
    UnknownSemanticDetail, UnknownSemanticFact,
    source::{ObservationBundle, ObservationData},
};

#[derive(Debug, Clone)]
pub(crate) struct ObservedExecutionCore {
    pub(super) surfaces: Vec<ObservedExecutionSurfaceCore>,
    pub(super) unit_summaries: Vec<ExecutionUnitSummaryCore>,
    pub(super) dependency_facts: Vec<DependencyFact>,
    pub(super) unknown_semantics: Vec<UnknownSemanticFactCore>,
    pub(super) coverage_state: ExecutionCoverageState,
    pub(super) coverage_issues: Vec<surfaces::ExecutionCoverageIssueRecord>,
}

#[derive(Debug, Clone)]
pub(crate) struct ObservedExecutionSurfaceCore {
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
                data.top_level(),
                semantics.as_ref(),
            )
        }
        ObservationData::Mb { session } => {
            surfaces::collect_execution_coverage_from_mb_with_budget(
                &session.mb,
                session.budget(),
                session
                    .schema_context()
                    .node_execution_semantics()?
                    .as_ref(),
            )
        }
    }?;

    let surface_capacity = coverage.surfaces.len();
    let mut mel_surface_facts_cache = HashMap::with_capacity(surface_capacity);
    let mut observed = Vec::with_capacity(surface_capacity);
    let mut unit_summaries = Vec::with_capacity(surface_capacity);
    let mut unknown_semantics = Vec::with_capacity(surface_capacity);
    for surface in coverage.surfaces {
        let should_model = should_model_as_execution_unit(&surface.origin);
        let mel = match surface.origin.lang {
            ExecutionLanguage::Python => None,
            ExecutionLanguage::Mel | ExecutionLanguage::Unknown if should_model => {
                let syntax = mel_surface_syntax_for_origin(&surface.origin);
                Some(mel_surface::collect_cached_mel_surface_facts(
                    &mut mel_surface_facts_cache,
                    &surface.text,
                    syntax,
                    observation.mel_parse_budget(),
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
            if !mel.diagnostics.is_empty() {
                coverage
                    .coverage_issues
                    .push(surface_diagnostic_issue(&surface, mel));
            }
        }

        if let Some((summary, unknown)) =
            summarize_execution_unit(&surface.origin, &surface.text, mel.as_deref())
        {
            if let Some(unknown) = unknown {
                unknown_semantics.push(UnknownSemanticFactCore {
                    origin: surface.origin.clone(),
                    detail: unknown,
                    preview: surface_preview_spec(&surface.text),
                });
            }
            unit_summaries.push(summary);
        }

        observed.push(ObservedExecutionSurfaceCore {
            text: surface.text,
            origin: surface.origin,
            mel,
        });
    }

    let coverage_state =
        derive_coverage_state(observation.scene_format(), &coverage.coverage_issues);
    let dependency_facts = dependency::collect_dependency_facts(observation, &observed)?;

    Ok(ObservedExecutionCore {
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
    let bytes = match &observation.data {
        ObservationData::Ma { data } => data.bytes()?,
        ObservationData::Mb { session } => session.mb.data.as_ref(),
    };
    Ok(SceneDigestSet {
        scene_sha256: sha256_hex(bytes),
        schema_bundle_sha256: None,
        policy_bundle_sha256: None,
    })
}

fn summarize_mel_surface(
    mel: Option<&MelSurfaceFacts>,
    text: &str,
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

    if !mel.normalized_commands.is_empty() {
        for command in &mel.normalized_commands {
            let name = command.schema_name.as_ref();
            let (call_effect, call_semantic_class, call_certainty, reason) =
                classify_mel_command_with_semantics(mel.source_text.as_ref(), command, name)
                    .map(|rule| {
                        (
                            rule.effect,
                            rule.semantic_class,
                            rule.certainty,
                            rule.reason(name),
                        )
                    })
                    .unwrap_or_else(|| {
                        (
                            ExecutionEffectClass::Unknown,
                            ExecutionSemanticClass::UnknownWrite,
                            EffectCertainty::Uncertain,
                            ExecutionReason::Named {
                                template: ExecutionReasonTemplate::UnclassifiedMelCommandDetected,
                                value: name.to_string(),
                            },
                        )
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
            reasons.push(reason);
        }
    } else {
        for call in &mel.calls {
            let name = call.name.as_ref();
            let (call_effect, call_semantic_class, call_certainty, reason) =
                classify_mel_command(name)
                    .map(|rule| {
                        (
                            rule.effect,
                            rule.semantic_class,
                            rule.certainty,
                            rule.reason(name),
                        )
                    })
                    .unwrap_or_else(|| {
                        (
                            ExecutionEffectClass::Unknown,
                            ExecutionSemanticClass::UnknownWrite,
                            EffectCertainty::Uncertain,
                            ExecutionReason::Named {
                                template: ExecutionReasonTemplate::UnclassifiedMelCommandDetected,
                                value: name.to_string(),
                            },
                        )
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
            reasons.push(reason);
        }
    }

    if text.trim().is_empty() {
        reasons.push(ExecutionReason::Static {
            value: StaticExecutionReason::ExecutionUnitBodyEmpty,
        });
    }

    (effect, semantic_class, certainty, reasons)
}

fn summarize_python_surface(
    text: &str,
) -> (
    ExecutionEffectClass,
    ExecutionSemanticClass,
    EffectCertainty,
    Vec<ExecutionReason>,
) {
    let Ok(program) = ast::Suite::parse(text, "<observe>") else {
        return (
            ExecutionEffectClass::Unknown,
            ExecutionSemanticClass::UnknownWrite,
            EffectCertainty::Uncertain,
            vec![ExecutionReason::Static {
                value: StaticExecutionReason::PythonParseFailurePreventsProvenEffectSummary,
            }],
        );
    };

    let mut visitor = PythonEffectVisitor::default();
    visitor.visit_suite(&program);
    visitor.finish()
}

fn materialize_observed_execution_surface(
    surface: &ObservedExecutionSurfaceCore,
    max_preview: usize,
) -> ObservedExecutionSurface {
    ObservedExecutionSurface {
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
        preview: render_preview(&issue.preview, max_preview),
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
) -> Option<(ExecutionUnitSummaryCore, Option<UnknownSemanticDetail>)> {
    if !should_model_as_execution_unit(origin) {
        return None;
    }

    let (effect, semantic_class, certainty, reasons) = match origin.lang {
        ExecutionLanguage::Python => summarize_python_surface(text),
        ExecutionLanguage::Mel => summarize_mel_surface(mel, text),
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
    effect: ExecutionEffectClass,
    semantic_class: ExecutionSemanticClass,
    certainty: EffectCertainty,
    reasons: Vec<ExecutionReason>,
    saw_any_stmt: bool,
}

impl Default for PythonEffectVisitor {
    fn default() -> Self {
        Self {
            effect: ExecutionEffectClass::PureComputation,
            semantic_class: ExecutionSemanticClass::General,
            certainty: EffectCertainty::Proven,
            reasons: Vec::new(),
            saw_any_stmt: false,
        }
    }
}

impl PythonEffectVisitor {
    fn visit_suite(&mut self, suite: &ast::Suite) {
        for stmt in suite {
            self.saw_any_stmt = true;
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::Import(import) => {
                for alias in &import.names {
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
            ast::Stmt::FunctionDef(function) => self.visit_suite(&function.body),
            ast::Stmt::AsyncFunctionDef(function) => self.visit_suite(&function.body),
            ast::Stmt::ClassDef(class_def) => self.visit_suite(&class_def.body),
            ast::Stmt::For(stmt) => {
                self.visit_expr(&stmt.target);
                self.visit_expr(&stmt.iter);
                self.visit_suite(&stmt.body);
                self.visit_suite(&stmt.orelse);
            }
            ast::Stmt::AsyncFor(stmt) => {
                self.visit_expr(&stmt.target);
                self.visit_expr(&stmt.iter);
                self.visit_suite(&stmt.body);
                self.visit_suite(&stmt.orelse);
            }
            ast::Stmt::While(stmt) => {
                self.visit_expr(&stmt.test);
                self.visit_suite(&stmt.body);
                self.visit_suite(&stmt.orelse);
            }
            ast::Stmt::If(stmt) => {
                self.visit_expr(&stmt.test);
                self.visit_suite(&stmt.body);
                self.visit_suite(&stmt.orelse);
            }
            ast::Stmt::With(stmt) => {
                for item in &stmt.items {
                    self.visit_expr(&item.context_expr);
                    if let Some(vars) = &item.optional_vars {
                        self.visit_expr(vars);
                    }
                }
                self.visit_suite(&stmt.body);
            }
            ast::Stmt::AsyncWith(stmt) => {
                for item in &stmt.items {
                    self.visit_expr(&item.context_expr);
                    if let Some(vars) = &item.optional_vars {
                        self.visit_expr(vars);
                    }
                }
                self.visit_suite(&stmt.body);
            }
            ast::Stmt::Try(stmt) => {
                self.visit_suite(&stmt.body);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    if let Some(expr) = &handler.type_ {
                        self.visit_expr(expr);
                    }
                    self.visit_suite(&handler.body);
                }
                self.visit_suite(&stmt.orelse);
                self.visit_suite(&stmt.finalbody);
            }
            ast::Stmt::TryStar(stmt) => {
                self.visit_suite(&stmt.body);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    if let Some(expr) = &handler.type_ {
                        self.visit_expr(expr);
                    }
                    self.visit_suite(&handler.body);
                }
                self.visit_suite(&stmt.orelse);
                self.visit_suite(&stmt.finalbody);
            }
            ast::Stmt::Match(stmt) => {
                self.visit_expr(&stmt.subject);
                for case in &stmt.cases {
                    if let Some(guard) = &case.guard {
                        self.visit_expr(guard);
                    }
                    self.visit_suite(&case.body);
                }
            }
            ast::Stmt::Return(stmt) => {
                if let Some(expr) = &stmt.value {
                    self.visit_expr(expr);
                }
            }
            ast::Stmt::Assign(stmt) => {
                for target in &stmt.targets {
                    self.visit_expr(target);
                }
                self.visit_expr(&stmt.value);
            }
            ast::Stmt::AnnAssign(stmt) => {
                self.visit_expr(&stmt.target);
                if let Some(expr) = &stmt.value {
                    self.visit_expr(expr);
                }
            }
            ast::Stmt::AugAssign(stmt) => {
                self.visit_expr(&stmt.target);
                self.visit_expr(&stmt.value);
            }
            ast::Stmt::Expr(stmt) => self.visit_expr(&stmt.value),
            ast::Stmt::Assert(stmt) => {
                self.visit_expr(&stmt.test);
                if let Some(expr) = &stmt.msg {
                    self.visit_expr(expr);
                }
            }
            ast::Stmt::Delete(stmt) => {
                for expr in &stmt.targets {
                    self.visit_expr(expr);
                }
            }
            ast::Stmt::Raise(stmt) => {
                self.raise(
                    ExecutionEffectClass::UIImpact,
                    ExecutionSemanticClass::General,
                    EffectCertainty::Proven,
                    ExecutionReason::Static {
                        value: StaticExecutionReason::PythonRaiseDetected,
                    },
                );
                if let Some(expr) = &stmt.exc {
                    self.visit_expr(expr);
                }
                if let Some(expr) = &stmt.cause {
                    self.visit_expr(expr);
                }
            }
            _ => {}
        }
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        match expr {
            ast::Expr::Call(call) => {
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
                                    template:
                                        ExecutionReasonTemplate::UnclassifiedPythonCallDetected,
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
                self.visit_expr(&call.func);
                for arg in &call.args {
                    self.visit_expr(arg);
                }
                for keyword in &call.keywords {
                    self.visit_expr(&keyword.value);
                }
            }
            ast::Expr::BoolOp(expr) => {
                for value in &expr.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::NamedExpr(expr) => {
                self.visit_expr(&expr.target);
                self.visit_expr(&expr.value);
            }
            ast::Expr::BinOp(expr) => {
                self.visit_expr(&expr.left);
                self.visit_expr(&expr.right);
            }
            ast::Expr::UnaryOp(expr) => self.visit_expr(&expr.operand),
            ast::Expr::Lambda(expr) => self.visit_expr(&expr.body),
            ast::Expr::IfExp(expr) => {
                self.visit_expr(&expr.test);
                self.visit_expr(&expr.body);
                self.visit_expr(&expr.orelse);
            }
            ast::Expr::Dict(expr) => {
                for key in expr.keys.iter().flatten() {
                    self.visit_expr(key);
                }
                for value in &expr.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::Set(expr) => {
                for elt in &expr.elts {
                    self.visit_expr(elt);
                }
            }
            ast::Expr::ListComp(expr) => self.visit_expr(&expr.elt),
            ast::Expr::SetComp(expr) => self.visit_expr(&expr.elt),
            ast::Expr::DictComp(expr) => {
                self.visit_expr(&expr.key);
                self.visit_expr(&expr.value);
            }
            ast::Expr::GeneratorExp(expr) => self.visit_expr(&expr.elt),
            ast::Expr::Await(expr) => self.visit_expr(&expr.value),
            ast::Expr::Yield(expr) => {
                if let Some(value) = &expr.value {
                    self.visit_expr(value);
                }
            }
            ast::Expr::YieldFrom(expr) => self.visit_expr(&expr.value),
            ast::Expr::Compare(expr) => {
                self.visit_expr(&expr.left);
                for comparator in &expr.comparators {
                    self.visit_expr(comparator);
                }
            }
            ast::Expr::Attribute(expr) => self.visit_expr(&expr.value),
            ast::Expr::Subscript(expr) => {
                self.visit_expr(&expr.value);
                self.visit_expr(&expr.slice);
            }
            ast::Expr::Starred(expr) => self.visit_expr(&expr.value),
            ast::Expr::Slice(expr) => {
                if let Some(lower) = &expr.lower {
                    self.visit_expr(lower);
                }
                if let Some(upper) = &expr.upper {
                    self.visit_expr(upper);
                }
                if let Some(step) = &expr.step {
                    self.visit_expr(step);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.visit_expr(elt);
                }
            }
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.visit_expr(elt);
                }
            }
            _ => {}
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
