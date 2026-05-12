mod analyze;
mod lower_python;
mod policy;
mod rules;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Display,
    path::{Path, PathBuf},
    sync::Arc,
};

use maya_scene_kit_observe::scene::{
    SceneFileIdentity, ScenePathResolutionContext, SceneResourceResolver, detect_scene_format,
    paths::{PathKind, ScenePathResolutionStatus},
};

pub use self::rules::ScriptAuditPlan;
use crate::scene::{
    AuditDisposition, AuditEvidence, AuditFinding, AuditFindingCode, AuditFindingDetail,
    AuditGraphReport, AuditGraphRoot, AuditNotice, AuditOptions, AuditProfile, AuditReferenceEdge,
    AuditReport, AuditSeverity, AuditSinkKind, AuditTraversalIssue, AuditTraversalIssueKind,
    DependencyFact, DependencyRiskClass, EffectCertainty, ExecutionCoverageState,
    ExecutionEffectClass, ExecutionLanguage, ExecutionObservationBundle, ExecutionSemanticClass,
    ExecutionUnitSummary, LoadOptions, Loader, ObservationBundle, SceneDigestSet, SceneFormat,
    SceneToolError, StaticAuditFindingDetail, ValidationState, execution::ObservedExecutionCatalog,
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
    audit_observation_source_with_digests(observation, plan, options, include_digests)
}

fn audit_execution_observation_with_digests(
    observation: &ExecutionObservationBundle,
    plan: &ScriptAuditPlan,
    options: AuditOptions,
    include_digests: bool,
) -> Result<AuditReport, SceneToolError> {
    audit_observation_source_with_digests(observation, plan, options, include_digests)
}

trait AuditObservationSource {
    fn scene_path(&self) -> &Path;
    fn scene_format(&self) -> SceneFormat;
    fn validation_state(&self) -> ValidationState;
    fn scene_digests(&self, max_preview: usize) -> Result<SceneDigestSet, SceneToolError>;
    fn observed_execution_catalog_with_digests(
        &self,
        max_preview: usize,
        include_digests: bool,
    ) -> Result<ObservedExecutionCatalog, SceneToolError>;
}

impl AuditObservationSource for ObservationBundle {
    fn scene_path(&self) -> &Path {
        self.scene_path()
    }

    fn scene_format(&self) -> SceneFormat {
        self.scene_format()
    }

    fn validation_state(&self) -> ValidationState {
        self.validation_state()
    }

    fn scene_digests(&self, max_preview: usize) -> Result<SceneDigestSet, SceneToolError> {
        self.scene_digests(max_preview)
    }

    fn observed_execution_catalog_with_digests(
        &self,
        max_preview: usize,
        include_digests: bool,
    ) -> Result<ObservedExecutionCatalog, SceneToolError> {
        self.observed_execution_catalog_with_digests(max_preview, include_digests)
    }
}

impl AuditObservationSource for ExecutionObservationBundle {
    fn scene_path(&self) -> &Path {
        self.scene_path()
    }

    fn scene_format(&self) -> SceneFormat {
        self.scene_format()
    }

    fn validation_state(&self) -> ValidationState {
        self.validation_state()
    }

    fn scene_digests(&self, max_preview: usize) -> Result<SceneDigestSet, SceneToolError> {
        self.scene_digests(max_preview)
    }

    fn observed_execution_catalog_with_digests(
        &self,
        max_preview: usize,
        include_digests: bool,
    ) -> Result<ObservedExecutionCatalog, SceneToolError> {
        self.observed_execution_catalog_with_digests(max_preview, include_digests)
    }
}

fn audit_observation_source_with_digests(
    observation: &impl AuditObservationSource,
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
                ValidationState::Invalid,
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
    let observation = match loader.observe_execution_path(path) {
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
    audit_execution_observation_with_digests(&observation, plan, options, include_digests)
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

const DEFAULT_REFERENCE_GRAPH_MAX_DEPTH: usize = 64;
const DEFAULT_REFERENCE_GRAPH_MAX_SCENES: usize = 4096;

pub fn audit_reference_graph_roots_with_options_and_digests<I, P>(
    roots: I,
    plan: &ScriptAuditPlan,
    load_options: &LoadOptions,
    options: AuditOptions,
    include_digests: bool,
) -> AuditGraphReport
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    ReferenceAuditRun::new(plan, load_options, options, include_digests).run(roots)
}

struct ReferenceAuditRun<'a> {
    plan: &'a ScriptAuditPlan,
    load_options: &'a LoadOptions,
    options: AuditOptions,
    include_digests: bool,
    resolver: SceneResourceResolver,
    roots: Vec<AuditGraphRoot>,
    reports: Vec<AuditReport>,
    report_by_identity: HashMap<String, usize>,
    failed_by_identity: HashMap<String, usize>,
    queued: HashSet<String>,
    visited: HashSet<String>,
    queue: VecDeque<ReferenceQueueEntry>,
    edges: Vec<AuditReferenceEdge>,
    traversal_issues: Vec<AuditTraversalIssue>,
    disposition: AuditDisposition,
}

struct ReferenceQueueEntry {
    path: PathBuf,
    identity: SceneFileIdentity,
    depth: usize,
    ancestors: Vec<String>,
}

impl<'a> ReferenceAuditRun<'a> {
    fn new(
        plan: &'a ScriptAuditPlan,
        load_options: &'a LoadOptions,
        options: AuditOptions,
        include_digests: bool,
    ) -> Self {
        Self {
            plan,
            load_options,
            options,
            include_digests,
            resolver: SceneResourceResolver::new(),
            roots: Vec::new(),
            reports: Vec::new(),
            report_by_identity: HashMap::new(),
            failed_by_identity: HashMap::new(),
            queued: HashSet::new(),
            visited: HashSet::new(),
            queue: VecDeque::new(),
            edges: Vec::new(),
            traversal_issues: Vec::new(),
            disposition: AuditDisposition::Allow,
        }
    }

    fn run<I, P>(mut self, roots: I) -> AuditGraphReport
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        for root in roots {
            self.enqueue_root(root.as_ref());
        }
        while let Some(entry) = self.queue.pop_front() {
            self.audit_queue_entry(entry);
        }
        self.finalize_graph_indexes();
        AuditGraphReport {
            roots: self.roots,
            reports: self.reports,
            edges: self.edges,
            traversal_issues: self.traversal_issues,
            disposition: self.disposition,
        }
    }

    fn enqueue_root(&mut self, path: &Path) {
        let identity = self.resolver.scene_file_identity(path);
        self.roots.push(AuditGraphRoot {
            path: path.to_path_buf(),
            identity: Some(identity.key.clone()),
            report_index: None,
            issue_index: None,
        });
        if self.queued.insert(identity.key.clone()) {
            self.queue.push_back(ReferenceQueueEntry {
                path: path.to_path_buf(),
                identity,
                depth: 0,
                ancestors: Vec::new(),
            });
        }
    }

    fn audit_queue_entry(&mut self, entry: ReferenceQueueEntry) {
        if self.visited.contains(&entry.identity.key) {
            return;
        }
        self.visited.insert(entry.identity.key.clone());
        match self.audit_graph_scene(&entry.path) {
            Ok((report, reference_targets)) => self.record_report(entry, report, reference_targets),
            Err(err) => {
                let issue_index = self.push_issue(AuditTraversalIssue {
                    kind: AuditTraversalIssueKind::LoadFailed,
                    scene_path: Some(entry.path),
                    source_path: None,
                    raw_target: None,
                    message: err.to_string(),
                });
                self.failed_by_identity
                    .insert(entry.identity.key.clone(), issue_index);
            }
        }
    }

    fn audit_graph_scene(&self, path: &Path) -> Result<(AuditReport, Vec<String>), SceneToolError> {
        let loader = Loader::new(self.load_options.clone());
        let observation = match loader.observe_audit_path(path) {
            Ok(observation) => observation,
            Err(SceneToolError::MelParseBudgetExceeded { limit }) => {
                let scene_format = detect_scene_format(path)?;
                return Ok((
                    build_parse_budget_blocked_audit_report(
                        path.to_path_buf(),
                        scene_format,
                        ValidationState::Invalid,
                        self.plan,
                        self.options,
                        limit,
                        None,
                    ),
                    Vec::new(),
                ));
            }
            Err(SceneToolError::MbParseBudgetExceeded { limit }) => {
                let scene_format = detect_scene_format(path)?;
                return Ok((
                    build_parse_budget_blocked_audit_report(
                        path.to_path_buf(),
                        scene_format,
                        ValidationState::Invalid,
                        self.plan,
                        self.options,
                        limit,
                        None,
                    ),
                    Vec::new(),
                ));
            }
            Err(err) => return Err(err),
        };
        let reference_targets = observation
            .scene_paths(PathKind::Reference)?
            .into_iter()
            .map(|entry| entry.value)
            .collect::<Vec<_>>();
        let report = audit_observation_with_digests(
            &observation,
            self.plan,
            self.options,
            self.include_digests,
        )?;
        Ok((report, reference_targets))
    }

    fn record_report(
        &mut self,
        entry: ReferenceQueueEntry,
        report: AuditReport,
        reference_targets: Vec<String>,
    ) {
        let report_index = self.reports.len();
        self.disposition = max_disposition(self.disposition, report.disposition);
        self.report_by_identity
            .insert(entry.identity.key.clone(), report_index);

        let source_path = report.scene_path.clone();
        let mut next_ancestors = entry.ancestors.clone();
        next_ancestors.push(entry.identity.key.clone());
        self.reports.push(report);

        for raw_target in reference_targets {
            self.record_reference_edge(
                &entry.identity,
                &source_path,
                &raw_target,
                entry.depth,
                &next_ancestors,
            );
        }
    }

    fn record_reference_edge(
        &mut self,
        source_identity: &SceneFileIdentity,
        source_path: &Path,
        raw_target: &str,
        source_depth: usize,
        next_ancestors: &[String],
    ) {
        let workspace_root = self.resolver.find_scene_workspace_root(source_path);
        let resolution_context =
            ScenePathResolutionContext::for_scene(source_path, workspace_root.as_ref());
        let resolution = self
            .resolver
            .resolve_scene_path_value(raw_target, &resolution_context);
        let mut edge = AuditReferenceEdge {
            source_identity: source_identity.key.clone(),
            source_path: source_path.to_path_buf(),
            raw_target: raw_target.to_string(),
            resolved_path: resolution.resolved_path.clone(),
            resolution_status: resolution.status,
            target_identity: None,
            target_report_index: None,
            issue_index: None,
        };

        match (resolution.status, resolution.resolved_path.as_deref()) {
            (ScenePathResolutionStatus::Exists, Some(child_path)) => {
                let child_identity = self.resolver.scene_file_identity(child_path);
                edge.target_identity = Some(child_identity.key.clone());
                if next_ancestors
                    .iter()
                    .any(|ancestor| ancestor == &child_identity.key)
                {
                    edge.issue_index = Some(self.push_issue(AuditTraversalIssue {
                        kind: AuditTraversalIssueKind::Cycle,
                        scene_path: Some(child_path.to_path_buf()),
                        source_path: Some(source_path.to_path_buf()),
                        raw_target: Some(raw_target.to_string()),
                        message: "reference cycle detected".to_string(),
                    }));
                } else if source_depth + 1 > DEFAULT_REFERENCE_GRAPH_MAX_DEPTH {
                    edge.issue_index = Some(self.push_issue(AuditTraversalIssue {
                        kind: AuditTraversalIssueKind::DepthLimit,
                        scene_path: Some(child_path.to_path_buf()),
                        source_path: Some(source_path.to_path_buf()),
                        raw_target: Some(raw_target.to_string()),
                        message: format!(
                            "reference graph depth limit exceeded: {}",
                            DEFAULT_REFERENCE_GRAPH_MAX_DEPTH
                        ),
                    }));
                } else if !self.visited.contains(&child_identity.key)
                    && !self.queued.contains(&child_identity.key)
                {
                    if self.visited.len() + self.queued.len() >= DEFAULT_REFERENCE_GRAPH_MAX_SCENES
                    {
                        edge.issue_index = Some(self.push_issue(AuditTraversalIssue {
                            kind: AuditTraversalIssueKind::SceneLimit,
                            scene_path: Some(child_path.to_path_buf()),
                            source_path: Some(source_path.to_path_buf()),
                            raw_target: Some(raw_target.to_string()),
                            message: format!(
                                "reference graph scene limit exceeded: {}",
                                DEFAULT_REFERENCE_GRAPH_MAX_SCENES
                            ),
                        }));
                    } else {
                        self.queued.insert(child_identity.key.clone());
                        self.queue.push_back(ReferenceQueueEntry {
                            path: child_path.to_path_buf(),
                            identity: child_identity,
                            depth: source_depth + 1,
                            ancestors: next_ancestors.to_vec(),
                        });
                    }
                }
            }
            (ScenePathResolutionStatus::Missing, _) => {
                edge.issue_index = Some(self.push_issue(AuditTraversalIssue {
                    kind: AuditTraversalIssueKind::MissingReference,
                    scene_path: resolution.resolved_path.clone(),
                    source_path: Some(source_path.to_path_buf()),
                    raw_target: Some(raw_target.to_string()),
                    message: "reference target is missing".to_string(),
                }));
            }
            (ScenePathResolutionStatus::Unresolved, _) => {
                edge.issue_index = Some(self.push_issue(AuditTraversalIssue {
                    kind: AuditTraversalIssueKind::UnresolvedReference,
                    scene_path: None,
                    source_path: Some(source_path.to_path_buf()),
                    raw_target: Some(raw_target.to_string()),
                    message: "reference target could not be resolved".to_string(),
                }));
            }
            (ScenePathResolutionStatus::Exists, None) => {}
        }

        self.edges.push(edge);
    }

    fn push_issue(&mut self, issue: AuditTraversalIssue) -> usize {
        let issue_index = self.traversal_issues.len();
        self.traversal_issues.push(issue);
        self.disposition = max_disposition(self.disposition, AuditDisposition::Review);
        issue_index
    }

    fn finalize_graph_indexes(&mut self) {
        for root in &mut self.roots {
            let Some(identity) = root.identity.as_deref() else {
                continue;
            };
            root.report_index = self.report_by_identity.get(identity).copied();
            root.issue_index = self.failed_by_identity.get(identity).copied();
        }
        for edge in &mut self.edges {
            let Some(identity) = edge.target_identity.as_deref() else {
                continue;
            };
            edge.target_report_index = self.report_by_identity.get(identity).copied();
            if edge.issue_index.is_none() {
                edge.issue_index = self.failed_by_identity.get(identity).copied();
            }
        }
    }
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
            evidence: surface
                .origin
                .node_name
                .as_ref()
                .map(|node_name| {
                    vec![
                        AuditEvidence::KeyValue {
                            key: crate::scene::AuditEvidenceKey::NodeName,
                            value: node_name.clone(),
                        },
                        AuditEvidence::FreeText {
                            value: surface.origin.source_kind.clone().unwrap_or_default(),
                        },
                    ]
                })
                .unwrap_or_else(|| {
                    vec![AuditEvidence::FreeText {
                        value: surface.origin.source_kind.clone().unwrap_or_default(),
                    }]
                }),
            preview_override: None,
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
            evidence: surface
                .origin
                .node_name
                .as_ref()
                .map(|node_name| {
                    vec![
                        AuditEvidence::KeyValue {
                            key: crate::scene::AuditEvidenceKey::NodeName,
                            value: node_name.clone(),
                        },
                        AuditEvidence::FreeText {
                            value: surface.origin.source_kind.clone().unwrap_or_default(),
                        },
                    ]
                })
                .unwrap_or_else(|| {
                    vec![AuditEvidence::FreeText {
                        value: surface.origin.source_kind.clone().unwrap_or_default(),
                    }]
                }),
            preview_override: None,
        });
    }
    findings
}
