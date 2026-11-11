pub(crate) mod catalog;
pub(crate) mod dependency;
mod effect_registry;
mod mel_surface;
mod python_source;
pub mod python_walk;
pub(crate) mod surfaces;

use std::sync::Arc;

pub use self::{
    catalog::observe_source_text,
    mel_surface::{
        MelCodeLikeValueFact, MelResolvedStringKind, MelSinkArgFact, MelSinkArgKind,
        MelStringAssemblyMarker, MelSurfaceCall, MelSurfaceCallSurfaceKind, MelSurfaceCommandMode,
        MelSurfaceDiagnostic, MelSurfaceDiagnosticStage, MelSurfaceFacts, MelSurfaceNormalizedArg,
        MelSurfaceNormalizedCommand, MelSurfaceNormalizedFlag, MelSurfaceNormalizedItem,
        MelSurfaceValidationDiagnostic, collect_mel_surface_facts,
        collect_mel_surface_facts_shared,
    },
    python_source::{
        PythonParseBudgetLimit, check_python_parse_budget,
        check_python_parse_budget_with_max_bytes, normalize_python_compat_source,
        with_python_analysis,
    },
    surfaces::ExecutionSurface,
};
use crate::scene::{
    DependencyFact, ExecutionCoverageIssue, ExecutionCoverageState, ExecutionUnitSummary,
    SceneDigestSet, UnknownSemanticFact,
};

#[derive(Debug, Clone)]
pub struct ObservedExecutionSurface {
    /// The budget that prevented Python analysis of this retained surface.
    pub python_parse_budget_limit: Option<PythonParseBudgetLimit>,
    pub surface: ExecutionSurface,
    pub mel: Option<Arc<MelSurfaceFacts>>,
}

#[derive(Debug, Clone)]
pub struct ObservedExecutionCatalog {
    /// The observation byte limit, also applied to Python bodies derived during audit.
    pub python_max_body_bytes: usize,
    pub surfaces: Vec<ObservedExecutionSurface>,
    pub unit_summaries: Vec<ExecutionUnitSummary>,
    pub dependency_facts: Vec<DependencyFact>,
    pub unknown_semantics: Vec<UnknownSemanticFact>,
    pub digests: SceneDigestSet,
    pub coverage_state: ExecutionCoverageState,
    pub coverage_issues: Vec<ExecutionCoverageIssue>,
}
