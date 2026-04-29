pub(crate) mod catalog;
pub(crate) mod dependency;
mod effect_registry;
mod mel_surface;
mod python_source;
pub(crate) mod surfaces;

use std::sync::Arc;

pub use self::{
    mel_surface::{
        MelCodeLikeValueFact, MelResolvedStringKind, MelSinkArgFact, MelSinkArgKind,
        MelStringAssemblyMarker, MelSurfaceCall, MelSurfaceCallSurfaceKind, MelSurfaceCommandMode,
        MelSurfaceDiagnostic, MelSurfaceDiagnosticStage, MelSurfaceFacts, MelSurfaceNormalizedArg,
        MelSurfaceNormalizedCommand, MelSurfaceNormalizedFlag, MelSurfaceNormalizedItem,
        MelSurfaceValidationDiagnostic, collect_mel_surface_facts,
        collect_mel_surface_facts_shared,
    },
    python_source::normalize_python_compat_source,
    surfaces::ExecutionSurface,
};
use crate::scene::{
    DependencyFact, ExecutionCoverageIssue, ExecutionCoverageState, ExecutionUnitSummary,
    SceneDigestSet, UnknownSemanticFact,
};

#[derive(Debug, Clone)]
pub struct ObservedExecutionSurface {
    pub surface: ExecutionSurface,
    pub mel: Option<Arc<MelSurfaceFacts>>,
}

#[derive(Debug, Clone)]
pub struct ObservedExecutionCatalog {
    pub surfaces: Vec<ObservedExecutionSurface>,
    pub unit_summaries: Vec<ExecutionUnitSummary>,
    pub dependency_facts: Vec<DependencyFact>,
    pub unknown_semantics: Vec<UnknownSemanticFact>,
    pub digests: SceneDigestSet,
    pub coverage_state: ExecutionCoverageState,
    pub coverage_issues: Vec<ExecutionCoverageIssue>,
}
