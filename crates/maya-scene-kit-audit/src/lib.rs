pub mod audit;
mod public;

pub mod scene {
    #[allow(unused_imports)]
    pub(crate) use maya_scene_kit_observe::scene::core::{SceneFormat, ValidationState};
    #[allow(unused_imports)]
    pub(crate) use maya_scene_kit_observe::scene::evidence::{
        DependencyFact, DependencyFactKind, DependencyRiskClass, EffectCertainty,
        ExecutionCoverageIssue, ExecutionCoverageIssueKind, ExecutionCoverageState,
        ExecutionEffectClass, ExecutionLanguage, ExecutionOrigin, ExecutionSemanticClass,
        ExecutionSurfaceKind, ExecutionTrigger, ExecutionUnitSummary, SceneDigestSet,
        UnknownSemanticFact,
    };
    #[allow(unused_imports)]
    pub(crate) use maya_scene_kit_observe::scene::{
        LoadOptions, Loader, ObservationBundle, SceneToolError,
    };

    pub use crate::public::audit::{
        AnalysisBudgets, AuditDisposition, AuditEvidence, AuditEvidenceKey, AuditFinding,
        AuditFindingCode, AuditFindingDetail, AuditHit, AuditNotice, AuditNoticeCode, AuditOptions,
        AuditProfile, AuditReport, AuditReviewCode, AuditReviewDetail, AuditReviewSignal,
        AuditSeverity, AuditSinkKind, AuditSurface, AuditSurfaceDerivation, ScriptAuditReport,
        StaticAuditFindingDetail, StaticAuditReviewDetail,
    };

    pub(crate) mod execution {
        #[allow(unused_imports)]
        pub use maya_scene_kit_observe::scene::execution::{
            ExecutionSurface, MelSurfaceCall, MelSurfaceCallSurfaceKind, MelSurfaceFacts,
            ObservedExecutionCatalog, ObservedExecutionSurface,
        };
    }
}
