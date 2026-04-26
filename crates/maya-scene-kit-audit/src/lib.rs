pub mod audit;
pub mod persistent_cache;
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
        ExecutionObservationBundle, LoadOptions, Loader, ObservationBundle, SceneToolError,
    };

    pub use crate::{
        persistent_cache::{
            AuditCacheAccess, AuditCacheHit, AuditCacheIdentity, AuditCacheMaintenanceStats,
            AuditCacheStore, AuditedSceneSnapshot, fingerprint_audit_plan,
        },
        public::audit::{
            AnalysisBudgets, AuditDisposition, AuditEvidence, AuditEvidenceKey, AuditFinding,
            AuditFindingCode, AuditFindingDetail, AuditGraphReport, AuditGraphRoot, AuditHit,
            AuditNotice, AuditNoticeCode, AuditOptions, AuditProfile, AuditReferenceEdge,
            AuditReport, AuditReviewCode, AuditReviewDetail, AuditReviewSignal, AuditSeverity,
            AuditSinkKind, AuditSurface, AuditSurfaceDerivation, AuditTraversalIssue,
            AuditTraversalIssueKind, ScriptAuditReport, StaticAuditFindingDetail,
            StaticAuditReviewDetail,
        },
    };

    pub(crate) mod execution {
        #[allow(unused_imports)]
        pub use maya_scene_kit_observe::scene::execution::{
            ExecutionSurface, MelSurfaceCall, MelSurfaceCallSurfaceKind, MelSurfaceFacts,
            ObservedExecutionCatalog, ObservedExecutionSurface,
        };
    }
}
