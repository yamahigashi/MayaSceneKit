pub mod audit;
pub mod persistent_cache;
mod public;

pub mod scene {
    #[allow(unused_imports)]
    pub(crate) use maya_scene_kit_observe::scene::core::{SceneFormat, ValidationState};
    pub use maya_scene_kit_observe::scene::evidence::ExecutionLanguage;
    #[allow(unused_imports)]
    pub(crate) use maya_scene_kit_observe::scene::evidence::{
        DependencyFact, DependencyFactKind, DependencyRiskClass, EffectCertainty,
        ExecutionCoverageIssue, ExecutionCoverageIssueKind, ExecutionCoverageState,
        ExecutionEffectClass, ExecutionOrigin, ExecutionSemanticClass, ExecutionSurfaceKind,
        ExecutionTrigger, ExecutionUnitSummary, SceneDigestSet, UnknownSemanticFact,
    };
    #[allow(unused_imports)]
    pub(crate) use maya_scene_kit_observe::scene::{
        ExecutionObservationBundle, LoadOptions, Loader, ObservationBundle, SceneToolError,
    };

    pub use crate::{
        audit::audit_source_text,
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
            AuditTraversalIssueKind, DEFAULT_REFERENCE_GRAPH_MAX_DEPTH,
            DEFAULT_REFERENCE_GRAPH_MAX_SCENES, ReferenceGraphOptions, ScriptAuditReport,
            StaticAuditFindingDetail, StaticAuditReviewDetail,
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
