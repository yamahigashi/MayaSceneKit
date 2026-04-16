use std::sync::Arc;

use crate::scene::{
    AuditFinding, AuditReviewSignal, AuditSurface, AuditSurfaceDerivation, ExecutionOrigin,
    execution::{MelSurfaceFacts, ObservedExecutionSurface},
};

#[derive(Debug, Clone)]
pub(crate) struct AnalysisSurface {
    pub(crate) text: Arc<str>,
    pub(crate) preview: String,
    pub(crate) origin: ExecutionOrigin,
    pub(crate) derivation: AuditSurfaceDerivation,
    pub(crate) mel: Option<Arc<MelSurfaceFacts>>,
}

#[derive(Debug, Default)]
pub(crate) struct SurfaceAnalysis {
    pub(crate) findings: Vec<AuditFinding>,
    pub(crate) review_signals: Vec<AuditReviewSignal>,
    pub(crate) derived_surfaces: Vec<AnalysisSurface>,
}

impl AnalysisSurface {
    pub(crate) fn observed(surface: ObservedExecutionSurface) -> Self {
        Self {
            text: surface.surface.text,
            preview: surface.surface.preview,
            origin: surface.surface.origin,
            derivation: AuditSurfaceDerivation::Observed,
            mel: surface.mel,
        }
    }

    pub(crate) fn into_public(self) -> AuditSurface {
        AuditSurface {
            origin: self.origin,
            preview: self.preview,
            derivation: self.derivation,
        }
    }

    pub(crate) fn discard_analysis_state(&mut self) {
        self.text = Arc::<str>::from("");
        self.mel = None;
    }
}
