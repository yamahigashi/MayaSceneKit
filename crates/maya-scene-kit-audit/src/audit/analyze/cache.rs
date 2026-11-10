use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use maya_scene_kit_observe::scene::evidence::ExecutionCoverageIssueDetail;

use super::{AnalysisSurface, SurfaceAnalysis, builders::preview_window};
use crate::scene::{AuditSurfaceDerivation, ExecutionCoverageIssue, ExecutionCoverageIssueKind};

const MAX_LITERAL_EVAL_DEPTH: usize = 8;
const MAX_DEPTH_LIMIT_ISSUES: usize = 100;

// Derived origins preserve the root's fields except language and source kind.
type OriginKey = (usize, &'static str, bool);
type BodyAnalyses = HashMap<Arc<str>, SurfaceAnalysis>;

#[derive(Default)]
pub(crate) struct DerivedAnalysisCache {
    entries: HashMap<OriginKey, HashMap<String, BodyAnalyses>>,
}

impl DerivedAnalysisCache {
    pub(crate) fn analyze(
        &mut self,
        surface_index: usize,
        surface: &AnalysisSurface,
        analyze: impl FnOnce(usize, &AnalysisSurface) -> SurfaceAnalysis,
    ) -> SurfaceAnalysis {
        if surface.derivation == AuditSurfaceDerivation::Observed {
            return analyze(surface_index, surface);
        }
        let origins = self
            .entries
            .entry((
                surface.root_index,
                surface.origin.lang.as_str(),
                surface.origin.source_kind.is_some(),
            ))
            .or_default();
        let source_kind = surface.origin.source_kind.as_deref().unwrap_or_default();
        let mut analysis = if let Some(bodies) = origins.get_mut(source_kind) {
            Self::analyze_body(bodies, surface, analyze)
        } else {
            let mut bodies = HashMap::new();
            let analysis = Self::analyze_body(&mut bodies, surface, analyze);
            origins.insert(source_kind.to_owned(), bodies);
            analysis
        };
        for finding in &mut analysis.findings {
            finding.surface_index = surface_index;
        }
        for signal in &mut analysis.review_signals {
            signal.surface_index = surface_index;
        }
        for derived in &mut analysis.derived_surfaces {
            derived.literal_eval_depth += surface.literal_eval_depth;
            derived.preview = preview_window(
                &derived.text,
                0,
                derived.text.len().min(24),
                surface.preview.len().max(16),
            );
        }
        analysis
    }

    fn analyze_body(
        bodies: &mut BodyAnalyses,
        surface: &AnalysisSurface,
        analyze: impl FnOnce(usize, &AnalysisSurface) -> SurfaceAnalysis,
    ) -> SurfaceAnalysis {
        if let Some(template) = bodies.get(surface.text.as_ref()) {
            return template.clone();
        }
        let mut relative = surface.clone();
        relative.literal_eval_depth = 0;
        let analysis = analyze(0, &relative);
        bodies.insert(Arc::clone(&surface.text), analysis.clone());
        analysis
    }
}

#[derive(Default)]
pub(crate) struct DepthLimitCoverage {
    positions: HashSet<(usize, Option<(usize, usize)>)>,
    suppressed: bool,
}

impl DepthLimitCoverage {
    pub(crate) fn retain(
        &mut self,
        surface_index: usize,
        surface: &AnalysisSurface,
        issues: &mut Vec<ExecutionCoverageIssue>,
    ) -> bool {
        if surface.literal_eval_depth <= MAX_LITERAL_EVAL_DEPTH {
            return true;
        }
        let position = (surface_index, surface.parent_position);
        if self.positions.contains(&position) {
            return false;
        }
        if self.positions.len() < MAX_DEPTH_LIMIT_ISSUES {
            self.positions.insert(position);
            let location = surface
                .parent_position
                .map_or_else(String::new, |(start, end)| {
                    format!(" at bytes {start}..{end}")
                });
            issues.push(ExecutionCoverageIssue {
                kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
                detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
                    diagnostic: format!("MEL literal evaluation depth exceeds {MAX_LITERAL_EVAL_DEPTH} on surface {surface_index}{location}; body was not analysed"),
                },
                origin: Some(surface.origin.clone()),
                preview: surface.preview.clone(),
            });
        } else if !self.suppressed {
            self.suppressed = true;
            issues.push(ExecutionCoverageIssue {
                kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
                detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
                    diagnostic: format!("Depth-limit issue cap {MAX_DEPTH_LIMIT_ISSUES} reached; further depth-limit issues were suppressed"),
                },
                origin: None,
                preview: String::new(),
            });
        }
        false
    }
}
