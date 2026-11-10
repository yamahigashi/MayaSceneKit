use std::{collections::HashMap, sync::Arc};

use super::rules::CompiledRule;
use crate::scene::{AuditFinding, execution::MelSurfaceFacts};

mod builders;
mod cache;
mod callback_flags;
mod custom_rules;
mod mel;
mod python;
mod surface;
mod text_scan;

pub(crate) use self::{
    cache::{DepthLimitCoverage, DerivedAnalysisCache},
    surface::AnalysisSurface,
    text_scan::scan_hard_python_obfuscation_markers,
};
use self::{
    mel::analyze_mel_surface_impl, python::analyze_python_surface_impl, surface::SurfaceAnalysis,
};

pub(crate) fn findings_for_custom_rules(
    surface_index: usize,
    surface: &AnalysisSurface,
    rules: &[CompiledRule],
) -> Vec<AuditFinding> {
    custom_rules::findings_for_custom_rules(surface_index, surface, rules)
}

pub(crate) fn analyze_mel_surface(
    surface_index: usize,
    surface: &AnalysisSurface,
    mel_surface_facts_cache: &mut HashMap<Arc<str>, Arc<MelSurfaceFacts>>,
) -> SurfaceAnalysis {
    if surface.mel.is_none()
        && surface.derivation != crate::scene::AuditSurfaceDerivation::Observed
        && surface.origin.lang == crate::scene::ExecutionLanguage::Mel
    {
        let mut prepared = surface.clone();
        prepared.mel = Some(callback_flags::collect_cached_mel_surface_facts(
            mel_surface_facts_cache,
            &surface.text,
        ));
        analyze_mel_surface_impl(surface_index, &prepared, mel_surface_facts_cache)
    } else {
        analyze_mel_surface_impl(surface_index, surface, mel_surface_facts_cache)
    }
}

pub(crate) fn analyze_python_surface(
    surface_index: usize,
    surface: &AnalysisSurface,
) -> SurfaceAnalysis {
    analyze_python_surface_impl(surface_index, surface)
}

#[cfg(test)]
mod tests;
