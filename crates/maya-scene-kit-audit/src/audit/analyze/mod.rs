use std::{collections::HashMap, sync::Arc};

use super::rules::CompiledRule;
use crate::scene::{AuditFinding, execution::MelSurfaceFacts};

mod builders;
mod callback_flags;
mod custom_rules;
mod mel;
mod python;
mod surface;
mod text_scan;

pub(crate) use self::surface::AnalysisSurface;
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
    analyze_mel_surface_impl(surface_index, surface, mel_surface_facts_cache)
}

pub(crate) fn analyze_python_surface(
    surface_index: usize,
    surface: &AnalysisSurface,
) -> SurfaceAnalysis {
    analyze_python_surface_impl(surface_index, surface)
}

#[cfg(test)]
mod tests;
