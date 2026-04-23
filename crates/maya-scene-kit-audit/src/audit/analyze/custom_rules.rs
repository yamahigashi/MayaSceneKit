use super::{
    AnalysisSurface, CompiledRule,
    builders::{build_finding, severity_for_trigger, snippet},
};
use crate::scene::{AuditEvidence, AuditFinding, AuditSeverity, AuditSinkKind};

pub(super) fn findings_for_custom_rules(
    surface_index: usize,
    surface: &AnalysisSurface,
    rules: &[CompiledRule],
) -> Vec<AuditFinding> {
    let mut hits = Vec::new();
    for rule in rules {
        match rule {
            CompiledRule::Regex { raw, re } => {
                for m in re.find_iter(&surface.text) {
                    let preview = snippet(&surface.text[m.start()..m.end()]);
                    hits.push(build_finding(
                        surface_index,
                        surface,
                        "custom_rule_match",
                        severity_for_trigger(AuditSeverity::Low, surface.origin.trigger),
                        AuditSinkKind::None,
                        Some(raw.clone()),
                        "custom audit rule matched execution surface",
                        vec![AuditEvidence::FreeText {
                            value: preview.clone(),
                        }],
                        Some(preview),
                    ));
                }
            }
        }
    }
    hits
}
