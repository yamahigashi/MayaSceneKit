use std::path::PathBuf;

use maya_scene_kit_observe::scene::execution::observe_source_text;

use super::{build_parse_budget_blocked_audit_report, build_script_audit_plan, evaluate_catalog};
use crate::scene::{
    AuditOptions, AuditReport, ExecutionLanguage, SceneFormat, SceneToolError, ValidationState,
};

/// Audits one source string without loading a scene or resolving external dependencies.
///
/// The report uses an empty scene path, Unknown scene format, and disabled scene digests.
/// Surface origins carry the supplied language and a manual invocation trigger.
/// Standalone input uses RawChunkText with standalone_source_text metadata and no chunk address.
/// Unknown language is a configuration error; source parse failures remain blocked reports.
pub fn audit_source_text(
    source: &str,
    language: ExecutionLanguage,
) -> Result<AuditReport, SceneToolError> {
    let plan = build_script_audit_plan(Vec::new(), 96)?;
    let options = AuditOptions::strict_default();
    let catalog = match observe_source_text(source, language) {
        Ok(catalog) => catalog,
        Err(SceneToolError::MelParseBudgetExceeded { limit }) => {
            return Ok(build_parse_budget_blocked_audit_report(
                PathBuf::new(),
                SceneFormat::Unknown,
                ValidationState::Invalid,
                &plan,
                options,
                limit,
                None,
            ));
        }
        Err(SceneToolError::PythonParseBudgetExceeded { limit }) => {
            return Ok(build_parse_budget_blocked_audit_report(
                PathBuf::new(),
                SceneFormat::Unknown,
                ValidationState::Invalid,
                &plan,
                options,
                limit,
                None,
            ));
        }
        Err(err) => return Err(err),
    };
    let validation_state = if catalog.coverage_issues.is_empty() {
        ValidationState::Validated
    } else {
        ValidationState::Invalid
    };
    Ok(evaluate_catalog(
        catalog,
        PathBuf::new(),
        SceneFormat::Unknown,
        validation_state,
        &plan,
        options,
        false,
    ))
}
