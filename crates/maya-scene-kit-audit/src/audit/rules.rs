use regex::{Regex, RegexBuilder};

use crate::scene::SceneToolError;

#[derive(Debug, Clone)]
pub(crate) enum CompiledRule {
    Regex { raw: String, re: Regex },
}

#[derive(Debug, Clone)]
/// Compiled audit rules and rendering options used by `audit_script_nodes`.
pub struct ScriptAuditPlan {
    pub(crate) rules: Vec<CompiledRule>,
    pub(crate) effective_rules: Vec<String>,
    pub(crate) max_preview: usize,
}

impl ScriptAuditPlan {
    /// Returns the effective user-supplied inline literal rules.
    pub fn effective_rules(&self) -> &[String] {
        &self.effective_rules
    }
}

pub(crate) fn build_script_audit_plan(
    inline_rules: Vec<String>,
    max_preview: usize,
) -> Result<ScriptAuditPlan, SceneToolError> {
    let effective_rules = inline_rules
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let rules = compile_audit_rules(effective_rules.clone())?;
    Ok(ScriptAuditPlan {
        rules,
        effective_rules,
        max_preview,
    })
}

fn compile_audit_rules(raw_rules: Vec<String>) -> Result<Vec<CompiledRule>, SceneToolError> {
    raw_rules.into_iter().map(compile_audit_rule).collect()
}

fn compile_audit_rule(raw: String) -> Result<CompiledRule, SceneToolError> {
    let pattern = literal_rule_pattern(&raw);
    let re = build_regex(&pattern)
        .map_err(|err| SceneToolError::Config(format!("invalid rule '{raw}': {err}")))?;
    Ok(CompiledRule::Regex { raw, re })
}

fn build_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let mut builder = RegexBuilder::new(pattern);
    builder.dot_matches_new_line(true);
    builder.build()
}

fn literal_rule_pattern(raw: &str) -> String {
    let escaped = regex::escape(raw);
    let starts_word = raw
        .chars()
        .next()
        .map(|c| c.is_alphanumeric() || c == '_')
        .unwrap_or(false);
    let ends_word = raw
        .chars()
        .last()
        .map(|c| c.is_alphanumeric() || c == '_')
        .unwrap_or(false);
    format!(
        "{}{}{}",
        if starts_word { r"\b" } else { "" },
        escaped,
        if ends_word { r"\b" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::{build_script_audit_plan, compile_audit_rules};

    #[test]
    fn audit_rule_loader_keeps_empty_rule_set_without_defaults() {
        let plan = build_script_audit_plan(vec![], 0).expect("plan");
        assert!(plan.effective_rules.is_empty());
    }

    #[test]
    fn literal_audit_rules_compile_with_word_boundaries() {
        let rules = compile_audit_rules(vec!["exec".to_string()]).expect("compile rules");
        assert_eq!(rules.len(), 1);
    }
}
