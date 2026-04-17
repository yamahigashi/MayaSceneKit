use std::borrow::Cow;

use regex::Regex;

use crate::{PathReplaceMode, PathReplaceRule};

pub(crate) enum CompiledPathReplaceRule {
    Literal { from: String, to: String },
    Regex { regex: Regex, to: String },
}

pub(crate) struct CompiledPathReplaceRules {
    rules: Vec<CompiledPathReplaceRule>,
}

impl CompiledPathReplaceRules {
    pub(crate) fn compile_lossy(rules: &[PathReplaceRule]) -> Self {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            if rule.from.is_empty() {
                continue;
            }
            match rule.mode {
                PathReplaceMode::Literal => compiled.push(CompiledPathReplaceRule::Literal {
                    from: rule.from.clone(),
                    to: rule.to.clone(),
                }),
                PathReplaceMode::Regex => {
                    let Ok(regex) = Regex::new(&rule.from) else {
                        continue;
                    };
                    compiled.push(CompiledPathReplaceRule::Regex {
                        regex,
                        to: rule.to.clone(),
                    });
                }
            }
        }
        Self { rules: compiled }
    }

    pub(crate) fn apply<'a>(&self, input: &'a str) -> (Cow<'a, str>, usize) {
        let mut current = Cow::Borrowed(input);
        let mut total = 0usize;
        for rule in &self.rules {
            match rule {
                CompiledPathReplaceRule::Literal { from, to } => {
                    let count = current.matches(from).count();
                    if count == 0 {
                        continue;
                    }
                    current = Cow::Owned(current.replace(from, to));
                    total += count;
                }
                CompiledPathReplaceRule::Regex { regex, to } => {
                    let count = regex.find_iter(&current).count();
                    if count == 0 {
                        continue;
                    }
                    current = Cow::Owned(regex.replace_all(&current, to.as_str()).into_owned());
                    total += count;
                }
            }
        }
        (current, total)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::CompiledPathReplaceRules;
    use crate::{PathReplaceMode, PathReplaceRule};

    #[test]
    fn compiled_replace_rules_preserve_rule_order() {
        let rules = vec![
            PathReplaceRule {
                from: "old".to_string(),
                to: "mid".to_string(),
                mode: PathReplaceMode::Literal,
            },
            PathReplaceRule {
                from: "mid/(.+)".to_string(),
                to: "new/$1".to_string(),
                mode: PathReplaceMode::Regex,
            },
        ];

        let compiled = CompiledPathReplaceRules::compile_lossy(&rules);
        let (rewritten, count) = compiled.apply("old/path.mb");
        assert_eq!(rewritten, "new/path.mb");
        assert_eq!(count, 2);
    }

    #[test]
    fn compiled_replace_rules_ignore_invalid_regexes() {
        let rules = vec![
            PathReplaceRule {
                from: "(".to_string(),
                to: "ignored".to_string(),
                mode: PathReplaceMode::Regex,
            },
            PathReplaceRule {
                from: "old".to_string(),
                to: "new".to_string(),
                mode: PathReplaceMode::Literal,
            },
        ];

        let compiled = CompiledPathReplaceRules::compile_lossy(&rules);
        let (rewritten, count) = compiled.apply("old/path.mb");
        assert_eq!(rewritten, "new/path.mb");
        assert_eq!(count, 1);
    }
}
