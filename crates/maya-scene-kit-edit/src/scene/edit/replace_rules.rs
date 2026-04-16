use super::*;

#[derive(Debug, Clone)]
pub(super) struct ResolvedPathOverride {
    pub(super) entry_index: usize,
    pub(super) entry: maya_scene_kit_observe::scene::paths::ScenePathEntry,
    pub(super) after_value: String,
}

pub(super) fn resolve_targeted_overrides(
    report: &ScenePathsReport,
    overrides: &[PathReplaceOverride],
) -> Result<Vec<ResolvedPathOverride>, SceneToolError> {
    let mut out = Vec::new();
    for override_item in overrides {
        let Some(entry) = report.entries.get(override_item.entry_index).cloned() else {
            return Err(SceneToolError::Message(format!(
                "path override entry_index out of range: {}",
                override_item.entry_index
            )));
        };
        if entry.value != override_item.before_value {
            return Err(SceneToolError::Message(format!(
                "path override before_value mismatch at entry {}",
                override_item.entry_index
            )));
        }
        if override_item.after_value == override_item.before_value {
            continue;
        }
        out.push(ResolvedPathOverride {
            entry_index: override_item.entry_index,
            entry,
            after_value: override_item.after_value.clone(),
        });
    }
    Ok(out)
}

pub(super) enum CompiledPreviewReplaceRule {
    Literal { from: String, to: String },
    Regex { to: String, regex: Regex },
}

pub(super) struct CompiledPreviewReplaceRules {
    rules: Vec<CompiledPreviewReplaceRule>,
}

impl CompiledPreviewReplaceRules {
    pub(super) fn compile(rules: &[PathReplaceRule]) -> Result<Self, SceneToolError> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            if rule.from.is_empty() {
                continue;
            }
            compiled.push(match rule.mode {
                PathReplaceMode::Literal => CompiledPreviewReplaceRule::Literal {
                    from: rule.from.clone(),
                    to: rule.to.clone(),
                },
                PathReplaceMode::Regex => {
                    let regex = Regex::new(&rule.from).map_err(|err| {
                        SceneToolError::Message(format!(
                            "invalid replace regex '{}': {err}",
                            rule.from
                        ))
                    })?;
                    CompiledPreviewReplaceRule::Regex {
                        to: rule.to.clone(),
                        regex,
                    }
                }
            });
        }
        Ok(Self { rules: compiled })
    }

    pub(super) fn apply(&self, input: &str) -> (String, usize) {
        let mut current = input.to_string();
        let mut total = 0usize;
        for rule in &self.rules {
            match rule {
                CompiledPreviewReplaceRule::Literal { from, to } => {
                    let count = current.matches(from).count();
                    if count == 0 {
                        continue;
                    }
                    current = current.replace(from, to);
                    total += count;
                }
                CompiledPreviewReplaceRule::Regex { regex, to, .. } => {
                    let count = regex.find_iter(&current).count();
                    if count == 0 {
                        continue;
                    }
                    current = regex.replace_all(&current, to.as_str()).into_owned();
                    total += count;
                }
            }
        }
        (current, total)
    }
}

pub(super) fn suggested_path_output(
    input_path: &Path,
    suffix: &str,
    extension: Option<&str>,
) -> PathBuf {
    let parent = input_path.parent().unwrap_or_else(|| Path::new(""));
    let stem = input_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("scene");
    let ext = extension
        .map(ToOwned::to_owned)
        .or_else(|| {
            input_path
                .extension()
                .and_then(|value| value.to_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    if ext.is_empty() {
        parent.join(format!("{stem}{suffix}"))
    } else {
        parent.join(format!("{stem}{suffix}.{ext}"))
    }
}
