use std::{borrow::Cow, collections::HashMap, sync::Arc};

use maya_scene_kit_formats::mel::{self, MelParseBudget};

#[derive(Debug, Clone)]
pub struct MelSurfaceFacts {
    pub source_text: Arc<str>,
    pub diagnostics: Vec<MelSurfaceDiagnostic>,
    pub validation_diagnostics: Vec<MelSurfaceValidationDiagnostic>,
    pub calls: Vec<MelSurfaceCall>,
    pub normalized_commands: Vec<MelSurfaceNormalizedCommand>,
}

pub fn collect_mel_surface_facts(source: &str) -> MelSurfaceFacts {
    collect_mel_surface_facts_with_budget(source, &MelParseBudget::default())
}

pub fn collect_mel_surface_facts_with_budget(
    source: &str,
    budget: &MelParseBudget,
) -> MelSurfaceFacts {
    map_mel_surface_facts(mel::collect_call_facts_with_budget(source, budget))
}

pub fn collect_mel_surface_facts_shared(source: Arc<str>) -> MelSurfaceFacts {
    collect_mel_surface_facts_shared_with_budget(source, &MelParseBudget::default())
}

pub fn collect_mel_surface_facts_shared_with_budget(
    source: Arc<str>,
    budget: &MelParseBudget,
) -> MelSurfaceFacts {
    map_mel_surface_facts(mel::collect_call_facts_shared_with_budget(source, budget))
}

pub(crate) fn collect_cached_mel_surface_facts(
    cache: &mut HashMap<Arc<str>, Arc<MelSurfaceFacts>>,
    source: &Arc<str>,
    budget: &MelParseBudget,
) -> Arc<MelSurfaceFacts> {
    if let Some(facts) = cache.get(source.as_ref()) {
        return Arc::clone(facts);
    }

    let facts = Arc::new(collect_mel_surface_facts_shared_with_budget(
        Arc::clone(source),
        budget,
    ));
    cache.insert(Arc::clone(source), Arc::clone(&facts));
    facts
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelSurfaceDiagnosticStage {
    Decode,
    Lex,
    Parse,
}

#[derive(Debug, Clone)]
pub struct MelSurfaceDiagnostic {
    pub stage: MelSurfaceDiagnosticStage,
    pub message: Cow<'static, str>,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone)]
pub struct MelSurfaceValidationDiagnostic {
    pub head: Option<Arc<str>>,
    pub message: Cow<'static, str>,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelSurfaceCallSurfaceKind {
    Function,
    ShellLike,
}

#[derive(Debug, Clone)]
pub struct MelSurfaceCall {
    pub name: Arc<str>,
    pub surface_kind: MelSurfaceCallSurfaceKind,
    pub captured: bool,
    pub literal_first_arg: Option<Arc<str>>,
    pub dynamic: bool,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelSurfaceCommandMode {
    Create,
    Edit,
    Query,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct MelSurfaceNormalizedArg {
    pub text_span: mel::MelSpan,
    pub literal: Option<Arc<str>>,
    pub dynamic: bool,
    pub span_start: usize,
    pub span_end: usize,
}

impl MelSurfaceNormalizedArg {
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        source
            .get(self.text_span.start..self.text_span.end)
            .unwrap_or("")
    }

    pub fn preferred_text<'a>(&'a self, source: &'a str) -> &'a str {
        self.literal.as_deref().unwrap_or_else(|| self.text(source))
    }
}

#[derive(Debug, Clone)]
pub struct MelSurfaceNormalizedFlag {
    pub source_span: mel::MelSpan,
    pub canonical_name: Option<Arc<str>>,
    pub value_shapes: Vec<mel::MelValueShape>,
    pub args: Vec<MelSurfaceNormalizedArg>,
    pub span_start: usize,
    pub span_end: usize,
}

impl MelSurfaceNormalizedFlag {
    pub fn source_text<'a>(&self, source: &'a str) -> &'a str {
        source
            .get(self.source_span.start..self.source_span.end)
            .unwrap_or("")
    }

    pub fn preferred_name<'a>(&'a self, source: &'a str) -> &'a str {
        self.canonical_name
            .as_deref()
            .unwrap_or_else(|| self.source_text(source))
    }

    pub fn matches_name(&self, source: &str, canonical: &str, short: &str) -> bool {
        self.canonical_name.as_deref() == Some(canonical) || self.source_text(source) == short
    }

    pub fn has_script_args(&self) -> bool {
        self.value_shapes
            .iter()
            .any(|shape| matches!(shape, mel::MelValueShape::Script))
    }

    pub fn iter_script_args(&self) -> impl Iterator<Item = &MelSurfaceNormalizedArg> + '_ {
        self.value_shapes
            .iter()
            .zip(self.args.iter())
            .filter_map(|(shape, arg)| matches!(shape, mel::MelValueShape::Script).then_some(arg))
    }

    pub fn script_arg_indexes(&self) -> Vec<usize> {
        self.value_shapes
            .iter()
            .enumerate()
            .filter_map(|(index, shape)| {
                matches!(shape, mel::MelValueShape::Script).then_some(index)
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub enum MelSurfaceNormalizedItem {
    Flag(MelSurfaceNormalizedFlag),
    Positional(MelSurfaceNormalizedArg),
}

#[derive(Debug, Clone)]
pub struct MelSurfaceNormalizedCommand {
    pub schema_name: Arc<str>,
    pub mode: MelSurfaceCommandMode,
    pub items: Vec<MelSurfaceNormalizedItem>,
    pub span_start: usize,
    pub span_end: usize,
}

fn map_mel_surface_facts(facts: mel::MelParseFacts) -> MelSurfaceFacts {
    MelSurfaceFacts {
        source_text: Arc::clone(&facts.source_text),
        diagnostics: facts
            .diagnostics
            .into_iter()
            .map(|diagnostic| MelSurfaceDiagnostic {
                stage: match diagnostic.stage {
                    mel::MelDiagnosticStage::Decode => MelSurfaceDiagnosticStage::Decode,
                    mel::MelDiagnosticStage::Lex => MelSurfaceDiagnosticStage::Lex,
                    mel::MelDiagnosticStage::Parse => MelSurfaceDiagnosticStage::Parse,
                },
                message: diagnostic.message,
                span_start: diagnostic.span.start,
                span_end: diagnostic.span.end,
            })
            .collect(),
        validation_diagnostics: facts
            .validation_diagnostics
            .into_iter()
            .map(|diagnostic| MelSurfaceValidationDiagnostic {
                head: diagnostic.head,
                message: diagnostic.message,
                span_start: diagnostic.span.start,
                span_end: diagnostic.span.end,
            })
            .collect(),
        calls: facts
            .calls
            .into_iter()
            .map(|call| MelSurfaceCall {
                name: call.name,
                surface_kind: match call.surface_kind {
                    mel::MelCallSurfaceKind::Function => MelSurfaceCallSurfaceKind::Function,
                    mel::MelCallSurfaceKind::ShellLike => MelSurfaceCallSurfaceKind::ShellLike,
                },
                captured: call.captured,
                literal_first_arg: call.literal_first_arg,
                dynamic: call.dynamic,
                span_start: call.span.start,
                span_end: call.span.end,
            })
            .collect(),
        normalized_commands: facts
            .normalized_invokes
            .into_iter()
            .map(|invoke| MelSurfaceNormalizedCommand {
                schema_name: invoke.command.schema_name,
                mode: match invoke.command.mode {
                    mel::MelNormalizedCommandMode::Create => MelSurfaceCommandMode::Create,
                    mel::MelNormalizedCommandMode::Edit => MelSurfaceCommandMode::Edit,
                    mel::MelNormalizedCommandMode::Query => MelSurfaceCommandMode::Query,
                    mel::MelNormalizedCommandMode::Unknown => MelSurfaceCommandMode::Unknown,
                },
                items: invoke
                    .command
                    .items
                    .into_iter()
                    .map(|item| match item {
                        mel::MelNormalizedCommandItemFact::Flag(flag) => {
                            MelSurfaceNormalizedItem::Flag(MelSurfaceNormalizedFlag {
                                source_span: flag.source_span,
                                canonical_name: flag.canonical_name,
                                value_shapes: flag.value_shapes,
                                args: flag
                                    .args
                                    .into_iter()
                                    .map(|arg| MelSurfaceNormalizedArg {
                                        text_span: arg.text_span,
                                        literal: arg.literal,
                                        dynamic: arg.dynamic,
                                        span_start: arg.span.start,
                                        span_end: arg.span.end,
                                    })
                                    .collect(),
                                span_start: flag.span.start,
                                span_end: flag.span.end,
                            })
                        }
                        mel::MelNormalizedCommandItemFact::Positional(arg) => {
                            MelSurfaceNormalizedItem::Positional(MelSurfaceNormalizedArg {
                                text_span: arg.text_span,
                                literal: arg.literal,
                                dynamic: arg.dynamic,
                                span_start: arg.span.start,
                                span_end: arg.span.end,
                            })
                        }
                    })
                    .collect(),
                span_start: invoke.span.start,
                span_end: invoke.span.end,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::collect_mel_surface_facts_shared;

    #[test]
    fn shared_surface_facts_reuse_input_arc() {
        let source: Arc<str> = Arc::from(r#"source "evil.mel""#);
        let facts = collect_mel_surface_facts_shared(Arc::clone(&source));

        assert!(Arc::ptr_eq(&facts.source_text, &source));
    }
}
