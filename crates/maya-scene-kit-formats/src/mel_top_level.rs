use std::{collections::HashMap, sync::Arc};

use maya_mel::{
    maya::{
        self, MayaCommandRegistry,
        model::{MayaTopLevelFacts as MayaFacts, MayaTopLevelItem},
    },
    parser::{
        Parse, ParseOptions, SharedParse, parse_shared_bytes, parse_shared_source_with_options,
        parse_source_with_options,
    },
    sema,
};

use super::{
    FullParseLike, MelAuditTopLevelFacts, MelNormalizedCommandFact, MelParseBudget,
    MelTopLevelCommandFact, MelTopLevelFacts, MelTopLevelItemFact, MelTopLevelOtherFact,
    MelTopLevelProcFact, collect_diagnostics, collect_sema_validation_diagnostics, display_span,
    map_source_encoding, span_key,
};
use crate::mel::mel_map::{
    map_maya_raw_shell_item, map_maya_specialized_command, map_normalized_command,
};

pub fn collect_top_level_facts(source: &str) -> MelTopLevelFacts {
    collect_top_level_facts_with_budget(source, &MelParseBudget::default())
}

pub fn collect_top_level_facts_with_budget(
    source: &str,
    budget: &MelParseBudget,
) -> MelTopLevelFacts {
    top_level_facts_from_parse(parse_source_with_options(
        source,
        ParseOptions {
            budgets: budget.to_parse_budgets(),
            ..ParseOptions::default()
        },
    ))
}

pub fn collect_top_level_facts_shared(source: Arc<str>) -> MelTopLevelFacts {
    collect_top_level_facts_shared_with_budget(source, &MelParseBudget::default())
}

pub fn collect_top_level_facts_shared_with_budget(
    source: Arc<str>,
    budget: &MelParseBudget,
) -> MelTopLevelFacts {
    top_level_facts_from_shared_parse(parse_shared_source_with_options(
        source,
        ParseOptions {
            budgets: budget.to_parse_budgets(),
            ..ParseOptions::default()
        },
    ))
}

pub fn collect_top_level_facts_from_bytes(bytes: &[u8]) -> MelTopLevelFacts {
    collect_top_level_facts_from_bytes_with_budget(bytes, &MelParseBudget::default())
}

pub fn collect_top_level_facts_from_bytes_with_budget(
    bytes: &[u8],
    budget: &MelParseBudget,
) -> MelTopLevelFacts {
    if *budget == MelParseBudget::default() {
        return top_level_facts_from_shared_parse(parse_shared_bytes(bytes));
    }
    top_level_facts_from_shared_parse(parse_shared_source_with_options(
        Arc::<str>::from(String::from_utf8_lossy(bytes).into_owned()),
        ParseOptions {
            budgets: budget.to_parse_budgets(),
            ..ParseOptions::default()
        },
    ))
}

pub fn collect_top_level_audit_candidates_from_bytes(bytes: &[u8]) -> MelAuditTopLevelFacts {
    collect_top_level_audit_candidates_from_bytes_with_budget(bytes, &MelParseBudget::default())
}

pub fn collect_top_level_audit_candidates_from_bytes_with_budget(
    bytes: &[u8],
    budget: &MelParseBudget,
) -> MelAuditTopLevelFacts {
    crate::ma::selective::extract_raw_selective_sections_from_ma_with_budget(bytes, budget)
        .audit_top_level
}

fn top_level_facts_from_parse(parse: Parse) -> MelTopLevelFacts {
    let registry = MayaCommandRegistry::new();
    let parts = collect_top_level_fact_parts(
        &parse,
        maya::collect_top_level_facts_with_registry(&parse, &registry),
        &registry,
    );

    MelTopLevelFacts {
        source_text: Arc::from(parse.source_text),
        source_encoding: map_source_encoding(parse.source_encoding),
        diagnostics: parts.diagnostics,
        validation_diagnostics: parts.validation_diagnostics,
        items: parts.items,
    }
}

fn top_level_facts_from_shared_parse(parse: SharedParse) -> MelTopLevelFacts {
    let registry = MayaCommandRegistry::new();
    let parts = collect_top_level_fact_parts(
        &parse,
        maya::collect_top_level_facts_shared_with_registry(&parse, &registry),
        &registry,
    );

    MelTopLevelFacts {
        source_text: Arc::clone(&parse.source_text),
        source_encoding: map_source_encoding(parse.source_encoding),
        diagnostics: parts.diagnostics,
        validation_diagnostics: parts.validation_diagnostics,
        items: parts.items,
    }
}

struct TopLevelFactParts {
    diagnostics: Vec<super::MelParseDiagnostic>,
    validation_diagnostics: Vec<super::MelValidationDiagnostic>,
    items: Vec<MelTopLevelItemFact>,
}

fn collect_top_level_fact_parts(
    parse: &impl FullParseLike,
    maya_top_level: MayaFacts,
    registry: &MayaCommandRegistry,
) -> TopLevelFactParts {
    let analysis = sema::analyze_with_registry(parse.syntax(), parse.source_view(), registry);
    let validation_diagnostics = collect_sema_validation_diagnostics(&analysis.diagnostics);
    let normalized_by_range = analysis
        .normalized_invokes
        .into_iter()
        .map(|invoke| {
            (
                span_key(invoke.range),
                map_normalized_command(parse, registry, invoke),
            )
        })
        .collect::<HashMap<_, _>>();

    let items = maya_top_level
        .items
        .into_iter()
        .filter_map(|item| map_top_level_item(parse, item, &normalized_by_range))
        .collect();

    TopLevelFactParts {
        diagnostics: collect_diagnostics(parse),
        validation_diagnostics,
        items,
    }
}

fn map_top_level_item(
    parse: &impl FullParseLike,
    item: MayaTopLevelItem,
    normalized_by_range: &HashMap<(usize, usize), MelNormalizedCommandFact>,
) -> Option<MelTopLevelItemFact> {
    match item {
        MayaTopLevelItem::Command(command) => {
            let key = span_key(command.span);
            Some(MelTopLevelItemFact::Command(Box::new(
                MelTopLevelCommandFact {
                    head: Arc::from(command.head),
                    captured: command.captured,
                    source_span: display_span(parse, command.span),
                    raw_items: command
                        .raw_items
                        .into_iter()
                        .map(|item| map_maya_raw_shell_item(parse, item))
                        .collect(),
                    span: super::MelSpan::from_text_range(command.span),
                    normalized: normalized_by_range.get(&key).cloned(),
                    specialized: command
                        .specialized
                        .and_then(|command| map_maya_specialized_command(parse, command)),
                },
            )))
        }
        MayaTopLevelItem::Proc {
            name,
            is_global,
            span,
        } => Some(MelTopLevelItemFact::Proc(MelTopLevelProcFact {
            name: Arc::from(name),
            is_global,
            source_span: display_span(parse, span),
            span: super::MelSpan::from_text_range(span),
        })),
        MayaTopLevelItem::Other { span } => {
            Some(MelTopLevelItemFact::Other(MelTopLevelOtherFact {
                source_span: display_span(parse, span),
                span: super::MelSpan::from_text_range(span),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{collect_top_level_facts, collect_top_level_facts_shared};

    #[test]
    fn shared_source_reuses_arc_and_matches_borrowed_path() {
        let source: Arc<str> = Arc::from(r#"file -r -ns "refNs" "C:/scene.ma";"#);
        let shared = collect_top_level_facts_shared(Arc::clone(&source));
        let borrowed = collect_top_level_facts(source.as_ref());

        assert!(Arc::ptr_eq(&shared.source_text, &source));
        assert_eq!(shared.diagnostics, borrowed.diagnostics);
        assert_eq!(
            shared.validation_diagnostics,
            borrowed.validation_diagnostics
        );
        assert_eq!(shared.items, borrowed.items);
    }
}
