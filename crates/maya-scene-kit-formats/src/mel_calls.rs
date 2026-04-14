use std::sync::Arc;

use maya_mel::{
    ast::{
        BinaryOp, Expr, InvokeExpr, InvokeSurface, Item, ProcDef, ShellWord, SourceFile, Stmt,
        SwitchLabel,
    },
    maya::MayaCommandRegistry,
    parser::{
        Parse, ParseMode, ParseOptions, SharedParse, parse_shared_bytes,
        parse_shared_source_with_options, parse_source_with_options,
    },
    sema,
    syntax::SourceView,
};

use super::{
    FullParseLike, MelCallFact, MelCallSurfaceKind, MelNormalizedInvokeFact, MelParseBudget,
    MelParseFacts, QuotedDecodePolicy, collect_diagnostics, collect_sema_validation_diagnostics,
    decode_quoted_text, map_source_encoding,
};
use crate::mel::mel_map::map_normalized_command;

pub fn collect_call_facts(source: &str) -> MelParseFacts {
    collect_call_facts_with_budget(source, &MelParseBudget::default())
}

pub fn collect_call_facts_with_budget(source: &str, budget: &MelParseBudget) -> MelParseFacts {
    call_facts_from_parse(parse_source_with_options(
        source,
        ParseOptions {
            mode: ParseMode::AllowTrailingStmtWithoutSemi,
            budgets: budget.to_parse_budgets(),
        },
    ))
}

pub fn collect_call_facts_shared(source: Arc<str>) -> MelParseFacts {
    collect_call_facts_shared_with_budget(source, &MelParseBudget::default())
}

pub fn collect_call_facts_shared_with_budget(
    source: Arc<str>,
    budget: &MelParseBudget,
) -> MelParseFacts {
    call_facts_from_shared_parse(parse_shared_source_with_options(
        source,
        ParseOptions {
            mode: ParseMode::AllowTrailingStmtWithoutSemi,
            budgets: budget.to_parse_budgets(),
        },
    ))
}

pub fn collect_call_facts_from_bytes(bytes: &[u8]) -> MelParseFacts {
    collect_call_facts_from_bytes_with_budget(bytes, &MelParseBudget::default())
}

pub fn collect_call_facts_from_bytes_with_budget(
    bytes: &[u8],
    budget: &MelParseBudget,
) -> MelParseFacts {
    if *budget == MelParseBudget::default() {
        return call_facts_from_shared_parse(parse_shared_bytes(bytes));
    }
    call_facts_from_shared_parse(parse_shared_source_with_options(
        Arc::<str>::from(String::from_utf8_lossy(bytes).into_owned()),
        ParseOptions {
            budgets: budget.to_parse_budgets(),
            ..ParseOptions::default()
        },
    ))
}

fn call_facts_from_parse(parse: Parse) -> MelParseFacts {
    let parts = collect_call_fact_parts(&parse);
    MelParseFacts {
        source_text: Arc::from(parse.source_text),
        source_encoding: map_source_encoding(parse.source_encoding),
        diagnostics: parts.diagnostics,
        validation_diagnostics: parts.validation_diagnostics,
        calls: parts.calls,
        normalized_invokes: parts.normalized_invokes,
    }
}

fn call_facts_from_shared_parse(parse: SharedParse) -> MelParseFacts {
    let parts = collect_call_fact_parts(&parse);
    MelParseFacts {
        source_text: Arc::clone(&parse.source_text),
        source_encoding: map_source_encoding(parse.source_encoding),
        diagnostics: parts.diagnostics,
        validation_diagnostics: parts.validation_diagnostics,
        calls: parts.calls,
        normalized_invokes: parts.normalized_invokes,
    }
}

struct CallFactParts {
    diagnostics: Vec<super::MelParseDiagnostic>,
    validation_diagnostics: Vec<super::MelValidationDiagnostic>,
    calls: Vec<MelCallFact>,
    normalized_invokes: Vec<MelNormalizedInvokeFact>,
}

fn collect_call_fact_parts(parse: &impl FullParseLike) -> CallFactParts {
    let mut calls = Vec::new();
    visit_source_file(parse.syntax(), parse.source_view(), &mut calls);
    let registry = MayaCommandRegistry::new();
    let analysis = sema::analyze_with_registry(parse.syntax(), parse.source_view(), &registry);
    let validation_diagnostics = collect_sema_validation_diagnostics(&analysis.diagnostics);
    let normalized_invokes = analysis
        .normalized_invokes
        .into_iter()
        .map(|invoke| {
            let span = super::MelSpan::from_text_range(invoke.range);
            let command = map_normalized_command(parse, &registry, invoke);
            MelNormalizedInvokeFact { span, command }
        })
        .collect();

    CallFactParts {
        diagnostics: collect_diagnostics(parse),
        validation_diagnostics,
        calls,
        normalized_invokes,
    }
}

fn visit_source_file(source: &SourceFile, source_view: SourceView<'_>, out: &mut Vec<MelCallFact>) {
    for item in &source.items {
        visit_item(item, source_view, out);
    }
}

fn visit_item(item: &Item, source_view: SourceView<'_>, out: &mut Vec<MelCallFact>) {
    match item {
        Item::Proc(proc_def) => visit_proc_def(proc_def, source_view, out),
        Item::Stmt(stmt) => visit_stmt(stmt, source_view, out),
    }
}

fn visit_proc_def(proc_def: &ProcDef, source_view: SourceView<'_>, out: &mut Vec<MelCallFact>) {
    visit_stmt(&proc_def.body, source_view, out);
}

fn visit_stmt(stmt: &Stmt, source_view: SourceView<'_>, out: &mut Vec<MelCallFact>) {
    match stmt {
        Stmt::Empty { .. } | Stmt::Break { .. } | Stmt::Continue { .. } => {}
        Stmt::Proc { proc_def, .. } => visit_proc_def(proc_def, source_view, out),
        Stmt::Block { statements, .. } => {
            for stmt in statements {
                visit_stmt(stmt, source_view, out);
            }
        }
        Stmt::Expr { expr, .. } => visit_expr(expr, source_view, out),
        Stmt::VarDecl { decl, .. } => {
            for declarator in &decl.declarators {
                if let Some(Some(expr)) = &declarator.array_size {
                    visit_expr(expr, source_view, out);
                }
                if let Some(expr) = &declarator.initializer {
                    visit_expr(expr, source_view, out);
                }
            }
        }
        Stmt::If {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            visit_expr(condition, source_view, out);
            visit_stmt(then_branch, source_view, out);
            if let Some(stmt) = else_branch {
                visit_stmt(stmt, source_view, out);
            }
        }
        Stmt::While {
            condition, body, ..
        } => {
            visit_expr(condition, source_view, out);
            visit_stmt(body, source_view, out);
        }
        Stmt::DoWhile {
            body, condition, ..
        } => {
            visit_stmt(body, source_view, out);
            visit_expr(condition, source_view, out);
        }
        Stmt::Switch {
            control, clauses, ..
        } => {
            visit_expr(control, source_view, out);
            for clause in clauses {
                if let SwitchLabel::Case(expr) = &clause.label {
                    visit_expr(expr, source_view, out);
                }
                for stmt in &clause.statements {
                    visit_stmt(stmt, source_view, out);
                }
            }
        }
        Stmt::For {
            init,
            condition,
            update,
            body,
            ..
        } => {
            if let Some(exprs) = init {
                for expr in exprs {
                    visit_expr(expr, source_view, out);
                }
            }
            if let Some(expr) = condition {
                visit_expr(expr, source_view, out);
            }
            if let Some(exprs) = update {
                for expr in exprs {
                    visit_expr(expr, source_view, out);
                }
            }
            visit_stmt(body, source_view, out);
        }
        Stmt::ForIn {
            binding,
            iterable,
            body,
            ..
        } => {
            visit_expr(binding, source_view, out);
            visit_expr(iterable, source_view, out);
            visit_stmt(body, source_view, out);
        }
        Stmt::Return { expr, .. } => {
            if let Some(expr) = expr {
                visit_expr(expr, source_view, out);
            }
        }
    }
}

fn visit_expr(expr: &Expr, source_view: SourceView<'_>, out: &mut Vec<MelCallFact>) {
    match expr {
        Expr::Ident { .. }
        | Expr::BareWord { .. }
        | Expr::Int { .. }
        | Expr::Float { .. }
        | Expr::String { .. } => {}
        Expr::Cast { expr, .. }
        | Expr::Unary { expr, .. }
        | Expr::PrefixUpdate { expr, .. }
        | Expr::PostfixUpdate { expr, .. } => visit_expr(expr, source_view, out),
        Expr::VectorLiteral { elements, .. } | Expr::ArrayLiteral { elements, .. } => {
            for expr in elements {
                visit_expr(expr, source_view, out);
            }
        }
        Expr::Binary { lhs, rhs, .. } | Expr::Assign { lhs, rhs, .. } => {
            visit_expr(lhs, source_view, out);
            visit_expr(rhs, source_view, out);
        }
        Expr::Ternary {
            condition,
            then_expr,
            else_expr,
            ..
        } => {
            visit_expr(condition, source_view, out);
            visit_expr(then_expr, source_view, out);
            visit_expr(else_expr, source_view, out);
        }
        Expr::Index { target, index, .. } => {
            visit_expr(target, source_view, out);
            visit_expr(index, source_view, out);
        }
        Expr::MemberAccess { target, .. } | Expr::ComponentAccess { target, .. } => {
            visit_expr(target, source_view, out);
        }
        Expr::Invoke(invoke) => {
            out.push(call_fact_for_invoke(source_view, invoke));
            match &invoke.surface {
                InvokeSurface::Function { args, .. } => {
                    for expr in args {
                        visit_expr(expr, source_view, out);
                    }
                }
                InvokeSurface::ShellLike { words, .. } => {
                    for word in words {
                        visit_shell_word(word, source_view, out);
                    }
                }
            }
        }
    }
}

fn visit_shell_word(word: &ShellWord, source_view: SourceView<'_>, out: &mut Vec<MelCallFact>) {
    match word {
        ShellWord::Variable { expr, .. }
        | ShellWord::GroupedExpr { expr, .. }
        | ShellWord::BraceList { expr, .. }
        | ShellWord::VectorLiteral { expr, .. } => visit_expr(expr, source_view, out),
        ShellWord::Capture { invoke, .. } => {
            out.push(call_fact_for_invoke(source_view, invoke));
            match &invoke.surface {
                InvokeSurface::Function { args, .. } => {
                    for expr in args {
                        visit_expr(expr, source_view, out);
                    }
                }
                InvokeSurface::ShellLike { words, .. } => {
                    for word in words {
                        visit_shell_word(word, source_view, out);
                    }
                }
            }
        }
        ShellWord::Flag { .. }
        | ShellWord::NumericLiteral { .. }
        | ShellWord::BareWord { .. }
        | ShellWord::QuotedString { .. } => {}
    }
}

fn call_fact_for_invoke(source_view: SourceView<'_>, invoke: &InvokeExpr) -> MelCallFact {
    match &invoke.surface {
        InvokeSurface::Function {
            head_range, args, ..
        } => {
            let literal_first_arg = args
                .first()
                .and_then(|expr| eval_string_literal_expr(source_view, expr));
            MelCallFact {
                name: Arc::from(source_view.slice(*head_range)),
                surface_kind: MelCallSurfaceKind::Function,
                captured: false,
                dynamic: !args.is_empty() && literal_first_arg.is_none(),
                literal_first_arg: literal_first_arg.map(Arc::from),
                span: super::MelSpan::from_text_range(invoke.range),
            }
        }
        InvokeSurface::ShellLike {
            head_range,
            words,
            captured,
        } => {
            let first_arg = words
                .iter()
                .find(|word| !matches!(word, ShellWord::Flag { .. }));
            let literal_first_arg =
                first_arg.and_then(|word| shell_word_literal(source_view, word));
            MelCallFact {
                name: Arc::from(source_view.slice(*head_range)),
                surface_kind: MelCallSurfaceKind::ShellLike,
                captured: *captured,
                dynamic: first_arg.is_some() && literal_first_arg.is_none(),
                literal_first_arg: literal_first_arg.map(Arc::from),
                span: super::MelSpan::from_text_range(invoke.range),
            }
        }
    }
}

pub(super) fn shell_word_literal(source_view: SourceView<'_>, word: &ShellWord) -> Option<String> {
    match word {
        ShellWord::NumericLiteral { text, .. } | ShellWord::BareWord { text, .. } => {
            Some(source_view.slice(*text).to_owned())
        }
        ShellWord::QuotedString { text, .. } => {
            let text = source_view.slice(*text);
            decode_quoted_text(text, QuotedDecodePolicy::LiteralExpr)
                .or_else(|| Some(text.to_owned()))
        }
        ShellWord::GroupedExpr { expr, .. } => eval_string_literal_expr(source_view, expr),
        ShellWord::Flag { .. }
        | ShellWord::Variable { .. }
        | ShellWord::BraceList { .. }
        | ShellWord::VectorLiteral { .. }
        | ShellWord::Capture { .. } => None,
    }
}

fn eval_string_literal_expr(source_view: SourceView<'_>, expr: &Expr) -> Option<String> {
    match expr {
        Expr::String { text, .. } => {
            decode_quoted_text(source_view.slice(*text), QuotedDecodePolicy::LiteralExpr)
                .or_else(|| Some(source_view.slice(*text).to_owned()))
        }
        Expr::Binary {
            op: BinaryOp::Add,
            lhs,
            rhs,
            ..
        } => Some(format!(
            "{}{}",
            eval_string_literal_expr(source_view, lhs)?,
            eval_string_literal_expr(source_view, rhs)?
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{collect_call_facts, collect_call_facts_from_bytes, collect_call_facts_shared};
    use crate::mel::{
        MelAuditTopLevelItemFact, MelCallSurfaceKind, MelDiagnosticStage,
        MelNormalizedCommandItemFact, MelParseDiagnostic, MelSourceEncoding, MelTopLevelItemFact,
        MelValueShape, collect_top_level_audit_candidates_from_bytes, collect_top_level_facts,
    };

    #[test]
    fn function_literal_concat_is_static() {
        let facts = collect_call_facts(r#"python("import sub" + "process")"#);
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].name.as_ref(), "python");
        assert_eq!(facts.calls[0].surface_kind, MelCallSurfaceKind::Function);
        assert_eq!(
            facts.calls[0].literal_first_arg.as_deref(),
            Some("import subprocess")
        );
        assert!(!facts.calls[0].dynamic);
        assert!(facts.diagnostics.is_empty());
    }

    #[test]
    fn variable_argument_is_dynamic() {
        let facts = collect_call_facts(r#"$p = "print('hello')"; python($p)"#);
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].name.as_ref(), "python");
        assert!(facts.calls[0].dynamic);
        assert!(facts.calls[0].literal_first_arg.is_none());
        assert!(facts.diagnostics.is_empty());
    }

    #[test]
    fn shell_like_source_without_semicolon_still_collects_call() {
        let facts = collect_call_facts(r#"source "evil.mel""#);
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].name.as_ref(), "source");
        assert_eq!(facts.calls[0].surface_kind, MelCallSurfaceKind::ShellLike);
        assert_eq!(
            facts.calls[0].literal_first_arg.as_deref(),
            Some("evil.mel")
        );
        assert!(facts.diagnostics.is_empty());
    }

    #[test]
    fn byte_parsing_reports_detected_encoding() {
        let (bytes, _, had_errors) = encoding_rs::SHIFT_JIS.encode(r#"print "設定";"#);
        assert!(!had_errors);
        let facts = collect_call_facts_from_bytes(bytes.as_ref());
        assert_eq!(facts.source_encoding, MelSourceEncoding::Cp932);
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].name.as_ref(), "print");
    }

    #[test]
    fn shared_source_reuses_arc_and_matches_borrowed_path() {
        let source: Arc<str> = Arc::from(r#"source "evil.mel""#);
        let shared = collect_call_facts_shared(Arc::clone(&source));
        let borrowed = collect_call_facts(source.as_ref());

        assert!(Arc::ptr_eq(&shared.source_text, &source));
        assert_eq!(shared.calls, borrowed.calls);
        assert_eq!(shared.diagnostics, borrowed.diagnostics);
        assert_eq!(
            shared.validation_diagnostics,
            borrowed.validation_diagnostics
        );
        assert_eq!(shared.normalized_invokes, borrowed.normalized_invokes);
    }

    #[test]
    fn top_level_file_command_exposes_normalized_command_flag() {
        let facts = collect_top_level_facts(
            r#"file -r -ns "refNs" -command "onLoad" "python(\"import os\")" "C:/scene.ma";"#,
        );

        let MelTopLevelItemFact::Command(command) = &facts.items[0] else {
            panic!("expected top-level command");
        };
        let normalized = command
            .normalized
            .as_ref()
            .expect("normalized file command");
        let callback_flag = normalized
            .items
            .iter()
            .find_map(|item| match item {
                MelNormalizedCommandItemFact::Flag(flag)
                    if flag.canonical_name.as_deref() == Some("command") =>
                {
                    Some(flag)
                }
                _ => None,
            })
            .expect("file -command flag");

        assert_eq!(normalized.schema_name.as_ref(), "file");
        assert_eq!(callback_flag.args.len(), 2);
        assert_eq!(callback_flag.args[0].literal.as_deref(), Some("onLoad"));
        assert_eq!(
            callback_flag.args[1].literal.as_deref(),
            Some(r#"python("import os")"#)
        );
        assert_eq!(
            callback_flag.value_shapes,
            vec![MelValueShape::String, MelValueShape::String]
        );
    }

    #[test]
    fn normalized_callback_flag_preserves_script_value_shape() {
        let facts = collect_call_facts(
            r#"modelEditor -e -editorChanged "print(\"updated\")" modelPanel4;"#,
        );
        let invoke = &facts.normalized_invokes[0].command;
        let flag = invoke
            .items
            .iter()
            .find_map(|item| match item {
                MelNormalizedCommandItemFact::Flag(flag)
                    if flag.canonical_name.as_deref() == Some("editorChanged") =>
                {
                    Some(flag)
                }
                _ => None,
            })
            .expect("editorChanged flag");

        assert_eq!(invoke.schema_name.as_ref(), "modelEditor");
        assert_eq!(flag.value_shapes, vec![MelValueShape::Script]);
    }

    #[test]
    fn top_level_proc_and_other_statements_are_preserved() {
        let facts = collect_top_level_facts(concat!(
            "global proc string hello() { return \"ok\"; }\n",
            "int $value = 1;\n",
        ));

        assert!(matches!(facts.items[0], MelTopLevelItemFact::Proc(_)));
        assert!(matches!(facts.items[1], MelTopLevelItemFact::Other(_)));
    }

    #[test]
    fn audit_candidates_keep_file_command_callback() {
        let facts = collect_top_level_audit_candidates_from_bytes(
            concat!(
                "file -r -command \"onLoad\" \"python(\\\"import os\\\")\" \"C:/scene.ma\";\n",
                "setAttr \".v\" yes;\n",
            )
            .as_bytes(),
        );

        let MelAuditTopLevelItemFact::Command(command) = &facts.items[0] else {
            panic!("expected command");
        };
        assert_eq!(command.head.as_ref(), "file");
        assert_eq!(
            command.file_command_callback.as_deref(),
            Some(r#"python("import os")"#)
        );
        assert_eq!(facts.items.len(), 1);
    }

    #[test]
    fn audit_candidates_filter_non_audit_commands() {
        let facts = collect_top_level_audit_candidates_from_bytes(
            concat!(
                "setAttr \".v\" yes;\n",
                "python(\"print(\\\"hi\\\")\");\n",
                "loadPlugin \"evil.mll\";\n",
            )
            .as_bytes(),
        );

        assert_eq!(facts.items.len(), 2);
        let heads = facts
            .items
            .iter()
            .filter_map(|item| match item {
                MelAuditTopLevelItemFact::Command(command) => Some(command.head.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(heads, vec!["python", "loadPlugin"]);
    }

    #[test]
    fn audit_candidates_keep_callback_bearing_top_level_command() {
        let facts = collect_top_level_audit_candidates_from_bytes(
            concat!(
                "setAttr \".v\" yes;\n",
                "nodeOutliner -e -selectCommand \"eval \\\"hello\\\"\" $myoutliner;\n",
            )
            .as_bytes(),
        );

        let heads = facts
            .items
            .iter()
            .filter_map(|item| match item {
                MelAuditTopLevelItemFact::Command(command) => Some(command.head.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(heads, vec!["nodeOutliner"]);
    }

    #[test]
    fn parser_entrypoints_do_not_change_decode_stage_surface() {
        let facts = collect_call_facts("python(\"ok\")");
        assert!(matches!(
            facts.diagnostics.first(),
            None | Some(MelParseDiagnostic {
                stage: MelDiagnosticStage::Decode
                    | MelDiagnosticStage::Lex
                    | MelDiagnosticStage::Parse,
                ..
            })
        ));
    }
}
