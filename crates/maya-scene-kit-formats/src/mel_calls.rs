use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use maya_mel::{
    ast::{
        AssignOp, BinaryOp, Expr, InvokeExpr, InvokeSurface, Item, ProcDef, ShellWord, SourceFile,
        Stmt, SwitchLabel,
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
    FullParseLike, MelCallFact, MelCallSurfaceKind, MelCodeLikeValueFact,
    MelNormalizedCommandItemFact, MelNormalizedInvokeFact, MelNormalizedPositionalArg,
    MelParseBudget, MelParseFacts, MelResolvedStringKind, MelSinkArgFact, MelSinkArgKind, MelSpan,
    MelStringAssemblyMarker, MelValueShape, QuotedDecodePolicy, collect_diagnostics,
    collect_sema_validation_diagnostics, decode_quoted_text, map_source_encoding,
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

pub fn collect_expression_call_facts(source: &str) -> MelParseFacts {
    collect_expression_call_facts_with_budget(source, &MelParseBudget::default())
}

pub fn collect_expression_call_facts_with_budget(
    source: &str,
    budget: &MelParseBudget,
) -> MelParseFacts {
    let parse = parse_source_with_options(
        source,
        ParseOptions {
            mode: ParseMode::ExpressionAllowTrailingStmtWithoutSemi,
            budgets: budget.to_parse_budgets(),
        },
    );
    if parse.errors.is_empty() {
        return call_facts_from_parse(parse);
    }
    if let Some(normalized) = normalize_leading_dot_expression_attrs(source) {
        let normalized_parse = parse_source_with_options(
            &normalized,
            ParseOptions {
                mode: ParseMode::ExpressionAllowTrailingStmtWithoutSemi,
                budgets: budget.to_parse_budgets(),
            },
        );
        if normalized_parse.errors.len() < parse.errors.len() {
            return call_facts_from_parse(normalized_parse);
        }
    }
    call_facts_from_parse(parse)
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

pub fn collect_expression_call_facts_shared_with_budget(
    source: Arc<str>,
    budget: &MelParseBudget,
) -> MelParseFacts {
    let parse = parse_shared_source_with_options(
        Arc::clone(&source),
        ParseOptions {
            mode: ParseMode::ExpressionAllowTrailingStmtWithoutSemi,
            budgets: budget.to_parse_budgets(),
        },
    );
    if parse.errors.is_empty() {
        return call_facts_from_shared_parse(parse);
    }
    if let Some(normalized) = normalize_leading_dot_expression_attrs(source.as_ref()) {
        let normalized_parse = parse_shared_source_with_options(
            Arc::<str>::from(normalized),
            ParseOptions {
                mode: ParseMode::ExpressionAllowTrailingStmtWithoutSemi,
                budgets: budget.to_parse_budgets(),
            },
        );
        if normalized_parse.errors.len() < parse.errors.len() {
            return call_facts_from_shared_parse(normalized_parse);
        }
    }
    call_facts_from_shared_parse(parse)
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
        sink_arg_facts: parts.sink_arg_facts,
        code_like_value_facts: parts.code_like_value_facts,
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
        sink_arg_facts: parts.sink_arg_facts,
        code_like_value_facts: parts.code_like_value_facts,
    }
}

fn normalize_leading_dot_expression_attrs(source: &str) -> Option<String> {
    let mut out = source.to_string();
    let mut changed = false;
    let mut previous_significant = None;
    let mut in_string = false;
    let mut escape = false;
    for (offset, ch) in source.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            previous_significant = Some(ch);
            continue;
        }

        if ch == '.'
            && source[offset + 1..]
                .chars()
                .next()
                .is_some_and(is_expression_attr_start)
            && previous_significant.is_none_or(allows_leading_dot_expr_attr)
        {
            out.replace_range(offset..offset + 1, "_");
            changed = true;
        }
        if !ch.is_whitespace() {
            previous_significant = Some(ch);
        }
    }
    changed.then_some(out)
}

fn is_expression_attr_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn allows_leading_dot_expr_attr(ch: char) -> bool {
    matches!(
        ch,
        '(' | '{'
            | '['
            | '='
            | '+'
            | '-'
            | '*'
            | '/'
            | '%'
            | ','
            | '?'
            | ':'
            | ';'
            | '<'
            | '>'
            | '!'
            | '&'
            | '|'
    )
}

struct CallFactParts {
    diagnostics: Vec<super::MelParseDiagnostic>,
    validation_diagnostics: Vec<super::MelValidationDiagnostic>,
    calls: Vec<MelCallFact>,
    normalized_invokes: Vec<MelNormalizedInvokeFact>,
    sink_arg_facts: Vec<MelSinkArgFact>,
    code_like_value_facts: Vec<MelCodeLikeValueFact>,
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
        .collect::<Vec<_>>();
    let flow = analyze_string_flow(
        parse.syntax(),
        parse.source_text(),
        parse.source_view(),
        &normalized_invokes,
    );

    CallFactParts {
        diagnostics: collect_diagnostics(parse),
        validation_diagnostics,
        calls,
        normalized_invokes,
        sink_arg_facts: flow.sink_arg_facts,
        code_like_value_facts: flow.code_like_value_facts,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedValue {
    Literal {
        text: String,
    },
    ProcReference {
        name: String,
    },
    AssembledLiteral {
        rendered_text: String,
        markers: Vec<MelStringAssemblyMarker>,
        origin_spans: Vec<MelSpan>,
    },
    Dynamic,
    Unknown,
}

impl ResolvedValue {
    fn literal(text: String) -> Self {
        Self::Literal { text }
    }

    fn assembled(
        rendered_text: String,
        markers: Vec<MelStringAssemblyMarker>,
        span: MelSpan,
    ) -> Self {
        Self::AssembledLiteral {
            rendered_text,
            markers: dedup_markers(markers),
            origin_spans: vec![span],
        }
    }

    fn resolved_kind(&self) -> MelResolvedStringKind {
        match self {
            Self::Literal { .. } => MelResolvedStringKind::Literal,
            Self::ProcReference { .. } => MelResolvedStringKind::ProcReference,
            Self::AssembledLiteral { .. } => MelResolvedStringKind::AssembledLiteral,
            Self::Dynamic => MelResolvedStringKind::Dynamic,
            Self::Unknown => MelResolvedStringKind::Unknown,
        }
    }

    fn rendered_text(&self) -> Option<&str> {
        match self {
            Self::Literal { text } => Some(text.as_str()),
            Self::ProcReference { name } => Some(name.as_str()),
            Self::AssembledLiteral { rendered_text, .. } => Some(rendered_text.as_str()),
            Self::Dynamic | Self::Unknown => None,
        }
    }

    fn markers(&self) -> &[MelStringAssemblyMarker] {
        match self {
            Self::AssembledLiteral { markers, .. } => markers,
            Self::Literal { .. } | Self::ProcReference { .. } | Self::Dynamic | Self::Unknown => {
                &[]
            }
        }
    }

    fn origin_spans(&self) -> &[MelSpan] {
        match self {
            Self::AssembledLiteral { origin_spans, .. } => origin_spans,
            Self::Literal { .. } | Self::ProcReference { .. } | Self::Dynamic | Self::Unknown => {
                &[]
            }
        }
    }
}

#[derive(Debug, Default)]
struct FlowFacts {
    sink_arg_facts: Vec<MelSinkArgFact>,
    code_like_value_facts: Vec<MelCodeLikeValueFact>,
}

#[derive(Debug, Default)]
struct FlowCollector {
    env: HashMap<String, ResolvedValue>,
    span_values: HashMap<MelSpan, ResolvedValue>,
    sink_arg_facts: Vec<MelSinkArgFact>,
}

fn analyze_string_flow(
    source: &SourceFile,
    source_text: &str,
    source_view: SourceView<'_>,
    normalized_invokes: &[MelNormalizedInvokeFact],
) -> FlowFacts {
    let mut collector = FlowCollector::default();
    collector.visit_source_file(source, source_text, source_view);

    for invoke in normalized_invokes {
        for item in &invoke.command.items {
            let MelNormalizedCommandItemFact::Flag(flag) = item else {
                continue;
            };
            for (shape, arg) in flag.value_shapes.iter().zip(flag.args.iter()) {
                if !matches!(shape, MelValueShape::Script) {
                    continue;
                }
                let sink_kind = if invoke.command.schema_name.eq_ignore_ascii_case("scriptJob") {
                    MelSinkArgKind::ScriptJobPayload
                } else {
                    MelSinkArgKind::CallbackFlag
                };
                let mut value = collector
                    .span_values
                    .get(&arg.text_span)
                    .cloned()
                    .unwrap_or_else(|| fallback_value_for_normalized_arg(source_text, arg));
                if sink_kind == MelSinkArgKind::CallbackFlag
                    && matches!(value, ResolvedValue::Literal { ref text } if is_bare_identifier(text))
                {
                    value = ResolvedValue::ProcReference {
                        name: value.rendered_text().unwrap_or_default().to_string(),
                    };
                }
                collector.sink_arg_facts.push(build_sink_arg_fact(
                    sink_kind,
                    Some(Arc::clone(&invoke.command.schema_name)),
                    Some(Arc::from(flag.preferred_name(source_text))),
                    arg.text_span,
                    &value,
                ));
            }
        }
    }

    let mut consumed_origins = HashSet::new();
    for fact in &collector.sink_arg_facts {
        if let Some(value) = collector.span_values.get(&fact.span) {
            consumed_origins.extend(value.origin_spans().iter().copied());
        }
    }

    let mut code_like_value_facts = Vec::new();
    let mut seen = HashSet::new();
    let mut seen_rendered = HashSet::new();
    for value in collector.span_values.values() {
        let ResolvedValue::AssembledLiteral {
            rendered_text,
            markers,
            origin_spans,
        } = value
        else {
            continue;
        };
        if !is_code_like_rendered_text(rendered_text) {
            continue;
        }
        if !seen_rendered.insert(rendered_text.clone()) {
            continue;
        }
        for origin in origin_spans {
            if consumed_origins.contains(origin) || !seen.insert(*origin) {
                continue;
            }
            code_like_value_facts.push(MelCodeLikeValueFact {
                resolved_kind: MelResolvedStringKind::AssembledLiteral,
                span: *origin,
                rendered_text: Arc::from(rendered_text.as_str()),
                markers: markers.clone(),
            });
        }
    }

    FlowFacts {
        sink_arg_facts: collector.sink_arg_facts,
        code_like_value_facts,
    }
}

impl FlowCollector {
    fn visit_source_file(
        &mut self,
        source: &SourceFile,
        source_text: &str,
        source_view: SourceView<'_>,
    ) {
        for item in &source.items {
            self.visit_item(item, source_text, source_view);
        }
    }

    fn visit_item(&mut self, item: &Item, source_text: &str, source_view: SourceView<'_>) {
        match item {
            Item::Proc(proc_def) => {
                let saved_env = std::mem::take(&mut self.env);
                self.visit_proc_def(proc_def, source_text, source_view);
                self.env = saved_env;
            }
            Item::Stmt(stmt) => self.visit_stmt(stmt, source_text, source_view),
        }
    }

    fn visit_proc_def(
        &mut self,
        proc_def: &ProcDef,
        source_text: &str,
        source_view: SourceView<'_>,
    ) {
        self.visit_stmt(&proc_def.body, source_text, source_view);
    }

    fn visit_stmt(&mut self, stmt: &Stmt, source_text: &str, source_view: SourceView<'_>) {
        match stmt {
            Stmt::Empty { .. } | Stmt::Break { .. } | Stmt::Continue { .. } => {}
            Stmt::Proc { proc_def, .. } => self.visit_proc_def(proc_def, source_text, source_view),
            Stmt::Block { statements, .. } => {
                for stmt in statements {
                    self.visit_stmt(stmt, source_text, source_view);
                }
            }
            Stmt::Expr { expr, .. } => {
                self.eval_expr(expr, source_text, source_view);
            }
            Stmt::VarDecl { decl, .. } => {
                for declarator in &decl.declarators {
                    if let Some(Some(expr)) = &declarator.array_size {
                        self.eval_expr(expr, source_text, source_view);
                    }
                    let value = declarator
                        .initializer
                        .as_ref()
                        .map(|expr| self.eval_expr(expr, source_text, source_view))
                        .unwrap_or(ResolvedValue::Unknown);
                    self.env
                        .insert(declarator.name_text(source_text).to_string(), value);
                }
            }
            Stmt::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                self.eval_expr(condition, source_text, source_view);
                self.visit_stmt_scoped(then_branch, source_text, source_view);
                if let Some(stmt) = else_branch {
                    self.visit_stmt_scoped(stmt, source_text, source_view);
                }
            }
            Stmt::While {
                condition, body, ..
            } => {
                self.eval_expr(condition, source_text, source_view);
                self.visit_stmt_scoped(body, source_text, source_view);
            }
            Stmt::DoWhile {
                body, condition, ..
            } => {
                self.visit_stmt_scoped(body, source_text, source_view);
                self.eval_expr(condition, source_text, source_view);
            }
            Stmt::Switch {
                control, clauses, ..
            } => {
                self.eval_expr(control, source_text, source_view);
                for clause in clauses {
                    if let SwitchLabel::Case(expr) = &clause.label {
                        self.eval_expr(expr, source_text, source_view);
                    }
                    for stmt in &clause.statements {
                        self.visit_stmt_scoped(stmt, source_text, source_view);
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
                        self.eval_expr(expr, source_text, source_view);
                    }
                }
                if let Some(expr) = condition {
                    self.eval_expr(expr, source_text, source_view);
                }
                if let Some(exprs) = update {
                    for expr in exprs {
                        self.eval_expr(expr, source_text, source_view);
                    }
                }
                self.visit_stmt_scoped(body, source_text, source_view);
            }
            Stmt::ForIn {
                binding,
                iterable,
                body,
                ..
            } => {
                self.eval_expr(binding, source_text, source_view);
                self.eval_expr(iterable, source_text, source_view);
                self.visit_stmt_scoped(body, source_text, source_view);
            }
            Stmt::Return { expr, .. } => {
                if let Some(expr) = expr {
                    self.eval_expr(expr, source_text, source_view);
                }
            }
        }
    }

    fn visit_stmt_scoped(&mut self, stmt: &Stmt, source_text: &str, source_view: SourceView<'_>) {
        let saved_env = self.env.clone();
        self.visit_stmt(stmt, source_text, source_view);
        self.env = saved_env;
    }

    fn eval_expr(
        &mut self,
        expr: &Expr,
        source_text: &str,
        source_view: SourceView<'_>,
    ) -> ResolvedValue {
        let value = match expr {
            Expr::Ident { .. } => {
                let Some(name) = expr.ident_text(source_text) else {
                    return ResolvedValue::Unknown;
                };
                match self.env.get(name).cloned() {
                    Some(ResolvedValue::AssembledLiteral {
                        rendered_text,
                        markers,
                        origin_spans,
                    }) => ResolvedValue::AssembledLiteral {
                        rendered_text,
                        markers: push_marker(markers, MelStringAssemblyMarker::VariableReference),
                        origin_spans,
                    },
                    Some(value) => value,
                    None => ResolvedValue::Unknown,
                }
            }
            Expr::BareWord { text, .. } => {
                ResolvedValue::literal(source_view.slice(*text).to_owned())
            }
            Expr::Int { value, .. } => ResolvedValue::literal(value.to_string()),
            Expr::Float { text, .. } => ResolvedValue::literal(source_view.slice(*text).to_owned()),
            Expr::String { text, .. } => ResolvedValue::literal(
                decode_quoted_text(source_view.slice(*text), QuotedDecodePolicy::LiteralExpr)
                    .unwrap_or_else(|| source_view.slice(*text).to_owned()),
            ),
            Expr::Cast { expr, .. }
            | Expr::Unary { expr, .. }
            | Expr::PrefixUpdate { expr, .. }
            | Expr::PostfixUpdate { expr, .. } => self.eval_expr(expr, source_text, source_view),
            Expr::VectorLiteral { elements, .. } | Expr::ArrayLiteral { elements, .. } => {
                for expr in elements {
                    self.eval_expr(expr, source_text, source_view);
                }
                ResolvedValue::Dynamic
            }
            Expr::Binary {
                op: BinaryOp::Add,
                lhs,
                rhs,
                ..
            } => combine_add_values(
                self.eval_expr(lhs, source_text, source_view),
                self.eval_expr(rhs, source_text, source_view),
                MelSpan::from_text_range(expr.range()),
            ),
            Expr::Binary { lhs, rhs, .. } => {
                self.eval_expr(lhs, source_text, source_view);
                self.eval_expr(rhs, source_text, source_view);
                ResolvedValue::Dynamic
            }
            Expr::Assign { op, lhs, rhs, .. } => {
                let rhs_value = self.eval_expr(rhs, source_text, source_view);
                let next_value = if let Some(name) = lhs.ident_text(source_text) {
                    let next = match op {
                        AssignOp::Assign => rhs_value.clone(),
                        AssignOp::AddAssign => combine_add_values(
                            self.env
                                .get(name)
                                .cloned()
                                .unwrap_or(ResolvedValue::Unknown),
                            rhs_value.clone(),
                            MelSpan::from_text_range(expr.range()),
                        ),
                        AssignOp::SubAssign | AssignOp::MulAssign | AssignOp::DivAssign => {
                            ResolvedValue::Dynamic
                        }
                    };
                    self.env.insert(name.to_string(), next.clone());
                    next
                } else {
                    rhs_value
                };
                self.record_expr_value(expr, next_value)
            }
            Expr::Ternary {
                condition,
                then_expr,
                else_expr,
                ..
            } => {
                self.eval_expr(condition, source_text, source_view);
                self.eval_expr(then_expr, source_text, source_view);
                self.eval_expr(else_expr, source_text, source_view);
                ResolvedValue::Dynamic
            }
            Expr::Index { target, index, .. } => {
                self.eval_expr(target, source_text, source_view);
                self.eval_expr(index, source_text, source_view);
                ResolvedValue::Dynamic
            }
            Expr::MemberAccess { target, .. } | Expr::ComponentAccess { target, .. } => {
                self.eval_expr(target, source_text, source_view);
                ResolvedValue::Dynamic
            }
            Expr::Invoke(invoke) => {
                self.visit_invoke(invoke, source_text, source_view);
                ResolvedValue::Unknown
            }
        };
        self.record_expr_value(expr, value)
    }

    fn record_expr_value(&mut self, expr: &Expr, value: ResolvedValue) -> ResolvedValue {
        self.span_values
            .insert(MelSpan::from_text_range(expr.range()), value.clone());
        value
    }

    fn visit_invoke(
        &mut self,
        invoke: &InvokeExpr,
        source_text: &str,
        source_view: SourceView<'_>,
    ) {
        match &invoke.surface {
            InvokeSurface::Function {
                head_range, args, ..
            } => {
                let head = source_view.slice(*head_range);
                let values = args
                    .iter()
                    .map(|arg| self.eval_expr(arg, source_text, source_view))
                    .collect::<Vec<_>>();
                if let (Some(first), Some(sink_kind)) =
                    (values.first(), sink_kind_for_function(head))
                {
                    self.sink_arg_facts.push(build_sink_arg_fact(
                        sink_kind,
                        None,
                        None,
                        MelSpan::from_text_range(args[0].range()),
                        first,
                    ));
                }
            }
            InvokeSurface::ShellLike { words, .. } => {
                for word in words {
                    self.eval_shell_word(word, source_text, source_view);
                }
            }
        }
    }

    fn eval_shell_word(
        &mut self,
        word: &ShellWord,
        source_text: &str,
        source_view: SourceView<'_>,
    ) -> ResolvedValue {
        let (span, value) = match word {
            ShellWord::Flag { range, .. } => {
                (MelSpan::from_text_range(*range), ResolvedValue::Unknown)
            }
            ShellWord::NumericLiteral { text, range } | ShellWord::BareWord { text, range } => (
                MelSpan::from_text_range(*range),
                ResolvedValue::literal(source_view.slice(*text).to_owned()),
            ),
            ShellWord::QuotedString { text, range } => (
                MelSpan::from_text_range(*range),
                ResolvedValue::literal(
                    decode_quoted_text(source_view.slice(*text), QuotedDecodePolicy::LiteralExpr)
                        .unwrap_or_else(|| source_view.slice(*text).to_owned()),
                ),
            ),
            ShellWord::Variable { expr, range }
            | ShellWord::GroupedExpr { expr, range }
            | ShellWord::BraceList { expr, range }
            | ShellWord::VectorLiteral { expr, range } => (
                MelSpan::from_text_range(*range),
                self.eval_expr(expr, source_text, source_view),
            ),
            ShellWord::Capture { invoke, range } => {
                self.visit_invoke(invoke, source_text, source_view);
                (MelSpan::from_text_range(*range), ResolvedValue::Dynamic)
            }
        };
        self.span_values.insert(span, value.clone());
        value
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

fn fallback_value_for_normalized_arg(
    source_text: &str,
    arg: &MelNormalizedPositionalArg,
) -> ResolvedValue {
    if let Some(literal) = &arg.literal {
        return ResolvedValue::literal(literal.to_string());
    }
    if arg.dynamic {
        return ResolvedValue::Dynamic;
    }
    let text = arg.text(source_text).trim();
    if text.is_empty() {
        ResolvedValue::Unknown
    } else {
        ResolvedValue::literal(text.to_string())
    }
}

fn build_sink_arg_fact(
    sink_kind: MelSinkArgKind,
    command_name: Option<Arc<str>>,
    flag_name: Option<Arc<str>>,
    span: MelSpan,
    value: &ResolvedValue,
) -> MelSinkArgFact {
    MelSinkArgFact {
        sink_kind,
        resolved_kind: value.resolved_kind(),
        span,
        command_name,
        flag_name,
        rendered_text: value.rendered_text().map(Arc::<str>::from),
        markers: value.markers().to_vec(),
        code_like: value
            .rendered_text()
            .is_some_and(is_code_like_rendered_text),
    }
}

fn combine_add_values(lhs: ResolvedValue, rhs: ResolvedValue, span: MelSpan) -> ResolvedValue {
    let lhs_text = lhs.rendered_text().map(str::to_owned);
    let rhs_text = rhs.rendered_text().map(str::to_owned);
    match (lhs_text, rhs_text) {
        (Some(lhs_text), Some(rhs_text)) => {
            let mut markers = lhs.markers().to_vec();
            markers.extend_from_slice(rhs.markers());
            markers.push(MelStringAssemblyMarker::Concat);
            ResolvedValue::assembled(format!("{lhs_text}{rhs_text}"), markers, span)
        }
        _ if matches!(lhs, ResolvedValue::Dynamic) || matches!(rhs, ResolvedValue::Dynamic) => {
            ResolvedValue::Dynamic
        }
        _ => ResolvedValue::Unknown,
    }
}

fn push_marker(
    mut markers: Vec<MelStringAssemblyMarker>,
    marker: MelStringAssemblyMarker,
) -> Vec<MelStringAssemblyMarker> {
    if !markers.contains(&marker) {
        markers.push(marker);
    }
    markers
}

fn dedup_markers(markers: Vec<MelStringAssemblyMarker>) -> Vec<MelStringAssemblyMarker> {
    let mut out = Vec::new();
    for marker in markers {
        if !out.contains(&marker) {
            out.push(marker);
        }
    }
    out
}

fn sink_kind_for_function(name: &str) -> Option<MelSinkArgKind> {
    if name.eq_ignore_ascii_case("python") {
        Some(MelSinkArgKind::Python)
    } else if name.eq_ignore_ascii_case("eval") {
        Some(MelSinkArgKind::Eval)
    } else if name.eq_ignore_ascii_case("evalDeferred") {
        Some(MelSinkArgKind::EvalDeferred)
    } else {
        None
    }
}

fn is_bare_identifier(text: &str) -> bool {
    let mut chars = text.trim().chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !matches!(first, 'a'..='z' | 'A'..='Z' | '_') {
        return false;
    }
    chars.all(|ch| matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_'))
}

fn is_code_like_rendered_text(text: &str) -> bool {
    if contains_exec_entry(text, "python")
        || contains_exec_entry(text, "eval")
        || contains_exec_entry(text, "evalDeferred")
    {
        return true;
    }
    let parse = parse_source_with_options(
        text,
        ParseOptions {
            mode: ParseMode::AllowTrailingStmtWithoutSemi,
            budgets: MelParseBudget::default()
                .with_max_bytes(text.len().max(1).saturating_mul(4).min(64 * 1024))
                .to_parse_budgets(),
        },
    );
    contains_any_invoke(&parse.syntax)
}

fn contains_exec_entry(text: &str, entry: &str) -> bool {
    text.match_indices(entry).any(|(idx, _)| {
        let before = idx
            .checked_sub(1)
            .and_then(|pos| text.as_bytes().get(pos))
            .copied();
        let after = text.as_bytes().get(idx + entry.len()).copied();
        !before.is_some_and(is_ident_byte) && after == Some(b'(')
    })
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn contains_any_invoke(source: &SourceFile) -> bool {
    source.items.iter().any(item_contains_invoke)
}

fn item_contains_invoke(item: &Item) -> bool {
    match item {
        Item::Proc(proc_def) => stmt_contains_invoke(&proc_def.body),
        Item::Stmt(stmt) => stmt_contains_invoke(stmt),
    }
}

fn stmt_contains_invoke(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr { expr, .. } => expr_contains_invoke(expr),
        Stmt::Block { statements, .. } => statements.iter().any(stmt_contains_invoke),
        Stmt::VarDecl { decl, .. } => decl.declarators.iter().any(|decl| {
            decl.array_size
                .as_ref()
                .and_then(|expr| expr.as_ref())
                .is_some_and(expr_contains_invoke)
                || decl.initializer.as_ref().is_some_and(expr_contains_invoke)
        }),
        Stmt::If {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            expr_contains_invoke(condition)
                || stmt_contains_invoke(then_branch)
                || else_branch
                    .as_ref()
                    .is_some_and(|stmt| stmt_contains_invoke(stmt))
        }
        Stmt::While {
            condition, body, ..
        } => expr_contains_invoke(condition) || stmt_contains_invoke(body),
        Stmt::DoWhile {
            body, condition, ..
        } => stmt_contains_invoke(body) || expr_contains_invoke(condition),
        Stmt::Switch {
            control, clauses, ..
        } => {
            expr_contains_invoke(control)
                || clauses.iter().any(|clause| {
                    matches!(&clause.label, SwitchLabel::Case(expr) if expr_contains_invoke(expr))
                        || clause.statements.iter().any(stmt_contains_invoke)
                })
        }
        Stmt::For {
            init,
            condition,
            update,
            body,
            ..
        } => {
            init.iter().flatten().any(expr_contains_invoke)
                || condition
                    .as_ref()
                    .is_some_and(|expr| expr_contains_invoke(expr))
                || update.iter().flatten().any(expr_contains_invoke)
                || stmt_contains_invoke(body)
        }
        Stmt::ForIn {
            binding,
            iterable,
            body,
            ..
        } => {
            expr_contains_invoke(binding)
                || expr_contains_invoke(iterable)
                || stmt_contains_invoke(body)
        }
        Stmt::Return { expr, .. } => expr.as_ref().is_some_and(expr_contains_invoke),
        Stmt::Proc { proc_def, .. } => stmt_contains_invoke(&proc_def.body),
        Stmt::Empty { .. } | Stmt::Break { .. } | Stmt::Continue { .. } => false,
    }
}

fn expr_contains_invoke(expr: &Expr) -> bool {
    match expr {
        Expr::Invoke(_) => true,
        Expr::Cast { expr, .. }
        | Expr::Unary { expr, .. }
        | Expr::PrefixUpdate { expr, .. }
        | Expr::PostfixUpdate { expr, .. } => expr_contains_invoke(expr),
        Expr::VectorLiteral { elements, .. } | Expr::ArrayLiteral { elements, .. } => {
            elements.iter().any(expr_contains_invoke)
        }
        Expr::Binary { lhs, rhs, .. } | Expr::Assign { lhs, rhs, .. } => {
            expr_contains_invoke(lhs) || expr_contains_invoke(rhs)
        }
        Expr::Ternary {
            condition,
            then_expr,
            else_expr,
            ..
        } => {
            expr_contains_invoke(condition)
                || expr_contains_invoke(then_expr)
                || expr_contains_invoke(else_expr)
        }
        Expr::Index { target, index, .. } => {
            expr_contains_invoke(target) || expr_contains_invoke(index)
        }
        Expr::MemberAccess { target, .. } | Expr::ComponentAccess { target, .. } => {
            expr_contains_invoke(target)
        }
        Expr::Ident { .. }
        | Expr::BareWord { .. }
        | Expr::Int { .. }
        | Expr::Float { .. }
        | Expr::String { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        collect_call_facts, collect_call_facts_from_bytes, collect_call_facts_shared,
        collect_expression_call_facts,
    };
    use crate::mel::{
        MelAuditTopLevelItemFact, MelCallSurfaceKind, MelDiagnosticStage,
        MelNormalizedCommandItemFact, MelParseDiagnostic, MelSinkArgKind, MelSourceEncoding,
        MelStringAssemblyMarker, MelTopLevelItemFact, MelValueShape,
        collect_top_level_audit_candidates_from_bytes, collect_top_level_facts,
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
        assert_eq!(facts.sink_arg_facts.len(), 1);
        assert_eq!(facts.sink_arg_facts[0].sink_kind, MelSinkArgKind::Python);
        assert_eq!(
            facts.sink_arg_facts[0].markers,
            vec![MelStringAssemblyMarker::Concat]
        );
    }

    #[test]
    fn variable_argument_is_dynamic_for_legacy_call_shape_but_sink_fact_is_literal() {
        let facts = collect_call_facts(r#"$p = "print('hello')"; python($p)"#);
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].name.as_ref(), "python");
        assert!(facts.calls[0].dynamic);
        assert!(facts.calls[0].literal_first_arg.is_none());
        assert!(facts.diagnostics.is_empty());
        assert_eq!(
            facts.sink_arg_facts[0].rendered_text.as_deref(),
            Some("print('hello')")
        );
    }

    #[test]
    fn callback_sink_fact_uses_proc_reference_shape() {
        let facts = collect_call_facts(r#"modelEditor -e -editorChanged "safeProc" modelPanel4;"#);
        let fact = facts
            .sink_arg_facts
            .iter()
            .find(|fact| fact.sink_kind == MelSinkArgKind::CallbackFlag)
            .expect("callback fact");
        assert_eq!(
            fact.resolved_kind,
            crate::mel::MelResolvedStringKind::ProcReference
        );
        assert_eq!(fact.rendered_text.as_deref(), Some("safeProc"));
    }

    #[test]
    fn assembled_code_like_value_is_exposed_without_sink() {
        let facts = collect_call_facts(r#"$body = "python(" + "\"print('ok')\"" + ")";"#);
        assert_eq!(facts.sink_arg_facts.len(), 0);
        assert!(!facts.code_like_value_facts.is_empty());
        assert!(
            facts
                .code_like_value_facts
                .iter()
                .any(|fact| fact.rendered_text.as_ref() == r#"python("print('ok')")"#)
        );
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
    fn expression_mode_parses_direct_attribute_assignment_without_command_diagnostics() {
        let facts = collect_expression_call_facts("ExampleNode.translateX = frame;");
        assert!(facts.diagnostics.is_empty());
        assert!(facts.calls.is_empty());
    }

    #[test]
    fn expression_mode_parses_current_node_attribute_assignment_without_command_diagnostics() {
        let facts = collect_expression_call_facts(".exampleAttr[0] = frame;");
        assert!(facts.diagnostics.is_empty());
        assert!(facts.calls.is_empty());
    }

    #[test]
    fn expression_mode_parses_current_node_attribute_conditionals() {
        let facts = collect_expression_call_facts(
            "if (.exampleAttr[0] > 0) { .otherAttr[0] = 1; } else { .otherAttr[0] = 0; }",
        );
        assert!(facts.diagnostics.is_empty());
        assert!(facts.calls.is_empty());
    }

    #[test]
    fn expression_mode_still_collects_sink_calls() {
        let facts = collect_expression_call_facts(r#"python("import os");"#);
        assert!(facts.diagnostics.is_empty());
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].name.as_ref(), "python");
        assert!(
            facts
                .sink_arg_facts
                .iter()
                .any(|fact| fact.sink_kind == MelSinkArgKind::Python)
        );
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
        assert_eq!(shared.sink_arg_facts, borrowed.sink_arg_facts);
        assert_eq!(shared.code_like_value_facts, borrowed.code_like_value_facts);
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
