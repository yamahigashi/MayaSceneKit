use std::{fmt, sync::OnceLock};

use maya_scene_kit_formats::mel::MelParseBudget;
use regex::Regex;
use rustpython_parser::{Parse, ast};

use super::python_walk::{
    PythonAstVisitor, PythonBody, PythonScope, PythonWalkPoint,
    bindings::{BodyBindings, enter_body_bindings, leave_body_bindings},
    walk_expr, walk_stmt, walk_suite,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonParseBudgetLimit {
    MaxBodyBytes,
    MaxNestingDepth,
}

impl fmt::Display for PythonParseBudgetLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MaxBodyBytes => "python_max_body_bytes",
            Self::MaxNestingDepth => "python_max_nesting_depth",
        })
    }
}

#[doc(hidden)]
pub fn with_python_analysis<T: Send>(source: &str, analyze: impl FnOnce(&str) -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("python-analysis".to_string())
            .stack_size(64 * 1024 * 1024)
            .spawn_scoped(scope, move || analyze(source))
            .expect("create Python analysis thread")
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

pub fn check_python_parse_budget(source: &str) -> Result<(), PythonParseBudgetLimit> {
    check_python_parse_budget_with_max_bytes(source, MelParseBudget::default().max_bytes)
}

/// Checks Python parsing limits using the byte limit of the originating observation.
pub fn check_python_parse_budget_with_max_bytes(
    source: &str,
    max_bytes: usize,
) -> Result<(), PythonParseBudgetLimit> {
    if source.len() > max_bytes {
        return Err(PythonParseBudgetLimit::MaxBodyBytes);
    }
    let mut pending = vec![(std::borrow::Cow::Borrowed(source), 0)];
    if source.lines().any(|line| {
        let line = line.trim_start();
        ["print ", "exec ", "raise ", "except "]
            .iter()
            .any(|prefix| line.starts_with(prefix))
    }) {
        let normalized = normalize_python_compat_source(source);
        if normalized != source {
            if normalized.len() > max_bytes {
                return Err(PythonParseBudgetLimit::MaxBodyBytes);
            }
            pending.push((std::borrow::Cow::Owned(normalized), 0));
        }
    }
    while let Some((source, base)) = pending.pop() {
        check_python_nesting(&source, base, &mut pending)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct PythonDepthFrame {
    base: usize,
    current: usize,
    peak: usize,
    lambda_parameters: usize,
}

impl PythonDepthFrame {
    fn new(base: usize) -> Self {
        Self {
            base,
            current: base,
            peak: base,
            lambda_parameters: 0,
        }
    }
}

fn check_python_nesting(
    source: &str,
    base: usize,
    pending: &mut Vec<(std::borrow::Cow<'_, str>, usize)>,
) -> Result<(), PythonParseBudgetLimit> {
    use rustpython_parser::{Mode, Tok, lexer};

    let limit = MelParseBudget::DEFAULT_MAX_PYTHON_NESTING_DEPTH;
    let mut indentation = vec![base];
    let mut conditional_chains = vec![0usize];
    let mut expression = vec![PythonDepthFrame::new(base)];
    let mut header_depth = base;
    let mut line_start = true;
    // Expression peaks are retained through closing brackets, but siblings share their base.
    // This conservatively bounds AST chains without parsing them recursively first.
    for token in lexer::lex(source, Mode::Module) {
        let Ok((token, _)) = token else { break };
        match token {
            Tok::Indent => {
                let depth = header_depth + 1;
                indentation.push(depth);
                conditional_chains.push(0);
                expression = vec![PythonDepthFrame::new(depth)];
            }
            Tok::Dedent => {
                if indentation.len() > 1 {
                    indentation.pop();
                    conditional_chains.pop();
                }
                expression = vec![PythonDepthFrame::new(*indentation.last().unwrap())];
                line_start = true;
            }
            Tok::Newline => {
                header_depth = expression.last().unwrap().peak;
                expression = vec![PythonDepthFrame::new(*indentation.last().unwrap())];
                line_start = true;
            }
            Tok::Semi => {
                expression = vec![PythonDepthFrame::new(
                    indentation.last().unwrap() + conditional_chains.last().unwrap(),
                )];
            }
            Tok::EndOfFile => break,
            token => {
                let leading = line_start;
                if leading {
                    line_start = false;
                    let chain = conditional_chains.last_mut().unwrap();
                    match token {
                        Tok::If => *chain = 1,
                        Tok::Elif => *chain += 1,
                        Tok::Else => {}
                        _ => *chain = 0,
                    }
                    expression = vec![PythonDepthFrame::new(indentation.last().unwrap() + *chain)];
                }
                match token {
                    Tok::Lpar | Tok::Lsqb | Tok::Lbrace => {
                        let depth = expression.last().unwrap().current + 1;
                        expression.push(PythonDepthFrame::new(depth));
                    }
                    Tok::Rpar | Tok::Rsqb | Tok::Rbrace => {
                        if expression.len() > 1 {
                            let child = expression.pop().unwrap();
                            expression.last_mut().unwrap().current = child.peak;
                        }
                    }
                    Tok::Comma => {
                        let frame = expression.last_mut().unwrap();
                        if frame.lambda_parameters == 0 {
                            frame.current = frame.base;
                        }
                    }
                    Tok::Lambda => {
                        let frame = expression.last_mut().unwrap();
                        frame.current += 1;
                        frame.lambda_parameters += 1;
                    }
                    Tok::Colon => {
                        let frame = expression.last_mut().unwrap();
                        frame.lambda_parameters = frame.lambda_parameters.saturating_sub(1);
                    }
                    Tok::String { value, kind, .. } if kind.is_any_fstring() => {
                        let depth = expression.last().unwrap().current + 2;
                        let mut start = 0;
                        while start < value.len() {
                            let Some(offset) = value[start..].find('{') else {
                                break;
                            };
                            start += offset + 1;
                            if value.as_bytes().get(start) == Some(&b'{') {
                                start += 1;
                                continue;
                            }
                            let mut scanner = PythonSourceScanner::default();
                            let Some(end) = scanner
                                .scan(&value[start..], |_, ch, depth| ch == b'}' && depth == 0)
                            else {
                                break;
                            };
                            pending.push((
                                std::borrow::Cow::Owned(value[start..start + end].to_string()),
                                depth,
                            ));
                            start += end + 1;
                        }
                    }
                    Tok::Plus
                    | Tok::Minus
                    | Tok::Star
                    | Tok::Slash
                    | Tok::Vbar
                    | Tok::Amper
                    | Tok::Less
                    | Tok::Greater
                    | Tok::Equal
                    | Tok::Dot
                    | Tok::Percent
                    | Tok::EqEqual
                    | Tok::NotEqual
                    | Tok::LessEqual
                    | Tok::GreaterEqual
                    | Tok::Tilde
                    | Tok::CircumFlex
                    | Tok::LeftShift
                    | Tok::RightShift
                    | Tok::DoubleStar
                    | Tok::DoubleSlash
                    | Tok::ColonEqual
                    | Tok::At
                    | Tok::And
                    | Tok::Or
                    | Tok::Not
                    | Tok::Await
                    | Tok::Yield
                    | Tok::For => expression.last_mut().unwrap().current += 1,
                    Tok::If | Tok::Else if !leading => expression.last_mut().unwrap().current += 1,
                    _ => {}
                }
            }
        }
        let frame = expression.last_mut().unwrap();
        frame.peak = frame.peak.max(frame.current);
        if frame.peak > limit {
            return Err(PythonParseBudgetLimit::MaxNestingDepth);
        }
    }
    Ok(())
}

pub(crate) fn parse_python_compat_suite(source: &str, max_bytes: usize) -> Option<ast::Suite> {
    check_python_parse_budget_with_max_bytes(source, max_bytes).ok()?;
    ast::Suite::parse(source, "<observe>").ok().or_else(|| {
        let normalized = normalize_python_compat_source(source);
        ast::Suite::parse(&normalized, "<observe>").ok()
    })
}

pub(crate) fn collect_static_maya_mel_eval_payloads(source: &str, max_bytes: usize) -> Vec<String> {
    with_python_analysis(source, |source| {
        let Some(program) = parse_python_compat_suite(source, max_bytes) else {
            return Vec::new();
        };
        let mut visitor = MayaMelEvalVisitor::for_body(&program);
        walk_suite(&mut visitor, &program);
        visitor.payloads
    })
}

pub fn normalize_python_compat_source(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut scanner = PythonSourceScanner::default();
    for line in source.split_inclusive('\n') {
        let (content, newline) = line
            .strip_suffix('\n')
            .map(|content| (content, "\n"))
            .unwrap_or((line, ""));
        let starts_in_string = scanner.quote.is_some();
        let comment_start = scanner.scan(line, |_, ch, _| ch == b'#');
        if starts_in_string || scanner.quote.is_some() {
            out.push_str(content);
        } else {
            let (code, comment) = content.split_at(comment_start.unwrap_or(content.len()));
            out.push_str(&normalize_python_compat_line(code, comment));
        }
        out.push_str(newline);
    }
    out
}

fn normalize_python_compat_line(code: &str, comment: &str) -> String {
    let indent_len = code.len() - code.trim_start_matches([' ', '\t']).len();
    let indent = &code[..indent_len];
    let trimmed = &code[indent_len..];

    if trimmed == "print" {
        return format!("{indent}print(){comment}");
    }
    if let Some(rest) = trimmed.strip_prefix("print ")
        && !rest.starts_with('(')
        && !rest.starts_with(">>")
    {
        return format!("{indent}print({rest}){comment}");
    }
    if let Some(rest) = trimmed.strip_prefix("exec ")
        && !rest.starts_with('(')
    {
        return format!(
            "{indent}exec({}){comment}",
            normalize_python2_exec_args(rest)
        );
    }
    if let Some(normalized) = normalize_python2_except_clause(trimmed) {
        return format!("{indent}{normalized}{comment}");
    }
    if let Some(rest) = trimmed.strip_prefix("raise ")
        && let Some(normalized) = normalize_python2_raise(rest)
    {
        return format!("{indent}{normalized}{comment}");
    }

    format!("{code}{comment}")
}

#[derive(Default)]
struct PythonSourceScanner {
    quote: Option<(u8, bool)>,
    escape: bool,
    depth: usize,
}

impl PythonSourceScanner {
    fn scan(
        &mut self,
        text: &str,
        mut matches: impl FnMut(usize, u8, usize) -> bool,
    ) -> Option<usize> {
        let bytes = text.as_bytes();
        let mut idx = 0;
        while idx < bytes.len() {
            let ch = bytes[idx];
            if self.escape {
                self.escape = false;
            } else if let Some((quote, triple)) = self.quote {
                if ch == b'\\' {
                    self.escape = true;
                } else if ch == quote && (!triple || bytes.get(idx..idx + 3) == Some(&[quote; 3])) {
                    self.quote = None;
                    if triple {
                        idx += 2;
                    }
                }
            } else {
                match ch {
                    b'\'' | b'"' => {
                        let triple = bytes.get(idx..idx + 3) == Some(&[ch; 3]);
                        self.quote = Some((ch, triple));
                        if triple {
                            idx += 2;
                        }
                    }
                    _ => {
                        if matches(idx, ch, self.depth) {
                            return Some(idx);
                        }
                        match ch {
                            b'#' => return None,
                            b'(' | b'[' | b'{' => self.depth += 1,
                            b')' | b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                            _ => {}
                        }
                    }
                }
            }
            idx += 1;
        }
        None
    }
}

fn normalize_python2_except_clause(trimmed: &str) -> Option<String> {
    static EXCEPT_RE: OnceLock<Regex> = OnceLock::new();
    let captures = EXCEPT_RE
        .get_or_init(|| {
            Regex::new(
                r"^except\s+([A-Za-z_][A-Za-z0-9_\.]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*:(.*)$",
            )
            .expect("valid except regex")
        })
        .captures(trimmed)?;
    Some(format!(
        "except {} as {}:{}",
        captures.get(1)?.as_str(),
        captures.get(2)?.as_str(),
        captures.get(3)?.as_str()
    ))
}

fn normalize_python2_raise(rest: &str) -> Option<String> {
    let parts = split_top_level_commas(rest);
    if parts.len() < 2 || parts[0].trim_start().starts_with('(') {
        return None;
    }
    Some(format!("raise {}({})", parts[0].trim(), parts[1].trim()))
}

fn normalize_python2_exec_args(rest: &str) -> String {
    if let Some(idx) = find_top_level_keyword(rest, " in ") {
        let body = rest[..idx].trim();
        let scopes = split_top_level_commas(rest[idx + 4..].trim());
        match scopes.as_slice() {
            [globals] => format!("{body}, {}", globals.trim()),
            [globals, locals, ..] => {
                format!("{body}, {}, {}", globals.trim(), locals.trim())
            }
            _ => body.to_string(),
        }
    } else {
        rest.trim().to_string()
    }
}

fn split_top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    PythonSourceScanner::default().scan(text, |idx, ch, depth| {
        if ch == b',' && depth == 0 {
            parts.push(&text[start..idx]);
            start = idx + 1;
        }
        false
    });
    parts.push(&text[start..]);
    parts
}

fn find_top_level_keyword(text: &str, needle: &str) -> Option<usize> {
    PythonSourceScanner::default().scan(text, |idx, ch, depth| {
        depth == 0 && ch == needle.as_bytes()[0] && text[idx..].starts_with(needle)
    })
}

mod callable_bindings;
use callable_bindings::CallableBindings;

#[derive(Default)]
struct MayaMelEvalVisitor {
    callable_bindings: CallableBindings,
    module_aliases: BodyBindings,
    string_values: BodyBindings,
    payloads: Vec<String>,
}

impl PythonAstVisitor for MayaMelEvalVisitor {
    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        self.record_statement(stmt);
        walk_stmt(self, stmt);
        self.record_assignment(stmt);
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        if let ast::Expr::Call(call) = expr {
            self.record_call(call);
        }
        walk_expr(self, expr);
    }

    fn at_point(&mut self, point: PythonWalkPoint<'_>) {
        match point {
            PythonWalkPoint::AfterForIter(target) | PythonWalkPoint::AfterDeleteTarget(target) => {
                self.clear_string_target(target);
            }
            PythonWalkPoint::AfterWithVars(item) => {
                if let Some(target) = &item.optional_vars {
                    self.clear_string_target(target);
                }
            }
            PythonWalkPoint::BeforeHandlerBody(_) | PythonWalkPoint::AfterComprehensionIter(_) => {}
        }
    }

    fn enter_scope(&mut self, scope: PythonScope<'_>) {
        self.callable_bindings.enter_scope(scope);
    }

    fn leave_scope(&mut self, _scope: PythonScope<'_>) {
        self.callable_bindings.leave_scope();
    }

    fn enter_body(&mut self, body: PythonBody<'_>) {
        enter_body_bindings(body, &mut self.module_aliases, &mut self.string_values);
    }

    fn leave_body(&mut self, _body: PythonBody<'_>) {
        leave_body_bindings(&mut self.module_aliases, &mut self.string_values, false);
    }
}

impl MayaMelEvalVisitor {
    fn for_body(body: &[ast::Stmt]) -> Self {
        Self {
            callable_bindings: CallableBindings::for_body(body),
            ..Self::default()
        }
    }

    fn record_statement(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::Import(import) => {
                for alias in &import.names {
                    self.record_module_import_alias(alias.name.as_str(), alias.asname.as_ref());
                }
            }
            ast::Stmt::ImportFrom(import) => {
                if let Some(module) = &import.module {
                    for alias in &import.names {
                        self.record_import_from_alias(
                            module.as_str(),
                            alias.name.as_str(),
                            alias.asname.as_ref(),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn record_assignment(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::Assign(stmt) => {
                let value = static_string_expr(&stmt.value, &self.string_values);
                for target in &stmt.targets {
                    self.record_string_target(target, value.clone());
                }
            }
            ast::Stmt::AnnAssign(stmt) => {
                if let Some(value_expr) = &stmt.value {
                    self.record_string_target(
                        &stmt.target,
                        static_string_expr(value_expr, &self.string_values),
                    );
                } else {
                    self.clear_string_target(&stmt.target);
                }
            }
            ast::Stmt::AugAssign(stmt) => {
                self.clear_string_target(&stmt.target);
            }
            _ => {}
        }
    }

    fn record_call(&mut self, call: &ast::ExprCall) {
        if (is_maya_mel_eval_call(&call.func, &self.module_aliases)
            || self.callable_bindings.is_eval_alias(&call.func))
            && let Some(payload) = call
                .args
                .first()
                .and_then(|arg| static_string_expr(arg, &self.string_values))
        {
            self.payloads.push(payload);
        }
    }

    fn record_module_import_alias(
        &mut self,
        module_name: &str,
        asname: Option<&rustpython_parser::ast::Identifier>,
    ) {
        let local_name = asname.map(ToString::to_string).unwrap_or_else(|| {
            module_name
                .split('.')
                .next()
                .unwrap_or(module_name)
                .to_string()
        });
        self.module_aliases
            .insert(local_name, Some(module_name.to_string()));
    }

    fn record_import_from_alias(
        &mut self,
        module_name: &str,
        imported_name: &str,
        asname: Option<&rustpython_parser::ast::Identifier>,
    ) {
        let local_name = asname
            .map(ToString::to_string)
            .unwrap_or_else(|| imported_name.to_string());
        self.module_aliases
            .insert(local_name, Some(format!("{module_name}.{imported_name}")));
    }

    fn record_string_target(&mut self, target: &ast::Expr, value: Option<String>) {
        match target {
            ast::Expr::Name(name) => {
                self.string_values.insert(name.id.to_string(), value);
            }
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.clear_string_target(elt);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.clear_string_target(elt);
                }
            }
            ast::Expr::Starred(expr) => self.clear_string_target(&expr.value),
            _ => {}
        }
    }

    fn clear_string_target(&mut self, target: &ast::Expr) {
        match target {
            ast::Expr::Name(name) => {
                self.string_values.insert(name.id.to_string(), None);
            }
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.clear_string_target(elt);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.clear_string_target(elt);
                }
            }
            ast::Expr::Starred(expr) => self.clear_string_target(&expr.value),
            _ => {}
        }
    }
}

pub(crate) fn is_maya_mel_eval_call(
    func: &ast::Expr,
    module_aliases: &std::collections::HashMap<String, Option<String>>,
) -> bool {
    let ast::Expr::Attribute(attr) = func else {
        return false;
    };
    if attr.attr.as_str() != "eval" {
        return false;
    }
    module_name_for_expr(&attr.value, module_aliases)
        .is_some_and(|module| is_maya_mel_module(&module))
}

fn is_maya_mel_module(module: &str) -> bool {
    module == "maya.mel" || module.ends_with(".maya.mel") || module == "mel"
}

fn module_name_for_expr(
    expr: &ast::Expr,
    module_aliases: &std::collections::HashMap<String, Option<String>>,
) -> Option<String> {
    match expr {
        ast::Expr::Name(name) => module_aliases.get(name.id.as_str()).cloned().flatten(),
        ast::Expr::Attribute(attr) => {
            let mut base = module_name_for_expr(&attr.value, module_aliases)?;
            base.push('.');
            base.push_str(attr.attr.as_str());
            Some(base)
        }
        _ => None,
    }
}

pub(crate) fn static_string_expr(
    expr: &ast::Expr,
    string_values: &std::collections::HashMap<String, Option<String>>,
) -> Option<String> {
    match expr {
        ast::Expr::Constant(ast::ExprConstant {
            value: ast::Constant::Str(value),
            ..
        }) => Some(value.to_string()),
        ast::Expr::Name(name) => string_values.get(name.id.as_str()).cloned().flatten(),
        ast::Expr::BinOp(expr) => {
            let left = static_string_expr(&expr.left, string_values)?;
            let right = static_string_expr(&expr.right, string_values)?;
            Some(format!("{left}{right}"))
        }
        _ => None,
    }
}

#[cfg(test)]
pub(super) mod tests {
    use rustpython_parser::{Parse, ast};

    use super::{collect_static_maya_mel_eval_payloads, normalize_python_compat_source};

    pub(in crate::scene::execution) fn collect_payloads_from_suite(
        program: &[ast::Stmt],
    ) -> Vec<String> {
        let mut visitor = super::MayaMelEvalVisitor::for_body(program);
        super::walk_suite(&mut visitor, program);
        visitor.payloads
    }

    #[test]
    fn python_collectors_use_the_supplied_byte_budget() {
        let source = "import maya.mel as mm\nmm.eval('print 1;')";
        assert!(super::parse_python_compat_suite(source, 8).is_none());
        assert!(super::collect_static_maya_mel_eval_payloads(source, 8).is_empty());
        assert!(super::parse_python_compat_suite(source, 128).is_some());
        assert_eq!(
            super::collect_static_maya_mel_eval_payloads(source, 128),
            ["print 1;"]
        );
    }

    #[test]
    fn collects_imported_mel_callable_names() {
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                "from maya.mel import eval as run\nrun('system(\"Example\");')",
                crate::scene::MelParseBudget::default().max_bytes
            ),
            ["system(\"Example\");"]
        );
    }

    #[test]
    fn collects_bare_imported_mel_callable_names() {
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                "from maya.mel import eval\neval('system(\"Example\");')",
                crate::scene::MelParseBudget::default().max_bytes
            ),
            ["system(\"Example\");"]
        );
    }

    #[test]
    fn collects_single_assignment_mel_callable_names() {
        for source in [
            "import maya.mel as mm\nrun = mm.eval\nrun('system(\"Example\");')",
            "from maya import mel as mm\nrun = mm.eval\nrun('system(\"Example\");')",
            "from maya import mel\nrun = mel.eval\nrun('system(\"Example\");')",
            "from maya.mel import eval\nrun = eval\nrun('system(\"Example\");')",
            "def Example():\n    from maya.mel import eval as run\n    run('system(\"Example\");')",
        ] {
            assert_eq!(
                collect_static_maya_mel_eval_payloads(
                    source,
                    crate::scene::MelParseBudget::default().max_bytes
                ),
                ["system(\"Example\");"]
            );
        }
        for source in [
            "from maya.mel import eval as run\nrun = Example\nrun('system(\"Example\");')",
            "if Example:\n    from maya.mel import eval as run\nrun('system(\"Example\");')",
            "from maya.mel import eval as run\nfor run in Example:\n    run('system(\"Example\");')",
            "from maya.mel import eval as run\nwith Example as run:\n    run('system(\"Example\");')",
            "from maya.mel import eval as run\ndel run\nrun('system(\"Example\");')",
        ] {
            assert_eq!(
                collect_static_maya_mel_eval_payloads(
                    source,
                    crate::scene::MelParseBudget::default().max_bytes
                ),
                ["system(\"Example\");"],
                "{source}"
            );
        }
        assert!(collect_static_maya_mel_eval_payloads("from maya.mel import eval as run\ndef Example(run):\n    run('system(\"Example\");')", crate::scene::MelParseBudget::default().max_bytes).is_empty());
    }

    #[test]
    fn collects_may_alias_try_body() {
        assert_eq!(collect_static_maya_mel_eval_payloads("try:\n    from maya.mel import eval as run\n    run('system(\"Example\");')\nexcept Exception:\n    pass", crate::scene::MelParseBudget::default().max_bytes).len(), 1);
    }

    #[test]
    fn collects_may_alias_conditional_body() {
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                "if Example:\n    from maya.mel import eval as run\n    run('system(\"Example\");')", crate::scene::MelParseBudget::default().max_bytes
            )
            .len(),
            1
        );
    }

    #[test]
    fn collects_may_alias_comprehension() {
        assert_eq!(collect_static_maya_mel_eval_payloads("from maya.mel import eval as run\n[run('system(\"Example\");') for item in Example]", crate::scene::MelParseBudget::default().max_bytes).len(), 1);
    }

    #[test]
    fn collects_may_alias_generator() {
        assert_eq!(collect_static_maya_mel_eval_payloads("from maya.mel import eval as run\n(run('system(\"Example\");') for item in Example)", crate::scene::MelParseBudget::default().max_bytes).len(), 1);
    }

    #[test]
    fn collects_may_alias_rebound_name() {
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                "import maya.mel as mm\nrun = mm.eval\nrun('system(\"Example\");')\nrun = print",
                crate::scene::MelParseBudget::default().max_bytes
            )
            .len(),
            1
        );
    }

    #[test]
    fn collects_may_alias_class_local_method() {
        assert_eq!(collect_static_maya_mel_eval_payloads("class Example:\n    from maya.mel import eval as run\n    def method(self):\n        run('system(\"Example\");')", crate::scene::MelParseBudget::default().max_bytes).len(), 0);
    }

    #[test]
    fn collects_may_alias_class_attribute_shadow() {
        assert_eq!(collect_static_maya_mel_eval_payloads("from maya.mel import eval as run\nclass Example:\n    run = print\n    def method(self):\n        run('system(\"Example\");')", crate::scene::MelParseBudget::default().max_bytes).len(), 1);
    }

    #[test]
    fn collects_may_alias_later_outer_binding() {
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                "def Example():\n    run('system(\"Example\");')\nfrom maya.mel import eval as run",
                crate::scene::MelParseBudget::default().max_bytes
            )
            .len(),
            1
        );
    }

    #[test]
    fn collects_may_alias_shared_import_root() {
        assert_eq!(collect_static_maya_mel_eval_payloads("import maya.cmds\nimport maya.mel\nrun = maya.mel.eval\nrun('system(\"Example\");')", crate::scene::MelParseBudget::default().max_bytes).len(), 1);
    }

    #[test]
    fn collects_may_alias_mel_module() {
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                "import mel\nrun = mel.eval\nrun('system(\"Example\");')",
                crate::scene::MelParseBudget::default().max_bytes
            )
            .len(),
            1
        );
    }

    #[test]
    fn collects_may_alias_nested_mel_module() {
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                "import Example.maya.mel as mm\nrun = mm.eval\nrun('system(\"Example\");')",
                crate::scene::MelParseBudget::default().max_bytes
            )
            .len(),
            1
        );
    }

    #[test]
    fn preserves_python2_statements_inside_triple_quoted_strings() {
        for quote in ["\"\"\"", "'''"] {
            let source =
                format!("Example = {quote}\nprint x\nexec y\nraise z, Sample\n{quote}\nprint x\n");
            let expected =
                format!("Example = {quote}\nprint x\nexec y\nraise z, Sample\n{quote}\nprint(x)\n");
            assert_eq!(normalize_python_compat_source(&source), expected);
        }
    }

    #[test]
    fn normalizes_python2_print_statements() {
        let normalized =
            normalize_python_compat_source("print 'start ExampleScriptNode'\nprint u'done'\n");
        ast::Suite::parse(&normalized, "<test>").expect("normalized python");
    }

    #[test]
    fn normalizes_python2_exec_statement() {
        let normalized = normalize_python_compat_source("exec 'print(1)'\n");
        assert!(normalized.contains("exec('print(1)')"));
        ast::Suite::parse(&normalized, "<test>").expect("normalized python");
    }

    #[test]
    fn normalizes_python2_except_and_raise() {
        let normalized = normalize_python_compat_source(
            "try:\n    pass\nexcept RuntimeError, err:\n    raise ValueError, err\n",
        );
        ast::Suite::parse(&normalized, "<test>").expect("normalized python");
    }

    #[test]
    fn collects_static_maya_mel_eval_payload_from_alias() {
        let payloads = collect_static_maya_mel_eval_payloads(
            "import maya.mel as mm\ncmd = 'set' + 'Project \"asset/example\";'\nmm.eval(cmd)\n",
            crate::scene::MelParseBudget::default().max_bytes,
        );
        assert_eq!(payloads, vec!["setProject \"asset/example\";"]);
    }

    #[test]
    fn ignores_dynamic_maya_mel_eval_payload() {
        let payloads = collect_static_maya_mel_eval_payloads(
            "import maya.mel as mm\nmm.eval(build_command())\n",
            crate::scene::MelParseBudget::default().max_bytes,
        );
        assert!(payloads.is_empty());
    }
}
