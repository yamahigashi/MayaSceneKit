use std::sync::OnceLock;

use regex::Regex;
use rustpython_parser::{Parse, ast};

pub(crate) fn parse_python_compat_suite(source: &str) -> Option<ast::Suite> {
    ast::Suite::parse(source, "<observe>").ok().or_else(|| {
        let normalized = normalize_python_compat_source(source);
        ast::Suite::parse(&normalized, "<observe>").ok()
    })
}

pub(crate) fn collect_static_maya_mel_eval_payloads(source: &str) -> Vec<String> {
    let Some(program) = parse_python_compat_suite(source) else {
        return Vec::new();
    };
    let mut visitor = MayaMelEvalVisitor::default();
    visitor.visit_suite(&program);
    visitor.payloads
}

pub fn normalize_python_compat_source(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        let (content, newline) = line
            .strip_suffix('\n')
            .map(|content| (content, "\n"))
            .unwrap_or((line, ""));
        out.push_str(&normalize_python_compat_line(content));
        out.push_str(newline);
    }
    out
}

fn normalize_python_compat_line(line: &str) -> String {
    let (code, comment) = split_code_and_comment(line);
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

    line.to_string()
}

fn split_code_and_comment(line: &str) -> (&str, &str) {
    let mut quote = None;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match quote {
            Some(active) => {
                if ch == '\\' {
                    escape = true;
                } else if ch == active {
                    quote = None;
                }
            }
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '#' => return (&line[..idx], &line[idx..]),
                _ => {}
            },
        }
    }
    (line, "")
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
    let mut quote = None;
    let mut escape = false;
    let mut depth = 0usize;
    let mut start = 0usize;

    for (idx, ch) in text.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match quote {
            Some(active) => {
                if ch == '\\' {
                    escape = true;
                } else if ch == active {
                    quote = None;
                }
            }
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    parts.push(&text[start..idx]);
                    start = idx + 1;
                }
                _ => {}
            },
        }
    }

    parts.push(&text[start..]);
    parts
}

fn find_top_level_keyword(text: &str, needle: &str) -> Option<usize> {
    let mut quote = None;
    let mut escape = false;
    let mut depth = 0usize;

    for (idx, ch) in text.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match quote {
            Some(active) => {
                if ch == '\\' {
                    escape = true;
                } else if ch == active {
                    quote = None;
                }
            }
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                _ if depth == 0 && text[idx..].starts_with(needle) => return Some(idx),
                _ => {}
            },
        }
    }

    None
}

#[derive(Default)]
struct MayaMelEvalVisitor {
    module_aliases: std::collections::HashMap<String, String>,
    string_values: std::collections::HashMap<String, Option<String>>,
    payloads: Vec<String>,
}

impl MayaMelEvalVisitor {
    fn visit_suite(&mut self, suite: &ast::Suite) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
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
            ast::Stmt::FunctionDef(function) => self.visit_suite(&function.body),
            ast::Stmt::AsyncFunctionDef(function) => self.visit_suite(&function.body),
            ast::Stmt::ClassDef(class_def) => self.visit_suite(&class_def.body),
            ast::Stmt::For(stmt) => {
                self.visit_expr(&stmt.iter);
                self.clear_string_target(&stmt.target);
                self.visit_suite(&stmt.body);
                self.visit_suite(&stmt.orelse);
            }
            ast::Stmt::AsyncFor(stmt) => {
                self.visit_expr(&stmt.iter);
                self.clear_string_target(&stmt.target);
                self.visit_suite(&stmt.body);
                self.visit_suite(&stmt.orelse);
            }
            ast::Stmt::While(stmt) => {
                self.visit_expr(&stmt.test);
                self.visit_suite(&stmt.body);
                self.visit_suite(&stmt.orelse);
            }
            ast::Stmt::If(stmt) => {
                self.visit_expr(&stmt.test);
                self.visit_suite(&stmt.body);
                self.visit_suite(&stmt.orelse);
            }
            ast::Stmt::With(stmt) => {
                for item in &stmt.items {
                    self.visit_expr(&item.context_expr);
                    if let Some(vars) = &item.optional_vars {
                        self.clear_string_target(vars);
                    }
                }
                self.visit_suite(&stmt.body);
            }
            ast::Stmt::AsyncWith(stmt) => {
                for item in &stmt.items {
                    self.visit_expr(&item.context_expr);
                    if let Some(vars) = &item.optional_vars {
                        self.clear_string_target(vars);
                    }
                }
                self.visit_suite(&stmt.body);
            }
            ast::Stmt::Try(stmt) => {
                self.visit_suite(&stmt.body);
                for handler in &stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    self.visit_suite(&handler.body);
                }
                self.visit_suite(&stmt.orelse);
                self.visit_suite(&stmt.finalbody);
            }
            ast::Stmt::Assign(stmt) => {
                self.visit_expr(&stmt.value);
                let value = static_string_expr(&stmt.value, &self.string_values);
                for target in &stmt.targets {
                    self.record_string_target(target, value.clone());
                }
            }
            ast::Stmt::AnnAssign(stmt) => {
                if let Some(value_expr) = &stmt.value {
                    self.visit_expr(value_expr);
                    self.record_string_target(
                        &stmt.target,
                        static_string_expr(value_expr, &self.string_values),
                    );
                } else {
                    self.clear_string_target(&stmt.target);
                }
            }
            ast::Stmt::AugAssign(stmt) => {
                self.visit_expr(&stmt.value);
                self.clear_string_target(&stmt.target);
            }
            ast::Stmt::Expr(stmt) => self.visit_expr(&stmt.value),
            ast::Stmt::Return(stmt) => {
                if let Some(expr) = &stmt.value {
                    self.visit_expr(expr);
                }
            }
            ast::Stmt::Delete(stmt) => {
                for target in &stmt.targets {
                    self.clear_string_target(target);
                }
            }
            ast::Stmt::Assert(stmt) => {
                self.visit_expr(&stmt.test);
                if let Some(expr) = &stmt.msg {
                    self.visit_expr(expr);
                }
            }
            ast::Stmt::Raise(stmt) => {
                if let Some(expr) = &stmt.exc {
                    self.visit_expr(expr);
                }
            }
            ast::Stmt::Global(_)
            | ast::Stmt::Nonlocal(_)
            | ast::Stmt::Pass(_)
            | ast::Stmt::Break(_)
            | ast::Stmt::Continue(_)
            | ast::Stmt::TypeAlias(_)
            | ast::Stmt::Match(_)
            | ast::Stmt::TryStar(_) => {}
        }
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        match expr {
            ast::Expr::Call(call) => {
                if is_maya_mel_eval_call(&call.func, &self.module_aliases)
                    && let Some(payload) = call
                        .args
                        .first()
                        .and_then(|arg| static_string_expr(arg, &self.string_values))
                {
                    self.payloads.push(payload);
                }
                self.visit_expr(&call.func);
                for arg in &call.args {
                    self.visit_expr(arg);
                }
                for keyword in &call.keywords {
                    self.visit_expr(&keyword.value);
                }
            }
            ast::Expr::BoolOp(expr) => {
                for value in &expr.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::NamedExpr(expr) => {
                self.visit_expr(&expr.target);
                self.visit_expr(&expr.value);
            }
            ast::Expr::BinOp(expr) => {
                self.visit_expr(&expr.left);
                self.visit_expr(&expr.right);
            }
            ast::Expr::UnaryOp(expr) => self.visit_expr(&expr.operand),
            ast::Expr::Lambda(expr) => self.visit_expr(&expr.body),
            ast::Expr::IfExp(expr) => {
                self.visit_expr(&expr.test);
                self.visit_expr(&expr.body);
                self.visit_expr(&expr.orelse);
            }
            ast::Expr::Dict(expr) => {
                for key in expr.keys.iter().flatten() {
                    self.visit_expr(key);
                }
                for value in &expr.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::Set(expr) => {
                for elt in &expr.elts {
                    self.visit_expr(elt);
                }
            }
            ast::Expr::ListComp(expr) => self.visit_expr(&expr.elt),
            ast::Expr::SetComp(expr) => self.visit_expr(&expr.elt),
            ast::Expr::DictComp(expr) => {
                self.visit_expr(&expr.key);
                self.visit_expr(&expr.value);
            }
            ast::Expr::GeneratorExp(expr) => self.visit_expr(&expr.elt),
            ast::Expr::Await(expr) => self.visit_expr(&expr.value),
            ast::Expr::Yield(expr) => {
                if let Some(value) = &expr.value {
                    self.visit_expr(value);
                }
            }
            ast::Expr::YieldFrom(expr) => self.visit_expr(&expr.value),
            ast::Expr::Compare(expr) => {
                self.visit_expr(&expr.left);
                for comparator in &expr.comparators {
                    self.visit_expr(comparator);
                }
            }
            ast::Expr::Attribute(expr) => self.visit_expr(&expr.value),
            ast::Expr::Subscript(expr) => {
                self.visit_expr(&expr.value);
                self.visit_expr(&expr.slice);
            }
            ast::Expr::Starred(expr) => self.visit_expr(&expr.value),
            ast::Expr::Slice(expr) => {
                if let Some(lower) = &expr.lower {
                    self.visit_expr(lower);
                }
                if let Some(upper) = &expr.upper {
                    self.visit_expr(upper);
                }
                if let Some(step) = &expr.step {
                    self.visit_expr(step);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.visit_expr(elt);
                }
            }
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.visit_expr(elt);
                }
            }
            _ => {}
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
            .insert(local_name, module_name.to_string());
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
            .insert(local_name, format!("{module_name}.{imported_name}"));
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
                self.string_values.remove(name.id.as_str());
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
    module_aliases: &std::collections::HashMap<String, String>,
) -> bool {
    let ast::Expr::Attribute(attr) = func else {
        return false;
    };
    if attr.attr.as_str() != "eval" {
        return false;
    }
    module_name_for_expr(&attr.value, module_aliases).is_some_and(|module| {
        module == "maya.mel" || module.ends_with(".maya.mel") || module == "mel"
    })
}

fn module_name_for_expr(
    expr: &ast::Expr,
    module_aliases: &std::collections::HashMap<String, String>,
) -> Option<String> {
    match expr {
        ast::Expr::Name(name) => module_aliases.get(name.id.as_str()).cloned(),
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
mod tests {
    use rustpython_parser::{Parse, ast};

    use super::{collect_static_maya_mel_eval_payloads, normalize_python_compat_source};

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
        );
        assert_eq!(payloads, vec!["setProject \"asset/example\";"]);
    }

    #[test]
    fn ignores_dynamic_maya_mel_eval_payload() {
        let payloads = collect_static_maya_mel_eval_payloads(
            "import maya.mel as mm\nmm.eval(build_command())\n",
        );
        assert!(payloads.is_empty());
    }
}
