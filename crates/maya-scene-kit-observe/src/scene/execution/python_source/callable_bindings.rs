use std::collections::{HashMap, VecDeque};

use rustpython_parser::ast;

use super::super::python_walk::{
    PythonAstVisitor, PythonScope, PythonWalkPoint, walk_expr, walk_pattern, walk_stmt, walk_suite,
};

#[derive(Clone, Copy)]
enum QualifiedName {
    Other,
    Maya,
    Mel,
    Eval,
}

impl QualifiedName {
    fn from_name(name: &str) -> Self {
        if name
            .strip_suffix(".eval")
            .is_some_and(super::is_maya_mel_module)
        {
            Self::Eval
        } else if super::is_maya_mel_module(name) {
            Self::Mel
        } else if name == "maya" || name.ends_with(".maya") {
            Self::Maya
        } else {
            Self::Other
        }
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }

    fn attribute(self, name: &str) -> Self {
        match (self, name) {
            (_, "maya") => Self::Maya,
            (Self::Maya, "mel") => Self::Mel,
            (Self::Mel, "eval") => Self::Eval,
            _ => Self::Other,
        }
    }
}

// Suffix classes keep cyclic alias equations finite without retaining arbitrary paths.
fn attributes(mut values: u8, names: &[String]) -> u8 {
    for name in names {
        let mut next = 0;
        for value in [
            QualifiedName::Other,
            QualifiedName::Maya,
            QualifiedName::Mel,
            QualifiedName::Eval,
        ] {
            if values & value.bit() != 0 {
                next |= value.attribute(name).bit();
            }
        }
        values = next;
    }
    values
}

enum Source {
    Qualified(QualifiedName),
    Reference {
        name: String,
        attributes: Vec<String>,
    },
}

impl Source {
    fn from_expr(expr: &ast::Expr) -> Option<Self> {
        let mut expr = expr;
        let mut attributes = Vec::new();
        while let ast::Expr::Attribute(attr) = expr {
            attributes.push(attr.attr.to_string());
            expr = &attr.value;
        }
        let ast::Expr::Name(name) = expr else {
            return None;
        };
        attributes.reverse();
        Some(Self::Reference {
            name: name.id.to_string(),
            attributes,
        })
    }
}

struct Scope {
    values: HashMap<String, u8>,
    parent: Option<usize>,
    class: bool,
}

#[derive(Default)]
pub(crate) struct CallableBindings {
    scopes: Vec<Scope>,
}

impl CallableBindings {
    pub(crate) fn for_body(body: &[ast::Stmt]) -> Self {
        let mut result = Self::default();
        let mut collector = BindingCollector::default();
        walk_suite(&mut collector, body);
        result.push(collector, false);
        result
    }

    pub(crate) fn enter_scope(&mut self, scope: PythonScope<'_>) {
        let mut collector = BindingCollector::default();
        match scope {
            PythonScope::FunctionBody { body, args, .. }
            | PythonScope::AsyncFunctionBody { body, args, .. } => {
                collector.parameters(args);
                walk_suite(&mut collector, body);
            }
            PythonScope::ClassBody { body, .. } => walk_suite(&mut collector, body),
            PythonScope::LambdaBody { args, body } => {
                collector.parameters(args);
                collector.visit_expr(body);
            }
            PythonScope::Comprehension { generators, kind } => {
                for (index, generator) in generators.iter().enumerate() {
                    collector.visit_expr(&generator.target);
                    if index != 0 {
                        collector.visit_expr(&generator.iter);
                    }
                    for expr in &generator.ifs {
                        collector.visit_expr(expr);
                    }
                }
                match kind {
                    ast::Expr::ListComp(expr) => collector.visit_expr(&expr.elt),
                    ast::Expr::SetComp(expr) => collector.visit_expr(&expr.elt),
                    ast::Expr::DictComp(expr) => {
                        collector.visit_expr(&expr.key);
                        collector.visit_expr(&expr.value);
                    }
                    ast::Expr::GeneratorExp(expr) => collector.visit_expr(&expr.elt),
                    _ => unreachable!("comprehension scope"),
                }
            }
        }
        self.push(collector, matches!(scope, PythonScope::ClassBody { .. }));
    }

    pub(crate) fn leave_scope(&mut self) {
        self.scopes.pop().expect("balanced Python scopes");
    }

    pub(crate) fn is_eval_alias(&self, expr: &ast::Expr) -> bool {
        let scope = self.scopes.len().checked_sub(1);
        match expr {
            ast::Expr::Name(name) => {
                self.lookup(scope, name.id.as_str()) & QualifiedName::Eval.bit() != 0
            }
            ast::Expr::Attribute(attr) if attr.attr.as_str() == "eval" => {
                let ast::Expr::Name(name) = attr.value.as_ref() else {
                    return false;
                };
                self.lookup(scope, name.id.as_str()) & QualifiedName::Mel.bit() != 0
            }
            _ => false,
        }
    }

    fn lookup(&self, mut scope: Option<usize>, name: &str) -> u8 {
        while let Some(index) = scope {
            let current = &self.scopes[index];
            if let Some(value) = current.values.get(name) {
                return *value;
            }
            scope = current.parent;
        }
        0
    }

    fn push(&mut self, collector: BindingCollector, class: bool) {
        let parent = self.scopes.iter().rposition(|scope| !scope.class);
        let indices: HashMap<_, _> = collector
            .bindings
            .keys()
            .enumerate()
            .map(|(index, name)| (name.clone(), index))
            .collect();
        let mut values = vec![0; indices.len()];
        let mut edges = vec![Vec::new(); indices.len()];
        for (name, sources) in collector.bindings {
            let target = indices[&name];
            for source in sources {
                match source {
                    Source::Qualified(value) => values[target] |= value.bit(),
                    Source::Reference {
                        name,
                        attributes: suffix,
                    } => {
                        if let Some(&source) = indices.get(&name) {
                            edges[source].push((target, suffix));
                        } else {
                            values[target] |= attributes(self.lookup(parent, &name), &suffix);
                        }
                    }
                }
            }
        }
        let mut pending: VecDeque<_> = values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| (*value != 0).then_some(index))
            .collect();
        while let Some(source) = pending.pop_front() {
            for (target, suffix) in &edges[source] {
                let next = values[*target] | attributes(values[source], suffix);
                if next != values[*target] {
                    values[*target] = next;
                    pending.push_back(*target);
                }
            }
        }
        self.scopes.push(Scope {
            values: indices
                .into_iter()
                .map(|(name, index)| (name, values[index]))
                .collect(),
            parent,
            class,
        });
    }
}

#[derive(Default)]
struct BindingCollector {
    bindings: HashMap<String, Vec<Source>>,
    nested_scope: usize,
}

impl BindingCollector {
    fn bind(&mut self, name: &str, source: Option<Source>) {
        self.bindings
            .entry(name.to_string())
            .or_default()
            .extend(source);
    }

    fn parameters(&mut self, args: &ast::Arguments) {
        for arg in args
            .posonlyargs
            .iter()
            .chain(&args.args)
            .chain(&args.kwonlyargs)
        {
            self.bind(arg.def.arg.as_str(), None);
        }
        for arg in args.vararg.iter().chain(args.kwarg.iter()) {
            self.bind(arg.arg.as_str(), None);
        }
    }

    fn assignment(&mut self, target: &ast::Expr, value: &ast::Expr) {
        if has_starred_target(target) {
            return;
        }
        match (target, value) {
            (ast::Expr::Name(name), value) => self.bind(name.id.as_str(), Source::from_expr(value)),
            (ast::Expr::Tuple(target), ast::Expr::Tuple(value))
                if target.elts.len() == value.elts.len() =>
            {
                for (target, value) in target.elts.iter().zip(&value.elts) {
                    self.assignment(target, value);
                }
            }
            (ast::Expr::List(target), ast::Expr::List(value))
                if target.elts.len() == value.elts.len() =>
            {
                for (target, value) in target.elts.iter().zip(&value.elts) {
                    self.assignment(target, value);
                }
            }
            _ => {}
        }
    }
}

impl PythonAstVisitor for BindingCollector {
    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        if self.nested_scope != 0 {
            return;
        }
        match stmt {
            ast::Stmt::Import(stmt) => {
                for alias in &stmt.names {
                    let (name, value) = if let Some(name) = &alias.asname {
                        (name.as_str(), alias.name.as_str())
                    } else {
                        let root = alias.name.as_str().split('.').next().unwrap();
                        (root, root)
                    };
                    self.bind(
                        name,
                        Some(Source::Qualified(QualifiedName::from_name(value))),
                    );
                }
            }
            ast::Stmt::ImportFrom(stmt) => {
                for alias in &stmt.names {
                    let value = stmt
                        .module
                        .as_ref()
                        .filter(|_| stmt.level.is_none_or(|level| level.to_u32() == 0))
                        .map(|module| {
                            Source::Qualified(QualifiedName::from_name(&format!(
                                "{module}.{}",
                                alias.name
                            )))
                        });
                    self.bind(alias.asname.as_ref().unwrap_or(&alias.name).as_str(), value);
                }
            }
            ast::Stmt::Assign(stmt) => {
                for target in &stmt.targets {
                    self.assignment(target, &stmt.value);
                }
            }
            ast::Stmt::AnnAssign(stmt) => {
                if let Some(value) = &stmt.value {
                    self.assignment(&stmt.target, value);
                }
            }
            ast::Stmt::FunctionDef(stmt) => self.bind(stmt.name.as_str(), None),
            ast::Stmt::AsyncFunctionDef(stmt) => self.bind(stmt.name.as_str(), None),
            ast::Stmt::ClassDef(stmt) => self.bind(stmt.name.as_str(), None),
            ast::Stmt::TypeAlias(stmt) => self.visit_expr(&stmt.name),
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        if self.nested_scope != 0 {
            return;
        }
        match expr {
            ast::Expr::Name(name) if name.ctx != ast::ExprContext::Load => {
                self.bind(name.id.as_str(), None)
            }
            ast::Expr::NamedExpr(expr) => self.assignment(&expr.target, &expr.value),
            _ => {}
        }
        walk_expr(self, expr);
    }

    fn at_point(&mut self, point: PythonWalkPoint<'_>) {
        if self.nested_scope == 0
            && let PythonWalkPoint::BeforeHandlerBody(handler) = point
            && let Some(name) = &handler.name
        {
            self.bind(name.as_str(), None);
        }
    }

    fn visit_pattern(&mut self, pattern: &ast::Pattern) {
        if self.nested_scope != 0 {
            return;
        }
        let name = match pattern {
            ast::Pattern::MatchAs(pattern) => pattern.name.as_ref(),
            ast::Pattern::MatchStar(pattern) => pattern.name.as_ref(),
            ast::Pattern::MatchMapping(pattern) => pattern.rest.as_ref(),
            _ => None,
        };
        if let Some(name) = name {
            self.bind(name.as_str(), None);
        }
        walk_pattern(self, pattern);
    }

    fn enter_scope(&mut self, _scope: PythonScope<'_>) {
        self.nested_scope += 1;
    }
    fn leave_scope(&mut self, _scope: PythonScope<'_>) {
        self.nested_scope -= 1;
    }
}

fn has_starred_target(target: &ast::Expr) -> bool {
    match target {
        ast::Expr::Starred(_) => true,
        ast::Expr::Tuple(target) => target.elts.iter().any(has_starred_target),
        ast::Expr::List(target) => target.elts.iter().any(has_starred_target),
        _ => false,
    }
}
