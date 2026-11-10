use rustpython_parser::ast;

#[derive(Clone, Copy)]
pub enum PythonScope<'a> {
    FunctionBody {
        name: &'a ast::Identifier,
        args: &'a ast::Arguments,
        body: &'a [ast::Stmt],
    },
    AsyncFunctionBody {
        name: &'a ast::Identifier,
        args: &'a ast::Arguments,
        body: &'a [ast::Stmt],
    },
    ClassBody {
        name: &'a ast::Identifier,
        body: &'a [ast::Stmt],
    },
    LambdaBody {
        args: &'a ast::Arguments,
        body: &'a ast::Expr,
    },
    Comprehension {
        generators: &'a [ast::Comprehension],
        kind: &'a ast::Expr,
    },
}

#[derive(Clone, Copy)]
pub enum PythonWalkPoint<'a> {
    AfterForIter(&'a ast::Expr),
    AfterWithVars(&'a ast::WithItem),
    AfterDeleteTarget(&'a ast::Expr),
    BeforeHandlerBody(&'a ast::ExceptHandlerExceptHandler),
    AfterComprehensionIter(&'a ast::Comprehension),
}

pub trait PythonAstVisitor {
    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        walk_stmt(self, stmt);
    }
    fn visit_expr(&mut self, expr: &ast::Expr) {
        walk_expr(self, expr);
    }
    fn visit_pattern(&mut self, pattern: &ast::Pattern) {
        walk_pattern(self, pattern);
    }
    fn visit_type_param(&mut self, param: &ast::TypeParam) {
        walk_type_param(self, param);
    }
    fn enter_scope(&mut self, _scope: PythonScope<'_>) {}
    fn leave_scope(&mut self, _scope: PythonScope<'_>) {}
    fn at_point(&mut self, _point: PythonWalkPoint<'_>) {}
}

pub fn walk_suite<V: PythonAstVisitor + ?Sized>(visitor: &mut V, suite: &[ast::Stmt]) {
    for stmt in suite {
        visitor.visit_stmt(stmt);
    }
}

fn expressions<V: PythonAstVisitor + ?Sized>(v: &mut V, expressions: &[ast::Expr]) {
    for expr in expressions {
        v.visit_expr(expr);
    }
}

fn optional<V: PythonAstVisitor + ?Sized>(v: &mut V, expr: Option<&ast::Expr>) {
    if let Some(expr) = expr {
        v.visit_expr(expr);
    }
}

fn defaults<V: PythonAstVisitor + ?Sized>(v: &mut V, args: &ast::Arguments) {
    for arg in args
        .posonlyargs
        .iter()
        .chain(&args.args)
        .chain(&args.kwonlyargs)
    {
        optional(v, arg.default.as_deref());
    }
}

fn annotations<V: PythonAstVisitor + ?Sized>(v: &mut V, args: &ast::Arguments) {
    for arg in args.posonlyargs.iter().chain(&args.args) {
        optional(v, arg.def.annotation.as_deref());
    }
    if let Some(arg) = &args.vararg {
        optional(v, arg.annotation.as_deref());
    }
    for arg in &args.kwonlyargs {
        optional(v, arg.def.annotation.as_deref());
    }
    if let Some(arg) = &args.kwarg {
        optional(v, arg.annotation.as_deref());
    }
}

fn type_params<V: PythonAstVisitor + ?Sized>(v: &mut V, params: &[ast::TypeParam]) {
    for param in params {
        v.visit_type_param(param);
    }
}

fn scoped_suite<V: PythonAstVisitor + ?Sized>(
    v: &mut V,
    scope: PythonScope<'_>,
    body: &[ast::Stmt],
) {
    v.enter_scope(scope);
    walk_suite(v, body);
    v.leave_scope(scope);
}

fn with_items<V: PythonAstVisitor + ?Sized>(v: &mut V, items: &[ast::WithItem]) {
    for item in items {
        v.visit_expr(&item.context_expr);
        optional(v, item.optional_vars.as_deref());
        v.at_point(PythonWalkPoint::AfterWithVars(item));
    }
}

fn handlers<V: PythonAstVisitor + ?Sized>(v: &mut V, handlers: &[ast::ExceptHandler]) {
    for ast::ExceptHandler::ExceptHandler(handler) in handlers {
        optional(v, handler.type_.as_deref());
        v.at_point(PythonWalkPoint::BeforeHandlerBody(handler));
        walk_suite(v, &handler.body);
    }
}

pub fn walk_stmt<V: PythonAstVisitor + ?Sized>(v: &mut V, stmt: &ast::Stmt) {
    match stmt {
        ast::Stmt::FunctionDef(s) => {
            defaults(v, &s.args);
            expressions(v, &s.decorator_list);
            type_params(v, &s.type_params);
            annotations(v, &s.args);
            optional(v, s.returns.as_deref());
            scoped_suite(
                v,
                PythonScope::FunctionBody {
                    name: &s.name,
                    args: &s.args,
                    body: &s.body,
                },
                &s.body,
            );
        }
        ast::Stmt::AsyncFunctionDef(s) => {
            defaults(v, &s.args);
            expressions(v, &s.decorator_list);
            type_params(v, &s.type_params);
            annotations(v, &s.args);
            optional(v, s.returns.as_deref());
            scoped_suite(
                v,
                PythonScope::AsyncFunctionBody {
                    name: &s.name,
                    args: &s.args,
                    body: &s.body,
                },
                &s.body,
            );
        }
        ast::Stmt::ClassDef(s) => {
            expressions(v, &s.decorator_list);
            type_params(v, &s.type_params);
            expressions(v, &s.bases);
            for keyword in &s.keywords {
                v.visit_expr(&keyword.value);
            }
            scoped_suite(
                v,
                PythonScope::ClassBody {
                    name: &s.name,
                    body: &s.body,
                },
                &s.body,
            );
        }
        ast::Stmt::Return(s) => optional(v, s.value.as_deref()),
        ast::Stmt::Delete(s) => {
            for target in &s.targets {
                v.visit_expr(target);
                v.at_point(PythonWalkPoint::AfterDeleteTarget(target));
            }
        }
        ast::Stmt::Assign(s) => {
            expressions(v, &s.targets);
            v.visit_expr(&s.value);
        }
        ast::Stmt::TypeAlias(s) => {
            type_params(v, &s.type_params);
            v.visit_expr(&s.value);
        }
        ast::Stmt::AugAssign(s) => {
            v.visit_expr(&s.target);
            v.visit_expr(&s.value);
        }
        ast::Stmt::AnnAssign(s) => {
            v.visit_expr(&s.target);
            v.visit_expr(&s.annotation);
            optional(v, s.value.as_deref());
        }
        ast::Stmt::For(s) => {
            v.visit_expr(&s.target);
            v.visit_expr(&s.iter);
            v.at_point(PythonWalkPoint::AfterForIter(&s.target));
            walk_suite(v, &s.body);
            walk_suite(v, &s.orelse);
        }
        ast::Stmt::AsyncFor(s) => {
            v.visit_expr(&s.target);
            v.visit_expr(&s.iter);
            v.at_point(PythonWalkPoint::AfterForIter(&s.target));
            walk_suite(v, &s.body);
            walk_suite(v, &s.orelse);
        }
        ast::Stmt::While(s) => {
            v.visit_expr(&s.test);
            walk_suite(v, &s.body);
            walk_suite(v, &s.orelse);
        }
        ast::Stmt::If(s) => {
            v.visit_expr(&s.test);
            walk_suite(v, &s.body);
            walk_suite(v, &s.orelse);
        }
        ast::Stmt::With(s) => {
            with_items(v, &s.items);
            walk_suite(v, &s.body);
        }
        ast::Stmt::AsyncWith(s) => {
            with_items(v, &s.items);
            walk_suite(v, &s.body);
        }
        ast::Stmt::Match(s) => {
            v.visit_expr(&s.subject);
            for case in &s.cases {
                v.visit_pattern(&case.pattern);
                optional(v, case.guard.as_deref());
                walk_suite(v, &case.body);
            }
        }
        ast::Stmt::Raise(s) => {
            optional(v, s.exc.as_deref());
            optional(v, s.cause.as_deref());
        }
        ast::Stmt::Try(s) => {
            walk_suite(v, &s.body);
            handlers(v, &s.handlers);
            walk_suite(v, &s.orelse);
            walk_suite(v, &s.finalbody);
        }
        ast::Stmt::TryStar(s) => {
            walk_suite(v, &s.body);
            handlers(v, &s.handlers);
            walk_suite(v, &s.orelse);
            walk_suite(v, &s.finalbody);
        }
        ast::Stmt::Assert(s) => {
            v.visit_expr(&s.test);
            optional(v, s.msg.as_deref());
        }
        ast::Stmt::Expr(s) => v.visit_expr(&s.value),
        ast::Stmt::Import(_)
        | ast::Stmt::ImportFrom(_)
        | ast::Stmt::Global(_)
        | ast::Stmt::Nonlocal(_)
        | ast::Stmt::Pass(_)
        | ast::Stmt::Break(_)
        | ast::Stmt::Continue(_) => {}
    }
}

fn comprehensions<V: PythonAstVisitor + ?Sized>(
    v: &mut V,
    kind: &ast::Expr,
    generators: &[ast::Comprehension],
    results: &[&ast::Expr],
) {
    if let Some(first) = generators.first() {
        v.visit_expr(&first.iter);
    }
    let scope = PythonScope::Comprehension { generators, kind };
    v.enter_scope(scope);
    for (index, generator) in generators.iter().enumerate() {
        v.visit_expr(&generator.target);
        if index != 0 {
            v.visit_expr(&generator.iter);
        }
        v.at_point(PythonWalkPoint::AfterComprehensionIter(generator));
        expressions(v, &generator.ifs);
    }
    for result in results {
        v.visit_expr(result);
    }
    v.leave_scope(scope);
}

pub fn walk_expr<V: PythonAstVisitor + ?Sized>(v: &mut V, expr: &ast::Expr) {
    match expr {
        ast::Expr::BoolOp(e) => expressions(v, &e.values),
        ast::Expr::NamedExpr(e) => {
            v.visit_expr(&e.target);
            v.visit_expr(&e.value);
        }
        ast::Expr::BinOp(e) => {
            v.visit_expr(&e.left);
            v.visit_expr(&e.right);
        }
        ast::Expr::UnaryOp(e) => v.visit_expr(&e.operand),
        ast::Expr::Lambda(e) => {
            defaults(v, &e.args);
            let scope = PythonScope::LambdaBody {
                args: &e.args,
                body: &e.body,
            };
            v.enter_scope(scope);
            v.visit_expr(&e.body);
            v.leave_scope(scope);
        }
        ast::Expr::IfExp(e) => {
            v.visit_expr(&e.test);
            v.visit_expr(&e.body);
            v.visit_expr(&e.orelse);
        }
        ast::Expr::Dict(e) => {
            for key in e.keys.iter().flatten() {
                v.visit_expr(key);
            }
            expressions(v, &e.values);
        }
        ast::Expr::Set(e) => expressions(v, &e.elts),
        ast::Expr::ListComp(e) => comprehensions(v, expr, &e.generators, &[&e.elt]),
        ast::Expr::SetComp(e) => comprehensions(v, expr, &e.generators, &[&e.elt]),
        ast::Expr::DictComp(e) => comprehensions(v, expr, &e.generators, &[&e.key, &e.value]),
        ast::Expr::GeneratorExp(e) => comprehensions(v, expr, &e.generators, &[&e.elt]),
        ast::Expr::Await(e) => v.visit_expr(&e.value),
        ast::Expr::Yield(e) => optional(v, e.value.as_deref()),
        ast::Expr::YieldFrom(e) => v.visit_expr(&e.value),
        ast::Expr::Compare(e) => {
            v.visit_expr(&e.left);
            expressions(v, &e.comparators);
        }
        ast::Expr::Call(e) => {
            v.visit_expr(&e.func);
            expressions(v, &e.args);
            for keyword in &e.keywords {
                v.visit_expr(&keyword.value);
            }
        }
        ast::Expr::FormattedValue(e) => {
            v.visit_expr(&e.value);
            optional(v, e.format_spec.as_deref());
        }
        ast::Expr::JoinedStr(e) => expressions(v, &e.values),
        ast::Expr::Constant(_) | ast::Expr::Name(_) => {}
        ast::Expr::Attribute(e) => v.visit_expr(&e.value),
        ast::Expr::Subscript(e) => {
            v.visit_expr(&e.value);
            v.visit_expr(&e.slice);
        }
        ast::Expr::Starred(e) => v.visit_expr(&e.value),
        ast::Expr::List(e) => expressions(v, &e.elts),
        ast::Expr::Tuple(e) => expressions(v, &e.elts),
        ast::Expr::Slice(e) => {
            optional(v, e.lower.as_deref());
            optional(v, e.upper.as_deref());
            optional(v, e.step.as_deref());
        }
    }
}

pub fn walk_pattern<V: PythonAstVisitor + ?Sized>(v: &mut V, pattern: &ast::Pattern) {
    match pattern {
        ast::Pattern::MatchValue(p) => v.visit_expr(&p.value),
        ast::Pattern::MatchSingleton(_) | ast::Pattern::MatchStar(_) => {}
        ast::Pattern::MatchSequence(p) => {
            for pattern in &p.patterns {
                v.visit_pattern(pattern);
            }
        }
        ast::Pattern::MatchMapping(p) => {
            expressions(v, &p.keys);
            for pattern in &p.patterns {
                v.visit_pattern(pattern);
            }
        }
        ast::Pattern::MatchClass(p) => {
            v.visit_expr(&p.cls);
            for pattern in p.patterns.iter().chain(&p.kwd_patterns) {
                v.visit_pattern(pattern);
            }
        }
        ast::Pattern::MatchAs(p) => {
            if let Some(pattern) = &p.pattern {
                v.visit_pattern(pattern);
            }
        }
        ast::Pattern::MatchOr(p) => {
            for pattern in &p.patterns {
                v.visit_pattern(pattern);
            }
        }
    }
}

pub fn walk_type_param<V: PythonAstVisitor + ?Sized>(v: &mut V, param: &ast::TypeParam) {
    match param {
        ast::TypeParam::TypeVar(p) => optional(v, p.bound.as_deref()),
        ast::TypeParam::ParamSpec(_) | ast::TypeParam::TypeVarTuple(_) => {}
    }
}

#[cfg(test)]
mod tests;
