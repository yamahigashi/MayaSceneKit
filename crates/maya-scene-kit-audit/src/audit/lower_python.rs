use std::collections::{HashMap, HashSet};

use maya_scene_kit_observe::scene::execution::{
    normalize_python_compat_source,
    python_walk::{
        PythonAstVisitor, PythonScope, PythonWalkPoint, walk_expr, walk_stmt, walk_suite,
    },
};
use rustpython_parser::{Parse, ast, ast::Ranged};

mod maya;
mod scope;
mod targets;
pub(crate) use maya::{MayaCall, MayaKind};
use scope::{
    AssignmentValue, Binding, LocalBindings, Scope, ScopeKind, add_first_comprehension_iterable,
    collect_arguments, collect_local_bindings, collect_pattern_bindings, in_iterable,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PythonCallKind {
    Exec,
    Eval,
    Compile,
    Import,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PythonCapabilityKind {
    Subprocess,
    Socket,
    Ctypes,
    FileOpen,
    FileWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PythonBodyArgKind {
    Literal,
    Dynamic,
    Assembled { markers: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PythonSignal {
    Call {
        kind: PythonCallKind,
        first_arg: PythonBodyArgKind,
    },
    Capability(PythonCapabilityKind),
    Maya(MayaCall),
    MayaUncertain {
        message: String,
    },
    AutorunPersistenceMarker {
        marker: String,
    },
    HardMarker {
        markers: Vec<String>,
    },
    UnresolvedCallTarget {
        message: String,
    },
    ParseFailure {
        message: String,
    },
}

pub(crate) fn collect_python_signals(source: &str) -> Vec<PythonSignal> {
    let original_program = parse_python_suite(source);
    let original_positions = original_program.is_some();
    let normalized = (!original_positions).then(|| normalize_python_compat_source(source));
    let program = original_program.or_else(|| {
        ast::Suite::parse(normalized.as_deref().expect("normalized source"), "<audit>").ok()
    });
    let Some(program) = program else {
        let mut signals = vec![PythonSignal::ParseFailure {
            message: "python parse failure".to_string(),
        }];
        let markers: Vec<_> =
            crate::audit::analyze::scan_hard_python_obfuscation_markers(source, false)
                .into_iter()
                .map(|marker| marker.label)
                .collect();
        if !markers.is_empty() {
            signals.push(PythonSignal::HardMarker { markers });
        }
        signals.extend(autorun_persistence_marker_signals(source));
        return signals;
    };
    let mut visitor = SignalVisitor {
        source: normalized.as_deref().unwrap_or(source),
        ..SignalVisitor::default()
    };
    visitor.enter(ScopeKind::Module, LocalBindings::default());
    walk_suite(&mut visitor, &program);
    for marker in crate::audit::analyze::scan_hard_python_obfuscation_markers(source, true) {
        let offset = ast::text_size::TextSize::from(marker.offset as u32);
        if !original_positions
            || !visitor
                .marker_occurrences
                .iter()
                .any(|(label, range)| label == &marker.label && range.contains(offset))
        {
            visitor.record_hard_markers(
                vec![marker.label],
                ast::text_size::TextRange::at(offset, 1.into()),
            );
        }
    }
    visitor
        .signals
        .extend(autorun_persistence_marker_signals(source));
    visitor.signals
}

fn parse_python_suite(source: &str) -> Option<ast::Suite> {
    ast::Suite::parse(source, "<audit>").ok()
}

#[derive(Default)]
struct SignalVisitor<'a> {
    source: &'a str,
    signals: Vec<PythonSignal>,
    scopes: Vec<Scope>,
    conditional_bindings: Vec<ConditionalBindings>,
    for_iterables: Vec<ast::Expr>,
    match_subjects: Vec<ast::Expr>,
    iterable_ranges: Vec<ast::text_size::TextRange>,
    pending_definition_safe: bool,
    handler_ends: HashMap<u32, Vec<String>>,
    pending_evaluations: HashMap<ast::text_size::TextRange, BindingEvaluation>,
    evaluated_values: HashMap<ast::text_size::TextRange, AssignmentValue>,
    marker_occurrences: HashSet<(String, ast::text_size::TextRange)>,
    builtin_poisoned: bool,
    implicit_calls: HashSet<ast::text_size::TextRange>,
    safe_builtins: std::cell::RefCell<HashMap<String, bool>>,
}

enum BindingEvaluation {
    Value,
    Iterable,
}

struct ConditionalBindings {
    depth: usize,
    alternatives: HashMap<(usize, String), Binding>,
    body_ends: HashSet<u32>,
    finally_start: Option<u32>,
    finished: bool,
}

fn conditional_body_ends(stmt: &ast::Stmt) -> HashSet<u32> {
    let mut bodies = Vec::new();
    let (body, orelse, handlers) = match stmt {
        ast::Stmt::If(value) => (&value.body, &value.orelse, None),
        ast::Stmt::While(value) => (&value.body, &value.orelse, None),
        ast::Stmt::For(value) => (&value.body, &value.orelse, None),
        ast::Stmt::AsyncFor(value) => (&value.body, &value.orelse, None),
        ast::Stmt::Try(value) => (&value.body, &value.orelse, Some(&value.handlers)),
        ast::Stmt::TryStar(value) => (&value.body, &value.orelse, Some(&value.handlers)),
        ast::Stmt::Match(value) => {
            return value
                .cases
                .iter()
                .filter_map(|case| case.body.last())
                .map(|stmt| stmt.range().start().to_u32())
                .collect();
        }
        _ => return HashSet::new(),
    };
    bodies.extend([body, orelse]);
    if let Some(handlers) = handlers {
        for ast::ExceptHandler::ExceptHandler(handler) in handlers {
            bodies.push(&handler.body);
        }
    }
    bodies
        .into_iter()
        .filter_map(|body| body.last())
        .map(|stmt| stmt.range().start().to_u32())
        .collect()
}

impl PythonAstVisitor for SignalVisitor<'_> {
    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        if let Some(conditional) = self.conditional_bindings.last_mut()
            && conditional.finally_start == Some(stmt.range().start().to_u32())
        {
            conditional.finished = true;
            let alternatives = std::mem::take(&mut conditional.alternatives);
            self.merge_conditional_bindings(alternatives);
        }
        let conditional = matches!(
            stmt,
            ast::Stmt::If(_)
                | ast::Stmt::While(_)
                | ast::Stmt::For(_)
                | ast::Stmt::AsyncFor(_)
                | ast::Stmt::Try(_)
                | ast::Stmt::TryStar(_)
                | ast::Stmt::Match(_)
        );
        if conditional {
            self.conditional_bindings.push(ConditionalBindings {
                depth: self.scopes.len() - 1,
                alternatives: HashMap::new(),
                body_ends: conditional_body_ends(stmt),
                finally_start: match stmt {
                    ast::Stmt::Try(value) => value.finalbody.first(),
                    ast::Stmt::TryStar(value) => value.finalbody.first(),
                    _ => None,
                }
                .map(|stmt| stmt.range().start().to_u32()),
                finished: false,
            });
        }
        match stmt {
            ast::Stmt::For(value) => self.for_iterables.push(*value.iter.clone()),
            ast::Stmt::AsyncFor(value) => self.for_iterables.push(*value.iter.clone()),
            ast::Stmt::Match(value) => self.match_subjects.push(*value.subject.clone()),
            _ => {}
        }
        match stmt {
            ast::Stmt::FunctionDef(value) => {
                self.pending_definition_safe = value.decorator_list.is_empty();
                self.implicit_calls.extend(
                    value
                        .decorator_list
                        .iter()
                        .filter(|expr| !matches!(expr, ast::Expr::Call(_)))
                        .map(Ranged::range),
                );
                self.prepare_argument_defaults(&value.args);
            }
            ast::Stmt::AsyncFunctionDef(value) => {
                self.pending_definition_safe = value.decorator_list.is_empty();
                self.implicit_calls.extend(
                    value
                        .decorator_list
                        .iter()
                        .filter(|expr| !matches!(expr, ast::Expr::Call(_)))
                        .map(Ranged::range),
                );
                self.prepare_argument_defaults(&value.args);
            }
            ast::Stmt::ClassDef(value) => {
                self.pending_definition_safe = value.decorator_list.is_empty()
                    && value
                        .bases
                        .iter()
                        .chain(value.keywords.iter().map(|keyword| &keyword.value))
                        .all(|expr| self.named_class_constructor(expr));
                self.implicit_calls.extend(
                    value
                        .decorator_list
                        .iter()
                        .filter(|expr| !matches!(expr, ast::Expr::Call(_)))
                        .map(Ranged::range),
                );
                self.implicit_calls.extend(
                    value
                        .keywords
                        .iter()
                        .filter(|keyword| {
                            keyword
                                .arg
                                .as_ref()
                                .is_some_and(|arg| arg.as_str() == "metaclass")
                        })
                        .map(|keyword| keyword.value.range()),
                );
            }
            _ => {}
        }
        walk_stmt(self, stmt);
        match stmt {
            ast::Stmt::Import(import) => {
                for alias in &import.names {
                    self.record_capability_module(alias.name.as_str());
                    self.record_hard_markers(
                        hard_markers_for_imported_module(alias.name.as_str()),
                        self.import_module_range(alias.range, alias.name.as_str()),
                    );
                    let top = alias
                        .name
                        .as_str()
                        .split('.')
                        .next()
                        .unwrap_or(alias.name.as_str());
                    let local = alias
                        .asname
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| top.to_string());
                    let module = if alias.asname.is_some() {
                        alias.name.as_str()
                    } else {
                        top
                    };
                    self.bind_name(
                        &local,
                        Binding {
                            modules: vec![module.to_string()],
                            statically_named: true,
                            ..Binding::default()
                        },
                        false,
                    );
                }
            }
            ast::Stmt::ImportFrom(import) => {
                if import.names.iter().any(|alias| alias.name.as_str() == "*") {
                    self.scopes
                        .last_mut()
                        .expect("import scope")
                        .wildcard_import = true;
                }
                if let Some(module) = &import.module {
                    self.record_capability_module(module.as_str());
                    let module_range = self.import_module_range(stmt.range(), module.as_str());
                    self.record_hard_markers(
                        hard_markers_for_imported_module(module.as_str()),
                        module_range,
                    );
                    for alias in &import.names {
                        if alias.name.as_str() == "*" {
                            if is_maya_target(module.as_str()) {
                                self.signals.push(PythonSignal::MayaUncertain {
                                    message:
                                        "Maya wildcard import leaves callable bindings unresolved"
                                            .to_string(),
                                });
                            }
                            continue;
                        }
                        self.record_hard_markers(
                            hard_markers_for_name(alias.name.as_str()),
                            self.import_module_range(alias.range, alias.name.as_str()),
                        );
                        let module = if import.level.is_some_and(|level| level.to_u32() != 0) {
                            "<relative>"
                        } else {
                            module.as_str()
                        };
                        let top = module.split('.').next().unwrap_or(module);
                        self.bind_name(
                            &alias_local_name(alias.name.as_str(), alias.asname.as_ref()),
                            Binding {
                                aliases: imported_call_alias(top, alias.name.as_str())
                                    .into_iter()
                                    .collect(),
                                modules: vec![format!("{module}.{}", alias.name)],
                                statically_named: true,
                                capabilities: capability_for_imported_name(
                                    top,
                                    alias.name.as_str(),
                                )
                                .into_iter()
                                .collect(),
                                strings: Vec::new(),
                                known_safe: self
                                    .safe_imported_callable(module, alias.name.as_str()),
                                ..Binding::default()
                            },
                            false,
                        );
                    }
                } else {
                    for alias in &import.names {
                        if alias.name.as_str() == "*" {
                            continue;
                        }
                        self.bind_name(
                            &alias_local_name(alias.name.as_str(), alias.asname.as_ref()),
                            Binding {
                                statically_named: true,
                                ..Binding::default()
                            },
                            false,
                        );
                    }
                }
            }
            ast::Stmt::Assign(value) => {
                let assignments: Vec<_> = value
                    .targets
                    .iter()
                    .flat_map(|target| self.prepare_assignment(target, &value.value))
                    .collect();
                for (target, binding) in assignments {
                    self.bind_target(target, binding, false);
                }
            }
            ast::Stmt::AnnAssign(value) => {
                if let Some(expr) = &value.value {
                    self.assign_target(&value.target, expr, false);
                }
            }
            ast::Stmt::AugAssign(value) => {
                self.bind_target(&value.target, Binding::default(), false)
            }
            ast::Stmt::For(_) | ast::Stmt::AsyncFor(_) => {
                self.for_iterables.pop();
            }
            ast::Stmt::Match(_) => {
                self.match_subjects.pop();
            }
            _ => {}
        }
        if conditional {
            self.finish_conditional();
        }
        if let Some(names) = self.handler_ends.remove(&stmt.range().start().to_u32()) {
            for name in names {
                self.bind_name(&name, Binding::default(), false);
            }
        }
        for index in 0..self.conditional_bindings.len() {
            let conditional = &self.conditional_bindings[index];
            if !conditional.finished
                && conditional
                    .body_ends
                    .contains(&stmt.range().start().to_u32())
            {
                let values: Vec<_> = conditional
                    .alternatives
                    .keys()
                    .map(|(owner, name)| {
                        ((*owner, name.clone()), self.resolve_name_from(name, *owner))
                    })
                    .collect();
                for (key, value) in values {
                    self.conditional_bindings[index]
                        .alternatives
                        .get_mut(&key)
                        .expect("recorded conditional binding")
                        .extend(value);
                }
            }
        }
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        let previous_ranges = self.iterable_ranges.len();
        if let Some(first) = add_first_comprehension_iterable(expr, &mut self.iterable_ranges) {
            self.pending_evaluations
                .insert(first.range(), BindingEvaluation::Iterable);
        }
        if let ast::Expr::Lambda(value) = expr {
            self.prepare_argument_defaults(&value.args);
        }
        match expr {
            ast::Expr::Call(call) => {
                self.record_hard_markers(
                    hard_markers_for_call(call),
                    callable_identifier_range(&call.func),
                );
                self.visit_call(call);
            }
            ast::Expr::Attribute(value) => self.record_hard_markers(
                hard_markers_for_attribute(value),
                attribute_identifier_range(value),
            ),
            ast::Expr::Subscript(value) => {
                self.record_hard_markers(hard_markers_for_subscript(value), value.range)
            }
            ast::Expr::Name(name) => {
                self.record_hard_markers(hard_markers_for_name(name.id.as_str()), name.range)
            }
            _ => {}
        }
        walk_expr(self, expr);
        if let ast::Expr::NamedExpr(value) = expr
            && !in_iterable(expr, &self.iterable_ranges)
        {
            self.assign_target(&value.target, &value.value, true);
        }
        if let Some(evaluation) = self.pending_evaluations.remove(&expr.range()) {
            let binding = match evaluation {
                BindingEvaluation::Value => AssignmentValue::Single(self.assigned_value(expr)),
                BindingEvaluation::Iterable => self.iterable_value(expr),
            };
            self.evaluated_values.insert(expr.range(), binding);
        }
        if self.implicit_calls.remove(&expr.range()) {
            self.check_implicit_call(expr);
        }
        self.iterable_ranges.truncate(previous_ranges);
    }

    fn enter_scope(&mut self, scope: PythonScope<'_>) {
        match scope {
            PythonScope::FunctionBody { name, args, body }
            | PythonScope::AsyncFunctionBody { name, args, body } => {
                self.bind_name(
                    name.as_str(),
                    Binding {
                        known_safe: self.pending_definition_safe,
                        statically_named: self.pending_definition_safe,
                        ..Binding::default()
                    },
                    false,
                );
                self.pending_definition_safe = false;
                let mut bindings = collect_local_bindings(body);
                collect_arguments(args, &mut bindings.names);
                self.enter(ScopeKind::Function, bindings);
                self.shadow_arguments(args);
            }
            PythonScope::ClassBody { name, body } => {
                self.bind_name(
                    name.as_str(),
                    Binding {
                        known_safe: self.pending_definition_safe,
                        statically_named: self.pending_definition_safe,
                        local_class: self.pending_definition_safe,
                        ..Binding::default()
                    },
                    false,
                );
                self.pending_definition_safe = false;
                self.enter(ScopeKind::Class, collect_local_bindings(body));
            }
            PythonScope::LambdaBody { args, body } => {
                let mut bindings = LocalBindings::default();
                bindings.visit_expr(body);
                collect_arguments(args, &mut bindings.names);
                self.enter(ScopeKind::Lambda, bindings);
                self.shadow_arguments(args);
            }
            PythonScope::Comprehension { generators, .. } => {
                self.conditional_bindings.push(ConditionalBindings {
                    depth: self.scopes.len() - 1,
                    alternatives: HashMap::new(),
                    body_ends: HashSet::new(),
                    finally_start: None,
                    finished: false,
                });
                let mut bindings = LocalBindings::default();
                for generator in generators {
                    collect_target_bindings(&generator.target, &mut bindings.names);
                }
                self.enter(ScopeKind::Comprehension, bindings);
            }
        }
    }

    fn leave_scope(&mut self, scope: PythonScope<'_>) {
        let depth = self.scopes.len() - 1;
        self.scopes.pop();
        for changed in &mut self.conditional_bindings {
            changed.alternatives.retain(|(owner, _), _| *owner != depth);
        }
        if matches!(scope, PythonScope::Comprehension { .. }) {
            self.finish_conditional();
        }
    }

    fn enter_body(
        &mut self,
        body: maya_scene_kit_observe::scene::execution::python_walk::PythonBody<'_>,
    ) {
        if let maya_scene_kit_observe::scene::execution::python_walk::PythonBody::MatchCase(case) =
            body
        {
            let binding = self
                .match_subjects
                .last()
                .map(|subject| self.assigned_value(subject))
                .unwrap_or_default();
            let mut names = HashSet::new();
            collect_pattern_bindings(&case.pattern, &mut names);
            for name in names {
                self.bind_name(&name, binding.clone(), false);
            }
        }
    }

    fn at_point(&mut self, point: PythonWalkPoint<'_>) {
        match point {
            PythonWalkPoint::AfterForIter(target) => {
                let binding = self
                    .for_iterables
                    .last()
                    .map(|iter| self.iterable_value(iter))
                    .unwrap_or_default();
                self.bind_prepared_target(target, binding, false);
            }
            PythonWalkPoint::AfterDeleteTarget(target) => self.delete_target(target),
            PythonWalkPoint::AfterWithVars(item) => {
                if let Some(target) = &item.optional_vars {
                    self.assign_target(target, &item.context_expr, false);
                }
            }
            PythonWalkPoint::BeforeHandlerBody(handler) => {
                if let Some(name) = &handler.name {
                    let binding = handler
                        .type_
                        .as_deref()
                        .map(|value| self.assigned_value(value))
                        .unwrap_or_default();
                    self.bind_name(name.as_str(), binding, false);
                    if let Some(last) = handler.body.last() {
                        self.handler_ends
                            .entry(last.range().start().to_u32())
                            .or_default()
                            .push(name.to_string());
                    }
                }
            }
            PythonWalkPoint::AfterComprehensionIter(generator) => {
                let binding = self
                    .evaluated_values
                    .remove(&generator.iter.range())
                    .unwrap_or_else(|| self.iterable_value(&generator.iter));
                self.bind_prepared_target(&generator.target, binding, false);
            }
        }
    }
}

impl SignalVisitor<'_> {
    fn finish_conditional(&mut self) {
        let alternatives = self
            .conditional_bindings
            .pop()
            .expect("conditional scope")
            .alternatives;
        self.merge_conditional_bindings(alternatives);
    }

    fn merge_conditional_bindings(&mut self, alternatives: HashMap<(usize, String), Binding>) {
        let mut changed: Vec<_> = alternatives.into_iter().collect();
        changed.sort_by(|left, right| left.0.cmp(&right.0));
        for ((owner, name), alternatives) in changed {
            if owner < self.scopes.len() {
                let mut binding = self.resolve_name_from(&name, owner);
                binding.extend(alternatives);
                let maya = binding.is_maya();
                let scope = &mut self.scopes[owner];
                scope.write(&name, binding, false);
                if maya {
                    scope.invalidate_modules(&name);
                    self.signals.push(PythonSignal::MayaUncertain {
                        message: format!("control flow leaves Maya alias {name} unresolved"),
                    });
                }
            }
        }
    }

    fn visit_call(&mut self, call: &ast::ExprCall) {
        let prior_signal_count = self.signals.len();
        if let ast::Expr::Call(dispatch) = call.func.as_ref()
            && is_dynamic_dispatch_call(dispatch)
            && dispatch
                .args
                .first()
                .is_some_and(|value| self.resolve_value(value).is_maya())
        {
            self.signals.push(PythonSignal::MayaUncertain {
                message: "Maya callable obtained through runtime attribute lookup".to_string(),
            });
        }
        let binding = self.resolve_value(&call.func);
        let mut concrete_maya = false;
        for target in &binding.modules {
            if let Some(operation) = maya::classify(target, call) {
                concrete_maya |= !operation.operations.is_empty();
                self.signals.push(PythonSignal::Maya(operation));
            }
        }
        let unbound_local = binding.unbound_local;
        let shadowed_target = !binding.known_safe && {
            let hidden = self.hidden_value(&call.func);
            !hidden.aliases.is_empty()
                || !hidden.capabilities.is_empty()
                || hidden.modules.iter().any(|target| {
                    maya::classify(target, call)
                        .is_some_and(|operation| !operation.operations.is_empty())
                })
        };
        let already_signaled = self.signals.len() != prior_signal_count;
        let known =
            concrete_maya || !binding.aliases.is_empty() || !binding.capabilities.is_empty();
        let unresolved = self.unresolved_target(&call.func, &binding);
        for kind in binding.aliases {
            self.signals.push(PythonSignal::Call {
                kind,
                first_arg: call
                    .args
                    .first()
                    .map(|arg| classify_python_body_arg(arg, self))
                    .unwrap_or(PythonBodyArgKind::Dynamic),
            });
        }
        for capability in binding.capabilities {
            self.signals.push(PythonSignal::Capability(capability));
        }
        if !known {
            if let Some(capability) = file_write_capability_from_call(&call.func) {
                self.signals.push(PythonSignal::Capability(capability));
            } else if is_maya_python_bridge_name(&call.func) {
                self.signals.push(PythonSignal::UnresolvedCallTarget {
                    message:
                        "python call target named \u{0060}python\u{0060} is not a Python built-in"
                            .to_string(),
                });
            } else if shadowed_target || unbound_local || self.wildcard_call_target(&call.func) {
                self.signals.push(PythonSignal::UnresolvedCallTarget {
                    message: format!(
                        "shadowed Python call target at byte {} cannot be resolved statically",
                        call.func.range().start().to_u32()
                    ),
                });
            } else if unresolved && (!already_signaled || unresolved_dynamic_dispatch(&call.func)) {
                self.signals.push(PythonSignal::UnresolvedCallTarget {
                    message: format!(
                        "Python call target at byte {} cannot be resolved statically",
                        call.func.range().start().to_u32()
                    ),
                });
            }
        }
    }

    fn import_module_range(
        &self,
        statement: ast::text_size::TextRange,
        module: &str,
    ) -> ast::text_size::TextRange {
        let top = module.split('.').next().unwrap_or(module);
        let source = &self.source[statement.start().to_usize()..statement.end().to_usize()];
        let Some((offset, _)) = source.match_indices(top).find(|(offset, _)| {
            let identifier = |ch: char| ch.is_alphanumeric() || ch == '_';
            !source[..*offset]
                .chars()
                .next_back()
                .is_some_and(identifier)
                && !source[*offset + top.len()..]
                    .chars()
                    .next()
                    .is_some_and(identifier)
        }) else {
            return ast::text_size::TextRange::empty(statement.start());
        };
        ast::text_size::TextRange::at(
            statement.start() + ast::text_size::TextSize::from(offset as u32),
            ast::text_size::TextSize::from(top.len() as u32),
        )
    }

    fn record_hard_markers(&mut self, markers: Vec<String>, range: ast::text_size::TextRange) {
        let markers: Vec<_> = markers
            .into_iter()
            .filter(|marker| self.marker_occurrences.insert((marker.clone(), range)))
            .collect();
        if !markers.is_empty() {
            self.signals.push(PythonSignal::HardMarker { markers });
        }
    }

    fn record_capability_module(&mut self, module: &str) {
        let top = module.split('.').next().unwrap_or(module);
        let capability = match top {
            "subprocess" => Some(PythonCapabilityKind::Subprocess),
            "socket" => Some(PythonCapabilityKind::Socket),
            "ctypes" => Some(PythonCapabilityKind::Ctypes),
            _ => None,
        };
        if let Some(capability) = capability {
            self.signals.push(PythonSignal::Capability(capability));
        }
    }
}

fn is_maya_target(target: &str) -> bool {
    target == "maya"
        || target.starts_with("maya.")
        || target == "pymel"
        || target.starts_with("pymel.")
}

fn collect_target_bindings(target: &ast::Expr, names: &mut HashSet<String>) {
    match target {
        ast::Expr::Name(name) => {
            names.insert(name.id.to_string());
        }
        ast::Expr::Tuple(value) => {
            for target in &value.elts {
                collect_target_bindings(target, names);
            }
        }
        ast::Expr::List(value) => {
            for target in &value.elts {
                collect_target_bindings(target, names);
            }
        }
        ast::Expr::Starred(value) => collect_target_bindings(&value.value, names),
        _ => {}
    }
}

fn direct_call_kind(name: &str) -> Option<PythonCallKind> {
    match name {
        "exec" => Some(PythonCallKind::Exec),
        "eval" => Some(PythonCallKind::Eval),
        "compile" => Some(PythonCallKind::Compile),
        "__import__" | "import_module" => Some(PythonCallKind::Import),
        _ => None,
    }
}

fn qualified_call_kind(module: &str, member: &str) -> Option<PythonCallKind> {
    let module = module.split('.').next().unwrap_or(module);
    match (module, member) {
        ("builtins", "exec") => Some(PythonCallKind::Exec),
        ("builtins", "eval") => Some(PythonCallKind::Eval),
        ("builtins", "compile") => Some(PythonCallKind::Compile),
        ("builtins", "__import__") => Some(PythonCallKind::Import),
        ("importlib", "import_module") => Some(PythonCallKind::Import),
        _ => None,
    }
}

fn is_maya_python_bridge_name(func: &ast::Expr) -> bool {
    matches!(func, ast::Expr::Name(name) if name.id.as_str() == "python")
}

fn indirect_call_name(call: &ast::ExprCall) -> Option<&str> {
    let getter = match call.func.as_ref() {
        ast::Expr::Name(name) => name.id.as_str(),
        ast::Expr::Attribute(attr) => attr.attr.as_str(),
        _ => return None,
    };
    if getter != "getattr" {
        return None;
    }
    call.args.get(1).and_then(string_literal_expr)
}

fn subscript_call_name(subscript: &ast::ExprSubscript) -> Option<&str> {
    let key = string_literal_expr(&subscript.slice)?;
    match subscript.value.as_ref() {
        ast::Expr::Attribute(attr) if attr.attr.as_str() == "__dict__" => Some(key),
        ast::Expr::Call(call) if is_locals_like_dispatch(call) => Some(key),
        _ => None,
    }
}

fn capability_for_imported_name(module: &str, name: &str) -> Option<PythonCapabilityKind> {
    match (module, name) {
        ("builtins", "open") => Some(PythonCapabilityKind::FileOpen),
        ("os", "system" | "popen") => Some(PythonCapabilityKind::Subprocess),
        ("os", "remove" | "unlink") => Some(PythonCapabilityKind::FileWrite),
        ("shutil", "copy" | "copyfile" | "move") => Some(PythonCapabilityKind::FileWrite),
        ("subprocess", _) => Some(PythonCapabilityKind::Subprocess),
        ("socket", _) => Some(PythonCapabilityKind::Socket),
        ("ctypes", _) => Some(PythonCapabilityKind::Ctypes),
        _ => None,
    }
}

fn imported_call_alias(module: &str, name: &str) -> Option<PythonCallKind> {
    match (module, name) {
        ("builtins", "exec") => Some(PythonCallKind::Exec),
        ("builtins", "eval") => Some(PythonCallKind::Eval),
        ("builtins", "compile") => Some(PythonCallKind::Compile),
        ("builtins", "__import__") => Some(PythonCallKind::Import),
        ("importlib", "import_module") => Some(PythonCallKind::Import),
        _ => None,
    }
}

fn capability_for_module_member(module: &str, member: &str) -> Option<PythonCapabilityKind> {
    let module = module.split('.').next().unwrap_or(module);
    match module {
        "subprocess" => Some(PythonCapabilityKind::Subprocess),
        "socket" => Some(PythonCapabilityKind::Socket),
        "ctypes" => Some(PythonCapabilityKind::Ctypes),
        "os" if matches!(member, "system" | "popen") => Some(PythonCapabilityKind::Subprocess),
        "builtins" if member == "open" => Some(PythonCapabilityKind::FileOpen),
        "os" if matches!(member, "remove" | "unlink") => Some(PythonCapabilityKind::FileWrite),
        "shutil" if matches!(member, "copy" | "copyfile" | "move") => {
            Some(PythonCapabilityKind::FileWrite)
        }
        _ => None,
    }
}

fn direct_capability(name: &str) -> Option<PythonCapabilityKind> {
    match name {
        "open" => Some(PythonCapabilityKind::FileOpen),
        _ => None,
    }
}

fn file_write_capability_from_call(func: &ast::Expr) -> Option<PythonCapabilityKind> {
    match func {
        ast::Expr::Attribute(attr) if matches!(attr.attr.as_str(), "write" | "writelines") => {
            Some(PythonCapabilityKind::FileWrite)
        }
        _ => None,
    }
}

fn autorun_persistence_marker_signals(source: &str) -> Vec<PythonSignal> {
    autorun_persistence_markers(source)
        .into_iter()
        .map(|marker| PythonSignal::AutorunPersistenceMarker { marker })
        .collect()
}

fn autorun_persistence_markers(source: &str) -> Vec<String> {
    let mut markers = Vec::new();
    let lower = source.to_ascii_lowercase();
    push_marker_if_contains(&mut markers, &lower, "userSetup.py", "usersetup.py");
    push_marker_if_contains(&mut markers, &lower, "userSetup.mel", "usersetup.mel");
    push_marker_if_contains(&mut markers, &lower, "/scripts/", "/scripts/");
    push_marker_if_contains(&mut markers, &lower, "\\scripts\\", "\\scripts\\");
    if (lower.contains("internalvar") || lower.contains("userappdir"))
        && (lower.contains(".py") || lower.contains(".mel"))
    {
        push_marker(&mut markers, "maya user script file");
    }
    markers
}

fn push_marker_if_contains(markers: &mut Vec<String>, haystack: &str, label: &str, needle: &str) {
    if haystack.contains(needle) {
        push_marker(markers, label);
    }
}

fn unresolved_dynamic_dispatch(func: &ast::Expr) -> bool {
    match func {
        ast::Expr::Call(call) => {
            is_dynamic_dispatch_call(call) && indirect_call_name(call).is_none()
        }
        ast::Expr::Subscript(subscript) => {
            string_literal_expr(&subscript.slice).is_none()
                && match subscript.value.as_ref() {
                    ast::Expr::Attribute(attr) => attr.attr.as_str() == "__dict__",
                    ast::Expr::Call(call) => is_locals_like_dispatch(call),
                    _ => false,
                }
        }
        _ => false,
    }
}

fn is_dynamic_dispatch_call(call: &ast::ExprCall) -> bool {
    match call.func.as_ref() {
        ast::Expr::Name(name) => {
            matches!(name.id.as_str(), "getattr" | "globals" | "locals" | "vars")
        }
        ast::Expr::Attribute(attr) => {
            matches!(
                attr.attr.as_str(),
                "getattr" | "globals" | "locals" | "vars"
            )
        }
        _ => false,
    }
}

fn is_locals_like_dispatch(call: &ast::ExprCall) -> bool {
    match call.func.as_ref() {
        ast::Expr::Name(name) => matches!(name.id.as_str(), "globals" | "locals" | "vars"),
        ast::Expr::Attribute(attr) => matches!(attr.attr.as_str(), "globals" | "locals" | "vars"),
        _ => false,
    }
}

fn hard_markers_for_call(call: &ast::ExprCall) -> Vec<String> {
    let mut markers = Vec::new();
    match call.func.as_ref() {
        ast::Expr::Name(name) => match name.id.as_str() {
            "chr" => push_marker(&mut markers, "chr("),
            "hex" => push_marker(&mut markers, "hex"),
            "globals" => push_marker(&mut markers, "globals("),
            "locals" => push_marker(&mut markers, "locals("),
            "vars" => push_marker(&mut markers, "vars("),
            _ => {}
        },
        ast::Expr::Attribute(attr) => match attr.attr.as_str() {
            "__getattribute__"
                if call
                    .args
                    .first()
                    .is_none_or(|arg| string_literal_expr(arg).is_none()) =>
            {
                push_marker(&mut markers, "__getattribute__");
            }
            "decode" => push_marker(&mut markers, ".decode("),
            "hex" | "fromhex" | "unhexlify" => push_marker(&mut markers, "hex"),
            "b64decode" | "standard_b64decode" | "urlsafe_b64decode" => {
                push_marker(&mut markers, "base64")
            }
            _ => {}
        },
        _ => {}
    }
    markers
}

fn hard_markers_for_attribute(attr: &ast::ExprAttribute) -> Vec<String> {
    let mut markers = Vec::new();
    match attr.attr.as_str() {
        "__import__" | "__builtins__" | "__globals__" | "__subclasses__" | "__code__"
        | "__closure__" | "__self__" => push_marker(&mut markers, attr.attr.as_str()),
        "decode" => push_marker(&mut markers, ".decode("),
        "hex" | "fromhex" | "unhexlify" => push_marker(&mut markers, "hex"),
        "b64decode" | "standard_b64decode" | "urlsafe_b64decode" => {
            push_marker(&mut markers, "base64")
        }
        _ => {}
    }
    markers
}

fn hard_markers_for_subscript(subscript: &ast::ExprSubscript) -> Vec<String> {
    let mut markers = Vec::new();
    if matches!(subscript.value.as_ref(), ast::Expr::Call(call) if is_locals_like_dispatch(call)) {
        push_marker(&mut markers, "dynamic dispatch");
    }
    markers
}

fn hard_markers_for_name(name: &str) -> Vec<String> {
    let mut markers = Vec::new();
    if matches!(name, "builtins" | "__builtins__" | "__import__") {
        push_marker(&mut markers, name);
    }
    markers
}

fn hard_markers_for_imported_module(module: &str) -> Vec<String> {
    let top = module.split('.').next().unwrap_or(module);
    let mut markers = Vec::new();
    match top {
        "base64" => push_marker(&mut markers, "base64"),
        "binascii" => push_marker(&mut markers, "hex"),
        "builtins" => push_marker(&mut markers, "builtins"),
        _ => {}
    }
    markers
}

fn attribute_identifier_range(attr: &ast::ExprAttribute) -> ast::text_size::TextRange {
    let end = attr.range.end();
    ast::text_size::TextRange::new(
        end - ast::text_size::TextSize::from(attr.attr.as_str().len() as u32),
        end,
    )
}

fn callable_identifier_range(expr: &ast::Expr) -> ast::text_size::TextRange {
    match expr {
        ast::Expr::Attribute(attr) => attribute_identifier_range(attr),
        _ => expr.range(),
    }
}

fn alias_local_name(name: &str, asname: Option<&ast::Identifier>) -> String {
    asname
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| name.rsplit('.').next().unwrap_or(name).to_string())
}

fn is_literal_expr(expr: &ast::Expr) -> bool {
    match expr {
        ast::Expr::Constant(constant) => matches!(
            constant.value,
            ast::Constant::Str(_) | ast::Constant::Bytes(_) | ast::Constant::None
        ),
        _ => false,
    }
}

fn string_literal_expr(expr: &ast::Expr) -> Option<&str> {
    match expr {
        ast::Expr::Constant(constant) => match &constant.value {
            ast::Constant::Str(value) => Some(value.as_str()),
            _ => None,
        },
        _ => None,
    }
}

fn classify_python_body_arg(expr: &ast::Expr, string_values: &SignalVisitor) -> PythonBodyArgKind {
    tracked_python_string_value(expr, string_values).unwrap_or_else(|| {
        if is_literal_expr(expr) {
            PythonBodyArgKind::Literal
        } else {
            PythonBodyArgKind::Dynamic
        }
    })
}

fn tracked_python_string_value(
    expr: &ast::Expr,
    string_values: &SignalVisitor,
) -> Option<PythonBodyArgKind> {
    match expr {
        ast::Expr::Constant(constant) => match constant.value {
            ast::Constant::Str(_) | ast::Constant::Bytes(_) => Some(PythonBodyArgKind::Literal),
            _ => None,
        },
        ast::Expr::Name(name) => {
            let values = string_values.resolve_name(name.id.as_str()).strings;
            let mut markers = Vec::new();
            for value in &values {
                merge_markers(&mut markers, assembled_markers(value));
            }
            if !markers.is_empty() {
                Some(PythonBodyArgKind::Assembled { markers })
            } else {
                values.into_iter().next()
            }
        }
        ast::Expr::JoinedStr(expr) => {
            let mut markers = Vec::new();
            for value in &expr.values {
                match value {
                    ast::Expr::Constant(constant)
                        if matches!(constant.value, ast::Constant::Str(_)) => {}
                    ast::Expr::FormattedValue(value) => {
                        merge_markers(
                            &mut markers,
                            tracked_python_string_value(&value.value, string_values)
                                .as_ref()
                                .and_then(assembled_markers),
                        );
                        push_marker(&mut markers, "f-string");
                    }
                    _ => push_marker(&mut markers, "f-string"),
                }
            }
            if markers.is_empty() {
                Some(PythonBodyArgKind::Literal)
            } else {
                Some(PythonBodyArgKind::Assembled { markers })
            }
        }
        ast::Expr::BinOp(expr) => match expr.op {
            ast::Operator::Add => {
                let left = tracked_python_string_value(&expr.left, string_values);
                let right = tracked_python_string_value(&expr.right, string_values);
                if left.is_none() && right.is_none() {
                    None
                } else {
                    Some(assemble_python_body_arg(" + ", left, right))
                }
            }
            ast::Operator::Mod => {
                let left = tracked_python_string_value(&expr.left, string_values);
                left.map(|left| assemble_python_body_arg("%", Some(left), None))
            }
            _ => None,
        },
        ast::Expr::Call(call) => tracked_string_value_from_call(call, string_values),
        _ => None,
    }
}

fn tracked_string_value_from_call(
    call: &ast::ExprCall,
    string_values: &SignalVisitor,
) -> Option<PythonBodyArgKind> {
    match call.func.as_ref() {
        ast::Expr::Name(name) => match name.id.as_str() {
            "chr" => Some(PythonBodyArgKind::Assembled {
                markers: vec!["chr(".to_string()],
            }),
            "format" => Some(PythonBodyArgKind::Assembled {
                markers: vec!["format(".to_string()],
            }),
            "hex" => Some(PythonBodyArgKind::Assembled {
                markers: vec!["hex".to_string()],
            }),
            "str" | "repr" | "bytes" => Some(PythonBodyArgKind::Dynamic),
            _ => None,
        },
        ast::Expr::Attribute(attr) => match attr.attr.as_str() {
            "format" => Some(PythonBodyArgKind::Assembled {
                markers: vec!["format(".to_string()],
            }),
            "join" => Some(PythonBodyArgKind::Assembled {
                markers: vec!["join(".to_string()],
            }),
            "decode" => Some(PythonBodyArgKind::Assembled {
                markers: vec![".decode(".to_string()],
            }),
            "hex" | "fromhex" | "unhexlify" => Some(PythonBodyArgKind::Assembled {
                markers: vec!["hex".to_string()],
            }),
            "b64decode" | "standard_b64decode" | "urlsafe_b64decode" => {
                Some(PythonBodyArgKind::Assembled {
                    markers: vec!["base64".to_string()],
                })
            }
            _ => tracked_python_string_value(&attr.value, string_values)
                .map(|_| PythonBodyArgKind::Dynamic),
        },
        _ => None,
    }
}

fn assemble_python_body_arg(
    marker: &str,
    left: Option<PythonBodyArgKind>,
    right: Option<PythonBodyArgKind>,
) -> PythonBodyArgKind {
    let mut markers = Vec::new();
    merge_markers(&mut markers, left.as_ref().and_then(assembled_markers));
    merge_markers(&mut markers, right.as_ref().and_then(assembled_markers));
    push_marker(&mut markers, marker);
    PythonBodyArgKind::Assembled { markers }
}

fn assembled_markers(value: &PythonBodyArgKind) -> Option<&[String]> {
    match value {
        PythonBodyArgKind::Assembled { markers } => Some(markers.as_slice()),
        _ => None,
    }
}

fn merge_markers(target: &mut Vec<String>, markers: Option<&[String]>) {
    if let Some(markers) = markers {
        for marker in markers {
            push_marker(target, marker);
        }
    }
}

fn push_marker(target: &mut Vec<String>, marker: &str) {
    if target.iter().all(|existing| existing != marker) {
        target.push(marker.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{PythonBodyArgKind, PythonCallKind, PythonSignal, collect_python_signals};

    fn has_call(source: &str, kind: PythonCallKind) -> bool {
        collect_python_signals(source).iter().any(
            |signal| matches!(signal, PythonSignal::Call { kind: actual, .. } if *actual == kind),
        )
    }

    fn call_count(source: &str, kind: PythonCallKind) -> usize {
        collect_python_signals(source)
            .iter()
            .filter(|signal| {
                matches!(signal, PythonSignal::Call { kind: actual, .. } if *actual == kind)
            })
            .count()
    }

    fn has_assembled_call(source: &str, kind: PythonCallKind) -> bool {
        collect_python_signals(source).iter().any(|signal| {
            matches!(
                signal,
                PythonSignal::Call {
                    kind: actual,
                    first_arg: PythonBodyArgKind::Assembled { .. },
                } if *actual == kind
            )
        })
    }

    fn has_parse_failure(source: &str) -> bool {
        collect_python_signals(source)
            .iter()
            .any(|signal| matches!(signal, PythonSignal::ParseFailure { .. }))
    }

    fn has_hard_marker(source: &str, expected: &str) -> bool {
        collect_python_signals(source).iter().any(|signal| {
            matches!(
                signal,
                PythonSignal::HardMarker { markers } if markers.iter().any(|marker| marker == expected)
            )
        })
    }

    #[test]
    fn collect_python_signals_detects_attribute_exec_calls() {
        assert!(has_call("builtins.exec('print(1)')", PythonCallKind::Exec));
    }

    #[test]
    fn collect_python_signals_detects_getattr_exec_calls() {
        assert!(has_call(
            "import builtins\ngetattr(builtins, 'exec')('print(1)')",
            PythonCallKind::Exec,
        ));
    }

    #[test]
    fn collect_python_signals_detects_importlib_member_calls() {
        assert!(has_call(
            "import importlib\nimportlib.import_module('os')",
            PythonCallKind::Import,
        ));
    }

    #[test]
    fn collect_python_signals_detects_exec_alias_assignment() {
        assert!(has_call(
            "import builtins\nrunner = getattr(builtins, 'exec')\nrunner('print(1)')",
            PythonCallKind::Exec,
        ));
    }

    #[test]
    fn collect_python_signals_detects_eval_alias_assignment() {
        assert!(has_call(
            "import builtins\nrunner = builtins.eval\nrunner('1 + 1')",
            PythonCallKind::Eval,
        ));
    }

    #[test]
    fn collect_python_signals_does_not_treat_maya_mel_eval_as_builtin_eval() {
        assert!(!has_call(
            "import maya.mel as mm\nmm.eval('setProject \"asset/example\";')",
            PythonCallKind::Eval,
        ));
    }

    #[test]
    fn collect_python_signals_does_not_treat_unknown_member_eval_as_builtin_eval() {
        assert!(!has_call("runner.eval('sample')", PythonCallKind::Eval,));
    }

    #[test]
    fn collect_python_signals_clears_alias_after_reassignment() {
        assert_eq!(
            call_count(
                "import builtins\nrunner = getattr(builtins, 'exec')\nrunner = print\nrunner('print(1)')",
                PythonCallKind::Exec,
            ),
            0,
        );
    }

    #[test]
    fn collect_python_signals_normalizes_python2_print_statements() {
        assert!(!has_parse_failure(
            "print 'start scriptNode ExampleGroup'\nprint 'done'"
        ));
    }

    #[test]
    fn collect_python_signals_normalizes_python2_exec_statement() {
        assert!(has_call("exec 'print(1)'", PythonCallKind::Exec));
    }

    #[test]
    fn collect_python_signals_normalizes_python2_except_and_raise() {
        assert!(!has_parse_failure(
            "try:\n    pass\nexcept RuntimeError, err:\n    raise ValueError, err"
        ));
    }

    #[test]
    fn collect_python_signals_marks_assembled_exec_body_via_assignment() {
        assert!(has_assembled_call(
            "code = 'pri' + 'nt(1)'\nexec(code)",
            PythonCallKind::Exec,
        ));
    }

    #[test]
    fn collect_python_signals_does_not_mark_non_sink_string_concat_as_body_assembly() {
        assert!(!has_assembled_call(
            "dLayer = 'layer'\ncmds.setAttr(dLayer + '.color', 13)",
            PythonCallKind::Exec,
        ));
    }

    #[test]
    fn collect_python_signals_does_not_mark_join_without_sink_as_hard_marker() {
        let signals =
            collect_python_signals("target = '.'.join([node_name, 'attr_name'])\nuse(target)");

        assert!(
            signals
                .iter()
                .all(|signal| !matches!(signal, PythonSignal::HardMarker { .. }))
        );
        assert!(!has_assembled_call(
            "target = '.'.join([node_name, 'attr_name'])\nuse(target)",
            PythonCallKind::Exec,
        ));
    }

    #[test]
    fn collect_python_signals_marks_join_when_it_reaches_exec_body() {
        assert!(has_assembled_call(
            "code = ''.join(['pri', 'nt(1)'])\nexec(code)",
            PythonCallKind::Exec,
        ));
    }

    #[test]
    fn collect_python_signals_marks_decode_base64_chr_and_builtins_as_hard_markers() {
        assert!(has_hard_marker("import base64", "base64"));
        assert!(has_hard_marker(
            "value = bytes.fromhex(sample).decode()",
            "hex"
        ));
        assert!(has_hard_marker(
            "value = bytes.fromhex(sample).decode()",
            ".decode("
        ));
        assert!(has_hard_marker(
            "value = base64.b64decode(sample)",
            "base64"
        ));
        assert!(has_hard_marker("value = chr(65)", "chr("));
        assert!(has_hard_marker(
            "value = __builtins__.__dict__[name]",
            "__builtins__"
        ));
        assert!(has_hard_marker(
            "value = globals()[name]",
            "dynamic dispatch"
        ));
    }

    #[test]
    fn collect_python_signals_uses_hard_marker_text_fallback_after_parse_failure() {
        let signals = collect_python_signals("if broken syntax:\n    value = data.decode(");

        assert!(
            signals
                .iter()
                .any(|signal| matches!(signal, PythonSignal::ParseFailure { .. }))
        );
        assert!(signals.iter().any(|signal| {
            matches!(
                signal,
                PythonSignal::HardMarker { markers } if markers.iter().any(|marker| marker == ".decode(")
            )
        }));
    }
}

#[cfg(test)]
mod skeleton_tests;

#[cfg(test)]
mod call_target_tests;
