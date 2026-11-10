use std::collections::{BTreeSet, HashMap, HashSet};

use maya_scene_kit_observe::scene::execution::{
    normalize_python_compat_source,
    python_walk::{
        PythonAstVisitor, PythonScope, PythonWalkPoint, walk_expr, walk_stmt, walk_suite,
    },
};
use rustpython_parser::{Parse, ast};

mod maya;
pub(crate) use maya::{MayaCall, MayaKind};

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
    let program = parse_python_suite(source).or_else(|| {
        let normalized = normalize_python_compat_source(source);
        ast::Suite::parse(&normalized, "<audit>").ok()
    });
    let Some(program) = program else {
        let mut signals = vec![PythonSignal::ParseFailure {
            message: "python parse failure".to_string(),
        }];
        let markers = crate::audit::analyze::scan_hard_python_obfuscation_markers(source);
        if !markers.is_empty() {
            signals.push(PythonSignal::HardMarker { markers });
        }
        signals.extend(autorun_persistence_marker_signals(source));
        return signals;
    };
    let mut visitor = SignalVisitor::default();
    visitor.alias_scopes.push(HashMap::new());
    visitor.module_alias_scopes.push(HashMap::new());
    visitor.capability_alias_scopes.push(HashMap::new());
    visitor.string_value_scopes.push(HashMap::new());
    walk_suite(&mut visitor, &program);
    visitor
        .signals
        .extend(autorun_persistence_marker_signals(source));
    visitor.signals
}

fn parse_python_suite(source: &str) -> Option<ast::Suite> {
    ast::Suite::parse(source, "<audit>").ok()
}

#[derive(Default)]
struct SignalVisitor {
    signals: Vec<PythonSignal>,
    alias_scopes: Vec<HashMap<String, PythonCallKind>>,
    module_alias_scopes: Vec<HashMap<String, String>>,
    capability_alias_scopes: Vec<HashMap<String, PythonCapabilityKind>>,
    string_value_scopes: Vec<HashMap<String, PythonBodyArgKind>>,
    conditional_bindings: Vec<(usize, BTreeSet<String>)>,
}

impl PythonAstVisitor for SignalVisitor {
    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        let conditional_aliases = matches!(
            stmt,
            ast::Stmt::If(_)
                | ast::Stmt::While(_)
                | ast::Stmt::For(_)
                | ast::Stmt::AsyncFor(_)
                | ast::Stmt::Try(_)
                | ast::Stmt::TryStar(_)
                | ast::Stmt::Match(_)
        )
        .then(|| self.current_module_aliases().cloned().unwrap_or_default());
        if conditional_aliases.is_some() {
            self.conditional_bindings
                .push((self.module_alias_scopes.len(), BTreeSet::new()));
        }
        walk_stmt(self, stmt);
        match stmt {
            ast::Stmt::Import(import) => {
                for alias in &import.names {
                    self.record_capability_module(alias.name.as_str());
                    self.record_hard_markers(hard_markers_for_imported_module(alias.name.as_str()));
                    self.record_module_import_alias(
                        alias
                            .asname
                            .as_ref()
                            .map(|name| name.to_string())
                            .unwrap_or_else(|| {
                                alias
                                    .name
                                    .as_str()
                                    .split('.')
                                    .next()
                                    .unwrap_or(alias.name.as_str())
                                    .to_string()
                            }),
                        if alias.asname.is_some() {
                            alias.name.as_str()
                        } else {
                            alias
                                .name
                                .as_str()
                                .split('.')
                                .next()
                                .unwrap_or(alias.name.as_str())
                        },
                    );
                }
            }
            ast::Stmt::ImportFrom(import) => {
                if let Some(module) = &import.module {
                    self.record_capability_module(module.as_str());
                    self.record_hard_markers(hard_markers_for_imported_module(module.as_str()));
                    for alias in &import.names {
                        if alias.name.as_str() == "*" && is_maya_target(module.as_str()) {
                            self.signals.push(PythonSignal::MayaUncertain {
                                message: "Maya wildcard import leaves callable bindings unresolved"
                                    .to_string(),
                            });
                        }
                        self.record_hard_markers(hard_markers_for_imported_name(
                            module.as_str(),
                            alias.name.as_str(),
                        ));
                        self.record_import_from_alias(
                            if import.level.is_some_and(|level| level.to_u32() != 0) {
                                "<relative>"
                            } else {
                                module.as_str()
                            },
                            alias.name.as_str(),
                            alias_local_name(alias.name.as_str(), alias.asname.as_ref()),
                        );
                    }
                }
            }
            ast::Stmt::Assign(stmt) => {
                let alias_kind = call_kind(
                    &stmt.value,
                    self.current_aliases(),
                    self.current_module_aliases(),
                );
                let module_alias = imported_module_name(&stmt.value, self.current_module_aliases());
                let capability_alias = imported_capability_name(
                    &stmt.value,
                    self.current_module_aliases(),
                    self.current_capability_aliases(),
                );
                let string_value =
                    tracked_python_string_value(&stmt.value, self.current_string_values());
                for expr in &stmt.targets {
                    self.record_alias_assignment(expr, alias_kind);
                    self.record_module_alias_assignment(expr, module_alias.clone());
                    self.record_capability_alias_assignment(expr, capability_alias);
                    self.record_string_value_assignment(expr, string_value.clone());
                }
            }
            ast::Stmt::AugAssign(stmt) => {
                self.clear_aliases_for_target(&stmt.target);
            }
            ast::Stmt::AnnAssign(stmt) => {
                if let Some(expr) = &stmt.value {
                    let alias_kind =
                        call_kind(expr, self.current_aliases(), self.current_module_aliases());
                    let module_alias = imported_module_name(expr, self.current_module_aliases());
                    let capability_alias = imported_capability_name(
                        expr,
                        self.current_module_aliases(),
                        self.current_capability_aliases(),
                    );
                    let string_value =
                        tracked_python_string_value(expr, self.current_string_values());
                    self.record_alias_assignment(&stmt.target, alias_kind);
                    self.record_module_alias_assignment(&stmt.target, module_alias);
                    self.record_capability_alias_assignment(&stmt.target, capability_alias);
                    self.record_string_value_assignment(&stmt.target, string_value);
                } else {
                    self.clear_aliases_for_target(&stmt.target);
                }
            }
            _ => {}
        }
        if let Some(before) = conditional_aliases {
            let after = self.current_module_aliases().cloned().unwrap_or_default();
            let (_, mut changed) = self.conditional_bindings.pop().expect("conditional scope");
            for name in before.keys().chain(after.keys()) {
                if before.get(name) != after.get(name)
                    && before
                        .get(name)
                        .into_iter()
                        .chain(after.get(name))
                        .any(|target| is_maya_target(target))
                {
                    changed.insert(name.clone());
                }
            }
            for name in changed {
                self.set_module_alias(&name, None);
                self.signals.push(PythonSignal::MayaUncertain {
                    message: format!("control flow leaves Maya alias {name} unresolved"),
                });
            }
        }
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        match expr {
            ast::Expr::Call(expr) => {
                self.record_hard_markers(hard_markers_for_call(expr));
                self.visit_call(expr);
            }
            ast::Expr::Attribute(expr) => {
                self.record_hard_markers(hard_markers_for_attribute(expr))
            }
            ast::Expr::Subscript(expr) => {
                self.record_hard_markers(hard_markers_for_subscript(expr))
            }
            ast::Expr::Name(name) => {
                self.record_hard_markers(hard_markers_for_name(name.id.as_str()))
            }
            _ => {}
        }
        let comprehension = matches!(
            expr,
            ast::Expr::ListComp(_)
                | ast::Expr::SetComp(_)
                | ast::Expr::DictComp(_)
                | ast::Expr::GeneratorExp(_)
        );
        // Iterable assignments must not escape into the enclosing analysis frame.
        if comprehension {
            self.alias_scopes
                .push(self.current_aliases().cloned().unwrap_or_default());
            self.module_alias_scopes
                .push(self.current_module_aliases().cloned().unwrap_or_default());
            self.capability_alias_scopes.push(
                self.current_capability_aliases()
                    .cloned()
                    .unwrap_or_default(),
            );
            self.string_value_scopes
                .push(self.current_string_values().cloned().unwrap_or_default());
        }
        walk_expr(self, expr);
        if comprehension {
            self.alias_scopes.pop();
            self.module_alias_scopes.pop();
            self.capability_alias_scopes.pop();
            self.string_value_scopes.pop();
        }
        if let ast::Expr::NamedExpr(expr) = expr {
            let target = imported_module_name(&expr.value, self.current_module_aliases());
            self.record_module_alias_assignment(&expr.target, target);
        }
    }

    fn enter_scope(&mut self, scope: PythonScope<'_>) {
        match scope {
            PythonScope::FunctionBody { name, args, body }
            | PythonScope::AsyncFunctionBody { name, args, body } => {
                self.set_module_alias(name.as_str(), None);
                self.push_body_scope();
                self.shadow_arguments(args);
                let mut names = HashSet::new();
                collect_local_bindings(body, &mut names);
                for name in names {
                    self.set_module_alias(&name, None);
                }
            }
            PythonScope::ClassBody { name, .. } => {
                self.set_module_alias(name.as_str(), None);
                self.push_body_scope();
            }
            PythonScope::LambdaBody { args, .. } => {
                self.module_alias_scopes
                    .push(self.current_module_aliases().cloned().unwrap_or_default());
                self.shadow_arguments(args);
            }
            PythonScope::Comprehension { .. } => {
                self.module_alias_scopes
                    .push(self.current_module_aliases().cloned().unwrap_or_default());
            }
        }
    }

    fn leave_scope(&mut self, scope: PythonScope<'_>) {
        match scope {
            PythonScope::FunctionBody { .. }
            | PythonScope::AsyncFunctionBody { .. }
            | PythonScope::ClassBody { .. } => {
                self.alias_scopes.pop();
                self.capability_alias_scopes.pop();
                self.string_value_scopes.pop();
            }
            PythonScope::LambdaBody { .. } | PythonScope::Comprehension { .. } => {}
        }
        self.module_alias_scopes.pop();
    }

    fn at_point(&mut self, point: PythonWalkPoint<'_>) {
        match point {
            PythonWalkPoint::AfterForIter(target) | PythonWalkPoint::AfterDeleteTarget(target) => {
                self.clear_aliases_for_target(target)
            }
            PythonWalkPoint::AfterWithVars(item) => {
                if let Some(target) = &item.optional_vars {
                    self.clear_aliases_for_target(target);
                }
            }
            PythonWalkPoint::BeforeHandlerBody(handler) => {
                if let Some(name) = &handler.name {
                    self.set_module_alias(name.as_str(), None);
                }
            }
            PythonWalkPoint::AfterComprehensionIter(generator) => {
                self.record_module_alias_assignment(&generator.target, None)
            }
        }
    }
}

impl SignalVisitor {
    fn push_body_scope(&mut self) {
        self.alias_scopes.push(HashMap::new());
        self.module_alias_scopes
            .push(self.module_alias_scopes.last().cloned().unwrap_or_default());
        self.capability_alias_scopes.push(HashMap::new());
        self.string_value_scopes.push(HashMap::new());
    }

    fn shadow_arguments(&mut self, args: &ast::Arguments) {
        for arg in args
            .posonlyargs
            .iter()
            .chain(&args.args)
            .chain(&args.kwonlyargs)
        {
            self.set_module_alias(arg.def.arg.as_str(), None);
        }
        for arg in args.vararg.iter().chain(&args.kwarg) {
            self.set_module_alias(arg.arg.as_str(), None);
        }
    }

    fn visit_call(&mut self, call: &ast::ExprCall) {
        if let ast::Expr::Call(dispatch) = call.func.as_ref()
            && is_dynamic_dispatch_call(dispatch)
            && dispatch
                .args
                .first()
                .and_then(|value| module_name_for_expr(value, self.current_module_aliases()))
                .is_some_and(|target| is_maya_target(&target))
        {
            self.signals.push(PythonSignal::MayaUncertain {
                message: "Maya callable obtained through runtime attribute lookup".to_string(),
            });
        }
        if let Some(target) = module_name_for_expr(&call.func, self.current_module_aliases())
            && let Some(operation) = maya::classify(&target, call)
        {
            self.signals.push(PythonSignal::Maya(operation));
        }
        if let Some(kind) = call_kind(
            &call.func,
            self.current_aliases(),
            self.current_module_aliases(),
        ) {
            self.signals.push(PythonSignal::Call {
                kind,
                first_arg: call
                    .args
                    .first()
                    .map(|arg| classify_python_body_arg(arg, self.current_string_values()))
                    .unwrap_or(PythonBodyArgKind::Dynamic),
            });
        } else if let Some(capability) = capability_from_call(
            &call.func,
            self.current_module_aliases(),
            self.current_capability_aliases(),
        ) {
            self.signals.push(PythonSignal::Capability(capability));
        } else if let Some(capability) = file_write_capability_from_call(&call.func) {
            self.signals.push(PythonSignal::Capability(capability));
        } else if is_maya_python_bridge_name(&call.func) {
            self.signals.push(PythonSignal::UnresolvedCallTarget {
                message: "python call target named `python` is not a Python built-in".to_string(),
            });
        } else if unresolved_dynamic_call(&call.func) {
            self.signals.push(PythonSignal::UnresolvedCallTarget {
                message: "python call target resolved through dynamic dispatch".to_string(),
            });
        }
    }

    fn record_hard_markers(&mut self, markers: Vec<String>) {
        if markers.is_empty() {
            return;
        }
        let already_seen = self.signals.iter().any(|signal| {
            matches!(
                signal,
                PythonSignal::HardMarker { markers: existing }
                    if markers.iter().all(|marker| existing.contains(marker))
            )
        });
        if !already_seen {
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

    fn current_aliases(&self) -> Option<&HashMap<String, PythonCallKind>> {
        self.alias_scopes.last()
    }

    fn current_module_aliases(&self) -> Option<&HashMap<String, String>> {
        self.module_alias_scopes.last()
    }

    fn current_capability_aliases(&self) -> Option<&HashMap<String, PythonCapabilityKind>> {
        self.capability_alias_scopes.last()
    }

    fn current_string_values(&self) -> Option<&HashMap<String, PythonBodyArgKind>> {
        self.string_value_scopes.last()
    }

    fn set_alias(&mut self, name: &str, alias_kind: Option<PythonCallKind>) {
        let Some(scope) = self.alias_scopes.last_mut() else {
            return;
        };
        if let Some(alias_kind) = alias_kind {
            scope.insert(name.to_string(), alias_kind);
        } else {
            scope.remove(name);
        }
    }

    fn set_module_alias(&mut self, name: &str, module: Option<String>) {
        let touches_maya = module.as_deref().is_some_and(is_maya_target)
            || self
                .current_module_aliases()
                .and_then(|scope| scope.get(name))
                .is_some_and(|target| is_maya_target(target));
        if touches_maya
            && let Some((depth, names)) = self.conditional_bindings.last_mut()
            && *depth == self.module_alias_scopes.len()
        {
            names.insert(name.to_string());
        }
        let Some(scope) = self.module_alias_scopes.last_mut() else {
            return;
        };
        if let Some(module) = module {
            scope.insert(name.to_string(), module);
        } else {
            scope.remove(name);
        }
    }

    fn set_capability_alias(&mut self, name: &str, capability: Option<PythonCapabilityKind>) {
        let Some(scope) = self.capability_alias_scopes.last_mut() else {
            return;
        };
        if let Some(capability) = capability {
            scope.insert(name.to_string(), capability);
        } else {
            scope.remove(name);
        }
    }

    fn set_string_value(&mut self, name: &str, value: Option<PythonBodyArgKind>) {
        let Some(scope) = self.string_value_scopes.last_mut() else {
            return;
        };
        if let Some(value) = value {
            scope.insert(name.to_string(), value);
        } else {
            scope.remove(name);
        }
    }

    fn record_alias_assignment(&mut self, target: &ast::Expr, alias_kind: Option<PythonCallKind>) {
        match target {
            ast::Expr::Name(name) => self.set_alias(name.id.as_str(), alias_kind),
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.clear_aliases_for_target(elt);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.clear_aliases_for_target(elt);
                }
            }
            ast::Expr::Starred(expr) => self.clear_aliases_for_target(&expr.value),
            _ => {}
        }
    }

    fn record_module_alias_assignment(&mut self, target: &ast::Expr, module: Option<String>) {
        match target {
            ast::Expr::Name(name) => self.set_module_alias(name.id.as_str(), module),
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.clear_aliases_for_target(elt);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.clear_aliases_for_target(elt);
                }
            }
            ast::Expr::Starred(expr) => self.clear_aliases_for_target(&expr.value),
            ast::Expr::Attribute(attr) => {
                let mut root = attr.value.as_ref();
                while let ast::Expr::Attribute(parent) = root {
                    root = parent.value.as_ref();
                }
                if let ast::Expr::Name(name) = root
                    && self
                        .current_module_aliases()
                        .and_then(|scope| scope.get(name.id.as_str()))
                        .is_some_and(|target| is_maya_target(target))
                {
                    self.set_module_alias(name.id.as_str(), None);
                    self.signals.push(PythonSignal::MayaUncertain {
                        message: "Maya module attribute assignment invalidates target resolution"
                            .to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    fn record_capability_alias_assignment(
        &mut self,
        target: &ast::Expr,
        capability: Option<PythonCapabilityKind>,
    ) {
        match target {
            ast::Expr::Name(name) => self.set_capability_alias(name.id.as_str(), capability),
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.clear_aliases_for_target(elt);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.clear_aliases_for_target(elt);
                }
            }
            ast::Expr::Starred(expr) => self.clear_aliases_for_target(&expr.value),
            _ => {}
        }
    }

    fn record_string_value_assignment(
        &mut self,
        target: &ast::Expr,
        value: Option<PythonBodyArgKind>,
    ) {
        match target {
            ast::Expr::Name(name) => self.set_string_value(name.id.as_str(), value),
            ast::Expr::Tuple(expr) => {
                for elt in &expr.elts {
                    self.clear_aliases_for_target(elt);
                }
            }
            ast::Expr::List(expr) => {
                for elt in &expr.elts {
                    self.clear_aliases_for_target(elt);
                }
            }
            ast::Expr::Starred(expr) => self.clear_aliases_for_target(&expr.value),
            _ => {}
        }
    }

    fn record_module_import_alias(&mut self, local_name: String, module: &str) {
        self.set_module_alias(&local_name, Some(module.to_string()));
    }

    fn record_import_from_alias(&mut self, module: &str, name: &str, local_name: String) {
        self.set_module_alias(&local_name, Some(format!("{module}.{name}")));
        let top = module.split('.').next().unwrap_or(module);
        if let Some(kind) = imported_call_alias(top, name) {
            self.set_alias(&local_name, Some(kind));
        }
        if let Some(capability) = capability_for_imported_name(top, name) {
            self.set_capability_alias(&local_name, Some(capability));
        }
    }

    fn clear_aliases_for_target(&mut self, target: &ast::Expr) {
        self.record_alias_assignment(target, None);
        self.record_module_alias_assignment(target, None);
        self.record_capability_alias_assignment(target, None);
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

fn collect_local_bindings(suite: &[ast::Stmt], names: &mut HashSet<String>) {
    for stmt in suite {
        match stmt {
            ast::Stmt::Assign(value) => {
                for target in &value.targets {
                    collect_target_bindings(target, names);
                }
            }
            ast::Stmt::AnnAssign(value) => collect_target_bindings(&value.target, names),
            ast::Stmt::AugAssign(value) => collect_target_bindings(&value.target, names),
            ast::Stmt::Delete(value) => {
                for target in &value.targets {
                    collect_target_bindings(target, names);
                }
            }
            ast::Stmt::Import(value) => {
                for alias in &value.names {
                    names.insert(
                        alias
                            .asname
                            .as_ref()
                            .map(|name| name.to_string())
                            .unwrap_or_else(|| {
                                alias
                                    .name
                                    .as_str()
                                    .split('.')
                                    .next()
                                    .unwrap_or(alias.name.as_str())
                                    .to_string()
                            }),
                    );
                }
            }
            ast::Stmt::ImportFrom(value) => {
                for alias in &value.names {
                    names.insert(alias_local_name(alias.name.as_str(), alias.asname.as_ref()));
                }
            }
            ast::Stmt::FunctionDef(value) => {
                names.insert(value.name.to_string());
            }
            ast::Stmt::AsyncFunctionDef(value) => {
                names.insert(value.name.to_string());
            }
            ast::Stmt::ClassDef(value) => {
                names.insert(value.name.to_string());
            }
            ast::Stmt::If(value) => {
                collect_local_bindings(&value.body, names);
                collect_local_bindings(&value.orelse, names);
            }
            ast::Stmt::While(value) => {
                collect_local_bindings(&value.body, names);
                collect_local_bindings(&value.orelse, names);
            }
            ast::Stmt::For(value) => {
                collect_target_bindings(&value.target, names);
                collect_local_bindings(&value.body, names);
                collect_local_bindings(&value.orelse, names);
            }
            ast::Stmt::AsyncFor(value) => {
                collect_target_bindings(&value.target, names);
                collect_local_bindings(&value.body, names);
                collect_local_bindings(&value.orelse, names);
            }
            ast::Stmt::With(value) => {
                for item in &value.items {
                    if let Some(target) = &item.optional_vars {
                        collect_target_bindings(target, names);
                    }
                }
                collect_local_bindings(&value.body, names);
            }
            ast::Stmt::AsyncWith(value) => {
                for item in &value.items {
                    if let Some(target) = &item.optional_vars {
                        collect_target_bindings(target, names);
                    }
                }
                collect_local_bindings(&value.body, names);
            }
            ast::Stmt::Try(value) => collect_try_bindings(
                &value.body,
                &value.handlers,
                &value.orelse,
                &value.finalbody,
                names,
            ),
            ast::Stmt::TryStar(value) => collect_try_bindings(
                &value.body,
                &value.handlers,
                &value.orelse,
                &value.finalbody,
                names,
            ),
            ast::Stmt::Match(value) => {
                for case in &value.cases {
                    collect_local_bindings(&case.body, names);
                }
            }
            _ => {}
        }
    }
    for stmt in suite {
        match stmt {
            ast::Stmt::Global(value) => {
                for name in &value.names {
                    names.remove(name.as_str());
                }
            }
            ast::Stmt::Nonlocal(value) => {
                for name in &value.names {
                    names.remove(name.as_str());
                }
            }
            _ => {}
        }
    }
}

fn collect_try_bindings(
    body: &[ast::Stmt],
    handlers: &[ast::ExceptHandler],
    orelse: &[ast::Stmt],
    finalbody: &[ast::Stmt],
    names: &mut HashSet<String>,
) {
    collect_local_bindings(body, names);
    for handler in handlers {
        let ast::ExceptHandler::ExceptHandler(handler) = handler;
        if let Some(name) = &handler.name {
            names.insert(name.to_string());
        }
        collect_local_bindings(&handler.body, names);
    }
    collect_local_bindings(orelse, names);
    collect_local_bindings(finalbody, names);
}

fn call_kind(
    func: &ast::Expr,
    aliases: Option<&HashMap<String, PythonCallKind>>,
    module_aliases: Option<&HashMap<String, String>>,
) -> Option<PythonCallKind> {
    match func {
        ast::Expr::Name(name) => direct_call_kind(name.id.as_str())
            .or_else(|| aliases.and_then(|scope| scope.get(name.id.as_str()).copied())),
        ast::Expr::Attribute(attr) => {
            let module = module_name_for_expr(&attr.value, module_aliases)?;
            qualified_call_kind(&module, attr.attr.as_str())
        }
        ast::Expr::Call(call) => indirect_call_name(call).and_then(direct_call_kind),
        ast::Expr::Subscript(subscript) => {
            subscript_call_name(subscript).and_then(direct_call_kind)
        }
        _ => None,
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

fn capability_from_call(
    func: &ast::Expr,
    module_aliases: Option<&HashMap<String, String>>,
    capability_aliases: Option<&HashMap<String, PythonCapabilityKind>>,
) -> Option<PythonCapabilityKind> {
    match func {
        ast::Expr::Name(name) => direct_capability(name.id.as_str())
            .or_else(|| capability_aliases.and_then(|scope| scope.get(name.id.as_str()).copied())),
        ast::Expr::Attribute(attr) => {
            let module = module_name_for_expr(&attr.value, module_aliases)?;
            capability_for_module_member(&module, attr.attr.as_str())
        }
        _ => None,
    }
}

fn imported_module_name(
    expr: &ast::Expr,
    module_aliases: Option<&HashMap<String, String>>,
) -> Option<String> {
    match expr {
        ast::Expr::Name(name) => {
            module_aliases.and_then(|scope| scope.get(name.id.as_str()).cloned())
        }
        ast::Expr::Attribute(attr) => module_name_for_expr(&attr.value, module_aliases)
            .map(|module| format!("{module}.{}", attr.attr)),
        ast::Expr::Call(call) => {
            let kind = call_kind(&call.func, None, module_aliases)?;
            if kind != PythonCallKind::Import {
                return None;
            }
            call.args
                .first()
                .and_then(string_literal_expr)
                .map(|module| module.split('.').next().unwrap_or(module).to_string())
        }
        _ => None,
    }
}

fn imported_capability_name(
    expr: &ast::Expr,
    module_aliases: Option<&HashMap<String, String>>,
    capability_aliases: Option<&HashMap<String, PythonCapabilityKind>>,
) -> Option<PythonCapabilityKind> {
    capability_from_call(expr, module_aliases, capability_aliases)
}

fn module_name_for_expr(
    expr: &ast::Expr,
    module_aliases: Option<&HashMap<String, String>>,
) -> Option<String> {
    match expr {
        ast::Expr::Name(name) => module_aliases
            .and_then(|scope| scope.get(name.id.as_str()).cloned())
            .or_else(|| match name.id.as_str() {
                "builtins" | "importlib" => Some(name.id.to_string()),
                _ => None,
            }),
        ast::Expr::Call(_) => imported_module_name(expr, module_aliases),
        ast::Expr::Attribute(attr) => module_name_for_expr(&attr.value, module_aliases)
            .map(|module| format!("{module}.{}", attr.attr)),
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

fn unresolved_dynamic_call(func: &ast::Expr) -> bool {
    match func {
        ast::Expr::Call(call) => {
            is_dynamic_dispatch_call(call) && indirect_call_name(call).is_none()
        }
        ast::Expr::Subscript(subscript) => is_dynamic_dispatch_subscript(subscript),
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

fn is_dynamic_dispatch_subscript(subscript: &ast::ExprSubscript) -> bool {
    match subscript.value.as_ref() {
        ast::Expr::Attribute(attr) if attr.attr.as_str() == "__dict__" => {
            string_literal_expr(&subscript.slice).is_none()
        }
        ast::Expr::Call(call) if is_locals_like_dispatch(call) => {
            string_literal_expr(&subscript.slice).is_none()
        }
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
            "getattr" => {
                if call.args.first().is_some_and(expr_names_builtins) {
                    push_marker(&mut markers, "builtins");
                }
            }
            _ => {}
        },
        ast::Expr::Attribute(attr) => {
            match attr.attr.as_str() {
                "decode" => push_marker(&mut markers, ".decode("),
                "hex" | "fromhex" | "unhexlify" => push_marker(&mut markers, "hex"),
                "b64decode" | "standard_b64decode" | "urlsafe_b64decode" => {
                    push_marker(&mut markers, "base64")
                }
                "getattr" => {
                    if call.args.first().is_some_and(expr_names_builtins) {
                        push_marker(&mut markers, "builtins");
                    }
                }
                _ => {}
            }
            if expr_names_builtins(&attr.value) {
                push_marker(&mut markers, "builtins");
            }
        }
        _ => {}
    }
    markers
}

fn hard_markers_for_attribute(attr: &ast::ExprAttribute) -> Vec<String> {
    let mut markers = Vec::new();
    match attr.attr.as_str() {
        "__dict__" if expr_names_builtins(&attr.value) => push_marker(&mut markers, "builtins"),
        "decode" => push_marker(&mut markers, ".decode("),
        "hex" | "fromhex" | "unhexlify" => push_marker(&mut markers, "hex"),
        "b64decode" | "standard_b64decode" | "urlsafe_b64decode" => {
            push_marker(&mut markers, "base64")
        }
        _ => {}
    }
    if expr_names_builtins(&attr.value) {
        push_marker(&mut markers, "builtins");
    }
    markers
}

fn hard_markers_for_subscript(subscript: &ast::ExprSubscript) -> Vec<String> {
    let mut markers = Vec::new();
    if expr_names_builtins(&subscript.value) {
        push_marker(&mut markers, "builtins");
    }
    if matches!(subscript.value.as_ref(), ast::Expr::Call(call) if is_locals_like_dispatch(call)) {
        push_marker(&mut markers, "dynamic dispatch");
    }
    markers
}

fn hard_markers_for_name(name: &str) -> Vec<String> {
    let mut markers = Vec::new();
    if name == "__builtins__" {
        push_marker(&mut markers, "__builtins__");
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

fn hard_markers_for_imported_name(module: &str, name: &str) -> Vec<String> {
    let mut markers = hard_markers_for_imported_module(module);
    match (module, name) {
        ("base64", "b64decode" | "standard_b64decode" | "urlsafe_b64decode") => {
            push_marker(&mut markers, "base64")
        }
        ("binascii", "unhexlify") => push_marker(&mut markers, "hex"),
        ("builtins", "getattr") => push_marker(&mut markers, "builtins"),
        _ => {}
    }
    markers
}

fn expr_names_builtins(expr: &ast::Expr) -> bool {
    match expr {
        ast::Expr::Name(name) => matches!(name.id.as_str(), "builtins" | "__builtins__"),
        ast::Expr::Attribute(attr) => expr_names_builtins(&attr.value),
        ast::Expr::Subscript(subscript) => expr_names_builtins(&subscript.value),
        _ => false,
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

fn classify_python_body_arg(
    expr: &ast::Expr,
    string_values: Option<&HashMap<String, PythonBodyArgKind>>,
) -> PythonBodyArgKind {
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
    string_values: Option<&HashMap<String, PythonBodyArgKind>>,
) -> Option<PythonBodyArgKind> {
    match expr {
        ast::Expr::Constant(constant) => match constant.value {
            ast::Constant::Str(_) | ast::Constant::Bytes(_) => Some(PythonBodyArgKind::Literal),
            _ => None,
        },
        ast::Expr::Name(name) => {
            string_values.and_then(|scope| scope.get(name.id.as_str()).cloned())
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
    string_values: Option<&HashMap<String, PythonBodyArgKind>>,
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
