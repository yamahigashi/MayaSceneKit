use super::*;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum ScopeKind {
    #[default]
    Module,
    Function,
    Class,
    Lambda,
    Comprehension,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct Binding {
    pub aliases: Vec<PythonCallKind>,
    pub modules: Vec<String>,
    pub capabilities: Vec<PythonCapabilityKind>,
    pub strings: Vec<PythonBodyArgKind>,
    pub known_safe: bool,
    pub unbound_local: bool,
}

impl Binding {
    pub fn extend(&mut self, other: Self) {
        self.known_safe &= other.known_safe;
        self.unbound_local |= other.unbound_local;
        extend_unique(&mut self.aliases, other.aliases);
        extend_unique(&mut self.modules, other.modules);
        extend_unique(&mut self.capabilities, other.capabilities);
        extend_unique(&mut self.strings, other.strings);
    }

    pub fn is_maya(&self) -> bool {
        self.modules.iter().any(|module| is_maya_target(module))
    }
}

fn extend_unique<T: PartialEq>(values: &mut Vec<T>, additions: Vec<T>) {
    for value in additions {
        if !values.contains(&value) {
            values.push(value);
        }
    }
}

#[derive(Default)]
pub(super) struct Scope {
    pub kind: ScopeKind,
    pub aliases: HashMap<String, Vec<PythonCallKind>>,
    pub modules: HashMap<String, Vec<String>>,
    pub capabilities: HashMap<String, Vec<PythonCapabilityKind>>,
    pub strings: HashMap<String, Vec<PythonBodyArgKind>>,
    pub bound: HashSet<String>,
    pub globals: HashSet<String>,
    pub nonlocals: HashSet<String>,
    candidates: HashMap<String, Binding>,
    shadowed: HashMap<String, Binding>,
    safe_callables: HashSet<String>,
    unbound_locals: HashSet<String>,
}

impl Scope {
    fn current_binding(&self, name: &str) -> Binding {
        Binding {
            aliases: self.aliases.get(name).cloned().unwrap_or_default(),
            modules: self.modules.get(name).cloned().unwrap_or_default(),
            capabilities: self.capabilities.get(name).cloned().unwrap_or_default(),
            strings: self.strings.get(name).cloned().unwrap_or_default(),
            known_safe: self.safe_callables.contains(name),
            unbound_local: self.unbound_locals.contains(name),
        }
    }

    pub fn binding(&self, name: &str) -> Binding {
        let mut binding = self.current_binding(name);
        if let Some(candidates) = self.candidates.get(name) {
            binding.extend(candidates.clone());
        }
        binding
    }

    pub(super) fn write(&mut self, name: &str, binding: Binding, candidate: bool) {
        self.bound.insert(name.to_string());
        if candidate {
            self.merge_candidate(name, binding);
            return;
        }
        if binding.known_safe {
            self.safe_callables.insert(name.to_string());
        } else {
            self.safe_callables.remove(name);
        }
        if binding.unbound_local {
            self.unbound_locals.insert(name.to_string());
        } else {
            self.unbound_locals.remove(name);
        }
        replace(&mut self.aliases, name, binding.aliases);
        replace(&mut self.modules, name, binding.modules);
        replace(&mut self.capabilities, name, binding.capabilities);
        replace(&mut self.strings, name, binding.strings);
    }

    fn remove_binding(&mut self, name: &str) {
        self.write(name, Binding::default(), false);
        self.bound.remove(name);
        self.candidates.remove(name);
        self.shadowed.remove(name);
    }

    pub fn merge_candidate(&mut self, name: &str, binding: Binding) {
        if let Some(previous) = self.candidates.get_mut(name) {
            previous.extend(binding);
        } else {
            self.candidates.insert(name.to_string(), binding);
        }
    }

    pub fn invalidate_modules(&mut self, name: &str) {
        self.modules.remove(name);
        if let Some(candidates) = self.candidates.get_mut(name) {
            candidates.modules.clear();
        }
    }
}

fn replace<T>(map: &mut HashMap<String, Vec<T>>, name: &str, values: Vec<T>) {
    if values.is_empty() {
        map.remove(name);
    } else {
        map.insert(name.to_string(), values);
    }
}

impl SignalVisitor {
    fn declared_owner(&self, index: usize, name: &str) -> Option<usize> {
        let scope = &self.scopes[index];
        if scope.globals.contains(name) {
            return Some(0);
        }
        if scope.nonlocals.contains(name) {
            return (1..index).rev().find(|&parent| {
                matches!(
                    self.scopes[parent].kind,
                    ScopeKind::Function | ScopeKind::Lambda
                ) && self.scopes[parent].bound.contains(name)
            });
        }
        None
    }

    fn binding_scope_from(&self, name: &str, last: usize, skip_class: bool) -> Option<usize> {
        for index in (0..=last).rev() {
            let scope = &self.scopes[index];
            if (index != last || skip_class) && scope.kind == ScopeKind::Class {
                continue;
            }
            if let Some(owner) = self.declared_owner(index, name) {
                return Some(owner);
            }
            if scope.bound.contains(name) {
                return Some(index);
            }
        }
        None
    }

    fn binding_scope(&self, name: &str) -> Option<usize> {
        self.binding_scope_from(name, self.scopes.len().checked_sub(1)?, false)
            .filter(|&index| index != 0 || self.scopes[index].bound.contains(name))
    }

    pub(super) fn resolve_name_from(&self, name: &str, last: usize) -> Binding {
        if let Some(index) = self.binding_scope_from(name, last, false)
            && (index != 0 || self.scopes[index].bound.contains(name))
        {
            return self.scopes[index].binding(name);
        }
        builtin_binding(name)
    }

    pub(super) fn resolve_name(&self, name: &str) -> Binding {
        self.scopes
            .len()
            .checked_sub(1)
            .map(|last| self.resolve_name_from(name, last))
            .unwrap_or_else(|| builtin_binding(name))
    }

    pub(super) fn hidden_value(&self, expr: &ast::Expr) -> Binding {
        match expr {
            ast::Expr::Name(name) => self
                .binding_scope(name.id.as_str())
                .and_then(|index| self.scopes[index].shadowed.get(name.id.as_str()))
                .cloned()
                .unwrap_or_default(),
            ast::Expr::Attribute(attr) => {
                member_binding(self.hidden_value(&attr.value), attr.attr.as_str())
            }
            _ => Binding::default(),
        }
    }

    fn hidden_name(&self, name: &str, owner: usize) -> Binding {
        let mut binding = builtin_binding(name);
        if let Some(index) = self.binding_scope_from(name, owner, false) {
            binding.extend(self.scopes[index].binding(name));
            if let Some(shadowed) = self.scopes[index].shadowed.get(name) {
                binding.extend(shadowed.clone());
            }
        }
        binding
    }

    pub(super) fn resolve_value(&self, expr: &ast::Expr) -> Binding {
        match expr {
            ast::Expr::Name(name) => self.resolve_name(name.id.as_str()),
            ast::Expr::Lambda(_) => Binding {
                known_safe: true,
                ..Binding::default()
            },
            ast::Expr::Attribute(attr) => {
                member_binding(self.resolve_value(&attr.value), attr.attr.as_str())
            }
            ast::Expr::Call(call) => {
                let mut binding = Binding::default();
                if let Some(kind) = indirect_call_name(call).and_then(direct_call_kind) {
                    binding.aliases.push(kind);
                }
                if self
                    .resolve_value(&call.func)
                    .aliases
                    .contains(&PythonCallKind::Import)
                    && let Some(module) = call.args.first().and_then(string_literal_expr)
                {
                    binding
                        .modules
                        .push(module.split('.').next().unwrap_or(module).to_string());
                }
                binding
            }
            ast::Expr::Subscript(value) => Binding {
                aliases: subscript_call_name(value)
                    .and_then(direct_call_kind)
                    .into_iter()
                    .collect(),
                ..Binding::default()
            },
            ast::Expr::NamedExpr(value) => self.resolve_value(&value.value),
            _ => Binding::default(),
        }
    }

    pub(super) fn assigned_value(&self, expr: &ast::Expr) -> Binding {
        let mut binding = self.resolve_value(expr);
        if let ast::Expr::Name(name) = expr
            && self.binding_scope(name.id.as_str()).is_none()
        {
            binding.known_safe = observed_safe_builtin(name.id.as_str());
        }
        if let Some(value) = tracked_python_string_value(expr, self) {
            binding.strings = vec![value];
        }
        binding
    }

    pub(super) fn iterable_value(&self, expr: &ast::Expr) -> Binding {
        let values = match expr {
            ast::Expr::List(value) => &value.elts,
            ast::Expr::Tuple(value) => &value.elts,
            ast::Expr::Set(value) => &value.elts,
            _ => return Binding::default(),
        };
        let mut bindings = values.iter().map(|value| self.assigned_value(value));
        let mut binding = bindings.next().unwrap_or_default();
        for value in bindings {
            binding.extend(value);
        }
        binding
    }

    pub(super) fn bind_name(&mut self, name: &str, binding: Binding, named_expr: bool) {
        let mut index = self.scopes.len() - 1;
        if named_expr {
            while self.scopes[index].kind == ScopeKind::Comprehension {
                index -= 1;
            }
        }
        let owner = self.declared_owner(index, name).unwrap_or(index);
        let hidden = self.hidden_name(name, owner);
        self.scopes[owner]
            .shadowed
            .entry(name.to_string())
            .or_default()
            .extend(hidden);
        let candidate = self.deferred_write(owner, index);
        let before = self.resolve_name_from(name, owner);
        for conditional in &mut self.conditional_bindings {
            if !conditional.finished
                && (conditional.depth == index || (conditional.depth == owner && !candidate))
            {
                conditional
                    .alternatives
                    .entry((owner, name.to_string()))
                    .or_insert_with(|| before.clone());
            }
        }
        if candidate && !self.scopes[owner].bound.contains(name) {
            self.scopes[owner].write(name, before, false);
        }
        self.scopes[owner].write(name, binding, candidate);
    }

    fn deferred_write(&self, owner: usize, index: usize) -> bool {
        owner != index
            && self.scopes[owner + 1..]
                .iter()
                .any(|scope| matches!(scope.kind, ScopeKind::Function | ScopeKind::Lambda))
    }

    pub(super) fn delete_target(&mut self, target: &ast::Expr) {
        match target {
            ast::Expr::Name(name) => {
                let name = name.id.as_str();
                let index = self.scopes.len() - 1;
                let owner = self.declared_owner(index, name).unwrap_or(index);
                if matches!(
                    self.scopes[owner].kind,
                    ScopeKind::Module | ScopeKind::Class
                ) {
                    if self.deferred_write(owner, index) {
                        self.bind_name(name, builtin_binding(name), false);
                    } else {
                        self.bind_name(name, Binding::default(), false);
                        self.scopes[owner].remove_binding(name);
                    }
                } else {
                    self.bind_name(
                        name,
                        Binding {
                            unbound_local: true,
                            ..Binding::default()
                        },
                        false,
                    );
                }
            }
            ast::Expr::Tuple(value) => {
                for target in &value.elts {
                    self.delete_target(target);
                }
            }
            ast::Expr::List(value) => {
                for target in &value.elts {
                    self.delete_target(target);
                }
            }
            _ => self.bind_target(target, Binding::default(), false),
        }
    }

    pub(super) fn bind_target(&mut self, target: &ast::Expr, binding: Binding, named_expr: bool) {
        match target {
            ast::Expr::Name(name) => self.bind_name(name.id.as_str(), binding, named_expr),
            ast::Expr::Tuple(value) => {
                for target in &value.elts {
                    self.bind_target(target, Binding::default(), named_expr);
                }
            }
            ast::Expr::List(value) => {
                for target in &value.elts {
                    self.bind_target(target, Binding::default(), named_expr);
                }
            }
            ast::Expr::Starred(value) => {
                self.bind_target(&value.value, Binding::default(), named_expr)
            }
            ast::Expr::Attribute(attr) => {
                let mut root = attr.value.as_ref();
                while let ast::Expr::Attribute(parent) = root {
                    root = parent.value.as_ref();
                }
                if let ast::Expr::Name(name) = root
                    && self.resolve_name(name.id.as_str()).is_maya()
                {
                    self.bind_name(name.id.as_str(), Binding::default(), named_expr);
                    self.signals.push(PythonSignal::MayaUncertain {
                        message: "Maya module attribute assignment invalidates target resolution"
                            .to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    pub(super) fn prepare_assignment<'a>(
        &self,
        target: &'a ast::Expr,
        value: &ast::Expr,
    ) -> Vec<(&'a ast::Expr, Binding)> {
        let targets = match target {
            ast::Expr::Tuple(value) => Some(&value.elts),
            ast::Expr::List(value) => Some(&value.elts),
            _ => None,
        };
        let values = match value {
            ast::Expr::Tuple(value) => Some(&value.elts),
            ast::Expr::List(value) => Some(&value.elts),
            _ => None,
        };
        if let (Some(targets), Some(values)) = (targets, values)
            && targets.len() == values.len()
        {
            targets
                .iter()
                .zip(values)
                .flat_map(|(target, value)| self.prepare_assignment(target, value))
                .collect()
        } else {
            vec![(target, self.assigned_value(value))]
        }
    }

    pub(super) fn assign_target(
        &mut self,
        target: &ast::Expr,
        value: &ast::Expr,
        named_expr: bool,
    ) {
        for (target, binding) in self.prepare_assignment(target, value) {
            self.bind_target(target, binding, named_expr);
        }
    }

    pub(super) fn enter(&mut self, kind: ScopeKind, bindings: LocalBindings) {
        let mut scope = Scope {
            kind,
            globals: bindings.globals,
            nonlocals: bindings.nonlocals,
            ..Scope::default()
        };
        if matches!(
            kind,
            ScopeKind::Function | ScopeKind::Lambda | ScopeKind::Comprehension
        ) {
            scope.bound = bindings.names;
            for name in scope.globals.iter().chain(&scope.nonlocals) {
                scope.bound.remove(name);
            }
        }
        if let Some(last) = self.scopes.len().checked_sub(1) {
            for name in &scope.bound {
                let mut hidden = builtin_binding(name);
                if let Some(index) = self.binding_scope_from(name, last, true) {
                    hidden.extend(self.scopes[index].binding(name));
                    if let Some(previous) = self.scopes[index].shadowed.get(name) {
                        hidden.extend(previous.clone());
                    }
                }
                scope.shadowed.insert(name.clone(), hidden);
            }
        }
        self.scopes.push(scope);
    }

    pub(super) fn prepare_argument_defaults(&mut self, args: &ast::Arguments) {
        for arg in args
            .posonlyargs
            .iter()
            .chain(&args.args)
            .chain(&args.kwonlyargs)
        {
            if let Some(default) = &arg.default {
                self.pending_evaluations
                    .insert(default.range(), BindingEvaluation::Value);
            }
        }
    }

    pub(super) fn shadow_arguments(&mut self, args: &ast::Arguments) {
        for arg in args
            .posonlyargs
            .iter()
            .chain(&args.args)
            .chain(&args.kwonlyargs)
        {
            let binding = arg
                .default
                .as_ref()
                .map(|default| {
                    self.evaluated_bindings
                        .remove(&default.range())
                        .expect("evaluated parameter default")
                })
                .unwrap_or_default();
            self.bind_name(arg.def.arg.as_str(), binding, false);
        }
        for arg in args.vararg.iter().chain(&args.kwarg) {
            self.bind_name(arg.arg.as_str(), Binding::default(), false);
        }
    }
}

#[derive(Default)]
pub(super) struct LocalBindings {
    pub names: HashSet<String>,
    pub globals: HashSet<String>,
    pub nonlocals: HashSet<String>,
    nested: usize,
    comprehension: usize,
    iterable_ranges: Vec<ast::text_size::TextRange>,
}

impl PythonAstVisitor for LocalBindings {
    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        if self.nested == 0 {
            match stmt {
                ast::Stmt::Global(value) => self
                    .globals
                    .extend(value.names.iter().map(ToString::to_string)),
                ast::Stmt::Nonlocal(value) => self
                    .nonlocals
                    .extend(value.names.iter().map(ToString::to_string)),
                ast::Stmt::FunctionDef(value) => {
                    self.names.insert(value.name.to_string());
                }
                ast::Stmt::AsyncFunctionDef(value) => {
                    self.names.insert(value.name.to_string());
                }
                ast::Stmt::ClassDef(value) => {
                    self.names.insert(value.name.to_string());
                }
                ast::Stmt::Import(value) => {
                    for alias in &value.names {
                        self.names.insert(
                            alias
                                .asname
                                .as_ref()
                                .map(ToString::to_string)
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
                        self.names
                            .insert(alias_local_name(alias.name.as_str(), alias.asname.as_ref()));
                    }
                }
                _ => {}
            }
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        let previous_ranges = self.iterable_ranges.len();
        add_first_comprehension_iterable(expr, &mut self.iterable_ranges);
        let iterable = in_iterable(expr, &self.iterable_ranges);
        if self.nested == 0 && !iterable {
            if let ast::Expr::Name(name) = expr
                && self.comprehension == 0
                && matches!(name.ctx, ast::ExprContext::Store | ast::ExprContext::Del)
            {
                self.names.insert(name.id.to_string());
            }
            if let ast::Expr::NamedExpr(value) = expr {
                collect_target_bindings(&value.target, &mut self.names);
            }
        }
        walk_expr(self, expr);
        self.iterable_ranges.truncate(previous_ranges);
    }

    fn visit_pattern(&mut self, pattern: &ast::Pattern) {
        if self.nested == 0 {
            collect_pattern_bindings(pattern, &mut self.names);
        }
        maya_scene_kit_observe::scene::execution::python_walk::walk_pattern(self, pattern);
    }

    fn at_point(&mut self, point: PythonWalkPoint<'_>) {
        if self.nested == 0
            && let PythonWalkPoint::BeforeHandlerBody(handler) = point
            && let Some(name) = &handler.name
        {
            self.names.insert(name.to_string());
        }
    }

    fn enter_scope(&mut self, scope: PythonScope<'_>) {
        if matches!(scope, PythonScope::Comprehension { .. }) {
            self.comprehension += 1;
        } else {
            self.nested += 1;
        }
    }

    fn leave_scope(&mut self, scope: PythonScope<'_>) {
        if matches!(scope, PythonScope::Comprehension { .. }) {
            self.comprehension -= 1;
        } else {
            self.nested -= 1;
        }
    }
}

pub(super) fn collect_local_bindings(body: &[ast::Stmt]) -> LocalBindings {
    let mut bindings = LocalBindings::default();
    walk_suite(&mut bindings, body);
    bindings
}

pub(super) fn collect_pattern_bindings(pattern: &ast::Pattern, names: &mut HashSet<String>) {
    match pattern {
        ast::Pattern::MatchAs(value) => {
            if let Some(name) = &value.name {
                names.insert(name.to_string());
            }
            if let Some(pattern) = &value.pattern {
                collect_pattern_bindings(pattern, names);
            }
        }
        ast::Pattern::MatchStar(value) => {
            if let Some(name) = &value.name {
                names.insert(name.to_string());
            }
        }
        ast::Pattern::MatchSequence(value) => {
            for pattern in &value.patterns {
                collect_pattern_bindings(pattern, names);
            }
        }
        ast::Pattern::MatchMapping(value) => {
            if let Some(name) = &value.rest {
                names.insert(name.to_string());
            }
            for pattern in &value.patterns {
                collect_pattern_bindings(pattern, names);
            }
        }
        ast::Pattern::MatchClass(value) => {
            for pattern in value.patterns.iter().chain(&value.kwd_patterns) {
                collect_pattern_bindings(pattern, names);
            }
        }
        ast::Pattern::MatchOr(value) => {
            for pattern in &value.patterns {
                collect_pattern_bindings(pattern, names);
            }
        }
        ast::Pattern::MatchValue(_) | ast::Pattern::MatchSingleton(_) => {}
    }
}

fn builtin_binding(name: &str) -> Binding {
    Binding {
        aliases: direct_call_kind(name).into_iter().collect(),
        modules: match name {
            "builtins" | "importlib" => vec![name.to_string()],
            _ => Vec::new(),
        },
        capabilities: direct_capability(name).into_iter().collect(),
        ..Binding::default()
    }
}

fn member_binding(receiver: Binding, member: &str) -> Binding {
    let mut members = receiver.modules.into_iter().map(|module| Binding {
        aliases: qualified_call_kind(&module, member).into_iter().collect(),
        capabilities: capability_for_module_member(&module, member)
            .into_iter()
            .collect(),
        known_safe: safe_imported_callable(&module, member),
        modules: vec![format!("{module}.{member}")],
        ..Binding::default()
    });
    let mut binding = members.next().unwrap_or_default();
    for member in members {
        binding.extend(member);
    }
    binding
}

pub(super) fn safe_imported_callable(module: &str, name: &str) -> bool {
    module == "builtins" && observed_safe_builtin(name)
}

fn observed_safe_builtin(name: &str) -> bool {
    use maya_scene_kit_observe::scene::evidence::{
        EffectCertainty, ExecutionEffectClass, ExecutionLanguage,
    };
    maya_scene_kit_observe::scene::execution::observe_source_text(
        &format!("{name}()"),
        ExecutionLanguage::Python,
    )
    .is_ok_and(|catalog| {
        catalog.unit_summaries.len() == 1
            && catalog.unit_summaries.iter().all(|unit| {
                unit.certainty == EffectCertainty::Proven
                    && matches!(
                        unit.effect,
                        ExecutionEffectClass::PureComputation
                            | ExecutionEffectClass::DiagnosticOutput
                            | ExecutionEffectClass::SceneReadOnly
                    )
            })
    })
}

pub(super) fn collect_arguments(args: &ast::Arguments, names: &mut HashSet<String>) {
    for arg in args
        .posonlyargs
        .iter()
        .chain(&args.args)
        .chain(&args.kwonlyargs)
    {
        names.insert(arg.def.arg.to_string());
    }
    for arg in args.vararg.iter().chain(&args.kwarg) {
        names.insert(arg.arg.to_string());
    }
}

pub(super) fn add_first_comprehension_iterable<'a>(
    expr: &'a ast::Expr,
    ranges: &mut Vec<ast::text_size::TextRange>,
) -> Option<&'a ast::Expr> {
    let generators = match expr {
        ast::Expr::ListComp(value) => &value.generators,
        ast::Expr::SetComp(value) => &value.generators,
        ast::Expr::DictComp(value) => &value.generators,
        ast::Expr::GeneratorExp(value) => &value.generators,
        _ => return None,
    };
    generators.first().map(|first| {
        ranges.push(first.iter.range());
        &first.iter
    })
}

pub(super) fn in_iterable(expr: &ast::Expr, ranges: &[ast::text_size::TextRange]) -> bool {
    ranges
        .iter()
        .any(|range| range.contains_range(expr.range()))
}
