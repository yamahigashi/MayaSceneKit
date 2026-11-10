use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

use rustpython_parser::ast;

use super::PythonBody;

type Values = HashMap<String, Option<String>>;
type Undo = HashMap<String, Option<Option<String>>>;

#[derive(Default)]
pub(crate) struct BodyBindings {
    values: Values,
    undo: Vec<Undo>,
}

impl Deref for BodyBindings {
    type Target = Values;

    fn deref(&self) -> &Values {
        &self.values
    }
}

impl BodyBindings {
    pub(crate) fn insert(&mut self, name: String, value: Option<String>) {
        if self.values.get(&name) == Some(&value) {
            return;
        }
        if let Some(undo) = self.undo.last_mut() {
            undo.entry(name.clone())
                .or_insert_with(|| self.values.get(&name).cloned());
        }
        self.values.insert(name, value);
    }

    fn enter(&mut self) {
        self.undo.push(HashMap::new());
    }

    fn leave(&mut self, ambiguous: bool) {
        let saved = self.undo.pop();
        debug_assert!(saved.is_some(), "balanced body notifications");
        let Some(saved) = saved else { return };
        for (name, value) in saved {
            if ambiguous {
                // Propagate changed names through enclosing isolated bodies.
                if let Some(undo) = self.undo.last_mut() {
                    undo.entry(name.clone()).or_insert_with(|| value.clone());
                }
                self.values.insert(name, None);
            } else if let Some(value) = value {
                self.values.insert(name, value);
            } else {
                self.values.remove(&name);
            }
        }
    }
}

pub(crate) fn leave_body_bindings(
    aliases: &mut BodyBindings,
    strings: &mut BodyBindings,
    ambiguous: bool,
) {
    let changed: HashSet<_> = if ambiguous {
        aliases
            .undo
            .last()
            .into_iter()
            .chain(strings.undo.last())
            .flat_map(|undo| undo.keys().cloned())
            .collect()
    } else {
        HashSet::new()
    };
    aliases.leave(ambiguous);
    strings.leave(ambiguous);
    for name in changed {
        aliases.insert(name.clone(), None);
        strings.insert(name, None);
    }
}

pub(crate) fn enter_body_bindings(
    body: PythonBody<'_>,
    aliases: &mut BodyBindings,
    strings: &mut BodyBindings,
) {
    aliases.enter();
    strings.enter();
    let mut clear = |name: &str| {
        aliases.insert(name.to_string(), None);
        strings.insert(name.to_string(), None);
    };
    match body {
        PythonBody::MatchCase(case) => clear_pattern_bindings(&case.pattern, &mut clear),
        PythonBody::TryStarHandler(handler) => {
            if let Some(name) = &handler.name {
                clear(name.as_str());
            }
        }
        PythonBody::TryStarBody | PythonBody::TryStarElse | PythonBody::TryStarFinally => {}
    }
}

fn clear_pattern_bindings(pattern: &ast::Pattern, clear: &mut impl FnMut(&str)) {
    match pattern {
        ast::Pattern::MatchAs(p) => {
            if let Some(name) = &p.name {
                clear(name.as_str());
            }
            if let Some(pattern) = &p.pattern {
                clear_pattern_bindings(pattern, clear);
            }
        }
        ast::Pattern::MatchStar(p) => {
            if let Some(name) = &p.name {
                clear(name.as_str());
            }
        }
        ast::Pattern::MatchMapping(p) => {
            if let Some(name) = &p.rest {
                clear(name.as_str());
            }
            for pattern in &p.patterns {
                clear_pattern_bindings(pattern, clear);
            }
        }
        ast::Pattern::MatchClass(p) => {
            for pattern in p.patterns.iter().chain(&p.kwd_patterns) {
                clear_pattern_bindings(pattern, clear);
            }
        }
        ast::Pattern::MatchSequence(p) => {
            for pattern in &p.patterns {
                clear_pattern_bindings(pattern, clear);
            }
        }
        ast::Pattern::MatchOr(p) => {
            for pattern in &p.patterns {
                clear_pattern_bindings(pattern, clear);
            }
        }
        ast::Pattern::MatchValue(_) | ast::Pattern::MatchSingleton(_) => {}
    }
}
