use std::{collections::HashSet, sync::Arc};

pub type SharedStr = Arc<str>;

#[derive(Default)]
pub(crate) struct StringInterner {
    entries: HashSet<SharedStr>,
}

impl StringInterner {
    pub(crate) fn intern(&mut self, value: &str) -> SharedStr {
        if let Some(existing) = self.entries.get(value) {
            return existing.clone();
        }
        let shared: SharedStr = Arc::from(value);
        self.entries.insert(shared.clone());
        shared
    }

    pub(crate) fn intern_owned(&mut self, value: String) -> SharedStr {
        if let Some(existing) = self.entries.get(value.as_str()) {
            return existing.clone();
        }
        let shared: SharedStr = Arc::from(value);
        self.entries.insert(shared.clone());
        shared
    }
}
