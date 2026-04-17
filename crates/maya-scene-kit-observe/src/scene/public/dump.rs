use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{SceneFormat, ScriptNodeEntry, ValidationState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SceneDumpRequireKind {
    MayaVersion,
    Plugin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SceneDumpRequireEntry {
    pub rendered: String,
    pub kind: SceneDumpRequireKind,
}

/// Read-only scene dump facts shared by CLI and GUI adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SceneDumpReport {
    /// Source scene path.
    pub scene_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Integrity summary shared with other read-only APIs.
    pub validation_state: ValidationState,
    /// `requires` entries in discovery order.
    pub requires: Vec<String>,
    /// Structured `requires` entries in discovery order.
    pub require_entries: Vec<SceneDumpRequireEntry>,
    /// Extracted script node bodies in discovery order.
    pub script_entries: Vec<ScriptNodeEntry>,
}

impl SceneDumpReport {
    /// Returns the number of `requires` entries.
    pub fn requires_count(&self) -> usize {
        self.requires.len()
    }

    /// Returns the number of extracted script node bodies.
    pub fn script_entry_count(&self) -> usize {
        self.script_entries.len()
    }
}
