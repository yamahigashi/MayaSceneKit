use std::path::PathBuf;

use super::{SceneFormat, ValidationState};

/// Summary of script node names discovered in a scene.
#[derive(Debug, Clone)]
pub struct ScriptNodeReport {
    /// Source scene path.
    pub scene_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Integrity summary shared with other read-only APIs.
    pub validation_state: ValidationState,
    /// Script node names in discovery order.
    pub nodes: Vec<String>,
}

impl ScriptNodeReport {
    /// Returns the number of discovered script nodes.
    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` when at least one script node exists.
    pub fn exists(&self) -> bool {
        !self.nodes.is_empty()
    }
}

/// One extracted script node body.
#[derive(Debug, Clone)]
pub struct ScriptNodeEntry {
    /// Script node name.
    pub name: String,
    /// Decoded script body text.
    pub body: String,
}

/// Extracted script node bodies for a scene.
#[derive(Debug, Clone)]
pub struct ScriptNodeEntriesReport {
    /// Source scene path.
    pub scene_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Integrity summary shared with other read-only APIs.
    pub validation_state: ValidationState,
    /// Extracted entries.
    pub entries: Vec<ScriptNodeEntry>,
}
