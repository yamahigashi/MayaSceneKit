use std::path::PathBuf;

use super::{SceneFormat, ValidationState};

/// Filter applied when collecting scene paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Return all supported path types.
    All,
    /// Return file texture paths only.
    File,
    /// Return reference paths only.
    Reference,
}

/// Classified storage style for a scene path value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenePathValueStyle {
    /// A value relative to the Maya workspace root.
    PlainRelative,
    /// A normal absolute filesystem path.
    Absolute,
    /// Maya's `prefix//suffix` form where `suffix` is workspace-relative.
    DoubleSlashWorkspaceRelative,
    /// A UNC/network absolute path.
    UncAbsolute,
}

/// Resolution outcome for a scene path value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenePathResolutionStatus {
    Exists,
    Missing,
    Unresolved,
}

/// Resolved path facts for a raw scene path value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenePathResolution {
    /// Original value storage style.
    pub style: ScenePathValueStyle,
    /// Candidate resolved filesystem path when one could be constructed.
    pub resolved_path: Option<PathBuf>,
    /// Resolution status for the candidate path.
    pub status: ScenePathResolutionStatus,
}

/// One discovered path entry from a scene.
#[derive(Debug, Clone)]
pub struct ScenePathEntry {
    /// Node type that owns the path.
    pub node_type: String,
    /// Node name that owns the path.
    pub node_name: String,
    /// Attribute path or shorthand.
    pub attr: String,
    /// Raw path value.
    pub value: String,
    /// Optional metadata collected during extraction.
    pub meta: Option<ScenePathMeta>,
}

/// Supplemental metadata for a path entry.
#[derive(Debug, Clone)]
pub struct ScenePathMeta {
    /// Extraction source identifier.
    pub origin: String,
    /// Short namespace or alias when available.
    pub short_name: Option<String>,
    /// Reference node name when available.
    pub reference_node: Option<String>,
    /// Format hint such as `mayaBinary`.
    pub format_hint: Option<String>,
    /// Reference options string when available.
    pub reference_options: Option<String>,
    /// Color space metadata when available.
    pub color_space: Option<String>,
    /// Raw uninterpreted fields preserved for inspection.
    pub raw_fields: Vec<String>,
    /// Raw chunk form when extracted from MB recovery.
    pub trace_form: Option<String>,
    /// Raw chunk tag when extracted from MB recovery.
    pub trace_tag: Option<String>,
    /// Raw chunk node offset when available.
    pub trace_node_offset: Option<usize>,
    /// Child alignment hint for raw MB provenance.
    pub trace_child_alignment: Option<usize>,
    /// Child header size hint for raw MB provenance.
    pub trace_child_header_size: Option<usize>,
}

/// Aggregate result returned by path collection APIs.
#[derive(Debug, Clone)]
pub struct ScenePathsReport {
    /// Source scene path.
    pub scene_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Integrity summary shared with other read-only APIs.
    pub validation_state: ValidationState,
    /// Collected path entries.
    pub entries: Vec<ScenePathEntry>,
}

impl ScenePathsReport {
    /// Returns the number of collected entries.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}
