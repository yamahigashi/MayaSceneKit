use std::path::PathBuf;

use serde::Serialize;

use crate::scene::SceneFormat;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbInspectOptions {
    pub max_depth: Option<usize>,
    pub preview_bytes: usize,
}

impl Default for MbInspectOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            preview_bytes: 24,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MbInspectReport {
    pub scene_path: PathBuf,
    pub scene_format: SceneFormat,
    pub root: MbInspectNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MbInspectNode {
    pub tag: String,
    pub offset: usize,
    pub aux: u32,
    pub size: usize,
    pub form_type: Option<String>,
    pub opaque: bool,
    pub payload_preview: Option<String>,
    pub children: Vec<MbInspectNode>,
}
