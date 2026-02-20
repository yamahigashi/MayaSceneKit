use std::f64::consts::PI;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::parser::{MayaBinaryParseError, parse_file};

#[allow(dead_code)]
mod decode;
#[allow(dead_code)]
mod patterns;
mod scene_extract;
#[allow(dead_code)]
mod util;

use self::scene_extract::{
    build_requires_dump_text, build_script_dump_text,
    detect_scene_format as detect_scene_format_impl, extract_requires_from_ma,
    extract_requires_from_mb, extract_scene_paths_from_ma, extract_scene_paths_from_mb,
    extract_script_entries_from_ma, extract_script_entries_from_mb, remove_script_nodes_from_ma,
    remove_script_nodes_from_mb, replace_scene_paths_in_ma, replace_scene_paths_in_mb,
    scan_script_nodes_in_ma, scan_script_nodes_in_mb,
};

#[derive(Debug, Error)]
pub enum SceneToolError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] MayaBinaryParseError),
}

#[derive(Debug, Clone)]
pub struct ScriptNodeReport {
    pub scene_path: PathBuf,
    pub scene_format: String,
    pub nodes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScriptNodeEntry {
    pub name: String,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct ScriptNodeEntriesReport {
    pub scene_path: PathBuf,
    pub scene_format: String,
    pub entries: Vec<ScriptNodeEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    All,
    File,
    Reference,
}

#[derive(Debug, Clone)]
pub struct ScenePathEntry {
    pub node_type: String,
    pub node_name: String,
    pub attr: String,
    pub value: String,
    pub meta: Option<ScenePathMeta>,
}

#[derive(Debug, Clone)]
pub struct ScenePathMeta {
    pub origin: String,
    pub short_name: Option<String>,
    pub reference_node: Option<String>,
    pub format_hint: Option<String>,
    pub color_space: Option<String>,
    pub raw_fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScenePathsReport {
    pub scene_path: PathBuf,
    pub scene_format: String,
    pub entries: Vec<ScenePathEntry>,
}

impl ScenePathsReport {
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

impl ScriptNodeReport {
    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    pub fn exists(&self) -> bool {
        !self.nodes.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct ScriptNodeCleanResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub scene_format: String,
    pub removed_nodes: Vec<String>,
}

impl ScriptNodeCleanResult {
    pub fn removed_count(&self) -> usize {
        self.removed_nodes.len()
    }
}

#[derive(Debug, Clone)]
pub struct ScriptNodeDumpResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub scene_format: String,
    pub dumped_nodes: Vec<String>,
}

impl ScriptNodeDumpResult {
    pub fn dumped_count(&self) -> usize {
        self.dumped_nodes.len()
    }
}

#[derive(Debug, Clone)]
pub struct RequiresDumpResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub scene_format: String,
    pub requires: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PathReplaceRule {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone)]
pub struct PathReplaceResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub scene_format: String,
    pub replaced_count: usize,
}

impl RequiresDumpResult {
    pub fn dumped_count(&self) -> usize {
        self.requires.len()
    }
}

pub fn replace_scene_paths(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    rules: &[PathReplaceRule],
) -> Result<PathReplaceResult, SceneToolError> {
    let src = input_path.as_ref();
    let dst = output_path.as_ref();
    let scene_format = detect_scene_format(src)?;

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    if scene_format == "ma" {
        let original = fs::read(src)?;
        let (rewritten, replaced_count) = replace_scene_paths_in_ma(&original, rules);
        fs::write(dst, rewritten)?;
        return Ok(PathReplaceResult {
            input_path: src.to_path_buf(),
            output_path: dst.to_path_buf(),
            scene_format,
            replaced_count,
        });
    }

    if scene_format == "mb" {
        let mb = parse_file(src)?;
        let (rewritten, replaced_count) = replace_scene_paths_in_mb(&mb.data, &mb.root, rules);
        fs::write(dst, rewritten)?;
        return Ok(PathReplaceResult {
            input_path: src.to_path_buf(),
            output_path: dst.to_path_buf(),
            scene_format,
            replaced_count,
        });
    }

    Err(SceneToolError::Message(format!(
        "Unsupported scene format: {}",
        src.display()
    )))
}

pub fn check_script_nodes(path: impl AsRef<Path>) -> Result<ScriptNodeReport, SceneToolError> {
    let scene_path = path.as_ref();
    let scene_format = detect_scene_format(scene_path)?;

    if scene_format == "ma" {
        let names = scan_script_nodes_in_ma(&fs::read(scene_path)?);
        return Ok(ScriptNodeReport {
            scene_path: scene_path.to_path_buf(),
            scene_format,
            nodes: names,
        });
    }

    if scene_format == "mb" {
        let mb = parse_file(scene_path)?;
        let names = scan_script_nodes_in_mb(&mb.data, &mb.root);
        return Ok(ScriptNodeReport {
            scene_path: scene_path.to_path_buf(),
            scene_format,
            nodes: names,
        });
    }

    Err(SceneToolError::Message(format!(
        "Unsupported scene format: {}",
        scene_path.display()
    )))
}

pub fn collect_script_node_entries(
    path: impl AsRef<Path>,
) -> Result<ScriptNodeEntriesReport, SceneToolError> {
    let scene_path = path.as_ref();
    let scene_format = detect_scene_format(scene_path)?;

    if scene_format == "ma" {
        let entries = extract_script_entries_from_ma(&fs::read(scene_path)?)
            .into_iter()
            .map(|(name, body)| ScriptNodeEntry { name, body })
            .collect();
        return Ok(ScriptNodeEntriesReport {
            scene_path: scene_path.to_path_buf(),
            scene_format,
            entries,
        });
    }

    if scene_format == "mb" {
        let mb = parse_file(scene_path)?;
        let entries = extract_script_entries_from_mb(&mb)
            .into_iter()
            .map(|(name, body)| ScriptNodeEntry { name, body })
            .collect();
        return Ok(ScriptNodeEntriesReport {
            scene_path: scene_path.to_path_buf(),
            scene_format,
            entries,
        });
    }

    Err(SceneToolError::Message(format!(
        "Unsupported scene format: {}",
        scene_path.display()
    )))
}

pub fn collect_scene_paths(
    path: impl AsRef<Path>,
    kind: PathKind,
) -> Result<ScenePathsReport, SceneToolError> {
    let scene_path = path.as_ref();
    let scene_format = detect_scene_format(scene_path)?;

    let entries = if scene_format == "ma" {
        extract_scene_paths_from_ma(&fs::read(scene_path)?)
    } else if scene_format == "mb" {
        extract_scene_paths_from_mb(&parse_file(scene_path)?)
    } else {
        return Err(SceneToolError::Message(format!(
            "Unsupported scene format: {}",
            scene_path.display()
        )));
    };

    let filtered = entries
        .into_iter()
        .filter(|e| match kind {
            PathKind::All => true,
            PathKind::File => e.node_type == "file",
            PathKind::Reference => e.node_type == "reference",
        })
        .collect();

    Ok(ScenePathsReport {
        scene_path: scene_path.to_path_buf(),
        scene_format,
        entries: filtered,
    })
}

pub fn remove_script_nodes(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<ScriptNodeCleanResult, SceneToolError> {
    let src = input_path.as_ref();
    let dst = output_path.as_ref();
    let scene_format = detect_scene_format(src)?;

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    if scene_format == "ma" {
        let original = fs::read(src)?;
        let (cleaned, removed_names) = remove_script_nodes_from_ma(&original);
        fs::write(dst, cleaned)?;
        return Ok(ScriptNodeCleanResult {
            input_path: src.to_path_buf(),
            output_path: dst.to_path_buf(),
            scene_format,
            removed_nodes: removed_names,
        });
    }

    if scene_format == "mb" {
        let mb = parse_file(src)?;
        let (cleaned, removed_names) = remove_script_nodes_from_mb(&mb.data, &mb.root);
        fs::write(dst, cleaned)?;
        return Ok(ScriptNodeCleanResult {
            input_path: src.to_path_buf(),
            output_path: dst.to_path_buf(),
            scene_format,
            removed_nodes: removed_names,
        });
    }

    Err(SceneToolError::Message(format!(
        "Unsupported scene format: {}",
        src.display()
    )))
}

pub fn dump_script_nodes(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<ScriptNodeDumpResult, SceneToolError> {
    let src = input_path.as_ref();
    let dst = output_path.as_ref();
    let scene_format = detect_scene_format(src)?;

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    let entries = if scene_format == "ma" {
        extract_script_entries_from_ma(&fs::read(src)?)
    } else if scene_format == "mb" {
        extract_script_entries_from_mb(&parse_file(src)?)
    } else {
        return Err(SceneToolError::Message(format!(
            "Unsupported scene format: {}",
            src.display()
        )));
    };

    fs::write(
        dst,
        build_script_dump_text(src, &scene_format, &entries).into_bytes(),
    )?;

    Ok(ScriptNodeDumpResult {
        input_path: src.to_path_buf(),
        output_path: dst.to_path_buf(),
        scene_format,
        dumped_nodes: entries.into_iter().map(|(n, _)| n).collect(),
    })
}

pub fn dump_requires(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<RequiresDumpResult, SceneToolError> {
    let src = input_path.as_ref();
    let dst = output_path.as_ref();
    let scene_format = detect_scene_format(src)?;

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    let requires = if scene_format == "ma" {
        extract_requires_from_ma(&fs::read(src)?)
    } else if scene_format == "mb" {
        extract_requires_from_mb(&parse_file(src)?)
    } else {
        return Err(SceneToolError::Message(format!(
            "Unsupported scene format: {}",
            src.display()
        )));
    };

    fs::write(
        dst,
        build_requires_dump_text(src, &scene_format, &requires).into_bytes(),
    )?;

    Ok(RequiresDumpResult {
        input_path: src.to_path_buf(),
        output_path: dst.to_path_buf(),
        scene_format,
        requires,
    })
}

pub fn detect_scene_format(path: impl AsRef<Path>) -> Result<String, SceneToolError> {
    detect_scene_format_impl(path)
}

#[allow(dead_code)]
pub(super) fn looks_like_radians(values: &[f64]) -> bool {
    let threshold = 2.0 * PI + 0.2;
    values
        .iter()
        .filter(|v| v.is_finite())
        .all(|v| v.abs() <= threshold)
}
