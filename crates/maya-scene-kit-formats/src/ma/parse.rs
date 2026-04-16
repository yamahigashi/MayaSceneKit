use crate::{error::SceneToolError, ma::ast::ParsedAsciiScene, mel};

#[path = "parse_add_attr.rs"]
mod parse_add_attr;
#[path = "parse_create_node.rs"]
mod parse_create_node;
#[path = "parse_driver.rs"]
mod parse_driver;
#[path = "parse_links.rs"]
mod parse_links;
#[path = "parse_references.rs"]
mod parse_references;
#[path = "parse_set_attr.rs"]
mod parse_set_attr;
#[path = "parse_support.rs"]
mod parse_support;
#[path = "parse_units.rs"]
mod parse_units;

use self::parse_driver::parse_ascii_scene_document_from_top_level;
#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaParseDiagnosticStage {
    Decode,
    Lex,
    Parse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaParseDiagnostic {
    pub stage: MaParseDiagnosticStage,
    pub message: String,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug)]
pub struct ParsedAsciiSceneDocument {
    pub scene: ParsedAsciiScene,
    pub source_encoding: mel::MelSourceEncoding,
    pub diagnostics: Vec<MaParseDiagnostic>,
}

pub fn parse_ascii_scene(text: &str) -> Result<ParsedAsciiScene, SceneToolError> {
    Ok(parse_ascii_scene_document_from_top_level(mel::collect_top_level_facts(text), true)?.scene)
}

pub fn parse_ascii_scene_bytes(bytes: &[u8]) -> Result<ParsedAsciiSceneDocument, SceneToolError> {
    parse_ascii_scene_document_from_top_level(mel::collect_top_level_facts_from_bytes(bytes), false)
}
