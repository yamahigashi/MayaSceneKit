use std::{collections::HashSet, sync::Arc};

use maya_scene_kit_formats::{
    ma::scripts::RawMaScriptEntry,
    mel::{self, MelAuditTopLevelItemFact},
};

use crate::{
    mb::{MbParseBudget, parse_section_chunks_with_hints, resolve_section_layout_hints},
    scene::{
        ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind, ExecutionLanguage,
        ExecutionOrigin, ExecutionSourceRange, ExecutionSurfaceKind, ExecutionTrigger,
        SceneToolError,
        decode::attr::decode_attr_payload,
        ir::{DecodedChunkRecord, DecodedEvent, SetAttrValue},
        recover::{collect_decoded_chunk_records, collect_raw_chunk_records_with_budget},
        schema::{SchemaRegistry, default_schema_registry},
    },
};

#[derive(Debug, Clone)]
pub struct ExecutionSurface {
    pub text: Arc<str>,
    pub origin: ExecutionOrigin,
    pub preview: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PreviewWindowSpec {
    pub(crate) text: Arc<str>,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl PreviewWindowSpec {
    pub(crate) fn new(text: Arc<str>, start: usize, end: usize) -> Self {
        Self { text, start, end }
    }

    pub(crate) fn prefix(text: Arc<str>) -> Self {
        let end = text.len().min(24);
        Self {
            text,
            start: 0,
            end,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutionSurfaceRecord {
    pub(crate) text: Arc<str>,
    pub(crate) origin: ExecutionOrigin,
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutionCoverageIssueRecord {
    pub(crate) kind: ExecutionCoverageIssueKind,
    pub(crate) detail: ExecutionCoverageIssueDetail,
    pub(crate) origin: Option<ExecutionOrigin>,
    pub(crate) preview: PreviewWindowSpec,
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutionCoverageCollection {
    pub(crate) surfaces: Vec<ExecutionSurfaceRecord>,
    pub(crate) coverage_issues: Vec<ExecutionCoverageIssueRecord>,
}

pub(crate) fn collect_execution_coverage_from_ma_parts(
    script_nodes: &[RawMaScriptEntry],
    top_level: &mel::MelAuditTopLevelFacts,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    collect_ma_coverage(script_nodes, top_level)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn collect_execution_coverage_from_mb(
    mb: &crate::mb::MayaBinaryFile,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    collect_execution_coverage_from_mb_with_budget(mb, &MbParseBudget::default())
}

pub(crate) fn collect_execution_coverage_from_mb_with_budget(
    mb: &crate::mb::MayaBinaryFile,
    budget: &MbParseBudget,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    collect_mb_coverage(mb, budget)
}

fn collect_ma_coverage(
    script_nodes: &[RawMaScriptEntry],
    top_level: &mel::MelAuditTopLevelFacts,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    let mut surfaces = collect_ma_script_node_surfaces(script_nodes);
    let coverage_issues = top_level
        .diagnostics
        .iter()
        .map(|diagnostic| {
            let preview_span = top_level.preview_span(diagnostic.span);
            ExecutionCoverageIssueRecord {
                kind: ExecutionCoverageIssueKind::TopLevelDiagnostics,
                detail: ExecutionCoverageIssueDetail::TopLevelDiagnostics {
                    diagnostic: diagnostic.message.to_string(),
                },
                origin: None,
                preview: PreviewWindowSpec::new(
                    top_level.preview_text(),
                    preview_span.start,
                    preview_span.end,
                ),
            }
        })
        .collect::<Vec<_>>();

    let mut coverage_issues = coverage_issues;
    for item in &top_level.items {
        match item {
            MelAuditTopLevelItemFact::Command(command) => {
                match classify_top_level_command(command.head.as_ref()) {
                    MaTopLevelAuditClass::ExecutionSurface | MaTopLevelAuditClass::Ignore => {
                        push_command_surface(
                            &mut surfaces,
                            command.source_text(top_level),
                            ExecutionSurfaceKind::TopLevelCommand,
                            ExecutionTrigger::FileOpen,
                            Some(command.head.to_string()),
                            Some(ExecutionSourceRange {
                                start: command.source_span.start,
                                end: command.source_span.end,
                            }),
                        );
                    }
                    MaTopLevelAuditClass::FileDependencyOnly => {}
                }
                if let Some(callback) = &command.file_command_callback {
                    surfaces.push(ExecutionSurfaceRecord {
                        text: Arc::<str>::from(callback.as_str()),
                        origin: ExecutionOrigin {
                            lang: ExecutionLanguage::Mel,
                            trigger: ExecutionTrigger::FileOpen,
                            surface_kind: ExecutionSurfaceKind::FileCommandCallback,
                            node_name: None,
                            attr_name: Some("-command".to_string()),
                            source_kind: Some("file -command".to_string()),
                            source_range: Some(ExecutionSourceRange {
                                start: command.source_span.start,
                                end: command.source_span.end,
                            }),
                            chunk_form: None,
                            chunk_tag: None,
                            chunk_node_offset: None,
                        },
                    });
                }
            }
            MelAuditTopLevelItemFact::Proc(proc_def) => {
                coverage_issues.push(ExecutionCoverageIssueRecord {
                    kind: ExecutionCoverageIssueKind::UnsupportedCoverage,
                    detail: ExecutionCoverageIssueDetail::UnsupportedProcDefinition {
                        is_global: proc_def.is_global,
                    },
                    origin: None,
                    preview: {
                        let preview_span = top_level.preview_span(proc_def.span);
                        PreviewWindowSpec::new(
                            top_level.preview_text(),
                            preview_span.start,
                            preview_span.end,
                        )
                    },
                });
                push_command_surface(
                    &mut surfaces,
                    proc_def.source_text(top_level),
                    ExecutionSurfaceKind::TopLevelProcDefinition,
                    ExecutionTrigger::Unknown,
                    Some("proc_definition".to_string()),
                    Some(ExecutionSourceRange {
                        start: proc_def.source_span.start,
                        end: proc_def.source_span.end,
                    }),
                );
            }
            MelAuditTopLevelItemFact::Other(other) => {
                if let Some(head) = classify_top_level_other(other.source_text(top_level)) {
                    push_command_surface(
                        &mut surfaces,
                        other.source_text(top_level),
                        ExecutionSurfaceKind::TopLevelCommand,
                        ExecutionTrigger::FileOpen,
                        Some(head.to_string()),
                        Some(ExecutionSourceRange {
                            start: other.source_span.start,
                            end: other.source_span.end,
                        }),
                    );
                } else {
                    coverage_issues.push(ExecutionCoverageIssueRecord {
                        kind: ExecutionCoverageIssueKind::UnsupportedCoverage,
                        detail: ExecutionCoverageIssueDetail::UnsupportedTopLevelStatement,
                        origin: None,
                        preview: {
                            let preview_span = top_level.preview_span(other.span);
                            PreviewWindowSpec::new(
                                top_level.preview_text(),
                                preview_span.start,
                                preview_span.end,
                            )
                        },
                    });
                    push_command_surface(
                        &mut surfaces,
                        other.source_text(top_level),
                        ExecutionSurfaceKind::TopLevelOtherStatement,
                        ExecutionTrigger::FileOpen,
                        Some("top_level_other".to_string()),
                        Some(ExecutionSourceRange {
                            start: other.source_span.start,
                            end: other.source_span.end,
                        }),
                    );
                }
            }
        }
    }

    Ok(ExecutionCoverageCollection {
        surfaces,
        coverage_issues,
    })
}

fn collect_ma_script_node_surfaces(
    script_nodes: &[RawMaScriptEntry],
) -> Vec<ExecutionSurfaceRecord> {
    let mut surfaces = Vec::with_capacity(script_nodes.len());

    for node in script_nodes {
        if node.body.is_empty() {
            continue;
        }
        let trigger = node
            .script_type
            .map(script_type_to_trigger)
            .unwrap_or(ExecutionTrigger::Manual);
        let lang = node
            .source_type
            .map(script_source_type_to_language)
            .unwrap_or(ExecutionLanguage::Mel);
        let source_kind = match (node.script_type, node.source_type) {
            (Some(script_type), Some(source_type)) => {
                Some(format!("scriptType={script_type},sourceType={source_type}"))
            }
            (Some(script_type), None) => Some(format!("scriptType={script_type}")),
            (None, Some(source_type)) => Some(format!("sourceType={source_type}")),
            (None, None) => None,
        };
        surfaces.push(ExecutionSurfaceRecord {
            text: Arc::<str>::from(node.body.as_str()),
            origin: ExecutionOrigin {
                lang,
                trigger,
                surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
                node_name: Some(node.name.clone()),
                attr_name: Some(".b".to_string()),
                source_range: None,
                source_kind,
                chunk_form: None,
                chunk_tag: None,
                chunk_node_offset: None,
            },
        });
    }

    surfaces
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaTopLevelAuditClass {
    ExecutionSurface,
    FileDependencyOnly,
    Ignore,
}

fn classify_top_level_command(head: &str) -> MaTopLevelAuditClass {
    match head {
        "python" | "eval" | "evalDeferred" | "scriptJob" | "source" | "loadPlugin"
        | "commandPort" | "print" | "warning" | "error" | "confirmDialog" | "headsUpMessage" => {
            MaTopLevelAuditClass::ExecutionSurface
        }
        "file" => MaTopLevelAuditClass::FileDependencyOnly,
        _ => MaTopLevelAuditClass::Ignore,
    }
}

fn classify_top_level_other(source_text: &str) -> Option<&'static str> {
    let trimmed = source_text.trim_start();
    [
        "python",
        "eval",
        "evalDeferred",
        "scriptJob",
        "source",
        "loadPlugin",
        "commandPort",
        "print",
        "warning",
        "error",
        "confirmDialog",
        "headsUpMessage",
    ]
    .into_iter()
    .find(|head| trimmed.starts_with(head) && trimmed[head.len()..].starts_with('('))
}

fn collect_mb_coverage(
    mb: &crate::mb::MayaBinaryFile,
    budget: &MbParseBudget,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    let mut surfaces = collect_mb_native_script_surfaces(mb);
    let raw_chunks = collect_raw_chunk_records_with_budget(mb, budget)?;
    let decoded_chunks = collect_decoded_chunk_records(
        &raw_chunks,
        mb.data.as_ref(),
        Arc::new(SchemaRegistry::new(
            default_schema_registry().paths().clone(),
        )),
    );
    let canonical_bodies = surfaces
        .iter()
        .filter_map(|surface| {
            (surface.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody)
                .then_some((surface.origin.chunk_node_offset, surface.text.clone()))
        })
        .collect::<HashSet<_>>();
    let mut seen_raw = HashSet::new();
    for (raw, decoded) in raw_chunks.into_iter().zip(decoded_chunks.iter()) {
        if !decoded_chunk_may_contain_execution_text(decoded) {
            continue;
        }
        let Some(text) =
            decode_raw_chunk_text(raw.chunk_ref.tag.as_str(), raw.payload(mb.data.as_ref()))
        else {
            continue;
        };
        if !contains_any_audit_marker(&text) {
            continue;
        }
        if canonical_bodies.contains(&(
            Some(raw.chunk_ref.node_offset),
            Arc::<str>::from(text.as_str()),
        )) {
            continue;
        }
        let key = (
            raw.chunk_ref.form.clone(),
            raw.chunk_ref.tag.clone(),
            raw.chunk_ref.node_offset,
            text.clone(),
        );
        if !seen_raw.insert(key) {
            continue;
        }
        surfaces.push(ExecutionSurfaceRecord {
            text: Arc::<str>::from(text),
            origin: ExecutionOrigin {
                lang: ExecutionLanguage::Unknown,
                trigger: ExecutionTrigger::FileOpen,
                surface_kind: ExecutionSurfaceKind::RawChunkText,
                node_name: None,
                attr_name: None,
                source_range: None,
                source_kind: Some(format!("{}:{}", raw.chunk_ref.form, raw.chunk_ref.tag)),
                chunk_form: Some(raw.chunk_ref.form.clone()),
                chunk_tag: Some(raw.chunk_ref.tag.clone()),
                chunk_node_offset: Some(raw.chunk_ref.node_offset),
            },
        });
    }

    Ok(ExecutionCoverageCollection {
        surfaces,
        coverage_issues: Vec::new(),
    })
}

fn decoded_chunk_may_contain_execution_text(decoded: &DecodedChunkRecord) -> bool {
    decoded
        .events
        .iter()
        .any(decoded_event_may_contain_execution_text)
        || matches!(
            decoded.quality,
            crate::scene::SchemaDecodeAttemptResult::Failed
        )
}

fn decoded_event_may_contain_execution_text(event: &DecodedEvent) -> bool {
    match event {
        DecodedEvent::ScriptBody { body } => !body.trim().is_empty(),
        DecodedEvent::SetAttr(op) => {
            op.attr_name_or_path == ".b"
                && matches!(&op.value, SetAttrValue::String(body) if !body.trim().is_empty())
        }
        DecodedEvent::Unknown(_) => true,
        DecodedEvent::CreateNode { .. }
        | DecodedEvent::AddAttr(_)
        | DecodedEvent::Connect { .. }
        | DecodedEvent::Relationship { .. }
        | DecodedEvent::SelectTarget { .. }
        | DecodedEvent::RefEdit { .. }
        | DecodedEvent::ReferenceFile { .. } => false,
    }
}

fn collect_mb_native_script_surfaces(
    mb: &crate::mb::MayaBinaryFile,
) -> Vec<ExecutionSurfaceRecord> {
    let mut surfaces = Vec::new();
    let mut seen = HashSet::new();

    for child in &mb.root.children {
        if child.form_type.as_deref() != Some("SCRP") {
            continue;
        }
        let (child_alignment, child_header_size) = resolve_section_layout_hints(
            &child.tag,
            child.form_type.as_deref(),
            child.child_alignment,
            child.child_header_size,
        );
        let payload = &mb.data[child.payload_offset..child.payload_end];
        if payload.len() < 4 || &payload[..4] != b"SCRP" {
            continue;
        }

        let parsed =
            parse_section_chunks_with_hints(&payload[4..], child_alignment, child_header_size);
        let mut node_name = format!("<SCRP@0x{:X}>", child.offset);
        let mut script_type = None;
        let mut source_type = None;
        let mut bodies = Vec::new();

        for chunk in parsed.chunks {
            if chunk.tag == "CREA" {
                if let Some(name) = crate::mb::paths::extract_mb_script_node_name_with_layout(
                    payload,
                    child_alignment,
                    child_header_size,
                ) {
                    node_name = name;
                }
                continue;
            }

            let Some((attr_name, _kind, value)) = decode_attr_payload(chunk.payload(&payload[4..]))
            else {
                continue;
            };
            match attr_name.as_str() {
                "b" => {
                    let body = crate::mb::decode_best_effort_script_text(&value);
                    if !body.is_empty() && !bodies.iter().any(|existing| existing == &body) {
                        bodies.push(body);
                    }
                }
                "st" => {
                    script_type = raw_u32_prefix(&value);
                }
                "stp" => {
                    source_type = raw_u32_prefix(&value);
                }
                _ => {}
            }
        }

        let trigger = script_type
            .map(script_type_to_trigger)
            .unwrap_or(ExecutionTrigger::Manual);
        let lang = source_type
            .map(script_source_type_to_language)
            .unwrap_or(ExecutionLanguage::Mel);
        let source_kind = match (script_type, source_type) {
            (Some(script_type), Some(source_type)) => {
                Some(format!("scriptType={script_type},sourceType={source_type}"))
            }
            (Some(script_type), None) => Some(format!("scriptType={script_type}")),
            (None, Some(source_type)) => Some(format!("sourceType={source_type}")),
            (None, None) => None,
        };

        for body in bodies {
            let key = (
                node_name.clone(),
                body.clone(),
                lang.as_str(),
                trigger.as_str(),
                child.offset,
            );
            if !seen.insert(key) {
                continue;
            }
            surfaces.push(ExecutionSurfaceRecord {
                text: Arc::<str>::from(body),
                origin: ExecutionOrigin {
                    lang,
                    trigger,
                    surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
                    node_name: Some(node_name.clone()),
                    attr_name: Some(".b".to_string()),
                    source_range: None,
                    source_kind: source_kind.clone(),
                    chunk_form: Some("SCRP".to_string()),
                    chunk_tag: Some("STR ".to_string()),
                    chunk_node_offset: Some(child.offset),
                },
            });
        }
    }

    surfaces
}

fn push_command_surface(
    surfaces: &mut Vec<ExecutionSurfaceRecord>,
    command: &str,
    surface_kind: ExecutionSurfaceKind,
    trigger: ExecutionTrigger,
    source_kind: Option<String>,
    source_range: Option<ExecutionSourceRange>,
) {
    surfaces.push(ExecutionSurfaceRecord {
        text: Arc::<str>::from(command),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger,
            surface_kind,
            node_name: None,
            attr_name: None,
            source_kind: Some(source_kind.unwrap_or_else(|| "command".to_string())),
            source_range,
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
        },
    });
}

fn script_type_to_trigger(script_type: u32) -> ExecutionTrigger {
    match script_type {
        0 => ExecutionTrigger::Manual,
        1 => ExecutionTrigger::FileOpen,
        2 | 3 => ExecutionTrigger::GuiOpenClose,
        4 | 5 => ExecutionTrigger::Render,
        6 => ExecutionTrigger::FileOpen,
        7 => ExecutionTrigger::TimeChanged,
        _ => ExecutionTrigger::Unknown,
    }
}

fn script_source_type_to_language(source_type: u32) -> ExecutionLanguage {
    match source_type {
        1 => ExecutionLanguage::Python,
        _ => ExecutionLanguage::Mel,
    }
}

fn decode_text_like_payload(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }

    let mut text = String::from_utf8_lossy(payload).into_owned();
    while text.ends_with('\0') {
        text.pop();
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let total_chars = trimmed.chars().count();
    let printable_chars = trimmed
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .count();
    if total_chars == 0 || printable_chars * 5 < total_chars * 4 {
        return None;
    }
    if !trimmed.chars().any(|ch| ch.is_ascii_alphabetic()) {
        return None;
    }

    Some(trimmed.to_string())
}

fn decode_raw_chunk_text(tag: &str, payload: &[u8]) -> Option<String> {
    if tag == "STR " {
        if let Some((attr_name, _kind, value)) = decode_attr_payload(payload) {
            if attr_name == "b" {
                let body = crate::mb::decode_best_effort_script_text(&value);
                let trimmed = body.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    decode_text_like_payload(payload)
}

fn contains_any_audit_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_call_like_token(&lower, "python")
        || contains_call_like_token(&lower, "exec")
        || contains_call_like_token(&lower, "chr")
        || contains_standalone_token(&lower, "eval")
        || contains_standalone_token(&lower, "evaldeferred")
        || contains_standalone_token(&lower, "scriptjob")
        || contains_standalone_token(&lower, "commandport")
        || contains_standalone_token(&lower, "loadplugin")
        || contains_standalone_token(&lower, "source")
}

fn contains_call_like_token(text: &str, needle: &str) -> bool {
    let mut search_start = 0usize;
    while let Some(found) = text[search_start..].find(needle) {
        let start = search_start + found;
        let end = start + needle.len();
        let left_ok = start == 0
            || !text[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !left_ok {
            search_start = end;
            continue;
        }
        let mut cursor = end;
        while let Some(ch) = text[cursor..].chars().next() {
            if ch.is_ascii_whitespace() {
                cursor += ch.len_utf8();
                continue;
            }
            if ch == '(' {
                return true;
            }
            break;
        }
        search_start = end;
    }
    false
}

fn contains_standalone_token(text: &str, needle: &str) -> bool {
    let mut search_start = 0usize;
    while let Some(found) = text[search_start..].find(needle) {
        let start = search_start + found;
        let end = start + needle.len();
        let left_ok = start == 0
            || !text[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        let right_ok = end == text.len()
            || !text[end..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if left_ok && right_ok {
            return true;
        }
        search_start = end;
    }
    false
}

fn raw_u32_prefix(value: &[u8]) -> Option<u32> {
    if let Some(bytes) = value.get(..8) {
        let raw = u64::from_be_bytes(bytes.try_into().ok()?);
        let decoded = f64::from_bits(raw);
        if decoded.is_finite() && decoded >= 0.0 {
            return Some(decoded as u32);
        }
    }
    let bytes = value.get(..4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

pub(crate) fn preview_window(text: &str, start: usize, end: usize, max_preview: usize) -> String {
    if text.is_empty() || max_preview == 0 {
        return String::new();
    }
    let start = clamp_char_boundary(text, start);
    let end = clamp_char_boundary(text, end);
    let chars: Vec<char> = text.chars().collect();
    let start_char = text[..start].chars().count();
    let end_char = text[..end].chars().count();
    let width = max_preview.max(16);
    let half = width / 2;
    let left = start_char.saturating_sub(half);
    let right = std::cmp::min(chars.len(), end_char + half);
    let mut s: String = chars[left..right].iter().collect();
    s = s
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    s
}

fn clamp_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use maya_scene_kit_formats::{ma, mel};

    use super::{
        collect_execution_coverage_from_ma_parts, collect_execution_coverage_from_mb,
        contains_any_audit_marker, decoded_chunk_may_contain_execution_text,
    };
    use crate::scene::{
        ExecutionSurfaceKind, SetAttrOp, SetAttrValue,
        ir::{ChunkRef, CreateNodeFlags, DecodedChunkRecord, DecodedEvent},
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn ma_surfaces_include_file_command_callback_but_not_proc_definition() {
        let input = concat!(
            "//Maya ASCII 2026 scene\n",
            "file -r -command \"onLoad\" \"python(\\\"import os\\\")\" \"C:/ref.ma\";\n",
            "global proc string hello() { return \"ok\"; }\n",
        );

        let script_entries = ma::scripts::extract_raw_script_entries_from_ma(input.as_bytes());
        let top_level = mel::collect_top_level_audit_candidates_from_bytes(input.as_bytes());
        let coverage = collect_execution_coverage_from_ma_parts(&script_entries, &top_level)
            .expect("coverage");
        let surfaces = coverage.surfaces;

        assert!(surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::FileCommandCallback
                && surface.text.as_ref() == r#"python("import os")"#
        }));
        assert!(surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::TopLevelProcDefinition
                && surface.text.as_ref() == r#"global proc string hello() { return "ok"; }"#
        }));
        assert!(!coverage.coverage_issues.is_empty());
    }

    #[test]
    fn ma_surfaces_include_callback_bearing_top_level_command_and_other_statement() {
        let input = concat!(
            "//Maya ASCII 2026 scene\n",
            "nodeOutliner -e -selectCommand \"eval \\\"hello\\\"\" $myoutliner;\n",
            "string $myoutliner = `nodeOutliner -showInputs true -addCommand \"print(\\\"ok\\\")\"`;\n",
        );

        let script_entries = ma::scripts::extract_raw_script_entries_from_ma(input.as_bytes());
        let top_level = mel::collect_top_level_audit_candidates_from_bytes(input.as_bytes());
        let coverage = collect_execution_coverage_from_ma_parts(&script_entries, &top_level)
            .expect("coverage");

        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::TopLevelCommand
                && surface.origin.source_kind.as_deref() == Some("nodeOutliner")
        }));
        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::TopLevelOtherStatement
                && surface.text.contains("-addCommand")
        }));
        assert!(coverage.coverage_issues.iter().any(|issue| {
            matches!(
                issue.detail,
                crate::scene::ExecutionCoverageIssueDetail::UnsupportedTopLevelStatement
            )
        }));
    }

    #[test]
    fn raw_marker_detection_requires_standalone_tokens() {
        assert!(contains_any_audit_marker(r#"source "tools/startup.mel""#));
        assert!(!contains_any_audit_marker(
            "setAttr \".x\" -type \"string\" \"fogSource\";"
        ));
        assert!(!contains_any_audit_marker("socket_blinn1SG"));
    }

    #[test]
    fn structured_non_script_chunks_do_not_remain_raw_execution_candidates() {
        let create_node = DecodedChunkRecord {
            chunk_ref: ChunkRef {
                form: "SCRP".to_string(),
                tag: "CREA".to_string(),
                node_offset: 0x1234,
                parent_tag: Some("FOR8".to_string()),
                chunk_aux: Some(0x7702_0000),
                child_alignment: Some(4),
                child_header_size: Some(16),
                payload_size: 16,
            },
            events: vec![DecodedEvent::CreateNode {
                name: Some("python_socket_manual".to_string()),
                parent: None,
                uid: None,
                create_flags: CreateNodeFlags::default(),
                used_len_prefixed_fields: false,
            }],
            quality: crate::scene::SchemaDecodeAttemptResult::Exact,
        };
        assert!(!decoded_chunk_may_contain_execution_text(&create_node));

        let script_body = DecodedChunkRecord {
            chunk_ref: create_node.chunk_ref.clone(),
            events: vec![DecodedEvent::SetAttr(SetAttrOp {
                attr_name_or_path: ".b".to_string(),
                array_size: None,
                channel_hint: None,
                lock: None,
                keyable: None,
                value: SetAttrValue::String(r#"python("import socket")"#.to_string()),
            })],
            quality: crate::scene::SchemaDecodeAttemptResult::Exact,
        };
        assert!(decoded_chunk_may_contain_execution_text(&script_body));
    }

    #[test]
    fn mb_python_socket_fixture_does_not_promote_scrp_crea_as_raw_surface() {
        let source = repo_root().join("tests/02/sphere.mb");
        let mb = crate::mb::parse_file(&source).expect("parse mb");
        let coverage = collect_execution_coverage_from_mb(&mb).expect("coverage");

        assert!(coverage.surfaces.iter().all(|surface| {
            !(surface.origin.surface_kind == ExecutionSurfaceKind::RawChunkText
                && surface.origin.source_kind.as_deref() == Some("SCRP:CREA"))
        }));
    }
}
