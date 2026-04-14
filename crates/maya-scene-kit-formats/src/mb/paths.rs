#![allow(dead_code)]

// Raw MB path/script helpers are chunk-level transport utilities used by rewrite
// and diagnostics. Canonical inspection APIs should prefer recovered scene state.
use std::collections::HashSet;

use crate::{
    mb::{
        Chunk, MayaBinaryFile, encode_root_chunk, parse_section_chunks_with_hints,
        resolve_section_layout_hints,
    },
    reference_semantics::{
        ScenePathAttrKind, classify_scene_path_attr, normalize_reference_file_type_token,
        parse_reference_options_token,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbScenePathEntry {
    pub node_type: String,
    pub node_name: String,
    pub attr: String,
    pub value: String,
    pub meta: Option<MbScenePathMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbScenePathMeta {
    pub origin: String,
    pub short_name: Option<String>,
    pub reference_node: Option<String>,
    pub format_hint: Option<String>,
    pub reference_options: Option<String>,
    pub color_space: Option<String>,
    pub raw_fields: Vec<String>,
    pub trace_form: Option<String>,
    pub trace_tag: Option<String>,
    pub trace_node_offset: Option<usize>,
    pub trace_child_alignment: Option<usize>,
    pub trace_child_header_size: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbRtftOwnerTrace {
    pub node_name: String,
    pub trace_form: String,
    pub trace_tag: Option<String>,
    pub trace_node_offset: usize,
    pub trace_child_alignment: Option<usize>,
    pub trace_child_header_size: Option<usize>,
}

pub(crate) fn scan_raw_script_nodes_in_mb(data: &[u8], root: &Chunk) -> Vec<String> {
    let mut names = Vec::new();
    for child in &root.children {
        if child.form_type.as_deref() != Some("SCRP") {
            continue;
        }
        let (child_alignment, child_header_size) = resolve_section_layout_hints(
            &child.tag,
            child.form_type.as_deref(),
            child.child_alignment,
            child.child_header_size,
        );
        let payload = &data[child.payload_offset..child.payload_end];
        let name =
            extract_mb_script_node_name_with_layout(payload, child_alignment, child_header_size)
                .unwrap_or_else(|| format!("<SCRP@0x{:X}>", child.offset));
        names.push(name);
    }
    names
}

pub(crate) fn extract_raw_script_entries_from_mb(mb: &MayaBinaryFile) -> Vec<(String, String)> {
    let mut out = Vec::new();
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
        let name =
            extract_mb_script_node_name_with_layout(payload, child_alignment, child_header_size)
                .unwrap_or_else(|| format!("<SCRP@0x{:X}>", child.offset));
        let body =
            extract_script_body_from_scrp_with_layout(payload, child_alignment, child_header_size);
        let key = (name.clone(), body.clone());
        if seen.insert(key.clone()) {
            out.push(key);
        }
    }

    out
}

pub fn remove_raw_script_nodes_from_mb(data: &[u8], root: &Chunk) -> (Vec<u8>, Vec<String>) {
    remove_raw_script_nodes_from_mb_by_name(data, root, &[])
}

pub fn locate_raw_script_node_forms_in_mb_by_name(
    data: &[u8],
    root: &Chunk,
    target_names: &[String],
) -> (Vec<(String, usize)>, Vec<String>) {
    let targets = target_names
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let target_all = targets.is_empty();
    let mut removed_locators = Vec::new();
    let mut removed_names = Vec::new();

    for child in &root.children {
        if child.form_type.as_deref() != Some("SCRP") {
            continue;
        }
        let (child_alignment, child_header_size) = resolve_section_layout_hints(
            &child.tag,
            child.form_type.as_deref(),
            child.child_alignment,
            child.child_header_size,
        );
        let payload = &data[child.payload_offset..child.payload_end];
        let name =
            extract_mb_script_node_name_with_layout(payload, child_alignment, child_header_size)
                .unwrap_or_else(|| format!("<SCRP@0x{:X}>", child.offset));
        let payload_text = String::from_utf8_lossy(payload);
        let matched_target = targets
            .iter()
            .copied()
            .find(|target| name == *target || payload_text.contains(target));
        if !target_all && matched_target.is_none() {
            continue;
        }
        removed_locators.push(("SCRP".to_string(), child.offset));
        removed_names.push(matched_target.unwrap_or(name.as_str()).to_string());
    }

    (removed_locators, removed_names)
}

pub fn remove_root_forms_from_mb_by_locator(
    data: &[u8],
    root: &Chunk,
    target_forms: &[(String, usize)],
) -> (Vec<u8>, Vec<(String, usize)>) {
    let children = &root.children;
    if children.is_empty() {
        return (data.to_vec(), vec![]);
    }

    let targets = target_forms
        .iter()
        .map(|(form, node_offset)| (form.as_str(), *node_offset))
        .collect::<HashSet<_>>();
    if targets.is_empty() {
        return (data.to_vec(), vec![]);
    }

    let mut removed = Vec::new();
    let mut kept_spans = Vec::new();

    for (idx, child) in children.iter().enumerate() {
        let next_offset = if idx + 1 < children.len() {
            children[idx + 1].offset
        } else {
            root.payload_end
        };
        let child_form = child.form_type.as_deref();
        let matched = child_form
            .map(|form| (form, child.offset))
            .filter(|locator| targets.contains(locator));
        if let Some((form, node_offset)) = matched {
            removed.push((form.to_string(), node_offset));
            continue;
        }
        kept_spans.push((child.offset, next_offset));
    }

    if removed.is_empty() {
        return (data.to_vec(), vec![]);
    }

    let Some(encoded) = encode_root_chunk_with_kept_spans(data, root, &kept_spans) else {
        return (data.to_vec(), vec![]);
    };
    (encoded, removed)
}

pub fn remove_raw_script_nodes_from_mb_by_name(
    data: &[u8],
    root: &Chunk,
    target_names: &[String],
) -> (Vec<u8>, Vec<String>) {
    let (removed_locators, removed_names) =
        locate_raw_script_node_forms_in_mb_by_name(data, root, target_names);
    if removed_names.is_empty() {
        return (data.to_vec(), vec![]);
    }
    let (encoded, removed) = remove_root_forms_from_mb_by_locator(data, root, &removed_locators);
    if removed.is_empty() {
        return (data.to_vec(), vec![]);
    }
    (encoded, removed_names)
}

pub fn extract_raw_scene_paths_from_mb(mb: &MayaBinaryFile) -> Vec<MbScenePathEntry> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for child in &mb.root.children {
        let (child_alignment, child_header_size) = resolve_section_layout_hints(
            &child.tag,
            child.form_type.as_deref(),
            child.child_alignment,
            child.child_header_size,
        );
        let form = child.form_type.as_deref().unwrap_or("");
        let payload = &mb.data[child.payload_offset..child.payload_end];

        if form == "FREF" {
            for e in extract_reference_entries_from_fref_payload(
                payload,
                child.offset,
                child_alignment,
                child_header_size,
            ) {
                let key = (
                    e.node_type.clone(),
                    e.node_name.clone(),
                    e.attr.clone(),
                    e.value.clone(),
                );
                if seen.insert(key) {
                    out.push(e);
                }
            }
            continue;
        }
        if form == "FRDI" {
            for e in extract_reference_entries_from_frdi_payload(
                payload,
                child.offset,
                child_alignment,
                child_header_size,
            ) {
                let key = (
                    e.node_type.clone(),
                    e.node_name.clone(),
                    e.attr.clone(),
                    e.value.clone(),
                );
                if seen.insert(key) {
                    out.push(e);
                }
            }
            continue;
        }
        if form == "RTFT" {
            for e in extract_file_entries_from_rtft_payload(
                payload,
                child.offset,
                child_alignment,
                child_header_size,
                Some(child.tag.as_str()),
            ) {
                let key = (
                    e.node_type.clone(),
                    e.node_name.clone(),
                    e.attr.clone(),
                    e.value.clone(),
                );
                if seen.insert(key) {
                    out.push(e);
                }
            }
            continue;
        }
    }

    out
}

pub fn collect_rtft_owner_traces_from_mb(mb: &MayaBinaryFile) -> Vec<MbRtftOwnerTrace> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for child in &mb.root.children {
        if child.form_type.as_deref() != Some("RTFT") {
            continue;
        }
        let Some(node_name) = child
            .children
            .iter()
            .find_map(|chunk| (chunk.tag == "CREA").then_some(chunk))
            .and_then(|chunk| extract_node_name_from_crea_payload(mb.payload(chunk)))
        else {
            continue;
        };
        let trace_tag = child
            .children
            .iter()
            .find_map(|chunk| {
                decode_string_attr_from_rtft_chunk(
                    &chunk.tag,
                    mb.payload(chunk),
                    Some(chunk.aux),
                    Some(child.tag.as_str()),
                )
                .and_then(|(attr_name, _value)| {
                    matches!(
                        classify_scene_path_attr(&attr_name),
                        Some(ScenePathAttrKind::FileTexturePath)
                    )
                    .then(|| chunk.tag.clone())
                })
            })
            .or_else(|| {
                child
                    .children
                    .iter()
                    .find_map(|chunk| (chunk.tag == "STR ").then(|| chunk.tag.clone()))
            });

        let key = (node_name.clone(), child.offset);
        if seen.insert(key) {
            out.push(MbRtftOwnerTrace {
                node_name,
                trace_form: "RTFT".to_string(),
                trace_tag,
                trace_node_offset: child.offset,
                trace_child_alignment: child.child_alignment,
                trace_child_header_size: child.child_header_size,
            });
        }
    }

    out
}

pub fn extract_mb_script_node_name_with_layout(
    payload: &[u8],
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> Option<String> {
    if payload.len() < 4 || &payload[..4] != b"SCRP" {
        return None;
    }

    let parsed = parse_section_chunks_with_hints(&payload[4..], child_alignment, child_header_size);
    for chunk in parsed.chunks {
        if chunk.tag == "CREA" {
            if let Some(name) = decode_crea_name_from_payload(chunk.payload(&payload[4..])) {
                return Some(name);
            }
            break;
        }
    }
    None
}

pub fn decode_best_effort_script_text(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }

    let Some(start) = payload.iter().position(|byte| (32..=126).contains(byte)) else {
        return String::new();
    };

    let mut raw = payload[start..].to_vec();
    while raw.last() == Some(&0) {
        raw.pop();
    }

    String::from_utf8_lossy(&raw).trim().to_string()
}

fn extract_script_body_from_scrp_with_layout(
    payload: &[u8],
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> String {
    if payload.len() < 4 {
        return String::new();
    }
    let mut bodies = Vec::new();
    let parsed = parse_section_chunks_with_hints(&payload[4..], child_alignment, child_header_size);
    for chunk in parsed.chunks {
        if chunk.tag != "STR " {
            continue;
        }
        if let Some((attr_name, _, value)) = decode_attr_triplet(chunk.payload(&payload[4..])) {
            if attr_name == "b" {
                let text = decode_best_effort_script_text(&value);
                if !text.is_empty() {
                    bodies.push(text);
                }
            }
        }
    }
    bodies.join("\n").trim().to_string()
}

fn extract_file_entries_from_rtft_payload(
    payload: &[u8],
    offset: usize,
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
    parent_tag: Option<&str>,
) -> Vec<MbScenePathEntry> {
    if payload.len() < 4 {
        return Vec::new();
    }
    let inner = &payload[4..];
    let parsed = parse_section_chunks_with_hints(inner, child_alignment, child_header_size);
    if parsed.chunks.is_empty() {
        return Vec::new();
    }

    let mut node_name = format!("<RTFT@0x{offset:X}>");
    let mut color_space: Option<String> = None;
    let mut paths: Vec<String> = Vec::new();
    let mut attrs: Vec<String> = Vec::new();

    for chunk in &parsed.chunks {
        let raw = chunk.payload(inner);
        if chunk.tag == "CREA" {
            if let Some(n) = extract_node_name_from_crea_payload(raw) {
                node_name = n;
            }
            continue;
        }
        let Some((attr_name, value)) =
            decode_string_attr_from_rtft_chunk(&chunk.tag, raw, Some(chunk.aux), parent_tag)
        else {
            continue;
        };

        match classify_scene_path_attr(&attr_name) {
            Some(ScenePathAttrKind::FileTexturePath) => paths.push(value.clone()),
            Some(ScenePathAttrKind::FileTextureColorSpace) => color_space = Some(value.clone()),
            _ => {}
        }
        attrs.push(format!("{attr_name}={value}"));
    }

    paths
        .into_iter()
        .map(|path| MbScenePathEntry {
            node_type: "file".to_string(),
            node_name: node_name.clone(),
            attr: ".ftn".to_string(),
            value: path,
            meta: Some(MbScenePathMeta {
                origin: "rtft".to_string(),
                short_name: Some(node_name.clone()),
                reference_node: None,
                format_hint: None,
                reference_options: None,
                color_space: color_space.clone(),
                raw_fields: attrs.clone(),
                trace_form: Some("RTFT".to_string()),
                trace_tag: Some("STR ".to_string()),
                trace_node_offset: Some(offset),
                trace_child_alignment: child_alignment,
                trace_child_header_size: child_header_size,
            }),
        })
        .collect()
}

fn extract_reference_entries_from_fref_payload(
    payload: &[u8],
    offset: usize,
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> Vec<MbScenePathEntry> {
    if payload.len() < 4 {
        return Vec::new();
    }
    let inner = &payload[4..];
    let parsed = parse_section_chunks_with_hints(inner, child_alignment, child_header_size);

    let mut out = Vec::new();
    for chunk in parsed.chunks {
        if chunk.tag != "FREF" {
            continue;
        }
        if let Some(entry) = decode_reference_from_fref_chunk(
            chunk.payload(inner),
            offset,
            child_alignment,
            child_header_size,
        ) {
            out.push(entry);
        }
    }
    out
}

fn extract_reference_entries_from_frdi_payload(
    payload: &[u8],
    offset: usize,
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> Vec<MbScenePathEntry> {
    if payload.len() < 4 {
        return Vec::new();
    }
    let inner = &payload[4..];
    let parsed = parse_section_chunks_with_hints(inner, child_alignment, child_header_size);

    let mut out = Vec::new();
    for chunk in parsed.chunks {
        if chunk.tag != "FRDI" {
            continue;
        }
        if let Some(entry) = decode_reference_from_frdi_chunk(
            chunk.payload(inner),
            offset,
            child_alignment,
            child_header_size,
        ) {
            out.push(entry);
        }
    }
    out
}

fn decode_reference_from_fref_chunk(
    payload: &[u8],
    offset: usize,
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> Option<MbScenePathEntry> {
    let record = parse_fref_record(payload)?;
    Some(MbScenePathEntry {
        node_type: "reference".to_string(),
        node_name: record.reference_node.clone(),
        attr: ".fn".to_string(),
        value: record.path,
        meta: Some(MbScenePathMeta {
            origin: "fref".to_string(),
            short_name: record.short_name,
            reference_node: Some(record.reference_node),
            format_hint: record.format_hint,
            reference_options: record.reference_options,
            color_space: None,
            raw_fields: record.raw_fields,
            trace_form: Some("FREF".to_string()),
            trace_tag: Some("FREF".to_string()),
            trace_node_offset: Some(offset),
            trace_child_alignment: child_alignment,
            trace_child_header_size: child_header_size,
        }),
    })
}

fn decode_reference_from_frdi_chunk(
    payload: &[u8],
    offset: usize,
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> Option<MbScenePathEntry> {
    let record = parse_frdi_record(payload)?;
    Some(MbScenePathEntry {
        node_type: "reference".to_string(),
        node_name: record.reference_node.clone(),
        attr: ".fn".to_string(),
        value: record.path,
        meta: Some(MbScenePathMeta {
            origin: "frdi".to_string(),
            short_name: record.short_name,
            reference_node: Some(record.reference_node),
            format_hint: record.format_hint,
            reference_options: record.reference_options,
            color_space: None,
            raw_fields: record.raw_fields,
            trace_form: Some("FRDI".to_string()),
            trace_tag: Some("FRDI".to_string()),
            trace_node_offset: Some(offset),
            trace_child_alignment: child_alignment,
            trace_child_header_size: child_header_size,
        }),
    })
}

#[derive(Debug, Clone)]
struct FrefRecord {
    path: String,
    reference_node: String,
    short_name: Option<String>,
    format_hint: Option<String>,
    reference_options: Option<String>,
    raw_fields: Vec<String>,
}

fn parse_fref_record(payload: &[u8]) -> Option<FrefRecord> {
    let raw_fields = extract_nul_terminated_ascii_fields(payload);
    let path = raw_fields
        .first()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let namespace = raw_fields
        .get(1)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let reference_node = raw_fields
        .get(2)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let format_hint = raw_fields
        .iter()
        .find_map(|token| normalize_reference_file_type_token(token))
        .map(str::to_string);
    let reference_options = parse_reference_options_from_fields(&raw_fields);
    Some(FrefRecord {
        path,
        reference_node: reference_node.unwrap_or_else(|| namespace.clone()),
        short_name: Some(namespace),
        format_hint,
        reference_options,
        raw_fields,
    })
}

fn parse_frdi_record(payload: &[u8]) -> Option<FrefRecord> {
    let raw_fields = extract_nul_terminated_ascii_fields(payload);
    if raw_fields.is_empty() {
        return None;
    }
    let fields: Vec<String> = raw_fields
        .iter()
        .map(|v| strip_leading_control_bytes(v))
        .collect();
    let path_idx = fields.iter().position(|value| {
        let lower = value.to_ascii_lowercase();
        (lower.contains(".mb") || lower.contains(".ma"))
            && (value.contains('/') || value.contains('\\'))
    })?;
    let path = fields[path_idx].clone();
    if path.is_empty() {
        return None;
    }
    let namespace = fields
        .iter()
        .skip(path_idx + 1)
        .find(|value| {
            !value.is_empty()
                && !value.ends_with("RN")
                && parse_reference_options_token(value).is_none()
                && normalize_reference_file_type_token(value).is_none()
        })?
        .clone();
    let reference_node = fields
        .iter()
        .skip(path_idx + 1)
        .find(|value| value.ends_with("RN"))
        .cloned()
        .unwrap_or_else(|| namespace.clone());
    let format_hint = fields
        .iter()
        .find_map(|token| normalize_reference_file_type_token(token))
        .map(str::to_string);
    let reference_options = parse_reference_options_from_fields(&fields);
    Some(FrefRecord {
        path,
        reference_node,
        short_name: Some(namespace),
        format_hint,
        reference_options,
        raw_fields,
    })
}

fn decode_attr_triplet(payload: &[u8]) -> Option<(String, u8, Vec<u8>)> {
    let attr_end = payload.iter().position(|b| *b == 0)?;
    let attr_name = String::from_utf8_lossy(&payload[..attr_end]).to_string();
    let kind = *payload.get(attr_end + 1)?;
    let value_raw = payload.get(attr_end + 2..)?.to_vec();
    Some((attr_name, kind, value_raw))
}

fn decode_string_attr_from_rtft_chunk(
    _tag: &str,
    payload: &[u8],
    _chunk_aux: Option<u32>,
    _parent_tag: Option<&str>,
) -> Option<(String, String)> {
    decode_attr_triplet(payload).and_then(|(attr_name, _kind, value_raw)| {
        let value = decode_raw_string_value(&value_raw);
        if value.is_empty() {
            None
        } else {
            Some((attr_name, value))
        }
    })
}

fn parse_reference_options_from_fields(fields: &[String]) -> Option<String> {
    fields
        .iter()
        .map(|v| v.trim())
        .find_map(parse_reference_options_token)
}

fn strip_leading_control_bytes(input: &str) -> String {
    input
        .trim_start_matches(|c: char| c.is_control())
        .trim()
        .to_string()
}

fn extract_nul_terminated_ascii_fields(data: &[u8]) -> Vec<String> {
    data.split(|b| *b == 0)
        .map(|raw| String::from_utf8_lossy(raw).to_string())
        .collect()
}

fn extract_node_name_from_crea_payload(payload: &[u8]) -> Option<String> {
    decode_crea_name_from_payload(payload)
}

fn decode_raw_string_value(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).trim().to_string()
}

fn decode_crea_name_from_payload(payload: &[u8]) -> Option<String> {
    let nul = payload.iter().position(|byte| *byte == 0)?;
    if nul == 0 {
        return None;
    }
    let raw = String::from_utf8_lossy(&payload[..nul]).to_string();
    extract_plausible_crea_name(&raw).or_else(|| {
        let stripped = strip_leading_control_bytes(&raw);
        (!stripped.is_empty()).then_some(stripped)
    })
}

fn extract_plausible_crea_name(raw: &str) -> Option<String> {
    let chars = raw.char_indices().collect::<Vec<_>>();
    for (start_ix, (_, ch)) in chars.iter().enumerate() {
        if !matches!(ch, 'A'..='Z' | 'a'..='z' | '_' | ':') {
            continue;
        }
        let start = chars[start_ix].0;
        let mut end = raw.len();
        for (offset, (byte_ix, next)) in chars.iter().enumerate().skip(start_ix + 1) {
            if matches!(next, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | ':') {
                continue;
            }
            end = *byte_ix;
            if offset == start_ix + 1 && *next == ':' {
                continue;
            }
            break;
        }
        if start < end {
            return Some(raw[start..end].to_string());
        }
        return Some(raw[start..].to_string());
    }
    None
}

fn encode_root_chunk_with_kept_spans(
    data: &[u8],
    root: &Chunk,
    kept_spans: &[(usize, usize)],
) -> Option<Vec<u8>> {
    let root_form = root.form_type.as_deref().unwrap_or("Maya").as_bytes();
    let mut payload_parts: Vec<u8> = Vec::new();
    payload_parts.extend_from_slice(root_form);

    let first_child_start = root.children.first().map(|child| child.offset)?;
    let prefix_start = root.payload_offset + 4;
    if first_child_start > prefix_start {
        payload_parts.extend_from_slice(&data[prefix_start..first_child_start]);
    }
    for (start, end) in kept_spans {
        payload_parts.extend_from_slice(&data[*start..*end]);
    }

    encode_root_chunk(root, &payload_parts)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tempfile::tempdir;

    use super::{
        collect_rtft_owner_traces_from_mb, decode_reference_from_frdi_chunk,
        decode_reference_from_fref_chunk, decode_string_attr_from_rtft_chunk, parse_fref_record,
        remove_root_forms_from_mb_by_locator,
    };
    use crate::mb::{parse_file, paths::extract_raw_scene_paths_from_mb};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn parse_fref_record_uses_schema_slots() {
        let payload = b"rig/charA_v001.mb\0charA\0\0mayaBinary\0-op \"v=0\"\0";
        let record = parse_fref_record(payload).expect("fref record");
        assert_eq!(record.path, "rig/charA_v001.mb");
        assert_eq!(record.reference_node, "charA");
        assert_eq!(record.short_name.as_deref(), Some("charA"));
        assert_eq!(record.format_hint.as_deref(), Some("mayaBinary"));
        assert_eq!(record.reference_options.as_deref(), Some("v=0"));
        assert!(record.raw_fields.len() >= 4);
        assert_eq!(record.raw_fields[2], "");
    }

    #[test]
    fn parse_fref_record_accepts_vers_options_token() {
        let payload = b"rig/charA_v001.mb\0charA\0charARN\0VERS|2026|\0mayaBinary\0";
        let record = parse_fref_record(payload).expect("fref record");
        assert_eq!(record.path, "rig/charA_v001.mb");
        assert_eq!(record.reference_node, "charARN");
        assert_eq!(record.short_name.as_deref(), Some("charA"));
        assert_eq!(record.reference_options.as_deref(), Some("VERS|2026|"));
    }

    #[test]
    fn parse_fref_record_rejects_missing_namespace_slot() {
        let payload = b"rig/charA_v001.mb\0\0charARN\0mayaBinary\0";
        assert!(parse_fref_record(payload).is_none());
    }

    #[test]
    fn decode_reference_from_frdi_chunk_parses_control_prefixed_fields() {
        let payload = b"\x01\x04\0\x02scenes/TestScene_0000.mb\0Model\0\x01\0Example:ModelRN\0VERS|2020|\0mayaBinary\0";
        let entry =
            decode_reference_from_frdi_chunk(payload, 0x4321, Some(8), Some(16)).expect("entry");
        assert_eq!(entry.node_type, "reference");
        assert_eq!(entry.node_name, "Example:ModelRN");
        assert_eq!(entry.attr, ".fn");
        assert_eq!(entry.value, "scenes/TestScene_0000.mb");

        let meta = entry.meta.expect("meta");
        assert_eq!(meta.origin, "frdi");
        assert_eq!(meta.short_name.as_deref(), Some("Model"));
        assert_eq!(meta.reference_node.as_deref(), Some("Example:ModelRN"));
        assert_eq!(meta.reference_options.as_deref(), Some("VERS|2020|"));
        assert_eq!(meta.trace_form.as_deref(), Some("FRDI"));
        assert_eq!(meta.trace_tag.as_deref(), Some("FRDI"));
        assert_eq!(meta.trace_node_offset, Some(0x4321));
    }

    #[test]
    fn decode_reference_from_fref_chunk_sets_trace_meta() {
        let payload = b"rig/charA_v001.mb\0charA\0charARN\0mayaBinary\0";
        let entry =
            decode_reference_from_fref_chunk(payload, 0x1234, Some(8), Some(16)).expect("entry");
        let meta = entry.meta.expect("meta");
        assert_eq!(meta.trace_form.as_deref(), Some("FREF"));
        assert_eq!(meta.trace_tag.as_deref(), Some("FREF"));
        assert_eq!(meta.trace_node_offset, Some(0x1234));
        assert_eq!(meta.trace_child_alignment, Some(8));
        assert_eq!(meta.trace_child_header_size, Some(16));
    }

    #[test]
    fn decode_rtft_string_attr_decodes_schema_triplet() {
        let payload = b"ftn\0\x00textures/albedo.png\0";
        let decoded =
            decode_string_attr_from_rtft_chunk("STR ", payload, None, None).expect("decode");
        assert_eq!(decoded.0, "ftn");
        assert_eq!(decoded.1, "textures/albedo.png");
    }

    #[test]
    fn remove_root_forms_from_mb_by_locator_drops_matching_owner_form() {
        let source = repo_root().join("tests/02/sphere.mb");
        let parsed = parse_file(&source).expect("parse fixture");
        let target = parsed
            .root
            .children
            .iter()
            .find_map(|child| {
                child
                    .form_type
                    .as_ref()
                    .map(|form| (form.clone(), child.offset))
            })
            .expect("owner form target");
        let target_form_count = parsed
            .root
            .children
            .iter()
            .filter(|child| child.form_type.as_deref() == Some(target.0.as_str()))
            .count();

        let (rewritten, removed) = remove_root_forms_from_mb_by_locator(
            &parsed.data,
            &parsed.root,
            std::slice::from_ref(&target),
        );

        assert_eq!(removed, vec![target.clone()]);

        let dir = tempdir().expect("tmpdir");
        let output = dir.path().join("cleaned.mb");
        fs::write(&output, rewritten).expect("write cleaned");
        let reparsed = parse_file(&output).expect("reparse cleaned");
        let rewritten_form_count = reparsed
            .root
            .children
            .iter()
            .filter(|child| child.form_type.as_deref() == Some(target.0.as_str()))
            .count();

        assert_eq!(reparsed.root.children.len() + 1, parsed.root.children.len());
        assert_eq!(rewritten_form_count + 1, target_form_count);
    }

    #[test]
    fn extract_raw_scene_paths_reads_rtft_entries_from_fixture() {
        let source = repo_root().join("tests/fixtures/mb/owner_delete/file_owner_delete.mb");
        let parsed = parse_file(&source).expect("parse fixture");
        let entries = extract_raw_scene_paths_from_mb(&parsed);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].node_type, "file");
        assert_eq!(entries[0].node_name, "deleteTex");
        assert_eq!(entries[0].attr, ".ftn");
        assert_eq!(entries[0].value, "textures/delete_me.tx");
        assert_eq!(
            entries[0]
                .meta
                .as_ref()
                .and_then(|meta| meta.trace_form.as_deref()),
            Some("RTFT")
        );
        assert!(
            entries[0]
                .meta
                .as_ref()
                .and_then(|meta| meta.trace_node_offset)
                .is_some()
        );
    }

    #[test]
    fn collect_rtft_owner_traces_reads_connected_fixture_nodes() {
        let source =
            repo_root().join("tests/fixtures/mb/owner_delete/connected_file_owner_delete.mb");
        let parsed = parse_file(&source).expect("parse fixture");
        let traces = collect_rtft_owner_traces_from_mb(&parsed);

        assert_eq!(traces.len(), 2);
        assert_eq!(traces[0].node_name, "c0000_000_ta");
        assert_eq!(traces[1].node_name, "c0000_000_tb");
        assert!(traces.iter().all(|trace| trace.trace_form == "RTFT"));
        assert!(traces.iter().all(|trace| trace.trace_node_offset > 0));
    }
}
