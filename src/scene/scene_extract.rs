use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::parser::{Chunk, MayaBinaryFile};

use super::SceneToolError;
use super::decode::{decode_attr_payload, parse_section_chunks};
use super::mb_to_ma::extract_head_metadata;
use super::patterns::{CREATE_SCRIPT_RE, NODE_NAME_RE, SCRIPT_NODE_NAME_FALLBACK_RE};
use super::util::{
    escape_ma_string, find_subslice, split_lines_keepends, trim_ascii, trim_ascii_start,
    trim_end_newline,
};
use super::{PathReplaceRule, ScenePathEntry, ScenePathMeta};

pub(super) fn detect_scene_format(path: impl AsRef<Path>) -> Result<String, SceneToolError> {
    let scene_path = path.as_ref();
    let suffix = scene_path
        .extension()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if suffix == "ma" {
        return Ok("ma".to_string());
    }
    if suffix == "mb" {
        return Ok("mb".to_string());
    }

    let data = fs::read(scene_path)?;
    let head = &data[..std::cmp::min(16, data.len())];
    if head.starts_with(b"FOR4") || head.starts_with(b"FOR8") {
        return Ok("mb".to_string());
    }
    if head
        .windows(b"Maya ASCII".len())
        .any(|w| w == b"Maya ASCII")
    {
        return Ok("ma".to_string());
    }
    Ok("unknown".to_string())
}

pub(super) fn scan_script_nodes_in_ma(data: &[u8]) -> Vec<String> {
    let lines = split_lines_keepends(data);
    find_script_blocks_in_ma(&lines)
        .into_iter()
        .map(|(_, _, name)| name)
        .collect()
}

pub(super) fn extract_script_entries_from_ma(data: &[u8]) -> Vec<(String, String)> {
    let lines = split_lines_keepends(data);
    let blocks = find_script_blocks_in_ma(&lines);
    let mut out = Vec::new();
    for (start, end, name) in blocks {
        let block = lines[start..end].concat();
        out.push((name, extract_script_body_from_ma_block(&block)));
    }
    out
}

fn extract_script_body_from_ma_block(block: &[u8]) -> String {
    let text = String::from_utf8_lossy(block).to_string();
    let marker = "setAttr \".b\" -type \"string\"";
    let Some(marker_pos) = text.find(marker) else {
        return String::new();
    };
    let mut cursor = marker_pos + marker.len();
    while cursor < text.len() && text[cursor..].chars().next().unwrap().is_whitespace() {
        cursor += text[cursor..].chars().next().unwrap().len_utf8();
    }
    if cursor >= text.len() {
        return String::new();
    }

    if text[cursor..].starts_with('"') {
        let (literal, _) = parse_ma_quoted_literal(&text, cursor);
        if let Some(v) = literal {
            return unescape_ma_string_literal(&v);
        }
        return String::new();
    }

    if !text[cursor..].starts_with('(') {
        return String::new();
    }
    cursor += 1;
    let mut parts = Vec::new();

    while cursor < text.len() {
        while cursor < text.len() {
            let ch = text[cursor..].chars().next().unwrap();
            if ch.is_whitespace() || ch == '+' {
                cursor += ch.len_utf8();
            } else {
                break;
            }
        }
        if cursor >= text.len() || text[cursor..].starts_with(");") {
            break;
        }
        if !text[cursor..].starts_with('"') {
            break;
        }
        let (literal, next_cursor) = parse_ma_quoted_literal(&text, cursor);
        if let Some(v) = literal {
            parts.push(unescape_ma_string_literal(&v));
            cursor = next_cursor;
        } else {
            break;
        }
    }

    parts.join("")
}

fn parse_ma_quoted_literal(text: &str, start: usize) -> (Option<String>, usize) {
    if start >= text.len() || !text[start..].starts_with('"') {
        return (None, start);
    }
    let mut out = String::new();
    let mut i = start + 1;
    while i < text.len() {
        let ch = text[i..].chars().next().unwrap();
        if ch == '\\' {
            let next_i = i + ch.len_utf8();
            if next_i < text.len() {
                let ch2 = text[next_i..].chars().next().unwrap();
                out.push('\\');
                out.push(ch2);
                i = next_i + ch2.len_utf8();
            } else {
                out.push('\\');
                return (Some(out), next_i);
            }
            continue;
        }
        if ch == '"' {
            return (Some(out), i + ch.len_utf8());
        }
        out.push(ch);
        i += ch.len_utf8();
    }
    (None, start)
}

fn unescape_ma_string_literal(text: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch != '\\' {
            out.push(ch);
            i += 1;
            continue;
        }
        if i + 1 >= chars.len() {
            out.push('\\');
            break;
        }
        let nxt = chars[i + 1];
        match nxt {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            _ => {
                out.push('\\');
                out.push(nxt);
            }
        }
        i += 2;
    }
    out
}

pub(super) fn remove_script_nodes_from_ma(data: &[u8]) -> (Vec<u8>, Vec<String>) {
    let lines = split_lines_keepends(data);
    let blocks = find_script_blocks_in_ma(&lines);
    if blocks.is_empty() {
        return (data.to_vec(), vec![]);
    }

    let skip_ranges: Vec<(usize, usize)> = blocks.iter().map(|(s, e, _)| (*s, *e)).collect();
    let removed_names: Vec<String> = blocks.into_iter().map(|(_, _, n)| n).collect();

    let mut out = Vec::new();
    let mut skip_idx = 0usize;
    let mut line_idx = 0usize;

    while line_idx < lines.len() {
        if skip_idx < skip_ranges.len() {
            let (start, end) = skip_ranges[skip_idx];
            if start <= line_idx && line_idx < end {
                line_idx = end;
                skip_idx += 1;
                continue;
            }
        }
        out.extend_from_slice(&lines[line_idx]);
        line_idx += 1;
    }

    (out, removed_names)
}

fn find_script_blocks_in_ma(lines: &[Vec<u8>]) -> Vec<(usize, usize, String)> {
    let mut blocks = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let line = &lines[i];
        if is_top_level_command(line) {
            let line_str = String::from_utf8_lossy(line);
            if CREATE_SCRIPT_RE.is_match(&line_str) {
                let name = extract_script_node_name_from_create(line, i);
                let mut j = i + 1;
                while j < lines.len() {
                    if is_top_level_command(&lines[j]) {
                        break;
                    }
                    j += 1;
                }
                blocks.push((i, j, name));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    blocks
}

fn is_top_level_command(line: &[u8]) -> bool {
    let stripped = trim_ascii(line);
    if stripped.is_empty() {
        return false;
    }
    if !line.is_empty() && (line[0] == b' ' || line[0] == b'\t') {
        return false;
    }
    !stripped.starts_with(b"//")
}

fn extract_script_node_name_from_create(line: &[u8], default_idx: usize) -> String {
    let s = String::from_utf8_lossy(line);
    if let Some(caps) = NODE_NAME_RE.captures(&s) {
        return caps.get(1).unwrap().as_str().to_string();
    }
    format!("<scriptNode@line{}>", default_idx + 1)
}

pub(super) fn scan_script_nodes_in_mb(data: &[u8], root: &Chunk) -> Vec<String> {
    let mut names = Vec::new();
    for child in &root.children {
        if child.form_type.as_deref() != Some("SCRP") {
            continue;
        }
        let payload = &data[child.payload_offset..child.payload_end];
        let name = extract_mb_script_node_name(payload)
            .unwrap_or_else(|| format!("<SCRP@0x{:X}>", child.offset));
        names.push(name);
    }
    names
}

pub(super) fn extract_script_entries_from_mb(mb: &MayaBinaryFile) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for child in &mb.root.children {
        if child.form_type.as_deref() != Some("SCRP") {
            continue;
        }
        let payload = &mb.data[child.payload_offset..child.payload_end];
        let name = extract_mb_script_node_name(payload)
            .unwrap_or_else(|| format!("<SCRP@0x{:X}>", child.offset));
        let body = extract_script_body_from_scrp(payload);
        let key = (name.clone(), body.clone());
        if seen.insert(key.clone()) {
            out.push(key);
        }
    }

    out
}

pub(super) fn remove_script_nodes_from_mb(data: &[u8], root: &Chunk) -> (Vec<u8>, Vec<String>) {
    let children = &root.children;
    if children.is_empty() {
        return (data.to_vec(), vec![]);
    }

    let mut removed_names = Vec::new();
    let mut kept_spans = Vec::new();

    for (idx, child) in children.iter().enumerate() {
        let next_offset = if idx + 1 < children.len() {
            children[idx + 1].offset
        } else {
            root.payload_end
        };
        if child.form_type.as_deref() == Some("SCRP") {
            let payload = &data[child.payload_offset..child.payload_end];
            let name = extract_mb_script_node_name(payload)
                .unwrap_or_else(|| format!("<SCRP@0x{:X}>", child.offset));
            removed_names.push(name);
            continue;
        }
        kept_spans.push((child.offset, next_offset));
    }

    if removed_names.is_empty() {
        return (data.to_vec(), vec![]);
    }

    let root_form = root.form_type.as_deref().unwrap_or("Maya").as_bytes();
    let mut payload_parts: Vec<u8> = Vec::new();
    payload_parts.extend_from_slice(root_form);

    let first_child_start = children[0].offset;
    let prefix_start = root.payload_offset + 4;
    if first_child_start > prefix_start {
        payload_parts.extend_from_slice(&data[prefix_start..first_child_start]);
    }
    for (start, end) in kept_spans {
        payload_parts.extend_from_slice(&data[start..end]);
    }

    let mut out = Vec::new();
    out.extend_from_slice(root.tag.as_bytes());
    out.extend_from_slice(&root.aux.to_be_bytes());
    out.extend_from_slice(&(payload_parts.len() as u64).to_be_bytes());
    out.extend_from_slice(&payload_parts);
    (out, removed_names)
}

pub(super) fn extract_mb_script_node_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 21 || &payload[..4] != b"SCRP" {
        return None;
    }

    if &payload[4..8] == b"CREA" && payload.len() >= 21 {
        let mut raw = payload[20..std::cmp::min(payload.len(), 20 + 256)].to_vec();
        if !raw.is_empty() && (raw[0] & 0x80) != 0 {
            raw.remove(0);
        }
        if let Some(end) = raw.iter().position(|b| *b == 0) {
            raw.truncate(end);
        }
        if !raw.is_empty() && raw.iter().all(|b| (32..=126).contains(b)) {
            return Some(String::from_utf8_lossy(&raw).to_string());
        }
    }

    let hay = String::from_utf8_lossy(&payload[..std::cmp::min(payload.len(), 1024)]);
    SCRIPT_NODE_NAME_FALLBACK_RE
        .captures(&hay)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

pub(super) fn extract_requires_from_ma(data: &[u8]) -> Vec<String> {
    let lines = split_lines_keepends(data);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut i = 0usize;

    while i < lines.len() {
        let stripped = trim_ascii_start(&lines[i]);
        if !stripped.starts_with(b"requires ") {
            i += 1;
            continue;
        }

        let mut command = trim_end_newline(stripped).to_vec();
        i += 1;
        while !command.contains(&b';') && i < lines.len() {
            command.push(b' ');
            command.extend_from_slice(trim_ascii(&lines[i]));
            i += 1;
        }

        let mut text = String::from_utf8_lossy(&command).to_string();
        text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if !text.ends_with(';') {
            text.push(';');
        }
        if seen.insert(text.clone()) {
            out.push(text);
        }
    }

    out
}

pub(super) fn extract_requires_from_mb(mb: &MayaBinaryFile) -> Vec<String> {
    let metadata = extract_head_metadata(mb);
    let vers = metadata
        .get("vers")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let mut out = vec![format!("requires maya \"{}\";", escape_ma_string(&vers))];
    let mut seen: HashSet<String> = out.iter().cloned().collect();

    if let Some(requires) = metadata.get("requires_list") {
        for req in requires.split('\n') {
            let t = req.trim();
            if t.is_empty() {
                continue;
            }
            let mut text = t.split_whitespace().collect::<Vec<_>>().join(" ");
            if !text.ends_with(';') {
                text.push(';');
            }
            if seen.insert(text.clone()) {
                out.push(text);
            }
        }
    }

    out
}

pub(super) fn build_script_dump_text(
    src: &Path,
    scene_format: &str,
    entries: &[(String, String)],
) -> String {
    let mut lines = vec![
        "# maya-scene-kit Script Node Dump".to_string(),
        format!("source: {}", src.display()),
        format!("format: {scene_format}"),
        format!("count: {}", entries.len()),
        String::new(),
    ];

    for (idx, (name, body)) in entries.iter().enumerate() {
        lines.push(format!("[[scriptNode {}: {}]]", idx + 1, name));
        if body.is_empty() {
            lines.push("<empty>".to_string());
        } else {
            lines.push(body.trim_end_matches('\n').to_string());
        }
        lines.push(String::new());
    }

    if entries.is_empty() {
        lines.push("# no script node found".to_string());
        lines.push(String::new());
    }

    lines.join("\n") + "\n"
}

pub(super) fn build_requires_dump_text(
    src: &Path,
    scene_format: &str,
    requires: &[String],
) -> String {
    let mut lines = vec![
        "# maya-scene-kit Requires Dump".to_string(),
        format!("source: {}", src.display()),
        format!("format: {scene_format}"),
        format!("count: {}", requires.len()),
        String::new(),
    ];

    if requires.is_empty() {
        lines.push("# no requires found".to_string());
        lines.push(String::new());
        return lines.join("\n") + "\n";
    }

    lines.extend_from_slice(requires);
    lines.push(String::new());
    lines.join("\n") + "\n"
}

pub(super) fn extract_script_body_from_scrp(payload: &[u8]) -> String {
    if payload.len() < 4 {
        return String::new();
    }
    let mut bodies = Vec::new();
    for (tag, body_payload) in parse_section_chunks(&payload[4..]) {
        if tag != "STR " {
            continue;
        }
        if let Some((attr_name, _, value)) = decode_attr_payload(&body_payload) {
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

pub(super) fn decode_best_effort_script_text(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }

    let mut start = find_subslice(payload, b"//");
    if start.is_none() {
        for key in [
            b"playbackOptions".as_slice(),
            b"global ",
            b"python(",
            b"print(",
        ] {
            start = find_subslice(payload, key);
            if start.is_some() {
                break;
            }
        }
    }
    if start.is_none() {
        start = payload
            .iter()
            .position(|b| *b == 9 || *b == 10 || *b == 13 || (32..=126).contains(b));
    }
    let Some(start) = start else {
        return String::new();
    };

    let mut raw = payload[start..].to_vec();
    if raw[..std::cmp::min(raw.len(), 8)].contains(&0) {
        if let Some(pos) = raw.iter().position(|b| *b == 0) {
            raw = raw[pos + 1..].to_vec();
        }
    }

    while !raw.is_empty() && [b' ', b'\t', b'\r', b'\n'].contains(&raw[0]) {
        raw.remove(0);
    }
    while raw.last() == Some(&0) {
        raw.pop();
    }

    String::from_utf8_lossy(&raw).trim().to_string()
}

pub(super) fn extract_scene_paths_from_ma(data: &[u8]) -> Vec<ScenePathEntry> {
    let lines = split_lines_keepends(data);
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < lines.len() {
        let line = &lines[i];
        if !is_top_level_command(line) {
            i += 1;
            continue;
        }
        let line_text = String::from_utf8_lossy(line);
        if !line_text.trim_start().starts_with("createNode ") {
            i += 1;
            continue;
        }

        let node_type = parse_create_node_type(&line_text);
        let node_name = extract_script_node_name_from_create(line, i);
        let mut j = i + 1;
        while j < lines.len() {
            if is_top_level_command(&lines[j]) {
                break;
            }
            j += 1;
        }

        if node_type == "file" || node_type == "reference" {
            for k in i + 1..j {
                let t = String::from_utf8_lossy(&lines[k]).to_string();
                if let Some((attr, value)) = parse_setattr_string_line(&t) {
                    if node_type == "file" && attr == ".ftn" {
                        out.push(ScenePathEntry {
                            node_type: "file".to_string(),
                            node_name: node_name.clone(),
                            attr,
                            value,
                            meta: None,
                        });
                    } else if node_type == "reference" && is_reference_attr(&attr) {
                        out.push(ScenePathEntry {
                            node_type: "reference".to_string(),
                            node_name: node_name.clone(),
                            attr,
                            value,
                            meta: None,
                        });
                    }
                }
            }
        }

        i = j;
    }

    out
}

pub(super) fn extract_scene_paths_from_mb(mb: &MayaBinaryFile) -> Vec<ScenePathEntry> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for child in &mb.root.children {
        let form = child.form_type.as_deref().unwrap_or("");
        let payload = &mb.data[child.payload_offset..child.payload_end];

        if form == "FREF" {
            for e in extract_reference_entries_from_fref_payload(payload, child.offset) {
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
            for e in extract_file_entries_from_rtft_payload(payload, child.offset) {
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

        let inner = if payload.len() >= 4 {
            &payload[4..]
        } else {
            &[]
        };
        let chunks = parse_section_chunks(inner);

        let mut node_name = format!("node@0x{:X}", child.offset);
        let mut node_type_hint = if form == "RTFT" {
            "file".to_string()
        } else {
            "unknown".to_string()
        };

        for (tag, p) in &chunks {
            if tag == "CREA" {
                if let Some(n) = extract_node_name_from_crea_payload(p) {
                    node_name = n;
                }
                break;
            }
        }

        for (_tag, p) in &chunks {
            let Some((attr_name, _kind, value_raw)) = decode_attr_payload(p) else {
                continue;
            };
            let value = decode_raw_string_value(&value_raw);
            if value.is_empty() {
                continue;
            }

            if attr_name == "ftn" || attr_name == ".ftn" {
                let e = ScenePathEntry {
                    node_type: "file".to_string(),
                    node_name: node_name.clone(),
                    attr: normalize_attr_name(&attr_name),
                    value,
                    meta: None,
                };
                let key = (
                    e.node_type.clone(),
                    e.node_name.clone(),
                    e.attr.clone(),
                    e.value.clone(),
                );
                if seen.insert(key) {
                    out.push(e);
                }
                continue;
            }

            if is_reference_attr_name(&attr_name) {
                if node_type_hint == "unknown" {
                    node_type_hint = "reference".to_string();
                }
                let e = ScenePathEntry {
                    node_type: "reference".to_string(),
                    node_name: node_name.clone(),
                    attr: normalize_attr_name(&attr_name),
                    value,
                    meta: None,
                };
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
        }
    }

    out
}

fn extract_file_entries_from_rtft_payload(payload: &[u8], offset: usize) -> Vec<ScenePathEntry> {
    if payload.len() < 4 {
        return Vec::new();
    }
    let inner = &payload[4..];
    let chunks = parse_section_chunks(inner);
    if chunks.is_empty() {
        return Vec::new();
    }

    let mut node_name = format!("<RTFT@0x{offset:X}>");
    let mut color_space: Option<String> = None;
    let mut paths: Vec<String> = Vec::new();
    let mut attrs: Vec<String> = Vec::new();

    for (tag, chunk_payload) in &chunks {
        if tag == "CREA" {
            if let Some(n) = extract_node_name_from_crea_payload(chunk_payload) {
                node_name = n;
            }
            continue;
        }
        if tag != "STR " {
            continue;
        }
        let Some((attr_name, _kind, value_raw)) = decode_attr_payload(chunk_payload) else {
            continue;
        };
        let value = decode_raw_string_value(&value_raw);
        if value.is_empty() {
            continue;
        }

        if attr_name == "ftn" || attr_name == ".ftn" {
            paths.push(value.clone());
        } else if attr_name == "cs" || attr_name == ".cs" {
            color_space = Some(value.clone());
        }
        attrs.push(format!("{attr_name}={value}"));
    }

    paths
        .into_iter()
        .map(|path| ScenePathEntry {
            node_type: "file".to_string(),
            node_name: node_name.clone(),
            attr: ".ftn".to_string(),
            value: path,
            meta: Some(ScenePathMeta {
                origin: "rtft".to_string(),
                short_name: Some(node_name.clone()),
                reference_node: None,
                format_hint: None,
                color_space: color_space.clone(),
                raw_fields: attrs.clone(),
            }),
        })
        .collect()
}

fn extract_reference_entries_from_fref_payload(
    payload: &[u8],
    offset: usize,
) -> Vec<ScenePathEntry> {
    if payload.len() < 4 {
        return Vec::new();
    }
    let inner = &payload[4..];
    let chunks = parse_section_chunks(inner);

    let mut out = Vec::new();
    for (tag, chunk_payload) in chunks {
        if tag != "FREF" {
            continue;
        }
        if let Some(entry) = decode_reference_from_fref_chunk(&chunk_payload, offset) {
            out.push(entry);
        }
    }
    out
}

fn decode_reference_from_fref_chunk(payload: &[u8], offset: usize) -> Option<ScenePathEntry> {
    let fields = extract_nul_terminated_ascii_fields(payload);
    if fields.is_empty() {
        return None;
    }

    let (path_idx, path) = fields
        .iter()
        .enumerate()
        .find_map(|(idx, s)| normalize_path_candidate(s).map(|p| (idx, p)))?;

    let node_name = fields
        .iter()
        .skip(path_idx + 1)
        .find(|s| is_reference_node_name(s))
        .cloned()
        .or_else(|| fields.iter().find(|s| is_reference_node_name(s)).cloned())
        .unwrap_or_else(|| format!("<FREF@0x{offset:X}>"));

    let short_name = fields
        .iter()
        .skip(path_idx + 1)
        .find(|s| !is_reference_node_name(s) && !s.contains('|'))
        .cloned();
    let format_hint = fields
        .iter()
        .find(|s| s.as_str() == "mayaBinary" || s.as_str() == "mayaAscii")
        .cloned();

    Some(ScenePathEntry {
        node_type: "reference".to_string(),
        node_name: node_name.clone(),
        attr: ".fn".to_string(),
        value: path,
        meta: Some(ScenePathMeta {
            origin: "fref".to_string(),
            short_name,
            reference_node: Some(node_name),
            format_hint,
            color_space: None,
            raw_fields: fields,
        }),
    })
}

fn extract_nul_terminated_ascii_fields(data: &[u8]) -> Vec<String> {
    data.split(|b| *b == 0)
        .filter_map(|raw| {
            let cleaned: Vec<u8> = raw
                .iter()
                .copied()
                .filter(|b| (32..=126).contains(b))
                .collect();
            if cleaned.is_empty() {
                None
            } else {
                let s = String::from_utf8_lossy(&cleaned).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            }
        })
        .collect()
}

fn normalize_path_candidate(token: &str) -> Option<String> {
    let t = token.trim_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '|');
    if t.is_empty() {
        return None;
    }
    if looks_like_scene_path(t) {
        return Some(t.to_string());
    }
    None
}

fn looks_like_scene_path(s: &str) -> bool {
    if !(s.contains('/') || s.contains('\\')) {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    lower.ends_with(".ma") || lower.ends_with(".mb")
}

fn is_reference_node_name(s: &str) -> bool {
    if s.len() < 3 || s.contains('|') || s.contains(' ') {
        return false;
    }
    s.ends_with("RN")
}

#[derive(Debug, Clone)]
struct RawSectionChunk {
    tag: String,
    aux: u32,
    payload: Vec<u8>,
}

pub(super) fn replace_scene_paths_in_ma(
    data: &[u8],
    rules: &[PathReplaceRule],
) -> (Vec<u8>, usize) {
    if rules.is_empty() {
        return (data.to_vec(), 0);
    }
    let lines = split_lines_keepends(data);
    let mut out = String::new();
    let mut total = 0usize;

    for line in lines {
        let line_text = String::from_utf8_lossy(&line).to_string();
        if let Some((attr, value)) = parse_setattr_string_line(&line_text) {
            if attr == ".ftn" || is_reference_attr(&attr) {
                let (new_value, c) = apply_replace_rules(&value, rules);
                if c > 0 {
                    total += c;
                    let indent = line_text
                        .chars()
                        .take_while(|c| *c == ' ' || *c == '\t')
                        .collect::<String>();
                    out.push_str(&format!(
                        "{indent}setAttr \"{attr}\" -type \"string\" \"{}\";\n",
                        escape_ma_string(&new_value)
                    ));
                    continue;
                }
            }
        }
        out.push_str(&line_text);
    }

    (out.into_bytes(), total)
}

pub(super) fn replace_scene_paths_in_mb(
    data: &[u8],
    root: &Chunk,
    rules: &[PathReplaceRule],
) -> (Vec<u8>, usize) {
    if rules.is_empty() || root.children.is_empty() {
        return (data.to_vec(), 0);
    }

    let children = &root.children;
    let mut payload_parts: Vec<u8> = Vec::new();
    payload_parts.extend_from_slice(root.form_type.as_deref().unwrap_or("Maya").as_bytes());

    let first_child_start = children[0].offset;
    let prefix_start = root.payload_offset + 4;
    if first_child_start > prefix_start {
        payload_parts.extend_from_slice(&data[prefix_start..first_child_start]);
    }

    let mut total = 0usize;
    for (idx, child) in children.iter().enumerate() {
        let next_offset = if idx + 1 < children.len() {
            children[idx + 1].offset
        } else {
            root.payload_end
        };
        let original_span = &data[child.offset..next_offset];
        let form = child.form_type.as_deref().unwrap_or("");

        if form == "RTFT" {
            if let Some((rewritten, count)) = rewrite_rtft_child(child, data, rules) {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if form == "FREF" {
            if let Some((rewritten, count)) = rewrite_fref_child(child, data, rules) {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        }

        payload_parts.extend_from_slice(original_span);
    }

    if total == 0 {
        return (data.to_vec(), 0);
    }

    let mut out = Vec::new();
    out.extend_from_slice(root.tag.as_bytes());
    out.extend_from_slice(&root.aux.to_be_bytes());
    out.extend_from_slice(&(payload_parts.len() as u64).to_be_bytes());
    out.extend_from_slice(&payload_parts);
    (out, total)
}

fn rewrite_rtft_child(
    child: &Chunk,
    data: &[u8],
    rules: &[PathReplaceRule],
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (chunks, align) = parse_section_chunks_full_auto(inner);
    if chunks.is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut new_chunks = Vec::new();

    for mut ch in chunks {
        if ch.tag == "STR " {
            if let Some((attr_name, kind, value_raw)) = decode_attr_payload(&ch.payload) {
                if attr_name == "ftn" || attr_name == ".ftn" {
                    let value = decode_raw_string_value(&value_raw);
                    let (new_value, c) = apply_replace_rules(&value, rules);
                    if c > 0 {
                        ch.payload =
                            encode_attr_payload_string(&attr_name, kind, new_value.as_bytes());
                        total += c;
                        changed = true;
                    }
                }
            }
        }
        new_chunks.push(ch);
    }

    if !changed {
        return None;
    }

    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"RTFT");
    new_payload.extend_from_slice(&encode_section_chunks_full(&new_chunks, align));
    let encoded_child = encode_chunk(child.tag.as_str(), child.aux, &new_payload, 4);
    Some((encoded_child, total))
}

fn rewrite_fref_child(
    child: &Chunk,
    data: &[u8],
    rules: &[PathReplaceRule],
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (chunks, align) = parse_section_chunks_full_auto(inner);
    if chunks.is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut new_chunks = Vec::new();

    for mut ch in chunks {
        if ch.tag == "FREF" {
            let (rewritten, c) = replace_first_path_field_in_nul_payload(&ch.payload, rules);
            if c > 0 {
                ch.payload = rewritten;
                total += c;
                changed = true;
            }
        }
        new_chunks.push(ch);
    }

    if !changed {
        return None;
    }

    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"FREF");
    new_payload.extend_from_slice(&encode_section_chunks_full(&new_chunks, align));
    let encoded_child = encode_chunk(child.tag.as_str(), child.aux, &new_payload, 4);
    Some((encoded_child, total))
}

fn replace_first_path_field_in_nul_payload(
    payload: &[u8],
    rules: &[PathReplaceRule],
) -> (Vec<u8>, usize) {
    let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
    if parts.is_empty() {
        return (payload.to_vec(), 0);
    }
    let mut replaced_count = 0usize;
    let mut replaced_index: Option<usize> = None;
    let mut replaced_value: Vec<u8> = Vec::new();

    for (idx, raw) in parts.iter().enumerate() {
        let text = String::from_utf8_lossy(raw).trim().to_string();
        if text.is_empty() || !looks_like_scene_path(&text) {
            continue;
        }
        let (new_text, c) = apply_replace_rules(&text, rules);
        if c > 0 {
            replaced_count = c;
            replaced_index = Some(idx);
            replaced_value = new_text.into_bytes();
        }
        break;
    }

    let Some(idx) = replaced_index else {
        return (payload.to_vec(), 0);
    };

    let mut out = Vec::new();
    for i in 0..parts.len() {
        if i == idx {
            out.extend_from_slice(&replaced_value);
        } else {
            out.extend_from_slice(parts[i]);
        }
        if i + 1 < parts.len() {
            out.push(0);
        }
    }
    (out, replaced_count)
}

fn apply_replace_rules(input: &str, rules: &[PathReplaceRule]) -> (String, usize) {
    let mut cur = input.to_string();
    let mut total = 0usize;
    for r in rules {
        if r.from.is_empty() {
            continue;
        }
        let count = cur.matches(&r.from).count();
        if count > 0 {
            cur = cur.replace(&r.from, &r.to);
            total += count;
        }
    }
    (cur, total)
}

fn parse_section_chunks_full_auto(data: &[u8]) -> (Vec<RawSectionChunk>, usize) {
    let parsed8 = parse_section_chunks_full_with_alignment(data, 8);
    let parsed4 = parse_section_chunks_full_with_alignment(data, 4);
    if parsed8.len() >= parsed4.len() {
        (parsed8, 8)
    } else {
        (parsed4, 4)
    }
}

fn parse_section_chunks_full_with_alignment(data: &[u8], alignment: usize) -> Vec<RawSectionChunk> {
    let mut out = Vec::new();
    let mut cursor = 0usize;

    while cursor + 16 <= data.len() {
        let tag_bytes = &data[cursor..cursor + 4];
        if !tag_bytes.iter().all(|b| (32..=126).contains(b)) {
            break;
        }
        let aux = u32::from_be_bytes(data[cursor + 4..cursor + 8].try_into().unwrap());
        let size = u64::from_be_bytes(data[cursor + 8..cursor + 16].try_into().unwrap()) as usize;
        let payload_start = cursor + 16;
        let payload_end = payload_start + size;
        if payload_end > data.len() {
            break;
        }
        out.push(RawSectionChunk {
            tag: String::from_utf8_lossy(tag_bytes).to_string(),
            aux,
            payload: data[payload_start..payload_end].to_vec(),
        });
        cursor += align_len(16 + size, alignment);
    }
    out
}

fn encode_section_chunks_full(chunks: &[RawSectionChunk], alignment: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for ch in chunks {
        out.extend_from_slice(&encode_chunk(&ch.tag, ch.aux, &ch.payload, alignment));
    }
    out
}

fn encode_chunk(tag: &str, aux: u32, payload: &[u8], alignment: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&aux.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    let pad = align_len(out.len(), alignment) - out.len();
    out.resize(out.len() + pad, 0);
    out
}

fn align_len(v: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return v;
    }
    let rem = v % alignment;
    if rem == 0 { v } else { v + (alignment - rem) }
}

fn encode_attr_payload_string(attr_name: &str, kind: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(attr_name.as_bytes());
    out.push(0);
    out.push(kind);
    out.extend_from_slice(value);
    out.push(0);
    out
}

fn parse_create_node_type(line: &str) -> String {
    let s = line.trim_start();
    let Some(rest) = s.strip_prefix("createNode ") else {
        return String::new();
    };
    rest.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

fn parse_setattr_string_line(line: &str) -> Option<(String, String)> {
    let s = line.trim_start();
    if !s.starts_with("setAttr ") || !s.contains("-type \"string\"") {
        return None;
    }

    let mut cursor = s.find('"')?;
    let (attr_lit, next) = parse_ma_quoted_literal(s, cursor);
    let attr = attr_lit?;
    cursor = next;

    let marker_pos = s[cursor..].find("-type \"string\"")?;
    cursor += marker_pos + "-type \"string\"".len();
    while cursor < s.len() && s[cursor..].chars().next().unwrap().is_whitespace() {
        cursor += s[cursor..].chars().next().unwrap().len_utf8();
    }
    if cursor >= s.len() || !s[cursor..].starts_with('"') {
        return None;
    }
    let (value_lit, _) = parse_ma_quoted_literal(s, cursor);
    let value = unescape_ma_string_literal(&value_lit?);
    Some((attr, value))
}

fn is_reference_attr(attr: &str) -> bool {
    attr == ".fn" || attr.starts_with(".fn[") || attr == ".f"
}

fn is_reference_attr_name(attr_name: &str) -> bool {
    attr_name == "fn" || attr_name.starts_with("fn[") || attr_name == "f"
}

fn normalize_attr_name(attr_name: &str) -> String {
    if attr_name.starts_with('.') {
        attr_name.to_string()
    } else {
        format!(".{attr_name}")
    }
}

fn decode_raw_string_value(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).trim().to_string()
}

fn extract_node_name_from_crea_payload(payload: &[u8]) -> Option<String> {
    let hay = String::from_utf8_lossy(&payload[..std::cmp::min(payload.len(), 512)]);
    for caps in super::patterns::NODE_TOKEN_RE.captures_iter(&hay) {
        let token = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if token.is_empty() {
            continue;
        }
        if token.len() == 1 {
            continue;
        }
        if ["application", "product", "version", "cutIdentifier", "osv"].contains(&token) {
            continue;
        }
        return Some(token.to_string());
    }
    None
}
