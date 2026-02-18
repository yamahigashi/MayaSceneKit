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
