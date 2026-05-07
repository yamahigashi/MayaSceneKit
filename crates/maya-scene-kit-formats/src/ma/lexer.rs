use once_cell::sync::Lazy;
use regex::Regex;

use crate::reference_semantics::{
    ScenePathAttrKind, classify_scene_path_attr, looks_like_qualified_scene_file_path,
};

static CREATE_SCRIPT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bcreateNode\s+script\b").unwrap());

pub(crate) fn split_lines_keepends(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, b) in data.iter().enumerate() {
        if *b == b'\n' {
            out.push(&data[start..=i]);
            start = i + 1;
        }
    }
    if start < data.len() {
        out.push(&data[start..]);
    }
    out
}

pub(crate) fn trim_ascii(input: &[u8]) -> &[u8] {
    trim_ascii_end(trim_ascii_start(input))
}

pub(crate) fn trim_ascii_start(input: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < input.len() && input[i].is_ascii_whitespace() {
        i += 1;
    }
    &input[i..]
}

fn trim_ascii_end(input: &[u8]) -> &[u8] {
    let mut i = input.len();
    while i > 0 && input[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    &input[..i]
}

pub(crate) fn is_top_level_command(line: &[u8]) -> bool {
    let stripped = trim_ascii(line);
    if stripped.is_empty() {
        return false;
    }
    if !line.is_empty() && (line[0] == b' ' || line[0] == b'\t') {
        return false;
    }
    !stripped.starts_with(b"//")
}

pub(crate) fn extract_script_node_name_from_create(line: &[u8], default_idx: usize) -> String {
    if let Some(name) = parse_create_node_name(line) {
        return name;
    }
    format!("<scriptNode@line{}>", default_idx + 1)
}

fn parse_create_node_name(line: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(line).ok()?;
    let bytes = text.as_bytes();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        cursor += bytes[cursor..]
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())?;
        if bytes[cursor] != b'-' {
            cursor += 1;
            continue;
        }
        let flag_start = cursor;
        cursor += 1;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if &text[flag_start..cursor] != "-n" {
            continue;
        }
        cursor += bytes[cursor..]
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())?;
        if bytes.get(cursor) != Some(&b'"') {
            return None;
        }
        let (literal, _) = parse_ma_quoted_literal(text, cursor);
        return literal;
    }

    None
}

pub(crate) fn parse_ma_quoted_literal(text: &str, start: usize) -> (Option<String>, usize) {
    if start >= text.len() || !text[start..].starts_with('"') {
        return (None, start);
    }
    let bytes = text.as_bytes();
    let mut fast = start + 1;
    while fast < bytes.len() {
        match bytes[fast] {
            b'"' => return (Some(text[start + 1..fast].to_string()), fast + 1),
            b'\\' => break,
            _ => fast += 1,
        }
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

pub(crate) fn unescape_ma_string_literal(text: &str) -> String {
    if !text.contains('\\') {
        return text.to_string();
    }

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

pub(crate) fn command_has_terminating_semicolon(command: &str) -> bool {
    let mut in_string = false;
    let mut escaped = false;

    for ch in command.chars() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            ';' => return true,
            _ => {}
        }
    }

    false
}

pub(crate) fn is_reference_attr(attr: &str) -> bool {
    matches!(
        classify_scene_path_attr(attr),
        Some(ScenePathAttrKind::ReferencePath)
    )
}

pub(crate) fn looks_like_scene_path(s: &str) -> bool {
    looks_like_qualified_scene_file_path(s)
}

pub(crate) fn parse_setattr_string_line(line: &str) -> Option<(String, String)> {
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

fn parse_setattr_string_value_after_marker(trimmed: &str, mut cursor: usize) -> Option<String> {
    while cursor < trimmed.len() {
        let ch = trimmed[cursor..].chars().next().unwrap();
        if ch.is_whitespace() {
            cursor += ch.len_utf8();
        } else {
            break;
        }
    }
    if cursor >= trimmed.len() {
        return None;
    }

    if trimmed[cursor..].starts_with('"') {
        let (value_lit, _) = parse_ma_quoted_literal(trimmed, cursor);
        return Some(unescape_ma_string_literal(&value_lit?));
    }
    if !trimmed[cursor..].starts_with('(') {
        return None;
    }
    cursor += 1;

    let mut parts = Vec::new();
    while cursor < trimmed.len() {
        while cursor < trimmed.len() {
            let ch = trimmed[cursor..].chars().next().unwrap();
            if ch.is_whitespace() || ch == '+' {
                cursor += ch.len_utf8();
            } else {
                break;
            }
        }
        if cursor >= trimmed.len() || trimmed[cursor..].starts_with(");") {
            break;
        }
        if !trimmed[cursor..].starts_with('"') {
            return None;
        }
        let (literal, next_cursor) = parse_ma_quoted_literal(trimmed, cursor);
        parts.push(unescape_ma_string_literal(&literal?));
        cursor = next_cursor;
    }

    Some(parts.join(""))
}

pub(crate) fn parse_setattr_string_value_tail(tail: &str) -> Option<String> {
    parse_setattr_string_value_after_marker(tail, 0)
}

pub(crate) fn parse_setattr_string_value(command: &str) -> Option<String> {
    let trimmed = command.trim_start();
    if !trimmed.starts_with("setAttr ") || !trimmed.contains("-type \"string\"") {
        return None;
    }
    let marker_pos = trimmed.find("-type \"string\"")?;
    let cursor = marker_pos + "-type \"string\"".len();
    parse_setattr_string_value_after_marker(trimmed, cursor)
}

pub(crate) fn parse_setattr_string_command(command: &str) -> Option<(String, String)> {
    if let Some(parsed) = parse_setattr_string_line(command) {
        return Some(parsed);
    }

    let trimmed = command.trim_start();
    if !trimmed.starts_with("setAttr ") || !trimmed.contains("-type \"string\"") {
        return None;
    }

    let mut cursor = trimmed.find('"')?;
    let (attr_lit, next) = parse_ma_quoted_literal(trimmed, cursor);
    let attr = attr_lit?;
    cursor = next;

    let marker_pos = trimmed[cursor..].find("-type \"string\"")?;
    cursor += marker_pos + "-type \"string\"".len();
    Some((
        attr,
        parse_setattr_string_value_after_marker(trimmed, cursor)?,
    ))
}

pub(crate) fn is_create_script_command(line: &[u8]) -> bool {
    CREATE_SCRIPT_RE.is_match(&String::from_utf8_lossy(line))
}

#[cfg(test)]
mod tests {
    use super::{extract_script_node_name_from_create, split_lines_keepends};

    fn parse_ma_borrowed_quoted_literal(text: &str, start: usize) -> (Option<&str>, usize) {
        if start >= text.len() || !text[start..].starts_with('"') {
            return (None, start);
        }
        let bytes = text.as_bytes();
        let mut cursor = start + 1;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'"' => return (Some(&text[start + 1..cursor]), cursor + 1),
                b'\\' => return (None, start),
                _ => cursor += 1,
            }
        }
        (None, start)
    }

    #[test]
    fn create_node_name_parser_extracts_named_node() {
        let line = br#"createNode script -n "scriptNode1" -p "root";"#;
        assert_eq!(extract_script_node_name_from_create(line, 0), "scriptNode1");
    }

    #[test]
    fn create_node_name_parser_handles_escaped_quotes() {
        let line = b"createNode script -n \"script\\\"Node1\";";
        assert_eq!(
            extract_script_node_name_from_create(line, 0),
            "script\\\"Node1"
        );
    }

    #[test]
    fn create_node_name_parser_falls_back_when_missing_name() {
        let line = br#"createNode script -s;"#;
        assert_eq!(
            extract_script_node_name_from_create(line, 41),
            "<scriptNode@line42>"
        );
    }

    #[test]
    fn borrowed_quoted_literal_parses_unescaped_text_without_allocating() {
        let text = r#"setAttr ".b" -type "string" "print";"#;
        let start = text.find('"').unwrap();
        let (literal, next) = parse_ma_borrowed_quoted_literal(text, start);
        assert_eq!(literal, Some(".b"));
        assert_eq!(next, start + 4);
    }

    #[test]
    fn borrowed_quoted_literal_rejects_escaped_payloads() {
        let text = "createNode script -n \"script\\\"Node1\";";
        let start = text.find('"').unwrap();
        let (literal, next) = parse_ma_borrowed_quoted_literal(text, start);
        assert_eq!(literal, None);
        assert_eq!(next, start);
    }

    #[test]
    fn split_lines_keepends_returns_borrowed_slices() {
        let input = b"first\nsecond\nthird";
        let lines = split_lines_keepends(input);
        assert_eq!(
            lines,
            vec![&b"first\n"[..], &b"second\n"[..], &b"third"[..]]
        );
        assert!(std::ptr::eq(lines[1].as_ptr(), input[6..].as_ptr()));
    }
}
