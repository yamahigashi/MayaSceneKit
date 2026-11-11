use std::{
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
};

// MA rewrite helpers intentionally operate on raw command text so path cleanup
// can preserve source formatting without becoming a semantic owner.
pub(crate) use crate::ma::lexer::command_has_terminating_semicolon;
use crate::{
    PathReplaceRule, PathReplaceSkips, ScenePathEntry,
    ma::{
        commands::{Token, is_file_command_callback_flag, setattr_flag_arity, tokenize_command},
        lexer::{
            extract_script_node_name_from_create, is_reference_attr, is_top_level_command,
            looks_like_scene_path, parse_ma_quoted_literal, split_lines_keepends,
            unescape_ma_string_literal,
        },
        paths::extract_raw_scene_paths_from_ma,
        text::escape_ma_string,
    },
    reference_semantics::{
        ScenePathAttrKind, classify_scene_path_attr, looks_like_scene_file_path,
    },
};

#[derive(Debug, Clone)]
pub struct MaPathReplaceChange {
    pub entry: Option<ScenePathEntry>,
    pub before_value: String,
    pub after_value: String,
    pub replacement_count: usize,
}

#[derive(Debug, Clone)]
pub struct MaPathReplaceResult {
    pub bytes: Vec<u8>,
    pub replacement_count: usize,
    pub skipped: PathReplaceSkips,
    pub paths: Vec<MaPathReplaceChange>,
}

#[derive(Debug, thiserror::Error)]
pub enum MaPathReplaceError {
    #[error("CP932 and GBK disagree on Maya ASCII command structure")]
    AmbiguousEncoding,
    #[error("path entry {entry_index} identifies multiple source value ranges")]
    AmbiguousEntry { entry_index: usize },
    #[error("path entry {entry_index} has no matching source value range")]
    MissingEntry { entry_index: usize },
    #[error("duplicate path replacement for entry {entry_index}")]
    DuplicateEntry { entry_index: usize },
    #[error("invalid replace regex: {0}")]
    InvalidRegex(#[from] regex::Error),
}

use std::ops::Range;

use maya_mel::parser::{
    LightParseOptions, ParseBudgets, SourceEncoding, scan_light_bytes_with_options_and_sink,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathToken {
    range: Range<usize>,
    quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathCommand {
    start: usize,
    end: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct PathCommands {
    commands: Vec<PathCommand>,
    structure: Vec<(usize, u8)>,
    unterminated_tail_from: Option<usize>,
}

fn source_width(data: &[u8], offset: usize, encoding: SourceEncoding) -> usize {
    let lead = match encoding {
        SourceEncoding::Utf8 => false,
        SourceEncoding::Cp932 => matches!(data[offset], 0x81..=0x9f | 0xe0..=0xfc),
        SourceEncoding::Gbk => matches!(data[offset], 0x81..=0xfe),
    };
    let trail = data.get(offset + 1).is_some_and(|byte| match encoding {
        SourceEncoding::Utf8 => false,
        SourceEncoding::Cp932 => matches!(byte, 0x40..=0x7e | 0x80..=0xfc),
        SourceEncoding::Gbk => matches!(byte, 0x40..=0x7e | 0x80..=0xfe),
    });
    if lead && trail { 2 } else { 1 }
}

static PATH_COMMAND_DELIMITER: once_cell::sync::Lazy<regex::bytes::Regex> =
    once_cell::sync::Lazy::new(|| regex::bytes::Regex::new(r#"[";/\r\n]"#).unwrap());

fn scan_path_commands(
    data: &[u8],
    encoding: SourceEncoding,
    check_structure: bool,
) -> PathCommands {
    let mut result = PathCommands {
        commands: Vec::new(),
        structure: Vec::new(),
        unterminated_tail_from: None,
    };
    let mut start = None;
    let mut cursor = usize::from(data.starts_with(&[0xef, 0xbb, 0xbf])) * 3;
    while cursor < data.len() {
        if data[cursor..].starts_with(b"/*") {
            cursor += 2;
            while cursor < data.len() && !data[cursor..].starts_with(b"*/") {
                cursor += source_width(data, cursor, encoding);
            }
            cursor = (cursor + 2).min(data.len());
            continue;
        }
        if data[cursor..].starts_with(b"//") {
            while cursor < data.len() && !matches!(data[cursor], b'\r' | b'\n') {
                cursor += source_width(data, cursor, encoding);
            }
            continue;
        }
        if data[cursor].is_ascii_whitespace() {
            let newline = matches!(data[cursor], b'\r' | b'\n');
            cursor += 1;
            if newline
                && cursor < data.len()
                && !data[cursor].is_ascii_whitespace()
                && !data[cursor..].starts_with(b"//")
                && let Some(start) = start.take()
            {
                result.commands.push(PathCommand { start, end: cursor });
            }
            continue;
        }
        if data[cursor] == b';' {
            if check_structure {
                result.structure.push((cursor, b';'));
            }
            if let Some(start) = start.take() {
                result.commands.push(PathCommand { start, end: cursor });
            }
            cursor += 1;
            continue;
        }
        let command_start = *start.get_or_insert(cursor);
        if data[cursor] == b'"' {
            if check_structure {
                result.structure.push((cursor, b'"'));
            }
            cursor += 1;
            while cursor < data.len() && data[cursor] != b'"' {
                if data[cursor] == b'\\' {
                    if check_structure {
                        result.structure.push((cursor, b'\\'));
                    }
                    cursor += 1;
                    if cursor < data.len() {
                        cursor += source_width(data, cursor, encoding);
                    }
                } else {
                    cursor += source_width(data, cursor, encoding);
                }
            }
            if cursor == data.len() {
                result.unterminated_tail_from = Some(command_start);
                return result;
            }
            if check_structure {
                result.structure.push((cursor, b'"'));
            }
            cursor += 1;
        } else {
            cursor += 1;
            cursor += PATH_COMMAND_DELIMITER
                .find(&data[cursor..])
                .map_or(data.len() - cursor, |found| found.start());
        }
    }
    if let Some(start) = start {
        result.commands.push(PathCommand {
            start,
            end: data.len(),
        });
    }
    result
}

fn header_path_encoding(data: &[u8]) -> Option<SourceEncoding> {
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    for line in data.split(|byte| matches!(byte, b'\r' | b'\n')) {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let comment = line.strip_prefix(b"//")?;
        let comment = super::lexer::trim_ascii(comment);
        let Some(prefix) = comment.get(..8) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case(b"Codeset:") {
            continue;
        }
        let code = super::lexer::trim_ascii(&comment[8..]);
        match code {
            b"932" => return Some(SourceEncoding::Cp932),
            b"936" => return Some(SourceEncoding::Gbk),
            b"65001" => return Some(SourceEncoding::Utf8),
            _ => {}
        }
    }
    None
}

fn path_source(data: &[u8]) -> Result<(SourceEncoding, PathCommands), MaPathReplaceError> {
    if std::str::from_utf8(data).is_ok() {
        return Ok((
            SourceEncoding::Utf8,
            scan_path_commands(data, SourceEncoding::Utf8, false),
        ));
    }
    if let Some(encoding) = header_path_encoding(data) {
        return Ok((encoding, scan_path_commands(data, encoding, false)));
    }
    let cp932 = scan_path_commands(data, SourceEncoding::Cp932, true);
    let gbk = scan_path_commands(data, SourceEncoding::Gbk, true);
    if cp932 != gbk {
        return Err(MaPathReplaceError::AmbiguousEncoding);
    }
    let detected = scan_light_bytes_with_options_and_sink(
        data,
        LightParseOptions {
            budgets: ParseBudgets {
                max_bytes: data.len(),
                ..ParseBudgets::default()
            },
            ..LightParseOptions::default()
        },
        &mut |_: maya_mel::parser::LightSourceView<'_>, _: maya_mel::parser::LightItem| {},
    )
    .source_encoding;
    Ok((
        detected,
        if matches!(detected, SourceEncoding::Gbk) {
            gbk
        } else {
            cp932
        },
    ))
}

#[derive(Clone)]
struct PathTokens<'a> {
    data: &'a [u8],
    cursor: usize,
    end: usize,
    encoding: SourceEncoding,
}

impl Iterator for PathTokens<'_> {
    type Item = PathToken;

    fn next(&mut self) -> Option<Self::Item> {
        while self.cursor < self.end {
            if self.data[self.cursor].is_ascii_whitespace() {
                self.cursor += 1;
            } else if self.data[self.cursor..].starts_with(b"//") {
                while self.cursor < self.end && !matches!(self.data[self.cursor], b'\r' | b'\n') {
                    self.cursor += source_width(self.data, self.cursor, self.encoding);
                }
            } else if self.data[self.cursor..].starts_with(b"/*") {
                self.cursor += 2;
                while self.cursor < self.end && !self.data[self.cursor..].starts_with(b"*/") {
                    self.cursor += source_width(self.data, self.cursor, self.encoding);
                }
                self.cursor = (self.cursor + 2).min(self.end);
            } else {
                break;
            }
        }
        if self.cursor == self.end {
            return None;
        }
        if self.data[self.cursor] == b'"' {
            self.cursor += 1;
            let start = self.cursor;
            while self.cursor < self.end && self.data[self.cursor] != b'"' {
                if self.data[self.cursor] == b'\\' {
                    self.cursor += 1;
                }
                if self.cursor < self.end {
                    self.cursor += source_width(self.data, self.cursor, self.encoding);
                }
            }
            let end = self.cursor;
            self.cursor = (self.cursor + 1).min(self.end);
            Some(PathToken {
                range: start..end,
                quoted: true,
            })
        } else {
            let start = self.cursor;
            if matches!(self.data[self.cursor], b'(' | b')' | b'+') {
                self.cursor += 1;
            } else {
                while self.cursor < self.end
                    && !self.data[self.cursor].is_ascii_whitespace()
                    && !matches!(self.data[self.cursor], b'"' | b'(' | b')' | b'+')
                    && !self.data[self.cursor..].starts_with(b"//")
                    && !self.data[self.cursor..].starts_with(b"/*")
                {
                    self.cursor += source_width(self.data, self.cursor, self.encoding);
                }
            }
            Some(PathToken {
                range: start..self.cursor,
                quoted: false,
            })
        }
    }
}

fn path_setattr_prefix(data: &[u8], mut tokens: PathTokens<'_>) -> bool {
    tokens.next();
    while let Some(token) = tokens.next() {
        let raw = &data[token.range];
        if token.quoted {
            let Ok(attr) = std::str::from_utf8(raw) else {
                return false;
            };
            if !matches!(
                classify_scene_path_attr(attr),
                Some(ScenePathAttrKind::FileTexturePath | ScenePathAttrKind::ReferencePath)
            ) {
                return false;
            }
            while let Some(flag) = tokens.next() {
                let raw = &data[flag.range];
                if flag.quoted || !raw.starts_with(b"-") {
                    return false;
                }
                if raw == b"-type" {
                    return tokens
                        .next()
                        .is_some_and(|t| t.quoted && &data[t.range] == b"string");
                }
                let arity = std::str::from_utf8(raw)
                    .ok()
                    .and_then(setattr_flag_arity)
                    .unwrap_or(1);
                for _ in 0..arity {
                    tokens.next();
                }
            }
            return false;
        }
        if !raw.starts_with(b"-") {
            return false;
        }
        let arity = std::str::from_utf8(raw)
            .ok()
            .and_then(setattr_flag_arity)
            .unwrap_or(1);
        for _ in 0..arity {
            tokens.next();
        }
    }
    false
}

fn path_codec(encoding: SourceEncoding) -> &'static encoding_rs::Encoding {
    match encoding {
        SourceEncoding::Utf8 => encoding_rs::UTF_8,
        SourceEncoding::Cp932 => encoding_rs::SHIFT_JIS,
        SourceEncoding::Gbk => encoding_rs::GBK,
    }
}

fn encode_path(text: &str, encoding: SourceEncoding) -> Option<Vec<u8>> {
    let (bytes, _, errors) = path_codec(encoding).encode(text);
    (!errors).then(|| bytes.into_owned())
}

fn decode_path(raw: &[u8], encoding: SourceEncoding) -> (String, bool) {
    let (text, errors) = path_codec(encoding).decode_without_bom_handling(raw);
    let roundtrips = !errors && encode_path(&text, encoding).as_deref() == Some(raw);
    (text.into_owned(), roundtrips)
}

fn token_value(data: &[u8], token: &PathToken, encoding: SourceEncoding) -> String {
    if token.quoted {
        let (text, _) = decode_path(&data[token.range.clone()], encoding);
        unescape_ma_string_literal(&text)
    } else {
        std::str::from_utf8(&data[token.range.clone()])
            .ok()
            .filter(|text| text.is_ascii())
            .unwrap_or_default()
            .to_string()
    }
}

#[derive(Clone)]
struct PathCandidate {
    excluded_ranges: Vec<Range<usize>>,
    ranges: Vec<Range<usize>>,
    entry: Option<ScenePathEntry>,
}

fn file_path_flag_arity(flag: &str) -> usize {
    use maya_mel::{
        maya::MayaCommandRegistry,
        sema::command_schema::{CommandRegistry, FlagArity},
    };
    let registry = MayaCommandRegistry::new();
    let schema = registry.lookup("file").expect("built-in file schema");
    let name = flag.trim_start_matches('-');
    let Some(flag) = schema
        .flags
        .iter()
        .find(|flag| flag.long_name.as_ref() == name || flag.short_name.as_deref() == Some(name))
    else {
        return 1;
    };
    match flag.arity_by_mode.create {
        FlagArity::None => 0,
        FlagArity::Exact(count) => usize::from(count),
        FlagArity::Range { max, .. } => usize::from(max),
    }
}

fn path_candidates(
    data: &[u8],
    commands: &[PathCommand],
    encoding: SourceEncoding,
) -> Vec<PathCandidate> {
    let mut candidates = Vec::new();
    let mut active: Option<ActiveScenePathBlock> = None;
    for command in commands {
        let tokens = PathTokens {
            data,
            cursor: command.start,
            end: command.end,
            encoding,
        };
        let Some(first) = tokens.clone().next() else {
            continue;
        };
        let head = &data[first.range];
        if head == b"setAttr" {
            if !path_setattr_prefix(data, tokens.clone()) {
                continue;
            }
        } else if !matches!(head, b"createNode" | b"file") {
            if !matches!(head, b"addAttr" | b"rename" | b"lockNode") {
                active = None;
            }
            continue;
        }
        let tokens: Vec<_> = tokens.collect();
        let values: Vec<_> = tokens
            .iter()
            .map(|t| token_value(data, t, encoding))
            .collect();
        let head = values[0].as_str();
        if head == "createNode" {
            let name = values.iter().enumerate().find_map(|(i, v)| {
                (!tokens[i].quoted && matches!(v.as_str(), "-n" | "-name"))
                    .then(|| values.get(i + 1).cloned())
                    .flatten()
            });
            active = values.get(1).map(|node_type| ActiveScenePathBlock {
                node_type: node_type.clone(),
                node_name: name.unwrap_or_else(|| {
                    format!(
                        "<scriptNode@line{}>",
                        data[..command.start]
                            .iter()
                            .filter(|&&b| b == b'\n')
                            .count()
                            + 1
                    )
                }),
            });
            continue;
        }
        if head == "file" {
            active = None;
            let mut path = None;
            let mut node_name = "<fileCmdRef>".to_string();
            let mut i = 1;
            while i < tokens.len() {
                if !tokens[i].quoted && values[i].starts_with('-') {
                    let flag = values[i].as_str();
                    let arity = file_path_flag_arity(flag);
                    if matches!(flag, "-rfn" | "-referenceNode")
                        && let Some(value) = values.get(i + 1)
                    {
                        node_name = value.clone();
                    }
                    i += 1 + arity;
                } else {
                    if tokens[i].quoted {
                        path = Some(i);
                    }
                    i += 1;
                }
            }
            if let Some(i) = path
                && (looks_like_scene_path(&values[i]) || looks_like_scene_file_path(&values[i]))
            {
                candidates.push(PathCandidate {
                    excluded_ranges: Vec::new(),
                    ranges: vec![tokens[i].range.clone()],
                    entry: Some(ScenePathEntry {
                        node_type: "reference".into(),
                        node_name,
                        attr: ".fn".into(),
                        value: values[i].clone(),
                        meta: None,
                    }),
                });
            }
            continue;
        }
        if head != "setAttr" {
            if !matches!(head, "addAttr" | "rename" | "lockNode") {
                active = None;
            }
            continue;
        }
        let Some(type_index) = values.iter().enumerate().find_map(|(i, v)| {
            (!tokens[i].quoted
                && v == "-type"
                && tokens.get(i + 1).is_some_and(|t| t.quoted)
                && values.get(i + 1).is_some_and(|v| v == "string"))
            .then_some(i)
        }) else {
            continue;
        };
        let mut attr_index = 1;
        while attr_index < type_index
            && !tokens[attr_index].quoted
            && values[attr_index].starts_with('-')
        {
            attr_index += 1 + setattr_flag_arity(&values[attr_index]).unwrap_or(1);
        }
        let Some(attr) = values.get(attr_index).filter(|attr| {
            attr_index < type_index
                && matches!(
                    classify_scene_path_attr(attr),
                    Some(ScenePathAttrKind::FileTexturePath | ScenePathAttrKind::ReferencePath)
                )
        }) else {
            continue;
        };
        let mut ranges = Vec::new();
        let mut i = type_index + 2;
        let grouped = values.get(i).is_some_and(|v| v == "(") && !tokens[i].quoted;
        if grouped {
            i += 1;
        }
        while let Some(token) = tokens.get(i) {
            if !token.quoted {
                break;
            }
            ranges.push(token.range.clone());
            i += 1;
            if values.get(i).is_some_and(|v| v == "+") && !tokens[i].quoted {
                i += 1;
            } else {
                break;
            }
        }
        if ranges.is_empty() {
            continue;
        }
        let value = ranges
            .iter()
            .map(|range| {
                let (raw, _) = decode_path(&data[range.clone()], encoding);
                unescape_ma_string_literal(&raw)
            })
            .collect::<String>();
        let entry = active
            .as_ref()
            .and_then(|block| scene_path_entry_from_setattr(block, attr, &value));
        candidates.push(PathCandidate {
            ranges,
            entry,
            excluded_ranges: Vec::new(),
        });
    }
    candidates
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaByteEdit {
    pub range: Range<usize>,
    pub bytes: Vec<u8>,
}

fn apply_path_value_edits(data: &[u8], mut edits: Vec<MaByteEdit>) -> Vec<u8> {
    edits.sort_by_key(|edit| (edit.range.start, edit.range.end));
    for edit in &edits {
        assert!(edit.range.start <= edit.range.end && edit.range.end <= data.len());
    }
    for pair in edits.windows(2) {
        assert!(pair[0].range.end <= pair[1].range.start && pair[0].range != pair[1].range);
    }
    let removed: usize = edits.iter().map(|edit| edit.range.len()).sum();
    let inserted: usize = edits.iter().map(|edit| edit.bytes.len()).sum();
    let mut bytes = Vec::with_capacity(data.len() - removed + inserted);
    let mut cursor = 0;
    for edit in edits {
        bytes.extend_from_slice(&data[cursor..edit.range.start]);
        bytes.extend_from_slice(&edit.bytes);
        cursor = edit.range.end;
    }
    bytes.extend_from_slice(&data[cursor..]);
    bytes
}

struct PathMatchRule {
    pattern: regex::Regex,
    replacement: String,
    literal: bool,
}

fn compile_path_matches(
    rules: &[PathReplaceRule],
) -> Result<Vec<PathMatchRule>, MaPathReplaceError> {
    rules
        .iter()
        .filter(|rule| !rule.from.is_empty())
        .map(|rule| {
            let literal = matches!(rule.mode, crate::PathReplaceMode::Literal);
            let pattern = if literal {
                regex::escape(&rule.from)
            } else {
                rule.from.clone()
            };
            Ok(PathMatchRule {
                pattern: regex::Regex::new(&pattern)?,
                replacement: rule.to.clone(),
                literal,
            })
        })
        .collect()
}

fn escaped_path_bytes(value: &str, encoding: SourceEncoding) -> Option<Vec<u8>> {
    let normalized;
    let value = if matches!(encoding, SourceEncoding::Cp932) {
        normalized = value.replace('¥', "\\").replace('‾', "~");
        normalized.as_str()
    } else {
        value
    };
    encode_path(&escape_ma_string(value), encoding)
}

pub struct MaPathRangeSkip {
    pub range: Range<usize>,
    pub skipped: PathReplaceSkips,
}

struct MaPathCandidateApplication {
    change: MaPathReplaceChange,
    skipped_ranges: Vec<MaPathRangeSkip>,
}

fn apply_path_candidate(
    data: &[u8],
    encoding: SourceEncoding,
    candidate: PathCandidate,
    rules: &[PathMatchRule],
    override_value: Option<&str>,
    skipped: &mut PathReplaceSkips,
    edits: &mut Vec<MaByteEdit>,
) -> MaPathCandidateApplication {
    let decoded: Vec<_> = candidate
        .ranges
        .iter()
        .map(|range| decode_path(&data[range.clone()], encoding))
        .collect();
    let original: Vec<_> = decoded
        .iter()
        .map(|(raw, _)| unescape_ma_string_literal(raw))
        .collect();
    let mut values = original.clone();
    let mut reasons = vec![0u8; values.len()];
    let mut crossed = vec![false; values.len()];
    let mut local_match = vec![false; values.len()];
    let canonical = |i: usize| {
        encode_path(&escape_ma_string(&original[i]), encoding).as_deref()
            == Some(&data[candidate.ranges[i].clone()])
    };
    let mut accept = |i: usize, next: String, values: &mut Vec<String>| {
        if candidate.excluded_ranges.contains(&candidate.ranges[i]) {
            return;
        }
        local_match[i] = true;
        let reason = if !decoded[i].1 {
            1
        } else if !canonical(i) {
            2
        } else {
            0
        };
        if reason != 0 {
            if reasons[i] == 0 || reason < reasons[i] {
                reasons[i] = reason;
            }
        } else {
            values[i] = next;
        }
    };
    if let Some(value) = override_value {
        if values.len() == 1 {
            if value != values[0] {
                accept(0, value.to_string(), &mut values);
            }
        } else if value != values.concat() {
            crossed.fill(true);
        }
    } else {
        for rule in rules {
            let joined = values.concat();
            let mut offsets = vec![0];
            for value in &values {
                offsets.push(offsets.last().unwrap() + value.len());
            }
            let mut replacements: Vec<Vec<(Range<usize>, String)>> = vec![Vec::new(); values.len()];
            for captures in rule.pattern.captures_iter(&joined) {
                let found = captures.get(0).expect("whole regex match");
                let index = offsets[1..]
                    .iter()
                    .position(|&end| found.start() < end)
                    .unwrap_or(values.len() - 1);
                if found.end() > offsets[index + 1] {
                    for j in index..values.len() {
                        if offsets[j] >= found.end() {
                            break;
                        }
                        crossed[j] = true;
                    }
                    continue;
                }
                let mut replacement = String::new();
                if rule.literal {
                    replacement.push_str(&rule.replacement);
                } else {
                    captures.expand(&rule.replacement, &mut replacement);
                }
                replacements[index].push((
                    found.start() - offsets[index]..found.end() - offsets[index],
                    replacement,
                ));
            }
            for (i, matches) in replacements.into_iter().enumerate() {
                if matches.is_empty() {
                    continue;
                }
                let mut next = values[i].clone();
                for (range, replacement) in matches.into_iter().rev() {
                    next.replace_range(range, &replacement);
                }
                if next != values[i] {
                    accept(i, next, &mut values);
                }
            }
        }
    }
    let mut count = 0;
    let mut skipped_ranges = Vec::new();
    for i in 0..values.len() {
        if candidate.excluded_ranges.contains(&candidate.ranges[i]) {
            continue;
        }
        if !decoded[i].1 && (!crossed[i] || local_match[i]) {
            reasons[i] = 1;
        }
        let mut range_skipped = PathReplaceSkips {
            non_utf8: usize::from(reasons[i] == 1),
            non_canonical_escape: usize::from(reasons[i] == 2),
            crosses_concat_boundary: usize::from(crossed[i]),
            ..Default::default()
        };
        if values[i] != original[i] {
            if let Some(bytes) = escaped_path_bytes(&values[i], encoding) {
                let (raw, _) = decode_path(&bytes, encoding);
                values[i] = unescape_ma_string_literal(&raw);
                if bytes != data[candidate.ranges[i].clone()] {
                    count += 1;
                    edits.push(MaByteEdit {
                        range: candidate.ranges[i].clone(),
                        bytes,
                    });
                }
            } else {
                if reasons[i] == 0 {
                    range_skipped.unrepresentable = 1;
                }
                values[i].clone_from(&original[i]);
            }
        }
        skipped.non_utf8 += range_skipped.non_utf8;
        skipped.non_canonical_escape += range_skipped.non_canonical_escape;
        skipped.unrepresentable += range_skipped.unrepresentable;
        skipped.crosses_concat_boundary += range_skipped.crosses_concat_boundary;
        if range_skipped.total() > 0 {
            skipped_ranges.push(MaPathRangeSkip {
                range: candidate.ranges[i].clone(),
                skipped: range_skipped,
            });
        }
    }
    MaPathCandidateApplication {
        change: MaPathReplaceChange {
            entry: candidate.entry,
            before_value: original.concat(),
            after_value: values.concat(),
            replacement_count: count,
        },
        skipped_ranges,
    }
}

fn empty_path_result(data: &[u8]) -> MaPathReplaceResult {
    MaPathReplaceResult {
        bytes: data.to_vec(),
        replacement_count: 0,
        skipped: PathReplaceSkips::default(),
        paths: Vec::new(),
    }
}

pub fn replace_raw_scene_paths_in_ma(
    data: &[u8],
    rules: &[PathReplaceRule],
) -> Result<MaPathReplaceResult, MaPathReplaceError> {
    let rules = compile_path_matches(rules)?;
    if rules.is_empty() {
        return Ok(empty_path_result(data));
    }
    replace_raw_scene_paths_in_ma_with_rules(data, &rules, None)
}

fn matching_path_candidate(
    candidates: &[PathCandidate],
    entry: &ScenePathEntry,
    entry_index: usize,
) -> Result<usize, MaPathReplaceError> {
    let fingerprint = scene_path_entry_fingerprint(entry);
    let mut matching = candidates.iter().enumerate().filter(|(_, candidate)| {
        candidate
            .entry
            .as_ref()
            .is_some_and(|entry| scene_path_entry_fingerprint(entry) == fingerprint)
    });
    let (index, _) = matching
        .next()
        .ok_or(MaPathReplaceError::MissingEntry { entry_index })?;
    if matching.next().is_some() {
        return Err(MaPathReplaceError::AmbiguousEntry { entry_index });
    }
    Ok(index)
}

fn replace_raw_scene_paths_in_ma_with_rules(
    data: &[u8],
    rules: &[PathMatchRule],
    replacements: Option<&[(usize, String)]>,
) -> Result<MaPathReplaceResult, MaPathReplaceError> {
    let (encoding, commands) = path_source(data)?;
    let candidates = path_candidates(data, &commands.commands, encoding);
    let mut selected = HashMap::new();
    if let Some(replacements) = replacements {
        let entries = extract_raw_scene_paths_from_ma(data);
        let mut seen = HashSet::new();
        for (index, value) in replacements {
            if !seen.insert(*index) {
                return Err(MaPathReplaceError::DuplicateEntry {
                    entry_index: *index,
                });
            }
            let Some(entry) = entries.get(*index) else {
                return Err(MaPathReplaceError::MissingEntry {
                    entry_index: *index,
                });
            };
            let candidate_index = matching_path_candidate(&candidates, entry, *index)?;
            selected.insert(candidate_index, value.as_str());
        }
    }
    let mut result = MaPathReplaceResult {
        bytes: Vec::new(),
        replacement_count: 0,
        skipped: PathReplaceSkips::default(),
        paths: Vec::new(),
    };
    result.skipped.unterminated_tail_from = commands.unterminated_tail_from;
    result.skipped.unterminated_tail = usize::from(commands.unterminated_tail_from.is_some());
    let mut edits = Vec::new();
    for (i, candidate) in candidates.into_iter().enumerate() {
        if replacements.is_some() && !selected.contains_key(&i) {
            continue;
        }
        let applied = apply_path_candidate(
            data,
            encoding,
            candidate,
            rules,
            selected.get(&i).copied(),
            &mut result.skipped,
            &mut edits,
        );
        result.replacement_count += applied.change.replacement_count;
        result.paths.push(applied.change);
    }
    result.bytes = apply_path_value_edits(data, edits);
    Ok(result)
}

pub fn replace_raw_scene_paths_in_ma_by_index(
    data: &[u8],
    replacements: &[(usize, String)],
) -> Result<MaPathReplaceResult, MaPathReplaceError> {
    if replacements.is_empty() {
        return Ok(empty_path_result(data));
    }
    replace_raw_scene_paths_in_ma_with_rules(data, &[], Some(replacements))
}

#[derive(Clone)]
pub struct MaPathCandidatePlan {
    pub entry_index: usize,
    encoding: SourceEncoding,
    candidate: PathCandidate,
}

impl MaPathCandidatePlan {
    pub fn ranges(&self) -> &[Range<usize>] {
        &self.candidate.ranges
    }
    pub fn entry(&self) -> &ScenePathEntry {
        self.candidate.entry.as_ref().expect("resolved path entry")
    }
}

pub struct MaPathCandidatesPlan {
    pub candidates: Vec<MaPathCandidatePlan>,
    pub skipped: PathReplaceSkips,
}

pub struct MaPathValuePlan {
    pub edits: Vec<MaByteEdit>,
    pub skipped: PathReplaceSkips,
    pub skipped_ranges: Vec<MaPathRangeSkip>,
}

pub fn collect_ma_path_candidates(
    data: &[u8],
    indices: &[usize],
) -> Result<MaPathCandidatesPlan, MaPathReplaceError> {
    if indices.is_empty() {
        return Ok(MaPathCandidatesPlan {
            candidates: Vec::new(),
            skipped: PathReplaceSkips::default(),
        });
    }
    let (encoding, commands) = path_source(data)?;
    let candidates = path_candidates(data, &commands.commands, encoding);
    let entries = extract_raw_scene_paths_from_ma(data);
    let mut seen = HashSet::new();
    let mut selected = HashSet::new();
    let mut plans = Vec::new();
    for &entry_index in indices {
        if !seen.insert(entry_index) {
            return Err(MaPathReplaceError::DuplicateEntry { entry_index });
        }
        let entry = entries
            .get(entry_index)
            .ok_or(MaPathReplaceError::MissingEntry { entry_index })?;
        let index = matching_path_candidate(&candidates, entry, entry_index)?;
        let candidate = &candidates[index];
        if !selected.insert(index) {
            return Err(MaPathReplaceError::AmbiguousEntry { entry_index });
        }
        plans.push(MaPathCandidatePlan {
            entry_index,
            encoding,
            candidate: candidate.clone(),
        });
    }
    Ok(MaPathCandidatesPlan {
        candidates: plans,
        skipped: PathReplaceSkips {
            unterminated_tail: usize::from(commands.unterminated_tail_from.is_some()),
            unterminated_tail_from: commands.unterminated_tail_from,
            ..PathReplaceSkips::default()
        },
    })
}

pub fn plan_ma_path_value(
    data: &[u8],
    candidate: &MaPathCandidatePlan,
    after: &str,
    excluded_ranges: &[Range<usize>],
) -> MaPathValuePlan {
    if after == candidate.entry().value {
        return MaPathValuePlan {
            edits: Vec::new(),
            skipped: PathReplaceSkips::default(),
            skipped_ranges: Vec::new(),
        };
    }
    let mut skipped = PathReplaceSkips::default();
    let mut edits = Vec::new();
    let mut selected = candidate.candidate.clone();
    selected.excluded_ranges = excluded_ranges.to_vec();
    let applied = apply_path_candidate(
        data,
        candidate.encoding,
        selected,
        &[],
        Some(after),
        &mut skipped,
        &mut edits,
    );
    MaPathValuePlan {
        edits,
        skipped,
        skipped_ranges: applied.skipped_ranges,
    }
}

/// Applies already validated, disjoint edits in descending original-byte order.
pub fn apply_ma_byte_edits(data: &[u8], edits: &mut [MaByteEdit]) -> Vec<u8> {
    edits.sort_by_key(|edit| std::cmp::Reverse((edit.range.start, edit.range.end)));
    let mut out = data.to_vec();
    for edit in edits {
        out.splice(edit.range.clone(), edit.bytes.iter().copied());
    }
    out
}

pub struct MaCommandRanges {
    ranges: Vec<Range<usize>>,
    encoding: SourceEncoding,
}

pub fn collect_ma_command_ranges(data: &[u8]) -> MaCommandRanges {
    use maya_mel::parser::{
        LightItem, LightSourceView, scan_light_bytes_with_encoding_and_options_and_sink,
    };
    let mut ranges = Vec::new();
    let mut sink = |_: LightSourceView<'_>, item: LightItem| {
        let span = match item {
            LightItem::Command(command) => command.span,
            LightItem::Proc(proc_def) => proc_def.span,
            LightItem::Other { span } => span,
        };
        ranges.push(usize::from(span.start())..usize::from(span.end()));
    };
    let options = LightParseOptions {
        budgets: ParseBudgets {
            max_bytes: data.len(),
            ..ParseBudgets::default()
        },
        ..LightParseOptions::default()
    };
    let scan = if let Some(encoding) = header_path_encoding(data) {
        scan_light_bytes_with_encoding_and_options_and_sink(data, encoding, options, &mut sink)
    } else {
        scan_light_bytes_with_options_and_sink(data, options, &mut sink)
    };
    MaCommandRanges {
        ranges,
        encoding: scan.source_encoding,
    }
}

impl MaCommandRanges {
    pub fn contains(&self, data: &[u8], mut range: Range<usize>) -> bool {
        let Some(bytes) = data.get(range.clone()) else {
            return false;
        };
        range.start += bytes
            .iter()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count();
        range.end -= bytes
            .iter()
            .rev()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count();
        range.start < range.end && self.ranges.contains(&range)
    }

    pub fn file_command_without_callback(&self, command: &[u8]) -> Option<(Vec<u8>, bool)> {
        let trailing = command
            .iter()
            .rev()
            .take_while(|byte| matches!(byte, b'\n' | b'\r'))
            .count();
        let trimmed = command
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())?
            + 1;
        let terminated = command[trimmed - 1] == b';';
        let tokens = PathTokens {
            data: command,
            cursor: 0,
            end: trimmed - usize::from(terminated),
            encoding: self.encoding,
        }
        .collect::<Vec<_>>();
        let head = tokens.first()?;
        if head.quoted || &command[head.range.clone()] != b"file" {
            return None;
        }
        let mut kept = Vec::new();
        let mut removed = false;
        let mut index = 0;
        while index < tokens.len() {
            let token = &tokens[index];
            if !token.quoted && is_file_command_callback_flag(&command[token.range.clone()]) {
                removed = true;
                index += 1;
                for _ in 0..2 {
                    let Some(argument) = tokens.get(index) else {
                        break;
                    };
                    if !argument.quoted && command[argument.range.clone()].starts_with(b"-") {
                        break;
                    }
                    index += 1;
                }
            } else {
                kept.push(token);
                index += 1;
            }
        }
        if !removed {
            return Some((command.to_vec(), false));
        }
        let mut bytes = Vec::new();
        for (index, token) in kept.iter().enumerate() {
            let symbol = |token: &PathToken, value: u8| {
                !token.quoted && command[token.range.clone()] == [value]
            };
            if index > 0
                && !symbol(token, b')')
                && !symbol(token, b'+')
                && !symbol(kept[index - 1], b'(')
                && !symbol(kept[index - 1], b'+')
            {
                bytes.push(b' ');
            }
            if token.quoted {
                bytes.push(b'"');
            }
            bytes.extend_from_slice(&command[token.range.clone()]);
            if token.quoted {
                bytes.push(b'"');
            }
        }
        if terminated {
            bytes.push(b';');
        }
        bytes.extend_from_slice(&command[command.len() - trailing..]);
        Some((bytes, true))
    }
}

pub fn ma_range_has_bytes(data: &[u8], start: usize, end: usize) -> bool {
    data.get(start..end)
        .map(|slice| slice.iter().any(|byte| !byte.is_ascii_whitespace()))
        .unwrap_or(false)
}

pub fn ma_file_command_callback_present(data: &[u8], start: usize, end: usize) -> bool {
    let Some(slice) = data.get(start..end) else {
        return false;
    };
    let command = String::from_utf8_lossy(slice);
    file_command_without_callback(&command)
        .map(|result| {
            result
                .map(|(rewritten, _)| rewritten != command)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaRangeEdit {
    pub start: usize,
    pub end: usize,
    pub kind: MaRangeEditKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaRangeEditKind {
    RemoveCommand,
    StripFileCommandCallback,
}

#[derive(Debug)]
pub enum MaRangeEditError {
    Overlap {
        first: MaRangeEdit,
        second: MaRangeEdit,
    },
    CallbackParse(crate::ma::error::MaParseError),
}

pub fn normalize_ma_range_edits(
    data_len: usize,
    edits: &[MaRangeEdit],
) -> Result<Vec<MaRangeEdit>, MaRangeEditError> {
    let mut normalized = edits
        .iter()
        .copied()
        .filter(|edit| edit.start < edit.end && edit.end <= data_len)
        .collect::<Vec<_>>();
    normalized.sort_by_key(|edit| {
        (
            edit.start,
            edit.end,
            edit.kind != MaRangeEditKind::RemoveCommand,
        )
    });
    normalized.dedup_by_key(|edit| (edit.start, edit.end));
    let removals = normalized
        .iter()
        .copied()
        .filter(|edit| edit.kind == MaRangeEditKind::RemoveCommand)
        .collect::<Vec<_>>();
    normalized.retain(|edit| {
        !removals.iter().any(|outer| {
            outer.start <= edit.start
                && edit.end <= outer.end
                && (outer.start != edit.start || outer.end != edit.end)
        })
    });
    for (index, first) in normalized.iter().enumerate() {
        for second in &normalized[index + 1..] {
            if second.start >= first.end {
                break;
            }
            if first.start < second.end && second.start < first.end {
                return Err(MaRangeEditError::Overlap {
                    first: *first,
                    second: *second,
                });
            }
        }
    }
    normalized.reverse();
    Ok(normalized)
}

pub fn apply_ma_range_edits(
    data: &[u8],
    edits: &[MaRangeEdit],
) -> Result<(Vec<u8>, usize), MaRangeEditError> {
    let normalized = normalize_ma_range_edits(data.len(), edits)?;
    let mut replacements = Vec::new();
    for edit in normalized {
        let replacement = match edit.kind {
            MaRangeEditKind::RemoveCommand => {
                if !ma_range_has_bytes(data, edit.start, edit.end) {
                    continue;
                }
                Vec::new()
            }
            MaRangeEditKind::StripFileCommandCallback => {
                let original = String::from_utf8_lossy(&data[edit.start..edit.end]);
                let Some((rewritten, changed)) = file_command_without_callback(&original)
                    .map_err(MaRangeEditError::CallbackParse)?
                else {
                    continue;
                };
                if !changed || rewritten == original {
                    continue;
                }
                rewritten.into_bytes()
            }
        };
        replacements.push((edit, replacement));
    }
    let count = replacements.len();
    let mut out = data.to_vec();
    for (edit, replacement) in replacements {
        out.splice(edit.start..edit.end, replacement);
    }
    Ok((out, count))
}

pub fn remove_top_level_commands_from_ma(
    data: &[u8],
    ranges: &[(usize, usize)],
) -> (Vec<u8>, usize) {
    let edits = ranges
        .iter()
        .map(|&(start, end)| MaRangeEdit {
            start,
            end,
            kind: MaRangeEditKind::RemoveCommand,
        })
        .collect::<Vec<_>>();
    apply_ma_range_edits(data, &edits).unwrap_or_else(|_| (data.to_vec(), 0))
}

pub fn remove_path_owner_nodes_from_ma(
    data: &[u8],
    targets: &[(String, String)],
) -> (Vec<u8>, Vec<(String, String)>) {
    let ranges = collect_path_owner_ranges_from_ma(data, targets);
    if ranges.is_empty() {
        return (data.to_vec(), Vec::new());
    }
    let mut out = String::new();
    let mut cursor = 0;
    let mut removed = HashSet::new();
    for (range, target) in ranges {
        out.push_str(&String::from_utf8_lossy(&data[cursor..range.start]));
        cursor = range.end;
        removed.insert(target);
    }
    out.push_str(&String::from_utf8_lossy(&data[cursor..]));
    (out.into_bytes(), removed.into_iter().collect())
}
pub fn collect_path_owner_ranges_from_ma(
    data: &[u8],
    targets: &[(String, String)],
) -> Vec<(Range<usize>, (String, String))> {
    let targets = targets
        .iter()
        .filter_map(|(node_type, node_name)| {
            let node_type = node_type.trim();
            let node_name = node_name.trim();
            (!node_type.is_empty() && !node_name.is_empty())
                .then(|| (node_type.to_string(), node_name.to_string()))
        })
        .collect::<HashSet<_>>();
    if targets.is_empty() {
        return Vec::new();
    }

    let encoding = scan_light_bytes_with_options_and_sink(
        data,
        LightParseOptions {
            budgets: ParseBudgets {
                max_bytes: data.len(),
                ..ParseBudgets::default()
            },
            ..LightParseOptions::default()
        },
        &mut |_: maya_mel::parser::LightSourceView<'_>, _: maya_mel::parser::LightItem| {},
    )
    .source_encoding;
    let lines = split_lines_keepends(data);
    let mut ranges = Vec::new();
    let mut offsets = vec![0];
    for line in &lines {
        offsets.push(offsets.last().unwrap() + line.len());
    }
    let mut i = 0usize;
    let mut line_number = 0usize;

    while i < lines.len() {
        let line_text = decode_owner_command_line(lines[i], encoding);
        let trimmed = line_text.trim_start();

        if is_top_level_command(lines[i]) && trimmed.starts_with("file ") {
            let (command, next) = collect_top_level_command_block(&lines, i, encoding);
            if let Some(entry) = extract_reference_entry_from_raw_file_command(&command) {
                let target = (entry.node_type, entry.node_name);
                if targets.contains(&target) {
                    ranges.push((offsets[i]..offsets[next], target));
                    i = next;
                    line_number += command.lines().count().max(1);
                    continue;
                }
            }
            i = next;
            line_number += command.lines().count().max(1);
            continue;
        }

        if is_top_level_command(lines[i]) && trimmed.starts_with("createNode ") {
            let (command, next) = collect_top_level_command_block(&lines, i, encoding);
            if let Some(block) = start_raw_create_node_block(trimmed.as_bytes(), line_number) {
                let target = (block.node_type, block.node_name);
                if targets.contains(&target) {
                    ranges.push((offsets[i]..offsets[next], target));
                    i = next;
                    line_number += command.lines().count().max(1);
                    continue;
                }
            }
            i = next;
            line_number += command.lines().count().max(1);
            continue;
        }

        i += 1;
        line_number += 1;
    }

    ranges
}

fn collect_top_level_command_block(
    lines: &[&[u8]],
    start: usize,
    encoding: SourceEncoding,
) -> (String, usize) {
    let mut command = decode_owner_command_line(lines[start], encoding);
    let mut next = start + 1;

    while !command_has_terminating_semicolon(&command) && next < lines.len() {
        if is_top_level_command(lines[next]) {
            break;
        }
        command.push_str(&decode_owner_command_line(lines[next], encoding));
        next += 1;
    }

    (command, next)
}

fn decode_owner_command_line(bytes: &[u8], encoding: SourceEncoding) -> String {
    maya_mel::parser::LightSourceView::Bytes { bytes, encoding }
        .decode_slice(maya_mel::syntax::TextRange::new(
            0.into(),
            (bytes.len() as u32).into(),
        ))
        .text
        .into_owned()
}

pub fn file_command_without_callback(
    command: &str,
) -> Result<Option<(String, bool)>, crate::ma::error::MaParseError> {
    let tokens = tokenize_command(command)?;
    if !matches!(tokens.first(), Some(Token::Bare(head)) if head == "file") {
        return Ok(None);
    }

    let mut out = vec![Token::Bare("file".to_string())];
    let mut idx = 1usize;
    let mut removed = false;

    while idx < tokens.len() {
        if matches!(tokens.get(idx), Some(Token::Bare(flag)) if is_file_command_callback_flag(flag.as_bytes()))
        {
            removed = true;
            idx += 1;
            let mut removed_args = 0usize;
            while idx < tokens.len() && removed_args < 2 {
                if matches!(tokens.get(idx), Some(Token::Bare(value)) if value.starts_with('-')) {
                    break;
                }
                idx += 1;
                removed_args += 1;
            }
            continue;
        }
        out.push(tokens[idx].clone());
        idx += 1;
    }

    if !removed {
        return Ok(Some((command.to_string(), false)));
    }

    let mut rewritten = render_command_tokens(&out);
    if command.trim_end().ends_with(';') {
        rewritten.push(';');
    }
    let trailing = command
        .chars()
        .rev()
        .take_while(|ch| matches!(ch, '\n' | '\r'))
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    rewritten.push_str(&trailing);
    Ok(Some((rewritten, true)))
}

fn render_command_tokens(tokens: &[Token]) -> String {
    let mut out = String::new();
    for (index, token) in tokens.iter().enumerate() {
        if index > 0 && !matches!(token, Token::Symbol(')')) {
            let prev = &tokens[index - 1];
            if !matches!(prev, Token::Symbol('(') | Token::Symbol('+'))
                && !matches!(token, Token::Symbol('+'))
            {
                out.push(' ');
            }
        }
        match token {
            Token::Bare(value) => out.push_str(value),
            Token::Quoted(value) => {
                out.push('"');
                out.push_str(&value.replace('\\', "\\\\").replace('"', "\\\""));
                out.push('"');
            }
            Token::Symbol(symbol) => out.push(*symbol),
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveScenePathBlock {
    node_type: String,
    node_name: String,
}

fn start_raw_create_node_block(trimmed: &[u8], line_number: usize) -> Option<ActiveScenePathBlock> {
    let node_type = raw_create_node_type(trimmed)?;
    Some(ActiveScenePathBlock {
        node_type,
        node_name: extract_script_node_name_from_create(trimmed, line_number),
    })
}

fn raw_create_node_type(trimmed: &[u8]) -> Option<String> {
    let rest = trimmed.strip_prefix(b"createNode ")?;
    let end = rest
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || *byte == b';')
        .unwrap_or(rest.len());
    (end > 0)
        .then(|| std::str::from_utf8(&rest[..end]).ok())
        .flatten()
        .map(ToOwned::to_owned)
}

fn scene_path_entry_from_setattr(
    block: &ActiveScenePathBlock,
    attr: &str,
    value: &str,
) -> Option<ScenePathEntry> {
    if is_file_texture_attr(attr) {
        return Some(ScenePathEntry {
            node_type: block.node_type.clone(),
            node_name: block.node_name.clone(),
            attr: attr.to_string(),
            value: value.to_string(),
            meta: None,
        });
    }

    if block.node_type == "reference" && is_reference_attr(attr) {
        return Some(ScenePathEntry {
            node_type: "reference".to_string(),
            node_name: block.node_name.clone(),
            attr: attr.to_string(),
            value: value.to_string(),
            meta: None,
        });
    }

    None
}

fn is_file_texture_attr(attr: &str) -> bool {
    matches!(
        classify_scene_path_attr(attr),
        Some(ScenePathAttrKind::FileTexturePath)
    )
}

fn extract_reference_entry_from_raw_file_command(command: &str) -> Option<ScenePathEntry> {
    let path = last_quoted_literal(command).filter(|value| looks_like_scene_file_path(value))?;
    let node_name = parse_file_command_flag_value(command, "-rfn")
        .unwrap_or_else(|| "<fileCmdRef>".to_string());

    Some(ScenePathEntry {
        node_type: "reference".to_string(),
        node_name,
        attr: ".fn".to_string(),
        value: path,
        meta: None,
    })
}

#[cfg(test)]
fn last_quoted_literal_range(command: &str) -> Option<(usize, usize)> {
    let mut cursor = 0usize;
    let mut last_range = None;
    while cursor < command.len() {
        let Some(next_quote_rel) = command[cursor..].find('"') else {
            break;
        };
        let quote_start = cursor + next_quote_rel;
        let (literal, next) = parse_ma_quoted_literal(command, quote_start);
        if literal.is_none() {
            break;
        }
        last_range = Some((quote_start, next));
        cursor = next;
    }
    last_range
}

pub(crate) fn last_quoted_literal(command: &str) -> Option<String> {
    let mut cursor = 0usize;
    let mut last = None;
    while cursor < command.len() {
        let Some(next_quote_rel) = command[cursor..].find('"') else {
            break;
        };
        let quote_start = cursor + next_quote_rel;
        let (literal, next) = parse_ma_quoted_literal(command, quote_start);
        last = Some(unescape_ma_string_literal(&literal?));
        cursor = next;
    }
    last
}

fn parse_file_command_flag_value(command: &str, flag: &str) -> Option<String> {
    let idx = command.find(flag)?;
    let mut cursor = idx + flag.len();
    while cursor < command.len() {
        let ch = command[cursor..].chars().next().unwrap();
        if ch.is_whitespace() {
            cursor += ch.len_utf8();
            continue;
        }
        break;
    }
    if cursor >= command.len() || !command[cursor..].starts_with('"') {
        return None;
    }
    let (literal, _) = parse_ma_quoted_literal(command, cursor);
    literal.map(|s| unescape_ma_string_literal(&s))
}

fn scene_path_entry_fingerprint(entry: &ScenePathEntry) -> u64 {
    let mut hasher = DefaultHasher::new();
    entry.node_type.hash(&mut hasher);
    entry.node_name.hash(&mut hasher);
    entry.attr.hash(&mut hasher);
    entry.value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    #[test]
    fn candidate_skip_stays_on_its_original_literal_range() {
        let input = br#"createNode file -n "Example";
setAttr ".ftn" -type "string" ("asset\d/" + "example/file.tx");
"#;
        let (encoding, commands) = super::path_source(input).unwrap();
        let candidate = super::path_candidates(input, &commands.commands, encoding).remove(0);
        let expected_range = candidate.ranges[0].clone();
        let unchanged_range = candidate.ranges[1].clone();
        let rules = [super::PathMatchRule {
            pattern: regex::Regex::new("asset").unwrap(),
            replacement: "Sample".into(),
            literal: true,
        }];
        let mut skipped = super::PathReplaceSkips::default();
        let mut edits = Vec::new();
        let applied = super::apply_path_candidate(
            input,
            encoding,
            candidate,
            &rules,
            None,
            &mut skipped,
            &mut edits,
        );
        assert!(edits.is_empty());
        assert_eq!(skipped.non_canonical_escape, 1);
        assert_eq!(applied.skipped_ranges.len(), 1);
        assert_eq!(applied.skipped_ranges[0].range, expected_range);
        assert_eq!(applied.skipped_ranges[0].skipped.non_canonical_escape, 1);
        assert!(
            !applied
                .skipped_ranges
                .iter()
                .any(|skip| skip.range == unchanged_range)
        );
    }

    use super::{
        MaRangeEdit, MaRangeEditError, MaRangeEditKind, apply_ma_range_edits,
        command_has_terminating_semicolon, ma_file_command_callback_present,
        normalize_ma_range_edits, remove_top_level_commands_from_ma, replace_raw_scene_paths_in_ma,
        replace_raw_scene_paths_in_ma_by_index,
    };
    use crate::{PathReplaceMode, PathReplaceRule};

    #[test]
    fn last_literals_stop_at_unterminated_quote() {
        let command = "file -r -ns \"Example\" \"asset/example/unfinished";
        let start = command.find('"').unwrap();
        assert_eq!(
            super::last_quoted_literal_range(command),
            Some((start, start + "\"Example\"".len()))
        );
        assert_eq!(super::last_quoted_literal(command), None);

        let command = "file -r \"asset/example/unfinished";
        assert_eq!(super::last_quoted_literal_range(command), None);
        assert_eq!(super::last_quoted_literal(command), None);
    }

    #[test]
    fn replace_scene_paths_preserves_unterminated_suffix() {
        let input = b"file -r -ns \"asset/example/Example.ma\" \"asset/example/unfinished\nrequires maya \"2024\";\n";
        for (from, expected_count) in [
            ("asset/example/absent.ma", 0),
            ("asset/example/Example.ma", 0),
        ] {
            let rules = vec![PathReplaceRule {
                from: from.to_string(),
                to: "asset/example/TestScene.ma".to_string(),
                mode: PathReplaceMode::Literal,
            }];
            let result = replace_raw_scene_paths_in_ma(input, &rules).unwrap();
            let (output, count) = (result.bytes, result.replacement_count);
            assert_eq!(count, expected_count);
            assert_eq!(output, input);
        }
    }

    #[test]
    fn replace_scene_paths_rewrites_file_command_and_multiline_setattr() {
        let input = br#"//Maya ASCII 2026 scene
file -rdi 1 -ns "Example" -rfn "ExampleRN" -op "VERS|2026|"
     -typ "mayaBinary" "rig/Example_v001.mb";
createNode file -n "file1";
    setAttr ".ftn" -type "string" (
        "rig/" +
        "Example_v001.mb"
    );
"#;
        let rules = vec![PathReplaceRule {
            from: "rig/".to_string(),
            to: "asset/".to_string(),
            mode: PathReplaceMode::Literal,
        }];
        let result = replace_raw_scene_paths_in_ma(input, &rules).unwrap();
        let (rewritten, count) = (result.bytes, result.replacement_count);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 2);
        assert!(text.contains("\"asset/Example_v001.mb\""));
        assert!(text.contains("\"asset/\" +"));
        assert!(text.contains("\"Example_v001.mb\""));
    }

    #[test]
    fn replace_scene_paths_rewrites_basename_file_command_path_only() {
        let input = br#"//Maya ASCII 2026 scene
file -r -ns "Example" -rfn "ExampleRN" -op "VERS|2026|" -typ "mayaAscii" "ExampleScene.ma";
"#;
        let rules = vec![PathReplaceRule {
            from: "ExampleScene.ma".to_string(),
            to: "SampleScene.ma".to_string(),
            mode: PathReplaceMode::Literal,
        }];
        let result = replace_raw_scene_paths_in_ma(input, &rules).unwrap();
        let (rewritten, count) = (result.bytes, result.replacement_count);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 1);
        assert!(text.contains("-ns \"Example\""));
        assert!(text.contains("-rfn \"ExampleRN\""));
        assert!(text.contains("-op \"VERS|2026|\""));
        assert!(text.contains("-typ \"mayaAscii\""));
        assert!(text.contains("\"SampleScene.ma\""));
    }

    #[test]
    fn replace_scene_paths_does_not_treat_file_command_flags_as_basename_paths() {
        let input = br#"//Maya ASCII 2026 scene
file -r -ns "Example.ma" -rfn "ExampleRN.ma" -op "VERS|2026|" -typ "mayaAscii" "asset/example/ExampleScene.ma";
"#;
        let rules = vec![PathReplaceRule {
            from: "Example".to_string(),
            to: "Sample".to_string(),
            mode: PathReplaceMode::Literal,
        }];
        let result = replace_raw_scene_paths_in_ma(input, &rules).unwrap();
        let (rewritten, count) = (result.bytes, result.replacement_count);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 1);
        assert!(text.contains("-ns \"Example.ma\""));
        assert!(text.contains("-rfn \"ExampleRN.ma\""));
        assert!(text.contains("\"asset/example/SampleScene.ma\""));
    }

    #[test]
    fn command_terminator_ignores_semicolon_inside_quotes() {
        let command = "file -r -op \"VERS;2026\" \n    -typ \"mayaBinary\" \"rig/Example.mb\"";
        assert!(!command_has_terminating_semicolon(command));
        let terminated = format!("{command};");
        assert!(command_has_terminating_semicolon(&terminated));
    }

    #[test]
    fn replace_scene_paths_keeps_multiline_file_command_with_quoted_semicolon_intact() {
        let input = br#"//Maya ASCII 2026 scene
file -rdi 1 -ns "Example" -rfn "ExampleRN"
     -op "VERS;2026"
     -typ "mayaBinary" "rig/Example_v001.mb";
"#;
        let rules = vec![PathReplaceRule {
            from: "rig/".to_string(),
            to: "asset/".to_string(),
            mode: PathReplaceMode::Literal,
        }];
        let result = replace_raw_scene_paths_in_ma(input, &rules).unwrap();
        let (rewritten, count) = (result.bytes, result.replacement_count);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 1);
        assert!(text.contains("-op \"VERS;2026\""));
        assert!(text.contains("\"asset/Example_v001.mb\""));
    }

    #[test]
    fn replace_scene_paths_by_index_changes_only_targeted_entry() {
        let input =
            br#"file -rdi 1 -ns "Example" -rfn "ExampleRN" -typ "mayaBinary" "shared/asset.mb";
createNode file -n "file1";
    setAttr ".ftn" -type "string" "shared/asset.mb";
"#;
        let result = replace_raw_scene_paths_in_ma_by_index(
            input,
            &[(1, "asset/example/Sample.png".into())],
        )
        .unwrap();
        let (rewritten, count) = (result.bytes, result.replacement_count);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 1);
        assert!(text.contains("\"shared/asset.mb\""));
        assert!(text.contains("setAttr \".ftn\" -type \"string\" \"asset/example/Sample.png\";"));
    }

    #[test]
    fn replace_scene_paths_by_index_rewrites_indexed_reference_attr() {
        let input = br#"createNode reference -n "ExampleRN";
    setAttr ".fn[0]" -type "string" "asset/example/ExampleScene.ma";
"#;
        let result = replace_raw_scene_paths_in_ma_by_index(
            input,
            &[(0, "asset/example/SampleScene.ma".into())],
        )
        .unwrap();
        let (rewritten, count) = (result.bytes, result.replacement_count);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 1);
        assert!(
            text.contains("setAttr \".fn[0]\" -type \"string\" \"asset/example/SampleScene.ma\";")
        );
    }

    #[test]
    fn replace_scene_paths_rewrites_file_texture_name_attrs_on_non_file_nodes() {
        let input = br#"createNode psdFileTex -n "psdTex1";
    setAttr ".fileTextureName" -type "string" "sourceimages/layered.psd";
createNode customPathNode -n "customTex1";
    setAttr ".fileTextureName" -type "string" "textures/custom.tx";
"#;
        let rules = vec![PathReplaceRule {
            from: "sourceimages/".to_string(),
            to: "archive/".to_string(),
            mode: PathReplaceMode::Literal,
        }];
        let result = replace_raw_scene_paths_in_ma(input, &rules).unwrap();
        let (rewritten, count) = (result.bytes, result.replacement_count);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 1);
        assert!(
            text.contains("setAttr \".fileTextureName\" -type \"string\" \"archive/layered.psd\";")
        );
        assert!(
            text.contains("setAttr \".fileTextureName\" -type \"string\" \"textures/custom.tx\";")
        );
    }

    #[test]
    fn remove_top_level_commands_drops_targeted_command_only() {
        let input = br#"requires maya "2026";
python("print(1)");
file -r "safe.ma";
"#;

        let start = input
            .windows("python(\"print(1)\");".len())
            .position(|window| window == b"python(\"print(1)\");")
            .expect("command start");
        let end = start + "python(\"print(1)\");\n".len();

        let (rewritten, removed) = remove_top_level_commands_from_ma(input, &[(start, end)]);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(removed, 1);
        assert!(!text.contains("python(\"print(1)\")"));
        assert!(text.contains("requires maya \"2026\";"));
        assert!(text.contains("file -r \"safe.ma\";"));
    }

    #[test]
    fn short_file_callback_is_present() {
        let input = br#"file -r -c "Example" "print(1)" "asset/example/file.ma";"#;
        assert!(ma_file_command_callback_present(input, 0, input.len()));
    }

    #[test]
    fn short_file_callback_range_edit_removes_flag_and_arguments() {
        let input = br#"file -r -c "Example" "print(1)" "asset/example/file.ma";"#;
        let (rewritten, count) = apply_ma_range_edits(
            input,
            &[MaRangeEdit {
                start: 0,
                end: input.len(),
                kind: MaRangeEditKind::StripFileCommandCallback,
            }],
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(rewritten, br#"file -r "asset/example/file.ma";"#);
    }

    #[test]
    fn short_file_callback_byte_rewrite_removes_flag_and_arguments() {
        let input = br#"file -r -c "Example" "print(1)" "asset/example/file.ma";"#;
        let ranges = super::collect_ma_command_ranges(input);
        let (rewritten, changed) = ranges.file_command_without_callback(input).unwrap();
        assert!(changed);
        assert_eq!(rewritten, br#"file -r "asset/example/file.ma";"#);
    }

    #[test]
    fn remove_file_command_callbacks_strips_flag_but_keeps_file_statement() {
        let input = br#"file -r -ns "ref" -command "onLoad" "python(\"import os\")" "C:/ref.ma";
"#;
        let end = input.len();
        assert!(ma_file_command_callback_present(input, 0, end));

        let (rewritten, removed) = apply_ma_range_edits(
            input,
            &[MaRangeEdit {
                start: 0,
                end,
                kind: MaRangeEditKind::StripFileCommandCallback,
            }],
        )
        .expect("rewrite");
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(removed, 1);
        assert!(!text.contains("-command"));
        assert!(text.contains("file -r -ns \"ref\" \"C:/ref.ma\";"));
    }
    #[test]
    fn range_edits_normalize_conflicts_and_containment() {
        use MaRangeEditKind::{RemoveCommand, StripFileCommandCallback};
        let remove = MaRangeEdit {
            start: 0,
            end: 20,
            kind: RemoveCommand,
        };
        let callback = MaRangeEdit {
            kind: StripFileCommandCallback,
            ..remove
        };
        assert_eq!(
            normalize_ma_range_edits(20, &[callback, remove]).unwrap(),
            vec![remove]
        );
        let inner_callback = MaRangeEdit {
            start: 5,
            end: 15,
            ..callback
        };
        assert_eq!(
            normalize_ma_range_edits(20, &[inner_callback, remove]).unwrap(),
            vec![remove]
        );
        let inner_remove = MaRangeEdit {
            start: 5,
            end: 15,
            ..remove
        };
        assert!(
            matches!(normalize_ma_range_edits(20, &[callback, inner_remove]), Err(MaRangeEditError::Overlap { first, second }) if first == callback && second == inner_remove)
        );
        let first = MaRangeEdit { end: 10, ..remove };
        assert!(
            matches!(normalize_ma_range_edits(20, &[inner_remove, first]), Err(MaRangeEditError::Overlap { first: a, second: b }) if a == first && b == inner_remove)
        );
    }

    #[test]
    fn range_edits_apply_touching_disjoint_and_duplicate_removals() {
        let input = b"ExampleExampleExampleExample";
        let first = MaRangeEdit {
            start: 0,
            end: 10,
            kind: MaRangeEditKind::RemoveCommand,
        };
        let touching = MaRangeEdit {
            start: 10,
            end: 20,
            ..first
        };
        assert_eq!(
            apply_ma_range_edits(input, &[first, touching]).unwrap(),
            (input[20..].to_vec(), 2)
        );
        let disjoint = MaRangeEdit {
            start: 15,
            end: 20,
            ..first
        };
        let expected = [input[10..15].to_vec(), input[20..].to_vec()].concat();
        assert_eq!(
            apply_ma_range_edits(input, &[first, disjoint]).unwrap(),
            (expected, 2)
        );
        assert_eq!(
            apply_ma_range_edits(input, &[first, first]).unwrap(),
            (input[10..].to_vec(), 1)
        );
        assert_eq!(
            normalize_ma_range_edits(input.len(), &[first, first]).unwrap(),
            vec![first]
        );
    }
}
