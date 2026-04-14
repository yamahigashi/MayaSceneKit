use crate::scene::AuditSeverity;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct MelSinkWordHits {
    bits: u8,
}

impl MelSinkWordHits {
    const PYTHON: u8 = 1 << 0;
    const EVAL_DEFERRED: u8 = 1 << 1;
    const EVAL: u8 = 1 << 2;
    const SCRIPT_JOB: u8 = 1 << 3;
    const COMMAND_PORT: u8 = 1 << 4;
    const ALL: u8 =
        Self::PYTHON | Self::EVAL_DEFERRED | Self::EVAL | Self::SCRIPT_JOB | Self::COMMAND_PORT;

    pub(super) fn insert(&mut self, sink_name: &str) {
        self.bits |= match sink_name {
            "python" => Self::PYTHON,
            "evalDeferred" => Self::EVAL_DEFERRED,
            "eval" => Self::EVAL,
            "scriptJob" => Self::SCRIPT_JOB,
            "commandPort" => Self::COMMAND_PORT,
            _ => 0,
        };
    }

    pub(super) fn contains(self, sink_name: &str) -> bool {
        let bit = match sink_name {
            "python" => Self::PYTHON,
            "evalDeferred" => Self::EVAL_DEFERRED,
            "eval" => Self::EVAL,
            "scriptJob" => Self::SCRIPT_JOB,
            "commandPort" => Self::COMMAND_PORT,
            _ => 0,
        };
        bit != 0 && self.bits & bit != 0
    }

    fn is_complete(self) -> bool {
        self.bits == Self::ALL
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ObfuscationMarkerHits {
    bits: u8,
}

impl ObfuscationMarkerHits {
    const BASE64: u8 = 1 << 0;
    const HEX: u8 = 1 << 1;
    const CHR: u8 = 1 << 2;
    const DECODE: u8 = 1 << 3;
    const JOIN: u8 = 1 << 4;
    const FORMAT: u8 = 1 << 5;
    const CONCAT: u8 = 1 << 6;
    const IMPORT: u8 = 1 << 7;
    const ALL: u8 = Self::BASE64
        | Self::HEX
        | Self::CHR
        | Self::DECODE
        | Self::JOIN
        | Self::FORMAT
        | Self::CONCAT
        | Self::IMPORT;
    const ORDERED_MARKERS: [(&'static str, u8); 8] = [
        ("base64", Self::BASE64),
        ("hex", Self::HEX),
        ("chr(", Self::CHR),
        (".decode(", Self::DECODE),
        ("join(", Self::JOIN),
        ("format(", Self::FORMAT),
        (" + ", Self::CONCAT),
        ("__import__", Self::IMPORT),
    ];

    fn insert(&mut self, bit: u8) {
        self.bits |= bit;
    }

    fn to_markers(self) -> Vec<String> {
        let mut markers = Vec::new();
        for (marker, bit) in Self::ORDERED_MARKERS {
            if self.bits & bit != 0 {
                markers.push(marker.to_string());
            }
        }
        markers
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MelTextScanResult {
    sink_word_hits: MelSinkWordHits,
    obfuscation_markers: ObfuscationMarkerHits,
}

#[derive(Debug)]
pub(super) struct MelTextScan<'a> {
    text: &'a str,
    result: Option<MelTextScanResult>,
}

impl<'a> MelTextScan<'a> {
    pub(super) fn new(text: &'a str) -> Self {
        Self { text, result: None }
    }

    pub(super) fn sink_word_hits(&mut self) -> MelSinkWordHits {
        self.result().sink_word_hits
    }

    pub(super) fn obfuscation_markers(&mut self) -> Vec<String> {
        self.result().obfuscation_markers.to_markers()
    }

    fn result(&mut self) -> MelTextScanResult {
        *self.result.get_or_insert_with(|| scan_mel_text(self.text))
    }
}

#[cfg(test)]
pub(super) fn scan_mel_sink_word_hits(text: &str) -> MelSinkWordHits {
    scan_mel_text(text).sink_word_hits
}

pub(super) fn scan_strong_obfuscation_markers(text: &str) -> Vec<String> {
    scan_mel_text(text)
        .obfuscation_markers
        .to_markers()
        .into_iter()
        .filter(|marker| !matches!(marker.as_str(), "format(" | " + "))
        .collect()
}

pub(super) fn obfuscation_marker_base_severity(markers: &[String]) -> AuditSeverity {
    let mut weak_count = 0usize;
    for marker in markers {
        match marker.as_str() {
            "format(" | " + " => weak_count += 1,
            _ => return AuditSeverity::Critical,
        }
    }

    if weak_count >= 2 {
        AuditSeverity::Critical
    } else {
        AuditSeverity::High
    }
}

fn scan_mel_text(text: &str) -> MelTextScanResult {
    let mut result = MelTextScanResult::default();
    let bytes = text.as_bytes();
    let mut idx = 0usize;

    while idx < bytes.len() {
        match bytes[idx].to_ascii_lowercase() {
            b'b' if has_ascii_prefix_at(bytes, idx, b"base64") => {
                result
                    .obfuscation_markers
                    .insert(ObfuscationMarkerHits::BASE64);
            }
            b'h' if has_ascii_prefix_at(bytes, idx, b"hex") => {
                result
                    .obfuscation_markers
                    .insert(ObfuscationMarkerHits::HEX);
            }
            b'c' if has_ascii_prefix_at(bytes, idx, b"chr(") => {
                result
                    .obfuscation_markers
                    .insert(ObfuscationMarkerHits::CHR);
            }
            b'.' if has_ascii_prefix_at(bytes, idx, b".decode(") => {
                result
                    .obfuscation_markers
                    .insert(ObfuscationMarkerHits::DECODE);
            }
            b'j' if has_ascii_prefix_at(bytes, idx, b"join(") => {
                result
                    .obfuscation_markers
                    .insert(ObfuscationMarkerHits::JOIN);
            }
            b'f' if has_ascii_prefix_at(bytes, idx, b"format(") => {
                result
                    .obfuscation_markers
                    .insert(ObfuscationMarkerHits::FORMAT);
            }
            b' ' if has_ascii_prefix_at(bytes, idx, b" + ") => {
                result
                    .obfuscation_markers
                    .insert(ObfuscationMarkerHits::CONCAT);
            }
            b'_' if has_ascii_prefix_at(bytes, idx, b"__import__") => {
                result
                    .obfuscation_markers
                    .insert(ObfuscationMarkerHits::IMPORT);
            }
            _ => {}
        }

        if !is_ascii_word_byte(bytes[idx]) {
            idx += 1;
            continue;
        }

        let start = idx;
        idx += 1;
        while idx < bytes.len() && is_ascii_word_byte(bytes[idx]) {
            idx += 1;
        }
        let word = &text[start..idx];
        if word.eq_ignore_ascii_case("python") {
            result.sink_word_hits.insert("python");
        } else if word.eq_ignore_ascii_case("evalDeferred") {
            result.sink_word_hits.insert("evalDeferred");
        } else if word.eq_ignore_ascii_case("eval") {
            result.sink_word_hits.insert("eval");
        } else if word.eq_ignore_ascii_case("scriptJob") {
            result.sink_word_hits.insert("scriptJob");
        } else if word.eq_ignore_ascii_case("commandPort") {
            result.sink_word_hits.insert("commandPort");
        }
        if result.sink_word_hits.is_complete()
            && result.obfuscation_markers.bits == ObfuscationMarkerHits::ALL
        {
            break;
        }
    }

    result
}

fn has_ascii_prefix_at(haystack: &[u8], start: usize, needle: &[u8]) -> bool {
    haystack
        .get(start..start + needle.len())
        .is_some_and(|slice| slice.eq_ignore_ascii_case(needle))
}

fn is_ascii_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

pub(super) fn extract_mel_literal_call_body(text: &str, fn_name: &str) -> Option<String> {
    let mut search_start = 0usize;
    while let Some(found_start) = find_ascii_word_case_insensitive(text, fn_name, search_start) {
        let mut idx = skip_ascii_ws(text, found_start + fn_name.len());
        if !text[idx..].starts_with('(') {
            search_start = idx.saturating_add(1);
            continue;
        }
        idx += 1;
        let (body, idx) = parse_mel_literal_concat_expr(text, idx)?;
        let idx = skip_ascii_ws(text, idx);
        if text[idx..].starts_with(')') {
            return Some(body);
        }
        search_start = idx.saturating_add(1);
    }
    None
}

#[cfg(test)]
pub(super) fn contains_ascii_word_case_insensitive(text: &str, needle: &str) -> bool {
    find_ascii_word_case_insensitive(text, needle, 0).is_some()
}

fn find_ascii_word_case_insensitive(text: &str, needle: &str, start: usize) -> Option<usize> {
    let mut search_start = start;
    while let Some(found) = find_ascii_case_insensitive(text, needle, search_start) {
        let end = found + needle.len();
        let left_ok = found == 0
            || !text[..found]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        let right_ok = end == text.len()
            || !text[end..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if left_ok && right_ok {
            return Some(found);
        }
        search_start = end;
    }
    None
}

fn find_ascii_case_insensitive(text: &str, needle: &str, start: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(start.min(text.len()));
    }

    let haystack = text.as_bytes();
    let needle = needle.as_bytes();
    if needle.len() > haystack.len() {
        return None;
    }

    let max_start = haystack.len() - needle.len();
    let mut index = start.min(max_start);
    while index <= max_start {
        if haystack[index..index + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn parse_mel_literal_concat_expr(text: &str, mut idx: usize) -> Option<(String, usize)> {
    let mut out = String::new();

    loop {
        idx = skip_ascii_ws(text, idx);
        let quote = text[idx..].chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let (segment, next_idx) = parse_mel_string_literal(text, idx, quote)?;
        out.push_str(&segment);
        idx = skip_ascii_ws(text, next_idx);
        if !text[idx..].starts_with('+') {
            break;
        }
        idx += 1;
    }

    Some((out, idx))
}

fn parse_mel_string_literal(text: &str, idx: usize, quote: char) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut escape = false;
    let mut iter = text[idx..].char_indices();
    let (_, first) = iter.next()?;
    if first != quote {
        return None;
    }

    for (rel, ch) in iter {
        if escape {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                '\'' => out.push('\''),
                '"' => out.push('"'),
                other => out.push(other),
            }
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch == quote {
            return Some((out, idx + rel + ch.len_utf8()));
        }
        out.push(ch);
    }

    None
}

fn skip_ascii_ws(text: &str, mut idx: usize) -> usize {
    while let Some(ch) = text[idx..].chars().next() {
        if !ch.is_ascii_whitespace() {
            break;
        }
        idx += ch.len_utf8();
    }
    idx
}
