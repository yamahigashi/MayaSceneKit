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
struct MelTextScanResult {
    sink_word_hits: MelSinkWordHits,
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

    fn result(&mut self) -> MelTextScanResult {
        *self.result.get_or_insert_with(|| scan_mel_text(self.text))
    }
}

#[cfg(test)]
pub(super) fn scan_mel_sink_word_hits(text: &str) -> MelSinkWordHits {
    scan_mel_text(text).sink_word_hits
}

pub(crate) fn scan_hard_python_obfuscation_markers(text: &str) -> Vec<String> {
    let mut markers = Vec::new();
    let patterns = [
        ("base64", "base64"),
        ("hex", "hex"),
        ("chr(", "chr("),
        (".decode(", ".decode("),
        ("__import__", "__import__"),
        ("builtins", "builtins"),
        ("__builtins__", "__builtins__"),
        ("globals(", "globals("),
        ("locals(", "locals("),
        ("vars(", "vars("),
    ];

    for (needle, label) in patterns {
        if contains_ascii_case_insensitive(text, needle) {
            markers.push(label.to_string());
        }
    }

    markers
}

fn scan_mel_text(text: &str) -> MelTextScanResult {
    let mut result = MelTextScanResult::default();
    let bytes = text.as_bytes();
    let mut idx = 0usize;

    while idx < bytes.len() {
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

        if result.sink_word_hits.is_complete() {
            break;
        }
    }

    result
}

fn is_ascii_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn contains_ascii_case_insensitive(text: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let haystack = text.as_bytes();
    let needle = needle.as_bytes();
    if needle.len() > haystack.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
