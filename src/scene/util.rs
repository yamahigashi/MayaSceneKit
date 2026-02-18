pub(super) fn align(value: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return value;
    }
    let rem = value % alignment;
    if rem == 0 {
        value
    } else {
        value + (alignment - rem)
    }
}

pub(super) fn escape_ma_string(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\\n")
}

pub(super) fn format_number(value: f64) -> String {
    if !value.is_finite() {
        return "0".to_string();
    }
    let nearest = value.round();
    if (value - nearest).abs() < 1e-12 {
        return format!("{}", nearest as i64);
    }
    let mut s = format!("{value:.15}");
    while s.contains('.') && s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

pub(super) fn split_lines_keepends(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, b) in data.iter().enumerate() {
        if *b == b'\n' {
            out.push(data[start..=i].to_vec());
            start = i + 1;
        }
    }
    if start < data.len() {
        out.push(data[start..].to_vec());
    }
    out
}

pub(super) fn trim_ascii(input: &[u8]) -> &[u8] {
    trim_ascii_end(trim_ascii_start(input))
}

pub(super) fn trim_ascii_start(input: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < input.len() && input[i].is_ascii_whitespace() {
        i += 1;
    }
    &input[i..]
}

pub(super) fn trim_ascii_end(input: &[u8]) -> &[u8] {
    let mut i = input.len();
    while i > 0 && input[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    &input[..i]
}

pub(super) fn trim_end_newline(input: &[u8]) -> &[u8] {
    let mut i = input.len();
    while i > 0 && (input[i - 1] == b'\n' || input[i - 1] == b'\r') {
        i -= 1;
    }
    &input[..i]
}

pub(super) fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
