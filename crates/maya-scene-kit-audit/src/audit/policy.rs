use crate::scene::{AuditSeverity, ExecutionTrigger};

pub(crate) fn severity_for_trigger(
    severity: AuditSeverity,
    trigger: ExecutionTrigger,
) -> AuditSeverity {
    if !trigger.is_autorun() {
        return severity;
    }
    match severity {
        AuditSeverity::Info => AuditSeverity::Low,
        AuditSeverity::Low => AuditSeverity::Medium,
        AuditSeverity::Medium => AuditSeverity::High,
        AuditSeverity::High => AuditSeverity::Critical,
        AuditSeverity::Critical => AuditSeverity::Critical,
    }
}

pub(crate) fn snippet(text: &str) -> String {
    let mut value = text.trim().replace('\n', "\\n");
    if value.len() > 120 {
        value.truncate(120);
    }
    value
}

pub(crate) fn preview_window(text: &str, start: usize, end: usize, max_preview: usize) -> String {
    if text.is_empty() || max_preview == 0 {
        return String::new();
    }
    if text.is_ascii() {
        let width = max_preview.max(16);
        let half = width / 2;
        let start = start.min(text.len());
        let end = end.min(text.len());
        let left = start.saturating_sub(half);
        let right = std::cmp::min(text.len(), end.saturating_add(half));
        return sanitize_preview(&text[left..right]);
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
    sanitize_preview(&chars[left..right].iter().collect::<String>())
}

fn sanitize_preview(text: &str) -> String {
    text.replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
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
    use super::preview_window;

    #[test]
    fn preview_window_can_be_disabled() {
        assert_eq!(preview_window("python(\"x\")", 0, 6, 0), "");
    }

    #[test]
    fn preview_window_escapes_ascii_control_chars() {
        assert_eq!(preview_window("a\nb\tc", 0, 5, 24), "a\\nb\\tc");
    }
}
