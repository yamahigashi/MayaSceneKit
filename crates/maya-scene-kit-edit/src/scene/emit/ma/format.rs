use std::{
    collections::HashMap,
    fmt::{Display, Write as _},
};

use maya_scene_kit_observe::scene::model::NumericValue;
use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug)]
pub(crate) struct EmissionIssue {
    pub node_type: String,
    pub target: String,
    pub position: String,
    pub reason: String,
}

#[derive(Default)]
pub(crate) struct EmitContext {
    pub issues: Vec<EmissionIssue>,
    node_type: String,
    target: String,
    issue_indices: HashMap<(String, String, String, String), usize>,
}

impl EmitContext {
    pub fn set_target(&mut self, node_type: &str, target: &str) {
        self.node_type = node_type.to_string();
        self.target = target.to_string();
    }

    pub fn record(&mut self, position: impl Display, value: &str, reason: &str) {
        let position = position.to_string();
        let key = (
            self.node_type.clone(),
            self.target.clone(),
            position.clone(),
            value.to_string(),
        );
        if let Some(&index) = self.issue_indices.get(&key) {
            let existing = &mut self.issues[index].reason;
            if !existing.split("; ").any(|part| part == reason) {
                existing.push_str("; ");
                existing.push_str(reason);
            }
            return;
        }
        self.issue_indices.insert(key, self.issues.len());
        self.issues.push(EmissionIssue {
            node_type: self.node_type.clone(),
            target: self.target.clone(),
            position,
            reason: reason.to_string(),
        });
    }
}

pub(crate) fn escape_ma_comment(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}' => {
                write!(escaped, "\\x{:02X}", ch as u32).expect("write to String");
            }
            '\u{2028}' | '\u{2029}' => {
                write!(escaped, "\\u{:04X}", ch as u32).expect("write to String");
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub(crate) fn escape_ma_string(
    text: &str,
    context: &mut EmitContext,
    position: impl Display,
) -> String {
    fn unsupported(ch: char) -> bool {
        matches!(ch, '\0' | '\u{001a}' | '\u{0085}' | '\u{2028}' | '\u{2029}')
    }
    if text.chars().any(unsupported) {
        context.record(
            position,
            text,
            "replaced unsupported string characters with U+FFFD",
        );
        let replacement: String = text
            .chars()
            .map(|ch| if unsupported(ch) { '\u{fffd}' } else { ch })
            .collect();
        maya_scene_kit_formats::ma::text::escape_ma_string(&replacement)
    } else {
        maya_scene_kit_formats::ma::text::escape_ma_string(text)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BareWordPosition {
    NodeType,
    SelectTarget,
    Unit,
    RequiresValue,
}

pub(crate) fn render_ma_bare_word(
    text: &str,
    kind: BareWordPosition,
    context: &mut EmitContext,
    position: &str,
) -> Option<String> {
    static CONTROL_OR_FORMAT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[\p{Cc}\p{Cf}]").expect("Unicode character classes"));
    let invalid = text.is_empty()
        || text.starts_with(['-', '$'])
        || CONTROL_OR_FORMAT.is_match(text)
        || text.chars().any(|ch| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    ';' | '"'
                        | '\''
                        | '\u{0060}'
                        | '('
                        | ')'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | ','
                        | '\\'
                        | '/'
                        | '*'
                        | '#'
                )
                || (matches!(kind, BareWordPosition::NodeType)
                    && matches!(ch, ':' | '|' | '.' | '[' | ']'))
        });
    if !invalid {
        return Some(text.to_string());
    }
    match kind {
        BareWordPosition::NodeType
        | BareWordPosition::SelectTarget
        | BareWordPosition::RequiresValue => {
            context.record(position, text, "quoted invalid bare word");
            Some(format!("\"{}\"", escape_ma_string(text, context, position)))
        }
        BareWordPosition::Unit => {
            context.record(
                position,
                text,
                "omitted currentUnit flag and value for invalid bare word",
            );
            None
        }
    }
}

pub(crate) fn format_number(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }
    value.to_string()
}

pub(crate) fn format_numeric_value(value: NumericValue) -> String {
    match value {
        NumericValue::Float64Bits(bits) => format_number(f64::from_bits(bits)),
        NumericValue::U32(value) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use maya_scene_kit_observe::scene::model::NumericValue;

    use super::{format_number, format_numeric_value};

    #[test]
    fn format_number_preserves_non_finite_values_as_tokens() {
        assert_eq!(format_number(f64::NAN), "nan");
        assert_eq!(format_number(f64::INFINITY), "inf");
        assert_eq!(format_number(f64::NEG_INFINITY), "-inf");
    }

    #[test]
    fn format_number_uses_round_trip_safe_rendering() {
        assert_eq!(format_number(28.0), "28");
        assert_eq!(
            format_number(std::f64::consts::FRAC_PI_2),
            "1.5707963267948966"
        );
    }

    #[test]
    fn format_numeric_value_renders_integral_variants() {
        assert_eq!(format_numeric_value(NumericValue::from_u32(7)), "7");
        assert_eq!(format_numeric_value(NumericValue::from_f64(2.5)), "2.5");
    }
}
