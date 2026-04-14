#[cfg(test)]
use crate::ma::commands::{Token, token_text};
use crate::ma::error::MaParseError;

pub(crate) fn parse_f64_token(value: &str) -> Result<f64, MaParseError> {
    normalize_scalar_token(value)
        .parse::<f64>()
        .map_err(|_| MaParseError::AsciiSyntax(format!("invalid numeric token: {value}")))
}

#[cfg(test)]
pub(crate) fn parse_bool_token(token: Option<&Token>, flag: &str) -> Result<bool, MaParseError> {
    let raw = token
        .and_then(token_text)
        .ok_or_else(|| MaParseError::Message(format!("{flag} is missing a boolean value")))?;
    match raw {
        "on" | "yes" | "true" | "1" => Ok(true),
        "off" | "no" | "false" | "0" => Ok(false),
        _ => Err(MaParseError::Message(format!(
            "{flag} expects boolean value, got {raw}"
        ))),
    }
}

#[cfg(test)]
pub(crate) fn parse_usize_token(token: Option<&Token>, label: &str) -> Result<usize, MaParseError> {
    let raw = token
        .and_then(token_text)
        .ok_or_else(|| MaParseError::Message(format!("{label} is missing a numeric value")))?;
    raw.parse::<usize>()
        .map_err(|_| MaParseError::Message(format!("{label} expects usize, got {raw}")))
}

#[cfg(test)]
pub(crate) fn parse_u32_token(token: Option<&Token>, label: &str) -> Result<u32, MaParseError> {
    let raw = token
        .and_then(token_text)
        .ok_or_else(|| MaParseError::Message(format!("{label} is missing a numeric value")))?;
    raw.parse::<u32>()
        .map_err(|_| MaParseError::Message(format!("{label} expects u32, got {raw}")))
}

fn normalize_scalar_token(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "on" | "true" => "1".to_string(),
        "no" | "off" | "false" => "0".to_string(),
        _ => value.trim().to_string(),
    }
}
