use crate::ma::error::MaParseError;

pub(crate) fn parse_f64_token(value: &str) -> Result<f64, MaParseError> {
    normalize_scalar_token(value)
        .parse::<f64>()
        .map_err(|_| MaParseError::AsciiSyntax(format!("invalid numeric token: {value}")))
}

fn normalize_scalar_token(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "on" | "true" => "1".to_string(),
        "no" | "off" | "false" => "0".to_string(),
        _ => value.trim().to_string(),
    }
}
