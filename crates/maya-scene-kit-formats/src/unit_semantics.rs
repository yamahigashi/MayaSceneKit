pub const DEFAULT_LINEAR_UNIT: &str = "centimeter";
pub const DEFAULT_ANGULAR_UNIT: &str = "degree";
pub const DEFAULT_TIME_UNIT: &str = "film";
pub const DEFAULT_TICKS_PER_SECOND: &str = "141120000";

pub fn normalize_linear_unit(value: &str) -> String {
    let raw = value.trim();
    if raw.is_empty() {
        return DEFAULT_LINEAR_UNIT.to_string();
    }
    match raw.to_lowercase().as_str() {
        "cm" => "centimeter",
        "mm" => "millimeter",
        "m" => "meter",
        "km" => "kilometer",
        "in" => "inch",
        "ft" => "foot",
        "yd" => "yard",
        _ => raw,
    }
    .to_string()
}

pub fn normalize_angular_unit(value: &str) -> String {
    let raw = value.trim();
    if raw.is_empty() {
        return DEFAULT_ANGULAR_UNIT.to_string();
    }
    match raw.to_lowercase().as_str() {
        "deg" => "degree",
        "rad" => "radian",
        _ => raw,
    }
    .to_string()
}

pub fn normalize_time_unit(value: &str) -> String {
    let raw = value.trim();
    if raw.is_empty() {
        return DEFAULT_TIME_UNIT.to_string();
    }
    let lowered = raw.to_lowercase();
    if [
        "game", "film", "pal", "ntsc", "show", "palf", "ntscf", "sec", "min", "hour", "millisec",
    ]
    .contains(&lowered.as_str())
    {
        lowered
    } else {
        raw.to_string()
    }
}

pub fn encode_linear_unit(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "centimeter" | "cm" => "cm".to_string(),
        "millimeter" | "mm" => "mm".to_string(),
        "meter" | "m" => "m".to_string(),
        "kilometer" | "km" => "km".to_string(),
        "inch" | "in" => "in".to_string(),
        "foot" | "ft" => "ft".to_string(),
        "yard" | "yd" => "yd".to_string(),
        other => other.to_string(),
    }
}

pub fn encode_angular_unit(value: &str) -> String {
    match value.trim().to_lowercase().as_str() {
        "degree" | "deg" => "deg".to_string(),
        "radian" | "rad" => "rad".to_string(),
        other => other.to_string(),
    }
}

pub fn encode_time_unit(value: &str) -> String {
    normalize_time_unit(value)
}
