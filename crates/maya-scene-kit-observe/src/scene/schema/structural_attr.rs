use std::{fs, path::Path, sync::Arc};

use serde::Deserialize;

use super::SchemaRegistry;
#[cfg(test)]
use super::default_schema_registry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scene) struct StructuralAttrHandlerRule {
    handler: String,
    kind_equals: Option<u8>,
    min_value_len: Option<usize>,
    max_value_len: Option<usize>,
    value_len_mod: Option<usize>,
    attr_name_equals: Option<String>,
    attr_name_prefix: Option<String>,
    attr_name_suffix: Option<String>,
    value_prefix: Option<Vec<u8>>,
    u32be_checks: Vec<StructuralU32BeCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scene) struct StructuralU32BeCheck {
    offset: usize,
    equals: Option<u32>,
    min: Option<u32>,
    max: Option<u32>,
}

impl StructuralAttrHandlerRule {
    pub(in crate::scene) fn handler(&self) -> &str {
        &self.handler
    }

    pub(in crate::scene) fn evaluate(
        &self,
        attr_name: &str,
        kind: u8,
        value_raw: &[u8],
    ) -> Result<(), String> {
        if let Some(expected) = self.kind_equals {
            if kind != expected {
                return Err(format!(
                    "kind mismatch expected=0x{expected:02X} actual=0x{kind:02X}"
                ));
            }
        }

        let value_len = value_raw.len();
        if let Some(min_len) = self.min_value_len {
            if value_len < min_len {
                return Err(format!(
                    "value length too short min={min_len} actual={value_len}"
                ));
            }
        }
        if let Some(max_len) = self.max_value_len {
            if value_len > max_len {
                return Err(format!(
                    "value length too long max={max_len} actual={value_len}"
                ));
            }
        }
        if let Some(modulo) = self.value_len_mod {
            if modulo == 0 || value_len % modulo != 0 {
                return Err(format!(
                    "value length modulo mismatch mod={modulo} actual={value_len}"
                ));
            }
        }
        if let Some(expected) = &self.attr_name_equals {
            if attr_name != expected {
                return Err(format!(
                    "attr_name mismatch expected='{expected}' actual='{attr_name}'"
                ));
            }
        }
        if let Some(prefix) = &self.attr_name_prefix {
            if !attr_name.starts_with(prefix) {
                return Err(format!(
                    "attr_name prefix mismatch prefix='{prefix}' actual='{attr_name}'"
                ));
            }
        }
        if let Some(suffix) = &self.attr_name_suffix {
            if !attr_name.ends_with(suffix) {
                return Err(format!(
                    "attr_name suffix mismatch suffix='{suffix}' actual='{attr_name}'"
                ));
            }
        }
        if let Some(prefix) = &self.value_prefix {
            if value_raw.len() < prefix.len() || &value_raw[..prefix.len()] != prefix {
                return Err("value prefix mismatch".to_string());
            }
        }
        for check in &self.u32be_checks {
            check.evaluate(value_raw)?;
        }
        Ok(())
    }
}

impl StructuralU32BeCheck {
    fn evaluate(&self, value_raw: &[u8]) -> Result<(), String> {
        if self.offset.checked_add(4).is_none() || self.offset + 4 > value_raw.len() {
            return Err(format!(
                "u32be check out of range offset={} value_len={}",
                self.offset,
                value_raw.len()
            ));
        }
        let value = u32::from_be_bytes(
            value_raw[self.offset..self.offset + 4]
                .try_into()
                .map_err(|_| "u32be read failed".to_string())?,
        );
        if let Some(expected) = self.equals {
            if value != expected {
                return Err(format!(
                    "u32be mismatch offset={} expected={} actual={}",
                    self.offset, expected, value
                ));
            }
        }
        if let Some(min) = self.min {
            if value < min {
                return Err(format!(
                    "u32be below min offset={} min={} actual={}",
                    self.offset, min, value
                ));
            }
        }
        if let Some(max) = self.max {
            if value > max {
                return Err(format!(
                    "u32be above max offset={} max={} actual={}",
                    self.offset, max, value
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ExternalStructuralAttrHandlerSchema {
    handlers: Vec<ExternalStructuralAttrHandlerRule>,
}

#[derive(Debug, Deserialize)]
struct ExternalStructuralAttrHandlerRule {
    handler: String,
    kind_equals: Option<u8>,
    min_value_len: Option<usize>,
    max_value_len: Option<usize>,
    value_len_mod: Option<usize>,
    attr_name_equals: Option<String>,
    attr_name_prefix: Option<String>,
    attr_name_suffix: Option<String>,
    value_prefix_hex: Option<String>,
    u32be_checks: Option<Vec<ExternalStructuralU32BeCheck>>,
}

#[derive(Debug, Deserialize)]
struct ExternalStructuralU32BeCheck {
    offset: usize,
    equals: Option<u32>,
    min: Option<u32>,
    max: Option<u32>,
}

#[cfg(test)]
pub(in crate::scene) fn structural_attr_handler_rules() -> Arc<Vec<StructuralAttrHandlerRule>> {
    structural_attr_handler_rules_with_registry(default_schema_registry())
}

pub(in crate::scene) fn structural_attr_handler_rules_with_registry(
    registry: &SchemaRegistry,
) -> Arc<Vec<StructuralAttrHandlerRule>> {
    if let Ok(cache) = registry.caches().structural_attrs.lock() {
        if let Some(cached) = cache.as_ref() {
            return Arc::clone(cached);
        }
    }
    let loaded = Arc::new(load_structural_attr_handler_rules(registry));
    if let Ok(mut cache) = registry.caches().structural_attrs.lock() {
        *cache = Some(Arc::clone(&loaded));
    }
    loaded
}

fn load_structural_attr_handler_rules(registry: &SchemaRegistry) -> Vec<StructuralAttrHandlerRule> {
    let path = registry.paths().structural_attr_schema_file.clone();
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    parse_external_structural_attr_handler_rules(&bytes).unwrap_or_default()
}

pub(in crate::scene) fn validate_structural_attr_schema_file(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_external_structural_attr_handler_rules(&bytes)
        .map(|_| ())
        .ok_or_else(|| format!("{}: malformed structural attr schema", path.display()))
}

fn parse_external_structural_attr_handler_rules(
    yaml_bytes: &[u8],
) -> Option<Vec<StructuralAttrHandlerRule>> {
    let schema: ExternalStructuralAttrHandlerSchema = serde_yaml::from_slice(yaml_bytes).ok()?;
    let mut out = Vec::new();
    for raw in schema.handlers {
        let handler = raw.handler.trim();
        if handler.is_empty() {
            continue;
        }
        let value_prefix = match raw.value_prefix_hex.as_deref() {
            Some(hex) => Some(parse_hex_bytes(hex)?),
            None => None,
        };
        let mut u32be_checks = Vec::new();
        for check in raw.u32be_checks.unwrap_or_default() {
            u32be_checks.push(StructuralU32BeCheck {
                offset: check.offset,
                equals: check.equals,
                min: check.min,
                max: check.max,
            });
        }
        out.push(StructuralAttrHandlerRule {
            handler: handler.to_string(),
            kind_equals: raw.kind_equals,
            min_value_len: raw.min_value_len,
            max_value_len: raw.max_value_len,
            value_len_mod: raw.value_len_mod,
            attr_name_equals: raw.attr_name_equals,
            attr_name_prefix: raw.attr_name_prefix,
            attr_name_suffix: raw.attr_name_suffix,
            value_prefix,
            u32be_checks,
        });
    }
    Some(out)
}

fn parse_hex_bytes(raw: &str) -> Option<Vec<u8>> {
    let cleaned = raw
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '_')
        .collect::<String>();
    if cleaned.is_empty() {
        return Some(Vec::new());
    }
    if cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let hi = bytes[idx] as char;
        let lo = bytes[idx + 1] as char;
        let pair = [hi, lo].iter().collect::<String>();
        let value = u8::from_str_radix(&pair, 16).ok()?;
        out.push(value);
        idx += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{parse_external_structural_attr_handler_rules, structural_attr_handler_rules};
    use crate::scene::schema::{SchemaRegistry, locator::SchemaPaths};

    #[test]
    fn default_schema_path_points_to_structural_attr_handlers_yaml() {
        let registry = SchemaRegistry::new(SchemaPaths::from_defaults());
        let path = &registry.paths().structural_attr_schema_file;
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("structural_attr_handlers.yaml")
        );
        assert_eq!(
            path.parent()
                .and_then(|value| value.file_name())
                .and_then(|value| value.to_str()),
            Some("schemas")
        );
    }

    #[test]
    fn yaml_rules_parse_and_filter_by_kind_and_min_len() {
        let yaml = r#"
handlers:
  - handler: attr.nurbs_curve
    kind_equals: 32
    min_value_len: 25
    max_value_len: 4096
    value_len_mod: 1
    attr_name_suffix: cc
    value_prefix_hex: "00 00 00 01"
    u32be_checks:
      - offset: 8
        max: 2
  - handler: attr.other
    kind_equals: 0
"#;
        let rules = parse_external_structural_attr_handler_rules(yaml.as_bytes()).expect("rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].handler(), "attr.nurbs_curve");
        let mut good = vec![0u8; 64];
        good[0..4].copy_from_slice(&1u32.to_be_bytes());
        good[8..12].copy_from_slice(&2u32.to_be_bytes());
        assert!(rules[0].evaluate("cc", 0x20, &good).is_ok());
        assert!(rules[0].evaluate("bad", 0x20, &good).is_err());
        assert!(rules[0].evaluate("cc", 0x20, &good[..4]).is_err());
        assert!(rules[0].evaluate("cc", 0x21, &good).is_err());
        assert_eq!(rules[1].handler(), "attr.other");
        assert!(rules[1].evaluate("foo", 0x00, &[]).is_ok());
        assert!(rules[1].evaluate("foo", 0x20, &[]).is_err());

        // Registry is loaded from on-disk schema; just verify surface is callable.
        let _ = structural_attr_handler_rules();
    }

    #[test]
    fn invalid_hex_prefix_rejects_rule_set() {
        let yaml = r#"
handlers:
  - handler: attr.nurbs_curve
    value_prefix_hex: "001"
"#;
        assert!(parse_external_structural_attr_handler_rules(yaml.as_bytes()).is_none());
    }
}
