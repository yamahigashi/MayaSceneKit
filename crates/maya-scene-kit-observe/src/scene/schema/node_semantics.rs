use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Deserialize;

use super::SchemaRegistry;
#[cfg(test)]
use super::default_schema_registry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AngularAttrKind {
    Scalar,
    Vector3,
}

#[allow(dead_code)]
#[cfg(test)]
pub(in crate::scene) fn node_angular_attr_rules_for_node_type(
    node_type: &str,
) -> Option<HashMap<String, AngularAttrKind>> {
    node_angular_attr_rules_for_node_type_with_registry(default_schema_registry(), node_type)
}

pub(in crate::scene) fn node_angular_attr_rules_for_node_type_with_registry(
    registry: &SchemaRegistry,
    node_type: &str,
) -> Option<HashMap<String, AngularAttrKind>> {
    let node_type = normalize_lookup_token(node_type)?;
    node_angular_attr_rules(registry).get(&node_type).cloned()
}

fn node_angular_attr_rules(
    registry: &SchemaRegistry,
) -> Arc<HashMap<String, HashMap<String, AngularAttrKind>>> {
    if let Ok(cache) = registry.caches().node_semantics.lock() {
        if let Some(cached) = cache.as_ref() {
            return Arc::clone(cached);
        }
    }
    let loaded = Arc::new(load_node_angular_attr_rules(registry));
    if let Ok(mut cache) = registry.caches().node_semantics.lock() {
        *cache = Some(Arc::clone(&loaded));
    }
    loaded
}

#[derive(Debug, Deserialize)]
struct ExternalNodeInfoSchema {
    version: Option<u32>,
    nodes: HashMap<String, ExternalNodeInfoNode>,
}

#[derive(Debug, Deserialize)]
struct ExternalNodeInfoNode {
    typeid: Option<serde_yaml::Value>,
    #[serde(default)]
    attrs: HashMap<String, ExternalNodeInfoAttr>,
}

#[derive(Debug, Deserialize)]
struct ExternalNodeInfoAttr {
    unit: Option<String>,
    kind: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct ParsedNodeInfo {
    typeid_to_typename: HashMap<u32, String>,
    angular_attrs: HashMap<String, HashMap<String, AngularAttrKind>>,
}

#[derive(Debug, Clone, Default)]
struct NormalizedNodeInfoEntry {
    display_name: String,
    typeid: Option<u32>,
    angular_attrs: HashMap<String, AngularAttrKind>,
}

fn load_node_angular_attr_rules(
    registry: &SchemaRegistry,
) -> HashMap<String, HashMap<String, AngularAttrKind>> {
    load_parsed_node_info_from_registry(registry)
        .map(|parsed| parsed.angular_attrs)
        .unwrap_or_default()
}

pub(in crate::scene) fn validate_node_info_schema_file(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_external_node_info(&bytes)
        .map(|_| ())
        .map_err(|err| format!("{}: {err}", path.display()))
}

pub(in crate::scene) fn load_typeid_typename_map_with_registry(
    registry: &SchemaRegistry,
) -> Result<HashMap<u32, String>, String> {
    load_parsed_node_info_from_registry(registry).map(|parsed| parsed.typeid_to_typename)
}

fn load_parsed_node_info_from_registry(
    registry: &SchemaRegistry,
) -> Result<ParsedNodeInfo, String> {
    load_parsed_node_info_from_paths(
        &registry.paths().node_info_schema_file,
        &registry.paths().additional_node_info_files,
    )
}

fn load_parsed_node_info_from_paths(
    base_path: &Path,
    additional_paths: &[PathBuf],
) -> Result<ParsedNodeInfo, String> {
    let mut unique_paths = vec![base_path.to_path_buf()];
    for path in additional_paths {
        if unique_paths.iter().any(|existing| existing == path) {
            continue;
        }
        unique_paths.push(path.clone());
    }

    let mut merged_nodes = HashMap::new();
    for path in unique_paths {
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let parsed =
            parse_external_node_info(&bytes).map_err(|err| format!("{}: {err}", path.display()))?;
        for (node_type, entry) in parsed {
            merged_nodes.insert(node_type, entry);
        }
    }

    let mut typeid_to_typename = HashMap::new();
    let mut angular_attrs = HashMap::new();
    for (node_type, entry) in merged_nodes {
        if let Some(typeid) = entry.typeid {
            typeid_to_typename.insert(typeid, entry.display_name.clone());
        }
        if !entry.angular_attrs.is_empty() {
            angular_attrs.insert(node_type, entry.angular_attrs);
        }
    }

    Ok(ParsedNodeInfo {
        typeid_to_typename,
        angular_attrs,
    })
}

fn parse_external_node_info(
    yaml_bytes: &[u8],
) -> Result<HashMap<String, NormalizedNodeInfoEntry>, String> {
    let schema: ExternalNodeInfoSchema =
        serde_yaml::from_slice(yaml_bytes).map_err(|e| format!("yaml parse error: {e}"))?;
    if !matches!(schema.version, Some(1)) {
        return Err("unsupported node info schema version".to_string());
    }

    let mut out = HashMap::new();
    for (raw_node_type, raw_node) in schema.nodes {
        let display_name = raw_node_type.trim();
        let Some(node_type) = normalize_lookup_token(display_name) else {
            continue;
        };

        let mut attrs = HashMap::new();
        for (raw_attr_name, raw_attr) in raw_node.attrs {
            let Some(kind) =
                parse_angular_attr_kind(raw_attr.unit.as_deref(), raw_attr.kind.as_deref())
            else {
                continue;
            };

            if let Some(token) = normalize_lookup_token(&raw_attr_name) {
                attrs.insert(token, kind);
            }
            for alias in raw_attr.aliases {
                if let Some(token) = normalize_lookup_token(&alias) {
                    attrs.insert(token, kind);
                }
            }
        }

        out.insert(
            node_type,
            NormalizedNodeInfoEntry {
                display_name: display_name.to_string(),
                typeid: parse_node_typeid(raw_node.typeid.as_ref())?,
                angular_attrs: attrs,
            },
        );
    }

    Ok(out)
}

#[cfg(test)]
fn parse_external_node_info_angular_rules(
    yaml_bytes: &[u8],
) -> Option<HashMap<String, HashMap<String, AngularAttrKind>>> {
    parse_external_node_info(yaml_bytes).ok().map(|entries| {
        entries
            .into_iter()
            .filter_map(|(node_type, entry)| {
                (!entry.angular_attrs.is_empty()).then_some((node_type, entry.angular_attrs))
            })
            .collect()
    })
}

fn parse_angular_attr_kind(unit: Option<&str>, kind: Option<&str>) -> Option<AngularAttrKind> {
    let unit = unit?.trim();
    if !unit.eq_ignore_ascii_case("angle") {
        return None;
    }
    let kind = kind?.trim();
    if kind.eq_ignore_ascii_case("scalar") {
        return Some(AngularAttrKind::Scalar);
    }
    if kind.eq_ignore_ascii_case("vector3") {
        return Some(AngularAttrKind::Vector3);
    }
    None
}

fn normalize_lookup_token(raw: &str) -> Option<String> {
    let token = raw.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_ascii_lowercase())
    }
}

fn parse_node_typeid(raw: Option<&serde_yaml::Value>) -> Result<Option<u32>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match raw {
        serde_yaml::Value::Number(n) => n
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| "node typeid is out of range".to_string()),
        serde_yaml::Value::String(token) => parse_typeid_string(token)
            .map(Some)
            .ok_or_else(|| format!("invalid node typeid '{token}'")),
        other => Err(format!("invalid node typeid value '{other:?}'")),
    }
}

fn parse_typeid_string(raw: &str) -> Option<u32> {
    let token = raw.trim();
    if token.is_empty() {
        return None;
    }
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).ok();
    }
    if token.chars().all(|c| c.is_ascii_digit()) {
        return token.parse::<u32>().ok();
    }
    u32::from_str_radix(token, 16).ok()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        AngularAttrKind, load_parsed_node_info_from_paths, parse_external_node_info,
        parse_external_node_info_angular_rules,
    };
    use crate::scene::schema::{SchemaRegistry, locator::SchemaPaths};

    #[test]
    fn default_schema_path_points_to_node_info_yaml() {
        let registry = SchemaRegistry::new(SchemaPaths::from_defaults());
        let path = &registry.paths().node_info_schema_file;
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("node_info.yaml")
        );
        assert_eq!(
            path.parent()
                .and_then(|value| value.file_name())
                .and_then(|value| value.to_str()),
            Some("schemas")
        );
    }

    #[test]
    fn parse_external_node_info_filters_non_angle_and_collects_aliases() {
        let yaml = r#"
version: 1
nodes:
  parentConstraint:
    typeid: 0x44504152
    attrs:
      tor:  { unit: angle, kind: vector3, aliases: [targetOffsetRotate] }
      torx: { unit: angle, kind: scalar, aliases: [targetOffsetRotateX] }
      tx:   { unit: linear, kind: scalar, aliases: [translateX] }
"#;

        let parsed = parse_external_node_info_angular_rules(yaml.as_bytes()).expect("parsed");
        let node = parsed
            .get("parentconstraint")
            .expect("parentConstraint rule set");
        assert_eq!(node.get("tor"), Some(&AngularAttrKind::Vector3));
        assert_eq!(
            node.get("targetoffsetrotate"),
            Some(&AngularAttrKind::Vector3)
        );
        assert_eq!(node.get("torx"), Some(&AngularAttrKind::Scalar));
        assert_eq!(
            node.get("targetoffsetrotatex"),
            Some(&AngularAttrKind::Scalar)
        );
        assert!(!node.contains_key("tx"));
        assert!(!node.contains_key("translatex"));
    }

    #[test]
    fn parse_external_node_info_requires_version_1() {
        let yaml = r#"
version: 2
nodes: {}
"#;
        assert!(parse_external_node_info_angular_rules(yaml.as_bytes()).is_none());
        assert!(parse_external_node_info(yaml.as_bytes()).is_err());
    }

    #[test]
    fn parse_external_node_info_accepts_yaml_hex_typeid() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("node_info_{unique}.yaml"));
        let yaml = r#"
version: 1
nodes:
  transform:
    typeid: 0x5846524D
    attrs:
      rx: { unit: angle, kind: scalar, aliases: [rotateX] }
"#;
        std::fs::write(&path, yaml).expect("write");
        let bytes = std::fs::read(&path).expect("read");
        let parsed = parse_external_node_info_angular_rules(&bytes).expect("parsed");
        let node = parsed.get("transform").expect("transform rule set");
        assert_eq!(node.get("rx"), Some(&AngularAttrKind::Scalar));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_parsed_node_info_collects_typeids() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("node_info_typeids_{unique}.yaml"));
        let yaml = r#"
version: 1
nodes:
  transform:
    typeid: 0x5846524D
    attrs: {}
  customNode:
    typeid: "1234"
    attrs: {}
"#;
        std::fs::write(&path, yaml).expect("write");
        let parsed = load_parsed_node_info_from_paths(&path, &[]).expect("parsed");
        assert_eq!(
            parsed
                .typeid_to_typename
                .get(&0x5846_524D)
                .map(String::as_str),
            Some("transform")
        );
        assert_eq!(
            parsed.typeid_to_typename.get(&1234).map(String::as_str),
            Some("customNode")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_parsed_node_info_overlay_replaces_whole_node_entry() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let base_path = std::env::temp_dir().join(format!("node_info_base_{unique}.yaml"));
        let overlay_path = std::env::temp_dir().join(format!("node_info_overlay_{unique}.yaml"));
        std::fs::write(
            &base_path,
            r#"
version: 1
nodes:
  transform:
    typeid: 0x5846524D
    attrs:
      rx: { unit: angle, kind: scalar, aliases: [rotateX] }
"#,
        )
        .expect("write base");
        std::fs::write(
            &overlay_path,
            r#"
version: 1
nodes:
  transform:
    typeid: 0x11111111
    attrs: {}
"#,
        )
        .expect("write overlay");
        let parsed =
            load_parsed_node_info_from_paths(&base_path, std::slice::from_ref(&overlay_path))
                .expect("parsed");
        assert_eq!(
            parsed
                .typeid_to_typename
                .get(&0x1111_1111)
                .map(String::as_str),
            Some("transform")
        );
        assert!(!parsed.angular_attrs.contains_key("transform"));
        let _ = std::fs::remove_file(&base_path);
        let _ = std::fs::remove_file(&overlay_path);
    }
}
