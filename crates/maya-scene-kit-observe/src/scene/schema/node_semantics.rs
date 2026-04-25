use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Deserialize;

use super::SchemaRegistry;
#[cfg(test)]
use super::default_schema_registry;
use crate::scene::{ExecutionLanguage, ExecutionTrigger};
use maya_scene_kit_formats::ma::raw_dump::RawMaNodeAttrSelector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AngularAttrKind {
    Scalar,
    Vector3,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NodeExecutionSemantics {
    profiles_by_node: HashMap<String, Vec<NodeExecutionProfile>>,
    profile_node_by_typeid: HashMap<u32, String>,
    ma_capture_attr_selectors: HashSet<RawMaNodeAttrSelector>,
}

impl NodeExecutionSemantics {
    pub(crate) fn profiles_for_node(&self, node_type: &str) -> &[NodeExecutionProfile] {
        let Some(node_type) = normalize_lookup_token(node_type) else {
            return &[];
        };
        self.profiles_by_node
            .get(&node_type)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn ma_capture_attr_selectors(&self) -> &HashSet<RawMaNodeAttrSelector> {
        &self.ma_capture_attr_selectors
    }

    pub(crate) fn node_type_for_typeid(&self, typeid: u32) -> Option<&str> {
        self.profile_node_by_typeid.get(&typeid).map(String::as_str)
    }

    pub(crate) fn source_label(&self, node_type: &str, attr_name: &str) -> Option<&str> {
        let node_type = normalize_lookup_token(node_type)?;
        let attr_name = normalize_attr_ref(attr_name)?;
        self.profiles_by_node
            .get(&node_type)?
            .iter()
            .find_map(|profile| profile.source_label(&attr_name))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeExecutionProfile {
    pub(crate) kind: NodeExecutionProfileKind,
}

impl NodeExecutionProfile {
    fn source_label(&self, attr_name: &str) -> Option<&str> {
        match &self.kind {
            NodeExecutionProfileKind::ScriptNode(_) => None,
            NodeExecutionProfileKind::AttrCallbacks(profile) => profile
                .attrs
                .iter()
                .find(|attr| attr.short_name == attr_name)
                .map(|attr| attr.display_name.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NodeExecutionProfileKind {
    ScriptNode(ScriptNodeExecutionProfile),
    AttrCallbacks(AttrCallbacksExecutionProfile),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScriptNodeExecutionProfile {
    pub(crate) body_attrs: Vec<String>,
    pub(crate) trigger_attr: Option<String>,
    pub(crate) trigger_decoder: Option<ExecutionDecoder>,
    pub(crate) language_attr: Option<String>,
    pub(crate) language_decoder: Option<ExecutionDecoder>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttrCallbacksExecutionProfile {
    pub(crate) attrs: Vec<NodeExecutionCallbackAttr>,
    pub(crate) default_language: ExecutionLanguage,
    pub(crate) default_trigger: ExecutionTrigger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeExecutionCallbackAttr {
    pub(crate) short_name: String,
    pub(crate) display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionDecoder {
    MayaScriptNodeScriptType,
    MayaScriptNodeSourceType,
}

pub(crate) fn node_execution_semantics_with_registry(
    registry: &SchemaRegistry,
) -> Result<Arc<NodeExecutionSemantics>, String> {
    if let Ok(cache) = registry.caches().node_execution_semantics.lock() {
        if let Some(cached) = cache.as_ref() {
            return Ok(Arc::clone(cached));
        }
    }
    let loaded = Arc::new(
        parsed_node_info_with_registry(registry)?
            .execution_semantics
            .clone(),
    );
    if let Ok(mut cache) = registry.caches().node_execution_semantics.lock() {
        *cache = Some(Arc::clone(&loaded));
    }
    Ok(loaded)
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
    execution: Option<ExternalNodeExecution>,
}

#[derive(Debug, Deserialize)]
struct ExternalNodeInfoAttr {
    unit: Option<String>,
    kind: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ExternalNodeExecution {
    #[serde(default)]
    profiles: Vec<ExternalNodeExecutionProfile>,
}

#[derive(Debug, Deserialize)]
struct ExternalNodeExecutionProfile {
    kind: String,
    #[serde(default)]
    body_attrs: Vec<String>,
    trigger_attr: Option<String>,
    trigger_decoder: Option<String>,
    language_attr: Option<String>,
    language_decoder: Option<String>,
    #[serde(default)]
    attrs: Vec<String>,
    default_language: Option<String>,
    default_trigger: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(in crate::scene) struct ParsedNodeInfo {
    typeid_to_typename: HashMap<u32, String>,
    angular_attrs: HashMap<String, HashMap<String, AngularAttrKind>>,
    execution_semantics: NodeExecutionSemantics,
}

#[derive(Debug, Clone, Default)]
struct NormalizedNodeInfoEntry {
    display_name: String,
    typeid: Option<u32>,
    angular_attrs: HashMap<String, AngularAttrKind>,
    execution_profiles: Vec<NodeExecutionProfile>,
}

fn load_node_angular_attr_rules(
    registry: &SchemaRegistry,
) -> HashMap<String, HashMap<String, AngularAttrKind>> {
    parsed_node_info_with_registry(registry)
        .map(|parsed| parsed.angular_attrs.clone())
        .unwrap_or_default()
}

pub(in crate::scene) fn validate_node_info_with_registry(
    registry: &SchemaRegistry,
) -> Result<(), String> {
    parsed_node_info_with_registry(registry).map(|_| ())
}

pub(in crate::scene) fn load_typeid_typename_map_with_registry(
    registry: &SchemaRegistry,
) -> Result<HashMap<u32, String>, String> {
    parsed_node_info_with_registry(registry).map(|parsed| parsed.typeid_to_typename.clone())
}

fn parsed_node_info_with_registry(
    registry: &SchemaRegistry,
) -> Result<Arc<ParsedNodeInfo>, String> {
    if let Ok(cache) = registry.caches().parsed_node_info.lock() {
        if let Some(cached) = cache.as_ref() {
            return cached.clone();
        }
    }

    let loaded = load_parsed_node_info_from_paths(
        &registry.paths().node_info_schema_file,
        &registry.paths().additional_node_info_files,
    )
    .map(Arc::new);
    if let Ok(mut cache) = registry.caches().parsed_node_info.lock() {
        *cache = Some(loaded.clone());
    }
    loaded
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
    let mut profiles_by_node = HashMap::new();
    let mut profile_node_by_typeid = HashMap::new();
    let mut ma_capture_attr_selectors = HashSet::new();
    for (node_type, entry) in merged_nodes {
        if let Some(typeid) = entry.typeid {
            typeid_to_typename.insert(typeid, entry.display_name.clone());
        }
        if !entry.angular_attrs.is_empty() {
            angular_attrs.insert(node_type.clone(), entry.angular_attrs);
        }
        if !entry.execution_profiles.is_empty() {
            if let Some(typeid) = entry.typeid {
                profile_node_by_typeid.insert(typeid, node_type.clone());
            }
            for profile in &entry.execution_profiles {
                match &profile.kind {
                    NodeExecutionProfileKind::ScriptNode(profile) => {
                        ma_capture_attr_selectors.extend(
                            profile
                                .body_attrs
                                .iter()
                                .map(|attr| ma_node_attr_selector(&node_type, None, attr)),
                        );
                        if let Some(attr) = &profile.trigger_attr {
                            ma_capture_attr_selectors
                                .insert(ma_node_attr_selector(&node_type, None, attr));
                        }
                        if let Some(attr) = &profile.language_attr {
                            ma_capture_attr_selectors
                                .insert(ma_node_attr_selector(&node_type, None, attr));
                        }
                    }
                    NodeExecutionProfileKind::AttrCallbacks(profile) => {
                        for attr in &profile.attrs {
                            ma_capture_attr_selectors.insert(ma_node_attr_selector(
                                &node_type,
                                None,
                                &attr.short_name,
                            ));
                            if node_type.eq_ignore_ascii_case("renderGlobals") {
                                ma_capture_attr_selectors.insert(ma_node_attr_selector(
                                    "",
                                    Some("defaultRenderGlobals"),
                                    &attr.short_name,
                                ));
                            }
                        }
                    }
                }
            }
            profiles_by_node.insert(node_type, entry.execution_profiles);
        }
    }

    Ok(ParsedNodeInfo {
        typeid_to_typename,
        angular_attrs,
        execution_semantics: NodeExecutionSemantics {
            profiles_by_node,
            profile_node_by_typeid,
            ma_capture_attr_selectors,
        },
    })
}

fn ma_node_attr_selector(
    node_type: &str,
    node_name: Option<&str>,
    attr: &str,
) -> RawMaNodeAttrSelector {
    RawMaNodeAttrSelector {
        node_type: node_type.to_string(),
        node_name: node_name.map(str::to_string),
        attr: format!(".{attr}"),
    }
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

        let attr_aliases = build_attr_aliases(&raw_node.attrs);
        let mut attrs = HashMap::new();
        for (raw_attr_name, raw_attr) in &raw_node.attrs {
            let Some(kind) =
                parse_angular_attr_kind(raw_attr.unit.as_deref(), raw_attr.kind.as_deref())
            else {
                continue;
            };

            if let Some(token) = normalize_lookup_token(raw_attr_name) {
                attrs.insert(token, kind);
            }
            for alias in &raw_attr.aliases {
                if let Some(token) = normalize_lookup_token(alias) {
                    attrs.insert(token, kind);
                }
            }
        }
        let execution_profiles = parse_node_execution_profiles(
            display_name,
            raw_node.execution.as_ref(),
            &attr_aliases,
        )?;

        out.insert(
            node_type,
            NormalizedNodeInfoEntry {
                display_name: display_name.to_string(),
                typeid: parse_node_typeid(raw_node.typeid.as_ref())?,
                angular_attrs: attrs,
                execution_profiles,
            },
        );
    }

    Ok(out)
}

fn build_attr_aliases(
    attrs: &HashMap<String, ExternalNodeInfoAttr>,
) -> HashMap<String, (String, String)> {
    let mut aliases = HashMap::new();
    for (raw_short, attr) in attrs {
        let Some(short) = normalize_lookup_token(raw_short) else {
            continue;
        };
        let display_name = attr
            .aliases
            .first()
            .cloned()
            .unwrap_or_else(|| raw_short.trim().to_string());
        aliases.insert(short.clone(), (short.clone(), display_name.clone()));
        for alias in &attr.aliases {
            if let Some(token) = normalize_lookup_token(alias) {
                aliases.insert(token, (short.clone(), display_name.clone()));
            }
        }
    }
    aliases
}

fn parse_node_execution_profiles(
    node_type: &str,
    execution: Option<&ExternalNodeExecution>,
    attr_aliases: &HashMap<String, (String, String)>,
) -> Result<Vec<NodeExecutionProfile>, String> {
    let Some(execution) = execution else {
        return Ok(Vec::new());
    };
    let mut profiles = Vec::new();
    for raw_profile in &execution.profiles {
        let kind = normalize_lookup_token(&raw_profile.kind)
            .ok_or_else(|| format!("{node_type}: execution profile kind is required"))?;
        let kind = match kind.as_str() {
            "script_node" => NodeExecutionProfileKind::ScriptNode(ScriptNodeExecutionProfile {
                body_attrs: normalize_profile_attr_list(
                    node_type,
                    "body_attrs",
                    &raw_profile.body_attrs,
                    attr_aliases,
                )?,
                trigger_attr: normalize_optional_profile_attr(
                    node_type,
                    "trigger_attr",
                    raw_profile.trigger_attr.as_deref(),
                    attr_aliases,
                )?,
                trigger_decoder: parse_execution_decoder(raw_profile.trigger_decoder.as_deref())?,
                language_attr: normalize_optional_profile_attr(
                    node_type,
                    "language_attr",
                    raw_profile.language_attr.as_deref(),
                    attr_aliases,
                )?,
                language_decoder: parse_execution_decoder(raw_profile.language_decoder.as_deref())?,
            }),
            "attr_callbacks" => {
                let attrs =
                    normalize_profile_callback_attrs(node_type, &raw_profile.attrs, attr_aliases)?;
                NodeExecutionProfileKind::AttrCallbacks(AttrCallbacksExecutionProfile {
                    attrs,
                    default_language: parse_execution_language(
                        raw_profile.default_language.as_deref(),
                    )?,
                    default_trigger: parse_execution_trigger(
                        raw_profile.default_trigger.as_deref(),
                    )?,
                })
            }
            _ => {
                return Err(format!(
                    "{node_type}: unknown execution profile kind '{kind}'"
                ));
            }
        };
        profiles.push(NodeExecutionProfile { kind });
    }
    Ok(profiles)
}

fn normalize_profile_attr_list(
    node_type: &str,
    field: &str,
    attrs: &[String],
    attr_aliases: &HashMap<String, (String, String)>,
) -> Result<Vec<String>, String> {
    attrs
        .iter()
        .map(|attr| normalize_profile_attr(node_type, field, attr, attr_aliases))
        .collect()
}

fn normalize_profile_callback_attrs(
    node_type: &str,
    attrs: &[String],
    attr_aliases: &HashMap<String, (String, String)>,
) -> Result<Vec<NodeExecutionCallbackAttr>, String> {
    attrs
        .iter()
        .map(|attr| {
            let key = normalize_lookup_token(attr)
                .ok_or_else(|| format!("{node_type}: empty attr in execution profile"))?;
            let (short_name, display_name) = attr_aliases
                .get(&key)
                .ok_or_else(|| {
                    format!("{node_type}: execution profile references unknown attr '{attr}'")
                })?
                .clone();
            Ok(NodeExecutionCallbackAttr {
                short_name,
                display_name,
            })
        })
        .collect()
}

fn normalize_optional_profile_attr(
    node_type: &str,
    field: &str,
    attr: Option<&str>,
    attr_aliases: &HashMap<String, (String, String)>,
) -> Result<Option<String>, String> {
    attr.map(|attr| normalize_profile_attr(node_type, field, attr, attr_aliases))
        .transpose()
}

fn normalize_profile_attr(
    node_type: &str,
    field: &str,
    attr: &str,
    attr_aliases: &HashMap<String, (String, String)>,
) -> Result<String, String> {
    let key = normalize_lookup_token(attr)
        .ok_or_else(|| format!("{node_type}: empty {field} attr in execution profile"))?;
    attr_aliases
        .get(&key)
        .map(|(short, _)| short.clone())
        .ok_or_else(|| format!("{node_type}: execution profile references unknown attr '{attr}'"))
}

fn parse_execution_decoder(raw: Option<&str>) -> Result<Option<ExecutionDecoder>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let token = normalize_lookup_token(raw).ok_or_else(|| "empty execution decoder".to_string())?;
    match token.as_str() {
        "maya_script_node_script_type" => Ok(Some(ExecutionDecoder::MayaScriptNodeScriptType)),
        "maya_script_node_source_type" => Ok(Some(ExecutionDecoder::MayaScriptNodeSourceType)),
        _ => Err(format!("unknown execution decoder '{raw}'")),
    }
}

fn parse_execution_language(raw: Option<&str>) -> Result<ExecutionLanguage, String> {
    match normalize_lookup_token(raw.unwrap_or("unknown")).as_deref() {
        Some("mel") => Ok(ExecutionLanguage::Mel),
        Some("python") => Ok(ExecutionLanguage::Python),
        Some("unknown") => Ok(ExecutionLanguage::Unknown),
        _ => Err(format!(
            "unknown execution default_language '{}'",
            raw.unwrap_or_default()
        )),
    }
}

fn parse_execution_trigger(raw: Option<&str>) -> Result<ExecutionTrigger, String> {
    match normalize_lookup_token(raw.unwrap_or("unknown")).as_deref() {
        Some("unknown") => Ok(ExecutionTrigger::Unknown),
        Some("manual") => Ok(ExecutionTrigger::Manual),
        Some("file_open") => Ok(ExecutionTrigger::FileOpen),
        Some("file_close") => Ok(ExecutionTrigger::FileClose),
        Some("gui_open_close") => Ok(ExecutionTrigger::GuiOpenClose),
        Some("render") => Ok(ExecutionTrigger::Render),
        Some("time_changed") => Ok(ExecutionTrigger::TimeChanged),
        Some("event_hook") => Ok(ExecutionTrigger::EventHook),
        _ => Err(format!(
            "unknown execution default_trigger '{}'",
            raw.unwrap_or_default()
        )),
    }
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

fn normalize_attr_ref(raw: &str) -> Option<String> {
    normalize_lookup_token(raw.trim_start_matches('.'))
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
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        AngularAttrKind, NodeExecutionProfileKind, load_parsed_node_info_from_paths,
        load_typeid_typename_map_with_registry, node_execution_semantics_with_registry,
        parse_external_node_info, parse_external_node_info_angular_rules,
    };
    use crate::scene::{
        ExecutionLanguage, ExecutionTrigger,
        schema::{SchemaRegistry, locator::SchemaPaths},
    };

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
    fn parse_external_node_info_normalizes_execution_profile_attrs() {
        let yaml = r#"
version: 1
nodes:
  script:
    typeid: 0x53435250
    execution:
      profiles:
        - kind: script_node
          body_attrs: [after, b]
          trigger_attr: scriptType
          trigger_decoder: maya_script_node_script_type
          language_attr: sourceType
          language_decoder: maya_script_node_source_type
    attrs:
      a: { unit: none, kind: scalar, aliases: [after] }
      b: { unit: none, kind: scalar, aliases: [before] }
      st: { unit: none, kind: scalar, aliases: [scriptType] }
      stp: { unit: none, kind: scalar, aliases: [sourceType] }
"#;
        let entries = parse_external_node_info(yaml.as_bytes()).expect("parsed");
        let script = entries.get("script").expect("script entry");
        let [profile] = script.execution_profiles.as_slice() else {
            panic!("expected one execution profile");
        };
        let NodeExecutionProfileKind::ScriptNode(profile) = &profile.kind else {
            panic!("expected script_node profile");
        };
        assert_eq!(profile.body_attrs, vec!["a", "b"]);
        assert_eq!(profile.trigger_attr.as_deref(), Some("st"));
        assert_eq!(profile.language_attr.as_deref(), Some("stp"));
    }

    #[test]
    fn parse_external_node_info_rejects_unknown_execution_profile_attr() {
        let yaml = r#"
version: 1
nodes:
  script:
    execution:
      profiles:
        - kind: script_node
          body_attrs: [missing]
    attrs:
      b: { unit: none, kind: scalar, aliases: [before] }
"#;
        let err = parse_external_node_info(yaml.as_bytes()).expect_err("invalid profile");
        assert!(err.contains("unknown attr 'missing'"));
    }

    #[test]
    fn load_parsed_node_info_builds_execution_semantics_and_alias_labels() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("node_info_execution_{unique}.yaml"));
        std::fs::write(
            &path,
            r#"
version: 1
nodes:
  renderGlobals:
    typeid: 0x52474C42
    execution:
      profiles:
        - kind: attr_callbacks
          default_language: mel
          default_trigger: render
          attrs: [preMel]
    attrs:
      pram: { unit: none, kind: scalar, aliases: [preMel] }
"#,
        )
        .expect("write");
        let parsed = load_parsed_node_info_from_paths(&path, &[]).expect("parsed");
        let semantics = parsed.execution_semantics;
        assert_eq!(
            semantics.node_type_for_typeid(0x5247_4C42),
            Some("renderglobals")
        );
        assert!(
            semantics
                .ma_capture_attr_selectors()
                .iter()
                .any(|selector| {
                    selector.node_type.eq_ignore_ascii_case("renderGlobals")
                        && selector.node_name.is_none()
                        && selector.attr == ".pram"
                })
        );
        assert_eq!(
            semantics.source_label("renderGlobals", "pram"),
            Some("preMel")
        );
        let [profile] = semantics.profiles_for_node("renderGlobals") else {
            panic!("expected renderGlobals profile");
        };
        let NodeExecutionProfileKind::AttrCallbacks(profile) = &profile.kind else {
            panic!("expected attr_callbacks profile");
        };
        assert_eq!(profile.default_language, ExecutionLanguage::Mel);
        assert_eq!(profile.default_trigger, ExecutionTrigger::Render);
        assert_eq!(profile.attrs[0].short_name, "pram");
        assert_eq!(profile.attrs[0].display_name, "preMel");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn registry_reuses_parsed_node_info_for_derived_semantics() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("node_info_shared_cache_{unique}.yaml"));
        std::fs::write(
            &path,
            r#"
version: 1
nodes:
  ExampleNode:
    typeid: 0x12345678
    execution:
      profiles:
        - kind: attr_callbacks
          default_language: mel
          default_trigger: render
          attrs: [callback]
    attrs:
      cb: { unit: none, kind: scalar, aliases: [callback] }
"#,
        )
        .expect("write");
        let mut paths = SchemaPaths::from_defaults();
        paths.node_info_schema_file = path.clone();
        let registry = SchemaRegistry::new(paths);

        let typeid_map = load_typeid_typename_map_with_registry(&registry).expect("typeid map");
        assert_eq!(
            typeid_map.get(&0x1234_5678).map(String::as_str),
            Some("ExampleNode")
        );
        let cached_before = {
            let cache = registry.caches().parsed_node_info.lock().expect("cache");
            let parsed = cache
                .as_ref()
                .expect("parsed cache populated")
                .as_ref()
                .expect("parsed cache ok");
            Arc::as_ptr(parsed)
        };

        let semantics =
            node_execution_semantics_with_registry(&registry).expect("execution semantics");
        assert_eq!(
            semantics.node_type_for_typeid(0x1234_5678),
            Some("examplenode")
        );
        let cached_after = {
            let cache = registry.caches().parsed_node_info.lock().expect("cache");
            let parsed = cache
                .as_ref()
                .expect("parsed cache still populated")
                .as_ref()
                .expect("parsed cache still ok");
            Arc::as_ptr(parsed)
        };
        assert_eq!(cached_before, cached_after);
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
