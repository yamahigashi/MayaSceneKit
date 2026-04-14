use std::{collections::HashMap, fs, path::Path, sync::Arc};

use serde::Deserialize;

use super::SchemaRegistry;
#[cfg(test)]
use super::default_schema_registry;
use crate::scene::ir::AddAttrValueSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::scene) enum AddAttrSoftRangeLayout {
    None,
    LeadingDoublePairAfterU32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::scene) enum AddAttrEnumNamesLayout {
    None,
    CStringListUntilMarkerOrNulRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scene) struct AddAttrTokenRule {
    pub(in crate::scene) token: String,
    pub(in crate::scene) value_spec: AddAttrValueSpec,
    pub(in crate::scene) min_value: Option<String>,
    pub(in crate::scene) max_value: Option<String>,
    pub(in crate::scene) soft_range_layout: AddAttrSoftRangeLayout,
    pub(in crate::scene) enum_names_layout: AddAttrEnumNamesLayout,
}

impl AddAttrTokenRule {
    fn new(
        token: &str,
        value_spec: AddAttrValueSpec,
        min_value: Option<&str>,
        max_value: Option<&str>,
        soft_range_layout: AddAttrSoftRangeLayout,
        enum_names_layout: AddAttrEnumNamesLayout,
    ) -> Self {
        Self {
            token: token.to_string(),
            value_spec,
            min_value: min_value.map(str::to_string),
            max_value: max_value.map(str::to_string),
            soft_range_layout,
            enum_names_layout,
        }
    }

    pub(in crate::scene) fn number_of_children(&self, header_raw: &[u8; 11]) -> Option<u32> {
        if !matches!(
            self.token.as_str(),
            "aFL2" | "aDB2" | "aLI2" | "aSI2" | "aFL3" | "aDB3" | "aLI3" | "aSI3" | "aCPD"
        ) {
            return None;
        }
        let count = u32::from_be_bytes(header_raw[3..7].try_into().ok()?);
        if count == 0 { None } else { Some(count) }
    }

    pub(in crate::scene) fn name_prefix_words(&self, header_raw: &[u8; 11]) -> Option<u32> {
        if !matches!(
            self.token.as_str(),
            "aFL2" | "aDB2" | "aLI2" | "aSI2" | "aFL3" | "aDB3" | "aLI3" | "aSI3" | "aCPD"
        ) {
            return None;
        }
        let words = u32::from_be_bytes(header_raw[7..11].try_into().ok()?);
        if words == 0 { None } else { Some(words) }
    }

    pub(in crate::scene) fn leading_name_padding_words(
        &self,
        header_raw: &[u8; 11],
    ) -> Option<u32> {
        if self.token != "aTIM" {
            return None;
        }
        let words = u32::from_be_bytes(header_raw[3..7].try_into().ok()?);
        words.checked_sub(1).filter(|count| *count > 0)
    }

    pub(in crate::scene) fn typed_data_type(&self, header_raw: &[u8; 11]) -> Option<String> {
        if self.token != "aTYP" {
            return None;
        }
        let marker = std::str::from_utf8(&header_raw[7..11]).ok()?;
        let data_type = match marker {
            "STR " => "string",
            "MATR" => "matrix",
            _ => return None,
        };
        Some(data_type.to_string())
    }
}

#[derive(Debug, Deserialize)]
struct ExternalAddAttrTokenSchema {
    tokens: HashMap<String, ExternalAddAttrTokenRule>,
}

#[derive(Debug, Deserialize)]
struct ExternalAddAttrTokenRule {
    value_spec: ExternalValueSpec,
    min_value: Option<String>,
    max_value: Option<String>,
    soft_range_layout: Option<String>,
    enum_names_layout: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExternalValueSpec {
    kind: String,
    value: Option<String>,
}

#[cfg(test)]
pub(in crate::scene) fn lookup_add_attr_token_rule(token: &str) -> Option<AddAttrTokenRule> {
    lookup_add_attr_token_rule_with_registry(default_schema_registry(), token)
}

pub(in crate::scene) fn lookup_add_attr_token_rule_with_registry(
    registry: &SchemaRegistry,
    token: &str,
) -> Option<AddAttrTokenRule> {
    add_attr_token_rules(registry).get(token).cloned()
}

#[cfg(test)]
pub(in crate::scene) fn lookup_add_attr_token_for_value_spec_with_registry(
    registry: &SchemaRegistry,
    value_spec: &AddAttrValueSpec,
) -> Option<String> {
    add_attr_token_rules(registry)
        .values()
        .find(|rule| &rule.value_spec == value_spec)
        .map(|rule| rule.token.clone())
}

fn add_attr_token_rules(registry: &SchemaRegistry) -> Arc<HashMap<String, AddAttrTokenRule>> {
    if let Ok(cache) = registry.caches().addattr_tokens.lock() {
        if let Some(cached) = cache.as_ref() {
            return Arc::clone(cached);
        }
    }
    let loaded = Arc::new(load_add_attr_token_rules(registry));
    if let Ok(mut cache) = registry.caches().addattr_tokens.lock() {
        *cache = Some(Arc::clone(&loaded));
    }
    loaded
}

fn load_add_attr_token_rules(registry: &SchemaRegistry) -> HashMap<String, AddAttrTokenRule> {
    let mut rules = default_add_attr_token_rules();
    let path = registry.paths().addattr_schema_file.clone();
    let Ok(bytes) = fs::read(path) else {
        return rules;
    };
    let Some(external_rules) = parse_external_token_rules(&bytes) else {
        return rules;
    };
    rules.extend(external_rules);
    rules
}

pub(in crate::scene) fn validate_add_attr_token_schema_file(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_external_token_rules(&bytes)
        .map(|_| ())
        .ok_or_else(|| format!("{}: malformed addattr schema", path.display()))
}

fn parse_external_token_rules(yaml_bytes: &[u8]) -> Option<HashMap<String, AddAttrTokenRule>> {
    let schema: ExternalAddAttrTokenSchema = serde_yaml::from_slice(yaml_bytes).ok()?;
    let mut out = HashMap::new();
    for (token, raw_rule) in schema.tokens {
        let value_spec = match raw_rule.value_spec.kind.as_str() {
            "attr_type" => AddAttrValueSpec::AttrType(raw_rule.value_spec.value?),
            "data_type" => AddAttrValueSpec::DataType(raw_rule.value_spec.value?),
            _ => return None,
        };
        let soft_range_layout = match raw_rule.soft_range_layout.as_deref() {
            Some("leading_double_pair_after_u32") => {
                AddAttrSoftRangeLayout::LeadingDoublePairAfterU32
            }
            Some(_) => return None,
            None => AddAttrSoftRangeLayout::None,
        };
        let enum_names_layout = match raw_rule.enum_names_layout.as_deref() {
            Some("cstring_list_until_marker_or_nul_run") => {
                AddAttrEnumNamesLayout::CStringListUntilMarkerOrNulRun
            }
            Some(_) => return None,
            None => AddAttrEnumNamesLayout::None,
        };
        out.insert(
            token.clone(),
            AddAttrTokenRule {
                token,
                value_spec,
                min_value: raw_rule.min_value,
                max_value: raw_rule.max_value,
                soft_range_layout,
                enum_names_layout,
            },
        );
    }
    Some(out)
}

fn default_add_attr_token_rules() -> HashMap<String, AddAttrTokenRule> {
    let mut out = HashMap::new();
    out.insert(
        "aBOL".to_string(),
        AddAttrTokenRule::new(
            "aBOL",
            AddAttrValueSpec::AttrType("bool".to_string()),
            Some("0"),
            Some("1"),
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aDBL".to_string(),
        AddAttrTokenRule::new(
            "aDBL",
            AddAttrValueSpec::AttrType("double".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aFLT".to_string(),
        AddAttrTokenRule::new(
            "aFLT",
            AddAttrValueSpec::AttrType("float".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aFL2".to_string(),
        AddAttrTokenRule::new(
            "aFL2",
            AddAttrValueSpec::AttrType("float2".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aFL3".to_string(),
        AddAttrTokenRule::new(
            "aFL3",
            AddAttrValueSpec::AttrType("float3".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aLNG".to_string(),
        AddAttrTokenRule::new(
            "aLNG",
            AddAttrValueSpec::AttrType("long".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aDB2".to_string(),
        AddAttrTokenRule::new(
            "aDB2",
            AddAttrValueSpec::AttrType("double2".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aDB3".to_string(),
        AddAttrTokenRule::new(
            "aDB3",
            AddAttrValueSpec::AttrType("double3".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aLI2".to_string(),
        AddAttrTokenRule::new(
            "aLI2",
            AddAttrValueSpec::AttrType("long2".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aLI3".to_string(),
        AddAttrTokenRule::new(
            "aLI3",
            AddAttrValueSpec::AttrType("long3".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aSI2".to_string(),
        AddAttrTokenRule::new(
            "aSI2",
            AddAttrValueSpec::AttrType("short2".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aSI3".to_string(),
        AddAttrTokenRule::new(
            "aSI3",
            AddAttrValueSpec::AttrType("short3".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aCPD".to_string(),
        AddAttrTokenRule::new(
            "aCPD",
            AddAttrValueSpec::AttrType("compound".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aLNR".to_string(),
        AddAttrTokenRule::new(
            "aLNR",
            AddAttrValueSpec::AttrType("doubleLinear".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aAGL".to_string(),
        AddAttrTokenRule::new(
            "aAGL",
            AddAttrValueSpec::AttrType("doubleAngle".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aINT".to_string(),
        AddAttrTokenRule::new(
            "aINT",
            AddAttrValueSpec::AttrType("long".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aLI1".to_string(),
        AddAttrTokenRule::new(
            "aLI1",
            AddAttrValueSpec::AttrType("long".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aSI1".to_string(),
        AddAttrTokenRule::new(
            "aSI1",
            AddAttrValueSpec::AttrType("short".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::LeadingDoublePairAfterU32,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aSTR".to_string(),
        AddAttrTokenRule::new(
            "aSTR",
            AddAttrValueSpec::DataType("string".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aTYP".to_string(),
        AddAttrTokenRule::new(
            "aTYP",
            AddAttrValueSpec::DataType("string".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aMSG".to_string(),
        AddAttrTokenRule::new(
            "aMSG",
            AddAttrValueSpec::AttrType("message".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aTIM".to_string(),
        AddAttrTokenRule::new(
            "aTIM",
            AddAttrValueSpec::AttrType("time".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::None,
        ),
    );
    out.insert(
        "aENM".to_string(),
        AddAttrTokenRule::new(
            "aENM",
            AddAttrValueSpec::AttrType("enum".to_string()),
            None,
            None,
            AddAttrSoftRangeLayout::None,
            AddAttrEnumNamesLayout::CStringListUntilMarkerOrNulRun,
        ),
    );
    out
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        lookup_add_attr_token_for_value_spec_with_registry, lookup_add_attr_token_rule,
        lookup_add_attr_token_rule_with_registry,
    };
    use crate::scene::{
        ir::AddAttrValueSpec,
        schema::{SchemaRegistry, locator::SchemaPaths},
    };

    #[test]
    fn default_schema_path_points_to_add_attr_tokens_yaml() {
        let registry = SchemaRegistry::new(SchemaPaths::from_defaults());
        let path = &registry.paths().addattr_schema_file;
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("add_attr_tokens.yaml")
        );
        assert_eq!(
            path.parent()
                .and_then(|value| value.file_name())
                .and_then(|value| value.to_str()),
            Some("schemas")
        );
    }

    #[test]
    fn builtins_include_signed_integer_tokens() {
        let long_rule = lookup_add_attr_token_rule("aLI1").expect("aLI1 rule");
        assert_eq!(
            long_rule.value_spec,
            AddAttrValueSpec::AttrType("long".to_string())
        );

        let short_rule = lookup_add_attr_token_rule("aSI1").expect("aSI1 rule");
        assert_eq!(
            short_rule.value_spec,
            AddAttrValueSpec::AttrType("short".to_string())
        );
    }

    #[test]
    fn builtins_include_message_and_enum_tokens() {
        let message_rule = lookup_add_attr_token_rule("aMSG").expect("aMSG rule");
        assert_eq!(
            message_rule.value_spec,
            AddAttrValueSpec::AttrType("message".to_string())
        );

        let time_rule = lookup_add_attr_token_rule("aTIM").expect("aTIM rule");
        assert_eq!(
            time_rule.value_spec,
            AddAttrValueSpec::AttrType("time".to_string())
        );

        let enum_rule = lookup_add_attr_token_rule("aENM").expect("aENM rule");
        assert_eq!(
            enum_rule.value_spec,
            AddAttrValueSpec::AttrType("enum".to_string())
        );
    }

    #[test]
    fn builtins_include_compound_and_vector_tokens() {
        let float2_rule = lookup_add_attr_token_rule("aFL2").expect("aFL2 rule");
        assert_eq!(
            float2_rule.value_spec,
            AddAttrValueSpec::AttrType("float2".to_string())
        );

        let float3_rule = lookup_add_attr_token_rule("aFL3").expect("aFL3 rule");
        assert_eq!(
            float3_rule.value_spec,
            AddAttrValueSpec::AttrType("float3".to_string())
        );

        let double2_rule = lookup_add_attr_token_rule("aDB2").expect("aDB2 rule");
        assert_eq!(
            double2_rule.value_spec,
            AddAttrValueSpec::AttrType("double2".to_string())
        );

        let double3_rule = lookup_add_attr_token_rule("aDB3").expect("aDB3 rule");
        assert_eq!(
            double3_rule.value_spec,
            AddAttrValueSpec::AttrType("double3".to_string())
        );

        let long2_rule = lookup_add_attr_token_rule("aLI2").expect("aLI2 rule");
        assert_eq!(
            long2_rule.value_spec,
            AddAttrValueSpec::AttrType("long2".to_string())
        );

        let long3_rule = lookup_add_attr_token_rule("aLI3").expect("aLI3 rule");
        assert_eq!(
            long3_rule.value_spec,
            AddAttrValueSpec::AttrType("long3".to_string())
        );

        let short2_rule = lookup_add_attr_token_rule("aSI2").expect("aSI2 rule");
        assert_eq!(
            short2_rule.value_spec,
            AddAttrValueSpec::AttrType("short2".to_string())
        );

        let short3_rule = lookup_add_attr_token_rule("aSI3").expect("aSI3 rule");
        assert_eq!(
            short3_rule.value_spec,
            AddAttrValueSpec::AttrType("short3".to_string())
        );

        let compound_rule = lookup_add_attr_token_rule("aCPD").expect("aCPD rule");
        assert_eq!(
            compound_rule.value_spec,
            AddAttrValueSpec::AttrType("compound".to_string())
        );
    }

    #[test]
    fn registry_scopes_addattr_schema_cache_per_pack() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root_a = std::env::temp_dir().join(format!("schema_pack_a_{unique}"));
        let root_b = std::env::temp_dir().join(format!("schema_pack_b_{unique}"));
        fs::create_dir_all(&root_a).expect("root_a");
        fs::create_dir_all(&root_b).expect("root_b");
        fs::write(
            root_a.join("add_attr_tokens.yaml"),
            "tokens:\n  aZZZ:\n    value_spec: { kind: attr_type, value: long }\n",
        )
        .expect("write a");
        fs::write(
            root_b.join("add_attr_tokens.yaml"),
            "tokens:\n  aZZZ:\n    value_spec: { kind: attr_type, value: string }\n",
        )
        .expect("write b");

        let mut paths_a = SchemaPaths::from_defaults();
        paths_a.addattr_schema_file = root_a.join("add_attr_tokens.yaml");
        let mut paths_b = SchemaPaths::from_defaults();
        paths_b.addattr_schema_file = root_b.join("add_attr_tokens.yaml");
        let registry_a = SchemaRegistry::new(paths_a);
        let registry_b = SchemaRegistry::new(paths_b);

        assert_eq!(
            lookup_add_attr_token_rule_with_registry(&registry_a, "aZZZ")
                .expect("rule a")
                .value_spec,
            AddAttrValueSpec::AttrType("long".to_string())
        );
        assert_eq!(
            lookup_add_attr_token_rule_with_registry(&registry_b, "aZZZ")
                .expect("rule b")
                .value_spec,
            AddAttrValueSpec::AttrType("string".to_string())
        );

        let _ = fs::remove_dir_all(&root_a);
        let _ = fs::remove_dir_all(&root_b);
    }

    #[test]
    fn reverse_lookup_uses_effective_registry_rules() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("schema_pack_reverse_lookup_{unique}"));
        fs::create_dir_all(&root).expect("root");
        fs::write(
            root.join("add_attr_tokens.yaml"),
            concat!(
                "tokens:\n",
                "  aBOL:\n",
                "    value_spec: { kind: attr_type, value: long }\n",
                "  aZZZ:\n",
                "    value_spec: { kind: attr_type, value: bool }\n",
            ),
        )
        .expect("write schema");

        let mut paths = SchemaPaths::from_defaults();
        paths.addattr_schema_file = root.join("add_attr_tokens.yaml");
        let registry = SchemaRegistry::new(paths);

        let token = lookup_add_attr_token_for_value_spec_with_registry(
            &registry,
            &AddAttrValueSpec::AttrType("bool".to_string()),
        )
        .expect("bool token");
        assert_eq!(token, "aZZZ");

        let _ = fs::remove_dir_all(&root);
    }
}
