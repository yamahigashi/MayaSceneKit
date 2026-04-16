use std::borrow::Cow;

use crate::scene::ir::NumericValue;

pub(super) mod addattr_tokens;
mod builtin;
pub(crate) mod context;
mod embedded;
mod eval;
mod external;
pub(crate) mod locator;
mod lookup;
pub(super) mod node_semantics;
pub(super) mod refedit;
mod refedit_candidate;
mod refedit_grouping;
mod refedit_loader;
mod refedit_parser;
mod refedit_spec;
mod registry;
pub(super) mod structural_attr;
pub(crate) mod typeid_map;
#[cfg(test)]
pub(in crate::scene) use self::lookup::lookup_chunk_schema;
#[cfg(all(test, doctest))]
pub(in crate::scene) use self::lookup::lookup_chunk_schema_with_context;
pub(in crate::scene) use self::{
    context::{SchemaContext, SchemaInputs},
    eval::{
        decode_fields_with_schema, field_bytes, field_numbers, field_text, field_text_values,
        field_u8, field_u32,
    },
    external::validate_chunk_schema_pack,
    lookup::lookup_chunk_schema_with_context_and_registry,
    registry::{SchemaRegistry, default_schema_registry},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SchemaFieldKind {
    U8,
    U32BE,
    U32Expr {
        expr: Cow<'static, str>,
    },
    CString {
        allow_eof_termination: bool,
    },
    CStringListRest {
        min_items: usize,
    },
    F64BEArray {
        count_from: Option<Cow<'static, str>>,
        count_expr: Option<Cow<'static, str>>,
    },
    U32BEArray {
        count_from: Option<Cow<'static, str>>,
        count_expr: Option<Cow<'static, str>>,
    },
    BytesRest {
        allow_empty: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SchemaField {
    pub(super) name: Cow<'static, str>,
    pub(super) kind: SchemaFieldKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChunkSchema {
    pub(super) schema_id: Cow<'static, str>,
    pub(super) form: Cow<'static, str>,
    pub(super) tag: Cow<'static, str>,
    pub(super) handler: Option<Cow<'static, str>>,
    pub(super) priority: i32,
    pub(super) when: Option<SchemaWhen>,
    pub(super) fields: Cow<'static, [SchemaField]>,
}

impl AsRef<ChunkSchema> for ChunkSchema {
    fn as_ref(&self) -> &ChunkSchema {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SchemaWhen {
    pub(super) aux_equals: Option<u32>,
    pub(super) aux_mask: Option<u32>,
    pub(super) payload_min: Option<usize>,
    pub(super) payload_max: Option<usize>,
    pub(super) payload_mod: Option<usize>,
    pub(super) parent_form: Option<Cow<'static, str>>,
    pub(super) parent_tag: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct SchemaLookupContext<'a> {
    pub(super) payload_size: Option<usize>,
    pub(super) aux: Option<u32>,
    pub(super) parent_form: Option<&'a str>,
    pub(super) parent_tag: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedField {
    pub(super) name: Cow<'static, str>,
    pub(super) value: DecodedFieldValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DecodedFieldValue {
    Text(String),
    U8(u8),
    U32(u32),
    Numbers(Vec<NumericValue>),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SchemaDecodeError {
    UnexpectedEof {
        field: Cow<'static, str>,
        needed: usize,
        offset: usize,
    },
    MissingNulTerminator {
        field: Cow<'static, str>,
        offset: usize,
    },
    TrailingNonNulBytes {
        offset: usize,
    },
    TooFewListItems {
        field: Cow<'static, str>,
        min_items: usize,
        actual_items: usize,
    },
    CountReferenceMissing {
        field: Cow<'static, str>,
        count_from: Cow<'static, str>,
    },
    InvalidCountExpression {
        field: Cow<'static, str>,
        expr: Cow<'static, str>,
    },
}

impl std::fmt::Display for SchemaDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaDecodeError::UnexpectedEof {
                field,
                needed,
                offset,
            } => {
                write!(
                    f,
                    "unexpected EOF for field '{field}' (need {needed} bytes) at payload offset {offset}"
                )
            }
            SchemaDecodeError::MissingNulTerminator { field, offset } => {
                write!(
                    f,
                    "missing NUL terminator for field '{field}' at payload offset {offset}"
                )
            }
            SchemaDecodeError::TrailingNonNulBytes { offset } => {
                write!(
                    f,
                    "unexpected trailing non-NUL bytes at payload offset {offset}"
                )
            }
            SchemaDecodeError::TooFewListItems {
                field,
                min_items,
                actual_items,
            } => {
                write!(
                    f,
                    "field '{field}' requires at least {min_items} items, got {actual_items}"
                )
            }
            SchemaDecodeError::CountReferenceMissing { field, count_from } => {
                write!(
                    f,
                    "field '{field}' references missing count field '{count_from}'"
                )
            }
            SchemaDecodeError::InvalidCountExpression { field, expr } => {
                write!(f, "field '{field}' has invalid count_expr '{expr}'")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SchemaLookupContext, decode_fields_with_schema, external::parse_external_schema_yaml,
        field_bytes, field_numbers, field_text, field_text_values, field_u8, field_u32,
        lookup::schema_matches_context, lookup_chunk_schema,
    };
    use crate::scene::ir::NumericValue;

    fn format_numeric_value(value: NumericValue) -> String {
        match value {
            NumericValue::Float64Bits(bits) => f64::from_bits(bits).to_string(),
            NumericValue::U32(value) => value.to_string(),
        }
    }

    #[test]
    fn slct_schema_decodes_cstring_target() {
        let schema = lookup_chunk_schema("SLCT", "SLCT").expect("schema exists");
        let fields = decode_fields_with_schema(schema, b":time1\0").expect("decode");
        assert_eq!(field_text(&fields, "target"), Some(":time1"));
    }

    #[test]
    fn slct_schema_rejects_non_nul_trailer() {
        let schema = lookup_chunk_schema("SLCT", "SLCT").expect("schema exists");
        let err = decode_fields_with_schema(schema, b":time1\0xyz").unwrap_err();
        assert!(
            err.to_string()
                .contains("unexpected trailing non-NUL bytes")
        );
    }

    #[test]
    fn slct_schema_accepts_eof_terminated_target() {
        let schema = lookup_chunk_schema("SLCT", "SLCT").expect("schema exists");
        let fields = decode_fields_with_schema(schema, b":time1").expect("decode");
        assert_eq!(field_text(&fields, "target"), Some(":time1"));
    }

    #[test]
    fn cons_cwfl_schema_decodes_mode_and_plugs() {
        let schema = lookup_chunk_schema("CONS", "CWFL").expect("schema exists");
        let fields =
            decode_fields_with_schema(schema, b"\x03src.plug\0dst.plug\0").expect("decode");
        assert_eq!(field_u8(&fields, "mode"), Some(3));
        assert_eq!(field_text(&fields, "src"), Some("src.plug"));
        assert_eq!(field_text(&fields, "dst"), Some("dst.plug"));
    }

    #[test]
    fn cons_rela_schema_decodes_tail_list() {
        let schema = lookup_chunk_schema("CONS", "RELA").expect("schema exists");
        let fields =
            decode_fields_with_schema(schema, b"foo\0head\0tailA\0tailB\0").expect("decode");
        assert_eq!(field_text(&fields, "kind"), Some("foo"));
        assert_eq!(field_text(&fields, "head"), Some("head"));
        assert_eq!(field_text_values(&fields, "tail"), vec!["tailA", "tailB"]);
    }

    #[test]
    fn attr_str_schema_decodes_attr_payload_triplet() {
        let schema = lookup_chunk_schema("ATTR", "STR ").expect("schema exists");
        let fields = decode_fields_with_schema(schema, b"cst\0\x00abc\0").expect("decode");
        assert_eq!(field_text(&fields, "attr_name"), Some("cst"));
        assert_eq!(field_u8(&fields, "kind"), Some(0));
        assert_eq!(field_bytes(&fields, "value_raw"), Some("abc\0".as_bytes()));
    }

    #[test]
    fn attr_str_array_schema_decodes_declared_count_and_values() {
        let schema = lookup_chunk_schema("ATTR", "STR#").expect("schema exists");
        let fields =
            decode_fields_with_schema(schema, b"p\0\x00\x00\x00\x00\x02A\0B\0").expect("decode");
        assert_eq!(field_text(&fields, "attr_name"), Some("p"));
        assert_eq!(field_u8(&fields, "kind"), Some(0));
        assert_eq!(field_u32(&fields, "declared_count"), Some(2));
        assert_eq!(field_text_values(&fields, "values"), vec!["A", "B"]);
    }

    #[test]
    fn refe_schema_decodes_attr_payload_triplet() {
        let schema = lookup_chunk_schema("REFE", "REFE").expect("schema exists");
        let fields = decode_fields_with_schema(schema, b"ed\0\x2Aabc").expect("decode");
        assert_eq!(field_text(&fields, "attr_name"), Some("ed"));
        assert_eq!(field_u8(&fields, "kind"), Some(0x2A));
        assert_eq!(field_bytes(&fields, "value_raw"), Some("abc".as_bytes()));
    }

    #[test]
    fn fref_schema_decodes_reference_fields() {
        let schema = lookup_chunk_schema("FREF", "FREF").expect("schema exists");
        let fields = decode_fields_with_schema(
            schema,
            b"rig/charA_v001.mb\0charA\0charARN\0mayaBinary\0-op \"v=0\"\0",
        )
        .expect("decode");
        assert_eq!(field_text(&fields, "path"), Some("rig/charA_v001.mb"));
        assert_eq!(field_text(&fields, "namespace"), Some("charA"));
        assert_eq!(field_text(&fields, "reference_node"), Some("charARN"));
        assert_eq!(
            field_bytes(&fields, "tail_raw"),
            Some("mayaBinary\0-op \"v=0\"\0".as_bytes())
        );
    }

    #[test]
    fn fref_external_legacy_field_names_remain_compatible() {
        let yaml = r#"
schema_id: schema.fref.legacy.compat.v1
handler: fref.reference_file
fields:
  - name: path
    kind: cstring
  - name: reference_node
    kind: cstring
  - name: short_name
    kind: cstring
  - name: tail_raw
    kind: bytes_rest
    allow_empty: true
"#;
        let schema =
            parse_external_schema_yaml("FREF", "FREF", yaml.as_bytes()).expect("schema parse");
        let fields =
            decode_fields_with_schema(schema, b"rig/charA_v001.mb\0charA\0charARN\0mayaBinary\0")
                .expect("decode");
        assert_eq!(field_text(&fields, "reference_node"), Some("charA"));
        assert_eq!(field_text(&fields, "short_name"), Some("charARN"));
    }

    #[test]
    fn rtft_schema_decodes_attr_payload_triplet() {
        let schema = lookup_chunk_schema("RTFT", "STR ").expect("schema exists");
        let fields =
            decode_fields_with_schema(schema, b"ftn\0\x00textures/a.mb\0").expect("decode");
        assert_eq!(field_text(&fields, "attr_name"), Some("ftn"));
        assert_eq!(field_u8(&fields, "kind"), Some(0));
        assert_eq!(
            field_bytes(&fields, "value_raw"),
            Some("textures/a.mb\0".as_bytes())
        );
    }

    #[test]
    fn external_schema_yaml_can_override_shape() {
        let yaml = r#"
schema_id: schema.external.refe.override.v1
fields:
  - name: attr_name
    kind: cstring
  - name: kind
    kind: u8
  - name: value_raw
    kind: bytes_rest
"#;
        let schema =
            parse_external_schema_yaml("REFE", "REFE", yaml.as_bytes()).expect("schema parse");
        let fields = decode_fields_with_schema(&schema, b"ed\0\x2Axyz").expect("decode");
        assert_eq!(schema.schema_id, "schema.external.refe.override.v1");
        assert_eq!(field_text(&fields, "attr_name"), Some("ed"));
        assert_eq!(field_u8(&fields, "kind"), Some(0x2A));
        assert_eq!(field_bytes(&fields, "value_raw"), Some("xyz".as_bytes()));
    }

    #[test]
    fn external_schema_yaml_parses_priority_and_when() {
        let yaml = r#"
schema_id: schema.external.attr.str.conditional.v1
priority: 7
when:
  payload_min: 4
  payload_max: 64
  payload_mod: 2
fields:
  - name: attr_name
    kind: cstring
  - name: kind
    kind: u8
  - name: value_raw
    kind: bytes_rest
"#;
        let schema =
            parse_external_schema_yaml("ATTR", "STR ", yaml.as_bytes()).expect("schema parse");
        assert_eq!(schema.priority, 7);
        let when = schema.when.expect("when");
        assert_eq!(when.payload_min, Some(4));
        assert_eq!(when.payload_max, Some(64));
        assert_eq!(when.payload_mod, Some(2));
    }

    #[test]
    fn schema_context_filters_payload_size_predicates() {
        let yaml = r#"
schema_id: schema.external.attr.str.conditional.v1
when:
  payload_min: 4
  payload_max: 8
fields:
  - name: attr_name
    kind: cstring
  - name: kind
    kind: u8
  - name: value_raw
    kind: bytes_rest
"#;
        let schema =
            parse_external_schema_yaml("ATTR", "STR ", yaml.as_bytes()).expect("schema parse");
        assert!(schema_matches_context(
            &schema,
            SchemaLookupContext {
                payload_size: Some(6),
                ..SchemaLookupContext::default()
            }
        ));
        assert!(!schema_matches_context(
            &schema,
            SchemaLookupContext {
                payload_size: Some(2),
                ..SchemaLookupContext::default()
            }
        ));
    }

    #[test]
    fn external_schema_supports_count_from_and_count_expr_arrays() {
        let yaml = r#"
schema_id: schema.external.test.count_expr.v1
fields:
  - name: item_count
    kind: u32be
  - name: values
    kind: f64be_array
    count_from: item_count
  - name: triple_count
    kind: u32_expr
    count_expr: "item_count * 3"
  - name: indices
    kind: u32be_array
    count_expr: "item_count + 1"
"#;
        let schema =
            parse_external_schema_yaml("TEST", "CNTX", yaml.as_bytes()).expect("schema parse");
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&1.0f64.to_be_bytes());
        payload.extend_from_slice(&2.5f64.to_be_bytes());
        payload.extend_from_slice(&7u32.to_be_bytes());
        payload.extend_from_slice(&8u32.to_be_bytes());
        payload.extend_from_slice(&9u32.to_be_bytes());

        let fields = decode_fields_with_schema(schema, &payload).expect("decode");
        assert_eq!(field_u32(&fields, "item_count"), Some(2));
        assert_eq!(field_u32(&fields, "triple_count"), Some(6));
        let values = field_numbers(&fields, "values").expect("values");
        assert_eq!(
            values
                .iter()
                .copied()
                .map(format_numeric_value)
                .collect::<Vec<_>>(),
            vec!["1".to_string(), "2.5".to_string()]
        );
        let indices = field_numbers(&fields, "indices").expect("indices");
        assert_eq!(
            indices
                .iter()
                .copied()
                .map(format_numeric_value)
                .collect::<Vec<_>>(),
            vec!["7".to_string(), "8".to_string(), "9".to_string()]
        );
    }

    #[test]
    fn external_schema_rejects_invalid_count_expr() {
        let yaml = r#"
schema_id: schema.external.test.bad_expr.v1
fields:
  - name: count
    kind: u32be
  - name: value
    kind: u32_expr
    count_expr: "count + "
"#;
        let schema =
            parse_external_schema_yaml("TEST", "BADX", yaml.as_bytes()).expect("schema parse");
        let err = decode_fields_with_schema(schema, &1u32.to_be_bytes()).unwrap_err();
        assert!(err.to_string().contains("invalid count_expr"));
    }
}
