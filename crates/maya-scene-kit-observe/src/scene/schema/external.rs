use std::{fs, path::Path, sync::Arc};

use serde::Deserialize;

use super::{
    ChunkSchema, SchemaField, SchemaFieldKind, SchemaRegistry, SchemaWhen,
    refedit::{is_refedit_schema_asset, validate_refedit_schema_file},
};

#[derive(Debug, Clone, Deserialize)]
struct ExternalChunkSchema {
    schema_id: Option<String>,
    form: Option<String>,
    tag: Option<String>,
    handler: Option<String>,
    priority: Option<i32>,
    when: Option<ExternalSchemaWhen>,
    fields: Vec<ExternalSchemaField>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalSchemaWhen {
    aux_equals: Option<u32>,
    aux_mask: Option<u32>,
    payload_min: Option<usize>,
    payload_max: Option<usize>,
    payload_mod: Option<usize>,
    parent_form: Option<String>,
    parent_tag: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalSchemaField {
    name: String,
    kind: String,
    allow_eof_termination: Option<bool>,
    min_items: Option<usize>,
    allow_empty: Option<bool>,
    count_from: Option<String>,
    count_expr: Option<String>,
}

pub(in crate::scene) fn validate_chunk_schema_root(root: &Path) -> Result<(), String> {
    if root.is_dir() {
        Ok(())
    } else {
        Err(format!(
            "{}: chunk schema root does not exist or is not a directory",
            root.display()
        ))
    }
}

pub(in crate::scene) fn validate_chunk_schema_pack(root: &Path) -> Result<(), String> {
    validate_chunk_schema_root(root)?;

    for form_entry in fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))? {
        let form_entry = form_entry.map_err(|e| format!("{}: {e}", root.display()))?;
        let form_path = form_entry.path();
        if !form_path.is_dir() {
            continue;
        }
        let Some(form) = form_path.file_name().and_then(|v| v.to_str()) else {
            continue;
        };

        for schema_entry in
            fs::read_dir(&form_path).map_err(|e| format!("{}: {e}", form_path.display()))?
        {
            let schema_entry = schema_entry.map_err(|e| format!("{}: {e}", form_path.display()))?;
            let schema_path = schema_entry.path();
            if schema_path.extension().and_then(|v| v.to_str()) != Some("yaml") {
                continue;
            }
            let Some(tag) = schema_path.file_stem().and_then(|v| v.to_str()) else {
                continue;
            };
            if is_refedit_schema_asset(form, tag) {
                validate_refedit_schema_file(&schema_path)?;
                continue;
            }
            let bytes =
                fs::read(&schema_path).map_err(|e| format!("{}: {e}", schema_path.display()))?;
            parse_external_schema_yaml(form, tag, &bytes).ok_or_else(|| {
                format!(
                    "{}: malformed chunk schema for {form}/{tag}",
                    schema_path.display()
                )
            })?;
        }
    }

    Ok(())
}

pub(in crate::scene) fn parse_external_schema_yaml(
    form: &str,
    tag: &str,
    yaml_bytes: &[u8],
) -> Option<ChunkSchema> {
    let spec: ExternalChunkSchema = serde_yaml::from_slice(yaml_bytes).ok()?;
    if let Some(spec_form) = &spec.form {
        if spec_form != form {
            return None;
        }
    }
    if let Some(spec_tag) = &spec.tag {
        if spec_tag != tag {
            return None;
        }
    }

    let mut fields = Vec::with_capacity(spec.fields.len());
    for field in spec.fields {
        let count_from = field.count_from.map(Into::into);
        let count_expr = field.count_expr.map(Into::into);
        let kind = match field.kind.as_str() {
            "u8" => SchemaFieldKind::U8,
            "u32be" => SchemaFieldKind::U32BE,
            "u32_expr" => SchemaFieldKind::U32Expr { expr: count_expr? },
            "cstring" => SchemaFieldKind::CString {
                allow_eof_termination: field.allow_eof_termination.unwrap_or(false),
            },
            "cstring_list_rest" => SchemaFieldKind::CStringListRest {
                min_items: field.min_items.unwrap_or(0),
            },
            "f64be_array" => SchemaFieldKind::F64BEArray {
                count_from,
                count_expr,
            },
            "u32be_array" => SchemaFieldKind::U32BEArray {
                count_from,
                count_expr,
            },
            "bytes_rest" => SchemaFieldKind::BytesRest {
                allow_empty: field.allow_empty.unwrap_or(true),
            },
            _ => return None,
        };

        fields.push(SchemaField {
            name: field.name.into(),
            kind,
        });
    }

    Some(ChunkSchema {
        schema_id: spec
            .schema_id
            .unwrap_or_else(|| format!("schema.external.{}.{}.v1", form, tag))
            .into(),
        form: spec.form.unwrap_or_else(|| form.to_string()).into(),
        tag: spec.tag.unwrap_or_else(|| tag.to_string()).into(),
        handler: spec.handler.map(Into::into),
        priority: spec.priority.unwrap_or(0),
        when: spec.when.map(|when| SchemaWhen {
            aux_equals: when.aux_equals,
            aux_mask: when.aux_mask,
            payload_min: when.payload_min,
            payload_max: when.payload_max,
            payload_mod: when.payload_mod,
            parent_form: when.parent_form.map(Into::into),
            parent_tag: when.parent_tag.map(Into::into),
        }),
        fields: fields.into(),
    })
}

pub(in crate::scene) fn lookup_external_schema(
    registry: &SchemaRegistry,
    form: &str,
    tag: &str,
) -> Option<Arc<ChunkSchema>> {
    if is_refedit_schema_asset(form, tag) {
        return None;
    }
    let path = registry
        .paths()
        .chunk_schema_root
        .join(form)
        .join(format!("{tag}.yaml"));
    let key = (form.to_string(), tag.to_string());
    if let Ok(cache) = registry.caches().chunk_schemas.lock() {
        if let Some(cached) = cache.get(&key) {
            return cached.clone();
        }
    }

    let loaded = fs::read(&path)
        .ok()
        .and_then(|bytes| parse_external_schema_yaml(form, tag, &bytes))
        .map(Arc::new);

    if let Ok(mut cache) = registry.caches().chunk_schemas.lock() {
        cache.insert(key, loaded.clone());
    }

    loaded
}
