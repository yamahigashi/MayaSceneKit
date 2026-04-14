use std::{fs, path::PathBuf, sync::Arc};

use once_cell::sync::Lazy;
use serde::Deserialize;

#[cfg(test)]
use super::default_schema_registry;
pub(in crate::scene) use super::refedit_spec::{RefEditRecordSpec, RefEditSchema};
use super::{
    SchemaRegistry,
    refedit_spec::{RecordDecodeMode, RecordEmitKind, RefEditLayoutSpec},
};

#[derive(Debug, Clone, Deserialize)]
struct ExternalRefEditSchema {
    schema_id: Option<String>,
    layouts: Vec<ExternalLayoutSpec>,
    records: Vec<ExternalRecordSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalLayoutSpec {
    name: String,
    group_list_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalRecordSpec {
    opcode: ExternalOpcode,
    mode: String,
    emit: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ExternalOpcode {
    Number(u64),
    Text(String),
}

const BUILTIN_RECORDS: [RefEditRecordSpec; 5] = [
    RefEditRecordSpec {
        opcode: 0,
        mode: RecordDecodeMode::TripletInline,
        emit: Some(RecordEmitKind::Op0),
    },
    RefEditRecordSpec {
        opcode: 1,
        mode: RecordDecodeMode::Marker,
        emit: Some(RecordEmitKind::Op1),
    },
    RefEditRecordSpec {
        opcode: 2,
        mode: RecordDecodeMode::TripletPrefixed,
        emit: Some(RecordEmitKind::Op2),
    },
    RefEditRecordSpec {
        opcode: 3,
        mode: RecordDecodeMode::TripletPrefixed,
        emit: Some(RecordEmitKind::Op3),
    },
    RefEditRecordSpec {
        opcode: 5,
        mode: RecordDecodeMode::CountedCStringArgs,
        emit: Some(RecordEmitKind::Op5),
    },
];

fn builtin_refedit_schema() -> Arc<RefEditSchema> {
    static BUILTIN: Lazy<Arc<RefEditSchema>> = Lazy::new(|| {
        Arc::new(RefEditSchema {
            schema_id: "schema.refe.ed.v1".to_string(),
            layouts: vec![
                RefEditLayoutSpec {
                    name: "TwoLists".to_string(),
                    group_list_count: 2,
                },
                RefEditLayoutSpec {
                    name: "OneList".to_string(),
                    group_list_count: 1,
                },
                RefEditLayoutSpec {
                    name: "Headerless".to_string(),
                    group_list_count: 0,
                },
            ],
            records: BUILTIN_RECORDS.to_vec(),
        })
    });
    Arc::clone(&BUILTIN)
}

fn parse_mode(value: &str) -> Option<RecordDecodeMode> {
    match value {
        "marker" => Some(RecordDecodeMode::Marker),
        "triplet_inline" => Some(RecordDecodeMode::TripletInline),
        "triplet_prefixed" => Some(RecordDecodeMode::TripletPrefixed),
        "counted_cstring_args" => Some(RecordDecodeMode::CountedCStringArgs),
        _ => None,
    }
}

fn parse_emit_kind(value: &str) -> Option<RecordEmitKind> {
    match value {
        "op0" => Some(RecordEmitKind::Op0),
        "op1" => Some(RecordEmitKind::Op1),
        "op2" => Some(RecordEmitKind::Op2),
        "op3" => Some(RecordEmitKind::Op3),
        "op5" => Some(RecordEmitKind::Op5),
        _ => None,
    }
}

fn parse_opcode(value: ExternalOpcode) -> Option<u8> {
    match value {
        ExternalOpcode::Number(v) => u8::try_from(v).ok(),
        ExternalOpcode::Text(text) => {
            let text = text.trim();
            if text.len() == 1 {
                return Some(text.as_bytes()[0]);
            }
            if let Some(stripped) = text.strip_prefix("0x") {
                return u8::from_str_radix(stripped, 16).ok();
            }
            text.parse::<u8>().ok()
        }
    }
}

pub(in crate::scene) fn parse_external_refedit_schema(yaml_bytes: &[u8]) -> Option<RefEditSchema> {
    let raw: ExternalRefEditSchema = serde_yaml::from_slice(yaml_bytes).ok()?;
    if raw.layouts.is_empty() || raw.records.is_empty() {
        return None;
    }

    let mut layouts = Vec::with_capacity(raw.layouts.len());
    for layout in raw.layouts {
        layouts.push(RefEditLayoutSpec {
            name: layout.name,
            group_list_count: layout.group_list_count,
        });
    }

    let mut records = Vec::with_capacity(raw.records.len());
    for record in raw.records {
        let opcode = parse_opcode(record.opcode)?;
        let mode = parse_mode(record.mode.trim())?;
        let emit = match record.emit.as_deref().map(str::trim) {
            Some(raw_emit) => Some(parse_emit_kind(raw_emit)?),
            None => None,
        };
        records.push(RefEditRecordSpec { opcode, mode, emit });
    }

    Some(RefEditSchema {
        schema_id: raw
            .schema_id
            .unwrap_or_else(|| "schema.external.refe.ed.v1".to_string()),
        layouts,
        records,
    })
}

fn load_external_refedit_schema(path: &PathBuf) -> Option<RefEditSchema> {
    let bytes = fs::read(path).ok()?;
    parse_external_refedit_schema(&bytes)
}

pub(in crate::scene) fn validate_refedit_schema_file(path: &PathBuf) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_external_refedit_schema(&bytes)
        .map(|_| ())
        .ok_or_else(|| format!("{}: malformed refedit schema", path.display()))
}

#[allow(dead_code)]
#[cfg(test)]
pub(in crate::scene) fn lookup_refedit_schema() -> Arc<RefEditSchema> {
    lookup_refedit_schema_with_registry(default_schema_registry())
}

pub(in crate::scene) fn lookup_refedit_schema_with_registry(
    registry: &SchemaRegistry,
) -> Arc<RefEditSchema> {
    if let Ok(cache) = registry.caches().refedit_schema.lock() {
        if let Some(value) = cache.as_ref() {
            return value.clone().unwrap_or_else(builtin_refedit_schema);
        }
    }

    let loaded = load_external_refedit_schema(&registry.paths().refedit_schema_file).map(Arc::new);
    if let Ok(mut cache) = registry.caches().refedit_schema.lock() {
        *cache = Some(loaded.clone());
    }
    if let Some(schema) = loaded {
        return schema;
    }
    builtin_refedit_schema()
}
