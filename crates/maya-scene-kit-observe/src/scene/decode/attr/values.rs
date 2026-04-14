#[cfg(test)]
use super::payload::decode_attr_payload;
use super::{
    add_attr::decode_add_attr_op_from_attr_chunk_with_registry,
    codecs::{decode_matrix_values, nurbs_curve_components_per_cv, parse_nurbs_curve_value_raw},
    payload::{attr_path, decode_component_list_attr, decode_indexed_double_range_attr},
};
use crate::{
    scene::{
        decode::numeric_f64,
        ir::{
            AddAttrOp, NumericValue, SetAttrOp, SetAttrValue, SkinWeightPair, SkinWeightRow,
            TimeValuePair,
        },
        patterns::*,
        schema::{DecodedField, SchemaRegistry, field_numbers, field_u8, field_u32},
    },
    typed_value_semantics::TypedValueKind,
};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum AttrDecodeOutcome {
    AddAttr(AddAttrOp),
    SetAttr(SetAttrOp),
    Unsupported {
        tag: String,
        attr_name: String,
        kind: u8,
        payload_size: usize,
    },
}

type AttrValueHandler = fn(&AttrValueDecodeContext<'_>) -> Option<SetAttrOp>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttrValueHandlerId {
    Flgs,
    Double,
    Compound,
    Typed(TypedValueKind),
    RefeBridge,
}

impl AttrValueHandlerId {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Flgs => "attr.flgs",
            Self::Double => "attr.dble",
            Self::Compound => "attr.cmpd",
            Self::Typed(kind) => kind.schema_handler(),
            Self::RefeBridge => "attr.refe_bridge",
        }
    }
}

struct AttrValueDecodeContext<'a> {
    handler_id: AttrValueHandlerId,
    attr_name: &'a str,
    kind: u8,
    value_raw: &'a [u8],
    attr_path: &'a str,
}

pub(crate) fn decode_attr_definition_chunk_to_outcome_with_registry(
    registry: &SchemaRegistry,
    payload: &[u8],
) -> AttrDecodeOutcome {
    match decode_add_attr_op_from_attr_chunk_with_registry(registry, payload) {
        Some(op) => AttrDecodeOutcome::AddAttr(op),
        None => AttrDecodeOutcome::Unsupported {
            tag: "ATTR".to_string(),
            attr_name: "<ATTR>".to_string(),
            kind: 0,
            payload_size: payload.len(),
        },
    }
}

#[cfg(test)]
pub(crate) fn decode_attr_value_chunk_to_setattr(tag: &str, payload: &[u8]) -> Option<SetAttrOp> {
    let (attr_name, kind, value_raw) = decode_attr_payload(payload)?;
    decode_attr_value_from_parts(tag, &attr_name, kind, &value_raw)
}

#[cfg(test)]
pub(crate) fn decode_attr_value_from_parts(
    tag: &str,
    attr_name: &str,
    kind: u8,
    value_raw: &[u8],
) -> Option<SetAttrOp> {
    let handler_id = attr_value_handler_id_from_tag(tag)?;
    decode_attr_value_from_handler(handler_id, attr_name, kind, value_raw)
}

pub(crate) fn decode_attr_value_from_handler(
    handler_id: AttrValueHandlerId,
    attr_name: &str,
    kind: u8,
    value_raw: &[u8],
) -> Option<SetAttrOp> {
    let attr_path = attr_path(attr_name);
    let context = AttrValueDecodeContext {
        handler_id,
        attr_name,
        kind,
        value_raw,
        attr_path: &attr_path,
    };
    let handler = dispatch_attr_value_handler(handler_id)?;
    handler(&context)
}

pub(crate) fn validate_attr_handler_payload_shape(
    handler_id: AttrValueHandlerId,
    kind: u8,
    value_raw: &[u8],
) -> Result<(), &'static str> {
    match handler_id {
        AttrValueHandlerId::Typed(TypedValueKind::NurbsCurve) => {
            if parse_nurbs_curve_value_raw(kind, value_raw).is_some() {
                Ok(())
            } else {
                Err("nurbsCurve payload shape mismatch")
            }
        }
        _ => Ok(()),
    }
}

pub(crate) fn decode_attr_value_from_schema_fields(
    handler_id: AttrValueHandlerId,
    attr_name: &str,
    kind: u8,
    fields: &[DecodedField],
) -> Option<SetAttrOp> {
    match handler_id {
        AttrValueHandlerId::Typed(TypedValueKind::NurbsCurve) => {
            decode_attr_value_nurbs_curve_from_schema_fields(attr_name, kind, fields)
        }
        _ => None,
    }
}

fn decode_attr_value_nurbs_curve_from_schema_fields(
    attr_name: &str,
    _kind: u8,
    fields: &[DecodedField],
) -> Option<SetAttrOp> {
    let degree = field_u32(fields, "degree")?;
    let spans = field_u32(fields, "spans")?;
    let form = field_u32(fields, "form")?;
    let is_rational = field_u32(fields, "is_rational").unwrap_or(0) != 0;
    let dimension = field_u32(fields, "dimension")
        .map(|v| v as usize)
        .or_else(|| field_u8(fields, "dimension").map(|v| v as usize))?;
    if dimension == 0 {
        return None;
    }
    let cv_count = field_u32(fields, "cv_count")? as usize;

    let knots = field_numbers(fields, "knots")?.to_vec();
    let cv_values = field_numbers(fields, "cv_values")?;
    let components_per_cv = nurbs_curve_components_per_cv(dimension, is_rational)?;
    if cv_values.len() != cv_count.checked_mul(components_per_cv)? {
        return None;
    }

    let mut cvs = Vec::with_capacity(cv_count);
    for idx in 0..cv_count {
        let start = idx * components_per_cv;
        let end = start + components_per_cv;
        cvs.push(cv_values[start..end].to_vec());
    }

    Some(SetAttrOp {
        attr_name_or_path: attr_path(attr_name),
        array_size: None,
        channel_hint: None,
        lock: None,
        keyable: None,
        value: SetAttrValue::NurbsCurve {
            degree,
            spans,
            form,
            is_rational,
            dimension,
            knots,
            cvs,
        },
    })
}

pub(crate) fn attr_value_handler_id_from_schema_handler(
    handler: &str,
    tag: &str,
) -> Option<AttrValueHandlerId> {
    if let Some(kind) = TypedValueKind::from_schema_handler(handler) {
        return Some(AttrValueHandlerId::Typed(kind));
    }
    match handler {
        "attr.flgs" => Some(AttrValueHandlerId::Flgs),
        "attr.dble" => Some(AttrValueHandlerId::Double),
        "attr.cmpd" => Some(AttrValueHandlerId::Compound),
        "attr.refe_bridge" => Some(AttrValueHandlerId::RefeBridge),
        "rtft.attr_payload" if tag == "STR " => {
            Some(AttrValueHandlerId::Typed(TypedValueKind::String))
        }
        _ => None,
    }
}

fn dispatch_attr_value_handler(handler_id: AttrValueHandlerId) -> Option<AttrValueHandler> {
    match handler_id {
        AttrValueHandlerId::Flgs => Some(decode_attr_value_tag_flgs),
        AttrValueHandlerId::Double => Some(decode_attr_value_tag_double_scalar_or_ranges),
        AttrValueHandlerId::Compound => Some(decode_attr_value_tag_compound_numbers),
        AttrValueHandlerId::Typed(kind) => match kind {
            TypedValueKind::String => Some(decode_attr_value_tag_string),
            TypedValueKind::StringArray => Some(decode_attr_value_tag_string_array),
            TypedValueKind::Int32Array => Some(decode_attr_value_tag_int32_array),
            TypedValueKind::Float3 => Some(decode_attr_value_tag_float3),
            TypedValueKind::Float2 => Some(decode_attr_value_tag_float2),
            TypedValueKind::Double3 => Some(decode_attr_value_tag_double3),
            TypedValueKind::Double2 => Some(decode_attr_value_tag_double2),
            TypedValueKind::Matrix => Some(decode_attr_value_tag_matrix),
            TypedValueKind::ComponentList => Some(decode_attr_value_tag_component_list),
            TypedValueKind::NurbsCurve => Some(decode_attr_value_tag_nurbs_curve),
            TypedValueKind::PolyFaces | TypedValueKind::DataPolyComponent => None,
        },
        AttrValueHandlerId::RefeBridge => Some(decode_attr_value_tag_refe_bridge),
    }
}

fn build_setattr_op(
    context: &AttrValueDecodeContext<'_>,
    array_size: Option<usize>,
    lock: Option<bool>,
    keyable: Option<bool>,
    value: SetAttrValue,
) -> SetAttrOp {
    let inferred_lock = if matches!(context.handler_id, AttrValueHandlerId::Flgs) {
        None
    } else {
        match context.kind {
            0x21 | 0x25 => Some(true),
            _ => None,
        }
    };
    SetAttrOp {
        attr_name_or_path: context.attr_path.to_string(),
        array_size,
        channel_hint: None,
        lock: lock.or(inferred_lock),
        keyable,
        value,
    }
}

fn decode_attr_value_tag_flgs(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    if context.value_raw.len() >= 4 {
        let count = u32::from_be_bytes(context.value_raw[..4].try_into().ok()?) as usize;
        if context.kind == 0x08 || context.kind == 0x28 {
            return Some(build_setattr_op(
                context,
                Some(count),
                None,
                None,
                SetAttrValue::None,
            ));
        }
    }
    let (lock, keyable) = match context.kind {
        0x20 => (None, Some(false)),
        0x24 => (None, Some(true)),
        0x21 => (Some(true), Some(false)),
        0x25 => (Some(true), None),
        _ => (None, None),
    };
    Some(build_setattr_op(
        context,
        None,
        lock,
        keyable,
        SetAttrValue::None,
    ))
}

fn decode_attr_value_tag_string(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    let end = context
        .value_raw
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(context.value_raw.len());
    let text = String::from_utf8_lossy(&context.value_raw[..end]).to_string();
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::String(text),
    ))
}

fn decode_attr_value_tag_string_array(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    if context.value_raw.len() < 4 {
        return None;
    }
    let count = u32::from_be_bytes(context.value_raw[..4].try_into().ok()?) as usize;
    let mut items = Vec::with_capacity(count);
    let mut cursor = 4usize;
    while items.len() < count {
        if cursor >= context.value_raw.len() {
            items.push(String::new());
            continue;
        }
        if let Some(end_rel) = context.value_raw[cursor..].iter().position(|b| *b == 0) {
            let end = cursor + end_rel;
            items.push(String::from_utf8_lossy(&context.value_raw[cursor..end]).to_string());
            cursor = end + 1;
        } else {
            items.push(String::from_utf8_lossy(&context.value_raw[cursor..]).to_string());
            cursor = context.value_raw.len();
        }
    }
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::StringArray {
            declared_count: count,
            values: items,
        },
    ))
}

fn decode_attr_value_tag_int32_array(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    if context.value_raw.len() % 4 != 0 {
        return None;
    }
    let vals: Vec<i32> = context
        .value_raw
        .chunks_exact(4)
        .map(|c| i32::from_be_bytes(c.try_into().unwrap()))
        .collect();
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::Int32Array(vals),
    ))
}

fn decode_attr_value_tag_float3(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    if context.value_raw.len() < 12 {
        return None;
    }
    let x = f32::from_bits(u32::from_be_bytes(
        context.value_raw[0..4].try_into().unwrap(),
    )) as f64;
    let y = f32::from_bits(u32::from_be_bytes(
        context.value_raw[4..8].try_into().unwrap(),
    )) as f64;
    let z = f32::from_bits(u32::from_be_bytes(
        context.value_raw[8..12].try_into().unwrap(),
    )) as f64;
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::TypedNumbers {
            value_type: "float3".to_string(),
            values: vec![numeric_f64(x), numeric_f64(y), numeric_f64(z)],
        },
    ))
}

fn decode_attr_value_tag_float2(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    if context.value_raw.len() < 8 || context.value_raw.len() % 8 != 0 {
        return None;
    }
    let vals: Vec<NumericValue> = context
        .value_raw
        .chunks_exact(4)
        .map(|c| NumericValue::from_f32(f32::from_bits(u32::from_be_bytes(c.try_into().unwrap()))))
        .collect();
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::TypedNumbers {
            value_type: "float2".to_string(),
            values: vals,
        },
    ))
}

fn decode_attr_value_tag_double_scalar_or_ranges(
    context: &AttrValueDecodeContext<'_>,
) -> Option<SetAttrOp> {
    if let Some(rows) = decode_skincluster_weightlist_attr(context.attr_name, context.value_raw) {
        return Some(build_setattr_op(
            context,
            None,
            None,
            None,
            SetAttrValue::SkinWeightRows(rows),
        ));
    }
    if let Some((count, values)) =
        decode_indexed_double_range_attr(context.attr_name, context.value_raw)
    {
        return Some(build_setattr_op(
            context,
            Some(count),
            None,
            None,
            SetAttrValue::Numbers(values),
        ));
    }
    if context.value_raw.len() < 8 {
        return None;
    }
    let value = f64::from_bits(u64::from_be_bytes(
        context.value_raw[0..8].try_into().unwrap(),
    ));
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::Scalar(numeric_f64(value)),
    ))
}

fn decode_attr_value_tag_double3(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    if context.value_raw.len() < 24 {
        return None;
    }
    let values = [
        f64::from_bits(u64::from_be_bytes(
            context.value_raw[0..8].try_into().unwrap(),
        )),
        f64::from_bits(u64::from_be_bytes(
            context.value_raw[8..16].try_into().unwrap(),
        )),
        f64::from_bits(u64::from_be_bytes(
            context.value_raw[16..24].try_into().unwrap(),
        )),
    ];
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::TypedNumbers {
            value_type: "double3".to_string(),
            values: vec![
                numeric_f64(values[0]),
                numeric_f64(values[1]),
                numeric_f64(values[2]),
            ],
        },
    ))
}

fn decode_attr_value_tag_double2(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    if context.value_raw.len() < 16 || context.value_raw.len() % 16 != 0 {
        return None;
    }
    let vals: Vec<NumericValue> = context
        .value_raw
        .chunks_exact(8)
        .map(|c| numeric_f64(f64::from_bits(u64::from_be_bytes(c.try_into().unwrap()))))
        .collect();
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::TypedNumbers {
            value_type: "double2".to_string(),
            values: vals,
        },
    ))
}

fn decode_attr_value_tag_compound_numbers(
    context: &AttrValueDecodeContext<'_>,
) -> Option<SetAttrOp> {
    if context.kind == 0x08 || context.kind == 0x28 {
        if context.value_raw.len() < 4 {
            return None;
        }
        let count = u32::from_be_bytes(context.value_raw[..4].try_into().ok()?) as usize;
        return Some(build_setattr_op(
            context,
            Some(count),
            None,
            None,
            SetAttrValue::None,
        ));
    }

    if context.value_raw.len() % 16 == 0
        && context.value_raw.len() >= 16
        && looks_like_cmpd_time_value_pairs(context.value_raw)
    {
        return decode_cmpd_time_value_pairs(context);
    }

    if context.value_raw.len() % 8 != 0 || context.value_raw.len() < 8 {
        return None;
    }
    let values: Vec<NumericValue> = context
        .value_raw
        .chunks_exact(8)
        .map(|c| numeric_f64(f64::from_bits(u64::from_be_bytes(c.try_into().unwrap()))))
        .collect();
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::Numbers(values),
    ))
}

fn looks_like_cmpd_time_value_pairs(value_raw: &[u8]) -> bool {
    value_raw.chunks_exact(16).all(|chunk| {
        let maybe_double = f64::from_bits(u64::from_be_bytes(chunk[0..8].try_into().unwrap()));
        !maybe_double.is_finite() || maybe_double.abs() > 1.0e12
    })
}

fn decode_cmpd_time_value_pairs(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    let mut pairs = Vec::new();
    for chunk in context.value_raw.chunks_exact(16) {
        let ticks = i64::from_be_bytes(chunk[0..8].try_into().ok()?);
        let value = f64::from_bits(u64::from_be_bytes(chunk[8..16].try_into().ok()?));
        pairs.push(TimeValuePair {
            time_ticks: ticks,
            value: numeric_f64(value),
        });
    }
    if pairs.is_empty() {
        return None;
    }
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::TimeValuePairs(pairs),
    ))
}

fn decode_attr_value_tag_matrix(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    let vals = decode_matrix_values(context.value_raw)?;
    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::TypedNumbers {
            value_type: "matrix".to_string(),
            values: vals,
        },
    ))
}

fn decode_attr_value_tag_component_list(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    decode_component_list_attr(context.value_raw).map(|components| {
        build_setattr_op(
            context,
            None,
            None,
            None,
            SetAttrValue::ComponentList(components),
        )
    })
}

fn decode_attr_value_tag_nurbs_curve(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    let parsed = parse_nurbs_curve_value_raw(context.kind, context.value_raw)?;

    Some(build_setattr_op(
        context,
        None,
        None,
        None,
        SetAttrValue::NurbsCurve {
            degree: parsed.degree,
            spans: parsed.spans,
            form: parsed.form,
            is_rational: parsed.is_rational,
            dimension: parsed.dimension,
            knots: parsed.knots,
            cvs: parsed.cvs,
        },
    ))
}

fn decode_attr_value_tag_refe_bridge(context: &AttrValueDecodeContext<'_>) -> Option<SetAttrOp> {
    if matches!(context.handler_id, AttrValueHandlerId::RefeBridge) && context.attr_name == "ed" {
        return None;
    }
    None
}

#[cfg(test)]
pub(crate) fn decode_attr_value_chunk_to_outcome(tag: &str, payload: &[u8]) -> AttrDecodeOutcome {
    let Some((attr_name, kind, value_raw)) = decode_attr_payload(payload) else {
        return AttrDecodeOutcome::Unsupported {
            tag: tag.to_string(),
            attr_name: "<decode_attr_payload_failed>".to_string(),
            kind: 0,
            payload_size: payload.len(),
        };
    };

    match decode_attr_value_chunk_to_setattr(tag, payload) {
        Some(op) => AttrDecodeOutcome::SetAttr(op),
        None => AttrDecodeOutcome::Unsupported {
            tag: tag.to_string(),
            attr_name,
            kind,
            payload_size: value_raw.len(),
        },
    }
}

fn decode_skincluster_weightlist_attr(
    attr_name: &str,
    value_raw: &[u8],
) -> Option<Vec<SkinWeightRow>> {
    let (start, end) = if let Some(caps) = SKIN_WEIGHT_LIST_RANGE_RE.captures(attr_name) {
        let start = caps.get(1)?.as_str().parse::<usize>().ok()?;
        let end = caps.get(2)?.as_str().parse::<usize>().ok()?;
        (start.min(end), start.max(end))
    } else if let Some(caps) = SKIN_WEIGHT_LIST_SINGLE_RE.captures(attr_name) {
        let idx = caps.get(1)?.as_str().parse::<usize>().ok()?;
        (idx, idx)
    } else {
        return None;
    };

    let expected_rows = end - start + 1;
    let mut cursor = 0usize;
    let mut rows = Vec::with_capacity(expected_rows);

    for _ in 0..expected_rows {
        if cursor + 4 > value_raw.len() {
            return None;
        }
        let pair_count =
            u32::from_be_bytes(value_raw[cursor..cursor + 4].try_into().ok()?) as usize;
        cursor += 4;

        let mut pairs = Vec::with_capacity(pair_count);
        for _ in 0..pair_count {
            if cursor + 12 > value_raw.len() {
                return None;
            }
            let influence_index =
                u32::from_be_bytes(value_raw[cursor..cursor + 4].try_into().ok()?) as usize;
            cursor += 4;
            let weight = f64::from_bits(u64::from_be_bytes(
                value_raw[cursor..cursor + 8].try_into().ok()?,
            ));
            cursor += 8;

            pairs.push(SkinWeightPair {
                influence_index,
                weight: numeric_f64(weight),
            });
        }

        rows.push(SkinWeightRow { pairs });
    }

    if cursor != value_raw.len() && !value_raw[cursor..].iter().all(|b| *b == 0) {
        return None;
    }

    if rows.is_empty() {
        return None;
    }

    Some(rows)
}
#[cfg(test)]
fn attr_value_handler_id_from_tag(tag: &str) -> Option<AttrValueHandlerId> {
    if let Some(kind) = TypedValueKind::from_binary_tag(tag) {
        return Some(AttrValueHandlerId::Typed(kind));
    }
    match tag {
        "FLGS" => Some(AttrValueHandlerId::Flgs),
        "DBLE" => Some(AttrValueHandlerId::Double),
        "CMPD" => Some(AttrValueHandlerId::Compound),
        "REFE" => Some(AttrValueHandlerId::RefeBridge),
        _ => None,
    }
}
