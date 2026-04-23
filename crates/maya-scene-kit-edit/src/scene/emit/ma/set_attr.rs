use std::{collections::HashMap, f64::consts::PI};

use maya_scene_kit_observe::scene::{
    model::{NumericValue, SetAttrOp, SetAttrValue},
    recovery::AngularAttrKind,
};

use crate::{
    scene::emit::ma::{
        format::{escape_ma_string, format_number, format_numeric_value},
        units::{AngularRenderUnit, TimeRenderContext},
    },
    typed_value_semantics::{TypedValueAngularRenderClass, TypedValueKind, TypedValueRenderClass},
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SetAttrRenderContext<'a> {
    pub(in crate::scene) time_render_context: Option<&'a TimeRenderContext>,
    pub(in crate::scene) angular_render_unit: AngularRenderUnit,
    pub(in crate::scene) angular_attrs: Option<&'a HashMap<String, AngularAttrKind>>,
}

pub(crate) fn render_set_attr_op_with_render_context(
    op: &SetAttrOp,
    render_context: SetAttrRenderContext<'_>,
) -> String {
    let mut prefix = String::from("setAttr");
    if let Some(size) = op.array_size {
        prefix.push_str(&format!(" -s {size}"));
    }
    if let Some(ch) = op.channel_hint {
        prefix.push_str(&format!(" -ch {ch}"));
    }
    if let Some(lock) = op.lock {
        prefix.push_str(if lock { " -l on" } else { " -l off" });
    }
    if let Some(keyable) = op.keyable {
        prefix.push_str(if keyable { " -k on" } else { " -k off" });
    }
    prefix.push_str(&format!(" \"{}\"", escape_ma_string(&op.attr_name_or_path)));
    let angular_kind = resolve_angular_attr_kind(&op.attr_name_or_path, render_context);

    match &op.value {
        SetAttrValue::None => format!("{prefix};"),
        SetAttrValue::Scalar(value) => {
            let rendered = render_scalar_with_angular_unit(
                value,
                angular_kind,
                render_context.angular_render_unit,
            );
            format!("{prefix} {rendered};")
        }
        SetAttrValue::Numbers(values) => {
            if values.is_empty() {
                format!("{prefix};")
            } else if op.array_size.is_some() {
                format!(
                    "{prefix} {} ;",
                    values
                        .iter()
                        .copied()
                        .map(format_numeric_value)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            } else {
                format!(
                    "{prefix} {};",
                    values
                        .iter()
                        .copied()
                        .map(format_numeric_value)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
        }
        SetAttrValue::TypedNumbers { value_type, values } => {
            let converted = render_typed_numbers_with_angular_unit(
                value_type,
                values,
                angular_kind,
                render_context,
            );
            let tail = converted.join(" ");
            let render_class = TypedValueKind::from_name(value_type)
                .map(TypedValueKind::render_class)
                .unwrap_or(TypedValueRenderClass::StandardInline);
            if matches!(render_class, TypedValueRenderClass::TupleInline) {
                format!(
                    "{prefix} -type \"{}\" {tail} ;",
                    escape_ma_string(value_type)
                )
            } else {
                format!(
                    "{prefix} -type \"{}\" {tail};",
                    escape_ma_string(value_type)
                )
            }
        }
        SetAttrValue::PolyFaces {
            uv_set,
            faces,
            uv_faces,
        } => {
            let mut out = format!("{prefix} -type \"polyFaces\" \n");
            for (idx, face) in faces.iter().enumerate() {
                let mut face_tokens = vec![face.len().to_string()];
                face_tokens.extend(face.iter().map(ToString::to_string));
                out.push_str(&format!("\t\tf {}\n", face_tokens.join(" ")));

                let uv = uv_faces.get(idx).cloned().unwrap_or_default();
                let mut uv_tokens = vec![uv_set.to_string(), uv.len().to_string()];
                uv_tokens.extend(uv.iter().map(ToString::to_string));
                out.push_str(&format!("\t\tmu {}\n", uv_tokens.join(" ")));
            }
            out.push_str("\t\t;");
            out
        }
        SetAttrValue::String(value) => {
            format!("{prefix} -type \"string\" \"{}\";", escape_ma_string(value))
        }
        SetAttrValue::StringArray {
            declared_count,
            values,
        } => {
            if values.is_empty() {
                format!("{prefix} -type \"stringArray\" 0  ;")
            } else {
                let emitted_count = values.len();
                let quoted = values
                    .iter()
                    .map(|value| format!("\"{}\"", escape_ma_string(value)))
                    .collect::<Vec<_>>()
                    .join(" ");
                let count = if *declared_count == emitted_count {
                    *declared_count
                } else {
                    emitted_count
                };
                format!("{prefix} -type \"stringArray\" {count} {quoted} ;")
            }
        }
        SetAttrValue::Int32Array(values) => {
            let rendered = values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            format!("{prefix} -type \"Int32Array\" {} {rendered};", values.len())
        }
        SetAttrValue::ComponentList(values) => {
            let quoted = values
                .iter()
                .map(|value| format!("\"{}\"", escape_ma_string(value)))
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "{prefix} -type \"componentList\" {} {quoted};",
                values.len()
            )
        }
        SetAttrValue::SkinWeightRows(rows) => {
            let mut out = format!("{prefix}\n");
            for (idx, row) in rows.iter().enumerate() {
                let mut tokens = vec![row.pairs.len().to_string()];
                for pair in &row.pairs {
                    tokens.push(pair.influence_index.to_string());
                    tokens.push(format_numeric_value(pair.weight));
                }
                let suffix = if idx + 1 == rows.len() { ";" } else { "" };
                out.push_str(&format!("\t\t{}{}\n", tokens.join(" "), suffix));
            }
            out.trim_end().to_string()
        }
        SetAttrValue::TimeValuePairs(pairs) => {
            let rendered = pairs
                .iter()
                .map(|pair| {
                    let time_token =
                        render_time_ticks(pair.time_ticks, render_context.time_render_context);
                    format!("{time_token} {}", format_numeric_value(pair.value))
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!("{prefix} {rendered};")
        }
        SetAttrValue::NurbsCurve {
            degree,
            spans,
            form,
            is_rational,
            dimension,
            knots,
            cvs,
        } => {
            let mut out = format!("{prefix} -type \"nurbsCurve\" \n");
            let rational = if *is_rational { "yes" } else { "no" };
            out.push_str(&format!(
                "\t\t{degree} {spans} {form} {rational} {dimension}\n"
            ));
            let knot_values = if knots.is_empty() {
                String::new()
            } else {
                format!(
                    " {}",
                    knots
                        .iter()
                        .copied()
                        .map(format_numeric_value)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            };
            out.push_str(&format!("\t\t{}{}\n", knots.len(), knot_values));
            out.push_str(&format!("\t\t{}\n", cvs.len()));
            for cv in cvs {
                out.push_str(&format!(
                    "\t\t{}\n",
                    cv.iter()
                        .copied()
                        .map(format_numeric_value)
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
            out.push_str("\t\t;");
            out
        }
    }
}

fn render_scalar_with_angular_unit(
    value: &NumericValue,
    angular_kind: Option<AngularAttrKind>,
    angular_render_unit: AngularRenderUnit,
) -> String {
    if angular_render_unit != AngularRenderUnit::Degree || angular_kind.is_none() {
        return format_numeric_value(*value);
    }
    match value.as_f64() {
        Some(raw) => format_number(raw * 180.0 / PI),
        None => format_numeric_value(*value),
    }
}

fn render_typed_numbers_with_angular_unit(
    value_type: &str,
    values: &[NumericValue],
    angular_kind: Option<AngularAttrKind>,
    render_context: SetAttrRenderContext<'_>,
) -> Vec<String> {
    if render_context.angular_render_unit != AngularRenderUnit::Degree {
        return values.iter().copied().map(format_numeric_value).collect();
    }
    if !matches!(angular_kind, Some(AngularAttrKind::Vector3)) {
        return values.iter().copied().map(format_numeric_value).collect();
    }
    let Some(kind) = TypedValueKind::from_name(value_type) else {
        return values.iter().copied().map(format_numeric_value).collect();
    };
    if !matches!(
        kind.angular_render_class(),
        TypedValueAngularRenderClass::Vector3
    ) {
        return values.iter().copied().map(format_numeric_value).collect();
    }
    values
        .iter()
        .map(|token| match token.as_f64() {
            Some(raw) => format_number(raw * 180.0 / PI),
            None => format_numeric_value(*token),
        })
        .collect()
}

fn resolve_angular_attr_kind(
    attr_path: &str,
    render_context: SetAttrRenderContext<'_>,
) -> Option<AngularAttrKind> {
    let token = normalize_attr_leaf_token(attr_path)?;
    if let Some(attrs) = render_context.angular_attrs {
        if let Some(kind) = attrs.get(&token) {
            return Some(*kind);
        }
    }
    None
}

pub(super) fn normalize_attr_leaf_token(attr_path: &str) -> Option<String> {
    let mut token = attr_path.trim();
    if token.is_empty() {
        return None;
    }
    if let Some(stripped) = token.strip_prefix('.') {
        token = stripped;
    }
    if let Some(idx) = token.rfind('.') {
        token = &token[idx + 1..];
    }
    if let Some(idx) = token.find('[') {
        token = &token[..idx];
    }
    if token.is_empty() {
        None
    } else {
        Some(token.to_ascii_lowercase())
    }
}

fn render_time_ticks(ticks: i64, time_render_context: Option<&TimeRenderContext>) -> String {
    let Some(context) = time_render_context else {
        return ticks.to_string();
    };
    let units_per_second = context.unit.units_per_second();
    let units = (ticks as f64) * units_per_second / context.ticks_per_second;
    format_number(units)
}
