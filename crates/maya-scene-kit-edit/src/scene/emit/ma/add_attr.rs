use maya_scene_kit_observe::scene::model::{AddAttrOp, AddAttrValueSpec, FlagState};

use crate::scene::emit::ma::format::{escape_ma_string, format_numeric_value};

pub(crate) fn render_add_attr_op(op: &AddAttrOp) -> Option<String> {
    if !op.is_emittable() {
        return None;
    }

    let mut parts = vec!["addAttr".to_string()];
    if let Some(disconnect_behaviour) = op.disconnect_behaviour {
        if disconnect_behaviour != 2 {
            parts.push(format!("-dcb {disconnect_behaviour}"));
        }
    }
    if op.used_as_proxy {
        parts.push("-uap".to_string());
    }
    if op.used_as_color {
        parts.push("-uac".to_string());
    }
    if op.storable.is_false() {
        parts.push("-s false".to_string());
    }
    if op.readable.is_false() {
        parts.push("-r false".to_string());
    }
    if op.writable.is_false() {
        parts.push("-w false".to_string());
    }
    if op.cached_internally.is_true() {
        parts.push("-ci true".to_string());
    }
    if op.internal_set.is_true() {
        parts.push("-is true".to_string());
    }
    if op.hidden.is_true() {
        parts.push("-h true".to_string());
    }
    if op.keyable.is_true() {
        parts.push("-k true".to_string());
    }
    if op.multi.is_true() {
        parts.push("-m".to_string());
    }
    if op.index_matters == FlagState::False {
        parts.push("-im false".to_string());
    }
    parts.push(format!("-sn \"{}\"", escape_ma_string(&op.short_name)));
    parts.push(format!("-ln \"{}\"", escape_ma_string(&op.long_name)));
    if let Some(nice_name) = &op.nice_name {
        parts.push(format!("-nn \"{}\"", escape_ma_string(nice_name)));
    }
    if let Some(default_value) = &op.default_value {
        parts.push(format!("-dv {}", format_numeric_value(default_value.value)));
    }
    if let Some(min_value) = &op.min_value {
        parts.push(format!("-min {}", format_numeric_value(*min_value)));
    }
    if let Some(max_value) = &op.max_value {
        parts.push(format!("-max {}", format_numeric_value(*max_value)));
    }
    if let Some(soft_min_value) = &op.soft_min_value {
        parts.push(format!("-smn {}", format_numeric_value(*soft_min_value)));
    }
    if let Some(soft_max_value) = &op.soft_max_value {
        parts.push(format!("-smx {}", format_numeric_value(*soft_max_value)));
    }
    match &op.value_spec {
        AddAttrValueSpec::AttrType(attr_type) => {
            parts.push(format!("-at \"{}\"", escape_ma_string(attr_type)));
            if attr_type == "enum" {
                if let Some(enum_names) = &op.enum_names {
                    parts.push(format!("-en \"{}\"", escape_ma_string(enum_names)));
                }
            }
        }
        AddAttrValueSpec::DataType(data_type) => {
            parts.push(format!("-dt \"{}\"", escape_ma_string(data_type)));
        }
        AddAttrValueSpec::UnknownToken { .. } => return None,
    }
    if let Some(number_of_children) = op.number_of_children {
        parts.push(format!("-nc {number_of_children}"));
    }
    if let Some(parent) = &op.parent {
        parts.push(format!("-p \"{}\"", escape_ma_string(parent)));
    }
    Some(format!("{};", parts.join(" ")))
}
