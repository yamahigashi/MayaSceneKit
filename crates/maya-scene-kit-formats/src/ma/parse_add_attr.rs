use super::parse_support::{normalized_arg_text, parse_numeric_token};
use crate::{
    addattr_semantics::add_attr_semantics,
    error::SceneToolError,
    ma::ast::{ParsedAddAttr, ParsedAddAttrDefaultValue},
    mel,
    model::{AddAttrValueSpec, FlagState},
};

fn parse_optional_bool_normalized_flag(
    source_text: &str,
    flag: &mel::MelNormalizedFlag,
    label: &str,
) -> Result<bool, SceneToolError> {
    match normalized_arg_text(source_text, flag.args.first()) {
        None => Ok(true),
        Some("on" | "yes" | "true" | "1") => Ok(true),
        Some("off" | "no" | "false" | "0") => Ok(false),
        Some(other) => Err(SceneToolError::Message(format!(
            "{label} expects boolean value, got {other}"
        ))),
    }
}

pub(super) fn parse_add_attr_specialized(
    source_text: &str,
    add_attr: &mel::MelSpecializedAddAttrCommand,
) -> Result<ParsedAddAttr, SceneToolError> {
    let mut short_name = None;
    let mut long_name = None;
    let mut parent = None;
    let mut number_of_children = None;
    let mut nice_name = None;
    let mut default_value = None;
    let mut min_value = None;
    let mut max_value = None;
    let mut soft_min_value = None;
    let mut soft_max_value = None;
    let mut enum_names = None;
    let mut used_as_color = false;
    let mut cached_internally = false;
    let mut hidden = false;
    let mut keyable = false;
    let mut multi = false;
    let mut index_matters = true;
    let mut value_spec = None;

    for flag in &add_attr.flags {
        let flag_name = flag.preferred_name(source_text);
        match flag_name {
            "shortName" | "-sn" => {
                short_name =
                    normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
            }
            "longName" | "-ln" => {
                long_name = normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
            }
            "parent" | "-p" => {
                parent = normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
            }
            "numberOfChildren" | "-nc" => {
                number_of_children = normalized_arg_text(source_text, flag.args.first())
                    .ok_or_else(|| {
                        SceneToolError::Message("addAttr -nc missing value".to_string())
                    })?
                    .parse::<u32>()
                    .map(Some)
                    .map_err(|_| {
                        SceneToolError::Message("addAttr -nc expects u32 value".to_string())
                    })?;
            }
            "niceName" | "-nn" => {
                nice_name = normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
            }
            "defaultValue" | "-dv" => {
                default_value = Some(parse_numeric_token(
                    normalized_arg_text(source_text, flag.args.first()).ok_or_else(|| {
                        SceneToolError::Message("addAttr -dv missing value".to_string())
                    })?,
                )?);
            }
            "minValue" | "-min" => {
                min_value = Some(parse_numeric_token(
                    normalized_arg_text(source_text, flag.args.first()).ok_or_else(|| {
                        SceneToolError::Message("addAttr -min missing value".to_string())
                    })?,
                )?);
            }
            "maxValue" | "-max" => {
                max_value = Some(parse_numeric_token(
                    normalized_arg_text(source_text, flag.args.first()).ok_or_else(|| {
                        SceneToolError::Message("addAttr -max missing value".to_string())
                    })?,
                )?);
            }
            "softMinValue" | "-smn" => {
                soft_min_value = Some(parse_numeric_token(
                    normalized_arg_text(source_text, flag.args.first()).ok_or_else(|| {
                        SceneToolError::Message("addAttr -smn missing value".to_string())
                    })?,
                )?);
            }
            "softMaxValue" | "-smx" => {
                soft_max_value = Some(parse_numeric_token(
                    normalized_arg_text(source_text, flag.args.first()).ok_or_else(|| {
                        SceneToolError::Message("addAttr -smx missing value".to_string())
                    })?,
                )?);
            }
            "enumName" | "-en" => {
                enum_names =
                    normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
            }
            "usedAsColor" | "-uac" => {
                used_as_color =
                    parse_optional_bool_normalized_flag(source_text, flag, "addAttr -uac")?;
            }
            "cachedInternally" | "-ci" => {
                cached_internally =
                    parse_optional_bool_normalized_flag(source_text, flag, "addAttr -ci")?;
            }
            "hidden" | "-h" => {
                hidden = parse_optional_bool_normalized_flag(source_text, flag, "addAttr -h")?;
            }
            "keyable" | "-k" => {
                keyable = parse_optional_bool_normalized_flag(source_text, flag, "addAttr -k")?;
            }
            "multi" | "-m" => {
                multi = parse_optional_bool_normalized_flag(source_text, flag, "addAttr -m")?;
            }
            "indexMatters" | "-im" => {
                index_matters =
                    parse_optional_bool_normalized_flag(source_text, flag, "addAttr -im")?;
            }
            "attributeType" | "-at" => {
                let attr_type =
                    normalized_arg_text(source_text, flag.args.first()).ok_or_else(|| {
                        SceneToolError::Message("addAttr -at missing type token".to_string())
                    })?;
                value_spec = Some(AddAttrValueSpec::AttrType(attr_type.to_string()));
            }
            "dataType" | "-dt" => {
                let data_type =
                    normalized_arg_text(source_text, flag.args.first()).ok_or_else(|| {
                        SceneToolError::Message("addAttr -dt missing type token".to_string())
                    })?;
                value_spec = Some(AddAttrValueSpec::DataType(data_type.to_string()));
            }
            _ => {}
        }
    }

    let short_name = short_name
        .ok_or_else(|| SceneToolError::Message("addAttr missing -sn short name".to_string()))?;
    let long_name = long_name
        .ok_or_else(|| SceneToolError::Message("addAttr missing -ln long name".to_string()))?;
    let value_spec = value_spec
        .ok_or_else(|| SceneToolError::Message("addAttr missing -at/-dt type".to_string()))?;
    let semantics = add_attr_semantics(&value_spec);

    Ok(ParsedAddAttr {
        attr_name: long_name.clone(),
        short_name,
        long_name,
        parent,
        number_of_children,
        nice_name,
        type_token: String::new(),
        header_raw: [0; 11],
        disconnect_behaviour: Some(2),
        used_as_proxy: false,
        used_as_color,
        storable: FlagState::True,
        readable: FlagState::True,
        writable: FlagState::True,
        cached_internally: FlagState::from_bool(cached_internally),
        hidden: FlagState::from_bool(hidden),
        keyable: FlagState::from_bool(keyable),
        multi: FlagState::from_bool(multi),
        index_matters: if multi {
            FlagState::from_bool(index_matters)
        } else {
            FlagState::Unknown
        },
        internal_set: FlagState::False,
        default_value: if semantics.allows_explicit_default_min_max() {
            default_value.map(|value| ParsedAddAttrDefaultValue { value })
        } else {
            None
        },
        min_value: if semantics.allows_explicit_default_min_max() {
            min_value
        } else {
            None
        },
        max_value: if semantics.allows_explicit_default_min_max() {
            max_value
        } else {
            None
        },
        soft_min_value: if semantics.allows_soft_range() {
            soft_min_value
        } else {
            None
        },
        soft_max_value: if semantics.allows_soft_range() {
            soft_max_value
        } else {
            None
        },
        enum_names: if semantics.allows_enum_names() {
            enum_names
        } else {
            None
        },
        value_spec,
    })
}

pub(super) fn parse_top_level_add_attr_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
) -> Result<ParsedAddAttr, SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::AddAttr(add_attr)) = command.specialized.as_ref()
    else {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported addAttr form in Maya ASCII scenes".to_string(),
        ));
    };
    parse_add_attr_specialized(source_text, add_attr)
}

#[cfg(test)]
mod tests {
    use super::super::parse_ascii_scene;
    use crate::{
        ma::ast::ParsedNodeOp,
        model::{AddAttrValueSpec, NumericValue},
    };

    #[test]
    fn parse_add_attr_applies_shared_numeric_and_enum_tail_semantics() {
        let scene = parse_ascii_scene(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode transform -n \"node1\";\n",
                "    addAttr -ln \"state\" -sn \"st\" -at \"enum\" -en \"A:B:C\" -dv 2 -min 1 -max 3;\n",
                "    addAttr -ln \"flag\" -sn \"flg\" -at \"bool\" -dv 1 -min 0 -max 1 -smn 0 -smx 1;\n",
                "    addAttr -ln \"messageAttr\" -sn \"msg\" -at \"message\" -dv 9 -min 4 -max 7 -en \"ignored\";\n",
            ),
        )
        .expect("parse");

        let ops = &scene.nodes[0].ops;

        let ParsedNodeOp::AddAttr(enum_op) = &ops[0] else {
            panic!("expected addAttr op");
        };
        assert_eq!(
            enum_op.value_spec,
            AddAttrValueSpec::AttrType("enum".to_string())
        );
        assert_eq!(enum_op.enum_names.as_deref(), Some("A:B:C"));
        assert_eq!(
            enum_op.default_value.as_ref().map(|value| value.value),
            Some(NumericValue::from_f64(2.0))
        );
        assert_eq!(enum_op.min_value, Some(NumericValue::from_f64(1.0)));
        assert_eq!(enum_op.max_value, Some(NumericValue::from_f64(3.0)));
        assert_eq!(enum_op.soft_min_value, None);
        assert_eq!(enum_op.soft_max_value, None);

        let ParsedNodeOp::AddAttr(bool_op) = &ops[1] else {
            panic!("expected addAttr op");
        };
        assert_eq!(
            bool_op.value_spec,
            AddAttrValueSpec::AttrType("bool".to_string())
        );
        assert_eq!(
            bool_op.default_value.as_ref().map(|value| value.value),
            Some(NumericValue::from_f64(1.0))
        );
        assert_eq!(bool_op.min_value, Some(NumericValue::from_f64(0.0)));
        assert_eq!(bool_op.max_value, Some(NumericValue::from_f64(1.0)));
        assert_eq!(bool_op.soft_min_value, Some(NumericValue::from_f64(0.0)));
        assert_eq!(bool_op.soft_max_value, Some(NumericValue::from_f64(1.0)));
        assert_eq!(bool_op.enum_names, None);

        let ParsedNodeOp::AddAttr(message_op) = &ops[2] else {
            panic!("expected addAttr op");
        };
        assert_eq!(
            message_op.value_spec,
            AddAttrValueSpec::AttrType("message".to_string())
        );
        assert_eq!(message_op.default_value, None);
        assert_eq!(message_op.min_value, None);
        assert_eq!(message_op.max_value, None);
        assert_eq!(message_op.enum_names, None);
    }

    #[test]
    fn parse_add_attr_accepts_boolean_shorthand_flags() {
        let scene = parse_ascii_scene(concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode transform -n \"node1\";\n",
            "    addAttr -ci true -m -k -sn \"items\" -ln \"items\" -at \"message\";\n",
        ))
        .expect("parse");

        let ParsedNodeOp::AddAttr(op) = &scene.nodes[0].ops[0] else {
            panic!("expected addAttr op");
        };
        assert_eq!(op.cached_internally, crate::model::FlagState::True);
        assert_eq!(op.multi, crate::model::FlagState::True);
        assert_eq!(op.keyable, crate::model::FlagState::True);
    }
}
