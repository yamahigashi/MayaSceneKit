use super::parse_support::{flag_matches, parse_numeric_token, raw_item_text};
#[cfg(test)]
use crate::ma::commands::{
    FlagCommandKind, Token, bare_token, command_flag_descriptor, token_text,
};
#[cfg(test)]
use crate::ma::values::parse_bool_token;
#[cfg(test)]
use crate::ma::values::parse_usize_token;
use crate::{
    error::SceneToolError,
    ma::ast::{
        ParsedAsciiRefEdit, ParsedAsciiRefEditGroup, ParsedAsciiRefEditRecord,
        ParsedOpaqueValueItem, ParsedSetAttr, ParsedSetAttrValue,
    },
    mel,
    typed_value_semantics::TypedValueKind,
};

pub(super) fn parse_specialized_set_attr_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
) -> Result<Option<ParsedSetAttr>, SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::SetAttr(set_attr)) = command.specialized.as_ref()
    else {
        return Ok(None);
    };
    let mut array_size = None;
    let mut channel_hint = None;
    let mut lock = None;
    let mut keyable = None;
    let mut value_type: Option<String> = None;

    for flag in &set_attr.flags {
        if flag_matches(source_text, flag, "size", "-s") {
            array_size = Some(parse_normalized_usize_arg(
                source_text,
                flag.args.first(),
                "-s",
            )?);
        } else if flag_matches(source_text, flag, "channelHint", "-ch")
            || flag_matches(source_text, flag, "channel", "-ch")
        {
            channel_hint = Some(parse_normalized_usize_arg(
                source_text,
                flag.args.first(),
                "-ch",
            )?);
        } else if flag_matches(source_text, flag, "lock", "-l") {
            lock = Some(parse_normalized_bool_arg(
                source_text,
                flag.args.first(),
                "-l",
            )?);
        } else if flag_matches(source_text, flag, "keyable", "-k") {
            keyable = Some(parse_normalized_bool_arg(
                source_text,
                flag.args.first(),
                "-k",
            )?);
        } else if flag_matches(source_text, flag, "type", "-type") {
            value_type = normalized_arg_value(source_text, flag.args.first());
        }
    }

    let attr_name_or_path = raw_item_text(source_text, set_attr.attr_path.as_ref())
        .map(|text| text.into_owned())
        .ok_or_else(|| {
            SceneToolError::Message("specialized setAttr missing attribute path".to_string())
        })?;
    let value = if matches!(
        set_attr.value_kind,
        mel::MelSetAttrValueKind::DataReferenceEdits
    ) {
        parse_data_reference_edits_raw_items(source_text, &set_attr.values)?
    } else if value_type.is_none() {
        if let Some(inferred_type) =
            infer_opaque_set_attr_type_raw_items(source_text, &attr_name_or_path, &set_attr.values)
        {
            parse_opaque_typed_value_raw_items(source_text, inferred_type, &set_attr.values)
        } else {
            parse_untyped_value_raw_items(source_text, &set_attr.values)?
        }
    } else {
        match value_type.as_deref().and_then(TypedValueKind::from_name) {
            Some(TypedValueKind::String) => parse_specialized_string_value(source_text, set_attr)?,
            Some(TypedValueKind::StringArray) => {
                parse_string_array_value_raw_items(source_text, &set_attr.values)?
            }
            Some(TypedValueKind::Int32Array) => {
                parse_int32_array_value_raw_items(source_text, &set_attr.values)?
            }
            Some(kind) if kind.supports_typed_numeric_payload() => {
                parse_typed_number_or_opaque_value_raw_items(
                    source_text,
                    kind.name(),
                    &set_attr.values,
                )?
            }
            Some(TypedValueKind::ComponentList) => {
                parse_component_list_value_raw_items(source_text, &set_attr.values)?
            }
            Some(TypedValueKind::PolyFaces)
            | Some(TypedValueKind::NurbsCurve)
            | Some(TypedValueKind::DataPolyComponent) => parse_opaque_typed_value_raw_items(
                source_text,
                value_type
                    .as_deref()
                    .expect("typed opaque setAttr must have a value type"),
                &set_attr.values,
            ),
            Some(kind) => {
                return Err(SceneToolError::UnsupportedAsciiFeature(format!(
                    "unsupported setAttr value type: {}",
                    kind.name()
                )));
            }
            None => {
                let other = value_type
                    .as_deref()
                    .expect("unsupported specialized setAttr type");
                return Err(SceneToolError::UnsupportedAsciiFeature(format!(
                    "unsupported setAttr value type: {other}"
                )));
            }
        }
    };

    Ok(Some(ParsedSetAttr {
        attr_name_or_path,
        array_size,
        channel_hint,
        lock,
        keyable,
        value,
    }))
}

#[cfg(test)]
pub(super) fn parse_set_attr_command(tokens: &[Token]) -> Result<ParsedSetAttr, SceneToolError> {
    let mut array_size = None;
    let mut channel_hint = None;
    let mut lock = None;
    let mut keyable = None;
    let mut value_type = None;

    let attr_index = tokens
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(idx, token)| matches!(token, Token::Quoted(_)).then_some(idx))
        .ok_or_else(|| SceneToolError::Message("setAttr missing attribute path".to_string()))?;

    let mut idx = 1usize;
    while idx < attr_index {
        let Some(flag) = bare_token(&tokens[idx]) else {
            break;
        };
        if command_flag_descriptor(FlagCommandKind::SetAttr, flag).is_none() {
            break;
        }
        match flag {
            "-s" => {
                array_size = Some(parse_usize_token(tokens.get(idx + 1), "-s")?);
                idx += 2;
            }
            "-ch" => {
                channel_hint = Some(parse_usize_token(tokens.get(idx + 1), "-ch")?);
                idx += 2;
            }
            "-l" => {
                lock = Some(parse_bool_token(tokens.get(idx + 1), "-l")?);
                idx += 2;
            }
            "-k" => {
                keyable = Some(parse_bool_token(tokens.get(idx + 1), "-k")?);
                idx += 2;
            }
            "-type" => {
                value_type = tokens.get(idx + 1).and_then(token_text).map(str::to_string);
                idx += 2;
            }
            _ => break,
        }
    }

    let attr_name_or_path = tokens
        .get(attr_index)
        .and_then(token_text)
        .map(str::to_string)
        .ok_or_else(|| SceneToolError::Message("setAttr missing attribute path".to_string()))?;
    idx = attr_index + 1;
    while idx < tokens.len() {
        let Some(flag) = bare_token(&tokens[idx]) else {
            break;
        };
        if !flag.starts_with('-') {
            break;
        }
        if command_flag_descriptor(FlagCommandKind::SetAttr, flag).is_none() {
            break;
        }
        match flag {
            "-s" => {
                array_size = Some(parse_usize_token(tokens.get(idx + 1), "-s")?);
                idx += 2;
            }
            "-ch" => {
                channel_hint = Some(parse_usize_token(tokens.get(idx + 1), "-ch")?);
                idx += 2;
            }
            "-l" => {
                lock = Some(parse_bool_token(tokens.get(idx + 1), "-l")?);
                idx += 2;
            }
            "-k" => {
                keyable = Some(parse_bool_token(tokens.get(idx + 1), "-k")?);
                idx += 2;
            }
            "-type" => {
                value_type = tokens.get(idx + 1).and_then(token_text).map(str::to_string);
                idx += 2;
            }
            _ => break,
        }
    }

    let value_tokens = &tokens[idx..];
    if matches!(value_type.as_deref(), Some("dataReferenceEdits")) {
        return Ok(ParsedSetAttr {
            attr_name_or_path,
            array_size,
            channel_hint,
            lock,
            keyable,
            value: parse_data_reference_edits_value(value_tokens)?,
        });
    }
    if value_type.is_none() {
        if let Some(inferred_type) = infer_opaque_set_attr_type(&attr_name_or_path, value_tokens) {
            return Ok(ParsedSetAttr {
                attr_name_or_path,
                array_size,
                channel_hint,
                lock,
                keyable,
                value: parse_opaque_typed_value(inferred_type, value_tokens),
            });
        }
    }

    let value = match value_type.as_deref().and_then(TypedValueKind::from_name) {
        Some(TypedValueKind::String) => parse_string_value(value_tokens)?,
        Some(TypedValueKind::StringArray) => parse_string_array_value(value_tokens)?,
        Some(TypedValueKind::Int32Array) => parse_int32_array_value(value_tokens)?,
        Some(kind) if kind.supports_typed_numeric_payload() => {
            parse_typed_number_or_opaque_value(kind.name(), value_tokens)?
        }
        Some(TypedValueKind::ComponentList) => parse_component_list_value(value_tokens)?,
        Some(TypedValueKind::PolyFaces)
        | Some(TypedValueKind::NurbsCurve)
        | Some(TypedValueKind::DataPolyComponent) => parse_opaque_typed_value(
            value_type
                .as_deref()
                .expect("typed opaque setAttr must have a value type"),
            value_tokens,
        ),
        Some(kind) => {
            return Err(SceneToolError::UnsupportedAsciiFeature(format!(
                "unsupported setAttr value type: {}",
                kind.name()
            )));
        }
        None => {
            if let Some(other) = value_type.as_deref() {
                return Err(SceneToolError::UnsupportedAsciiFeature(format!(
                    "unsupported setAttr value type: {other}"
                )));
            }
            parse_untyped_value(value_tokens)?
        }
    };

    Ok(ParsedSetAttr {
        attr_name_or_path,
        array_size,
        channel_hint,
        lock,
        keyable,
        value,
    })
}

fn parse_specialized_string_value(
    source_text: &str,
    set_attr: &mel::MelSpecializedSetAttrCommand,
) -> Result<ParsedSetAttrValue, SceneToolError> {
    match set_attr.values.as_slice() {
        [] => Ok(ParsedSetAttrValue::String(String::new())),
        [item] if item.value_text(source_text).is_some() => Ok(ParsedSetAttrValue::String(
            item.value_text(source_text)
                .expect("guarded simple raw string item")
                .into_owned(),
        )),
        _ => {
            let expression = set_attr
                .values
                .first()
                .map(|item| item.source_text(source_text))
                .unwrap_or_default();
            Ok(ParsedSetAttrValue::String(
                parse_parenthesized_string_concat_expression(expression)?,
            ))
        }
    }
}

fn parse_parenthesized_string_concat_expression(
    expression: &str,
) -> Result<String, SceneToolError> {
    let mut chars = expression.trim().chars().peekable();
    match chars.next() {
        Some('(') => {}
        _ => {
            return Err(SceneToolError::UnsupportedAsciiFeature(
                "unsupported setAttr string expression in Maya ASCII scenes".to_string(),
            ));
        }
    }

    let mut value = String::new();
    let mut expect_term = true;
    loop {
        while matches!(chars.peek(), Some(ch) if ch.is_whitespace()) {
            chars.next();
        }

        let Some(ch) = chars.next() else {
            break;
        };

        if expect_term {
            match ch {
                '"' => value.push_str(&parse_double_quoted_string_literal(&mut chars)?),
                ')' => break,
                _ => {
                    return Err(SceneToolError::UnsupportedAsciiFeature(
                        "unsupported setAttr string expression in Maya ASCII scenes".to_string(),
                    ));
                }
            }
            expect_term = false;
            continue;
        }

        match ch {
            '+' => expect_term = true,
            ')' => break,
            _ if ch.is_whitespace() => {}
            _ => {
                return Err(SceneToolError::UnsupportedAsciiFeature(
                    "unsupported setAttr string expression in Maya ASCII scenes".to_string(),
                ));
            }
        }
    }

    while matches!(chars.peek(), Some(ch) if ch.is_whitespace()) {
        chars.next();
    }
    if chars.next().is_some() || expect_term {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported setAttr string expression in Maya ASCII scenes".to_string(),
        ));
    }

    Ok(value)
}

fn parse_double_quoted_string_literal(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<String, SceneToolError> {
    let mut value = String::new();
    let mut escape = false;

    for ch in chars.by_ref() {
        if escape {
            match ch {
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                other => {
                    value.push('\\');
                    value.push(other);
                }
            }
            escape = false;
            continue;
        }

        match ch {
            '\\' => escape = true,
            '"' => return Ok(value),
            _ => value.push(ch),
        }
    }

    Err(SceneToolError::UnsupportedAsciiFeature(
        "unsupported setAttr string expression in Maya ASCII scenes".to_string(),
    ))
}

fn raw_item_scalar_text<'a>(
    source_text: &'a str,
    item: &'a mel::MelRawShellItem,
    label: &str,
) -> Result<std::borrow::Cow<'a, str>, SceneToolError> {
    let value = item.preferred_text(source_text);
    if value.is_empty() {
        return Err(SceneToolError::Message(format!("{label} missing value")));
    }
    Ok(value)
}

fn parse_opaque_typed_value_raw_items(
    source_text: &str,
    value_type: &str,
    items: &[mel::MelRawShellItem],
) -> ParsedSetAttrValue {
    ParsedSetAttrValue::OpaqueTyped {
        value_type: value_type.to_string(),
        items: items
            .iter()
            .map(|item| match item.kind {
                mel::MelRawShellItemKind::Quoted => {
                    ParsedOpaqueValueItem::Quoted(item.preferred_text(source_text).into_owned())
                }
                mel::MelRawShellItemKind::Flag
                | mel::MelRawShellItemKind::Numeric
                | mel::MelRawShellItemKind::Bare
                | mel::MelRawShellItemKind::Dynamic => {
                    ParsedOpaqueValueItem::Bare(item.preferred_text(source_text).into_owned())
                }
            })
            .collect(),
    }
}

fn infer_opaque_set_attr_type_raw_items<'a>(
    source_text: &'a str,
    attr_name_or_path: &str,
    items: &'a [mel::MelRawShellItem],
) -> Option<&'static str> {
    let first = items.first()?;
    let first_bare = match first.kind {
        mel::MelRawShellItemKind::Quoted => return None,
        _ => first.preferred_text(source_text),
    };
    (attr_name_or_path.starts_with(".fc[") && matches!(first_bare.as_ref(), "f" | "mu" | "mc"))
        .then_some("polyFaces")
}

fn normalized_arg_value(
    source_text: &str,
    arg: Option<&mel::MelNormalizedPositionalArg>,
) -> Option<String> {
    let arg = arg?;
    arg.literal.as_deref().map(str::to_string).or_else(|| {
        let trimmed = arg.text(source_text).trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn parse_normalized_usize_arg(
    source_text: &str,
    arg: Option<&mel::MelNormalizedPositionalArg>,
    label: &str,
) -> Result<usize, SceneToolError> {
    normalized_arg_value(source_text, arg)
        .ok_or_else(|| SceneToolError::AsciiSyntax(format!("{label} missing numeric value")))?
        .parse::<usize>()
        .map_err(|_| SceneToolError::AsciiSyntax(format!("{label} invalid numeric value")))
}

fn parse_normalized_bool_arg(
    source_text: &str,
    arg: Option<&mel::MelNormalizedPositionalArg>,
    label: &str,
) -> Result<bool, SceneToolError> {
    match normalized_arg_value(source_text, arg).as_deref() {
        Some("on" | "yes" | "true" | "1") => Ok(true),
        Some("off" | "no" | "false" | "0") => Ok(false),
        Some(other) => Err(SceneToolError::Message(format!(
            "{label} expects boolean value, got {other}"
        ))),
        None => Err(SceneToolError::Message(format!(
            "{label} is missing a boolean value"
        ))),
    }
}

#[cfg(test)]
fn parse_opaque_typed_value(value_type: &str, tokens: &[Token]) -> ParsedSetAttrValue {
    ParsedSetAttrValue::OpaqueTyped {
        value_type: value_type.to_string(),
        items: tokens
            .iter()
            .map(|token| match token {
                Token::Bare(value) => ParsedOpaqueValueItem::Bare(value.clone()),
                Token::Quoted(value) => ParsedOpaqueValueItem::Quoted(value.clone()),
                Token::Symbol(ch) => ParsedOpaqueValueItem::Symbol(*ch),
            })
            .collect(),
    }
}

#[cfg(test)]
fn infer_opaque_set_attr_type<'a>(attr_name_or_path: &str, tokens: &'a [Token]) -> Option<&'a str> {
    let first_bare = tokens.first().and_then(bare_token)?;
    (attr_name_or_path.starts_with(".fc[") && matches!(first_bare, "f" | "mu" | "mc"))
        .then_some("polyFaces")
}

#[cfg(test)]
fn parse_data_reference_edits_value(
    tokens: &[Token],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    let root_node = tokens
        .first()
        .and_then(token_text)
        .map(str::to_string)
        .ok_or_else(|| {
            SceneToolError::Message(
                "dataReferenceEdits setAttr missing root node token".to_string(),
            )
        })?;

    let mut groups = Vec::new();
    let mut idx = 1usize;
    while idx < tokens.len() {
        let Some(group_name) = tokens.get(idx).and_then(token_text).map(str::to_string) else {
            return Err(SceneToolError::Message(
                "dataReferenceEdits group header missing group name".to_string(),
            ));
        };
        let expected_count = parse_refedit_u32_token(
            tokens.get(idx + 1),
            "dataReferenceEdits group header missing expected count",
        )?;
        idx += 2;

        let mut records = Vec::new();
        while idx < tokens.len() && !is_data_reference_edits_group_header(tokens, idx) {
            let (record, next_idx) = parse_data_reference_edits_record(tokens, idx)?;
            records.push(record);
            idx = next_idx;
        }

        groups.push(ParsedAsciiRefEditGroup {
            name: group_name,
            expected_count,
            records,
        });
    }

    Ok(ParsedSetAttrValue::DataReferenceEdits(ParsedAsciiRefEdit {
        root_node,
        groups,
    }))
}

fn parse_data_reference_edits_raw_items(
    source_text: &str,
    items: &[mel::MelRawShellItem],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    let root_node = items
        .first()
        .ok_or_else(|| {
            SceneToolError::Message(
                "dataReferenceEdits specialized form missing root node token".to_string(),
            )
        })
        .and_then(|item| {
            refedit_item_value(
                source_text,
                item,
                "dataReferenceEdits specialized form missing root node token",
            )
        })?;

    let mut groups = Vec::new();
    let mut idx = 1usize;
    while idx < items.len() {
        let group_name = refedit_item_value(
            source_text,
            items.get(idx).ok_or_else(|| {
                SceneToolError::Message(
                    "dataReferenceEdits group header missing group name".to_string(),
                )
            })?,
            "dataReferenceEdits group header missing group name",
        )?;
        let expected_count = parse_refedit_u32_item(
            source_text,
            items.get(idx + 1),
            "dataReferenceEdits group header missing expected count",
        )?;
        idx += 2;

        let mut records = Vec::new();
        while idx < items.len()
            && !is_data_reference_edits_raw_group_header(source_text, items, idx)
        {
            let (record, next_idx) =
                parse_data_reference_edits_raw_record(source_text, items, idx)?;
            records.push(record);
            idx = next_idx;
        }

        groups.push(ParsedAsciiRefEditGroup {
            name: group_name,
            expected_count,
            records,
        });
    }

    Ok(ParsedSetAttrValue::DataReferenceEdits(ParsedAsciiRefEdit {
        root_node,
        groups,
    }))
}

#[cfg(test)]
fn is_data_reference_edits_group_header(tokens: &[Token], idx: usize) -> bool {
    matches!(tokens.get(idx), Some(Token::Quoted(value)) if is_data_reference_edits_group_name(value))
        && tokens
            .get(idx + 1)
            .and_then(token_text)
            .and_then(|value| value.parse::<u32>().ok())
            .is_some()
}

fn is_data_reference_edits_raw_group_header(
    source_text: &str,
    items: &[mel::MelRawShellItem],
    idx: usize,
) -> bool {
    matches!(
        items.get(idx),
        Some(mel::MelRawShellItem {
            kind: mel::MelRawShellItemKind::Quoted,
            ..
        })
    ) && items
        .get(idx)
        .and_then(|item| item.value_text(source_text))
        .as_deref()
        .is_some_and(is_data_reference_edits_group_name)
        && items
            .get(idx + 1)
            .and_then(|item| item.value_text(source_text))
            .as_deref()
            .and_then(|value| value.parse::<u32>().ok())
            .is_some()
}

fn is_data_reference_edits_group_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':'))
}

#[cfg(test)]
fn parse_data_reference_edits_record(
    tokens: &[Token],
    idx: usize,
) -> Result<(ParsedAsciiRefEditRecord, usize), SceneToolError> {
    let opcode =
        parse_refedit_u32_token(tokens.get(idx), "dataReferenceEdits record missing opcode")?;
    let mut next_idx = idx + 1;

    let record = match opcode {
        0 => ParsedAsciiRefEditRecord::Op0(
            parse_refedit_string_token(
                tokens.get(next_idx),
                "dataReferenceEdits op0 missing first argument",
            )?,
            parse_refedit_string_token(
                tokens.get(next_idx + 1),
                "dataReferenceEdits op0 missing second argument",
            )?,
            parse_refedit_string_token(
                tokens.get(next_idx + 2),
                "dataReferenceEdits op0 missing third argument",
            )?,
        ),
        1 => {
            let mut args = Vec::new();
            while next_idx < tokens.len()
                && !is_data_reference_edits_group_header(tokens, next_idx)
                && !matches!(
                    tokens.get(next_idx),
                    Some(Token::Bare(value)) if value.parse::<u32>().is_ok()
                )
            {
                args.push(parse_refedit_string_token(
                    tokens.get(next_idx),
                    "dataReferenceEdits op1 missing argument",
                )?);
                next_idx += 1;
            }
            return Ok((ParsedAsciiRefEditRecord::Op1(args), next_idx));
        }
        2 => ParsedAsciiRefEditRecord::Op2(
            parse_refedit_string_token(
                tokens.get(next_idx),
                "dataReferenceEdits op2 missing first argument",
            )?,
            parse_refedit_string_token(
                tokens.get(next_idx + 1),
                "dataReferenceEdits op2 missing second argument",
            )?,
            parse_refedit_string_token(
                tokens.get(next_idx + 2),
                "dataReferenceEdits op2 missing third argument",
            )?,
        ),
        3 => ParsedAsciiRefEditRecord::Op3(
            parse_refedit_string_token(
                tokens.get(next_idx),
                "dataReferenceEdits op3 missing first argument",
            )?,
            parse_refedit_string_token(
                tokens.get(next_idx + 1),
                "dataReferenceEdits op3 missing second argument",
            )?,
            parse_refedit_string_token(
                tokens.get(next_idx + 2),
                "dataReferenceEdits op3 missing third argument",
            )?,
        ),
        5 => {
            let sub = parse_refedit_u32_token(
                tokens.get(next_idx),
                "dataReferenceEdits op5 missing sub-count",
            )?;
            next_idx += 1;
            let mut args = Vec::new();
            while next_idx < tokens.len()
                && !is_data_reference_edits_group_header(tokens, next_idx)
                && !matches!(
                    tokens.get(next_idx),
                    Some(Token::Bare(value)) if value.parse::<u32>().is_ok()
                )
            {
                args.push(parse_refedit_string_token(
                    tokens.get(next_idx),
                    "dataReferenceEdits op5 missing argument",
                )?);
                next_idx += 1;
            }
            return Ok((ParsedAsciiRefEditRecord::Op5 { sub, args }, next_idx));
        }
        other => {
            return Err(SceneToolError::Message(format!(
                "unsupported dataReferenceEdits opcode: {other}"
            )));
        }
    };

    Ok((record, next_idx + 3))
}

fn parse_data_reference_edits_raw_record(
    source_text: &str,
    items: &[mel::MelRawShellItem],
    idx: usize,
) -> Result<(ParsedAsciiRefEditRecord, usize), SceneToolError> {
    let opcode = parse_refedit_u32_item(
        source_text,
        items.get(idx),
        "dataReferenceEdits record missing opcode",
    )?;
    let mut next_idx = idx + 1;

    let record = match opcode {
        0 => ParsedAsciiRefEditRecord::Op0(
            refedit_item_value(
                source_text,
                items.get(next_idx).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op0 missing first argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op0 missing first argument",
            )?,
            refedit_item_value(
                source_text,
                items.get(next_idx + 1).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op0 missing second argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op0 missing second argument",
            )?,
            refedit_item_value(
                source_text,
                items.get(next_idx + 2).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op0 missing third argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op0 missing third argument",
            )?,
        ),
        1 => {
            let mut args = Vec::new();
            while next_idx < items.len()
                && !is_data_reference_edits_raw_group_header(source_text, items, next_idx)
                && !is_refedit_numeric_record_boundary(source_text, items.get(next_idx))
            {
                args.push(refedit_item_value(
                    source_text,
                    items.get(next_idx).ok_or_else(|| {
                        SceneToolError::Message(
                            "dataReferenceEdits op1 missing argument".to_string(),
                        )
                    })?,
                    "dataReferenceEdits op1 missing argument",
                )?);
                next_idx += 1;
            }
            return Ok((ParsedAsciiRefEditRecord::Op1(args), next_idx));
        }
        2 => ParsedAsciiRefEditRecord::Op2(
            refedit_item_value(
                source_text,
                items.get(next_idx).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op2 missing first argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op2 missing first argument",
            )?,
            refedit_item_value(
                source_text,
                items.get(next_idx + 1).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op2 missing second argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op2 missing second argument",
            )?,
            refedit_item_value(
                source_text,
                items.get(next_idx + 2).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op2 missing third argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op2 missing third argument",
            )?,
        ),
        3 => ParsedAsciiRefEditRecord::Op3(
            refedit_item_value(
                source_text,
                items.get(next_idx).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op3 missing first argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op3 missing first argument",
            )?,
            refedit_item_value(
                source_text,
                items.get(next_idx + 1).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op3 missing second argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op3 missing second argument",
            )?,
            refedit_item_value(
                source_text,
                items.get(next_idx + 2).ok_or_else(|| {
                    SceneToolError::Message(
                        "dataReferenceEdits op3 missing third argument".to_string(),
                    )
                })?,
                "dataReferenceEdits op3 missing third argument",
            )?,
        ),
        5 => {
            let sub = parse_refedit_u32_item(
                source_text,
                items.get(next_idx),
                "dataReferenceEdits op5 missing sub-count",
            )?;
            next_idx += 1;
            let mut args = Vec::new();
            while next_idx < items.len()
                && !is_data_reference_edits_raw_group_header(source_text, items, next_idx)
                && !is_refedit_numeric_record_boundary(source_text, items.get(next_idx))
            {
                args.push(refedit_item_value(
                    source_text,
                    items.get(next_idx).ok_or_else(|| {
                        SceneToolError::Message(
                            "dataReferenceEdits op5 missing argument".to_string(),
                        )
                    })?,
                    "dataReferenceEdits op5 missing argument",
                )?);
                next_idx += 1;
            }
            return Ok((ParsedAsciiRefEditRecord::Op5 { sub, args }, next_idx));
        }
        other => {
            return Err(SceneToolError::Message(format!(
                "unsupported dataReferenceEdits opcode: {other}"
            )));
        }
    };

    Ok((record, next_idx + 3))
}

#[cfg(test)]
fn parse_refedit_u32_token(token: Option<&Token>, message: &str) -> Result<u32, SceneToolError> {
    token
        .and_then(token_text)
        .ok_or_else(|| SceneToolError::Message(message.to_string()))?
        .parse::<u32>()
        .map_err(|_| SceneToolError::Message(message.to_string()))
}

fn parse_refedit_u32_item(
    source_text: &str,
    item: Option<&mel::MelRawShellItem>,
    message: &str,
) -> Result<u32, SceneToolError> {
    item.and_then(|item| item.value_text(source_text))
        .as_deref()
        .ok_or_else(|| SceneToolError::Message(message.to_string()))?
        .parse::<u32>()
        .map_err(|_| SceneToolError::Message(message.to_string()))
}

fn is_refedit_numeric_record_boundary(
    source_text: &str,
    item: Option<&mel::MelRawShellItem>,
) -> bool {
    matches!(
        item,
        Some(mel::MelRawShellItem {
            kind: mel::MelRawShellItemKind::Numeric | mel::MelRawShellItemKind::Bare,
            ..
        })
    ) && item
        .and_then(|item| item.value_text(source_text))
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .is_some()
}

#[cfg(test)]
fn parse_refedit_string_token(
    token: Option<&Token>,
    message: &str,
) -> Result<String, SceneToolError> {
    token
        .and_then(token_text)
        .map(str::to_string)
        .ok_or_else(|| SceneToolError::Message(message.to_string()))
}

fn refedit_item_value(
    source_text: &str,
    item: &mel::MelRawShellItem,
    message: &str,
) -> Result<String, SceneToolError> {
    item.value_text(source_text)
        .map(|value| value.into_owned())
        .ok_or_else(|| SceneToolError::Message(message.to_string()))
}

#[cfg(test)]
fn parse_string_value(tokens: &[Token]) -> Result<ParsedSetAttrValue, SceneToolError> {
    if tokens.is_empty() {
        return Ok(ParsedSetAttrValue::String(String::new()));
    }
    if matches!(tokens.first(), Some(Token::Symbol('('))) {
        let mut value = String::new();
        for token in &tokens[1..] {
            match token {
                Token::Quoted(part) => value.push_str(part),
                Token::Symbol(')') | Token::Symbol('+') => {}
                other => {
                    return Err(SceneToolError::Message(format!(
                        "unexpected token in string concatenation: {other:?}"
                    )));
                }
            }
        }
        return Ok(ParsedSetAttrValue::String(value));
    }
    let value = tokens
        .first()
        .and_then(token_text)
        .ok_or_else(|| SceneToolError::Message("string setAttr missing value".to_string()))?;
    Ok(ParsedSetAttrValue::String(value.to_string()))
}

fn parse_string_array_value_raw_items(
    source_text: &str,
    items: &[mel::MelRawShellItem],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    let declared_count = items
        .first()
        .ok_or_else(|| SceneToolError::Message("stringArray count missing value".to_string()))
        .and_then(|item| {
            raw_item_scalar_text(source_text, item, "stringArray count").and_then(|value| {
                value.parse::<usize>().map_err(|_| {
                    SceneToolError::Message("stringArray count invalid value".to_string())
                })
            })
        })?;
    let values = items
        .iter()
        .skip(1)
        .map(|item| item.preferred_text(source_text).into_owned())
        .collect::<Vec<_>>();
    Ok(ParsedSetAttrValue::StringArray {
        declared_count,
        values,
    })
}

#[cfg(test)]
fn parse_string_array_value(tokens: &[Token]) -> Result<ParsedSetAttrValue, SceneToolError> {
    let declared_count = parse_usize_token(tokens.first(), "stringArray count")?;
    let values = tokens
        .iter()
        .skip(1)
        .filter_map(token_text)
        .map(str::to_string)
        .collect::<Vec<_>>();
    Ok(ParsedSetAttrValue::StringArray {
        declared_count,
        values,
    })
}

fn parse_int32_array_value_raw_items(
    source_text: &str,
    items: &[mel::MelRawShellItem],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    let declared_count = items
        .first()
        .ok_or_else(|| SceneToolError::Message("Int32Array count missing value".to_string()))
        .and_then(|item| {
            raw_item_scalar_text(source_text, item, "Int32Array count").and_then(|value| {
                value.parse::<usize>().map_err(|_| {
                    SceneToolError::Message("Int32Array count invalid value".to_string())
                })
            })
        })?;
    let mut values = Vec::new();
    for item in items.iter().skip(1).take(declared_count) {
        let raw = raw_item_scalar_text(source_text, item, "Int32Array value")?;
        values.push(raw.parse::<i32>().map_err(|_| {
            SceneToolError::Message(format!("Int32Array value is not an i32: {raw}"))
        })?);
    }
    Ok(ParsedSetAttrValue::Int32Array(values))
}

#[cfg(test)]
fn parse_int32_array_value(tokens: &[Token]) -> Result<ParsedSetAttrValue, SceneToolError> {
    let declared_count = parse_usize_token(tokens.first(), "Int32Array count")?;
    let mut values = Vec::new();
    for token in tokens.iter().skip(1).take(declared_count) {
        let raw = token_text(token).ok_or_else(|| {
            SceneToolError::Message("Int32Array contains a non-scalar token".to_string())
        })?;
        values.push(raw.parse::<i32>().map_err(|_| {
            SceneToolError::Message(format!("Int32Array value is not an i32: {raw}"))
        })?);
    }
    Ok(ParsedSetAttrValue::Int32Array(values))
}

fn parse_typed_number_value_raw_items(
    source_text: &str,
    value_type: &str,
    items: &[mel::MelRawShellItem],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    let values = items
        .iter()
        .map(|item| raw_item_scalar_text(source_text, item, "typed numeric value"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|value| parse_numeric_token(value.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedSetAttrValue::TypedNumbers {
        value_type: value_type.to_string(),
        values,
    })
}

#[cfg(test)]
fn parse_typed_number_value(
    value_type: &str,
    tokens: &[Token],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    let values = tokens
        .iter()
        .filter_map(token_text)
        .map(parse_numeric_token)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedSetAttrValue::TypedNumbers {
        value_type: value_type.to_string(),
        values,
    })
}

fn parse_typed_number_or_opaque_value_raw_items(
    source_text: &str,
    value_type: &str,
    items: &[mel::MelRawShellItem],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    if value_type == "matrix"
        && matches!(
            items.first().map(|item| item.preferred_text(source_text)),
            Some(value) if value.as_ref() == "xform"
        )
    {
        return Ok(parse_opaque_typed_value_raw_items(
            source_text,
            value_type,
            items,
        ));
    }
    parse_typed_number_value_raw_items(source_text, value_type, items)
}

#[cfg(test)]
fn parse_typed_number_or_opaque_value(
    value_type: &str,
    tokens: &[Token],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    if value_type == "matrix" && matches!(tokens.first().and_then(token_text), Some("xform")) {
        return Ok(parse_opaque_typed_value(value_type, tokens));
    }
    parse_typed_number_value(value_type, tokens)
}

fn parse_component_list_value_raw_items(
    source_text: &str,
    items: &[mel::MelRawShellItem],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    let declared_count = items
        .first()
        .ok_or_else(|| SceneToolError::Message("componentList count missing value".to_string()))
        .and_then(|item| {
            raw_item_scalar_text(source_text, item, "componentList count").and_then(|value| {
                value.parse::<usize>().map_err(|_| {
                    SceneToolError::Message("componentList count invalid value".to_string())
                })
            })
        })?;
    let values = items
        .iter()
        .skip(1)
        .take(declared_count)
        .map(|item| item.preferred_text(source_text).into_owned())
        .collect::<Vec<_>>();
    Ok(ParsedSetAttrValue::ComponentList(values))
}

#[cfg(test)]
fn parse_component_list_value(tokens: &[Token]) -> Result<ParsedSetAttrValue, SceneToolError> {
    let declared_count = parse_usize_token(tokens.first(), "componentList count")?;
    let values = tokens
        .iter()
        .skip(1)
        .take(declared_count)
        .filter_map(token_text)
        .map(str::to_string)
        .collect::<Vec<_>>();
    Ok(ParsedSetAttrValue::ComponentList(values))
}

fn parse_untyped_value_raw_items(
    source_text: &str,
    items: &[mel::MelRawShellItem],
) -> Result<ParsedSetAttrValue, SceneToolError> {
    if items.is_empty() {
        return Ok(ParsedSetAttrValue::None);
    }
    let values = items
        .iter()
        .map(|item| raw_item_scalar_text(source_text, item, "setAttr value"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|value| parse_numeric_token(value.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() == 1 {
        Ok(ParsedSetAttrValue::Scalar(values[0]))
    } else {
        Ok(ParsedSetAttrValue::Numbers(values))
    }
}

#[cfg(test)]
fn parse_untyped_value(tokens: &[Token]) -> Result<ParsedSetAttrValue, SceneToolError> {
    if tokens.is_empty() {
        return Ok(ParsedSetAttrValue::None);
    }
    let values = tokens
        .iter()
        .filter_map(token_text)
        .map(parse_numeric_token)
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() == 1 {
        Ok(ParsedSetAttrValue::Scalar(values[0]))
    } else {
        Ok(ParsedSetAttrValue::Numbers(values))
    }
}
