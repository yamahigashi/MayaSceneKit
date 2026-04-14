use crate::{
    addattr_semantics::add_attr_semantics,
    scene::{
        decode::{numeric_f64, parse_numeric_literal},
        ir::{AddAttrDefaultValue, AddAttrOp, AddAttrValueSpec, FlagState, NumericValue},
        schema::{
            SchemaRegistry,
            addattr_tokens::{
                AddAttrEnumNamesLayout, AddAttrSoftRangeLayout,
                lookup_add_attr_token_rule_with_registry,
            },
        },
    },
};

const ADD_ATTR_HEADER_LEN: usize = 11;

#[derive(Debug, Clone)]
struct DecodedAddAttrLayout {
    type_token: String,
    attr_layout_byte: u8,
    header_raw: [u8; ADD_ATTR_HEADER_LEN],
    long_name: String,
    short_name: String,
    number_of_children: Option<u32>,
    tail_offset: usize,
}

#[derive(Debug, Default, Clone)]
struct AddAttrTailMetadata {
    parent: Option<String>,
    nice_name: Option<String>,
    explicit_default_value: Option<NumericValue>,
    explicit_min_value: Option<NumericValue>,
    explicit_max_value: Option<NumericValue>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AddAttrHeaderFlags {
    pub(crate) disconnect_behaviour: u8,
    pub(crate) storable: bool,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    pub(crate) cached_internally: bool,
    pub(crate) used_as_color: bool,
    pub(crate) has_parent: bool,
    pub(crate) hidden: bool,
    pub(crate) keyable: bool,
    pub(crate) multi: bool,
    pub(crate) index_matters: bool,
    pub(crate) internal_set: bool,
}

#[cfg(test)]
pub(crate) fn decode_add_attr_op_from_attr_chunk(payload: &[u8]) -> Option<AddAttrOp> {
    decode_add_attr_op_from_attr_chunk_with_registry(
        crate::scene::schema::default_schema_registry(),
        payload,
    )
}

pub(crate) fn decode_add_attr_op_from_attr_chunk_with_registry(
    registry: &SchemaRegistry,
    payload: &[u8],
) -> Option<AddAttrOp> {
    decode_typed_add_attr(registry, payload)
}

fn decode_typed_add_attr(registry: &SchemaRegistry, payload: &[u8]) -> Option<AddAttrOp> {
    let layout = decode_add_attr_layout(registry, payload)?;
    let header_flags = decode_add_attr_header_flags(&layout.header_raw);
    let token_rule = lookup_add_attr_token_rule_with_registry(registry, &layout.type_token);
    let mut value_spec = token_rule
        .as_ref()
        .map(|rule| rule.value_spec.clone())
        .unwrap_or_else(|| AddAttrValueSpec::UnknownToken {
            token: layout.type_token.clone(),
        });
    if layout.type_token == "aTYP" {
        if let Some(data_type) = decode_add_attr_typed_data_type(registry, &layout.header_raw) {
            value_spec = AddAttrValueSpec::DataType(data_type);
        }
    }
    let tail = &payload[layout.tail_offset..];
    let tail_metadata = decode_add_attr_tail_metadata(&value_spec, tail, header_flags.has_parent);
    let min_value = tail_metadata.explicit_min_value.or_else(|| {
        token_rule
            .as_ref()
            .and_then(|rule| rule.min_value.as_deref().and_then(parse_numeric_literal))
    });
    let max_value = tail_metadata.explicit_max_value.or_else(|| {
        token_rule
            .as_ref()
            .and_then(|rule| rule.max_value.as_deref().and_then(parse_numeric_literal))
    });
    let (soft_min_value, soft_max_value) =
        match token_rule.as_ref().map(|rule| rule.soft_range_layout) {
            Some(AddAttrSoftRangeLayout::LeadingDoublePairAfterU32) => {
                decode_add_attr_soft_range_from_tail(tail)
            }
            _ => (None, None),
        };
    let enum_names = match token_rule.as_ref().map(|rule| rule.enum_names_layout) {
        Some(AddAttrEnumNamesLayout::CStringListUntilMarkerOrNulRun) => {
            decode_add_attr_enum_names_from_tail(tail)
        }
        _ => None,
    };
    let default_value = tail_metadata
        .explicit_default_value
        .map(|value| AddAttrDefaultValue { value });

    Some(AddAttrOp {
        attr_name: layout.long_name.clone(),
        short_name: layout.short_name,
        long_name: layout.long_name,
        parent: tail_metadata.parent,
        number_of_children: layout.number_of_children,
        nice_name: tail_metadata.nice_name,
        type_token: layout.type_token,
        header_raw: layout.header_raw,
        disconnect_behaviour: Some(header_flags.disconnect_behaviour),
        used_as_proxy: layout.attr_layout_byte == 1,
        used_as_color: header_flags.used_as_color,
        storable: FlagState::from_bool(header_flags.storable),
        readable: FlagState::from_bool(header_flags.readable),
        writable: FlagState::from_bool(header_flags.writable),
        cached_internally: FlagState::from_bool(header_flags.cached_internally),
        hidden: FlagState::from_bool(header_flags.hidden),
        keyable: FlagState::from_bool(header_flags.keyable),
        multi: FlagState::from_bool(header_flags.multi),
        index_matters: if header_flags.multi {
            FlagState::from_bool(header_flags.index_matters)
        } else {
            FlagState::Unknown
        },
        internal_set: FlagState::from_bool(header_flags.internal_set),
        default_value,
        min_value,
        max_value,
        soft_min_value,
        soft_max_value,
        enum_names,
        value_spec,
    })
}

fn decode_add_attr_tail_metadata(
    value_spec: &AddAttrValueSpec,
    tail: &[u8],
    has_parent: bool,
) -> AddAttrTailMetadata {
    let mut out = AddAttrTailMetadata::default();
    let mut cursor = 0usize;
    let semantics = add_attr_semantics(value_spec);
    if has_parent
        && tail
            .first()
            .map(|byte| byte.is_ascii_graphic() || *byte == b' ')
            .unwrap_or(false)
    {
        if let Some(raw_parent_name) = read_cstring_allow_empty(tail, &mut cursor) {
            let parent_name = raw_parent_name.trim();
            if is_attr_identifier(parent_name) {
                out.parent = Some(parent_name.to_string());
            } else {
                cursor = 0;
            }
        }
    }

    let allow_nice_name = out.parent.is_none() && semantics.allows_nice_name();
    if allow_nice_name
        && tail
            .get(cursor)
            .map(|byte| byte.is_ascii_graphic() || *byte == b' ')
            .unwrap_or(false)
    {
        let mut nice_name_cursor = cursor;
        if let Some(raw_nice_name) = read_cstring_allow_empty(tail, &mut nice_name_cursor) {
            let nice_name = raw_nice_name.trim();
            if !nice_name.is_empty()
                && nice_name
                    .chars()
                    .all(|ch| ch.is_ascii_graphic() || ch == ' ')
            {
                out.nice_name = Some(nice_name.to_string());
                cursor = nice_name_cursor;
            }
        }
    }
    if semantics.allows_enum_names() {
        if let Some((_, enum_cursor)) = decode_add_attr_enum_names_with_cursor_from_tail(tail) {
            if let Some((min_value, max_value, default_value)) =
                parse_add_attr_numeric_tail_payload(&tail[enum_cursor..])
            {
                let min_finite = min_value.map(|v| v.is_finite()).unwrap_or(false);
                let max_finite = max_value.map(|v| v.is_finite()).unwrap_or(true);
                if min_finite && max_finite && default_value.is_finite() {
                    out.explicit_min_value = min_value.map(numeric_f64);
                    out.explicit_max_value = max_value.map(numeric_f64);
                    if default_value != 0.0 {
                        out.explicit_default_value = Some(numeric_f64(default_value));
                    }
                }
            }
        }
        return out;
    }
    if !semantics.allows_numeric_tail() {
        return out;
    }
    let Some((min_value, max_value, default_value)) =
        parse_add_attr_numeric_tail_payload(&tail[cursor..])
    else {
        return out;
    };
    let min_finite = min_value.map(|v| v.is_finite()).unwrap_or(false);
    let max_finite = max_value.map(|v| v.is_finite()).unwrap_or(true);
    if min_finite && max_finite && default_value.is_finite() {
        let has_explicit_default = default_value != 0.0;
        out.explicit_min_value = min_value.map(numeric_f64);
        out.explicit_max_value = max_value.map(numeric_f64);
        if has_explicit_default {
            out.explicit_default_value = Some(numeric_f64(default_value));
        }
    }

    out
}

fn decode_add_attr_layout(
    registry: &SchemaRegistry,
    payload: &[u8],
) -> Option<DecodedAddAttrLayout> {
    if payload.len() < 5 + ADD_ATTR_HEADER_LEN + 2 {
        return None;
    }
    let attr_layout_byte = payload[4];
    if attr_layout_byte != 0 && attr_layout_byte != 1 {
        return None;
    }
    let type_token = std::str::from_utf8(&payload[0..4]).ok()?.to_string();
    if !type_token.starts_with('a') {
        return None;
    }

    let mut header_raw = [0u8; ADD_ATTR_HEADER_LEN];
    header_raw.copy_from_slice(&payload[5..5 + ADD_ATTR_HEADER_LEN]);
    let token_rule = crate::scene::schema::addattr_tokens::lookup_add_attr_token_rule_with_registry(
        registry,
        &type_token,
    );
    let number_of_children = token_rule
        .as_ref()
        .and_then(|rule| rule.number_of_children(&header_raw));
    let name_prefix_words = token_rule
        .as_ref()
        .and_then(|rule| rule.name_prefix_words(&header_raw));
    let leading_name_padding_words = token_rule
        .as_ref()
        .and_then(|rule| rule.leading_name_padding_words(&header_raw));

    let start_cursor = 5 + ADD_ATTR_HEADER_LEN;
    let mut cursor = start_cursor;
    if let Some(padding_words) = leading_name_padding_words {
        let padding_bytes = (padding_words as usize).checked_mul(4)?;
        cursor = cursor.checked_add(padding_bytes)?;
    }
    let long_raw = if let Some(prefix_words) = name_prefix_words {
        let raw_with_prefix = read_cstring(payload, &mut cursor)?;
        let prefix_bytes = (prefix_words as usize).checked_mul(4)?;
        if raw_with_prefix.len() < prefix_bytes {
            return None;
        }
        raw_with_prefix[prefix_bytes..].to_string()
    } else {
        read_cstring(payload, &mut cursor)?
    };
    let short_name = read_cstring_allow_empty(payload, &mut cursor)?;
    let long_name = normalize_attr_name_token(&long_raw);
    if long_name.is_empty() {
        return None;
    }
    let short_name = if short_name.is_empty() {
        long_name.clone()
    } else {
        short_name
    };

    Some(DecodedAddAttrLayout {
        type_token,
        attr_layout_byte,
        header_raw,
        long_name,
        short_name,
        number_of_children,
        tail_offset: cursor,
    })
}

fn decode_add_attr_typed_data_type(
    registry: &SchemaRegistry,
    header_raw: &[u8; ADD_ATTR_HEADER_LEN],
) -> Option<String> {
    crate::scene::schema::addattr_tokens::lookup_add_attr_token_rule_with_registry(registry, "aTYP")
        .and_then(|rule| rule.typed_data_type(header_raw))
}

pub(crate) fn parse_add_attr_numeric_tail_payload(
    payload: &[u8],
) -> Option<(Option<f64>, Option<f64>, f64)> {
    const DBLE: &[u8; 4] = b"DBLE";

    if payload.len() >= 32 && payload.get(20..24) == Some(DBLE.as_slice()) {
        if !payload[0..4].iter().all(|b| *b == 0) {
            return None;
        }
        let min_value = read_f64_be(payload, 4)?;
        let max_value = read_f64_be(payload, 12)?;
        let default_value = read_f64_be(payload, 24)?;
        if payload[32..].iter().all(|b| *b == 0) {
            return Some((Some(min_value), Some(max_value), default_value));
        }
    }
    if payload.len() >= 24 && payload.get(12..16) == Some(DBLE.as_slice()) {
        if !payload[0..4].iter().all(|b| *b == 0) {
            return None;
        }
        let min_value = read_f64_be(payload, 4)?;
        let default_value = read_f64_be(payload, 16)?;
        if payload[24..].iter().all(|b| *b == 0) {
            return Some((Some(min_value), None, default_value));
        }
    }
    if payload.len() >= 16 && payload.get(4..8) == Some(DBLE.as_slice()) {
        if !payload[0..4].iter().all(|b| *b == 0) {
            return None;
        }
        let default_value = read_f64_be(payload, 8)?;
        if payload[16..].iter().all(|b| *b == 0) {
            return Some((None, None, default_value));
        }
    }
    if payload.len() >= 12 && payload.get(0..4) == Some(DBLE.as_slice()) {
        let default_value = read_f64_be(payload, 4)?;
        if payload[12..].iter().all(|b| *b == 0) {
            return Some((None, None, default_value));
        }
    }
    None
}

fn read_f64_be(payload: &[u8], offset: usize) -> Option<f64> {
    let raw: [u8; 8] = payload.get(offset..offset + 8)?.try_into().ok()?;
    Some(f64::from_bits(u64::from_be_bytes(raw)))
}

fn decode_add_attr_soft_range_from_tail(
    tail: &[u8],
) -> (Option<NumericValue>, Option<NumericValue>) {
    if tail.len() < 24 {
        return (None, None);
    }
    if !tail[0..4].iter().all(|b| *b == 0) {
        return (None, None);
    }
    if tail.get(20..24) != Some(b"DBLE".as_slice()) {
        return (None, None);
    }
    let Some(min_raw) = tail.get(4..12).and_then(|raw| raw.try_into().ok()) else {
        return (None, None);
    };
    let Some(max_raw) = tail.get(12..20).and_then(|raw| raw.try_into().ok()) else {
        return (None, None);
    };
    let soft_min = f64::from_bits(u64::from_be_bytes(min_raw));
    let soft_max = f64::from_bits(u64::from_be_bytes(max_raw));
    if !soft_min.is_finite() || !soft_max.is_finite() {
        return (None, None);
    }
    (Some(numeric_f64(soft_min)), Some(numeric_f64(soft_max)))
}

fn decode_add_attr_enum_names_from_tail(tail: &[u8]) -> Option<String> {
    decode_add_attr_enum_names_with_cursor_from_tail(tail).map(|(enum_names, _)| enum_names)
}

fn decode_add_attr_enum_names_with_cursor_from_tail(tail: &[u8]) -> Option<(String, usize)> {
    if tail.is_empty() {
        return None;
    }

    let mut cursor = 0usize;
    let mut labels = Vec::new();
    while cursor < tail.len() {
        if tail[cursor..].starts_with(b"DBLE") {
            break;
        }
        if tail[cursor] == 0 {
            break;
        }
        let end_rel = tail[cursor..].iter().position(|b| *b == 0)?;
        let end = cursor + end_rel;
        if end == cursor {
            break;
        }
        let token = &tail[cursor..end];
        if !token.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            break;
        }
        labels.push(String::from_utf8_lossy(token).to_string());
        cursor = end + 1;
    }

    if labels.is_empty() {
        None
    } else {
        Some((labels.join(":"), cursor))
    }
}

pub(crate) fn decode_add_attr_header_flags(raw: &[u8; ADD_ATTR_HEADER_LEN]) -> AddAttrHeaderFlags {
    let b0 = raw[0];
    let b1 = raw[1];
    let b2 = raw[2];
    let disconnect_behaviour = match (b0 >> 6) & 0b11 {
        0b10 => 0,
        0b01 => 1,
        _ => 2,
    };
    AddAttrHeaderFlags {
        disconnect_behaviour,
        storable: (b0 & 0x20) != 0,
        readable: (b0 & 0x08) != 0,
        writable: (b0 & 0x10) != 0,
        cached_internally: (b2 & 0x40) != 0,
        used_as_color: (b1 & 0x04) != 0,
        has_parent: (b2 & 0x20) != 0,
        hidden: (b1 & 0x20) != 0,
        keyable: (b1 & 0x40) != 0,
        multi: (b2 & 0x01) != 0,
        index_matters: (b1 & 0x01) == 0,
        internal_set: (b2 & 0x80) != 0,
    }
}

pub(super) fn read_cstring(payload: &[u8], cursor: &mut usize) -> Option<String> {
    read_cstring_allow_empty(payload, cursor).filter(|value| !value.is_empty())
}

pub(super) fn read_cstring_allow_empty(payload: &[u8], cursor: &mut usize) -> Option<String> {
    let rest = payload.get(*cursor..)?;
    let nul = rest.iter().position(|b| *b == 0)?;
    let value = String::from_utf8_lossy(&rest[..nul]).to_string();
    *cursor += nul + 1;
    Some(value)
}

pub(super) fn is_attr_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'[' | b']'))
}

pub(super) fn normalize_attr_name_token(token: &str) -> String {
    token
        .trim_matches(|c: char| c.is_ascii_control() || c == '\0')
        .trim()
        .to_string()
}
