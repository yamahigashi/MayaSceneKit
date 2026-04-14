use super::{ChunkSchema, DecodedField, DecodedFieldValue, SchemaDecodeError, SchemaFieldKind};
use crate::scene::ir::NumericValue;

fn sanitize_token(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .trim_matches(|c: char| c.is_control())
        .to_string()
}

fn resolve_count(
    field_name: &str,
    count_from: Option<&str>,
    count_expr: Option<&str>,
    fields: &[DecodedField],
) -> Result<usize, SchemaDecodeError> {
    if let Some(name) = count_from {
        return lookup_count_value(fields, name).ok_or(SchemaDecodeError::CountReferenceMissing {
            field: field_name.to_string().into(),
            count_from: name.to_string().into(),
        });
    }
    if let Some(expr) = count_expr {
        return eval_count_expr(expr, fields).ok_or(SchemaDecodeError::InvalidCountExpression {
            field: field_name.to_string().into(),
            expr: expr.to_string().into(),
        });
    }
    Err(SchemaDecodeError::InvalidCountExpression {
        field: field_name.to_string().into(),
        expr: "<missing count_from/count_expr>".into(),
    })
}

fn lookup_count_value(fields: &[DecodedField], name: &str) -> Option<usize> {
    fields.iter().rev().find_map(|field| {
        if field.name.as_ref() != name {
            return None;
        }
        match field.value {
            DecodedFieldValue::U8(v) => Some(v as usize),
            DecodedFieldValue::U32(v) => Some(v as usize),
            _ => None,
        }
    })
}

fn eval_count_expr(expr: &str, fields: &[DecodedField]) -> Option<usize> {
    let mut parser = CountExprParser {
        src: expr.as_bytes(),
        cursor: 0,
        fields,
    };
    let value = parser.parse_expr()?;
    parser.skip_ws();
    if parser.cursor != parser.src.len() || value < 0 {
        return None;
    }
    usize::try_from(value).ok()
}

struct CountExprParser<'a> {
    src: &'a [u8],
    cursor: usize,
    fields: &'a [DecodedField],
}

impl CountExprParser<'_> {
    fn skip_ws(&mut self) {
        while self.cursor < self.src.len() && self.src[self.cursor].is_ascii_whitespace() {
            self.cursor += 1;
        }
    }

    fn parse_expr(&mut self) -> Option<i64> {
        let mut value = self.parse_term()?;
        loop {
            self.skip_ws();
            let op = match self.src.get(self.cursor).copied() {
                Some(b'+') | Some(b'-') => self.src[self.cursor],
                _ => break,
            };
            self.cursor += 1;
            let rhs = self.parse_term()?;
            value = if op == b'+' {
                value.checked_add(rhs)?
            } else {
                value.checked_sub(rhs)?
            };
        }
        Some(value)
    }

    fn parse_term(&mut self) -> Option<i64> {
        let mut value = self.parse_factor()?;
        loop {
            self.skip_ws();
            let op = match self.src.get(self.cursor).copied() {
                Some(b'*') | Some(b'/') => self.src[self.cursor],
                _ => break,
            };
            self.cursor += 1;
            let rhs = self.parse_factor()?;
            value = if op == b'*' {
                value.checked_mul(rhs)?
            } else if rhs == 0 {
                return None;
            } else {
                value.checked_div(rhs)?
            };
        }
        Some(value)
    }

    fn parse_factor(&mut self) -> Option<i64> {
        self.skip_ws();
        match self.src.get(self.cursor).copied()? {
            b'(' => {
                self.cursor += 1;
                let value = self.parse_expr()?;
                self.skip_ws();
                if self.src.get(self.cursor) != Some(&b')') {
                    return None;
                }
                self.cursor += 1;
                Some(value)
            }
            b'-' => {
                self.cursor += 1;
                self.parse_factor()?.checked_neg()
            }
            b'0'..=b'9' => self.parse_number(),
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => self.parse_identifier_value(),
            _ => None,
        }
    }

    fn parse_number(&mut self) -> Option<i64> {
        let start = self.cursor;
        while self.cursor < self.src.len() && self.src[self.cursor].is_ascii_digit() {
            self.cursor += 1;
        }
        std::str::from_utf8(&self.src[start..self.cursor])
            .ok()?
            .parse::<i64>()
            .ok()
    }

    fn parse_identifier_value(&mut self) -> Option<i64> {
        let start = self.cursor;
        while self.cursor < self.src.len() {
            let b = self.src[self.cursor];
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.cursor += 1;
            } else {
                break;
            }
        }
        let ident = std::str::from_utf8(&self.src[start..self.cursor]).ok()?;
        let value = lookup_count_value(self.fields, ident)?;
        i64::try_from(value).ok()
    }
}

pub(in crate::scene) fn decode_fields_with_schema(
    schema: impl AsRef<ChunkSchema>,
    payload: &[u8],
) -> Result<Vec<DecodedField>, SchemaDecodeError> {
    let schema = schema.as_ref();
    let mut out = Vec::new();
    let mut cursor = 0usize;

    for (field_idx, field) in schema.fields.iter().enumerate() {
        let is_last_field = field_idx + 1 == schema.fields.len();
        match field.kind {
            SchemaFieldKind::U8 => {
                if cursor + 1 > payload.len() {
                    return Err(SchemaDecodeError::UnexpectedEof {
                        field: field.name.clone(),
                        needed: 1,
                        offset: cursor,
                    });
                }
                out.push(DecodedField {
                    name: field.name.clone(),
                    value: DecodedFieldValue::U8(payload[cursor]),
                });
                cursor += 1;
            }
            SchemaFieldKind::U32BE => {
                if cursor + 4 > payload.len() {
                    return Err(SchemaDecodeError::UnexpectedEof {
                        field: field.name.clone(),
                        needed: 4,
                        offset: cursor,
                    });
                }
                out.push(DecodedField {
                    name: field.name.clone(),
                    value: DecodedFieldValue::U32(u32::from_be_bytes(
                        payload[cursor..cursor + 4].try_into().unwrap(),
                    )),
                });
                cursor += 4;
            }
            SchemaFieldKind::U32Expr { ref expr } => {
                let value = eval_count_expr(expr.as_ref(), &out).ok_or(
                    SchemaDecodeError::InvalidCountExpression {
                        field: field.name.clone(),
                        expr: expr.clone(),
                    },
                )?;
                let value = u32::try_from(value).map_err(|_| {
                    SchemaDecodeError::InvalidCountExpression {
                        field: field.name.clone(),
                        expr: expr.clone(),
                    }
                })?;
                out.push(DecodedField {
                    name: field.name.clone(),
                    value: DecodedFieldValue::U32(value),
                });
            }
            SchemaFieldKind::CString {
                allow_eof_termination,
            } => {
                if let Some(nul_pos_rel) = payload[cursor..].iter().position(|b| *b == 0) {
                    let end = cursor + nul_pos_rel;
                    let value = sanitize_token(&payload[cursor..end]);
                    out.push(DecodedField {
                        name: field.name.clone(),
                        value: DecodedFieldValue::Text(value),
                    });
                    cursor = end + 1;
                    continue;
                }

                if allow_eof_termination && is_last_field {
                    let value = sanitize_token(&payload[cursor..]);
                    out.push(DecodedField {
                        name: field.name.clone(),
                        value: DecodedFieldValue::Text(value),
                    });
                    cursor = payload.len();
                    continue;
                }

                return Err(SchemaDecodeError::MissingNulTerminator {
                    field: field.name.clone(),
                    offset: cursor,
                });
            }
            SchemaFieldKind::CStringListRest { min_items } => {
                let items = payload[cursor..]
                    .split(|b| *b == 0)
                    .map(sanitize_token)
                    .filter(|token| !token.trim().is_empty())
                    .collect::<Vec<_>>();
                if items.len() < min_items {
                    return Err(SchemaDecodeError::TooFewListItems {
                        field: field.name.clone(),
                        min_items,
                        actual_items: items.len(),
                    });
                }
                for item in items {
                    out.push(DecodedField {
                        name: field.name.clone(),
                        value: DecodedFieldValue::Text(item),
                    });
                }
                cursor = payload.len();
            }
            SchemaFieldKind::F64BEArray {
                ref count_from,
                ref count_expr,
            } => {
                let count = resolve_count(
                    &field.name,
                    count_from.as_ref().map(|value| value.as_ref()),
                    count_expr.as_ref().map(|value| value.as_ref()),
                    &out,
                )?;
                let needed = count
                    .checked_mul(8)
                    .ok_or(SchemaDecodeError::UnexpectedEof {
                        field: field.name.clone(),
                        needed: usize::MAX,
                        offset: cursor,
                    })?;
                if cursor + needed > payload.len() {
                    return Err(SchemaDecodeError::UnexpectedEof {
                        field: field.name.clone(),
                        needed,
                        offset: cursor,
                    });
                }
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    let end = cursor + 8;
                    let bits = u64::from_be_bytes(payload[cursor..end].try_into().unwrap());
                    values.push(NumericValue::from_f64(f64::from_bits(bits)));
                    cursor = end;
                }
                out.push(DecodedField {
                    name: field.name.clone(),
                    value: DecodedFieldValue::Numbers(values),
                });
            }
            SchemaFieldKind::U32BEArray {
                ref count_from,
                ref count_expr,
            } => {
                let count = resolve_count(
                    &field.name,
                    count_from.as_ref().map(|value| value.as_ref()),
                    count_expr.as_ref().map(|value| value.as_ref()),
                    &out,
                )?;
                let needed = count
                    .checked_mul(4)
                    .ok_or(SchemaDecodeError::UnexpectedEof {
                        field: field.name.clone(),
                        needed: usize::MAX,
                        offset: cursor,
                    })?;
                if cursor + needed > payload.len() {
                    return Err(SchemaDecodeError::UnexpectedEof {
                        field: field.name.clone(),
                        needed,
                        offset: cursor,
                    });
                }
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    let end = cursor + 4;
                    let value = u32::from_be_bytes(payload[cursor..end].try_into().unwrap());
                    values.push(NumericValue::from_u32(value));
                    cursor = end;
                }
                out.push(DecodedField {
                    name: field.name.clone(),
                    value: DecodedFieldValue::Numbers(values),
                });
            }
            SchemaFieldKind::BytesRest { allow_empty } => {
                let rest = payload[cursor..].to_vec();
                if rest.is_empty() && !allow_empty {
                    return Err(SchemaDecodeError::UnexpectedEof {
                        field: field.name.clone(),
                        needed: 1,
                        offset: cursor,
                    });
                }
                out.push(DecodedField {
                    name: field.name.clone(),
                    value: DecodedFieldValue::Bytes(rest),
                });
                cursor = payload.len();
            }
        }
    }

    if cursor < payload.len() && payload[cursor..].iter().any(|b| *b != 0) {
        return Err(SchemaDecodeError::TrailingNonNulBytes { offset: cursor });
    }

    Ok(out)
}

pub(in crate::scene) fn field_text<'a>(fields: &'a [DecodedField], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find_map(|field| match (&field.name, &field.value) {
            (field_name, DecodedFieldValue::Text(value)) if *field_name == name => {
                Some(value.as_str())
            }
            _ => None,
        })
}

pub(in crate::scene) fn field_text_values<'a>(
    fields: &'a [DecodedField],
    name: &str,
) -> Vec<&'a str> {
    fields
        .iter()
        .filter_map(|field| match (&field.name, &field.value) {
            (field_name, DecodedFieldValue::Text(value)) if *field_name == name => {
                Some(value.as_str())
            }
            _ => None,
        })
        .collect()
}

pub(in crate::scene) fn field_u8(fields: &[DecodedField], name: &str) -> Option<u8> {
    fields
        .iter()
        .find_map(|field| match (&field.name, &field.value) {
            (field_name, DecodedFieldValue::U8(value)) if *field_name == name => Some(*value),
            _ => None,
        })
}

pub(in crate::scene) fn field_u32(fields: &[DecodedField], name: &str) -> Option<u32> {
    fields
        .iter()
        .find_map(|field| match (&field.name, &field.value) {
            (field_name, DecodedFieldValue::U32(value)) if *field_name == name => Some(*value),
            _ => None,
        })
}

pub(in crate::scene) fn field_numbers<'a>(
    fields: &'a [DecodedField],
    name: &str,
) -> Option<&'a [NumericValue]> {
    fields
        .iter()
        .find_map(|field| match (&field.name, &field.value) {
            (field_name, DecodedFieldValue::Numbers(values)) if *field_name == name => {
                Some(values.as_slice())
            }
            _ => None,
        })
}

pub(in crate::scene) fn field_bytes<'a>(
    fields: &'a [DecodedField],
    name: &str,
) -> Option<&'a [u8]> {
    fields
        .iter()
        .find_map(|field| match (&field.name, &field.value) {
            (field_name, DecodedFieldValue::Bytes(value)) if *field_name == name => {
                Some(value.as_slice())
            }
            _ => None,
        })
}
