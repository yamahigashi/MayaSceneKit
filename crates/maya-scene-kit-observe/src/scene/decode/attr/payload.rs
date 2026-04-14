use crate::{
    scene::{decode::numeric_f64, ir::NumericValue},
    typed_value_semantics::component_prefix_from_code,
};

pub(crate) fn decode_attr_payload(payload: &[u8]) -> Option<(String, u8, Vec<u8>)> {
    if payload.is_empty() {
        return None;
    }
    let nul = payload.iter().position(|b| *b == 0)?;
    if nul == 0 || nul + 1 >= payload.len() {
        return None;
    }
    let name = String::from_utf8_lossy(&payload[..nul]).to_string();
    let kind = payload[nul + 1];
    let value_raw = payload[nul + 2..].to_vec();
    Some((name, kind, value_raw))
}

pub(crate) fn decode_indexed_double_range_attr(
    attr_name: &str,
    value_raw: &[u8],
) -> Option<(usize, Vec<NumericValue>)> {
    let (start, end) = parse_simple_index_range_attr(attr_name)?;
    if value_raw.len() < 16 || value_raw.len() % 8 != 0 {
        return None;
    }
    let count = end.checked_sub(start)?.checked_add(1)?;
    let values: Vec<NumericValue> = value_raw
        .chunks_exact(8)
        .map(|c| numeric_f64(f64::from_bits(u64::from_be_bytes(c.try_into().unwrap()))))
        .collect();
    if values.len() != count {
        return None;
    }
    Some((count, values))
}

pub(crate) fn parse_simple_index_range_attr(attr_name: &str) -> Option<(usize, usize)> {
    let lb = attr_name.find('[')?;
    let rb = attr_name[lb + 1..].find(']')? + lb + 1;
    if rb + 1 != attr_name.len() {
        return None;
    }
    let range = &attr_name[lb + 1..rb];
    let (a, b) = range.split_once(':')?;
    let start = a.parse::<usize>().ok()?;
    let end = b.parse::<usize>().ok()?;
    Some((start.min(end), start.max(end)))
}

pub(crate) fn decode_component_list_attr(value_raw: &[u8]) -> Option<Vec<String>> {
    if value_raw.len() < 4 {
        return None;
    }
    let group_count = u32::from_be_bytes(value_raw[0..4].try_into().ok()?) as usize;
    let mut cursor = 4usize;
    let mut components = Vec::new();

    for _ in 0..group_count {
        if cursor + 8 > value_raw.len() {
            return None;
        }
        let code = String::from_utf8_lossy(&value_raw[cursor..cursor + 4]).to_string();
        cursor += 4;
        let range_count =
            u32::from_be_bytes(value_raw[cursor..cursor + 4].try_into().ok()?) as usize;
        cursor += 4;

        let prefix = component_prefix_from_code(&code)?;

        for _ in 0..range_count {
            if cursor + 8 > value_raw.len() {
                return None;
            }
            let start = i32::from_be_bytes(value_raw[cursor..cursor + 4].try_into().ok()?);
            let end = i32::from_be_bytes(value_raw[cursor + 4..cursor + 8].try_into().ok()?);
            cursor += 8;

            let token = if start < 0 || end < 0 {
                format!("{prefix}[*]")
            } else if start == end {
                format!("{prefix}[{start}]")
            } else {
                format!("{prefix}[{start}:{end}]")
            };
            components.push(token);
        }
    }

    if components.is_empty() {
        return None;
    }

    Some(components)
}

pub(crate) fn attr_path(name: &str) -> String {
    if name.starts_with('.') {
        name.to_string()
    } else {
        format!(".{name}")
    }
}
