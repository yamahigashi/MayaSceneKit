use super::{
    super::ir::{RefEditGroup, RefEditGroupSource, RefEditRecord},
    refedit_spec::{RecordEmitKind, RefEditRecordSpec},
};

pub(in crate::scene) fn read_cstring(data: &[u8], cursor: usize) -> Option<(String, usize)> {
    if cursor >= data.len() {
        return None;
    }
    let end_rel = data[cursor..].iter().position(|b| *b == 0)?;
    let end = cursor + end_rel;
    Some((
        String::from_utf8_lossy(&data[cursor..end]).to_string(),
        end + 1,
    ))
}

pub(in crate::scene) fn read_printable_cstring(
    data: &[u8],
    cursor: usize,
    allow_empty: bool,
) -> Option<(String, usize)> {
    if cursor >= data.len() {
        return None;
    }
    let end_rel = data[cursor..].iter().position(|b| *b == 0)?;
    let end = cursor + end_rel;
    let raw = &data[cursor..end];
    if (!allow_empty && raw.is_empty()) || raw.iter().any(|b| *b < 0x20 || *b == 0x7F) {
        return None;
    }
    Some((String::from_utf8_lossy(raw).to_string(), end + 1))
}

pub(in crate::scene) fn read_text_cstring(data: &[u8], cursor: usize) -> Option<(String, usize)> {
    read_printable_cstring(data, cursor, false)
}

pub(in crate::scene) fn read_u32_be(data: &[u8], cursor: usize) -> Option<(u32, usize)> {
    if cursor + 4 > data.len() {
        return None;
    }
    Some((
        u32::from_be_bytes(data[cursor..cursor + 4].try_into().ok()?),
        cursor + 4,
    ))
}

pub(in crate::scene) fn parse_triplet(
    data: &[u8],
    start: usize,
    specs: &[RefEditRecordSpec],
) -> Option<([String; 3], usize)> {
    let (a, p1) = read_text_cstring(data, start)?;
    let (b, p2) = read_text_cstring(data, p1)?;
    if has_opcode_or_eof(data, p2, specs) || parse_inline_group_header(data, p2, specs).is_some() {
        return Some(([a, b, String::new()], p2));
    }
    let (c, p3) = read_printable_cstring(data, p2, true)?;
    Some(([a, b, c], p3))
}

pub(in crate::scene) fn parse_group_lists_exact(
    data: &[u8],
    start: usize,
    list_count: usize,
    specs: &[RefEditRecordSpec],
) -> Option<(Vec<RefEditGroup>, usize)> {
    let mut cursor = start;
    let mut groups = Vec::new();

    for list_index in 0..list_count {
        let (mut list_groups, next_cursor) = parse_group_list(data, cursor, specs, list_index)?;
        if next_cursor <= cursor {
            return None;
        }
        groups.append(&mut list_groups);
        cursor = next_cursor;
    }
    Some((groups, cursor))
}

pub(in crate::scene) fn to_refedit_record(
    emit: RecordEmitKind,
    triplet: Option<[String; 3]>,
    sub: Option<u32>,
    args: Option<Vec<String>>,
) -> Option<RefEditRecord> {
    match emit {
        RecordEmitKind::Op0 => {
            let [a, b, c] = triplet?;
            Some(RefEditRecord::Op0(a, b, c))
        }
        RecordEmitKind::Op1 => Some(RefEditRecord::Op1(args?)),
        RecordEmitKind::Op2 => {
            let [a, b, c] = triplet?;
            Some(RefEditRecord::Op2(a, b, c))
        }
        RecordEmitKind::Op3 => {
            let [a, b, c] = triplet?;
            Some(RefEditRecord::Op3(a, b, c))
        }
        RecordEmitKind::Op5 => Some(RefEditRecord::Op5 {
            sub: sub?,
            args: args?,
        }),
    }
}

pub(in crate::scene) fn lookup_spec(
    specs: &[RefEditRecordSpec],
    opcode: u8,
) -> Option<RefEditRecordSpec> {
    specs.iter().copied().find(|spec| spec.opcode == opcode)
}

fn is_refedit_group_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_')
}

fn is_plausible_expected_count(data: &[u8], count: u32) -> bool {
    (count as usize) <= data.len()
}

pub(in crate::scene) fn read_opcode_u32(data: &[u8], cursor: usize) -> Option<(u8, usize)> {
    let (raw, next) = read_u32_be(data, cursor)?;
    let opcode = u8::try_from(raw).ok()?;
    Some((opcode, next))
}

fn parse_group_entry(
    data: &[u8],
    cursor: usize,
    source: RefEditGroupSource,
) -> Option<(RefEditGroup, usize)> {
    let (name, after_name) = read_text_cstring(data, cursor)?;
    if !is_refedit_group_name(&name) {
        return None;
    }
    let (expected_count, after_expected) = read_u32_be(data, after_name)?;
    if !is_plausible_expected_count(data, expected_count) {
        return None;
    }
    Some((
        RefEditGroup {
            name,
            expected_count,
            source,
            first_offset: cursor,
        },
        after_expected,
    ))
}

fn is_known_opcode(specs: &[RefEditRecordSpec], opcode: u8) -> bool {
    lookup_spec(specs, opcode).is_some()
}

pub(in crate::scene) fn has_opcode_or_eof(
    data: &[u8],
    cursor: usize,
    specs: &[RefEditRecordSpec],
) -> bool {
    if cursor >= data.len() {
        return true;
    }
    read_opcode_u32(data, cursor)
        .map(|(opcode, _)| is_known_opcode(specs, opcode))
        .unwrap_or(false)
}

fn parse_group_list(
    data: &[u8],
    start: usize,
    specs: &[RefEditRecordSpec],
    _list_index: usize,
) -> Option<(Vec<RefEditGroup>, usize)> {
    const MAX_GROUP_ENTRIES: usize = 200_000;

    let (group_count_raw, mut cursor) = read_u32_be(data, start)?;
    let target_count = group_count_raw as usize;
    if target_count > MAX_GROUP_ENTRIES + 1 {
        return None;
    }

    let mut groups = Vec::with_capacity(target_count.min(1024));
    while groups.len() < target_count {
        let Some((group, next_cursor)) =
            parse_group_entry(data, cursor, RefEditGroupSource::HeaderList)
        else {
            break;
        };
        groups.push(group);
        cursor = next_cursor;
    }

    if groups.len() == target_count {
        return Some((groups, cursor));
    }

    if target_count > 0
        && groups.len() + 1 == target_count
        && has_opcode_or_eof(data, cursor, specs)
    {
        return Some((groups, cursor));
    }

    None
}

fn parse_inline_group_header(
    data: &[u8],
    cursor: usize,
    specs: &[RefEditRecordSpec],
) -> Option<(RefEditGroup, usize)> {
    let (group, next) = parse_group_entry(data, cursor, RefEditGroupSource::InlineHeader)?;
    if !has_opcode_or_eof(data, next, specs) {
        return None;
    }
    Some((group, next))
}
