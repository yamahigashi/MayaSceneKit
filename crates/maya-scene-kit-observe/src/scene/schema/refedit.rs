#[cfg(test)]
use super::refedit_loader::parse_external_refedit_schema;
pub(in crate::scene) use super::refedit_loader::validate_refedit_schema_file;
use super::{
    super::ir::{RefEditData, RefEditGroup, RefEditGroupSource, RefEditRecord, RefEditUnknownTail},
    SchemaRegistry,
    refedit_candidate::parse_refedit_data,
    refedit_grouping::{ParseRecordsResult, ParsedBoundary},
    refedit_loader::lookup_refedit_schema_with_registry,
    refedit_parser::{
        has_opcode_or_eof, lookup_spec, parse_group_lists_exact, parse_triplet, read_cstring,
        read_opcode_u32, read_printable_cstring, read_text_cstring, read_u32_be, to_refedit_record,
    },
    refedit_spec::{RecordDecodeMode, RecordEmitKind, RefEditRecordSpec},
};

pub(in crate::scene) fn is_refedit_schema_asset(form: &str, tag: &str) -> bool {
    form == "REFE" && tag == "ed"
}

fn parse_group_entry(
    data: &[u8],
    cursor: usize,
    source: RefEditGroupSource,
) -> Option<(RefEditGroup, usize)> {
    let (name, after_name) = read_text_cstring(data, cursor)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_')
    {
        return None;
    }
    let (expected_count, after_expected) = read_u32_be(data, after_name)?;
    if (expected_count as usize) > data.len() {
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

fn parse_marker_payload_args(
    data: &[u8],
    start: usize,
    specs: &[RefEditRecordSpec],
) -> Option<(Vec<String>, usize)> {
    let mut cursor = start;
    let mut args = Vec::new();
    loop {
        if has_opcode_or_eof(data, cursor, specs)
            || parse_inline_group_header(data, cursor, specs).is_some()
        {
            return (!args.is_empty()).then_some((args, cursor));
        }
        let (arg, next) = read_text_cstring(data, cursor)?;
        args.push(arg);
        cursor = next;
    }
}

fn parse_counted_sub_u32(data: &[u8], opcode_end: usize) -> Option<(u32, usize)> {
    // Canonical layout is opcode(u32) + count(u32).
    let (sub, next) = read_u32_be(data, opcode_end)?;
    Some((sub, next))
}

fn parse_inline_group_header(
    data: &[u8],
    cursor: usize,
    specs: &[RefEditRecordSpec],
) -> Option<(RefEditGroup, usize)> {
    let (group, after_expected) =
        parse_group_entry(data, cursor, RefEditGroupSource::InlineHeader)?;
    if !has_opcode_or_eof(data, after_expected, specs) {
        return None;
    }
    Some((group, after_expected))
}

fn parse_context_header(
    data: &[u8],
    start: usize,
    specs: &[RefEditRecordSpec],
) -> Option<(RefEditRecord, usize)> {
    let (node, after_node) = read_text_cstring(data, start)?;
    let (index, after_index) = read_u32_be(data, after_node)?;
    if !has_opcode_or_eof(data, after_index, specs)
        && parse_inline_group_header(data, after_index, specs).is_none()
    {
        return None;
    }
    Some((RefEditRecord::Context(node, index), after_index))
}

fn parse_trailing_cstring_args(
    data: &[u8],
    start: usize,
    specs: &[RefEditRecordSpec],
) -> (Vec<String>, usize) {
    fn looks_like_empty_cstring_followed_by_opcode(
        data: &[u8],
        cursor: usize,
        specs: &[RefEditRecordSpec],
    ) -> bool {
        if cursor + 5 > data.len() || data[cursor] != 0 {
            return false;
        }
        if data[cursor..].iter().all(|b| *b == 0) {
            return false;
        }
        if data[cursor + 1] != 0 || data[cursor + 2] != 0 || data[cursor + 3] != 0 {
            return false;
        }
        is_known_opcode(specs, data[cursor + 4])
    }

    let mut args = Vec::new();
    let mut cursor = start;
    loop {
        if cursor >= data.len() || parse_inline_group_header(data, cursor, specs).is_some() {
            return (args, cursor);
        }
        if has_opcode_or_eof(data, cursor, specs)
            && !looks_like_empty_cstring_followed_by_opcode(data, cursor, specs)
        {
            return (args, cursor);
        }
        let Some((arg, next)) = read_printable_cstring(data, cursor, true) else {
            // Fail closed: keep deterministic record boundary by not consuming partial trailing bytes.
            return (Vec::new(), start);
        };
        args.push(arg);
        cursor = next;
    }
}

fn parse_single_record(
    data: &[u8],
    cursor: usize,
    specs: &[RefEditRecordSpec],
) -> Option<(Option<RefEditRecord>, usize)> {
    if cursor >= data.len() {
        return None;
    }
    let (opcode, opcode_end) = read_opcode_u32(data, cursor)?;
    let spec = lookup_spec(specs, opcode)?;

    let (emitted, next_cursor) = match spec.mode {
        RecordDecodeMode::Marker => {
            let (args, next_cursor) = parse_marker_payload_args(data, opcode_end, specs)?;
            let emitted = spec
                .emit
                .and_then(|emit| to_refedit_record(emit, None, None, Some(args)));
            (emitted, next_cursor)
        }
        RecordDecodeMode::TripletInline => {
            let (triplet, next_cursor) = parse_triplet(data, opcode_end, specs)?;
            let emitted = spec
                .emit
                .and_then(|emit| to_refedit_record(emit, Some(triplet), None, None));
            (emitted, next_cursor)
        }
        RecordDecodeMode::TripletPrefixed => {
            if let Some((triplet, next_cursor)) = parse_triplet(data, opcode_end, specs) {
                let emitted = spec
                    .emit
                    .and_then(|emit| to_refedit_record(emit, Some(triplet), None, None));
                (emitted, next_cursor)
            } else if matches!(spec.emit, Some(RecordEmitKind::Op2)) {
                let (record, next_cursor) = parse_context_header(data, opcode_end, specs)?;
                (Some(record), next_cursor)
            } else {
                return None;
            }
        }
        RecordDecodeMode::CountedCStringArgs => {
            let (sub, mut next_cursor) = parse_counted_sub_u32(data, opcode_end)?;
            let mut args = Vec::new();
            for _ in 0..sub {
                let (arg, after_arg) = read_printable_cstring(data, next_cursor, true)?;
                args.push(arg);
                next_cursor = after_arg;
            }
            let (trailing, after_trailing) = parse_trailing_cstring_args(data, next_cursor, specs);
            if !trailing.is_empty() {
                args.extend(trailing);
            }
            next_cursor = after_trailing;
            let emitted = spec
                .emit
                .and_then(|emit| to_refedit_record(emit, None, Some(sub), Some(args)));
            (emitted, next_cursor)
        }
    };

    Some((emitted, next_cursor))
}

fn can_resume_parse_at(data: &[u8], cursor: usize, specs: &[RefEditRecordSpec]) -> bool {
    if cursor >= data.len() {
        return false;
    }
    if read_opcode_u32(data, cursor)
        .map(|(opcode, _)| is_known_opcode(specs, opcode))
        .unwrap_or(false)
        && parse_single_record(data, cursor, specs).is_some()
    {
        return true;
    }
    parse_inline_group_header(data, cursor, specs).is_some()
}

fn find_recovery_cursor(data: &[u8], start: usize, specs: &[RefEditRecordSpec]) -> usize {
    let mut cursor = start.min(data.len());
    while cursor < data.len() {
        if data[cursor..].iter().all(|b| *b == 0) {
            return cursor;
        }
        if can_resume_parse_at(data, cursor, specs) {
            return cursor;
        }
        cursor += 1;
    }
    data.len()
}

fn parse_records_with_boundaries(
    data: &[u8],
    start: usize,
    specs: &[RefEditRecordSpec],
) -> Result<ParseRecordsResult, String> {
    let mut records = Vec::new();
    let mut boundaries = Vec::new();
    let mut cursor = start;
    let mut first_unknown_tail: Option<RefEditUnknownTail> = None;
    let mut unknown_segment_count = 0usize;

    while cursor < data.len() {
        if data[cursor..].iter().all(|b| *b == 0) {
            break;
        }

        if let Some((record, next)) = parse_single_record(data, cursor, specs) {
            if let Some(record) = record {
                match record {
                    RefEditRecord::Context(name, expected_count) => {
                        boundaries.push(ParsedBoundary {
                            record_index: records.len(),
                            group: RefEditGroup {
                                name,
                                expected_count,
                                source: RefEditGroupSource::ContextBoundary,
                                first_offset: cursor,
                            },
                        });
                    }
                    _ => records.push(record),
                }
            }
            cursor = next;
            continue;
        }

        if let Some((group, next)) = parse_inline_group_header(data, cursor, specs) {
            boundaries.push(ParsedBoundary {
                record_index: records.len(),
                group,
            });
            cursor = next;
            continue;
        }

        if data[cursor] == 0 {
            cursor += 1;
            continue;
        }

        let unknown_start = cursor;
        let unknown_opcode = read_opcode_u32(data, cursor)
            .map(|(opcode, _)| opcode)
            .unwrap_or(data[cursor]);

        // Fail closed when decode never established structure yet.
        // This avoids mid-stream guessing from arbitrary payload prefixes.
        if records.is_empty() && boundaries.is_empty() {
            return Ok(ParseRecordsResult {
                records,
                boundaries,
                unknown_tail: Some(RefEditUnknownTail {
                    start_offset: unknown_start,
                    opcode: unknown_opcode,
                    payload: data[unknown_start..].to_vec(),
                }),
                unknown_segment_count: 1,
            });
        }

        let mut recovery = find_recovery_cursor(data, cursor + 1, specs);
        if recovery <= unknown_start {
            recovery = (unknown_start + 1).min(data.len());
        }

        if first_unknown_tail.is_none() {
            first_unknown_tail = Some(RefEditUnknownTail {
                start_offset: unknown_start,
                opcode: unknown_opcode,
                payload: data[unknown_start..recovery].to_vec(),
            });
        }
        unknown_segment_count = unknown_segment_count.saturating_add(1);
        cursor = recovery;
    }

    Ok(ParseRecordsResult {
        records,
        boundaries,
        unknown_tail: first_unknown_tail,
        unknown_segment_count,
    })
}

#[cfg(test)]
type ParsedRecords = (
    Vec<RefEditRecord>,
    Vec<RefEditGroup>,
    Option<RefEditUnknownTail>,
);

#[cfg(test)]
fn parse_records(
    data: &[u8],
    start: usize,
    specs: &[RefEditRecordSpec],
) -> Result<ParsedRecords, String> {
    let parsed = parse_records_with_boundaries(data, start, specs)?;
    let inline_groups = parsed.boundaries.into_iter().map(|b| b.group).collect();
    Ok((parsed.records, inline_groups, parsed.unknown_tail))
}

#[cfg(test)]
pub(in crate::scene) fn decode_reference_edits_data_with_reason(
    value_raw: &[u8],
) -> Result<RefEditData, String> {
    decode_reference_edits_data_with_reason_and_registry(
        super::default_schema_registry(),
        value_raw,
    )
}

pub(in crate::scene) fn decode_reference_edits_data_with_reason_and_registry(
    registry: &SchemaRegistry,
    value_raw: &[u8],
) -> Result<RefEditData, String> {
    if std::env::var("SCENEKIT_DEBUG_REFE_RAW").is_ok() {
        let mut out = String::new();
        out.push_str(&format!("len={}\n", value_raw.len()));
        let head = value_raw
            .iter()
            .take(160)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        out.push_str(&format!("head={head}\n"));
        for (i, raw) in value_raw.split(|b| *b == 0).take(80).enumerate() {
            let hex = raw
                .iter()
                .take(80)
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!("[{i}] len={} hex={hex}\n", raw.len()));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("tmp/refe_raw_debug.txt")
        {
            let _ = std::io::Write::write_all(&mut f, out.as_bytes());
            let _ = std::io::Write::write_all(&mut f, b"\n");
        }
    }

    let schema = lookup_refedit_schema_with_registry(registry);
    let (root_node, start) =
        read_cstring(value_raw, 0).ok_or_else(|| "missing root node cstring".to_string())?;
    parse_refedit_data(
        value_raw,
        &root_node,
        start,
        &schema,
        parse_group_lists_exact,
        parse_records_with_boundaries,
    )
    .map_err(|reason| format!("{} {reason}", schema.schema_id))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use serde::Deserialize;

    use super::{
        decode_reference_edits_data_with_reason, parse_external_refedit_schema, parse_records,
    };
    use crate::scene::ir::{RefEditGroupSource, RefEditRecord};

    #[derive(Debug, Deserialize)]
    struct SyntheticFixtureFile {
        cases: Vec<SyntheticFixtureCase>,
    }

    #[derive(Debug, Deserialize)]
    struct SyntheticFixtureCase {
        id: String,
        root_node: String,
        #[serde(default)]
        group_lists: Vec<Vec<SyntheticGroup>>,
        #[serde(default)]
        records: Vec<SyntheticRecord>,
        raw_tail_ascii: Option<String>,
        expected: SyntheticExpected,
    }

    #[derive(Debug, Deserialize)]
    struct SyntheticGroup {
        name: String,
        expected_count: u32,
    }

    #[derive(Debug, Deserialize)]
    struct SyntheticRecord {
        op: String,
        sub: Option<u32>,
        #[serde(default)]
        args: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct SyntheticExpected {
        has_unknown_tail: bool,
        expected_group_count: usize,
        #[serde(default)]
        required_group_names: Vec<String>,
        unknown_opcode_hex: Option<String>,
    }

    fn synthetic_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .join("tests")
            .join("fixtures")
            .join("refedit")
            .join("synthetic_cases.yaml")
    }

    fn push_cstring(out: &mut Vec<u8>, text: &str) {
        out.extend_from_slice(text.as_bytes());
        out.push(0);
    }

    fn push_u32_be(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_op2(out: &mut Vec<u8>, node: &str, attr: &str, value: &str) {
        push_u32_be(out, 2);
        push_cstring(out, node);
        push_cstring(out, attr);
        push_cstring(out, value);
    }

    fn load_synthetic_fixtures() -> SyntheticFixtureFile {
        let bytes = fs::read(synthetic_fixture_path()).expect("read synthetic fixture yaml");
        serde_yaml::from_slice(&bytes).expect("parse synthetic fixture yaml")
    }

    fn build_payload(case: &SyntheticFixtureCase) -> Vec<u8> {
        let mut out = Vec::new();
        push_cstring(&mut out, &case.root_node);

        for list in &case.group_lists {
            push_u32_be(&mut out, list.len() as u32);
            for group in list {
                push_cstring(&mut out, &group.name);
                push_u32_be(&mut out, group.expected_count);
            }
        }

        for record in &case.records {
            match record.op.as_str() {
                "op5" => {
                    let sub = record.sub.expect("op5 requires sub");
                    push_u32_be(&mut out, 5);
                    push_u32_be(&mut out, sub);
                    for arg in &record.args {
                        push_cstring(&mut out, arg);
                    }
                }
                other => panic!("unsupported synthetic record op: {other}"),
            }
        }

        if let Some(tail) = &case.raw_tail_ascii {
            out.extend_from_slice(tail.as_bytes());
        }

        out
    }

    #[test]
    fn decode_reference_edits_data_supports_single_group_layout() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(b"grp\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(b"a\0b\0c\0");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.root_node, "root");
        assert_eq!(data.groups.len(), 1);
        assert_eq!(data.groups[0].name, "grp");
        assert_eq!(data.groups[0].expected_count, 1);
        assert_eq!(data.unknown_tail, None);
        assert_eq!(
            data.grouped_records[0],
            vec![RefEditRecord::Op2(
                "a".to_string(),
                "b".to_string(),
                "c".to_string()
            )]
        );
    }

    #[test]
    fn decode_reference_edits_data_supports_headerless_records() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"x\0y\0z\0");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.root_node, "root");
        assert_eq!(data.groups.len(), 1);
        assert_eq!(data.groups[0].name, "root");
        assert_eq!(data.groups[0].expected_count, 1);
        assert_eq!(data.unknown_tail, None);
        assert_eq!(
            data.grouped_records[0],
            vec![RefEditRecord::Op3(
                "x".to_string(),
                "y".to_string(),
                "z".to_string()
            )]
        );
    }

    #[test]
    fn decode_reference_edits_data_supports_minus_one_group_count_variant() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"refA\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(b"refB\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"a\0b\0c\0");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.root_node, "root");
        assert_eq!(data.groups.len(), 2);
        assert_eq!(data.groups[0].name, "refA");
        assert_eq!(data.groups[1].name, "refB");
        assert_eq!(data.unknown_tail, None);
        assert_eq!(data.grouped_records[0].len(), 0);
        assert_eq!(
            data.grouped_records[1],
            vec![RefEditRecord::Op3(
                "a".to_string(),
                "b".to_string(),
                "c".to_string()
            )]
        );
    }

    #[test]
    fn decode_reference_edits_data_uses_context_boundary_for_group_switch() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(b"grpA\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(b"grpB\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(b"grpB\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"x\0y\0z\0");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.groups.len(), 2);
        assert_eq!(data.groups[0].name, "grpA");
        assert_eq!(data.groups[1].name, "grpB");
        assert_eq!(data.grouped_records[0].len(), 0);
        assert_eq!(data.grouped_records[1].len(), 1);
        assert_eq!(data.parse_stats.boundary_count, 1);
    }

    #[test]
    fn decode_reference_edits_data_context_boundary_with_same_name_adds_new_group() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&1u32.to_be_bytes());

        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"a\0b\0c\0");

        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&2u32.to_be_bytes());

        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"d\0e\0f\0");
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"g\0h\0i\0");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.groups.len(), 2);
        assert_eq!(data.groups[0].name, "root");
        assert_eq!(data.groups[0].expected_count, 1);
        assert_eq!(data.groups[1].name, "root");
        assert_eq!(data.groups[1].expected_count, 2);
        assert_eq!(data.grouped_records[0].len(), 1);
        assert_eq!(data.grouped_records[1].len(), 2);
        assert_eq!(data.parse_stats.boundary_count, 1);
    }

    #[test]
    fn decode_reference_edits_data_inline_boundary_with_same_name_adds_new_group() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&1u32.to_be_bytes());

        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"a\0b\0c\0");

        payload.extend_from_slice(b"childRN\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"d\0e\0f\0");

        payload.extend_from_slice(b"childRN\0");
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"g\0h\0i\0");
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"j\0k\0l\0");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.groups.len(), 3);
        assert_eq!(data.groups[0].name, "root");
        assert_eq!(data.groups[1].name, "childRN");
        assert_eq!(data.groups[2].name, "childRN");
        assert_eq!(data.grouped_records[0].len(), 1);
        assert_eq!(data.grouped_records[1].len(), 1);
        assert_eq!(data.grouped_records[2].len(), 2);
        assert_eq!(data.parse_stats.boundary_count, 2);
    }

    #[test]
    fn decode_reference_edits_data_selects_layout_candidate_with_smaller_unknown_tail() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"x\0y\0z\0");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.unknown_tail, None);
        assert!(data.parse_stats.candidate_count >= 2);
        assert_eq!(data.parse_stats.selected_group_list_count, 1);
    }

    #[test]
    fn decode_reference_edits_data_recovers_records_after_unknown_segment() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"root\0");
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(b"grp\0");
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"a\0b\0c\0");
        payload.push(0x7F);
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(b"d\0e\0f\0");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.groups.len(), 1);
        assert_eq!(data.grouped_records[0].len(), 2);
        let unknown = data.unknown_tail.expect("unknown");
        assert_eq!(unknown.opcode, 0x7F);
        assert_eq!(unknown.payload, vec![0x7F]);
        assert_eq!(data.parse_stats.unknown_segment_count, 1);
    }

    #[test]
    fn decode_reference_edits_data_preserves_unknown_tail() {
        let payload = b"root\0\xFFbad".to_vec();
        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.root_node, "root");
        assert_eq!(data.groups.len(), 1);
        assert_eq!(data.groups[0].name, "root");
        assert_eq!(data.groups[0].expected_count, 0);
        let unknown_tail = data.unknown_tail.expect("unknown tail");
        assert_eq!(unknown_tail.opcode, 0xFF);
        assert_eq!(unknown_tail.payload, b"\xFFbad");
    }

    #[test]
    fn decode_reference_edits_data_preserves_translate_av_cluster_raw() {
        let mut payload = Vec::new();
        push_cstring(&mut payload, "root");
        push_u32_be(&mut payload, 1);
        push_cstring(&mut payload, "grp");
        push_u32_be(&mut payload, 5);
        push_op2(
            &mut payload,
            "|world|ctrl",
            "translate",
            " -type \"double3\" 0 0 -0.00010300000000285081",
        );
        push_op2(&mut payload, "|world|ctrl", "translateX", " -av");
        push_op2(&mut payload, "|world|ctrl", "translateY", " -av");
        push_op2(&mut payload, "|world|ctrl", "translateZ", " -av");
        push_op2(&mut payload, "|world|ctrl", "rotateOrder", " 3");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.groups.len(), 1);
        assert_eq!(data.groups[0].expected_count, 5);
        assert_eq!(data.grouped_records[0].len(), 5);
        assert_eq!(
            data.grouped_records[0][0],
            RefEditRecord::Op2(
                "|world|ctrl".to_string(),
                "translate".to_string(),
                " -type \"double3\" 0 0 -0.00010300000000285081".to_string()
            )
        );
        assert_eq!(
            data.grouped_records[0][4],
            RefEditRecord::Op2(
                "|world|ctrl".to_string(),
                "rotateOrder".to_string(),
                " 3".to_string()
            )
        );
    }

    #[test]
    fn decode_reference_edits_data_keeps_translate_when_av_cluster_is_incomplete() {
        let mut payload = Vec::new();
        push_cstring(&mut payload, "root");
        push_u32_be(&mut payload, 1);
        push_cstring(&mut payload, "grp");
        push_u32_be(&mut payload, 4);
        push_op2(
            &mut payload,
            "|world|ctrl",
            "translate",
            " -type \"double3\" 0 0 -0.00010300000000285081",
        );
        push_op2(&mut payload, "|world|ctrl", "translateX", " -av");
        push_op2(&mut payload, "|world|ctrl", "translateZ", " -av");
        push_op2(&mut payload, "|world|ctrl", "rotateOrder", " 3");

        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.groups.len(), 1);
        assert_eq!(data.groups[0].expected_count, 4);
        assert_eq!(data.grouped_records[0].len(), 4);
    }

    #[test]
    fn external_refedit_schema_is_parsed() {
        let yaml = r#"
schema_id: schema.external.refe.ed.test.v1
layouts:
  - name: OneList
    group_list_count: 1
records:
  - opcode: 2
    mode: triplet_prefixed
    emit: op2
"#;
        let schema = parse_external_refedit_schema(yaml.as_bytes()).expect("parse");
        assert_eq!(schema.schema_id, "schema.external.refe.ed.test.v1");
        assert_eq!(schema.layouts.len(), 1);
        assert_eq!(schema.records.len(), 1);
        let (records, inline_groups, unknown_tail) =
            parse_records(b"\0\0\0\x02a\0b\0c\0", 0, &schema.records).expect("records");
        assert!(inline_groups.is_empty());
        assert_eq!(unknown_tail, None);
        assert_eq!(
            records,
            vec![RefEditRecord::Op2(
                "a".to_string(),
                "b".to_string(),
                "c".to_string()
            )]
        );
    }

    #[test]
    fn parse_records_preserves_unknown_opcode_tail() {
        let yaml = r#"
schema_id: schema.external.refe.ed.test.v1
layouts:
  - name: Headerless
    group_list_count: 0
records:
  - opcode: 2
    mode: triplet_prefixed
    emit: op2
"#;
        let schema = parse_external_refedit_schema(yaml.as_bytes()).expect("parse");
        let (records, inline_groups, unknown_tail) =
            parse_records(b"\0\0\0\x02a\0b\0c\0\x7Frest", 0, &schema.records).expect("records");
        assert!(inline_groups.is_empty());
        assert_eq!(
            records,
            vec![RefEditRecord::Op2(
                "a".to_string(),
                "b".to_string(),
                "c".to_string()
            )]
        );
        let unknown_tail = unknown_tail.expect("unknown tail");
        assert_eq!(unknown_tail.opcode, 0x7F);
        assert_eq!(unknown_tail.payload, b"\x7Frest");
    }

    #[test]
    fn parse_records_marker_can_emit_cstring_payload() {
        let yaml = r#"
schema_id: schema.external.refe.ed.test.v1
layouts:
  - name: Headerless
    group_list_count: 0
records:
  - opcode: 1
    mode: marker
    emit: op1
"#;
        let schema = parse_external_refedit_schema(yaml.as_bytes()).expect("parse");
        let (records, inline_groups, unknown_tail) = parse_records(
            b"\0\0\0\x01path\0blendParent1\0blendParent1\0-k 1 1\0",
            0,
            &schema.records,
        )
        .expect("records");
        assert!(inline_groups.is_empty());
        assert_eq!(unknown_tail, None);
        assert_eq!(
            records,
            vec![RefEditRecord::Op1(vec![
                "path".to_string(),
                "blendParent1".to_string(),
                "blendParent1".to_string(),
                "-k 1 1".to_string(),
            ])]
        );
    }

    #[test]
    fn parse_records_does_not_guess_prefixed_counted_cstring_args() {
        let yaml = r#"
schema_id: schema.external.refe.ed.test.v1
layouts:
  - name: Headerless
    group_list_count: 0
records:
  - opcode: 5
    mode: counted_cstring_args
    emit: op5
"#;
        let schema = parse_external_refedit_schema(yaml.as_bytes()).expect("parse");
        let mut payload = Vec::new();
        payload.extend_from_slice(b"ph[0]\0");
        payload.extend_from_slice(&5u32.to_be_bytes());
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(b"root\0node.attr\0");
        let (records, inline_groups, unknown_tail) =
            parse_records(&payload, 0, &schema.records).expect("records");
        assert!(inline_groups.is_empty());
        assert!(records.is_empty());
        let unknown_tail = unknown_tail.expect("unknown tail");
        assert_eq!(unknown_tail.opcode, b'p');
        assert_eq!(unknown_tail.payload, payload);
    }

    #[test]
    fn parse_records_rejects_schema_defined_u8_opcode_stream() {
        let yaml = r#"
schema_id: schema.external.refe.ed.test.v1
layouts:
  - name: Headerless
    group_list_count: 0
records:
  - opcode: "|"
    mode: triplet_inline
    emit: op0
  - opcode: 3
    mode: triplet_prefixed
    emit: op3
"#;
        let schema = parse_external_refedit_schema(yaml.as_bytes()).expect("parse");
        let payload = b"|a\0b\0\0\x03x\0y\0z\0";
        let (records, inline_groups, unknown_tail) =
            parse_records(payload, 0, &schema.records).expect("records");
        assert!(inline_groups.is_empty());
        assert!(records.is_empty());
        let unknown_tail = unknown_tail.expect("unknown tail");
        assert_eq!(unknown_tail.opcode, b'|');
        assert_eq!(unknown_tail.payload, payload);
    }

    #[test]
    fn parse_records_counted_cstring_args_can_consume_trailing_cstrings() {
        let yaml = r#"
schema_id: schema.external.refe.ed.test.v1
layouts:
  - name: Headerless
    group_list_count: 0
records:
  - opcode: 5
    mode: counted_cstring_args
    emit: op5
"#;
        let schema = parse_external_refedit_schema(yaml.as_bytes()).expect("parse");
        let payload = b"\0\0\0\x05\0\0\0\x03root\0node.attr\0ph[10]\0dst.attr\0";
        let (records, inline_groups, unknown_tail) =
            parse_records(payload, 0, &schema.records).expect("records");
        assert!(inline_groups.is_empty());
        assert_eq!(unknown_tail, None);
        assert_eq!(
            records,
            vec![RefEditRecord::Op5 {
                sub: 3,
                args: vec![
                    "root".to_string(),
                    "node.attr".to_string(),
                    "ph[10]".to_string(),
                    "dst.attr".to_string(),
                ],
            }]
        );
    }

    #[test]
    fn parse_records_counted_cstring_args_can_consume_multi_trailing_cstrings() {
        let yaml = r#"
schema_id: schema.external.refe.ed.test.v1
layouts:
  - name: Headerless
    group_list_count: 0
records:
  - opcode: 5
    mode: counted_cstring_args
    emit: op5
"#;
        let schema = parse_external_refedit_schema(yaml.as_bytes()).expect("parse");
        let payload = b"\0\0\0\x05\0\0\0\x02root\0set.members\0ph[123]\0target.attr\0";
        let (records, inline_groups, unknown_tail) =
            parse_records(payload, 0, &schema.records).expect("records");
        assert!(inline_groups.is_empty());
        assert_eq!(unknown_tail, None);
        assert_eq!(
            records,
            vec![RefEditRecord::Op5 {
                sub: 2,
                args: vec![
                    "root".to_string(),
                    "set.members".to_string(),
                    "ph[123]".to_string(),
                    "target.attr".to_string(),
                ],
            }]
        );
    }

    #[test]
    fn parse_records_marker_payload_supports_short_arity() {
        let yaml = r#"
schema_id: schema.external.refe.ed.test.v1
layouts:
  - name: Headerless
    group_list_count: 0
records:
  - opcode: 1
    mode: marker
    emit: op1
  - opcode: 2
    mode: triplet_prefixed
    emit: op2
"#;
        let schema = parse_external_refedit_schema(yaml.as_bytes()).expect("parse");
        let payload = b"\0\0\0\x01a\0b\0\0\0\0\x02x\0y\0z\0";
        let (records, inline_groups, unknown_tail) =
            parse_records(payload, 0, &schema.records).expect("records");
        assert!(inline_groups.is_empty());
        assert_eq!(unknown_tail, None);
        assert_eq!(
            records,
            vec![
                RefEditRecord::Op1(vec!["a".to_string(), "b".to_string()]),
                RefEditRecord::Op2("x".to_string(), "y".to_string(), "z".to_string()),
            ]
        );
    }

    #[test]
    fn synthetic_refedit_fixture_file_loads() {
        let fixtures = load_synthetic_fixtures();
        assert!(!fixtures.cases.is_empty());
    }

    #[test]
    fn synthetic_refedit_fixture_cases_decode_with_expected_shape() {
        let fixtures = load_synthetic_fixtures();
        for case in &fixtures.cases {
            let payload = build_payload(case);
            let data = decode_reference_edits_data_with_reason(&payload)
                .unwrap_or_else(|e| panic!("case={} decode failed: {e}", case.id));

            assert_eq!(data.root_node, case.root_node, "case={}", case.id);
            assert_eq!(
                data.unknown_tail.is_some(),
                case.expected.has_unknown_tail,
                "case={}",
                case.id
            );
            assert_eq!(
                data.groups.len(),
                case.expected.expected_group_count,
                "case={}",
                case.id
            );

            for required in &case.expected.required_group_names {
                assert!(
                    data.groups.iter().any(|g| g.name == *required),
                    "case={} missing required group={required}",
                    case.id
                );
            }

            if let Some(expected_opcode_hex) = &case.expected.unknown_opcode_hex {
                let unknown = data.unknown_tail.as_ref().expect("unknown tail");
                assert_eq!(
                    format!("0x{:02X}", unknown.opcode),
                    *expected_opcode_hex,
                    "case={}",
                    case.id
                );
            }
        }
    }

    #[test]
    fn synthetic_rig_like_case_preserves_placeholder_and_empty_args() {
        let fixtures = load_synthetic_fixtures();
        let case = fixtures
            .cases
            .iter()
            .find(|c| c.id == "rig_like_op5_with_placeholder_empty")
            .expect("fixture case exists");
        let payload = build_payload(case);
        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.groups.len(), 2);
        assert_eq!(data.groups[0].name, "asset_bodyRN");
        assert_eq!(data.groups[0].expected_count, 0);
        assert_eq!(data.groups[0].source, RefEditGroupSource::HeaderList);
        assert_eq!(data.groups[1].name, "asset_bodyRN");
        assert_eq!(data.groups[1].expected_count, 3);
        assert_eq!(data.groups[1].source, RefEditGroupSource::HeaderList);
        assert!(data.grouped_records[0].is_empty());
        assert_eq!(data.grouped_records[1].len(), 3);

        let op5 = data
            .grouped_records
            .iter()
            .flatten()
            .find_map(|record| match record {
                RefEditRecord::Op5 { sub, args } => Some((*sub, args.clone())),
                _ => None,
            })
            .expect("op5 record");

        assert_eq!(op5.0, 3);
        assert!(
            op5.1.iter().any(|v| v.contains(".placeHolderList[")),
            "placeholder arg not found"
        );
        assert_eq!(op5.1.last().map(String::as_str), Some(""));
    }

    #[test]
    fn synthetic_rig_like_sub1_root_marker_is_retained() {
        let fixtures = load_synthetic_fixtures();
        let case = fixtures
            .cases
            .iter()
            .find(|c| c.id == "rig_like_op5_sub1_root_retained")
            .expect("fixture case exists");
        let payload = build_payload(case);
        let data = decode_reference_edits_data_with_reason(&payload).expect("decode");
        assert_eq!(data.groups.len(), 1);
        assert_eq!(data.grouped_records[0].len(), 1);
        let op5 = data.grouped_records[0]
            .first()
            .and_then(|record| match record {
                RefEditRecord::Op5 { sub, args } => Some((*sub, args.clone())),
                _ => None,
            })
            .expect("op5 record");
        assert_eq!(op5.0, 1);
        assert_eq!(op5.1, vec!["asset_bodyRN".to_string()]);
    }
}
