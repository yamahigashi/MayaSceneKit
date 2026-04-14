use super::{
    super::ir::{RefEditData, RefEditGroup, RefEditGroupSource, RefEditParseStats},
    refedit_grouping::{
        ParseRecordsResult, RefEditParseCandidate, assign_records_to_groups_with_boundaries,
        available_layout_counts, parse_candidate_record_count, select_best_candidate,
    },
    refedit_spec::{RefEditRecordSpec, RefEditSchema},
};

pub(in crate::scene) fn build_parse_candidate(
    payload: &[u8],
    root_node: &str,
    start: usize,
    schema: &RefEditSchema,
    layout_order: usize,
    group_list_count: usize,
    parse_group_lists_exact: impl Fn(
        &[u8],
        usize,
        usize,
        &[RefEditRecordSpec],
    ) -> Option<(Vec<RefEditGroup>, usize)>,
    parse_records_with_boundaries: impl Fn(
        &[u8],
        usize,
        &[RefEditRecordSpec],
    ) -> Result<ParseRecordsResult, String>,
) -> Option<RefEditParseCandidate> {
    let (header_groups, record_start) =
        parse_group_lists_exact(payload, start, group_list_count, &schema.records)?;
    let parsed = parse_records_with_boundaries(payload, record_start, &schema.records).ok()?;
    let (groups, grouped_records) = assign_records_to_groups_with_boundaries(
        root_node,
        header_groups,
        &parsed.records,
        &parsed.boundaries,
    );
    if groups.is_empty() && parsed.records.is_empty() && parsed.unknown_tail.is_none() {
        return None;
    }

    Some(RefEditParseCandidate {
        layout_order,
        group_list_count,
        groups,
        grouped_records,
        unknown_tail: parsed.unknown_tail,
        boundary_count: parsed.boundaries.len(),
        unknown_segment_count: parsed.unknown_segment_count,
    })
}

pub(in crate::scene) fn parse_refedit_data(
    payload: &[u8],
    root_node: &str,
    start: usize,
    schema: &RefEditSchema,
    parse_group_lists_exact: impl Fn(
        &[u8],
        usize,
        usize,
        &[RefEditRecordSpec],
    ) -> Option<(Vec<RefEditGroup>, usize)>,
    parse_records_with_boundaries: impl Fn(
        &[u8],
        usize,
        &[RefEditRecordSpec],
    ) -> Result<ParseRecordsResult, String>,
) -> Result<RefEditData, String> {
    let layout_counts = available_layout_counts(schema);
    let mut candidates = Vec::new();
    for (layout_order, group_list_count) in layout_counts {
        if let Some(candidate) = build_parse_candidate(
            payload,
            root_node,
            start,
            schema,
            layout_order,
            group_list_count,
            &parse_group_lists_exact,
            &parse_records_with_boundaries,
        ) {
            candidates.push(candidate);
        }
    }

    if candidates.is_empty() {
        return Err("no parse candidate matched schema layouts".to_string());
    }

    let candidate_count = candidates.len();
    let selected = select_best_candidate(candidates);
    let mut groups = selected.groups;
    let mut grouped_records = selected.grouped_records;
    let unknown_tail = selected.unknown_tail;

    if groups.is_empty() {
        let total_records = parse_candidate_record_count(&grouped_records);
        if total_records == 0 && unknown_tail.is_none() {
            return Err("record list is empty".to_string());
        }
        groups.push(RefEditGroup {
            name: root_node.to_string(),
            expected_count: total_records as u32,
            source: RefEditGroupSource::ImplicitRoot,
            first_offset: start,
        });
        grouped_records.push(Vec::new());
    }

    Ok(RefEditData {
        root_node: root_node.to_string(),
        groups,
        grouped_records,
        unknown_tail,
        parse_stats: RefEditParseStats {
            candidate_count,
            selected_group_list_count: selected.group_list_count,
            parsed_group_list_count: selected.group_list_count,
            boundary_count: selected.boundary_count,
            unknown_segment_count: selected.unknown_segment_count,
        },
    })
}
