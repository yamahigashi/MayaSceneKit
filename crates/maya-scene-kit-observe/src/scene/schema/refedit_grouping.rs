use super::{
    super::ir::{RefEditGroup, RefEditGroupSource, RefEditRecord, RefEditUnknownTail},
    refedit_spec::RefEditSchema,
};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scene) struct ParsedBoundary {
    pub(in crate::scene) record_index: usize,
    pub(in crate::scene) group: RefEditGroup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scene) struct ParseRecordsResult {
    pub(in crate::scene) records: Vec<RefEditRecord>,
    pub(in crate::scene) boundaries: Vec<ParsedBoundary>,
    pub(in crate::scene) unknown_tail: Option<RefEditUnknownTail>,
    pub(in crate::scene) unknown_segment_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scene) struct RefEditParseCandidate {
    pub(in crate::scene) layout_order: usize,
    pub(in crate::scene) group_list_count: usize,
    pub(in crate::scene) groups: Vec<RefEditGroup>,
    pub(in crate::scene) grouped_records: Vec<Vec<RefEditRecord>>,
    pub(in crate::scene) unknown_tail: Option<RefEditUnknownTail>,
    pub(in crate::scene) boundary_count: usize,
    pub(in crate::scene) unknown_segment_count: usize,
}

fn find_initial_auto_group_index(groups: &[RefEditGroup]) -> Option<usize> {
    if groups.is_empty() {
        return None;
    }
    Some(
        groups
            .iter()
            .position(|g| g.expected_count > 0)
            .unwrap_or(0),
    )
}

#[derive(Debug, Default)]
struct BoundaryGroupIndexes {
    exact: HashMap<(String, u32), Vec<usize>>,
    by_name: HashMap<String, Vec<usize>>,
}

impl BoundaryGroupIndexes {
    fn from_groups(groups: &[RefEditGroup]) -> Self {
        let mut indexes = Self::default();
        for (idx, group) in groups.iter().enumerate() {
            indexes.insert(group, idx);
        }
        indexes
    }

    fn insert(&mut self, group: &RefEditGroup, idx: usize) {
        self.exact
            .entry((group.name.clone(), group.expected_count))
            .or_default()
            .push(idx);
        self.by_name
            .entry(group.name.clone())
            .or_default()
            .push(idx);
    }
}

fn first_index_at_or_after(indexes: &[usize], hint_start: usize) -> Option<usize> {
    indexes.iter().copied().find(|&idx| idx >= hint_start)
}

fn find_boundary_target_group_index(
    indexes: &BoundaryGroupIndexes,
    boundary: &RefEditGroup,
    hint_start: usize,
) -> Option<usize> {
    first_index_at_or_after(
        indexes
            .exact
            .get(&(boundary.name.clone(), boundary.expected_count))
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        hint_start,
    )
    .or_else(|| {
        first_index_at_or_after(
            indexes
                .by_name
                .get(boundary.name.as_str())
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            hint_start,
        )
    })
}

pub(in crate::scene) fn assign_records_to_groups_with_boundaries(
    root_node: &str,
    mut groups: Vec<RefEditGroup>,
    records: &[RefEditRecord],
    boundaries: &[ParsedBoundary],
) -> (Vec<RefEditGroup>, Vec<Vec<RefEditRecord>>) {
    let mut grouped_records: Vec<Vec<RefEditRecord>> = vec![Vec::new(); groups.len()];
    let mut group_indexes = BoundaryGroupIndexes::from_groups(&groups);

    let mut current_idx = find_initial_auto_group_index(&groups);
    let mut auto_assigned = 0usize;
    let mut boundary_idx = 0usize;

    for (record_idx, record) in records.iter().enumerate() {
        while boundary_idx < boundaries.len() && boundaries[boundary_idx].record_index == record_idx
        {
            let hint_start = current_idx.map(|i| i.saturating_add(1)).unwrap_or(0);
            let boundary_group = boundaries[boundary_idx].group.clone();
            let target_idx = current_idx
                .filter(|&i| {
                    groups[i].name == boundary_group.name
                        && groups[i].expected_count == boundary_group.expected_count
                })
                .or_else(|| {
                    find_boundary_target_group_index(&group_indexes, &boundary_group, hint_start)
                })
                .unwrap_or_else(|| {
                    groups.push(boundary_group);
                    grouped_records.push(Vec::new());
                    let idx = groups.len() - 1;
                    group_indexes.insert(&groups[idx], idx);
                    idx
                });
            current_idx = Some(target_idx);
            auto_assigned = grouped_records[target_idx].len();
            boundary_idx += 1;
        }

        if current_idx.is_none() {
            groups.push(RefEditGroup {
                name: root_node.to_string(),
                expected_count: records.len() as u32,
                source: RefEditGroupSource::ImplicitRoot,
                first_offset: 0,
            });
            grouped_records.push(Vec::new());
            current_idx = Some(groups.len() - 1);
            auto_assigned = 0;
        }

        let idx = current_idx.expect("group index");
        grouped_records[idx].push(record.clone());

        if !groups.is_empty() {
            let mut auto_idx = idx;
            auto_assigned = auto_assigned.saturating_add(1);
            loop {
                let expected = groups[auto_idx].expected_count as usize;
                if expected == 0 || auto_assigned < expected {
                    break;
                }
                if auto_idx + 1 >= groups.len() {
                    break;
                }
                auto_idx += 1;
                current_idx = Some(auto_idx);
                auto_assigned = 0;
                if groups[auto_idx].expected_count == 0 {
                    continue;
                }
                break;
            }
        }
    }

    while boundary_idx < boundaries.len() {
        let hint_start = current_idx.map(|i| i.saturating_add(1)).unwrap_or(0);
        let boundary_group = boundaries[boundary_idx].group.clone();
        if find_boundary_target_group_index(&group_indexes, &boundary_group, hint_start).is_none() {
            groups.push(boundary_group);
            grouped_records.push(Vec::new());
            let idx = groups.len() - 1;
            group_indexes.insert(&groups[idx], idx);
        }
        boundary_idx += 1;
    }

    (groups, grouped_records)
}

fn parse_candidate_group_mismatch(
    groups: &[RefEditGroup],
    grouped_records: &[Vec<RefEditRecord>],
) -> usize {
    groups
        .iter()
        .enumerate()
        .map(|(idx, g)| {
            let actual = grouped_records.get(idx).map(|v| v.len()).unwrap_or(0);
            actual.abs_diff(g.expected_count as usize)
        })
        .sum()
}

pub(in crate::scene) fn parse_candidate_record_count(
    grouped_records: &[Vec<RefEditRecord>],
) -> usize {
    grouped_records.iter().map(Vec::len).sum()
}

pub(in crate::scene) fn available_layout_counts(schema: &RefEditSchema) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (layout_order, layout) in schema.layouts.iter().enumerate() {
        if seen.insert(layout.group_list_count) {
            out.push((layout_order, layout.group_list_count));
        }
    }
    out
}

pub(in crate::scene) fn select_best_candidate(
    mut candidates: Vec<RefEditParseCandidate>,
) -> RefEditParseCandidate {
    candidates.sort_by(|a, b| {
        let a_unknown = a
            .unknown_tail
            .as_ref()
            .map(|t| t.payload.len())
            .unwrap_or(0);
        let b_unknown = b
            .unknown_tail
            .as_ref()
            .map(|t| t.payload.len())
            .unwrap_or(0);
        a_unknown
            .cmp(&b_unknown)
            .then_with(|| {
                parse_candidate_group_mismatch(&a.groups, &a.grouped_records).cmp(
                    &parse_candidate_group_mismatch(&b.groups, &b.grouped_records),
                )
            })
            .then_with(|| {
                parse_candidate_record_count(&b.grouped_records)
                    .cmp(&parse_candidate_record_count(&a.grouped_records))
            })
            .then_with(|| a.layout_order.cmp(&b.layout_order))
    });
    candidates.remove(0)
}
