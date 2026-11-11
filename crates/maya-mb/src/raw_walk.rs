use super::{
    BudgetContext, FourCC, LayoutHints, MayaBinaryParseError, MbParseBudget, MbParseBudgetLimit,
    MbSectionScanState, SectionChunk, is_group_chunk_tag, resolve_section_layout_hints,
};
use crate::section::SectionCursor;

#[derive(Debug, Clone)]
#[must_use = "inspect the section scan state before accepting a partial result"]
#[non_exhaustive]
pub struct MbWalkResult {
    pub chunks: Vec<SectionChunk>,
    pub state: MbSectionScanState,
}

pub fn walk_group_chunks_with_layout(data: &[u8], hints: LayoutHints) -> MbWalkResult {
    let mut chunks = Vec::new();
    let state = visit_group_chunks_with_layout(data, hints, |chunk| chunks.push(chunk));
    MbWalkResult { chunks, state }
}

pub fn visit_group_chunks_with_layout(
    data: &[u8],
    hints: LayoutHints,
    visitor: impl FnMut(SectionChunk),
) -> MbSectionScanState {
    visit_iterative(data, hints, 0, &MbParseBudget::default(), false, visitor)
        .expect("soft budget scan")
}

pub fn walk_group_chunks_with_layout_with_budget(
    data: &[u8],
    hints: LayoutHints,
    starting_depth: usize,
    budget: &MbParseBudget,
) -> Result<MbWalkResult, MayaBinaryParseError> {
    let mut chunks = Vec::new();
    let state =
        visit_group_chunks_with_layout_with_budget(data, hints, starting_depth, budget, |chunk| {
            chunks.push(chunk)
        })?;
    Ok(MbWalkResult { chunks, state })
}

pub fn visit_group_chunks_with_layout_with_budget(
    data: &[u8],
    hints: LayoutHints,
    starting_depth: usize,
    budget: &MbParseBudget,
    visitor: impl FnMut(SectionChunk),
) -> Result<MbSectionScanState, MayaBinaryParseError> {
    visit_iterative(data, hints, starting_depth, budget, true, visitor)
}

fn parse_group_form_type(payload: &[u8]) -> Option<FourCC> {
    let raw = payload.get(..4)?;
    if raw.iter().all(|b| (32..=126).contains(b)) {
        Some(FourCC::new(
            raw.try_into().expect("slice is 4 bytes by construction"),
        ))
    } else {
        None
    }
}

struct WalkFrame<'a> {
    cursor: SectionCursor<'a>,
    base: usize,
    count: usize,
    depth: usize,
    hints: LayoutHints,
}

fn visit_iterative(
    data: &[u8],
    hints: LayoutHints,
    starting_depth: usize,
    budget: &MbParseBudget,
    hard: bool,
    mut visitor: impl FnMut(SectionChunk),
) -> Result<MbSectionScanState, MayaBinaryParseError> {
    if !data.is_empty() && starting_depth > budget.max_depth {
        return stop_or_error(
            hard,
            MbParseBudgetLimit::MaxDepth,
            BudgetContext::Depth {
                depth: starting_depth,
                maximum: budget.max_depth,
            },
        );
    }
    if data.len() > budget.max_parse_bytes {
        return stop_or_error(
            hard,
            MbParseBudgetLimit::MaxParseBytes,
            BudgetContext::InputBytes {
                size: data.len(),
                maximum: budget.max_parse_bytes,
                after_read: true,
            },
        );
    }
    let mut stack = vec![WalkFrame {
        cursor: SectionCursor::new(data, hints),
        base: 0,
        count: 0,
        depth: starting_depth,
        hints,
    }];
    let mut state = MbSectionScanState::Complete;
    let mut total = 0;
    while let Some(frame) = stack.last_mut() {
        let Some(mut chunk) = frame.cursor.next() else {
            state.merge(frame.cursor.state());
            stack.pop();
            continue;
        };
        if frame.count >= budget.max_children_per_group {
            return stop_or_error(
                hard,
                MbParseBudgetLimit::MaxChildrenPerGroup,
                BudgetContext::Children {
                    depth: frame.depth,
                    maximum: budget.max_children_per_group,
                },
            );
        }
        if total >= budget.max_total_chunks {
            return stop_or_error(
                hard,
                MbParseBudgetLimit::MaxTotalChunks,
                BudgetContext::TotalChunks {
                    maximum: budget.max_total_chunks,
                },
            );
        }
        frame.count += 1;
        total += 1;
        chunk.offset_spans(frame.base);
        let payload = chunk.payload(data);
        if payload.len() >= 4 && is_group_chunk_tag(chunk.tag()) {
            let inferred = resolve_section_layout_hints(
                chunk.tag(),
                parse_group_form_type(payload),
                LayoutHints::new(),
            );
            let mut next_hints = frame.hints;
            if let Some(alignment) = inferred.alignment() {
                next_hints = next_hints.with_alignment(alignment);
            }
            if let Some(header) = inferred.header_format() {
                next_hints = next_hints.with_header_format(header);
            }
            let depth = frame.depth + 1;
            if payload.len() > 4 && depth > budget.max_depth {
                return stop_or_error(
                    hard,
                    MbParseBudgetLimit::MaxDepth,
                    BudgetContext::Depth {
                        depth,
                        maximum: budget.max_depth,
                    },
                );
            }
            stack.push(WalkFrame {
                cursor: SectionCursor::new(&payload[4..], next_hints),
                base: chunk.payload_span().start + 4,
                count: 0,
                depth,
                hints: next_hints,
            });
        } else {
            visitor(chunk);
        }
    }
    Ok(state)
}

fn stop_or_error(
    hard: bool,
    limit: MbParseBudgetLimit,
    context: BudgetContext,
) -> Result<MbSectionScanState, MayaBinaryParseError> {
    if hard {
        Err(MayaBinaryParseError::BudgetExceeded { limit, context })
    } else {
        Ok(MbSectionScanState::Stopped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ByteSpan;

    #[test]
    fn child_budget_preserves_nested_starting_depth() {
        let nested = b"FOR4\0\0\0\x14TESTDATA\0\0\0\0DATA\0\0\0\0";
        let error = walk_group_chunks_with_layout_with_budget(
            nested,
            LayoutHints::from_numeric(Some(4), Some(8)),
            2,
            &MbParseBudget {
                max_children_per_group: 1,
                ..MbParseBudget::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::BudgetExceeded {
                limit: MbParseBudgetLimit::MaxChildrenPerGroup,
                context: BudgetContext::Children {
                    depth: 3,
                    maximum: 1
                }
            }
        ));
        assert_eq!(
            error.to_string(),
            "Maya Binary semantic walk exceeded child budget: depth=3 limit=1"
        );
    }

    #[test]
    fn budget_failures_preserve_typed_context() {
        let leaf = b"DATA\0\0\0\0";
        let nested = b"FOR4\0\0\0\x0cTESTDATA\0\0\0\0";
        for (data, starting_depth, budget, limit, context, expected) in [
            (
                leaf.as_slice(),
                2,
                MbParseBudget {
                    max_depth: 1,
                    ..MbParseBudget::default()
                },
                MbParseBudgetLimit::MaxDepth,
                BudgetContext::Depth {
                    depth: 2,
                    maximum: 1,
                },
                "Maya Binary semantic walk exceeded depth budget: depth=2 limit=1",
            ),
            (
                nested.as_slice(),
                0,
                MbParseBudget {
                    max_depth: 0,
                    ..MbParseBudget::default()
                },
                MbParseBudgetLimit::MaxDepth,
                BudgetContext::Depth {
                    depth: 1,
                    maximum: 0,
                },
                "Maya Binary semantic walk exceeded depth budget: depth=1 limit=0",
            ),
            (
                leaf.as_slice(),
                0,
                MbParseBudget {
                    max_children_per_group: 0,
                    ..MbParseBudget::default()
                },
                MbParseBudgetLimit::MaxChildrenPerGroup,
                BudgetContext::Children {
                    depth: 0,
                    maximum: 0,
                },
                "Maya Binary semantic walk exceeded child budget: depth=0 limit=0",
            ),
            (
                leaf.as_slice(),
                0,
                MbParseBudget {
                    max_total_chunks: 0,
                    ..MbParseBudget::default()
                },
                MbParseBudgetLimit::MaxTotalChunks,
                BudgetContext::TotalChunks { maximum: 0 },
                "Maya Binary semantic walk exceeded total chunk budget: limit=0",
            ),
        ] {
            let error = walk_group_chunks_with_layout_with_budget(
                data,
                LayoutHints::from_numeric(Some(4), Some(8)),
                starting_depth,
                &budget,
            )
            .unwrap_err();
            assert_eq!(error.budget_limit(), Some(limit));
            assert!(
                matches!(error, MayaBinaryParseError::BudgetExceeded { limit: actual_limit, context: actual_context } if actual_limit == limit && actual_context == context)
            );
            assert_eq!(error.to_string(), expected);
        }
        let no_depth = MbParseBudget {
            max_depth: 0,
            ..MbParseBudget::default()
        };
        assert!(
            walk_group_chunks_with_layout_with_budget(
                &[],
                LayoutHints::from_numeric(Some(4), Some(8)),
                1,
                &no_depth
            )
            .unwrap()
            .chunks
            .is_empty()
        );
        assert!(
            walk_group_chunks_with_layout_with_budget(
                b"FOR4\0\0\0\x04TEST",
                LayoutHints::from_numeric(Some(4), Some(8)),
                0,
                &no_depth
            )
            .unwrap()
            .chunks
            .is_empty()
        );

        let error = walk_group_chunks_with_layout_with_budget(
            leaf,
            LayoutHints::from_numeric(Some(4), Some(8)),
            0,
            &MbParseBudget {
                max_children_per_group: 0,
                max_total_chunks: 0,
                ..MbParseBudget::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MayaBinaryParseError::BudgetExceeded {
                limit: MbParseBudgetLimit::MaxChildrenPerGroup,
                context: BudgetContext::Children {
                    depth: 0,
                    maximum: 0
                }
            }
        ));
        assert_eq!(
            error.budget_limit(),
            Some(MbParseBudgetLimit::MaxChildrenPerGroup)
        );
        assert_eq!(
            error.to_string(),
            "Maya Binary semantic walk exceeded child budget: depth=0 limit=0"
        );
    }

    #[test]
    fn typed_layout_walk_preserves_nested_order() {
        use std::num::NonZeroUsize;

        use crate::{ChunkLayout, HeaderFormat, encode_chunk};
        let four = ChunkLayout::new(NonZeroUsize::new(4).unwrap(), HeaderFormat::FourByte);
        let eight = ChunkLayout::new(NonZeroUsize::new(8).unwrap(), HeaderFormat::EightByte);
        let nested_leaf = encode_chunk(FourCC::new(*b"DATA"), 0x11, b"X", eight).unwrap();
        let mut for8_payload = b"TEST".to_vec();
        for8_payload.extend_from_slice(&nested_leaf);
        let for8 = encode_chunk(FourCC::new(*b"FOR8"), 0, &for8_payload, four).unwrap();
        let mut for4_payload = b"TEST".to_vec();
        for4_payload.extend_from_slice(&for8);
        let for4 = encode_chunk(FourCC::new(*b"FOR4"), 0, &for4_payload, four).unwrap();
        let mut data = encode_chunk(FourCC::new(*b"DATA"), 0, b"A", four).unwrap();
        data.extend_from_slice(&for4);
        data.extend_from_slice(&encode_chunk(FourCC::new(*b"DATA"), 0, b"B", four).unwrap());
        let hints = LayoutHints::from_numeric(Some(4), Some(8));
        let budget = MbParseBudget::default();
        let walked = walk_group_chunks_with_layout(&data, hints);
        let budgeted = walk_group_chunks_with_layout_with_budget(&data, hints, 0, &budget).unwrap();
        let mut visited = Vec::new();
        assert_eq!(
            visit_group_chunks_with_layout(&data, hints, |chunk| visited.push(chunk)),
            MbSectionScanState::Complete
        );
        let mut visited_budgeted = Vec::new();
        assert_eq!(
            visit_group_chunks_with_layout_with_budget(&data, hints, 0, &budget, |chunk| {
                visited_budgeted.push(chunk)
            })
            .unwrap(),
            MbSectionScanState::Complete
        );
        let expected = [
            (
                FourCC::new(*b"DATA"),
                0,
                ByteSpan::new(8, 9),
                0,
                12,
                b"A".as_slice(),
            ),
            (
                FourCC::new(*b"DATA"),
                0x11,
                ByteSpan::new(52, 53),
                0,
                24,
                b"X".as_slice(),
            ),
            (
                FourCC::new(*b"DATA"),
                0,
                ByteSpan::new(68, 69),
                60,
                72,
                b"B".as_slice(),
            ),
        ];
        for chunks in [walked.chunks, budgeted.chunks, visited, visited_budgeted] {
            let actual: Vec<_> = chunks
                .iter()
                .map(|c| {
                    (
                        c.tag,
                        c.aux,
                        c.payload_span,
                        c.chunk_start,
                        c.chunk_end,
                        c.payload(&data),
                    )
                })
                .collect();
            assert_eq!(actual, expected);
        }
        assert!(
            walk_group_chunks_with_layout(&data, LayoutHints::default())
                .chunks
                .is_empty()
        );
        assert!(
            walk_group_chunks_with_layout_with_budget(&data, LayoutHints::default(), 0, &budget)
                .unwrap()
                .chunks
                .is_empty()
        );
        let mut count = 0;
        assert_eq!(
            visit_group_chunks_with_layout(&data, LayoutHints::default(), |_| count += 1),
            MbSectionScanState::Stopped
        );
        assert_eq!(
            visit_group_chunks_with_layout_with_budget(
                &data,
                LayoutHints::default(),
                0,
                &budget,
                |_| count += 1,
            )
            .unwrap(),
            MbSectionScanState::Stopped
        );
        assert_eq!(count, 0);
    }
}
