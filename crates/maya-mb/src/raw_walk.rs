use super::{
    BudgetContext, ByteSpan, FourCC, LayoutHints, MayaBinaryParseError, MbParseBudget,
    MbParseBudgetLimit, ParsedSection, SectionChunk, is_group_chunk_tag,
    parse_section_chunks_with_hints, resolve_section_layout_hints,
};

/// Walks leaves in order using optional section hints; unspecified hints scan nothing.
pub fn walk_group_chunks_with_layout(data: &[u8], hints: LayoutHints) -> Vec<SectionChunk> {
    let mut out = Vec::new();
    walk_group_chunks_with_layout_iterative(data, hints, None, None, &mut out)
        .expect("unbudgeted raw walk should not fail");
    out
}

/// Visits leaves in order, inferring nested group layouts including FOR8/Maya.
/// Unspecified initial hints scan nothing.
pub fn visit_group_chunks_with_layout(
    data: &[u8],
    hints: LayoutHints,
    visitor: impl FnMut(SectionChunk),
) {
    visit_group_chunks_with_layout_iterative(data, hints, None, None, visitor)
        .expect("unbudgeted raw walk should not fail");
}

/// Walks leaves with layout hints and a parsing budget. Nonzero alignment and
/// header width remain independent, including for FOR8/Maya.
pub fn walk_group_chunks_with_layout_with_budget(
    data: &[u8],
    hints: LayoutHints,
    starting_depth: usize,
    budget: &MbParseBudget,
) -> Result<Vec<SectionChunk>, MayaBinaryParseError> {
    let mut out = Vec::new();
    let mut state = WalkBudgetState::new(budget);
    walk_group_chunks_with_layout_iterative(
        data,
        hints,
        Some(starting_depth),
        Some(&mut state),
        &mut out,
    )?;
    Ok(out)
}

/// Visits leaves with independent layout hints and a parsing budget.
/// Unspecified initial hints scan nothing; nested groups infer missing layout.
pub fn visit_group_chunks_with_layout_with_budget(
    data: &[u8],
    hints: LayoutHints,
    starting_depth: usize,
    budget: &MbParseBudget,
    visitor: impl FnMut(SectionChunk),
) -> Result<(), MayaBinaryParseError> {
    let mut state = WalkBudgetState::new(budget);
    visit_group_chunks_with_layout_iterative(
        data,
        hints,
        Some(starting_depth),
        Some(&mut state),
        visitor,
    )
}

pub(crate) fn parse_section_chunks_with_layout_hints(
    data: &[u8],
    hints: LayoutHints,
) -> ParsedSection {
    parse_section_chunks_with_hints(data, hints)
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

#[derive(Debug)]
struct WalkFrame {
    chunks: Vec<SectionChunk>,
    next_index: usize,
    next_depth: usize,
    hints: LayoutHints,
}

#[derive(Debug, Clone, Copy)]
struct WalkBudgetState<'a> {
    budget: &'a MbParseBudget,
    total_chunks: usize,
}

impl<'a> WalkBudgetState<'a> {
    fn new(budget: &'a MbParseBudget) -> Self {
        Self {
            budget,
            total_chunks: 0,
        }
    }

    fn claim_chunk(&mut self) -> bool {
        if self.total_chunks >= self.budget.max_total_chunks {
            return false;
        }
        self.total_chunks += 1;
        true
    }
}

fn walk_group_chunks_with_layout_iterative(
    data: &[u8],
    hints: LayoutHints,
    starting_depth: Option<usize>,
    state: Option<&mut WalkBudgetState<'_>>,
    out: &mut Vec<SectionChunk>,
) -> Result<(), MayaBinaryParseError> {
    visit_group_chunks_with_layout_iterative(data, hints, starting_depth, state, |chunk| {
        out.push(chunk)
    })
}

fn visit_group_chunks_with_layout_iterative(
    data: &[u8],
    hints: LayoutHints,
    starting_depth: Option<usize>,
    mut state: Option<&mut WalkBudgetState<'_>>,
    mut visitor: impl FnMut(SectionChunk),
) -> Result<(), MayaBinaryParseError> {
    let initial_depth = starting_depth.unwrap_or_default();
    if let Some(budget_state) = state.as_ref()
        && !data.is_empty()
        && initial_depth > budget_state.budget.max_depth
    {
        return Err(MayaBinaryParseError::BudgetExceeded {
            limit: MbParseBudgetLimit::MaxDepth,
            context: BudgetContext::Depth {
                depth: initial_depth,
                maximum: budget_state.budget.max_depth,
            },
        });
    }

    let mut initial = parse_section_chunks_with_layout_hints(data, hints);
    let mut stack = vec![WalkFrame {
        chunks: take_and_offset_chunks(&mut initial, 0),
        next_index: 0,
        next_depth: initial_depth + 1,
        hints,
    }];

    while !stack.is_empty() {
        let frame_index = stack.len() - 1;
        if stack[frame_index].next_index >= stack[frame_index].chunks.len() {
            stack.pop();
            continue;
        }

        let (chunk, child_index, next_depth, frame_hints) = {
            let frame = &mut stack[frame_index];
            let child_index = frame.next_index;
            let chunk = frame.chunks[child_index].clone();
            frame.next_index += 1;
            (chunk, child_index, frame.next_depth, frame.hints)
        };

        if let Some(budget_state) = state.as_deref_mut() {
            if child_index >= budget_state.budget.max_children_per_group {
                return Err(MayaBinaryParseError::BudgetExceeded {
                    limit: MbParseBudgetLimit::MaxChildrenPerGroup,
                    context: BudgetContext::Children {
                        depth: next_depth.saturating_sub(1),
                        maximum: budget_state.budget.max_children_per_group,
                    },
                });
            }
            if !budget_state.claim_chunk() {
                return Err(MayaBinaryParseError::BudgetExceeded {
                    limit: MbParseBudgetLimit::MaxTotalChunks,
                    context: BudgetContext::TotalChunks {
                        maximum: budget_state.budget.max_total_chunks,
                    },
                });
            }
        }

        let payload = chunk.payload(data);
        if payload.len() >= 4 && is_group_chunk_tag(chunk.tag) {
            let form_type = parse_group_form_type(payload);
            let inferred = resolve_section_layout_hints(chunk.tag, form_type, LayoutHints::new());
            let mut next_hints = frame_hints;
            if let Some(alignment) = inferred.alignment() {
                next_hints = next_hints.with_alignment(alignment);
            }
            if let Some(header_format) = inferred.header_format() {
                next_hints = next_hints.with_header_format(header_format);
            }
            if let Some(budget_state) = state.as_ref()
                && !payload[4..].is_empty()
                && next_depth > budget_state.budget.max_depth
            {
                return Err(MayaBinaryParseError::BudgetExceeded {
                    limit: MbParseBudgetLimit::MaxDepth,
                    context: BudgetContext::Depth {
                        depth: next_depth,
                        maximum: budget_state.budget.max_depth,
                    },
                });
            }
            let container_span = chunk
                .payload_span
                .checked_subspan(4, payload.len() - 4)
                .unwrap_or(ByteSpan::new(
                    chunk.payload_span.end,
                    chunk.payload_span.end,
                ));
            let mut parsed =
                parse_section_chunks_with_layout_hints(container_span.slice(data), next_hints);
            stack.push(WalkFrame {
                chunks: take_and_offset_chunks(&mut parsed, container_span.start),
                next_index: 0,
                next_depth: next_depth + 1,
                hints: next_hints,
            });
            continue;
        }
        visitor(chunk);
    }

    Ok(())
}

fn take_and_offset_chunks(parsed: &mut ParsedSection, base: usize) -> Vec<SectionChunk> {
    let mut chunks = std::mem::take(&mut parsed.chunks);
    for chunk in &mut chunks {
        chunk.offset_spans(base);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use crate::{ChunkLayout, HeaderFormat, encode_chunk};
        use std::num::NonZeroUsize;
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
        visit_group_chunks_with_layout(&data, hints, |chunk| visited.push(chunk));
        let mut visited_budgeted = Vec::new();
        visit_group_chunks_with_layout_with_budget(&data, hints, 0, &budget, |chunk| {
            visited_budgeted.push(chunk)
        })
        .unwrap();
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
        for chunks in [walked, budgeted, visited, visited_budgeted] {
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
        assert!(walk_group_chunks_with_layout(&data, LayoutHints::default()).is_empty());
        assert!(
            walk_group_chunks_with_layout_with_budget(&data, LayoutHints::default(), 0, &budget)
                .unwrap()
                .is_empty()
        );
        let mut count = 0;
        visit_group_chunks_with_layout(&data, LayoutHints::default(), |_| count += 1);
        visit_group_chunks_with_layout_with_budget(
            &data,
            LayoutHints::default(),
            0,
            &budget,
            |_| count += 1,
        )
        .unwrap();
        assert_eq!(count, 0);
    }
}
