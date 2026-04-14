use super::{
    ByteSpan, MayaBinaryParseError, MbParseBudget, MbParseBudgetLimit, ParsedSection, SectionChunk,
    is_group_chunk_tag, parse_section_chunks_with_hints, resolve_section_layout_hints,
};

pub fn walk_group_chunks_with_layout(
    data: &[u8],
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> Vec<SectionChunk> {
    let mut out = Vec::new();
    walk_group_chunks_with_layout_iterative(
        data,
        child_alignment,
        child_header_size,
        None,
        None,
        &mut out,
    )
    .expect("unbudgeted raw walk should not fail");
    out
}

pub fn walk_group_chunks_with_layout_with_budget(
    data: &[u8],
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
    starting_depth: usize,
    budget: &MbParseBudget,
) -> Result<Vec<SectionChunk>, MayaBinaryParseError> {
    let mut out = Vec::new();
    let mut state = WalkBudgetState::new(budget);
    walk_group_chunks_with_layout_iterative(
        data,
        child_alignment,
        child_header_size,
        Some(starting_depth),
        Some(&mut state),
        &mut out,
    )?;
    Ok(out)
}

pub(crate) fn parse_section_chunks_with_layout_hints(
    data: &[u8],
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> ParsedSection {
    parse_section_chunks_with_hints(data, child_alignment, child_header_size)
}

fn parse_group_form_type(payload: &[u8]) -> Option<&str> {
    let raw = payload.get(..4)?;
    if raw.iter().all(|b| (32..=126).contains(b)) {
        std::str::from_utf8(raw).ok()
    } else {
        None
    }
}

#[derive(Debug)]
struct WalkFrame {
    chunks: Vec<SectionChunk>,
    next_index: usize,
    next_depth: usize,
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
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
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
    starting_depth: Option<usize>,
    mut state: Option<&mut WalkBudgetState<'_>>,
    out: &mut Vec<SectionChunk>,
) -> Result<(), MayaBinaryParseError> {
    let initial_depth = starting_depth.unwrap_or_default();
    if let Some(budget_state) = state.as_ref()
        && !data.is_empty()
        && initial_depth > budget_state.budget.max_depth
    {
        return Err(MayaBinaryParseError::semantic_walk_budget_exceeded(
            MbParseBudgetLimit::MaxDepth,
            format!(
                "Maya Binary semantic walk exceeded depth budget: depth={} limit={}",
                initial_depth, budget_state.budget.max_depth
            ),
        ));
    }

    let mut initial =
        parse_section_chunks_with_layout_hints(data, child_alignment, child_header_size);
    let mut stack = vec![WalkFrame {
        chunks: take_and_offset_chunks(&mut initial, 0),
        next_index: 0,
        next_depth: initial_depth + 1,
        child_alignment,
        child_header_size,
    }];

    while !stack.is_empty() {
        let frame_index = stack.len() - 1;
        if stack[frame_index].next_index >= stack[frame_index].chunks.len() {
            stack.pop();
            continue;
        }

        let (chunk, child_index, next_depth, frame_child_alignment, frame_child_header_size) = {
            let frame = &mut stack[frame_index];
            let child_index = frame.next_index;
            let chunk = frame.chunks[child_index].clone();
            frame.next_index += 1;
            (
                chunk,
                child_index,
                frame.next_depth,
                frame.child_alignment,
                frame.child_header_size,
            )
        };

        if let Some(budget_state) = state.as_deref_mut() {
            if child_index >= budget_state.budget.max_children_per_group {
                return Err(MayaBinaryParseError::semantic_walk_budget_exceeded(
                    MbParseBudgetLimit::MaxChildrenPerGroup,
                    format!(
                        "Maya Binary semantic walk exceeded child budget: depth={} limit={}",
                        next_depth.saturating_sub(1),
                        budget_state.budget.max_children_per_group
                    ),
                ));
            }
            if !budget_state.claim_chunk() {
                return Err(MayaBinaryParseError::semantic_walk_budget_exceeded(
                    MbParseBudgetLimit::MaxTotalChunks,
                    format!(
                        "Maya Binary semantic walk exceeded total chunk budget: limit={}",
                        budget_state.budget.max_total_chunks
                    ),
                ));
            }
        }

        let payload = chunk.payload(data);
        if payload.len() >= 4 && is_group_chunk_tag(chunk.tag.as_str()) {
            let form_type = parse_group_form_type(payload);
            let (inferred_alignment, inferred_header_size) =
                resolve_section_layout_hints(&chunk.tag, form_type, None, None);
            let next_alignment = inferred_alignment.or(frame_child_alignment);
            let next_header_size = inferred_header_size.or(frame_child_header_size);
            if let Some(budget_state) = state.as_ref()
                && !payload[4..].is_empty()
                && next_depth > budget_state.budget.max_depth
            {
                return Err(MayaBinaryParseError::semantic_walk_budget_exceeded(
                    MbParseBudgetLimit::MaxDepth,
                    format!(
                        "Maya Binary semantic walk exceeded depth budget: depth={} limit={}",
                        next_depth, budget_state.budget.max_depth
                    ),
                ));
            }
            let container_span = chunk
                .payload_span
                .checked_subspan(4, payload.len() - 4)
                .unwrap_or(ByteSpan::new(
                    chunk.payload_span.end,
                    chunk.payload_span.end,
                ));
            let mut parsed = parse_section_chunks_with_layout_hints(
                container_span.slice(data),
                next_alignment,
                next_header_size,
            );
            stack.push(WalkFrame {
                chunks: take_and_offset_chunks(&mut parsed, container_span.start),
                next_index: 0,
                next_depth: next_depth + 1,
                child_alignment: next_alignment,
                child_header_size: next_header_size,
            });
            continue;
        }
        out.push(chunk);
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
