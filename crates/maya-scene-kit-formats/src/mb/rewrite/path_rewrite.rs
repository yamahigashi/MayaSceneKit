use std::{borrow::Cow, collections::HashMap, num::NonZeroUsize};

use maya_mb::ParsedSection;

// MB rewrite helpers intentionally stay chunk-oriented so replacement can preserve
// binary layout details without becoming the canonical semantic inspection path.
use crate::mb::{
    Chunk, ChunkLayout, FourCC, LayoutHints, parse_section_chunks_with_hints_with_budget,
    paths::{extract_raw_scene_path_records_from_mb_parts, extract_raw_scene_paths_from_mb_parts},
    resolve_section_layout_hints,
    rewrite::{encode_chunk, encode_root_chunk, rewrite_attr_payload_string_preserving_shape},
};
use crate::{
    ma::types::PathReplaceRule,
    reference_semantics::{ScenePathAttrKind, classify_scene_path_attr},
    replace_rules::CompiledPathReplaceRules,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbPathReplaceRule {
    pub from: String,
    pub to: String,
    pub mode: crate::ma::types::PathReplaceMode,
}

pub fn replace_scene_paths_in_mb_cow<'a>(
    data: &'a [u8],
    root: &Chunk,
    rules: &[MbPathReplaceRule],
) -> Result<(Cow<'a, [u8]>, usize), crate::mb::MbRewriteError> {
    let compiled_rules = CompiledPathReplaceRules::compile_lossy(&normalize_mb_rules(rules));
    replace_raw_scene_paths_in_mb_with_rules(data, root, &compiled_rules, &|_, _| true)
}

fn replace_raw_scene_paths_in_mb_with_rules<'a>(
    data: &'a [u8],
    root: &Chunk,
    compiled_rules: &CompiledPathReplaceRules,
    accept_payload: &impl Fn(usize, usize) -> bool,
) -> Result<(Cow<'a, [u8]>, usize), crate::mb::MbRewriteError> {
    crate::mb::rewrite::require_complete_mb_sections(data, root)?;
    if compiled_rules.is_empty() || root.children().is_empty() {
        return Ok((Cow::Borrowed(data), 0));
    }
    let children = root.children();
    let mut payload_parts: Vec<u8> = Vec::new();
    payload_parts.extend_from_slice(root.form_type().unwrap_or(FourCC::new(*b"Maya")).as_bytes());

    let first_child_start = children[0].offset();
    let prefix_start = root.payload_offset() + 4;
    if first_child_start > prefix_start {
        payload_parts.extend_from_slice(&data[prefix_start..first_child_start]);
    }

    let mut total = 0usize;
    for child in children {
        let next_offset = crate::mb::rewrite::child_span_end(root, child);
        let original_span = &data[child.offset()..next_offset];

        if child.form_type().is_some_and(|f| f == "RTFT") {
            if let Some((rewritten, count)) =
                rewrite_rtft_child(child, data, compiled_rules, accept_payload)
            {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if child.form_type().is_some_and(|f| f == "FRDI") {
            if let Some((rewritten, count)) =
                rewrite_frdi_child(child, data, compiled_rules, accept_payload)
            {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if child.form_type().is_some_and(|f| f == "FREF") {
            if let Some((rewritten, count)) =
                rewrite_fref_child(child, data, compiled_rules, accept_payload)
            {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if child.form_type().is_some_and(|f| f == "HEAD") {
            if let Some((rewritten, count)) =
                rewrite_head_child(child, data, compiled_rules, accept_payload)
            {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        }

        payload_parts.extend_from_slice(original_span);
    }

    if total == 0 {
        return Ok((Cow::Borrowed(data), 0));
    }

    let Ok(encoded) = encode_root_chunk(root, &payload_parts) else {
        return Ok((Cow::Borrowed(data), 0));
    };
    Ok((Cow::Owned(encoded), total))
}

pub fn replace_scene_paths_in_mb(
    data: &[u8],
    root: &Chunk,
    rules: &[MbPathReplaceRule],
) -> Result<(Vec<u8>, usize), crate::mb::MbRewriteError> {
    replace_scene_paths_in_mb_cow(data, root, rules)
        .map(|(bytes, count)| (bytes.into_owned(), count))
}

pub fn replace_scene_paths_in_mb_by_index(
    data: &[u8],
    root: &Chunk,
    replacements: &[(usize, String)],
) -> Result<(Vec<u8>, usize), crate::mb::MbRewriteError> {
    replace_scene_paths_in_mb_by_index_cow(data, root, replacements)
        .map(|(bytes, count)| (bytes.into_owned(), count))
}

pub fn replace_scene_paths_in_mb_by_index_cow<'a>(
    data: &'a [u8],
    root: &Chunk,
    replacements: &[(usize, String)],
) -> Result<(Cow<'a, [u8]>, usize), crate::mb::MbRewriteError> {
    crate::mb::rewrite::require_complete_mb_sections(data, root)?;
    if replacements.is_empty() || root.children().is_empty() {
        return Ok((Cow::Borrowed(data), 0));
    }
    let targets = replacement_targets_for_mb(data, root, replacements);
    if targets.is_empty() {
        return Ok((Cow::Borrowed(data), 0));
    }

    let children = root.children();
    let mut payload_parts: Vec<u8> = Vec::new();
    payload_parts.extend_from_slice(root.form_type().unwrap_or(FourCC::new(*b"Maya")).as_bytes());

    let first_child_start = children[0].offset();
    let prefix_start = root.payload_offset() + 4;
    if first_child_start > prefix_start {
        payload_parts.extend_from_slice(&data[prefix_start..first_child_start]);
    }

    let mut total = 0usize;
    for child in children {
        let next_offset = crate::mb::rewrite::child_span_end(root, child);
        let original_span = &data[child.offset()..next_offset];

        if child.form_type().is_some_and(|f| f == "RTFT") {
            if let Some((rewritten, count)) =
                rewrite_rtft_child_by_targets(child, data, &targets, &|_, _| true)
            {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if child.form_type().is_some_and(|f| f == "FRDI") {
            if let Some((rewritten, count)) =
                rewrite_frdi_child_by_targets(child, data, &targets, &|_, _| true)
            {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if child.form_type().is_some_and(|f| f == "FREF") {
            if let Some((rewritten, count)) =
                rewrite_fref_child_by_targets(child, data, &targets, &|_, _| true)
            {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        }

        payload_parts.extend_from_slice(original_span);
    }

    if total == 0 {
        return Ok((Cow::Borrowed(data), 0));
    }

    let Ok(encoded) = encode_root_chunk(root, &payload_parts) else {
        return Ok((Cow::Borrowed(data), 0));
    };
    Ok((Cow::Owned(encoded), total))
}

fn rewrite_section_payloads_preserving_encode_fallback(
    inner: &[u8],
    parsed: &ParsedSection,
    rewritten_payloads: &[(usize, Vec<u8>)],
    can_encode_payload: impl Fn(usize, usize) -> bool,
) -> Option<Vec<u8>> {
    let rewrites: Vec<(usize, &[u8])> = rewritten_payloads
        .iter()
        .filter(|(index, payload)| can_encode_payload(*index, payload.len()))
        .map(|(index, payload)| (*index, payload.as_slice()))
        .collect();
    parsed.rewrite_payloads(inner, &rewrites).ok()
}

fn rewrite_rtft_child(
    child: &Chunk,
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
    accept_payload: &impl Fn(usize, usize) -> bool,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset()..child.payload_end()];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let hints = resolve_section_layout_hints(
        child.tag(),
        child.form_type(),
        child
            .child_layout()
            .map_or_else(LayoutHints::new, LayoutHints::from),
    );
    let parsed = parse_section_chunks_with_hints_with_budget(
        inner,
        hints,
        child
            .section_budget()
            .unwrap_or(&crate::mb::MbParseBudget::default()),
    );
    if parsed.chunks().is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks().iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag() != "STR " {
            continue;
        }
        if let Some((attr_name, kind, value_raw)) = decode_attr_triplet(chunk_payload) {
            if matches!(
                classify_scene_path_attr(&attr_name),
                Some(ScenePathAttrKind::FileTexturePath)
            ) {
                let value = decode_raw_string_value_preserving_whitespace_lossy(&value_raw);
                let (new_value, count) = compiled_rules.apply(&value);
                if count > 0 {
                    if let Some(rewritten_payload) = rewrite_attr_payload_string_preserving_shape(
                        chunk_payload,
                        kind,
                        &new_value,
                    ) {
                        if rewritten_payload != chunk_payload {
                            rewritten_payloads.push((idx, rewritten_payload));
                            total += count;
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    if !changed {
        return None;
    }

    let new_inner = rewrite_section_payloads_preserving_encode_fallback(
        inner,
        &parsed,
        &rewritten_payloads,
        |index, len| parsed.can_encode_payload(index, len) && accept_payload(index, len),
    )?;
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"RTFT");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag(),
        child.aux(),
        &new_payload,
        ChunkLayout::new(
            NonZeroUsize::new(4).expect("nonzero alignment"),
            child.header_format(),
        ),
    )
    .ok()?;
    Some((encoded_child, total))
}

fn rewrite_fref_child(
    child: &Chunk,
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
    accept_payload: &impl Fn(usize, usize) -> bool,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset()..child.payload_end()];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let hints = resolve_section_layout_hints(
        child.tag(),
        child.form_type(),
        child
            .child_layout()
            .map_or_else(LayoutHints::new, LayoutHints::from),
    );
    let parsed = parse_section_chunks_with_hints_with_budget(
        inner,
        hints,
        child
            .section_budget()
            .unwrap_or(&crate::mb::MbParseBudget::default()),
    );
    if parsed.chunks().is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks().iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag() != "FREF" {
            continue;
        }
        let (rewritten, count) =
            replace_first_path_field_in_nul_payload_with_rules(chunk_payload, compiled_rules);
        if count > 0 && rewritten != chunk_payload {
            rewritten_payloads.push((idx, rewritten));
            total += count;
            changed = true;
        }
    }

    if !changed {
        return None;
    }

    let new_inner = rewrite_section_payloads_preserving_encode_fallback(
        inner,
        &parsed,
        &rewritten_payloads,
        |index, len| parsed.can_encode_payload(index, len) && accept_payload(index, len),
    )?;
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"FREF");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag(),
        child.aux(),
        &new_payload,
        ChunkLayout::new(
            NonZeroUsize::new(4).expect("nonzero alignment"),
            child.header_format(),
        ),
    )
    .ok()?;
    Some((encoded_child, total))
}

fn rewrite_frdi_child(
    child: &Chunk,
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
    accept_payload: &impl Fn(usize, usize) -> bool,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset()..child.payload_end()];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let hints = resolve_section_layout_hints(
        child.tag(),
        child.form_type(),
        child
            .child_layout()
            .map_or_else(LayoutHints::new, LayoutHints::from),
    );
    let parsed = parse_section_chunks_with_hints_with_budget(
        inner,
        hints,
        child
            .section_budget()
            .unwrap_or(&crate::mb::MbParseBudget::default()),
    );
    if parsed.chunks().is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks().iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag() != "FRDI" {
            continue;
        }
        let (rewritten, count) =
            replace_path_field_in_frdi_payload_with_rules(chunk_payload, compiled_rules);
        if count > 0 && rewritten != chunk_payload {
            rewritten_payloads.push((idx, rewritten));
            total += count;
            changed = true;
        }
    }

    if !changed {
        return None;
    }

    let new_inner = rewrite_section_payloads_preserving_encode_fallback(
        inner,
        &parsed,
        &rewritten_payloads,
        |index, len| parsed.can_encode_payload(index, len) && accept_payload(index, len),
    )?;
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"FRDI");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag(),
        child.aux(),
        &new_payload,
        ChunkLayout::new(
            NonZeroUsize::new(4).expect("nonzero alignment"),
            child.header_format(),
        ),
    )
    .ok()?;
    Some((encoded_child, total))
}

fn rewrite_head_child(
    child: &Chunk,
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
    accept_payload: &impl Fn(usize, usize) -> bool,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset()..child.payload_end()];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let hints = resolve_section_layout_hints(
        child.tag(),
        child.form_type(),
        child
            .child_layout()
            .map_or_else(LayoutHints::new, LayoutHints::from),
    );
    let parsed = parse_section_chunks_with_hints_with_budget(
        inner,
        hints,
        child
            .section_budget()
            .unwrap_or(&crate::mb::MbParseBudget::default()),
    );
    if parsed.chunks().is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks().iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag() != "INCL" {
            continue;
        }
        let payload_text = String::from_utf8_lossy(chunk_payload);
        let payload_text = payload_text.trim_end_matches(char::from(0));
        let (new_text, count) = compiled_rules.apply(payload_text);
        if count == 0 {
            continue;
        }
        let rewritten_payload =
            replace_text_payload_preserving_nul_suffix(chunk_payload, new_text.as_ref());
        if rewritten_payload != chunk_payload {
            rewritten_payloads.push((idx, rewritten_payload));
            total += count;
            changed = true;
        }
    }

    if !changed {
        return None;
    }

    let new_inner = rewrite_section_payloads_preserving_encode_fallback(
        inner,
        &parsed,
        &rewritten_payloads,
        |index, len| parsed.can_encode_payload(index, len) && accept_payload(index, len),
    )?;
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"HEAD");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag(),
        child.aux(),
        &new_payload,
        ChunkLayout::new(
            NonZeroUsize::new(4).expect("nonzero alignment"),
            child.header_format(),
        ),
    )
    .ok()?;
    Some((encoded_child, total))
}

fn rewrite_rtft_child_by_targets(
    child: &Chunk,
    data: &[u8],
    targets: &HashMap<TargetKey, String>,
    accept_payload: &impl Fn(usize, usize) -> bool,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset()..child.payload_end()];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let hints = resolve_section_layout_hints(
        child.tag(),
        child.form_type(),
        child
            .child_layout()
            .map_or_else(LayoutHints::new, LayoutHints::from),
    );
    let parsed = parse_section_chunks_with_hints_with_budget(
        inner,
        hints,
        child
            .section_budget()
            .unwrap_or(&crate::mb::MbParseBudget::default()),
    );
    if parsed.chunks().is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks().iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag() != "STR " {
            continue;
        }
        if let Some((attr_name, kind, value_raw)) = decode_attr_triplet(chunk_payload) {
            if matches!(
                classify_scene_path_attr(&attr_name),
                Some(ScenePathAttrKind::FileTexturePath)
            ) {
                let value = decode_raw_string_value_preserving_whitespace_lossy(&value_raw);
                let key =
                    TargetKey::new("rtft", child.offset(), chunk.chunk_start(), value.clone());
                let Some(after_value) = targets.get(&key) else {
                    continue;
                };
                if let Some(rewritten_payload) =
                    rewrite_attr_payload_string_preserving_shape(chunk_payload, kind, after_value)
                {
                    if rewritten_payload != chunk_payload {
                        rewritten_payloads.push((idx, rewritten_payload));
                        total += 1;
                        changed = true;
                    }
                }
            }
        }
    }

    if !changed {
        return None;
    }

    let new_inner = rewrite_section_payloads_preserving_encode_fallback(
        inner,
        &parsed,
        &rewritten_payloads,
        |index, len| parsed.can_encode_payload(index, len) && accept_payload(index, len),
    )?;
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"RTFT");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag(),
        child.aux(),
        &new_payload,
        ChunkLayout::new(
            NonZeroUsize::new(4).expect("nonzero alignment"),
            child.header_format(),
        ),
    )
    .ok()?;
    Some((encoded_child, total))
}

fn rewrite_frdi_child_by_targets(
    child: &Chunk,
    data: &[u8],
    targets: &HashMap<TargetKey, String>,
    accept_payload: &impl Fn(usize, usize) -> bool,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset()..child.payload_end()];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let hints = resolve_section_layout_hints(
        child.tag(),
        child.form_type(),
        child
            .child_layout()
            .map_or_else(LayoutHints::new, LayoutHints::from),
    );
    let parsed = parse_section_chunks_with_hints_with_budget(
        inner,
        hints,
        child
            .section_budget()
            .unwrap_or(&crate::mb::MbParseBudget::default()),
    );
    if parsed.chunks().is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks().iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag() != "FRDI" {
            continue;
        }
        let Some(before_value) = path_field_from_frdi_payload(chunk_payload) else {
            continue;
        };
        let key = TargetKey::new(
            "frdi",
            child.offset(),
            chunk.chunk_start(),
            before_value.clone(),
        );
        let Some(after_value) = targets.get(&key) else {
            continue;
        };
        let (rewritten, count) =
            replace_path_field_in_frdi_payload_exact(chunk_payload, &before_value, after_value);
        if count > 0 && rewritten != chunk_payload {
            rewritten_payloads.push((idx, rewritten));
            total += count;
            changed = true;
        }
    }

    if !changed {
        return None;
    }

    let new_inner = rewrite_section_payloads_preserving_encode_fallback(
        inner,
        &parsed,
        &rewritten_payloads,
        |index, len| parsed.can_encode_payload(index, len) && accept_payload(index, len),
    )?;
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"FRDI");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag(),
        child.aux(),
        &new_payload,
        ChunkLayout::new(
            NonZeroUsize::new(4).expect("nonzero alignment"),
            child.header_format(),
        ),
    )
    .ok()?;
    Some((encoded_child, total))
}

fn rewrite_fref_child_by_targets(
    child: &Chunk,
    data: &[u8],
    targets: &HashMap<TargetKey, String>,
    accept_payload: &impl Fn(usize, usize) -> bool,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset()..child.payload_end()];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let hints = resolve_section_layout_hints(
        child.tag(),
        child.form_type(),
        child
            .child_layout()
            .map_or_else(LayoutHints::new, LayoutHints::from),
    );
    let parsed = parse_section_chunks_with_hints_with_budget(
        inner,
        hints,
        child
            .section_budget()
            .unwrap_or(&crate::mb::MbParseBudget::default()),
    );
    if parsed.chunks().is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks().iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag() != "FREF" {
            continue;
        }
        let Some(before_value) = first_path_field_from_nul_payload(chunk_payload) else {
            continue;
        };
        let key = TargetKey::new(
            "fref",
            child.offset(),
            chunk.chunk_start(),
            before_value.clone(),
        );
        let Some(after_value) = targets.get(&key) else {
            continue;
        };
        let (rewritten, count) = replace_first_path_field_in_nul_payload_exact(
            chunk_payload,
            &before_value,
            after_value,
        );
        if count > 0 && rewritten != chunk_payload {
            rewritten_payloads.push((idx, rewritten));
            total += count;
            changed = true;
        }
    }

    if !changed {
        return None;
    }

    let new_inner = rewrite_section_payloads_preserving_encode_fallback(
        inner,
        &parsed,
        &rewritten_payloads,
        |index, len| parsed.can_encode_payload(index, len) && accept_payload(index, len),
    )?;
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"FREF");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag(),
        child.aux(),
        &new_payload,
        ChunkLayout::new(
            NonZeroUsize::new(4).expect("nonzero alignment"),
            child.header_format(),
        ),
    )
    .ok()?;
    Some((encoded_child, total))
}

fn replace_first_path_field_in_nul_payload_with_rules(
    payload: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
) -> (Vec<u8>, usize) {
    let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
    if parts.is_empty() {
        return (payload.to_vec(), 0);
    }
    let mut replaced_count = 0usize;
    let mut replaced_index: Option<usize> = None;
    let mut replaced_value: Vec<u8> = Vec::new();

    if let Some(raw) = parts.first() {
        if let Ok(text) = std::str::from_utf8(raw) {
            if !text.is_empty() {
                let (new_text, count) = compiled_rules.apply(text);
                if count > 0 {
                    replaced_count = count;
                    replaced_index = Some(0);
                    replaced_value = new_text.into_owned().into_bytes();
                }
            }
        }
    }

    let Some(idx) = replaced_index else {
        return (payload.to_vec(), 0);
    };

    let mut out = Vec::new();
    for i in 0..parts.len() {
        if i == idx {
            out.extend_from_slice(&replaced_value);
        } else {
            out.extend_from_slice(parts[i]);
        }
        if i + 1 < parts.len() {
            out.push(0);
        }
    }
    (out, replaced_count)
}

fn replace_first_path_field_in_nul_payload_exact(
    payload: &[u8],
    expected: &str,
    replacement: &str,
) -> (Vec<u8>, usize) {
    let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
    if parts.is_empty() {
        return (payload.to_vec(), 0);
    }
    let Some(raw) = parts.first() else {
        return (payload.to_vec(), 0);
    };
    let Ok(text) = std::str::from_utf8(raw) else {
        return (payload.to_vec(), 0);
    };
    if text != expected {
        return (payload.to_vec(), 0);
    }

    let mut out = Vec::new();
    for i in 0..parts.len() {
        if i == 0 {
            out.extend_from_slice(replacement.as_bytes());
        } else {
            out.extend_from_slice(parts[i]);
        }
        if i + 1 < parts.len() {
            out.push(0);
        }
    }
    (out, 1)
}

fn first_path_field_from_nul_payload(payload: &[u8]) -> Option<String> {
    let raw = payload.split(|b| *b == 0).next()?;
    let text = std::str::from_utf8(raw).ok()?;
    (!text.is_empty()).then(|| text.to_string())
}

fn replace_path_field_in_frdi_payload_with_rules(
    payload: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
) -> (Vec<u8>, usize) {
    let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
    if parts.is_empty() {
        return (payload.to_vec(), 0);
    }

    let Some((idx, stripped_text)) = frdi_path_field_index(&parts) else {
        return (payload.to_vec(), 0);
    };

    let (new_text, count) = compiled_rules.apply(stripped_text);
    if count == 0 {
        return (payload.to_vec(), 0);
    }

    let raw = parts[idx];
    let prefix_len = raw
        .iter()
        .take_while(|byte| (**byte as char).is_control())
        .count();
    let mut replaced = raw[..prefix_len].to_vec();
    replaced.extend_from_slice(new_text.as_ref().as_bytes());

    let mut out = Vec::new();
    for i in 0..parts.len() {
        if i == idx {
            out.extend_from_slice(&replaced);
        } else {
            out.extend_from_slice(parts[i]);
        }
        if i + 1 < parts.len() {
            out.push(0);
        }
    }
    (out, count)
}

fn replace_path_field_in_frdi_payload_exact(
    payload: &[u8],
    expected: &str,
    replacement: &str,
) -> (Vec<u8>, usize) {
    let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
    if parts.is_empty() {
        return (payload.to_vec(), 0);
    }

    let Some((idx, stripped_text)) = frdi_path_field_index(&parts) else {
        return (payload.to_vec(), 0);
    };
    if stripped_text != expected {
        return (payload.to_vec(), 0);
    }

    let raw = parts[idx];
    let prefix_len = raw
        .iter()
        .take_while(|byte| (**byte as char).is_control())
        .count();
    let mut replaced = raw[..prefix_len].to_vec();
    replaced.extend_from_slice(replacement.as_bytes());

    let mut out = Vec::new();
    for i in 0..parts.len() {
        if i == idx {
            out.extend_from_slice(&replaced);
        } else {
            out.extend_from_slice(parts[i]);
        }
        if i + 1 < parts.len() {
            out.push(0);
        }
    }
    (out, 1)
}

fn path_field_from_frdi_payload(payload: &[u8]) -> Option<String> {
    let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
    let (_, path) = frdi_path_field_index(&parts)?;
    Some(path.to_string())
}

fn frdi_path_field_index<'a>(parts: &'a [&'a [u8]]) -> Option<(usize, &'a str)> {
    for (idx, raw) in parts.iter().enumerate() {
        let Some(text) = std::str::from_utf8(raw).ok() else {
            continue;
        };
        let stripped = text.trim_start_matches(|c: char| c.is_control()).trim();
        let lower = stripped.to_ascii_lowercase();
        if (lower.contains(".mb") || lower.contains(".ma") || lower.contains(".fbx"))
            && (stripped.contains('/') || stripped.contains('\\'))
        {
            return Some((idx, stripped));
        }
    }
    None
}

fn replace_text_payload_preserving_nul_suffix(payload: &[u8], replacement: &str) -> Vec<u8> {
    let nul_suffix_len = payload.iter().rev().take_while(|byte| **byte == 0).count();
    let mut out = Vec::with_capacity(replacement.len() + nul_suffix_len);
    out.extend_from_slice(replacement.as_bytes());
    out.extend(std::iter::repeat_n(0, nul_suffix_len));
    out
}

fn decode_raw_string_value_preserving_whitespace_lossy(raw: &[u8]) -> String {
    let value = String::from_utf8_lossy(raw);
    let value = value.trim_end_matches(char::from(0));
    if value.is_empty() {
        return String::new();
    }
    value.trim_matches('"').to_string()
}

fn decode_attr_triplet(payload: &[u8]) -> Option<(String, u8, Vec<u8>)> {
    let attr_end = payload.iter().position(|b| *b == 0)?;
    let attr_name = String::from_utf8_lossy(&payload[..attr_end]).to_string();
    let kind = *payload.get(attr_end + 1)?;
    let value_raw = payload.get(attr_end + 2..)?.to_vec();
    Some((attr_name, kind, value_raw))
}

fn normalize_mb_rules(rules: &[MbPathReplaceRule]) -> Vec<PathReplaceRule> {
    rules
        .iter()
        .map(|rule| PathReplaceRule {
            from: rule.from.clone(),
            to: rule.to.clone(),
            mode: rule.mode,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TargetKey {
    origin: String,
    outer_offset: usize,
    inner_chunk_start: usize,
    value: String,
}

impl TargetKey {
    fn new(
        origin: impl Into<String>,
        outer_offset: usize,
        inner_chunk_start: usize,
        value: impl Into<String>,
    ) -> Self {
        Self {
            origin: origin.into(),
            outer_offset,
            inner_chunk_start,
            value: value.into(),
        }
    }
}

fn replacement_targets_for_mb(
    data: &[u8],
    root: &Chunk,
    replacements: &[(usize, String)],
) -> HashMap<TargetKey, String> {
    let entries = extract_raw_scene_paths_from_mb_parts(data, root).value;
    let physical_entries = extract_raw_scene_path_records_from_mb_parts(data, root).value;
    let mut out = HashMap::new();

    for (index, after_value) in replacements {
        let Some(entry) = entries.get(*index) else {
            continue;
        };
        if entry.node_type == "reference" {
            let mut matched_physical_record = false;
            for physical_entry in &physical_entries {
                if physical_entry.node_type != "reference"
                    || physical_entry.value != entry.value
                    || !same_reference_identity(entry, physical_entry)
                {
                    continue;
                }
                if insert_replacement_target(&mut out, physical_entry, after_value) {
                    matched_physical_record = true;
                }
            }
            if matched_physical_record {
                continue;
            }
        }
        insert_replacement_target(&mut out, entry, after_value);
    }

    out
}

fn same_reference_identity(
    a: &crate::mb::paths::MbScenePathEntry,
    b: &crate::mb::paths::MbScenePathEntry,
) -> bool {
    let a_ref = a
        .meta
        .as_ref()
        .and_then(|meta| meta.reference_node.as_deref());
    let b_ref = b
        .meta
        .as_ref()
        .and_then(|meta| meta.reference_node.as_deref());
    match (a_ref, b_ref) {
        (Some(a_ref), Some(b_ref)) => a_ref == b_ref,
        _ => a.node_name == b.node_name,
    }
}

fn insert_replacement_target(
    out: &mut HashMap<TargetKey, String>,
    entry: &crate::mb::paths::MbScenePathEntry,
    after_value: &str,
) -> bool {
    let Some(meta) = entry.meta.as_ref() else {
        return false;
    };
    let Some(offset) = meta.trace_node_offset else {
        return false;
    };
    let Some(chunk_start) = meta.trace_child_chunk_start else {
        return false;
    };
    out.insert(
        TargetKey::new(
            meta.origin.clone(),
            offset,
            chunk_start,
            entry.value.clone(),
        ),
        after_value.to_string(),
    );
    true
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, num::NonZeroUsize};

    use tempfile::tempdir;

    use super::{
        MbPathReplaceRule, replace_scene_paths_in_mb, replace_scene_paths_in_mb_by_index,
        replace_scene_paths_in_mb_cow, replace_text_payload_preserving_nul_suffix,
        rewrite_rtft_child,
    };
    use crate::{
        mb::{
            ChunkLayout, FourCC, HeaderFormat, LayoutHints, parse_file,
            parse_section_chunks_with_hints, rewrite::encode_chunk,
        },
        replace_rules::CompiledPathReplaceRules,
    };

    fn replace_first_path_field_in_nul_payload(
        payload: &[u8],
        rules: &[MbPathReplaceRule],
    ) -> (Vec<u8>, usize) {
        let compiled_rules =
            CompiledPathReplaceRules::compile_lossy(&super::normalize_mb_rules(rules));
        super::replace_first_path_field_in_nul_payload_with_rules(payload, &compiled_rules)
    }

    fn replace_path_field_in_frdi_payload(
        payload: &[u8],
        rules: &[MbPathReplaceRule],
    ) -> (Vec<u8>, usize) {
        let compiled_rules =
            CompiledPathReplaceRules::compile_lossy(&super::normalize_mb_rules(rules));
        super::replace_path_field_in_frdi_payload_with_rules(payload, &compiled_rules)
    }

    fn with_opaque_tail(source: &[u8], tail: &[u8]) -> Vec<u8> {
        let parsed = crate::mb::parse_bytes(source.to_vec()).unwrap();
        assert_eq!(parsed.root().children().len(), 1);
        let child = &parsed.root().children()[0];
        let payload = parsed.payload(child);
        assert!(payload.ends_with(tail));
        let mut payload = payload[..payload.len() - tail.len()].to_vec();
        payload.extend_from_slice(&manual_chunk(b"DATA", 0, tail, HeaderFormat::EightByte, 8));
        let mut root_payload = b"Maya".to_vec();
        root_payload.extend_from_slice(&manual_chunk(
            b"FOR8",
            0,
            &payload,
            HeaderFormat::EightByte,
            4,
        ));
        manual_chunk(b"FOR8", 0, &root_payload, HeaderFormat::EightByte, 1)
    }

    fn build_mb_with_single_form(
        form: &str,
        inner_chunk_tag: &str,
        inner_chunk_payload: &[u8],
        inner_tail: &[u8],
    ) -> Vec<u8> {
        build_mb_with_forms(&[(form, inner_chunk_tag, inner_chunk_payload, inner_tail)])
    }

    fn build_mb_with_form_payloads(
        form: &str,
        inner_chunk_tag: &str,
        inner_chunk_payloads: &[&[u8]],
        inner_tail: &[u8],
    ) -> Vec<u8> {
        let mut inner = Vec::new();
        for inner_chunk_payload in inner_chunk_payloads {
            inner.extend_from_slice(
                &encode_chunk(
                    inner_chunk_tag.parse::<FourCC>().expect("4-byte tag"),
                    0,
                    inner_chunk_payload,
                    ChunkLayout::new(
                        NonZeroUsize::new(8).expect("nonzero alignment"),
                        HeaderFormat::EightByte,
                    ),
                )
                .expect("inner chunk"),
            );
        }
        inner.extend_from_slice(inner_tail);

        let mut child_payload = form.as_bytes().to_vec();
        child_payload.extend_from_slice(&inner);
        let child = encode_chunk(
            FourCC::new(*b"FOR8"),
            0,
            &child_payload,
            ChunkLayout::new(
                NonZeroUsize::new(4).expect("nonzero alignment"),
                HeaderFormat::EightByte,
            ),
        )
        .expect("child chunk");

        let mut root_payload = b"Maya".to_vec();
        root_payload.extend_from_slice(&child);
        encode_chunk(
            FourCC::new(*b"FOR8"),
            0,
            &root_payload,
            ChunkLayout::new(
                NonZeroUsize::new(1).expect("nonzero alignment"),
                HeaderFormat::EightByte,
            ),
        )
        .expect("root chunk")
    }

    fn build_mb_with_forms(forms: &[(&str, &str, &[u8], &[u8])]) -> Vec<u8> {
        let mut children = Vec::new();
        for (form, inner_chunk_tag, inner_chunk_payload, inner_tail) in forms {
            let mut inner = encode_chunk(
                inner_chunk_tag.parse::<FourCC>().expect("4-byte tag"),
                0,
                inner_chunk_payload,
                ChunkLayout::new(
                    NonZeroUsize::new(8).expect("nonzero alignment"),
                    HeaderFormat::EightByte,
                ),
            )
            .expect("inner chunk");
            inner.extend_from_slice(inner_tail);

            let mut child_payload = form.as_bytes().to_vec();
            child_payload.extend_from_slice(&inner);
            let child = encode_chunk(
                FourCC::new(*b"FOR8"),
                0,
                &child_payload,
                ChunkLayout::new(
                    NonZeroUsize::new(4).expect("nonzero alignment"),
                    HeaderFormat::EightByte,
                ),
            )
            .expect("child chunk");
            children.extend_from_slice(&child);
        }

        let mut root_payload = b"Maya".to_vec();
        root_payload.extend_from_slice(&children);
        encode_chunk(
            FourCC::new(*b"FOR8"),
            0,
            &root_payload,
            ChunkLayout::new(
                NonZeroUsize::new(1).expect("nonzero alignment"),
                HeaderFormat::EightByte,
            ),
        )
        .expect("root chunk")
    }

    #[test]
    fn replace_first_path_field_preserves_invalid_utf8_without_rewrite() {
        let payload = b"\xFFscene.mb\0charA\0charARN\0";
        let rules = vec![MbPathReplaceRule {
            from: "scene".to_string(),
            to: "asset".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_first_path_field_in_nul_payload(payload, &rules);
        assert_eq!(count, 0);
        assert_eq!(rewritten, payload);
    }

    #[test]
    fn replace_scene_paths_keeps_bytes_identical_without_match() {
        let mb = build_mb_with_single_form("RTFT", "STR ", b"ftn\0\x00old/path.mb\0", b"\xFA\xFB");
        let malformed = crate::mb::parse_bytes(mb.clone()).unwrap();
        assert!(replace_scene_paths_in_mb(&mb, malformed.root(), &[]).is_err());
        let mb = with_opaque_tail(&mb, &[0xFA, 0xFB]);
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let rules = vec![MbPathReplaceRule {
            from: "missing/".to_string(),
            to: "asset/".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_scene_paths_in_mb(&mb, parsed.root(), &rules).unwrap();
        assert_eq!(count, 0);
        assert_eq!(rewritten, mb);
    }

    #[test]
    fn replace_scene_paths_cow_borrows_input_without_match() {
        let mb = build_mb_with_single_form("RTFT", "STR ", b"ftn\0\x00old/path.mb\0", b"\xFA\xFB");
        let malformed = crate::mb::parse_bytes(mb.clone()).unwrap();
        assert!(replace_scene_paths_in_mb_cow(&mb, malformed.root(), &[]).is_err());
        let mb = with_opaque_tail(&mb, &[0xFA, 0xFB]);
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let rules = vec![MbPathReplaceRule {
            from: "missing/".to_string(),
            to: "asset/".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_scene_paths_in_mb_cow(&mb, parsed.root(), &rules).unwrap();
        assert_eq!(count, 0);
        assert!(matches!(rewritten, Cow::Borrowed(bytes) if bytes == mb.as_slice()));
    }

    #[test]
    fn replace_scene_paths_rtft_preserves_tail_and_non_nul_termination() {
        let mb =
            build_mb_with_single_form("RTFT", "STR ", b"ftn\0\x00old/path.mb", b"\xF1\xF2\xF3");
        let malformed = crate::mb::parse_bytes(mb.clone()).unwrap();
        assert!(replace_scene_paths_in_mb(&mb, malformed.root(), &[]).is_err());
        let mb = with_opaque_tail(&mb, &[0xF1, 0xF2, 0xF3]);
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        let output = dir.path().join("dst.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let rules = vec![MbPathReplaceRule {
            from: "old".to_string(),
            to: "new".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_scene_paths_in_mb(&mb, parsed.root(), &rules).unwrap();
        assert_eq!(count, 1);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root().children()[0];
        let payload = &parsed_rewritten.data()[child.payload_offset()..child.payload_end()];
        let hints = crate::mb::resolve_section_layout_hints(
            child.tag(),
            child.form_type(),
            child
                .child_layout()
                .map_or_else(LayoutHints::new, LayoutHints::from),
        );
        let parsed_section = parse_section_chunks_with_hints(&payload[4..], hints);
        assert!(parsed_section.tail(&payload[4..]).is_empty());
        assert_eq!(
            parsed_section
                .chunks()
                .last()
                .unwrap()
                .payload(&payload[4..]),
            &[0xF1, 0xF2, 0xF3]
        );
        let str_chunk = parsed_section
            .chunks()
            .iter()
            .find(|chunk| chunk.tag() == "STR ")
            .expect("str chunk");
        let str_payload = str_chunk.payload(&payload[4..]);
        assert!(!str_payload.ends_with(&[0]));
        assert!(String::from_utf8_lossy(str_payload).contains("new/path.mb"));
    }

    #[test]
    fn replace_scene_paths_rtft_rewrites_file_texture_name_attr() {
        let mut payload = b"RTFT".to_vec();
        payload.extend_from_slice(
            &encode_chunk(
                FourCC::new(*b"CREA"),
                0,
                b"psdTex1\0",
                ChunkLayout::new(
                    NonZeroUsize::new(8).expect("nonzero alignment"),
                    HeaderFormat::EightByte,
                ),
            )
            .expect("crea chunk"),
        );
        payload.extend_from_slice(
            &encode_chunk(
                FourCC::new(*b"STR "),
                0,
                b"fileTextureName\0\x00sourceimages/layered.psd\0",
                ChunkLayout::new(
                    NonZeroUsize::new(8).expect("nonzero alignment"),
                    HeaderFormat::EightByte,
                ),
            )
            .expect("str chunk"),
        );
        let child_bytes = encode_chunk(
            FourCC::new(*b"FOR8"),
            0,
            &payload,
            ChunkLayout::new(
                NonZeroUsize::new(8).expect("nonzero alignment"),
                HeaderFormat::EightByte,
            ),
        )
        .expect("child chunk");
        let parsed_child = crate::mb::parse_bytes_with_budget(
            child_bytes[..16 + payload.len()].to_vec(),
            &crate::mb::MbParseBudget {
                max_depth: 0,
                ..Default::default()
            },
        )
        .expect("parse child");
        let child = parsed_child.root();
        let rules = vec![MbPathReplaceRule {
            from: "sourceimages/".to_string(),
            to: "archive/".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];
        let compiled = CompiledPathReplaceRules::compile_lossy(&super::normalize_mb_rules(&rules));
        let (rewritten, count) =
            rewrite_rtft_child(child, &child_bytes, &compiled, &|_, _| true).expect("rtft rewrite");
        assert_eq!(count, 1);
        assert!(
            rewritten
                .windows(b"archive/layered.psd".len())
                .any(|window| window == b"archive/layered.psd")
        );
    }

    #[test]
    fn replace_scene_paths_fref_rewrites_only_first_slot_and_keeps_tail() {
        let mb = build_mb_with_single_form(
            "FREF",
            "FREF",
            b"old/char.mb\0charA\0charARN\0mayaBinary\0",
            b"\xCC\xDD",
        );
        let malformed = crate::mb::parse_bytes(mb.clone()).unwrap();
        assert!(replace_scene_paths_in_mb(&mb, malformed.root(), &[]).is_err());
        let mb = with_opaque_tail(&mb, &[0xCC, 0xDD]);
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        let output = dir.path().join("dst.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let rules = vec![MbPathReplaceRule {
            from: "old".to_string(),
            to: "new".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_scene_paths_in_mb(&mb, parsed.root(), &rules).unwrap();
        assert_eq!(count, 1);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root().children()[0];
        let payload = &parsed_rewritten.data()[child.payload_offset()..child.payload_end()];
        let hints = crate::mb::resolve_section_layout_hints(
            child.tag(),
            child.form_type(),
            child
                .child_layout()
                .map_or_else(LayoutHints::new, LayoutHints::from),
        );
        let parsed_section = parse_section_chunks_with_hints(&payload[4..], hints);
        assert!(parsed_section.tail(&payload[4..]).is_empty());
        assert_eq!(
            parsed_section
                .chunks()
                .last()
                .unwrap()
                .payload(&payload[4..]),
            &[0xCC, 0xDD]
        );
        let fref_chunk = parsed_section
            .chunks()
            .iter()
            .find(|chunk| chunk.tag() == "FREF")
            .expect("fref chunk");
        let fields: Vec<&[u8]> = fref_chunk
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        assert_eq!(fields[0], b"new/char.mb");
        assert_eq!(fields[1], b"charA");
        assert_eq!(fields[2], b"charARN");
    }

    #[test]
    fn replace_path_field_in_frdi_payload_preserves_control_prefix() {
        let payload = b"\x01old/char.mb\0charA\0\x01\0charARN\0VERS|2026|\0mayaBinary\0".to_vec();
        let rules = vec![MbPathReplaceRule {
            from: "old".to_string(),
            to: "new".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];

        let (rewritten, count) = replace_path_field_in_frdi_payload(&payload, &rules);
        assert_eq!(count, 1);
        let fields: Vec<&[u8]> = rewritten.split(|b| *b == 0).collect();
        assert_eq!(fields[0], b"\x01new/char.mb");
        assert_eq!(fields[1], b"charA");
        assert_eq!(fields[2], b"\x01");
    }

    #[test]
    fn replace_scene_paths_by_index_rewrites_frdi_reference_path() {
        let mb = build_mb_with_single_form(
            "FRDI",
            "FRDI",
            b"\x01\x04\0\x02asset/example/old_scene.mb\0Example\0\x01\0ExampleRN\0VERS|2026|\0mayaBinary\0",
            b"\xEE\xEF",
        );
        let malformed = crate::mb::parse_bytes(mb.clone()).unwrap();
        assert!(replace_scene_paths_in_mb_by_index(&mb, malformed.root(), &[]).is_err());
        let mb = with_opaque_tail(&mb, &[0xEE, 0xEF]);
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        let output = dir.path().join("dst.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let entries = super::extract_raw_scene_paths_from_mb_parts(&mb, parsed.root()).value;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "asset/example/old_scene.mb");

        let (rewritten, count) = replace_scene_paths_in_mb_by_index(
            &mb,
            parsed.root(),
            &[(0, "asset/example/new_scene.mb".to_string())],
        )
        .unwrap();
        assert_eq!(count, 1);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root().children()[0];
        let payload = &parsed_rewritten.data()[child.payload_offset()..child.payload_end()];
        let hints = crate::mb::resolve_section_layout_hints(
            child.tag(),
            child.form_type(),
            child
                .child_layout()
                .map_or_else(LayoutHints::new, LayoutHints::from),
        );
        let parsed_section = parse_section_chunks_with_hints(&payload[4..], hints);
        assert!(parsed_section.tail(&payload[4..]).is_empty());
        assert_eq!(
            parsed_section
                .chunks()
                .last()
                .unwrap()
                .payload(&payload[4..]),
            &[0xEE, 0xEF]
        );
        let frdi_chunk = parsed_section
            .chunks()
            .iter()
            .find(|chunk| chunk.tag() == "FRDI")
            .expect("frdi chunk");
        let fields: Vec<&[u8]> = frdi_chunk
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        assert_eq!(fields[1], b"\x02asset/example/new_scene.mb");
        assert_eq!(fields[2], b"Example");
        assert_eq!(fields[4], b"ExampleRN");
    }

    #[test]
    fn replace_scene_paths_by_index_rewrites_matching_fref_and_frdi_reference_records() {
        let mb = build_mb_with_forms(&[
            (
                "FREF",
                "FREF",
                b"asset/example/old_scene.mb\0Example\0ExampleRN\0mayaBinary\0",
                b"",
            ),
            (
                "FRDI",
                "FRDI",
                b"\x01\x04\0\x02asset/example/old_scene.mb\0Example\0\x01\0ExampleRN\0VERS|2026|\0mayaBinary\0",
                b"",
            ),
        ]);
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        let output = dir.path().join("dst.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        assert_eq!(parsed.root().children().len(), 2);
        assert_eq!(
            parsed.root().children()[0].form_type(),
            Some(FourCC::new(*b"FREF"))
        );
        assert_eq!(
            parsed.root().children()[1].form_type(),
            Some(FourCC::new(*b"FRDI"))
        );
        let entries = super::extract_raw_scene_paths_from_mb_parts(&mb, parsed.root()).value;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "asset/example/old_scene.mb");
        let targets = super::replacement_targets_for_mb(
            &mb,
            parsed.root(),
            &[(0, "asset/example/new_scene.mb".to_string())],
        );
        assert_eq!(targets.len(), 2);

        let (rewritten, count) = replace_scene_paths_in_mb_by_index(
            &mb,
            parsed.root(),
            &[(0, "asset/example/new_scene.mb".to_string())],
        )
        .unwrap();
        assert_eq!(count, 2);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let fref_child = &parsed_rewritten.root().children()[0];
        let fref_payload =
            &parsed_rewritten.data()[fref_child.payload_offset()..fref_child.payload_end()];
        let fref_section = parse_section_chunks_with_hints(
            &fref_payload[4..],
            LayoutHints::from_numeric(Some(8), Some(16)),
        );
        let fref_chunk = fref_section
            .chunks()
            .iter()
            .find(|chunk| chunk.tag() == "FREF")
            .expect("fref chunk");
        let fref_fields: Vec<&[u8]> = fref_chunk
            .payload(&fref_payload[4..])
            .split(|b| *b == 0)
            .collect();
        assert_eq!(fref_fields[0], b"asset/example/new_scene.mb");

        let frdi_child = &parsed_rewritten.root().children()[1];
        let frdi_payload =
            &parsed_rewritten.data()[frdi_child.payload_offset()..frdi_child.payload_end()];
        let frdi_section = parse_section_chunks_with_hints(
            &frdi_payload[4..],
            LayoutHints::from_numeric(Some(8), Some(16)),
        );
        let frdi_chunk = frdi_section
            .chunks()
            .iter()
            .find(|chunk| chunk.tag() == "FRDI")
            .expect("frdi chunk");
        let frdi_fields: Vec<&[u8]> = frdi_chunk
            .payload(&frdi_payload[4..])
            .split(|b| *b == 0)
            .collect();
        assert_eq!(frdi_fields[1], b"\x02asset/example/new_scene.mb");
    }

    #[test]
    fn replace_scene_paths_by_index_keeps_same_path_different_fref_record_unchanged() {
        let mb = build_mb_with_form_payloads(
            "FREF",
            "FREF",
            &[
                b"asset/example/shared_scene.mb\0ExampleA\0ExampleARN\0mayaBinary\0",
                b"asset/example/shared_scene.mb\0ExampleB\0ExampleBRN\0mayaBinary\0",
            ],
            b"",
        );
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        let output = dir.path().join("dst.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let entries = super::extract_raw_scene_paths_from_mb_parts(&mb, parsed.root()).value;
        assert_eq!(entries.len(), 2);

        let (rewritten, count) = replace_scene_paths_in_mb_by_index(
            &mb,
            parsed.root(),
            &[(0, "asset/example/first_scene.mb".to_string())],
        )
        .unwrap();
        assert_eq!(count, 1);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root().children()[0];
        let payload = &parsed_rewritten.data()[child.payload_offset()..child.payload_end()];
        let section = parse_section_chunks_with_hints(
            &payload[4..],
            LayoutHints::from_numeric(Some(8), Some(16)),
        );
        let fref_chunks: Vec<_> = section
            .chunks()
            .iter()
            .filter(|chunk| chunk.tag() == "FREF")
            .collect();
        assert_eq!(fref_chunks.len(), 2);
        let first_fields: Vec<&[u8]> = fref_chunks[0]
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        let second_fields: Vec<&[u8]> = fref_chunks[1]
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        assert_eq!(first_fields[0], b"asset/example/first_scene.mb");
        assert_eq!(first_fields[2], b"ExampleARN");
        assert_eq!(second_fields[0], b"asset/example/shared_scene.mb");
        assert_eq!(second_fields[2], b"ExampleBRN");
    }

    #[test]
    fn replace_scene_paths_by_index_keeps_same_path_different_frdi_record_unchanged() {
        let mb = build_mb_with_form_payloads(
            "FRDI",
            "FRDI",
            &[
                b"\x01\x04\0\x02asset/example/shared_scene.mb\0ExampleA\0\x01\0ExampleARN\0VERS|2026|\0mayaBinary\0",
                b"\x01\x04\0\x02asset/example/shared_scene.mb\0ExampleB\0\x01\0ExampleBRN\0VERS|2026|\0mayaBinary\0",
            ],
            b"",
        );
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        let output = dir.path().join("dst.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let entries = super::extract_raw_scene_paths_from_mb_parts(&mb, parsed.root()).value;
        assert_eq!(entries.len(), 2);

        let (rewritten, count) = replace_scene_paths_in_mb_by_index(
            &mb,
            parsed.root(),
            &[(0, "asset/example/first_scene.mb".to_string())],
        )
        .unwrap();
        assert_eq!(count, 1);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root().children()[0];
        let payload = &parsed_rewritten.data()[child.payload_offset()..child.payload_end()];
        let section = parse_section_chunks_with_hints(
            &payload[4..],
            LayoutHints::from_numeric(Some(8), Some(16)),
        );
        let frdi_chunks: Vec<_> = section
            .chunks()
            .iter()
            .filter(|chunk| chunk.tag() == "FRDI")
            .collect();
        assert_eq!(frdi_chunks.len(), 2);
        let first_fields: Vec<&[u8]> = frdi_chunks[0]
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        let second_fields: Vec<&[u8]> = frdi_chunks[1]
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        assert_eq!(first_fields[1], b"\x02asset/example/first_scene.mb");
        assert_eq!(first_fields[4], b"ExampleARN");
        assert_eq!(second_fields[1], b"\x02asset/example/shared_scene.mb");
        assert_eq!(second_fields[4], b"ExampleBRN");
    }

    #[test]
    fn replace_scene_paths_by_index_can_apply_distinct_same_path_replacements() {
        let mb = build_mb_with_form_payloads(
            "FREF",
            "FREF",
            &[
                b"asset/example/shared_scene.mb\0ExampleA\0ExampleARN\0mayaBinary\0",
                b"asset/example/shared_scene.mb\0ExampleB\0ExampleBRN\0mayaBinary\0",
            ],
            b"",
        );
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        let output = dir.path().join("dst.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let entries = super::extract_raw_scene_paths_from_mb_parts(&mb, parsed.root()).value;
        assert_eq!(entries.len(), 2);

        let (rewritten, count) = replace_scene_paths_in_mb_by_index(
            &mb,
            parsed.root(),
            &[
                (0, "asset/example/first_scene.mb".to_string()),
                (1, "asset/example/second_scene.mb".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(count, 2);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root().children()[0];
        let payload = &parsed_rewritten.data()[child.payload_offset()..child.payload_end()];
        let section = parse_section_chunks_with_hints(
            &payload[4..],
            LayoutHints::from_numeric(Some(8), Some(16)),
        );
        let fref_chunks: Vec<_> = section
            .chunks()
            .iter()
            .filter(|chunk| chunk.tag() == "FREF")
            .collect();
        assert_eq!(fref_chunks.len(), 2);
        let first_fields: Vec<&[u8]> = fref_chunks[0]
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        let second_fields: Vec<&[u8]> = fref_chunks[1]
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        assert_eq!(first_fields[0], b"asset/example/first_scene.mb");
        assert_eq!(second_fields[0], b"asset/example/second_scene.mb");
    }

    #[test]
    fn replace_scene_paths_by_index_rewrites_frdi_fbx_reference_path() {
        let mb = build_mb_with_single_form(
            "FRDI",
            "FRDI",
            b"\x01\x04\0\x02asset/example/ExampleAsset.fbx\0Example\0\x01\0ExampleRN\0VERS|2026|\0FBX\0",
            b"",
        );
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        let output = dir.path().join("dst.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let entries = super::extract_raw_scene_paths_from_mb_parts(&mb, parsed.root()).value;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "asset/example/ExampleAsset.fbx");

        let (rewritten, count) = replace_scene_paths_in_mb_by_index(
            &mb,
            parsed.root(),
            &[(0, "asset/example/UpdatedAsset.fbx".to_string())],
        )
        .unwrap();
        assert_eq!(count, 1);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root().children()[0];
        let payload = &parsed_rewritten.data()[child.payload_offset()..child.payload_end()];
        let section = parse_section_chunks_with_hints(
            &payload[4..],
            LayoutHints::from_numeric(Some(8), Some(16)),
        );
        let frdi_chunk = section
            .chunks()
            .iter()
            .find(|chunk| chunk.tag() == "FRDI")
            .expect("frdi chunk");
        let fields: Vec<&[u8]> = frdi_chunk
            .payload(&payload[4..])
            .split(|b| *b == 0)
            .collect();
        assert_eq!(fields[1], b"\x02asset/example/UpdatedAsset.fbx");
    }

    #[test]
    fn replace_text_payload_preserves_nul_suffix() {
        let rewritten =
            replace_text_payload_preserving_nul_suffix(b"old/char.mb(\0\0", "new/char.mb(");
        assert_eq!(rewritten, b"new/char.mb(\0\0");
    }

    fn literal_rules(from: &str, to: &str) -> Vec<MbPathReplaceRule> {
        vec![MbPathReplaceRule {
            from: from.into(),
            to: to.into(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }]
    }

    fn manual_chunk(
        tag: &[u8; 4],
        aux: u32,
        payload: &[u8],
        header: HeaderFormat,
        alignment: usize,
    ) -> Vec<u8> {
        let mut bytes = tag.to_vec();
        match header {
            HeaderFormat::FourByte => {
                bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes())
            }
            HeaderFormat::EightByte => {
                bytes.extend_from_slice(&aux.to_be_bytes());
                bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            }
        }
        bytes.extend_from_slice(payload);
        while bytes.len() % alignment != 0 {
            bytes.push(0);
        }
        bytes
    }

    fn path_cases() -> [(&'static str, &'static str, &'static [u8]); 4] {
        [
            ("RTFT", "STR ", b"ftn\0\0asset/example/file.mb\0"),
            (
                "FREF",
                "FREF",
                b"asset/example/file.mb\0Example\0ExampleRN\0",
            ),
            (
                "FRDI",
                "FRDI",
                b"\x01asset/example/file.mb\0Example\0\x01\0ExampleRN\0",
            ),
            ("HEAD", "INCL", b"asset/example/file.mb\0"),
        ]
    }

    fn rewrite_case(
        form: &str,
        by_targets: bool,
        child: &crate::mb::Chunk,
        data: &[u8],
        accept_payload: &impl Fn(usize, usize) -> bool,
    ) -> (Vec<u8>, usize) {
        let rules = CompiledPathReplaceRules::compile_lossy(&super::normalize_mb_rules(
            &literal_rules("file", "test"),
        ));
        if by_targets {
            let inner = &data[child.payload_offset() + 4..child.payload_end()];
            let parsed = parse_section_chunks_with_hints(
                inner,
                LayoutHints::new().with_header_format(HeaderFormat::EightByte),
            );
            let targets = parsed
                .chunks()
                .iter()
                .filter(|chunk| chunk.tag() != "DATA")
                .map(|chunk| {
                    (
                        super::TargetKey::new(
                            form.to_ascii_lowercase(),
                            child.offset(),
                            chunk.chunk_start(),
                            "asset/example/file.mb",
                        ),
                        "asset/example/test.mb".to_string(),
                    )
                })
                .collect();
            match form {
                "RTFT" => {
                    super::rewrite_rtft_child_by_targets(child, data, &targets, accept_payload)
                }
                "FRDI" => {
                    super::rewrite_frdi_child_by_targets(child, data, &targets, accept_payload)
                }
                "FREF" => {
                    super::rewrite_fref_child_by_targets(child, data, &targets, accept_payload)
                }
                _ => None,
            }
            .unwrap()
        } else {
            match form {
                "RTFT" => super::rewrite_rtft_child(child, data, &rules, accept_payload),
                "FRDI" => super::rewrite_frdi_child(child, data, &rules, accept_payload),
                "FREF" => super::rewrite_fref_child(child, data, &rules, accept_payload),
                "HEAD" => super::rewrite_head_child(child, data, &rules, accept_payload),
                _ => None,
            }
            .unwrap()
        }
    }

    #[test]
    fn encode_error_facade_is_the_same_type() {
        let error: crate::mb::EncodeError = maya_mb::EncodeError::DuplicateRewrite { index: 2 };
        let original: maya_mb::EncodeError = error.clone();
        assert_eq!(error, original);
        assert_eq!(error.to_string(), "duplicate rewrite for chunk index 2");
    }

    #[test]
    fn head_same_length_rewrite_completes_missing_inner_padding() {
        let source = b"FOR4\0\0\0\x1cMayaFOR4\0\0\0\x0dHEADINCL\0\0\0\x01X\0\0\0";
        let parsed = crate::mb::parse_bytes(source.to_vec()).unwrap();
        let rules = literal_rules("X", "Y");
        let compiled = CompiledPathReplaceRules::compile_lossy(&super::normalize_mb_rules(&rules));
        let (child, count) =
            super::rewrite_head_child(&parsed.root().children()[0], source, &compiled, &|_, _| {
                true
            })
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(child, b"FOR4\0\0\0\x10HEADINCL\0\0\0\x01Y\0\0\0");
        let (rewritten, total) = replace_scene_paths_in_mb(source, parsed.root(), &rules).unwrap();
        assert_eq!(total, 1);
        assert_eq!(
            rewritten,
            b"FOR4\0\0\0\x1cMayaFOR4\0\0\0\x10HEADINCL\0\0\0\x01Y\0\0\0"
        );
    }

    #[test]
    fn head_same_length_rewrite_preserves_complete_nonzero_four_byte_padding() {
        let source = b"FOR4\0\0\0\x1cMayaFOR4\0\0\0\x10HEADINCL\0\0\0\x01X\xA1\xB2\xC3";
        let parsed = crate::mb::parse_bytes(source.to_vec()).unwrap();
        let (rewritten, count) =
            replace_scene_paths_in_mb(source, parsed.root(), &literal_rules("X", "Y")).unwrap();
        assert_eq!(count, 1);
        let output = crate::mb::parse_bytes(rewritten.clone()).unwrap();
        let child = &output.root().children()[0];
        assert_eq!(
            &rewritten[child.payload_offset() + 4..child.payload_end()],
            b"INCL\0\0\0\x01Y\xA1\xB2\xC3"
        );
    }

    #[test]
    fn all_seven_rewriters_preserve_complete_nonzero_padding() {
        for (form, tag, payload) in path_cases() {
            let mut payload = payload.to_vec();
            if (16 + payload.len()) % 8 == 0 {
                payload.push(0);
            }
            let mut inner = manual_chunk(
                tag.as_bytes().try_into().unwrap(),
                0x11223344,
                &payload,
                HeaderFormat::EightByte,
                8,
            );
            let pad_start = 16 + payload.len();
            let pad_end = inner.len();
            assert!(pad_start < pad_end);
            inner[pad_start..].fill(0xCC);
            let mut neighbor =
                manual_chunk(b"DATA", 0x55667788, b"Example", HeaderFormat::EightByte, 8);
            *neighbor.last_mut().unwrap() = 0xDD;
            inner.extend_from_slice(&neighbor);
            inner.extend_from_slice(&[0xFA, 0xFB, 0xFC]);
            let mut child_payload = form.as_bytes().to_vec();
            child_payload.extend_from_slice(&inner);
            let child_bytes = manual_chunk(
                b"FOR8",
                0x12345678,
                &child_payload,
                HeaderFormat::EightByte,
                4,
            );
            let mut root_payload = b"Maya".to_vec();
            root_payload.extend_from_slice(&child_bytes);
            let source = manual_chunk(b"FOR8", 0, &root_payload, HeaderFormat::EightByte, 1);
            let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
            let child = &parsed.root().children()[0];
            let mut expected = child_bytes.clone();
            let path_start = expected
                .windows(4)
                .position(|bytes| bytes == b"file")
                .unwrap();
            expected[path_start..path_start + 4].copy_from_slice(b"test");
            let mut legacy = expected.clone();
            legacy[20 + pad_start..20 + pad_end].fill(0);
            for by_targets in [false, true] {
                if by_targets && form == "HEAD" {
                    continue;
                }
                let (rewritten, count) =
                    rewrite_case(form, by_targets, child, &source, &|_, _| true);
                assert_eq!(count, 1, "{form}, targets={by_targets}");
                assert_eq!(rewritten, expected, "{form}, targets={by_targets}");
                assert_eq!(&rewritten[..16], &child_bytes[..16]);
                assert_eq!(
                    rewritten
                        .iter()
                        .zip(&legacy)
                        .enumerate()
                        .filter(|(_, (a, b))| a != b)
                        .map(|(index, _)| index)
                        .collect::<Vec<_>>(),
                    (20 + pad_start..20 + pad_end).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn all_seven_rewriters_keep_individual_fallback_and_counts() {
        for (form, tag, payload) in path_cases() {
            let mut source = build_mb_with_form_payloads(
                form,
                tag,
                &[payload, payload, payload],
                &[0xFA, 0xFB, 0xFC],
            );
            let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
            let child = &parsed.root().children()[0];
            assert!(child.payload_end() < source.len());
            source[child.payload_end()..].fill(0xDD);
            let inner = &source[child.payload_offset() + 4..child.payload_end()];
            let section = parse_section_chunks_with_hints(
                inner,
                LayoutHints::new().with_header_format(HeaderFormat::EightByte),
            );
            assert_eq!(section.chunks().len(), 3);
            for rejected in [vec![0, 2], vec![0, 1, 2]] {
                let accept_payload = |index, _| !rejected.contains(&index);
                let mut expected_inner = inner.to_vec();
                if rejected.len() == 2 {
                    let chunk = &section.chunks()[1];
                    let span = chunk.payload_span();
                    let path_start = span.start
                        + inner[span.start..span.end]
                            .windows(4)
                            .position(|bytes| bytes == b"file")
                            .unwrap();
                    expected_inner[path_start..path_start + 4].copy_from_slice(b"test");
                }
                let mut expected_payload = form.as_bytes().to_vec();
                expected_payload.extend_from_slice(&expected_inner);
                let expected =
                    manual_chunk(b"FOR8", 0, &expected_payload, HeaderFormat::EightByte, 4);
                for by_targets in [false, true] {
                    if by_targets && form == "HEAD" {
                        continue;
                    }
                    let (rewritten, count) =
                        rewrite_case(form, by_targets, child, &source, &accept_payload);
                    assert_eq!(count, 3, "{form}, targets={by_targets}");
                    assert_eq!(rewritten, expected, "{form}, targets={by_targets}");
                    assert!(
                        rewritten[16 + expected_payload.len()..]
                            .iter()
                            .all(|byte| *byte == 0)
                    );
                    assert_ne!(&rewritten, &source[child.offset()..]);
                }
                let compiled = CompiledPathReplaceRules::compile_lossy(&super::normalize_mb_rules(
                    &literal_rules("file", "test"),
                ));
                assert!(
                    super::replace_raw_scene_paths_in_mb_with_rules(
                        &source,
                        parsed.root(),
                        &compiled,
                        &accept_payload,
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn user_indices_keep_last_duplicate_ignore_invalid_and_rewrite_other_records() {
        let source = build_mb_with_form_payloads(
            "FREF",
            "FREF",
            &[
                b"asset/example/file.mb\0Example\0ExampleRN\0",
                b"asset/example/other.mb\0Sample\0SampleRN\0",
            ],
            &[0xFA, 0xFB],
        );
        let malformed = crate::mb::parse_bytes(source.clone()).unwrap();
        assert!(replace_scene_paths_in_mb_by_index(&source, malformed.root(), &[]).is_err());
        let source = with_opaque_tail(&source, &[0xFA, 0xFB]);
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let entries = super::extract_raw_scene_paths_from_mb_parts(&source, parsed.root()).value;
        assert_eq!(entries.len(), 2);
        let first = entries
            .iter()
            .position(|entry| entry.value == "asset/example/file.mb")
            .unwrap();
        let second = entries
            .iter()
            .position(|entry| entry.value == "asset/example/other.mb")
            .unwrap();
        let (rewritten, count) = replace_scene_paths_in_mb_by_index(
            &source,
            parsed.root(),
            &[
                (first, "asset/example/ignored.mb".into()),
                (entries.len(), "asset/example/invalid.mb".into()),
                (first, "asset/example/test.mb".into()),
                (usize::MAX, "asset/example/invalid.mb".into()),
                (second, "asset/example/sample.mb".into()),
            ],
        )
        .unwrap();
        assert_eq!(count, 2);
        let output = crate::mb::parse_bytes(rewritten.clone()).unwrap();
        let values = super::extract_raw_scene_paths_from_mb_parts(&rewritten, output.root())
            .value
            .into_iter()
            .map(|entry| entry.value)
            .collect::<Vec<_>>();
        assert_eq!(values[first], "asset/example/test.mb");
        assert_eq!(values[second], "asset/example/sample.mb");
    }

    #[test]
    fn root_builders_match_manual_headers_without_trailing_padding() {
        fn expected_form(form: &str, tag: &str, payloads: &[&[u8]], tail: &[u8]) -> Vec<u8> {
            let mut payload = form.as_bytes().to_vec();
            for inner in payloads {
                payload.extend_from_slice(&manual_chunk(
                    tag.as_bytes().try_into().unwrap(),
                    0,
                    inner,
                    HeaderFormat::EightByte,
                    8,
                ));
            }
            payload.extend_from_slice(tail);
            manual_chunk(b"FOR8", 0, &payload, HeaderFormat::EightByte, 4)
        }
        let payloads: &[&[u8]] = &[b"X", b"Example"];
        for count in 0..=2 {
            let actual = build_mb_with_form_payloads("TEST", "DATA", &payloads[..count], b"end");
            let mut root_payload = b"Maya".to_vec();
            root_payload.extend_from_slice(&expected_form(
                "TEST",
                "DATA",
                &payloads[..count],
                b"end",
            ));
            assert_eq!(
                actual,
                manual_chunk(b"FOR8", 0, &root_payload, HeaderFormat::EightByte, 1)
            );
            assert_eq!(actual.len(), 16 + root_payload.len());
        }
        let forms: &[(&str, &str, &[u8], &[u8])] = &[
            ("TEST", "DATA", b"X", b"end"),
            ("TEST", "DATA", b"Example", b"end"),
        ];
        for count in 0..=2 {
            let actual = build_mb_with_forms(&forms[..count]);
            let mut root_payload = b"Maya".to_vec();
            for (form, tag, payload, tail) in &forms[..count] {
                root_payload.extend_from_slice(&expected_form(form, tag, &[payload], tail));
            }
            assert_eq!(root_payload.len() % 8, 4);
            assert_eq!(
                actual,
                manual_chunk(b"FOR8", 0, &root_payload, HeaderFormat::EightByte, 1)
            );
            assert_eq!(actual.len(), 16 + root_payload.len());
        }
    }
}
