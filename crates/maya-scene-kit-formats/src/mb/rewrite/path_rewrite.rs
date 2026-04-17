use std::{borrow::Cow, collections::HashMap};

// MB rewrite helpers intentionally stay chunk-oriented so replacement can preserve
// binary layout details without becoming the canonical semantic inspection path.
use crate::mb::{
    Chunk, parse_section_chunks_full_with_hints,
    paths::extract_raw_scene_paths_from_mb_parts,
    resolve_section_layout_hints,
    rewrite::{
        chunk_header_format_from_chunk, encode_chunk, encode_root_chunk,
        rebuild_section_with_payload_rewrites, rewrite_attr_payload_string_preserving_shape,
    },
};
use crate::{ma::types::PathReplaceRule, replace_rules::CompiledPathReplaceRules};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbPathReplaceRule {
    pub from: String,
    pub to: String,
    pub mode: crate::ma::types::PathReplaceMode,
}

pub(crate) fn replace_raw_scene_paths_in_mb(
    data: &[u8],
    root: &Chunk,
    rules: &[MbPathReplaceRule],
) -> (Vec<u8>, usize) {
    let compiled_rules = CompiledPathReplaceRules::compile_lossy(&normalize_mb_rules(rules));
    let (rewritten, count) = replace_raw_scene_paths_in_mb_with_rules(data, root, &compiled_rules);
    (rewritten.into_owned(), count)
}

pub fn replace_scene_paths_in_mb_cow<'a>(
    data: &'a [u8],
    root: &Chunk,
    rules: &[MbPathReplaceRule],
) -> (Cow<'a, [u8]>, usize) {
    let compiled_rules = CompiledPathReplaceRules::compile_lossy(&normalize_mb_rules(rules));
    replace_raw_scene_paths_in_mb_with_rules(data, root, &compiled_rules)
}

fn replace_raw_scene_paths_in_mb_with_rules<'a>(
    data: &'a [u8],
    root: &Chunk,
    compiled_rules: &CompiledPathReplaceRules,
) -> (Cow<'a, [u8]>, usize) {
    if compiled_rules.is_empty() || root.children.is_empty() {
        return (Cow::Borrowed(data), 0);
    }
    let children = &root.children;
    let mut payload_parts: Vec<u8> = Vec::new();
    payload_parts.extend_from_slice(root.form_type.as_deref().unwrap_or("Maya").as_bytes());

    let first_child_start = children[0].offset;
    let prefix_start = root.payload_offset + 4;
    if first_child_start > prefix_start {
        payload_parts.extend_from_slice(&data[prefix_start..first_child_start]);
    }

    let mut total = 0usize;
    for (idx, child) in children.iter().enumerate() {
        let next_offset = if idx + 1 < children.len() {
            children[idx + 1].offset
        } else {
            root.payload_end
        };
        let original_span = &data[child.offset..next_offset];
        let form = child.form_type.as_deref().unwrap_or("");

        if form == "RTFT" {
            if let Some((rewritten, count)) = rewrite_rtft_child(child, data, compiled_rules) {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if form == "FRDI" {
            if let Some((rewritten, count)) = rewrite_frdi_child(child, data, compiled_rules) {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if form == "FREF" {
            if let Some((rewritten, count)) = rewrite_fref_child(child, data, compiled_rules) {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if form == "HEAD" {
            if let Some((rewritten, count)) = rewrite_head_child(child, data, compiled_rules) {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        }

        payload_parts.extend_from_slice(original_span);
    }

    if total == 0 {
        return (Cow::Borrowed(data), 0);
    }

    let Some(encoded) = encode_root_chunk(root, &payload_parts) else {
        return (Cow::Borrowed(data), 0);
    };
    (Cow::Owned(encoded), total)
}

pub fn replace_scene_paths_in_mb(
    data: &[u8],
    root: &Chunk,
    rules: &[MbPathReplaceRule],
) -> (Vec<u8>, usize) {
    replace_raw_scene_paths_in_mb(data, root, rules)
}

pub fn replace_scene_paths_in_mb_by_index(
    data: &[u8],
    root: &Chunk,
    replacements: &[(usize, String)],
) -> (Vec<u8>, usize) {
    replace_scene_paths_in_mb_by_index_cow(data, root, replacements).map_owned()
}

pub fn replace_scene_paths_in_mb_by_index_cow<'a>(
    data: &'a [u8],
    root: &Chunk,
    replacements: &[(usize, String)],
) -> (Cow<'a, [u8]>, usize) {
    if replacements.is_empty() || root.children.is_empty() {
        return (Cow::Borrowed(data), 0);
    }
    let targets = replacement_targets_for_mb(data, root, replacements);
    if targets.is_empty() {
        return (Cow::Borrowed(data), 0);
    }

    let children = &root.children;
    let mut payload_parts: Vec<u8> = Vec::new();
    payload_parts.extend_from_slice(root.form_type.as_deref().unwrap_or("Maya").as_bytes());

    let first_child_start = children[0].offset;
    let prefix_start = root.payload_offset + 4;
    if first_child_start > prefix_start {
        payload_parts.extend_from_slice(&data[prefix_start..first_child_start]);
    }

    let mut total = 0usize;
    for (idx, child) in children.iter().enumerate() {
        let next_offset = if idx + 1 < children.len() {
            children[idx + 1].offset
        } else {
            root.payload_end
        };
        let original_span = &data[child.offset..next_offset];
        let form = child.form_type.as_deref().unwrap_or("");

        if form == "RTFT" {
            if let Some((rewritten, count)) = rewrite_rtft_child_by_targets(child, data, &targets) {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        } else if form == "FREF" {
            if let Some((rewritten, count)) = rewrite_fref_child_by_targets(child, data, &targets) {
                payload_parts.extend_from_slice(&rewritten);
                total += count;
                continue;
            }
        }

        payload_parts.extend_from_slice(original_span);
    }

    if total == 0 {
        return (Cow::Borrowed(data), 0);
    }

    let Some(encoded) = encode_root_chunk(root, &payload_parts) else {
        return (Cow::Borrowed(data), 0);
    };
    (Cow::Owned(encoded), total)
}

fn rewrite_rtft_child(
    child: &Chunk,
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (child_alignment, child_header_size) = resolve_section_layout_hints(
        &child.tag,
        child.form_type.as_deref(),
        child.child_alignment,
        child.child_header_size,
    );
    let parsed = parse_section_chunks_full_with_hints(inner, child_alignment, child_header_size);
    if parsed.chunks.is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks.iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag != "STR " {
            continue;
        }
        if let Some((attr_name, kind, value_raw)) = decode_attr_triplet(chunk_payload) {
            if attr_name == "ftn" || attr_name == ".ftn" {
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

    let new_inner = rebuild_section_with_payload_rewrites(inner, &parsed, &rewritten_payloads);
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"RTFT");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag.as_str(),
        child.aux,
        &new_payload,
        4,
        chunk_header_format_from_chunk(child),
    )?;
    Some((encoded_child, total))
}

fn rewrite_fref_child(
    child: &Chunk,
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (child_alignment, child_header_size) = resolve_section_layout_hints(
        &child.tag,
        child.form_type.as_deref(),
        child.child_alignment,
        child.child_header_size,
    );
    let parsed = parse_section_chunks_full_with_hints(inner, child_alignment, child_header_size);
    if parsed.chunks.is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks.iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag != "FREF" {
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

    let new_inner = rebuild_section_with_payload_rewrites(inner, &parsed, &rewritten_payloads);
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"FREF");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag.as_str(),
        child.aux,
        &new_payload,
        4,
        chunk_header_format_from_chunk(child),
    )?;
    Some((encoded_child, total))
}

fn rewrite_frdi_child(
    child: &Chunk,
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (child_alignment, child_header_size) = resolve_section_layout_hints(
        &child.tag,
        child.form_type.as_deref(),
        child.child_alignment,
        child.child_header_size,
    );
    let parsed = parse_section_chunks_full_with_hints(inner, child_alignment, child_header_size);
    if parsed.chunks.is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks.iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag != "FRDI" {
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

    let new_inner = rebuild_section_with_payload_rewrites(inner, &parsed, &rewritten_payloads);
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"FRDI");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag.as_str(),
        child.aux,
        &new_payload,
        4,
        chunk_header_format_from_chunk(child),
    )?;
    Some((encoded_child, total))
}

fn rewrite_head_child(
    child: &Chunk,
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (child_alignment, child_header_size) = resolve_section_layout_hints(
        &child.tag,
        child.form_type.as_deref(),
        child.child_alignment,
        child.child_header_size,
    );
    let parsed = parse_section_chunks_full_with_hints(inner, child_alignment, child_header_size);
    if parsed.chunks.is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks.iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag != "INCL" {
            continue;
        }
        let payload_text = String::from_utf8_lossy(chunk_payload);
        let payload_text = payload_text.trim_end_matches(char::from(0));
        let (new_text, count) = compiled_rules.apply(&payload_text);
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

    let new_inner = rebuild_section_with_payload_rewrites(inner, &parsed, &rewritten_payloads);
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"HEAD");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag.as_str(),
        child.aux,
        &new_payload,
        4,
        chunk_header_format_from_chunk(child),
    )?;
    Some((encoded_child, total))
}

fn rewrite_rtft_child_by_targets(
    child: &Chunk,
    data: &[u8],
    targets: &HashMap<TargetKey, String>,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (child_alignment, child_header_size) = resolve_section_layout_hints(
        &child.tag,
        child.form_type.as_deref(),
        child.child_alignment,
        child.child_header_size,
    );
    let parsed = parse_section_chunks_full_with_hints(inner, child_alignment, child_header_size);
    if parsed.chunks.is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks.iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag != "STR " {
            continue;
        }
        if let Some((attr_name, kind, value_raw)) = decode_attr_triplet(chunk_payload) {
            if attr_name == "ftn" || attr_name == ".ftn" {
                let value = decode_raw_string_value_preserving_whitespace_lossy(&value_raw);
                let key = ("rtft".to_string(), child.offset, value.clone());
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

    let new_inner = rebuild_section_with_payload_rewrites(inner, &parsed, &rewritten_payloads);
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"RTFT");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag.as_str(),
        child.aux,
        &new_payload,
        4,
        chunk_header_format_from_chunk(child),
    )?;
    Some((encoded_child, total))
}

fn rewrite_fref_child_by_targets(
    child: &Chunk,
    data: &[u8],
    targets: &HashMap<TargetKey, String>,
) -> Option<(Vec<u8>, usize)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (child_alignment, child_header_size) = resolve_section_layout_hints(
        &child.tag,
        child.form_type.as_deref(),
        child.child_alignment,
        child.child_header_size,
    );
    let parsed = parse_section_chunks_full_with_hints(inner, child_alignment, child_header_size);
    if parsed.chunks.is_empty() {
        return None;
    }

    let mut changed = false;
    let mut total = 0usize;
    let mut rewritten_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, chunk) in parsed.chunks.iter().enumerate() {
        let chunk_payload = chunk.payload(inner);
        if chunk.tag != "FREF" {
            continue;
        }
        let Some(before_value) = first_path_field_from_nul_payload(chunk_payload) else {
            continue;
        };
        let key = ("fref".to_string(), child.offset, before_value.clone());
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

    let new_inner = rebuild_section_with_payload_rewrites(inner, &parsed, &rewritten_payloads);
    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"FREF");
    new_payload.extend_from_slice(&new_inner);
    let encoded_child = encode_chunk(
        child.tag.as_str(),
        child.aux,
        &new_payload,
        4,
        chunk_header_format_from_chunk(child),
    )?;
    Some((encoded_child, total))
}

#[cfg(test)]
pub(crate) fn replace_first_path_field_in_nul_payload(
    payload: &[u8],
    rules: &[MbPathReplaceRule],
) -> (Vec<u8>, usize) {
    let compiled_rules = CompiledPathReplaceRules::compile_lossy(&normalize_mb_rules(rules));
    replace_first_path_field_in_nul_payload_with_rules(payload, &compiled_rules)
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

#[cfg(test)]
fn replace_path_field_in_frdi_payload(
    payload: &[u8],
    rules: &[MbPathReplaceRule],
) -> (Vec<u8>, usize) {
    let compiled_rules = CompiledPathReplaceRules::compile_lossy(&normalize_mb_rules(rules));
    replace_path_field_in_frdi_payload_with_rules(payload, &compiled_rules)
}

fn replace_path_field_in_frdi_payload_with_rules(
    payload: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
) -> (Vec<u8>, usize) {
    let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
    if parts.is_empty() {
        return (payload.to_vec(), 0);
    }

    let mut path_index = None;
    let mut stripped_text = "";
    for (idx, raw) in parts.iter().enumerate() {
        let Some(text) = std::str::from_utf8(raw).ok() else {
            continue;
        };
        let stripped = text.trim_start_matches(|c: char| c.is_control()).trim();
        let lower = stripped.to_ascii_lowercase();
        if (lower.contains(".mb") || lower.contains(".ma"))
            && (stripped.contains('/') || stripped.contains('\\'))
        {
            path_index = Some(idx);
            stripped_text = stripped;
            break;
        }
    }

    let Some(idx) = path_index else {
        return (payload.to_vec(), 0);
    };

    let (new_text, count) = compiled_rules.apply(&stripped_text);
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

type TargetKey = (String, usize, String);

fn replacement_targets_for_mb(
    data: &[u8],
    root: &Chunk,
    replacements: &[(usize, String)],
) -> HashMap<TargetKey, String> {
    let entries = extract_raw_scene_paths_from_mb_parts(data, root);
    let mut out = HashMap::new();

    for (index, after_value) in replacements {
        let Some(entry) = entries.get(*index) else {
            continue;
        };
        let Some(meta) = entry.meta.as_ref() else {
            continue;
        };
        let Some(offset) = meta.trace_node_offset else {
            continue;
        };
        out.insert(
            (meta.origin.clone(), offset, entry.value.clone()),
            after_value.clone(),
        );
    }

    out
}

trait IntoOwnedBytes {
    fn map_owned(self) -> (Vec<u8>, usize);
}

impl<'a> IntoOwnedBytes for (Cow<'a, [u8]>, usize) {
    fn map_owned(self) -> (Vec<u8>, usize) {
        (self.0.into_owned(), self.1)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use tempfile::tempdir;

    use super::{
        super::chunk_encode::append_chunk_header, MbPathReplaceRule,
        replace_first_path_field_in_nul_payload, replace_path_field_in_frdi_payload,
        replace_scene_paths_in_mb, replace_scene_paths_in_mb_cow,
        replace_text_payload_preserving_nul_suffix,
    };
    use crate::mb::{
        parse_file, parse_section_chunks_full_with_hints, rewrite::encode_chunk,
        section::SectionHeaderFormat,
    };

    fn build_mb_with_single_form(
        form: &str,
        inner_chunk_tag: &str,
        inner_chunk_payload: &[u8],
        inner_tail: &[u8],
    ) -> Vec<u8> {
        let mut inner = encode_chunk(
            inner_chunk_tag,
            0,
            inner_chunk_payload,
            8,
            SectionHeaderFormat::EightByte,
        )
        .expect("inner chunk");
        inner.extend_from_slice(inner_tail);

        let mut child_payload = form.as_bytes().to_vec();
        child_payload.extend_from_slice(&inner);
        let child = encode_chunk("FOR8", 0, &child_payload, 8, SectionHeaderFormat::EightByte)
            .expect("child chunk");

        let mut root_payload = b"Maya".to_vec();
        root_payload.extend_from_slice(&child);
        let mut root = Vec::new();
        append_chunk_header(
            &mut root,
            "FOR8",
            0,
            root_payload.len(),
            SectionHeaderFormat::EightByte,
        )
        .expect("root chunk");
        root.extend_from_slice(&root_payload);
        root
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
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let rules = vec![MbPathReplaceRule {
            from: "missing/".to_string(),
            to: "asset/".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_scene_paths_in_mb(&mb, &parsed.root, &rules);
        assert_eq!(count, 0);
        assert_eq!(rewritten, mb);
    }

    #[test]
    fn replace_scene_paths_cow_borrows_input_without_match() {
        let mb = build_mb_with_single_form("RTFT", "STR ", b"ftn\0\x00old/path.mb\0", b"\xFA\xFB");
        let dir = tempdir().expect("tmp");
        let input = dir.path().join("src.mb");
        std::fs::write(&input, &mb).expect("write");
        let parsed = parse_file(&input).expect("parse");
        let rules = vec![MbPathReplaceRule {
            from: "missing/".to_string(),
            to: "asset/".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_scene_paths_in_mb_cow(&mb, &parsed.root, &rules);
        assert_eq!(count, 0);
        assert!(matches!(rewritten, Cow::Borrowed(bytes) if bytes == mb.as_slice()));
    }

    #[test]
    fn replace_scene_paths_rtft_preserves_tail_and_non_nul_termination() {
        let mb =
            build_mb_with_single_form("RTFT", "STR ", b"ftn\0\x00old/path.mb", b"\xF1\xF2\xF3");
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
        let (rewritten, count) = replace_scene_paths_in_mb(&mb, &parsed.root, &rules);
        assert_eq!(count, 1);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root.children[0];
        let payload = &parsed_rewritten.data[child.payload_offset..child.payload_end];
        let (child_alignment, child_header_size) = crate::mb::resolve_section_layout_hints(
            &child.tag,
            child.form_type.as_deref(),
            child.child_alignment,
            child.child_header_size,
        );
        let parsed_section =
            parse_section_chunks_full_with_hints(&payload[4..], child_alignment, child_header_size);
        assert_eq!(parsed_section.tail(&payload[4..]), &[0xF1, 0xF2, 0xF3]);
        let str_chunk = parsed_section
            .chunks
            .iter()
            .find(|chunk| chunk.tag == "STR ")
            .expect("str chunk");
        let str_payload = str_chunk.payload(&payload[4..]);
        assert!(!str_payload.ends_with(&[0]));
        assert!(String::from_utf8_lossy(str_payload).contains("new/path.mb"));
    }

    #[test]
    fn replace_scene_paths_fref_rewrites_only_first_slot_and_keeps_tail() {
        let mb = build_mb_with_single_form(
            "FREF",
            "FREF",
            b"old/char.mb\0charA\0charARN\0mayaBinary\0",
            b"\xCC\xDD",
        );
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
        let (rewritten, count) = replace_scene_paths_in_mb(&mb, &parsed.root, &rules);
        assert_eq!(count, 1);
        std::fs::write(&output, &rewritten).expect("write");

        let parsed_rewritten = parse_file(&output).expect("parse");
        let child = &parsed_rewritten.root.children[0];
        let payload = &parsed_rewritten.data[child.payload_offset..child.payload_end];
        let (child_alignment, child_header_size) = crate::mb::resolve_section_layout_hints(
            &child.tag,
            child.form_type.as_deref(),
            child.child_alignment,
            child.child_header_size,
        );
        let parsed_section =
            parse_section_chunks_full_with_hints(&payload[4..], child_alignment, child_header_size);
        assert_eq!(parsed_section.tail(&payload[4..]), &[0xCC, 0xDD]);
        let fref_chunk = parsed_section
            .chunks
            .iter()
            .find(|chunk| chunk.tag == "FREF")
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
    fn replace_text_payload_preserves_nul_suffix() {
        let rewritten =
            replace_text_payload_preserving_nul_suffix(b"old/char.mb(\0\0", "new/char.mb(");
        assert_eq!(rewritten, b"new/char.mb(\0\0");
    }
}
