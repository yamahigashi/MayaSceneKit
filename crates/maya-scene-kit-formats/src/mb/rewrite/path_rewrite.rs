use std::{borrow::Cow, collections::HashMap, num::NonZeroUsize, ops::Range};

use super::{MbPayloadLocator, MbRewriteError, encode_chunk, encode_root_chunk};
use crate::{
    PathReplaceSkips,
    ma::types::PathReplaceRule,
    mb::{
        Chunk, ChunkLayout, FourCC,
        paths::{
            extract_raw_scene_path_records_from_mb_parts, extract_raw_scene_paths_from_mb_parts,
        },
    },
    reference_semantics::{ScenePathAttrKind, classify_scene_path_attr},
    replace_rules::CompiledPathReplaceRules,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbPathReplaceRule {
    pub from: String,
    pub to: String,
    pub mode: crate::ma::types::PathReplaceMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbPathStatus {
    Applied,
    Unchanged,
    Undecodable,
    PayloadRejected,
    UnmatchedLocator,
    DuplicateRequest,
}

#[derive(Debug, Clone)]
pub struct MbPathChange {
    pub locator: Option<MbPayloadLocator>,
    pub entry_index: Option<usize>,
    pub before_value: Option<String>,
    pub after_value: Option<String>,
    pub status: MbPathStatus,
}

#[derive(Debug, Clone)]
pub struct MbPathChanges {
    pub replacement_count: usize,
    pub skipped: PathReplaceSkips,
    pub paths: Vec<MbPathChange>,
}

impl Default for MbPathChanges {
    fn default() -> Self {
        Self {
            replacement_count: 0,
            skipped: PathReplaceSkips::binary(),
            paths: Vec::new(),
        }
    }
}

impl MbPathChanges {
    fn push(&mut self, change: MbPathChange) {
        match change.status {
            MbPathStatus::Applied => self.replacement_count += 1,
            MbPathStatus::Undecodable => self.skipped.non_utf8 += 1,
            MbPathStatus::PayloadRejected => *self.skipped.payload_rejected.as_mut().unwrap() += 1,
            MbPathStatus::UnmatchedLocator => {
                *self.skipped.unmatched_locator.as_mut().unwrap() += 1
            }
            MbPathStatus::DuplicateRequest => {
                *self.skipped.duplicate_request.as_mut().unwrap() += 1
            }
            MbPathStatus::Unchanged => {}
        }
        self.paths.push(change);
    }
}

type SectionEncoder = fn(
    &maya_mb::ParsedSection,
    &[u8],
    &[(usize, &[u8])],
) -> Result<Vec<u8>, crate::mb::EncodeError>;
type ChunkEncoder = fn(&Chunk, &[u8]) -> Result<Vec<u8>, crate::mb::EncodeError>;

struct PathEncoders {
    section: SectionEncoder,
    child: ChunkEncoder,
    root: ChunkEncoder,
}

impl Default for PathEncoders {
    fn default() -> Self {
        Self {
            section: maya_mb::ParsedSection::rewrite_payloads,
            child: |child, payload| {
                encode_chunk(
                    child.tag(),
                    child.aux(),
                    payload,
                    ChunkLayout::new(NonZeroUsize::new(4).unwrap(), child.header_format()),
                )
            },
            root: encode_root_chunk,
        }
    }
}

enum Replacement<'a> {
    Rules(&'a CompiledPathReplaceRules),
    Targets(&'a HashMap<TargetKey, String>),
}

pub fn replace_scene_paths_in_mb_cow<'a>(
    data: &'a [u8],
    root: &Chunk,
    rules: &[MbPathReplaceRule],
) -> Result<(Cow<'a, [u8]>, MbPathChanges), MbRewriteError> {
    let compiled = CompiledPathReplaceRules::compile_lossy(&normalize_mb_rules(rules));
    replace_raw_scene_paths_in_mb_with_rules(data, root, &compiled, &|_, _| true)
}

fn replace_raw_scene_paths_in_mb_with_rules<'a>(
    data: &'a [u8],
    root: &Chunk,
    rules: &CompiledPathReplaceRules,
    accept: &impl Fn(usize, usize) -> bool,
) -> Result<(Cow<'a, [u8]>, MbPathChanges), MbRewriteError> {
    replace_mb_paths(
        data,
        root,
        Replacement::Rules(rules),
        accept,
        MbPathChanges::default(),
        &PathEncoders::default(),
    )
}

pub fn replace_scene_paths_in_mb(
    data: &[u8],
    root: &Chunk,
    rules: &[MbPathReplaceRule],
) -> Result<(Vec<u8>, MbPathChanges), MbRewriteError> {
    replace_scene_paths_in_mb_cow(data, root, rules)
        .map(|(bytes, changes)| (bytes.into_owned(), changes))
}

pub fn replace_scene_paths_in_mb_by_index(
    data: &[u8],
    root: &Chunk,
    replacements: &[(usize, String)],
) -> Result<(Vec<u8>, MbPathChanges), MbRewriteError> {
    replace_scene_paths_in_mb_by_index_cow(data, root, replacements)
        .map(|(bytes, changes)| (bytes.into_owned(), changes))
}

pub fn replace_scene_paths_in_mb_by_index_cow<'a>(
    data: &'a [u8],
    root: &Chunk,
    replacements: &[(usize, String)],
) -> Result<(Cow<'a, [u8]>, MbPathChanges), MbRewriteError> {
    super::require_complete_mb_sections(data, root)?;
    let mut changes = MbPathChanges::default();
    let mut seen = std::collections::BTreeSet::new();
    for (index, _) in replacements {
        if !seen.insert(index) {
            changes.push(MbPathChange {
                locator: None,
                entry_index: Some(*index),
                before_value: None,
                after_value: None,
                status: MbPathStatus::DuplicateRequest,
            });
        }
    }
    let targets = replacement_targets_for_mb(data, root, replacements);
    let entries = extract_raw_scene_paths_from_mb_parts(data, root).value;
    for index in seen {
        if entries.get(*index).is_none_or(|entry| {
            entry.meta.as_ref().is_none_or(|meta| {
                meta.trace_node_offset.is_none() || meta.trace_child_chunk_start.is_none()
            })
        }) {
            changes.push(MbPathChange {
                locator: None,
                entry_index: Some(*index),
                before_value: None,
                after_value: None,
                status: MbPathStatus::UnmatchedLocator,
            });
        }
    }
    replace_mb_paths(
        data,
        root,
        Replacement::Targets(&targets),
        &|_, _| true,
        changes,
        &PathEncoders::default(),
    )
}

fn replace_mb_paths<'a>(
    data: &'a [u8],
    root: &Chunk,
    replacement: Replacement<'_>,
    accept: &impl Fn(usize, usize) -> bool,
    mut changes: MbPathChanges,
    encoders: &PathEncoders,
) -> Result<(Cow<'a, [u8]>, MbPathChanges), MbRewriteError> {
    super::require_complete_mb_sections(data, root)?;
    if root.children().is_empty()
        || match &replacement {
            Replacement::Rules(rules) => rules.is_empty(),
            Replacement::Targets(targets) => targets.is_empty(),
        }
    {
        return Ok((Cow::Borrowed(data), changes));
    }
    let entries = extract_raw_scene_paths_from_mb_parts(data, root).value;
    let mut entry_indices = HashMap::new();
    let physical = extract_raw_scene_path_records_from_mb_parts(data, root).value;
    let references: HashMap<_, _> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.node_type == "reference")
        .map(|(index, entry)| ((reference_identity(entry), entry.value.as_str()), index))
        .collect();
    for (index, entry) in entries.iter().enumerate() {
        if let Some(meta) = &entry.meta
            && let (Some(outer), Some(inner)) =
                (meta.trace_node_offset, meta.trace_child_chunk_start)
        {
            entry_indices.insert((outer, inner), index);
        }
    }
    for entry in &physical {
        if entry.node_type == "reference"
            && let Some(index) = references.get(&(reference_identity(entry), entry.value.as_str()))
            && let Some(meta) = &entry.meta
            && let (Some(outer), Some(inner)) =
                (meta.trace_node_offset, meta.trace_child_chunk_start)
        {
            entry_indices.insert((outer, inner), *index);
        }
    }
    let mut payload = root
        .form_type()
        .unwrap_or(FourCC::new(*b"Maya"))
        .as_bytes()
        .to_vec();
    let mut cursor = root.payload_offset() + 4;
    for child in root.children() {
        payload.extend_from_slice(&data[cursor..child.offset()]);
        let (bytes, child_changes) =
            rewrite_path_child(root, child, data, &replacement, accept, encoders)?;
        let end = super::child_span_end(root, child);
        if child_changes.replacement_count == 0 {
            payload.extend_from_slice(&data[child.offset()..end]);
        } else {
            payload.extend_from_slice(&bytes);
        }
        cursor = end;
        for mut change in child_changes.paths {
            change.entry_index = change.locator.as_ref().and_then(|locator| {
                entry_indices
                    .get(&(locator.node_offset, locator.chunk_start))
                    .copied()
            });
            changes.push(change);
        }
    }
    payload.extend_from_slice(&data[cursor..root.payload_end()]);
    if let Replacement::Targets(targets) = &replacement {
        for key in targets.keys() {
            if !changes.paths.iter().any(|change| {
                change.locator.as_ref().is_some_and(|locator| {
                    locator.node_offset == key.outer_offset
                        && locator.chunk_start == key.inner_chunk_start
                })
            }) {
                changes.push(MbPathChange {
                    locator: Some(MbPayloadLocator {
                        form: key.origin.to_ascii_uppercase(),
                        node_offset: key.outer_offset,
                        chunk_start: key.inner_chunk_start,
                    }),
                    entry_index: entry_indices
                        .get(&(key.outer_offset, key.inner_chunk_start))
                        .copied(),
                    before_value: Some(key.value.clone()),
                    after_value: Some(key.value.clone()),
                    status: MbPathStatus::UnmatchedLocator,
                });
            }
        }
    }
    if changes.replacement_count == 0 {
        return Ok((Cow::Borrowed(data), changes));
    }
    let bytes = (encoders.root)(root, &payload).map_err(MbRewriteError::RootEncode)?;
    Ok((Cow::Owned(bytes), changes))
}

fn path_value_range(form: &str, tag: &str, payload: &[u8]) -> Option<Range<usize>> {
    let start = match (form, tag) {
        ("RTFT", "STR ") => {
            let end = payload.iter().position(|byte| *byte == 0)?;
            let attr = std::str::from_utf8(&payload[..end]).ok()?;
            if classify_scene_path_attr(attr) != Some(ScenePathAttrKind::FileTexturePath) {
                return None;
            }
            return super::attr_payload::attr_value_range(payload);
        }
        ("HEAD", "INCL") | ("FREF", "FREF") => 0,
        ("FRDI", "FRDI") => {
            let mut offset = 0;
            let mut found = None;
            for part in payload.split(|byte| *byte == 0) {
                let prefix = part
                    .iter()
                    .take_while(|byte| (**byte as char).is_control())
                    .count();
                let raw = &part[prefix..];
                let lower: Vec<_> = raw.iter().map(u8::to_ascii_lowercase).collect();
                if raw.iter().any(|byte| matches!(byte, b'/' | b'\\'))
                    && [b".mb".as_slice(), b".ma", b".fbx"]
                        .iter()
                        .any(|ext| lower.windows(ext.len()).any(|window| window == *ext))
                {
                    found = Some(offset + prefix);
                    break;
                }
                offset += part.len() + 1;
            }
            found?
        }
        _ => return None,
    };
    let raw = payload.get(start..)?;
    let end = if form == "HEAD" {
        payload.len() - raw.iter().rev().take_while(|byte| **byte == 0).count()
    } else {
        start + raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len())
    };
    Some(start..end)
}

fn inner_quoted(value: &str) -> (&str, bool) {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        (&value[1..value.len() - 1], true)
    } else {
        (value, false)
    }
}

fn rewrite_path_child(
    root: &Chunk,
    child: &Chunk,
    data: &[u8],
    replacement: &Replacement<'_>,
    accept: &impl Fn(usize, usize) -> bool,
    encoders: &PathEncoders,
) -> Result<(Vec<u8>, MbPathChanges), MbRewriteError> {
    let mut changes = MbPathChanges::default();
    let form = child
        .form_type()
        .map(|form| form.to_string())
        .unwrap_or_default();
    if !matches!(form.as_str(), "RTFT" | "FREF" | "FRDI" | "HEAD") {
        return Ok((Vec::new(), changes));
    }
    let payload = &data[child.payload_offset()..child.payload_end()];
    let Some(inner) = payload.get(4..) else {
        return Ok((Vec::new(), changes));
    };
    let parsed = super::parse_complete_section(inner, child, root)?;
    let mut rewrites = Vec::new();
    for (index, chunk) in parsed.chunks().iter().enumerate() {
        let raw = chunk.payload(inner);
        let Some(range) = path_value_range(&form, &chunk.tag().to_string(), raw) else {
            continue;
        };
        let locator = MbPayloadLocator {
            form: form.clone(),
            node_offset: child.offset(),
            chunk_start: chunk.chunk_start(),
        };
        let target = match replacement {
            Replacement::Targets(targets) => {
                let target = targets.iter().find(|(key, _)| {
                    key.outer_offset == child.offset()
                        && key.inner_chunk_start == chunk.chunk_start()
                });
                let Some(target) = target else {
                    continue;
                };
                Some(target)
            }
            Replacement::Rules(rules) if rules.is_empty() => continue,
            Replacement::Rules(_) => None,
        };
        let mut change = MbPathChange {
            locator: Some(locator),
            entry_index: None,
            before_value: None,
            after_value: None,
            status: MbPathStatus::Undecodable,
        };
        let Ok(value) = std::str::from_utf8(&raw[range.clone()]) else {
            changes.push(change);
            continue;
        };
        change.before_value = Some(value.to_owned());
        change.after_value = Some(value.to_owned());
        let (inside, quoted) = if form == "RTFT" {
            inner_quoted(value)
        } else if form == "FRDI" {
            (value.trim(), false)
        } else {
            (value, false)
        };
        let after = match (replacement, target) {
            (Replacement::Rules(rules), _) => rules.apply(inside).0.into_owned(),
            (_, Some((key, after))) => {
                if key.value != value.trim() {
                    change.status = MbPathStatus::UnmatchedLocator;
                    changes.push(change);
                    continue;
                }
                if quoted {
                    inner_quoted(after).0.to_owned()
                } else {
                    after.clone()
                }
            }
            _ => unreachable!(),
        };
        let after = if form == "FRDI" {
            let start = value.len() - value.trim_start().len();
            let end = start + inside.len();
            format!("{}{after}{}", &value[..start], &value[end..])
        } else if quoted {
            format!("\"{after}\"")
        } else {
            after
        };
        if after == value {
            change.status = MbPathStatus::Unchanged;
            changes.push(change);
            continue;
        }
        let mut rewritten = raw.to_vec();
        rewritten.splice(range, after.bytes());
        if !parsed.can_encode_payload(index, rewritten.len()) || !accept(index, rewritten.len()) {
            change.status = MbPathStatus::PayloadRejected;
        } else {
            change.status = MbPathStatus::Applied;
            change.after_value = Some(after);
            rewrites.push((index, rewritten));
        }
        changes.push(change);
    }
    if changes.replacement_count == 0 {
        let end = (child.payload_end() + (4 - child.size() % 4) % 4).min(data.len());
        return Ok((data[child.offset()..end].to_vec(), changes));
    }
    let refs: Vec<_> = rewrites
        .iter()
        .map(|(index, bytes)| (*index, bytes.as_slice()))
        .collect();
    let new_inner =
        (encoders.section)(&parsed, inner, &refs).map_err(MbRewriteError::SectionEncode)?;
    let mut new_payload = form.as_bytes().to_vec();
    new_payload.extend_from_slice(&new_inner);
    let bytes = (encoders.child)(child, &new_payload).map_err(MbRewriteError::ChildEncode)?;
    Ok((bytes, changes))
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

#[derive(Debug, Clone)]
pub struct MbPathCandidatePlan {
    pub entry_index: usize,
    pub locator: super::MbPayloadLocator,
    pub entry: crate::mb::paths::MbScenePathEntry,
    pub before: Vec<u8>,
}

pub fn collect_mb_path_candidates(
    data: &[u8],
    root: &Chunk,
    indices: &[usize],
) -> Result<Vec<MbPathCandidatePlan>, super::MbPlanError> {
    super::require_complete_mb_sections(data, root)?;
    let entries = extract_raw_scene_paths_from_mb_parts(data, root).value;
    let mut candidates = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for &entry_index in indices {
        let entry = entries
            .get(entry_index)
            .ok_or(super::MbPlanError::MissingEntry { entry_index })?;
        let targets = replacement_targets_for_mb(data, root, &[(entry_index, entry.value.clone())]);
        if targets.is_empty() {
            return Err(super::MbPlanError::MissingEntry { entry_index });
        }
        for (key, _) in targets {
            let child = root
                .children()
                .iter()
                .find(|child| child.offset() == key.outer_offset)
                .ok_or(super::MbPlanError::MissingEntry { entry_index })?;
            let locator = super::MbPayloadLocator {
                form: child
                    .form_type()
                    .map(|form| form.to_string())
                    .unwrap_or_default(),
                node_offset: key.outer_offset,
                chunk_start: key.inner_chunk_start,
            };
            if !seen.insert(locator.clone()) {
                return Err(super::MbPlanError::AmbiguousEntry { entry_index });
            }
            let inner = &data[child.payload_offset() + 4..child.payload_end()];
            let parsed = super::parse_complete_section(inner, child, root)?;
            let before = parsed
                .chunks()
                .iter()
                .find(|chunk| chunk.chunk_start() == locator.chunk_start)
                .ok_or_else(|| super::MbPlanError::InvalidLocator(format!("{locator:?}")))?
                .payload(inner)
                .to_vec();
            candidates.push(MbPathCandidatePlan {
                entry_index,
                locator,
                entry: entry.clone(),
                before,
            });
        }
    }
    candidates.sort_by_key(|candidate| (candidate.entry_index, candidate.locator.clone()));
    Ok(candidates)
}

pub fn plan_mb_path_value(
    data: &[u8],
    root: &Chunk,
    candidate: &MbPathCandidatePlan,
    after: &str,
) -> Result<(Option<super::MbPayloadEdit>, MbPathStatus), super::MbPlanError> {
    super::require_complete_mb_sections(data, root)?;
    let invalid = || super::MbPlanError::InvalidLocator(format!("{:?}", candidate.locator));
    let child = root
        .children()
        .iter()
        .find(|child| child.offset() == candidate.locator.node_offset)
        .ok_or_else(invalid)?;
    let inner = data
        .get(child.payload_offset() + 4..child.payload_end())
        .ok_or_else(invalid)?;
    let parsed = super::parse_complete_section(inner, child, root)?;
    let (index, chunk) = parsed
        .chunks()
        .iter()
        .enumerate()
        .find(|(_, chunk)| chunk.chunk_start() == candidate.locator.chunk_start)
        .ok_or_else(invalid)?;
    let payload = chunk.payload(inner);
    let range = path_value_range(&candidate.locator.form, &chunk.tag().to_string(), payload)
        .ok_or_else(invalid)?;
    let Ok(before) = std::str::from_utf8(&payload[range.clone()]) else {
        return Ok((None, MbPathStatus::Undecodable));
    };
    let quoted = candidate.locator.form == "RTFT" && inner_quoted(before).1;
    let after = if quoted {
        format!("\"{}\"", inner_quoted(after).0)
    } else {
        after.to_owned()
    };
    let mut rewritten = payload.to_vec();
    rewritten.splice(range, after.bytes());
    if rewritten == payload {
        return Ok((None, MbPathStatus::Unchanged));
    }
    if !parsed.can_encode_payload(index, rewritten.len()) {
        return Ok((None, MbPathStatus::PayloadRejected));
    }
    Ok((
        Some(super::MbPayloadEdit {
            locator: candidate.locator.clone(),
            bytes: rewritten,
        }),
        MbPathStatus::Applied,
    ))
}

fn reference_identity(entry: &crate::mb::paths::MbScenePathEntry) -> &str {
    entry
        .meta
        .as_ref()
        .and_then(|meta| meta.reference_node.as_deref())
        .unwrap_or(&entry.node_name)
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
        replace_scene_paths_in_mb_cow,
    };
    use crate::{
        mb::{
            ChunkLayout, FourCC, HeaderFormat, LayoutHints, parse_file,
            parse_section_chunks_with_hints, rewrite::encode_chunk,
        },
        replace_rules::CompiledPathReplaceRules,
    };

    #[test]
    fn path_rewrite_refuses_section_trailing_bytes() {
        let source = build_mb_with_single_form(
            "RTFT",
            "STR ",
            b"ftn\0\0asset/example/file.mb\0",
            b"Example",
        );
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let rules = CompiledPathReplaceRules::compile_lossy(&super::normalize_mb_rules(
            &literal_rules("example", "Sample"),
        ));
        let result = super::replace_raw_scene_paths_in_mb_with_rules(
            &source,
            parsed.root(),
            &rules,
            &|_, _| true,
        );
        assert!(
            matches!(
                result,
                Err(super::MbRewriteError::IncompleteTree(
                    crate::mb::MbCompleteness::Truncated {
                        first_reason: crate::mb::MbTruncationReason::Malformed(
                            crate::mb::MayaBinaryParseError::HeaderOutOfBounds {
                                offset: 88,
                                header_size: 16,
                                limit: 95,
                                ..
                            }
                        ),
                        truncated_groups: 1,
                    }
                ))
            ),
            "{result:?}"
        );
    }

    fn rewritten_test_payload(
        form: &str,
        tag: &str,
        payload: &[u8],
        rules: &[MbPathReplaceRule],
    ) -> (Vec<u8>, usize) {
        let source = build_mb_with_single_form(form, tag, payload, &[]);
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let (output, changes) = replace_scene_paths_in_mb(&source, parsed.root(), rules).unwrap();
        let parsed = crate::mb::parse_bytes(output.clone()).unwrap();
        let child = &parsed.root().children()[0];
        let inner = &output[child.payload_offset() + 4..child.payload_end()];
        let section =
            parse_section_chunks_with_hints(inner, super::super::composite::section_hints(child));
        (
            section.chunks()[0].payload(inner).to_vec(),
            changes.replacement_count,
        )
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
        let (rewritten, count) = rewritten_test_payload("FREF", "FREF", payload, &rules);
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
        let count = count.replacement_count;
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
        let count = count.replacement_count;
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
        let count = count.replacement_count;
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
        let (rewritten, count) = super::rewrite_path_child(
            child,
            child,
            &child_bytes,
            &super::Replacement::Rules(&compiled),
            &|_, _| true,
            &super::PathEncoders::default(),
        )
        .expect("rtft rewrite");
        assert_eq!(count.replacement_count, 1);
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
        let count = count.replacement_count;
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
    fn frdi_trailing_cr_without_matching_rule_is_unchanged() {
        let source = build_mb_with_single_form(
            "FRDI",
            "FRDI",
            b"\x01asset/example/Sample.mb\r\0Example\0",
            &[],
        );
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let (rewritten, changes) =
            replace_scene_paths_in_mb(&source, parsed.root(), &literal_rules("missing", "sample"))
                .unwrap();
        assert_eq!(changes.replacement_count, 0);
        assert_eq!(changes.paths[0].status, super::MbPathStatus::Unchanged);
        assert_eq!(rewritten, source);
    }

    #[test]
    fn frdi_trailing_cr_with_matching_rule_is_preserved() {
        let source = build_mb_with_single_form(
            "FRDI",
            "FRDI",
            b"\x01asset/example/Sample.mb\r\0Example\0",
            &[],
        );
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let (rewritten, changes) = replace_scene_paths_in_mb(
            &source,
            parsed.root(),
            &literal_rules("Sample", "TestScene"),
        )
        .unwrap();
        assert_eq!(changes.replacement_count, 1);
        assert_eq!(changes.paths[0].status, super::MbPathStatus::Applied);
        assert_eq!(
            rewritten,
            build_mb_with_single_form(
                "FRDI",
                "FRDI",
                b"\x01asset/example/TestScene.mb\r\0Example\0",
                &[],
            )
        );
    }

    #[test]
    fn frdi_targets_preserve_surrounding_whitespace() {
        let source = build_mb_with_single_form(
            "FRDI",
            "FRDI",
            b"\x01  asset/example/Sample.mb\r\0Example\0",
            &[],
        );
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let (rewritten, changes) = replace_scene_paths_in_mb_by_index(
            &source,
            parsed.root(),
            &[(0, "asset/example/TestScene.mb".into())],
        )
        .unwrap();
        assert_eq!(changes.replacement_count, 1);
        assert_eq!(changes.paths[0].status, super::MbPathStatus::Applied);
        assert_eq!(
            rewritten,
            build_mb_with_single_form(
                "FRDI",
                "FRDI",
                b"\x01  asset/example/TestScene.mb\r\0Example\0",
                &[],
            )
        );
    }

    #[test]
    fn frdi_noop_target_preserves_original_bytes() {
        let source = build_mb_with_single_form(
            "FRDI",
            "FRDI",
            b"\x01asset/example/Sample.mb\r\0Example\0",
            &[],
        );
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let (rewritten, changes) = replace_scene_paths_in_mb_by_index(
            &source,
            parsed.root(),
            &[(0, "asset/example/Sample.mb".into())],
        )
        .unwrap();
        assert_eq!(changes.replacement_count, 0);
        assert_eq!(changes.paths[0].status, super::MbPathStatus::Unchanged);
        assert_eq!(rewritten, source);
    }

    #[test]
    fn frdi_rules_preserve_leading_whitespace() {
        let source = build_mb_with_single_form(
            "FRDI",
            "FRDI",
            b"\x01  asset/example/Sample.mb\0Example\0",
            &[],
        );
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let (rewritten, changes) = replace_scene_paths_in_mb(
            &source,
            parsed.root(),
            &literal_rules("Sample", "TestScene"),
        )
        .unwrap();
        assert_eq!(changes.replacement_count, 1);
        assert_eq!(
            rewritten,
            build_mb_with_single_form(
                "FRDI",
                "FRDI",
                b"\x01  asset/example/TestScene.mb\0Example\0",
                &[],
            )
        );
    }

    #[test]
    fn frdi_whitespace_only_value_is_not_a_path() {
        let source = build_mb_with_single_form("FRDI", "FRDI", b"\x01  \t\r\0", &[]);
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let (rewritten, changes) =
            replace_scene_paths_in_mb(&source, parsed.root(), &literal_rules(" ", "Example"))
                .unwrap();
        assert_eq!(changes.replacement_count, 0);
        assert!(changes.paths.is_empty());
        assert_eq!(rewritten, source);
    }

    #[test]
    fn replace_path_field_in_frdi_payload_preserves_control_prefix() {
        let payload = b"\x01old/char.mb\0charA\0\x01\0charARN\0VERS|2026|\0mayaBinary\0".to_vec();
        let rules = vec![MbPathReplaceRule {
            from: "old".to_string(),
            to: "new".to_string(),
            mode: crate::ma::types::PathReplaceMode::Literal,
        }];

        let (rewritten, count) = rewritten_test_payload("FRDI", "FRDI", &payload, &rules);
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
        let count = count.replacement_count;
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
        let count = count.replacement_count;
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
        let count = count.replacement_count;
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
        let count = count.replacement_count;
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
        let count = count.replacement_count;
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
        let count = count.replacement_count;
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
        let rewritten = rewritten_test_payload(
            "HEAD",
            "INCL",
            b"old/char.mb(\0\0",
            &literal_rules("old/", "new/"),
        )
        .0;
        assert_eq!(rewritten, b"new/char.mb(\0\0");
    }

    #[test]
    fn undecodable_texture_value_is_preserved() {
        for (form, tag, payload) in [
            (
                "RTFT",
                "STR ",
                b"ftn\0\x01asset/example/\x83\x65.png\0".as_slice(),
            ),
            ("HEAD", "INCL", b"asset/example/\x83\x65.mb\0"),
            (
                "FREF",
                "FREF",
                b"asset/example/\x83\x65.mb\0Example\0ExampleRN\0",
            ),
            (
                "FRDI",
                "FRDI",
                b"\x01asset/example/\x83\x65.mb\0Example\0\x01\0ExampleRN\0",
            ),
        ] {
            let source = build_mb_with_single_form(form, tag, payload, &[]);
            let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
            let (bytes, changes) = replace_scene_paths_in_mb(
                &source,
                parsed.root(),
                &literal_rules("example", "sample"),
            )
            .unwrap();
            assert_eq!(bytes, source);
            assert_eq!(changes.replacement_count, 0);
            assert_eq!(changes.skipped.non_utf8, 1);
            assert_eq!(changes.paths.len(), 1);
            let locator = changes.paths[0].locator.as_ref().unwrap();
            assert_eq!(locator.node_offset, parsed.root().children()[0].offset());
            assert_eq!(locator.chunk_start, 0);
            assert_eq!(locator.form, form);
            assert_eq!(changes.paths[0].status, super::MbPathStatus::Undecodable);
            if form == "RTFT" {
                let (bytes, changes) = replace_scene_paths_in_mb_by_index(
                    &source,
                    parsed.root(),
                    &[(0, "asset/sample/file.png".into())],
                )
                .unwrap();
                assert_eq!(bytes, source);
                assert_eq!(changes.skipped.non_utf8, 1);
                let candidate = super::collect_mb_path_candidates(&source, parsed.root(), &[0])
                    .unwrap()
                    .remove(0);
                let (edit, status) = super::plan_mb_path_value(
                    &source,
                    parsed.root(),
                    &candidate,
                    "asset/sample/file.png",
                )
                .unwrap();
                assert!(edit.is_none());
                assert_eq!(status, super::MbPathStatus::Undecodable);
            }
        }
    }

    #[test]
    fn texture_value_quotes_and_opaque_tail_survive_replacement() {
        for value in [
            b"\"asset/example/file.png\"\0\xff\0".as_slice(),
            b"asset/example/file.png\0Sample\0\0",
            b"\"\"asset/example/file.png\"\"\0",
            b"\"asset/example/file.png\0",
            "asset/example/例.png\0\0".as_bytes(),
            b"\0\0",
            b"\"\"\0",
        ] {
            let mut payload = b"ftn\0\x01".to_vec();
            payload.extend_from_slice(value);
            let source = build_mb_with_single_form("RTFT", "STR ", &payload, &[]);
            let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
            let (unchanged, changes) = replace_scene_paths_in_mb(
                &source,
                parsed.root(),
                &literal_rules("missing", "sample"),
            )
            .unwrap();
            assert_eq!(unchanged, source);
            assert_eq!(changes.replacement_count, 0);
            let (bytes, changes) = replace_scene_paths_in_mb(
                &source,
                parsed.root(),
                &literal_rules("example", "long_sample"),
            )
            .unwrap();
            let count = usize::from(payload.windows(7).any(|part| part == b"example"));
            if let Some(start) = payload.windows(7).position(|part| part == b"example") {
                payload.splice(start..start + 7, b"long_sample".iter().copied());
            }
            assert_eq!(
                bytes,
                build_mb_with_single_form("RTFT", "STR ", &payload, &[])
            );
            assert_eq!(changes.replacement_count, count);
            let entries =
                super::extract_raw_scene_paths_from_mb_parts(&source, parsed.root()).value;
            if let Some(entry) = entries.first() {
                let after = entry.value.replace("example", "long_sample");
                let (targeted, changes) =
                    replace_scene_paths_in_mb_by_index(&source, parsed.root(), &[(0, after)])
                        .unwrap();
                assert_eq!(targeted, bytes);
                assert_eq!(changes.replacement_count, count);
            }
        }
        for payload in [
            b"\"asset/example/file.mb\"\0\0".as_slice(),
            b"asset/example/file.mb\0Sample\0\0",
            "asset/example/例.mb\0".as_bytes(),
            b"\0\0",
        ] {
            let source = build_mb_with_single_form("HEAD", "INCL", payload, &[]);
            let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
            assert_eq!(
                replace_scene_paths_in_mb(
                    &source,
                    parsed.root(),
                    &literal_rules("missing", "sample")
                )
                .unwrap()
                .0,
                source
            );
            let (bytes, changes) = replace_scene_paths_in_mb(
                &source,
                parsed.root(),
                &literal_rules("example", "long_sample"),
            )
            .unwrap();
            let mut expected = payload.to_vec();
            if let Some(start) = expected.windows(7).position(|part| part == b"example") {
                expected.splice(start..start + 7, b"long_sample".iter().copied());
            }
            assert_eq!(
                bytes,
                build_mb_with_single_form("HEAD", "INCL", &expected, &[])
            );
            assert_eq!(changes.replacement_count, usize::from(expected != payload));
        }
    }

    #[test]
    fn repeated_matches_count_one_physical_record() {
        let source = build_mb_with_single_form("HEAD", "INCL", b"asset/example/example.mb\0", &[]);
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let (_, count) =
            replace_scene_paths_in_mb(&source, parsed.root(), &literal_rules("example", "sample"))
                .unwrap();
        let count = count.replacement_count;
        assert_eq!(count, 1);
    }

    #[test]
    fn encoder_failures_return_no_output() {
        let source = build_mb_with_single_form("HEAD", "INCL", b"asset/example/file.mb\0", &[]);
        let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
        let rules = CompiledPathReplaceRules::compile_lossy(&super::normalize_mb_rules(
            &literal_rules("example", "sample"),
        ));
        for phase in 0..3 {
            let mut encoders = super::PathEncoders::default();
            match phase {
                0 => encoders.section = |_, _, _| Err(crate::mb::EncodeError::LengthOverflow),
                1 => encoders.child = |_, _| Err(crate::mb::EncodeError::LengthOverflow),
                _ => encoders.root = |_, _| Err(crate::mb::EncodeError::LengthOverflow),
            }
            let result = super::replace_mb_paths(
                &source,
                parsed.root(),
                super::Replacement::Rules(&rules),
                &|_, _| true,
                super::MbPathChanges::default(),
                &encoders,
            );
            assert!(matches!(
                (phase, result),
                (0, Err(super::MbRewriteError::SectionEncode(_)))
                    | (1, Err(super::MbRewriteError::ChildEncode(_)))
                    | (2, Err(super::MbRewriteError::RootEncode(_)))
            ));
        }
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
            let (bytes, changes) = super::rewrite_path_child(
                child,
                child,
                data,
                &super::Replacement::Targets(&targets),
                accept_payload,
                &super::PathEncoders::default(),
            )
            .unwrap();
            {
                let expected_skips = changes
                    .paths
                    .iter()
                    .filter(|change| change.status == super::MbPathStatus::PayloadRejected)
                    .count();
                assert_eq!(changes.skipped.payload_rejected, Some(expected_skips));
                assert_eq!(
                    changes.replacement_count + expected_skips,
                    changes.paths.len()
                );
                (bytes, changes.replacement_count)
            }
        } else {
            let (bytes, changes) = super::rewrite_path_child(
                child,
                child,
                data,
                &super::Replacement::Rules(&rules),
                accept_payload,
                &super::PathEncoders::default(),
            )
            .unwrap();
            {
                let expected_skips = changes
                    .paths
                    .iter()
                    .filter(|change| change.status == super::MbPathStatus::PayloadRejected)
                    .count();
                assert_eq!(changes.skipped.payload_rejected, Some(expected_skips));
                assert_eq!(
                    changes.replacement_count + expected_skips,
                    changes.paths.len()
                );
                (bytes, changes.replacement_count)
            }
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
        let (child, count) = super::rewrite_path_child(
            parsed.root(),
            &parsed.root().children()[0],
            source,
            &super::Replacement::Rules(&compiled),
            &|_, _| true,
            &super::PathEncoders::default(),
        )
        .unwrap();
        assert_eq!(count.replacement_count, 1);
        assert_eq!(child, b"FOR4\0\0\0\x10HEADINCL\0\0\0\x01Y\0\0\0");
        let (rewritten, total) = replace_scene_paths_in_mb(source, parsed.root(), &rules).unwrap();
        let total = total.replacement_count;
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
        let count = count.replacement_count;
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
            let source = build_mb_with_form_payloads(form, tag, &[payload, payload, payload], &[]);
            let parsed = crate::mb::parse_bytes(source.clone()).unwrap();
            let child = &parsed.root().children()[0];
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
                    assert_eq!(count, 3 - rejected.len(), "{form}, targets={by_targets}");
                    if rejected.len() == 3 {
                        assert_eq!(&rewritten, &source[child.offset()..]);
                        continue;
                    }
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
                    .is_ok()
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
        assert_eq!(count.skipped.duplicate_request, Some(1));
        assert_eq!(count.skipped.unmatched_locator, Some(2));
        let count = count.replacement_count;
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
