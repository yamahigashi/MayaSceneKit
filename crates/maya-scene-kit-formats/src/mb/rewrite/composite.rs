use std::{collections::BTreeSet, num::NonZeroUsize};

use crate::mb::{
    Chunk, ChunkLayout, EncodeError, LayoutHints, MbRewriteError, parse_section_chunks_with_hints,
    resolve_section_layout_hints,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MbPayloadLocator {
    pub form: String,
    pub node_offset: usize,
    pub chunk_start: usize,
}

#[derive(Debug, Clone)]
pub struct MbPayloadEdit {
    pub locator: MbPayloadLocator,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct MbOriginalEdits {
    pub removed_forms: Vec<(String, usize)>,
    pub removed_records: Vec<MbPayloadLocator>,
    pub rewritten_records: Vec<MbPayloadEdit>,
}

#[derive(Debug, thiserror::Error)]
pub enum MbPlanError {
    #[error(transparent)]
    Incomplete(#[from] MbRewriteError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("missing or ambiguous original MB locator: {0}")]
    InvalidLocator(String),
    #[error("path entry {entry_index} has no matching original MB record")]
    MissingEntry { entry_index: usize },
    #[error("path entry {entry_index} shares an original MB record with another entry")]
    AmbiguousEntry { entry_index: usize },
    #[error("cannot combine record deletion and replacement in MB section {form} at {node_offset}")]
    MixedRecordEdits { form: String, node_offset: usize },
}

pub fn locate_mb_path_owner_forms(
    data: &[u8],
    root: &Chunk,
    node_type: &str,
    node_name: &str,
) -> Result<Vec<(String, usize)>, MbPlanError> {
    super::require_complete_mb_sections(data, root)?;
    Ok(
        crate::mb::paths::extract_raw_scene_paths_from_mb_parts(data, root)
            .value
            .into_iter()
            .filter(|entry| entry.node_type == node_type && entry.node_name == node_name)
            .filter_map(|entry| {
                let meta = entry.meta?;
                Some((meta.trace_form?, meta.trace_node_offset?))
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    )
}

pub fn collect_mb_plugin_require_records(
    data: &[u8],
    root: &Chunk,
    requested: &[String],
) -> Vec<(MbPayloadLocator, Vec<u8>)> {
    let mut records = Vec::new();
    for child in root
        .children()
        .iter()
        .filter(|child| child.form_type().is_some_and(|form| form == "HEAD"))
    {
        let payload = &data[child.payload_offset()..child.payload_end()];
        let Some(inner) = payload.get(4..) else {
            continue;
        };
        let parsed = parse_section_chunks_with_hints(inner, section_hints(child));
        for chunk in parsed.chunks() {
            if chunk.tag() != "PLUG" {
                continue;
            }
            if let Some(entry) =
                crate::mb::head::decode_plug_to_requires_entry(chunk.payload(inner))
            {
                let rendered = crate::mb::head::render_requires_entry(&entry);
                if requested.iter().any(|name| name.trim() == rendered) {
                    records.push((
                        MbPayloadLocator {
                            form: "HEAD".into(),
                            node_offset: child.offset(),
                            chunk_start: chunk.chunk_start(),
                        },
                        chunk.payload(inner).to_vec(),
                    ));
                }
            }
        }
    }
    records
}

pub(super) fn section_hints(child: &Chunk) -> LayoutHints {
    resolve_section_layout_hints(
        child.tag(),
        child.form_type(),
        child
            .child_layout()
            .map_or_else(LayoutHints::new, LayoutHints::from),
    )
}

pub fn apply_mb_original_edits(
    data: &[u8],
    root: &Chunk,
    plan: &MbOriginalEdits,
) -> Result<Vec<u8>, MbPlanError> {
    apply_mb_original_edits_with_encoder(data, root, plan, &super::encode_root_chunk)
}

pub fn validate_mb_original_edits(plan: &MbOriginalEdits) -> Result<(), MbPlanError> {
    let removed_sections = plan
        .removed_records
        .iter()
        .map(|locator| (&locator.form, locator.node_offset))
        .collect::<BTreeSet<_>>();
    for edit in &plan.rewritten_records {
        if removed_sections.contains(&(&edit.locator.form, edit.locator.node_offset)) {
            return Err(MbPlanError::MixedRecordEdits {
                form: edit.locator.form.clone(),
                node_offset: edit.locator.node_offset,
            });
        }
    }
    Ok(())
}

fn apply_mb_original_edits_with_encoder(
    data: &[u8],
    root: &Chunk,
    plan: &MbOriginalEdits,
    encode_root: &impl Fn(&Chunk, &[u8]) -> Result<Vec<u8>, EncodeError>,
) -> Result<Vec<u8>, MbPlanError> {
    super::require_complete_mb_sections(data, root)?;
    validate_mb_original_edits(plan)?;
    let mut pending_forms = plan.removed_forms.iter().cloned().collect::<BTreeSet<_>>();
    let mut pending_records = plan
        .removed_records
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut pending_updates = plan
        .rewritten_records
        .iter()
        .map(|edit| edit.locator.clone())
        .collect::<BTreeSet<_>>();
    if pending_updates.len() != plan.rewritten_records.len() {
        return Err(MbPlanError::InvalidLocator(
            "duplicate payload rewrite".into(),
        ));
    }
    let mut payload = root
        .form_type()
        .ok_or_else(|| MbPlanError::InvalidLocator("root has no form".into()))?
        .as_bytes()
        .to_vec();
    let mut cursor = root.payload_offset() + 4;
    for child in root.children() {
        payload.extend_from_slice(&data[cursor..child.offset()]);
        cursor = super::child_span_end(root, child);
        let form = child
            .form_type()
            .map(|form| form.to_string())
            .unwrap_or_default();
        if pending_forms.remove(&(form.clone(), child.offset())) {
            continue;
        }
        let removals = plan
            .removed_records
            .iter()
            .filter(|locator| locator.node_offset == child.offset() && locator.form == form)
            .collect::<Vec<_>>();
        let updates = plan
            .rewritten_records
            .iter()
            .filter(|edit| edit.locator.node_offset == child.offset() && edit.locator.form == form)
            .collect::<Vec<_>>();
        if removals.is_empty() && updates.is_empty() {
            payload.extend_from_slice(&data[child.offset()..cursor]);
            continue;
        }
        let inner = data
            .get(child.payload_offset() + 4..child.payload_end())
            .ok_or_else(|| MbPlanError::InvalidLocator(form.clone()))?;
        let parsed = parse_section_chunks_with_hints(inner, section_hints(child));
        let new_inner = if removals.is_empty() {
            let mut rewrites = Vec::new();
            for edit in updates {
                let index = parsed
                    .chunks()
                    .iter()
                    .position(|chunk| chunk.chunk_start() == edit.locator.chunk_start)
                    .ok_or_else(|| MbPlanError::InvalidLocator(format!("{:?}", edit.locator)))?;
                rewrites.push((index, edit.bytes.as_slice()));
                pending_updates.remove(&edit.locator);
            }
            parsed.rewrite_payloads(inner, &rewrites)?
        } else {
            let mut out = Vec::new();
            let mut position = 0;
            for chunk in parsed.chunks() {
                out.extend_from_slice(&inner[position..chunk.chunk_start()]);
                let locator = MbPayloadLocator {
                    form: form.clone(),
                    node_offset: child.offset(),
                    chunk_start: chunk.chunk_start(),
                };
                if !pending_records.remove(&locator) {
                    out.extend_from_slice(&inner[chunk.chunk_start()..chunk.chunk_end()]);
                }
                position = chunk.chunk_end();
            }
            out.extend_from_slice(&inner[position..]);
            out
        };
        let mut child_payload = form.as_bytes().to_vec();
        child_payload.extend_from_slice(&new_inner);
        let mut encoded = super::encode_chunk(
            child.tag(),
            child.aux(),
            &child_payload,
            ChunkLayout::new(NonZeroUsize::new(4).unwrap(), child.header_format()),
        )?;
        if child_payload.len() == child.size() && encoded.len() == cursor - child.offset() {
            let padding = child.header_format().header_size() + child_payload.len();
            encoded[padding..].copy_from_slice(&data[child.payload_end()..cursor]);
        }
        payload.extend_from_slice(&encoded);
    }
    payload.extend_from_slice(&data[cursor..root.payload_end()]);
    if !pending_forms.is_empty() || !pending_records.is_empty() || !pending_updates.is_empty() {
        return Err(MbPlanError::InvalidLocator(
            "requested edit was not applied".into(),
        ));
    }
    if plan.removed_forms.is_empty()
        && plan.removed_records.is_empty()
        && plan.rewritten_records.is_empty()
    {
        return Ok(data.to_vec());
    }
    Ok(encode_root(root, &payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_record_edits_are_rejected_before_encoding() {
        let bytes =
            b"FOR4\0\0\0\x30MayaFOR4\0\0\0\x24HEADPLUG\0\0\0\x08Example\0PLUG\0\0\0\x07Sample\0\0";
        let mb = crate::mb::parse_bytes(bytes.to_vec()).unwrap();
        let plan = MbOriginalEdits {
            removed_records: vec![MbPayloadLocator {
                form: "HEAD".into(),
                node_offset: 12,
                chunk_start: 0,
            }],
            rewritten_records: vec![MbPayloadEdit {
                locator: MbPayloadLocator {
                    form: "HEAD".into(),
                    node_offset: 12,
                    chunk_start: 16,
                },
                bytes: b"SampleUpdated\0".to_vec(),
            }],
            ..Default::default()
        };
        let encoded = std::cell::Cell::new(false);
        assert!(matches!(
            validate_mb_original_edits(&plan),
            Err(MbPlanError::MixedRecordEdits { .. })
        ));
        let error = apply_mb_original_edits_with_encoder(bytes, mb.root(), &plan, &|_, _| {
            encoded.set(true);
            Ok(Vec::new())
        })
        .unwrap_err();
        assert!(!encoded.get());
        assert_eq!(
            error.to_string(),
            "cannot combine record deletion and replacement in MB section HEAD at 12"
        );
    }

    #[test]
    fn root_encode_failure_is_returned_without_output() {
        let bytes = b"FOR4\0\0\0\x10MayaFOR4\0\0\0\x04SCRP";
        let mb = crate::mb::parse_bytes(bytes.to_vec()).unwrap();
        let plan = MbOriginalEdits {
            removed_forms: vec![("SCRP".into(), 12)],
            ..Default::default()
        };
        let result = apply_mb_original_edits_with_encoder(bytes, mb.root(), &plan, &|_, _| {
            Err(EncodeError::LengthOverflow)
        });
        assert!(matches!(
            result,
            Err(MbPlanError::Encode(EncodeError::LengthOverflow))
        ));
    }
}
