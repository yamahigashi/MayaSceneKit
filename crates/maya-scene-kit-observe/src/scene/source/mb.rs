use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
};

use maya_scene_kit_formats::mb::{
    MayaBinaryFile, collect_rtft_owner_traces_from_mb,
    paths::{MbRtftOwnerTrace, MbScenePathEntry},
};

use crate::{
    reference_semantics::{ScenePathAttrKind, classify_scene_path_attr},
    scene::{
        decode::families::decode_crea_payload,
        paths::{PathKind, ScenePathEntry, ScenePathMeta},
    },
};

pub(crate) fn canonical_scene_path_entry_kind(entry: &ScenePathEntry) -> PathKind {
    if entry.node_type == "reference" {
        PathKind::Reference
    } else {
        PathKind::File
    }
}

pub(crate) fn collect_mb_scene_paths(
    mb: &MayaBinaryFile,
    nodes: &[crate::scene::ir::RecoveredNode],
    reference_files: &[crate::scene::ir::ReferenceFileOp],
    raw_entries: &[MbScenePathEntry],
    raw_chunks: &[crate::scene::ir::RawChunkRecord],
    raw_source: &[u8],
) -> Vec<ScenePathEntry> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut raw_file_meta = build_raw_mb_file_meta_index(raw_entries);
    let fallback_file_meta = build_mb_file_owner_trace_index(mb, raw_chunks, raw_source);

    for reference in reference_files {
        push_unique_scene_path_entry(
            &mut out,
            &mut seen,
            ScenePathEntry {
                node_type: "reference".to_string(),
                node_name: reference.reference_node.to_string(),
                attr: ".fn".to_string(),
                value: reference.path.clone(),
                meta: Some(ScenePathMeta {
                    origin: "canonical-reference-file".to_string(),
                    short_name: Some(reference.namespace.to_string()),
                    reference_node: Some(reference.reference_node.to_string()),
                    format_hint: Some(reference.file_type.to_string()),
                    reference_options: reference.options.clone(),
                    color_space: None,
                    raw_fields: vec![],
                    trace_form: reference.trace.as_ref().map(|trace| trace.form.clone()),
                    trace_tag: reference.trace.as_ref().map(|trace| trace.tag.clone()),
                    trace_node_offset: reference.trace.as_ref().map(|trace| trace.node_offset),
                    trace_child_alignment: reference
                        .trace
                        .as_ref()
                        .and_then(|trace| trace.child_alignment),
                    trace_child_header_size: reference
                        .trace
                        .as_ref()
                        .and_then(|trace| trace.child_header_size),
                }),
            },
        );
    }

    for node in nodes {
        if node.node_type.as_ref() != "file" {
            continue;
        }
        for attr in &node.attrs {
            let crate::scene::ir::RecoveredAttrOp::SetAttr(op) = attr else {
                continue;
            };
            let crate::scene::ir::SetAttrValue::String(value) = &op.value else {
                continue;
            };
            if !matches!(
                classify_scene_path_attr(&op.attr_name_or_path),
                Some(ScenePathAttrKind::FileTexturePath)
            ) {
                continue;
            }
            push_unique_scene_path_entry(
                &mut out,
                &mut seen,
                ScenePathEntry {
                    node_type: "file".to_string(),
                    node_name: node.name.clone(),
                    attr: op.attr_name_or_path.clone(),
                    value: value.clone(),
                    meta: take_raw_mb_file_meta(&mut raw_file_meta, &node.name, value)
                        .map(|meta| {
                            merge_mb_file_meta_with_owner_trace(
                                meta,
                                fallback_file_meta.get(&node.name),
                            )
                        })
                        .or_else(|| fallback_file_meta.get(&node.name).cloned()),
                },
            );
        }
    }

    out
}

fn build_mb_file_owner_trace_index(
    mb: &MayaBinaryFile,
    raw_chunks: &[crate::scene::ir::RawChunkRecord],
    raw_source: &[u8],
) -> BTreeMap<String, ScenePathMeta> {
    let mut index = BTreeMap::new();

    for trace in collect_rtft_owner_traces_from_mb(mb) {
        index
            .entry(trace.node_name.clone())
            .or_insert_with(|| map_mb_owner_trace_meta_ref(&trace));
    }

    for (node_name, meta) in build_mb_file_owner_trace_index_from_raw_chunks(raw_chunks, raw_source)
    {
        index
            .entry(node_name)
            .and_modify(|existing| {
                *existing = merge_mb_file_meta_with_owner_trace(existing.clone(), Some(&meta));
            })
            .or_insert(meta);
    }

    index
}

fn build_mb_file_owner_trace_index_from_raw_chunks(
    raw_chunks: &[crate::scene::ir::RawChunkRecord],
    raw_source: &[u8],
) -> BTreeMap<String, ScenePathMeta> {
    let mut grouped = BTreeMap::<usize, ScenePathMeta>::new();
    let mut names = BTreeMap::<usize, String>::new();

    for raw in raw_chunks {
        let payload = raw.payload(raw_source);
        if raw.chunk_ref.form != "RTFT" {
            continue;
        }
        let meta = grouped
            .entry(raw.chunk_ref.node_offset)
            .or_insert_with(|| ScenePathMeta {
                origin: "rtft-fallback".to_string(),
                short_name: None,
                reference_node: None,
                format_hint: None,
                reference_options: None,
                color_space: None,
                raw_fields: Vec::new(),
                trace_form: Some(raw.chunk_ref.form.clone()),
                trace_tag: None,
                trace_node_offset: Some(raw.chunk_ref.node_offset),
                trace_child_alignment: raw.chunk_ref.child_alignment,
                trace_child_header_size: raw.chunk_ref.child_header_size,
            });
        if meta.trace_tag.is_none()
            && matches!(
                decode_rtft_attr_name(payload).as_deref(),
                Some("ftn") | Some(".ftn")
            )
        {
            meta.trace_tag = Some(raw.chunk_ref.tag.clone());
        }
        if let Some(node_name) = (raw.chunk_ref.tag == "CREA")
            .then(|| decode_crea_name(payload))
            .flatten()
        {
            names.entry(raw.chunk_ref.node_offset).or_insert(node_name);
        }
    }

    let mut index = BTreeMap::new();
    for (node_offset, node_name) in names {
        if let Some(mut meta) = grouped.remove(&node_offset) {
            meta.short_name = Some(node_name.clone());
            index.insert(node_name, meta);
        }
    }

    index
}

fn build_raw_mb_file_meta_index(
    raw_entries: &[MbScenePathEntry],
) -> BTreeMap<(String, String), VecDeque<ScenePathMeta>> {
    let mut index = BTreeMap::<(String, String), VecDeque<ScenePathMeta>>::new();

    for entry in raw_entries {
        if entry.node_type != "file" {
            continue;
        }
        if !matches!(
            classify_scene_path_attr(&entry.attr),
            Some(ScenePathAttrKind::FileTexturePath)
        ) {
            continue;
        }
        let Some(meta) = entry.meta.as_ref().map(map_mb_scene_path_meta_ref) else {
            continue;
        };
        index
            .entry((entry.node_name.clone(), entry.value.clone()))
            .or_default()
            .push_back(meta);
    }

    index
}

fn take_raw_mb_file_meta(
    raw_file_meta: &mut BTreeMap<(String, String), VecDeque<ScenePathMeta>>,
    node_name: &str,
    value: &str,
) -> Option<ScenePathMeta> {
    raw_file_meta
        .get_mut(&(node_name.to_string(), value.to_string()))
        .and_then(VecDeque::pop_front)
}

fn merge_mb_file_meta_with_owner_trace(
    mut meta: ScenePathMeta,
    fallback: Option<&ScenePathMeta>,
) -> ScenePathMeta {
    let Some(fallback) = fallback else {
        return meta;
    };

    if meta.short_name.is_none() {
        meta.short_name = fallback.short_name.clone();
    }
    if meta.trace_form.is_none() {
        meta.trace_form = fallback.trace_form.clone();
    }
    if meta.trace_tag.is_none() {
        meta.trace_tag = fallback.trace_tag.clone();
    }
    if meta.trace_node_offset.is_none() {
        meta.trace_node_offset = fallback.trace_node_offset;
    }
    if meta.trace_child_alignment.is_none() {
        meta.trace_child_alignment = fallback.trace_child_alignment;
    }
    if meta.trace_child_header_size.is_none() {
        meta.trace_child_header_size = fallback.trace_child_header_size;
    }

    meta
}

fn map_mb_scene_path_meta_ref(
    meta: &maya_scene_kit_formats::mb::paths::MbScenePathMeta,
) -> ScenePathMeta {
    ScenePathMeta {
        origin: meta.origin.clone(),
        short_name: meta.short_name.clone(),
        reference_node: meta.reference_node.clone(),
        format_hint: meta.format_hint.clone(),
        reference_options: meta.reference_options.clone(),
        color_space: meta.color_space.clone(),
        raw_fields: meta.raw_fields.clone(),
        trace_form: meta.trace_form.clone(),
        trace_tag: meta.trace_tag.clone(),
        trace_node_offset: meta.trace_node_offset,
        trace_child_alignment: meta.trace_child_alignment,
        trace_child_header_size: meta.trace_child_header_size,
    }
}

fn map_mb_owner_trace_meta_ref(trace: &MbRtftOwnerTrace) -> ScenePathMeta {
    ScenePathMeta {
        origin: "rtft-fallback".to_string(),
        short_name: Some(trace.node_name.clone()),
        reference_node: None,
        format_hint: None,
        reference_options: None,
        color_space: None,
        raw_fields: Vec::new(),
        trace_form: Some(trace.trace_form.clone()),
        trace_tag: trace.trace_tag.clone(),
        trace_node_offset: Some(trace.trace_node_offset),
        trace_child_alignment: trace.trace_child_alignment,
        trace_child_header_size: trace.trace_child_header_size,
    }
}

fn push_unique_scene_path_entry(
    out: &mut Vec<ScenePathEntry>,
    seen: &mut HashSet<u64>,
    entry: ScenePathEntry,
) {
    if seen.insert(scene_path_entry_fingerprint(&entry)) {
        out.push(entry);
    }
}

fn decode_rtft_attr_name(payload: &[u8]) -> Option<String> {
    let attr_end = payload.iter().position(|b| *b == 0)?;
    Some(String::from_utf8_lossy(&payload[..attr_end]).to_string())
}

fn decode_crea_name(payload: &[u8]) -> Option<String> {
    decode_crea_payload(payload).name
}

fn scene_path_entry_fingerprint(entry: &ScenePathEntry) -> u64 {
    let mut hasher = DefaultHasher::new();
    entry.node_type.hash(&mut hasher);
    entry.node_name.hash(&mut hasher);
    entry.attr.hash(&mut hasher);
    entry.value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{decode_rtft_attr_name, push_unique_scene_path_entry};
    use crate::scene::paths::{ScenePathEntry, ScenePathMeta};

    fn scene_path_entry(trace_tag: &str, trace_node_offset: usize) -> ScenePathEntry {
        ScenePathEntry {
            node_type: "file".to_string(),
            node_name: "ExampleFile".to_string(),
            attr: ".ftn".to_string(),
            value: "asset/example/file.png".to_string(),
            meta: Some(ScenePathMeta {
                origin: "rtft".to_string(),
                short_name: Some("ExampleFile".to_string()),
                reference_node: None,
                format_hint: None,
                reference_options: None,
                color_space: None,
                raw_fields: vec!["ftn=asset/example/file.png".to_string()],
                trace_form: Some("RTFT".to_string()),
                trace_tag: Some(trace_tag.to_string()),
                trace_node_offset: Some(trace_node_offset),
                trace_child_alignment: Some(8),
                trace_child_header_size: Some(16),
            }),
        }
    }

    #[test]
    fn decode_rtft_attr_name_returns_bytes_before_first_nul() {
        let payload = b"ftn\0asset/example/file.png\0ignored";
        assert_eq!(decode_rtft_attr_name(payload).as_deref(), Some("ftn"));
    }

    #[test]
    fn decode_rtft_attr_name_does_not_return_last_non_empty_chunk() {
        let payload = b"ftn\0asset/example/file.png";
        assert_eq!(decode_rtft_attr_name(payload).as_deref(), Some("ftn"));
    }

    #[test]
    fn push_unique_scene_path_entry_dedupes_trace_only_differences() {
        let mut out = Vec::new();
        let mut seen = HashSet::new();

        push_unique_scene_path_entry(&mut out, &mut seen, scene_path_entry("STR ", 0x10));
        push_unique_scene_path_entry(&mut out, &mut seen, scene_path_entry("DATA", 0x20));

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].node_name, "ExampleFile");
        assert_eq!(out[0].value, "asset/example/file.png");
    }
}
