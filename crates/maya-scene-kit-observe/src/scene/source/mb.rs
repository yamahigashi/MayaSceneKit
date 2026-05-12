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
        paths::{PathKind, ScenePathEntry, ScenePathMeta},
        scripts::ScriptNodeEntry,
    },
};

#[derive(Debug, Clone)]
pub(crate) struct RawMbSelectiveSections {
    pub(crate) scene_paths: Vec<ScenePathEntry>,
    pub(crate) script_entries: Vec<ScriptNodeEntry>,
}

pub(crate) fn collect_raw_mb_selective_sections(mb: &MayaBinaryFile) -> RawMbSelectiveSections {
    RawMbSelectiveSections {
        scene_paths: collect_raw_mb_scene_paths(mb),
        script_entries: collect_raw_mb_script_entries(mb),
    }
}

pub(crate) fn canonical_scene_path_entry_kind(entry: &ScenePathEntry) -> PathKind {
    if entry.node_type == "reference" {
        PathKind::Reference
    } else {
        PathKind::File
    }
}

pub(crate) fn collect_raw_mb_scene_paths(mb: &MayaBinaryFile) -> Vec<ScenePathEntry> {
    let raw_entries = maya_scene_kit_formats::mb::paths::extract_raw_scene_paths_from_mb(mb);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut raw_file_meta = build_raw_mb_file_meta_index(&raw_entries);
    let owner_trace_meta = build_mb_file_owner_trace_index_from_root(mb);

    for entry in raw_entries {
        let kind = canonical_raw_mb_scene_path_kind(&entry);
        match kind {
            PathKind::Reference => {
                let meta = entry.meta.as_ref().map(map_mb_scene_path_meta_ref);
                push_unique_scene_path_entry(
                    &mut out,
                    &mut seen,
                    ScenePathEntry {
                        node_type: "reference".to_string(),
                        node_name: entry.node_name,
                        attr: entry.attr,
                        value: entry.value,
                        meta,
                    },
                );
            }
            PathKind::File => {
                if !matches!(
                    classify_scene_path_attr(&entry.attr),
                    Some(ScenePathAttrKind::FileTexturePath)
                ) {
                    continue;
                }
                let meta =
                    take_raw_mb_file_meta(&mut raw_file_meta, &entry.node_name, &entry.value)
                        .map(|meta| {
                            merge_mb_file_meta_with_owner_trace(
                                meta,
                                owner_trace_meta.get(&entry.node_name),
                            )
                        })
                        .or_else(|| owner_trace_meta.get(&entry.node_name).cloned());
                push_unique_scene_path_entry(
                    &mut out,
                    &mut seen,
                    ScenePathEntry {
                        node_type: entry.node_type,
                        node_name: entry.node_name,
                        attr: entry.attr,
                        value: entry.value,
                        meta,
                    },
                );
            }
            PathKind::All => unreachable!("raw MB scene path kind is canonicalized"),
        }
    }

    out
}

fn canonical_raw_mb_scene_path_kind(entry: &MbScenePathEntry) -> PathKind {
    if entry.node_type == "reference" {
        PathKind::Reference
    } else {
        PathKind::File
    }
}

pub(crate) fn collect_raw_mb_script_entries(mb: &MayaBinaryFile) -> Vec<ScriptNodeEntry> {
    maya_scene_kit_formats::mb::extract_raw_script_entries_from_mb(mb)
        .into_iter()
        .map(|(name, body)| ScriptNodeEntry { name, body })
        .collect()
}

fn build_mb_file_owner_trace_index_from_root(
    mb: &MayaBinaryFile,
) -> BTreeMap<String, ScenePathMeta> {
    let mut index = BTreeMap::new();

    for trace in collect_rtft_owner_traces_from_mb(mb) {
        index
            .entry(trace.node_name.clone())
            .or_insert_with(|| map_mb_owner_trace_meta_ref(&trace));
    }

    index
}

fn build_raw_mb_file_meta_index(
    raw_entries: &[MbScenePathEntry],
) -> BTreeMap<(String, String), VecDeque<ScenePathMeta>> {
    let mut index = BTreeMap::<(String, String), VecDeque<ScenePathMeta>>::new();

    for entry in raw_entries {
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

    use super::push_unique_scene_path_entry;
    use crate::scene::paths::{ScenePathEntry, ScenePathMeta};

    fn scene_path_entry(trace_tag: &str, trace_node_offset: usize) -> ScenePathEntry {
        ScenePathEntry {
            node_type: "psdFileTex".to_string(),
            node_name: "ExampleFile".to_string(),
            attr: ".fileTextureName".to_string(),
            value: "asset/example/file.png".to_string(),
            meta: Some(ScenePathMeta {
                origin: "rtft".to_string(),
                short_name: Some("ExampleFile".to_string()),
                reference_node: None,
                format_hint: None,
                reference_options: None,
                color_space: None,
                raw_fields: vec!["fileTextureName=asset/example/file.png".to_string()],
                trace_form: Some("RTFT".to_string()),
                trace_tag: Some(trace_tag.to_string()),
                trace_node_offset: Some(trace_node_offset),
                trace_child_alignment: Some(8),
                trace_child_header_size: Some(16),
            }),
        }
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
