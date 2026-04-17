use std::collections::HashMap;

use crate::{
    reference_semantics::{
        default_reference_file_type, derive_parent_reference_node, parse_reference_include_path,
    },
    scene::ir::{
        ChunkTrace, Confidence, DecodedChunkRecord, DecodedEvent, ReferenceFileOp, StringInterner,
    },
};

pub(crate) fn recover_reference_files(
    decoded_chunks: &[DecodedChunkRecord],
) -> Vec<ReferenceFileOp> {
    let mut out = Vec::new();
    let mut interner = StringInterner::default();
    for decoded in decoded_chunks {
        let trace = Some(ChunkTrace {
            form: decoded.chunk_ref.form.clone(),
            tag: decoded.chunk_ref.tag.clone(),
            node_offset: decoded.chunk_ref.node_offset,
            chunk_aux: decoded.chunk_ref.chunk_aux,
            child_alignment: decoded.chunk_ref.child_alignment,
            child_header_size: decoded.chunk_ref.child_header_size,
        });
        for event in &decoded.events {
            let DecodedEvent::ReferenceFile {
                path,
                reference_node,
                namespace,
                file_type,
                options,
            } = event
            else {
                continue;
            };
            out.push(ReferenceFileOp {
                path: path.clone(),
                namespace: namespace
                    .as_ref()
                    .map(|value| interner.intern(value.as_ref()))
                    .unwrap_or_else(|| interner.intern(reference_node.as_ref())),
                reference_node: interner.intern(reference_node.as_ref()),
                file_type: file_type
                    .as_ref()
                    .map(|value| interner.intern(value.as_ref()))
                    .unwrap_or_else(|| interner.intern(default_reference_file_type())),
                options: options.clone(),
                namespace_defaulted: namespace.is_none(),
                file_type_defaulted: file_type.is_none(),
                path_inferred_from_parent_include: false,
                trace: trace.clone(),
                confidence: if trace.is_some() {
                    Confidence::Exact
                } else {
                    Confidence::Inferred
                },
            });
        }
    }
    dedupe_reference_files_by_node(&mut out);
    normalize_nested_reference_paths(&mut out);
    out
}

fn dedupe_reference_files_by_node(reference_files: &mut Vec<ReferenceFileOp>) {
    let mut deduped = Vec::with_capacity(reference_files.len());
    let mut deduped_index_by_node = HashMap::with_capacity(reference_files.len());
    for op in reference_files.drain(..) {
        let Some(existing_idx) = deduped_index_by_node.get(&op.reference_node).copied() else {
            deduped_index_by_node.insert(op.reference_node.clone(), deduped.len());
            deduped.push(op);
            continue;
        };
        let existing = &mut deduped[existing_idx];

        if existing.namespace_defaulted && !op.namespace_defaulted {
            existing.namespace = op.namespace.clone();
            existing.namespace_defaulted = false;
        }
        if existing.file_type_defaulted && !op.file_type_defaulted {
            existing.file_type = op.file_type.clone();
            existing.file_type_defaulted = false;
        }
        if existing.options.is_none() && op.options.is_some() {
            existing.options = op.options.clone();
        }
        if existing.path.is_empty() && !op.path.is_empty() {
            existing.path = op.path.clone();
        }
        if existing.trace.is_none() && op.trace.is_some() {
            existing.trace = op.trace.clone();
        }
        if matches!(existing.confidence, Confidence::Inferred)
            && matches!(op.confidence, Confidence::Exact)
        {
            existing.confidence = Confidence::Exact;
        }
    }
    *reference_files = deduped;
}

fn path_is_absolute(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with('\\') {
        return true;
    }
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'/' || bytes[2] == b'\\')
}

pub(crate) fn normalize_nested_reference_paths(reference_files: &mut [ReferenceFileOp]) {
    let include_by_node = reference_files
        .iter()
        .filter_map(|op| {
            let include_path = op
                .options
                .as_deref()
                .and_then(parse_reference_include_path)?;
            Some((op.reference_node.clone(), include_path))
        })
        .collect::<std::collections::HashMap<_, _>>();

    for op in reference_files.iter_mut() {
        if path_is_absolute(&op.path) {
            continue;
        }
        let Some(parent_node) = derive_parent_reference_node(&op.reference_node) else {
            continue;
        };
        let Some(parent_include) = include_by_node.get(parent_node.as_str()) else {
            continue;
        };
        if path_is_absolute(parent_include) {
            op.path = parent_include.clone();
            op.path_inferred_from_parent_include = true;
        }
    }
}
#[cfg(test)]
pub(crate) fn reference_file_op_from_entry(
    entry: crate::mb::paths::MbScenePathEntry,
) -> Option<ReferenceFileOp> {
    use crate::reference_semantics::{
        ScenePathAttrKind, classify_scene_path_attr, normalize_reference_file_type_token,
        parse_reference_options_token,
    };

    if entry.node_type != "reference"
        || !matches!(
            classify_scene_path_attr(&entry.attr),
            Some(ScenePathAttrKind::ReferencePath)
        )
        || entry.value.is_empty()
    {
        return None;
    }
    let meta = entry.meta?;
    let reference_node = meta.reference_node.clone()?;
    let namespace = meta
        .short_name
        .clone()
        .unwrap_or_else(|| reference_node.clone());
    let file_type = meta
        .format_hint
        .as_deref()
        .and_then(normalize_reference_file_type_token)
        .unwrap_or(default_reference_file_type())
        .to_string();
    let options = meta
        .reference_options
        .as_deref()
        .and_then(parse_reference_options_token);
    let trace = chunk_trace_from_scene_path_meta(&meta);
    let confidence = if trace.is_some() {
        Confidence::Exact
    } else {
        Confidence::Inferred
    };

    let mut interner = StringInterner::default();
    Some(ReferenceFileOp {
        path: entry.value,
        namespace: interner.intern_owned(namespace),
        reference_node: interner.intern_owned(reference_node),
        file_type: interner.intern_owned(file_type),
        options,
        namespace_defaulted: meta.short_name.is_none(),
        file_type_defaulted: meta.format_hint.is_none(),
        path_inferred_from_parent_include: false,
        trace,
        confidence,
    })
}

#[cfg(test)]
fn chunk_trace_from_scene_path_meta(
    meta: &crate::mb::paths::MbScenePathMeta,
) -> Option<ChunkTrace> {
    Some(ChunkTrace {
        form: meta.trace_form.clone()?,
        tag: meta.trace_tag.clone()?,
        node_offset: meta.trace_node_offset?,
        chunk_aux: None,
        child_alignment: meta.trace_child_alignment,
        child_header_size: meta.trace_child_header_size,
    })
}
