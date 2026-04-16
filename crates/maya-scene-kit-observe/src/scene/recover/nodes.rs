use std::collections::{HashMap, HashSet};

use crate::scene::{
    ir::{
        ChunkTrace, Confidence, CreateNodeFlags, DecodedChunkRecord, DecodedEvent, FlagState,
        RecoveredAttrOp, RecoveredNode, RecoveryIssue, RecoveryIssueKind, SemanticProvenance,
        SetAttrOp, SetAttrValue, StringInterner,
    },
    schema::typeid_map::TypeIdTypeNameResolver,
};

type NodeKey = (String, String, Option<String>, Option<String>, usize);
type NodeBaseKey = (String, String, Option<String>);

pub(crate) fn recover_nodes(
    decoded_chunks: &[DecodedChunkRecord],
    typeid_resolver: Option<&TypeIdTypeNameResolver>,
) -> Vec<RecoveredNode> {
    let mut node_order: Vec<NodeKey> = Vec::new();
    let mut node_attrs: HashMap<NodeKey, Vec<RecoveredAttrOp>> = HashMap::new();
    let mut node_decode_notes: HashMap<NodeKey, Vec<RecoveryIssue>> = HashMap::new();
    let mut node_create_flags: HashMap<NodeKey, CreateNodeFlags> = HashMap::new();
    let mut node_candidates_by_base: HashMap<NodeBaseKey, Vec<NodeKey>> = HashMap::new();
    let mut duplicate_node_keys_noted: HashSet<NodeKey> = HashSet::new();
    let mut interner = StringInterner::default();
    let mut cursor = 0usize;

    while cursor < decoded_chunks.len() {
        let first = &decoded_chunks[cursor];
        let form = first.chunk_ref.form.clone();
        let node_offset = first.chunk_ref.node_offset;
        let child_alignment = first.chunk_ref.child_alignment;
        let child_header_size = first.chunk_ref.child_header_size;

        let mut name: Option<String> = None;
        let mut parent: Option<String> = None;
        let mut uid: Option<String> = None;
        let mut attrs: Vec<RecoveredAttrOp> = Vec::new();
        let mut decode_notes: Vec<RecoveryIssue> = Vec::new();
        let mut script_bodies: Vec<String> = Vec::new();
        let mut create_flags = CreateNodeFlags::default();

        while cursor < decoded_chunks.len()
            && decoded_chunks[cursor].chunk_ref.form == form
            && decoded_chunks[cursor].chunk_ref.node_offset == node_offset
        {
            let decoded = &decoded_chunks[cursor];
            for event in &decoded.events {
                match event {
                    DecodedEvent::CreateNode {
                        name: event_name,
                        parent: event_parent,
                        uid: event_uid,
                        create_flags: event_flags,
                        used_len_prefixed_fields,
                    } => {
                        if event_name.is_some() {
                            name = event_name.clone();
                            parent = event_parent.clone();
                        }
                        if event_uid.is_some() {
                            uid = event_uid.clone();
                        }
                        merge_create_node_flags(&mut create_flags, event_flags);
                        if *used_len_prefixed_fields {
                            decode_notes.push(RecoveryIssue {
                                kind: RecoveryIssueKind::Inferred,
                                confidence: Confidence::Inferred,
                                attr_name: "<CREA>".to_string(),
                                reason: Some(
                                    "name/parent decoded via length-prefixed CREA fields"
                                        .to_string(),
                                ),
                                semantic_provenance: None,
                                value_kind_hex: None,
                                payload_size: Some(decoded.chunk_ref.payload_size),
                                payload_digest_hex: None,
                                payload_preview_hex: None,
                                payload_inline_hex: None,
                                refedit_unknown_tail_offset: None,
                                refedit_unknown_tail_opcode_hex: None,
                                refedit_unknown_tail_payload_size: None,
                                refedit_unknown_tail_payload_preview_hex: None,
                                decoder_attempts: vec![],
                                trace: Some(chunk_trace_from_record(decoded)),
                            });
                        }
                    }
                    DecodedEvent::ScriptBody { body } => {
                        if !body.is_empty() {
                            push_script_body_attr(&mut attrs, body);
                            if !script_bodies.iter().any(|existing| existing == body) {
                                script_bodies.push(body.clone());
                            }
                        }
                    }
                    DecodedEvent::AddAttr(op) => attrs.push(RecoveredAttrOp::AddAttr(op.clone())),
                    DecodedEvent::SetAttr(op) => attrs.push(RecoveredAttrOp::SetAttr(op.clone())),
                    DecodedEvent::Unknown(unknown) => decode_notes.push(RecoveryIssue {
                        kind: RecoveryIssueKind::Unsupported,
                        confidence: Confidence::Unknown,
                        attr_name: "<unknown-chunk>".to_string(),
                        reason: Some(unknown.reason.clone()),
                        semantic_provenance: None,
                        value_kind_hex: None,
                        payload_size: Some(unknown.payload_size),
                        payload_digest_hex: Some(unknown.payload_digest_hex.clone()),
                        payload_preview_hex: Some(unknown.payload_preview_hex.clone()),
                        payload_inline_hex: unknown.payload_inline_hex.clone(),
                        refedit_unknown_tail_offset: None,
                        refedit_unknown_tail_opcode_hex: None,
                        refedit_unknown_tail_payload_size: None,
                        refedit_unknown_tail_payload_preview_hex: None,
                        decoder_attempts: unknown.decoder_attempts.clone(),
                        trace: Some(unknown.trace.clone()),
                    }),
                    DecodedEvent::RefEdit { attr_name, data } => {
                        attrs.push(RecoveredAttrOp::RefEdit {
                            attr_name: interner.intern(attr_name.as_ref()),
                            data: data.clone(),
                        })
                    }
                    DecodedEvent::Connect { .. }
                    | DecodedEvent::Relationship { .. }
                    | DecodedEvent::SelectTarget { .. }
                    | DecodedEvent::ReferenceFile { .. } => {}
                }
            }
            cursor += 1;
        }

        let mut node_type_and_provenance =
            resolve_node_type(&form, name.as_deref(), typeid_resolver);
        if !script_bodies.is_empty() && node_type_and_provenance.0.is_none() {
            node_type_and_provenance.0 = Some("script".to_string());
        }
        if !script_bodies.is_empty() && name.is_none() {
            name = Some(format!("scriptNode_{node_offset:08X}"));
            decode_notes.push(RecoveryIssue::inferred_analysis(
                ".b",
                "script body recovered without CREA name; synthesized script node name from chunk offset",
            ));
        }
        let (node_type, node_type_provenance) = node_type_and_provenance;

        if let Some(provenance) = node_type_provenance {
            decode_notes.push(RecoveryIssue::inferred_analysis_with_provenance(
                "<CREA>",
                "node type inferred from recovered node name suffix",
                provenance,
            ));
        }

        if node_type.is_none() {
            decode_notes.push(RecoveryIssue {
                kind: RecoveryIssueKind::Unsupported,
                confidence: Confidence::Unknown,
                attr_name: "<CREA>".to_string(),
                reason: Some(format!(
                    "node form '{form}' is not mapped to a Maya node type"
                )),
                semantic_provenance: None,
                value_kind_hex: None,
                payload_size: Some(first.chunk_ref.payload_size),
                payload_digest_hex: None,
                payload_preview_hex: None,
                payload_inline_hex: None,
                refedit_unknown_tail_offset: None,
                refedit_unknown_tail_opcode_hex: None,
                refedit_unknown_tail_payload_size: None,
                refedit_unknown_tail_payload_preview_hex: None,
                decoder_attempts: vec![],
                trace: Some(ChunkTrace {
                    form: form.clone(),
                    tag: "CREA".to_string(),
                    node_offset,
                    chunk_aux: None,
                    child_alignment,
                    child_header_size,
                }),
            });
        }

        if let (Some(node_type), Some(name)) = (node_type, name) {
            let base_key = (node_type.clone(), name.clone(), parent.clone());
            let existing_candidates = node_candidates_by_base
                .get(&base_key)
                .cloned()
                .unwrap_or_default();
            let occurrence = if uid.is_some() || existing_candidates.is_empty() {
                0
            } else {
                existing_candidates.len()
            };
            let key = recovered_node_merge_key(
                &node_type,
                &name,
                parent.as_deref(),
                uid.as_deref(),
                occurrence,
            );
            if !node_attrs.contains_key(&key) {
                node_order.push(key.clone());
            }
            node_attrs
                .entry(key.clone())
                .or_default()
                .append(&mut attrs);
            node_decode_notes
                .entry(key.clone())
                .or_default()
                .append(&mut decode_notes);
            node_create_flags
                .entry(key.clone())
                .or_insert(create_flags.clone());

            let candidates = node_candidates_by_base.entry(base_key.clone()).or_default();
            if !candidates.iter().any(|existing| existing == &key) {
                if !candidates.is_empty() && duplicate_node_keys_noted.insert(key.clone()) {
                    for existing in candidates.iter() {
                        node_decode_notes
                            .entry(existing.clone())
                            .or_default()
                            .push(RecoveryIssue::inferred_analysis(
                                "<CREA>",
                                "duplicate recovered node base key encountered; preserved separate recovered candidates",
                            ));
                    }
                    node_decode_notes
                        .entry(key.clone())
                        .or_default()
                        .push(RecoveryIssue::inferred_analysis(
                            "<CREA>",
                            "duplicate recovered node base key encountered; preserved separate recovered candidates",
                        ));
                }
                candidates.push(key);
            }
        }
    }

    node_order
        .into_iter()
        .map(|key| {
            let (node_type, name, parent, uid, _) = key.clone();
            RecoveredNode {
                node_type: interner.intern_owned(node_type),
                name,
                parent,
                uid,
                attrs: node_attrs.remove(&key).unwrap_or_default(),
                decode_notes: node_decode_notes.remove(&key).unwrap_or_default(),
                create_flags: node_create_flags.remove(&key).unwrap_or_default(),
            }
        })
        .collect()
}

fn merge_create_node_flags(base: &mut CreateNodeFlags, newer: &CreateNodeFlags) {
    if base.shared == FlagState::Unknown {
        base.shared = newer.shared;
    }
    if base.skip_select == FlagState::Unknown {
        base.skip_select = newer.skip_select;
    }
    if base.raw_header_prefix.is_empty() && !newer.raw_header_prefix.is_empty() {
        base.raw_header_prefix = newer.raw_header_prefix.clone();
    }
    if base.raw_flag_byte.is_none() {
        base.raw_flag_byte = newer.raw_flag_byte;
    }
}

fn chunk_trace_from_record(decoded: &DecodedChunkRecord) -> ChunkTrace {
    ChunkTrace {
        form: decoded.chunk_ref.form.clone(),
        tag: decoded.chunk_ref.tag.clone(),
        node_offset: decoded.chunk_ref.node_offset,
        chunk_aux: decoded.chunk_ref.chunk_aux,
        child_alignment: decoded.chunk_ref.child_alignment,
        child_header_size: decoded.chunk_ref.child_header_size,
    }
}

fn push_script_body_attr(attrs: &mut Vec<RecoveredAttrOp>, body: &str) {
    let duplicate = attrs.iter().any(|attr| {
        matches!(
            attr,
            RecoveredAttrOp::SetAttr(SetAttrOp {
                attr_name_or_path,
                value: SetAttrValue::String(existing),
                ..
            }) if attr_name_or_path == ".b" && existing == body
        )
    });
    if duplicate {
        return;
    }
    attrs.push(RecoveredAttrOp::SetAttr(SetAttrOp {
        attr_name_or_path: ".b".to_string(),
        array_size: None,
        channel_hint: None,
        lock: None,
        keyable: None,
        value: SetAttrValue::String(body.to_string()),
    }));
}

pub(crate) fn recovered_node_merge_key(
    node_type: &str,
    name: &str,
    parent: Option<&str>,
    uid: Option<&str>,
    occurrence: usize,
) -> (String, String, Option<String>, Option<String>, usize) {
    (
        node_type.to_string(),
        name.to_string(),
        parent.map(|value| value.to_string()),
        uid.map(|value| value.to_string()),
        occurrence,
    )
}

pub(crate) fn parse_form_type_id(raw: &str) -> Option<u32> {
    if raw.len() == 4 && raw.is_ascii() {
        return Some(u32::from_be_bytes(raw.as_bytes().try_into().ok()?));
    }
    let hex = raw.strip_prefix('[')?.strip_suffix(']')?;
    u32::from_str_radix(hex, 16).ok()
}

pub(crate) fn infer_node_type_from_name(name: &str) -> Option<String> {
    if let Some(suffix) = name.rsplit('_').next() {
        if let Some(token) = strip_trailing_digits(suffix).filter(|token| is_type_token(token)) {
            return Some(token.to_string());
        }
    }
    if let Some(token) = strip_trailing_digits(name).filter(|token| is_type_token(token)) {
        return Some(token.to_string());
    }
    None
}

fn resolve_node_type(
    form: &str,
    name: Option<&str>,
    typeid_resolver: Option<&TypeIdTypeNameResolver>,
) -> (Option<String>, Option<SemanticProvenance>) {
    if let Some(node_type) = parse_form_type_id(form)
        .and_then(|type_id| typeid_resolver.and_then(|resolver| resolver.lookup(type_id)))
    {
        return (Some(node_type), None);
    }
    if let Some(node_type) = name.and_then(infer_node_type_from_name) {
        return (
            Some(node_type),
            Some(SemanticProvenance::NodeNameSuffixInference),
        );
    }
    (None, None)
}

fn strip_trailing_digits(raw: &str) -> Option<&str> {
    let trimmed = raw.trim_end_matches(|c: char| c.is_ascii_digit());
    if trimmed.is_empty() || trimmed.len() == raw.len() {
        return None;
    }
    Some(trimmed)
}

fn is_type_token(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if token.starts_with("default") || !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
