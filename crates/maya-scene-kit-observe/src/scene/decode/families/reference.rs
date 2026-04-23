use super::shared::make_unknown_event;
use crate::{
    reference_semantics::{normalize_reference_file_type_token, parse_reference_options_token},
    scene::{
        decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
        ir::{ChunkTrace, DecodedEvent},
        schema::{
            SchemaLookupContext, decode_fields_with_schema, field_bytes, field_text,
            lookup_chunk_schema_with_context_and_registry,
        },
    },
};

pub(crate) struct ReferenceFamilyDecoder;

impl ChunkDecoder for ReferenceFamilyDecoder {
    fn decoder_id(&self) -> &'static str {
        "reference_decoder"
    }

    fn handles_handler(&self, handler: &str) -> bool {
        handler == "fref.reference_file"
    }

    fn decode_attempt(&self, context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
        if context.form == "FRDI" && context.tag == "FRDI" {
            return decode_frdi_chunk(context);
        }

        let schema_context = SchemaLookupContext {
            payload_size: Some(context.payload.len()),
            aux: context.chunk_aux,
            parent_form: context.parent_form,
            parent_tag: context.parent_tag,
        };
        let Some(schema) = lookup_chunk_schema_with_context_and_registry(
            context.registry,
            context.form,
            context.tag,
            schema_context,
        ) else {
            return DecodeAttempt::Pass {
                reason: "no schema for form/tag",
            };
        };
        let Some(handler) = schema.handler.as_deref() else {
            return DecodeAttempt::Pass {
                reason: "schema missing handler",
            };
        };
        if handler != "fref.reference_file" {
            return DecodeAttempt::Pass {
                reason: "schema not handled by reference decoder",
            };
        }
        let trace = ChunkTrace {
            form: context.form.to_string(),
            tag: context.tag.to_string(),
            node_offset: context.node_offset,
            chunk_aux: context.chunk_aux,
            child_alignment: context.child_alignment,
            child_header_size: context.child_header_size,
        };

        let fields = match decode_fields_with_schema(&schema, context.payload) {
            Ok(fields) => fields,
            Err(err) => {
                return DecodeAttempt::Handled(vec![make_unknown_event(
                    format!("{} decode failed: {err}", schema.schema_id),
                    context.payload,
                    trace,
                    "reference_decoder",
                )]);
            }
        };

        let path = sanitize_reference_slot(field_text(&fields, "path").unwrap_or_default());
        if path.is_empty() {
            return DecodeAttempt::Handled(vec![make_unknown_event(
                format!("{} missing required path", schema.schema_id),
                context.payload,
                trace,
                "reference_decoder",
            )]);
        }

        // Canonical FREF slot semantics: [path, namespace, reference_node, ...tail].
        // Keep legacy field name fallback for external schema packs.
        let namespace_slot_raw = field_text(&fields, "namespace")
            .or_else(|| field_text(&fields, "reference_node"))
            .unwrap_or_default();
        let namespace_slot = sanitize_reference_slot(namespace_slot_raw);
        if namespace_slot.is_empty() {
            return DecodeAttempt::Handled(vec![make_unknown_event(
                format!("{} missing required namespace slot", schema.schema_id),
                context.payload,
                trace,
                "reference_decoder",
            )]);
        }

        let reference_node_slot_raw = field_text(&fields, "reference_node")
            .or_else(|| field_text(&fields, "short_name"))
            .unwrap_or_default();
        let reference_node_slot = sanitize_reference_slot(reference_node_slot_raw);
        let reference_node = if reference_node_slot.is_empty() {
            namespace_slot.clone()
        } else {
            reference_node_slot
        };
        let namespace = Some(namespace_slot);

        let tail =
            match parse_fref_tail_fields(field_bytes(&fields, "tail_raw").unwrap_or_default()) {
                Ok(tail) => tail,
                Err(reason) => {
                    return DecodeAttempt::Handled(vec![make_unknown_event(
                        format!("{} tail decode failed: {reason}", schema.schema_id),
                        context.payload,
                        trace,
                        "reference_decoder",
                    )]);
                }
            };

        DecodeAttempt::Handled(vec![DecodedEvent::ReferenceFile {
            path,
            reference_node: reference_node.into(),
            namespace: namespace.map(Into::into),
            file_type: tail.file_type.map(Into::into),
            options: tail.options,
        }])
    }
}

fn decode_frdi_chunk(context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
    let Some(fields) = parse_frdi_fields(context.payload) else {
        return DecodeAttempt::Pass {
            reason: "frdi payload did not match reference layout",
        };
    };

    DecodeAttempt::Handled(vec![DecodedEvent::ReferenceFile {
        path: fields.path,
        reference_node: fields.reference_node.into(),
        namespace: Some(fields.namespace.into()),
        file_type: fields.file_type.map(Into::into),
        options: fields.options,
    }])
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FrefTailFields {
    file_type: Option<String>,
    options: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrdiFields {
    path: String,
    namespace: String,
    reference_node: String,
    file_type: Option<String>,
    options: Option<String>,
}

fn parse_fref_tail_fields(raw: &[u8]) -> Result<FrefTailFields, String> {
    let mut fields = FrefTailFields::default();

    for token in raw
        .split(|b| *b == 0)
        .map(|part| String::from_utf8_lossy(part).trim().to_string())
        .filter(|value| !value.is_empty())
    {
        if let Some(file_type) = normalize_reference_file_type_token(&token) {
            if fields.file_type.replace(token.clone()).is_some() {
                return Err("duplicate file_type token".to_string());
            }
            fields.file_type = Some(file_type.to_string());
            continue;
        }

        if token.starts_with("-op ") {
            if fields.options.is_some() {
                return Err("duplicate -op token".to_string());
            }
            fields.options = parse_reference_options_token(&token);
            continue;
        }

        if let Some(options) = parse_reference_options_token(&token) {
            if fields.options.is_some() {
                return Err("duplicate options token".to_string());
            }
            fields.options = Some(options);
            continue;
        }

        // Observed FREF payloads may include non-semantic exporter labels such as
        // "FBX export" after the VERS options token. They do not affect the
        // reference file identity, so keep the reference event instead of
        // downgrading the whole chunk to unknown raw text.
    }

    Ok(fields)
}

fn sanitize_reference_slot(value: &str) -> String {
    value
        .trim_start_matches(|c: char| c.is_control())
        .trim()
        .to_string()
}

fn parse_frdi_fields(raw: &[u8]) -> Option<FrdiFields> {
    let fields = raw
        .split(|b| *b == 0)
        .map(|part| {
            String::from_utf8_lossy(part)
                .trim_start_matches(|c: char| c.is_control())
                .trim()
                .to_string()
        })
        .collect::<Vec<_>>();
    if fields.is_empty() {
        return None;
    }

    let path_idx = fields
        .iter()
        .position(|value| looks_like_frdi_dependency_path(value))?;
    let path = fields[path_idx].clone();
    if path.is_empty() {
        return None;
    }

    let namespace = fields
        .iter()
        .skip(path_idx + 1)
        .find(|value| {
            !value.is_empty()
                && !value.ends_with("RN")
                && normalize_reference_file_type_token(value).is_none()
                && parse_reference_options_token(value).is_none()
        })?
        .clone();
    let reference_node = fields
        .iter()
        .skip(path_idx + 1)
        .find(|value| value.ends_with("RN"))
        .cloned()
        .unwrap_or_else(|| namespace.clone());
    let file_type = fields
        .iter()
        .find_map(|token| normalize_reference_file_type_token(token))
        .map(str::to_string);
    let options = fields
        .iter()
        .find_map(|value| parse_reference_options_token(value));

    Some(FrdiFields {
        path,
        namespace,
        reference_node,
        file_type,
        options,
    })
}

fn looks_like_frdi_dependency_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    (lower.contains(".mb") || lower.contains(".ma") || lower.contains(".fbx"))
        && (value.contains('/') || value.contains('\\'))
}

#[cfg(test)]
mod tests {
    use super::ReferenceFamilyDecoder;
    use crate::scene::{
        decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
        ir::DecodedEvent,
    };

    fn context(payload: &[u8]) -> ChunkDecodeContext<'_> {
        ChunkDecodeContext {
            registry: crate::scene::schema::default_schema_registry(),
            form: "FREF",
            tag: "FREF",
            payload,
            node_offset: 0x100,
            chunk_aux: None,
            child_alignment: Some(8),
            child_header_size: Some(16),
            parent_form: Some("FREF"),
            parent_tag: Some("FOR8"),
        }
    }

    fn frdi_context(payload: &[u8]) -> ChunkDecodeContext<'_> {
        ChunkDecodeContext {
            registry: crate::scene::schema::default_schema_registry(),
            form: "FRDI",
            tag: "FRDI",
            payload,
            node_offset: 0x200,
            chunk_aux: None,
            child_alignment: Some(8),
            child_header_size: Some(16),
            parent_form: Some("FRDI"),
            parent_tag: Some("FOR8"),
        }
    }

    #[test]
    fn fref_schema_decodes_reference_file_event() {
        let decoder = ReferenceFamilyDecoder;
        let payload = b"rig/charA_v001.mb\0charA\0charARN\0mayaBinary\0-op \"v=0\"\0";

        let DecodeAttempt::Handled(events) = decoder.decode_attempt(&context(payload)) else {
            panic!("expected handled");
        };

        assert_eq!(events.len(), 1);
        let DecodedEvent::ReferenceFile {
            path,
            reference_node,
            namespace,
            file_type,
            options,
        } = &events[0]
        else {
            panic!("expected reference file event");
        };

        assert_eq!(path, "rig/charA_v001.mb");
        assert_eq!(reference_node.as_ref(), "charARN");
        assert_eq!(namespace.as_deref(), Some("charA"));
        assert_eq!(file_type.as_deref(), Some("mayaBinary"));
        assert_eq!(options.as_deref(), Some("v=0"));
    }

    #[test]
    fn fref_schema_accepts_vers_options_token() {
        let decoder = ReferenceFamilyDecoder;
        let payload = b"rig/charA_v001.mb\0charA\0charARN\0VERS|2026|\0";

        let DecodeAttempt::Handled(events) = decoder.decode_attempt(&context(payload)) else {
            panic!("expected handled");
        };

        assert_eq!(events.len(), 1);
        let DecodedEvent::ReferenceFile {
            path,
            reference_node,
            namespace,
            file_type,
            options,
        } = &events[0]
        else {
            panic!("expected reference file event");
        };
        assert_eq!(path, "rig/charA_v001.mb");
        assert_eq!(reference_node.as_ref(), "charARN");
        assert_eq!(namespace.as_deref(), Some("charA"));
        assert_eq!(file_type.as_deref(), None);
        assert_eq!(options.as_deref(), Some("VERS|2026|"));
    }

    #[test]
    fn fref_schema_accepts_fbx_export_tail_metadata() {
        let decoder = ReferenceFamilyDecoder;
        let payload = b"assets/example/ExampleAsset.fbx\0Source\0\x01\x01SourceRN\0\0\0\0\0VERS|2020|\0FBX export\0";

        let DecodeAttempt::Handled(events) = decoder.decode_attempt(&context(payload)) else {
            panic!("expected handled");
        };

        assert_eq!(events.len(), 1);
        let DecodedEvent::ReferenceFile {
            path,
            reference_node,
            namespace,
            file_type,
            options,
        } = &events[0]
        else {
            panic!("expected reference file event");
        };

        assert_eq!(path, "assets/example/ExampleAsset.fbx");
        assert_eq!(reference_node.as_ref(), "SourceRN");
        assert_eq!(namespace.as_deref(), Some("Source"));
        assert_eq!(file_type.as_deref(), None);
        assert_eq!(options.as_deref(), Some("VERS|2020|"));
    }

    #[test]
    fn frdi_chunk_decodes_reference_file_event() {
        let decoder = ReferenceFamilyDecoder;
        let payload = b"\x01\x04\0\x02scenes/TestScene_0000.mb\0Model\0\x01\0Example:ModelRN\0VERS|2020|\0mayaBinary\0";

        let DecodeAttempt::Handled(events) = decoder.decode_attempt(&frdi_context(payload)) else {
            panic!("expected handled");
        };

        assert_eq!(events.len(), 1);
        let DecodedEvent::ReferenceFile {
            path,
            reference_node,
            namespace,
            file_type,
            options,
        } = &events[0]
        else {
            panic!("expected reference file event");
        };

        assert_eq!(path, "scenes/TestScene_0000.mb");
        assert_eq!(reference_node.as_ref(), "Example:ModelRN");
        assert_eq!(namespace.as_deref(), Some("Model"));
        assert_eq!(file_type.as_deref(), Some("mayaBinary"));
        assert_eq!(options.as_deref(), Some("VERS|2020|"));
    }

    #[test]
    fn frdi_chunk_decodes_fbx_dependency_file_event() {
        let decoder = ReferenceFamilyDecoder;
        let payload = b"\0\0\0\x02assets/example/ExampleAsset.fbx\0Source\0\x01\0Import_00_Example:SourceRN\0\0\0\0VERS|2020|\0FBX export\0";

        let DecodeAttempt::Handled(events) = decoder.decode_attempt(&frdi_context(payload)) else {
            panic!("expected handled");
        };

        assert_eq!(events.len(), 1);
        let DecodedEvent::ReferenceFile {
            path,
            reference_node,
            namespace,
            file_type,
            options,
        } = &events[0]
        else {
            panic!("expected reference file event");
        };

        assert_eq!(path, "assets/example/ExampleAsset.fbx");
        assert_eq!(reference_node.as_ref(), "Import_00_Example:SourceRN");
        assert_eq!(namespace.as_deref(), Some("Source"));
        assert_eq!(file_type.as_deref(), None);
        assert_eq!(options.as_deref(), Some("VERS|2020|"));
    }
}
