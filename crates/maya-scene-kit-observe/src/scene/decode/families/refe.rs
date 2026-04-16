use super::shared::make_unknown_event;
use crate::scene::{
    decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
    ir::{ChunkTrace, DecodedEvent},
    schema::{
        SchemaLookupContext, decode_fields_with_schema, field_bytes, field_text,
        lookup_chunk_schema_with_context_and_registry,
        refedit::decode_reference_edits_data_with_reason_and_registry,
    },
};

pub(crate) struct RefeFamilyDecoder;

impl ChunkDecoder for RefeFamilyDecoder {
    fn decoder_id(&self) -> &'static str {
        "refe_decoder"
    }

    fn handles_handler(&self, handler: &str) -> bool {
        handler == "refe.attr_payload"
    }

    fn decode_attempt(&self, context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
        let schema_context = SchemaLookupContext {
            payload_size: Some(context.payload.len()),
            aux: context.chunk_aux,
            parent_form: context.parent_form,
            parent_tag: context.parent_tag,
        };
        let schema = lookup_chunk_schema_with_context_and_registry(
            context.registry,
            context.form,
            context.tag,
            schema_context,
        )
        .or_else(|| {
            // REFE payload appears under multiple parent forms (e.g. REFN).
            // Resolve by tag fallback to the canonical REFE schema.
            if context.tag == "REFE" {
                lookup_chunk_schema_with_context_and_registry(
                    context.registry,
                    "REFE",
                    "REFE",
                    schema_context,
                )
            } else {
                None
            }
        });
        let Some(schema) = schema else {
            return DecodeAttempt::Pass {
                reason: "no schema for form/tag",
            };
        };
        let Some(handler) = schema.handler.as_deref() else {
            return DecodeAttempt::Pass {
                reason: "schema missing handler",
            };
        };
        if handler != "refe.attr_payload" {
            return DecodeAttempt::Pass {
                reason: "schema not handled by refe decoder",
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
                    "refe_decoder",
                )]);
            }
        };

        let attr_name = field_text(&fields, "attr_name")
            .unwrap_or_default()
            .to_string();
        let value_raw = field_bytes(&fields, "value_raw")
            .unwrap_or_default()
            .to_vec();

        if attr_name == "ed" {
            return DecodeAttempt::Handled(
                match decode_reference_edits_data_with_reason_and_registry(
                    context.registry,
                    &value_raw,
                ) {
                    Ok(data) => vec![DecodedEvent::RefEdit {
                        attr_name: attr_name.into(),
                        data,
                    }],
                    Err(err) => vec![make_unknown_event(
                        format!("REFE.ed decode failed: {err}"),
                        &value_raw,
                        trace,
                        "refe_decoder",
                    )],
                },
            );
        }

        DecodeAttempt::Handled(vec![make_unknown_event(
            format!("REFE attr payload unsupported outside 'ed' (attr={attr_name})"),
            context.payload,
            trace,
            "refe_decoder",
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::RefeFamilyDecoder;
    use crate::scene::{
        decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
        ir::DecodedEvent,
    };

    fn context<'a>(form: &'a str, payload: &'a [u8]) -> ChunkDecodeContext<'a> {
        ChunkDecodeContext {
            registry: crate::scene::schema::default_schema_registry(),
            form,
            tag: "REFE",
            payload,
            node_offset: 0x100,
            chunk_aux: None,
            child_alignment: Some(8),
            child_header_size: Some(16),
            parent_form: Some(form),
            parent_tag: Some("FOR8"),
        }
    }

    #[test]
    fn non_ed_refe_payload_is_reported_as_unknown() {
        let decoder = RefeFamilyDecoder;
        let payload = b"name\0\x00value\0";

        let DecodeAttempt::Handled(events) = decoder.decode_attempt(&context("REFE", payload))
        else {
            panic!("expected handled");
        };

        assert_eq!(events.len(), 1);
        let DecodedEvent::Unknown(unknown) = &events[0] else {
            panic!("expected unknown event");
        };
        assert!(unknown.reason.contains("unsupported outside 'ed'"));
    }

    #[test]
    fn refe_payload_under_refn_form_uses_refe_schema_fallback() {
        let decoder = RefeFamilyDecoder;
        let payload = b"name\0\x00value\0";

        let DecodeAttempt::Handled(events) = decoder.decode_attempt(&context("REFN", payload))
        else {
            panic!("expected handled");
        };

        assert_eq!(events.len(), 1);
        let DecodedEvent::Unknown(unknown) = &events[0] else {
            panic!("expected unknown event");
        };
        assert!(unknown.reason.contains("unsupported outside 'ed'"));
    }
}
