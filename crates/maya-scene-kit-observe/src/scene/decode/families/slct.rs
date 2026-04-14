use super::shared::make_unknown_event;
use crate::scene::{
    decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
    ir::{ChunkTrace, DecodedEvent},
    schema::{
        SchemaLookupContext, decode_fields_with_schema, field_text,
        lookup_chunk_schema_with_context_and_registry,
    },
};

pub(crate) struct SlctFamilyDecoder;

impl ChunkDecoder for SlctFamilyDecoder {
    fn decoder_id(&self) -> &'static str {
        "slct_decoder"
    }

    fn handles_handler(&self, handler: &str) -> bool {
        handler == "slct.target"
    }

    fn decode_attempt(&self, context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
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
        if handler != "slct.target" {
            return DecodeAttempt::Pass {
                reason: "schema not handled by slct decoder",
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
                    "slct_decoder",
                )]);
            }
        };
        let target = field_text(&fields, "target")
            .unwrap_or_default()
            .trim()
            .to_string();
        if target.is_empty() {
            return DecodeAttempt::Handled(vec![make_unknown_event(
                format!("{} target decode failed", schema.schema_id),
                context.payload,
                trace,
                "slct_decoder",
            )]);
        }
        DecodeAttempt::Handled(vec![DecodedEvent::SelectTarget { target }])
    }
}
