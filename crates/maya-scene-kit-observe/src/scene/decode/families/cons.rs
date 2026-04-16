use super::shared::make_unknown_event;
use crate::scene::{
    decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
    ir::{ChunkTrace, DecodedEvent},
    schema::{
        SchemaLookupContext, decode_fields_with_schema, field_text, field_text_values, field_u8,
        lookup_chunk_schema_with_context_and_registry,
    },
};

pub(crate) struct ConsFamilyDecoder;

impl ChunkDecoder for ConsFamilyDecoder {
    fn decoder_id(&self) -> &'static str {
        "cons_decoder"
    }

    fn handles_handler(&self, handler: &str) -> bool {
        handler.starts_with("cons.")
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
        if !handler.starts_with("cons.") {
            return DecodeAttempt::Pass {
                reason: "schema not handled by cons decoder",
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
                    "cons_decoder",
                )]);
            }
        };

        DecodeAttempt::Handled(match handler {
            "cons.cwfl" => {
                let mode = field_u8(&fields, "mode").unwrap_or(0);
                let src = field_text(&fields, "src").unwrap_or_default().to_string();
                let dst = field_text(&fields, "dst").unwrap_or_default().to_string();
                if src.is_empty() || dst.is_empty() {
                    vec![make_unknown_event(
                        format!("{} missing src/dst", schema.schema_id),
                        context.payload,
                        trace,
                        "cons_decoder",
                    )]
                } else {
                    vec![DecodedEvent::Connect { src, dst, mode }]
                }
            }
            "cons.rela" => {
                let kind = field_text(&fields, "kind").unwrap_or_default().to_string();
                let head = field_text(&fields, "head").unwrap_or_default().to_string();
                let tail = field_text_values(&fields, "tail")
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                if kind.is_empty() || head.is_empty() || tail.is_empty() {
                    vec![make_unknown_event(
                        format!("{} missing relationship fields", schema.schema_id),
                        context.payload,
                        trace,
                        "cons_decoder",
                    )]
                } else {
                    vec![DecodedEvent::Relationship {
                        kind: kind.into(),
                        head,
                        tail,
                    }]
                }
            }
            _ => vec![make_unknown_event(
                format!(
                    "{} unsupported in cons decoder (handler={handler})",
                    schema.schema_id
                ),
                context.payload,
                trace,
                "cons_decoder",
            )],
        })
    }
}
