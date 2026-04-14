use super::shared::{
    make_unknown_event, make_unknown_event_with_attempts, make_unsupported_attr_unknown,
};
#[cfg(test)]
use crate::scene::decode::attr::decode_attr_value_chunk_to_outcome;
use crate::scene::{
    decode::{
        attr::{
            AttrDecodeOutcome, attr_value_handler_id_from_schema_handler,
            decode_attr_definition_chunk_to_outcome_with_registry, decode_attr_payload,
            decode_attr_value_from_handler, decode_attr_value_from_schema_fields,
            validate_attr_handler_payload_shape,
        },
        dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
    },
    ir::{ChunkTrace, DecodedEvent, SchemaDecodeAttempt, SchemaDecodeAttemptResult},
    schema::{
        self, SchemaLookupContext, decode_fields_with_schema, field_bytes, field_text, field_u8,
        lookup_chunk_schema_with_context_and_registry,
        structural_attr::structural_attr_handler_rules_with_registry,
    },
};

pub(crate) struct AttrFamilyDecoder;

enum StructuralFallbackDecodeResult {
    Applied {
        events: Vec<DecodedEvent>,
        quality: SchemaDecodeAttemptResult,
    },
    Rejected {
        reason: String,
        attempts: Vec<SchemaDecodeAttempt>,
    },
    NotApplicable,
}

impl ChunkDecoder for AttrFamilyDecoder {
    fn decoder_id(&self) -> &'static str {
        "attr_decoder"
    }

    fn handles_handler(&self, handler: &str) -> bool {
        handler.starts_with("attr.") || handler == "rtft.attr_payload"
    }

    fn decode_attempt(&self, context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
        let has_attr_schema = lookup_attr_value_schema(
            context.registry,
            context.form,
            context.tag,
            context.payload.len(),
            context.chunk_aux,
            context.parent_form,
            context.parent_tag,
        )
        .is_some();
        if context.tag != "ATTR"
            && !has_attr_schema
            && decode_attr_payload(context.payload).is_none()
        {
            return DecodeAttempt::Pass {
                reason: "tag not in attr family",
            };
        }
        let trace = context.trace();
        decode_attr_family_events(
            context.registry,
            context.form,
            context.tag,
            context.payload,
            context.chunk_aux,
            context.parent_form,
            context.parent_tag,
            has_attr_schema,
            trace,
        )
    }
}

fn decode_attr_family_events(
    registry: &schema::SchemaRegistry,
    form: &str,
    tag: &str,
    payload: &[u8],
    chunk_aux: Option<u32>,
    parent_form: Option<&str>,
    parent_tag: Option<&str>,
    has_attr_schema: bool,
    trace: ChunkTrace,
) -> DecodeAttempt {
    if tag == "ATTR" {
        return DecodeAttempt::HandledWithQuality {
            events: decode_attr_definition_events(registry, payload, trace),
            quality: SchemaDecodeAttemptResult::Exact,
        };
    }
    if let Some((events, quality)) = decode_attr_value_events_schema(
        registry,
        form,
        tag,
        payload,
        chunk_aux,
        parent_form,
        parent_tag,
        trace.clone(),
    ) {
        return DecodeAttempt::HandledWithQuality { events, quality };
    }
    match decode_attr_value_events_structural_fallback(registry, payload) {
        StructuralFallbackDecodeResult::Applied { events, quality } => {
            return DecodeAttempt::HandledWithQuality { events, quality };
        }
        StructuralFallbackDecodeResult::Rejected {
            reason,
            mut attempts,
        } => {
            attempts.push(SchemaDecodeAttempt {
                decoder_id: "attr_decoder".to_string(),
                result: SchemaDecodeAttemptResult::Failed,
                reason: Some(reason.clone()),
            });
            return DecodeAttempt::HandledWithQuality {
                events: vec![make_unknown_event_with_attempts(
                    reason, payload, trace, attempts,
                )],
                quality: SchemaDecodeAttemptResult::Failed,
            };
        }
        StructuralFallbackDecodeResult::NotApplicable => {}
    }
    if !has_attr_schema {
        return DecodeAttempt::Pass {
            reason: "tag not in attr family",
        };
    }
    DecodeAttempt::HandledWithQuality {
        events: vec![make_unknown_event(
            format!("attr schema route not found for tag {tag}"),
            payload,
            trace,
            "attr_decoder",
        )],
        quality: SchemaDecodeAttemptResult::Failed,
    }
}

fn decode_attr_value_events_structural_fallback(
    registry: &schema::SchemaRegistry,
    payload: &[u8],
) -> StructuralFallbackDecodeResult {
    let Some((attr_name, kind, value_raw)) = decode_attr_payload(payload) else {
        return StructuralFallbackDecodeResult::NotApplicable;
    };

    let mut attempts = Vec::new();
    let mut matched_handlers = Vec::new();
    let mut successful = Vec::new();

    for rule in structural_attr_handler_rules_with_registry(registry).iter() {
        let attempt_id = format!("attr_fallback.{}", rule.handler());
        match rule.evaluate(&attr_name, kind, &value_raw) {
            Ok(()) => {
                matched_handlers.push(rule.handler().to_string());
                let Some(handler_id) =
                    attr_value_handler_id_from_schema_handler(rule.handler(), "ATTR")
                else {
                    attempts.push(SchemaDecodeAttempt {
                        decoder_id: attempt_id,
                        result: SchemaDecodeAttemptResult::Failed,
                        reason: Some("handler metadata is not a typed attr handler".to_string()),
                    });
                    continue;
                };
                if let Err(reason) =
                    validate_attr_handler_payload_shape(handler_id, kind, &value_raw)
                {
                    attempts.push(SchemaDecodeAttempt {
                        decoder_id: attempt_id,
                        result: SchemaDecodeAttemptResult::Failed,
                        reason: Some(reason.to_string()),
                    });
                    continue;
                }

                match decode_attr_value_from_handler(handler_id, &attr_name, kind, &value_raw) {
                    Some(op) => {
                        attempts.push(SchemaDecodeAttempt {
                            decoder_id: attempt_id,
                            result: SchemaDecodeAttemptResult::Partial,
                            reason: Some("candidate matched and decoded".to_string()),
                        });
                        successful.push(op);
                    }
                    None => {
                        attempts.push(SchemaDecodeAttempt {
                            decoder_id: attempt_id,
                            result: SchemaDecodeAttemptResult::Failed,
                            reason: Some("handler decode failed".to_string()),
                        });
                    }
                }
            }
            Err(reason) => {
                attempts.push(SchemaDecodeAttempt {
                    decoder_id: attempt_id,
                    result: SchemaDecodeAttemptResult::Pass,
                    reason: Some(reason),
                });
            }
        }
    }

    if successful.len() == 1 {
        return StructuralFallbackDecodeResult::Applied {
            events: vec![DecodedEvent::SetAttr(successful.remove(0))],
            quality: SchemaDecodeAttemptResult::Partial,
        };
    }

    if successful.len() > 1 {
        let reason = format!(
            "structural fallback ambiguous: attr={attr_name} kind=0x{kind:02X} candidates={}",
            matched_handlers.join(",")
        );
        return StructuralFallbackDecodeResult::Rejected { reason, attempts };
    }

    if !matched_handlers.is_empty() {
        return StructuralFallbackDecodeResult::Rejected {
            reason: format!(
                "structural fallback decode failed: attr={attr_name} kind=0x{kind:02X}"
            ),
            attempts,
        };
    }

    StructuralFallbackDecodeResult::NotApplicable
}

fn decode_attr_value_events_schema(
    registry: &schema::SchemaRegistry,
    form: &str,
    tag: &str,
    payload: &[u8],
    chunk_aux: Option<u32>,
    parent_form: Option<&str>,
    parent_tag: Option<&str>,
    trace: ChunkTrace,
) -> Option<(Vec<DecodedEvent>, SchemaDecodeAttemptResult)> {
    let schema = lookup_attr_value_schema(
        registry,
        form,
        tag,
        payload.len(),
        chunk_aux,
        parent_form,
        parent_tag,
    )?;
    let fields = match decode_fields_with_schema(&schema, payload) {
        Ok(fields) => fields,
        Err(err) => {
            return Some((
                vec![make_unknown_event(
                    format!("{} decode failed: {err}", schema.schema_id),
                    payload,
                    trace,
                    "attr_decoder",
                )],
                SchemaDecodeAttemptResult::Failed,
            ));
        }
    };

    let attr_name = field_text(&fields, "attr_name")
        .unwrap_or_default()
        .to_string();
    if attr_name.is_empty() {
        return Some((
            vec![make_unknown_event(
                format!("{} missing attr_name", schema.schema_id),
                payload,
                trace,
                "attr_decoder",
            )],
            SchemaDecodeAttemptResult::Failed,
        ));
    }

    let Some(handler) = resolve_attr_handler(&schema, tag) else {
        return Some((
            vec![make_unknown_event(
                format!("{} missing handler metadata", schema.schema_id),
                payload,
                trace,
                "attr_decoder",
            )],
            SchemaDecodeAttemptResult::Failed,
        ));
    };
    let kind = field_u8(&fields, "kind").unwrap_or(0);
    if let Some(op) = decode_attr_value_from_schema_fields(handler, &attr_name, kind, &fields) {
        return Some((
            vec![DecodedEvent::SetAttr(op)],
            SchemaDecodeAttemptResult::Exact,
        ));
    }

    let mut used_payload_fallback = false;
    let value_raw_owned = if let Some(raw) = field_bytes(&fields, "value_raw") {
        raw.to_vec()
    } else if let Some((_, _, value_raw)) = decode_attr_payload(payload) {
        used_payload_fallback = true;
        value_raw
    } else {
        Vec::new()
    };
    let op = match decode_attr_value_from_handler(handler, &attr_name, kind, &value_raw_owned) {
        Some(op) => op,
        None => {
            return Some((
                vec![make_unknown_event(
                    format!(
                        "{} value decode failed (handler={})",
                        schema.schema_id,
                        handler.as_str(),
                    ),
                    payload,
                    trace,
                    "attr_decoder",
                )],
                SchemaDecodeAttemptResult::Failed,
            ));
        }
    };

    let quality = if used_payload_fallback
        || (handler.as_str() == "attr.matr" && value_raw_owned.len() != 128)
    {
        SchemaDecodeAttemptResult::Partial
    } else {
        SchemaDecodeAttemptResult::Exact
    };
    Some((vec![DecodedEvent::SetAttr(op)], quality))
}

pub(super) fn decode_attr_definition_events(
    registry: &schema::SchemaRegistry,
    payload: &[u8],
    trace: ChunkTrace,
) -> Vec<DecodedEvent> {
    decode_attr_outcome_events(
        decode_attr_definition_chunk_to_outcome_with_registry(registry, payload),
        payload,
        trace,
    )
}

#[cfg(test)]
pub(super) fn decode_attr_value_events(
    tag: &str,
    payload: &[u8],
    trace: ChunkTrace,
) -> Vec<DecodedEvent> {
    if let Some((events, _quality)) = decode_attr_value_events_schema(
        schema::default_schema_registry(),
        "ATTR",
        tag,
        payload,
        None,
        None,
        None,
        trace.clone(),
    ) {
        return events;
    }
    decode_attr_outcome_events(
        decode_attr_value_chunk_to_outcome(tag, payload),
        payload,
        trace,
    )
}

pub(super) fn decode_attr_outcome_events(
    outcome: AttrDecodeOutcome,
    payload: &[u8],
    trace: ChunkTrace,
) -> Vec<DecodedEvent> {
    match outcome {
        AttrDecodeOutcome::AddAttr(op) => vec![DecodedEvent::AddAttr(op)],
        AttrDecodeOutcome::SetAttr(op) => vec![DecodedEvent::SetAttr(op)],
        AttrDecodeOutcome::Unsupported {
            tag,
            attr_name,
            kind,
            payload_size,
        } => vec![make_unsupported_attr_unknown(
            format!("decode failed for {tag} attr={attr_name} kind=0x{kind:02X}"),
            payload_size,
            payload,
            trace,
            "attr_decoder",
        )],
    }
}

fn lookup_attr_value_schema(
    registry: &schema::SchemaRegistry,
    form: &str,
    tag: &str,
    payload_size: usize,
    chunk_aux: Option<u32>,
    parent_form: Option<&str>,
    parent_tag: Option<&str>,
) -> Option<std::sync::Arc<schema::ChunkSchema>> {
    let context = SchemaLookupContext {
        payload_size: Some(payload_size),
        aux: chunk_aux,
        parent_form,
        parent_tag,
    };
    let schema = lookup_chunk_schema_with_context_and_registry(registry, form, tag, context)
        .or_else(|| {
            lookup_chunk_schema_with_context_and_registry(registry, "ATTR", tag, context)
        })?;
    let has_attr_handler = schema
        .handler
        .as_deref()
        .and_then(|handler| attr_value_handler_id_from_schema_handler(handler, tag))
        .is_some();
    if has_attr_handler { Some(schema) } else { None }
}

fn resolve_attr_handler(
    schema: &schema::ChunkSchema,
    tag: &str,
) -> Option<crate::scene::decode::attr::AttrValueHandlerId> {
    schema
        .handler
        .as_deref()
        .and_then(|handler| attr_value_handler_id_from_schema_handler(handler, tag))
}

#[cfg(test)]
mod tests {
    use super::{AttrFamilyDecoder, decode_attr_value_events};
    use crate::scene::{
        decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
        ir::{ChunkTrace, DecodedEvent, SchemaDecodeAttemptResult, SetAttrValue},
    };

    fn trace() -> ChunkTrace {
        ChunkTrace {
            form: "XFRM".to_string(),
            tag: "STR ".to_string(),
            node_offset: 0x10,
            chunk_aux: None,
            child_alignment: Some(8),
            child_header_size: Some(16),
        }
    }

    fn context<'a>(
        form: &'a str,
        tag: &'a str,
        payload: &'a [u8],
        node_offset: usize,
        chunk_aux: Option<u32>,
    ) -> ChunkDecodeContext<'a> {
        ChunkDecodeContext {
            registry: crate::scene::schema::default_schema_registry(),
            form,
            tag,
            payload,
            node_offset,
            chunk_aux,
            child_alignment: Some(8),
            child_header_size: Some(16),
            parent_form: Some(form),
            parent_tag: Some("FOR8"),
        }
    }

    #[test]
    fn schema_attr_str_decodes_to_setattr_string() {
        let payload = b"txt\0\x00hello\0";
        let events = decode_attr_value_events("STR ", payload, trace());
        assert_eq!(events.len(), 1);
        let DecodedEvent::SetAttr(op) = &events[0] else {
            panic!("expected setattr event");
        };
        assert_eq!(op.attr_name_or_path, ".txt");
        assert!(matches!(op.value, SetAttrValue::String(ref v) if v == "hello"));
    }

    #[test]
    fn schema_attr_i32_array_decodes_to_setattr_int32_array() {
        let payload = b"ids\0\x00\x00\x00\x00\x01\xFF\xFF\xFF\xFE";
        let events = decode_attr_value_events("I32#", payload, trace());
        assert_eq!(events.len(), 1);
        let DecodedEvent::SetAttr(op) = &events[0] else {
            panic!("expected setattr event");
        };
        assert_eq!(op.attr_name_or_path, ".ids");
        assert!(matches!(op.value, SetAttrValue::Int32Array(ref v) if v == &vec![1, -2]));
    }

    #[test]
    fn schema_attr_str_array_decodes_to_setattr_string_array() {
        let payload = b"labels\0\x00\x00\x00\x00\x02left\0right\0";
        let events = decode_attr_value_events("STR#", payload, trace());
        assert_eq!(events.len(), 1);
        let DecodedEvent::SetAttr(op) = &events[0] else {
            panic!("expected setattr event");
        };
        assert_eq!(op.attr_name_or_path, ".labels");
        assert!(matches!(
            op.value,
            SetAttrValue::StringArray {
                declared_count: 2,
                ref values
            } if values == &vec!["left".to_string(), "right".to_string()]
        ));
    }

    #[test]
    fn schema_attr_flgs_array_decodes_array_size() {
        let payload = b"arr\0\x08\x00\x00\x00\x03";
        let events = decode_attr_value_events("FLGS", payload, trace());
        assert_eq!(events.len(), 1);
        let DecodedEvent::SetAttr(op) = &events[0] else {
            panic!("expected setattr event");
        };
        assert_eq!(op.attr_name_or_path, ".arr");
        assert_eq!(op.array_size, Some(3));
        assert_eq!(op.keyable, None);
        assert!(matches!(op.value, SetAttrValue::None));
    }

    #[test]
    fn schema_attr_flt3_delegates_numeric_decode() {
        let mut payload = b"v\0\x00".to_vec();
        payload.extend_from_slice(&(1.0f32).to_bits().to_be_bytes());
        payload.extend_from_slice(&(2.5f32).to_bits().to_be_bytes());
        payload.extend_from_slice(&(-3.0f32).to_bits().to_be_bytes());

        let events = decode_attr_value_events("FLT3", &payload, trace());
        assert_eq!(events.len(), 1);
        let DecodedEvent::SetAttr(op) = &events[0] else {
            panic!("expected setattr event");
        };
        assert_eq!(op.attr_name_or_path, ".v");
        assert!(matches!(
            op.value,
            SetAttrValue::TypedNumbers {
                ref value_type,
                ref values
            } if value_type == "float3"
                && values == &vec![
                    crate::scene::ir::NumericValue::from_f64(1.0),
                    crate::scene::ir::NumericValue::from_f64(2.5),
                    crate::scene::ir::NumericValue::from_f64(-3.0),
                ]
        ));
    }

    #[test]
    fn rtft_schema_is_decoded_by_attr_family_decoder() {
        let decoder = AttrFamilyDecoder;
        let payload = b"ftn\0\x00textures/albedo.png\0";

        let DecodeAttempt::HandledWithQuality { events, quality } =
            decoder.decode_attempt(&context("RTFT", "STR ", payload, 0x200, None))
        else {
            panic!("expected handled");
        };
        assert!(matches!(quality, SchemaDecodeAttemptResult::Exact));

        assert_eq!(events.len(), 1);
        let DecodedEvent::SetAttr(op) = &events[0] else {
            panic!("expected setattr event");
        };
        assert_eq!(op.attr_name_or_path, ".ftn");
        assert!(matches!(
            op.value,
            SetAttrValue::String(ref value) if value == "textures/albedo.png"
        ));
    }

    #[test]
    fn non_schema_nrbc_payload_is_decoded_by_structural_fallback() {
        let decoder = AttrFamilyDecoder;
        let mut payload = Vec::new();
        payload.extend_from_slice(b"cc\0");
        payload.push(0x20);
        payload.extend_from_slice(&1u32.to_be_bytes()); // degree
        payload.extend_from_slice(&3u32.to_be_bytes()); // spans
        payload.extend_from_slice(&0u32.to_be_bytes()); // form
        payload.extend_from_slice(&0u32.to_be_bytes()); // is rational
        payload.push(3u8); // dimension
        payload.extend_from_slice(&4u32.to_be_bytes()); // knot count
        for knot in [0.0f64, 1.0, 2.0, 3.0] {
            payload.extend_from_slice(&knot.to_be_bytes());
        }
        payload.extend_from_slice(&4u32.to_be_bytes()); // cv count
        let cvs = [
            [0.0f64, 0.0, 0.0],
            [2.0f64, 0.0, 0.0],
            [2.0f64, 1.5, 0.0],
            [0.0f64, 1.5, 0.0],
        ];
        for cv in cvs {
            for value in cv {
                payload.extend_from_slice(&value.to_be_bytes());
            }
        }

        let DecodeAttempt::HandledWithQuality { events, quality } =
            decoder.decode_attempt(&context("NCRV", "NRBC", &payload, 0x300, Some(0x2002_0000)))
        else {
            panic!("expected handled");
        };
        assert!(matches!(quality, SchemaDecodeAttemptResult::Partial));
        assert_eq!(events.len(), 1);
        let DecodedEvent::SetAttr(op) = &events[0] else {
            panic!("expected setattr event");
        };
        assert_eq!(op.attr_name_or_path, ".cc");
        let SetAttrValue::NurbsCurve { degree, spans, .. } = &op.value else {
            panic!("expected nurbs curve value");
        };
        assert_eq!(*degree, 1);
        assert_eq!(*spans, 3);
    }

    #[test]
    fn structural_fallback_rule_match_with_invalid_shape_returns_unknown() {
        let decoder = AttrFamilyDecoder;
        let mut payload = Vec::new();
        payload.extend_from_slice(b"cc\0");
        payload.push(0x20);
        payload.extend_from_slice(&1u32.to_be_bytes()); // degree
        payload.extend_from_slice(&1u32.to_be_bytes()); // spans
        payload.extend_from_slice(&0u32.to_be_bytes()); // form
        payload.extend_from_slice(&0u32.to_be_bytes()); // non-rational
        payload.push(0u8); // dimension (shape-invalid)
        payload.extend_from_slice(&0u32.to_be_bytes()); // knot count (shape-invalid)
        payload.extend_from_slice(&0u32.to_be_bytes()); // cv count

        let DecodeAttempt::HandledWithQuality { events, quality } =
            decoder.decode_attempt(&context("NCRV", "NRBC", &payload, 0x380, Some(0x2002_0000)))
        else {
            panic!("expected handled");
        };
        assert!(matches!(quality, SchemaDecodeAttemptResult::Failed));
        assert_eq!(events.len(), 1);
        let DecodedEvent::Unknown(unknown) = &events[0] else {
            panic!("expected unknown event");
        };
        assert!(unknown.reason.contains("structural fallback decode failed"));
        assert!(
            unknown
                .decoder_attempts
                .iter()
                .any(|attempt| attempt.decoder_id == "attr_fallback.attr.nurbs_curve")
        );
    }

    #[test]
    fn non_schema_non_matching_attr_payload_passes_decoder() {
        let decoder = AttrFamilyDecoder;
        let payload = b"foo\0\x00\x01\x02\x03";
        let attempt = decoder.decode_attempt(&context("ABCD", "WXYZ", payload, 0x400, None));
        assert!(matches!(attempt, DecodeAttempt::Pass { .. }));
    }
}
