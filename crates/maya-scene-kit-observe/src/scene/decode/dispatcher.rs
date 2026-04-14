use std::sync::Arc;

use super::families::{
    AttrFamilyDecoder, ConsFamilyDecoder, CreaFamilyDecoder, MeshPayloadDecoder, RefeFamilyDecoder,
    ReferenceFamilyDecoder, ScriptFamilyDecoder, SlctFamilyDecoder,
    make_unknown_event_with_attempts,
};
use crate::scene::{
    ir::{ChunkTrace, DecodedEvent, SchemaDecodeAttempt, SchemaDecodeAttemptResult},
    schema::{SchemaLookupContext, SchemaRegistry, lookup_chunk_schema_with_context_and_registry},
};

pub(crate) enum DecodeAttempt {
    Handled(Vec<DecodedEvent>),
    HandledWithQuality {
        events: Vec<DecodedEvent>,
        quality: SchemaDecodeAttemptResult,
    },
    Pass {
        reason: &'static str,
    },
}

pub(crate) struct DecodeDispatchResult {
    pub(crate) events: Vec<DecodedEvent>,
    pub(crate) quality: SchemaDecodeAttemptResult,
}

#[derive(Clone, Copy)]
pub(crate) struct ChunkDecodeContext<'a> {
    pub(in crate::scene) registry: &'a SchemaRegistry,
    pub(crate) form: &'a str,
    pub(crate) tag: &'a str,
    pub(crate) payload: &'a [u8],
    pub(crate) node_offset: usize,
    pub(crate) chunk_aux: Option<u32>,
    pub(crate) child_alignment: Option<usize>,
    pub(crate) child_header_size: Option<usize>,
    pub(crate) parent_form: Option<&'a str>,
    pub(crate) parent_tag: Option<&'a str>,
}

impl ChunkDecodeContext<'_> {
    pub(crate) fn trace(&self) -> ChunkTrace {
        ChunkTrace {
            form: self.form.to_string(),
            tag: self.tag.to_string(),
            node_offset: self.node_offset,
            chunk_aux: self.chunk_aux,
            child_alignment: self.child_alignment,
            child_header_size: self.child_header_size,
        }
    }
}

pub(crate) trait ChunkDecoder {
    fn decoder_id(&self) -> &'static str;

    fn handles_handler(&self, _handler: &str) -> bool {
        false
    }

    fn decode_attempt(&self, context: &ChunkDecodeContext<'_>) -> DecodeAttempt;
}

pub(crate) struct DecoderDispatcher {
    registry: Arc<SchemaRegistry>,
    decoders: Vec<Box<dyn ChunkDecoder>>,
}

impl DecoderDispatcher {
    pub(in crate::scene) fn new(registry: Arc<SchemaRegistry>) -> Self {
        Self {
            registry,
            decoders: vec![
                Box::new(CreaFamilyDecoder),
                Box::new(ScriptFamilyDecoder),
                Box::new(RefeFamilyDecoder),
                Box::new(ReferenceFamilyDecoder),
                Box::new(AttrFamilyDecoder),
                Box::new(MeshPayloadDecoder),
                Box::new(ConsFamilyDecoder),
                Box::new(SlctFamilyDecoder),
            ],
        }
    }

    #[cfg(test)]
    fn with_decoders(decoders: Vec<Box<dyn ChunkDecoder>>) -> Self {
        Self {
            registry: Arc::new(SchemaRegistry::new(
                crate::scene::schema::locator::SchemaPaths::from_defaults(),
            )),
            decoders,
        }
    }

    pub(crate) fn decode_with_quality(
        &self,
        form: &str,
        tag: &str,
        payload: &[u8],
        node_offset: usize,
        chunk_aux: Option<u32>,
        child_alignment: Option<usize>,
        child_header_size: Option<usize>,
        parent_form: Option<&str>,
        parent_tag: Option<&str>,
    ) -> DecodeDispatchResult {
        let context = ChunkDecodeContext {
            registry: self.registry.as_ref(),
            form,
            tag,
            payload,
            node_offset,
            chunk_aux,
            child_alignment,
            child_header_size,
            parent_form,
            parent_tag,
        };
        self.decode_with_context(context)
    }

    fn decode_with_context(&self, context: ChunkDecodeContext<'_>) -> DecodeDispatchResult {
        let mut attempted = Vec::new();
        let mut routed_decoder_idx: Option<usize> = None;
        let schema_context = SchemaLookupContext {
            payload_size: Some(context.payload.len()),
            aux: context.chunk_aux,
            parent_form: context.parent_form,
            parent_tag: context.parent_tag,
        };

        if let Some(schema) = lookup_chunk_schema_with_context_and_registry(
            context.registry,
            context.form,
            context.tag,
            schema_context,
        ) {
            if let Some(handler) = schema.handler.as_deref() {
                let mut candidates = self
                    .decoders
                    .iter()
                    .enumerate()
                    .filter(|(_, decoder)| decoder.handles_handler(handler))
                    .map(|(idx, _)| idx)
                    .collect::<Vec<_>>();
                if !candidates.is_empty() {
                    candidates.sort_by_key(|idx| self.decoders[*idx].decoder_id());
                    let selected = candidates[0];
                    routed_decoder_idx = Some(selected);
                    let selected_id = self.decoders[selected].decoder_id().to_string();
                    let resolution_reason = if candidates.len() > 1 {
                        format!(
                            "dispatch via schema handler '{handler}' (multi-match={}, selected={selected_id})",
                            candidates.len()
                        )
                    } else {
                        format!("dispatch via schema handler '{handler}' (selected={selected_id})")
                    };
                    match self.decoders[selected].decode_attempt(&context) {
                        DecodeAttempt::Handled(events) => {
                            return DecodeDispatchResult {
                                events,
                                quality: SchemaDecodeAttemptResult::Exact,
                            };
                        }
                        DecodeAttempt::HandledWithQuality { events, quality } => {
                            return DecodeDispatchResult { events, quality };
                        }
                        DecodeAttempt::Pass { reason } => {
                            attempted.push(SchemaDecodeAttempt {
                                decoder_id: selected_id,
                                result: SchemaDecodeAttemptResult::Pass,
                                reason: Some(format!(
                                    "{resolution_reason}; decoder pass: {reason}"
                                )),
                            });
                        }
                    }
                } else {
                    attempted.push(SchemaDecodeAttempt {
                        decoder_id: "dispatcher".to_string(),
                        result: SchemaDecodeAttemptResult::Pass,
                        reason: Some(format!(
                            "schema handler '{handler}' has no registered decoder"
                        )),
                    });
                }
            } else {
                attempted.push(SchemaDecodeAttempt {
                    decoder_id: "dispatcher".to_string(),
                    result: SchemaDecodeAttemptResult::Pass,
                    reason: Some("schema matched but handler is missing".to_string()),
                });
            }
        } else {
            attempted.push(SchemaDecodeAttempt {
                decoder_id: "dispatcher".to_string(),
                result: SchemaDecodeAttemptResult::Pass,
                reason: Some("no schema matched dispatch context".to_string()),
            });
        }

        for (idx, decoder) in self.decoders.iter().enumerate() {
            if routed_decoder_idx == Some(idx) {
                continue;
            }
            match decoder.decode_attempt(&context) {
                DecodeAttempt::Handled(events) => {
                    return DecodeDispatchResult {
                        events,
                        quality: SchemaDecodeAttemptResult::Exact,
                    };
                }
                DecodeAttempt::HandledWithQuality { events, quality } => {
                    return DecodeDispatchResult { events, quality };
                }
                DecodeAttempt::Pass { reason } => {
                    attempted.push(SchemaDecodeAttempt {
                        decoder_id: decoder.decoder_id().to_string(),
                        result: SchemaDecodeAttemptResult::Pass,
                        reason: Some(format!("fallback dispatch: {reason}")),
                    });
                }
            };
        }

        let unresolved_reason = if routed_decoder_idx.is_some() {
            "schema-driven decoder and fallback decoders did not handle chunk"
        } else {
            "no decoder registered for chunk tag"
        };
        DecodeDispatchResult {
            events: vec![make_unknown_event_with_attempts(
                unresolved_reason,
                context.payload,
                context.trace(),
                attempted,
            )],
            quality: SchemaDecodeAttemptResult::Failed,
        }
    }

    #[cfg(test)]
    pub(crate) fn decode(
        &self,
        form: &str,
        tag: &str,
        payload: &[u8],
        node_offset: usize,
        chunk_aux: Option<u32>,
        child_alignment: Option<usize>,
        child_header_size: Option<usize>,
        parent_form: Option<&str>,
        parent_tag: Option<&str>,
    ) -> Vec<DecodedEvent> {
        let result = self.decode_with_quality(
            form,
            tag,
            payload,
            node_offset,
            chunk_aux,
            child_alignment,
            child_header_size,
            parent_form,
            parent_tag,
        );
        let _ = result.quality;
        result.events
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt, DecoderDispatcher};
    use crate::scene::ir::{DecodedEvent, SchemaDecodeAttemptResult};

    fn dispatcher_for_tests() -> DecoderDispatcher {
        DecoderDispatcher::new(Arc::new(crate::scene::schema::SchemaRegistry::new(
            crate::scene::schema::locator::SchemaPaths::from_defaults(),
        )))
    }

    struct GreedyFallbackDecoder;

    impl ChunkDecoder for GreedyFallbackDecoder {
        fn decoder_id(&self) -> &'static str {
            "greedy_fallback"
        }

        fn decode_attempt(&self, _context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
            DecodeAttempt::Handled(vec![DecodedEvent::SelectTarget {
                target: "greedy".to_string(),
            }])
        }
    }

    struct SchemaBoundDecoder {
        id: &'static str,
        target: &'static str,
    }

    impl ChunkDecoder for SchemaBoundDecoder {
        fn decoder_id(&self) -> &'static str {
            self.id
        }

        fn handles_handler(&self, handler: &str) -> bool {
            handler == "slct.target"
        }

        fn decode_attempt(&self, _context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
            DecodeAttempt::Handled(vec![DecodedEvent::SelectTarget {
                target: self.target.to_string(),
            }])
        }
    }

    #[test]
    fn unknown_chunk_records_decoder_pass_attempts() {
        let dispatcher = dispatcher_for_tests();
        let events = dispatcher.decode(
            "XXXX",
            "ZZZZ",
            b"\x01\x02",
            0x1234,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(events.len(), 1);

        let unknown = match &events[0] {
            DecodedEvent::Unknown(unknown) => unknown,
            other => panic!("expected unknown event, got {other:?}"),
        };

        assert!(!unknown.decoder_attempts.is_empty());
        assert!(
            unknown
                .decoder_attempts
                .iter()
                .all(|attempt| matches!(attempt.result, SchemaDecodeAttemptResult::Pass))
        );
    }

    #[test]
    fn unknown_chunk_reports_failed_dispatch_quality() {
        let dispatcher = dispatcher_for_tests();
        let result = dispatcher.decode_with_quality(
            "XXXX",
            "ZZZZ",
            b"\x01\x02",
            0x1234,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(matches!(result.quality, SchemaDecodeAttemptResult::Failed));
        assert_eq!(result.events.len(), 1);
    }

    #[test]
    fn schema_handler_dispatch_is_order_independent_against_fallback_decoders() {
        let dispatcher_a = DecoderDispatcher::with_decoders(vec![
            Box::new(GreedyFallbackDecoder),
            Box::new(SchemaBoundDecoder {
                id: "schema_decoder",
                target: ":schema",
            }),
        ]);
        let dispatcher_b = DecoderDispatcher::with_decoders(vec![
            Box::new(SchemaBoundDecoder {
                id: "schema_decoder",
                target: ":schema",
            }),
            Box::new(GreedyFallbackDecoder),
        ]);

        let events_a = dispatcher_a.decode(
            "SLCT",
            "SLCT",
            b":time1\0",
            0x40,
            None,
            Some(8),
            Some(16),
            Some("SLCT"),
            Some("FOR8"),
        );
        let events_b = dispatcher_b.decode(
            "SLCT",
            "SLCT",
            b":time1\0",
            0x40,
            None,
            Some(8),
            Some(16),
            Some("SLCT"),
            Some("FOR8"),
        );

        let target_a = match &events_a[0] {
            DecodedEvent::SelectTarget { target } => target.as_str(),
            other => panic!("unexpected event: {other:?}"),
        };
        let target_b = match &events_b[0] {
            DecodedEvent::SelectTarget { target } => target.as_str(),
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(target_a, ":schema");
        assert_eq!(target_b, ":schema");
    }

    #[test]
    fn schema_handler_overlap_uses_deterministic_decoder_id_order() {
        let dispatcher = DecoderDispatcher::with_decoders(vec![
            Box::new(SchemaBoundDecoder {
                id: "zzz_decoder",
                target: ":z",
            }),
            Box::new(SchemaBoundDecoder {
                id: "aaa_decoder",
                target: ":a",
            }),
        ]);

        let events = dispatcher.decode(
            "SLCT",
            "SLCT",
            b":time1\0",
            0x88,
            None,
            Some(8),
            Some(16),
            Some("SLCT"),
            Some("FOR8"),
        );
        let target = match &events[0] {
            DecodedEvent::SelectTarget { target } => target.as_str(),
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(target, ":a");
    }
}
