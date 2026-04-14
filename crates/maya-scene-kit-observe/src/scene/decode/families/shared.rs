use std::fmt::Write as _;

use crate::scene::ir::{
    ChunkTrace, DecodedEvent, SchemaDecodeAttempt, SchemaDecodeAttemptResult, UnknownEvent,
};

fn payload_digest_hex(payload: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in payload {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn payload_preview_hex(payload: &[u8], max_len: usize) -> String {
    let mut out = String::with_capacity(max_len.saturating_mul(2));
    for byte in payload.iter().take(max_len) {
        write!(&mut out, "{byte:02x}").expect("write hex");
    }
    out
}

fn payload_inline_hex(payload: &[u8], max_len: usize) -> Option<String> {
    if payload.len() > max_len {
        return None;
    }
    let mut out = String::with_capacity(payload.len() * 2);
    for byte in payload {
        write!(&mut out, "{byte:02x}").expect("write hex");
    }
    Some(out)
}

pub(crate) fn make_unknown_event(
    reason: impl Into<String>,
    payload: &[u8],
    trace: ChunkTrace,
    decoder_id: &str,
) -> DecodedEvent {
    let reason = reason.into();
    make_unknown_event_with_attempts(
        reason.clone(),
        payload,
        trace,
        vec![SchemaDecodeAttempt {
            decoder_id: decoder_id.to_string(),
            result: SchemaDecodeAttemptResult::Failed,
            reason: Some(reason),
        }],
    )
}

pub(crate) fn make_unknown_event_with_attempts(
    reason: impl Into<String>,
    payload: &[u8],
    trace: ChunkTrace,
    decoder_attempts: Vec<SchemaDecodeAttempt>,
) -> DecodedEvent {
    DecodedEvent::Unknown(UnknownEvent {
        reason: reason.into(),
        payload_size: payload.len(),
        payload_digest_hex: payload_digest_hex(payload),
        payload_preview_hex: payload_preview_hex(payload, 64),
        payload_inline_hex: payload_inline_hex(payload, 256),
        decoder_attempts,
        trace,
    })
}

pub(crate) fn make_unsupported_attr_unknown(
    reason: String,
    payload_size: usize,
    payload: &[u8],
    trace: ChunkTrace,
    decoder_id: &str,
) -> DecodedEvent {
    DecodedEvent::Unknown(UnknownEvent {
        reason,
        payload_size,
        payload_digest_hex: payload_digest_hex(payload),
        payload_preview_hex: payload_preview_hex(payload, 64),
        payload_inline_hex: payload_inline_hex(payload, 256),
        decoder_attempts: vec![SchemaDecodeAttempt {
            decoder_id: decoder_id.to_string(),
            result: SchemaDecodeAttemptResult::Failed,
            reason: Some("unsupported attr decode".to_string()),
        }],
        trace,
    })
}
