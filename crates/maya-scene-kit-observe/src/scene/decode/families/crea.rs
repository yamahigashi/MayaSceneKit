use super::super::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt};
use crate::{
    mb::decode_best_effort_script_text,
    scene::{
        decode::attr::decode_attr_payload,
        ir::{CreateNodeFlags, DecodedEvent, FlagState},
    },
};

#[derive(Debug, Clone, Default)]
pub(crate) struct CreaDecoded {
    pub(crate) name: Option<String>,
    pub(crate) parent: Option<String>,
    pub(crate) uid: Option<String>,
    pub(crate) create_flags: CreateNodeFlags,
    pub(crate) source: CreaDecodeSource,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum CreaDecodeSource {
    CstringFields,
    LenPrefixedFields,
    #[default]
    Missing,
}

pub(crate) struct CreaFamilyDecoder;
pub(crate) struct ScriptFamilyDecoder;

impl ChunkDecoder for CreaFamilyDecoder {
    fn decoder_id(&self) -> &'static str {
        "crea.family"
    }

    fn decode_attempt(&self, context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
        if context.tag != "CREA" {
            return DecodeAttempt::Pass {
                reason: "not a CREA chunk",
            };
        }
        let decoded = decode_crea_payload(context.payload);
        let quality = match decoded.source {
            CreaDecodeSource::CstringFields => crate::scene::ir::SchemaDecodeAttemptResult::Exact,
            CreaDecodeSource::LenPrefixedFields => {
                crate::scene::ir::SchemaDecodeAttemptResult::Partial
            }
            CreaDecodeSource::Missing => crate::scene::ir::SchemaDecodeAttemptResult::Failed,
        };
        DecodeAttempt::HandledWithQuality {
            events: vec![DecodedEvent::CreateNode {
                name: decoded.name,
                parent: decoded.parent,
                uid: decoded.uid,
                create_flags: decoded.create_flags,
                used_len_prefixed_fields: decoded.source == CreaDecodeSource::LenPrefixedFields,
            }],
            quality,
        }
    }
}

impl ChunkDecoder for ScriptFamilyDecoder {
    fn decoder_id(&self) -> &'static str {
        "scrp.family"
    }

    fn decode_attempt(&self, context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
        if context.form != "SCRP" || context.tag != "STR " {
            return DecodeAttempt::Pass {
                reason: "not a SCRP/STR script body chunk",
            };
        }
        let Some((attr_name, _, value)) = decode_attr_payload(context.payload) else {
            return DecodeAttempt::Pass {
                reason: "payload did not decode as ATTR triplet",
            };
        };
        if attr_name != "b" {
            return DecodeAttempt::Pass {
                reason: "SCRP string chunk is not the body attribute",
            };
        }
        DecodeAttempt::Handled(vec![DecodedEvent::ScriptBody {
            body: decode_best_effort_script_text(&value),
        }])
    }
}

pub(crate) fn decode_crea_payload(payload: &[u8]) -> CreaDecoded {
    let direct = decode_crea_body(payload, None);
    let Some((body, uid)) = split_crea_body_and_uid(payload) else {
        return direct;
    };
    let split = decode_crea_body(body, uid);

    if split.source == CreaDecodeSource::Missing {
        return direct;
    }
    if direct.source == CreaDecodeSource::Missing {
        return split;
    }
    if split.name == direct.name && split.parent == direct.parent {
        return split;
    }

    direct
}

fn decode_crea_body(body: &[u8], uid: Option<String>) -> CreaDecoded {
    let mut out = CreaDecoded {
        name: None,
        parent: None,
        uid,
        create_flags: CreateNodeFlags::default(),
        source: CreaDecodeSource::Missing,
    };

    if let Some((name, parent)) = decode_crea_len_prefixed_fields(body) {
        out.name = Some(name);
        out.parent = parent;
        out.create_flags = decode_create_node_flags_from_len_prefixed(body);
        out.source = CreaDecodeSource::LenPrefixedFields;
        return out;
    }

    if let Some((name, parent, name_start)) = decode_crea_cstring_fields(body) {
        out.name = Some(name);
        out.parent = parent;
        out.create_flags = decode_create_node_flags_from_cstring(body, name_start);
        out.source = CreaDecodeSource::CstringFields;
        return out;
    }

    out
}

fn split_crea_body_and_uid(payload: &[u8]) -> Option<(&[u8], Option<String>)> {
    if payload.len() < 16 {
        return None;
    }
    let uid = decode_uid_from_crea(payload);
    Some((&payload[..payload.len() - 16], uid))
}

fn decode_crea_cstring_fields(body: &[u8]) -> Option<(String, Option<String>, usize)> {
    let mut starts = vec![0usize];
    let header_len = detect_crea_cstring_header_len(body);
    if header_len > 0 {
        starts.push(header_len);
    }

    for start in starts {
        let Some((name, next)) = read_cstring_field(body, start) else {
            continue;
        };
        let parent = read_cstring_field(body, next).map(|(p, _)| p);
        return Some((name, parent, start));
    }
    None
}

fn decode_crea_len_prefixed_fields(body: &[u8]) -> Option<(String, Option<String>)> {
    for mode in [LenMode::U16Be, LenMode::U32Be] {
        if let Some((name, parent)) = scan_len_prefixed_from(body, 0, mode) {
            return Some((name, parent));
        }
    }
    None
}

#[derive(Clone, Copy)]
enum LenMode {
    U16Be,
    U32Be,
}

fn scan_len_prefixed_from(
    body: &[u8],
    start: usize,
    mode: LenMode,
) -> Option<(String, Option<String>)> {
    let width = match mode {
        LenMode::U16Be => 2usize,
        LenMode::U32Be => 4usize,
    };
    if start + width > body.len() {
        return None;
    }

    let read_len = |buf: &[u8], pos: usize| -> Option<usize> {
        Some(match mode {
            LenMode::U16Be => u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize,
            LenMode::U32Be => {
                u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize
            }
        })
    };

    let len1 = read_len(body, start)?;
    if len1 == 0 {
        return None;
    }
    let s1 = start + width;
    let e1 = s1.checked_add(len1)?;
    if e1 > body.len() {
        return None;
    }
    let name = String::from_utf8_lossy(&body[s1..e1]).to_string();

    if e1 + width > body.len() {
        return Some((name, None));
    }

    let len2 = read_len(body, e1)?;
    if len2 == 0 {
        return Some((name, None));
    }
    let s2 = e1 + width;
    let e2 = s2.checked_add(len2)?;
    if e2 > body.len() {
        return Some((name, None));
    }
    let parent = String::from_utf8_lossy(&body[s2..e2]).to_string();
    Some((name, Some(parent)))
}

fn read_cstring_field(body: &[u8], mut start: usize) -> Option<(String, usize)> {
    while start < body.len() && body[start] == 0 {
        start += 1;
    }
    if start >= body.len() {
        return None;
    }
    let rel_end = body[start..].iter().position(|b| *b == 0)?;
    let end = start + rel_end;
    if end == start {
        return None;
    }
    if !body[start..end]
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ')
    {
        return None;
    }
    let field = String::from_utf8_lossy(&body[start..end]).to_string();
    Some((field, end + 1))
}

fn detect_crea_cstring_header_len(body: &[u8]) -> usize {
    let mut n = 0usize;
    while n < body.len() && n < 4 {
        let b = body[n];
        if b.is_ascii_graphic() || b == b' ' {
            break;
        }
        n += 1;
    }
    n
}

fn decode_uid_from_crea(payload: &[u8]) -> Option<String> {
    if payload.len() < 16 {
        return None;
    }
    let raw = &payload[payload.len() - 16..];
    if raw.iter().all(|b| *b == 0) {
        return None;
    }

    let mut ordered = Vec::with_capacity(16);
    for i in [0usize, 4, 8, 12] {
        let mut part = raw[i..i + 4].to_vec();
        part.reverse();
        ordered.extend_from_slice(&part);
    }
    let mut hexed = String::with_capacity(ordered.len() * 2);
    for byte in ordered {
        write!(&mut hexed, "{byte:02X}").expect("write hex");
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hexed[0..8],
        &hexed[8..12],
        &hexed[12..16],
        &hexed[16..20],
        &hexed[20..32]
    ))
}

fn decode_create_node_flags_from_cstring(body: &[u8], name_start: usize) -> CreateNodeFlags {
    let prefix_len = name_start.min(body.len());
    let raw_header_prefix = body[..prefix_len].to_vec();
    let raw_flag_byte = raw_header_prefix.first().copied();
    let shared = raw_flag_byte
        .map(|byte| FlagState::from_bool((byte & 0x01) != 0))
        .unwrap_or(FlagState::Unknown);

    CreateNodeFlags {
        shared,
        skip_select: FlagState::Unknown,
        raw_header_prefix,
        raw_flag_byte,
    }
}

fn decode_create_node_flags_from_len_prefixed(_body: &[u8]) -> CreateNodeFlags {
    CreateNodeFlags::default()
}
use std::fmt::Write as _;

#[cfg(test)]
mod tests {
    use super::{CreaDecodeSource, decode_crea_payload};

    #[test]
    fn decode_crea_payload_preserves_cstring_name_without_uid_suffix() {
        let payload = b"\0uiConfigurationScriptNode\0";

        let decoded = decode_crea_payload(payload);

        assert_eq!(decoded.name.as_deref(), Some("uiConfigurationScriptNode"));
        assert_eq!(decoded.parent, None);
        assert_eq!(decoded.uid, None);
        assert_eq!(decoded.source, CreaDecodeSource::CstringFields);
    }

    #[test]
    fn decode_crea_payload_preserves_cstring_name_with_trailing_uid() {
        let mut payload = b"\0sceneConfigurationScriptNode\0".to_vec();
        payload.extend(1u8..=16u8);

        let decoded = decode_crea_payload(&payload);

        assert_eq!(
            decoded.name.as_deref(),
            Some("sceneConfigurationScriptNode")
        );
        assert_eq!(decoded.parent, None);
        assert_eq!(
            decoded.uid.as_deref(),
            Some("04030201-0807-0605-0C0B-0A09100F0E0D")
        );
        assert_eq!(decoded.source, CreaDecodeSource::CstringFields);
    }
}
