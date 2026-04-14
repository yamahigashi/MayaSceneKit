use crate::scene::{
    decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
    ir::{DecodedEvent, NumericValue, SchemaDecodeAttemptResult, SetAttrOp, SetAttrValue},
};

const VERTICES_PER_CHUNK: usize = 166;
const EDGES_PER_CHUNK: usize = 166;
const FACES_PER_CHUNK: usize = 500;
const NORMALS_PER_CHUNK: usize = 166;
const SENTINEL_POSITIVE_1E20_BITS: u32 = 0x60AD78EC;
const SENTINEL_NEGATIVE_1E20_BITS: u32 = 0xE0AD78EC;

pub(crate) struct MeshPayloadDecoder;

impl ChunkDecoder for MeshPayloadDecoder {
    fn decoder_id(&self) -> &'static str {
        "mesh_payload_decoder"
    }

    fn decode_attempt(&self, context: &ChunkDecodeContext<'_>) -> DecodeAttempt {
        if context.tag != "MESH" {
            return DecodeAttempt::Pass {
                reason: "tag not mesh payload",
            };
        }
        let Some(parsed) = parse_indexed_mesh_payload(context.payload) else {
            return DecodeAttempt::Pass {
                reason: "payload not indexed mesh layout",
            };
        };
        let events = build_mesh_setattr_events(parsed);
        DecodeAttempt::HandledWithQuality {
            events,
            quality: SchemaDecodeAttemptResult::Exact,
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedMeshPayload {
    uv_set_index: usize,
    positions: Vec<f32>,
    normal_bits: Vec<u32>,
    edges: Vec<(u32, u32)>,
    face_edges: Vec<Vec<i32>>,
    face_uvs: Vec<Vec<u32>>,
    total_face_entries: usize,
}

fn parse_indexed_mesh_payload(payload: &[u8]) -> Option<ParsedMeshPayload> {
    let nul = payload.iter().position(|b| *b == 0)?;
    if nul == 0 || nul + 2 > payload.len() {
        return None;
    }
    let _attr_name = std::str::from_utf8(&payload[..nul]).ok()?;
    let kind = payload[nul + 1];
    if kind != 0x20 {
        return None;
    }

    let mut cursor = nul + 2;

    let position_value_count = read_u32_be(payload, &mut cursor)? as usize;
    if position_value_count == 0 || position_value_count % 3 != 0 {
        return None;
    }
    let positions = read_f32_be_vec(payload, &mut cursor, position_value_count)?;

    let edge_value_count = read_u32_be(payload, &mut cursor)? as usize;
    if edge_value_count == 0 || edge_value_count % 2 != 0 {
        return None;
    }
    let edge_values = read_u32_be_vec(payload, &mut cursor, edge_value_count)?;

    let face_entry_count = read_u32_be(payload, &mut cursor)? as usize;
    if face_entry_count == 0 {
        return None;
    }
    let face_edge_words = read_u32_be_vec(payload, &mut cursor, face_entry_count)?;
    let (normal_bits, uv_cursor) = parse_optional_normal_block(payload, cursor, face_entry_count)
        .unwrap_or_else(|| (Vec::new(), cursor));
    let (uv_set_index, face_uv_values) = if uv_cursor == cursor {
        parse_face_uv_values(payload, uv_cursor, face_entry_count)?
    } else {
        parse_face_uv_values(payload, uv_cursor, face_entry_count)
            .or_else(|| parse_face_uv_values(payload, cursor, face_entry_count))?
    };

    let edges = edge_values
        .chunks_exact(2)
        .map(|pair| (pair[0], pair[1]))
        .collect::<Vec<_>>();

    let mut decoded_face_edges_flat = Vec::with_capacity(face_edge_words.len());
    let mut face_lengths = Vec::new();
    let mut current_face_len = 0usize;

    for word in face_edge_words {
        let flag = (word >> 24) as u8;
        let edge_id = word & 0x00FF_FFFF;
        if edge_id as usize >= edges.len() {
            return None;
        }

        let decoded_edge = match flag {
            0x00 | 0x60 => edge_id as i32,
            0x80 | 0xE0 => -((edge_id as i32) + 1),
            _ => return None,
        };
        decoded_face_edges_flat.push(decoded_edge);
        current_face_len += 1;

        if matches!(flag, 0x60 | 0xE0) {
            if current_face_len < 3 {
                return None;
            }
            face_lengths.push(current_face_len);
            current_face_len = 0;
        }
    }
    if current_face_len != 0 || face_lengths.is_empty() {
        return None;
    }

    let mut face_edges = Vec::with_capacity(face_lengths.len());
    let mut face_uvs = Vec::with_capacity(face_lengths.len());
    let mut offset = 0usize;
    for face_len in face_lengths {
        let next = offset + face_len;
        if next > decoded_face_edges_flat.len() || next > face_uv_values.len() {
            return None;
        }
        face_edges.push(decoded_face_edges_flat[offset..next].to_vec());
        face_uvs.push(face_uv_values[offset..next].to_vec());
        offset = next;
    }
    if offset != decoded_face_edges_flat.len() || offset != face_uv_values.len() {
        return None;
    }

    Some(ParsedMeshPayload {
        uv_set_index,
        positions,
        normal_bits,
        edges,
        face_edges,
        face_uvs,
        total_face_entries: offset,
    })
}

fn parse_optional_normal_block(
    payload: &[u8],
    cursor: usize,
    face_entry_count: usize,
) -> Option<(Vec<u32>, usize)> {
    let mut probe = cursor;
    let normal_value_count = read_u32_be(payload, &mut probe)? as usize;
    if normal_value_count == 0 || normal_value_count % 3 != 0 {
        return None;
    }
    let normal_bits = read_u32_be_vec(payload, &mut probe, normal_value_count)?;

    // Optional trailer observed in large mesh payloads.
    let trailer_0 = read_u32_be(payload, &mut probe)?;
    let _trailer_1 = read_u32_be(payload, &mut probe)?;
    let trailer_2 = read_u32_be(payload, &mut probe)?;
    if trailer_0 != 0 || trailer_2 != 0 {
        return None;
    }

    // Only accept when uv parsing can continue from this new cursor.
    parse_face_uv_values(payload, probe, face_entry_count)?;
    Some((normal_bits, probe))
}

fn parse_face_uv_values(
    payload: &[u8],
    cursor: usize,
    face_entry_count: usize,
) -> Option<(usize, Vec<u32>)> {
    parse_face_uv_values_direct(payload, cursor, face_entry_count)
        .or_else(|| scan_face_uv_values_by_name(payload, cursor, face_entry_count))
}

fn parse_face_uv_values_direct(
    payload: &[u8],
    cursor: usize,
    face_entry_count: usize,
) -> Option<(usize, Vec<u32>)> {
    let mut cursor = cursor;
    let _uv_header = read_u32_be(payload, &mut cursor)?;
    let uv_set_count = read_u32_be(payload, &mut cursor)? as usize;
    if uv_set_count == 0 || uv_set_count > 16 {
        return None;
    }

    for _ in 0..uv_set_count {
        let set_index = read_u32_be(payload, &mut cursor)? as usize;
        let _set_name = read_cstring(payload, &mut cursor)?;
        let uv_value_count = read_u32_be(payload, &mut cursor)? as usize;
        if uv_value_count == 0 || uv_value_count % 2 != 0 {
            return None;
        }
        let _uv_values = read_f32_be_vec(payload, &mut cursor, uv_value_count)?;

        // In variant payloads, per-set face-uv indices may start right after uv values.
        let saved = cursor;
        let face_uv_count = read_u32_be(payload, &mut cursor)? as usize;
        if face_uv_count == face_entry_count {
            let face_uv_values = read_u32_be_vec(payload, &mut cursor, face_uv_count)?;
            return Some((set_index, face_uv_values));
        }
        cursor = saved;
    }

    None
}

fn scan_face_uv_values_by_name(
    payload: &[u8],
    start: usize,
    face_entry_count: usize,
) -> Option<(usize, Vec<u32>)> {
    let mut pos = start;
    while pos + 10 <= payload.len() {
        if !is_name_char(payload[pos]) {
            pos += 1;
            continue;
        }

        let mut end = pos;
        while end < payload.len() && end - pos <= 32 && is_name_char(payload[end]) {
            end += 1;
        }
        if end <= pos || end >= payload.len() || payload[end] != 0 {
            pos += 1;
            continue;
        }

        let after_name = end + 1;
        let uv_value_count = read_u32_be_at(payload, after_name)? as usize;
        if uv_value_count == 0 || uv_value_count % 2 != 0 {
            pos += 1;
            continue;
        }
        let uv_bytes = uv_value_count.checked_mul(4)?;
        let after_uv = after_name.checked_add(4)?.checked_add(uv_bytes)?;
        if after_uv + 4 > payload.len() {
            pos += 1;
            continue;
        }

        let face_uv_count = read_u32_be_at(payload, after_uv)? as usize;
        if face_uv_count != face_entry_count {
            pos += 1;
            continue;
        }
        let mut face_cursor = after_uv + 4;
        let face_uv_values = read_u32_be_vec(payload, &mut face_cursor, face_uv_count)?;
        let set_index = pos
            .checked_sub(4)
            .and_then(|idx| read_u32_be_at(payload, idx))
            .unwrap_or(0) as usize;
        return Some((set_index, face_uv_values));
    }
    None
}

fn build_mesh_setattr_events(parsed: ParsedMeshPayload) -> Vec<DecodedEvent> {
    let mut events = Vec::new();

    let vertex_count = parsed.positions.len() / 3;
    events.push(DecodedEvent::SetAttr(SetAttrOp {
        attr_name_or_path: ".vt".to_string(),
        array_size: Some(vertex_count),
        channel_hint: None,
        lock: None,
        keyable: None,
        value: SetAttrValue::None,
    }));
    for start in (0..vertex_count).step_by(VERTICES_PER_CHUNK) {
        let end = (start + VERTICES_PER_CHUNK).min(vertex_count) - 1;
        let mut values = Vec::with_capacity((end - start + 1) * 3);
        for idx in (start * 3)..=((end * 3) + 2) {
            values.push(NumericValue::from_f32(parsed.positions[idx]));
        }
        events.push(DecodedEvent::SetAttr(SetAttrOp {
            attr_name_or_path: range_attr(".vt", start, end),
            array_size: None,
            channel_hint: None,
            lock: None,
            keyable: None,
            value: SetAttrValue::Numbers(values),
        }));
    }

    let edge_count = parsed.edges.len();
    events.push(DecodedEvent::SetAttr(SetAttrOp {
        attr_name_or_path: ".ed".to_string(),
        array_size: Some(edge_count),
        channel_hint: None,
        lock: None,
        keyable: None,
        value: SetAttrValue::None,
    }));
    for start in (0..edge_count).step_by(EDGES_PER_CHUNK) {
        let end = (start + EDGES_PER_CHUNK).min(edge_count) - 1;
        let mut values = Vec::with_capacity((end - start + 1) * 3);
        for idx in start..=end {
            let (a, b) = parsed.edges[idx];
            values.push(NumericValue::from_u32(a));
            values.push(NumericValue::from_u32(b));
            values.push(NumericValue::from_u32(1));
        }
        events.push(DecodedEvent::SetAttr(SetAttrOp {
            attr_name_or_path: range_attr(".ed", start, end),
            array_size: None,
            channel_hint: None,
            lock: None,
            keyable: None,
            value: SetAttrValue::Numbers(values),
        }));
    }

    if !parsed.normal_bits.is_empty() {
        let normal_count = parsed.normal_bits.len() / 3;
        events.push(DecodedEvent::SetAttr(SetAttrOp {
            attr_name_or_path: ".n".to_string(),
            array_size: Some(normal_count),
            channel_hint: None,
            lock: None,
            keyable: None,
            value: SetAttrValue::None,
        }));
        for start in (0..normal_count).step_by(NORMALS_PER_CHUNK) {
            let end = (start + NORMALS_PER_CHUNK).min(normal_count) - 1;
            let mut values = Vec::with_capacity((end - start + 1) * 3);
            for idx in (start * 3)..=((end * 3) + 2) {
                values.push(format_f32_bits(parsed.normal_bits[idx]));
            }
            events.push(DecodedEvent::SetAttr(SetAttrOp {
                attr_name_or_path: range_attr(".n", start, end),
                array_size: None,
                channel_hint: None,
                lock: None,
                keyable: None,
                value: SetAttrValue::TypedNumbers {
                    value_type: "float3".to_string(),
                    values,
                },
            }));
        }
    }

    let face_count = parsed.face_edges.len();
    events.push(DecodedEvent::SetAttr(SetAttrOp {
        attr_name_or_path: ".fc".to_string(),
        array_size: Some(face_count),
        channel_hint: Some(parsed.total_face_entries),
        lock: None,
        keyable: None,
        value: SetAttrValue::None,
    }));
    for start in (0..face_count).step_by(FACES_PER_CHUNK) {
        let end = (start + FACES_PER_CHUNK).min(face_count) - 1;
        events.push(DecodedEvent::SetAttr(SetAttrOp {
            attr_name_or_path: range_attr(".fc", start, end),
            array_size: None,
            channel_hint: None,
            lock: None,
            keyable: None,
            value: SetAttrValue::PolyFaces {
                uv_set: parsed.uv_set_index,
                faces: parsed.face_edges[start..=end].to_vec(),
                uv_faces: parsed.face_uvs[start..=end].to_vec(),
            },
        }));
    }

    events
}

fn format_f32_bits(bits: u32) -> NumericValue {
    if bits == SENTINEL_POSITIVE_1E20_BITS {
        return NumericValue::from_f64(1e20);
    }
    if bits == SENTINEL_NEGATIVE_1E20_BITS {
        return NumericValue::from_f64(-1e20);
    }
    NumericValue::from_f32(f32::from_bits(bits))
}

fn range_attr(base: &str, start: usize, end: usize) -> String {
    if start == end {
        format!("{base}[{start}]")
    } else {
        format!("{base}[{start}:{end}]")
    }
}

fn read_u32_be(payload: &[u8], cursor: &mut usize) -> Option<u32> {
    let end = cursor.checked_add(4)?;
    let raw = payload.get(*cursor..end)?;
    *cursor = end;
    Some(u32::from_be_bytes(raw.try_into().ok()?))
}

fn read_u32_be_at(payload: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let raw = payload.get(offset..end)?;
    Some(u32::from_be_bytes(raw.try_into().ok()?))
}

fn read_u32_be_vec(payload: &[u8], cursor: &mut usize, count: usize) -> Option<Vec<u32>> {
    let byte_len = count.checked_mul(4)?;
    let end = cursor.checked_add(byte_len)?;
    let raw = payload.get(*cursor..end)?;
    *cursor = end;
    Some(
        raw.chunks_exact(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .collect(),
    )
}

fn read_f32_be_vec(payload: &[u8], cursor: &mut usize, count: usize) -> Option<Vec<f32>> {
    let byte_len = count.checked_mul(4)?;
    let end = cursor.checked_add(byte_len)?;
    let raw = payload.get(*cursor..end)?;
    *cursor = end;
    Some(
        raw.chunks_exact(4)
            .map(|chunk| f32::from_bits(u32::from_be_bytes(chunk.try_into().unwrap())))
            .collect(),
    )
}

fn read_cstring(payload: &[u8], cursor: &mut usize) -> Option<String> {
    if *cursor >= payload.len() {
        return None;
    }
    let rel = payload[*cursor..].iter().position(|b| *b == 0)?;
    let end = *cursor + rel;
    let out = std::str::from_utf8(payload.get(*cursor..end)?)
        .ok()?
        .to_string();
    *cursor = end + 1;
    Some(out)
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'[' | b']' | b'.')
}

#[cfg(test)]
mod tests {
    use super::MeshPayloadDecoder;
    use crate::scene::{
        decode::dispatcher::{ChunkDecodeContext, ChunkDecoder, DecodeAttempt},
        ir::{DecodedEvent, NumericValue, SetAttrOp, SetAttrValue},
    };

    fn context(payload: &[u8]) -> ChunkDecodeContext<'_> {
        ChunkDecodeContext {
            registry: crate::scene::schema::default_schema_registry(),
            form: "DMSH",
            tag: "MESH",
            payload,
            node_offset: 0,
            chunk_aux: None,
            child_alignment: None,
            child_header_size: None,
            parent_form: Some("DMSH"),
            parent_tag: Some("FOR8"),
        }
    }

    #[test]
    fn decodes_indexed_mesh_payload_into_vt_ed_fc_events() {
        let payload = build_sample_mesh_payload();
        let decoder = MeshPayloadDecoder;
        let attempt = decoder.decode_attempt(&context(&payload));

        let DecodeAttempt::HandledWithQuality { events, .. } = attempt else {
            panic!("expected handled mesh payload");
        };
        assert_eq!(events.len(), 6);

        let DecodedEvent::SetAttr(vt_decl) = &events[0] else {
            panic!("expected vt decl");
        };
        assert_eq!(vt_decl.attr_name_or_path, ".vt");
        assert_eq!(vt_decl.array_size, Some(4));

        let DecodedEvent::SetAttr(ed_decl) = &events[2] else {
            panic!("expected ed decl");
        };
        assert_eq!(ed_decl.attr_name_or_path, ".ed");
        assert_eq!(ed_decl.array_size, Some(4));

        let DecodedEvent::SetAttr(fc_decl) = &events[4] else {
            panic!("expected fc decl");
        };
        assert_eq!(fc_decl.attr_name_or_path, ".fc");
        assert_eq!(fc_decl.array_size, Some(1));
        assert_eq!(fc_decl.channel_hint, Some(4));

        let DecodedEvent::SetAttr(fc_values) = &events[5] else {
            panic!("expected fc values");
        };
        match &fc_values.value {
            SetAttrValue::PolyFaces {
                uv_set,
                faces,
                uv_faces,
            } => {
                assert_eq!(*uv_set, 0);
                assert_eq!(faces, &vec![vec![0, 1, -3, -4]]);
                assert_eq!(uv_faces, &vec![vec![0, 1, 2, 3]]);
            }
            other => panic!("unexpected value: {other:?}"),
        }
    }

    #[test]
    fn passes_when_mesh_payload_shape_does_not_match() {
        let decoder = MeshPayloadDecoder;
        let attempt = decoder.decode_attempt(&context(b"o\0\x20\x00"));
        assert!(matches!(attempt, DecodeAttempt::Pass { .. }));
    }

    #[test]
    fn decodes_mesh_payload_with_scanned_uv_section() {
        let payload = build_sample_mesh_payload_with_scanned_uv_section();
        let decoder = MeshPayloadDecoder;
        let attempt = decoder.decode_attempt(&context(&payload));

        let DecodeAttempt::HandledWithQuality { events, .. } = attempt else {
            panic!("expected handled mesh payload");
        };
        let Some(DecodedEvent::SetAttr(fc_decl)) = events.get(4) else {
            panic!("expected fc decl");
        };
        assert_eq!(fc_decl.array_size, Some(1));
        assert_eq!(fc_decl.channel_hint, Some(4));

        let Some(DecodedEvent::SetAttr(fc_values)) = events.get(5) else {
            panic!("expected fc values");
        };
        match &fc_values.value {
            SetAttrValue::PolyFaces {
                uv_set,
                faces,
                uv_faces,
            } => {
                assert_eq!(*uv_set, 0);
                assert_eq!(faces, &vec![vec![0, 1, -3, -4]]);
                assert_eq!(uv_faces, &vec![vec![0, 1, 2, 3]]);
            }
            other => panic!("unexpected value: {other:?}"),
        }
    }

    #[test]
    fn decodes_mesh_payload_with_optional_normals_block() {
        let payload = build_sample_mesh_payload_with_normals_block();
        let decoder = MeshPayloadDecoder;
        let attempt = decoder.decode_attempt(&context(&payload));

        let DecodeAttempt::HandledWithQuality { events, .. } = attempt else {
            panic!("expected handled mesh payload");
        };
        let n_decl = find_set_attr(&events, ".n").expect("normal decl");
        assert_eq!(n_decl.array_size, Some(4));

        let n_values = find_set_attr(&events, ".n[0:3]").expect("normal values");
        let SetAttrValue::TypedNumbers { value_type, values } = &n_values.value else {
            panic!("expected typed normal values");
        };
        assert_eq!(value_type, "float3");
        assert_eq!(values.len(), 12);
        assert_eq!(values[0], NumericValue::from_f64(1e20));
    }

    fn build_sample_mesh_payload() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"o");
        out.push(0);
        out.push(0x20);

        append_u32(&mut out, 12);
        let vt = [
            0.0f32, 0.0, 0.0, //
            1.0, 0.0, 0.0, //
            1.0, 1.0, 0.0, //
            0.0, 1.0, 0.0, //
        ];
        for v in vt {
            append_f32(&mut out, v);
        }

        append_u32(&mut out, 8);
        let edges = [0u32, 1, 1, 2, 2, 3, 3, 0];
        for e in edges {
            append_u32(&mut out, e);
        }

        append_u32(&mut out, 4);
        let face_edges = [0x00000000u32, 0x00000001, 0x80000002, 0xE0000003];
        for w in face_edges {
            append_u32(&mut out, w);
        }

        append_u32(&mut out, 0);
        append_u32(&mut out, 1);
        append_u32(&mut out, 0);
        out.extend_from_slice(b"map1");
        out.push(0);
        append_u32(&mut out, 8);
        let uv_values = [0.0f32, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0];
        for v in uv_values {
            append_f32(&mut out, v);
        }

        append_u32(&mut out, 4);
        for uv in [0u32, 1, 2, 3] {
            append_u32(&mut out, uv);
        }
        out.resize(out.len() + 20, 0);
        out
    }

    fn build_sample_mesh_payload_with_scanned_uv_section() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"o");
        out.push(0);
        out.push(0x20);

        append_u32(&mut out, 12);
        let vt = [
            0.0f32, 0.0, 0.0, //
            1.0, 0.0, 0.0, //
            1.0, 1.0, 0.0, //
            0.0, 1.0, 0.0, //
        ];
        for v in vt {
            append_f32(&mut out, v);
        }

        append_u32(&mut out, 8);
        let edges = [0u32, 1, 1, 2, 2, 3, 3, 0];
        for e in edges {
            append_u32(&mut out, e);
        }

        append_u32(&mut out, 4);
        let face_edges = [0x00000000u32, 0x00000001, 0x80000002, 0xE0000003];
        for w in face_edges {
            append_u32(&mut out, w);
        }

        // Prefix with data that breaks direct uv parsing and forces scan fallback.
        append_u32(&mut out, 1234);
        append_u32(&mut out, 0x60AD78EC);
        append_u32(&mut out, 0x60AD78EC);
        append_u32(&mut out, 0);
        append_u32(&mut out, 1);
        append_u32(&mut out, 0);
        out.extend_from_slice(b"map1");
        out.push(0);
        append_u32(&mut out, 8);
        let uv_values = [0.0f32, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0];
        for v in uv_values {
            append_f32(&mut out, v);
        }
        append_u32(&mut out, 4);
        for uv in [0u32, 1, 2, 3] {
            append_u32(&mut out, uv);
        }
        // Trailing non-zero bytes should not reject decode.
        append_u32(&mut out, 0xDEADBEEF);
        out
    }

    fn build_sample_mesh_payload_with_normals_block() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"o");
        out.push(0);
        out.push(0x20);

        append_u32(&mut out, 12);
        let vt = [
            0.0f32, 0.0, 0.0, //
            1.0, 0.0, 0.0, //
            1.0, 1.0, 0.0, //
            0.0, 1.0, 0.0, //
        ];
        for v in vt {
            append_f32(&mut out, v);
        }

        append_u32(&mut out, 8);
        let edges = [0u32, 1, 1, 2, 2, 3, 3, 0];
        for e in edges {
            append_u32(&mut out, e);
        }

        append_u32(&mut out, 4);
        let face_edges = [0x00000000u32, 0x00000001, 0x80000002, 0xE0000003];
        for w in face_edges {
            append_u32(&mut out, w);
        }

        append_u32(&mut out, 12);
        append_u32(&mut out, 0x60AD78EC);
        append_f32(&mut out, 0.0);
        append_f32(&mut out, 1.0);
        append_f32(&mut out, 1.0);
        append_f32(&mut out, 0.0);
        append_f32(&mut out, 0.0);
        append_f32(&mut out, 0.0);
        append_f32(&mut out, 0.0);
        append_f32(&mut out, 1.0);
        append_f32(&mut out, 0.0);
        append_f32(&mut out, 0.0);
        append_f32(&mut out, 0.0);
        append_u32(&mut out, 0);
        append_u32(&mut out, 1);
        append_u32(&mut out, 0);

        append_u32(&mut out, 0);
        append_u32(&mut out, 1);
        append_u32(&mut out, 0);
        out.extend_from_slice(b"map1");
        out.push(0);
        append_u32(&mut out, 8);
        let uv_values = [0.0f32, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0];
        for v in uv_values {
            append_f32(&mut out, v);
        }

        append_u32(&mut out, 4);
        for uv in [0u32, 1, 2, 3] {
            append_u32(&mut out, uv);
        }
        out.resize(out.len() + 20, 0);
        out
    }

    fn find_set_attr<'a>(events: &'a [DecodedEvent], attr_path: &str) -> Option<&'a SetAttrOp> {
        events.iter().find_map(|event| match event {
            DecodedEvent::SetAttr(op) if op.attr_name_or_path == attr_path => Some(op),
            _ => None,
        })
    }

    fn append_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn append_f32(out: &mut Vec<u8>, value: f32) {
        out.extend_from_slice(&value.to_bits().to_be_bytes());
    }
}
