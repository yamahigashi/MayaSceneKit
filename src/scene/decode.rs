use std::collections::{HashMap, HashSet};
use std::f64::consts::PI;

use super::looks_like_radians;
use super::patterns::*;
use super::util::{align, escape_ma_string, format_number};

pub(super) fn decode_slct_target(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let end = payload
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).trim().to_string()
}

pub(super) fn decode_select_command(tag: &str, payload: &[u8]) -> Option<String> {
    if tag == "ATTR" {
        return decode_add_attr_from_attr_chunk(payload);
    }
    decode_attr_chunk_to_setattr(tag, payload)
}

pub(super) fn walk_group_chunks(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let group_tags: HashSet<&'static str> = ["FOR8", "FOR4", "LIS8", "LIS4", "CAT8", "CAT4"]
        .into_iter()
        .collect();
    for (tag, payload) in parse_section_chunks(data) {
        if group_tags.contains(tag.as_str()) && payload.len() >= 4 {
            out.extend(walk_group_chunks(&payload[4..]));
        } else {
            out.push((tag, payload));
        }
    }
    out
}

pub(super) fn decode_cwfl(payload: &[u8]) -> Option<(u8, String, String)> {
    if payload.is_empty() {
        return None;
    }
    let mode = payload[0];
    let tokens: Vec<String> = payload[1..]
        .split(|b| *b == 0)
        .map(sanitize_token)
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() < 2 {
        return None;
    }
    Some((mode, tokens[0].clone(), tokens[1].clone()))
}

pub(super) fn format_connectattr(src: &str, dst: &str, mode: u8) -> String {
    let na_flag = if (mode & 0x01) != 0 { " -na" } else { "" };
    let lock_flag = if (mode & 0x02) != 0 { " -l on" } else { "" };
    format!(
        "connectAttr \"{}\" \"{}\"{}{};",
        escape_ma_string(src),
        escape_ma_string(dst),
        na_flag,
        lock_flag
    )
}

pub(super) fn is_known_connection(
    src: &str,
    dst: &str,
    known_nodes: Option<&HashSet<String>>,
) -> bool {
    match known_nodes {
        None => true,
        Some(nodes) => plug_is_known(src, nodes) && plug_is_known(dst, nodes),
    }
}

pub(super) fn is_noisy_skincluster_link(src: &str, dst: &str, mode: u8) -> bool {
    if mode != 0 {
        return false;
    }
    let src_attr = plug_attr_name(src);
    if !["wm", "obcc", "liw"].contains(&src_attr.as_str()) {
        return false;
    }
    let dst_attr = plug_attr_name(dst);
    SKINCLUSTER_INDEX_ATTR_RE.is_match(&dst_attr)
}

pub(super) fn has_disallowed_namespace_node(
    plug: &str,
    known_nodes: Option<&HashSet<String>>,
) -> bool {
    let Some(known_nodes) = known_nodes else {
        return false;
    };
    let node = plug_node_name(plug);
    if !node.starts_with(':') {
        return false;
    }
    let node_name = &node[1..];
    if known_nodes.contains(node_name) {
        return false;
    }
    if ALLOWED_NAMESPACE_NODE_NAMES.contains(&node_name) {
        return false;
    }
    true
}

pub(super) fn is_out_of_bounds_dagpose_link(
    src: &str,
    dst: &str,
    dagpose_array_sizes: Option<&HashMap<String, HashMap<String, usize>>>,
) -> bool {
    let Some(sizes) = dagpose_array_sizes else {
        return false;
    };
    is_out_of_bounds_dagpose_plug(src, sizes) || is_out_of_bounds_dagpose_plug(dst, sizes)
}

pub(super) fn is_out_of_bounds_dagpose_plug(
    plug: &str,
    dagpose_array_sizes: &HashMap<String, HashMap<String, usize>>,
) -> bool {
    let mut node_name = plug_node_name(plug);
    if node_name.starts_with(':') {
        node_name = node_name[1..].to_string();
    }

    let Some(attr_sizes) = dagpose_array_sizes.get(&node_name) else {
        return false;
    };
    let mut parts = plug.splitn(2, '.');
    let _ = parts.next();
    let Some(rest) = parts.next() else {
        return false;
    };

    let first_token = rest.split('.').next().unwrap_or_default();
    let Some(caps) = PLUG_INDEX_TOKEN_RE.captures(first_token) else {
        return false;
    };
    let attr_name = caps.name("attr").map(|m| m.as_str()).unwrap_or_default();
    if !["m", "p", "wm"].contains(&attr_name) {
        return false;
    }
    let index: usize = caps
        .name("index")
        .and_then(|m| m.as_str().parse::<usize>().ok())
        .unwrap_or(0);

    match attr_sizes.get(attr_name) {
        Some(size) => index >= *size,
        None => false,
    }
}

pub(super) fn is_allowed_skincluster_link(
    dst: &str,
    skincluster_influence_indices: Option<&HashMap<String, HashSet<usize>>>,
) -> bool {
    let Some(indices) = skincluster_influence_indices else {
        return false;
    };
    let Some((node_name, index)) = parse_skincluster_dst_index(dst) else {
        return false;
    };
    match indices.get(&node_name) {
        Some(known) => known.contains(&index),
        None => false,
    }
}

pub(super) fn parse_skincluster_dst_index(dst: &str) -> Option<(String, usize)> {
    let caps = SKINCLUSTER_DST_ATTR_RE.captures(dst)?;
    let node_name = caps.name("node")?.as_str().to_string();
    let index = caps.name("index")?.as_str().parse::<usize>().ok()?;
    Some((node_name, index))
}

pub(super) fn plug_is_known(plug: &str, known_nodes: &HashSet<String>) -> bool {
    let node = plug_node_name(plug);
    if node.is_empty() {
        return false;
    }
    if node.starts_with(':') {
        return true;
    }
    known_nodes.contains(&node)
}

pub(super) fn plug_node_name(plug: &str) -> String {
    let token = plug.split('.').next().unwrap_or_default().trim();
    if token.is_empty() {
        return String::new();
    }
    if token.starts_with(':') {
        return token.to_string();
    }
    if token.contains('|') {
        let leaf = token.rsplit('|').next().unwrap_or_default();
        if !leaf.is_empty() {
            return leaf.to_string();
        }
    }
    token.to_string()
}

pub(super) fn plug_attr_name(plug: &str) -> String {
    plug.split_once('.')
        .map(|(_, p)| p.trim().to_string())
        .unwrap_or_default()
}

pub(super) fn decode_rela_to_relationship(payload: &[u8]) -> Option<String> {
    let tokens: Vec<String> = payload
        .split(|b| *b == 0)
        .map(sanitize_token)
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() < 4 {
        return None;
    }

    let kind = escape_ma_string(&tokens[0]);
    let head = escape_ma_string(&tokens[1]);
    let tail = tokens[2..]
        .iter()
        .map(|t| format!("\"{}\"", escape_ma_string(t)))
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!("relationship \"{kind}\" \"{head}\" {tail};"))
}

pub(super) fn sanitize_token(raw: &[u8]) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut start = 0usize;
    while start < raw.len() && !(32..=126).contains(&raw[start]) {
        start += 1;
    }
    let mut end = raw.len();
    while end > start && !(32..=126).contains(&raw[end - 1]) {
        end -= 1;
    }
    if start >= end {
        return String::new();
    }
    String::from_utf8_lossy(&raw[start..end]).to_string()
}

pub(super) fn parse_section_chunks(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let parsed8 = parse_section_chunks_with_alignment(data, 8);
    let parsed4 = parse_section_chunks_with_alignment(data, 4);
    if parsed8.len() >= parsed4.len() {
        parsed8
    } else {
        parsed4
    }
}

pub(super) fn parse_section_chunks_with_alignment(
    data: &[u8],
    alignment: usize,
) -> Vec<(String, Vec<u8>)> {
    let mut chunks = Vec::new();
    let mut cursor = 0usize;
    let data_len = data.len();

    while cursor + 16 <= data_len {
        let tag_bytes = &data[cursor..cursor + 4];
        if !tag_bytes.iter().all(|b| (32..=126).contains(b)) {
            break;
        }
        let size = u64::from_be_bytes(data[cursor + 8..cursor + 16].try_into().unwrap()) as usize;
        let payload_start = cursor + 16;
        let payload_end = payload_start + size;
        if payload_end > data_len {
            break;
        }
        let tag = String::from_utf8_lossy(tag_bytes).to_string();
        chunks.push((tag, data[payload_start..payload_end].to_vec()));
        cursor += align(16 + size, alignment);
    }

    chunks
}

pub(super) fn decode_attr_chunk_to_setattr(tag: &str, payload: &[u8]) -> Option<String> {
    if tag == "ATTR" {
        return decode_add_attr_from_attr_chunk(payload);
    }

    let (attr_name, kind, value_raw) = decode_attr_payload(payload)?;
    let attr_path = attr_path(&attr_name);

    if tag == "FLGS" {
        if value_raw.len() >= 4 {
            let count = u32::from_be_bytes(value_raw[..4].try_into().ok()?) as usize;
            if kind == 0x08 || kind == 0x28 || ARRAY_SIZE_ATTRS.contains(&attr_name.as_str()) {
                return Some(format!("setAttr -s {count} \"{attr_path}\";"));
            }
        }
        return Some(format!("setAttr -k off \"{attr_path}\";"));
    }

    if tag == "STR " {
        let end = value_raw
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(value_raw.len());
        let text = String::from_utf8_lossy(&value_raw[..end]).to_string();
        return Some(format!(
            "setAttr \"{attr_path}\" -type \"string\" \"{}\";",
            escape_ma_string(&text)
        ));
    }

    if tag == "STR#" {
        if value_raw.len() < 4 {
            return None;
        }
        let count = u32::from_be_bytes(value_raw[..4].try_into().ok()?) as usize;
        let raw_items: Vec<&[u8]> = value_raw[4..]
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .collect();
        let items: Vec<String> = raw_items
            .into_iter()
            .take(count)
            .map(|p| String::from_utf8_lossy(p).to_string())
            .collect();
        if count == 0 {
            return Some(format!(
                "setAttr \"{attr_path}\" -type \"stringArray\" 0  ;"
            ));
        }
        let values = items
            .iter()
            .map(|v| format!("\"{}\"", escape_ma_string(v)))
            .collect::<Vec<_>>()
            .join(" ");
        return Some(format!(
            "setAttr \"{attr_path}\" -type \"stringArray\" {count} {values} ;"
        ));
    }

    if tag == "I32#" {
        if value_raw.len() % 4 != 0 {
            return None;
        }
        let vals: Vec<i32> = value_raw
            .chunks_exact(4)
            .map(|c| i32::from_be_bytes(c.try_into().unwrap()))
            .collect();
        let values = vals
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        return Some(format!(
            "setAttr \"{attr_path}\" -type \"Int32Array\" {} {values};",
            vals.len()
        ));
    }

    if tag == "FLT3" {
        if value_raw.len() < 12 {
            return None;
        }
        let x = f32::from_bits(u32::from_be_bytes(value_raw[0..4].try_into().unwrap())) as f64;
        let y = f32::from_bits(u32::from_be_bytes(value_raw[4..8].try_into().unwrap())) as f64;
        let z = f32::from_bits(u32::from_be_bytes(value_raw[8..12].try_into().unwrap())) as f64;
        return Some(format!(
            "setAttr \"{attr_path}\" -type \"float3\" {} {} {} ;",
            format_number(x),
            format_number(y),
            format_number(z)
        ));
    }

    if tag == "FLT2" {
        if value_raw.len() < 8 || value_raw.len() % 8 != 0 {
            return None;
        }
        let vals: Vec<String> = value_raw
            .chunks_exact(4)
            .map(
                |c| format_number(f32::from_bits(u32::from_be_bytes(c.try_into().unwrap())) as f64),
            )
            .collect();
        return Some(format!(
            "setAttr \"{attr_path}\" -type \"float2\" {} ;",
            vals.join(" ")
        ));
    }

    if tag == "DBLE" {
        if value_raw.len() < 8 {
            return None;
        }
        let value = f64::from_bits(u64::from_be_bytes(value_raw[0..8].try_into().unwrap()));
        if is_bool_attr(&attr_name, value) {
            let bool_text = if value != 0.0 { "yes" } else { "no" };
            return Some(format!("setAttr \"{attr_path}\" {bool_text};"));
        }
        return Some(format!("setAttr \"{attr_path}\" {};", format_number(value)));
    }

    if tag == "DBL3" {
        if value_raw.len() < 24 {
            return None;
        }
        let mut values = vec![
            f64::from_bits(u64::from_be_bytes(value_raw[0..8].try_into().unwrap())),
            f64::from_bits(u64::from_be_bytes(value_raw[8..16].try_into().unwrap())),
            f64::from_bits(u64::from_be_bytes(value_raw[16..24].try_into().unwrap())),
        ];
        if attr_name == "r" && looks_like_radians(&values) {
            values = values.into_iter().map(|v| v * 180.0 / PI).collect();
        }
        return Some(format!(
            "setAttr \"{attr_path}\" -type \"double3\" {} {} {} ;",
            format_number(values[0]),
            format_number(values[1]),
            format_number(values[2])
        ));
    }

    if tag == "DBL2" {
        if value_raw.len() < 16 || value_raw.len() % 16 != 0 {
            return None;
        }
        let vals: Vec<String> = value_raw
            .chunks_exact(8)
            .map(|c| format_number(f64::from_bits(u64::from_be_bytes(c.try_into().unwrap()))))
            .collect();
        return Some(format!(
            "setAttr \"{attr_path}\" -type \"double2\" {} ;",
            vals.join(" ")
        ));
    }

    if tag == "CMPD" {
        if value_raw.len() < 24 {
            return None;
        }
        let a = f64::from_bits(u64::from_be_bytes(value_raw[0..8].try_into().unwrap()));
        let b = f64::from_bits(u64::from_be_bytes(value_raw[8..16].try_into().unwrap()));
        let c = f64::from_bits(u64::from_be_bytes(value_raw[16..24].try_into().unwrap()));
        return Some(format!(
            "setAttr \"{attr_path}\" {} {} {};",
            format_number(a),
            format_number(b),
            format_number(c)
        ));
    }

    if tag == "MATR" {
        if value_raw.len() < 128 || value_raw.len() % 8 != 0 {
            return None;
        }
        let vals: Vec<String> = value_raw
            .chunks_exact(8)
            .map(|c| format_number(f64::from_bits(u64::from_be_bytes(c.try_into().unwrap()))))
            .collect();
        return Some(format!(
            "setAttr \"{attr_path}\" -type \"matrix\" {};",
            vals.join(" ")
        ));
    }

    if tag == "CMP#" {
        return decode_component_list_attr(&attr_path, &value_raw);
    }

    None
}

pub(super) fn decode_attr_payload(payload: &[u8]) -> Option<(String, u8, Vec<u8>)> {
    if payload.is_empty() {
        return None;
    }
    let nul = payload.iter().position(|b| *b == 0)?;
    if nul == 0 || nul + 1 >= payload.len() {
        return None;
    }
    let name = String::from_utf8_lossy(&payload[..nul]).to_string();
    let kind = payload[nul + 1];
    let value_raw = payload[nul + 2..].to_vec();
    Some((name, kind, value_raw))
}

pub(super) fn decode_add_attr_from_attr_chunk(payload: &[u8]) -> Option<String> {
    let marker = b"STR ";
    let pos = payload.windows(marker.len()).position(|w| w == marker)?;
    let tail = &payload[pos + marker.len()..];
    let raw_parts: Vec<&[u8]> = tail.split(|b| *b == 0).filter(|p| !p.is_empty()).collect();
    if raw_parts.len() < 2 {
        return None;
    }

    let long_name = sanitize_token(raw_parts[0]);
    let short_name = sanitize_token(raw_parts[1]);
    if long_name.is_empty() || short_name.is_empty() {
        return None;
    }

    Some(format!(
        "addAttr -ci true -h true -sn \"{}\" -ln \"{}\" -dt \"string\";",
        escape_ma_string(&short_name),
        escape_ma_string(&long_name)
    ))
}

pub(super) fn decode_component_list_attr(attr_path: &str, value_raw: &[u8]) -> Option<String> {
    if value_raw.len() < 4 {
        return None;
    }
    let group_count = u32::from_be_bytes(value_raw[0..4].try_into().ok()?) as usize;
    let mut cursor = 4usize;
    let mut components = Vec::new();

    for _ in 0..group_count {
        if cursor + 8 > value_raw.len() {
            return None;
        }
        let code = String::from_utf8_lossy(&value_raw[cursor..cursor + 4]).to_string();
        cursor += 4;
        let range_count =
            u32::from_be_bytes(value_raw[cursor..cursor + 4].try_into().ok()?) as usize;
        cursor += 4;

        let prefix = match code.as_str() {
            "CMDV" => "vtx",
            "CMDF" => "f",
            "CMDE" => "e",
            _ => return None,
        };

        for _ in 0..range_count {
            if cursor + 8 > value_raw.len() {
                return None;
            }
            let start = i32::from_be_bytes(value_raw[cursor..cursor + 4].try_into().ok()?);
            let end = i32::from_be_bytes(value_raw[cursor + 4..cursor + 8].try_into().ok()?);
            cursor += 8;

            let token = if start < 0 || end < 0 {
                format!("{prefix}[*]")
            } else if start == end {
                format!("{prefix}[{start}]")
            } else {
                format!("{prefix}[{start}:{end}]")
            };
            components.push(token);
        }
    }

    if components.is_empty() {
        return None;
    }

    let values = components
        .iter()
        .map(|c| format!("\"{}\"", escape_ma_string(c)))
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!(
        "setAttr \"{attr_path}\" -type \"componentList\" {} {values};",
        components.len()
    ))
}

pub(super) fn decode_plug_to_requires(payload: &[u8]) -> Option<String> {
    let parts: Vec<String> = payload
        .split(|b| *b == 0)
        .map(sanitize_token)
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() < 2 {
        return None;
    }

    let name = parts[0].trim();
    let version = parts[1].trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }

    let mut options = if parts.len() >= 3 {
        parts[2].trim().to_string()
    } else {
        String::new()
    };
    if !options.is_empty() && !options.starts_with('-') {
        options.clear();
    }
    let options_part = if options.is_empty() {
        String::new()
    } else {
        format!(" {options}")
    };

    Some(format!(
        "requires{options_part} \"{}\" \"{}\";",
        escape_ma_string(name),
        escape_ma_string(version)
    ))
}

pub(super) fn attr_path(name: &str) -> String {
    if name.starts_with('.') {
        name.to_string()
    } else {
        format!(".{name}")
    }
}

pub(super) fn is_bool_attr(name: &str, value: f64) -> bool {
    if BOOL_ATTRS.contains(&name) {
        return true;
    }
    name.starts_with('v') && (value == 0.0 || value == 1.0)
}
