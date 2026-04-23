use std::collections::HashSet;

use crate::{
    ma::text::escape_ma_string,
    maya_defaults::DEFAULT_MAYA_VERSION,
    mb::{
        Chunk, MayaBinaryFile, parse_section_chunks_full_with_hints,
        parse_section_chunks_with_hints, resolve_section_layout_hints,
        rewrite::{chunk_header_format_from_chunk, encode_chunk},
    },
    unit_semantics::{
        DEFAULT_ANGULAR_UNIT, DEFAULT_LINEAR_UNIT, DEFAULT_TIME_UNIT, normalize_angular_unit,
        normalize_linear_unit, normalize_time_unit,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbRequiresEntry {
    pub plugin_name: String,
    pub version: String,
    pub options: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HeadMetadata {
    pub vers: Option<String>,
    pub chng: Option<String>,
    pub luni: Option<String>,
    pub auni: Option<String>,
    pub tuni: Option<String>,
    pub tdur: Option<String>,
    pub file_info: Vec<(String, String)>,
    pub requires: Vec<MbRequiresEntry>,
}

impl HeadMetadata {
    pub fn maya_version(&self) -> &str {
        self.vers.as_deref().unwrap_or(DEFAULT_MAYA_VERSION)
    }

    pub fn linear_unit(&self) -> &str {
        self.luni.as_deref().unwrap_or(DEFAULT_LINEAR_UNIT)
    }

    pub fn angular_unit(&self) -> &str {
        self.auni.as_deref().unwrap_or(DEFAULT_ANGULAR_UNIT)
    }

    pub fn time_unit(&self) -> &str {
        self.tuni.as_deref().unwrap_or(DEFAULT_TIME_UNIT)
    }
}

pub fn extract_head_metadata(mb: &MayaBinaryFile) -> HeadMetadata {
    let mut metadata = HeadMetadata::default();

    for head in mb
        .root
        .children
        .iter()
        .filter(|chunk| chunk.form_type.as_deref() == Some("HEAD"))
    {
        let payload = &mb.data[head.payload_offset..head.payload_end];
        if payload.len() < 4 {
            continue;
        }
        let (child_alignment, child_header_size) = resolve_section_layout_hints(
            &head.tag,
            head.form_type.as_deref(),
            head.child_alignment,
            head.child_header_size,
        );
        let parsed =
            parse_section_chunks_with_hints(&payload[4..], child_alignment, child_header_size);
        for chunk in parsed.chunks {
            let raw = chunk.payload(&payload[4..]);
            let text = String::from_utf8_lossy(raw)
                .trim_end_matches('\0')
                .to_string();
            match chunk.tag.as_str() {
                "VERS" if !text.is_empty() => {
                    metadata.vers = Some(text);
                }
                "CHNG" if !text.is_empty() => {
                    metadata.chng = Some(text);
                }
                "LUNI" if !text.is_empty() => {
                    metadata.luni = Some(normalize_linear_unit(&text));
                }
                "AUNI" if !text.is_empty() => {
                    metadata.auni = Some(normalize_angular_unit(&text));
                }
                "TUNI" if !text.is_empty() => {
                    metadata.tuni = Some(normalize_time_unit(&text));
                }
                "TDUR" if !text.is_empty() => {
                    metadata.tdur = Some(text);
                }
                "FINF" => {
                    if let Some((key, value)) = decode_finf(raw) {
                        metadata.file_info.push((key, value));
                    }
                }
                "PLUG" => {
                    if let Some(req) = decode_plug_to_requires_entry(raw) {
                        metadata.requires.push(req);
                    }
                }
                _ => {}
            }
        }
    }

    metadata
}

pub fn render_requires_entry(entry: &MbRequiresEntry) -> String {
    let options_part = entry
        .options
        .as_deref()
        .map(|value| format!(" {value}"))
        .unwrap_or_default();
    format!(
        "requires{options_part} \"{}\" \"{}\";",
        escape_ma_string(&entry.plugin_name),
        escape_ma_string(&entry.version)
    )
}

pub fn remove_plugin_requires_from_mb(
    data: &[u8],
    root: &Chunk,
    target_rendered: &[String],
) -> (Vec<u8>, Vec<String>) {
    let (rewritten, _, removed) =
        remove_root_forms_and_plugin_requires_from_mb(data, root, &[], target_rendered);
    (rewritten, removed)
}

pub fn remove_root_forms_and_plugin_requires_from_mb(
    data: &[u8],
    root: &Chunk,
    target_forms: &[(String, usize)],
    target_rendered: &[String],
) -> (Vec<u8>, Vec<(String, usize)>, Vec<String>) {
    let children = &root.children;
    if children.is_empty() {
        return (data.to_vec(), Vec::new(), Vec::new());
    }

    let form_targets = target_forms
        .iter()
        .map(|(form, node_offset)| (form.as_str(), *node_offset))
        .collect::<HashSet<_>>();
    let targets = target_rendered
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<HashSet<_>>();
    let target_all = targets.is_empty();

    let mut payload_parts: Vec<u8> = Vec::new();
    payload_parts.extend_from_slice(root.form_type.as_deref().unwrap_or("Maya").as_bytes());

    let first_child_start = children[0].offset;
    let prefix_start = root.payload_offset + 4;
    if first_child_start > prefix_start {
        payload_parts.extend_from_slice(&data[prefix_start..first_child_start]);
    }

    let mut removed_forms = Vec::new();
    let mut removed = Vec::new();
    let mut changed = false;

    for (idx, child) in children.iter().enumerate() {
        let next_offset = if idx + 1 < children.len() {
            children[idx + 1].offset
        } else {
            root.payload_end
        };
        let original_span = &data[child.offset..next_offset];
        if let Some(form) = child.form_type.as_deref()
            && form_targets.contains(&(form, child.offset))
        {
            removed_forms.push((form.to_string(), child.offset));
            changed = true;
            continue;
        }
        if child.form_type.as_deref() != Some("HEAD") {
            payload_parts.extend_from_slice(original_span);
            continue;
        }

        if let Some((rewritten, removed_here)) =
            rewrite_head_child_without_plugin_requires(child, data, &targets, target_all)
        {
            payload_parts.extend_from_slice(&rewritten);
            removed.extend(removed_here);
            changed = true;
        } else {
            payload_parts.extend_from_slice(original_span);
        }
    }

    if !changed {
        return (data.to_vec(), Vec::new(), Vec::new());
    }

    let Some(encoded) = crate::mb::encode_root_chunk(root, &payload_parts) else {
        return (data.to_vec(), Vec::new(), Vec::new());
    };
    (encoded, removed_forms, removed)
}

fn decode_finf(payload: &[u8]) -> Option<(String, String)> {
    let parts: Vec<String> = payload
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect();
    if parts.len() >= 2 {
        return Some((parts[0].clone(), parts[1].clone()));
    }
    None
}

fn decode_plug_to_requires_entry(payload: &[u8]) -> Option<MbRequiresEntry> {
    fn sanitize_token(raw: &[u8]) -> String {
        String::from_utf8_lossy(raw)
            .trim_matches(|c: char| c.is_control())
            .to_string()
    }

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

    let options = if parts.len() >= 3 {
        let options = parts[2].trim();
        if options.is_empty() || !options.starts_with('-') {
            None
        } else {
            Some(options.to_string())
        }
    } else {
        None
    };

    Some(MbRequiresEntry {
        plugin_name: name.to_string(),
        version: version.to_string(),
        options,
    })
}

fn rewrite_head_child_without_plugin_requires(
    child: &Chunk,
    data: &[u8],
    targets: &HashSet<&str>,
    target_all: bool,
) -> Option<(Vec<u8>, Vec<String>)> {
    let payload = &data[child.payload_offset..child.payload_end];
    if payload.len() < 4 {
        return None;
    }
    let inner = &payload[4..];
    let (child_alignment, child_header_size) = resolve_section_layout_hints(
        &child.tag,
        child.form_type.as_deref(),
        child.child_alignment,
        child.child_header_size,
    );
    let parsed = parse_section_chunks_full_with_hints(inner, child_alignment, child_header_size);
    if parsed.chunks.is_empty() {
        return None;
    }

    let mut removed = Vec::new();
    let mut new_inner = Vec::new();
    for chunk in &parsed.chunks {
        let raw = chunk.payload(inner);
        let rendered = if chunk.tag == "PLUG" {
            decode_plug_to_requires_entry(raw)
                .map(|entry| render_requires_entry(&entry))
                .filter(|rendered| target_all || targets.contains(rendered.as_str()))
        } else {
            None
        };

        if let Some(rendered) = rendered {
            removed.push(rendered);
            continue;
        }

        new_inner.extend_from_slice(&inner[chunk.chunk_start..chunk.chunk_end]);
    }
    new_inner.extend_from_slice(parsed.tail(inner));

    if removed.is_empty() {
        return None;
    }

    let mut new_payload = Vec::new();
    new_payload.extend_from_slice(b"HEAD");
    new_payload.extend_from_slice(&new_inner);
    let encoded = encode_chunk(
        child.tag.as_str(),
        child.aux,
        &new_payload,
        4,
        chunk_header_format_from_chunk(child),
    )?;
    Some((encoded, removed))
}

#[cfg(test)]
mod tests {
    use super::{extract_head_metadata, remove_plugin_requires_from_mb, render_requires_entry};
    use crate::mb::{MbParseBudget, parse_file, parse_file_with_budget};

    fn build_chunk_with_alignment(tag: &str, payload: &[u8], sibling_alignment: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(payload);
        while (out.len() - 16) % sibling_alignment != 0 {
            out.push(0);
        }
        out
    }

    fn build_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
        build_chunk_with_alignment(tag, payload, 8)
    }

    fn build_form_with_alignment(
        form: &str,
        children: &[Vec<u8>],
        sibling_alignment: usize,
    ) -> Vec<u8> {
        let mut payload = form.as_bytes().to_vec();
        for child in children {
            payload.extend_from_slice(child);
        }
        build_chunk_with_alignment("FOR8", &payload, sibling_alignment)
    }

    fn build_root(children: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = b"Maya".to_vec();
        for child in children {
            payload.extend_from_slice(child);
        }

        let mut out = Vec::new();
        out.extend_from_slice(b"FOR8");
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn write_temp_mb(bytes: &[u8], suffix: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("maya_scene_kit_formats_head_{suffix}_{unique}.mb"));
        std::fs::write(&path, bytes).expect("write temp mb");
        path
    }

    #[test]
    fn remove_plugin_requires_preserves_head_version_chunk() {
        let head = build_form_with_alignment(
            "HEAD",
            &[
                build_chunk("VERS", b"2026\0"),
                build_chunk("PLUG", b"pluginA\x001.0\0"),
                build_chunk("PLUG", b"pluginB\x002.0\0-op \"v=0\"\0"),
            ],
            4,
        );
        let source = write_temp_mb(&build_root(&[head]), "remove_plugin_requires");
        let mb = parse_file_with_budget(
            &source,
            &MbParseBudget {
                max_depth: 2,
                ..MbParseBudget::default()
            },
        )
        .expect("parse with budget");

        let (rewritten, removed) = remove_plugin_requires_from_mb(
            &mb.data,
            &mb.root,
            &[String::from("requires \"pluginA\" \"1.0\";")],
        );
        assert_eq!(removed, vec!["requires \"pluginA\" \"1.0\";".to_string()]);

        std::fs::write(&source, &rewritten).expect("rewrite temp mb");
        let reparsed = parse_file(&source).expect("reparse");
        let metadata = extract_head_metadata(&reparsed);
        let rendered = metadata
            .requires
            .iter()
            .map(render_requires_entry)
            .collect::<Vec<_>>();

        let _ = std::fs::remove_file(&source);

        assert_eq!(metadata.vers.as_deref(), Some("2026"));
        assert_eq!(
            rendered,
            vec!["requires -op \"v=0\" \"pluginB\" \"2.0\";".to_string()]
        );
    }
}
