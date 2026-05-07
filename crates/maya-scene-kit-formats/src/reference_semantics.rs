#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenePathAttrKind {
    ReferencePath,
    FileTexturePath,
    FileTextureColorSpace,
}

pub const DEFAULT_REFERENCE_FILE_TYPE: &str = "mayaBinary";

pub fn default_reference_file_type() -> &'static str {
    DEFAULT_REFERENCE_FILE_TYPE
}

pub fn normalize_reference_file_type_token(token: &str) -> Option<&'static str> {
    match token.trim() {
        DEFAULT_REFERENCE_FILE_TYPE => Some(DEFAULT_REFERENCE_FILE_TYPE),
        "mayaAscii" => Some("mayaAscii"),
        _ => None,
    }
}

pub fn parse_reference_options_token(token: &str) -> Option<String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("-op ") {
        let value = rest.trim();
        if value.is_empty() {
            return None;
        }
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            return Some(value[1..value.len() - 1].to_string());
        }
        return Some(value.to_string());
    }
    if trimmed.contains("VERS|") {
        return Some(trimmed.to_string());
    }
    None
}

pub fn encode_reference_options_token(options: &str) -> Option<String> {
    let trimmed = options.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("VERS|") {
        return Some(trimmed.to_string());
    }
    Some(format!("-op \"{trimmed}\""))
}

pub fn render_reference_options_clause(options: &str) -> Option<String> {
    let trimmed = options.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(format!(" -op \"{trimmed}\""))
}

pub fn reference_depth(reference_node: &str) -> usize {
    reference_node.matches(':').count() + 1
}

pub fn derive_parent_reference_node(reference_node: &str) -> Option<String> {
    let (prefix, _) = reference_node.rsplit_once(':')?;
    Some(format!("{prefix}RN"))
}

pub fn parse_reference_include_path(options: &str) -> Option<String> {
    let idx = options.find("INCL|")?;
    let start = idx + "INCL|".len();
    let rest = options.get(start..)?;
    let end_rel = rest.find('(')?;
    let path = rest[..end_rel].trim();
    if path.is_empty() || path == "undef" {
        return None;
    }
    let after_open = rest.as_bytes().get(end_rel + 1).copied();
    if after_open != Some(b'|') {
        return None;
    }
    Some(path.to_string())
}

pub fn classify_scene_path_attr(attr_name: &str) -> Option<ScenePathAttrKind> {
    let normalized = normalize_scene_path_attr_for_classification(attr_name)?;
    match normalized.as_str() {
        "fn" | "f" => Some(ScenePathAttrKind::ReferencePath),
        "ftn" | "filetexturename" => Some(ScenePathAttrKind::FileTexturePath),
        "cs" => Some(ScenePathAttrKind::FileTextureColorSpace),
        _ => None,
    }
}

pub fn looks_like_scene_file_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.ends_with(".ma") || lower.ends_with(".mb")
}

pub fn looks_like_qualified_scene_file_path(value: &str) -> bool {
    (value.contains('/') || value.contains('\\')) && looks_like_scene_file_path(value)
}

fn normalize_scene_path_attr_for_classification(attr_name: &str) -> Option<String> {
    let mut normalized = attr_name.trim().trim_start_matches('.');
    normalized = normalized.rsplit('.').next().unwrap_or(normalized);
    normalized = normalized.split('[').next().unwrap_or(normalized);
    (!normalized.is_empty()).then(|| normalized.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_REFERENCE_FILE_TYPE, ScenePathAttrKind, classify_scene_path_attr,
        derive_parent_reference_node, looks_like_qualified_scene_file_path,
        looks_like_scene_file_path, parse_reference_include_path, reference_depth,
        render_reference_options_clause,
    };

    #[test]
    fn reference_helpers_centralize_depth_and_parent_derivation() {
        assert_eq!(reference_depth("Root:ChildRN"), 2);
        assert_eq!(
            derive_parent_reference_node("Root:ChildRN").as_deref(),
            Some("RootRN")
        );
    }

    #[test]
    fn parse_reference_include_path_reads_strict_incl_payload() {
        let options = "VERS|2020|INCL|D:/example/TestScene_0000_Model.mb(|LUNI|cm|";
        assert_eq!(
            parse_reference_include_path(options).as_deref(),
            Some("D:/example/TestScene_0000_Model.mb")
        );
    }

    #[test]
    fn render_reference_options_clause_quotes_normalized_options() {
        assert_eq!(DEFAULT_REFERENCE_FILE_TYPE, "mayaBinary");
        assert_eq!(
            render_reference_options_clause("VERS|2026|").as_deref(),
            Some(" -op \"VERS|2026|\"")
        );
    }

    #[test]
    fn classify_scene_path_attr_normalizes_indexed_and_compound_paths() {
        assert_eq!(
            classify_scene_path_attr(".fn[0]"),
            Some(ScenePathAttrKind::ReferencePath)
        );
        assert_eq!(
            classify_scene_path_attr(".fn[0:2]"),
            Some(ScenePathAttrKind::ReferencePath)
        );
        assert_eq!(
            classify_scene_path_attr(".ref.fn[3]"),
            Some(ScenePathAttrKind::ReferencePath)
        );
        assert_eq!(
            classify_scene_path_attr(".fileTextureName[0]"),
            Some(ScenePathAttrKind::FileTexturePath)
        );
    }

    #[test]
    fn scene_file_path_helpers_split_contextual_and_generic_shapes() {
        assert!(looks_like_scene_file_path("ExampleScene.ma"));
        assert!(looks_like_scene_file_path("asset/example/ExampleScene.mb"));
        assert!(!looks_like_scene_file_path("ExampleTexture.png"));
        assert!(!looks_like_qualified_scene_file_path("ExampleScene.ma"));
        assert!(looks_like_qualified_scene_file_path(
            "asset/example/ExampleScene.ma"
        ));
    }
}
