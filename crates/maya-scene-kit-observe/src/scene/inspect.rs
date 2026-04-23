use std::path::Path;

pub use crate::scene::public::{MbInspectNode, MbInspectOptions, MbInspectReport};
use crate::{
    mb::{Chunk, MbParseBudget, parse_file_with_budget},
    scene::{
        SceneToolError, core::SceneFormat, ops,
        source::loader::materialize_adaptive_mb_parse_budget,
    },
};

pub fn inspect_mb(
    path: impl AsRef<Path>,
    options: MbInspectOptions,
) -> Result<MbInspectReport, SceneToolError> {
    let scene_path = path.as_ref();
    let scene_format = ops::detect_scene_format(scene_path)?;
    if scene_format != SceneFormat::Mb {
        return Err(SceneToolError::UnsupportedSceneFormat {
            path: scene_path.to_path_buf(),
            detected: scene_format,
        });
    }

    inspect_mb_with_budget(scene_path, options, &MbParseBudget::default())
}

pub fn inspect_mb_with_max_parse_bytes(
    path: impl AsRef<Path>,
    options: MbInspectOptions,
    max_parse_bytes: usize,
) -> Result<MbInspectReport, SceneToolError> {
    let scene_path = path.as_ref();
    let source_bytes_len = std::fs::metadata(scene_path)?.len() as usize;
    let budget = materialize_adaptive_mb_parse_budget(source_bytes_len, max_parse_bytes);
    inspect_mb_with_budget(scene_path, options, &budget)
}

fn inspect_mb_with_budget(
    scene_path: &Path,
    options: MbInspectOptions,
    budget: &MbParseBudget,
) -> Result<MbInspectReport, SceneToolError> {
    let mb = parse_file_with_budget(scene_path, budget)?;
    Ok(MbInspectReport {
        scene_path: scene_path.to_path_buf(),
        scene_format: SceneFormat::Mb,
        root: inspect_node(&mb.root, &mb.data, 0, options),
    })
}

fn inspect_node(
    chunk: &Chunk,
    file_data: &[u8],
    depth: usize,
    options: MbInspectOptions,
) -> MbInspectNode {
    let children = if options
        .max_depth
        .is_some_and(|max_depth| depth >= max_depth)
    {
        Vec::new()
    } else {
        chunk
            .children
            .iter()
            .map(|child| inspect_node(child, file_data, depth + 1, options))
            .collect()
    };

    MbInspectNode {
        tag: chunk.tag.clone(),
        offset: chunk.offset,
        aux: chunk.aux,
        size: chunk.size,
        payload_offset: chunk.payload_offset,
        payload_end: chunk.payload_end,
        child_alignment: chunk.child_alignment,
        child_header_size: chunk.child_header_size,
        form_type: chunk.form_type.clone(),
        opaque: chunk.is_group() && !chunk.children_parsed,
        payload_preview: payload_preview(file_data, chunk, options.preview_bytes),
        children,
    }
}

fn payload_preview(data: &[u8], chunk: &Chunk, preview_bytes: usize) -> Option<String> {
    if preview_bytes == 0 || chunk.size == 0 || chunk.form_type.is_some() {
        return None;
    }
    let end = std::cmp::min(chunk.payload_end, chunk.payload_offset + preview_bytes);
    let raw = &data[chunk.payload_offset..end];
    let text: String = raw
        .iter()
        .map(|b| {
            if (32..=126).contains(b) {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    let text = text.trim_end_matches('\0').to_string();
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        MbInspectOptions, MbParseBudget, SceneFormat, SceneToolError, inspect_mb,
        inspect_mb_with_budget, inspect_mb_with_max_parse_bytes,
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .to_path_buf()
    }

    #[test]
    fn inspect_mb_returns_chunk_tree_for_mb_input() {
        let source = repo_root().join("tests/02/sphere.mb");
        let report = inspect_mb(&source, MbInspectOptions::default()).expect("inspect");

        assert_eq!(report.scene_format, SceneFormat::Mb);
        assert!(report.root.tag == "FOR4" || report.root.tag == "FOR8");
        assert!(!report.root.children.is_empty());
    }

    #[test]
    fn inspect_mb_rejects_ma_input_explicitly() {
        let source = repo_root().join("tests/02/sphere.ma");
        let err = inspect_mb(&source, MbInspectOptions::default()).expect_err("ma rejected");

        match err {
            SceneToolError::UnsupportedSceneFormat { detected, .. } => {
                assert_eq!(detected, SceneFormat::Ma);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn inspect_mb_honors_max_depth() {
        let source = repo_root().join("tests/02/sphere.mb");
        let report = inspect_mb(
            &source,
            MbInspectOptions {
                max_depth: Some(0),
                preview_bytes: 24,
            },
        )
        .expect("inspect");

        assert!(report.root.children.is_empty());
    }

    #[test]
    fn inspect_mb_honors_preview_bytes_zero() {
        let source = repo_root().join("tests/02/sphere.mb");
        let report = inspect_mb(
            &source,
            MbInspectOptions {
                max_depth: None,
                preview_bytes: 0,
            },
        )
        .expect("inspect");

        fn assert_no_preview(node: &super::MbInspectNode) {
            assert!(node.payload_preview.is_none());
            for child in &node.children {
                assert_no_preview(child);
            }
        }

        assert_no_preview(&report.root);
    }

    #[test]
    fn inspect_mb_marks_budget_truncated_groups_as_opaque() {
        let source = repo_root().join("tests/02/sphere.mb");
        let report = inspect_mb_with_budget(
            &source,
            MbInspectOptions::default(),
            &MbParseBudget {
                max_depth: 1,
                ..MbParseBudget::default()
            },
        )
        .expect("inspect");

        assert!(report.root.children.iter().any(|child| child.opaque));
    }

    #[test]
    fn inspect_mb_with_max_parse_bytes_rejects_too_small_budget() {
        let source = repo_root().join("tests/02/sphere.mb");
        let err = inspect_mb_with_max_parse_bytes(&source, MbInspectOptions::default(), 1)
            .expect_err("budget rejection");

        match err {
            SceneToolError::MbParseBudgetExceeded { limit } => {
                assert_eq!(limit, crate::scene::MbParseBudgetLimit::MaxParseBytes);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
