mod composite;
pub use composite::{
    MbOriginalEdits, MbPayloadEdit, MbPayloadLocator, MbPlanError, apply_mb_original_edits,
    collect_mb_plugin_require_records, locate_mb_path_owner_forms, validate_mb_original_edits,
};
mod attr_payload;
mod path_rewrite;

pub(crate) use maya_mb::{encode_chunk, encode_root_chunk};

pub use self::path_rewrite::{
    MbPathCandidatePlan, MbPathChange, MbPathChanges, MbPathReplaceRule, MbPathStatus,
    collect_mb_path_candidates, plan_mb_path_value, replace_scene_paths_in_mb,
    replace_scene_paths_in_mb_by_index, replace_scene_paths_in_mb_by_index_cow,
    replace_scene_paths_in_mb_cow,
};

#[derive(Debug, Clone)]
pub enum MbRewriteError {
    IncompleteTree(crate::mb::MbCompleteness),
    SectionScanStopped,
    SectionEncode(crate::mb::EncodeError),
    ChildEncode(crate::mb::EncodeError),
    RootEncode(crate::mb::EncodeError),
    Parse(crate::mb::MayaBinaryParseError),
}

impl std::fmt::Display for MbRewriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SectionEncode(error) => write!(f, "cannot encode MB section: {error}"),
            Self::ChildEncode(error) => write!(f, "cannot encode MB child: {error}"),
            Self::RootEncode(error) => write!(f, "cannot encode MB root: {error}"),
            Self::IncompleteTree(completeness) => write!(
                f,
                "cannot rewrite incomplete Maya Binary tree: {completeness}"
            ),
            Self::Parse(error) => write!(f, "cannot rewrite Maya Binary: {error}"),
            Self::SectionScanStopped => {
                f.write_str("cannot rewrite Maya Binary: MB section scan stopped")
            }
        }
    }
}
impl std::error::Error for MbRewriteError {}

pub fn require_complete_mb_tree(root: &crate::mb::Chunk) -> Result<(), MbRewriteError> {
    match root.completeness() {
        crate::mb::MbCompleteness::Complete => Ok(()),
        completeness => Err(MbRewriteError::IncompleteTree(completeness)),
    }
}

pub fn require_complete_mb_sections(
    data: &[u8],
    root: &crate::mb::Chunk,
) -> Result<(), MbRewriteError> {
    require_complete_mb_tree(root)?;
    if root
        .scan_root_sections(
            data,
            root.section_budget()
                .unwrap_or(&crate::mb::MbParseBudget::default()),
        )
        .map_err(MbRewriteError::Parse)?
        == crate::mb::MbSectionScanState::Stopped
    {
        return Err(MbRewriteError::SectionScanStopped);
    }
    Ok(())
}

pub(crate) fn child_span_end(root: &crate::mb::Chunk, child: &crate::mb::Chunk) -> usize {
    let alignment = root
        .child_layout()
        .map_or(1, |layout| layout.alignment_usize());
    let padding = (alignment - child.size() % alignment) % alignment;
    child
        .payload_end()
        .saturating_add(padding)
        .min(root.payload_end())
}
