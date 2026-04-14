pub(crate) use crate::mb::defaults::{
    EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE, header_size_to_width,
};
use crate::mb::defaults::{resolve_parser_group_defaults, resolve_section_layout_defaults};

pub(crate) fn is_group_chunk_tag(tag: &str) -> bool {
    matches!(tag, "FOR4" | "FOR8" | "CAT4" | "CAT8" | "LIS4" | "LIS8")
}

pub fn resolve_section_layout_hints(
    chunk_tag: &str,
    form_type: Option<&str>,
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> (Option<usize>, Option<usize>) {
    resolve_section_layout_defaults(chunk_tag, form_type, child_alignment, child_header_size)
}

pub(crate) fn resolve_parser_group_layout(
    chunk_tag: &str,
    form_type: Option<&str>,
    fallback_header_size: usize,
) -> (usize, usize) {
    resolve_parser_group_defaults(chunk_tag, form_type, fallback_header_size)
}

#[cfg(test)]
mod tests {
    use super::{
        EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE, is_group_chunk_tag,
        resolve_parser_group_layout, resolve_section_layout_hints,
    };

    #[test]
    fn group_tag_detection_is_explicit() {
        assert!(is_group_chunk_tag("FOR4"));
        assert!(is_group_chunk_tag("FOR8"));
        assert!(is_group_chunk_tag("CAT4"));
        assert!(is_group_chunk_tag("CAT8"));
        assert!(is_group_chunk_tag("LIS4"));
        assert!(is_group_chunk_tag("LIS8"));
        assert!(!is_group_chunk_tag("ABCD"));
        assert!(!is_group_chunk_tag("FORM"));
    }

    #[test]
    fn section_layout_keeps_explicit_hints() {
        let (alignment, header_size) =
            resolve_section_layout_hints("FOR8", Some("Maya"), Some(16), Some(24));
        assert_eq!(alignment, Some(16));
        assert_eq!(header_size, Some(24));
    }

    #[test]
    fn section_layout_infers_for4_defaults() {
        let (alignment, header_size) = resolve_section_layout_hints("FOR4", None, None, None);
        assert_eq!(alignment, Some(4));
        assert_eq!(header_size, Some(FOUR_BYTE_HEADER_SIZE));
    }

    #[test]
    fn section_layout_infers_for8_maya_alignment() {
        let (alignment, header_size) =
            resolve_section_layout_hints("FOR8", Some("Maya"), None, None);
        assert_eq!(alignment, Some(4));
        assert_eq!(header_size, Some(EIGHT_BYTE_HEADER_SIZE));
    }

    #[test]
    fn section_layout_infers_for8_non_maya_alignment() {
        let (alignment, header_size) =
            resolve_section_layout_hints("FOR8", Some("ABCD"), None, None);
        assert_eq!(alignment, Some(8));
        assert_eq!(header_size, Some(EIGHT_BYTE_HEADER_SIZE));
    }

    #[test]
    fn parser_group_layout_uses_fallback_header_for_unknown_tag() {
        let (alignment, header_size) = resolve_parser_group_layout("ABCD", Some("Maya"), 12);
        assert_eq!(alignment, 4);
        assert_eq!(header_size, 12);
    }

    #[test]
    fn parser_group_layout_uses_maya_for8_alignment_override() {
        let (alignment, header_size) = resolve_parser_group_layout("FOR8", Some("Maya"), 20);
        assert_eq!(alignment, 4);
        assert_eq!(header_size, 20);
    }
}
