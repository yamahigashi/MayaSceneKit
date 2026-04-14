pub(crate) const FOUR_BYTE_HEADER_SIZE: usize = 8;
pub(crate) const EIGHT_BYTE_HEADER_SIZE: usize = 16;

pub(crate) fn header_size_to_width(header_size: usize) -> Option<usize> {
    match header_size {
        FOUR_BYTE_HEADER_SIZE => Some(4),
        EIGHT_BYTE_HEADER_SIZE => Some(8),
        _ => None,
    }
}

pub(crate) fn resolve_section_layout_defaults(
    chunk_tag: &str,
    form_type: Option<&str>,
    child_alignment: Option<usize>,
    child_header_size: Option<usize>,
) -> (Option<usize>, Option<usize>) {
    if child_alignment.is_some() && child_header_size.is_some() {
        return (child_alignment, child_header_size);
    }

    if chunk_tag.ends_with('4') {
        return (
            child_alignment.or(Some(4)),
            child_header_size.or(Some(FOUR_BYTE_HEADER_SIZE)),
        );
    }
    if chunk_tag.ends_with('8') {
        return (
            child_alignment.or(Some(default_group_alignment(chunk_tag, form_type))),
            child_header_size.or(Some(EIGHT_BYTE_HEADER_SIZE)),
        );
    }

    (child_alignment, child_header_size)
}

pub(crate) fn resolve_parser_group_defaults(
    chunk_tag: &str,
    form_type: Option<&str>,
    fallback_header_size: usize,
) -> (usize, usize) {
    let (_, header_size_hint) =
        resolve_section_layout_defaults(chunk_tag, form_type, None, Some(fallback_header_size));
    let header_size = header_size_hint.unwrap_or(fallback_header_size);
    (default_group_alignment(chunk_tag, form_type), header_size)
}

pub(crate) fn default_header_size_for_alignment(alignment: usize) -> usize {
    if alignment >= 8 {
        EIGHT_BYTE_HEADER_SIZE
    } else {
        FOUR_BYTE_HEADER_SIZE
    }
}

pub(crate) fn default_alignment_for_header_size(header_size: usize) -> usize {
    header_size_to_width(header_size).unwrap_or(4)
}

fn default_group_alignment(chunk_tag: &str, form_type: Option<&str>) -> usize {
    if chunk_tag.ends_with('8') {
        if form_type == Some("Maya") { 4 } else { 8 }
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE, default_alignment_for_header_size,
        default_header_size_for_alignment, resolve_parser_group_defaults,
        resolve_section_layout_defaults,
    };

    #[test]
    fn section_layout_defaults_keep_explicit_hints() {
        let (alignment, header_size) =
            resolve_section_layout_defaults("FOR8", Some("Maya"), Some(16), Some(24));
        assert_eq!(alignment, Some(16));
        assert_eq!(header_size, Some(24));
    }

    #[test]
    fn section_layout_defaults_infer_for8_maya_alignment() {
        let (alignment, header_size) =
            resolve_section_layout_defaults("FOR8", Some("Maya"), None, None);
        assert_eq!(alignment, Some(4));
        assert_eq!(header_size, Some(EIGHT_BYTE_HEADER_SIZE));
    }

    #[test]
    fn parser_group_defaults_fallback_to_four_byte_alignment() {
        let (alignment, header_size) = resolve_parser_group_defaults("ABCD", Some("Maya"), 12);
        assert_eq!(alignment, 4);
        assert_eq!(header_size, 12);
    }

    #[test]
    fn default_size_and_alignment_round_trip() {
        assert_eq!(default_header_size_for_alignment(4), FOUR_BYTE_HEADER_SIZE);
        assert_eq!(default_header_size_for_alignment(8), EIGHT_BYTE_HEADER_SIZE);
        assert_eq!(default_alignment_for_header_size(FOUR_BYTE_HEADER_SIZE), 4);
        assert_eq!(default_alignment_for_header_size(EIGHT_BYTE_HEADER_SIZE), 8);
    }
}
