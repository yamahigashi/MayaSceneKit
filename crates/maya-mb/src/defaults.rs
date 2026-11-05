use crate::{ChunkLayout, FourCC, HeaderFormat, LayoutHints};
use std::num::NonZeroUsize;

pub(crate) const FOUR_BYTE_HEADER_SIZE: usize = 8;
pub(crate) const EIGHT_BYTE_HEADER_SIZE: usize = 16;

pub(crate) fn resolve_section_layout_defaults(
    chunk_tag: FourCC,
    form_type: Option<FourCC>,
    mut hints: LayoutHints,
) -> LayoutHints {
    if hints.alignment().is_some() && hints.header_format().is_some() {
        return hints;
    }

    if chunk_tag.as_ascii().is_some_and(|s| s.ends_with('4')) {
        if hints.alignment().is_none() {
            hints = hints.with_alignment(NonZeroUsize::new(4).expect("nonzero alignment"));
        }
        if hints.header_format().is_none() {
            hints = hints.with_header_format(HeaderFormat::FourByte);
        }
        return hints;
    }
    if chunk_tag.as_ascii().is_some_and(|s| s.ends_with('8')) {
        if hints.alignment().is_none() {
            hints = hints.with_alignment(default_group_alignment(chunk_tag, form_type));
        }
        if hints.header_format().is_none() {
            hints = hints.with_header_format(HeaderFormat::EightByte);
        }
        return hints;
    }
    hints
}

pub(crate) fn resolve_parser_group_defaults(
    chunk_tag: FourCC,
    form_type: Option<FourCC>,
    fallback_header_format: HeaderFormat,
) -> ChunkLayout {
    let hints = resolve_section_layout_defaults(
        chunk_tag,
        form_type,
        LayoutHints::new().with_header_format(fallback_header_format),
    );
    ChunkLayout::new(
        default_group_alignment(chunk_tag, form_type),
        hints.header_format().unwrap_or(fallback_header_format),
    )
}

pub(crate) fn default_header_format_for_alignment(alignment: NonZeroUsize) -> HeaderFormat {
    if alignment.get() >= 8 {
        HeaderFormat::EightByte
    } else {
        HeaderFormat::FourByte
    }
}

pub(crate) fn default_alignment_for_header_format(header_format: HeaderFormat) -> NonZeroUsize {
    match header_format {
        HeaderFormat::FourByte => NonZeroUsize::new(4).expect("nonzero alignment"),
        HeaderFormat::EightByte => NonZeroUsize::new(8).expect("nonzero alignment"),
    }
}

fn default_group_alignment(chunk_tag: FourCC, form_type: Option<FourCC>) -> NonZeroUsize {
    if chunk_tag.as_ascii().is_some_and(|s| s.ends_with('8')) {
        if form_type.is_some_and(|f| f == "Maya") {
            NonZeroUsize::new(4).expect("nonzero alignment")
        } else {
            NonZeroUsize::new(8).expect("nonzero alignment")
        }
    } else {
        NonZeroUsize::new(4).expect("nonzero alignment")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE, default_alignment_for_header_format,
        default_header_format_for_alignment, resolve_parser_group_defaults,
        resolve_section_layout_defaults,
    };
    use crate::{FourCC, HeaderFormat, LayoutHints};
    use std::num::NonZeroUsize;

    #[test]
    fn section_layout_defaults_keep_explicit_hints() {
        let hints = resolve_section_layout_defaults(
            FourCC::new(*b"FOR8"),
            Some(FourCC::new(*b"Maya")),
            LayoutHints::new()
                .with_alignment(NonZeroUsize::new(16).unwrap())
                .with_header_format(HeaderFormat::FourByte),
        );
        let alignment = hints.alignment().map(|a| a.get());
        let header_size = hints.header_format().map(|f| f.header_size());
        assert_eq!(alignment, Some(16));
        assert_eq!(header_size, Some(8));
    }

    #[test]
    fn section_layout_defaults_infer_for8_maya_alignment() {
        let hints = resolve_section_layout_defaults(
            FourCC::new(*b"FOR8"),
            Some(FourCC::new(*b"Maya")),
            LayoutHints::new(),
        );
        let alignment = hints.alignment().map(|a| a.get());
        let header_size = hints.header_format().map(|f| f.header_size());
        assert_eq!(alignment, Some(4));
        assert_eq!(header_size, Some(EIGHT_BYTE_HEADER_SIZE));
    }

    #[test]
    fn parser_group_defaults_fallback_to_four_byte_alignment() {
        let layout = resolve_parser_group_defaults(
            FourCC::new(*b"ABCD"),
            Some(FourCC::new(*b"Maya")),
            HeaderFormat::EightByte,
        );
        let alignment = layout.alignment_usize();
        let header_size = layout.header_format().header_size();
        assert_eq!(alignment, 4);
        assert_eq!(header_size, 16);
    }

    #[test]
    fn default_size_and_alignment_round_trip() {
        assert_eq!(
            default_header_format_for_alignment(NonZeroUsize::new(4).unwrap()).header_size(),
            FOUR_BYTE_HEADER_SIZE
        );
        assert_eq!(
            default_header_format_for_alignment(NonZeroUsize::new(8).unwrap()).header_size(),
            EIGHT_BYTE_HEADER_SIZE
        );
        assert_eq!(
            default_alignment_for_header_format(HeaderFormat::FourByte).get(),
            4
        );
        assert_eq!(
            default_alignment_for_header_format(HeaderFormat::EightByte).get(),
            8
        );
    }
}
