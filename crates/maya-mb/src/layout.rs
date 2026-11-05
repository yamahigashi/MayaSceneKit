pub(crate) use crate::defaults::{EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE};
use crate::defaults::{resolve_parser_group_defaults, resolve_section_layout_defaults};
use crate::{FourCC, HeaderFormat};
use std::num::NonZeroUsize;

/// Independent, optional hints for a chunk section.
/// Unspecified hints leave a section unscanned. FOR8/Maya uses alignment 4
/// with an eight-byte size field, so alignment and header format are independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayoutHints {
    alignment: Option<NonZeroUsize>,
    header_format: Option<HeaderFormat>,
}

impl LayoutHints {
    /// Creates hints with neither component specified.
    pub const fn new() -> Self {
        Self {
            alignment: None,
            header_format: None,
        }
    }
    /// Sets any positive alignment without changing the header hint.
    pub const fn with_alignment(mut self, alignment: NonZeroUsize) -> Self {
        self.alignment = Some(alignment);
        self
    }
    /// Sets the header hint without changing the alignment hint.
    pub const fn with_header_format(mut self, header_format: HeaderFormat) -> Self {
        self.header_format = Some(header_format);
        self
    }
    /// Returns the optional nonzero alignment.
    pub const fn alignment(self) -> Option<NonZeroUsize> {
        self.alignment
    }
    /// Returns the optional header format.
    pub const fn header_format(self) -> Option<HeaderFormat> {
        self.header_format
    }
    /// Normalizes numeric hints independently: zero alignment and header sizes
    /// other than 8 or 16 become unspecified.
    pub const fn from_numeric(alignment: Option<usize>, header_size: Option<usize>) -> Self {
        let alignment = match alignment {
            Some(value) => NonZeroUsize::new(value),
            None => None,
        };
        let header_format = match header_size {
            Some(value) => HeaderFormat::from_header_size(value),
            None => None,
        };
        Self {
            alignment,
            header_format,
        }
    }
}

/// A resolved chunk layout with any positive alignment and an independent header.
/// For example, FOR8/Maya children have alignment 4 and an eight-byte size field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLayout {
    alignment: NonZeroUsize,
    header_format: HeaderFormat,
}

impl ChunkLayout {
    /// Creates a layout without restricting alignment to powers of two.
    pub const fn new(alignment: NonZeroUsize, header_format: HeaderFormat) -> Self {
        Self {
            alignment,
            header_format,
        }
    }
    /// Returns the nonzero alignment.
    pub const fn alignment(self) -> NonZeroUsize {
        self.alignment
    }
    /// Returns the header format.
    pub const fn header_format(self) -> HeaderFormat {
        self.header_format
    }
    /// Returns the alignment as a positive integer.
    pub const fn alignment_usize(self) -> usize {
        self.alignment.get()
    }
}

/// Converts a resolved layout into hints without losing either component.
impl From<ChunkLayout> for LayoutHints {
    fn from(layout: ChunkLayout) -> Self {
        LayoutHints::new()
            .with_alignment(layout.alignment())
            .with_header_format(layout.header_format())
    }
}

pub(crate) fn is_group_chunk_tag(tag: FourCC) -> bool {
    tag.is_group()
}

/// Fills missing hints from a printable group suffix, preserving explicit hints.
/// FOR8/Maya defaults to alignment 4 and an eight-byte size field.
pub fn resolve_section_layout_hints(
    chunk_tag: FourCC,
    form_type: Option<FourCC>,
    hints: LayoutHints,
) -> LayoutHints {
    resolve_section_layout_defaults(chunk_tag, form_type, hints)
}

pub(crate) fn resolve_parser_group_layout(
    chunk_tag: FourCC,
    form_type: Option<FourCC>,
    fallback_header_format: HeaderFormat,
) -> ChunkLayout {
    resolve_parser_group_defaults(chunk_tag, form_type, fallback_header_format)
}

#[cfg(test)]
mod tests {
    use super::{
        EIGHT_BYTE_HEADER_SIZE, FOUR_BYTE_HEADER_SIZE, is_group_chunk_tag,
        resolve_parser_group_layout, resolve_section_layout_hints,
    };
    use crate::{FourCC, HeaderFormat, LayoutHints};
    use std::num::NonZeroUsize;

    #[test]
    fn group_tag_detection_is_explicit() {
        assert!(is_group_chunk_tag(FourCC::new(*b"FOR4")));
        assert!(is_group_chunk_tag(FourCC::new(*b"FOR8")));
        assert!(is_group_chunk_tag(FourCC::new(*b"CAT4")));
        assert!(is_group_chunk_tag(FourCC::new(*b"CAT8")));
        assert!(is_group_chunk_tag(FourCC::new(*b"LIS4")));
        assert!(is_group_chunk_tag(FourCC::new(*b"LIS8")));
        assert!(!is_group_chunk_tag(FourCC::new(*b"ABCD")));
        assert!(!is_group_chunk_tag(FourCC::new(*b"FORM")));
    }

    #[test]
    fn section_layout_keeps_explicit_hints() {
        let hints = resolve_section_layout_hints(
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
    fn section_layout_infers_for4_defaults() {
        let hints = resolve_section_layout_hints(FourCC::new(*b"FOR4"), None, LayoutHints::new());
        let alignment = hints.alignment().map(|a| a.get());
        let header_size = hints.header_format().map(|f| f.header_size());
        assert_eq!(alignment, Some(4));
        assert_eq!(header_size, Some(FOUR_BYTE_HEADER_SIZE));
    }

    #[test]
    fn section_layout_for4_preserves_explicit_eight_byte_header() {
        let hints = resolve_section_layout_hints(
            FourCC::new(*b"FOR4"),
            None,
            LayoutHints::new().with_header_format(HeaderFormat::EightByte),
        );

        assert_eq!(hints.alignment().map(|alignment| alignment.get()), Some(4));
        assert_eq!(hints.header_format(), Some(HeaderFormat::EightByte));
    }

    #[test]
    fn section_layout_infers_for8_maya_alignment() {
        let hints = resolve_section_layout_hints(
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
    fn section_layout_infers_for8_non_maya_alignment() {
        let hints = resolve_section_layout_hints(
            FourCC::new(*b"FOR8"),
            Some(FourCC::new(*b"ABCD")),
            LayoutHints::new(),
        );
        let alignment = hints.alignment().map(|a| a.get());
        let header_size = hints.header_format().map(|f| f.header_size());
        assert_eq!(alignment, Some(8));
        assert_eq!(header_size, Some(EIGHT_BYTE_HEADER_SIZE));
    }

    #[test]
    fn parser_group_layout_uses_fallback_header_for_unknown_tag() {
        let layout = resolve_parser_group_layout(
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
    fn parser_group_layout_uses_maya_for8_alignment_override() {
        let layout = resolve_parser_group_layout(
            FourCC::new(*b"FOR8"),
            Some(FourCC::new(*b"Maya")),
            HeaderFormat::FourByte,
        );
        let alignment = layout.alignment_usize();
        let header_size = layout.header_format().header_size();
        assert_eq!(alignment, 4);
        assert_eq!(header_size, 8);
    }

    #[test]
    fn layout_hints_numeric_boundary() {
        assert_eq!(LayoutHints::new(), LayoutHints::default());
        const HINTS: LayoutHints = LayoutHints::new()
            .with_alignment(NonZeroUsize::new(3).unwrap())
            .with_header_format(HeaderFormat::EightByte);
        const ALIGNMENT: Option<NonZeroUsize> = HINTS.alignment();
        const HEADER: Option<HeaderFormat> = HINTS.header_format();
        const NUMERIC: LayoutHints = LayoutHints::from_numeric(Some(3), Some(16));
        assert_eq!(ALIGNMENT.map(|a| a.get()), Some(3));
        assert_eq!(HEADER, Some(HeaderFormat::EightByte));
        assert_eq!(NUMERIC, HINTS);
        let updated = HINTS.with_alignment(NonZeroUsize::new(1).unwrap());
        assert_eq!(updated.alignment().unwrap().get(), 1);
        assert_eq!(updated.header_format(), HEADER);
        let updated = HINTS.with_header_format(HeaderFormat::FourByte);
        assert_eq!(updated.alignment(), ALIGNMENT);
        assert_eq!(updated.header_format(), Some(HeaderFormat::FourByte));

        for alignment in [None, Some(0), Some(1), Some(3), Some(4), Some(8), Some(16)] {
            for header_size in [
                None,
                Some(0),
                Some(8),
                Some(12),
                Some(16),
                Some(20),
                Some(24),
            ] {
                let hints = LayoutHints::from_numeric(alignment, header_size);
                assert_eq!(
                    hints.alignment().map(|a| a.get()),
                    alignment.filter(|a| *a != 0)
                );
                let expected = match header_size {
                    Some(8) => Some(HeaderFormat::FourByte),
                    Some(16) => Some(HeaderFormat::EightByte),
                    _ => None,
                };
                assert_eq!(hints.header_format(), expected);
            }
        }
    }

    #[test]
    fn chunk_layout_preserves_independent_components() {
        use crate::ChunkLayout;
        const LAYOUT: ChunkLayout =
            ChunkLayout::new(NonZeroUsize::new(4).unwrap(), HeaderFormat::EightByte);
        const ALIGNMENT: NonZeroUsize = LAYOUT.alignment();
        const HEADER: HeaderFormat = LAYOUT.header_format();
        const NUMERIC: usize = LAYOUT.alignment_usize();
        assert_eq!(ALIGNMENT.get(), 4);
        assert_eq!(HEADER, HeaderFormat::EightByte);
        assert_eq!(NUMERIC, 4);
        for alignment in [1, 3, 4, 8, 16] {
            for header_format in [HeaderFormat::FourByte, HeaderFormat::EightByte] {
                let layout = ChunkLayout::new(NonZeroUsize::new(alignment).unwrap(), header_format);
                let copied = layout;
                let cloned = Clone::clone(&layout);
                assert_eq!(copied, layout);
                assert_eq!(cloned, layout);
                assert_eq!(layout.alignment().get(), alignment);
                assert_eq!(layout.alignment_usize(), alignment);
                assert_eq!(layout.header_format(), header_format);
            }
        }
        assert_ne!(
            LAYOUT,
            ChunkLayout::new(NonZeroUsize::new(8).unwrap(), HeaderFormat::FourByte)
        );
    }

    #[test]
    fn layout_resolution_preserves_partial_hints() {
        for (tag, form, default_alignment, default_header) in [
            (*b"FOR4", None, Some(4), Some(8)),
            (*b"FOR8", Some(FourCC::new(*b"Maya")), Some(4), Some(16)),
            (*b"FOR8", Some(FourCC::new(*b"TEST")), Some(8), Some(16)),
            (*b"DATA", None, None, None),
        ] {
            for alignment in [None, Some(3)] {
                for header in [None, Some(8)] {
                    let hints = resolve_section_layout_hints(
                        FourCC::new(tag),
                        form,
                        LayoutHints::from_numeric(alignment, header),
                    );
                    assert_eq!(
                        hints.alignment().map(|a| a.get()),
                        alignment.or(default_alignment)
                    );
                    assert_eq!(
                        hints.header_format().map(|f| f.header_size()),
                        header.or(default_header)
                    );
                }
            }
        }
        let hints = LayoutHints::from_numeric(Some(16), Some(24));
        assert_eq!(hints.alignment().unwrap().get(), 16);
        assert_eq!(hints.header_format(), None);
        let hints =
            resolve_section_layout_hints(FourCC::new(*b"FOR8"), Some(FourCC::new(*b"Maya")), hints);
        assert_eq!(hints.alignment().unwrap().get(), 16);
        assert_eq!(hints.header_format(), Some(HeaderFormat::EightByte));
        let zero = LayoutHints::from_numeric(Some(0), Some(16));
        assert_eq!(zero.alignment(), None);
        let resolved =
            resolve_section_layout_hints(FourCC::new(*b"FOR8"), Some(FourCC::new(*b"Maya")), zero);
        assert_eq!(resolved.alignment().unwrap().get(), 4);
    }
}
