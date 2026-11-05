use std::{fmt, str::FromStr};

use thiserror::Error;

/// A four-byte chunk tag or form identifier, preserving its original bytes.
///
/// Display uses printable ASCII or eight uppercase hexadecimal digits in brackets.
/// String parsing and equality use UTF-8 bytes and require exactly four bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FourCC([u8; 4]);

impl FourCC {
    /// Whether this tag is one of FOR4, FOR8, CAT4, CAT8, LIS4, or LIS8.
    pub fn is_group(&self) -> bool {
        matches!(
            self.as_ascii(),
            Some("FOR4") | Some("FOR8") | Some("CAT4") | Some("CAT8") | Some("LIS4") | Some("LIS8")
        )
    }

    /// Creates an identifier from exactly four bytes, without content restrictions.
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Returns the original four bytes.
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Returns text only when all four bytes are printable ASCII (0x20 through 0x7E).
    pub fn as_ascii(&self) -> Option<&str> {
        if self.0.iter().all(|b| (0x20..=0x7E).contains(b)) {
            std::str::from_utf8(&self.0).ok()
        } else {
            None
        }
    }
}

impl From<[u8; 4]> for FourCC {
    fn from(bytes: [u8; 4]) -> Self {
        Self::new(bytes)
    }
}

impl From<FourCC> for [u8; 4] {
    fn from(tag: FourCC) -> Self {
        tag.0
    }
}

impl AsRef<[u8]> for FourCC {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for FourCC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(text) = self.as_ascii() {
            f.write_str(text)
        } else {
            write!(
                f,
                "[{:02X}{:02X}{:02X}{:02X}]",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        }
    }
}

impl fmt::Debug for FourCC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FourCC({self})")
    }
}

impl PartialEq<str> for FourCC {
    fn eq(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl PartialEq<&str> for FourCC {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<FourCC> for str {
    fn eq(&self, other: &FourCC) -> bool {
        other == self
    }
}

impl PartialEq<FourCC> for &str {
    fn eq(&self, other: &FourCC) -> bool {
        other == *self
    }
}

/// An error for a string whose UTF-8 byte length is not four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("FourCC requires exactly 4 bytes, got {len} bytes")]
pub struct FourCCParseError {
    len: usize,
}

impl FourCCParseError {
    /// Returns the rejected string's UTF-8 byte length.
    #[expect(
        clippy::len_without_is_empty,
        reason = "This reports the rejected input length, not a collection length."
    )]
    pub fn len(&self) -> usize {
        self.len
    }
}

impl FromStr for FourCC {
    type Err = FourCCParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s
            .as_bytes()
            .try_into()
            .map_err(|_| FourCCParseError { len: s.len() })?;
        Ok(Self::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::FourCC;

    #[test]
    fn is_group_accepts_only_supported_group_tags() {
        for bytes in [*b"FOR4", *b"FOR8", *b"CAT4", *b"CAT8", *b"LIS4", *b"LIS8"] {
            let tag = FourCC::new(bytes);
            assert!(tag.is_group(), "{tag}");
        }
        for bytes in [
            *b"FORM",
            *b"ABCD",
            *b"ABC4",
            *b"ABC8",
            *b"FOR2",
            [0x00, 0x01, 0x7F, 0xFF],
        ] {
            let tag = FourCC::new(bytes);
            assert!(!tag.is_group(), "{tag}");
        }
    }

    #[test]
    fn printable_tag() {
        let tag = FourCC::new(*b"FOR8");
        assert_eq!(tag.to_string(), "FOR8");
        assert_eq!(tag.as_ascii(), Some("FOR8"));
        assert_eq!(tag, "FOR8");
        assert_eq!("FOR8", tag);
    }

    #[test]
    fn non_printable_tag() {
        let tag = FourCC::new([0x00, 0x01, 0x7F, 0xFF]);
        assert_eq!(tag.to_string(), "[00017FFF]");
        assert_eq!(tag.as_ascii(), None);
        assert_eq!(format!("{tag:?}"), "FourCC([00017FFF])");
    }

    #[test]
    fn printable_boundaries() {
        assert_eq!(FourCC::new([0x20; 4]).as_ascii(), Some("    "));
        assert_eq!(FourCC::new([0x7E; 4]).as_ascii(), Some("~~~~"));
        assert_eq!(FourCC::new([0x1F; 4]).as_ascii(), None);
        assert_eq!(FourCC::new([0x7F; 4]).as_ascii(), None);
    }

    #[test]
    fn mixed_bytes_require_all_printable_ascii() {
        assert_eq!(FourCC::new([0x41, 0x42, 0x43, 0x00]).as_ascii(), None);
        assert_eq!(FourCC::new([0x00, 0x41, 0x42, 0x43]).as_ascii(), None);
        assert_eq!(
            FourCC::new([0x41, 0x42, 0x43, 0x7E]).as_ascii(),
            Some("ABC~")
        );
    }

    #[test]
    fn string_equality_requires_exact_raw_bytes() {
        let tag = FourCC::new(*b"FOR8");
        assert_ne!(tag, "FOR");
        assert_ne!(tag, "FOR88");
        assert_ne!(tag, "FOR9");
        assert_ne!(FourCC::new([0x00, 0x01, 0x7F, 0xFF]), "[00017FFF]");
        let s: &str = "FOR8";
        assert!(*s == tag);
    }

    #[test]
    fn parsing_uses_utf8_byte_length() {
        let tag = "éAB".parse::<FourCC>().unwrap();
        assert_eq!(tag, "éAB");
        assert_eq!("éAB", tag);
        let error = "ABC".parse::<FourCC>().unwrap_err();
        assert_eq!(error.len(), 3);
        assert_eq!(
            error.to_string(),
            "FourCC requires exactly 4 bytes, got 3 bytes"
        );
        assert_eq!("ABCDE".parse::<FourCC>().unwrap_err().len(), 5);
        assert_eq!("[00017FFF]".parse::<FourCC>().unwrap_err().len(), 10);
    }

    #[test]
    fn layout_suffix_requires_printable_tag() {
        for bytes in [[0x00, 0x41, 0x42, 0x34], [0x00, 0x41, 0x42, 0x38]] {
            assert_eq!(
                crate::resolve_section_layout_hints(
                    FourCC::new(bytes),
                    None,
                    crate::LayoutHints::new()
                ),
                crate::LayoutHints::new()
            );
        }
        assert_eq!(
            crate::resolve_section_layout_hints(
                FourCC::new(*b"FOR4"),
                None,
                crate::LayoutHints::new()
            ),
            crate::LayoutHints::from_numeric(Some(4), Some(8))
        );
    }
}
