mod addattr_semantics;
pub mod byte_span;
mod error;
pub mod ma;
pub mod maya_defaults;
pub mod mb;
pub mod mel;
mod model;
pub mod reference_semantics;
mod replace_rules;
mod typed_value_semantics;
pub mod unit_semantics;

pub(crate) use ma::types::{PathReplaceMode, PathReplaceRule, ScenePathEntry, ScenePathMeta};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathReplaceSkips {
    pub non_utf8: usize,
    pub non_canonical_escape: usize,
    pub unrepresentable: usize,
    pub crosses_concat_boundary: usize,
    pub unterminated_tail: usize,
    pub unterminated_tail_from: Option<usize>,
    pub payload_rejected: Option<usize>,
    pub unmatched_locator: Option<usize>,
    pub duplicate_request: Option<usize>,
}

impl PathReplaceSkips {
    pub fn binary() -> Self {
        Self {
            payload_rejected: Some(0),
            unmatched_locator: Some(0),
            duplicate_request: Some(0),
            ..Self::default()
        }
    }

    pub fn total(&self) -> usize {
        self.non_utf8
            + self.non_canonical_escape
            + self.unrepresentable
            + self.crosses_concat_boundary
            + self.unterminated_tail
            + self.payload_rejected.unwrap_or(0)
            + self.unmatched_locator.unwrap_or(0)
            + self.duplicate_request.unwrap_or(0)
    }
}

impl serde::Serialize for PathReplaceSkips {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let ascii = self.payload_rejected.is_none();
        let mut state = serializer.serialize_struct("PathReplaceSkips", 9)?;
        state.serialize_field("non_utf8", &self.non_utf8)?;
        state.serialize_field(
            "non_canonical_escape",
            &ascii.then_some(self.non_canonical_escape),
        )?;
        state.serialize_field("unrepresentable", &ascii.then_some(self.unrepresentable))?;
        state.serialize_field(
            "crosses_concat_boundary",
            &ascii.then_some(self.crosses_concat_boundary),
        )?;
        state.serialize_field(
            "unterminated_tail",
            &ascii.then_some(self.unterminated_tail),
        )?;
        state.serialize_field("unterminated_tail_from", &self.unterminated_tail_from)?;
        state.serialize_field("payload_rejected", &self.payload_rejected)?;
        state.serialize_field("unmatched_locator", &self.unmatched_locator)?;
        state.serialize_field("duplicate_request", &self.duplicate_request)?;
        state.end()
    }
}
