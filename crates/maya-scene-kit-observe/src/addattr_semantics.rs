use crate::model::AddAttrValueSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddAttrTailSemantics {
    None,
    Numeric,
    Enum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddAttrAngularSemantics {
    None,
    Scalar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddAttrSemantics {
    tail: AddAttrTailSemantics,
    angular: AddAttrAngularSemantics,
}

impl AddAttrSemantics {
    pub(crate) fn allows_numeric_tail(self) -> bool {
        !matches!(self.tail, AddAttrTailSemantics::None)
    }

    pub(crate) fn allows_enum_names(self) -> bool {
        matches!(self.tail, AddAttrTailSemantics::Enum)
    }

    #[cfg(test)]
    pub(crate) fn allows_explicit_default_min_max(self) -> bool {
        self.allows_numeric_tail()
    }

    #[cfg(test)]
    pub(crate) fn allows_soft_range(self) -> bool {
        matches!(self.tail, AddAttrTailSemantics::Numeric)
    }

    pub(crate) fn allows_nice_name(self) -> bool {
        !self.allows_enum_names()
    }

    pub(crate) fn angular_semantics(self) -> AddAttrAngularSemantics {
        self.angular
    }
}

pub(crate) fn add_attr_semantics(value_spec: &AddAttrValueSpec) -> AddAttrSemantics {
    let (tail, angular) = match value_spec {
        AddAttrValueSpec::AttrType(attr_type) => match attr_type.as_str() {
            "double" | "float" | "long" | "short" | "doubleLinear" | "bool" => {
                (AddAttrTailSemantics::Numeric, AddAttrAngularSemantics::None)
            }
            "doubleAngle" | "floatAngle" => (
                AddAttrTailSemantics::Numeric,
                AddAttrAngularSemantics::Scalar,
            ),
            "enum" => (AddAttrTailSemantics::Enum, AddAttrAngularSemantics::None),
            _ => (AddAttrTailSemantics::None, AddAttrAngularSemantics::None),
        },
        AddAttrValueSpec::DataType(_) | AddAttrValueSpec::UnknownToken { .. } => {
            (AddAttrTailSemantics::None, AddAttrAngularSemantics::None)
        }
    };
    AddAttrSemantics { tail, angular }
}

#[cfg(test)]
mod tests {
    use super::{AddAttrAngularSemantics, add_attr_semantics};
    use crate::model::AddAttrValueSpec;

    #[test]
    fn enum_uses_enum_tail_semantics() {
        let semantics = add_attr_semantics(&AddAttrValueSpec::AttrType("enum".to_string()));
        assert!(semantics.allows_numeric_tail());
        assert!(semantics.allows_enum_names());
        assert!(!semantics.allows_nice_name());
        assert!(!semantics.allows_soft_range());
    }

    #[test]
    fn bool_uses_numeric_tail_semantics() {
        let semantics = add_attr_semantics(&AddAttrValueSpec::AttrType("bool".to_string()));
        assert!(semantics.allows_numeric_tail());
        assert!(semantics.allows_explicit_default_min_max());
        assert!(semantics.allows_soft_range());
        assert!(!semantics.allows_enum_names());
    }

    #[test]
    fn float_angle_uses_scalar_angular_semantics() {
        let semantics = add_attr_semantics(&AddAttrValueSpec::AttrType("floatAngle".to_string()));
        assert_eq!(
            semantics.angular_semantics(),
            AddAttrAngularSemantics::Scalar
        );
    }

    #[test]
    fn message_has_no_tail_semantics() {
        let semantics = add_attr_semantics(&AddAttrValueSpec::AttrType("message".to_string()));
        assert!(!semantics.allows_numeric_tail());
        assert!(!semantics.allows_enum_names());
        assert!(semantics.allows_nice_name());
    }
}
