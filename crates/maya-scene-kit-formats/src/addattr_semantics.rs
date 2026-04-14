use crate::model::AddAttrValueSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddAttrTailSemantics {
    None,
    Numeric,
    Enum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddAttrSemantics {
    tail: AddAttrTailSemantics,
}

impl AddAttrSemantics {
    pub(crate) fn allows_explicit_default_min_max(self) -> bool {
        !matches!(self.tail, AddAttrTailSemantics::None)
    }

    pub(crate) fn allows_soft_range(self) -> bool {
        matches!(self.tail, AddAttrTailSemantics::Numeric)
    }

    pub(crate) fn allows_enum_names(self) -> bool {
        matches!(self.tail, AddAttrTailSemantics::Enum)
    }
}

pub(crate) fn add_attr_semantics(value_spec: &AddAttrValueSpec) -> AddAttrSemantics {
    let tail = match value_spec {
        AddAttrValueSpec::AttrType(attr_type) => match attr_type.as_str() {
            "double" | "float" | "long" | "short" | "doubleLinear" | "bool" => {
                AddAttrTailSemantics::Numeric
            }
            "doubleAngle" | "floatAngle" => AddAttrTailSemantics::Numeric,
            "enum" => AddAttrTailSemantics::Enum,
            _ => AddAttrTailSemantics::None,
        },
        AddAttrValueSpec::DataType(_) | AddAttrValueSpec::UnknownToken { .. } => {
            AddAttrTailSemantics::None
        }
    };
    AddAttrSemantics { tail }
}
