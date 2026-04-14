#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypedValueKind {
    String,
    StringArray,
    Int32Array,
    Double3,
    Double2,
    Float3,
    Float2,
    Matrix,
    ComponentList,
    PolyFaces,
    NurbsCurve,
    DataPolyComponent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypedValueCodec {
    String,
    StringArray,
    Int32Array,
    Double3,
    Double2,
    Float3,
    Float2,
    Matrix,
    ComponentList,
    PolyFaces,
    NurbsCurve,
    DataPolyComponent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypedValueShape {
    Scalar,
    DeclaredCount,
    FixedElements(usize),
    MultipleOf(usize),
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TypedValueDescriptor {
    pub(crate) kind: TypedValueKind,
    pub(crate) name: &'static str,
    pub(crate) schema_handler: &'static str,
    pub(crate) binary_tag: Option<&'static str>,
    pub(crate) binary_kind: u8,
    pub(crate) codec: TypedValueCodec,
    pub(crate) shape: TypedValueShape,
}

const TYPED_VALUE_DESCRIPTORS: &[TypedValueDescriptor] = &[
    TypedValueDescriptor {
        kind: TypedValueKind::String,
        name: "string",
        schema_handler: "attr.string",
        binary_tag: Some("STR "),
        binary_kind: 0x20,
        codec: TypedValueCodec::String,
        shape: TypedValueShape::Scalar,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::StringArray,
        name: "stringArray",
        schema_handler: "attr.string_array",
        binary_tag: Some("STR#"),
        binary_kind: 0x20,
        codec: TypedValueCodec::StringArray,
        shape: TypedValueShape::DeclaredCount,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Int32Array,
        name: "Int32Array",
        schema_handler: "attr.int32_array",
        binary_tag: Some("I32#"),
        binary_kind: 0x20,
        codec: TypedValueCodec::Int32Array,
        shape: TypedValueShape::DeclaredCount,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Double3,
        name: "double3",
        schema_handler: "attr.dbl3",
        binary_tag: Some("DBL3"),
        binary_kind: 0x20,
        codec: TypedValueCodec::Double3,
        shape: TypedValueShape::FixedElements(3),
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Double2,
        name: "double2",
        schema_handler: "attr.dbl2",
        binary_tag: Some("DBL2"),
        binary_kind: 0x20,
        codec: TypedValueCodec::Double2,
        shape: TypedValueShape::MultipleOf(2),
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Float3,
        name: "float3",
        schema_handler: "attr.flt3",
        binary_tag: Some("FLT3"),
        binary_kind: 0x20,
        codec: TypedValueCodec::Float3,
        shape: TypedValueShape::FixedElements(3),
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Float2,
        name: "float2",
        schema_handler: "attr.flt2",
        binary_tag: Some("FLT2"),
        binary_kind: 0x20,
        codec: TypedValueCodec::Float2,
        shape: TypedValueShape::MultipleOf(2),
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Matrix,
        name: "matrix",
        schema_handler: "attr.matr",
        binary_tag: Some("MATR"),
        binary_kind: 0x20,
        codec: TypedValueCodec::Matrix,
        shape: TypedValueShape::FixedElements(16),
    },
    TypedValueDescriptor {
        kind: TypedValueKind::ComponentList,
        name: "componentList",
        schema_handler: "attr.cmp_list",
        binary_tag: Some("CMP#"),
        binary_kind: 0x20,
        codec: TypedValueCodec::ComponentList,
        shape: TypedValueShape::DeclaredCount,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::PolyFaces,
        name: "polyFaces",
        schema_handler: "attr.poly_faces",
        binary_tag: None,
        binary_kind: 0x20,
        codec: TypedValueCodec::PolyFaces,
        shape: TypedValueShape::Opaque,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::NurbsCurve,
        name: "nurbsCurve",
        schema_handler: "attr.nurbs_curve",
        binary_tag: None,
        binary_kind: 0x20,
        codec: TypedValueCodec::NurbsCurve,
        shape: TypedValueShape::Opaque,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::DataPolyComponent,
        name: "dataPolyComponent",
        schema_handler: "attr.data_poly_component",
        binary_tag: None,
        binary_kind: 0x20,
        codec: TypedValueCodec::DataPolyComponent,
        shape: TypedValueShape::Opaque,
    },
];

const COMPONENT_CODES: &[(&str, &str)] = &[("CMDV", "vtx"), ("CMDF", "f"), ("CMDE", "e")];

#[cfg(test)]
pub(crate) fn typed_value_descriptor_from_binary_tag(
    tag: &str,
) -> Option<&'static TypedValueDescriptor> {
    TYPED_VALUE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.binary_tag == Some(tag))
}

impl TypedValueKind {
    pub(crate) fn from_name(value_type: &str) -> Option<Self> {
        typed_value_descriptor_from_name(value_type).map(|descriptor| descriptor.kind)
    }

    #[cfg(test)]
    pub(crate) fn from_binary_tag(tag: &str) -> Option<Self> {
        typed_value_descriptor_from_binary_tag(tag).map(|descriptor| descriptor.kind)
    }

    pub(crate) fn from_schema_handler(handler: &str) -> Option<Self> {
        typed_value_descriptor_from_schema_handler(handler).map(|descriptor| descriptor.kind)
    }

    pub(crate) fn schema_handler(self) -> &'static str {
        self.descriptor().schema_handler
    }

    pub(crate) fn shape(self) -> TypedValueShape {
        self.descriptor().shape
    }

    fn descriptor(self) -> &'static TypedValueDescriptor {
        typed_value_descriptor(self)
    }
}

pub(crate) fn typed_value_descriptor(kind: TypedValueKind) -> &'static TypedValueDescriptor {
    TYPED_VALUE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.kind == kind)
        .expect("typed value descriptor")
}

pub(crate) fn typed_value_descriptor_from_name(
    value_type: &str,
) -> Option<&'static TypedValueDescriptor> {
    TYPED_VALUE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name == value_type)
}

pub(crate) fn typed_value_descriptor_from_schema_handler(
    handler: &str,
) -> Option<&'static TypedValueDescriptor> {
    TYPED_VALUE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.schema_handler == handler)
}

pub(crate) fn component_prefix_from_code(code: &str) -> Option<&'static str> {
    COMPONENT_CODES
        .iter()
        .find_map(|(raw_code, prefix)| (*raw_code == code).then_some(*prefix))
}

#[cfg(test)]
mod tests {
    use super::{
        TypedValueCodec, TypedValueKind, TypedValueShape, typed_value_descriptor_from_binary_tag,
        typed_value_descriptor_from_schema_handler,
    };

    #[test]
    fn binary_tag_lookup_uses_same_descriptor_metadata() {
        let descriptor = typed_value_descriptor_from_binary_tag("DBL3").expect("DBL3");
        assert_eq!(descriptor.kind, TypedValueKind::Double3);
        assert_eq!(descriptor.codec, TypedValueCodec::Double3);
        assert_eq!(descriptor.shape, TypedValueShape::FixedElements(3));
        assert_eq!(descriptor.binary_tag, Some("DBL3"));
    }

    #[test]
    fn schema_handler_lookup_uses_same_descriptor_metadata() {
        let descriptor = typed_value_descriptor_from_schema_handler("attr.string_array")
            .expect("attr.string_array");
        assert_eq!(descriptor.kind, TypedValueKind::StringArray);
        assert_eq!(descriptor.binary_tag, Some("STR#"));
        assert_eq!(descriptor.shape, TypedValueShape::DeclaredCount);
        assert_eq!(descriptor.binary_kind, 0x20);
    }
}
