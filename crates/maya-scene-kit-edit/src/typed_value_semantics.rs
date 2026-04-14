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
pub(crate) enum TypedValueRenderClass {
    StandardInline,
    TupleInline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypedValueAngularRenderClass {
    None,
    Vector3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TypedValueDescriptor {
    pub(crate) kind: TypedValueKind,
    pub(crate) name: &'static str,
    pub(crate) render_class: TypedValueRenderClass,
    pub(crate) angular_render_class: TypedValueAngularRenderClass,
}

const TYPED_VALUE_DESCRIPTORS: &[TypedValueDescriptor] = &[
    TypedValueDescriptor {
        kind: TypedValueKind::String,
        name: "string",
        render_class: TypedValueRenderClass::StandardInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::StringArray,
        name: "stringArray",
        render_class: TypedValueRenderClass::StandardInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Int32Array,
        name: "Int32Array",
        render_class: TypedValueRenderClass::StandardInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Double3,
        name: "double3",
        render_class: TypedValueRenderClass::TupleInline,
        angular_render_class: TypedValueAngularRenderClass::Vector3,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Double2,
        name: "double2",
        render_class: TypedValueRenderClass::TupleInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Float3,
        name: "float3",
        render_class: TypedValueRenderClass::TupleInline,
        angular_render_class: TypedValueAngularRenderClass::Vector3,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Float2,
        name: "float2",
        render_class: TypedValueRenderClass::TupleInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::Matrix,
        name: "matrix",
        render_class: TypedValueRenderClass::StandardInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::ComponentList,
        name: "componentList",
        render_class: TypedValueRenderClass::StandardInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::PolyFaces,
        name: "polyFaces",
        render_class: TypedValueRenderClass::StandardInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::NurbsCurve,
        name: "nurbsCurve",
        render_class: TypedValueRenderClass::StandardInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
    TypedValueDescriptor {
        kind: TypedValueKind::DataPolyComponent,
        name: "dataPolyComponent",
        render_class: TypedValueRenderClass::StandardInline,
        angular_render_class: TypedValueAngularRenderClass::None,
    },
];

impl TypedValueKind {
    pub(crate) fn from_name(value_type: &str) -> Option<Self> {
        typed_value_descriptor_from_name(value_type).map(|descriptor| descriptor.kind)
    }

    pub(crate) fn render_class(self) -> TypedValueRenderClass {
        self.descriptor().render_class
    }

    pub(crate) fn angular_render_class(self) -> TypedValueAngularRenderClass {
        self.descriptor().angular_render_class
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

#[cfg(test)]
mod tests {
    use super::{TypedValueAngularRenderClass, TypedValueKind, TypedValueRenderClass};

    #[test]
    fn double3_uses_tuple_rendering() {
        let kind = TypedValueKind::from_name("double3").expect("double3");
        assert_eq!(kind, TypedValueKind::Double3);
        assert_eq!(kind.render_class(), TypedValueRenderClass::TupleInline);
        assert_eq!(
            kind.angular_render_class(),
            TypedValueAngularRenderClass::Vector3
        );
    }

    #[test]
    fn string_array_uses_standard_rendering() {
        let kind = TypedValueKind::from_name("stringArray").expect("stringArray");
        assert_eq!(kind, TypedValueKind::StringArray);
        assert_eq!(kind.render_class(), TypedValueRenderClass::StandardInline);
        assert_eq!(
            kind.angular_render_class(),
            TypedValueAngularRenderClass::None
        );
    }
}
