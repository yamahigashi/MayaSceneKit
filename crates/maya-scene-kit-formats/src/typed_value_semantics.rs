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

impl TypedValueKind {
    pub(crate) fn from_name(value_type: &str) -> Option<Self> {
        Some(match value_type {
            "string" => Self::String,
            "stringArray" => Self::StringArray,
            "Int32Array" => Self::Int32Array,
            "double3" => Self::Double3,
            "double2" => Self::Double2,
            "float3" => Self::Float3,
            "float2" => Self::Float2,
            "matrix" => Self::Matrix,
            "componentList" => Self::ComponentList,
            "polyFaces" => Self::PolyFaces,
            "nurbsCurve" => Self::NurbsCurve,
            "dataPolyComponent" => Self::DataPolyComponent,
            _ => return None,
        })
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::StringArray => "stringArray",
            Self::Int32Array => "Int32Array",
            Self::Double3 => "double3",
            Self::Double2 => "double2",
            Self::Float3 => "float3",
            Self::Float2 => "float2",
            Self::Matrix => "matrix",
            Self::ComponentList => "componentList",
            Self::PolyFaces => "polyFaces",
            Self::NurbsCurve => "nurbsCurve",
            Self::DataPolyComponent => "dataPolyComponent",
        }
    }

    pub(crate) fn supports_typed_numeric_payload(self) -> bool {
        matches!(
            self,
            Self::Double3 | Self::Double2 | Self::Float3 | Self::Float2 | Self::Matrix
        )
    }
}
