#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericValue {
    Float64Bits(u64),
    U32(u32),
}

impl NumericValue {
    pub fn from_f64(value: f64) -> Self {
        Self::Float64Bits(value.to_bits())
    }

    pub fn from_f32(value: f32) -> Self {
        Self::from_f64(value as f64)
    }

    pub fn from_u32(value: u32) -> Self {
        Self::U32(value)
    }

    pub fn as_f64(self) -> Option<f64> {
        match self {
            Self::Float64Bits(bits) => Some(f64::from_bits(bits)),
            Self::U32(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddAttrValueSpec {
    AttrType(String),
    DataType(String),
    UnknownToken { token: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlagState {
    True,
    False,
    #[default]
    Unknown,
}

impl FlagState {
    pub fn from_bool(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }

    pub fn is_true(self) -> bool {
        matches!(self, Self::True)
    }

    pub fn is_false(self) -> bool {
        matches!(self, Self::False)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateNodeFlags {
    pub shared: FlagState,
    pub skip_select: FlagState,
    pub raw_header_prefix: Vec<u8>,
    pub raw_flag_byte: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAttrDefaultValue {
    pub value: NumericValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAttrOp {
    pub attr_name: String,
    pub short_name: String,
    pub long_name: String,
    pub parent: Option<String>,
    pub number_of_children: Option<u32>,
    pub nice_name: Option<String>,
    pub type_token: String,
    pub header_raw: [u8; 11],
    pub disconnect_behaviour: Option<u8>,
    pub used_as_proxy: bool,
    pub used_as_color: bool,
    pub storable: FlagState,
    pub readable: FlagState,
    pub writable: FlagState,
    pub cached_internally: FlagState,
    pub hidden: FlagState,
    pub keyable: FlagState,
    pub multi: FlagState,
    pub index_matters: FlagState,
    pub internal_set: FlagState,
    pub default_value: Option<AddAttrDefaultValue>,
    pub min_value: Option<NumericValue>,
    pub max_value: Option<NumericValue>,
    pub soft_min_value: Option<NumericValue>,
    pub soft_max_value: Option<NumericValue>,
    pub enum_names: Option<String>,
    pub value_spec: AddAttrValueSpec,
}

impl AddAttrOp {
    pub fn is_emittable(&self) -> bool {
        !matches!(self.value_spec, AddAttrValueSpec::UnknownToken { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkinWeightPair {
    pub influence_index: usize,
    pub weight: NumericValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkinWeightRow {
    pub pairs: Vec<SkinWeightPair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeValuePair {
    pub time_ticks: i64,
    pub value: NumericValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetAttrValue {
    None,
    Scalar(NumericValue),
    Numbers(Vec<NumericValue>),
    TypedNumbers {
        value_type: String,
        values: Vec<NumericValue>,
    },
    PolyFaces {
        uv_set: usize,
        faces: Vec<Vec<i32>>,
        uv_faces: Vec<Vec<u32>>,
    },
    String(String),
    StringArray {
        declared_count: usize,
        values: Vec<String>,
    },
    Int32Array(Vec<i32>),
    ComponentList(Vec<String>),
    SkinWeightRows(Vec<SkinWeightRow>),
    TimeValuePairs(Vec<TimeValuePair>),
    NurbsCurve {
        degree: u32,
        spans: u32,
        form: u32,
        is_rational: bool,
        dimension: usize,
        knots: Vec<NumericValue>,
        cvs: Vec<Vec<NumericValue>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAttrOp {
    pub attr_name_or_path: String,
    pub array_size: Option<usize>,
    pub channel_hint: Option<usize>,
    pub lock: Option<bool>,
    pub keyable: Option<bool>,
    pub value: SetAttrValue,
}
