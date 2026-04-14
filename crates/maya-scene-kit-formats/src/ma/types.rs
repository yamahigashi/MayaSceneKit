#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericValue {
    Float64Bits(u64),
    U32(u32),
}

impl NumericValue {
    pub fn from_f64(value: f64) -> Self {
        Self::Float64Bits(value.to_bits())
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
}

#[derive(Debug, Clone)]
pub struct ScenePathEntry {
    pub node_type: String,
    pub node_name: String,
    pub attr: String,
    pub value: String,
    pub meta: Option<ScenePathMeta>,
}

#[derive(Debug, Clone)]
pub struct ScenePathMeta {
    pub origin: String,
    pub short_name: Option<String>,
    pub reference_node: Option<String>,
    pub format_hint: Option<String>,
    pub reference_options: Option<String>,
    pub color_space: Option<String>,
    pub raw_fields: Vec<String>,
    pub trace_form: Option<String>,
    pub trace_tag: Option<String>,
    pub trace_node_offset: Option<usize>,
    pub trace_child_alignment: Option<usize>,
    pub trace_child_header_size: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct PathReplaceRule {
    pub from: String,
    pub to: String,
    pub mode: PathReplaceMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathReplaceMode {
    #[default]
    Literal,
    Regex,
}
