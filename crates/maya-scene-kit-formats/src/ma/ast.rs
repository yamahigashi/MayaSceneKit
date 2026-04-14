use crate::model::{AddAttrValueSpec, FlagState, NumericValue};

#[derive(Debug, Default)]
pub struct ParsedAsciiScene {
    pub version: Option<String>,
    pub changed: Option<String>,
    pub linear_unit: Option<String>,
    pub angular_unit: Option<String>,
    pub time_unit: Option<String>,
    pub time_duration: Option<String>,
    pub file_info: Vec<(String, String)>,
    pub plugin_requires: Vec<PluginRequire>,
    pub file_commands: Vec<ParsedFileCommand>,
    pub nodes: Vec<ParsedNode>,
    pub select_blocks: Vec<ParsedSelectBlock>,
    pub links: Vec<ParsedLinkOp>,
}

#[derive(Debug)]
pub struct PluginRequire {
    pub name: String,
    pub version: String,
    pub options: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFileCommand {
    pub path: String,
    pub namespace: Option<String>,
    pub reference_node: Option<String>,
    pub file_type: Option<String>,
    pub options: Option<String>,
    pub is_reference: bool,
}

#[derive(Debug)]
pub struct ParsedNode {
    pub node_type: String,
    pub name: String,
    pub parent: Option<String>,
    pub shared: bool,
    pub uid: Option<String>,
    pub ops: Vec<ParsedNodeOp>,
}

#[derive(Debug)]
pub enum ParsedNodeOp {
    AddAttr(ParsedAddAttr),
    SetAttr(ParsedSetAttr),
}

#[derive(Debug)]
pub enum ParsedSelectBlockOp {
    AddAttr(ParsedAddAttr),
    SetAttr(ParsedSetAttr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedSelectBlockNote {
    #[allow(dead_code)]
    MissingTarget { placeholder: String },
}

#[derive(Debug)]
pub struct ParsedSelectBlock {
    pub target: String,
    pub notes: Vec<ParsedSelectBlockNote>,
    pub ops: Vec<ParsedSelectBlockOp>,
}

#[derive(Debug)]
pub enum ParsedLinkOp {
    Connect {
        src: String,
        dst: String,
        mode: u8,
    },
    Relationship {
        kind: String,
        head: String,
        tail: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddAttrDefaultValue {
    pub value: NumericValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddAttr {
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
    pub default_value: Option<ParsedAddAttrDefaultValue>,
    pub min_value: Option<NumericValue>,
    pub max_value: Option<NumericValue>,
    pub soft_min_value: Option<NumericValue>,
    pub soft_max_value: Option<NumericValue>,
    pub enum_names: Option<String>,
    pub value_spec: AddAttrValueSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSkinWeightPair {
    pub influence_index: usize,
    pub weight: NumericValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSkinWeightRow {
    pub pairs: Vec<ParsedSkinWeightPair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTimeValuePair {
    pub time_ticks: i64,
    pub value: NumericValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedAsciiRefEditRecord {
    Op0(String, String, String),
    Op1(Vec<String>),
    Op2(String, String, String),
    Op3(String, String, String),
    Op5 { sub: u32, args: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAsciiRefEditGroup {
    pub name: String,
    pub expected_count: u32,
    pub records: Vec<ParsedAsciiRefEditRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAsciiRefEdit {
    pub root_node: String,
    pub groups: Vec<ParsedAsciiRefEditGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedOpaqueValueItem {
    Bare(String),
    Quoted(String),
    Symbol(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedSetAttrValue {
    None,
    Scalar(NumericValue),
    Numbers(Vec<NumericValue>),
    TypedNumbers {
        value_type: String,
        values: Vec<NumericValue>,
    },
    #[allow(dead_code)]
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
    OpaqueTyped {
        value_type: String,
        items: Vec<ParsedOpaqueValueItem>,
    },
    DataReferenceEdits(ParsedAsciiRefEdit),
    ComponentList(Vec<String>),
    #[allow(dead_code)]
    SkinWeightRows(Vec<ParsedSkinWeightRow>),
    #[allow(dead_code)]
    TimeValuePairs(Vec<ParsedTimeValuePair>),
    #[allow(dead_code)]
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
pub struct ParsedSetAttr {
    pub attr_name_or_path: String,
    pub array_size: Option<usize>,
    pub channel_hint: Option<usize>,
    pub lock: Option<bool>,
    pub keyable: Option<bool>,
    pub value: ParsedSetAttrValue,
}
