use super::{CreateNodeFlags, UnknownEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefEditGroupSource {
    HeaderList,
    InlineHeader,
    ContextBoundary,
    ImplicitRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEditGroup {
    pub name: String,
    pub expected_count: u32,
    pub source: RefEditGroupSource,
    pub first_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefEditRecord {
    Context(String, u32),
    Op0(String, String, String),
    Op1(Vec<String>),
    Op2(String, String, String),
    Op3(String, String, String),
    Op5 { sub: u32, args: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEditUnknownTail {
    pub start_offset: usize,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefEditParseStats {
    pub candidate_count: usize,
    pub selected_group_list_count: usize,
    pub parsed_group_list_count: usize,
    pub boundary_count: usize,
    pub unknown_segment_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEditData {
    pub root_node: String,
    pub groups: Vec<RefEditGroup>,
    pub grouped_records: Vec<Vec<RefEditRecord>>,
    pub unknown_tail: Option<RefEditUnknownTail>,
    pub parse_stats: RefEditParseStats,
}

use super::{AddAttrOp, SetAttrOp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedEvent {
    CreateNode {
        name: Option<String>,
        parent: Option<String>,
        uid: Option<String>,
        create_flags: CreateNodeFlags,
        used_len_prefixed_fields: bool,
    },
    ScriptBody {
        body: String,
    },
    AddAttr(AddAttrOp),
    SetAttr(SetAttrOp),
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
    SelectTarget {
        target: String,
    },
    RefEdit {
        attr_name: String,
        data: RefEditData,
    },
    ReferenceFile {
        path: String,
        reference_node: String,
        namespace: Option<String>,
        file_type: Option<String>,
        options: Option<String>,
    },
    Unknown(UnknownEvent),
}
