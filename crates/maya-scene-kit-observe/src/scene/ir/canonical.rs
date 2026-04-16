use super::{
    AddAttrOp, ChunkTrace, Confidence, CreateNodeFlags, RecoveryIssue, RefEditData, SetAttrOp,
    SharedStr,
};

#[derive(Debug, Clone)]
pub struct RecoveredNode {
    pub node_type: SharedStr,
    pub name: String,
    pub parent: Option<String>,
    pub uid: Option<String>,
    pub attrs: Vec<RecoveredAttrOp>,
    pub decode_notes: Vec<RecoveryIssue>,
    pub create_flags: CreateNodeFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveredAttrOp {
    AddAttr(AddAttrOp),
    SetAttr(SetAttrOp),
    RefEdit {
        attr_name: SharedStr,
        data: RefEditData,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectBlockOp {
    AddAttr(AddAttrOp),
    SetAttr(SetAttrOp),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectBlockNote {
    MissingTarget { placeholder: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectBlock {
    pub target: String,
    pub notes: Vec<SelectBlockNote>,
    pub ops: Vec<SelectBlockOp>,
    pub trace: Option<ChunkTrace>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOp {
    Connect {
        src: String,
        dst: String,
        mode: u8,
        trace: Option<ChunkTrace>,
        confidence: Confidence,
    },
    Relationship {
        kind: SharedStr,
        head: String,
        tail: Vec<String>,
        trace: Option<ChunkTrace>,
        confidence: Confidence,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceFileOp {
    pub path: String,
    pub namespace: SharedStr,
    pub reference_node: SharedStr,
    pub file_type: SharedStr,
    pub options: Option<String>,
    pub namespace_defaulted: bool,
    pub file_type_defaulted: bool,
    pub path_inferred_from_parent_include: bool,
    pub trace: Option<ChunkTrace>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Default)]
pub struct SceneModel {
    pub nodes: Vec<RecoveredNode>,
    pub select_blocks: Vec<SelectBlock>,
    pub links: Vec<LinkOp>,
    pub reference_files: Vec<ReferenceFileOp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TypeIdResolverStatus {
    Provided,
    #[default]
    LoadedDefault,
    DefaultLoadFailed {
        message: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct SceneBuildOutput {
    pub scene: SceneModel,
    pub artifacts: super::SceneArtifacts,
    pub typeid_resolver_status: TypeIdResolverStatus,
}
