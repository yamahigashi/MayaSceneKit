use maya_scene_kit_formats::{
    maya_defaults::DEFAULT_MAYA_VERSION,
    mb::{HeadMetadata, MbRequiresEntry},
    unit_semantics::{DEFAULT_ANGULAR_UNIT, DEFAULT_LINEAR_UNIT, DEFAULT_TIME_UNIT},
};

pub use crate::scene::ir::{
    AddAttrDefaultValue, AddAttrOp, AddAttrValueSpec, CreateNodeFlags, FlagState, LinkOp,
    NumericValue, RecoveredAttrOp, RecoveredNode, RefEditData, RefEditGroup,
    RefEditGroupSource, RefEditParseStats, RefEditRecord, RefEditUnknownTail,
    SceneModel as IrSceneModel, SelectBlock, SelectBlockNote, SelectBlockOp, SetAttrOp,
    SetAttrValue, SkinWeightPair, SkinWeightRow, TimeValuePair,
};

pub use crate::scene::ir::ReferenceFileOp;

#[derive(Debug, Clone)]
pub struct RecoveredHeader {
    pub vers: Option<String>,
    pub chng: Option<String>,
    pub luni: Option<String>,
    pub auni: Option<String>,
    pub tuni: Option<String>,
    pub tdur: Option<String>,
    pub file_info: Vec<(String, String)>,
    pub requires: Vec<MbRequiresEntry>,
}

impl RecoveredHeader {
    pub fn maya_version(&self) -> &str {
        self.vers.as_deref().unwrap_or(DEFAULT_MAYA_VERSION)
    }

    pub fn linear_unit(&self) -> &str {
        self.luni.as_deref().unwrap_or(DEFAULT_LINEAR_UNIT)
    }

    pub fn angular_unit(&self) -> &str {
        self.auni.as_deref().unwrap_or(DEFAULT_ANGULAR_UNIT)
    }

    pub fn time_unit(&self) -> &str {
        self.tuni.as_deref().unwrap_or(DEFAULT_TIME_UNIT)
    }
}

impl From<HeadMetadata> for RecoveredHeader {
    fn from(value: HeadMetadata) -> Self {
        Self {
            vers: value.vers,
            chng: value.chng,
            luni: value.luni,
            auni: value.auni,
            tuni: value.tuni,
            tdur: value.tdur,
            file_info: value.file_info,
            requires: value.requires,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveredScene {
    pub nodes: Vec<RecoveredNode>,
    pub select_blocks: Vec<SelectBlock>,
    pub links: Vec<LinkOp>,
    pub reference_files: Vec<ReferenceFileOp>,
}

impl RecoveredScene {
    pub fn from_scene_model(model: IrSceneModel) -> Self {
        Self {
            nodes: model.nodes,
            select_blocks: model.select_blocks,
            links: model.links,
            reference_files: model.reference_files,
        }
    }
}

impl From<IrSceneModel> for RecoveredScene {
    fn from(model: IrSceneModel) -> Self {
        Self::from_scene_model(model)
    }
}

pub type SceneModel = RecoveredScene;
