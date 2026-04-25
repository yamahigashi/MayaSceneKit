use std::path::PathBuf;

use maya_scene_kit_observe::scene::evidence::{
    ExecutionOrigin, ExecutionSourceRange, ExecutionSurfaceKind,
};

use super::{OperationMode, SceneFormat, ValidationState, staging::StagedSceneArtifact};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutionCleanTarget {
    ScriptNode { node_name: String },
    PluginRequire { rendered: String },
    TopLevelCommand { source_range: ExecutionSourceRange },
    FileCommandCallback { source_range: ExecutionSourceRange },
    MbOwnerForm { form: String, node_offset: usize },
}

pub fn clean_target_for_execution_origin(origin: &ExecutionOrigin) -> Option<ExecutionCleanTarget> {
    match origin.surface_kind {
        ExecutionSurfaceKind::ScriptNodeBody => origin
            .chunk_form
            .as_ref()
            .zip(origin.chunk_node_offset)
            .map(|(form, node_offset)| ExecutionCleanTarget::MbOwnerForm {
                form: form.clone(),
                node_offset,
            })
            .or_else(|| {
                origin
                    .node_name
                    .as_ref()
                    .map(|node_name| ExecutionCleanTarget::ScriptNode {
                        node_name: node_name.clone(),
                    })
            }),
        ExecutionSurfaceKind::TopLevelCommand
        | ExecutionSurfaceKind::TopLevelProcDefinition
        | ExecutionSurfaceKind::TopLevelOtherStatement => origin
            .source_range
            .map(|source_range| ExecutionCleanTarget::TopLevelCommand { source_range }),
        ExecutionSurfaceKind::FileCommandCallback => origin
            .source_range
            .map(|source_range| ExecutionCleanTarget::FileCommandCallback { source_range }),
        ExecutionSurfaceKind::NodeAttrCallback | ExecutionSurfaceKind::RawChunkText => origin
            .chunk_form
            .as_ref()
            .zip(origin.chunk_node_offset)
            .map(|(form, node_offset)| ExecutionCleanTarget::MbOwnerForm {
                form: form.clone(),
                node_offset,
            }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionCleanPreview {
    pub input_path: PathBuf,
    pub scene_format: SceneFormat,
    pub operation_mode: OperationMode,
    pub validation_state: ValidationState,
    pub cleaned_targets: Vec<ExecutionCleanTarget>,
    pub removed_script_nodes: Vec<String>,
    pub removed_plugin_requires: Vec<String>,
}

impl ExecutionCleanPreview {
    pub fn cleaned_count(&self) -> usize {
        self.cleaned_targets.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionCleanStageResult {
    pub preview: ExecutionCleanPreview,
    pub artifact: StagedSceneArtifact,
}

#[derive(Debug, Clone)]
pub struct ExecutionCleanResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub scene_format: SceneFormat,
    pub operation_mode: OperationMode,
    pub validation_state: ValidationState,
    pub cleaned_targets: Vec<ExecutionCleanTarget>,
    pub removed_script_nodes: Vec<String>,
    pub removed_plugin_requires: Vec<String>,
}

impl ExecutionCleanResult {
    pub fn cleaned_count(&self) -> usize {
        self.cleaned_targets.len()
    }
}

#[cfg(test)]
mod tests {
    use maya_scene_kit_observe::scene::evidence::{ExecutionLanguage, ExecutionTrigger};

    use super::*;

    #[test]
    fn clean_target_for_execution_origin_maps_script_node_ma() {
        let origin = ExecutionOrigin {
            lang: ExecutionLanguage::Python,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some("ExampleScript".to_string()),
            attr_name: Some(".b".to_string()),
            source_kind: Some("scriptType=1".to_string()),
            source_range: None,
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        };

        assert_eq!(
            clean_target_for_execution_origin(&origin),
            Some(ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScript".to_string(),
            })
        );
    }

    #[test]
    fn clean_target_for_execution_origin_prefers_script_node_mb_owner_form() {
        let origin = ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some("ExampleScript".to_string()),
            attr_name: Some(".b".to_string()),
            source_kind: Some("scriptType=1".to_string()),
            source_range: None,
            chunk_form: Some("SCRP".to_string()),
            chunk_tag: Some("STR ".to_string()),
            chunk_node_offset: Some(0x1234),
            ..ExecutionOrigin::without_chunk_address()
        };

        assert_eq!(
            clean_target_for_execution_origin(&origin),
            Some(ExecutionCleanTarget::MbOwnerForm {
                form: "SCRP".to_string(),
                node_offset: 0x1234,
            })
        );
    }

    #[test]
    fn clean_target_for_execution_origin_maps_file_callback() {
        let origin = ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::FileCommandCallback,
            node_name: None,
            attr_name: None,
            source_kind: Some("file -command".to_string()),
            source_range: Some(ExecutionSourceRange { start: 8, end: 32 }),
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        };

        assert_eq!(
            clean_target_for_execution_origin(&origin),
            Some(ExecutionCleanTarget::FileCommandCallback {
                source_range: ExecutionSourceRange { start: 8, end: 32 },
            })
        );
    }

    #[test]
    fn clean_target_for_execution_origin_maps_top_level_to_command_range() {
        for surface_kind in [
            ExecutionSurfaceKind::TopLevelCommand,
            ExecutionSurfaceKind::TopLevelProcDefinition,
            ExecutionSurfaceKind::TopLevelOtherStatement,
        ] {
            let origin = ExecutionOrigin {
                lang: ExecutionLanguage::Mel,
                trigger: ExecutionTrigger::Manual,
                surface_kind,
                node_name: None,
                attr_name: None,
                source_kind: Some("top_level".to_string()),
                source_range: Some(ExecutionSourceRange { start: 40, end: 92 }),
                chunk_form: None,
                chunk_tag: None,
                chunk_node_offset: None,
                ..ExecutionOrigin::without_chunk_address()
            };

            assert_eq!(
                clean_target_for_execution_origin(&origin),
                Some(ExecutionCleanTarget::TopLevelCommand {
                    source_range: ExecutionSourceRange { start: 40, end: 92 },
                })
            );
        }
    }

    #[test]
    fn clean_target_for_execution_origin_maps_raw_chunk_text() {
        let origin = ExecutionOrigin {
            lang: ExecutionLanguage::Unknown,
            trigger: ExecutionTrigger::Unknown,
            surface_kind: ExecutionSurfaceKind::RawChunkText,
            node_name: None,
            attr_name: None,
            source_kind: None,
            source_range: None,
            chunk_form: Some("SCRP".to_string()),
            chunk_tag: Some("STR ".to_string()),
            chunk_node_offset: Some(0xCFC),
            ..ExecutionOrigin::without_chunk_address()
        };

        assert_eq!(
            clean_target_for_execution_origin(&origin),
            Some(ExecutionCleanTarget::MbOwnerForm {
                form: "SCRP".to_string(),
                node_offset: 0xCFC,
            })
        );
    }

    #[test]
    fn clean_target_for_execution_origin_returns_none_without_addressing() {
        let origin = ExecutionOrigin {
            lang: ExecutionLanguage::Unknown,
            trigger: ExecutionTrigger::Unknown,
            surface_kind: ExecutionSurfaceKind::RawChunkText,
            node_name: None,
            attr_name: None,
            source_kind: None,
            source_range: None,
            chunk_form: Some("SCRP".to_string()),
            chunk_tag: Some("STR ".to_string()),
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        };

        assert_eq!(clean_target_for_execution_origin(&origin), None);
    }
}
