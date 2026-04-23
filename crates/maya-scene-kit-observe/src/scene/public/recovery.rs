#![allow(unused_imports)]

use std::{collections::HashMap, path::Path, sync::Arc};

pub use crate::scene::forensics::{
    ChunkRef, ChunkTrace, Confidence, DecodeQualityRecord, NodeRecoveryIssue, RawChunkRecord,
    RecoveryForensics, RecoveryIssue, RecoveryIssueKind, SchemaDecodeAttempt,
    SchemaDecodeAttemptResult, SemanticProvenance, TypeIdResolverStatus,
};
pub use crate::scene::model::{
    AddAttrDefaultValue, AddAttrOp, AddAttrValueSpec, CreateNodeFlags, FlagState, LinkOp,
    NumericValue, RecoveredAttrOp, RecoveredHeader, RecoveredNode, RecoveredScene, RefEditData,
    RefEditGroup, RefEditGroupSource, RefEditParseStats, RefEditRecord, RefEditUnknownTail,
    ReferenceFileOp, SelectBlock, SelectBlockNote, SelectBlockOp, SetAttrOp, SetAttrValue,
    SkinWeightPair, SkinWeightRow, TimeValuePair,
};
pub use crate::scene::schema::node_semantics::AngularAttrKind;

use crate::{
    addattr_semantics::{AddAttrAngularSemantics, add_attr_semantics},
    mb::extract_head_metadata,
    scene::{
        LoadOptions, SceneFormat, SceneToolError,
        analyze::analyze_scene_model,
        forensics::DecodeQualityRecord as PublicDecodeQualityRecord,
        ir::SceneBuildOutput,
        mb_read_session::MbReadSession,
        schema::{
            SchemaContext,
            node_semantics::{
                AngularAttrKind as SchemaAngularAttrKind,
                node_angular_attr_rules_for_node_type_with_registry,
            },
        },
    },
};

#[derive(Debug, Clone)]
pub struct MbRecoveryBundle {
    pub header: RecoveredHeader,
    pub scene: RecoveredScene,
    pub issues: Vec<NodeRecoveryIssue>,
    pub forensics: RecoveryForensics,
    pub angular_attrs_by_node: HashMap<String, HashMap<String, SchemaAngularAttrKind>>,
}

pub fn validate_additional_node_info_paths(options: &LoadOptions) -> Result<(), SceneToolError> {
    SchemaContext::from_inputs_cached(&options.schema_inputs()).map(|_| ())
}

pub fn recover_mb_scene(
    path: impl AsRef<Path>,
    options: &LoadOptions,
) -> Result<MbRecoveryBundle, SceneToolError> {
    let path = path.as_ref();
    let scene_format = crate::scene::detect_scene_format(path)?;
    if scene_format != SceneFormat::Mb {
        return Err(SceneToolError::UnsupportedSceneFormat {
            path: path.to_path_buf(),
            detected: scene_format,
        });
    }

    let schema_context = SchemaContext::from_inputs_cached(&options.schema_inputs())?;
    let budget = options.materialize_mb_parse_budget_for_path(path)?;
    let session = MbReadSession::load_raw(path, Arc::clone(&schema_context), &budget)?;
    let build = session.build()?;

    Ok(MbRecoveryBundle {
        header: RecoveredHeader::from(extract_head_metadata(&session.mb)),
        scene: RecoveredScene::from_scene_model(build.scene.clone()),
        issues: analyze_scene_model(&build.scene, &build.artifacts)
            .into_iter()
            .map(Into::into)
            .collect(),
        forensics: recovery_forensics_from_build(build),
        angular_attrs_by_node: build_node_angular_attrs(
            &build.scene.nodes,
            schema_context.as_ref(),
        ),
    })
}

fn recovery_forensics_from_build(build: &SceneBuildOutput) -> RecoveryForensics {
    let raw_chunks = build
        .artifacts
        .raw_chunks
        .iter()
        .map(|chunk| RawChunkRecord {
            chunk_ref: chunk.chunk_ref.clone().into(),
            payload: chunk.payload(build.artifacts.raw_source.as_ref()).to_vec(),
        })
        .collect();
    let decode_qualities = build
        .artifacts
        .decode_qualities
        .iter()
        .cloned()
        .map(PublicDecodeQualityRecord::from)
        .collect();

    RecoveryForensics {
        raw_chunks,
        decode_qualities,
        typeid_resolver_status: build.typeid_resolver_status.clone().into(),
    }
}

fn build_node_angular_attrs(
    nodes: &[RecoveredNode],
    schema_context: &SchemaContext,
) -> HashMap<String, HashMap<String, SchemaAngularAttrKind>> {
    let registry = schema_context.registry();
    nodes
        .iter()
        .map(|node| {
            let mut attrs = node_angular_attr_rules_for_node_type_with_registry(
                registry.as_ref(),
                &node.node_type,
            )
            .unwrap_or_default();

            let mut angle_children_by_parent: HashMap<String, usize> = HashMap::new();
            for op in &node.attrs {
                let RecoveredAttrOp::AddAttr(add_attr) = op else {
                    continue;
                };
                if !matches!(
                    add_attr_semantics(&add_attr.value_spec).angular_semantics(),
                    AddAttrAngularSemantics::Scalar
                ) {
                    continue;
                }

                if let Some(token) = normalize_attr_leaf_token(&add_attr.short_name) {
                    attrs.insert(token, SchemaAngularAttrKind::Scalar);
                }
                if let Some(token) = normalize_attr_leaf_token(&add_attr.long_name) {
                    attrs.insert(token, SchemaAngularAttrKind::Scalar);
                }
                if let Some(parent) = &add_attr.parent {
                    if let Some(parent_token) = normalize_attr_leaf_token(parent) {
                        *angle_children_by_parent.entry(parent_token).or_insert(0) += 1;
                    }
                }
            }

            for (parent, count) in angle_children_by_parent {
                if count >= 2 {
                    attrs.insert(parent, SchemaAngularAttrKind::Vector3);
                }
            }

            (node.name.clone(), attrs)
        })
        .collect()
}

fn normalize_attr_leaf_token(attr_path: &str) -> Option<String> {
    let mut token = attr_path.trim();
    if token.is_empty() {
        return None;
    }
    if let Some(stripped) = token.strip_prefix('.') {
        token = stripped;
    }
    if let Some(idx) = token.rfind('.') {
        token = &token[idx + 1..];
    }
    if let Some(idx) = token.find('[') {
        token = &token[..idx];
    }
    if token.is_empty() {
        None
    } else {
        Some(token.to_ascii_lowercase())
    }
}
