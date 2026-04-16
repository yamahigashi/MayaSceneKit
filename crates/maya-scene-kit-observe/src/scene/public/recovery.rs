use std::{collections::HashMap, path::Path};

pub use crate::scene::{
    ir::{
        AddAttrDefaultValue, AddAttrOp, AddAttrValueSpec, ChunkRef, ChunkTrace, Confidence,
        CreateNodeFlags, DecodeQualityRecord, FlagState, LinkOp, NodeRecoveryIssue, NumericValue,
        RawChunkRecord, RecoveredAttrOp, RecoveredNode, RecoveryIssue, RecoveryIssueKind,
        RefEditData, RefEditGroup, RefEditGroupSource, RefEditParseStats, RefEditRecord,
        RefEditUnknownTail, ReferenceFileOp, SceneArtifacts, SceneBuildOutput, SceneModel,
        SchemaDecodeAttempt, SchemaDecodeAttemptResult, SelectBlock, SelectBlockNote,
        SelectBlockOp, SemanticProvenance, SetAttrOp, SetAttrValue, SkinWeightPair, SkinWeightRow,
        TimeValuePair, TypeIdResolverStatus,
    },
    schema::node_semantics::AngularAttrKind,
};
use crate::{
    addattr_semantics::{AddAttrAngularSemantics, add_attr_semantics},
    mb::{HeadMetadata, extract_head_metadata},
    scene::{
        LoadOptions, SceneFormat, SceneToolError,
        analyze::analyze_scene_model,
        mb_read_session::MbReadSession,
        runtime_assets::RuntimeAssets,
        schema::node_semantics::{
            AngularAttrKind as SchemaAngularAttrKind,
            node_angular_attr_rules_for_node_type_with_registry,
        },
    },
};

#[derive(Debug, Clone)]
pub struct MbRecoveryBundle {
    pub header: HeadMetadata,
    pub build: crate::scene::ir::SceneBuildOutput,
    pub issues: Vec<NodeRecoveryIssue>,
    pub angular_attrs_by_node: HashMap<String, HashMap<String, SchemaAngularAttrKind>>,
}

pub fn validate_additional_node_info_paths(options: &LoadOptions) -> Result<(), SceneToolError> {
    let assets = RuntimeAssets::from_schema_inputs(&options.schema_inputs());
    assets.validate_schema_inputs()?;
    assets.build_typeid_typename_resolver()?;
    Ok(())
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

    let session =
        MbReadSession::load_raw(path, &options.schema_inputs(), options.mb_parse_budget())?;
    let build = session.build()?;
    let issues = analyze_scene_model(&build.scene, &build.artifacts);
    let angular_attrs_by_node = build_node_angular_attrs(
        &build.scene.nodes,
        &RuntimeAssets::from_schema_inputs(&options.schema_inputs()),
    );

    Ok(MbRecoveryBundle {
        header: extract_head_metadata(&session.mb),
        build: build.clone(),
        issues,
        angular_attrs_by_node,
    })
}

fn build_node_angular_attrs(
    nodes: &[crate::scene::ir::RecoveredNode],
    assets: &RuntimeAssets,
) -> HashMap<String, HashMap<String, AngularAttrKind>> {
    let registry = assets.registry();
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
                let crate::scene::ir::RecoveredAttrOp::AddAttr(add_attr) = op else {
                    continue;
                };
                if !matches!(
                    add_attr_semantics(&add_attr.value_spec).angular_semantics(),
                    AddAttrAngularSemantics::Scalar
                ) {
                    continue;
                }

                if let Some(token) = normalize_attr_leaf_token(&add_attr.short_name) {
                    attrs.insert(token, AngularAttrKind::Scalar);
                }
                if let Some(token) = normalize_attr_leaf_token(&add_attr.long_name) {
                    attrs.insert(token, AngularAttrKind::Scalar);
                }
                if let Some(parent) = &add_attr.parent {
                    if let Some(parent_token) = normalize_attr_leaf_token(parent) {
                        *angle_children_by_parent.entry(parent_token).or_insert(0) += 1;
                    }
                }
            }

            for (parent, count) in angle_children_by_parent {
                if count >= 2 {
                    attrs.insert(parent, AngularAttrKind::Vector3);
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
