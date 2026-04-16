use std::sync::Arc;

use crate::{
    mb::{MayaBinaryFile, MayaBinaryParseError, MbParseBudget},
    scene::{
        ir::{SceneArtifacts, SceneBuildOutput, SceneModel, TypeIdResolverStatus},
        recover,
        schema::{
            SchemaRegistry,
            typeid_map::{TypeIdTypeNameResolver, build_typeid_typename_resolver_with_registry},
        },
    },
};

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_scene_model(
    mb: &MayaBinaryFile,
    typeid_resolver: Option<&TypeIdTypeNameResolver>,
    registry: Arc<SchemaRegistry>,
) -> SceneBuildOutput {
    let (default_typeid_resolver, typeid_resolver_status) = if typeid_resolver.is_none() {
        match build_typeid_typename_resolver_with_registry(registry.as_ref()) {
            Ok(resolver) => (Some(resolver), TypeIdResolverStatus::LoadedDefault),
            Err(message) => (None, TypeIdResolverStatus::DefaultLoadFailed { message }),
        }
    } else {
        (None, TypeIdResolverStatus::Provided)
    };
    let typeid_resolver = typeid_resolver.or(default_typeid_resolver.as_ref());
    let raw_chunks = recover::collect_raw_chunk_records(mb);
    build_scene_model_from_raw_chunks(
        Arc::clone(&mb.data),
        raw_chunks,
        typeid_resolver,
        registry,
        typeid_resolver_status,
    )
}

#[allow(dead_code)]
pub(crate) fn build_scene_model_with_budget(
    mb: &MayaBinaryFile,
    typeid_resolver: &TypeIdTypeNameResolver,
    registry: Arc<SchemaRegistry>,
    budget: &MbParseBudget,
) -> Result<SceneBuildOutput, MayaBinaryParseError> {
    let raw_chunks = recover::collect_raw_chunk_records_with_budget(mb, budget)?;
    Ok(build_scene_model_from_raw_chunks(
        Arc::clone(&mb.data),
        raw_chunks,
        Some(typeid_resolver),
        registry,
        TypeIdResolverStatus::Provided,
    ))
}

pub(crate) fn build_scene_model_from_decoded_chunks(
    raw_source: Arc<[u8]>,
    raw_chunks: Vec<crate::scene::ir::RawChunkRecord>,
    decoded_chunks: Vec<crate::scene::ir::DecodedChunkRecord>,
    typeid_resolver: Option<&TypeIdTypeNameResolver>,
    _registry: Arc<SchemaRegistry>,
    typeid_resolver_status: TypeIdResolverStatus,
) -> SceneBuildOutput {
    let decode_qualities = recover::collect_decode_quality_records(&decoded_chunks);
    let nodes = recover::recover_nodes(&decoded_chunks, typeid_resolver);
    SceneBuildOutput {
        scene: SceneModel {
            nodes,
            select_blocks: recover::recover_select_blocks(&decoded_chunks),
            links: recover::recover_links_from_cons(&decoded_chunks),
            reference_files: recover::recover_reference_files(&decoded_chunks),
        },
        artifacts: SceneArtifacts {
            raw_source,
            raw_chunks,
            decode_qualities,
        },
        typeid_resolver_status,
    }
}

fn build_scene_model_from_raw_chunks(
    raw_source: Arc<[u8]>,
    raw_chunks: Vec<crate::scene::ir::RawChunkRecord>,
    typeid_resolver: Option<&TypeIdTypeNameResolver>,
    registry: Arc<SchemaRegistry>,
    typeid_resolver_status: TypeIdResolverStatus,
) -> SceneBuildOutput {
    let decoded_chunks = recover::collect_decoded_chunk_records(
        &raw_chunks,
        raw_source.as_ref(),
        Arc::clone(&registry),
    );
    build_scene_model_from_decoded_chunks(
        raw_source,
        raw_chunks,
        decoded_chunks,
        typeid_resolver,
        registry,
        typeid_resolver_status,
    )
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use super::build_scene_model;
    use crate::{
        mb::{
            Chunk, MayaBinaryFile, parse_file,
            paths::{MbScenePathEntry, MbScenePathMeta},
        },
        scene::{
            ir::{Confidence, DecodedEvent, LinkOp, ReferenceFileOp, TypeIdResolverStatus},
            schema::locator::SchemaPaths,
        },
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .to_path_buf()
    }

    fn build_test_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(payload);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out
    }

    fn build_test_form(form: &str, chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = form.as_bytes().to_vec();
        for chunk in chunks {
            payload.extend_from_slice(chunk);
        }
        build_test_chunk("FOR8", &payload)
    }

    fn build_test_mb(children: &[Vec<u8>]) -> MayaBinaryFile {
        let mut data = Vec::new();
        let mut root_children = Vec::new();

        for (idx, child_payload) in children.iter().enumerate() {
            let chunk_offset = data.len();
            data.extend_from_slice(child_payload);
            let payload_offset = chunk_offset + 16;
            let payload_end = data.len();
            root_children.push(Chunk {
                tag: "FOR8".to_string(),
                offset: idx * 0x100,
                aux: 0,
                size: child_payload.len().saturating_sub(16),
                payload_offset,
                payload_end,
                form_type: Some("SCRP".to_string()),
                child_alignment: Some(8),
                child_header_size: Some(16),
                children_parsed: false,
                children: vec![],
            });
        }

        MayaBinaryFile {
            path: None,
            data: data.clone().into(),
            root: Chunk {
                tag: "FOR8".to_string(),
                offset: 0,
                aux: 0,
                size: data.len(),
                payload_offset: 0,
                payload_end: data.len(),
                form_type: Some("Maya".to_string()),
                child_alignment: Some(8),
                child_header_size: Some(16),
                children_parsed: true,
                children: root_children,
            },
        }
    }

    #[test]
    fn build_scene_model_recovers_nodes_links_and_selects() {
        let source = repo_root().join("tests/02/sphere.mb");
        let mb = parse_file(&source).unwrap();
        let output = build_scene_model(
            &mb,
            None,
            Arc::new(crate::scene::schema::SchemaRegistry::new(
                crate::scene::schema::locator::SchemaPaths::from_defaults(),
            )),
        );
        let model = &output.scene;

        assert!(model.nodes.iter().any(|n| n.name == "persp"));
        assert!(model.nodes.iter().any(|n| n.node_type == "script"));
        assert!(
            model
                .nodes
                .iter()
                .filter(|node| node.node_type == "script")
                .flat_map(|node| node.attrs.iter())
                .any(|attr| matches!(
                    attr,
                    crate::scene::ir::RecoveredAttrOp::SetAttr(op)
                        if op.attr_name_or_path == ".b"
                            && matches!(
                                op.value,
                                crate::scene::ir::SetAttrValue::String(ref body) if !body.is_empty()
                            )
                ))
        );
        assert!(
            model
                .select_blocks
                .iter()
                .any(|block| block.target == ":time1")
        );
        assert!(model.links.iter().any(|link| matches!(
            link,
            LinkOp::Connect { src, dst, .. }
                if src == "polySphere1.out" && dst == "pSphereShape1.i"
        )));
        assert!(!output.artifacts.raw_chunks.is_empty());
        assert!(
            output
                .artifacts
                .raw_chunks
                .iter()
                .any(|record| record.chunk_ref.form == "SLCT" && record.chunk_ref.tag == "SLCT")
        );
    }

    #[test]
    fn build_scene_model_preserves_duplicate_candidates_without_uid_merge() {
        let crea = build_test_chunk("CREA", b"script1\0");
        let first = build_test_form("SCRP", std::slice::from_ref(&crea));
        let second = build_test_form("SCRP", std::slice::from_ref(&crea));
        let mb = build_test_mb(&[first, second]);

        let output = build_scene_model(
            &mb,
            None,
            Arc::new(crate::scene::schema::SchemaRegistry::new(
                crate::scene::schema::locator::SchemaPaths::from_defaults(),
            )),
        );
        let script_nodes = output
            .scene
            .nodes
            .iter()
            .filter(|node| node.node_type == "script" && node.name == "script1")
            .collect::<Vec<_>>();

        assert_eq!(script_nodes.len(), 2);
        assert!(script_nodes.iter().all(|node| {
            node.decode_notes.iter().any(|note| {
                note.reason.as_deref()
                    == Some(
                        "duplicate recovered node base key encountered; preserved separate recovered candidates",
                    )
            })
        }));
        assert_eq!(
            output.typeid_resolver_status,
            TypeIdResolverStatus::LoadedDefault
        );
    }

    #[test]
    fn build_scene_model_reports_default_resolver_load_failure() {
        let source = repo_root().join("tests/02/sphere.mb");
        let mb = parse_file(&source).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let bad_node_info = dir.path().join("node_info.yaml");
        std::fs::write(&bad_node_info, "not: [valid").unwrap();
        let mut paths = SchemaPaths::from_defaults();
        paths.node_info_schema_file = bad_node_info.clone();

        let output = build_scene_model(
            &mb,
            None,
            Arc::new(crate::scene::schema::SchemaRegistry::new(paths)),
        );
        match output.typeid_resolver_status {
            TypeIdResolverStatus::DefaultLoadFailed { message } => {
                assert!(message.contains("node_info.yaml"));
            }
            other => panic!("unexpected resolver status: {other:?}"),
        }
    }

    #[test]
    fn reference_file_op_from_entry_propagates_trace() {
        let entry = MbScenePathEntry {
            node_type: "reference".to_string(),
            node_name: "charARN".to_string(),
            attr: ".fn".to_string(),
            value: "rig/charA_v001.mb".to_string(),
            meta: Some(MbScenePathMeta {
                origin: "fref".to_string(),
                short_name: Some("charA".to_string()),
                reference_node: Some("charARN".to_string()),
                format_hint: Some("mayaBinary".to_string()),
                reference_options: Some("-op \"v=0\"".to_string()),
                color_space: None,
                raw_fields: vec![],
                trace_form: Some("FREF".to_string()),
                trace_tag: Some("FREF".to_string()),
                trace_node_offset: Some(0x1234),
                trace_child_alignment: Some(8),
                trace_child_header_size: Some(16),
            }),
        };

        let op = crate::scene::recover::references::reference_file_op_from_entry(entry)
            .expect("reference op");
        assert_eq!(op.path, "rig/charA_v001.mb");
        assert_eq!(op.namespace, "charA");
        assert_eq!(op.reference_node, "charARN");
        assert_eq!(op.options.as_deref(), Some("v=0"));
        assert!(matches!(op.confidence, Confidence::Exact));
        let trace = op.trace.expect("trace");
        assert_eq!(trace.form, "FREF");
        assert_eq!(trace.tag, "FREF");
        assert_eq!(trace.node_offset, 0x1234);
        assert_eq!(trace.child_alignment, Some(8));
        assert_eq!(trace.child_header_size, Some(16));
    }

    #[test]
    fn recover_reference_files_includes_frdi_events() {
        let decoded = vec![crate::scene::ir::DecodedChunkRecord {
            chunk_ref: crate::scene::ir::ChunkRef {
                form: "FRDI".to_string(),
                tag: "FRDI".to_string(),
                node_offset: 0x999,
                parent_tag: Some("FOR8".to_string()),
                chunk_aux: None,
                child_alignment: Some(8),
                child_header_size: Some(16),
                payload_size: 0,
            },
            events: vec![DecodedEvent::ReferenceFile {
                path: "scenes/TestScene_0000.mb".to_string(),
                reference_node: "Example:ModelRN".to_string(),
                namespace: Some("Model".to_string()),
                file_type: Some("mayaBinary".to_string()),
                options: Some("VERS|2020|".to_string()),
            }],
            quality: crate::scene::ir::SchemaDecodeAttemptResult::Exact,
        }];

        let refs = crate::scene::recover::references::recover_reference_files(&decoded);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].path, "scenes/TestScene_0000.mb");
        assert_eq!(refs[0].namespace, "Model");
        assert_eq!(refs[0].reference_node, "Example:ModelRN");
        assert_eq!(refs[0].options.as_deref(), Some("VERS|2020|"));
        let trace = refs[0].trace.as_ref().expect("trace");
        assert_eq!(trace.form, "FRDI");
        assert_eq!(trace.tag, "FRDI");
    }

    #[test]
    fn recover_reference_files_dedupes_matching_fref_and_frdi_root_entries() {
        let decoded = vec![
            crate::scene::ir::DecodedChunkRecord {
                chunk_ref: crate::scene::ir::ChunkRef {
                    form: "FRDI".to_string(),
                    tag: "FRDI".to_string(),
                    node_offset: 0x111,
                    parent_tag: Some("FOR8".to_string()),
                    chunk_aux: None,
                    child_alignment: Some(8),
                    child_header_size: Some(16),
                    payload_size: 0,
                },
                events: vec![DecodedEvent::ReferenceFile {
                    path: "rig.mb".to_string(),
                    reference_node: "ExampleRN".to_string(),
                    namespace: Some("Example".to_string()),
                    file_type: Some("mayaBinary".to_string()),
                    options: Some("VERS|2020|".to_string()),
                }],
                quality: crate::scene::ir::SchemaDecodeAttemptResult::Exact,
            },
            crate::scene::ir::DecodedChunkRecord {
                chunk_ref: crate::scene::ir::ChunkRef {
                    form: "FREF".to_string(),
                    tag: "FREF".to_string(),
                    node_offset: 0x222,
                    parent_tag: Some("FOR8".to_string()),
                    chunk_aux: None,
                    child_alignment: Some(8),
                    child_header_size: Some(16),
                    payload_size: 0,
                },
                events: vec![DecodedEvent::ReferenceFile {
                    path: "rig.mb".to_string(),
                    reference_node: "ExampleRN".to_string(),
                    namespace: Some("Example".to_string()),
                    file_type: Some("mayaBinary".to_string()),
                    options: Some("VERS|2020|".to_string()),
                }],
                quality: crate::scene::ir::SchemaDecodeAttemptResult::Exact,
            },
        ];

        let refs = crate::scene::recover::references::recover_reference_files(&decoded);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].reference_node, "ExampleRN");
        assert_eq!(refs[0].path, "rig.mb");
        assert_eq!(refs[0].options.as_deref(), Some("VERS|2020|"));
    }

    #[test]
    fn parse_form_type_id_supports_ascii_and_hex_forms() {
        assert_eq!(
            crate::scene::recover::nodes::parse_form_type_id("JOIN"),
            Some(0x4A4F494E)
        );
        assert_eq!(
            crate::scene::recover::nodes::parse_form_type_id("[00115DC3]"),
            Some(0x0011_5DC3)
        );
    }

    #[test]
    fn infer_node_type_from_name_supports_suffix_forms() {
        assert_eq!(
            crate::scene::recover::nodes::infer_node_type_from_name("customNodeType63").as_deref(),
            Some("customNodeType")
        );
        assert_eq!(
            crate::scene::recover::nodes::infer_node_type_from_name("L_AddW0_1_pointConstraint1")
                .as_deref(),
            Some("pointConstraint")
        );
        assert_eq!(
            crate::scene::recover::nodes::infer_node_type_from_name("defaultArnoldRenderOptions"),
            None
        );
    }

    #[test]
    fn recovered_node_merge_key_separates_uid_scoped_candidates() {
        let a = crate::scene::recover::nodes::recovered_node_merge_key(
            "transform",
            "pCube1",
            Some("|group1"),
            Some("UID-A"),
            0,
        );
        let b = crate::scene::recover::nodes::recovered_node_merge_key(
            "transform",
            "pCube1",
            Some("|group1"),
            Some("UID-B"),
            0,
        );
        let c = crate::scene::recover::nodes::recovered_node_merge_key(
            "transform",
            "pCube1",
            Some("|group1"),
            None,
            0,
        );

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn normalize_nested_reference_paths_uses_parent_incl_for_relative_nested_paths() {
        let mut refs = vec![
            ReferenceFileOp {
                path: "D:/example/TestScene.mb".to_string(),
                namespace: "Example".to_string(),
                reference_node: "ExampleRN".to_string(),
                file_type: "mayaBinary".to_string(),
                options: Some(
                    "VERS|2020|INCL|D:/example/TestScene_0000_Model.mb(|LUNI|cm|".to_string(),
                ),
                namespace_defaulted: false,
                file_type_defaulted: false,
                path_inferred_from_parent_include: false,
                trace: None,
                confidence: Confidence::Inferred,
            },
            ReferenceFileOp {
                path: "scenes/TestScene_0000_Model.mb".to_string(),
                namespace: "Model".to_string(),
                reference_node: "Example:ModelRN".to_string(),
                file_type: "mayaBinary".to_string(),
                options: Some("VERS|2020|INCL|D:/example/TestScene_0000_low.mb(|LUNI|cm|".to_string()),
                namespace_defaulted: false,
                file_type_defaulted: false,
                path_inferred_from_parent_include: false,
                trace: None,
                confidence: Confidence::Inferred,
            },
            ReferenceFileOp {
                path: "scenes/TestScene_0000_low.mb".to_string(),
                namespace: "Scale".to_string(),
                reference_node: "Example:Model:ScaleRN".to_string(),
                file_type: "mayaBinary".to_string(),
                options: Some("VERS|2020|INCL|undef(|LUNI|cm|".to_string()),
                namespace_defaulted: false,
                file_type_defaulted: false,
                path_inferred_from_parent_include: false,
                trace: None,
                confidence: Confidence::Inferred,
            },
            ReferenceFileOp {
                path: "scenes/TestScene_0000.mb".to_string(),
                namespace: "Import_Model".to_string(),
                reference_node: "Import:Import_ModelRN".to_string(),
                file_type: "mayaBinary".to_string(),
                options: Some("VERS|2020|INCL|undef(|LUNI|cm|".to_string()),
                namespace_defaulted: false,
                file_type_defaulted: false,
                path_inferred_from_parent_include: false,
                trace: None,
                confidence: Confidence::Inferred,
            },
        ];

        crate::scene::recover::references::normalize_nested_reference_paths(&mut refs);

        assert_eq!(refs[1].path, "D:/example/TestScene_0000_Model.mb");
        assert_eq!(refs[2].path, "D:/example/TestScene_0000_low.mb");
        assert_eq!(refs[3].path, "scenes/TestScene_0000.mb");
    }
}
