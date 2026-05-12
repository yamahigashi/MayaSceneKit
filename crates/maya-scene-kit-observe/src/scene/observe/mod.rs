#[cfg(test)]
pub(crate) use crate::scene::execution::{catalog, dependency, surfaces};

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use maya_scene_kit_formats::ma as format_ma;

    use super::{catalog, dependency, surfaces};
    use crate::{
        mb::{MbParseBudget, MbParseBudgetLimit},
        scene::{
            DependencyFactDetail, DependencyFactKind, DependencyRiskClass, EffectCertainty,
            ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind, ExecutionCoverageState,
            ExecutionEffectClass, ExecutionSemanticClass, ExecutionSurfaceKind, LoadOptions,
            Loader, MelParseBudget, MelParseBudgetLimit, ScenePathResolutionContext,
            SceneResourceResolver, SceneToolError, ValidationState, collect_scene_dump,
            collect_scene_paths,
            core::SceneFormat,
            dump::SceneDumpRequireKind,
            find_scene_workspace_root,
            paths::{PathKind, ScenePathResolutionStatus, ScenePathValueStyle},
            source::{
                loader::{MbParseBudgetMode, materialize_adaptive_mb_parse_budget},
                ma as observe_ma, mb,
            },
        },
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn wrap_scene_with_refedit(snippet: &str) -> String {
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode reference -n \"refNode\";\n",
                "{snippet}\n",
                "createNode script -n \"scriptNode1\";\n",
                "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
            ),
            snippet = snippet,
        )
    }

    fn build_mb_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(payload);
        while (out.len() - 16) % 8 != 0 {
            out.push(0);
        }
        out
    }

    fn build_mb_form(form: &str, children: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = form.as_bytes().to_vec();
        for child in children {
            payload.extend_from_slice(child);
        }
        build_mb_chunk("FOR8", &payload)
    }

    fn build_mb_root(children: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = b"Maya".to_vec();
        for child in children {
            payload.extend_from_slice(child);
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"FOR8");
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn build_mb_chunk_with_alignment(
        tag: &str,
        payload: &[u8],
        sibling_alignment: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(payload);
        while (out.len() - 16) % sibling_alignment != 0 {
            out.push(0);
        }
        out
    }

    fn build_mb_form_with_alignment(
        form: &str,
        children: &[Vec<u8>],
        sibling_alignment: usize,
    ) -> Vec<u8> {
        let mut payload = form.as_bytes().to_vec();
        for child in children {
            payload.extend_from_slice(child);
        }
        build_mb_chunk_with_alignment("FOR8", &payload, sibling_alignment)
    }

    fn build_repeated_mb_form(
        form: &str,
        chunk_tag: &str,
        chunk_payload: &[u8],
        count: usize,
        sibling_alignment: usize,
    ) -> Vec<u8> {
        let mut payload =
            Vec::with_capacity(form.len() + count.saturating_mul(16 + chunk_payload.len()));
        payload.extend_from_slice(form.as_bytes());
        for _ in 0..count {
            payload.extend_from_slice(&build_mb_chunk_with_alignment(
                chunk_tag,
                chunk_payload,
                sibling_alignment,
            ));
        }
        build_mb_chunk_with_alignment("FOR8", &payload, sibling_alignment)
    }

    #[test]
    fn ma_script_entries_tolerate_data_reference_edits_blocks() {
        let fixtures = [
            include_str!(
                "../../../../../tests/fixtures/refedit/sanitized/case_op3_empty_tail_ed_block01.ma"
            ),
            include_str!(
                "../../../../../tests/fixtures/refedit/sanitized/case_op0_flag_payload_ed_block02.ma"
            ),
            include_str!(
                "../../../../../tests/fixtures/refedit/sanitized/case_op5_placeholder_ed_block01.ma"
            ),
            include_str!(
                "../../../../../tests/fixtures/refedit/sanitized/case_mixed_op2_op0_ed_block02.ma"
            ),
            include_str!(
                "../../../../../tests/fixtures/refedit/sanitized/case_empty_root_ed_block06.ma"
            ),
        ];

        for fixture in fixtures {
            let scene = wrap_scene_with_refedit(fixture);
            let raw_entries =
                format_ma::scripts::extract_raw_script_entries_from_ma(scene.as_bytes());
            let entries = observe_ma::collect_ma_script_entries(&raw_entries);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name, "scriptNode1");
            assert_eq!(entries[0].body, "print \"ok\";");
        }
    }

    #[test]
    fn ma_scene_paths_tolerate_data_reference_edits_blocks() {
        let scene = wrap_scene_with_refedit(include_str!(
            "../../../../../tests/fixtures/refedit/sanitized/case_mixed_op2_op0_ed_block02.ma"
        ));

        let entries = observe_ma::collect_ma_scene_paths(scene.as_bytes());
        let file_entries = entries
            .into_iter()
            .filter(|entry| entry.node_type == "file" && entry.attr == ".ftn")
            .collect::<Vec<_>>();

        assert_eq!(file_entries.len(), 1);
        assert_eq!(
            PathKind::File,
            mb::canonical_scene_path_entry_kind(&file_entries[0])
        );
        assert_eq!(file_entries[0].value, "textures/albedo.png");
    }

    #[test]
    fn ma_extractors_tolerate_opaque_typed_attrs() {
        let scene = include_str!("../../../../../tests/fixtures/ma/opaque_typed_attrs.ma");
        let raw_entries = format_ma::scripts::extract_raw_script_entries_from_ma(scene.as_bytes());
        let script_entries = observe_ma::collect_ma_script_entries(&raw_entries);
        assert_eq!(script_entries.len(), 1);
        assert_eq!(script_entries[0].name, "scriptNode1");
        assert_eq!(script_entries[0].body, "print \"opaque ok\";");

        let path_entries = observe_ma::collect_ma_scene_paths(scene.as_bytes());
        let file_entries = path_entries
            .into_iter()
            .filter(|entry| entry.node_type == "file" && entry.attr == ".ftn")
            .collect::<Vec<_>>();
        assert_eq!(file_entries.len(), 1);
        assert_eq!(file_entries[0].value, "textures/albedo.png");
    }

    #[test]
    fn derive_coverage_state_does_not_blanket_block_mb() {
        assert_eq!(
            catalog::derive_coverage_state(SceneFormat::Mb, &[]),
            ExecutionCoverageState::Complete
        );
        assert_eq!(
            catalog::derive_coverage_state(
                SceneFormat::Mb,
                &[surfaces::ExecutionCoverageIssueRecord {
                    kind: ExecutionCoverageIssueKind::UnsupportedCoverage,
                    detail: ExecutionCoverageIssueDetail::UnsupportedTopLevelStatement,
                    origin: None,
                    preview: surfaces::PreviewWindowSpec::new(Arc::<str>::from(""), 0, 0),
                }]
            ),
            ExecutionCoverageState::Unsupported
        );
    }

    #[test]
    fn ma_dependency_facts_dedup_duplicate_scene_path_targets() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("duplicate_paths.ma");
        std::fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode file -n \"fileA\";\n",
                "    setAttr \".ftn\" -type \"string\" \"shared/path/albedo.png\";\n",
                "createNode file -n \"fileB\";\n",
                "    setAttr \".ftn\" -type \"string\" \"shared/path/albedo.png\";\n",
            ),
        )
        .expect("write fixture");

        let observation = Loader::new(Default::default())
            .observe_path(&source)
            .expect("observation");
        let dependency_facts = observation.dependency_facts(24).expect("dependency facts");
        let file_path_facts = dependency_facts
            .iter()
            .filter(|fact| {
                fact.kind == DependencyFactKind::FilePath && fact.target == "shared/path/albedo.png"
            })
            .collect::<Vec<_>>();

        assert_eq!(file_path_facts.len(), 1);
    }

    #[test]
    fn malformed_ma_top_level_diagnostics_downgrade_validation_and_coverage() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("malformed_top_level.ma");
        fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode file -n \"file1\";\n",
                "/* hidden tail\n",
                "file -r -rfn \"charARN\" \"rig/charA_v001.mb\";\n",
                "createNode script -n \"scriptNode1\";\n",
                "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
            ),
        )
        .expect("write malformed scene");

        let observation = Loader::new(Default::default())
            .observe_path(&source)
            .expect("observation");
        let catalog = observation
            .observed_execution_catalog(64)
            .expect("execution catalog");

        assert_eq!(observation.validation_state(), ValidationState::Partial);
        assert_eq!(catalog.coverage_state, ExecutionCoverageState::Incomplete);
        assert!(catalog.surfaces.is_empty());
        assert!(
            catalog
                .coverage_issues
                .iter()
                .any(|issue| { issue.kind == ExecutionCoverageIssueKind::TopLevelDiagnostics })
        );
    }

    #[test]
    fn ma_budget_exceed_returns_error_for_observe_path_and_bytes() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("budget_exceeded.ma");
        let bytes = concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
        )
        .as_bytes()
        .to_vec();
        fs::write(&source, &bytes).expect("write scene");
        let options = LoadOptions::default().with_max_parse_bytes(8);

        let path_err = Loader::new(options.clone())
            .observe_path(&source)
            .err()
            .expect("path budget rejection");
        let bytes_err = Loader::new(options)
            .observe_bytes(&source, SceneFormat::Ma, ValidationState::Validated, bytes)
            .err()
            .expect("bytes budget rejection");

        for err in [path_err, bytes_err] {
            match err {
                SceneToolError::MelParseBudgetExceeded { limit } => {
                    assert_eq!(limit, MelParseBudgetLimit::MaxBytes);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn mel_surface_budget_exceed_fails_catalog_instead_of_partial_success() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("surface_budget.ma");
        fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"scriptNode1\";\n",
                "    setAttr \".b\" -type \"string\" \"if (1) { if (1) { print \\\"hi\\\"; } }\";\n",
            ),
        )
        .expect("write scene");
        let options = LoadOptions::default().with_mel_parse_budget(MelParseBudget {
            max_nesting_depth: 1,
            ..MelParseBudget::default()
        });

        let observation = Loader::new(options)
            .observe_path(&source)
            .expect("observation");
        let err = observation
            .observed_execution_catalog(64)
            .expect_err("surface budget rejection");

        match err {
            SceneToolError::MelParseBudgetExceeded { limit } => {
                assert_eq!(limit, MelParseBudgetLimit::MaxNestingDepth);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn mb_budget_exceed_returns_error_for_observe_path_and_bytes() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = repo_root().join("tests/02/sphere.mb");
        let bytes = fs::read(&source).expect("fixture bytes");
        let target = dir.path().join("budget_exceeded.mb");
        fs::write(&target, &bytes).expect("write fixture copy");
        let options = LoadOptions::default().with_max_parse_bytes(1);

        let path_err = Loader::new(options.clone())
            .observe_path(&target)
            .err()
            .expect("path budget rejection");
        let bytes_err = Loader::new(options)
            .observe_bytes(&target, SceneFormat::Mb, ValidationState::Validated, bytes)
            .err()
            .expect("bytes budget rejection");

        for err in [path_err, bytes_err] {
            match err {
                SceneToolError::MbParseBudgetExceeded { limit } => {
                    assert_eq!(limit, MbParseBudgetLimit::MaxParseBytes);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn mb_child_budget_exceed_fails_observe_path_immediately() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("surface_budget.mb");
        let bytes = build_mb_root(&[build_mb_form(
            "TEST",
            &[build_mb_chunk("ONE ", b"1"), build_mb_chunk("TWO ", b"2")],
        )]);
        fs::write(&source, bytes).expect("write scene");
        let options = LoadOptions::default().with_mb_parse_budget(MbParseBudget {
            max_children_per_group: 1,
            ..MbParseBudget::default()
        });

        let err = Loader::new(options)
            .observe_path(&source)
            .err()
            .expect("observe path budget rejection");

        match err {
            SceneToolError::MbParseBudgetExceeded { limit } => {
                assert_eq!(limit, MbParseBudgetLimit::MaxChildrenPerGroup);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn observed_execution_surfaces_reuse_mel_facts_across_preview_sizes() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("cached_surfaces.ma");
        std::fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"scriptNode1\";\n",
                "\tsetAttr \".b\" -type \"string\" \"source \\\"tools/startup.mel\\\"; print \\\"abcdefghijklmnopqrstuvwxyz0123456789\\\";\";\n",
                "\tsetAttr \".st\" 1;\n",
            ),
        )
        .expect("write fixture");

        let observation = Loader::new(Default::default())
            .observe_path(&source)
            .expect("observation");

        let short = observation
            .observed_execution_surfaces(16)
            .expect("short preview surfaces");
        let long = observation
            .observed_execution_surfaces(80)
            .expect("long preview surfaces");

        let short_script = short
            .iter()
            .find(|surface| surface.surface.origin.node_name.as_deref() == Some("scriptNode1"))
            .expect("short script surface");
        let long_script = long
            .iter()
            .find(|surface| surface.surface.origin.node_name.as_deref() == Some("scriptNode1"))
            .expect("long script surface");

        assert_ne!(short_script.surface.preview, long_script.surface.preview);
        assert!(Arc::ptr_eq(
            short_script.mel.as_ref().expect("short mel facts"),
            long_script.mel.as_ref().expect("long mel facts")
        ));
    }

    #[test]
    fn repeated_observe_queries_reuse_cached_semantic_core_and_digests() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("cached_catalog.ma");
        std::fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"scriptNode1\";\n",
                "\tsetAttr \".b\" -type \"string\" \"source \\\"tools/startup.mel\\\"; python(\\\"print('hi')\\\");\";\n",
                "\tsetAttr \".st\" 1;\n",
                "createNode file -n \"file1\";\n",
                "\tsetAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
            ),
        )
        .expect("write fixture");

        let observation = Loader::new(Default::default())
            .observe_path(&source)
            .expect("observation");

        assert!(observation.cached_execution_core_ptr().is_none());
        assert!(observation.cached_scene_digests_ptr().is_none());

        let preview_only_catalog = observation
            .observed_execution_catalog_with_digests(16, false)
            .expect("catalog without digests");
        assert!(!preview_only_catalog.unit_summaries.is_empty());
        assert!(preview_only_catalog.digests.scene_sha256.is_empty());
        let core_ptr = observation
            .cached_execution_core_ptr()
            .expect("cached execution core after preview-only catalog");
        assert!(observation.cached_scene_digests_ptr().is_none());

        let summaries = observation
            .execution_unit_summaries(16)
            .expect("execution unit summaries");
        assert!(!summaries.is_empty());
        assert_eq!(
            core_ptr,
            observation
                .cached_execution_core_ptr()
                .expect("cached execution core after summaries")
        );
        let digests_ptr = observation
            .cached_scene_digests_ptr()
            .expect("cached scene digests after summaries");

        let surfaces = observation
            .observed_execution_surfaces(80)
            .expect("observed execution surfaces");
        assert!(!surfaces.is_empty());
        assert_eq!(
            core_ptr,
            observation
                .cached_execution_core_ptr()
                .expect("cached execution core after surfaces")
        );
        assert_eq!(
            digests_ptr,
            observation
                .cached_scene_digests_ptr()
                .expect("cached scene digests after surfaces")
        );

        let dependency_facts = observation.dependency_facts(24).expect("dependency facts");
        assert!(!dependency_facts.is_empty());
        assert_eq!(
            core_ptr,
            observation
                .cached_execution_core_ptr()
                .expect("cached execution core after dependency facts")
        );
        assert_eq!(
            digests_ptr,
            observation
                .cached_scene_digests_ptr()
                .expect("cached scene digests after dependency facts")
        );

        let digests = observation.scene_digests(0).expect("scene digests");
        assert!(!digests.scene_sha256.is_empty());
        assert_eq!(
            digests_ptr,
            observation
                .cached_scene_digests_ptr()
                .expect("cached scene digests after digests query")
        );

        let catalog = observation
            .observed_execution_catalog_with_digests(8, true)
            .expect("catalog with digests");
        assert!(!catalog.digests.scene_sha256.is_empty());
        assert_eq!(
            core_ptr,
            observation
                .cached_execution_core_ptr()
                .expect("cached execution core after catalog")
        );
        assert_eq!(
            digests_ptr,
            observation
                .cached_scene_digests_ptr()
                .expect("cached scene digests after catalog")
        );
    }

    #[test]
    fn ma_observe_path_without_retained_bytes_reloads_only_on_digest_demand() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("transient_bytes.ma");
        std::fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"scriptNode1\";\n",
                "\tsetAttr \".b\" -type \"string\" \"python(\\\"print('hi')\\\")\";\n",
                "\tsetAttr \".st\" 1;\n",
                "createNode file -n \"file1\";\n",
                "\tsetAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
            ),
        )
        .expect("write fixture");

        let retained = Loader::new(Default::default())
            .observe_path(&source)
            .expect("retained observation");
        let transient = Loader::new(Default::default())
            .observe_path_without_retained_ma_bytes(&source)
            .expect("transient observation");

        assert!(retained.cached_ma_bytes_ptr().is_some());
        assert!(transient.cached_ma_bytes_ptr().is_none());

        let dump = transient.scene_dump_report().expect("scene dump");
        assert_eq!(dump.script_entries.len(), 1);
        let paths = transient.scene_paths(PathKind::File).expect("scene paths");
        assert_eq!(paths.len(), 1);
        assert!(transient.cached_ma_bytes_ptr().is_none());

        let digests = transient.scene_digests(0).expect("scene digests");
        assert!(!digests.scene_sha256.is_empty());
        assert!(transient.cached_ma_bytes_ptr().is_some());
    }

    #[test]
    fn scene_digests_do_not_force_semantic_core_build() {
        let source = repo_root().join("tests/02/sphere.mb");
        let observation = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observation");

        assert!(observation.cached_execution_core_ptr().is_none());
        assert!(observation.cached_scene_digests_ptr().is_none());

        let digests = observation.scene_digests(0).expect("scene digests");

        assert!(!digests.scene_sha256.is_empty());
        assert!(observation.cached_execution_core_ptr().is_none());
        assert!(observation.cached_scene_digests_ptr().is_some());
    }

    #[test]
    fn execution_observation_path_defers_mb_integrity_decode() {
        let source = repo_root().join("tests/02/sphere.mb");
        let observation = Loader::new(LoadOptions::default())
            .observe_execution_path(&source)
            .expect("observation");

        assert_eq!(observation.validation_state(), ValidationState::Partial);

        let catalog = observation
            .observed_execution_catalog(24)
            .expect("execution catalog");

        assert!(!catalog.surfaces.is_empty());
    }

    #[test]
    fn ma_observation_catalog_includes_render_globals_callbacks_from_path_and_bytes() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("render_callbacks.ma");
        let bytes = concat!(
            "//Maya ASCII 2026 scene\n",
            "select -ne :defaultRenderGlobals;\n",
            "    setAttr \".poam\" -type \"string\" \"eval(\\\"ExampleCallback;\\\")\";\n",
            "    setAttr \".prlm\" -type \"string\" \"python(\\\"print(\\\\\\\"Example\\\\\\\")\\\")\";\n",
        )
        .as_bytes()
        .to_vec();
        fs::write(&source, &bytes).expect("write scene");

        let path_observation = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("path observation");
        let bytes_observation = Loader::new(LoadOptions::default())
            .observe_bytes(&source, SceneFormat::Ma, ValidationState::Validated, bytes)
            .expect("bytes observation");

        for observation in [&path_observation, &bytes_observation] {
            let catalog = observation
                .observed_execution_catalog(64)
                .expect("execution catalog");
            assert!(catalog.surfaces.iter().any(|surface| {
                surface.surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                    && surface.surface.origin.node_name.as_deref() == Some("defaultRenderGlobals")
                    && surface.surface.origin.attr_name.as_deref() == Some(".poam")
            }));
            assert!(catalog.surfaces.iter().any(|surface| {
                surface.surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                    && surface.surface.origin.attr_name.as_deref() == Some(".prlm")
            }));
        }
    }

    #[test]
    fn ma_expression_literal_python_bridge_uses_inner_python_summary() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("expression_python_print.ma");
        fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode expression -n \"ExampleExpression\";\n",
                "    setAttr \".ixp\" -type \"string\" \"python(\\\"print('Sample')\\\");\";\n",
            ),
        )
        .expect("write scene");

        let catalog = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observation")
            .observed_execution_catalog(64)
            .expect("execution catalog");
        let summary = catalog
            .unit_summaries
            .iter()
            .find(|summary| {
                summary.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                    && summary.origin.attr_name.as_deref() == Some(".ixp")
            })
            .expect("expression summary");

        assert_eq!(
            summary.origin.source_kind.as_deref(),
            Some("internalExpression")
        );
        assert_eq!(summary.effect, ExecutionEffectClass::DiagnosticOutput);
        assert_eq!(summary.semantic_class, ExecutionSemanticClass::General);
        assert_eq!(summary.certainty, EffectCertainty::Proven);
    }

    #[test]
    fn ma_expression_dynamic_python_bridge_keeps_mel_dynamic_summary() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("expression_python_dynamic.ma");
        fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode expression -n \"ExampleExpression\";\n",
                "    setAttr \".ixp\" -type \"string\" \"$body = \\\"print('Sample')\\\"; python($body);\";\n",
            ),
        )
        .expect("write scene");

        let catalog = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observation")
            .observed_execution_catalog(64)
            .expect("execution catalog");
        let summary = catalog
            .unit_summaries
            .iter()
            .find(|summary| {
                summary.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                    && summary.origin.attr_name.as_deref() == Some(".ixp")
            })
            .expect("expression summary");

        assert_eq!(summary.effect, ExecutionEffectClass::DynamicEvaluation);
    }

    #[test]
    fn ma_analysis_observation_captures_execution_attrs_without_lazy_execution_sections() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("analysis_render_callbacks.ma");
        let bytes = concat!(
            "//Maya ASCII 2026 scene\n",
            "select -ne :defaultRenderGlobals;\n",
            "    setAttr \".poam\" -type \"string\" \"eval(\\\"ExampleCallback;\\\")\";\n",
            "    setAttr \".prlm\" -type \"string\" \"python(\\\"print(\\\\\\\"Example\\\\\\\")\\\")\";\n",
        )
        .as_bytes()
        .to_vec();
        fs::write(&source, &bytes).expect("write scene");

        let path_observation = Loader::new(LoadOptions::default())
            .observe_analysis_path(&source)
            .expect("path analysis observation");
        let bytes_observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(&source, SceneFormat::Ma, ValidationState::Validated, bytes)
            .expect("bytes analysis observation");

        for observation in [&path_observation, &bytes_observation] {
            assert!(observation.cached_ma_bytes_ptr().is_some());
            assert!(observation.cached_ma_execution_sections_ptr().is_none());

            let catalog = observation
                .observed_execution_catalog(64)
                .expect("execution catalog");

            assert!(catalog.surfaces.iter().any(|surface| {
                surface.surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                    && surface.surface.origin.node_name.as_deref() == Some("defaultRenderGlobals")
                    && surface.surface.origin.attr_name.as_deref() == Some(".poam")
            }));
            assert!(catalog.surfaces.iter().any(|surface| {
                surface.surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                    && surface.surface.origin.attr_name.as_deref() == Some(".prlm")
            }));
            assert!(observation.cached_ma_execution_sections_ptr().is_none());
        }
    }

    #[test]
    fn ma_execution_observation_matches_regular_observation_catalog() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("execution_match.ma");
        fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "createNode script -n \"ExampleScript\";\n",
                "    setAttr \".a\" -type \"string\" \"print \\\"After\\\";\";\n",
                "    setAttr \".b\" -type \"string\" \"print \\\"Before\\\";\";\n",
                "    setAttr \".st\" 1;\n",
                "select -ne :defaultRenderGlobals;\n",
                "    setAttr \".prm\" -type \"string\" \"print \\\"Render\\\";\";\n",
            ),
        )
        .expect("write scene");

        let regular = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("regular observation")
            .observed_execution_catalog(64)
            .expect("regular catalog");
        let execution = Loader::new(LoadOptions::default())
            .observe_execution_path(&source)
            .expect("execution observation")
            .observed_execution_catalog(64)
            .expect("execution catalog");
        let execution_bytes = Loader::new(LoadOptions::default())
            .observe_execution_bytes(
                &source,
                SceneFormat::Ma,
                ValidationState::Validated,
                fs::read(&source).expect("read scene"),
            )
            .expect("execution bytes observation")
            .observed_execution_catalog(64)
            .expect("execution bytes catalog");

        let regular_origins = regular
            .surfaces
            .iter()
            .map(|surface| {
                (
                    surface.surface.origin.surface_kind,
                    surface.surface.origin.node_name.clone(),
                    surface.surface.origin.attr_name.clone(),
                )
            })
            .collect::<Vec<_>>();
        let execution_origins = execution
            .surfaces
            .iter()
            .map(|surface| {
                (
                    surface.surface.origin.surface_kind,
                    surface.surface.origin.node_name.clone(),
                    surface.surface.origin.attr_name.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(regular_origins, execution_origins);
        let execution_bytes_origins = execution_bytes
            .surfaces
            .iter()
            .map(|surface| {
                (
                    surface.surface.origin.surface_kind,
                    surface.surface.origin.node_name.clone(),
                    surface.surface.origin.attr_name.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(regular_origins, execution_bytes_origins);
    }

    #[test]
    fn mb_scene_paths_do_not_force_full_build() {
        let source = repo_root().join("tests/02/sphere.mb");
        let observation = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observation");

        assert!(observation.cached_mb_scene_facts_ptr().is_none());
        assert!(observation.cached_mb_build_ptr().is_none());

        let paths = observation.scene_paths(PathKind::All).expect("scene paths");

        let _ = paths;
        assert!(observation.cached_mb_scene_facts_ptr().is_none());
        assert!(observation.cached_mb_build_ptr().is_none());
    }

    #[test]
    fn mb_script_entries_do_not_force_full_build() {
        let source = repo_root().join("tests/02/sphere.mb");
        let observation = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observation");

        assert!(observation.cached_mb_scene_facts_ptr().is_none());
        assert!(observation.cached_mb_build_ptr().is_none());

        let entries = observation.script_node_entries().expect("script entries");

        assert!(!entries.is_empty());
        assert!(observation.cached_mb_scene_facts_ptr().is_none());
        assert!(observation.cached_mb_build_ptr().is_none());
    }

    #[test]
    fn mb_analysis_observation_does_not_force_full_build() {
        let source = repo_root().join("tests/02/sphere.mb");
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_path(&source)
            .expect("analysis observation");

        assert_eq!(observation.validation_state(), ValidationState::Partial);
        assert!(observation.cached_mb_scene_facts_ptr().is_none());
        assert!(observation.cached_mb_build_ptr().is_none());

        let catalog = observation
            .observed_execution_catalog(64)
            .expect("execution catalog");

        assert!(!catalog.surfaces.is_empty());
        assert!(observation.cached_mb_scene_facts_ptr().is_none());
        assert!(observation.cached_mb_build_ptr().is_none());
    }

    #[test]
    fn mb_observation_bundle_stays_usable_after_source_file_is_removed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("copied_sphere.mb");
        fs::copy(repo_root().join("tests/02/sphere.mb"), &source).expect("copy fixture");

        let observation = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observation");
        fs::remove_file(&source).expect("remove source");

        let report = observation
            .observed_execution_catalog(24)
            .expect("catalog after source delete");
        assert!(!report.surfaces.is_empty());
        assert!(
            !observation
                .script_node_entries()
                .expect("scripts")
                .is_empty()
        );
    }

    #[test]
    fn ma_observation_skips_schema_context_initialization() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let missing_chunk_root = dir.path().join("missing_chunks");
        let options = LoadOptions::default().with_chunk_schema_root(&missing_chunk_root);

        let observation = Loader::new(options)
            .observe_path(repo_root().join("tests/02/sphere.ma"))
            .expect("ma observation should not require schema context");

        assert_eq!(observation.scene_format(), SceneFormat::Ma);
    }

    #[test]
    fn mb_observation_still_validates_schema_context_inputs() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let missing_chunk_root = dir.path().join("missing_chunks");
        let options = LoadOptions::default().with_chunk_schema_root(&missing_chunk_root);

        let err = match Loader::new(options).observe_path(repo_root().join("tests/02/sphere.mb")) {
            Ok(_) => panic!("mb observation should still require schema context"),
            Err(err) => err,
        };

        match err {
            SceneToolError::Config(message) => {
                assert!(message.contains("missing_chunks"));
            }
            other => panic!("expected schema config error, got {other:?}"),
        }
    }

    #[test]
    fn mb_load_options_accept_parse_budget() {
        let source = repo_root().join("tests/02/sphere.mb");
        let options = LoadOptions::default().with_mb_parse_budget(MbParseBudget {
            max_depth: 128,
            max_children_per_group: 100_000,
            max_total_chunks: 1_000_000,
            max_parse_bytes: 512 * 1024 * 1024,
        });

        let observation = Loader::new(options)
            .observe_path(&source)
            .expect("observation");

        assert_eq!(observation.scene_format(), SceneFormat::Mb);
    }

    #[test]
    fn mb_load_options_default_to_adaptive_mode_and_exact_override() {
        let adaptive = LoadOptions::default();
        let exact = LoadOptions::default().with_mb_parse_budget(MbParseBudget {
            max_depth: 32,
            max_children_per_group: 64,
            max_total_chunks: 128,
            max_parse_bytes: 256,
        });

        assert_eq!(adaptive.mb_parse_budget_mode(), MbParseBudgetMode::Adaptive);
        assert_eq!(exact.mb_parse_budget_mode(), MbParseBudgetMode::Exact);
    }

    #[test]
    fn with_max_parse_bytes_materializes_adaptive_mb_budget_from_effective_bytes() {
        let options = LoadOptions::default().with_max_parse_bytes(80 * 1024 * 1024);
        let adaptive = options.materialize_mb_parse_budget_for_bytes(96 * 1024 * 1024);

        assert_eq!(adaptive.max_depth, 128);
        assert_eq!(adaptive.max_children_per_group, 262_144);
        assert_eq!(adaptive.max_total_chunks, (80 * 1024 * 1024) / 64);
        assert_eq!(adaptive.max_parse_bytes, 80 * 1024 * 1024);
        assert_eq!(options.mel_parse_budget().max_bytes, 80 * 1024 * 1024);
    }

    #[test]
    fn with_max_parse_bytes_preserves_exact_mb_budget_override_shape() {
        let options = LoadOptions::default()
            .with_mb_parse_budget(MbParseBudget {
                max_depth: 7,
                max_children_per_group: 11,
                max_total_chunks: 13,
                max_parse_bytes: 17,
            })
            .with_max_parse_bytes(19);
        let exact = options.materialize_mb_parse_budget_for_bytes(200 * 1024 * 1024);

        assert_eq!(exact.max_depth, 7);
        assert_eq!(exact.max_children_per_group, 11);
        assert_eq!(exact.max_total_chunks, 13);
        assert_eq!(exact.max_parse_bytes, 19);
        assert_eq!(options.mb_parse_budget_mode(), MbParseBudgetMode::Exact);
    }

    #[test]
    fn materialize_adaptive_mb_budget_uses_source_size_capped_by_max_parse_bytes() {
        let adaptive = materialize_adaptive_mb_parse_budget(96 * 1024 * 1024, 80 * 1024 * 1024);

        assert_eq!(adaptive.max_depth, 128);
        assert_eq!(adaptive.max_children_per_group, 262_144);
        assert_eq!(adaptive.max_total_chunks, (80 * 1024 * 1024) / 64);
        assert_eq!(adaptive.max_parse_bytes, 80 * 1024 * 1024);
    }

    #[test]
    fn scene_path_dependency_fact_captures_origin_fields() {
        assert_eq!(
            DependencyFactDetail::ScenePath {
                node_type: "file".to_string(),
                attr: ".ftn".to_string()
            },
            dependency::build_scene_path_dependency_fact(
                DependencyFactKind::FilePath,
                "file",
                ".ftn",
                "textures/albedo.png"
            )
            .detail
        );
        assert_eq!(
            DependencyFactDetail::ScenePath {
                node_type: "cacheFile".to_string(),
                attr: ".fcp".to_string()
            },
            dependency::build_scene_path_dependency_fact(
                DependencyFactKind::FilePath,
                "cacheFile",
                ".fcp",
                "cache/foo.xml"
            )
            .detail
        );
    }

    #[test]
    fn classify_dependency_risk_preserves_common_path_cases() {
        assert_eq!(
            dependency::classify_dependency_risk("C:/textures/albedo.png"),
            DependencyRiskClass::Uncertain
        );
        assert_eq!(
            dependency::classify_dependency_risk("//server/share/albedo.png"),
            DependencyRiskClass::Uncertain
        );
        assert_eq!(
            dependency::classify_dependency_risk("/var/tmp/albedo.png"),
            DependencyRiskClass::Uncertain
        );
        assert_eq!(
            dependency::classify_dependency_risk("../textures/albedo.png"),
            DependencyRiskClass::Review
        );
        assert_eq!(
            dependency::classify_dependency_risk("textures/albedo.png"),
            DependencyRiskClass::Informational
        );
    }

    #[test]
    fn collect_scene_dump_reads_ma_requires_and_scripts() {
        let source = repo_root().join("tests/02/sphere.ma");
        let report = collect_scene_dump(&source).expect("scene dump");

        assert_eq!(report.scene_format, SceneFormat::Ma);
        assert!(report.requires_count() > 0);
        assert_eq!(report.require_entries.len(), report.requires.len());
        assert_eq!(
            report.require_entries[0].kind,
            SceneDumpRequireKind::MayaVersion
        );
        assert!(report.script_entry_count() > 0);
    }

    #[test]
    fn load_options_with_max_parse_bytes_updates_mb_and_mel_budgets() {
        let options = LoadOptions::default().with_max_parse_bytes(1234);

        assert_eq!(options.mb_parse_budget().max_parse_bytes, 1234);
        assert_eq!(options.mel_parse_budget().max_bytes, 1234);
    }

    #[test]
    fn adaptive_default_mb_budget_accepts_wide_group_that_exact_default_rejects() {
        let bytes = build_mb_root(&[build_repeated_mb_form("TEST", "DATA", b"", 100_001, 4)]);
        let exact_mb = crate::mb::parse_bytes_with_budget(bytes.clone(), &MbParseBudget::default())
            .expect("exact default should parse scene");
        let exact_err = crate::scene::recover::collect_raw_chunk_records_with_budget(
            &exact_mb,
            &MbParseBudget::default(),
        )
        .expect_err("exact default should reject wide group during raw walk");
        let adaptive_budget =
            LoadOptions::default().materialize_mb_parse_budget_for_bytes(bytes.len());
        let adaptive_mb = crate::mb::parse_bytes_with_budget(bytes, &adaptive_budget)
            .expect("adaptive default should parse scene");
        let adaptive_raw = crate::scene::recover::collect_raw_chunk_records_with_budget(
            &adaptive_mb,
            &adaptive_budget,
        )
        .expect("adaptive default should walk wide group");

        assert_eq!(
            exact_err.budget_limit(),
            Some(MbParseBudgetLimit::MaxChildrenPerGroup)
        );
        assert!(!adaptive_raw.is_empty());
    }

    #[test]
    fn adaptive_default_mb_budget_accepts_large_total_chunk_scene_that_exact_default_rejects() {
        let chunk_payload = [b'X'; 64];
        let mut subforms = Vec::with_capacity(11);
        for _ in 0..11 {
            subforms.push(build_repeated_mb_form(
                "TEST",
                "DATA",
                &chunk_payload,
                96_000,
                8,
            ));
        }
        let bytes = build_mb_root(&[build_mb_form_with_alignment("TEST", &subforms, 4)]);
        let exact_mb = crate::mb::parse_bytes_with_budget(bytes.clone(), &MbParseBudget::default())
            .expect("exact default should parse scene");
        let exact_err = crate::scene::recover::collect_raw_chunk_records_with_budget(
            &exact_mb,
            &MbParseBudget::default(),
        )
        .expect_err("exact default should reject large total chunk scene during raw walk");
        let adaptive_budget =
            LoadOptions::default().materialize_mb_parse_budget_for_bytes(bytes.len());
        let adaptive_mb = crate::mb::parse_bytes_with_budget(bytes, &adaptive_budget)
            .expect("adaptive default should parse scene");
        let adaptive_raw = crate::scene::recover::collect_raw_chunk_records_with_budget(
            &adaptive_mb,
            &adaptive_budget,
        )
        .expect("adaptive default should walk large total chunk scene");

        assert_eq!(
            exact_err.budget_limit(),
            Some(MbParseBudgetLimit::MaxTotalChunks)
        );
        assert!(!adaptive_raw.is_empty());
    }

    #[test]
    fn collect_scene_dump_reads_mb_requires_and_scripts() {
        let source = repo_root().join("tests/02/sphere.mb");
        let report = collect_scene_dump(&source).expect("scene dump");

        assert_eq!(report.scene_format, SceneFormat::Mb);
        assert!(report.requires_count() > 0);
        assert_eq!(report.require_entries.len(), report.requires.len());
        assert_eq!(
            report.require_entries[0].kind,
            SceneDumpRequireKind::MayaVersion
        );
        assert!(report.script_entry_count() > 0);
    }

    #[test]
    fn collect_scene_paths_preserves_mb_file_owner_trace_metadata_for_fixture() {
        let source = repo_root().join("tests/fixtures/mb/owner_delete/file_owner_delete.mb");
        let report = collect_scene_paths(&source, PathKind::File).expect("scene paths");

        assert_eq!(report.entries.len(), 2);

        let delete_entry = report
            .entries
            .iter()
            .find(|entry| entry.node_name == "deleteTex")
            .expect("deleteTex entry");
        let delete_meta = delete_entry.meta.as_ref().expect("deleteTex meta");
        assert_eq!(delete_meta.origin, "rtft");
        assert_eq!(delete_meta.trace_form.as_deref(), Some("RTFT"));
        assert!(delete_meta.trace_node_offset.is_some());

        let keep_entry = report
            .entries
            .iter()
            .find(|entry| entry.node_name == "keepTex")
            .expect("keepTex entry");
        let keep_meta = keep_entry.meta.as_ref().expect("keepTex meta");
        assert_eq!(keep_meta.trace_form.as_deref(), Some("RTFT"));
        assert!(keep_meta.trace_node_offset.is_some());
    }

    #[test]
    fn collect_scene_paths_preserves_connected_mb_file_owner_trace_metadata_for_fixture() {
        let source =
            repo_root().join("tests/fixtures/mb/owner_delete/connected_file_owner_delete.mb");
        let report = collect_scene_paths(&source, PathKind::File).expect("scene paths");

        assert_eq!(report.entries.len(), 2);
        assert!(report.entries.iter().all(|entry| entry.meta.is_some()));
        assert!(report.entries.iter().all(|entry| {
            entry
                .meta
                .as_ref()
                .and_then(|meta| meta.trace_form.as_deref())
                == Some("RTFT")
        }));
        assert!(report.entries.iter().all(|entry| {
            entry
                .meta
                .as_ref()
                .and_then(|meta| meta.trace_node_offset)
                .is_some()
        }));
    }

    #[test]
    fn observe_bytes_matches_path_observation_for_mb_fixture() {
        let source = repo_root().join("tests/fixtures/mb/owner_delete/file_owner_delete.mb");
        let bytes = fs::read(&source).expect("read fixture");

        let path_observation = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observe path");
        let bytes_observation = Loader::new(LoadOptions::default())
            .observe_bytes(
                &source,
                SceneFormat::Mb,
                path_observation.validation_state(),
                bytes,
            )
            .expect("observe bytes");

        assert_eq!(bytes_observation.scene_format(), SceneFormat::Mb);
        assert_eq!(
            bytes_observation.validation_state(),
            path_observation.validation_state()
        );
        let bytes_paths = bytes_observation
            .scene_paths(PathKind::File)
            .expect("bytes paths");
        let path_paths = path_observation
            .scene_paths(PathKind::File)
            .expect("path paths");
        let bytes_summary = bytes_paths
            .iter()
            .map(|entry| {
                (
                    entry.node_type.clone(),
                    entry.node_name.clone(),
                    entry.value.clone(),
                    entry.meta.as_ref().and_then(|meta| meta.trace_form.clone()),
                    entry.meta.as_ref().and_then(|meta| meta.trace_node_offset),
                )
            })
            .collect::<Vec<_>>();
        let path_summary = path_paths
            .iter()
            .map(|entry| {
                (
                    entry.node_type.clone(),
                    entry.node_name.clone(),
                    entry.value.clone(),
                    entry.meta.as_ref().and_then(|meta| meta.trace_form.clone()),
                    entry.meta.as_ref().and_then(|meta| meta.trace_node_offset),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(bytes_summary, path_summary);

        let bytes_dump = bytes_observation.scene_dump_report().expect("bytes dump");
        let path_dump = path_observation.scene_dump_report().expect("path dump");
        let bytes_scripts = bytes_dump
            .script_entries
            .iter()
            .map(|entry| (entry.name.clone(), entry.body.clone()))
            .collect::<Vec<_>>();
        let path_scripts = path_dump
            .script_entries
            .iter()
            .map(|entry| (entry.name.clone(), entry.body.clone()))
            .collect::<Vec<_>>();
        assert_eq!(bytes_scripts, path_scripts);
    }

    #[test]
    fn collect_scene_dump_classifies_plugin_requires_for_ma() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = dir.path().join("require_types.ma");
        fs::write(
            &source,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "requires \"pluginA\" \"1.0\";\n",
            ),
        )
        .expect("write scene");

        let report = collect_scene_dump(&source).expect("scene dump");
        assert_eq!(report.require_entries.len(), 2);
        assert_eq!(
            report.require_entries[0].kind,
            SceneDumpRequireKind::MayaVersion
        );
        assert_eq!(report.require_entries[1].kind, SceneDumpRequireKind::Plugin);
        assert_eq!(
            report.require_entries[1].rendered,
            "requires \"pluginA\" \"1.0\";"
        );
    }

    #[test]
    fn find_scene_workspace_root_returns_nearest_workspace() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let outer = dir.path().join("workspace");
        let inner = outer.join("shots/shot01");
        fs::create_dir_all(&inner).expect("create dirs");
        fs::write(outer.join("workspace.mel"), "// outer").expect("write outer workspace");
        fs::write(inner.join("workspace.mel"), "// inner").expect("write inner workspace");
        let scene_path = inner.join("scene.ma");
        fs::write(&scene_path, "// scene").expect("write scene");

        assert_eq!(find_scene_workspace_root(&scene_path), Some(inner));
    }

    #[test]
    fn resolve_scene_path_value_marks_relative_without_context_unresolved() {
        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::new();
        let resolution = resolver.resolve_scene_path_value("textures/albedo.png", &context);

        assert_eq!(resolution.style, ScenePathValueStyle::PlainRelative);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Unresolved);
        assert_eq!(resolution.resolved_path, None);
    }

    #[test]
    fn resolve_scene_path_value_joins_plain_relative_to_workspace_root() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("textures")).expect("create textures");
        let target = workspace.join("textures/albedo.png");
        fs::write(&target, "png").expect("write texture");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let resolution = resolver.resolve_scene_path_value("textures/albedo.png", &context);

        assert_eq!(resolution.style, ScenePathValueStyle::PlainRelative);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(target));
    }

    #[test]
    fn resolve_scene_path_value_preserves_absolute_paths() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let absolute = dir.path().join("absolute.png");
        fs::write(&absolute, "png").expect("write absolute");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(dir.path()));
        let resolution =
            resolver.resolve_scene_path_value(absolute.to_string_lossy().as_ref(), &context);

        assert_eq!(resolution.style, ScenePathValueStyle::Absolute);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(absolute));
    }

    #[test]
    fn resolve_scene_path_value_uses_suffix_for_maya_double_slash_style() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("sourceimages")).expect("create sourceimages");
        let target = workspace.join("sourceimages/albedo.png");
        fs::write(&target, "png").expect("write texture");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let resolution =
            resolver.resolve_scene_path_value("C:/project//sourceimages/albedo.png", &context);

        assert_eq!(
            resolution.style,
            ScenePathValueStyle::DoubleSlashWorkspaceRelative
        );
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(target));
    }

    #[test]
    fn resolve_scene_path_value_preserves_unc_paths() {
        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::new();
        let resolution = resolver.resolve_scene_path_value("//server/share/albedo.png", &context);

        assert_eq!(resolution.style, ScenePathValueStyle::UncAbsolute);
        assert_eq!(
            resolution.resolved_path,
            Some(PathBuf::from("//server/share/albedo.png"))
        );
        assert_eq!(resolution.status, ScenePathResolutionStatus::Missing);
    }

    #[test]
    fn resolve_scene_path_value_distinguishes_missing_candidates() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(&workspace).expect("create workspace");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let resolution = resolver.resolve_scene_path_value("textures/missing.png", &context);

        assert_eq!(resolution.style, ScenePathValueStyle::PlainRelative);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Missing);
        assert_eq!(
            resolution.resolved_path,
            Some(workspace.join("textures/missing.png"))
        );
    }
}
