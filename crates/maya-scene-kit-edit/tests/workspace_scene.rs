use std::path::PathBuf;

use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, MaterializeOptions, PathOwnerDeleteTarget, PathReplaceMode,
    PathReplaceOverride, PathReplaceRule, clean_execution_targets, collect_raw_chunks,
    convert_to_maya_ascii, convert_to_maya_ascii_with_options,
    convert_to_maya_ascii_with_report_and_options, preview_clean_execution_targets,
    preview_delete_path_owner_nodes, preview_remove_script_nodes,
    preview_remove_script_nodes_by_name, preview_replace_scene_path_candidates,
    preview_replace_scene_path_candidates_in_report, preview_replace_scene_paths,
    preview_replace_scene_paths_with_overrides,
    preview_replace_scene_paths_with_overrides_in_report, remove_script_nodes,
    remove_script_nodes_by_name, replace_scene_paths, save_staged_artifact,
    stage_delete_path_owner_nodes, stage_maya_ascii, stage_remove_script_nodes,
    stage_remove_script_nodes_by_name, stage_replace_scene_paths,
    stage_replace_scene_paths_with_overrides, stage_replace_scene_paths_with_overrides_in_report,
    stage_scene_edits, stage_scene_edits_in_report_with_bytes,
};
use maya_scene_kit_formats::mb::parse_file;
use maya_scene_kit_observe::scene::core::{OperationMode, SceneFormat, ValidationState};
use maya_scene_kit_observe::scene::evidence::ExecutionSourceRange;
use maya_scene_kit_observe::scene::paths::{PathKind, ScenePathsReport};
use maya_scene_kit_observe::scene::scripts::ScriptNodeEntry;
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, SceneToolError, check_script_nodes, collect_scene_paths,
    collect_script_node_entries, detect_scene_format,
};
use serde::Deserialize;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn semantic_manifest_path() -> PathBuf {
    repo_root().join("tests/fixtures/semantic/manifest.yaml")
}

#[derive(Debug, Deserialize)]
struct SemanticManifest {
    cases: Vec<SemanticCase>,
}

#[derive(Debug, Deserialize)]
struct SemanticCase {
    id: String,
    ma: String,
    mb: Option<String>,
    expected_script_nodes: Vec<String>,
    expected_reference_path_count: usize,
    expected_file_path_count: usize,
    requires_contains: Vec<String>,
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

fn sorted_script_entries(entries: Vec<ScriptNodeEntry>) -> Vec<(String, String)> {
    let mut values = entries
        .into_iter()
        .map(|entry| (entry.name, entry.body.trim_end().to_string()))
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn build_mb_chunk_with_alignment(tag: &str, payload: &[u8], sibling_alignment: usize) -> Vec<u8> {
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

fn build_mb_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
    build_mb_chunk_with_alignment(tag, payload, 8)
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

#[test]
fn semantic_manifest_pairs_match_for_paths_and_script_nodes() {
    let manifest: SemanticManifest = serde_yaml::from_str(
        &std::fs::read_to_string(semantic_manifest_path()).expect("read semantic manifest"),
    )
    .expect("parse semantic manifest");

    for case in manifest.cases {
        let ma = repo_root().join(&case.ma);
        let mut script_nodes = check_script_nodes(&ma).expect("ma script report").nodes;
        script_nodes.sort();
        let mut expected_script_nodes = case.expected_script_nodes.clone();
        expected_script_nodes.sort();
        assert_eq!(
            script_nodes, expected_script_nodes,
            "script mismatch for {}",
            case.id
        );

        let reference_count = collect_scene_paths(&ma, PathKind::Reference)
            .expect("ma reference paths")
            .entries
            .len();
        let file_count = collect_scene_paths(&ma, PathKind::File)
            .expect("ma file paths")
            .entries
            .len();
        assert_eq!(
            reference_count, case.expected_reference_path_count,
            "reference path count mismatch for {}",
            case.id
        );
        assert_eq!(
            file_count, case.expected_file_path_count,
            "file path count mismatch for {}",
            case.id
        );

        let requires = Loader::new(LoadOptions::default())
            .observe_path(&ma)
            .expect("observe")
            .requires()
            .expect("requires");
        for needle in &case.requires_contains {
            assert!(
                requires.iter().any(|value| value.contains(needle)),
                "missing requires token {} for {}",
                needle,
                case.id
            );
        }

        if let Some(mb) = &case.mb {
            let mb = repo_root().join(mb);
            let mut ma_entries = collect_script_node_entries(&ma)
                .expect("ma script entries")
                .entries
                .into_iter()
                .map(|entry| (entry.name, entry.body.trim_end().to_string()))
                .collect::<Vec<_>>();
            let mut mb_entries = collect_script_node_entries(&mb)
                .expect("mb script entries")
                .entries
                .into_iter()
                .map(|entry| (entry.name, entry.body.trim_end().to_string()))
                .collect::<Vec<_>>();
            ma_entries.sort();
            mb_entries.sort();
            assert_eq!(ma_entries, mb_entries, "script mismatch for {}", case.id);
        }
    }
}

#[test]
fn sphere_pair_script_read_apis_match_for_ma_and_mb() {
    let ma = repo_root().join("tests/02/sphere.ma");
    let mb = repo_root().join("tests/02/sphere.mb");

    let ma_names = check_script_nodes(&ma).expect("ma script report");
    let mb_names = check_script_nodes(&mb).expect("mb script report");
    assert_eq!(ma_names.scene_format, SceneFormat::Ma);
    assert_eq!(mb_names.scene_format, SceneFormat::Mb);
    let ma_nodes = sorted_strings(ma_names.nodes);
    let mb_nodes = sorted_strings(mb_names.nodes);
    assert_eq!(ma_nodes, mb_nodes);
    assert_eq!(
        mb_nodes,
        vec![
            "sceneConfigurationScriptNode".to_string(),
            "uiConfigurationScriptNode".to_string(),
        ]
    );

    let ma_entries = collect_script_node_entries(&ma).expect("ma script entries");
    let mb_entries = collect_script_node_entries(&mb).expect("mb script entries");
    assert_eq!(ma_entries.scene_format, SceneFormat::Ma);
    assert_eq!(mb_entries.scene_format, SceneFormat::Mb);

    let ma_entries = sorted_script_entries(ma_entries.entries);
    let mb_entries = sorted_script_entries(mb_entries.entries);
    assert_eq!(ma_entries, mb_entries);
    assert_eq!(ma_entries.len(), 2);
    assert!(ma_entries.iter().any(|(name, body)| {
        name == "uiConfigurationScriptNode" && body.contains("Maya Mel UI Configuration File.")
    }));
}

#[test]
fn baseline_convert_to_ascii_with_report_covers_ma_and_mb_shapes() {
    let dir = tempdir().expect("tmpdir");
    let ma_source = repo_root().join("tests/02/sphere.ma");
    let mb_source = repo_root().join("tests/02/sphere.mb");
    let ma_output = dir.path().join("sphere_copy.ma");
    let mb_output = dir.path().join("sphere_from_mb.ma");

    let ma_report = convert_to_maya_ascii_with_report_and_options(
        &ma_source,
        &ma_output,
        &MaterializeOptions::default(),
    )
    .expect("ma report");
    let mb_report = convert_to_maya_ascii_with_report_and_options(
        &mb_source,
        &mb_output,
        &MaterializeOptions::default(),
    )
    .expect("mb report");

    assert_eq!(ma_report.output_path, ma_output);
    assert_eq!(mb_report.output_path, mb_output);
    assert_eq!(ma_report.scene_format, SceneFormat::Ma);
    assert_eq!(mb_report.scene_format, SceneFormat::Mb);
    assert!(ma_report.issues.is_empty());
    assert!(ma_report.raw_chunks.is_empty());
    assert_eq!(ma_report.raw_chunk_count, 0);
    assert!(mb_report.raw_chunk_count > 0);
    assert!(!mb_report.raw_chunks.is_empty());
    assert!(mb_report.raw_payload_size_total > 0);
    assert!(
        mb_report
            .decode_quality_distribution
            .iter()
            .any(|entry| entry.count > 0)
    );
    assert!(
        std::fs::read_to_string(&mb_output)
            .unwrap()
            .contains("createNode transform -s -n \"persp\";")
    );
}

#[test]
fn mb_read_only_apis_share_validation_state_for_canonical_recovery() {
    let source = repo_root().join("tests/02/sphere.mb");
    let check = check_script_nodes(&source).expect("check");
    let entries = collect_script_node_entries(&source).expect("entries");
    let paths = collect_scene_paths(&source, PathKind::All).expect("paths");

    assert_eq!(check.validation_state, entries.validation_state);
    assert_eq!(check.validation_state, paths.validation_state);
    assert_eq!(check.validation_state, ValidationState::Partial);
}

#[test]
fn mb_observation_bundle_stays_usable_after_source_file_is_removed() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("copied.mb");
    std::fs::write(
        &source,
        std::fs::read(repo_root().join("tests/02/sphere.mb")).unwrap(),
    )
    .expect("copy fixture");

    let observation = Loader::new(LoadOptions::default())
        .observe_path(&source)
        .expect("observe");
    std::fs::remove_file(&source).expect("remove source");

    let requires = observation.requires().expect("requires");
    let catalog = observation
        .observed_execution_catalog(64)
        .expect("execution catalog");

    assert!(!requires.is_empty());
    assert!(!catalog.surfaces.is_empty());
}

#[test]
fn script_check_ma() {
    let report = check_script_nodes(repo_root().join("tests/02/sphere.ma")).unwrap();
    assert_eq!(report.scene_format, SceneFormat::Ma);
    assert!(report.count() >= 2);
    assert!(
        report
            .nodes
            .iter()
            .any(|n| n == "uiConfigurationScriptNode")
    );
    assert!(
        report
            .nodes
            .iter()
            .any(|n| n == "sceneConfigurationScriptNode")
    );
}

#[test]
fn script_clean_ma() {
    let source = repo_root().join("tests/02/sphere.ma");
    let dir = tempdir().unwrap();
    let output = dir.path().join("sphere_clean.ma");
    let result = remove_script_nodes(&source, &output).unwrap();
    assert_eq!(result.scene_format, SceneFormat::Ma);
    assert!(result.removed_count() >= 2);

    let report = check_script_nodes(&output).unwrap();
    assert_eq!(report.count(), 0);
    assert!(
        std::fs::read_to_string(&output)
            .unwrap()
            .contains("createNode mesh -n \"pSphereShape1\"")
    );
}

#[test]
fn script_check_and_clean_mb() {
    let source = repo_root().join("tests/02/sphere.mb");
    let original_report = check_script_nodes(&source).unwrap();
    assert_eq!(original_report.scene_format, SceneFormat::Mb);
    assert!(original_report.count() > 0);

    let dir = tempdir().unwrap();
    let output = dir.path().join("sphere_clean.mb");
    let result = remove_script_nodes(&source, &output).unwrap();
    assert_eq!(result.scene_format, SceneFormat::Mb);
    assert_eq!(result.removed_count(), original_report.count());

    let cleaned_report = check_script_nodes(&output).unwrap();
    assert_eq!(cleaned_report.count(), 0);

    let parsed = parse_file(&output).unwrap();
    assert!(
        !parsed
            .root
            .children
            .iter()
            .any(|child| child.form_type.as_deref() == Some("SCRP"))
    );
}

#[test]
fn replace_preview_matches_execution_for_ma_and_is_non_destructive() {
    let source = repo_root().join("tests/fixtures/ma/opaque_typed_attrs.ma");
    let dir = tempdir().expect("tmpdir");
    let output = dir.path().join("opaque_typed_attrs_rewritten.ma");
    let original = std::fs::read(&source).expect("read source");
    let rules = vec![PathReplaceRule {
        from: "textures/".to_string(),
        to: "assets/".to_string(),
        mode: PathReplaceMode::Literal,
    }];

    let preview = preview_replace_scene_paths(&source, &rules).expect("preview replace");
    assert_eq!(preview.scene_format, SceneFormat::Ma);
    assert_eq!(preview.matched_count, 1);
    assert_eq!(std::fs::read(&source).expect("re-read source"), original);
    assert_eq!(preview.items.len(), 1);
    assert_eq!(preview.items[0].node_type, "file");
    assert_eq!(preview.items[0].before_value, "textures/albedo.png");
    assert_eq!(preview.items[0].after_value, "assets/albedo.png");

    let result = replace_scene_paths(&source, &output, &rules).expect("execute replace");
    assert_eq!(result.replaced_count, preview.matched_count);
    assert!(
        std::fs::read_to_string(&output)
            .expect("read output")
            .contains("assets/albedo.png")
    );
}

#[test]
fn replace_candidate_preview_includes_unmatched_paths() {
    let source = repo_root().join("tests/fixtures/ma/opaque_typed_attrs.ma");
    let rules = vec![PathReplaceRule {
        from: String::new(),
        to: "assets/".to_string(),
        mode: PathReplaceMode::Literal,
    }];

    let preview =
        preview_replace_scene_path_candidates(&source, &rules).expect("candidate preview");
    assert!(!preview.items.is_empty());
    assert!(
        preview
            .items
            .iter()
            .all(|item| item.before_value == item.after_value)
    );
    assert_eq!(preview.matched_count, 0);
}

#[test]
fn report_based_candidate_preview_matches_path_based_preview() {
    let source = repo_root().join("tests/fixtures/ma/opaque_typed_attrs.ma");
    let rules = vec![PathReplaceRule {
        from: "textures/".to_string(),
        to: "assets/".to_string(),
        mode: PathReplaceMode::Literal,
    }];

    let report = collect_scene_paths(&source, PathKind::All).expect("collect report");
    let from_path = preview_replace_scene_path_candidates(&source, &rules).expect("path preview");
    let from_report =
        preview_replace_scene_path_candidates_in_report(&report, &rules).expect("report preview");

    assert_eq!(from_report.scene_format, from_path.scene_format);
    assert_eq!(from_report.validation_state, from_path.validation_state);
    assert_eq!(from_report.matched_count, from_path.matched_count);
    assert_eq!(from_report.items, from_path.items);
}

#[test]
fn replace_preview_supports_regex_mode_for_ma() {
    let source = repo_root().join("tests/fixtures/ma/opaque_typed_attrs.ma");
    let dir = tempdir().expect("tmpdir");
    let output = dir.path().join("opaque_typed_attrs_regex.ma");
    let rules = vec![PathReplaceRule {
        from: r"textures/(.+)\.png".to_string(),
        to: "assets/$1.tx".to_string(),
        mode: PathReplaceMode::Regex,
    }];

    let preview = preview_replace_scene_paths(&source, &rules).expect("regex preview replace");
    assert_eq!(preview.matched_count, 1);
    assert_eq!(preview.items[0].after_value, "assets/albedo.tx");

    let result = replace_scene_paths(&source, &output, &rules).expect("regex execute replace");
    assert_eq!(result.replaced_count, preview.matched_count);
    assert!(
        std::fs::read_to_string(&output)
            .expect("read output")
            .contains("assets/albedo.tx")
    );
}

#[test]
fn replace_stage_matches_execution_for_ma() {
    let source = repo_root().join("tests/fixtures/ma/opaque_typed_attrs.ma");
    let dir = tempdir().expect("tmpdir");
    let staged_output = dir.path().join("opaque_typed_attrs_staged.ma");
    let execute_output = dir.path().join("opaque_typed_attrs_execute.ma");
    let rules = vec![PathReplaceRule {
        from: "textures/".to_string(),
        to: "assets/".to_string(),
        mode: PathReplaceMode::Literal,
    }];

    let staged = stage_replace_scene_paths(&source, &rules).expect("stage replace");
    assert_eq!(staged.preview.matched_count, 1);
    save_staged_artifact(&staged.artifact, &staged_output).expect("save staged replace");

    let executed = replace_scene_paths(&source, &execute_output, &rules).expect("execute replace");
    assert_eq!(executed.replaced_count, staged.preview.matched_count);
    assert_eq!(
        std::fs::read(&staged_output).expect("read staged output"),
        std::fs::read(&execute_output).expect("read execute output")
    );
}

#[test]
fn clean_preview_matches_execution_for_ma() {
    let source = repo_root().join("tests/02/sphere.ma");
    let dir = tempdir().expect("tmpdir");
    let output = dir.path().join("sphere_clean_previewed.ma");
    let original = std::fs::read(&source).expect("read source");

    let preview = preview_remove_script_nodes(&source).expect("preview clean");
    assert_eq!(preview.scene_format, SceneFormat::Ma);
    assert!(preview.removed_count() >= 2);
    assert_eq!(std::fs::read(&source).expect("re-read source"), original);

    let result = remove_script_nodes(&source, &output).expect("execute clean");
    assert_eq!(result.removed_nodes, preview.removed_nodes);
}

#[test]
fn clean_stage_matches_execution_for_ma() {
    let source = repo_root().join("tests/02/sphere.ma");
    let dir = tempdir().expect("tmpdir");
    let staged_output = dir.path().join("sphere_clean_staged.ma");
    let execute_output = dir.path().join("sphere_clean_execute.ma");

    let staged = stage_remove_script_nodes(&source).expect("stage clean");
    save_staged_artifact(&staged.artifact, &staged_output).expect("save staged clean");

    let executed = remove_script_nodes(&source, &execute_output).expect("execute clean");
    assert_eq!(executed.removed_nodes, staged.preview.removed_nodes);
    assert_eq!(
        std::fs::read(&staged_output).expect("read staged output"),
        std::fs::read(&execute_output).expect("read execute output")
    );
}

#[test]
fn targeted_clean_preview_and_stage_remove_only_selected_ma_script_node() {
    let source = repo_root().join("tests/02/sphere.ma");
    let targets = vec!["uiConfigurationScriptNode".to_string()];

    let preview =
        preview_remove_script_nodes_by_name(&source, &targets).expect("targeted preview clean");
    assert_eq!(preview.removed_nodes, targets);

    let staged =
        stage_remove_script_nodes_by_name(&source, &targets).expect("targeted stage clean");
    assert_eq!(staged.preview.removed_nodes, preview.removed_nodes);

    let dir = tempdir().expect("tmpdir");
    let output = dir.path().join("sphere_targeted_clean.ma");
    save_staged_artifact(&staged.artifact, &output).expect("save staged clean");

    let report = check_script_nodes(&output).expect("check cleaned scene");
    assert_eq!(report.count(), 1);
    assert_eq!(
        report.nodes,
        vec!["sceneConfigurationScriptNode".to_string()]
    );
}

#[test]
fn replace_override_stage_changes_only_targeted_ma_entry() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("override_paths.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "file -rdi 1 -ns \"charA\" -rfn \"charARN\" -typ \"mayaBinary\" \"shared/asset.mb\";\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"shared/asset.mb\";\n",
        ),
    )
    .expect("write source");

    let all_paths = collect_scene_paths(&source, PathKind::All).expect("collect paths");
    assert_eq!(all_paths.entries.len(), 2);

    let overrides = vec![PathReplaceOverride {
        entry_index: 1,
        before_value: "shared/asset.mb".to_string(),
        after_value: "textures/hero_diffuse.png".to_string(),
    }];

    let preview =
        preview_replace_scene_paths_with_overrides(&source, &overrides).expect("preview overrides");
    assert_eq!(preview.matched_count, 1);
    assert_eq!(preview.items[0].node_name, "file1");

    let report_preview =
        preview_replace_scene_paths_with_overrides_in_report(&all_paths, &overrides)
            .expect("preview overrides from report");
    assert_eq!(report_preview, preview);

    let staged =
        stage_replace_scene_paths_with_overrides(&source, &overrides).expect("stage overrides");
    let staged_from_report =
        stage_replace_scene_paths_with_overrides_in_report(&all_paths, &overrides)
            .expect("stage overrides from report");
    assert_eq!(staged_from_report.preview, staged.preview);
    assert_eq!(staged_from_report.artifact.bytes, staged.artifact.bytes);
    let output = String::from_utf8(staged.artifact.bytes.clone()).expect("utf8");
    assert!(output.contains("\"shared/asset.mb\""));
    assert!(output.contains("setAttr \".ftn\" -type \"string\" \"textures/hero_diffuse.png\";"));
}

#[test]
fn replace_and_delete_support_file_texture_name_on_non_file_nodes() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("non_file_texture_nodes.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode psdFileTex -n \"psdTex1\";\n",
            "    setAttr \".fileTextureName\" -type \"string\" \"sourceimages/layered.psd\";\n",
            "createNode movie -n \"movieTex1\";\n",
            "    setAttr \".fileTextureName\" -type \"string\" \"movies/clip.mov\";\n",
        ),
    )
    .expect("write source");

    let report = collect_scene_paths(&source, PathKind::File).expect("collect file paths");
    assert_eq!(report.entries.len(), 2);
    assert_eq!(report.entries[0].node_type, "psdFileTex");
    assert_eq!(report.entries[0].attr, ".fileTextureName");
    assert_eq!(report.entries[1].node_type, "movie");

    let overrides = vec![PathReplaceOverride {
        entry_index: 1,
        before_value: "movies/clip.mov".to_string(),
        after_value: "archive/clip.mov".to_string(),
    }];
    let staged =
        stage_replace_scene_paths_with_overrides_in_report(&report, &overrides).expect("replace");
    let replaced = String::from_utf8(staged.artifact.bytes.clone()).expect("utf8");
    assert!(replaced.contains("sourceimages/layered.psd"));
    assert!(replaced.contains("archive/clip.mov"));

    let delete_preview = preview_delete_path_owner_nodes(
        &source,
        &[PathOwnerDeleteTarget {
            node_type: "psdFileTex".to_string(),
            node_name: "psdTex1".to_string(),
        }],
    )
    .expect("delete preview");
    assert_eq!(delete_preview.deleted_count(), 1);

    let deleted = stage_delete_path_owner_nodes(
        &source,
        &[PathOwnerDeleteTarget {
            node_type: "psdFileTex".to_string(),
            node_name: "psdTex1".to_string(),
        }],
    )
    .expect("delete stage");
    let deleted_text = String::from_utf8(deleted.artifact.bytes).expect("utf8");
    assert!(!deleted_text.contains("createNode psdFileTex -n \"psdTex1\";"));
    assert!(deleted_text.contains("createNode movie -n \"movieTex1\";"));
}

#[test]
fn composite_stage_from_replaced_bytes_preserves_replace_overrides() {
    let dir = tempdir().expect("tmpdir");
    let source = dir.path().join("scene.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
            "createNode file -n \"file2\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/spec.tx\";\n",
        ),
    )
    .expect("write source");

    let report = collect_scene_paths(&source, PathKind::All).expect("paths");
    let overrides = vec![
        PathReplaceOverride {
            entry_index: 0,
            before_value: "textures/diffuse.tx".to_string(),
            after_value: "textures/diffuse_replaced.tx".to_string(),
        },
        PathReplaceOverride {
            entry_index: 1,
            before_value: "textures/spec.tx".to_string(),
            after_value: "textures/spec_replaced.tx".to_string(),
        },
    ];
    let replaced =
        stage_replace_scene_paths_with_overrides_in_report(&report, &overrides).expect("replace");
    let observed = Loader::new(LoadOptions::default())
        .observe_bytes(
            &source,
            report.scene_format,
            report.validation_state,
            replaced.artifact.bytes.clone(),
        )
        .expect("observe replaced bytes");
    let current_report = ScenePathsReport {
        scene_path: observed.scene_path().to_path_buf(),
        scene_format: observed.scene_format(),
        validation_state: observed.validation_state(),
        entries: observed
            .scene_paths(PathKind::All)
            .expect("current scene paths"),
    };

    let staged = stage_scene_edits_in_report_with_bytes(
        &current_report,
        &replaced.artifact.bytes,
        &[],
        &[PathOwnerDeleteTarget {
            node_type: "file".to_string(),
            node_name: "file1".to_string(),
        }],
    )
    .expect("composite stage");

    assert_eq!(staged.preview.deleted_path_owner_targets.len(), 1);
    let output = String::from_utf8(staged.artifact.bytes).expect("utf8");
    assert!(!output.contains("createNode file -n \"file1\";"));
    assert!(output.contains("textures/spec_replaced.tx"));
    assert!(!output.contains("textures/spec.tx"));
}

#[test]
fn clean_preview_matches_execution_for_mb() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().expect("tmpdir");
    let output = dir.path().join("sphere_clean_previewed.mb");
    let original = std::fs::read(&source).expect("read source");

    let preview = preview_remove_script_nodes(&source).expect("preview clean");
    assert_eq!(preview.scene_format, SceneFormat::Mb);
    assert!(preview.removed_count() >= 2);
    assert_eq!(std::fs::read(&source).expect("re-read source"), original);

    let result = remove_script_nodes(&source, &output).expect("execute clean");
    assert_eq!(result.removed_nodes, preview.removed_nodes);
}

#[test]
fn clean_stage_matches_execution_for_mb() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().expect("tmpdir");
    let staged_output = dir.path().join("sphere_clean_staged.mb");
    let execute_output = dir.path().join("sphere_clean_execute.mb");

    let staged = stage_remove_script_nodes(&source).expect("stage clean");
    save_staged_artifact(&staged.artifact, &staged_output).expect("save staged clean");

    let executed = remove_script_nodes(&source, &execute_output).expect("execute clean");
    assert_eq!(executed.removed_nodes, staged.preview.removed_nodes);
    assert_eq!(
        std::fs::read(&staged_output).expect("read staged output"),
        std::fs::read(&execute_output).expect("read execute output")
    );
}

#[test]
fn targeted_clean_execution_removes_only_selected_mb_script_node() {
    let source = repo_root().join("tests/02/sphere.mb");
    let targets = vec!["uiConfigurationScriptNode".to_string()];
    let dir = tempdir().expect("tmpdir");
    let output = dir.path().join("sphere_targeted_clean.mb");

    let result =
        remove_script_nodes_by_name(&source, &output, &targets).expect("execute targeted clean");
    assert_eq!(result.removed_nodes, targets);

    let report = check_script_nodes(&output).expect("check cleaned scene");
    assert_eq!(report.count(), 1);
    assert_eq!(
        report.nodes,
        vec!["sceneConfigurationScriptNode".to_string()]
    );
}

#[test]
fn to_ascii_stage_matches_execution_for_mb() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().expect("tmpdir");
    let staged_output = dir.path().join("sphere_staged.ma");
    let execute_output = dir.path().join("sphere_execute.ma");

    let staged = stage_maya_ascii(&source).expect("stage to-ascii");
    assert_eq!(staged.report.scene_format, SceneFormat::Mb);
    save_staged_artifact(&staged.artifact, &staged_output).expect("save staged to-ascii");

    let executed = convert_to_maya_ascii_with_report_and_options(
        &source,
        &execute_output,
        &MaterializeOptions::default(),
    )
    .expect("execute to-ascii");
    assert_eq!(executed.validation_state, staged.report.validation_state);
    assert_eq!(
        std::fs::read(&staged_output).expect("read staged output"),
        std::fs::read(&execute_output).expect("read execute output")
    );
}

#[test]
fn script_entries_mb_use_canonical_scene_model() {
    let source = repo_root().join("tests/02/sphere.mb");
    let report = collect_script_node_entries(&source).unwrap();
    assert_eq!(report.scene_format, SceneFormat::Mb);
    assert!(report.entries.len() >= 2);
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.name == "uiConfigurationScriptNode" && !entry.body.is_empty())
    );
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.name == "sceneConfigurationScriptNode" && !entry.body.is_empty())
    );
}

#[test]
fn script_entries_ma_use_canonical_ast_model() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("script_nodes.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" (\n",
            "        \"print(\\\"hello\\\")\" +\n",
            "        \"\\n\"\n",
            "    );\n",
            "createNode transform -n \"x1\";\n",
        ),
    )
    .unwrap();

    let names = check_script_nodes(&source).unwrap();
    assert_eq!(names.scene_format, SceneFormat::Ma);
    assert_eq!(names.nodes, vec!["scriptNode1".to_string()]);

    let report = collect_script_node_entries(&source).unwrap();
    assert_eq!(report.scene_format, SceneFormat::Ma);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].name, "scriptNode1");
    assert_eq!(report.entries[0].body, "print(\"hello\")\n");
}

#[test]
fn convert_to_ascii_from_mb_best_effort() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().unwrap();
    let output = dir.path().join("sphere.ma");
    let converted = convert_to_maya_ascii(&source, &output).unwrap();
    assert_eq!(converted, output);

    let text = std::fs::read_to_string(output).unwrap();
    assert!(text.contains("//Generated by maya-scene-kit best-effort converter."));
    assert!(text.contains("createNode transform -s -n \"persp\";"));
    assert!(text.contains("createNode lightLinker -s -n \"lightLinker1\";"));
    assert!(text.contains("setAttr \".t\" -type \"double3\" 28 21 28 ;"));
    assert!(text.contains("setAttr \".imn\" -type \"string\" \"persp\";"));
    assert!(text.contains("setAttr \".st\" 3;"));
    assert!(text.contains("rename -uid \"97D44983-42C6-68B1-0C0B-6CA5DEEBF0CD\";"));
    assert!(text.contains("connectAttr \"polySphere1.out\" \"pSphereShape1.i\";"));
    assert!(text.contains(
        "relationship \"shadowLink\" \":lightLinker1\" \":initialShadingGroup.message\" \":defaultLightSet.message\";"
    ));
    assert!(!text.contains("//Last modified:"));
    assert!(!text.contains("//Source:"));
}

#[test]
fn convert_to_ascii_can_opt_in_output_metadata() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().unwrap();
    let output = dir.path().join("sphere.ma");
    let options = MaterializeOptions::default().with_embed_output_metadata(true);
    let converted = convert_to_maya_ascii_with_options(&source, &output, &options).unwrap();
    assert_eq!(converted, output);

    let text = std::fs::read_to_string(output).unwrap();
    assert!(text.contains("//Source:"));
    assert!(!text.contains("//Last modified:"));
}

#[test]
fn convert_to_ascii_strict_rejection_does_not_leave_partial_output() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().unwrap();
    let output = dir.path().join("sphere_strict.ma");

    let best_effort_report = convert_to_maya_ascii_with_report_and_options(
        &source,
        &output,
        &MaterializeOptions::default(),
    )
    .unwrap();
    assert_eq!(
        best_effort_report.validation_state,
        ValidationState::Partial
    );
    assert!(output.exists());

    std::fs::remove_file(&output).unwrap();

    let strict_options = MaterializeOptions::default().with_operation_mode(OperationMode::Strict);
    let err = convert_to_maya_ascii_with_options(&source, &output, &strict_options).unwrap_err();
    assert!(matches!(
        err,
        SceneToolError::RejectedByMode {
            validation_state: ValidationState::Partial,
            ..
        }
    ));
    assert!(!output.exists());
}

#[test]
fn convert_to_ascii_rejects_malformed_external_addattr_schema() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().unwrap();
    let output = dir.path().join("sphere.ma");
    let bad_schema = dir.path().join("bad_addattr.yaml");
    std::fs::write(
        &bad_schema,
        "tokens:\n  bad:\n    value_spec:\n      kind: nope\n",
    )
    .unwrap();

    let options = MaterializeOptions::default().with_addattr_schema_path(&bad_schema);
    let err = convert_to_maya_ascii_with_options(&source, &output, &options).unwrap_err();
    assert!(matches!(err, SceneToolError::Config(_)));
    let message = err.to_string();
    assert!(message.contains("malformed addattr schema"));
    assert!(message.contains("bad_addattr.yaml"));
}

#[test]
fn convert_to_ascii_rejects_malformed_chunk_schema_pack() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().unwrap();
    let output = dir.path().join("sphere.ma");
    let chunk_root = dir.path().join("chunks");
    let attr_dir = chunk_root.join("ATTR");
    std::fs::create_dir_all(&attr_dir).unwrap();
    std::fs::write(attr_dir.join("STR .yaml"), "not: [valid").unwrap();

    let options = MaterializeOptions::default().with_chunk_schema_root(&chunk_root);
    let err = convert_to_maya_ascii_with_options(&source, &output, &options).unwrap_err();
    assert!(matches!(err, SceneToolError::Config(_)));
    let message = err.to_string();
    assert!(message.contains("malformed chunk schema"));
    assert!(message.contains("STR .yaml"));
}

#[test]
fn convert_to_ascii_passthrough_ma_skips_runtime_schema_validation() {
    let source = repo_root().join("tests/02/sphere.ma");
    let dir = tempdir().unwrap();
    let output = dir.path().join("sphere_copy.ma");
    let bad_schema = dir.path().join("bad_addattr.yaml");
    std::fs::write(
        &bad_schema,
        "tokens:\n  bad:\n    value_spec:\n      kind: nope\n",
    )
    .unwrap();

    let options = MaterializeOptions::default().with_addattr_schema_path(&bad_schema);
    let converted = convert_to_maya_ascii_with_options(&source, &output, &options).unwrap();
    assert_eq!(converted, output);
    assert_eq!(
        std::fs::read(&source).unwrap(),
        std::fs::read(&output).unwrap()
    );
}

#[test]
fn detect_scene_format_prefers_content_over_extension() {
    let source = repo_root().join("tests/02/sphere.mb");
    let dir = tempdir().unwrap();
    let disguised = dir.path().join("sphere_disguised.ma");
    std::fs::write(&disguised, std::fs::read(source).unwrap()).unwrap();
    assert_eq!(detect_scene_format(&disguised).unwrap(), SceneFormat::Mb);
}

#[test]
fn collect_paths_from_ma_file_command_multiline() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("refs.ma");
    std::fs::write(
        &source,
        r#"//Maya ASCII 2026 scene
file -rdi 1 -ns "charA" -rfn "charARN" -op "VERS|2026|"
     -typ "mayaBinary" "rig/charA_v001.mb";
file -r -ns "charA" -dr 1 -rfn "charARN" -op "VERS|2026|"
     -typ "mayaBinary" "rig/charA_v001.mb";
file -rdi 1 -ns "charB" -rfn "charBRN" -typ "mayaAscii"
     "../../asset/charB.ma";
"#,
    )
    .unwrap();

    let report = collect_scene_paths(&source, PathKind::Reference).unwrap();
    assert_eq!(report.scene_format, SceneFormat::Ma);
    assert_eq!(report.count(), 2);
    assert!(
        report
            .entries
            .iter()
            .any(|e| e.node_name == "charARN" && e.value == "rig/charA_v001.mb")
    );
    assert!(
        report
            .entries
            .iter()
            .any(|e| e.node_name == "charBRN" && e.value == "../../asset/charB.ma")
    );
}

#[test]
fn preview_clean_execution_targets_supports_top_level_command() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("top_level.ma");
    let command = "python(\"print(1)\");";
    std::fs::write(
        &source,
        format!(
            "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n{command}\nfile -r \"safe.ma\";\n"
        ),
    )
    .unwrap();

    let start = "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n".len();
    let end = start + command.len() + 1;
    let preview = preview_clean_execution_targets(
        &source,
        &[ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange { start, end },
        }],
    )
    .unwrap();

    assert_eq!(preview.cleaned_count(), 1);
    assert!(preview.removed_script_nodes.is_empty());

    let output = dir.path().join("top_level_clean.ma");
    let result = clean_execution_targets(
        &source,
        &output,
        &[ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange { start, end },
        }],
    )
    .unwrap();
    let text = std::fs::read_to_string(&output).unwrap();
    assert_eq!(result.cleaned_count(), 1);
    assert!(!text.contains(command));
    assert!(text.contains("file -r \"safe.ma\";"));
}

#[test]
fn delete_path_owner_nodes_stages_ma_file_and_reference_owners() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("owners.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "file -r -ns \"charA\" -rfn \"charARN\" -typ \"mayaBinary\" \"rig/charA_v001.mb\";\n",
            "createNode reference -n \"charARN\";\n",
            "    setAttr \".fn\" -type \"string\" \"rig/charA_v001.mb\";\n",
            "createNode file -n \"fileTex\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/diffuse.tx\";\n",
            "createNode file -n \"keepTex\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/keep.tx\";\n",
        ),
    )
    .unwrap();

    let targets = vec![
        PathOwnerDeleteTarget {
            node_type: "reference".to_string(),
            node_name: "charARN".to_string(),
        },
        PathOwnerDeleteTarget {
            node_type: "file".to_string(),
            node_name: "fileTex".to_string(),
        },
    ];
    let preview = preview_delete_path_owner_nodes(&source, &targets).unwrap();
    assert_eq!(preview.deleted_count(), 2);

    let staged = stage_delete_path_owner_nodes(&source, &targets).unwrap();
    let text = String::from_utf8(staged.artifact.bytes).unwrap();

    assert!(!text.contains("createNode file -n \"fileTex\";"));
    assert!(!text.contains("-rfn \"charARN\""));
    assert!(!text.contains("createNode reference -n \"charARN\";"));
    assert!(text.contains("createNode file -n \"keepTex\";"));
}

#[test]
fn delete_path_owner_nodes_stages_mb_file_owner_from_maya_fixture() {
    let dir = tempdir().unwrap();
    let source = repo_root().join("tests/fixtures/mb/owner_delete/file_owner_delete.mb");
    let targets = vec![PathOwnerDeleteTarget {
        node_type: "file".to_string(),
        node_name: "deleteTex".to_string(),
    }];

    let preview = preview_delete_path_owner_nodes(&source, &targets).unwrap();
    assert_eq!(preview.deleted_targets, targets);
    assert_eq!(preview.deleted_count(), 1);

    let staged = stage_delete_path_owner_nodes(&source, &targets).unwrap();
    let output = dir.path().join("file_owner_delete_node_removed.mb");
    std::fs::write(&output, &staged.artifact.bytes).unwrap();

    let report = collect_scene_paths(&output, PathKind::File).unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].node_name, "keepTex");
    assert_eq!(report.entries[0].value, "textures/keep_me.tx");
}

#[test]
fn delete_path_owner_nodes_stages_connected_mb_file_owner_from_maya_fixture() {
    let dir = tempdir().unwrap();
    let source = repo_root().join("tests/fixtures/mb/owner_delete/connected_file_owner_delete.mb");
    let targets = vec![PathOwnerDeleteTarget {
        node_type: "file".to_string(),
        node_name: "c0000_000_ta".to_string(),
    }];

    let preview = preview_delete_path_owner_nodes(&source, &targets).unwrap();
    assert_eq!(preview.deleted_targets, targets);
    assert_eq!(preview.deleted_count(), 1);

    let staged = stage_delete_path_owner_nodes(&source, &targets).unwrap();
    let output = dir
        .path()
        .join("connected_file_owner_delete_node_removed.mb");
    std::fs::write(&output, &staged.artifact.bytes).unwrap();

    let report = collect_scene_paths(&output, PathKind::File).unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].node_name, "c0000_000_tb");
    assert_eq!(
        report.entries[0].value,
        "D:/GENBA_Merlin/Merlin_svn/model/Character/c0000//sourceimages/e1013_f00_tb.psd"
    );
}

#[test]
fn stage_scene_edits_composes_path_delete_before_script_clean_for_ma() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("scene_edits.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode script -n \"deleteScript\";\n",
            "    setAttr \".b\" -type \"string\" \"python(\\\"print(1)\\\")\";\n",
            "createNode file -n \"deleteTex\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/delete.tx\";\n",
            "createNode file -n \"keepTex\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/keep.tx\";\n",
        ),
    )
    .unwrap();

    let staged = stage_scene_edits(
        &source,
        &[ExecutionCleanTarget::ScriptNode {
            node_name: "deleteScript".to_string(),
        }],
        &[PathOwnerDeleteTarget {
            node_type: "file".to_string(),
            node_name: "deleteTex".to_string(),
        }],
    )
    .unwrap();

    let text = String::from_utf8(staged.artifact.bytes).unwrap();
    assert!(staged.preview.has_clean_targets());
    assert!(staged.preview.has_deleted_path_owner_targets());
    assert!(!text.contains("createNode script -n \"deleteScript\";"));
    assert!(!text.contains("createNode file -n \"deleteTex\";"));
    assert!(text.contains("createNode file -n \"keepTex\";"));
}

#[test]
fn preview_clean_execution_targets_supports_top_level_proc_definition() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("top_level_proc.ma");
    let proc_def = "global proc string hello() { return \"ok\"; }";
    std::fs::write(
        &source,
        format!(
            "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n{proc_def}\npython(\"print(1)\");\n"
        ),
    )
    .unwrap();

    let start = "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n".len();
    let end = start + proc_def.len() + 1;
    let preview = preview_clean_execution_targets(
        &source,
        &[ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange { start, end },
        }],
    )
    .unwrap();

    assert_eq!(preview.cleaned_count(), 1);

    let output = dir.path().join("top_level_proc_clean.ma");
    let result = clean_execution_targets(
        &source,
        &output,
        &[ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange { start, end },
        }],
    )
    .unwrap();
    let text = std::fs::read_to_string(&output).unwrap();
    assert_eq!(result.cleaned_count(), 1);
    assert!(!text.contains(proc_def));
    assert!(text.contains("python(\"print(1)\");"));
}

#[test]
fn preview_clean_execution_targets_supports_top_level_other_statement() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("top_level_other.ma");
    let statement =
        "string $myoutliner = `nodeOutliner -showInputs true -addCommand \"print(\\\"ok\\\")\"`;";
    std::fs::write(
        &source,
        format!("//Maya ASCII 2026 scene\nrequires maya \"2026\";\n{statement}\n"),
    )
    .unwrap();

    let start = "//Maya ASCII 2026 scene\nrequires maya \"2026\";\n".len();
    let end = start + statement.len() + 1;
    let preview = preview_clean_execution_targets(
        &source,
        &[ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange { start, end },
        }],
    )
    .unwrap();

    assert_eq!(preview.cleaned_count(), 1);

    let output = dir.path().join("top_level_other_clean.ma");
    let result = clean_execution_targets(
        &source,
        &output,
        &[ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange { start, end },
        }],
    )
    .unwrap();
    let text = std::fs::read_to_string(&output).unwrap();
    assert_eq!(result.cleaned_count(), 1);
    assert!(!text.contains("-addCommand"));
    assert!(!text.contains(statement));
}

#[test]
fn clean_execution_targets_strips_file_command_callback_flag() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("callback.ma");
    let command = r#"file -r -ns "ref" -command "onLoad" "python(\"import os\")" "C:/ref.ma";"#;
    std::fs::write(&source, format!("//Maya ASCII 2026 scene\n{command}\n")).unwrap();

    let result = clean_execution_targets(
        &source,
        dir.path().join("callback_clean.ma"),
        &[ExecutionCleanTarget::FileCommandCallback {
            source_range: ExecutionSourceRange {
                start: "//Maya ASCII 2026 scene\n".len(),
                end: "//Maya ASCII 2026 scene\n".len() + command.len() + 1,
            },
        }],
    )
    .unwrap();

    let text = std::fs::read_to_string(dir.path().join("callback_clean.ma")).unwrap();
    assert_eq!(result.cleaned_count(), 1);
    assert!(!text.contains("-command"));
    assert!(text.contains(r#"file -r -ns "ref" "C:/ref.ma";"#));
}

#[test]
fn clean_execution_targets_supports_mb_owner_form() {
    let dir = tempdir().unwrap();
    let source = repo_root().join("tests/02/sphere.mb");
    let target = collect_raw_chunks(&source)
        .unwrap()
        .into_iter()
        .find_map(|chunk| {
            match (
                chunk.trace_form.as_str(),
                chunk.trace_tag.as_str(),
                chunk.trace_node_offset,
            ) {
                ("SCRP", "STR ", node_offset) => Some(ExecutionCleanTarget::MbOwnerForm {
                    form: "SCRP".to_string(),
                    node_offset,
                }),
                _ => None,
            }
        })
        .expect("raw chunk owner form target");
    let preview = preview_clean_execution_targets(&source, std::slice::from_ref(&target)).unwrap();
    assert_eq!(preview.cleaned_count(), 1);
    assert!(preview.removed_script_nodes.is_empty());

    let before_entries = collect_script_node_entries(&source).unwrap();
    let output = dir.path().join("raw_chunk_clean.mb");
    let result = clean_execution_targets(&source, &output, &[target]).unwrap();
    let after_entries = collect_script_node_entries(&output).unwrap();

    assert_eq!(result.cleaned_count(), 1);
    assert!(after_entries.entries.len() < before_entries.entries.len());
}

#[test]
fn clean_execution_targets_supports_plugin_require_for_ma() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("plugin_require.ma");
    std::fs::write(
        &source,
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "requires \"pluginA\" \"1.0\";\n",
            "file -r \"safe.ma\";\n",
        ),
    )
    .unwrap();

    let preview = preview_clean_execution_targets(
        &source,
        &[ExecutionCleanTarget::PluginRequire {
            rendered: "requires \"pluginA\" \"1.0\";".to_string(),
        }],
    )
    .unwrap();
    assert_eq!(preview.cleaned_count(), 1);
    assert_eq!(
        preview.removed_plugin_requires,
        vec!["requires \"pluginA\" \"1.0\";".to_string()]
    );

    let output = dir.path().join("plugin_require_clean.ma");
    let result = clean_execution_targets(
        &source,
        &output,
        &[ExecutionCleanTarget::PluginRequire {
            rendered: "requires \"pluginA\" \"1.0\";".to_string(),
        }],
    )
    .unwrap();
    let text = std::fs::read_to_string(&output).unwrap();
    assert_eq!(result.cleaned_count(), 1);
    assert!(text.contains("requires maya \"2026\";"));
    assert!(!text.contains("requires \"pluginA\" \"1.0\";"));
    assert!(text.contains("file -r \"safe.ma\";"));
}

#[test]
fn clean_execution_targets_supports_plugin_require_for_mb() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("plugin_require.mb");
    let head = build_mb_form_with_alignment(
        "HEAD",
        &[
            build_mb_chunk("VERS", b"2026\0"),
            build_mb_chunk("PLUG", b"pluginA\x001.0\0"),
            build_mb_chunk("PLUG", b"pluginB\x002.0\0"),
        ],
        4,
    );
    std::fs::write(&source, build_mb_root(&[head])).unwrap();

    let preview = preview_clean_execution_targets(
        &source,
        &[ExecutionCleanTarget::PluginRequire {
            rendered: "requires \"pluginA\" \"1.0\";".to_string(),
        }],
    )
    .unwrap();
    assert_eq!(preview.cleaned_count(), 1);
    assert_eq!(
        preview.removed_plugin_requires,
        vec!["requires \"pluginA\" \"1.0\";".to_string()]
    );

    let output = dir.path().join("plugin_require_clean.mb");
    let result = clean_execution_targets(
        &source,
        &output,
        &[ExecutionCleanTarget::PluginRequire {
            rendered: "requires \"pluginA\" \"1.0\";".to_string(),
        }],
    )
    .unwrap();
    let report = Loader::new(LoadOptions::default())
        .observe_path(&output)
        .unwrap()
        .scene_dump_report()
        .unwrap();

    assert_eq!(result.cleaned_count(), 1);
    assert!(
        report
            .requires
            .iter()
            .any(|value| value == "requires maya \"2026\";")
    );
    assert!(
        !report
            .requires
            .iter()
            .any(|value| value == "requires \"pluginA\" \"1.0\";")
    );
    assert!(
        report
            .requires
            .iter()
            .any(|value| value == "requires \"pluginB\" \"2.0\";")
    );
}
