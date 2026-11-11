use maya_scene_kit_edit::scene::{
    PatchPlanner, PathOwnerDeleteTarget, PathReplaceMode, PathReplaceOverride, PathReplaceRule,
};
use maya_scene_kit_observe::scene::{SceneToolError, collect_scene_paths, paths::PathKind};

#[path = "support/mb_chunks.rs"]
mod mb_chunks;

fn scene(value: &str) -> Vec<u8> {
    format!("//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/{value}.tx\";\n").into_bytes()
}

fn check(entry: usize, same_length: bool, missing_source: bool, binary: bool) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join(if binary { "Example.mb" } else { "Example.ma" });
    let bytes = if binary {
        mb_chunks::build_mb_root(&[mb_chunks::build_mb_form_with_alignment(
            "RTFT",
            &[
                mb_chunks::build_mb_chunk("CREA", b"Example\0"),
                mb_chunks::build_mb_chunk("STR ", b"ftn\0\x00asset/example/Example.tx\0"),
            ],
            8,
        )])
    } else {
        scene("Example")
    };
    std::fs::write(&path, &bytes).unwrap();
    let mut report = collect_scene_paths(&path, PathKind::All).unwrap();
    assert_eq!(report.entries.len(), 1);
    if missing_source {
        report.source = None;
    } else {
        let replacement = if binary {
            mb_chunks::build_mb_root(&[])
        } else if same_length {
            scene("SampleA")
        } else {
            scene("TestAsset")
        };
        assert_eq!(bytes.len() == replacement.len(), same_length);
        std::fs::write(&path, replacement).unwrap();
    }
    let planner = PatchPlanner::new(
        maya_scene_kit_edit::scene::MaterializeOptions::default()
            .with_operation_mode(maya_scene_kit_edit::scene::OperationMode::Forensic),
    );
    let targets = [PathOwnerDeleteTarget {
        node_type: "file".into(),
        node_name: "Example".into(),
    }];
    let result = match entry {
        0 => planner
            .stage_replace_scene_paths_with_overrides_in_report(
                &report,
                &[PathReplaceOverride {
                    entry_index: 0,
                    before_value: report.entries[0].value.clone(),
                    after_value: "asset/example/Sample.tx".into(),
                }],
            )
            .map(|_| ()),
        1 => planner
            .preview_replace_scene_path_candidates_in_report(
                &report,
                &[PathReplaceRule {
                    from: "asset/".into(),
                    to: "sample/".into(),
                    mode: PathReplaceMode::Literal,
                }],
            )
            .map(|_| ()),
        2 => planner
            .preview_delete_path_owner_nodes_in_report(&report, &targets)
            .map(|_| ()),
        3 => planner
            .stage_delete_path_owner_nodes_in_report(&report, &targets)
            .map(|_| ()),
        _ => unreachable!(),
    };
    assert!(
        matches!(result, Err(SceneToolError::SourceChanged { path: ref changed }) if changed == &path),
        "{result:?}"
    );
}

#[test]
fn overrides_reject_changed_length() {
    check(0, false, false, false);
}
#[test]
fn candidates_reject_changed_length() {
    check(1, false, false, false);
}
#[test]
fn owner_preview_rejects_changed_length() {
    check(2, false, false, false);
}
#[test]
fn owner_stage_rejects_changed_length() {
    check(3, false, false, false);
}
#[test]
fn overrides_reject_changed_digest() {
    check(0, true, false, false);
}
#[test]
fn overrides_reject_missing_source() {
    check(0, false, true, false);
}
#[test]
fn binary_overrides_reject_changed_length() {
    check(0, false, false, true);
}
