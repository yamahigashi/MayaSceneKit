use maya_scene_kit_edit::scene::{
    PathOwnerDeleteTarget, PathReplaceOverride, SceneEditIntent, SceneEditLocator, SceneEditPlan,
    SceneEditStatus, stage_scene_edit_plan,
};
use maya_scene_kit_observe::scene::{LoadOptions, Loader, paths::PathKind};

const HEADER: &str = "//Maya ASCII 2026 scene\n";
const BLOCK: &str = "createNode file -n \"Example\";\n    setAttr \".ftn\" -type \"string\" \"asset/example/file.tx\";\n";

fn plan(source: &str) -> (tempfile::TempDir, SceneEditPlan) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    std::fs::write(&path, source).unwrap();
    let report = Loader::new(LoadOptions::default())
        .observe_path(&path)
        .unwrap()
        .scene_paths_report(PathKind::All)
        .unwrap();
    let mut intents = report
        .entries
        .iter()
        .enumerate()
        .map(|(entry_index, entry)| {
            SceneEditIntent::Path(PathReplaceOverride {
                entry_index,
                before_value: entry.value.clone(),
                after_value: "asset/example/changed.tx".into(),
            })
        })
        .collect::<Vec<_>>();
    intents.push(SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
        node_type: "file".into(),
        node_name: "Example".into(),
    }));
    (
        dir,
        SceneEditPlan {
            report,
            clean_source: None,
            intents,
        },
    )
}

#[test]
fn owner_paths_are_attributed_to_their_containing_deleted_block() {
    for count in [1, 2] {
        let source = format!(
            "{HEADER}{BLOCK}{}",
            if count == 2 {
                BLOCK.replace("file.tx", "next.tx")
            } else {
                String::new()
            }
        );
        let (_dir, plan) = plan(&source);
        let staged = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
        assert_eq!(staged.artifact.bytes, HEADER.as_bytes());
        assert_eq!(staged.changes.physical_deletion_count, count);
        assert_eq!(staged.changes.superseded_path_override_count, count);
        assert_eq!(staged.changes.records.len(), count * 2);
        assert_eq!(staged.changes.path_replacements.replacement_count, 0);
        let paths = staged
            .changes
            .records
            .iter()
            .filter(|record| matches!(record.intent, SceneEditIntent::Path(_)))
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), count);
        for (index, record) in paths.into_iter().enumerate() {
            assert_eq!(record.status, SceneEditStatus::Superseded);
            assert_eq!(
                record.superseded_by,
                Some(SceneEditLocator::MaRange {
                    start: HEADER.len() + BLOCK.len() * index,
                    end: HEADER.len() + BLOCK.len() * (index + 1),
                })
            );
        }
    }
}

#[test]
fn owner_path_in_a_later_command_is_replaced_independently() {
    let later = "setAttr \".ftn\" -type \"string\" \"asset/example/later.tx\";\n";
    let source = format!("{HEADER}{BLOCK}{later}");
    let (_dir, mut plan) = plan(&source);
    let staged = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
    assert_eq!(
        staged.artifact.bytes,
        format!("{HEADER}{}", later.replace("later.tx", "changed.tx")).as_bytes()
    );
    assert_eq!(staged.changes.physical_deletion_count, 1);
    assert_eq!(staged.changes.path_replacements.replacement_count, 1);
    assert_eq!(staged.changes.superseded_path_override_count, 1);
    let surviving = staged
        .changes
        .records
        .iter()
        .find(|record| record.before == b"asset/example/later.tx")
        .unwrap();
    assert_eq!(surviving.status, SceneEditStatus::Applied);
    assert_eq!(surviving.superseded_by, None);
    plan.intents
        .retain(|intent| matches!(intent, SceneEditIntent::Path(_)));
    let independent = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
    let independent = independent
        .changes
        .records
        .iter()
        .find(|record| record.locator == surviving.locator)
        .unwrap();
    assert_eq!(surviving, independent);
}
