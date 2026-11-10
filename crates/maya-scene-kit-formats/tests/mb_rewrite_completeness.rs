use maya_scene_kit_formats::mb::{self, MbNameSelection, MbParseBudget};

#[test]
fn all_rewriters_refuse_incomplete_trees_even_without_targets() {
    let bytes = b"FOR4\0\0\0\x14MayaDATA\0\0\0\0DATA\0\0\0\0";
    for budget in [
        MbParseBudget {
            max_children_per_group: 1,
            ..Default::default()
        },
        MbParseBudget {
            max_total_chunks: 2,
            ..Default::default()
        },
        MbParseBudget {
            max_depth: 0,
            ..Default::default()
        },
    ] {
        let parsed = mb::parse_bytes_with_budget(bytes.to_vec(), &budget).unwrap();
        assert_rejected(&parsed);
    }
    let parsed = mb::parse_bytes(b"FOR4\0\0\0\x0cMayaDATA\0\0\0\x20".to_vec()).unwrap();
    assert_rejected(&parsed);
}

fn assert_rejected(parsed: &mb::MayaBinaryFile) {
    let data = parsed.data();
    let root = parsed.root();
    assert!(mb::replace_scene_paths_in_mb(data, root, &[]).is_err());
    assert!(mb::replace_scene_paths_in_mb_cow(data, root, &[]).is_err());
    assert!(mb::rewrite::replace_scene_paths_in_mb_by_index(data, root, &[]).is_err());
    assert!(mb::rewrite::replace_scene_paths_in_mb_by_index_cow(data, root, &[]).is_err());
    assert!(mb::remove_raw_script_nodes_from_mb(data, root).is_err());
    assert!(mb::paths::remove_raw_script_nodes_from_mb_by_name(data, root, &[]).is_err());
    assert!(mb::remove_root_forms_from_mb_by_locator(data, root, &[]).is_err());
    assert!(mb::remove_plugin_requires_from_mb(data, root, &[]).is_err());
    assert!(
        mb::remove_root_forms_and_plugin_requires_from_mb(data, root, &[], MbNameSelection::All)
            .is_err()
    );
}
