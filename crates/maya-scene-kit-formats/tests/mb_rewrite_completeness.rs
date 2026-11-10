use maya_scene_kit_formats::mb::{
    self, MbCompleteness, MbNameSelection, MbParseBudget, MbTruncationReason,
};

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
    macro_rules! assert_incomplete {
        ($result:expr) => {
            let error = $result.unwrap_err();
            let mb::MbRewriteError::IncompleteTree(completeness) = error else {
                panic!("expected incomplete tree");
            };
            assert!(matches!(
                completeness,
                MbCompleteness::Truncated {
                    first_reason: MbTruncationReason::ChildLimit
                        | MbTruncationReason::ChunkBudget
                        | MbTruncationReason::DepthLimit
                        | MbTruncationReason::Malformed(_),
                    truncated_groups: 1,
                }
            ));
            assert_eq!(completeness.to_string(), parsed.completeness().to_string());
        };
    }
    assert_incomplete!(mb::replace_scene_paths_in_mb(data, root, &[]));
    assert_incomplete!(mb::replace_scene_paths_in_mb_cow(data, root, &[]));
    assert_incomplete!(mb::rewrite::replace_scene_paths_in_mb_by_index(
        data,
        root,
        &[]
    ));
    assert_incomplete!(mb::rewrite::replace_scene_paths_in_mb_by_index_cow(
        data,
        root,
        &[]
    ));
    assert_incomplete!(mb::remove_raw_script_nodes_from_mb(data, root));
    assert_incomplete!(mb::paths::remove_raw_script_nodes_from_mb_by_name(
        data,
        root,
        &[]
    ));
    assert_incomplete!(mb::remove_root_forms_from_mb_by_locator(data, root, &[]));
    assert_incomplete!(mb::remove_plugin_requires_from_mb(data, root, &[]));
    assert_incomplete!(mb::remove_root_forms_and_plugin_requires_from_mb(
        data,
        root,
        &[],
        MbNameSelection::All
    ));
}

#[test]
fn fixture_terminal_children_and_owner_traces() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (fixture, terminal_group, owner_offsets, connections, relations) in [
        ("tests/01/skin.mb", 32576, vec![], 53, 4),
        ("tests/02/sphere.mb", 50580, vec![], 8, 4),
        (
            "tests/fixtures/mb/owner_delete/connected_file_owner_delete.mb",
            8488,
            vec![4364, 5036],
            65,
            8,
        ),
        (
            "tests/fixtures/mb/owner_delete/file_owner_delete.mb",
            6292,
            vec![3324, 3464],
            13,
            4,
        ),
    ] {
        let parsed = mb::parse_file(root.join(fixture)).unwrap();
        let visible = parsed
            .walk()
            .into_iter()
            .filter_map(|group| {
                let last = group.children().last()?;
                let alignment = group.child_layout()?.alignment_usize();
                (last.payload_end() == group.payload_end() && last.size() % alignment != 0).then(
                    || {
                        (
                            group.offset(),
                            group
                                .children()
                                .iter()
                                .map(|child| child.tag().to_string())
                                .collect::<Vec<_>>(),
                        )
                    },
                )
            })
            .collect::<Vec<_>>();
        let traces = mb::collect_rtft_owner_traces_from_mb(&parsed)
            .value
            .into_iter()
            .map(|trace| {
                (
                    trace.trace_node_offset,
                    trace.trace_form,
                    trace.trace_tag,
                    trace.trace_child_alignment,
                    trace.trace_child_header_size,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            visible,
            vec![(terminal_group, vec!["FOR8".to_string()])],
            "{fixture}"
        );
        let group = parsed
            .walk()
            .into_iter()
            .find(|chunk| chunk.offset() == terminal_group)
            .unwrap();
        let descendants = parsed
            .walk()
            .into_iter()
            .filter(|chunk| {
                chunk.offset() > group.offset() && chunk.payload_end() <= group.payload_end()
            })
            .map(|chunk| chunk.tag().to_string())
            .collect::<Vec<_>>();
        let mut counts = std::collections::BTreeMap::new();
        for tag in descendants {
            *counts.entry(tag).or_insert(0usize) += 1;
        }
        assert_eq!(
            counts,
            std::collections::BTreeMap::from([
                ("FOR8".to_string(), 1),
                ("CWFL".to_string(), connections),
                ("RELA".to_string(), relations),
            ]),
            "newly visible descendants {fixture}"
        );
        let expected = owner_offsets
            .into_iter()
            .map(|offset| {
                (
                    offset,
                    "RTFT".to_string(),
                    Some("STR ".to_string()),
                    Some(8),
                    Some(16),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(traces, expected, "{fixture}");
    }
}
