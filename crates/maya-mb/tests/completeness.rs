use maya_mb::{
    MayaBinaryParseError, MbChildren, MbCompleteness, MbParseBudget, MbTruncationReason,
    parse_bytes, parse_bytes_with_budget, parse_file,
};

fn group(children: &[u8]) -> Vec<u8> {
    let mut bytes = b"FOR4".to_vec();
    bytes.extend_from_slice(&(4u32 + children.len() as u32).to_be_bytes());
    bytes.extend_from_slice(b"SCRP");
    bytes.extend_from_slice(children);
    bytes
}

#[test]
fn preserves_prefix_reasons_and_subtree_counts() {
    let valid = group(&[]);
    let malformed = b"DATA\0\0\0\x20";
    let mut children = valid.clone();
    children.extend_from_slice(malformed);
    let bytes = group(&children);
    let parsed = parse_bytes(bytes.clone()).unwrap();
    assert_eq!(parsed.root().children().len(), 1);
    assert!(matches!(
        parsed.root().children_state(),
        MbChildren::Truncated {
            reason: MbTruncationReason::Malformed(MayaBinaryParseError::PayloadOutOfBounds {
                offset: 24,
                ..
            }),
            ..
        }
    ));
    assert!(matches!(
        parsed.completeness(),
        MbCompleteness::Truncated {
            first_reason: MbTruncationReason::Malformed(_),
            truncated_groups: 1
        }
    ));
    let clone = parsed.clone().with_path("Example.mb");
    assert!(std::sync::Arc::ptr_eq(parsed.data_arc(), clone.data_arc()));
    assert_eq!(clone.walk().len(), 2);
    assert_eq!(
        clone.completeness().to_string(),
        parsed.completeness().to_string()
    );

    let dir = std::env::temp_dir().join(format!("Example-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Example.mb");
    for data in [bytes, group(malformed)] {
        std::fs::write(&path, &data).unwrap();
        let from_file = parse_file(&path).unwrap();
        let from_bytes = parse_bytes(data).unwrap();
        assert_eq!(
            from_file.completeness().to_string(),
            from_bytes.completeness().to_string()
        );
        assert_eq!(
            from_file.root().children().len(),
            from_bytes.root().children().len()
        );
    }
    std::fs::remove_dir_all(dir).unwrap();

    let leaves = group(b"DATA\0\0\0\0DATA\0\0\0\0");
    for (budget, reason) in [
        (
            MbParseBudget {
                max_children_per_group: 1,
                ..Default::default()
            },
            "ChildLimit",
        ),
        (
            MbParseBudget {
                max_total_chunks: 2,
                ..Default::default()
            },
            "ChunkBudget",
        ),
    ] {
        let parsed = parse_bytes_with_budget(leaves.clone(), &budget).unwrap();
        assert_eq!(parsed.root().children().len(), 1);
        assert_eq!(
            parsed.completeness().to_string(),
            format!("truncated first_reason={reason} truncated_groups=1")
        );
    }
    let exact = MbParseBudget {
        max_children_per_group: 2,
        max_total_chunks: 3,
        ..Default::default()
    };
    assert!(matches!(
        parse_bytes_with_budget(leaves, &exact)
            .unwrap()
            .completeness(),
        MbCompleteness::Complete
    ));
    assert!(matches!(
        parse_bytes_with_budget(
            group(&[]),
            &MbParseBudget {
                max_children_per_group: 0,
                max_total_chunks: 1,
                ..Default::default()
            }
        )
        .unwrap()
        .completeness(),
        MbCompleteness::Complete
    ));
    for depth in [0, 1] {
        let parsed = parse_bytes_with_budget(
            group(&valid),
            &MbParseBudget {
                max_depth: depth,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(parsed.not_expanded_groups(), 1);
        assert!(matches!(
            parsed.completeness(),
            MbCompleteness::Truncated {
                first_reason: MbTruncationReason::DepthLimit,
                truncated_groups: 1
            }
        ));
        assert_eq!(parsed.root().children_complete(), depth == 1);
    }
    let broken_group = group(malformed);
    let mut nested = broken_group.clone();
    nested.extend_from_slice(&broken_group);
    let parsed = parse_bytes(group(&nested)).unwrap();
    assert!(parsed.root().children_complete());
    assert_eq!(parsed.root().children().len(), 2);
    assert!(matches!(
        parsed.completeness(),
        MbCompleteness::Truncated {
            truncated_groups: 2,
            ..
        }
    ));
    assert!(matches!(
        parsed.root().children()[0].completeness(),
        MbCompleteness::Truncated {
            truncated_groups: 1,
            ..
        }
    ));
    // The parent budget reason precedes the retained descendant error.
    let parsed = parse_bytes_with_budget(
        group(&nested),
        &MbParseBudget {
            max_total_chunks: 3,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(matches!(
        parsed.completeness(),
        MbCompleteness::Truncated {
            first_reason: MbTruncationReason::ChunkBudget,
            truncated_groups: 2
        }
    ));

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for fixture in [
        "tests/01/skin.mb",
        "tests/02/sphere.mb",
        "tests/fixtures/mb/owner_delete/connected_file_owner_delete.mb",
        "tests/fixtures/mb/owner_delete/file_owner_delete.mb",
    ] {
        assert!(
            matches!(
                parse_file(root.join(fixture)).unwrap().completeness(),
                MbCompleteness::Complete
            ),
            "{fixture}"
        );
    }
}
