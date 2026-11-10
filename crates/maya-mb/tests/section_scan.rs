use maya_mb::{
    FourCC, HeaderFormat, LayoutHints, MbParseBudget, MbParseBudgetLimit, MbSectionScanState,
    parse_section_chunks_with_hints_with_budget, walk_group_chunks_with_layout_with_budget,
};

#[test]
fn nonprintable_chunks_are_bounded_before_retention() {
    let data = [0u8; 24];
    let hints = LayoutHints::new().with_header_format(HeaderFormat::FourByte);
    for (children, total, limit) in [
        (2, 3, MbParseBudgetLimit::MaxChildrenPerGroup),
        (3, 2, MbParseBudgetLimit::MaxTotalChunks),
        (2, 2, MbParseBudgetLimit::MaxChildrenPerGroup),
    ] {
        let budget = MbParseBudget {
            max_children_per_group: children,
            max_total_chunks: total,
            ..MbParseBudget::default()
        };
        let parsed = parse_section_chunks_with_hints_with_budget(&data, hints, &budget);
        assert_eq!(parsed.chunks().len(), 2);
        assert_eq!(parsed.state(), MbSectionScanState::Stopped);
        assert_eq!(parsed.tail(&data), &[0; 8]);
        assert_eq!(parsed.chunks()[0].tag(), FourCC::new([0; 4]));
        let error =
            walk_group_chunks_with_layout_with_budget(&data, hints, 0, &budget).unwrap_err();
        assert_eq!(error.budget_limit(), Some(limit));
    }
    let budget = MbParseBudget {
        max_parse_bytes: 23,
        ..MbParseBudget::default()
    };
    let parsed = parse_section_chunks_with_hints_with_budget(&data, hints, &budget);
    assert!(parsed.chunks().is_empty());
    assert_eq!(parsed.tail(&data), data);
    assert_eq!(parsed.state(), MbSectionScanState::Stopped);
    assert_eq!(
        walk_group_chunks_with_layout_with_budget(&data, hints, 0, &budget)
            .unwrap_err()
            .budget_limit(),
        Some(MbParseBudgetLimit::MaxParseBytes)
    );
}

#[test]
fn budget_error_wins_after_nested_scan_stop() {
    let mut data = b"FOR4\0\0\0\x08TESTDATA".to_vec();
    data.extend_from_slice(&[0; 16]);
    let budget = MbParseBudget {
        max_children_per_group: 2,
        max_total_chunks: 2,
        ..MbParseBudget::default()
    };
    let hints = LayoutHints::new().with_header_format(HeaderFormat::FourByte);
    assert_eq!(
        walk_group_chunks_with_layout_with_budget(&data, hints, 0, &budget)
            .unwrap_err()
            .budget_limit(),
        Some(MbParseBudgetLimit::MaxChildrenPerGroup)
    );
}
