use maya_mb::parse_bytes;

#[test]
fn accepts_omitted_terminal_child_padding() {
    let mut bytes = b"FOR8\0\0\0\0".to_vec();
    bytes.extend_from_slice(&26u64.to_be_bytes());
    bytes.extend_from_slice(b"MayaDATA\0\0\0\0");
    bytes.extend_from_slice(&6u64.to_be_bytes());
    bytes.extend_from_slice(b"Sample");
    let parsed = parse_bytes(bytes).unwrap();
    assert!(parsed.root().children_complete());
    assert_eq!(parsed.root().children().len(), 1);
    assert_eq!(parsed.payload(&parsed.root().children()[0]), b"Sample");
}

#[test]
fn parser_and_section_agree_on_padding_boundaries() {
    use maya_mb::{LayoutHints, MbChildren, MbTruncationReason, parse_section_chunks_with_hints};

    fn chunk(tag: &[u8; 4], payload: &[u8], wide: bool) -> Vec<u8> {
        let mut bytes = tag.to_vec();
        if wide {
            bytes.extend_from_slice(&0u32.to_be_bytes());
            bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        } else {
            bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        }
        bytes.extend_from_slice(payload);
        bytes
    }

    for (tag, form, wide, alignment) in [
        (b"FOR4", b"Maya", false, 4),
        (b"FOR8", b"Maya", true, 4),
        (b"LIS8", b"CONS", true, 8),
    ] {
        for nested in [false, true] {
            for case in ["omitted", "complete", "partial", "oversize", "nonterminal"] {
                let mut children = chunk(b"DATA", b"X", wide);
                match case {
                    "complete" => children.resize(children.len() + alignment - 1, 0),
                    "partial" => children.push(0),
                    "oversize" => {
                        children.pop();
                    }
                    "nonterminal" => children.extend_from_slice(&chunk(b"TEST", b"", wide)),
                    _ => {}
                }
                let mut payload = form.to_vec();
                payload.extend_from_slice(&children);
                let mut bytes = chunk(tag, &payload, wide);
                if nested {
                    let mut outer = form.to_vec();
                    outer.extend_from_slice(&bytes);
                    bytes = chunk(tag, &outer, wide);
                }
                if tag == b"LIS8" {
                    let mut outer = b"Maya".to_vec();
                    outer.extend_from_slice(&bytes);
                    bytes = chunk(b"FOR8", &outer, true);
                }
                let parsed = parse_bytes(bytes).unwrap();
                let root = if tag == b"LIS8" {
                    &parsed.root().children()[0]
                } else {
                    parsed.root()
                };
                let group = if nested { &root.children()[0] } else { root };
                let section = parse_section_chunks_with_hints(
                    &children,
                    LayoutHints::from(group.child_layout().unwrap()),
                );
                assert_eq!(
                    section.chunks().len(),
                    group.children().len(),
                    "{case} {wide} {alignment} {nested}"
                );
                assert_eq!(
                    group.children().len(),
                    usize::from(!matches!(case, "partial" | "oversize")),
                    "retained children {case}"
                );
                if case == "partial" {
                    assert!(matches!(
                        group.children_state(),
                        MbChildren::Truncated {
                            reason: MbTruncationReason::Malformed(
                                maya_mb::MayaBinaryParseError::AlignedEndOutOfBounds { .. }
                            ),
                            ..
                        }
                    ));
                }
                let complete = matches!(case, "omitted" | "complete");
                assert_eq!(group.children_complete(), complete, "{case}");
                assert_eq!(section.tail_span().is_empty(), complete, "{case}");
                if complete {
                    assert_eq!(group.children().len(), 1);
                    assert_eq!(parsed.payload(&group.children()[0]), b"X");
                } else {
                    assert!(matches!(
                        group.children_state(),
                        MbChildren::Truncated {
                            reason: MbTruncationReason::Malformed(_),
                            ..
                        }
                    ));
                }
            }
        }
    }
}
