use maya_scene_kit_formats::mb::{MbCompleteness, parse_bytes, replace_scene_paths_in_mb_cow};

#[test]
fn complete_mixed_width_tree_refuses_noop_rewrite() {
    let mut bytes =
        b"FOR4\0\0\0\x2cMayaFOR4\0\0\0\x20HEADFOR8\0\0\0\x14TESTDATA\0\0\0\x01X".to_vec();
    bytes.extend_from_slice(&[0; 7]);
    let mb = parse_bytes(bytes).unwrap();
    assert!(matches!(mb.completeness(), MbCompleteness::Complete));
    assert_eq!(
        maya_scene_kit_formats::mb::extract_head_metadata(&mb).section_state,
        maya_scene_kit_formats::mb::MbSectionScanState::Stopped
    );
    assert_eq!(
        maya_scene_kit_formats::mb::paths::extract_raw_scene_paths_from_mb(&mb).state,
        maya_scene_kit_formats::mb::MbSectionScanState::Stopped
    );
    assert!(replace_scene_paths_in_mb_cow(mb.data(), mb.root(), &[]).is_err());
}

#[test]
fn nonprintable_chunks_preserve_extraction_and_replacement() {
    use std::num::NonZeroUsize;

    use maya_mb::encode_chunk;
    use maya_scene_kit_formats::mb::{
        ChunkLayout, FourCC, HeaderFormat, LayoutHints, MbPathReplaceRule, MbSectionScanState,
        paths::extract_raw_script_entries_from_mb, walk_group_chunks_with_layout,
    };
    for wide in [false, true] {
        let header = if wide {
            HeaderFormat::EightByte
        } else {
            HeaderFormat::FourByte
        };
        let layout = ChunkLayout::new(NonZeroUsize::new(if wide { 8 } else { 4 }).unwrap(), header);
        let outer = ChunkLayout::new(NonZeroUsize::new(4).unwrap(), header);
        let group = FourCC::new(if wide { *b"FOR8" } else { *b"FOR4" });
        let mut root_payload = b"Maya".to_vec();
        for (form, body) in [
            (b"SCRP", b"b\0\0print \"Example\";\0".as_slice()),
            (b"RTFT", b"ftn\0\0asset/example/Example.mb\0".as_slice()),
        ] {
            let mut payload = form.to_vec();
            for (tag, value) in [
                (FourCC::new(*b"CREA"), b"ExampleScript\0".as_slice()),
                (FourCC::new([0, 0, 0, 1]), &[]),
                (FourCC::new(*b"STR "), body),
            ] {
                payload.extend_from_slice(&encode_chunk(tag, 0, value, layout).unwrap());
            }
            let walked = walk_group_chunks_with_layout(&payload[4..], LayoutHints::from(layout));
            assert_eq!(walked.state, MbSectionScanState::Complete);
            assert_eq!(walked.chunks.len(), 3);
            assert_eq!(walked.chunks[2].tag(), "STR ");
            root_payload.extend_from_slice(&encode_chunk(group, 0, &payload, outer).unwrap());
        }
        let mb = parse_bytes(encode_chunk(group, 0, &root_payload, outer).unwrap()).unwrap();
        let scripts = extract_raw_script_entries_from_mb(&mb);
        assert_eq!(scripts.state, MbSectionScanState::Complete);
        assert!(scripts.value[0].1.contains("Example"));
        let paths = maya_scene_kit_formats::mb::paths::extract_raw_scene_paths_from_mb(&mb);
        assert_eq!(paths.state, MbSectionScanState::Complete);
        assert_eq!(paths.value[0].value, "asset/example/Example.mb");
        let rule = MbPathReplaceRule {
            from: "asset/example/Example.mb".into(),
            to: "asset/example/Sample.mb".into(),
            mode: maya_scene_kit_formats::ma::types::PathReplaceMode::Literal,
        };
        let (bytes, count) = replace_scene_paths_in_mb_cow(mb.data(), mb.root(), &[rule]).unwrap();
        assert_eq!(count.replacement_count, 1);
        let updated = parse_bytes(bytes.into_owned()).unwrap();
        assert_eq!(
            maya_scene_kit_formats::mb::paths::extract_raw_scene_paths_from_mb(&updated).value[0]
                .value,
            "asset/example/Sample.mb"
        );
    }
}

#[test]
fn root_leaf_allows_rewrite() {
    let mb = parse_bytes(b"FOR4\0\0\0\x14MayaDATA\0\0\0\x08ABCDEFGH".to_vec()).unwrap();
    assert!(matches!(mb.completeness(), MbCompleteness::Complete));
    assert!(replace_scene_paths_in_mb_cow(mb.data(), mb.root(), &[]).is_ok());
}

#[test]
fn raised_parse_budget_is_preserved_when_cleaning() {
    use maya_scene_kit_formats::mb::{
        MbParseBudget, parse_bytes_with_budget, remove_raw_script_nodes_from_mb,
    };
    fn chunk(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut bytes = tag.to_vec();
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    }
    let mut section = b"SCRP".to_vec();
    for _ in 0..100_001 {
        section.extend_from_slice(&chunk(b"DATA", &[]));
    }
    section.extend_from_slice(&chunk(b"CREA", b"ExampleScript\0"));
    let mut root = b"Maya".to_vec();
    root.extend_from_slice(&chunk(b"FOR4", &section));
    let budget = MbParseBudget {
        max_children_per_group: 200_000,
        ..MbParseBudget::default()
    };
    let mb = parse_bytes_with_budget(chunk(b"FOR4", &root), &budget).unwrap();
    assert!(matches!(mb.completeness(), MbCompleteness::Complete));
    let (cleaned, count) = remove_raw_script_nodes_from_mb(mb.data(), mb.root()).unwrap();
    assert_eq!(count, ["ExampleScript"]);
    assert!(parse_bytes(cleaned).unwrap().root().children().is_empty());
}

#[test]
fn rewrite_budget_error_retains_its_reason() {
    use maya_scene_kit_formats::mb::{
        ChunkLayout, FourCC, HeaderFormat, MbParseBudget, parse_bytes_with_budget,
    };
    let layout = ChunkLayout::new(
        std::num::NonZeroUsize::new(4).unwrap(),
        HeaderFormat::EightByte,
    );
    let mut bytes = maya_mb::encode_chunk(FourCC::new(*b"DATA"), 0, &[], layout).unwrap();
    for (tag, form) in [(b"FOR4", b"TEST"), (b"FOR8", b"HEAD"), (b"FOR8", b"Maya")] {
        let mut payload = form.to_vec();
        payload.extend_from_slice(&bytes);
        bytes = maya_mb::encode_chunk(FourCC::new(*tag), 0, &payload, layout).unwrap();
    }
    let budget = MbParseBudget {
        max_children_per_group: 1,
        ..MbParseBudget::default()
    };
    let mb = parse_bytes_with_budget(bytes, &budget).unwrap();
    assert!(matches!(mb.completeness(), MbCompleteness::Complete));
    let error =
        maya_scene_kit_formats::mb::rewrite::require_complete_mb_sections(mb.data(), mb.root())
            .unwrap_err();
    assert!(error.to_string().contains("child budget"), "{error}");
    assert!(!error.to_string().contains("section scan stopped"));
}
