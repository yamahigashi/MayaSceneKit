use maya_scene_kit_formats::ma::{
    rewrite::replace_raw_scene_paths_in_ma,
    types::{PathReplaceMode, PathReplaceRule},
};

fn replace(input: &[u8], from: &str, to: &str) -> (Vec<u8>, usize) {
    let result = replace_raw_scene_paths_in_ma(
        input,
        &[PathReplaceRule {
            from: from.into(),
            to: to.into(),
            mode: PathReplaceMode::Literal,
        }],
    )
    .unwrap();
    (result.bytes, result.replacement_count)
}

#[test]
fn preserves_ranges_and_counts_changed_literals() {
    for input in [
        b"setAttr -l on \".ftn\" -type \"string\" \"old/old/Example.ma\"; // Sample\r\n".as_slice(),
        b"file -r \"old/Example.ma\"; file -r \"old/Sample.ma\";\r\n",
        b"/* // */ setAttr\t\".ftn\" -type \"string\" \"old/Example.ma\";\r",
        b"// Sample\rsetAttr \".ftn\" -type \"string\" \"old/Example.ma\";\r",
        b"\xef\xbb\xbffile\t-r \"old/Example.ma\";\r\n",
    ] {
        let (actual, count) = replace(input, "old/", "asset/");
        let expected = String::from_utf8_lossy(input)
            .replace("old/", "asset/")
            .into_bytes();
        assert_eq!(actual, expected);
        assert_eq!(
            count,
            if input.windows(7).filter(|w| *w == b"file -r").count() == 2 {
                2
            } else {
                1
            }
        );
    }
}

#[test]
fn preserves_invalid_and_noncanonical_literals() {
    for raw in [
        b"old/a\\rb\\d.ma".as_slice(),
        b"old/\nExample.ma",
        b"old/\x81?Example.ma",
    ] {
        let input = [
            b"// Codeset: 932\nsetAttr \".ftn\" -type \"string\" \"".as_slice(),
            raw,
            b"\";\n",
        ]
        .concat();
        assert_eq!(replace(&input, "old/", "asset/").0, input);
    }
}

#[test]
fn concatenation_uses_whole_value_match_boundaries() {
    let input = b"setAttr \".ftn\" -type \"string\" (\"old/\" + \"Example.ma\");\r\n";
    assert_eq!(replace(input, "old/Example", "asset/Sample").0, input);
    assert_eq!(
        replace(input, "old/", "asset/").0,
        b"setAttr \".ftn\" -type \"string\" (\"asset/\" + \"Example.ma\");\r\n"
    );
}

#[test]
fn malformed_tail_preserves_previous_complete_commands() {
    let input = b"file -r \"old/Example.ma\";\nfile -r -ns \"old/Sample.ma\" \"unfinished\\";
    assert_eq!(
        replace(input, "old/", "asset/"),
        (
            b"file -r \"asset/Example.ma\";\nfile -r -ns \"old/Sample.ma\" \"unfinished\\".to_vec(),
            1
        )
    );
}

#[test]
fn width_scanning_preserves_undecodable_names() {
    let input = b"// Codeset: 932\ncreateNode file -n \"\xfc\\\";\n    setAttr -l on \".ftn\" -type \"string\" \"old/Example.ma\";\r\n";
    let expected = b"// Codeset: 932\ncreateNode file -n \"\xfc\\\";\n    setAttr -l on \".ftn\" -type \"string\" \"asset/Example.ma\";\r\n";
    assert_eq!(replace(input, "old/", "asset/"), (expected.to_vec(), 1));
    assert_eq!(replace(input, "absent/", "asset/"), (input.to_vec(), 0));
}

fn apply(
    input: &[u8],
    from: &str,
    to: &str,
    mode: PathReplaceMode,
) -> maya_scene_kit_formats::ma::rewrite::MaPathReplaceResult {
    replace_raw_scene_paths_in_ma(
        input,
        &[PathReplaceRule {
            from: from.into(),
            to: to.into(),
            mode,
        }],
    )
    .unwrap()
}

#[test]
fn undecodable_values_do_not_hide_later_commands() {
    for invalid in [b"\xfc\\".as_slice(), b"\x81?", b"\xe3\x81\x82"] {
        let input = [b"// Codeset: 932\n// \x83\x65\x83\x58\x83\x67\nfile -r \"old/Sample.ma\";\nsetAttr \".ftn\" -type \"string\" \"old/".as_slice(), invalid, b".ma\";\nfile -r \"old/Example.ma\";\r\n"].concat();
        let result = apply(&input, "old/", "asset/", PathReplaceMode::Literal);
        assert_eq!(result.replacement_count, 2);
        assert_eq!(result.skipped.non_utf8, 1);
        assert_eq!(result.skipped.total(), 1);
        let expected = [b"// Codeset: 932\n// \x83\x65\x83\x58\x83\x67\nfile -r \"asset/Sample.ma\";\nsetAttr \".ftn\" -type \"string\" \"old/".as_slice(), invalid, b".ma\";\nfile -r \"asset/Example.ma\";\r\n"].concat();
        assert_eq!(result.bytes, expected);
        let unmatched = apply(&input, "absent/", "asset/", PathReplaceMode::Literal);
        assert_eq!(unmatched.bytes, input);
        assert_eq!(unmatched.skipped.non_utf8, 1);
    }
}

#[test]
fn encoding_labels_do_not_override_unambiguous_structure() {
    let input = "// Codeset: 932\r\nsetAttr \".ftn\" -type \"string\" \"ँ\\\"old/Example.ma\";\r\n";
    let result = apply(input.as_bytes(), "old/", "asset/", PathReplaceMode::Literal);
    assert_eq!(result.bytes, input.replace("old/", "asset/").as_bytes());
    assert_eq!(result.replacement_count, 1);
    assert_eq!(result.skipped.total(), 0);

    let gbk = b"// Codeset: 936\ncreateNode file -n \"\xa1\\\";\nsetAttr -l on \".ftn\" -type \"string\" \"old/Example.ma\";\r\n";
    let result = apply(gbk, "old/", "asset/", PathReplaceMode::Literal);
    let expected = b"// Codeset: 936\ncreateNode file -n \"\xa1\\\";\nsetAttr -l on \".ftn\" -type \"string\" \"asset/Example.ma\";\r\n";
    assert_eq!(result.bytes, expected);
    assert_eq!(result.replacement_count, 1);
    assert_eq!(result.skipped.total(), 0);
    let no_header = &gbk[b"// Codeset: 936\n".len()..];
    assert!(
        replace_raw_scene_paths_in_ma(
            no_header,
            &[PathReplaceRule {
                from: "old/".into(),
                to: "asset/".into(),
                mode: PathReplaceMode::Literal
            }]
        )
        .is_err()
    );
    assert_eq!(
        replace_raw_scene_paths_in_ma(no_header, &[]).unwrap().bytes,
        no_header
    );
}

#[test]
fn replacement_encoding_preserves_closing_quotes() {
    let input = b"// Codeset: 932\n// \x83\x65\x83\x58\x83\x67\nfile -r \"old/Example.ma\";\r\n";
    let result = apply(
        input,
        "old/Example.ma",
        "asset/Example.ma¥‾",
        PathReplaceMode::Literal,
    );
    assert_eq!(
        result.bytes,
        b"// Codeset: 932\n// \x83\x65\x83\x58\x83\x67\nfile -r \"asset/Example.ma\\\\~\";\r\n"
    );
    assert_eq!(result.replacement_count, 1);
    assert_eq!(result.paths[0].after_value, "asset/Example.ma\\~");
    let result = apply(input, "old/", "😀/", PathReplaceMode::Literal);
    assert_eq!(result.bytes, input);
    assert_eq!(result.replacement_count, 0);
    assert_eq!(result.skipped.unrepresentable, 1);
}

#[test]
fn escaped_matches_use_decoded_offsets_and_preserve_other_literals() {
    let input = b"setAttr -l on \".ftn\" -type \"string\" (\"old/a\\\\b.ma\" + \"a\\d.ma\");\r\n";
    let result = apply(input, "a\\b", "a/b", PathReplaceMode::Literal);
    assert_eq!(
        result.bytes,
        b"setAttr -l on \".ftn\" -type \"string\" (\"old/a/b.ma\" + \"a\\d.ma\");\r\n"
    );
    assert_eq!(result.replacement_count, 1);
    assert_eq!(result.skipped.total(), 0);
    for raw in [
        b"old/\nExample.ma".as_slice(),
        b"old/a\\d.ma",
        b"old/a\\rb.ma",
        b"old/a\\tb.ma",
    ] {
        let input = [
            b"setAttr \".ftn\" -type \"string\" \"".as_slice(),
            raw,
            b"\";\r\n",
        ]
        .concat();
        let result = apply(&input, "old/", "asset/", PathReplaceMode::Literal);
        assert_eq!(result.bytes, input);
        assert_eq!(result.skipped.non_canonical_escape, 1);
        assert_eq!(result.skipped.total(), 1);
    }
}

#[test]
fn concatenation_skip_priority_and_regex_anchors_use_complete_values() {
    let input = b"setAttr \".ftn\" -type \"string\" (\"old/\" + \"a\\d.ma\");\r\n";
    let result = apply(input, "old/a", "asset/Example", PathReplaceMode::Literal);
    assert_eq!(result.bytes, input);
    assert_eq!(result.skipped.crosses_concat_boundary, 2);
    assert_eq!(result.skipped.total(), 2);
    let input = b"setAttr \".ftn\" -type \"string\" (\"old/\" + \"old/Example.ma\");\r\n";
    let result = apply(input, "^old/", "asset/", PathReplaceMode::Regex);
    assert_eq!(
        result.bytes,
        b"setAttr \".ftn\" -type \"string\" (\"asset/\" + \"old/Example.ma\");\r\n"
    );
    assert_eq!(result.replacement_count, 1);
    let result = apply(input, "old/", "asset/", PathReplaceMode::Literal);
    assert_eq!(result.replacement_count, 2);
    let result = apply(input, "old/", "old/", PathReplaceMode::Literal);
    assert_eq!(result.bytes, input);
    assert_eq!(result.replacement_count, 0);
    assert_eq!(result.skipped.total(), 0);
    let joined = b"setAttr \".ftn\" -type \"string\" (\"Sample\" + \"Example.ma\");\r\n";
    let result = apply(joined, r"\bExample", "TestAsset", PathReplaceMode::Regex);
    assert_eq!(result.bytes, joined);
    assert_eq!(result.replacement_count, 0);
    let result = apply(joined, r"ma$", "mb", PathReplaceMode::Regex);
    assert_eq!(
        result.bytes,
        b"setAttr \".ftn\" -type \"string\" (\"Sample\" + \"Example.mb\");\r\n"
    );
    assert_eq!(result.replacement_count, 1);
}

#[test]
fn flags_and_unrelated_attributes_are_not_paths() {
    let input = b"setAttr \".nts\" -type \"string\" \"old/Example.ma\"; setAttr \".cs\" -type \"string\" \"old/Example.ma\";\r\nfile -r -op \"old/Sample.ma\" \"old/Example.ma\" -typ \"mayaAscii\";\r\nsetAttr \".ftn\" -type \"string\" \"string\";\r\n";
    let result = apply(input, "old/", "asset/", PathReplaceMode::Literal);
    assert_eq!(result.bytes, b"setAttr \".nts\" -type \"string\" \"old/Example.ma\"; setAttr \".cs\" -type \"string\" \"old/Example.ma\";\r\nfile -r -op \"old/Sample.ma\" \"asset/Example.ma\" -typ \"mayaAscii\";\r\nsetAttr \".ftn\" -type \"string\" \"string\";\r\n");
    assert_eq!(result.replacement_count, 1);
    assert_eq!(result.skipped.total(), 0);
    let result = apply(input, "string", "Sample", PathReplaceMode::Literal);
    assert!(
        result
            .bytes
            .ends_with(b"setAttr \".ftn\" -type \"string\" \"Sample\";\r\n")
    );
    assert_eq!(result.replacement_count, 1);
}

#[test]
fn comments_and_missing_semicolons_preserve_command_boundaries() {
    let input = b"/* // \" old/Example.ma ; */ file -r \"old/Example.ma\"\r\nfile -r \"old/Sample.ma\"; // \" old/Example.ma\rsetAttr \".ftn\" -type \"string\" \"old/TestScene.ma\";\r";
    let result = apply(input, "old/", "asset/", PathReplaceMode::Literal);
    assert_eq!(result.bytes, b"/* // \" old/Example.ma ; */ file -r \"asset/Example.ma\"\r\nfile -r \"asset/Sample.ma\"; // \" old/Example.ma\rsetAttr \".ftn\" -type \"string\" \"asset/TestScene.ma\";\r");
    assert_eq!(result.replacement_count, 3);
    assert_eq!(result.skipped.total(), 0);
}

#[test]
fn indexed_replacement_rejects_duplicate_source_ranges() {
    use maya_scene_kit_formats::ma::rewrite::{
        MaPathReplaceError, replace_raw_scene_paths_in_ma_by_index,
    };
    let input = b"file -r \"old/Example.ma\";\nfile -r \"old/Example.ma\";\n";
    assert!(matches!(
        replace_raw_scene_paths_in_ma_by_index(input, &[(0, "asset/Example.ma".into())]),
        Err(MaPathReplaceError::AmbiguousEntry { entry_index: 0 })
    ));
    let input =
        b"// Codeset: 932\nfile -r \"old/\x81?Example.ma\";\nfile -r \"old/\x82?Example.ma\";\n";
    assert!(matches!(
        replace_raw_scene_paths_in_ma_by_index(input, &[(0, "asset/Example.ma".into())]),
        Err(MaPathReplaceError::AmbiguousEntry { entry_index: 0 })
    ));
    let input = b"// Codeset: 932\nfile -r \"old/\x83\x65.ma\";\nfile -r \"old/\x83\x66.ma\";\r\n";
    let result =
        replace_raw_scene_paths_in_ma_by_index(input, &[(0, "asset/Example.ma".into())]).unwrap();
    assert_eq!(
        result.bytes,
        b"// Codeset: 932\nfile -r \"asset/Example.ma\";\nfile -r \"old/\x83\x66.ma\";\r\n"
    );
    assert_eq!(result.replacement_count, 1);
}

#[test]
fn indexed_replacement_preserves_ranges_and_counts_only_selected_values() {
    use maya_scene_kit_formats::ma::{
        paths::extract_raw_scene_paths_from_ma, rewrite::replace_raw_scene_paths_in_ma_by_index,
    };
    let input = b"// Codeset: 932\ncreateNode file -n \"\x83\x65\x83\x58\x83\x67\";\n    setAttr -l on \".ftn\" -type \"string\" \"old/Example.ma\";\r\ncreateNode file -n \"Sample\";\n    setAttr \".ftn\" -type \"string\" \"old/\x81?Sample.ma\";\r\n";
    let result =
        replace_raw_scene_paths_in_ma_by_index(input, &[(0, "asset/Example.ma".into())]).unwrap();
    let expected = b"// Codeset: 932\ncreateNode file -n \"\x83\x65\x83\x58\x83\x67\";\n    setAttr -l on \".ftn\" -type \"string\" \"asset/Example.ma\";\r\ncreateNode file -n \"Sample\";\n    setAttr \".ftn\" -type \"string\" \"old/\x81?Sample.ma\";\r\n";
    assert_eq!(result.bytes, expected);
    assert_eq!(result.replacement_count, 1);
    assert_eq!(result.skipped.total(), 0);
    let entries = extract_raw_scene_paths_from_ma(input);
    let index = entries
        .iter()
        .position(|entry| entry.node_name == "Sample")
        .unwrap();
    let result =
        replace_raw_scene_paths_in_ma_by_index(input, &[(index, "asset/Sample.ma".into())])
            .unwrap();
    assert_eq!(result.bytes, input);
    assert_eq!(result.skipped.non_utf8, 1);
    assert_eq!(result.skipped.total(), 1);
}

#[test]
fn insertion_and_escape_contract_apply_once() {
    use maya_scene_kit_formats::ma::{
        rewrite::replace_raw_scene_paths_in_ma_by_index, text::escape_ma_string,
    };
    let input = b"createNode file -n \"Example\";\n    setAttr -l on \".ftn\" -type \"string\" \"old/Example.ma\";\r\n";
    for replacement in [
        "asset/\"Example\"\\Sample.ma",
        "asset/Example\nSample.ma",
        "asset/Example\r\nSample.ma",
        "asset/Example\rSample.ma",
        "asset/Example\tSample.ma",
        "asset/Example\\d.ma",
    ] {
        let expected = format!(
            "createNode file -n \"Example\";\n    setAttr -l on \".ftn\" -type \"string\" \"{}\";\r\n",
            escape_ma_string(replacement)
        );
        let rule_result = apply(
            input,
            "old/Example.ma",
            replacement,
            PathReplaceMode::Literal,
        );
        assert_eq!(rule_result.bytes, expected.as_bytes());
        let indexed =
            replace_raw_scene_paths_in_ma_by_index(input, &[(0, replacement.into())]).unwrap();
        assert_eq!(indexed.bytes, expected.as_bytes());
        assert_eq!(indexed.replacement_count, 1);
    }
    let empty = b"setAttr \".ftn\" -type \"string\" \"\";\r\n";
    let result = apply(empty, "^$", "asset/Example.ma", PathReplaceMode::Regex);
    assert_eq!(
        result.bytes,
        b"setAttr \".ftn\" -type \"string\" \"asset/Example.ma\";\r\n"
    );
    assert_eq!(result.replacement_count, 1);
}

#[test]
fn malformed_file_and_setattr_tails_are_reported_once() {
    use maya_scene_kit_formats::ma::rewrite::replace_raw_scene_paths_in_ma_by_index;
    for tail in [
        b"file -r -ns \"old/Example.ma\" \"unfinished".as_slice(),
        b"file -r \"unfinished\\",
        b"setAttr \".ftn\" -type \"string\" \"unfinished",
        b"setAttr \".ftn\" -type \"string\" \"unfinished\\",
    ] {
        let prefix = b"file -r \"old/Sample.ma\";\r\n";
        let input = [prefix.as_slice(), tail].concat();
        let result = apply(&input, "old/", "asset/", PathReplaceMode::Literal);
        assert_eq!(
            result.bytes,
            [b"file -r \"asset/Sample.ma\";\r\n".as_slice(), tail].concat()
        );
        assert_eq!(result.skipped.unterminated_tail, 1);
        assert_eq!(result.skipped.unterminated_tail_from, Some(prefix.len()));
        assert_eq!(result.skipped.total(), 1);
        let result =
            replace_raw_scene_paths_in_ma_by_index(&input, &[(0, "asset/Sample.ma".into())])
                .unwrap();
        assert_eq!(
            result.bytes,
            [b"file -r \"asset/Sample.ma\";\r\n".as_slice(), tail].concat()
        );
        assert_eq!(result.skipped.unterminated_tail_from, Some(prefix.len()));
    }
}

#[test]
fn existing_scenes_keep_all_original_bytes() {
    use maya_scene_kit_formats::ma::{
        paths::extract_raw_scene_paths_from_ma, text::escape_ma_string,
    };
    for fixture in [
        "tests/01/skin.ma",
        "tests/02/sphere.ma",
        "tests/fixtures/ma/opaque_typed_attrs.ma",
        "tests/fixtures/mb/owner_delete/connected_file_owner_delete.ma",
        "tests/fixtures/mb/owner_delete/file_owner_delete.ma",
        "tests/fixtures/refedit/sanitized/case_empty_root_ed_block06.ma",
        "tests/fixtures/refedit/sanitized/case_mixed_op2_op0_ed_block02.ma",
        "tests/fixtures/refedit/sanitized/case_op0_flag_payload_ed_block02.ma",
        "tests/fixtures/refedit/sanitized/case_op3_empty_tail_ed_block01.ma",
        "tests/fixtures/refedit/sanitized/case_op5_placeholder_ed_block01.ma",
        "tests/fixtures/semantic/custom_unknown_node.ma",
        "tests/fixtures/semantic/formatting_distorted_script.ma",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(fixture);
        let source = std::fs::read(path).unwrap();
        let result = apply(
            &source,
            "asset/example/Absent",
            "asset/example/Sample",
            PathReplaceMode::Literal,
        );
        assert_eq!(result.bytes, source, "{fixture}");
        assert_eq!(result.replacement_count, 0);
        let unique = extract_raw_scene_paths_from_ma(&source)
            .into_iter()
            .find_map(|entry| {
                let literal = format!("\"{}\"", escape_ma_string(&entry.value));
                let offsets: Vec<_> = source
                    .windows(literal.len())
                    .enumerate()
                    .filter_map(|(offset, window)| (window == literal.as_bytes()).then_some(offset))
                    .collect();
                if offsets.len() != 1 {
                    return None;
                }
                Some((entry.value, offsets[0] + 1..offsets[0] + literal.len() - 1))
            });
        if let Some((before, range)) = unique {
            let rule = format!("^{}$", regex::escape(&before));
            let result = apply(
                &source,
                &rule,
                "asset/example/Sample.ma",
                PathReplaceMode::Regex,
            );
            let mut expected = source.clone();
            expected.splice(range, b"asset/example/Sample.ma".iter().copied());
            assert_eq!(result.bytes, expected, "{fixture}");
            assert_eq!(result.replacement_count, 1, "{fixture}");
        } else {
            let input = [
                source.as_slice(),
                b"\nfile -r \"asset/example/Example.ma\";\r\n",
            ]
            .concat();
            let result = apply(
                &input,
                "asset/example/Example.ma",
                "asset/example/Sample.ma",
                PathReplaceMode::Literal,
            );
            assert_eq!(
                result.bytes,
                [
                    source.as_slice(),
                    b"\nfile -r \"asset/example/Sample.ma\";\r\n"
                ]
                .concat(),
                "{fixture}"
            );
            assert_eq!(result.replacement_count, 1, "{fixture}");
        }
    }
}

#[test]
fn replacement_aliases_are_specific_to_cp932() {
    let input = b"file -r \"old/Example.ma\";\n";
    let result = apply(input, "old/", "asset/¥‾/", PathReplaceMode::Literal);
    assert_eq!(
        result.bytes,
        "file -r \"asset/¥‾/Example.ma\";\n".as_bytes()
    );
    let declared = [b"// Codeset: 932\n// \x83\x65\n".as_slice(), input].concat();
    let result = apply(&declared, "old/", "asset/¥‾/", PathReplaceMode::Literal);
    assert_eq!(
        result.bytes,
        b"// Codeset: 932\n// \x83\x65\nfile -r \"asset/\\\\~/Example.ma\";\n"
    );
}

#[test]
fn unmatched_index_is_an_error_instead_of_a_silent_noop() {
    use maya_scene_kit_formats::ma::rewrite::replace_raw_scene_paths_in_ma_by_index;
    let input = b"file -r \"old/Example.ma\";\n";
    assert!(
        replace_raw_scene_paths_in_ma_by_index(input, &[(99, "asset/Example.ma".into())]).is_err()
    );
    let input = b"createNode file;\r    setAttr \".ftn\" -type \"string\" \"old/Example.ma\";\r";
    if let Ok(result) =
        replace_raw_scene_paths_in_ma_by_index(input, &[(0, "asset/Example.ma".into())])
    {
        assert!(result.replacement_count > 0 || result.skipped.total() > 0)
    }
}

#[test]
fn invalid_trail_does_not_consume_a_closing_quote() {
    for header in [b"// Codeset: 932\n", b"// Codeset: 936\n"] {
        let input = [
            header.as_slice(),
            b"setAttr \".ftn\" -type \"string\" \"old/Example\x83\";\nfile -r \"old/Sample.ma\";\n",
        ]
        .concat();
        let expected = [
            header.as_slice(),
            b"setAttr \".ftn\" -type \"string\" \"old/Example\x83\";\nfile -r \"asset/Sample.ma\";\n",
        ]
        .concat();
        let result = apply(&input, "old/", "asset/", PathReplaceMode::Literal);
        assert_eq!(result.bytes, expected);
        assert_eq!(result.skipped.non_utf8, 1);
        assert_eq!(result.skipped.unterminated_tail, 0);
        assert_eq!(result.replacement_count, 1);
    }
}

#[test]
fn undeclared_halfwidth_kana_before_quote_keeps_command_boundaries() {
    let input = b"// Example\nfile -r -ns \"\xb1\" \"old/Example.ma\";\n";
    let result = apply(input, "old/", "asset/", PathReplaceMode::Literal);
    assert_eq!(
        result.bytes,
        b"// Example\nfile -r -ns \"\xb1\" \"asset/Example.ma\";\n"
    );
    assert_eq!(result.replacement_count, 1);
}

#[test]
fn codeset_text_outside_header_cannot_suppress_ambiguity() {
    use maya_scene_kit_formats::ma::rewrite::MaPathReplaceError;
    for tail in [
        b"file -r \"old/Codeset: 936/Sample.ma\";\n".as_slice(),
        b"// Codeset: 936\n",
    ] {
        let input = [b"file -r \"old/\xa1\\\";\n".as_slice(), tail].concat();
        let result = replace_raw_scene_paths_in_ma(
            &input,
            &[PathReplaceRule {
                from: "old/".into(),
                to: "asset/".into(),
                mode: PathReplaceMode::Literal,
            }],
        );
        assert!(matches!(result, Err(MaPathReplaceError::AmbiguousEncoding)));
    }
}

#[test]
fn invalid_regex_is_rejected_and_empty_patterns_do_not_scan() {
    let input = b"// Codeset: 932\n// \x83\x65\nfile -r \"old/\x81?Example.ma\";\n";
    let result = replace_raw_scene_paths_in_ma(
        input,
        &[PathReplaceRule {
            from: "[".into(),
            to: "asset/".into(),
            mode: PathReplaceMode::Regex,
        }],
    );
    assert!(result.is_err());
    let result = apply(input, "", "asset/", PathReplaceMode::Literal);
    assert_eq!(result.bytes, input);
    assert_eq!(result.skipped.total(), 0);
}

#[test]
fn repeated_crossing_rules_count_each_literal_once() {
    let input = b"setAttr \".ftn\" -type \"string\" (\"old/\" + \"Example.ma\");\n";
    let rules = (0..3)
        .map(|_| PathReplaceRule {
            from: "old/Example".into(),
            to: "asset/Sample".into(),
            mode: PathReplaceMode::Literal,
        })
        .collect::<Vec<_>>();
    let result = replace_raw_scene_paths_in_ma(input, &rules).unwrap();
    assert_eq!(result.bytes, input);
    assert_eq!(result.skipped.crosses_concat_boundary, 2);
    assert_eq!(result.skipped.total(), 2);
}

#[test]
fn missing_semicolon_ends_at_top_level_block_comment() {
    let input = b"//Maya ASCII 2026 scene\nfile -r \"old/Example.ma\"\n/* Sample */\nfile -r \"old/Sample.ma\";\n";
    let result = apply(input, "old/", "asset/", PathReplaceMode::Literal);
    assert_eq!(result.bytes, b"//Maya ASCII 2026 scene\nfile -r \"asset/Example.ma\"\n/* Sample */\nfile -r \"asset/Sample.ma\";\n");
    assert_eq!(result.replacement_count, 2);
}

#[test]
fn cr_line_ends_and_indented_continuations_preserve_ranges() {
    let input = b"file -r \"old/Example.ma\"\rfile -r \"old/Sample.ma\";\rsetAttr \".ftn\" -type \"string\"\r    \"old/TestScene.ma\";\r";
    let result = apply(input, "old/", "asset/", PathReplaceMode::Literal);
    assert_eq!(result.bytes, b"file -r \"asset/Example.ma\"\rfile -r \"asset/Sample.ma\";\rsetAttr \".ftn\" -type \"string\"\r    \"asset/TestScene.ma\";\r");
    assert_eq!(result.replacement_count, 3);
}

#[test]
fn regex_matches_replace_all_and_chains_rules_on_literal_bytes() {
    let input = b"setAttr \".ftn\" -type \"string\" \"old/Example.ma\";\n";
    for pattern in [".*", ".+|$", "^|$", "old/|$"] {
        let expected = regex::Regex::new(pattern)
            .unwrap()
            .replace_all("old/Example.ma", "asset/Sample.ma")
            .into_owned();
        let result = apply(input, pattern, "asset/Sample.ma", PathReplaceMode::Regex);
        assert_eq!(
            result.bytes,
            format!("setAttr \".ftn\" -type \"string\" \"{expected}\";\n").as_bytes(),
            "{pattern}"
        );
    }
    let result = replace_raw_scene_paths_in_ma(
        input,
        &[
            PathReplaceRule {
                from: "old/".into(),
                to: "mid/".into(),
                mode: PathReplaceMode::Literal,
            },
            PathReplaceRule {
                from: "mid/(.+)".into(),
                to: "asset/$1".into(),
                mode: PathReplaceMode::Regex,
            },
        ],
    )
    .unwrap();
    assert_eq!(
        result.bytes,
        b"setAttr \".ftn\" -type \"string\" \"asset/Example.ma\";\n"
    );
    assert_eq!(result.replacement_count, 1);
}

#[test]
fn duplicate_index_requests_are_rejected() {
    use maya_scene_kit_formats::ma::rewrite::replace_raw_scene_paths_in_ma_by_index;
    let input = b"file -r \"old/Example.ma\";\n";
    assert!(
        replace_raw_scene_paths_in_ma_by_index(
            input,
            &[
                (0, "asset/Example.ma".into()),
                (0, "asset/Sample.ma".into())
            ]
        )
        .is_err()
    );
}

#[test]
fn empty_patterns_return_without_encoding_skips() {
    let input = b"// Codeset: 932\nfile -r \"old/\x81?Example.ma\";\n";
    let result = apply(input, "", "asset/", PathReplaceMode::Literal);
    assert_eq!(result.skipped.total(), 0);
    assert_eq!(result.bytes, input);
}

#[test]
fn column_zero_block_comment_resynchronizes_before_same_line_command() {
    let input = b"file -r \"old/Example.ma\"\n/* Sample */ file -r \"old/Sample.ma\";\n";
    let result = apply(input, "old/", "asset/", PathReplaceMode::Literal);
    assert_eq!(
        result.bytes,
        b"file -r \"asset/Example.ma\"\n/* Sample */ file -r \"asset/Sample.ma\";\n"
    );
    assert_eq!(result.replacement_count, 2);
}
