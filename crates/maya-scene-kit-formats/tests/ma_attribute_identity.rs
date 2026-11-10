use maya_scene_kit_formats::ma::selective::extract_raw_selective_sections_from_ma;

#[test]
fn script_aliases_and_absolute_plugs_share_ordered_assignments() {
    for name in ["Example", "\"Example\"", ":Example", "\":Example\""] {
        let input = format!(
            "createNode script -n {name}; setAttr \":Example.before\" -type \"string\" \"Sample\";"
        );
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(result.dump_sections.script_entries.len(), 1);
        assert_eq!(result.dump_sections.script_entries[0].body(), "Sample");
        assert!(result.audit_top_level.diagnostics.is_empty());
    }

    let mut failures = Vec::new();
    for (first, second) in [
        (".b", ".before"),
        (".before", ".b"),
        (".a", ".after"),
        (".after", ".a"),
        ("Example.b", ".before"),
        (".before", "Example.b"),
    ] {
        for separator in [" ", "\t"] {
            for flag in ["-type ", "-type  ", "-typ "] {
                let input = format!(
                    "createNode script -n Example; setAttr{separator}\"{first}\" {flag}\"string\" \"Sample\"; setAttr \"{second}\" -type \"string\" \"Example\"; setAttr \".scriptType\" 0; setAttr \"Example.st\" 1; setAttr \".sourceType\" 0; setAttr \"Example.stp\" 1;"
                );
                let result = extract_raw_selective_sections_from_ma(input.as_bytes());
                let entry = &result.dump_sections.script_entries[0];
                if entry.assignments.len() != 6
                    || entry.script_type() != Some(1)
                    || entry.source_type() != Some(1)
                    || !result.audit_top_level.diagnostics.is_empty()
                {
                    failures.push(input);
                }
            }
        }
    }
    assert!(failures.is_empty(), "failed inputs: {failures:#?}");
}

#[test]
fn duplicate_names_keep_first_absolute_owner_and_separate_relative_owner() {
    let result = extract_raw_selective_sections_from_ma(b"createNode script -n Example; setAttr \".b\" -type \"string\" \"Example\"; createNode script -n Example; setAttr \".b\" -type \"string\" \"Sample\"; setAttr \"Example.before\" -type \"string\" \"TestScene\"; select -ne Example; setAttr \".after\" -type \"string\" \"TestAsset\";");
    let entries = &result.dump_sections.script_entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].assignments.len(), 3);
    assert_eq!(entries[0].body(), "TestScene");
    assert_eq!(entries[1].body(), "Sample");
}

#[test]
fn unselected_scripts_keep_entries_and_absolute_assignments() {
    let mut failures = Vec::new();
    for (input, body) in [
        ("createNode script -ss -n Example;", ""),
        (
            "createNode script -ss -n Example; setAttr \"Example.before\" -type \"string\" \"Sample\";",
            "Sample",
        ),
    ] {
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        let entries = &result.dump_sections.script_entries;
        if entries.len() != 1 || entries[0].name != "Example" || entries[0].body() != body {
            failures.push(input);
        }
    }
    assert!(
        failures.is_empty(),
        "missing entries or assignments: {failures:?}"
    );
}

#[test]
fn absolute_assignments_preserve_selection_and_rename_order() {
    let input = b"createNode script -n Example; setAttr \".before\" -type \"string\" \"Example\"; createNode script -n Sample; setAttr \"Example.b\" -type \"string\" \"Sample\"; setAttr \".b\" -type \"string\" \"TestAsset\"; rename Example TestScene; setAttr \"TestScene.before\" -type \"string\" \"TestScene\";";
    let result = extract_raw_selective_sections_from_ma(input);
    let entries = &result.dump_sections.script_entries;
    assert_eq!(entries[0].name, "TestScene");
    assert_eq!(entries[0].assignments.len(), 3);
    assert!(
        entries[0]
            .assignments
            .windows(2)
            .all(|a| a[0].start < a[1].start)
    );
    assert_eq!(entries[0].body(), "TestScene");
    assert_eq!(entries[1].body(), "TestAsset");
}

#[test]
fn compound_and_indexed_execution_plugs_are_diagnosed() {
    for owner in ["Example:Sample", "|Example|Sample"] {
        let input = format!(
            "createNode script -n Sample; setAttr \"{owner}.before\" -type \"string\" \"Example\";"
        );
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(result.audit_top_level.diagnostics.len(), 1);
        let span = result.audit_top_level.diagnostics[0].span;
        assert_eq!(span.start, input.find("setAttr").unwrap());
        assert_eq!(span.end, input.len());
        assert!(
            result.dump_sections.script_entries[0]
                .assignments
                .is_empty()
        );
    }

    let mut failures = Vec::new();
    for plug in [
        "Example.items[0].before",
        "Example.b[0]",
        ".items[0].before",
        ".b[0]",
    ] {
        let input = format!(
            "createNode script -n Example; setAttr \"{plug}\" -type \"string\" \"Sample\";"
        );
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        if result.audit_top_level.diagnostics.len() != 1
            || result.audit_top_level.diagnostics[0].span.start != input.find("setAttr").unwrap()
            || result.audit_top_level.diagnostics[0].span.end != input.len()
            || !result.dump_sections.script_entries[0]
                .assignments
                .is_empty()
        {
            failures.push(plug);
        }
    }
    assert!(failures.is_empty(), "unsupported plugs: {failures:?}");
}

#[test]
fn unreadable_aliases_and_missing_typed_values_remain_assignments() {
    for body in [
        "print(\"Example; Sample\")".to_string(),
        "Example ".repeat(600),
    ] {
        let escaped = body.replace('\\', "\\\\").replace('"', "\\\"");
        let input = format!(
            "createNode script -n Example; setAttr\n \".before\"\n -type \"string\"\n \"{escaped}\";"
        );
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(result.dump_sections.script_entries[0].body(), body);
        assert_eq!(result.dump_sections.script_entries[0].assignments.len(), 1);
        let assignment = &result.dump_sections.script_entries[0].assignments[0];
        assert_eq!(assignment.start, input.find("setAttr").unwrap());
        assert_eq!(assignment.end, input.len());
    }
    let values = "Sample ".repeat(80);
    let input =
        format!("createNode script -n Example; setAttr \".before\" -type \"string\" {values};");
    let result = extract_raw_selective_sections_from_ma(input.as_bytes());
    assert_eq!(result.dump_sections.script_entries[0].assignments.len(), 1);
    assert_eq!(
        result.dump_sections.script_entries[0].assignments[0].string_value,
        None
    );

    let result = extract_raw_selective_sections_from_ma(b"createNode script -n Example; setAttr \".before\" -type \"string\"; setAttr \".sourceType\" Sample; setAttr \".scriptType\" Sample; setAttr \".after\" -lock on; setAttr \".before\" -type \"string\" \"\";");
    let entry = &result.dump_sections.script_entries[0];
    assert_eq!(entry.assignments.len(), 4);
    assert_eq!(entry.assignments[0].string_value, None);
    assert_eq!(entry.assignments[1].attr, ".stp");
    assert_eq!(entry.assignments[2].attr, ".st");
    assert_eq!(entry.assignments[3].string_value.as_deref(), Some(""));
}

#[test]
fn dynamic_rename_invalidates_possible_previous_owners() {
    for old in ["$Sample", "\x60print \"Sample\"\x60"] {
        let input = format!(
            "createNode script -n Example; setAttr \".b\" -type \"string\" \"Example\"; rename {old} TestAsset; setAttr \"Example.before\" -type \"string\" \"Sample\";"
        );
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(result.dump_sections.script_entries[0].assignments.len(), 1);
        assert!(
            result
                .audit_top_level
                .diagnostics
                .iter()
                .any(|issue| issue.message.contains("dynamic rename")),
            "{old}"
        );
        assert!(
            result
                .audit_top_level
                .diagnostics
                .iter()
                .any(|issue| issue.message.contains("absolute execution attribute"))
        );
    }
}

#[test]
fn duplicate_relative_owner_survives_renaming_first_owner() {
    let result = extract_raw_selective_sections_from_ma(b"createNode script -n Example; setAttr \".b\" -type \"string\" \"Example\"; createNode script -n Example; setAttr \".b\" -type \"string\" \"Sample\"; rename Example TestScene; setAttr \".a\" -type \"string\" \"TestAsset\"; setAttr \"TestScene.before\" -type \"string\" \"TestScene\";");
    let entries = &result.dump_sections.script_entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "TestScene");
    assert_eq!(entries[0].body(), "TestScene");
    assert_eq!(entries[0].assignments.len(), 2);
    assert_eq!(entries[1].name, "Example");
    assert_eq!(entries[1].body(), "Sample");
    assert_eq!(entries[1].assignments.len(), 2);
    assert_eq!(entries[1].assignments[1].attr, ".a");
}

#[test]
fn rename_collision_preserves_distinct_histories() {
    let input = b"createNode script -n Example; setAttr \".b\" -type \"string\" \"Example\"; setAttr \".stp\" 1; createNode script -n Sample; setAttr \".stp\" 0; rename Sample Example; setAttr \".a\" -type \"string\" \"Sample\"; select -ne Example; setAttr \".st\" 1;";
    let result = extract_raw_selective_sections_from_ma(input);
    let entries = &result.dump_sections.script_entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].assignments.len(), 3);
    assert_eq!(entries[0].source_type(), Some(1));
    assert_eq!(entries[1].assignments.len(), 2);
    assert_eq!(entries[1].source_type(), Some(0));
}

#[test]
fn dynamic_plug_concatenations_fail_closed() {
    for plug in [
        "(\".\" + \"b\")",
        "(\"Example\" + \".b\")",
        "$Sample",
        "(getAttr(\"Example.b\"))",
    ] {
        let input =
            format!("createNode script -n Example; setAttr {plug} -type \"string\" \"Sample\";");
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(result.audit_top_level.diagnostics.len(), 1, "{plug}");
        assert_eq!(
            result.audit_top_level.diagnostics[0].span.start,
            input.find("setAttr").unwrap()
        );
        assert!(
            result.dump_sections.script_entries[0]
                .assignments
                .is_empty()
        );
    }
}

#[test]
fn unrelated_attributes_do_not_report_execution_coverage() {
    for input in [
        "createNode transform -n Example; createNode mesh -n Sample; select Example Sample; setAttr \".items[0].b\" 1;",
        "createNode transform -n Example; setAttr \".items[0].b\" 1;",
        "createNode mesh -n Example; setAttr \".items[0].before\" 1;",
        "select -ne :time1 :initialShadingGroup; setAttr \".o\" 1;",
        "select -cl; setAttr \".o\" 1;",
        "createNode script -n uiConfigurationScriptNode; setAttr \".b\" -type \"string\" \"\"; rename -uid \"Example\";",
        "createNode script -n sceneConfigurationScriptNode; setAttr \".b\" -type \"string\" \"\";",
        "select -ne :defaultRenderGlobals; setAttr \".ren\" -type \"string\" \"Example\";",
    ] {
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert!(result.audit_top_level.diagnostics.is_empty(), "{input}");
        assert!(result.node_attr_values.is_empty());
    }
}

#[test]
fn absolute_and_script_paths_do_not_expand_scene_path_collection() {
    for input in [
        "createNode file -n Example; setAttr \"Example.ftn\" -type \"string\" \"asset/example/file.fbx\";",
        "createNode script -n Example; setAttr \".ftn\" -type \"string\" \"asset/example/file.fbx\";",
    ] {
        let result = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert!(result.scene_paths.is_empty(), "{input}");
    }
}

#[test]
fn unterminated_assignment_reports_only_lexical_failure() {
    let input = "select -ne Example; setAttr \".b\" 1; setAttr \"Sample.b\" 1; setAttr \".b\" 1;";
    let result = extract_raw_selective_sections_from_ma(input.as_bytes());
    assert_eq!(result.audit_top_level.diagnostics.len(), 2);
    assert_eq!(
        result.audit_top_level.diagnostics[0].span.start,
        input.find("setAttr").unwrap()
    );
    assert_eq!(
        result.audit_top_level.diagnostics[1].span.start,
        input.find("setAttr \"Sample.b\"").unwrap()
    );

    let result =
        extract_raw_selective_sections_from_ma(b"setAttr \"Example.b\" -type \"string\" \"Sample");
    assert_eq!(
        result.audit_top_level.diagnostics.len(),
        1,
        "{:?}",
        result.audit_top_level.diagnostics
    );
    assert!(
        result.audit_top_level.diagnostics[0]
            .message
            .contains("unterminated")
    );
}
