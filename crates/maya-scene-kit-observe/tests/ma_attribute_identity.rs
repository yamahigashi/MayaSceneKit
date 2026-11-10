use std::path::Path;

use maya_scene_kit_observe::scene::{
    LoadOptions, Loader,
    core::{SceneFormat, ValidationState},
    execution::ObservedExecutionCatalog,
};

fn catalog(input: &str) -> ObservedExecutionCatalog {
    Loader::new(LoadOptions::default())
        .observe_analysis_bytes(
            Path::new("Example.ma"),
            SceneFormat::Ma,
            ValidationState::Validated,
            input.as_bytes().to_vec(),
        )
        .unwrap()
        .observed_execution_catalog(8)
        .unwrap()
}

#[test]
fn alias_histories_share_effective_context_and_surface_identity() {
    for (a, b, canonical) in [
        (".b", ".before", ".b"),
        (".before", ".b", ".b"),
        (".a", ".after", ".a"),
        (".after", ".a", ".a"),
        ("Example.b", ".before", ".b"),
        (".before", "Example.b", ".b"),
    ] {
        for (numeric, language, trigger) in [
            (
                "setAttr \".st\" 0; setAttr \".scriptType\" 1; setAttr \".stp\" 0; setAttr \".sourceType\" 1;",
                "python",
                "file_open",
            ),
            (
                "setAttr \".scriptType\" 1; setAttr \"Example.st\" 0; setAttr \".sourceType\" 1; setAttr \"Example.stp\" 0;",
                "mel",
                "manual",
            ),
        ] {
            let input = format!(
                "createNode script -n Example; setAttr \"{a}\" -type \"string\" \"print('Example')\"; setAttr \"{b}\" -type \"string\" \"print('Sample')\"; {numeric}"
            );
            let result = catalog(&input);
            assert_eq!(result.surfaces.len(), 2, "{input}");
            for (index, entry) in result.surfaces.iter().enumerate() {
                let origin = &entry.surface.origin;
                assert_eq!(origin.attr_name.as_deref(), Some(canonical));
                assert_eq!(origin.overwritten, index == 0);
                assert_eq!(origin.assignment_index, (index == 0).then_some(index));
                assert_eq!(origin.lang.as_str(), language);
                assert_eq!(origin.trigger.as_str(), trigger);
            }
        }
    }
}

#[test]
fn default_callback_aliases_are_canonical_and_not_duplicated() {
    for assignment in [
        "setAttr \"defaultRenderGlobals.preRenderMel\" -type \"string\" \"print 1;\";",
        "select -ne :defaultRenderGlobals; setAttr \".preRenderMel\" -type \"string\" \"print 1;\";",
    ] {
        let result = catalog(assignment);
        assert_eq!(result.surfaces.len(), 1);
        let origin = &result.surfaces[0].surface.origin;
        assert_eq!(origin.node_name.as_deref(), Some("defaultRenderGlobals"));
        assert_eq!(origin.attr_name.as_deref(), Some(".prm"));
    }
}

#[test]
fn unreadable_alias_values_keep_body_and_context_issues_separate() {
    let result = catalog(
        "createNode script -n Example; setAttr \".before\" 1; setAttr \".after\" -type \"string\"; setAttr \".scriptType\" Sample; setAttr \".sourceType\" Sample;",
    );
    assert!(result.surfaces.is_empty());
    assert_eq!(result.coverage_issues.len(), 3);
}

#[test]
fn unknown_forward_and_dynamic_rename_owners_fail_closed() {
    let input = "setAttr \"Example.before\" -type \"string\" \"print 1;\"; createNode script -n Example; setAttr \".before\" -type \"string\" \"print 2;\"; rename Example $Sample; setAttr \"Example.before\" -type \"string\" \"print 3;\"; setAttr \"Sample.prm\" -type \"string\" \"print 4;\";";
    let result = catalog(input);
    assert_eq!(result.surfaces.len(), 1);
    assert_eq!(
        result.surfaces[0].surface.origin.attr_name.as_deref(),
        Some(".b")
    );
    assert_eq!(result.coverage_issues.len(), 4);
    let selectors = std::collections::HashSet::from([
        maya_scene_kit_formats::ma::raw_dump::RawMaNodeAttrSelector {
            node_type: String::new(),
            node_name: None,
            attr: ".prm".into(),
            canonical_attr: ".prm".into(),
        },
    ]);
    let raw = maya_scene_kit_formats::ma::selective::extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(
        input.as_bytes(), &maya_scene_kit_formats::mel::MelParseBudget::default(), &selectors,
    );
    let mut actual: Vec<_> = raw
        .audit_top_level
        .diagnostics
        .iter()
        .map(|issue| issue.span.start)
        .collect();
    actual.sort_unstable();
    let expected = vec![
        0,
        input.find("rename").unwrap(),
        input.rfind("setAttr \"Example.before").unwrap(),
        input.find("setAttr \"Sample.prm").unwrap(),
    ];
    assert_eq!(actual, expected);
}

#[test]
fn expression_aliases_keep_short_profile_origins() {
    for (alias, canonical) in [("expression", ".e"), ("internalExpression", ".ixp")] {
        let result = catalog(&format!(
            "createNode expression -n Example; setAttr \".{alias}\" -type \"string\" \"print 1;\";"
        ));
        assert_eq!(result.surfaces.len(), 1);
        let origin = &result.surfaces[0].surface.origin;
        assert_eq!(origin.attr_name.as_deref(), Some(canonical));
        assert_eq!(origin.lang.as_str(), "mel");
        assert_eq!(origin.trigger.as_str(), "time_changed");
    }
}

#[test]
fn empty_alias_assignment_overwrites_without_adding_a_surface() {
    let result = catalog(
        "createNode script -n Example; setAttr \".b\" -type \"string\" \"print 1;\"; setAttr \"Example.before\" -type \"string\" \"\"; setAttr \".after\" -lock on;",
    );
    assert_eq!(result.surfaces.len(), 1);
    assert!(result.surfaces[0].surface.origin.overwritten);
    assert_eq!(result.surfaces[0].surface.origin.assignment_index, Some(0));
    assert!(result.coverage_issues.is_empty());
}

#[test]
fn unreadable_final_numeric_aliases_make_body_context_unknown() {
    let result = catalog(
        "createNode script -n Example; setAttr \".before\" -type \"string\" \"print 1;\"; setAttr \".st\" 1; setAttr \"Example.scriptType\" Sample; setAttr \".stp\" 1; setAttr \"Example.sourceType\" Sample;",
    );
    assert_eq!(result.surfaces.len(), 1);
    let origin = &result.surfaces[0].surface.origin;
    assert_eq!(origin.trigger.as_str(), "unknown");
    assert_eq!(origin.lang.as_str(), "unknown");
    assert_eq!(result.coverage_issues.len(), 1);
}

#[test]
fn word_based_string_assignment_forms_preserve_bodies() {
    let mut failures = Vec::new();
    for (node_type, attr) in [("script", ".b"), ("expression", ".ixp")] {
        for statement in [
            format!("setAttr \"{attr}\" -typ \"string\" \"print 1;\";"),
            format!("setAttr \"{attr}\" -type  \"string\" \"print 1;\";"),
            format!("setAttr\t\"{attr}\" -type \"string\" \"print 1;\";"),
            format!("setAttr -type \"string\" \"{attr}\" \"print 1;\";"),
            format!("setAttr \"{attr}\" \"print 1;\" -type \"string\";"),
            format!("setAttr\n \"{attr}\"\n -type \"string\"\n \"print 1;\";"),
        ] {
            let result = catalog(&format!("createNode {node_type} -n Example; {statement}"));
            if result.surfaces.len() != 1 || result.surfaces[0].surface.text.as_ref() != "print 1;"
            {
                failures.push((node_type, statement));
            }
        }
    }
    assert!(failures.is_empty(), "unreadable assignments: {failures:?}");
}

#[test]
fn unreadable_callback_aliases_retain_positioned_coverage() {
    for input in [
        "createNode expression -n Example; setAttr \".internalExpression\" 1;",
        "setAttr \"defaultRenderGlobals.preRenderMel\" 1;",
        "createNode expression -n Example; setAttr \".internalExpression\" -type \"string\" Sample;",
    ] {
        let result = catalog(input);
        assert!(result.surfaces.is_empty());
        assert_eq!(result.coverage_issues.len(), 1, "{input}");
        let origin = result.coverage_issues[0].origin.as_ref().unwrap();
        let span = origin.source_range.as_ref().unwrap();
        assert_eq!(
            &input[span.start..span.end],
            &input[input.find("setAttr").unwrap()..]
        );
    }
}

#[test]
fn default_callbacks_survive_invalidated_and_colliding_names() {
    let mut failures = Vec::new();
    for prefix in [
        "rename $Sample Example; select -ne :defaultRenderGlobals;",
        "rename defaultRenderGlobals Example; select -ne :defaultRenderGlobals;",
        "createNode transform -n Example; rename Example defaultRenderGlobals; select -ne :defaultRenderGlobals;",
    ] {
        let result = catalog(&format!(
            "{prefix} setAttr \".preRenderMel\" -type \"string\" \"print 1;\";"
        ));
        if result.surfaces.len() != 1
            || result.surfaces[0].surface.origin.attr_name.as_deref() != Some(".prm")
        {
            failures.push(prefix);
        }
    }
    let result = catalog(
        "rename $Sample Example; setAttr \"defaultRenderGlobals.prm\" -type \"string\" \"print 1;\";",
    );
    if result.surfaces.len() != 1 {
        failures.push("absolute defaultRenderGlobals.prm after dynamic rename");
    }
    assert!(failures.is_empty(), "lost callbacks: {failures:?}");
}

#[test]
fn uppercase_aliases_do_not_create_surfaces() {
    let result = catalog(
        "createNode script -n Example; setAttr \".BEFORE\" -type \"string\" \"Sample\"; createNode expression -n Sample; setAttr \".INTERNALEXPRESSION\" -type \"string\" \"Sample\";",
    );
    assert!(result.surfaces.is_empty());
    assert!(result.coverage_issues.is_empty());
}
