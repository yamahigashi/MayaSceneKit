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
const SOURCE: &str = "createNode transform -n ExampleSource; setAttr \".note\" -type \"string\" \"print('Example')\";";
const SCRIPT: &str = "createNode script -n ExampleScript; setAttr \".st\" 1; setAttr \".stp\" 1;";

#[test]
fn connection_flags_and_provenance() {
    let inferred = catalog(&format!(
        "createNode transform -n ExampleSource; setAttr \".note\" \"print('Example')\"; {SCRIPT} connectAttr ExampleSource.note ExampleScript.b;"
    ));
    assert_eq!(inferred.surfaces.len(), 1);
    assert!(inferred.coverage_issues.is_empty());
    for flags in ["", "-na", "-f", "-l off", "-rd Example.note"] {
        let input = format!(
            "{SOURCE}{SCRIPT} connectAttr ExampleSource.note ExampleScript.before {flags};"
        );
        let result = catalog(&input);
        assert_eq!(result.surfaces.len(), 1, "{flags}");
        let origin = &result.surfaces[0].surface.origin;
        assert_eq!(origin.attr_name.as_deref(), Some(".b"));
        assert_eq!(origin.lang.as_str(), "python");
        assert_eq!(origin.trigger.as_str(), "file_open");
        let value = serde_json::to_value(origin).unwrap();
        assert_eq!(value["connection_source_plug"], "ExampleSource.note");
        assert_eq!(
            value["connection_range"]["start"],
            input.find("connectAttr").unwrap()
        );
        assert!(result.coverage_issues.is_empty());
    }
}

#[test]
fn connection_histories_preserve_empty_repeated_and_direct_bodies() {
    let empty = catalog(&format!(
        "createNode transform -n ExampleSource; setAttr \".note\" -type string \"\"; {SCRIPT} connectAttr ExampleSource.note ExampleScript.b;"
    ));
    assert!(empty.surfaces.is_empty());
    assert!(empty.coverage_issues.is_empty());

    for final_value in ["print('Sample')", "print('Example')", ""] {
        let input = format!(
            "{SOURCE}{SCRIPT} setAttr \".b\" -type \"string\" \"print('TestScene')\"; connectAttr ExampleSource.note ExampleScript.b; setAttr \"ExampleSource.note\" -type \"string\" \"{final_value}\";"
        );
        let result = catalog(&input);
        assert_eq!(
            result.surfaces.len(),
            if final_value.is_empty() { 2 } else { 3 }
        );
        let direct = serde_json::to_value(&result.surfaces[0].surface.origin).unwrap();
        assert_eq!(direct["overwritten_by_connection"], true);
        assert!(result.surfaces[1].surface.origin.overwritten);
        assert_eq!(result.surfaces[1].surface.text.as_ref(), "print('Example')");
    }
}

#[test]
fn unresolved_and_multihop_sources_are_positioned_issues() {
    for source in [
        "Sample.note",
        "ExampleSource.missing",
        "ExampleSource.note[0]",
        "ExampleSource.compound.note",
        "|ExampleSource.note",
    ] {
        let input = format!("{SOURCE}{SCRIPT} connectAttr \"{source}\" ExampleScript.b;");
        let result = catalog(&input);
        assert_connection_issue(
            &input,
            input.find("connectAttr").unwrap(),
            "connection source",
        );
        assert_eq!(
            result
                .coverage_issues
                .last()
                .unwrap()
                .origin
                .as_ref()
                .unwrap()
                .source_range
                .unwrap()
                .start,
            input.find("connectAttr").unwrap()
        );
    }
    for middle in [
        "",
        "setAttr \".note\" -type \"string\" \"print('Sample')\";",
    ] {
        let input = format!(
            "{SOURCE} createNode transform -n Sample; {middle}{SCRIPT} connectAttr ExampleSource.note Sample.note; connectAttr Sample.note ExampleScript.b;"
        );
        assert_connection_issue(&input, input.rfind("connectAttr").unwrap(), "multiple hops");
    }
}

#[test]
fn dynamic_alias_sources_are_never_silently_resolved() {
    for extra in ["setAttr \".nt\" -type \"string\" \"print('Sample')\";", ""] {
        let input = format!(
            "{SOURCE} addAttr -sn nt -ln note -dt string; {extra}{SCRIPT} connectAttr ExampleSource.note ExampleScript.b;"
        );
        assert_connection_issue(
            &input,
            input.find("connectAttr").unwrap(),
            "alias is unresolved",
        );
    }
}

#[test]
fn renamed_source_and_duplicate_connections_retain_identity() {
    let result = catalog(&format!(
        "{SOURCE} rename ExampleSource ExampleMoved; setAttr \".note\" -type \"string\" \"print('Sample')\"; {SCRIPT} connectAttr :ExampleMoved.note :ExampleScript.b; connectAttr ExampleMoved.note ExampleScript.b;"
    ));
    assert_eq!(result.surfaces.len(), 4);
    assert!(result.coverage_issues.is_empty());
}

#[test]
fn forward_connections_and_connected_controls_are_unknown() {
    let input = format!("connectAttr ExampleSource.note ExampleScript.b; {SOURCE}{SCRIPT}");
    assert_connection_issue(&input, 0, "cannot resolve connection destination");
    let input = format!(
        "{SOURCE}{SCRIPT} setAttr \".b\" -type \"string\" \"print('Example')\"; connectAttr ExampleSource.note ExampleScript.scriptType;"
    );
    let result = catalog(&input);
    assert_connection_issue(
        &input,
        input.find("connectAttr").unwrap(),
        "connected trigger / language",
    );
    assert_eq!(
        result.surfaces[0].surface.origin.trigger.as_str(),
        "unknown"
    );
    assert_eq!(result.surfaces[0].surface.origin.lang.as_str(), "unknown");
}

#[test]
fn callback_connections_and_normal_connections_are_distinguished() {
    for (node_type, attr) in [
        ("script", "after"),
        ("expression", "internalExpression"),
        ("expression", "expression"),
        ("renderGlobals", "preRenderMel"),
        ("renderGlobals", "prm"),
        ("transform", "preMel"),
    ] {
        let result = catalog(&format!(
            "{SOURCE} createNode {node_type} -n Example; connectAttr ExampleSource.note Example.{attr};"
        ));
        assert_eq!(result.surfaces.len(), 1, "{node_type}.{attr}");
    }
    for target in [
        ":renderPartition.st",
        ":perspShape.b",
        "ExampleRig:Sample.b",
        "ExampleRig:Sample.pom",
        "ExampleSource.b",
        "ExampleSource.tx",
    ] {
        let result = catalog(&format!(
            "createNode transform -n Sample; setAttr \".tx\" 1; createNode transform -n ExampleSource; connectAttr Sample.tx {target} -na;"
        ));
        assert!(result.coverage_issues.is_empty(), "{target}");
        assert!(result.surfaces.is_empty());
    }
}

#[test]
fn malformed_connections_are_diagnosed() {
    for suffix in [
        "ExampleSource.note",
        "ExampleSource.note ExampleScript.b Sample.note",
        "ExampleSource.note ExampleScript.b -unknown",
        "ExampleSource.note ExampleScript.b -l",
        "ExampleSource.note (\"Example\" + \"Sample\")",
    ] {
        let input = format!("{SOURCE}{SCRIPT} connectAttr {suffix};");
        let result = catalog(&input);
        assert!(
            result.coverage_issues.iter().any(|issue| {
                issue.kind.as_str() == "top_level_diagnostics"
                    && format!("{:?}", issue.detail)
                        .contains("cannot determine connectAttr destination")
            }),
            "{suffix}: {:#?}",
            result.coverage_issues
        );
        let raw = maya_scene_kit_formats::ma::selective::extract_raw_selective_sections_from_ma(
            input.as_bytes(),
        );
        assert!(
            raw.audit_top_level
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.span.start == input.find("connectAttr").unwrap())
        );
    }
}

#[test]
fn connection_capture_paths_produce_identical_evidence() {
    let input = format!(
        "{SOURCE} createNode script -n Sample; setAttr .st 1; setAttr .stp 1; setAttr .before -type string \"print('Sample')\"; {SCRIPT} setAttr .before -type string \"print('TestScene')\"; connectAttr ExampleSource.note ExampleScript.before; connectAttr Sample.before ExampleScript.b -f;"
    );
    let loader = Loader::new(LoadOptions::default());
    let eager = loader
        .observe_analysis_bytes(
            Path::new("Example.ma"),
            SceneFormat::Ma,
            ValidationState::Validated,
            input.as_bytes().to_vec(),
        )
        .unwrap()
        .observed_execution_catalog(8)
        .unwrap();
    let lazy = loader
        .observe_bytes(
            Path::new("Example.ma"),
            SceneFormat::Ma,
            ValidationState::Validated,
            input.as_bytes().to_vec(),
        )
        .unwrap()
        .observed_execution_catalog(8)
        .unwrap();
    assert_eq!(eager.surfaces.len(), 4);
    assert_eq!(lazy.surfaces.len(), eager.surfaces.len());
    for (lazy, eager) in lazy.surfaces.iter().zip(&eager.surfaces) {
        assert_eq!(lazy.surface.origin, eager.surface.origin);
        assert_eq!(lazy.surface.text, eager.surface.text);
    }
    assert_eq!(
        eager
            .surfaces
            .iter()
            .filter(|surface| surface.surface.origin.connection_range.is_some())
            .count(),
        2
    );
    assert!(eager.coverage_issues.is_empty());
    assert!(lazy.coverage_issues.is_empty());
}

#[test]
fn aliases_in_source_history_and_incoming_edges_are_conservative() {
    let input = format!(
        "{SOURCE} addAttr -sn nt -ln note -dt string; createNode transform -n Sample; addAttr -sn nt -ln note -dt string; setAttr \".note\" -type \"string\" \"print('Sample')\"; {SCRIPT} connectAttr ExampleSource.nt Sample.nt; connectAttr Sample.note ExampleScript.b;"
    );
    assert_connection_issue(
        &input,
        input.rfind("connectAttr").unwrap(),
        "alias is unresolved",
    );
    let input = format!(
        "createNode script -n ExampleSource; setAttr \".stp\" 1; setAttr \".before\" -type \"string\" \"print('Example')\"; {SCRIPT} connectAttr ExampleSource.b ExampleScript.b;"
    );
    let result = catalog(&input);
    assert_eq!(result.surfaces.len(), 2);
    assert!(result.coverage_issues.is_empty());
}

#[test]
fn duplicate_node_names_do_not_merge_connection_histories() {
    let input = format!(
        "{SOURCE} createNode transform -n ExampleSource; setAttr \".note\" -type \"string\" \"print('Sample')\"; {SCRIPT} connectAttr ExampleSource.note ExampleScript.b;"
    );
    let result = catalog(&input);
    assert_eq!(result.surfaces.len(), 1);
    assert_eq!(result.surfaces[0].surface.text.as_ref(), "print('Example')");
}

#[test]
fn source_read_failures_keep_other_bodies_and_assignment_ranges() {
    let input = format!(
        "{SOURCE} setAttr \".note\" -type string $Example; {SCRIPT} connectAttr ExampleSource.note ExampleScript.b;"
    );
    let result = catalog(&input);
    assert!(
        result
            .surfaces
            .iter()
            .any(|surface| surface.surface.text.as_ref() == "print('Example')")
    );
    assert!(result.coverage_issues.iter().any(|issue| {
        let value = serde_json::to_value(&issue.origin).unwrap();
        value["connection_source_range"]["start"]
            == input.find("setAttr \".note\" -type string").unwrap()
    }));
}

#[test]
fn unknown_and_compound_execution_destinations_are_issues() {
    for dst in [
        "Sample.before",
        "Sample.b",
        "ExampleScript.compound.before",
        "ExampleScript.b[0]",
        "|ExampleScript.b",
        "ExampleGroup|ExampleScript.b",
    ] {
        let input = format!("{SOURCE}{SCRIPT} connectAttr ExampleSource.note \"{dst}\";");
        assert_connection_issue(
            &input,
            input.find("connectAttr").unwrap(),
            "cannot resolve connection destination",
        );
    }
}

fn assert_connection_issue(input: &str, position: usize, reason: &str) {
    let result = catalog(input);
    assert!(
        result.coverage_issues.iter().any(|issue| {
            issue.kind.as_str() == "surface_diagnostics"
                && issue
                    .origin
                    .as_ref()
                    .and_then(|origin| origin.source_range)
                    .is_some_and(|range| range.start == position)
                && format!("{:?}", issue.detail).contains(reason)
        }),
        "{:#?}",
        result.coverage_issues
    );
}

#[test]
fn referenced_sources_into_startup_nodes_are_not_execution() {
    for (source, destination) in [
        ("ExampleRig:ExampleSG.pa", ":creasePartition.st"),
        ("ExampleRig:ExampleSG.pa", ":renderPartition.st"),
        ("ExampleRig:ExampleNode.msg", ":perspShape.b"),
        ("ExampleRig:ExampleNode.msg", ":frontShape.b"),
        ("ExampleRig:ExampleNode.msg", ":perspShape.preMel"),
    ] {
        let input = format!("connectAttr {source} {destination} -na;");
        let result = catalog(&input);
        assert!(result.coverage_issues.is_empty(), "{destination}");
        assert!(result.surfaces.is_empty());
    }
}

#[test]
fn incoming_builtin_aliases_are_unresolved() {
    let input = format!(
        "createNode transform -n ExamplePayload; setAttr .nts -type string \"print('Example')\"; createNode transform -n ExampleSource; setAttr .nts -type string \"print('Sample')\"; {SCRIPT} connectAttr ExamplePayload.notes ExampleSource.notes; connectAttr ExampleSource.nts ExampleScript.b;"
    );
    assert_connection_issue(&input, input.rfind("connectAttr").unwrap(), "multiple hops");
    let distinct = format!(
        "{SOURCE} createNode script -n Sample; setAttr .st 1; setAttr .stp 1; setAttr .b -type string \"print('Sample')\"; {SCRIPT} connectAttr ExampleSource.note Sample.a; connectAttr Sample.b ExampleScript.b;"
    );
    assert!(catalog(&distinct).coverage_issues.is_empty());
}

#[test]
fn incoming_forward_references_are_unresolved() {
    let input = format!(
        "connectAttr ExamplePayload.note ExampleSource.note; createNode transform -n ExamplePayload; {SOURCE}{SCRIPT} connectAttr ExampleSource.note ExampleScript.b;"
    );
    assert_connection_issue(&input, input.rfind("connectAttr").unwrap(), "multiple hops");
}

#[test]
fn direct_callback_aliases_are_overwritten_by_connections() {
    let input = format!(
        "{SOURCE} createNode expression -n ExampleExpr; setAttr .internalExpression -type string \"print('Sample')\"; connectAttr ExampleSource.note ExampleExpr.ixp;"
    );
    let result = catalog(&input);
    assert_eq!(result.surfaces.len(), 2);
    assert!(result.surfaces[0].surface.origin.overwritten_by_connection);
}

#[test]
fn untyped_connection_long_names_require_coverage() {
    for attr in [
        "before",
        "after",
        "scriptType",
        "sourceType",
        "expression",
        "internalExpression",
    ] {
        assert_connection_issue(
            &format!("connectAttr Sample.o ns:Example.{attr};"),
            0,
            "cannot resolve connection destination",
        );
    }
}

#[test]
fn unmapped_execution_connection_is_reported_but_ordinary_connections_are_silent() {
    let result = catalog(
        "createNode transform -n Example; createNode script -n ExampleScript; connectAttr Example.tx ExampleScript.sampleAttribute;",
    );
    assert_eq!(result.coverage_issues.len(), 1);
    assert!(
        format!("{:?}", result.coverage_issues[0].detail)
            .contains("cannot resolve destination attribute")
    );
    assert!(result.surfaces.is_empty());
    let ordinary = catalog(
        "createNode transform -n Example; createNode transform -n Sample; connectAttr Example.tx Sample.sampleAttribute; connectAttr Example.tx Sample.tx;",
    );
    assert!(ordinary.coverage_issues.is_empty());
    assert!(ordinary.surfaces.is_empty());
}

#[test]
fn connection_without_source_attribute_reports_source_diagnostic() {
    let result = catalog(
        "createNode transform -n Example; createNode transform -n Sample; connectAttr Example Sample.tx;",
    );
    let diagnostics = format!("{:?}", result.coverage_issues);
    assert!(
        diagnostics.contains("cannot determine connectAttr source"),
        "{diagnostics}"
    );
    assert!(!diagnostics.contains("cannot determine connectAttr destination"));
}

#[test]
fn connection_without_destination_attribute_control_reports_destination() {
    let result = catalog(
        "createNode transform -n Example; createNode transform -n Sample; connectAttr Example.tx Sample;",
    );
    let diagnostics = format!("{:?}", result.coverage_issues);
    assert!(diagnostics.contains("cannot determine connectAttr destination"));
    assert!(!diagnostics.contains("cannot determine connectAttr source"));
}
