use std::path::Path;

use maya_scene_kit_audit::{
    audit::{audit_observation, build_script_audit_plan},
    scene::{AuditDisposition, AuditOptions},
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader,
    core::{SceneFormat, ValidationState},
};

#[test]
fn alternate_execution_attribute_spellings_are_audited() {
    let python = "import os; os.system('echo Sample')";
    let mel = r#"python("import os; os.system('echo Sample')")"#;
    let mel_string = mel.replace('"', "\\\"");
    let benign = "print('Example')";
    let mut scenes = Vec::new();
    for attr in [".before", ".after", "ExampleScript.b"] {
        scenes.push(format!("createNode script -n ExampleScript; setAttr \"{attr}\" -type \"string\" \"{python}\"; setAttr \".scriptType\" 1; setAttr \".sourceType\" 1;"));
    }
    for (first, second) in [
        (".b", ".before"),
        (".before", ".b"),
        (".a", ".after"),
        (".after", ".a"),
        (".before", ".before"),
        ("ExampleScript.b", "ExampleScript.b"),
    ] {
        for (a, b) in [(python, benign), (benign, python)] {
            scenes.push(format!("createNode script -n ExampleScript; setAttr \"{first}\" -type \"string\" \"{a}\"; setAttr \"{second}\" -type \"string\" \"{b}\"; setAttr \".st\" 0; setAttr \".scriptType\" 1; setAttr \".stp\" 0; setAttr \".sourceType\" 1;"));
        }
    }
    for (node_type, attr) in [
        ("script", ".b"),
        ("expression", ".ixp"),
        ("expression", ".internalExpression"),
    ] {
        for (space, flag) in [(" ", "-typ "), (" ", "-type  "), ("\t", "-type ")] {
            scenes.push(format!("createNode {node_type} -n ExampleScript; setAttr{space}\"{attr}\" {flag}\"string\" \"{mel_string}\";"));
        }
    }
    scenes.push(format!(
        "setAttr \"defaultRenderGlobals.prm\" -type \"string\" \"{mel_string}\";",
    ));
    let plan = build_script_audit_plan(vec![], 64).unwrap();

    for (scene, surface_count) in [
        (
            "createNode script -n Example; setAttr \".before\" -type \"string\" \"print('Example')\"; setAttr \".sourceType\" 1;",
            1,
        ),
        (
            "createNode script -n Example; createNode transform -n Sample; setAttr \"Sample.before\" -type \"string\" \"print('Example')\";",
            0,
        ),
        (
            "createNode script -n Example; setAttr \".BEFORE\" -type \"string\" \"print('Example')\";",
            0,
        ),
    ] {
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                Path::new("Example.ma"),
                SceneFormat::Ma,
                ValidationState::Validated,
                scene.as_bytes().to_vec(),
            )
            .unwrap();
        let report =
            audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
        assert_eq!(report.surfaces.len(), surface_count);
        assert!(report.findings.is_empty());
        assert!(report.coverage_issues.is_empty());
    }
    let mut failures = Vec::new();
    for (index, scene) in scenes.iter().enumerate() {
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes(
                Path::new("Example.ma"),
                SceneFormat::Ma,
                ValidationState::Validated,
                scene.as_bytes().to_vec(),
            )
            .unwrap();
        let report =
            audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
        let python_finding = report
            .findings
            .iter()
            .any(|finding| format!("{:?}", finding.code).starts_with("Python"));
        if report.disposition != AuditDisposition::DenyMalicious || !python_finding {
            failures.push((index, report.disposition));
        }
    }
    assert!(failures.is_empty(), "undetected cases: {failures:?}");
}
