use maya_scene_kit_audit::{
    audit::{audit_script_nodes_with_options, build_script_audit_plan},
    scene::{
        AuditDisposition, AuditEvidence, AuditEvidenceKey, AuditFindingCode, AuditFindingDetail,
        AuditOptions, AuditReport, AuditReviewCode, AuditSeverity, AuditSinkKind,
        ExecutionLanguage, audit_source_text,
    },
};
use maya_scene_kit_observe::scene::{LoadOptions, evidence::ExecutionTrigger};

fn scene(source: &str, autorun: bool) -> AuditReport {
    let dir = tempfile::tempdir().expect("temporary scene directory");
    let path = dir.path().join("TestScene.ma");
    let escaped = source
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    let script_type = if autorun { 1 } else { 0 };
    std::fs::write(&path, format!(
        "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"Example\";\n    setAttr \".st\" {script_type};\n    setAttr \".stp\" 1;\n    setAttr \".b\" -type \"string\" \"{escaped}\";\n"
    )).expect("write synthetic scene");
    audit_script_nodes_with_options(
        &path,
        &build_script_audit_plan(Vec::new(), 96).expect("plan"),
        &LoadOptions::default(),
        AuditOptions::strict_default(),
    )
    .expect("scene audit")
}

fn paired(source: &str) -> [AuditReport; 2] {
    let reports = [
        audit_source_text(source, ExecutionLanguage::Python).expect("source audit"),
        scene(source, false),
    ];
    for report in &reports {
        assert!(
            report
                .surfaces
                .iter()
                .any(|surface| surface.origin.lang == ExecutionLanguage::Python),
            "{source}"
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.code == AuditFindingCode::PythonParseFailure),
            "{source}"
        );
    }
    reports
}

fn assert_uncertain(report: &AuditReport, source: &str) {
    assert!(report.blocked_on_uncertainty, "{source}");
    assert!(!report.unknown_semantics.is_empty(), "{source}");
    let review = report
        .review_signals
        .iter()
        .find(|review| review.code == AuditReviewCode::PythonMayaUncertain)
        .unwrap_or_else(|| panic!("missing Maya uncertainty: {source}"));
    assert!(review.surface_index < report.surfaces.len());
    assert!(
        report
            .unknown_semantics
            .iter()
            .any(|fact| fact.origin == report.surfaces[review.surface_index].origin),
        "{source}"
    );
}

fn assert_finding(
    report: &AuditReport,
    code: AuditFindingCode,
    sink: AuditSinkKind,
    severity: AuditSeverity,
    source: &str,
) {
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.code == code)
        .unwrap_or_else(|| panic!("missing {code:?}: {source}"));
    assert_eq!(finding.sink, sink, "{source}");
    assert_eq!(finding.severity, severity, "{source}");
    assert!(
        matches!(finding.detail, AuditFindingDetail::Static { .. }),
        "{source}"
    );
    assert_eq!(
        report.disposition,
        AuditDisposition::DenyMalicious,
        "{source}"
    );
    assert!(finding.surface_index < report.surfaces.len());
    assert!(
        finding.evidence.iter().any(|evidence| matches!(evidence,
        AuditEvidence::KeyValue { key: AuditEvidenceKey::Command, value }
        if value.starts_with("maya.") || value.starts_with("pymel."))),
        "{source}"
    );
    assert!(
        finding.evidence.iter().any(|evidence| matches!(evidence,
        AuditEvidence::FreeText { value } if value.starts_with("operation="))),
        "{source}"
    );
}

struct Family {
    target: &'static str,
    positive: &'static str,
    query: &'static str,
    code: AuditFindingCode,
    sink: AuditSinkKind,
    severity: AuditSeverity,
    label: &'static str,
    code_label: &'static str,
}

fn families() -> [Family; 8] {
    [
        Family {
            target: "file",
            positive: "open=True",
            query: "q=True, sceneName=True",
            code: AuditFindingCode::PythonMayaFile,
            sink: AuditSinkKind::PyMayaFile,
            severity: AuditSeverity::High,
            label: "py_maya_file",
            code_label: "python_maya_file",
        },
        Family {
            target: "sysFile",
            positive: "'asset/example/file.txt', delete=True",
            query: "'asset/example/file.txt', delete=False",
            code: AuditFindingCode::PythonFileWrite,
            sink: AuditSinkKind::PyFileWrite,
            severity: AuditSeverity::Critical,
            label: "py_file_write",
            code_label: "python_file_write",
        },
        Family {
            target: "scriptJob",
            positive: "event=['Example', 'print(1)']",
            query: "listJobs=True",
            code: AuditFindingCode::PythonMayaScriptJob,
            sink: AuditSinkKind::PyMayaScriptJob,
            severity: AuditSeverity::High,
            label: "py_maya_script_job",
            code_label: "python_maya_script_job",
        },
        Family {
            target: "commandPort",
            positive: "name='Example'",
            query: "listPorts=True",
            code: AuditFindingCode::PythonMayaCommandPort,
            sink: AuditSinkKind::PySocket,
            severity: AuditSeverity::High,
            label: "py_socket",
            code_label: "python_maya_command_port",
        },
        Family {
            target: "scriptNode",
            positive: "beforeScript='print(1)', sourceType='python'",
            query: "'Example', q=True, beforeScript=True",
            code: AuditFindingCode::PythonMayaScriptNode,
            sink: AuditSinkKind::PyMayaScriptNode,
            severity: AuditSeverity::High,
            label: "py_maya_script_node",
            code_label: "python_maya_script_node",
        },
        Family {
            target: "loadPlugin",
            positive: "'Example'",
            query: "'Example', pluginPath=True",
            code: AuditFindingCode::PythonMayaLoadPlugin,
            sink: AuditSinkKind::PyMayaLoadPlugin,
            severity: AuditSeverity::High,
            label: "py_maya_load_plugin",
            code_label: "python_maya_load_plugin",
        },
        Family {
            target: "evalDeferred",
            positive: "'print(1)'",
            query: "list=True",
            code: AuditFindingCode::PythonMayaEvalDeferred,
            sink: AuditSinkKind::PyMayaEvalDeferred,
            severity: AuditSeverity::High,
            label: "py_maya_eval_deferred",
            code_label: "python_maya_eval_deferred",
        },
        Family {
            target: "MEventMessage.addEventCallback",
            positive: "'Example', ExampleCallback",
            query: "",
            code: AuditFindingCode::PythonMayaCallback,
            sink: AuditSinkKind::PyMayaCallback,
            severity: AuditSeverity::High,
            label: "py_maya_callback",
            code_label: "python_maya_callback",
        },
    ]
}

#[test]
fn every_maya_family_has_paired_positive_query_dynamic_alias_shadow_and_unrelated_cases() {
    for family in families() {
        let module = if family.code == AuditFindingCode::PythonMayaCallback {
            "maya.api.OpenMaya"
        } else {
            "maya.cmds"
        };
        assert_eq!(family.sink.as_str(), family.label);
        assert_eq!(
            serde_json::to_value(family.sink).expect("sink serialization"),
            family.label
        );
        assert_eq!(family.code.as_str(), family.code_label);
        assert_eq!(
            serde_json::to_value(family.code).expect("code serialization"),
            family.code_label
        );
        let positive = format!(
            "import {module} as example\nexample.{}({})",
            family.target, family.positive
        );
        for report in paired(&positive) {
            assert_finding(
                &report,
                family.code,
                family.sink,
                family.severity,
                &positive,
            );
        }
        let autorun = scene(&positive, true);
        assert_finding(
            &autorun,
            family.code,
            family.sink,
            AuditSeverity::Critical,
            &positive,
        );
        assert!(
            autorun
                .surfaces
                .iter()
                .any(|surface| surface.origin.trigger != ExecutionTrigger::Manual)
        );
        let query_target = if family.code == AuditFindingCode::PythonMayaCallback {
            "MEventMessage.getEventNames"
        } else {
            family.target
        };
        let query = format!(
            "import {module} as example\nexample.{query_target}({})",
            family.query
        );
        let shadow = format!(
            "import {module} as example\ndef Example(example):\n    example.{}({})",
            family.target, family.positive
        );
        let unrelated = format!("example.{}({})", family.target, family.positive);
        for source in [&query, &shadow, &unrelated] {
            for report in paired(source) {
                assert!(
                    !report
                        .findings
                        .iter()
                        .any(|finding| finding.code == family.code),
                    "{source}"
                );
            }
        }
        let dynamic = format!(
            "import {module} as example\nexample.{}(**example_options)",
            family.target
        );
        for report in paired(&dynamic) {
            assert_uncertain(&report, &dynamic);
        }
        let (from_module, member) = family
            .target
            .rsplit_once('.')
            .map(|(class, member)| (format!("{module}.{class}"), member))
            .unwrap_or((module.to_string(), family.target));
        let alias = if family.code == AuditFindingCode::PythonMayaCallback {
            format!(
                "from {module} import MEventMessage as ExampleClass\nexample_call = ExampleClass.addEventCallback\nexample_call({})",
                family.positive
            )
        } else {
            format!(
                "from {from_module} import {member} as example_import\nexample_call = example_import\nexample_call({})",
                family.positive
            )
        };
        for report in paired(&alias) {
            assert_finding(&report, family.code, family.sink, family.severity, &alias);
        }
    }
}

#[test]
fn file_operations_normalize_all_long_and_short_action_flags() {
    for (long, short, severity) in [
        ("save", "s", AuditSeverity::Critical),
        ("open", "o", AuditSeverity::High),
        ("newFile", "new", AuditSeverity::High),
        ("import", "i", AuditSeverity::High),
        ("reference", "r", AuditSeverity::High),
        ("force", "f", AuditSeverity::High),
        ("exportAll", "ea", AuditSeverity::Critical),
        ("exportSelected", "es", AuditSeverity::Critical),
        ("exportAnim", "ean", AuditSeverity::Critical),
        ("exportSelectedAnim", "esa", AuditSeverity::Critical),
        ("exportAnimFromReference", "ear", AuditSeverity::Critical),
        (
            "exportSelectedAnimFromReference",
            "esar",
            AuditSeverity::Critical,
        ),
        ("exportAsReference", "er", AuditSeverity::Critical),
        ("exportAsSegment", "eas", AuditSeverity::Critical),
        ("exportSelectedNoReference", "esn", AuditSeverity::Critical),
        ("exportUnloadedReferences", "eur", AuditSeverity::Critical),
        ("exportEdits", "ee", AuditSeverity::Critical),
    ] {
        for flag in [long, short] {
            if flag == "import" {
                continue;
            }
            let source = format!("import maya.cmds\nmaya.cmds.file({flag}=True)");
            for report in paired(&source) {
                assert_finding(
                    &report,
                    AuditFindingCode::PythonMayaFile,
                    AuditSinkKind::PyMayaFile,
                    severity,
                    &source,
                );
                assert!(report.findings.iter().flat_map(|finding| &finding.evidence).any(|evidence|
                    matches!(evidence, AuditEvidence::FreeText { value } if value == &format!("operation={long}"))), "{source}");
            }
        }
    }
    for args in ["force=False", "save=False", "q=True, sn=True"] {
        let source = format!("from maya import cmds\ncmds.file({args})");
        for report in paired(&source) {
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|finding| finding.code == AuditFindingCode::PythonMayaFile)
            );
        }
    }
    let source = "from maya import cmds\ncmds.file(save=True, force=True)";
    for report in paired(source) {
        assert_finding(
            &report,
            AuditFindingCode::PythonMayaFile,
            AuditSinkKind::PyMayaFile,
            AuditSeverity::Critical,
            source,
        );
    }
}

#[test]
fn pymel_wrappers_and_qualified_modules_share_classification() {
    for module in ["pymel.core", "pymel.core.system", "pymel.core.general"] {
        for (operation, severity) in [
            ("saveFile", AuditSeverity::Critical),
            ("saveAs", AuditSeverity::Critical),
            ("openFile", AuditSeverity::High),
            ("newFile", AuditSeverity::High),
            ("importFile", AuditSeverity::High),
            ("createReference", AuditSeverity::High),
            ("exportAll", AuditSeverity::Critical),
            ("exportSelected", AuditSeverity::Critical),
            ("exportAnim", AuditSeverity::Critical),
            ("exportSelectedAnim", AuditSeverity::Critical),
            ("exportAnimFromReference", AuditSeverity::Critical),
            ("exportSelectedAnimFromReference", AuditSeverity::Critical),
            ("exportAsReference", AuditSeverity::Critical),
            ("exportAsSegment", AuditSeverity::Critical),
            ("exportSelectedNoReference", AuditSeverity::Critical),
            ("exportUnloadedReferences", AuditSeverity::Critical),
            ("exportEdits", AuditSeverity::Critical),
        ] {
            let source = format!(
                "import {module} as pm\nexample_call = pm.{operation}\nexample_call('asset/example/file.ma')"
            );
            for report in paired(&source) {
                assert_finding(
                    &report,
                    AuditFindingCode::PythonMayaFile,
                    AuditSinkKind::PyMayaFile,
                    severity,
                    &source,
                );
            }
        }
        for family in families()
            .into_iter()
            .filter(|family| family.code != AuditFindingCode::PythonMayaCallback)
        {
            let source = format!(
                "import {module}\n{module}.{}({})",
                family.target, family.positive
            );
            for report in paired(&source) {
                assert_finding(&report, family.code, family.sink, family.severity, &source);
            }
        }
    }
}

#[test]
fn unknown_flags_unpacking_and_conflicting_query_modes_never_exempt_operations() {
    for source in [
        "import maya.cmds as mc\nmc.scriptJob(q=True)",
        "import maya.cmds as mc\nmc.loadPlugin(q=True)",
        "import maya.cmds as mc\nmc.evalDeferred(q=True)",
        "import maya.cmds as mc\nmc.scriptJob(exists=example_id)",
        "import maya.cmds as mc\ngetattr(mc, 'file')(q=True)",
        "from maya.cmds import *\nfile(q=True)",
        "if example_condition:\n    from maya.cmds import file as example_call\nelse:\n    example_call = Example\nexample_call(q=True)",
        "import maya.cmds as mc\nmc.file(q=True, **example_options)",
        "import maya.cmds as mc\nmc.file(q=True, example_flag=True)",
        "import maya.cmds as mc\nmc.file(force=example_value)",
        "import maya.cmds as mc\nmc.file(*example_args)",
        "import maya.cmds as mc\nmc.file(q=example_value)",
        "import maya.cmds as mc\nmc.file(**{'import': True})",
        "import maya.cmds as mc\nmc.sysFile(q=True)",
        "import maya.cmds as mc\nmc.sysFile(delete=example_value)",
        "import maya.cmds as mc\nmc.commandPort(name=example_name)",
        "import maya.cmds as mc\nmc.scriptJob(kill=1)",
        "import maya.cmds as mc\nmc.scriptJob(killAll=True)",
        "import maya.cmds as mc\nmc.commandPort(name='Example', close=True)",
        "import maya.cmds as mc\nmc.loadPlugin(removeCallback=ExampleCallback)",
        "import maya.OpenMaya as om\nom.MMessage.removeCallback(example_id)",
    ] {
        for report in paired(source) {
            assert_uncertain(&report, source);
            assert_eq!(report.disposition, AuditDisposition::Review, "{source}");
        }
    }
    for source in [
        "from maya import cmds\ncmds.file(q=True, save=True)",
        "from maya import cmds\ncmds.file(save=True, **example_options)",
        "from maya import cmds\ncmds.file(save=True, s=False)",
    ] {
        for report in paired(source) {
            assert_uncertain(&report, source);
            assert_finding(
                &report,
                AuditFindingCode::PythonMayaFile,
                AuditSinkKind::PyMayaFile,
                AuditSeverity::Critical,
                source,
            );
        }
    }
}

#[test]
fn maya_queries_still_visit_nested_argument_expressions_and_preserve_dynamic_target_denial() {
    for source in [
        "from maya import cmds\ncmds.file(q=True, sceneName=eval('1'))",
        "import maya.cmds as mc\ngetattr(mc, example_name)(q=True)",
        "import maya.cmds as mc\nmc.__dict__[example_name](q=True)",
    ] {
        for report in paired(source) {
            assert_eq!(
                report.disposition,
                AuditDisposition::DenyMalicious,
                "{source}"
            );
            assert!(
                report.findings.iter().any(|finding| matches!(
                    finding.code,
                    AuditFindingCode::PythonEval | AuditFindingCode::PythonUnresolvedCallTarget
                )),
                "{source}"
            );
        }
    }
}

#[test]
fn reassignment_deletion_arguments_and_lexical_locals_shadow_imports() {
    for source in [
        "import maya.cmds as mc\nmc = Example\nmc.file(save=True)",
        "from maya.cmds import file as example_call\nexample_call = Example\nexample_call(save=True)",
        "import maya.cmds as mc\ndel mc\nmc.file(save=True)",
        "import maya.cmds as mc\ndef Example(mc):\n    mc.file(save=True)",
        "import maya.cmds as mc\ndef Example():\n    mc.file(save=True)\n    mc = example_object",
        "import maya.cmds as mc\nExample = lambda mc: mc.file(save=True)",
        "import maya.cmds as mc\n[mc.file(save=True) for mc in example_items]",
        "import maya.cmds as mc\ndef mc():\n    pass\nmc.file(save=True)",
        "from .maya import cmds\ncmds.file(save=True)",
    ] {
        for report in paired(source) {
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|finding| finding.code == AuditFindingCode::PythonMayaFile),
                "{source}"
            );
        }
    }
    for source in [
        "import maya.cmds as mc\ndef Example():\n    mc.file(save=True)",
        "from maya import cmds\nexample_call = cmds.file\ndef Example():\n    example_call(save=True)",
        "import maya.cmds as mc\ndef Example(mc):\n    pass\nmc.file(save=True)",
    ] {
        for report in paired(source) {
            assert_finding(
                &report,
                AuditFindingCode::PythonMayaFile,
                AuditSinkKind::PyMayaFile,
                AuditSeverity::Critical,
                source,
            );
        }
    }
    let source =
        "import maya.cmds as mc\nif example_condition:\n    mc = Example\nmc.file(save=True)";
    for report in paired(source) {
        assert_uncertain(&report, source);
    }
}

#[test]
fn message_registration_supports_api_versions_class_aliases_and_pymel() {
    for module in ["maya.OpenMaya", "maya.api.OpenMaya", "pymel.api"] {
        for (class, method) in [
            ("MSceneMessage", "addCallback"),
            ("MSceneMessage", "addCheckCallback"),
            ("MDGMessage", "addNodeAddedCallback"),
            ("MEventMessage", "addEventCallback"),
            ("MNodeMessage", "addAttributeChangedCallback"),
            ("MDagMessage", "addAllDagChangesCallback"),
            ("MConditionMessage", "addConditionCallback"),
            ("MTimerMessage", "addTimerCallback"),
            ("MCommandMessage", "addCommandCallback"),
            ("MLockMessage", "addNodeLockCallback"),
            ("MPolyMessage", "addPolyTopologyChangedCallback"),
            ("MUserEventMessage", "addUserEventCallback"),
        ] {
            let source = format!(
                "from {module} import {class} as ExampleClass\nexample_call = ExampleClass.{method}\nexample_call('Example', ExampleCallback)"
            );
            for report in paired(&source) {
                assert_finding(
                    &report,
                    AuditFindingCode::PythonMayaCallback,
                    AuditSinkKind::PyMayaCallback,
                    AuditSeverity::High,
                    &source,
                );
                assert_uncertain(&report, &source);
            }
        }
    }
    for source in [
        "import maya.api.OpenMaya as om\nom.MFnDependencyNode.addAttribute(example_attribute)",
        "example.MSceneMessage.addCallback(ExampleCallback)",
        "from Example import MSceneMessage\nMSceneMessage.addCallback(ExampleCallback)",
    ] {
        for report in paired(source) {
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|finding| finding.code == AuditFindingCode::PythonMayaCallback),
                "{source}"
            );
        }
    }
}

#[test]
fn short_flags_and_dynamic_bodies_retain_proven_capabilities() {
    for (target, args, code, sink, severity) in [
        (
            "sysFile",
            "'asset/example/file.txt', ren=example_destination",
            AuditFindingCode::PythonFileWrite,
            AuditSinkKind::PyFileWrite,
            AuditSeverity::Critical,
        ),
        (
            "sysFile",
            "'asset/example/file.txt', mov=example_destination",
            AuditFindingCode::PythonFileWrite,
            AuditSinkKind::PyFileWrite,
            AuditSeverity::Critical,
        ),
        (
            "sysFile",
            "'asset/example/file.txt', cp=example_destination",
            AuditFindingCode::PythonFileWrite,
            AuditSinkKind::PyFileWrite,
            AuditSeverity::Critical,
        ),
        (
            "sysFile",
            "'asset/example', md=True",
            AuditFindingCode::PythonFileWrite,
            AuditSinkKind::PyFileWrite,
            AuditSeverity::Critical,
        ),
        (
            "sysFile",
            "'asset/example', red=True",
            AuditFindingCode::PythonFileWrite,
            AuditSinkKind::PyFileWrite,
            AuditSeverity::Critical,
        ),
        (
            "scriptNode",
            "bs=example_body, st=1, stp='python'",
            AuditFindingCode::PythonMayaScriptNode,
            AuditSinkKind::PyMayaScriptNode,
            AuditSeverity::High,
        ),
        (
            "scriptNode",
            "'Example', eb=True",
            AuditFindingCode::PythonMayaScriptNode,
            AuditSinkKind::PyMayaScriptNode,
            AuditSeverity::High,
        ),
        (
            "scriptNode",
            "'Example', ea=True",
            AuditFindingCode::PythonMayaScriptNode,
            AuditSinkKind::PyMayaScriptNode,
            AuditSeverity::High,
        ),
        (
            "loadPlugin",
            "example_plugin, quiet=True",
            AuditFindingCode::PythonMayaLoadPlugin,
            AuditSinkKind::PyMayaLoadPlugin,
            AuditSeverity::High,
        ),
        (
            "loadPlugin",
            "allPlugins=True, addCallback=ExampleCallback",
            AuditFindingCode::PythonMayaLoadPlugin,
            AuditSinkKind::PyMayaLoadPlugin,
            AuditSeverity::High,
        ),
        (
            "evalDeferred",
            "ExampleCallback, lowestPriority=True",
            AuditFindingCode::PythonMayaEvalDeferred,
            AuditSinkKind::PyMayaEvalDeferred,
            AuditSeverity::High,
        ),
        (
            "evalDeferred",
            "example_body, ls=True",
            AuditFindingCode::PythonMayaEvalDeferred,
            AuditSinkKind::PyMayaEvalDeferred,
            AuditSeverity::High,
        ),
        (
            "commandPort",
            "n='Example', stp='python', sw=False",
            AuditFindingCode::PythonMayaCommandPort,
            AuditSinkKind::PySocket,
            AuditSeverity::High,
        ),
    ] {
        let source = format!("from maya import cmds\ncmds.{target}({args})");
        for report in paired(&source) {
            assert_finding(&report, code, sink, severity, &source);
        }
    }
    for flag in [
        "event",
        "e",
        "conditionTrue",
        "ct",
        "conditionFalse",
        "cf",
        "conditionChange",
        "cc",
        "attributeChange",
        "ac",
        "attributeAdded",
        "aa",
        "attributeDeleted",
        "ad",
        "connectionChange",
        "con",
        "timeChange",
        "tc",
        "idleEvent",
        "ie",
        "nodeDeleted",
        "nd",
        "uiDeleted",
        "uid",
    ] {
        let source = format!("import maya.cmds as mc\nmc.scriptJob({flag}=ExampleCallback)");
        for report in paired(&source) {
            assert_finding(
                &report,
                AuditFindingCode::PythonMayaScriptJob,
                AuditSinkKind::PyMayaScriptJob,
                AuditSeverity::High,
                &source,
            );
            assert_uncertain(&report, &source);
        }
    }
}

#[test]
fn disabled_mutations_do_not_conflict_with_independent_proven_actions() {
    for source in [
        "from maya import cmds\ncmds.file(save=True, force=False)",
        "from maya import cmds\ncmds.sysFile('asset/example/file.txt', copy='asset/example/copy.txt', delete=False)",
    ] {
        for report in paired(source) {
            assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
            assert!(
                !report
                    .review_signals
                    .iter()
                    .any(|signal| signal.code == AuditReviewCode::PythonMayaUncertain),
                "{source}"
            );
        }
    }
    for flag in [
        "delete",
        "makeDir",
        "removeEmptyDir",
        "rename",
        "move",
        "copy",
    ] {
        let source =
            format!("from maya import cmds\ncmds.sysFile('asset/example/file.txt', {flag}=False)");
        for report in paired(&source) {
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|finding| finding.code == AuditFindingCode::PythonFileWrite),
                "{source}"
            );
        }
    }
}

#[test]
fn dynamic_modes_do_not_claim_an_unproven_action() {
    for (call, code) in [
        (
            "commandPort(name='Example', q=example_mode)",
            AuditFindingCode::PythonMayaCommandPort,
        ),
        (
            "commandPort(name='Example', **example_options)",
            AuditFindingCode::PythonMayaCommandPort,
        ),
        (
            "loadPlugin('Example', pluginPath=example_mode)",
            AuditFindingCode::PythonMayaLoadPlugin,
        ),
        (
            "scriptNode('Example', q=example_mode, scriptType=True)",
            AuditFindingCode::PythonMayaScriptNode,
        ),
        (
            "scriptNode('Example', q=True, beforeScript=example_value)",
            AuditFindingCode::PythonMayaScriptNode,
        ),
    ] {
        let source = format!("from maya import cmds\ncmds.{call}");
        for report in paired(&source) {
            assert_uncertain(&report, &source);
            assert!(
                !report.findings.iter().any(|finding| finding.code == code),
                "{source}"
            );
            assert_eq!(report.disposition, AuditDisposition::Review, "{source}");
        }
    }
}
