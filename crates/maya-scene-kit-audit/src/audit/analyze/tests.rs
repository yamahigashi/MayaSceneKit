use std::sync::Arc;

use maya_scene_kit_observe::scene::execution::collect_mel_surface_facts;

use super::{
    AnalysisSurface, analyze_mel_surface,
    mel::{find_mel_call, mel_sink_line_preview},
    text_scan::scan_mel_sink_word_hits,
};
use crate::scene::{
    AuditEvidence, AuditEvidenceKey, AuditSinkKind, AuditSurfaceDerivation, ExecutionLanguage,
    ExecutionOrigin, ExecutionSurfaceKind, ExecutionTrigger,
    execution::{MelSurfaceCall, MelSurfaceCallSurfaceKind, MelSurfaceFacts},
};

#[test]
fn sink_word_scan_tracks_whole_command_port_word() {
    assert!(
        !scan_mel_sink_word_hits("ExamplecommandPort; commandPortExample;").contains("commandPort")
    );
    assert!(scan_mel_sink_word_hits("commandPort -n \"Example\";").contains("commandPort"));
}

#[test]
fn parser_backed_lookup_matches_call_name_case_insensitively() {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(r#"source "evil.mel""#),
        preview: r#"source "evil.mel""#.to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: None,
            attr_name: None,
            source_range: None,
            source_kind: None,
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(MelSurfaceFacts {
            source_text: Arc::from(r#"source "evil.mel""#),
            diagnostics: Vec::new(),
            validation_diagnostics: Vec::new(),
            calls: vec![MelSurfaceCall {
                name: "source".into(),
                surface_kind: MelSurfaceCallSurfaceKind::ShellLike,
                captured: false,
                literal_first_arg: Some("evil.mel".into()),
                dynamic: false,
                span_start: 0,
                span_end: 17,
            }],
            normalized_commands: Vec::new(),
            sink_arg_facts: Vec::new(),
            code_like_value_facts: Vec::new(),
        })),
    };

    let call = find_mel_call(&surface, "Source").expect("parser-backed source call");
    assert_eq!(call.literal_first_arg.as_deref(), Some("evil.mel"));
}

#[test]
fn mel_exec_command_emits_dedicated_finding() {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(r#"exec "SampleTool.exe";"#),
        preview: "exec".to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some("ExampleExecScript".to_string()),
            attr_name: Some(".b".to_string()),
            source_range: None,
            source_kind: Some("scriptType=1".to_string()),
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(
            r#"exec "SampleTool.exe";"#,
        ))),
    };

    let analysis = analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new());

    assert!(analysis.findings.iter().any(|finding| {
        finding.code.as_str() == "mel_exec" && finding.sink == AuditSinkKind::MelExec
    }));
}

#[test]
fn mel_exec_detection_does_not_scan_nested_python_strings() {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(r#"python("exec('print(1)')");"#),
        preview: "python".to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some("ExamplePythonBridgeScript".to_string()),
            attr_name: Some(".b".to_string()),
            source_range: None,
            source_kind: Some("scriptType=1".to_string()),
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(
            r#"python("exec('print(1)')");"#,
        ))),
    };

    let analysis = analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new());

    assert!(
        analysis
            .findings
            .iter()
            .all(|finding| finding.code.as_str() != "mel_exec")
    );
    assert!(
        analysis
            .findings
            .iter()
            .any(|finding| finding.sink == AuditSinkKind::MelPython)
    );
}

#[test]
fn callback_inline_body_emits_review_signal_and_derived_surface() {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(r#"modelEditor -e -editorChanged "print \"ok\";" modelPanel4;"#),
        preview: "modelEditor".to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some("uiConfigScript".to_string()),
            attr_name: Some(".b".to_string()),
            source_range: None,
            source_kind: Some("scriptType=1".to_string()),
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(
            r#"modelEditor -e -editorChanged "print \"ok\";" modelPanel4;"#,
        ))),
    };

    let analysis = analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new());

    assert!(analysis.findings.is_empty());
    assert!(
        analysis
            .derived_surfaces
            .iter()
            .any(|derived| derived.derivation == AuditSurfaceDerivation::MelCallbackLiteral)
    );
    assert!(
        analysis
            .review_signals
            .iter()
            .any(|review| review.code.as_str() == "mel_callback_body")
    );
    let callback_review = analysis
        .review_signals
        .iter()
        .find(|review| review.code.as_str() == "mel_callback_body")
        .expect("callback review");
    assert_eq!(
        callback_review.preview_override.as_deref(),
        Some(r#"print "ok";"#)
    );
    assert!(callback_review.evidence.iter().any(|evidence| {
        matches!(
            evidence,
            AuditEvidence::KeyValue {
                key: AuditEvidenceKey::NodeName,
                value
            } if value == "uiConfigScript"
        )
    }));
}

#[test]
fn bare_identifier_callback_flag_emits_review_signal_only() {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(r#"modelEditor -e -editorChanged "safeProc" modelPanel4;"#),
        preview: "modelEditor".to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some("uiConfigScript".to_string()),
            attr_name: Some(".b".to_string()),
            source_range: None,
            source_kind: Some("scriptType=1".to_string()),
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(
            r#"modelEditor -e -editorChanged "safeProc" modelPanel4;"#,
        ))),
    };

    let analysis = analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new());

    assert!(analysis.findings.is_empty());
    assert!(analysis.derived_surfaces.is_empty());
    assert!(
        analysis
            .review_signals
            .iter()
            .any(|review| { review.code.as_str() == "mel_callback_proc_reference" })
    );
    let review = analysis
        .review_signals
        .iter()
        .find(|review| review.code.as_str() == "mel_callback_proc_reference")
        .expect("callback proc review");
    assert_eq!(review.preview_override.as_deref(), Some("safeProc"));
    assert!(review.evidence.iter().any(|evidence| {
        matches!(
            evidence,
            AuditEvidence::KeyValue {
                key: AuditEvidenceKey::NodeName,
                value
            } if value == "uiConfigScript"
        )
    }));
}

#[test]
fn empty_braced_callback_flag_is_ignored() {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(r#"nodeOutliner -e -selectCommand "{}" outlinerPanel1;"#),
        preview: "nodeOutliner".to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some("uiConfigurationScriptNode".to_string()),
            attr_name: Some(".b".to_string()),
            source_range: None,
            source_kind: Some("scriptType=1".to_string()),
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(
            r#"nodeOutliner -e -selectCommand "{}" outlinerPanel1;"#,
        ))),
    };

    let analysis = analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new());

    assert!(analysis.findings.is_empty());
    assert!(analysis.derived_surfaces.is_empty());
    assert!(analysis.review_signals.is_empty());
}

#[test]
fn bare_mel_variable_is_not_obfuscation_marker() {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(r#"$editorName = "panel1"; modelEditor -q -camera $editorName;"#),
        preview: "$editorName".to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: None,
            attr_name: None,
            source_range: None,
            source_kind: None,
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(MelSurfaceFacts {
            source_text: Arc::from(
                r#"$editorName = "panel1"; modelEditor -q -camera $editorName;"#,
            ),
            diagnostics: Vec::new(),
            validation_diagnostics: Vec::new(),
            calls: Vec::new(),
            normalized_commands: Vec::new(),
            sink_arg_facts: Vec::new(),
            code_like_value_facts: Vec::new(),
        })),
    };

    let analysis = analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new());
    assert!(
        analysis
            .findings
            .iter()
            .all(|finding| finding.code.as_str() != "obfuscation_markers")
    );
}

#[test]
fn mel_sink_finding_uses_rendered_body_as_preview_override() {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(r#"eval("print \"sample\";");"#),
        preview: "eval".to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some("ExampleScriptNode".to_string()),
            attr_name: Some(".b".to_string()),
            source_range: None,
            source_kind: Some("scriptType=1".to_string()),
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(
            r#"eval("print \"sample\";");"#,
        ))),
    };

    let analysis = analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new());
    let finding = analysis
        .findings
        .iter()
        .find(|finding| finding.code.as_str() == "mel_eval")
        .expect("mel eval finding");

    assert_eq!(
        finding.preview_override.as_deref(),
        Some(r#"print "sample";"#)
    );
    assert!(finding.evidence.iter().any(|evidence| {
        matches!(
            evidence,
            AuditEvidence::KeyValue {
                key: AuditEvidenceKey::NodeName,
                value
            } if value == "ExampleScriptNode"
        )
    }));
}

#[test]
fn dynamic_mel_sink_finding_uses_sink_span_preview_override() {
    let source = concat!(
        "float $ExampleFrame = frame;\n",
        "string\t$ExampleBody = getenv(\"EXAMPLE_ENV\");\r\n",
        "eval($ExampleBody);"
    );
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(source),
        preview: "float $ExampleFrame = frame".to_string(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::NodeAttrCallback,
            node_name: Some("ExampleExpression".to_string()),
            attr_name: Some(".ixp".to_string()),
            source_range: None,
            source_kind: Some("internalExpression".to_string()),
            chunk_form: Some("DEXP".to_string()),
            chunk_tag: Some("STR ".to_string()),
            chunk_node_offset: Some(0x40),
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(source))),
    };

    let analysis = analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new());
    let finding = analysis
        .findings
        .iter()
        .find(|finding| finding.code.as_str() == "mel_eval")
        .expect("mel eval finding");
    let preview = finding
        .preview_override
        .as_deref()
        .expect("preview override");

    assert!(preview.contains("eval($ExampleBody)"));
    assert!(preview.contains('\n'));
    assert!(preview.contains("string    $ExampleBody"));
    assert!(!preview.contains('\r'));
}

#[test]
fn dynamic_mel_sink_preview_is_limited_to_sink_line_context() {
    let mut source = String::new();
    for index in 0..35 {
        source.push_str(&format!("string $ExampleBefore{index:02} = \"sample\";\n"));
    }
    source.push_str("string $ExampleBody = getenv(\"EXAMPLE_ENV\");\n");
    let sink_position = source.len();
    source.push_str("eval($ExampleBody);\n");
    for index in 0..15 {
        source.push_str(&format!("string $ExampleAfter{index:02} = \"sample\";\n"));
    }

    let preview = mel_sink_line_preview(&source, sink_position);

    assert!(preview.starts_with("[... omitted before ...] string $ExampleBefore06"));
    assert!(!preview.contains("ExampleBefore05"));
    assert!(preview.contains("ExampleBefore06"));
    assert!(preview.contains("eval($ExampleBody)"));
    assert!(preview.contains("ExampleAfter09"));
    assert!(!preview.contains("ExampleAfter10"));
    assert!(preview.ends_with(" [... omitted after ...]"));
    assert!(preview.lines().count() <= 41);
}

#[test]
fn dynamic_mel_sink_preview_truncates_long_lines_on_char_boundary() {
    let mut source = String::from("eval($ExampleBody); ");
    source.push_str(&"ExampleValue".repeat(1300));
    source.push('界');

    let preview = mel_sink_line_preview(&source, 0);

    assert!(preview.len() <= 12 * 1024);
    assert!(preview.is_char_boundary(preview.len()));
    assert!(preview.ends_with(" [... omitted after ...]"));
}

fn literal_sink_surface(body: &str) -> AnalysisSurface {
    AnalysisSurface {
        root_index: 3,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(body),
        preview: body.into(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger: ExecutionTrigger::FileOpen,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(body))),
    }
}

#[test]
fn literal_sink_calls_preserve_every_body_and_parser_fallback() {
    for sink in ["python", "eval", "evalDeferred"] {
        for function_syntax in [false, true] {
            let bodies = if sink == "python" {
                [
                    "print('Example')",
                    "import subprocess; subprocess.call(['echo', 'Example'])",
                ]
            } else {
                ["print(1)", "exec(\"Example\")"]
            };
            let text = bodies
                .map(|body| {
                    let quoted = serde_json::to_string(body).unwrap();
                    if function_syntax {
                        format!("{sink}({quoted});")
                    } else {
                        format!("{sink} {quoted};")
                    }
                })
                .join(" ");
            let surface = literal_sink_surface(&text);
            let facts = surface.mel.as_ref().unwrap();
            if function_syntax && sink == "python" {
                assert_eq!(facts.sink_arg_facts.len(), 2);
                assert_ne!(facts.sink_arg_facts[0].span, facts.sink_arg_facts[1].span);
            }
            for retained_facts in [2, 1, 0] {
                let mut surface = surface.clone();
                Arc::make_mut(surface.mel.as_mut().unwrap())
                    .sink_arg_facts
                    .truncate(retained_facts);
                let analysis = analyze_mel_surface(0, &surface, &mut Default::default());
                assert_eq!(
                    analysis.derived_surfaces.len(),
                    2,
                    "{sink}, function={function_syntax}, facts={retained_facts}"
                );
                assert_eq!(analysis.findings.len(), 2);
                for (derived, body) in analysis.derived_surfaces.iter().zip(bodies) {
                    assert_eq!(derived.text.as_ref(), body);
                    assert_eq!(derived.root_index, 3);
                    assert_eq!(derived.origin.trigger, surface.origin.trigger);
                }
                let dangerous = &analysis.derived_surfaces[1];
                let nested = if sink == "python" {
                    super::analyze_python_surface(
                        1,
                        dangerous,
                        maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes,
                    )
                } else {
                    analyze_mel_surface(1, dangerous, &mut Default::default())
                };
                assert!(nested.findings.iter().any(|finding| finding.code.as_str()
                    == if sink == "python" {
                        "python_subprocess"
                    } else {
                        "mel_exec"
                    }));
            }
        }
    }
}

#[test]
fn literal_and_dynamic_sink_arguments_are_order_independent() {
    for sink in ["python", "eval", "evalDeferred"] {
        for args in [
            ["\"print(1)\"", "$Example", "\"exec('Example')\""],
            ["\"exec('Example')\"", "$Example", "\"print(1)\""],
        ] {
            let text = args.map(|arg| format!("{sink}({arg});")).join(" ");
            let analysis =
                analyze_mel_surface(0, &literal_sink_surface(&text), &mut Default::default());
            assert_eq!(analysis.findings.len(), 3, "{text}");
            assert_eq!(analysis.derived_surfaces.len(), 2);
            assert!(
                analysis
                    .derived_surfaces
                    .iter()
                    .any(|surface| surface.text.as_ref() == "exec('Example')")
            );
        }
    }
}

#[test]
fn literal_eval_reaches_system_body() {
    let body = "eval(\"system(\\\"echo Example\\\")\");";
    let analysis = analyze_mel_surface(0, &literal_sink_surface(body), &mut Default::default());
    assert_eq!(analysis.derived_surfaces.len(), 1);
    assert_eq!(
        analysis.derived_surfaces[0].text.as_ref(),
        "system(\"echo Example\")"
    );
    assert_eq!(
        analysis.derived_surfaces[0].origin.lang,
        ExecutionLanguage::Mel
    );
}

#[test]
fn repeated_literal_analysis_preserves_each_occurrence() {
    let mut cache = super::cache::DerivedAnalysisCache::default();
    let mut surface = literal_sink_surface("eval(\"exec(\\\"Example\\\")\");");
    surface.derivation = AuditSurfaceDerivation::MelCallbackLiteral;
    let mut analyses = 0;
    for (index, depth) in [(11, 0), (12, 7)] {
        surface.literal_eval_depth = depth;
        let analysis = cache.analyze(index, &surface, |index, surface| {
            analyses += 1;
            analyze_mel_surface(index, surface, &mut Default::default())
        });
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].surface_index, index);
        assert_eq!(analysis.derived_surfaces.len(), 1);
        assert_eq!(analysis.derived_surfaces[0].root_index, surface.root_index);
        assert_eq!(analysis.derived_surfaces[0].literal_eval_depth, depth + 1);
    }
    assert_eq!(analyses, 1);
    surface.root_index += 1;
    cache.analyze(13, &surface, |index, surface| {
        analyses += 1;
        analyze_mel_surface(index, surface, &mut Default::default())
    });
    assert_eq!(analyses, 2);
    let mut python = literal_sink_surface("exec('Example')");
    python.origin.lang = ExecutionLanguage::Python;
    python.derivation = AuditSurfaceDerivation::MelPythonLiteralBridge;
    let mut python_analyses = 0;
    for index in [21, 22] {
        let analysis = cache.analyze(index, &python, |index, surface| {
            python_analyses += 1;
            super::analyze_python_surface(
                index,
                surface,
                maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes,
            )
        });
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.code.as_str() == "python_pyexec")
        );
        assert!(
            analysis
                .findings
                .iter()
                .all(|finding| finding.surface_index == index)
        );
    }
    assert_eq!(python_analyses, 1);
}

#[test]
fn variable_literal_eval_retains_its_call_position_once() {
    let body = "string $Example = \"exec(\\\"Example\\\")\";\neval($Example);";
    let surface = literal_sink_surface(body);
    let facts = surface.mel.as_ref().unwrap();
    let call = facts
        .calls
        .iter()
        .find(|call| call.name.as_ref() == "eval")
        .unwrap();
    let fact = facts
        .sink_arg_facts
        .iter()
        .find(|fact| {
            fact.sink_kind == maya_scene_kit_observe::scene::execution::MelSinkArgKind::Eval
        })
        .unwrap();
    assert_eq!(fact.span.start, body.rfind("$Example").unwrap());
    assert!(call.span_start <= fact.span.start && fact.span.end <= call.span_end);
    let analysis = analyze_mel_surface(17, &surface, &mut Default::default());
    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(analysis.findings[0].code.as_str(), "mel_eval");
    assert_eq!(analysis.findings[0].surface_index, 17);
    assert_eq!(analysis.derived_surfaces.len(), 1);
    assert_eq!(
        analysis.derived_surfaces[0].parent_position,
        Some((call.span_start, call.span_end))
    );
}

#[test]
fn repeated_depth_limit_position_is_reported_once_per_surface() {
    let mut coverage = super::cache::DepthLimitCoverage::default();
    let mut surface = literal_sink_surface("print(1)");
    surface.literal_eval_depth = 9;
    surface.parent_position = Some((0, 10));
    let mut issues = Vec::new();
    for _ in 0..4 {
        assert!(!coverage.retain(11, &surface, &mut issues));
    }
    assert_eq!(issues.len(), 1);
    assert!(!coverage.retain(12, &surface, &mut issues));
    assert_eq!(issues.len(), 2);
    for index in 13..111 {
        assert!(!coverage.retain(index, &surface, &mut issues));
    }
    assert_eq!(issues.len(), 100);
    assert!(!coverage.retain(11, &surface, &mut issues));
    assert_eq!(issues.len(), 100);
    for index in 111..115 {
        assert!(!coverage.retain(index, &surface, &mut issues));
    }
    assert_eq!(issues.len(), 101);
    surface.literal_eval_depth = 8;
    assert!(coverage.retain(115, &surface, &mut issues));
    assert_eq!(issues.len(), 101);
}

#[test]
fn nested_sink_arguments_belong_to_their_own_call() {
    let surface = literal_sink_surface("eval(eval(\"print(1)\"));");
    let analysis = analyze_mel_surface(0, &surface, &mut Default::default());
    assert_eq!(analysis.findings.len(), 2);
    assert_eq!(analysis.derived_surfaces.len(), 1);
    let inner = surface
        .mel
        .as_ref()
        .unwrap()
        .calls
        .iter()
        .filter(|call| call.name.as_ref() == "eval")
        .max_by_key(|call| call.span_start)
        .unwrap();
    assert_eq!(
        analysis.derived_surfaces[0].parent_position,
        Some((inner.span_start, inner.span_end))
    );
}

#[test]
fn repeated_literal_bodies_share_text_and_keep_positions() {
    for sink in ["python", "eval", "evalDeferred"] {
        let body = format!("{sink}(\"print(1)\"); {sink}(\"print(1)\");");
        for use_facts in [true, false] {
            let mut surface = literal_sink_surface(&body);
            if !use_facts {
                Arc::make_mut(surface.mel.as_mut().unwrap())
                    .sink_arg_facts
                    .clear();
            }
            let analysis = analyze_mel_surface(19, &surface, &mut Default::default());
            assert_eq!(analysis.findings.len(), 2);
            assert!(
                analysis
                    .findings
                    .iter()
                    .all(|finding| finding.surface_index == 19)
            );
            assert_eq!(analysis.derived_surfaces.len(), 2);
            assert!(Arc::ptr_eq(
                &analysis.derived_surfaces[0].text,
                &analysis.derived_surfaces[1].text
            ));
            assert_ne!(
                analysis.derived_surfaces[0].parent_position,
                analysis.derived_surfaces[1].parent_position
            );
        }
    }
}

fn dangerous_command_analysis(text: &str, trigger: ExecutionTrigger) -> super::SurfaceAnalysis {
    let surface = AnalysisSurface {
        root_index: 0,
        literal_eval_depth: 0,
        parent_position: None,
        text: Arc::from(text),
        preview: text.into(),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            ..ExecutionOrigin::without_chunk_address()
        },
        derivation: AuditSurfaceDerivation::Observed,
        mel: Some(Arc::new(collect_mel_surface_facts(text))),
    };
    analyze_mel_surface(0, &surface, &mut std::collections::HashMap::new())
}

macro_rules! dangerous_command_test {
    ($name:ident, $text:expr, $code:literal, $severity:ident) => {
        #[test]
        fn $name() {
            use crate::scene::AuditSeverity;
            for trigger in [ExecutionTrigger::Manual, ExecutionTrigger::FileOpen] {
                let analysis = dangerous_command_analysis($text, trigger);
                let findings = analysis
                    .findings
                    .iter()
                    .filter(|f| f.code.as_str() == $code)
                    .collect::<Vec<_>>();
                assert_eq!(
                    findings.len(),
                    1,
                    "{:#?}\n{:#?}",
                    analysis.findings,
                    collect_mel_surface_facts($text)
                );
                let expected = if trigger == ExecutionTrigger::FileOpen {
                    AuditSeverity::Critical
                } else {
                    AuditSeverity::$severity
                };
                assert_eq!(findings[0].severity, expected);
                let json = serde_json::to_value(findings[0]).unwrap();
                assert_eq!(json["code"], $code);
                let repeated = dangerous_command_analysis(&format!("{} {}", $text, $text), trigger);
                assert_eq!(
                    repeated
                        .findings
                        .iter()
                        .filter(|f| f.code.as_str() == $code)
                        .count(),
                    2
                );
                for inert in [
                    format!("// {}", $text),
                    format!("/* {} */", $text),
                    format!(
                        "string $Example = {};",
                        serde_json::to_string($text).unwrap()
                    ),
                ] {
                    let inert = dangerous_command_analysis(&inert, trigger);
                    assert!(!inert.findings.iter().any(|f| f.code.as_str() == $code));
                }
            }
        }
    };
}

dangerous_command_test!(
    system_command_finding,
    r#"system "echo Example";"#,
    "mel_system",
    High
);

dangerous_command_test!(
    system_function_finding,
    r#"system("echo Example");"#,
    "mel_system",
    High
);

dangerous_command_test!(
    popen_command_finding,
    r#"popen "echo Example" "r";"#,
    "mel_popen",
    High
);

dangerous_command_test!(
    popen_function_finding,
    r#"popen("echo Example", "r");"#,
    "mel_popen",
    High
);

dangerous_command_test!(
    fopen_command_finding,
    r#"fopen "asset/example/file.txt" "w";"#,
    "mel_file_open",
    Critical
);

dangerous_command_test!(
    fopen_function_finding,
    r#"fopen("asset/example/file.txt", "w");"#,
    "mel_file_open",
    Critical
);

dangerous_command_test!(
    fprint_command_finding,
    r#"fprint $Example "Sample";"#,
    "mel_file_write",
    Critical
);

dangerous_command_test!(
    fprint_function_finding,
    r#"fprint($Example, "Sample");"#,
    "mel_file_write",
    Critical
);

dangerous_command_test!(
    fwrite_command_finding,
    r#"fwrite $Example "Sample";"#,
    "mel_file_write",
    Critical
);

dangerous_command_test!(
    fwrite_function_finding,
    r#"fwrite($Example, "Sample");"#,
    "mel_file_write",
    Critical
);

dangerous_command_test!(
    evalecho_command_finding,
    r#"evalEcho "print(1)";"#,
    "mel_evalecho",
    Critical
);

dangerous_command_test!(
    evalecho_function_finding,
    r#"evalEcho("print(1)");"#,
    "mel_evalecho",
    Critical
);

dangerous_command_test!(
    callpython_command_finding,
    r#"callPython "Example" "Sample";"#,
    "mel_callpython",
    Critical
);

dangerous_command_test!(
    callpython_function_finding,
    r#"callPython("Example", "Sample");"#,
    "mel_callpython",
    Critical
);

dangerous_command_test!(
    source_command_finding,
    r#"source "Example.mel";"#,
    "mel_source",
    High
);

dangerous_command_test!(
    source_function_finding,
    r#"source("Example.mel");"#,
    "mel_source",
    High
);

dangerous_command_test!(
    loadplugin_command_finding,
    r#"loadPlugin "ExamplePlugin";"#,
    "mel_loadplugin",
    High
);

dangerous_command_test!(
    loadplugin_function_finding,
    r#"loadPlugin("ExamplePlugin");"#,
    "mel_loadplugin",
    High
);

dangerous_command_test!(
    sysfile_command_finding,
    r#"sysFile -delete "asset/example/file.txt";"#,
    "mel_sysfile",
    Critical
);

dangerous_command_test!(
    sysfile_function_finding,
    r#"sysFile("asset/example/file.txt", "-delete");"#,
    "mel_sysfile",
    Critical
);

#[test]
fn file_commands_distinguish_read_modes_and_independent_handles() {
    for text in [
        r#"int $Example = fopen("asset/example/file.txt", "w"); fprint $Sample "Example";"#,
        r#"int $Example = fopen("asset/example/file.txt", "w"); fwrite($Sample, "Example");"#,
    ] {
        let analysis = dangerous_command_analysis(text, ExecutionTrigger::Manual);
        assert!(
            analysis
                .findings
                .iter()
                .any(|f| f.code.as_str() == "mel_file_open")
        );
        assert!(
            analysis
                .findings
                .iter()
                .any(|f| f.code.as_str() == "mel_file_write")
        );
    }
    for mode in [
        "r", "rb", "w", "a", "r+", "wb", "ab", "w+", "a+", "$Example",
    ] {
        let argument = if mode.starts_with('$') {
            mode.to_string()
        } else {
            format!("\"{mode}\"")
        };
        for text in [
            format!("fopen \"asset/example/file.txt\" {argument};"),
            format!("fopen(\"asset/example/file.txt\", {argument});"),
        ] {
            let analysis = dangerous_command_analysis(&text, ExecutionTrigger::Manual);
            assert_eq!(
                analysis
                    .findings
                    .iter()
                    .any(|f| f.code.as_str() == "mel_file_open"),
                !matches!(mode, "r" | "rb"),
                "{text}"
            );
        }
    }
    for text in [
        r#"fopen /* Example ( */ ("asset/example/file.txt", /* Sample */ "r" /* Example */);"#,
        r#"fopen("asset/example/file.txt", "rb");"#,
    ] {
        assert!(
            !dangerous_command_analysis(text, ExecutionTrigger::Manual)
                .findings
                .iter()
                .any(|f| f.code.as_str() == "mel_file_open")
        );
    }
}

#[test]
fn sysfile_mutations_and_queries_are_distinguished() {
    for flag in [
        "delete",
        "del",
        "rename",
        "ren",
        "move",
        "mov",
        "copy",
        "cp",
        "makeDir",
        "md",
        "removeEmptyDir",
        "red",
        "exists",
        "ex",
    ] {
        for text in [
            format!("sysFile -{flag} \"asset/example/file.txt\";"),
            format!("sysFile(\"asset/example/file.txt\", \"-{flag}\");"),
        ] {
            let analysis = dangerous_command_analysis(&text, ExecutionTrigger::Manual);
            assert_eq!(
                analysis
                    .findings
                    .iter()
                    .any(|f| f.code.as_str() == "mel_sysfile"),
                !matches!(flag, "exists" | "ex"),
                "{text}"
            );
        }
    }
    for text in [
        r#"sysFile $Example;"#,
        r#"sysFile("asset/example/file.txt", $Example);"#,
    ] {
        assert!(
            dangerous_command_analysis(text, ExecutionTrigger::Manual)
                .findings
                .iter()
                .any(|f| f.code.as_str() == "mel_sysfile")
        );
    }
    for text in [
        r#"sysFile("-query", "asset/example/file.txt");"#,
        r#"sysFile -q "asset/example/file.txt";"#,
    ] {
        assert!(
            !dangerous_command_analysis(text, ExecutionTrigger::Manual)
                .findings
                .iter()
                .any(|f| f.code.as_str() == "mel_sysfile")
        );
    }
}

#[test]
fn literal_eval_reaches_system_finding() {
    let analysis = dangerous_command_analysis(
        r#"eval("system(\"echo Example\")");"#,
        ExecutionTrigger::Manual,
    );
    let body = &analysis.derived_surfaces[0].text;
    assert!(
        dangerous_command_analysis(body, ExecutionTrigger::Manual)
            .findings
            .iter()
            .any(|f| f.code.as_str() == "mel_system")
    );
}
