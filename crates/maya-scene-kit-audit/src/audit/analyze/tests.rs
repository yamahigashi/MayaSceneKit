use std::sync::Arc;

use maya_scene_kit_observe::scene::execution::collect_mel_surface_facts;

use super::{
    AnalysisSurface, analyze_mel_surface,
    mel::find_mel_call,
    text_scan::{
        contains_ascii_word_case_insensitive, extract_mel_literal_call_body,
        obfuscation_marker_base_severity, scan_mel_sink_word_hits,
    },
};
use crate::scene::{
    AuditSeverity, AuditSurfaceDerivation, ExecutionLanguage, ExecutionOrigin,
    ExecutionSurfaceKind, ExecutionTrigger,
    execution::{MelSurfaceCall, MelSurfaceCallSurfaceKind, MelSurfaceFacts},
};

#[test]
fn mel_literal_call_body_allows_space_before_parenthesis() {
    assert_eq!(
        extract_mel_literal_call_body("python(\"print('hello')\")", "python"),
        Some("print('hello')".to_string())
    );
    assert_eq!(
        extract_mel_literal_call_body("python (\"print('hello')\")", "python"),
        Some("print('hello')".to_string())
    );
    assert_eq!(
        extract_mel_literal_call_body("python ('print(\"hello\")')", "python"),
        Some("print(\"hello\")".to_string())
    );
    assert_eq!(
        extract_mel_literal_call_body("python(\"import sub\" + \"process\")", "python"),
        Some("import subprocess".to_string())
    );
    assert_eq!(
        extract_mel_literal_call_body("python ( 'print(' + \"\\\"hello\\\"\" + ')' )", "python"),
        Some("print(\"hello\")".to_string())
    );
}

#[test]
fn ascii_word_lookup_matches_sink_names_case_insensitively() {
    assert!(contains_ascii_word_case_insensitive(
        "exec('print(1)')",
        "exec"
    ));
    assert!(contains_ascii_word_case_insensitive(
        "exec ('print(1)')",
        "exec"
    ));
    assert!(contains_ascii_word_case_insensitive(
        "commandPort -n \"x\";",
        "commandPort"
    ));
    assert!(!contains_ascii_word_case_insensitive(
        "execute('print(1)')",
        "exec"
    ));
}

#[test]
fn sink_word_scan_tracks_whole_word_hits_without_overlap() {
    let hits = scan_mel_sink_word_hits(
        "python(\"ok\"); evalDeferred(\"later\"); reevaluateNode; scriptJob -e \"x\"; commandPort -n \"y\";",
    );

    assert!(hits.contains("python"));
    assert!(hits.contains("evalDeferred"));
    assert!(!hits.contains("eval"));
    assert!(hits.contains("scriptJob"));
    assert!(hits.contains("commandPort"));
}

#[test]
fn parser_backed_lookup_matches_call_name_case_insensitively() {
    let surface = AnalysisSurface {
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
        })),
    };

    let call = find_mel_call(&surface, "Source").expect("parser-backed source call");
    assert_eq!(call.literal_first_arg.as_deref(), Some("evil.mel"));
}

#[test]
fn callback_inline_body_emits_review_signal_and_derived_surface() {
    let surface = AnalysisSurface {
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
}

#[test]
fn bare_identifier_callback_flag_emits_review_signal_only() {
    let surface = AnalysisSurface {
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
}

#[test]
fn empty_braced_callback_flag_is_ignored() {
    let surface = AnalysisSurface {
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
fn obfuscation_marker_severity_tiers_strong_and_weak_markers() {
    assert_eq!(
        obfuscation_marker_base_severity(&["base64".to_string()]),
        AuditSeverity::Critical
    );
    assert_eq!(
        obfuscation_marker_base_severity(&["format(".to_string()]),
        AuditSeverity::High
    );
    assert_eq!(
        obfuscation_marker_base_severity(&[" + ".to_string(), "format(".to_string()]),
        AuditSeverity::Critical
    );
}
