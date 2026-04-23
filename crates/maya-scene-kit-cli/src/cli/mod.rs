use std::path::PathBuf;

mod args;
mod cmd;
pub(crate) mod fs;
mod issues_artifacts;
mod output_contracts;
mod render;
mod runtime_context;

#[cfg(test)]
use self::issues_artifacts::{
    attach_unknown_payload_blobs_from_raw_chunks, unknown_payload_digest_hex,
};
use self::{
    args::{build_parser, normalize_argv},
    cmd::{
        ScriptAuditArgs, parse_operation_mode, parse_path_kind, run_dump, run_inspect, run_paths,
        run_replace_paths, run_script_audit, run_script_clean, run_to_ascii,
    },
};

pub fn main(argv: Vec<String>) -> i32 {
    let normalized = normalize_argv(argv);
    let matches = build_parser()
        .try_get_matches_from(std::iter::once("maya-scene-kit".to_string()).chain(normalized));

    let matches = match matches {
        Ok(m) => m,
        Err(e) => {
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
            let _ = e.print();
            return code;
        }
    };

    match matches.subcommand() {
        Some(("inspect", m)) => {
            let path = m.get_one::<PathBuf>("path").unwrap();
            let max_depth = m.get_one::<usize>("max-depth").copied();
            let preview_bytes = *m.get_one::<usize>("preview-bytes").unwrap_or(&24);
            let at = m.get_one::<String>("at").map(|value| value.as_str());
            let max_bytes = m.get_one::<usize>("max-bytes").copied();
            run_inspect(path, max_depth, preview_bytes, at, max_bytes)
        }
        Some(("dump", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let out = m.get_one::<PathBuf>("out");
            let out_dir = m.get_one::<PathBuf>("out-dir");
            let node_info_paths = m
                .get_many::<PathBuf>("node-info")
                .map(|v| v.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let max_bytes = m.get_one::<usize>("max-bytes").copied();
            run_dump(input, out, out_dir, &node_info_paths, max_bytes)
        }
        Some(("paths", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let kind = parse_path_kind(
                m.get_one::<String>("kind")
                    .map(|s| s.as_str())
                    .unwrap_or("all"),
            );
            let out = m.get_one::<PathBuf>("out");
            let out_dir = m.get_one::<PathBuf>("out-dir");
            let json_output = m.get_flag("json");
            let node_info_paths = m
                .get_many::<PathBuf>("node-info")
                .map(|v| v.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let max_bytes = m.get_one::<usize>("max-bytes").copied();
            run_paths(
                input,
                kind,
                out,
                out_dir,
                json_output,
                &node_info_paths,
                max_bytes,
            )
        }
        Some(("audit", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let rules = m
                .get_many::<String>("rule")
                .map(|v| v.map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            let json_output = m.get_flag("json");
            let summary_only = m.get_flag("summary-only");
            let max_preview = *m.get_one::<usize>("max-preview").unwrap_or(&96);
            let node_info_paths = m
                .get_many::<PathBuf>("node-info")
                .map(|v| v.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let max_bytes = m.get_one::<usize>("max-bytes").copied();
            run_script_audit(ScriptAuditArgs {
                input,
                inline_rules: rules,
                json_output,
                summary_only,
                max_preview,
                node_info_paths: &node_info_paths,
                max_bytes,
            })
        }
        Some(("to-ascii", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let output = m.get_one::<PathBuf>("output").unwrap();
            let issues_json = m.get_one::<PathBuf>("issues-json");
            let node_info_paths = m
                .get_many::<PathBuf>("node-info")
                .map(|v| v.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let max_bytes = m.get_one::<usize>("max-bytes").copied();
            let embed_metadata = m.get_flag("embed-metadata");
            let write_unknown_blobs = m.get_flag("write-unknown-blobs");
            let mode = parse_operation_mode(
                m.get_one::<String>("mode")
                    .map(|s| s.as_str())
                    .unwrap_or("best-effort"),
            );
            run_to_ascii(
                input,
                output,
                issues_json,
                &node_info_paths,
                max_bytes,
                embed_metadata,
                write_unknown_blobs,
                mode,
            )
        }
        Some(("clean", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let output = m.get_one::<PathBuf>("output").unwrap();
            let node_info_paths = m
                .get_many::<PathBuf>("node-info")
                .map(|v| v.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let max_bytes = m.get_one::<usize>("max-bytes").copied();
            run_script_clean(input, output, &node_info_paths, max_bytes)
        }
        Some(("replace", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let out = m.get_one::<PathBuf>("out");
            let out_dir = m.get_one::<PathBuf>("out-dir");
            let rules_raw = m
                .get_many::<String>("rule")
                .map(|v| v.map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            let node_info_paths = m
                .get_many::<PathBuf>("node-info")
                .map(|v| v.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let max_bytes = m.get_one::<usize>("max-bytes").copied();
            run_replace_paths(input, out, out_dir, rules_raw, &node_info_paths, max_bytes)
        }
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        attach_unknown_payload_blobs_from_raw_chunks, build_parser, normalize_argv, run_paths,
        run_replace_paths, unknown_payload_digest_hex,
    };
    use crate::{
        cli::render::{
            json::{render_audit_hit_json, render_review_signal_json},
            text::{
                group_audit_hit_indexes, group_review_signal_indexes, render_audit_hit_text,
                render_grouped_audit_hit_text, render_grouped_review_signal_text,
                summarize_unit_reason,
            },
        },
        scene::{
            AuditEvidence, AuditEvidenceKey, AuditFindingCode, AuditFindingDetail, AuditHit,
            AuditReviewCode, AuditReviewDetail, AuditReviewSignal, Confidence,
            ExecutionEffectClass, ExecutionOrigin, ExecutionReason, ExecutionSemanticClass,
            ExecutionSurfaceKind, ExecutionTrigger, ExecutionUnitSummary, IssueKind,
            MayaAsciiIssue, PathKind, RawChunkDump, SceneFormat, StaticAuditFindingDetail,
            StaticAuditReviewDetail,
        },
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .to_path_buf()
    }

    #[test]
    fn parser_accepts_inspect_subcommand() {
        let matches = build_parser()
            .try_get_matches_from(["maya-scene-kit", "inspect", "tests/02/sphere.mb"])
            .expect("inspect matches");
        assert_eq!(matches.subcommand_name(), Some("inspect"));
    }

    #[test]
    fn normalize_argv_keeps_inspect_as_known_command() {
        let normalized = normalize_argv(vec![
            "inspect".to_string(),
            "tests/02/sphere.mb".to_string(),
        ]);
        assert_eq!(normalized[0], "inspect");
    }

    #[test]
    fn inspect_accepts_mb_input() {
        let code = super::main(vec![
            "inspect".to_string(),
            repo_root().join("tests/02/sphere.mb").display().to_string(),
        ]);
        assert_eq!(code, 0);
    }

    #[test]
    fn inspect_rejects_ma_input() {
        let code = super::main(vec![
            "inspect".to_string(),
            repo_root().join("tests/02/sphere.ma").display().to_string(),
        ]);
        assert_eq!(code, 1);
    }

    #[test]
    fn inspect_rejects_directory_input() {
        let code = super::main(vec![
            "inspect".to_string(),
            repo_root().join("tests/02").display().to_string(),
        ]);
        assert_eq!(code, 2);
    }

    #[test]
    fn attach_unknown_payload_blob_writes_blob_and_sets_ref() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let blob_dir_path = dir.path().join("issues.unknown_blobs");
        let blob_dir_name = "issues.unknown_blobs";

        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let digest = unknown_payload_digest_hex(&payload);

        let raw_chunks = vec![RawChunkDump {
            trace_form: "ATTR".to_string(),
            trace_tag: "ZZZZ".to_string(),
            trace_node_offset: 0x1000,
            trace_chunk_aux: Some(0xE7010000),
            trace_child_alignment: Some(8),
            trace_child_header_size: Some(16),
            payload: payload.clone(),
        }];

        let mut issues = vec![MayaAsciiIssue {
            node_type: "x".to_string(),
            node_name: "y".to_string(),
            kind: IssueKind::Unsupported,
            confidence: Confidence::Unknown,
            attr_name: "<unknown-chunk>".to_string(),
            reason: Some("test".to_string()),
            semantic_provenance: None,
            value_kind_hex: None,
            payload_size: Some(payload.len()),
            payload_digest_hex: Some(digest.clone()),
            payload_preview_hex: None,
            payload_inline_hex: None,
            payload_blob_ref: None,
            refedit_unknown_tail_offset: None,
            refedit_unknown_tail_opcode_hex: None,
            refedit_unknown_tail_payload_size: None,
            refedit_unknown_tail_payload_preview_hex: None,
            decoder_attempts: vec![],
            trace_form: Some("ATTR".to_string()),
            trace_tag: Some("ZZZZ".to_string()),
            trace_node_offset: Some(0x1000),
            trace_chunk_aux: Some(0xE7010000),
            trace_child_alignment: Some(8),
            trace_child_header_size: Some(16),
        }];

        attach_unknown_payload_blobs_from_raw_chunks(
            &raw_chunks,
            &blob_dir_path,
            blob_dir_name,
            &mut issues,
        );

        let expected_ref = format!("{blob_dir_name}/{digest}.bin");
        assert_eq!(
            issues[0].payload_blob_ref.as_deref(),
            Some(expected_ref.as_str())
        );
        let blob_file = blob_dir_path.join(format!("{digest}.bin"));
        let written = std::fs::read(blob_file).expect("blob exists");
        assert_eq!(written, payload);
    }

    #[test]
    fn unknown_payload_digest_uses_sha256_hex_shape() {
        let digest = unknown_payload_digest_hex(b"maya-scene-kit");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn render_audit_hit_omits_preview_when_empty() {
        let hit = AuditHit {
            code: AuditFindingCode::MelPython,
            severity: crate::scene::AuditSeverity::Medium,
            surface_index: 0,
            sink: crate::scene::AuditSinkKind::MelPython,
            rule: Some("python(".to_string()),
            detail: AuditFindingDetail::Static {
                value: StaticAuditFindingDetail::MelPythonLiteralBridgeNotAutoAllowed,
            },
            evidence: vec![],
            preview_override: None,
        };
        let report = crate::scene::AuditReport {
            scene_path: PathBuf::from("a.ma"),
            scene_format: SceneFormat::Ma,
            profile: crate::scene::AuditProfile::StrictDefault,
            validation_state: crate::scene::ValidationState::Validated,
            effective_rules: vec![],
            surface_count: 1,
            coverage_state: crate::scene::ExecutionCoverageState::Complete,
            coverage_issues: vec![],
            blocked_on_uncertainty: false,
            disposition: crate::scene::AuditDisposition::DenyMalicious,
            unit_summaries: vec![],
            dependency_facts: vec![],
            unknown_semantics: vec![],
            digests: crate::scene::SceneDigestSet {
                scene_sha256: String::new(),
                schema_bundle_sha256: None,
                policy_bundle_sha256: None,
            },
            notices: vec![],
            surfaces: vec![crate::scene::AuditSurface {
                origin: crate::scene::ExecutionOrigin {
                    lang: crate::scene::ExecutionLanguage::Mel,
                    trigger: crate::scene::ExecutionTrigger::FileOpen,
                    surface_kind: crate::scene::ExecutionSurfaceKind::ScriptNodeBody,
                    node_name: Some("script1".to_string()),
                    attr_name: Some(".b".to_string()),
                    source_range: None,
                    source_kind: Some("scriptType=6".to_string()),
                    chunk_form: None,
                    chunk_tag: None,
                    chunk_node_offset: None,
                    ..crate::scene::ExecutionOrigin::without_chunk_address()
                },
                preview: String::new(),
                derivation: crate::scene::AuditSurfaceDerivation::Observed,
            }],
            review_signals: vec![],
            findings: vec![hit.clone()],
        };
        assert_eq!(
            render_audit_hit_text(&report, &hit),
            "- finding path=a.ma severity=medium sink=mel_python finding_id=mel_python node=script1 attr=.b chunk=-:-@- msg=\"MEL -> python(...) fixed-literal bridge is not auto-allowed\""
        );
        let json = render_audit_hit_json("a.ma", &report, &hit);
        assert!(json.get("preview").is_some());
    }

    #[test]
    fn render_audit_hit_includes_raw_chunk_addresses() {
        let hit = AuditHit {
            code: AuditFindingCode::UnknownExecutionLanguage,
            severity: crate::scene::AuditSeverity::High,
            surface_index: 0,
            sink: crate::scene::AuditSinkKind::None,
            rule: None,
            detail: AuditFindingDetail::Static {
                value: StaticAuditFindingDetail::ExecutionSurfaceLanguageCouldNotBeInferred,
            },
            evidence: vec![],
            preview_override: None,
        };
        let report = crate::scene::AuditReport {
            scene_path: PathBuf::from("a.mb"),
            scene_format: SceneFormat::Mb,
            profile: crate::scene::AuditProfile::StrictDefault,
            validation_state: crate::scene::ValidationState::Validated,
            effective_rules: vec![],
            surface_count: 1,
            coverage_state: crate::scene::ExecutionCoverageState::Incomplete,
            coverage_issues: vec![],
            blocked_on_uncertainty: true,
            disposition: crate::scene::AuditDisposition::DenyUncertain,
            unit_summaries: vec![],
            dependency_facts: vec![],
            unknown_semantics: vec![],
            digests: crate::scene::SceneDigestSet {
                scene_sha256: String::new(),
                schema_bundle_sha256: None,
                policy_bundle_sha256: None,
            },
            notices: vec![],
            surfaces: vec![crate::scene::AuditSurface {
                origin: crate::scene::ExecutionOrigin {
                    lang: crate::scene::ExecutionLanguage::Unknown,
                    trigger: crate::scene::ExecutionTrigger::FileOpen,
                    surface_kind: crate::scene::ExecutionSurfaceKind::RawChunkText,
                    node_name: None,
                    attr_name: None,
                    source_range: None,
                    source_kind: None,
                    chunk_form: Some("FRDI".to_string()),
                    chunk_tag: Some("FRDI".to_string()),
                    chunk_node_offset: Some(0x7A8),
                    chunk_aux: Some(0x2C010000),
                    chunk_payload_offset: Some(0x7CC),
                    chunk_payload_size: Some(0xFF),
                    chunk_child_alignment: Some(8),
                    chunk_child_header_size: Some(16),
                },
                preview: "Source".to_string(),
                derivation: crate::scene::AuditSurfaceDerivation::Observed,
            }],
            review_signals: vec![],
            findings: vec![hit.clone()],
        };

        let rendered = render_audit_hit_text(&report, &hit);
        assert!(rendered.contains("chunk=FRDI:FRDI@1960"));
        assert!(rendered.contains("addr=0x000007A8"));
        assert!(rendered.contains("payload=0x000007CC..0x000008CB"));
        assert!(rendered.contains("aux=0x2C010000"));
    }

    #[test]
    fn grouped_audit_hit_includes_count_and_evidence() {
        let hit = AuditHit {
            code: AuditFindingCode::MelCallbackFlag,
            severity: crate::scene::AuditSeverity::High,
            surface_index: 0,
            sink: crate::scene::AuditSinkKind::MelCallbackFlag,
            rule: None,
            detail: AuditFindingDetail::Static {
                value: StaticAuditFindingDetail::ScriptBearingMelCallbackFlagDetected,
            },
            evidence: vec![
                AuditEvidence::KeyValue {
                    key: AuditEvidenceKey::Command,
                    value: "nodeEditor".to_string(),
                },
                AuditEvidence::KeyValue {
                    key: AuditEvidenceKey::Flag,
                    value: "createNodeCommand".to_string(),
                },
            ],
            preview_override: None,
        };
        let report = crate::scene::AuditReport {
            scene_path: PathBuf::from("a.ma"),
            scene_format: SceneFormat::Ma,
            profile: crate::scene::AuditProfile::StrictDefault,
            validation_state: crate::scene::ValidationState::Validated,
            effective_rules: vec![],
            surface_count: 1,
            coverage_state: crate::scene::ExecutionCoverageState::Complete,
            coverage_issues: vec![],
            blocked_on_uncertainty: false,
            disposition: crate::scene::AuditDisposition::DenyMalicious,
            unit_summaries: vec![],
            dependency_facts: vec![],
            unknown_semantics: vec![],
            digests: crate::scene::SceneDigestSet {
                scene_sha256: String::new(),
                schema_bundle_sha256: None,
                policy_bundle_sha256: None,
            },
            notices: vec![],
            surfaces: vec![crate::scene::AuditSurface {
                origin: crate::scene::ExecutionOrigin {
                    lang: crate::scene::ExecutionLanguage::Mel,
                    trigger: crate::scene::ExecutionTrigger::FileOpen,
                    surface_kind: crate::scene::ExecutionSurfaceKind::ScriptNodeBody,
                    node_name: Some("script1".to_string()),
                    attr_name: Some(".b".to_string()),
                    source_range: None,
                    source_kind: Some("scriptType=6".to_string()),
                    chunk_form: None,
                    chunk_tag: None,
                    chunk_node_offset: None,
                    ..crate::scene::ExecutionOrigin::without_chunk_address()
                },
                preview: String::new(),
                derivation: crate::scene::AuditSurfaceDerivation::Observed,
            }],
            review_signals: vec![],
            findings: vec![hit.clone()],
        };

        assert_eq!(
            render_grouped_audit_hit_text("a.ma", &report, &hit, 2),
            "- finding path=a.ma count=2 severity=high sink=mel_callback_flag finding_id=mel_callback_flag node=script1 attr=.b chunk=-:-@- msg=\"script-bearing MEL callback flag detected\" evidence=\"command=nodeEditor; flag=createNodeCommand\""
        );
    }

    #[test]
    fn summarize_unit_reason_prefers_effect_matching_reason() {
        let summary = ExecutionUnitSummary {
            origin: ExecutionOrigin {
                lang: crate::scene::ExecutionLanguage::Mel,
                trigger: ExecutionTrigger::GuiOpenClose,
                surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
                node_name: Some("script1".to_string()),
                attr_name: Some(".b".to_string()),
                source_range: None,
                source_kind: None,
                chunk_form: None,
                chunk_tag: None,
                chunk_node_offset: None,
                ..ExecutionOrigin::without_chunk_address()
            },
            effect: ExecutionEffectClass::HookRegistration,
            semantic_class: ExecutionSemanticClass::General,
            certainty: crate::scene::EffectCertainty::Proven,
            preview: String::new(),
            reasons: vec![
                ExecutionReason::Named {
                    template: crate::scene::ExecutionReasonTemplate::UiImpactingMelCommandDetected,
                    value: "panel".to_string(),
                },
                ExecutionReason::FlagOnCommand {
                    flag_name: "createNodeCommand".to_string(),
                    command_name: "nodeEditor".to_string(),
                },
                ExecutionReason::Named {
                    template: crate::scene::ExecutionReasonTemplate::ReadOnlyMelCommandDetected,
                    value: "getPanel".to_string(),
                },
            ],
        };

        assert_eq!(
            summarize_unit_reason(&summary),
            "flag `createNodeCommand` on command `nodeEditor` detected (+2 more reasons)"
        );
    }

    #[test]
    fn group_audit_hit_indexes_collapses_duplicates() {
        let hit = AuditHit {
            code: AuditFindingCode::MelCallbackFlag,
            severity: crate::scene::AuditSeverity::High,
            surface_index: 0,
            sink: crate::scene::AuditSinkKind::MelCallbackFlag,
            rule: None,
            detail: AuditFindingDetail::Static {
                value: StaticAuditFindingDetail::ScriptBearingMelCallbackFlagDetected,
            },
            evidence: vec![AuditEvidence::KeyValue {
                key: AuditEvidenceKey::Command,
                value: "nodeEditor".to_string(),
            }],
            preview_override: None,
        };
        let report = crate::scene::AuditReport {
            scene_path: PathBuf::from("a.ma"),
            scene_format: SceneFormat::Ma,
            profile: crate::scene::AuditProfile::StrictDefault,
            validation_state: crate::scene::ValidationState::Validated,
            effective_rules: vec![],
            surface_count: 1,
            coverage_state: crate::scene::ExecutionCoverageState::Complete,
            coverage_issues: vec![],
            blocked_on_uncertainty: false,
            disposition: crate::scene::AuditDisposition::DenyMalicious,
            unit_summaries: vec![],
            dependency_facts: vec![],
            unknown_semantics: vec![],
            digests: crate::scene::SceneDigestSet {
                scene_sha256: String::new(),
                schema_bundle_sha256: None,
                policy_bundle_sha256: None,
            },
            notices: vec![],
            surfaces: vec![crate::scene::AuditSurface {
                origin: crate::scene::ExecutionOrigin {
                    lang: crate::scene::ExecutionLanguage::Mel,
                    trigger: crate::scene::ExecutionTrigger::FileOpen,
                    surface_kind: crate::scene::ExecutionSurfaceKind::ScriptNodeBody,
                    node_name: Some("script1".to_string()),
                    attr_name: Some(".b".to_string()),
                    source_range: None,
                    source_kind: Some("scriptType=6".to_string()),
                    chunk_form: None,
                    chunk_tag: None,
                    chunk_node_offset: None,
                    ..crate::scene::ExecutionOrigin::without_chunk_address()
                },
                preview: String::new(),
                derivation: crate::scene::AuditSurfaceDerivation::Observed,
            }],
            review_signals: vec![],
            findings: vec![hit.clone(), hit],
        };

        assert_eq!(group_audit_hit_indexes(&report), vec![(0, 2)]);
    }

    #[test]
    fn grouped_review_signal_includes_count_and_evidence() {
        let review = AuditReviewSignal {
            code: AuditReviewCode::MelCallbackProcReference,
            surface_index: 0,
            detail: AuditReviewDetail::Static {
                value: StaticAuditReviewDetail::MelCallbackProcReferenceDetected,
            },
            evidence: vec![
                AuditEvidence::KeyValue {
                    key: AuditEvidenceKey::Command,
                    value: "nodeEditor".to_string(),
                },
                AuditEvidence::KeyValue {
                    key: AuditEvidenceKey::Flag,
                    value: "createNodeCommand".to_string(),
                },
                AuditEvidence::KeyValue {
                    key: AuditEvidenceKey::CallbackTarget,
                    value: "nodeEdCreateNodeCommand".to_string(),
                },
            ],
            preview_override: None,
        };
        let report = crate::scene::AuditReport {
            scene_path: PathBuf::from("a.ma"),
            scene_format: SceneFormat::Ma,
            profile: crate::scene::AuditProfile::StrictDefault,
            validation_state: crate::scene::ValidationState::Validated,
            effective_rules: vec![],
            surface_count: 1,
            coverage_state: crate::scene::ExecutionCoverageState::Complete,
            coverage_issues: vec![],
            blocked_on_uncertainty: false,
            disposition: crate::scene::AuditDisposition::Review,
            unit_summaries: vec![],
            dependency_facts: vec![],
            unknown_semantics: vec![],
            digests: crate::scene::SceneDigestSet {
                scene_sha256: String::new(),
                schema_bundle_sha256: None,
                policy_bundle_sha256: None,
            },
            notices: vec![],
            surfaces: vec![crate::scene::AuditSurface {
                origin: crate::scene::ExecutionOrigin {
                    lang: crate::scene::ExecutionLanguage::Mel,
                    trigger: crate::scene::ExecutionTrigger::FileOpen,
                    surface_kind: crate::scene::ExecutionSurfaceKind::ScriptNodeBody,
                    node_name: Some("script1".to_string()),
                    attr_name: Some(".b".to_string()),
                    source_range: None,
                    source_kind: Some("scriptType=6".to_string()),
                    chunk_form: None,
                    chunk_tag: None,
                    chunk_node_offset: None,
                    ..crate::scene::ExecutionOrigin::without_chunk_address()
                },
                preview: String::new(),
                derivation: crate::scene::AuditSurfaceDerivation::Observed,
            }],
            review_signals: vec![review.clone(), review.clone()],
            findings: vec![],
        };

        assert_eq!(group_review_signal_indexes(&report), vec![(0, 2)]);
        assert_eq!(
            render_grouped_review_signal_text("a.ma", &report, &review, 2),
            "- review path=a.ma count=2 review_id=mel_callback_proc_reference node=script1 attr=.b chunk=-:-@- msg=\"MEL callback flag references a proc name; offline behavior remains runtime-dependent\" evidence=\"command=nodeEditor; flag=createNodeCommand; callback_target=nodeEdCreateNodeCommand\""
        );
        let json = render_review_signal_json("a.ma", &report, &review);
        assert_eq!(
            json["review_id"].as_str(),
            Some("mel_callback_proc_reference")
        );
    }

    #[test]
    fn grouped_inline_callback_review_signal_renders_new_review_id() {
        let review = AuditReviewSignal {
            code: AuditReviewCode::MelCallbackBody,
            surface_index: 0,
            detail: AuditReviewDetail::Static {
                value: StaticAuditReviewDetail::MelCallbackBodyDetected,
            },
            evidence: vec![
                AuditEvidence::KeyValue {
                    key: AuditEvidenceKey::Command,
                    value: "modelEditor".to_string(),
                },
                AuditEvidence::KeyValue {
                    key: AuditEvidenceKey::Flag,
                    value: "editorChanged".to_string(),
                },
                AuditEvidence::KeyValue {
                    key: AuditEvidenceKey::CallbackTarget,
                    value: "print \"ok\";".to_string(),
                },
            ],
            preview_override: None,
        };
        let report = crate::scene::AuditReport {
            scene_path: PathBuf::from("a.ma"),
            scene_format: SceneFormat::Ma,
            profile: crate::scene::AuditProfile::StrictDefault,
            validation_state: crate::scene::ValidationState::Validated,
            effective_rules: vec![],
            surface_count: 1,
            coverage_state: crate::scene::ExecutionCoverageState::Complete,
            coverage_issues: vec![],
            blocked_on_uncertainty: true,
            disposition: crate::scene::AuditDisposition::Review,
            unit_summaries: vec![],
            dependency_facts: vec![],
            unknown_semantics: vec![],
            digests: crate::scene::SceneDigestSet {
                scene_sha256: String::new(),
                schema_bundle_sha256: None,
                policy_bundle_sha256: None,
            },
            notices: vec![],
            surfaces: vec![crate::scene::AuditSurface {
                origin: crate::scene::ExecutionOrigin {
                    lang: crate::scene::ExecutionLanguage::Mel,
                    trigger: crate::scene::ExecutionTrigger::FileOpen,
                    surface_kind: crate::scene::ExecutionSurfaceKind::ScriptNodeBody,
                    node_name: Some("script1".to_string()),
                    attr_name: Some(".b".to_string()),
                    source_range: None,
                    source_kind: Some("scriptType=1".to_string()),
                    chunk_form: None,
                    chunk_tag: None,
                    chunk_node_offset: None,
                    ..crate::scene::ExecutionOrigin::without_chunk_address()
                },
                preview: String::new(),
                derivation: crate::scene::AuditSurfaceDerivation::Observed,
            }],
            review_signals: vec![review.clone(), review.clone()],
            findings: vec![],
        };

        assert_eq!(group_review_signal_indexes(&report), vec![(0, 2)]);
        assert_eq!(
            render_grouped_review_signal_text("a.ma", &report, &review, 2),
            "- review path=a.ma count=2 review_id=mel_callback_body node=script1 attr=.b chunk=-:-@- msg=\"MEL callback flag embeds inline script body; derived sink findings determine deny behavior\" evidence=\"command=modelEditor; flag=editorChanged; callback_target=print \"ok\";\""
        );
        let json = render_review_signal_json("a.ma", &report, &review);
        assert_eq!(json["review_id"].as_str(), Some("mel_callback_body"));
    }

    #[test]
    fn to_ascii_write_unknown_blobs_flag_defaults_to_false() {
        let matches = build_parser()
            .try_get_matches_from(["maya-scene-kit", "to-ascii", "in.mb", "out.ma"])
            .expect("parse");
        let (_, sub) = matches.subcommand().expect("subcommand");
        assert!(!sub.get_flag("write-unknown-blobs"));
    }

    #[test]
    fn replace_accepts_directory_input_with_single_scene_and_out_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let input_dir = dir.path().join("input");
        let output_dir = dir.path().join("output");
        std::fs::create_dir_all(&input_dir).expect("mkdir");

        let source = repo_root().join("tests/02/sphere.ma");
        let input_file = input_dir.join("sphere.ma");
        std::fs::copy(&source, &input_file).expect("copy fixture");

        let exit = run_replace_paths(
            &input_dir,
            None,
            Some(&output_dir),
            vec!["persp=perspRenamed".to_string()],
            &[],
            None,
        );
        assert_eq!(exit, 0);
        assert!(output_dir.join("sphere.ma").exists());
    }

    #[test]
    fn clean_rejects_mode_flag() {
        let err = build_parser()
            .try_get_matches_from([
                "maya-scene-kit",
                "clean",
                "in.ma",
                "out.ma",
                "--mode",
                "forensic",
            ])
            .expect_err("expected parse failure");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn replace_rejects_mode_flag() {
        let err = build_parser()
            .try_get_matches_from([
                "maya-scene-kit",
                "replace",
                "in.ma",
                "--rule",
                "a=b",
                "--out",
                "out.ma",
                "--mode",
                "forensic",
            ])
            .expect_err("expected parse failure");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn audit_rejects_removed_rule_filter_flags() {
        for argv in [
            vec![
                "maya-scene-kit",
                "audit",
                "in.ma",
                "--rule-file",
                "rules.txt",
            ],
            vec!["maya-scene-kit", "audit", "in.ma", "--ignore-case"],
            vec!["maya-scene-kit", "audit", "in.ma", "--regex"],
            vec!["maya-scene-kit", "audit", "in.ma", "--only-hit-nodes"],
        ] {
            let err = build_parser()
                .try_get_matches_from(argv)
                .expect_err("expected parse failure");
            assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn replace_rejects_rule_file_flag() {
        let err = build_parser()
            .try_get_matches_from([
                "maya-scene-kit",
                "replace",
                "in.ma",
                "--rule-file",
                "rules.txt",
                "--out",
                "out.ma",
            ])
            .expect_err("expected parse failure");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn inspect_accepts_max_bytes_flag() {
        let matches = build_parser()
            .try_get_matches_from(["maya-scene-kit", "inspect", "in.mb", "--max-bytes", "1234"])
            .expect("parse");
        let (_, sub) = matches.subcommand().expect("subcommand");
        assert_eq!(sub.get_one::<usize>("max-bytes").copied(), Some(1234));
    }

    #[test]
    fn clean_and_replace_accept_common_loading_flags() {
        let clean = build_parser()
            .try_get_matches_from([
                "maya-scene-kit",
                "clean",
                "in.mb",
                "out.mb",
                "--node-info",
                "plugin.yaml",
                "--max-bytes",
                "1234",
            ])
            .expect("clean parse");
        let (_, clean_sub) = clean.subcommand().expect("clean subcommand");
        assert_eq!(
            clean_sub
                .get_many::<PathBuf>("node-info")
                .expect("node info")
                .count(),
            1
        );
        assert_eq!(clean_sub.get_one::<usize>("max-bytes").copied(), Some(1234));

        let replace = build_parser()
            .try_get_matches_from([
                "maya-scene-kit",
                "replace",
                "in.mb",
                "--rule",
                "a=b",
                "--out",
                "out.mb",
                "--node-info",
                "plugin.yaml",
                "--max-bytes",
                "5678",
            ])
            .expect("replace parse");
        let (_, replace_sub) = replace.subcommand().expect("replace subcommand");
        assert_eq!(
            replace_sub
                .get_many::<PathBuf>("node-info")
                .expect("node info")
                .count(),
            1
        );
        assert_eq!(
            replace_sub.get_one::<usize>("max-bytes").copied(),
            Some(5678)
        );
    }

    #[test]
    fn normalize_argv_leaves_path_like_input_unchanged() {
        let argv = vec!["tests/02/sphere.ma".to_string()];
        assert_eq!(normalize_argv(argv.clone()), argv);
    }

    #[test]
    fn paths_accepts_directory_input_with_single_scene_and_out_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let input_dir = dir.path().join("input");
        let output_dir = dir.path().join("output");
        std::fs::create_dir_all(&input_dir).expect("mkdir");

        let source = repo_root().join("tests/02/sphere.ma");
        let input_file = input_dir.join("sphere.ma");
        std::fs::copy(&source, &input_file).expect("copy fixture");

        let exit = run_paths(
            &input_dir,
            PathKind::All,
            None,
            Some(&output_dir),
            false,
            &[],
            None,
        );
        assert_eq!(exit, 0);
        assert!(output_dir.join("sphere.ma.scene_paths.txt").exists());
    }

    #[test]
    fn audit_and_paths_accept_opaque_typed_ascii_scene() {
        let source = repo_root().join("tests/fixtures/ma/opaque_typed_attrs.ma");

        let audit_code = super::main(vec![
            "audit".to_string(),
            source.display().to_string(),
            "--summary-only".to_string(),
        ]);
        assert_eq!(audit_code, 0);

        let paths_code = super::main(vec!["paths".to_string(), source.display().to_string()]);
        assert_eq!(paths_code, 0);
    }
}
