use maya_scene_kit_edit::scene::{
    ExecutionCleanTarget, PathOwnerDeleteTarget, PathReplaceOverride, SceneEditError,
    SceneEditIntent, SceneEditPlan, SceneEditStatus, save_staged_artifact, stage_scene_edit_plan,
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader,
    evidence::ExecutionSourceRange,
    paths::{PathKind, ScenePathsReport, SceneSourceFingerprint},
};

fn observation(path: &std::path::Path) -> (ScenePathsReport, SceneSourceFingerprint) {
    let observed = Loader::new(LoadOptions::default())
        .observe_path(path)
        .unwrap();
    let report = observed.scene_paths_report(PathKind::All).unwrap();
    let source = observed.source_fingerprint().unwrap();
    (report, source)
}

fn replacement(report: &ScenePathsReport, name: &str, after: &str) -> SceneEditIntent {
    let (entry_index, entry) = report
        .entries
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.node_name == name)
        .unwrap();
    SceneEditIntent::Path(PathReplaceOverride {
        entry_index,
        before_value: entry.value.clone(),
        after_value: after.into(),
    })
}

fn command(source: &str, text: &str) -> ExecutionCleanTarget {
    let start = source.find(text).unwrap();
    ExecutionCleanTarget::TopLevelCommand {
        source_range: ExecutionSourceRange {
            start,
            end: start + text.len(),
        },
    }
}

fn chunk(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

fn form(kind: &[u8; 4], parts: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = kind.to_vec();
    for part in parts {
        payload.extend_from_slice(part);
    }
    chunk(b"FOR4", &payload)
}

fn file(name: &str, value: &str) -> Vec<u8> {
    form(
        b"RTFT",
        &[
            chunk(b"CREA", format!("{name}\0").as_bytes()),
            chunk(b"STR ", format!("ftn\0\0{value}\0").as_bytes()),
        ],
    )
}

fn assert_single_operation_bytes(
    report: &ScenePathsReport,
    clean_source: &SceneSourceFingerprint,
    bytes: &[u8],
    intents: &[SceneEditIntent],
) {
    use maya_scene_kit_edit::scene::{
        stage_clean_execution_targets, stage_delete_path_owner_nodes,
        stage_replace_scene_paths_with_overrides_in_report,
    };
    for intent in intents {
        let plan = SceneEditPlan {
            report: report.clone(),
            clean_source: Some(clean_source.clone()),
            intents: vec![intent.clone()],
        };
        let composed = stage_scene_edit_plan(&plan, bytes).unwrap();
        let original = match intent {
            SceneEditIntent::Path(value) => {
                stage_replace_scene_paths_with_overrides_in_report(
                    report,
                    std::slice::from_ref(value),
                )
                .unwrap()
                .artifact
            }
            SceneEditIntent::Clean(target) => {
                stage_clean_execution_targets(&report.scene_path, std::slice::from_ref(target))
                    .unwrap()
                    .artifact
            }
            SceneEditIntent::DeleteOwner(target) => {
                stage_delete_path_owner_nodes(&report.scene_path, std::slice::from_ref(target))
                    .unwrap()
                    .artifact
            }
        };
        assert_eq!(composed.artifact.bytes, original.bytes);
    }
}

const ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

#[test]
fn ascii_length_changes_and_all_intent_orders_save_original_targets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = concat!(
        "//Maya ASCII 2026 scene\n",
        "createNode file -n \"Example\";\n",
        "setAttr \".ftn\" -type \"string\" \"asset/example/file.tx\";\n",
        "python(\"print('Example')\");\n",
        "createNode file -n \"Sample\";\n",
        "setAttr \".ftn\" -type \"string\" \"asset/example/other.tx\";\n",
        "currentUnit -l centimeter;\n",
    );
    std::fs::write(&path, source).unwrap();
    let (report, clean_source) = observation(&path);
    for after in ["asset/example/longer_file_name.tx", "a.tx"] {
        let intents = [
            replacement(&report, "Example", after),
            SceneEditIntent::Clean(command(source, "python(\"print('Example')\");")),
            SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
                node_type: "file".into(),
                node_name: "Sample".into(),
            }),
        ];
        assert_single_operation_bytes(&report, &clean_source, source.as_bytes(), &intents);
        let mut baseline = None;
        for order in ORDERS {
            let plan = SceneEditPlan {
                report: report.clone(),
                clean_source: Some(clean_source.clone()),
                intents: order.map(|i| intents[i].clone()).into(),
            };
            let staged = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
            let expected = source
                .replace("asset/example/file.tx", after)
                .replace("python(\"print('Example')\");", "")
                .replace("createNode file -n \"Sample\";\n", "");
            assert_eq!(staged.artifact.bytes, expected.as_bytes());
            assert_eq!(staged.changes.path_replacements.replacement_count, 1);
            assert_eq!(staged.changes.physical_deletion_count, 2);
            let output = dir.path().join("Sample.ma");
            save_staged_artifact(&staged.artifact, &output).unwrap();
            assert_eq!(std::fs::read(output).unwrap(), expected.as_bytes());
            let result = (staged.artifact.bytes, staged.changes);
            if let Some(baseline) = &baseline {
                assert_eq!(baseline, &result);
            }
            baseline = Some(result);
        }
    }
}

#[test]
fn binary_length_changes_and_all_intent_orders_save_original_forms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.mb");
    let original = file("Example", "asset/example/file.tx");
    let script = form(b"SCRP", &[chunk(b"CREA", b"ExampleScript\0")]);
    let source = form(
        b"Maya",
        &[
            original.clone(),
            script,
            file("Sample", "asset/example/other.tx"),
        ],
    );
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    for after in ["asset/example/longer_file_name.tx", "a.tx"] {
        let intents = [
            replacement(&report, "Example", after),
            SceneEditIntent::Clean(ExecutionCleanTarget::MbOwnerForm {
                form: "SCRP".into(),
                node_offset: 12 + original.len(),
            }),
            SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
                node_type: "file".into(),
                node_name: "Sample".into(),
            }),
        ];
        assert_single_operation_bytes(&report, &clean_source, &source, &intents);
        let mut baseline = None;
        for order in ORDERS {
            let plan = SceneEditPlan {
                report: report.clone(),
                clean_source: Some(clean_source.clone()),
                intents: order.map(|i| intents[i].clone()).into(),
            };
            let staged = stage_scene_edit_plan(&plan, &source).unwrap();
            let expected = form(b"Maya", &[file("Example", after)]);
            assert_eq!(staged.artifact.bytes, expected);
            assert_eq!(staged.changes.path_replacements.replacement_count, 1);
            assert_eq!(staged.changes.physical_deletion_count, 2);
            let output = dir.path().join("Sample.mb");
            save_staged_artifact(&staged.artifact, &output).unwrap();
            assert_eq!(std::fs::read(output).unwrap(), expected);
            let result = (staged.artifact.bytes, staged.changes);
            if let Some(baseline) = &baseline {
                assert_eq!(baseline, &result);
            }
            baseline = Some(result);
        }
    }
}

#[test]
fn owner_deletion_and_duplicate_clean_respect_path_containment() {
    for binary in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(if binary {
            "TestScene.mb"
        } else {
            "TestScene.ma"
        });
        let source = if binary {
            form(b"Maya", &[file("Example", "asset/example/file.tx")])
        } else {
            b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/file.tx\";\n".to_vec()
        };
        std::fs::write(&path, &source).unwrap();
        let (report, clean_source) = observation(&path);
        let clean = if binary {
            ExecutionCleanTarget::MbOwnerForm {
                form: "RTFT".into(),
                node_offset: 12,
            }
        } else {
            command(
                std::str::from_utf8(&source).unwrap(),
                "createNode file -n \"Example\";\n",
            )
        };
        let intents = [
            replacement(&report, "Example", "asset/example/changed.tx"),
            SceneEditIntent::Clean(clean.clone()),
            SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
                node_type: "file".into(),
                node_name: "Example".into(),
            }),
        ];
        let mut first = None;
        for order in ORDERS {
            let mut ordered = order.map(|index| intents[index].clone()).to_vec();
            ordered.push(SceneEditIntent::Clean(clean.clone()));
            let plan = SceneEditPlan {
                intents: ordered,
                report: report.clone(),
                clean_source: Some(clean_source.clone()),
            };
            let staged = stage_scene_edit_plan(&plan, &source).unwrap();
            assert_eq!(
                staged.changes.path_replacements.replacement_count,
                usize::from(!binary)
            );
            assert_eq!(
                staged.changes.superseded_path_override_count,
                usize::from(binary)
            );
            assert_eq!(staged.changes.physical_deletion_count, 1);
            assert_eq!(staged.preview.cleaned_targets.len(), 1);
            assert_eq!(staged.preview.deleted_path_owner_targets.len(), 1);
            let path_status = if binary {
                SceneEditStatus::Superseded
            } else {
                SceneEditStatus::Applied
            };
            assert!(staged.changes.records.iter().any(|record| {
                matches!(record.intent, SceneEditIntent::Path(_)) && record.status == path_status
            }));
            let expected = if binary {
                form(b"Maya", &[])
            } else {
                String::from_utf8(source.clone())
                    .unwrap()
                    .replace("createNode file -n \"Example\";\n", "")
                    .replace("asset/example/file.tx", "asset/example/changed.tx")
                    .into_bytes()
            };
            let output = dir
                .path()
                .join(if binary { "Sample.mb" } else { "Sample.ma" });
            save_staged_artifact(&staged.artifact, &output).unwrap();
            assert_eq!(std::fs::read(output).unwrap(), expected);
            if let Some(first) = &first {
                assert_eq!(&staged, first);
            } else {
                first = Some(staged);
            }
        }
    }
}

#[test]
fn callback_and_path_share_one_original_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let header = "//Maya ASCII 2026 scene\n";
    let file =
        "file -r -rfn \"Example\" -command \"onLoad\" \"print(1)\" \"asset/example/Example.ma\";\n";
    let source = format!("{header}{file}");
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    let plan = SceneEditPlan {
        intents: vec![
            replacement(&report, "Example", "asset/example/longer.ma"),
            SceneEditIntent::Clean(ExecutionCleanTarget::FileCommandCallback {
                source_range: ExecutionSourceRange {
                    start: header.len(),
                    end: source.len(),
                },
            }),
        ],
        report,
        clean_source: Some(clean_source),
    };
    let staged = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
    assert_eq!(
        staged.artifact.bytes,
        format!("{header}file -r -rfn \"Example\" \"asset/example/longer.ma\";\n").as_bytes()
    );
    assert_eq!(staged.changes.path_replacements.replacement_count, 1);
}

#[test]
fn stale_missing_filtered_and_foreign_sources_are_rejected_without_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = b"//Maya ASCII 2026 scene\ncurrentUnit -l centimeter;\n";
    std::fs::write(&path, source).unwrap();
    let (report, clean_source) = observation(&path);
    let plan = SceneEditPlan {
        report,
        clean_source: Some(clean_source),
        intents: vec![],
    };
    assert!(matches!(
        stage_scene_edit_plan(&plan, source),
        Err(SceneEditError::NoEffectiveEdits { .. })
    ));
    let mut missing = plan.clone();
    missing.report.source = None;
    assert!(matches!(
        stage_scene_edit_plan(&missing, source),
        Err(SceneEditError::MissingSource { .. })
    ));
    let mut different = source.to_vec();
    different[1] = b' ';
    assert!(matches!(
        stage_scene_edit_plan(&plan, &different),
        Err(SceneEditError::SourceMismatch { .. })
    ));
    different.push(b' ');
    assert!(matches!(
        stage_scene_edit_plan(&plan, &different),
        Err(SceneEditError::SourceLengthMismatch { .. })
    ));
    let mut foreign = plan.clone();
    foreign.clean_source = Some(SceneSourceFingerprint {
        sha256: "0".repeat(64),
        byte_len: source.len(),
    });
    foreign.intents.push(SceneEditIntent::Clean(command(
        std::str::from_utf8(source).unwrap(),
        "currentUnit -l centimeter;",
    )));
    assert!(matches!(
        stage_scene_edit_plan(&foreign, source),
        Err(SceneEditError::SourceMismatch { .. })
    ));
    let mut filtered = plan;
    filtered.report.kind = Some(PathKind::File);
    assert!(matches!(
        stage_scene_edit_plan(&filtered, source),
        Err(SceneEditError::FilteredReport)
    ));
    assert!(!dir.path().join("Sample.ma").exists());
}

#[test]
fn invalid_ranges_missing_deletions_and_incomplete_binary_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = b"//Maya ASCII 2026 scene\ncurrentUnit -l centimeter;\n";
    std::fs::write(&path, source).unwrap();
    let (report, clean_source) = observation(&path);
    for target in [
        ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange { start: 9, end: 8 },
        },
        ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange {
                start: 9,
                end: 9999,
            },
        },
        ExecutionCleanTarget::ScriptNode {
            node_name: "Sample".into(),
        },
    ] {
        let plan = SceneEditPlan {
            report: report.clone(),
            clean_source: Some(clean_source.clone()),
            intents: vec![SceneEditIntent::Clean(target)],
        };
        assert!(matches!(
            stage_scene_edit_plan(&plan, source),
            Err(SceneEditError::InvalidTarget { .. })
        ));
    }
    let bytes = b"FOR4\0\0\0\x18MayaFOR4\0\0\0\x04SCRPDATA\0\0\0\x20";
    let mut report = report;
    report.scene_format = maya_scene_kit_observe::scene::SceneFormat::Mb;
    report.source = None;
    let plan = SceneEditPlan {
        report,
        clean_source: None,
        intents: vec![],
    };
    assert!(matches!(
        stage_scene_edit_plan(&plan, bytes),
        Err(SceneEditError::Binary(_))
    ));
    assert!(!dir.path().join("Sample.ma").exists());
}

#[test]
fn touching_commands_empty_literals_and_fragment_rejection_use_original_ranges() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = "//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"\";\npython(\"print('Example')\");python(\"print('Sample')\");\n";
    std::fs::write(&path, source).unwrap();
    let (report, clean_source) = observation(&path);
    let first = command(source, "python(\"print('Example')\");");
    let second = command(source, "python(\"print('Sample')\");");
    let mut plan = SceneEditPlan {
        intents: vec![
            replacement(&report, "Example", "asset/example/file.tx"),
            SceneEditIntent::Clean(first.clone()),
            SceneEditIntent::Clean(second),
        ],
        report,
        clean_source: Some(clean_source),
    };
    let staged = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
    assert_eq!(staged.changes.path_replacements.replacement_count, 1);
    assert_eq!(staged.changes.physical_deletion_count, 2);
    let ExecutionCleanTarget::TopLevelCommand { source_range } = first else {
        unreachable!()
    };
    let insertion = source.find("\"\";").unwrap() + 1;
    for range in [
        source_range.start + 1..source_range.end + 1,
        source_range.start + 1..source_range.end - 1,
        insertion..insertion + 2,
        insertion - 1..insertion,
    ] {
        plan.intents.push(SceneEditIntent::Clean(
            ExecutionCleanTarget::TopLevelCommand {
                source_range: ExecutionSourceRange {
                    start: range.start,
                    end: range.end,
                },
            },
        ));
        assert!(matches!(
            stage_scene_edit_plan(&plan, source.as_bytes()),
            Err(SceneEditError::InvalidTarget { .. })
        ));
        plan.intents.pop();
    }
    plan.intents.truncate(1);
    plan.intents.push(SceneEditIntent::Clean(command(
        source,
        "setAttr \".ftn\" -type \"string\" \"\";",
    )));
    let staged = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
    assert_eq!(staged.changes.superseded_path_override_count, 1);
    let output = dir.path().join("Sample.ma");
    save_staged_artifact(&staged.artifact, &output).unwrap();
    assert_eq!(
        std::fs::read(output).unwrap(),
        source
            .replace("setAttr \".ftn\" -type \"string\" \"\";", "")
            .as_bytes()
    );
}

#[test]
fn duplicate_overrides_and_callback_containing_deletion_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = "//Maya ASCII 2026 scene\nfile -r -rfn \"Example\" -command \"onLoad\" \"print(1)\" \"asset/example/Example.ma\";\n";
    std::fs::write(&path, source).unwrap();
    let (report, clean_source) = observation(&path);
    let intent = replacement(&report, "Example", "asset/example/Sample.ma");
    let mut plan = SceneEditPlan {
        report,
        clean_source: Some(clean_source),
        intents: vec![intent.clone(), intent],
    };
    assert!(matches!(
        stage_scene_edit_plan(&plan, source.as_bytes()),
        Err(SceneEditError::DuplicateOverride { .. })
    ));
    plan.intents.truncate(1);
    let start = source.find("file -r").unwrap();
    plan.intents.push(SceneEditIntent::Clean(
        ExecutionCleanTarget::FileCommandCallback {
            source_range: ExecutionSourceRange {
                start,
                end: source.len(),
            },
        },
    ));
    plan.intents.push(SceneEditIntent::Clean(
        ExecutionCleanTarget::TopLevelCommand {
            source_range: ExecutionSourceRange {
                start: start + 1,
                end: source.len() - 1,
            },
        },
    ));
    assert!(matches!(
        stage_scene_edit_plan(&plan, source.as_bytes()),
        Err(SceneEditError::InvalidTarget { .. })
    ));
    assert!(!dir.path().join("Sample.ma").exists());
}

#[test]
fn reference_entry_reports_mixed_physical_records_without_double_counting() {
    use maya_scene_kit_edit::scene::ScenePathOutcome;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.mb");
    let fref = form(
        b"FREF",
        &[chunk(
            b"FREF",
            b"asset/example/Example.mb\0Example\0ExampleRN\0mayaBinary\0",
        )],
    );
    let frdi = form(b"FRDI", &[chunk(b"FRDI", b"\x01\x04\0\x02asset/example/Example.mb\0Example\0\x01\0ExampleRN\0VERS|2026|\0mayaBinary\0")]);
    let source = form(b"Maya", &[fref.clone(), frdi]);
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    assert_eq!(report.entries.len(), 1);
    let plan = SceneEditPlan {
        intents: vec![
            SceneEditIntent::Path(PathReplaceOverride {
                entry_index: 0,
                before_value: report.entries[0].value.clone(),
                after_value: "asset/example/Sample.mb".into(),
            }),
            SceneEditIntent::Clean(ExecutionCleanTarget::MbOwnerForm {
                form: "FREF".into(),
                node_offset: 12,
            }),
        ],
        report,
        clean_source: Some(clean_source),
    };
    let staged = stage_scene_edit_plan(&plan, &source).unwrap();
    assert_eq!(staged.changes.path_replacements.replacement_count, 1);
    assert_eq!(staged.changes.superseded_path_override_count, 0);
    assert_eq!(
        staged.changes.path_entries[0].outcome,
        ScenePathOutcome::Mixed
    );
    let expected = form(b"Maya", &[form(b"FRDI", &[chunk(b"FRDI", b"\x01\x04\0\x02asset/example/Sample.mb\0Example\0\x01\0ExampleRN\0VERS|2026|\0mayaBinary\0")])]);
    assert_eq!(staged.artifact.bytes, expected);
}

#[test]
fn surviving_owner_path_checks_encoding_and_preserves_non_utf8_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let mut source = b"//Maya ASCII 2026 scene\n//Codeset: 932\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/file.tx\";\ncreateNode transform -n \"Sample".to_vec();
    source.extend_from_slice(&[0x83, 0x5c]);
    source.extend_from_slice(b"\";\n");
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    let plan = SceneEditPlan {
        intents: vec![
            replacement(&report, "Example", "asset/example/😀.tx"),
            SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
                node_type: "file".into(),
                node_name: "Example".into(),
            }),
        ],
        report,
        clean_source: Some(clean_source),
    };
    let staged = stage_scene_edit_plan(&plan, &source).unwrap();
    assert_eq!(
        staged
            .changes
            .path_replacements
            .skipped
            .unwrap()
            .unrepresentable,
        1
    );
    assert_eq!(staged.changes.superseded_path_override_count, 0);
    assert_eq!(staged.changes.path_replacements.replacement_count, 0);
    let path_record = staged
        .changes
        .records
        .iter()
        .find(|record| matches!(record.intent, SceneEditIntent::Path(_)))
        .unwrap();
    assert_eq!(path_record.status, SceneEditStatus::Skipped);
    assert_eq!(path_record.superseded_by, None);
    assert!(staged.artifact.bytes.ends_with(b"Sample\x83\x5c\";\n"));
    assert!(
        staged
            .artifact
            .bytes
            .windows(b"asset/example/file.tx".len())
            .any(|part| part == b"asset/example/file.tx")
    );
}

#[test]
fn binary_owner_locator_must_belong_to_the_requested_original_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.mb");
    let first = file("Example", "asset/example/file.tx");
    let source = form(
        b"Maya",
        &[first.clone(), file("Sample", "asset/example/other.tx")],
    );
    std::fs::write(&path, &source).unwrap();
    let (mut report, clean_source) = observation(&path);
    report.entries[0].meta.as_mut().unwrap().trace_node_offset = Some(12 + first.len());
    let plan = SceneEditPlan {
        report,
        clean_source: Some(clean_source),
        intents: vec![SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
            node_type: "file".into(),
            node_name: "Example".into(),
        })],
    };
    assert!(matches!(
        stage_scene_edit_plan(&plan, &source),
        Err(SceneEditError::InvalidTarget { .. })
    ));
}

#[test]
fn deleted_concatenated_literal_is_not_counted_as_an_encoding_skip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = "//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" (\"asset/\" + \"example/file.tx\");\n";
    std::fs::write(&path, source).unwrap();
    let (report, clean_source) = observation(&path);
    let start = source.find("setAttr").unwrap();
    let plan = SceneEditPlan {
        intents: vec![
            replacement(&report, "Example", "asset/example/Sample.tx"),
            SceneEditIntent::Clean(ExecutionCleanTarget::TopLevelCommand {
                source_range: ExecutionSourceRange {
                    start,
                    end: source.len() - 1,
                },
            }),
        ],
        report,
        clean_source: Some(clean_source),
    };
    let staged = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
    assert_eq!(staged.changes.path_replacements.skipped.unwrap().total(), 0);
    assert_eq!(staged.changes.superseded_path_override_count, 1);
    let output = dir.path().join("Sample.ma");
    save_staged_artifact(&staged.artifact, &output).unwrap();
    assert_eq!(
        std::fs::read(output).unwrap(),
        b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\n\n"
    );
}

#[test]
fn combined_deletions_preserve_original_command_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let prefix = "//Maya ASCII 2026 scene\ncreateNode script -n \"ExampleScript\";\n    setAttr \".b\" -type \"string\" \"print(1)\";\n";
    let command = "python(\"print('Example')\");";
    let source = format!("{prefix}{command}\ncurrentUnit -l centimeter;\n");
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    let plan = SceneEditPlan {
        report,
        clean_source: Some(clean_source),
        intents: vec![
            SceneEditIntent::Clean(ExecutionCleanTarget::ScriptNode {
                node_name: "ExampleScript".into(),
            }),
            SceneEditIntent::Clean(ExecutionCleanTarget::TopLevelCommand {
                source_range: ExecutionSourceRange {
                    start: prefix.len(),
                    end: prefix.len() + command.len(),
                },
            }),
        ],
    };
    let staged = stage_scene_edit_plan(&plan, source.as_bytes()).unwrap();
    assert_eq!(
        staged.artifact.bytes,
        b"//Maya ASCII 2026 scene\n\ncurrentUnit -l centimeter;\n"
    );
}

#[test]
fn callback_composition_preserves_cp932_path_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let header = b"//Maya ASCII 2026 scene\n//Codeset: 932\n";
    let file = b"file -r -rfn \"Example\" -command \"onLoad\" \"print(1)\" \"asset/example/\x83\x5c.ma\";\n";
    let source = [header.as_slice(), file.as_slice()].concat();
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    let plan = SceneEditPlan {
        intents: vec![
            replacement(&report, "Example", "asset/example/ソ-longer.ma"),
            SceneEditIntent::Clean(ExecutionCleanTarget::FileCommandCallback {
                source_range: ExecutionSourceRange {
                    start: header.len(),
                    end: source.len(),
                },
            }),
        ],
        report,
        clean_source: Some(clean_source),
    };
    let staged = stage_scene_edit_plan(&plan, &source).unwrap();
    let output = dir.path().join("Sample.ma");
    save_staged_artifact(&staged.artifact, &output).unwrap();
    assert_eq!(
        std::fs::read(output).unwrap(),
        [
            header.as_slice(),
            b"file -r -rfn \"Example\" \"asset/example/\x83\x5c-longer.ma\";\n",
        ]
        .concat()
    );
    assert_eq!(staged.changes.path_replacements.replacement_count, 1);
}

#[test]
fn command_deletion_rejects_literal_and_multibyte_fragments() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = b"//Maya ASCII 2026 scene\n//Codeset: 932\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/\x83\x5c.ma\";\n";
    std::fs::write(&path, source).unwrap();
    let (report, clean_source) = observation(&path);
    let literal = source
        .windows(6)
        .position(|bytes| bytes == b"asset/")
        .unwrap();
    let trail = source.iter().position(|byte| *byte == 0x83).unwrap() + 1;
    for range in [literal..literal + 6, trail..trail + 1] {
        let plan = SceneEditPlan {
            report: report.clone(),
            clean_source: Some(clean_source.clone()),
            intents: vec![SceneEditIntent::Clean(
                ExecutionCleanTarget::TopLevelCommand {
                    source_range: ExecutionSourceRange {
                        start: range.start,
                        end: range.end,
                    },
                },
            )],
        };
        assert!(matches!(
            stage_scene_edit_plan(&plan, source),
            Err(SceneEditError::InvalidTarget { .. })
        ));
        assert!(!dir.path().join("Sample.ma").exists());
    }
}

#[test]
fn composed_ascii_is_copied_unvalidated() {
    use maya_scene_kit_edit::scene::ValidationState;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/file.tx\";\n";
    std::fs::write(&path, source).unwrap();
    let (mut report, _) = observation(&path);
    report.validation_state = ValidationState::Validated;
    let plan = SceneEditPlan {
        intents: vec![replacement(&report, "Example", "asset/example/Sample.tx")],
        report,
        clean_source: None,
    };
    let staged = stage_scene_edit_plan(&plan, source).unwrap();
    assert_eq!(
        staged.preview.validation_state,
        ValidationState::CopiedUnvalidated
    );
    assert_eq!(
        staged.artifact.validation_state,
        ValidationState::CopiedUnvalidated
    );
}

#[test]
fn path_and_owner_edits_ignore_unrelated_clean_fingerprints() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let source = b"//Maya ASCII 2026 scene\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/file.tx\";\n";
    std::fs::write(&path, source).unwrap();
    let (report, _) = observation(&path);
    for intent in [
        replacement(&report, "Example", "asset/example/Sample.tx"),
        SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
            node_type: "file".into(),
            node_name: "Example".into(),
        }),
    ] {
        let plan = SceneEditPlan {
            report: report.clone(),
            clean_source: Some(SceneSourceFingerprint {
                sha256: "0".repeat(64),
                byte_len: source.len(),
            }),
            intents: vec![intent],
        };
        assert!(stage_scene_edit_plan(&plan, source).is_ok());
    }
}

#[test]
fn overlapping_binary_intents_report_physical_payloads_in_every_order() {
    use maya_scene_kit_edit::scene::{SceneEditLocator, ScenePathOutcome};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.mb");
    let fref_payload = b"asset/example/Example.mb\0Example\0ExampleRN\0mayaBinary\0";
    let frdi_payload = b"\x01\x04\0\x02asset/example/Example.mb\0Example\0\x01\0ExampleRN\0VERS|2026|\0mayaBinary\0";
    let after_payload = b"\x01\x04\0\x02asset/example/Sample.mb\0Example\0\x01\0ExampleRN\0VERS|2026|\0mayaBinary\0";
    let fref = form(b"FREF", &[chunk(b"FREF", fref_payload)]);
    let frdi = form(b"FRDI", &[chunk(b"FRDI", frdi_payload)]);
    let source = form(b"Maya", &[fref, frdi]);
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    assert_eq!(report.entries.len(), 1);
    let entry = &report.entries[0];
    let intents = [
        SceneEditIntent::Path(PathReplaceOverride {
            entry_index: 0,
            before_value: entry.value.clone(),
            after_value: "asset/example/Sample.mb".into(),
        }),
        SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
            node_type: entry.node_type.clone(),
            node_name: entry.node_name.clone(),
        }),
        SceneEditIntent::Clean(ExecutionCleanTarget::MbOwnerForm {
            form: "FREF".into(),
            node_offset: 12,
        }),
    ];
    let mut first = None;
    for order in ORDERS {
        let staged = stage_scene_edit_plan(
            &SceneEditPlan {
                report: report.clone(),
                clean_source: Some(clean_source.clone()),
                intents: order.map(|index| intents[index].clone()).into(),
            },
            &source,
        )
        .unwrap();
        assert_eq!(staged.changes.physical_deletion_count, 1);
        assert_eq!(staged.changes.path_replacements.replacement_count, 1);
        assert_eq!(
            staged.changes.path_entries[0].outcome,
            ScenePathOutcome::Mixed
        );
        let record = staged.changes.records.iter().find(|record| {
            matches!(&record.locator, SceneEditLocator::MbRecord { form, .. } if form == "FRDI")
        }).unwrap();
        assert_eq!(record.before, frdi_payload);
        assert_eq!(record.after, after_payload);
        let superseded = staged.changes.records.iter().find(|record| {
            matches!(&record.locator, SceneEditLocator::MbRecord { form, .. } if form == "FREF")
        }).unwrap();
        assert_eq!(superseded.before, fref_payload);
        assert_eq!(superseded.status, SceneEditStatus::Superseded);
        let expected = form(b"Maya", &[form(b"FRDI", &[chunk(b"FRDI", after_payload)])]);
        let output = dir.path().join("Sample.mb");
        save_staged_artifact(&staged.artifact, &output).unwrap();
        assert_eq!(std::fs::read(output).unwrap(), expected);
        if let Some(first) = &first {
            assert_eq!(&staged, first);
        } else {
            first = Some(staged);
        }
    }
}

#[test]
fn binary_completeness_and_fingerprints_precede_intent_validation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.mb");
    let incomplete = b"FOR4\0\0\0\x18MayaFOR4\0\0\0\x04SCRPDATA\0\0\0\x20";
    std::fs::write(&path, incomplete).unwrap();
    let (mut report, _) = observation(&path);
    assert_eq!(report.source.as_ref().unwrap().byte_len, incomplete.len());
    report.source = None;
    let plan = SceneEditPlan {
        report,
        clean_source: None,
        intents: vec![],
    };
    assert!(matches!(
        stage_scene_edit_plan(&plan, incomplete),
        Err(SceneEditError::Binary(_))
    ));

    let source = form(b"Maya", &[file("Example", "asset/example/file.tx")]);
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    let value = replacement(&report, "Example", "asset/example/Sample.tx");
    let mut plan = SceneEditPlan {
        report,
        clean_source: Some(clean_source),
        intents: vec![
            value.clone(),
            value,
            SceneEditIntent::Clean(ExecutionCleanTarget::MbOwnerForm {
                form: "RTFT".into(),
                node_offset: 12,
            }),
        ],
    };
    plan.clean_source.as_mut().unwrap().byte_len += 1;
    assert!(matches!(
        stage_scene_edit_plan(&plan, &source),
        Err(SceneEditError::SourceLengthMismatch { .. })
    ));
    plan.clean_source.as_mut().unwrap().byte_len -= 1;
    plan.clean_source.as_mut().unwrap().sha256 = "0".repeat(64);
    assert!(matches!(
        stage_scene_edit_plan(&plan, &source),
        Err(SceneEditError::SourceMismatch {
            source_kind: "clean"
        })
    ));
    plan.clean_source = None;
    assert!(matches!(
        stage_scene_edit_plan(&plan, &source),
        Err(SceneEditError::MissingSource {
            source_kind: "clean"
        })
    ));
    plan.clean_source = plan.report.source.clone();
    assert!(matches!(
        stage_scene_edit_plan(&plan, &source),
        Err(SceneEditError::DuplicateOverride { .. })
    ));
    assert!(!dir.path().join("Sample.mb").exists());
}

#[test]
fn plugin_and_path_records_preserve_payloads_in_every_order() {
    use maya_scene_kit_edit::scene::SceneEditLocator;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.mb");
    let plugin = b"ExamplePlugin\x001.0\0";
    let source = form(
        b"Maya",
        &[
            form(b"HEAD", &[chunk(b"PLUG", plugin)]),
            file("Example", "asset/example/file.tx"),
            file("Sample", "asset/example/other.tx"),
        ],
    );
    std::fs::write(&path, &source).unwrap();
    let (report, clean_source) = observation(&path);
    let intents = [
        replacement(&report, "Example", "asset/example/longer_file.tx"),
        SceneEditIntent::Clean(ExecutionCleanTarget::PluginRequire {
            rendered: "requires \"ExamplePlugin\" \"1.0\";".into(),
        }),
        SceneEditIntent::DeleteOwner(PathOwnerDeleteTarget {
            node_type: "file".into(),
            node_name: "Sample".into(),
        }),
    ];
    let mut first = None;
    for order in ORDERS {
        let plan = SceneEditPlan {
            report: report.clone(),
            clean_source: Some(clean_source.clone()),
            intents: order.map(|index| intents[index].clone()).into(),
        };
        let staged = stage_scene_edit_plan(&plan, &source).unwrap();
        let record = staged.changes.records.iter().find(|record| matches!(&record.locator, SceneEditLocator::MbRecord { form, .. } if form == "HEAD")).unwrap();
        assert_eq!(record.before, plugin);
        assert!(record.after.is_empty());
        let expected = form(
            b"Maya",
            &[
                form(b"HEAD", &[]),
                file("Example", "asset/example/longer_file.tx"),
            ],
        );
        let output = dir.path().join("Sample.mb");
        save_staged_artifact(&staged.artifact, &output).unwrap();
        assert_eq!(std::fs::read(output).unwrap(), expected);
        if let Some(first) = &first {
            assert_eq!(&staged, first);
        } else {
            first = Some(staged);
        }
    }
}

#[test]
fn owner_deletion_matches_observed_cp932_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let text = "//Maya ASCII 2026 scene\n//Codeset: 932\ncreateNode file -n \"Exampleサンプル\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/file.tx\";\n";
    let name = b"Example\x83\x54\x83\x93\x83\x76\x83\x8b";
    let bytes = [
        b"//Maya ASCII 2026 scene\n//Codeset: 932\ncreateNode file -n \"".as_slice(),
        name,
        b"\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/file.tx\";\n",
    ]
    .concat();
    std::fs::write(&path, &bytes).unwrap();
    let (report, _) = observation(&path);
    let entry = &report.entries[0];
    assert_eq!(entry.node_name, "Exampleサンプル");
    let target = PathOwnerDeleteTarget {
        node_type: entry.node_type.clone(),
        node_name: entry.node_name.clone(),
    };
    let plan = SceneEditPlan {
        report,
        clean_source: None,
        intents: vec![SceneEditIntent::DeleteOwner(target)],
    };
    let staged = stage_scene_edit_plan(&plan, &bytes).unwrap();
    let expected = text.replace("createNode file -n \"Exampleサンプル\";\n", "");
    assert_eq!(staged.artifact.bytes, expected.as_bytes());
}
