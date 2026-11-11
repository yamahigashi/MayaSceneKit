use std::{cell::RefCell, collections::VecDeque, time::SystemTime};

use sha2::{Digest, Sha256};

use super::loader::{LoadOptions, Loader};
use crate::scene::{ExecutionCoverageIssueDetail, ExecutionCoverageState, SceneToolError};

#[derive(Default)]
pub(super) struct Supply {
    pub bodies: VecDeque<Vec<u8>>,
    pub calls: usize,
    pub opens: usize,
    pub sniffs: usize,
    pub states: VecDeque<Option<(u64, Option<SystemTime>)>>,
}

thread_local! {
    pub(super) static SUPPLY: RefCell<Option<Supply>> = const { RefCell::new(None) };
}

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        SUPPLY.with(|s| *s.borrow_mut() = None);
        TRACE.with(|t| *t.borrow_mut() = None);
    }
}

fn supply(bodies: Vec<Vec<u8>>, states: Vec<Option<(u64, Option<SystemTime>)>>) -> Reset {
    SUPPLY.with(|s| {
        *s.borrow_mut() = Some(Supply {
            bodies: bodies.into(),
            calls: 0,
            opens: 0,
            sniffs: 0,
            states: states.into(),
        })
    });
    Reset
}

fn calls() -> usize {
    SUPPLY.with(|s| s.borrow().as_ref().unwrap().calls)
}

const EXAMPLE: &[u8] = concat!(
    "//Maya ASCII 2026 scene\n",
    "createNode script -n \"ExampleScript\";\n",
    "setAttr \".b\" -type \"string\" \"print(1);\";\n",
    "setAttr \".st\" 1;\n",
    "select -ne :defaultRenderGlobals;\n",
    "setAttr \".poam\" -type \"string\" \"ExampleCallback;\";\n",
)
.as_bytes();

#[test]
fn released_execution_digest_uses_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    std::fs::write(&path, EXAMPLE).unwrap();
    let changed = b"//Maya ASCII 2026 scene\n";
    let _reset = supply(vec![EXAMPLE.to_vec(), changed.to_vec()], vec![]);
    let retained = Loader::new(LoadOptions::default())
        .observe_path(&path)
        .unwrap();
    let _reset = supply(vec![EXAMPLE.to_vec(), changed.to_vec()], vec![]);
    let observation = Loader::new(LoadOptions::default())
        .observe_execution_path(&path)
        .unwrap();
    std::fs::write(&path, changed).unwrap();
    assert!(observation.cached_ma_bytes_ptr().is_none());
    for preview in [0, 96] {
        assert_eq!(
            observation.scene_digests(preview).unwrap().scene_sha256,
            format!("{:x}", Sha256::digest(EXAMPLE))
        );
    }
    assert!(observation.cached_ma_bytes_ptr().is_none());
    assert_eq!(calls(), 1);
    assert_eq!(
        retained.scene_digests(0).unwrap().scene_sha256,
        format!("{:x}", Sha256::digest(EXAMPLE))
    );
    assert_eq!(
        retained.script_node_entries().unwrap()[0].name,
        "ExampleScript"
    );
    assert!(
        retained
            .observed_execution_catalog(96)
            .unwrap()
            .surfaces
            .iter()
            .any(|surface| surface.surface.text.contains("print(1)"))
    );
    assert!(
        retained
            .observed_execution_catalog(96)
            .unwrap()
            .surfaces
            .iter()
            .any(
                |surface| surface.surface.origin.attr_name.as_deref() == Some(".poam")
                    && surface.surface.text.contains("ExampleCallback")
            )
    );
    assert_eq!(calls(), 1);
}

#[test]
fn over_budget_ma_does_not_read_body() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    let mut bytes = EXAMPLE.to_vec();
    bytes.resize(2048, b' ');
    std::fs::write(&path, &bytes).unwrap();
    let _reset = supply(vec![bytes], vec![]);
    let result = Loader::new(LoadOptions::default().with_max_parse_bytes(1024)).observe_path(&path);
    assert!(matches!(
        result,
        Err(SceneToolError::MelParseBudgetExceeded { .. })
    ));
    assert_eq!(calls(), 0);
    let mut exact = b"//Maya ASCII 2026 scene\n".to_vec();
    exact.resize(1024, b' ');
    std::fs::write(&path, &exact).unwrap();
    let _reset = supply(vec![exact.clone()], vec![]);
    assert!(
        Loader::new(LoadOptions::default().with_max_parse_bytes(1024))
            .observe_path(&path)
            .is_ok()
    );
    assert_eq!(calls(), 1);
    exact.push(b' ');
    let _reset = supply(vec![exact], vec![]);
    assert!(matches!(
        Loader::new(LoadOptions::default().with_max_parse_bytes(1024)).observe_path(&path),
        Err(SceneToolError::MelParseBudgetExceeded { .. })
    ));
    assert_eq!(calls(), 1);
}

#[test]
fn changed_read_has_fixed_coverage_issue() {
    let dir = tempfile::tempdir().unwrap();
    let mut binary = b"FOR4".to_vec();
    binary.extend_from_slice(&4u32.to_be_bytes());
    binary.extend_from_slice(b"Maya");
    for (name, bytes) in [("Example.ma", EXAMPLE.to_vec()), ("Example.mb", binary)] {
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        let len = bytes.len() as u64;
        let time = SystemTime::UNIX_EPOCH;
        for (after, changed) in [
            (Some((len + 1, Some(time))), true),
            (
                Some((len, Some(time + std::time::Duration::from_secs(1)))),
                true,
            ),
            (Some((len, None)), true),
            (None, true),
            (Some((len, Some(time))), false),
        ] {
            let _reset = supply(vec![bytes.clone()], vec![Some((len, Some(time))), after]);
            let observation = Loader::new(LoadOptions::default())
                .observe_analysis_path(&path)
                .unwrap();
            let catalog = observation
                .observed_execution_catalog_with_digests(96, false)
                .unwrap();
            let issues: Vec<_> = catalog.coverage_issues.iter().filter(|issue| matches!(&issue.detail, ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic } if diagnostic == "scene file changed while it was being read")).collect();
            assert_eq!(issues.len(), usize::from(changed));
            if changed {
                assert_ne!(catalog.coverage_state, ExecutionCoverageState::Complete);
                assert!(issues[0].origin.is_none());
                assert_eq!(
                    issues[0].preview,
                    "scene file changed while it was being read"
                );
            }
            if changed {
                assert!(
                    observation
                        .observed_execution_catalog_with_digests(0, false)
                        .unwrap()
                        .coverage_issues
                        .iter()
                        .any(|issue| issue.preview == "scene file changed while it was being read")
                );
            }
            assert!(catalog.digests.scene_sha256.is_empty());
            assert_eq!(calls(), 1);
        }
    }
    let unsupported = b"//Maya ASCII 2026 scene\nglobal proc Example() {}\n";
    let path = dir.path().join("Example.ma");
    std::fs::write(&path, unsupported).unwrap();
    let _reset = supply(
        vec![unsupported.to_vec()],
        vec![Some((unsupported.len() as u64, None)), None],
    );
    let catalog = Loader::new(LoadOptions::default())
        .observe_analysis_path(&path)
        .unwrap()
        .observed_execution_catalog(96)
        .unwrap();
    assert_eq!(catalog.coverage_state, ExecutionCoverageState::Unsupported);
}

#[test]
fn light_digest_does_not_reacquire_released_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    std::fs::write(&path, EXAMPLE).unwrap();
    let _reset = supply(vec![EXAMPLE.to_vec(), EXAMPLE.to_vec()], vec![]);
    let observation = Loader::new(LoadOptions::default())
        .observe_path_without_retained_ma_bytes(&path)
        .unwrap();
    assert!(observation.scene_digests(96).is_err());
    assert!(observation.cached_ma_bytes_ptr().is_none());
    assert_eq!(calls(), 1);
}

#[test]
fn invalid_input_does_not_prepare_schema() {
    let dir = tempfile::tempdir().unwrap();
    let options =
        LoadOptions::default().with_chunk_schema_root(dir.path().join("ExampleMissingSchema"));
    let missing = dir.path().join("ExampleMissing.ma");
    let unknown = dir.path().join("ExampleUnknown.ma");
    std::fs::write(&unknown, b"Example unknown format").unwrap();
    for execution in [false, true] {
        for (path, absent) in [(&missing, true), (&unknown, false)] {
            let loader = Loader::new(options.clone());
            let result = if execution {
                loader.observe_execution_path(path).map(|_| ())
            } else {
                loader.observe_path(path).map(|_| ())
            };
            if absent {
                assert!(
                    matches!(result, Err(SceneToolError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
                );
            } else {
                assert!(matches!(
                    result,
                    Err(SceneToolError::UnsupportedSceneFormat { .. })
                ));
            }
            assert!(!loader.has_cached_schema_context());
        }
    }
    for (name, bytes) in [
        ("Example.ma", EXAMPLE.to_vec()),
        ("Example.mb", binary_example()),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        let _reset = trace(Trace::default());
        Loader::new(LoadOptions::default())
            .observe_analysis_path(&path)
            .unwrap();
        TRACE.with(|t| {
            assert_eq!(
                t.borrow().as_ref().unwrap().events,
                [
                    ReadEvent::Open,
                    ReadEvent::Metadata,
                    ReadEvent::Sniff,
                    ReadEvent::Schema,
                    ReadEvent::Body,
                    ReadEvent::BodyDone(bytes.len()),
                    ReadEvent::Metadata
                ]
            )
        });
    }
}

#[test]
fn missing_before_metadata_marks_read_unstable() {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("Example.ma", EXAMPLE.to_vec()),
        ("Example.mb", binary_example()),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        for after in [Some((bytes.len() as u64, None)), None] {
            let _reset = supply(vec![bytes.clone()], vec![None, after]);
            let observation = Loader::new(LoadOptions::default())
                .observe_analysis_path(&path)
                .unwrap();
            assert_eq!(
                observation.source_snapshot().identity.stability(),
                super::snapshot::ReadStability::Unstable
            );
            let catalog = observation.observed_execution_catalog(96).unwrap();
            assert!(catalog.coverage_issues.iter().any(|issue| matches!(&issue.detail, ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic } if diagnostic == "scene file changed while it was being read")));
            SUPPLY.with(|s| {
                let s = s.borrow();
                let s = s.as_ref().unwrap();
                assert_eq!((s.opens, s.sniffs, s.calls), (1, 1, 1));
                assert!(s.states.is_empty());
            });
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReadEvent {
    Open,
    Metadata,
    Sniff,
    Schema,
    Body,
    BodyDone(usize),
}

#[derive(Default)]
struct Trace {
    events: Vec<ReadEvent>,
    after_body: Option<Box<dyn FnOnce()>>,
    after_sniff: Option<Box<dyn FnOnce()>>,
}

thread_local! {
    static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) };
}

pub(super) fn record(event: ReadEvent) {
    SUPPLY.with(|s| {
        if let Some(s) = s.borrow_mut().as_mut() {
            match event {
                ReadEvent::Open => s.opens += 1,
                ReadEvent::Sniff => s.sniffs += 1,
                _ => {}
            }
        }
    });
    let callback = TRACE.with(|t| {
        t.borrow_mut().as_mut().and_then(|t| {
            let callback = match event {
                ReadEvent::Sniff => t.after_sniff.take(),
                ReadEvent::BodyDone(_) => t.after_body.take(),
                _ => None,
            };
            t.events.push(event);
            callback
        })
    });
    if let Some(callback) = callback {
        callback();
    }
}

fn trace(trace: Trace) -> Reset {
    TRACE.with(|t| *t.borrow_mut() = Some(trace));
    Reset
}

fn binary_example() -> Vec<u8> {
    let mut bytes = b"FOR4".to_vec();
    bytes.extend_from_slice(&4u32.to_be_bytes());
    bytes.extend_from_slice(b"Maya");
    bytes
}

#[test]
fn real_body_read_obeys_budget_and_precedes_after_metadata() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    let limit = 2048;
    let mut bytes = b"//Maya ASCII 2026 scene\n".to_vec();
    bytes.resize(limit, b' ');
    std::fs::write(&path, &bytes).unwrap();
    let append_path = path.clone();
    let _reset = trace(Trace {
        after_body: Some(Box::new(move || {
            std::fs::OpenOptions::new()
                .append(true)
                .open(append_path)
                .unwrap()
                .write_all(b" ")
                .unwrap();
        })),
        ..Trace::default()
    });
    let observation = Loader::new(LoadOptions::default().with_max_parse_bytes(limit))
        .observe_path(&path)
        .unwrap();
    assert_eq!(
        observation.source_snapshot().identity.stability(),
        super::snapshot::ReadStability::Unstable
    );
    TRACE.with(|t| {
        assert_eq!(
            t.borrow().as_ref().unwrap().events,
            [
                ReadEvent::Open,
                ReadEvent::Metadata,
                ReadEvent::Sniff,
                ReadEvent::Body,
                ReadEvent::BodyDone(limit),
                ReadEvent::Metadata
            ]
        )
    });
    let _reset = trace(Trace::default());
    let result =
        Loader::new(LoadOptions::default().with_max_parse_bytes(limit)).observe_path(&path);
    assert!(matches!(
        result,
        Err(SceneToolError::MelParseBudgetExceeded {
            limit: crate::scene::MelParseBudgetLimit::MaxBytes
        })
    ));
    TRACE.with(|t| {
        assert!(
            !t.borrow()
                .as_ref()
                .unwrap()
                .events
                .contains(&ReadEvent::Body)
        )
    });
    std::fs::write(&path, &bytes).unwrap();
    let append_path = path.clone();
    let _reset = trace(Trace {
        after_sniff: Some(Box::new(move || {
            std::fs::OpenOptions::new()
                .append(true)
                .open(append_path)
                .unwrap()
                .write_all(&[b' '; 4096])
                .unwrap();
        })),
        ..Trace::default()
    });
    assert!(matches!(
        Loader::new(LoadOptions::default().with_max_parse_bytes(limit)).observe_path(&path),
        Err(SceneToolError::MelParseBudgetExceeded {
            limit: crate::scene::MelParseBudgetLimit::MaxBytes
        })
    ));
    TRACE.with(|t| {
        assert!(
            t.borrow()
                .as_ref()
                .unwrap()
                .events
                .contains(&ReadEvent::BodyDone(limit + 1))
        )
    });
}

#[test]
fn bytes_input_has_no_file_state_or_change_issue() {
    use crate::scene::{SceneFormat, ValidationState};
    for (format, bytes) in [
        (SceneFormat::Ma, EXAMPLE.to_vec()),
        (SceneFormat::Mb, binary_example()),
    ] {
        let _reset = supply(vec![], vec![None]);
        let observation = Loader::new(LoadOptions::default())
            .observe_analysis_bytes("Example", format, ValidationState::Validated, bytes)
            .unwrap();
        assert_eq!(
            observation.source_snapshot().identity.stability(),
            super::snapshot::ReadStability::Absent
        );
        assert!(!observation.observed_execution_catalog(96).unwrap().coverage_issues.iter().any(|issue| matches!(&issue.detail, ExecutionCoverageIssueDetail::TopLevelDiagnostics { diagnostic } if diagnostic == "scene file changed while it was being read")));
        SUPPLY.with(|s| {
            let s = s.borrow();
            let s = s.as_ref().unwrap();
            assert_eq!((s.opens, s.sniffs, s.calls), (0, 0, 0));
            assert_eq!(s.states.len(), 1);
        });
    }
}

#[test]
fn binary_digest_uses_acquired_bytes_after_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    let bytes = binary_example();
    std::fs::write(&path, &bytes).unwrap();
    let _reset = supply(vec![bytes.clone()], vec![]);
    let observation = Loader::new(LoadOptions::default())
        .observe_analysis_path(&path)
        .unwrap();
    std::fs::write(&path, b"Example replacement").unwrap();
    assert_eq!(
        observation.scene_digests(0).unwrap().scene_sha256,
        format!("{:x}", Sha256::digest(&bytes))
    );
    SUPPLY.with(|s| {
        let s = s.borrow();
        let s = s.as_ref().unwrap();
        assert_eq!((s.opens, s.sniffs, s.calls), (1, 1, 1));
    });
}

#[test]
fn over_budget_binary_sniffs_once_without_reading_body() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    let mut bytes = binary_example();
    bytes.resize(2048, 0);
    std::fs::write(&path, &bytes).unwrap();
    let _reset = supply(vec![], vec![]);
    assert!(matches!(
        Loader::new(LoadOptions::default().with_max_parse_bytes(1024)).observe_analysis_path(&path),
        Err(SceneToolError::MbParseBudgetExceeded {
            limit: crate::mb::MbParseBudgetLimit::MaxParseBytes
        })
    ));
    SUPPLY.with(|s| {
        let s = s.borrow();
        let s = s.as_ref().unwrap();
        assert_eq!((s.opens, s.sniffs, s.calls), (1, 1, 0));
    });
}

#[test]
fn unstable_reads_do_not_create_cache_snapshots() {
    use crate::scene::ObservedSceneSnapshot;
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("Example.ma", EXAMPLE.to_vec()),
        ("Example.mb", b"FOR4\0\0\0\x04Maya".to_vec()),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        let len = bytes.len() as u64;
        let time = SystemTime::UNIX_EPOCH;
        for after in [
            Some((len + 1, Some(time))),
            Some((len, Some(time + std::time::Duration::from_secs(1)))),
            Some((len, None)),
            None,
        ] {
            let _reset = supply(vec![bytes.clone()], vec![Some((len, Some(time))), after]);
            let options = LoadOptions::default();
            let observation = Loader::new(options.clone())
                .observe_analysis_path(&path)
                .unwrap();
            assert!(ObservedSceneSnapshot::from_observation(&observation, &options).is_err());
        }
    }
}
