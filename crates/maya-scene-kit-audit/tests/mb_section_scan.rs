use std::path::Path;

use maya_scene_kit_observe::scene::{
    LoadOptions, Loader,
    core::{SceneFormat, ValidationState},
    evidence::ExecutionCoverageIssueDetail,
};

fn chunk(tag: &[u8; 4], payload: &[u8], wide: bool) -> Vec<u8> {
    let mut out = tag.to_vec();
    if wide {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    } else {
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(payload);
    while out.len() % if wide { 8 } else { 4 } != 0 {
        out.push(0);
    }
    out
}
fn form(name: &[u8; 4], children: &[Vec<u8>], wide: bool) -> Vec<u8> {
    let mut payload = name.to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    let mut out = chunk(if wide { b"FOR8" } else { b"FOR4" }, &payload, wide);
    out.truncate(if wide { 16 } else { 8 } + payload.len());
    out
}

#[test]
fn script_body_after_nonprintable_tag_is_observed() {
    for wide in [true, false] {
        let bytes = form(
            b"Maya",
            &[form(
                b"SCRP",
                &[
                    chunk(b"CREA", b"ExampleScript\0", wide),
                    chunk(&[0, 0, 0, 1], &[], wide),
                    chunk(&[0, 0, 0, 2], b"print \"Example\";", wide),
                    chunk(b"STR ", b"b\0\0print \"Example\";\0", wide),
                ],
                wide,
            )],
            wide,
        );
        let observation = Loader::new(LoadOptions::default())
            .observe_execution_bytes(
                Path::new("Example.mb"),
                SceneFormat::Mb,
                ValidationState::Validated,
                bytes,
            )
            .unwrap();
        let catalog = observation.observed_execution_catalog(64).unwrap();
        assert!(
            catalog
                .surfaces
                .iter()
                .any(|s| s.surface.text.contains("Example"))
        );
        assert!(catalog.coverage_issues.is_empty());
    }
    for malformed in [
        b"DATA\0\0\0\x09X".as_slice(),
        b"DATA\0\0\0",
        b"DATA\0\0\0\x01X\0",
    ] {
        let bytes = form(
            b"Maya",
            &[form(
                b"SCRP",
                &[
                    chunk(b"CREA", b"ExampleScript\0", false),
                    chunk(&[0, 0, 0, 1], &[], false),
                    chunk(b"STR ", b"b\0\0print \"Example\";\0", false),
                    malformed.to_vec(),
                ],
                false,
            )],
            false,
        );
        let observation = Loader::new(LoadOptions::default())
            .observe_execution_bytes(
                Path::new("Example.mb"),
                SceneFormat::Mb,
                ValidationState::Validated,
                bytes,
            )
            .unwrap();
        let catalog = observation.observed_execution_catalog(64).unwrap();
        assert!(
            catalog
                .surfaces
                .iter()
                .any(|surface| surface.surface.text.contains("Example"))
        );
        assert_eq!(catalog.coverage_issues.len(), 1);
        assert!(
            matches!(&catalog.coverage_issues[0].detail, ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason } if reason.contains("Malformed") && !reason.contains("MB section scan stopped"))
        );
    }
}

#[test]
fn complete_mixed_width_tree_reports_one_scan_stop() {
    let mut nested = b"TESTDATA\0\0\0\x01X".to_vec();
    nested.extend_from_slice(&[0; 7]);
    let bytes = form(
        b"Maya",
        &[form(b"HEAD", &[chunk(b"FOR8", &nested, false)], false)],
        false,
    );
    assert_eq!(bytes.len(), 52);
    let observation = Loader::new(LoadOptions::default())
        .observe_execution_bytes(
            Path::new("Example.mb"),
            SceneFormat::Mb,
            ValidationState::Validated,
            bytes,
        )
        .unwrap();
    let catalog = observation.observed_execution_catalog(64).unwrap();
    assert_eq!(catalog.coverage_issues.len(), 1);
    let issue = &catalog.coverage_issues[0];
    assert!(issue.origin.is_none());
    assert!(
        matches!(&issue.detail, ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason } if reason == "MB section scan stopped")
    );
}

#[test]
fn root_leaf_has_no_section_issue() {
    let observation = Loader::new(LoadOptions::default())
        .observe_execution_bytes(
            Path::new("Example.mb"),
            SceneFormat::Mb,
            ValidationState::Validated,
            form(b"Maya", &[chunk(b"DATA", b"ABCDEFGH", false)], false),
        )
        .unwrap();
    assert!(
        observation
            .observed_execution_catalog(64)
            .unwrap()
            .coverage_issues
            .is_empty()
    );
}
