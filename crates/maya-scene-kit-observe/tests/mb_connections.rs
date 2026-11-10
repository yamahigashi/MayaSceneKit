#[path = "support/mb_connections.rs"]
mod fixture;
use std::path::Path;

use fixture::*;
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader,
    core::{SceneFormat, ValidationState},
    execution::ObservedExecutionCatalog,
};

fn catalog(bytes: Vec<u8>) -> ObservedExecutionCatalog {
    Loader::new(LoadOptions::default())
        .observe_analysis_bytes(
            Path::new("Example.mb"),
            SceneFormat::Mb,
            ValidationState::Validated,
            bytes,
        )
        .unwrap()
        .observed_execution_catalog(256)
        .unwrap()
}

#[test]
fn connected_body_has_destination_context_and_chunk_provenance() {
    let bytes = example(
        &[b"print('Example')"],
        ":ExampleSource.note",
        "ExampleScript.before",
        &[],
    );
    let result = catalog(bytes.clone());
    assert_eq!(result.surfaces.len(), 1);
    assert!(
        result.coverage_issues.is_empty(),
        "{:?}",
        result.coverage_issues
    );
    let origin = &result.surfaces[0].surface.origin;
    assert_eq!(origin.lang.as_str(), "python");
    assert_eq!(origin.trigger.as_str(), "file_open");
    assert_eq!(origin.attr_name.as_deref(), Some(".b"));
    assert_eq!(
        origin.connection_source_plug.as_deref(),
        Some("ExampleSource.note")
    );
    assert_eq!(origin.chunk_form.as_deref(), Some("CONS"));
    assert_eq!(origin.chunk_tag.as_deref(), Some("CWFL"));
    assert!(origin.chunk_payload_offset.is_some());
    assert!(origin.connection_range.is_some());
    assert!(origin.connection_source_range.is_some());
    let connection = origin.connection_range.unwrap();
    let source = origin.connection_source_range.unwrap();
    assert_eq!(&bytes[connection.start..connection.start + 4], b"CWFL");
    assert_eq!(&bytes[source.start..source.start + 4], b"STR ");
    assert_eq!(origin.chunk_payload_offset, Some(connection.start + 16));
    assert_eq!(origin.chunk_child_alignment, Some(8));
    assert_eq!(origin.chunk_child_header_size, Some(16));
}

#[test]
fn unresolved_sources_have_positioned_issues() {
    for (values, source, extra) in [
        (vec![], "ExampleSource.note", vec![]),
        (vec![b"Example".as_slice()], "Sample.note", vec![]),
        (vec![b"Example".as_slice()], "ExampleSource.note[0]", vec![]),
        (
            vec![b"Example".as_slice(), b"Sample"],
            "ExampleSource.note",
            vec![],
        ),
        (
            vec![b"Example".as_slice(), b""],
            "ExampleSource.note",
            vec![],
        ),
        (
            vec![b"Example".as_slice(), b"Example"],
            "ExampleSource.note",
            vec![],
        ),
        (
            vec![b"Example".as_slice()],
            "ExampleSource.note",
            vec![node("XFRM", "ExampleSource", &[])],
        ),
        (
            vec![b"Example".as_slice()],
            "ExampleSource.note",
            vec![form(
                "CONS",
                &[connection("Sample.note", "ExampleSource.note")],
            )],
        ),
        (vec![b"\xff".as_slice()], "ExampleSource.note", vec![]),
    ] {
        let result = catalog(example(&values, source, "ExampleScript.b", &extra));
        assert!(result.surfaces.is_empty());
        assert!(
            result.coverage_issues.iter().any(|issue| {
                let Some(origin) = &issue.origin else {
                    return false;
                };
                origin.chunk_tag.as_deref() == Some("CWFL")
                    && origin.chunk_payload_offset.is_some()
                    && origin.connection_range.is_some()
            }),
            "{source}: {:?}",
            result.coverage_issues
        );
    }
}

#[test]
fn connected_controls_and_direct_bodies_are_marked() {
    let result = catalog(scene(&[
        node(
            "XFRM",
            "ExampleSource",
            &[attr("STR ", "note", b"print('Example')")],
        ),
        script(&[attr("STR ", "b", b"print('Sample')")]),
        form(
            "CONS",
            &[
                connection("ExampleSource.note", "ExampleScript.b"),
                connection("ExampleSource.note", "ExampleScript.scriptType"),
            ],
        ),
    ]));
    assert_eq!(result.surfaces.len(), 2);
    assert!(result.surfaces[0].surface.origin.overwritten_by_connection);
    assert!(
        result
            .surfaces
            .iter()
            .all(|s| s.surface.origin.trigger.as_str() == "unknown"
                && s.surface.origin.lang.as_str() == "unknown")
    );
    assert!(result.coverage_issues.iter().any(|i| {
        i.origin
            .as_ref()
            .is_some_and(|o| o.chunk_tag.as_deref() == Some("CWFL"))
    }));
}

#[test]
fn normal_connections_and_empty_source_remain_empty() {
    let connections: Vec<_> = (0..10000)
        .map(|_| connection("ExampleSource.tx", "Sample.tx"))
        .collect();
    let normal = catalog(scene(&[form("CONS", &connections)]));
    assert!(normal.surfaces.is_empty());
    assert!(normal.coverage_issues.is_empty());
    let empty = catalog(example(
        &[b""],
        "ExampleSource.note",
        "ExampleScript.b",
        &[],
    ));
    assert!(empty.surfaces.is_empty());
    assert!(empty.coverage_issues.is_empty());
    for destination in [":perspShape.b", ":creasePartition.st"] {
        let result = catalog(scene(&[form(
            "CONS",
            &[connection("ExampleRig:ExampleSource.msg", destination)],
        )]));
        assert!(result.surfaces.is_empty());
        assert!(
            result.coverage_issues.is_empty(),
            "{destination}: {:?}",
            result.coverage_issues
        );
    }
    let mismatch = catalog(scene(&[
        node("XFRM", "ExampleSource", &[attr("STR ", "note", b"Example")]),
        node("RBL2", "Sample", &[]),
        form("CONS", &[connection("ExampleSource.note", "Sample.b")]),
    ]));
    assert!(mismatch.surfaces.is_empty());
    assert!(mismatch.coverage_issues.is_empty());
}

#[test]
fn destination_resolution_and_multiple_destinations_preserve_order() {
    let result = catalog(scene(&[
        node(
            "XFRM",
            "ExampleSource",
            &[attr("STR ", "note", b"print(\"Example\");")],
        ),
        script(&[attr("STR ", "b", b"print('Sample')")]),
        node("DEXP", "ExampleExpression", &[]),
        form(
            "CONS",
            &[
                connection("ExampleSource.note", "ExampleScript.after"),
                connection("ExampleSource.note", "ExampleExpression.internalExpression"),
                connection("ExampleSource.note", "ExampleScript.b"),
            ],
        ),
    ]));
    assert_eq!(result.surfaces.len(), 4);
    assert!(
        result.coverage_issues.is_empty(),
        "{:?}",
        result.coverage_issues
    );
    assert!(result.surfaces[0].surface.origin.overwritten_by_connection);
    let origins: Vec<_> = result.surfaces[1..]
        .iter()
        .map(|s| &s.surface.origin)
        .collect();
    assert_eq!(
        origins
            .iter()
            .map(|o| o.attr_name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        [".a", ".ixp", ".b"]
    );
    assert!(
        origins
            .windows(2)
            .all(|o| o[0].connection_range.unwrap().start < o[1].connection_range.unwrap().start)
    );
}

#[test]
fn ambiguous_destinations_and_malformed_sources_are_positioned() {
    for (destination, extra) in [
        ("ExampleScript.b", vec![script(&[])]),
        ("ExampleScript.b[0]", vec![]),
        ("ExampleScript.compound.before", vec![]),
        ("Sample.before", vec![]),
        (
            "ExampleUnknown.before",
            vec![node("XPLT", "ExampleUnknown", &[])],
        ),
    ] {
        let result = catalog(example(
            &[b"print('Example')"],
            "ExampleSource.note",
            destination,
            &extra,
        ));
        assert!(result.surfaces.is_empty());
        assert!(
            result
                .coverage_issues
                .iter()
                .any(|issue| issue
                    .origin
                    .as_ref()
                    .is_some_and(|o| o.chunk_tag.as_deref() == Some("CWFL")
                        && o.chunk_payload_offset.is_some())),
            "{destination}: {:?}",
            result.coverage_issues
        );
    }
    let malformed = catalog(scene(&[
        script(&[]),
        form("CONS", &[chunk("CWFL", b"\0\0ExampleScript.b\0", 8)]),
    ]));
    assert!(malformed.coverage_issues.iter().any(|issue| {
        issue
            .origin
            .as_ref()
            .is_some_and(|o| o.chunk_tag.as_deref() == Some("CWFL"))
    }));
}

#[test]
fn noncandidate_malformed_connections_keep_raw_coverage() {
    use maya_scene_kit_observe::scene::evidence::{
        ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind,
    };
    for (payload, marker) in [
        (b"\0\0ExampleNode.tx\0".as_slice(), None),
        (b"\0print(Example)".as_slice(), None),
        (b"\0python(Example)".as_slice(), Some("python")),
    ] {
        let result = catalog(scene(&[form("CONS", &[chunk("CWFL", payload, 8)])]));
        assert!(result.surfaces.is_empty());
        assert_eq!(result.coverage_issues.len(), 1, "{payload:?}");
        let issue = &result.coverage_issues[0];
        if let Some(marker) = marker {
            assert_eq!(issue.kind, ExecutionCoverageIssueKind::UnknownRawMbPayload);
            assert!(
                matches!(&issue.detail, ExecutionCoverageIssueDetail::UnknownRawMbPayload { marker: actual } if actual == marker)
            );
        } else {
            assert_eq!(
                issue.kind,
                ExecutionCoverageIssueKind::UnexplainedRawMbPayload
            );
            assert!(
                matches!(&issue.detail, ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason } if reason == "undecoded text-like MB payload in CONS:CWFL")
            );
        }
        let origin = issue.origin.as_ref().unwrap();
        assert_eq!(origin.source_kind.as_deref(), Some("CONS:CWFL"));
        assert_eq!(origin.chunk_form.as_deref(), Some("CONS"));
        assert_eq!(origin.chunk_tag.as_deref(), Some("CWFL"));
        assert_eq!(origin.chunk_payload_size, Some(payload.len()));
        assert!(origin.connection_range.is_none());
        assert_eq!(
            issue.preview,
            std::str::from_utf8(payload)
                .unwrap()
                .trim_end_matches(char::from(0))
        );
    }
}

#[test]
fn ambiguous_destinations_require_numeric_source_proof() {
    for (attrs, source, extra) in [
        (
            vec![attr("STR ", "nt", b"print('Example')")],
            "ExampleSource.note",
            vec![],
        ),
        (vec![], "ExampleSource.note", vec![]),
        (vec![], "Sample.note", vec![]),
        (
            vec![attr("DBLE", "note", &[0])],
            "ExampleSource.note",
            vec![],
        ),
        (
            vec![attr("DBLE", "note", &1.0f64.to_be_bytes())],
            "ExampleSource.note",
            vec![form(
                "CONS",
                &[connection("Sample.note", "ExampleSource.note")],
            )],
        ),
        (
            vec![attr("DBLE", "note", &1.0f64.to_be_bytes())],
            "ExampleSource.note",
            vec![node("XFRM", "ExampleSource", &[])],
        ),
    ] {
        let mut forms = vec![
            node("XFRM", "ExampleSource", &attrs),
            form("CONS", &[connection(source, "ExampleRig:ExampleScript.b")]),
        ];
        forms.extend(extra);
        let result = catalog(scene(&forms));
        assert!(result.surfaces.is_empty());
        let connection_issues: Vec<_> = result
            .coverage_issues
            .iter()
            .filter(|issue| {
                issue
                    .origin
                    .as_ref()
                    .is_some_and(|origin| origin.chunk_tag.as_deref() == Some("CWFL"))
            })
            .collect();
        assert_eq!(
            connection_issues.len(),
            1,
            "{source}: {:?}",
            result.coverage_issues
        );
        let origin = connection_issues[0].origin.as_ref().unwrap();
        assert!(origin.connection_range.is_some());
        assert_eq!(origin.chunk_tag.as_deref(), Some("CWFL"));
    }
    for name in ["ExampleScript", "perspShape"] {
        let duplicated_destination = catalog(scene(&[
            node("XFRM", "ExampleSource", &[]),
            node("SCRP", name, &[]),
            node("SCRP", name, &[]),
            form(
                "CONS",
                &[connection("ExampleSource.note", &format!("{name}.b"))],
            ),
        ]));
        assert_eq!(duplicated_destination.coverage_issues.len(), 1, "{name}");
    }
    for numeric in [
        attr("DBLE", "note", &1.0f64.to_be_bytes()),
        attr("LONG", "note", &1u32.to_be_bytes()),
    ] {
        let result = catalog(scene(&[
            node("XFRM", "ExampleSource", &[numeric]),
            form(
                "CONS",
                &[connection(
                    "ExampleSource.note",
                    "ExampleRig:ExampleScript.b",
                )],
            ),
        ]));
        assert!(result.surfaces.is_empty());
        assert!(
            result.coverage_issues.is_empty(),
            "{:?}",
            result.coverage_issues
        );
    }
}

#[test]
fn identical_connection_records_keep_first_surface_or_issue() {
    for values in [vec![attr("STR ", "note", b"print('Example')")], vec![]] {
        let resolved = !values.is_empty();
        let edge = connection("ExampleSource.note", "ExampleScript.b");
        let bytes = scene(&[
            node("XFRM", "ExampleSource", &values),
            script(&[]),
            form("CONS", &[edge.clone(), edge.clone()]),
            form("CONS", &[edge]),
        ]);
        let first = bytes.windows(4).position(|bytes| bytes == b"CWFL").unwrap();
        let result = catalog(bytes);
        let origin = if resolved {
            assert_eq!(result.surfaces.len(), 1);
            assert!(result.coverage_issues.is_empty());
            &result.surfaces[0].surface.origin
        } else {
            assert!(result.surfaces.is_empty());
            assert_eq!(result.coverage_issues.len(), 1);
            result.coverage_issues[0].origin.as_ref().unwrap()
        };
        assert_eq!(origin.connection_range.unwrap().start, first);
    }
}

#[test]
fn connection_issues_identify_both_plugs() {
    let result = catalog(example(
        &[],
        "ExampleSource.note",
        "ExampleScript.before",
        &[],
    ));
    assert_eq!(result.coverage_issues.len(), 1);
    let issue = &result.coverage_issues[0];
    for plug in ["ExampleSource.note", "ExampleScript.before"] {
        assert!(
            format!("{:?}", issue.detail).contains(plug),
            "{:?}",
            issue.detail
        );
        assert!(issue.preview.contains(plug), "{}", issue.preview);
    }
}
