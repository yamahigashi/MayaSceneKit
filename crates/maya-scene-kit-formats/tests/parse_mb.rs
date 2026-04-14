use std::path::PathBuf;

use maya_scene_kit_formats::mb::{
    MayaBinaryParseError, MbParseBudget, MbParseBudgetLimit, extract_head_metadata, parse_file,
    parse_file_with_budget, resolve_section_layout_hints,
    walk_group_chunks_with_layout_with_budget,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build_chunk_with_alignment(tag: &str, payload: &[u8], sibling_alignment: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    while (out.len() - 16) % sibling_alignment != 0 {
        out.push(0);
    }
    out
}

fn build_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
    build_chunk_with_alignment(tag, payload, 8)
}

fn build_form_with_alignment(
    form: &str,
    children: &[Vec<u8>],
    sibling_alignment: usize,
) -> Vec<u8> {
    let mut payload = form.as_bytes().to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }
    build_chunk_with_alignment("FOR8", &payload, sibling_alignment)
}

fn build_form(form: &str, children: &[Vec<u8>]) -> Vec<u8> {
    build_form_with_alignment(form, children, 8)
}

fn build_root(children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = b"Maya".to_vec();
    for child in children {
        payload.extend_from_slice(child);
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"FOR8");
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn write_temp_mb(bytes: &[u8], suffix: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("maya_scene_kit_formats_{suffix}_{unique}.mb"));
    std::fs::write(&path, bytes).expect("write temp mb");
    path
}

#[test]
fn parse_small_sample_root_and_header_group() {
    let mb = parse_file(repo_root().join("tests/02/sphere.mb")).unwrap();
    assert_eq!(mb.root.tag, "FOR8");
    assert_eq!(mb.root.form_type.as_deref(), Some("Maya"));
    assert!(!mb.root.children.is_empty());
    assert_eq!(mb.root.children[0].tag, "FOR8");
    assert_eq!(mb.root.children[0].form_type.as_deref(), Some("HEAD"));
}

#[test]
fn parse_legacy_sample() {
    let mb = parse_file(repo_root().join("tests/01/skin.mb")).unwrap();
    assert_eq!(mb.root.tag, "FOR8");
    assert_eq!(mb.root.form_type.as_deref(), Some("Maya"));
    assert!(mb.walk().len() > 10);
}

#[test]
fn parse_error_for_too_small_data() {
    let path = repo_root().join("tests/tmp_too_small.mb");
    std::fs::write(&path, b"FOR8").unwrap();
    let result = parse_file(&path);
    let _ = std::fs::remove_file(&path);
    assert!(matches!(result, Err(MayaBinaryParseError::Message(_))));
}

#[test]
fn parse_file_with_budget_limits_nested_group_expansion() {
    let nested = build_form_with_alignment(
        "DEEP",
        &[build_form("NEST", &[build_chunk("TEXT", b"payload")])],
        4,
    );
    let source = write_temp_mb(&build_root(&[nested]), "depth_budget");
    let mb = parse_file_with_budget(
        &source,
        &MbParseBudget {
            max_depth: 1,
            ..MbParseBudget::default()
        },
    )
    .expect("parse with depth budget");
    let _ = std::fs::remove_file(&source);

    assert_eq!(mb.root.children.len(), 1);
    assert_eq!(mb.root.children[0].form_type.as_deref(), Some("DEEP"));
    assert!(!mb.root.children[0].children_parsed);
    assert!(mb.root.children[0].children.is_empty());
}

#[test]
fn parse_file_with_budget_limits_children_per_group() {
    let child = build_form_with_alignment(
        "TEST",
        &[
            build_chunk("ONE ", b"1"),
            build_chunk("TWO ", b"2"),
            build_chunk("THRE", b"3"),
        ],
        4,
    );
    let source = write_temp_mb(&build_root(&[child]), "child_budget");
    let mb = parse_file_with_budget(
        &source,
        &MbParseBudget {
            max_children_per_group: 2,
            ..MbParseBudget::default()
        },
    )
    .expect("parse with child budget");
    let _ = std::fs::remove_file(&source);

    assert_eq!(mb.root.children[0].children.len(), 2);
    assert!(!mb.root.children[0].children_parsed);
}

#[test]
fn parse_file_with_budget_limits_total_chunks() {
    let child = build_form_with_alignment(
        "TEST",
        &[
            build_chunk("ONE ", b"1"),
            build_chunk("TWO ", b"2"),
            build_chunk("THRE", b"3"),
        ],
        4,
    );
    let source = write_temp_mb(&build_root(&[child]), "total_budget");
    let mb = parse_file_with_budget(
        &source,
        &MbParseBudget {
            max_total_chunks: 3,
            ..MbParseBudget::default()
        },
    )
    .expect("parse with total chunk budget");
    let _ = std::fs::remove_file(&source);

    assert_eq!(mb.root.children[0].children.len(), 1);
    assert!(!mb.root.children[0].children_parsed);
}

#[test]
fn parse_file_with_budget_rejects_oversized_file_before_parse() {
    let source = write_temp_mb(b"FOR8", "oversized");
    let result = parse_file_with_budget(
        &source,
        &MbParseBudget {
            max_parse_bytes: 2,
            ..MbParseBudget::default()
        },
    );
    let _ = std::fs::remove_file(&source);

    assert!(matches!(
        result,
        Err(MayaBinaryParseError::BudgetExceeded {
            limit: MbParseBudgetLimit::MaxParseBytes,
            ..
        })
    ));
}

#[test]
fn extract_head_metadata_reads_head_payload_without_child_parse() {
    let head = build_form_with_alignment(
        "HEAD",
        &[
            build_chunk("VERS", b"2026\0"),
            build_chunk("PLUG", b"testPlugin\0version2026\0-op \"v=0\"\0"),
        ],
        4,
    );
    let source = write_temp_mb(&build_root(&[head]), "head_scan");
    let mb = parse_file_with_budget(
        &source,
        &MbParseBudget {
            max_depth: 1,
            ..MbParseBudget::default()
        },
    )
    .expect("parse with head depth budget");
    let _ = std::fs::remove_file(&source);

    assert!(!mb.root.children[0].children_parsed);
    let metadata = extract_head_metadata(&mb);
    assert_eq!(metadata.vers.as_deref(), Some("2026"));
    assert_eq!(metadata.requires.len(), 1);
    assert_eq!(metadata.requires[0].plugin_name, "testPlugin");
}

#[test]
fn budgeted_raw_walk_rejects_child_overflow() {
    let child = build_form_with_alignment(
        "TEST",
        &[build_chunk("ONE ", b"1"), build_chunk("TWO ", b"2")],
        4,
    );
    let source = write_temp_mb(&build_root(&[child]), "walk_budget");
    let mb = parse_file(&source).expect("parse");
    let _ = std::fs::remove_file(&source);

    let node = &mb.root.children[0];
    let payload = &mb.data[node.payload_offset..node.payload_end];
    let (child_alignment, child_header_size) = resolve_section_layout_hints(
        &node.tag,
        node.form_type.as_deref(),
        node.child_alignment,
        node.child_header_size,
    );
    let err = walk_group_chunks_with_layout_with_budget(
        &payload[4..],
        child_alignment,
        child_header_size,
        2,
        &MbParseBudget {
            max_children_per_group: 1,
            ..MbParseBudget::default()
        },
    )
    .expect_err("budget should reject wide section");

    assert!(matches!(
        err,
        MayaBinaryParseError::BudgetExceeded {
            limit: MbParseBudgetLimit::MaxChildrenPerGroup,
            ..
        }
    ));
}
