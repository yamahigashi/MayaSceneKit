use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{fs::write_output_bytes, output_contracts::unknown_blob_dir_name};
use crate::scene::{IssueKind, MayaAsciiIssue, RawChunkDump};

pub(super) fn unknown_payload_digest_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(super) fn attach_unknown_payload_blobs_from_raw_chunks(
    raw_chunks: &[RawChunkDump],
    blob_dir_path: &Path,
    blob_dir_name: &str,
    issues: &mut [MayaAsciiIssue],
) {
    let mut blob_dir_created = false;
    let mut used = vec![false; raw_chunks.len()];

    for issue in issues.iter_mut() {
        if issue.kind != IssueKind::Unsupported || issue.attr_name != "<unknown-chunk>" {
            continue;
        }
        if issue.payload_inline_hex.is_some() {
            continue;
        }
        let Some(digest) = issue.payload_digest_hex.clone() else {
            continue;
        };
        let Some(trace_form) = issue.trace_form.clone() else {
            continue;
        };
        let Some(trace_tag) = issue.trace_tag.clone() else {
            continue;
        };
        let Some(trace_offset) = issue.trace_node_offset else {
            continue;
        };
        let trace_aux = issue.trace_chunk_aux;

        let matched_idx = raw_chunks.iter().enumerate().find_map(|(idx, chunk)| {
            if used[idx] {
                return None;
            }
            if chunk.trace_form != trace_form
                || chunk.trace_tag != trace_tag
                || chunk.trace_node_offset != trace_offset
            {
                return None;
            }
            if trace_aux.is_some() && chunk.trace_chunk_aux != trace_aux {
                return None;
            }
            if let Some(size) = issue.payload_size {
                if chunk.payload.len() != size {
                    return None;
                }
            }
            if unknown_payload_digest_hex(&chunk.payload) != digest {
                return None;
            }
            Some(idx)
        });

        let Some(idx) = matched_idx else {
            continue;
        };
        used[idx] = true;

        if !blob_dir_created {
            if fs::create_dir_all(blob_dir_path).is_err() {
                continue;
            }
            blob_dir_created = true;
        }

        let filename = format!("{digest}.bin");
        let blob_path = blob_dir_path.join(&filename);
        if !blob_path.exists() && write_output_bytes(&blob_path, &raw_chunks[idx].payload).is_err()
        {
            continue;
        }
        issue.payload_blob_ref = Some(format!("{blob_dir_name}/{filename}"));
    }
}

pub(super) fn attach_unknown_payload_blobs_to_issues(
    issues_json_path: &Path,
    raw_chunks: &[RawChunkDump],
    issues: &mut [MayaAsciiIssue],
) {
    if raw_chunks.is_empty() {
        return;
    }

    let parent_dir = issues_json_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = issues_json_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("issues");
    let blob_dir_name = unknown_blob_dir_name(stem);
    let blob_dir_path = parent_dir.join(&blob_dir_name);
    attach_unknown_payload_blobs_from_raw_chunks(
        raw_chunks,
        &blob_dir_path,
        &blob_dir_name,
        issues,
    );
}
