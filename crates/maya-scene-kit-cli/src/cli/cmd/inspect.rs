use std::path::PathBuf;

use crate::scene::{
    MbInspectNode, MbInspectOptions, SceneToolError, inspect_mb, inspect_mb_with_max_parse_bytes,
};

pub(crate) fn run_inspect(
    path: &PathBuf,
    max_depth: Option<usize>,
    preview_bytes: usize,
    max_bytes: Option<usize>,
) -> i32 {
    if path.is_dir() {
        eprintln!(
            "error: inspect only supports a single Maya Binary (.mb) file: {}",
            path.display()
        );
        return 2;
    }

    let options = MbInspectOptions {
        max_depth,
        preview_bytes,
    };
    let result = match max_bytes {
        Some(max_parse_bytes) => inspect_mb_with_max_parse_bytes(path, options, max_parse_bytes),
        None => inspect_mb(path, options),
    };

    match result {
        Ok(report) => {
            print_chunk(&report.root, 0);
            0
        }
        Err(SceneToolError::Io(e)) => {
            eprintln!("error: {e}");
            2
        }
        Err(SceneToolError::UnsupportedSceneFormat { path, detected }) => {
            eprintln!(
                "error: inspect only supports Maya Binary (.mb) input: {} ({})",
                path.display(),
                detected
            );
            1
        }
        Err(SceneToolError::Parse(e)) => {
            eprintln!("parse error: {e}");
            1
        }
        Err(
            SceneToolError::Config(msg)
            | SceneToolError::AsciiSyntax(msg)
            | SceneToolError::UnsupportedAsciiFeature(msg)
            | SceneToolError::EncodeInvariant(msg)
            | SceneToolError::AtomicWrite(msg)
            | SceneToolError::Message(msg),
        ) => {
            eprintln!("error: {msg}");
            1
        }
        Err(SceneToolError::MelParseBudgetExceeded { limit }) => {
            eprintln!("error: parse budget exceeded: {limit}");
            1
        }
        Err(SceneToolError::MbParseBudgetExceeded { limit }) => {
            eprintln!("error: parse budget exceeded: {limit}");
            1
        }
        Err(SceneToolError::InvalidUtf8 { policy, message }) => {
            eprintln!("error: invalid UTF-8 Maya ASCII input ({policy}): {message}");
            1
        }
        Err(SceneToolError::RejectedByMode {
            mode,
            validation_state,
            issue_count,
            unknown_count,
        }) => {
            eprintln!(
                "error: operation rejected by mode {mode}: validation_state={validation_state} issues={issue_count} unknown_entries={unknown_count}"
            );
            1
        }
    }
}

fn print_chunk(chunk: &MbInspectNode, depth: usize) {
    let indent = "  ".repeat(depth);
    let mut line = format!(
        "{indent}{} off=0x{:08X} aux=0x{:08X} size={}",
        chunk.tag, chunk.offset, chunk.aux, chunk.size
    );
    if let Some(form) = &chunk.form_type {
        line.push_str(&format!(" form={form}"));
        if chunk.opaque {
            line.push_str(" opaque=1");
        }
    } else if let Some(preview) = &chunk.payload_preview {
        line.push_str(&format!(" data='{preview}'"));
    }
    println!("{line}");

    for child in &chunk.children {
        print_chunk(child, depth + 1);
    }
}
