use std::{fs, path::PathBuf};

use crate::scene::{
    MbInspectNode, MbInspectOptions, SceneToolError, inspect_mb, inspect_mb_with_max_parse_bytes,
};

pub(crate) fn run_inspect(
    path: &PathBuf,
    max_depth: Option<usize>,
    preview_bytes: usize,
    at: Option<&str>,
    max_bytes: Option<usize>,
) -> i32 {
    if path.is_dir() {
        eprintln!(
            "error: inspect only supports a single Maya Binary (.mb) file: {}",
            path.display()
        );
        return 2;
    }

    let at_offset = match at.map(parse_offset) {
        Some(Ok(value)) => Some(value),
        Some(Err(message)) => {
            eprintln!("error: {message}");
            return 2;
        }
        None => None,
    };
    let options = MbInspectOptions {
        max_depth: if at_offset.is_some() { None } else { max_depth },
        preview_bytes,
    };
    let result = match max_bytes {
        Some(max_parse_bytes) => inspect_mb_with_max_parse_bytes(path, options, max_parse_bytes),
        None => inspect_mb(path, options),
    };

    match result {
        Ok(report) => {
            if let Some(offset) = at_offset {
                match fs::read(path) {
                    Ok(data) => print_chunk_at(&report.root, &data, offset, preview_bytes),
                    Err(e) => {
                        eprintln!("error: {e}");
                        return 2;
                    }
                }
            } else {
                print_chunk(&report.root, 0);
            }
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

fn parse_offset(value: &str) -> Result<usize, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("--at requires a byte offset".to_string());
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return usize::from_str_radix(hex, 16).map_err(|_| format!("invalid --at offset: {value}"));
    }
    trimmed
        .parse::<usize>()
        .map_err(|_| format!("invalid --at offset: {value}"))
}

fn print_chunk_at(root: &MbInspectNode, data: &[u8], offset: usize, preview_bytes: usize) {
    let mut chain = Vec::new();
    if !find_chunk_chain(root, offset, &mut chain) {
        println!("no chunk contains offset 0x{offset:08X} ({offset})");
        return;
    }

    println!("offset=0x{offset:08X} ({offset})");
    println!("chain:");
    for (depth, chunk) in chain.iter().enumerate() {
        let indent = "  ".repeat(depth);
        println!("{indent}{}", chunk_summary(chunk));
    }

    let Some(target) = chain.last() else {
        return;
    };
    println!("target:");
    println!("  {}", chunk_summary(target));
    println!(
        "  payload=0x{:08X}..0x{:08X} size={}",
        target.payload_offset, target.payload_end, target.size
    );
    if let Some(alignment) = target.child_alignment {
        println!("  child_alignment={alignment}");
    }
    if let Some(header_size) = target.child_header_size {
        println!("  child_header_size={header_size}");
    }
    let preview_len = preview_bytes.min(target.payload_end.saturating_sub(target.payload_offset));
    if preview_len > 0 && target.payload_end <= data.len() {
        let preview = &data[target.payload_offset..target.payload_offset + preview_len];
        println!("  hex_preview={}", hex_preview(preview));
    }
    let fields = nul_fields(
        data.get(target.payload_offset..target.payload_end)
            .unwrap_or_default(),
    );
    if !fields.is_empty() {
        println!("  fields:");
        for (index, field) in fields.iter().enumerate() {
            println!("    [{index}] {field}");
        }
    }
}

fn find_chunk_chain<'a>(
    chunk: &'a MbInspectNode,
    offset: usize,
    chain: &mut Vec<&'a MbInspectNode>,
) -> bool {
    if offset < chunk.offset || offset >= chunk.payload_end {
        return false;
    }
    chain.push(chunk);
    for child in &chunk.children {
        if find_chunk_chain(child, offset, chain) {
            return true;
        }
    }
    true
}

fn chunk_summary(chunk: &MbInspectNode) -> String {
    let mut summary = format!(
        "{} off=0x{:08X} aux=0x{:08X} size={}",
        chunk.tag, chunk.offset, chunk.aux, chunk.size
    );
    if let Some(form) = &chunk.form_type {
        summary.push_str(&format!(" form={form}"));
        if chunk.opaque {
            summary.push_str(" opaque=1");
        }
    }
    summary
}

fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn nul_fields(payload: &[u8]) -> Vec<String> {
    payload
        .split(|byte| *byte == 0)
        .map(|part| {
            String::from_utf8_lossy(part)
                .trim_start_matches(|ch: char| ch.is_control())
                .trim()
                .to_string()
        })
        .filter(|value| {
            !value.is_empty()
                && value
                    .chars()
                    .all(|ch| !ch.is_control() || matches!(ch, '\t' | '\n' | '\r'))
        })
        .collect()
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
