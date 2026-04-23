// Raw MA script helpers are transport-oriented lexical utilities for cleanup and
// best-effort extraction. Canonical inspection APIs should prefer MA AST owners.
use std::collections::HashSet;

pub use crate::ma::raw_dump::RawMaScriptEntry;
use crate::ma::{
    lexer::{
        extract_script_node_name_from_create, is_create_script_command, is_top_level_command,
        split_lines_keepends,
    },
    raw_dump::extract_raw_dump_sections_from_ma,
};

pub fn scan_raw_script_nodes_in_ma(data: &[u8]) -> Vec<String> {
    extract_raw_script_entries_from_ma(data)
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

pub fn extract_raw_script_entries_from_ma(data: &[u8]) -> Vec<RawMaScriptEntry> {
    extract_raw_dump_sections_from_ma(data).script_entries
}

pub fn remove_raw_script_nodes_from_ma(data: &[u8]) -> (Vec<u8>, Vec<String>) {
    remove_raw_script_nodes_from_ma_by_name(data, &[])
}

pub fn remove_raw_script_nodes_from_ma_by_name(
    data: &[u8],
    target_names: &[String],
) -> (Vec<u8>, Vec<String>) {
    let lines = split_lines_keepends(data);
    let mut blocks = find_script_blocks_in_ma(&lines);
    if !target_names.is_empty() {
        let targets = target_names
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        blocks.retain(|(_, _, name)| targets.contains(name.as_str()));
    }
    if blocks.is_empty() {
        return (data.to_vec(), vec![]);
    }

    let skip_ranges: Vec<(usize, usize)> = blocks
        .iter()
        .map(|(start, end, _)| (*start, *end))
        .collect();
    let removed_names: Vec<String> = blocks.into_iter().map(|(_, _, name)| name).collect();

    let mut out = Vec::new();
    let mut skip_idx = 0usize;
    let mut line_idx = 0usize;

    while line_idx < lines.len() {
        if skip_idx < skip_ranges.len() {
            let (start, end) = skip_ranges[skip_idx];
            if start <= line_idx && line_idx < end {
                line_idx = end;
                skip_idx += 1;
                continue;
            }
        }
        out.extend_from_slice(lines[line_idx]);
        line_idx += 1;
    }

    (out, removed_names)
}

fn find_script_blocks_in_ma(lines: &[&[u8]]) -> Vec<(usize, usize, String)> {
    let mut blocks = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let line = &lines[i];
        if is_top_level_command(line) && is_create_script_command(line) {
            let name = extract_script_node_name_from_create(line, i);
            let mut j = i + 1;
            while j < lines.len() {
                if is_top_level_command(lines[j]) {
                    break;
                }
                j += 1;
            }
            blocks.push((i, j, name));
            i = j;
            continue;
        }
        i += 1;
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::{extract_raw_script_entries_from_ma, scan_raw_script_nodes_in_ma};

    #[test]
    fn raw_ma_script_extraction_handles_string_bodies_and_types() {
        let input = concat!(
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" (\"python(\\\"print\\\"\" +\n",
            "        \" )\");\n",
            "    setAttr \".st\" 1;\n",
            "    setAttr \".stp\" 1;\n",
        );

        let entries = extract_raw_script_entries_from_ma(input.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "scriptNode1");
        assert_eq!(entries[0].body, "python(\"print\" )");
        assert_eq!(entries[0].script_type, Some(1));
        assert_eq!(entries[0].source_type, Some(1));
    }

    #[test]
    fn raw_ma_script_scan_returns_names_for_blocks_without_bodies() {
        let input = concat!(
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".st\" 2;\n",
            "createNode transform -n \"pCube1\";\n",
        );

        let names = scan_raw_script_nodes_in_ma(input.as_bytes());
        assert_eq!(names, vec!["scriptNode1".to_string()]);

        let entries = extract_raw_script_entries_from_ma(input.as_bytes());
        assert_eq!(entries[0].body, "");
        assert_eq!(entries[0].script_type, Some(2));
    }
}
