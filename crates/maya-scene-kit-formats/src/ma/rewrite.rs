use std::{
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
};

// MA rewrite helpers intentionally operate on raw command text so path cleanup
// can preserve source formatting without becoming a semantic owner.
pub(crate) use crate::ma::lexer::command_has_terminating_semicolon;
use crate::{
    PathReplaceRule, ScenePathEntry,
    ma::{
        commands::{Token, tokenize_command},
        lexer::{
            extract_script_node_name_from_create, is_reference_attr, is_top_level_command,
            looks_like_scene_path, parse_ma_quoted_literal, parse_setattr_string_command,
            parse_setattr_string_line, split_lines_keepends, unescape_ma_string_literal,
        },
        paths::extract_raw_scene_paths_from_ma,
        text::escape_ma_string,
    },
    replace_rules::CompiledPathReplaceRules,
};

pub fn replace_raw_scene_paths_in_ma(data: &[u8], rules: &[PathReplaceRule]) -> (Vec<u8>, usize) {
    if rules.is_empty() {
        return (data.to_vec(), 0);
    }
    let compiled_rules = CompiledPathReplaceRules::compile_lossy(rules);
    replace_raw_scene_paths_in_ma_with_rules(data, &compiled_rules)
}

fn replace_raw_scene_paths_in_ma_with_rules(
    data: &[u8],
    compiled_rules: &CompiledPathReplaceRules,
) -> (Vec<u8>, usize) {
    let lines = split_lines_keepends(data);
    let mut out = String::new();
    let mut total = 0usize;
    let mut i = 0usize;

    while i < lines.len() {
        let line_text = String::from_utf8_lossy(&lines[i]).to_string();
        let trimmed = line_text.trim_start();

        if is_top_level_command(&lines[i]) && trimmed.starts_with("file ") {
            let (command, next) = collect_top_level_command_block(&lines, i);
            let (rewritten, count) = rewrite_ma_file_command_paths(&command, compiled_rules);
            if count > 0 {
                total += count;
                out.push_str(&rewritten);
            } else {
                out.push_str(&command);
            }
            i = next;
            continue;
        }

        if trimmed.starts_with("setAttr ") && line_text.contains("-type \"string\"") {
            let (command, next) = collect_command_until_semicolon(&lines, i);
            if let Some((attr, value)) = parse_setattr_string_command(&command) {
                if attr == ".ftn" || is_reference_attr(&attr) {
                    let (new_value, count) = compiled_rules.apply(&value);
                    if count > 0 {
                        total += count;
                        out.push_str(&rewrite_setattr_string_command(
                            &attr, &new_value, &line_text,
                        ));
                        i = next;
                        continue;
                    }
                }
            }
            out.push_str(&command);
            i = next;
            continue;
        }

        if let Some((attr, value)) = parse_setattr_string_line(&line_text) {
            if attr == ".ftn" || is_reference_attr(&attr) {
                let (new_value, count) = compiled_rules.apply(&value);
                if count > 0 {
                    total += count;
                    out.push_str(&rewrite_setattr_string_command(
                        &attr, &new_value, &line_text,
                    ));
                    i += 1;
                    continue;
                }
            }
        }

        out.push_str(&line_text);
        i += 1;
    }

    (out.into_bytes(), total)
}

pub fn replace_raw_scene_paths_in_ma_by_index(
    data: &[u8],
    replacements: &[(usize, String)],
) -> (Vec<u8>, usize) {
    if replacements.is_empty() {
        return (data.to_vec(), 0);
    }

    let entries = extract_raw_scene_paths_from_ma(data);
    let targets = replacement_targets(&entries, replacements);
    if targets.is_empty() {
        return (data.to_vec(), 0);
    }

    let lines = split_lines_keepends(data);
    let mut out = String::new();
    let mut total = 0usize;
    let mut i = 0usize;
    let mut line_number = 0usize;
    let mut active_block: Option<ActiveScenePathBlock> = None;

    while i < lines.len() {
        let line_text = String::from_utf8_lossy(&lines[i]).to_string();
        let trimmed = line_text.trim_start();

        if is_top_level_command(&lines[i]) {
            active_block = None;

            if trimmed.starts_with("file ") {
                let (command, next) = collect_top_level_command_block(&lines, i);
                if let Some(entry) = extract_reference_entry_from_raw_file_command(&command)
                    && let Some(after_value) = targets.get(&scene_path_entry_fingerprint(&entry))
                {
                    let (rewritten, changed) = rewrite_last_quoted_literal(&command, after_value);
                    if changed {
                        total += 1;
                        out.push_str(&rewritten);
                        i = next;
                        line_number += command.lines().count().max(1);
                        continue;
                    }
                }

                out.push_str(&command);
                i = next;
                line_number += command.lines().count().max(1);
                continue;
            }

            if trimmed.starts_with("createNode ") {
                active_block = start_raw_create_node_block(trimmed.as_bytes(), line_number);
                out.push_str(&line_text);
                i += 1;
                line_number += 1;
                continue;
            }
        }

        if let Some(block) = active_block.as_ref()
            && trimmed.starts_with("setAttr ")
        {
            let (command, next) = collect_command_until_semicolon(&lines, i);
            if let Some((attr, value)) = parse_setattr_string_command(&command)
                && let Some(entry) = scene_path_entry_from_setattr(block, &attr, &value)
                && let Some(after_value) = targets.get(&scene_path_entry_fingerprint(&entry))
            {
                total += 1;
                out.push_str(&rewrite_setattr_string_command(
                    &attr,
                    after_value,
                    &command,
                ));
                i = next;
                line_number += command.lines().count().max(1);
                continue;
            }

            out.push_str(&command);
            i = next;
            line_number += command.lines().count().max(1);
            continue;
        }

        out.push_str(&line_text);
        i += 1;
        line_number += 1;
    }

    if total == 0 {
        return (data.to_vec(), 0);
    }

    (out.into_bytes(), total)
}

pub fn ma_range_has_bytes(data: &[u8], start: usize, end: usize) -> bool {
    data.get(start..end)
        .map(|slice| slice.iter().any(|byte| !byte.is_ascii_whitespace()))
        .unwrap_or(false)
}

pub fn ma_file_command_callback_present(data: &[u8], start: usize, end: usize) -> bool {
    let Some(slice) = data.get(start..end) else {
        return false;
    };
    let command = String::from_utf8_lossy(slice);
    file_command_without_callback(&command)
        .map(|result| {
            result
                .map(|(rewritten, _)| rewritten != command)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

pub fn remove_top_level_commands_from_ma(
    data: &[u8],
    ranges: &[(usize, usize)],
) -> (Vec<u8>, usize) {
    if ranges.is_empty() {
        return (data.to_vec(), 0);
    }

    let mut out = data.to_vec();
    let mut normalized = ranges
        .iter()
        .copied()
        .filter(|(start, end)| start < end && *end <= data.len())
        .collect::<Vec<_>>();
    normalized.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));

    let mut removed = 0usize;
    for (start, end) in normalized {
        if start >= out.len() || end > out.len() {
            continue;
        }
        if !out[start..end]
            .iter()
            .any(|byte| !byte.is_ascii_whitespace())
        {
            continue;
        }
        out.splice(start..end, std::iter::empty());
        removed += 1;
    }

    (out, removed)
}

pub fn remove_file_command_callbacks_from_ma(
    data: &[u8],
    ranges: &[(usize, usize)],
) -> Result<(Vec<u8>, usize), crate::ma::error::MaParseError> {
    if ranges.is_empty() {
        return Ok((data.to_vec(), 0));
    }

    let mut out = data.to_vec();
    let mut normalized = ranges
        .iter()
        .copied()
        .filter(|(start, end)| start < end && *end <= data.len())
        .collect::<Vec<_>>();
    normalized.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));

    let mut removed = 0usize;
    for (start, end) in normalized {
        if start >= out.len() || end > out.len() {
            continue;
        }
        let original = String::from_utf8_lossy(&out[start..end]).to_string();
        let Some((rewritten, changed)) = file_command_without_callback(&original)? else {
            continue;
        };
        if !changed {
            continue;
        }
        out.splice(start..end, rewritten.into_bytes());
        removed += 1;
    }

    Ok((out, removed))
}

pub fn remove_path_owner_nodes_from_ma(
    data: &[u8],
    targets: &[(String, String)],
) -> (Vec<u8>, Vec<(String, String)>) {
    let targets = targets
        .iter()
        .filter_map(|(node_type, node_name)| {
            let node_type = node_type.trim();
            let node_name = node_name.trim();
            (!node_type.is_empty() && !node_name.is_empty())
                .then(|| (node_type.to_string(), node_name.to_string()))
        })
        .collect::<HashSet<_>>();
    if targets.is_empty() {
        return (data.to_vec(), Vec::new());
    }

    let lines = split_lines_keepends(data);
    let mut out = String::new();
    let mut removed = HashSet::<(String, String)>::new();
    let mut i = 0usize;
    let mut line_number = 0usize;

    while i < lines.len() {
        let line_text = String::from_utf8_lossy(&lines[i]).to_string();
        let trimmed = line_text.trim_start();

        if is_top_level_command(&lines[i]) && trimmed.starts_with("file ") {
            let (command, next) = collect_top_level_command_block(&lines, i);
            if let Some(entry) = extract_reference_entry_from_raw_file_command(&command) {
                let target = (entry.node_type, entry.node_name);
                if targets.contains(&target) {
                    removed.insert(target);
                    i = next;
                    line_number += command.lines().count().max(1);
                    continue;
                }
            }
            out.push_str(&command);
            i = next;
            line_number += command.lines().count().max(1);
            continue;
        }

        if is_top_level_command(&lines[i]) && trimmed.starts_with("createNode ") {
            let (command, next) = collect_top_level_command_block(&lines, i);
            if let Some(block) = start_raw_create_node_block(trimmed.as_bytes(), line_number) {
                let target = (block.node_type, block.node_name);
                if targets.contains(&target) {
                    removed.insert(target);
                    i = next;
                    line_number += command.lines().count().max(1);
                    continue;
                }
            }
            out.push_str(&command);
            i = next;
            line_number += command.lines().count().max(1);
            continue;
        }

        out.push_str(&line_text);
        i += 1;
        line_number += 1;
    }

    if removed.is_empty() {
        return (data.to_vec(), Vec::new());
    }

    let removed = targets
        .into_iter()
        .filter(|target| removed.contains(target))
        .collect::<Vec<_>>();
    (out.into_bytes(), removed)
}

fn collect_top_level_command_block(lines: &[Vec<u8>], start: usize) -> (String, usize) {
    let mut command = String::from_utf8_lossy(&lines[start]).to_string();
    let mut next = start + 1;

    while !command_has_terminating_semicolon(&command) && next < lines.len() {
        if is_top_level_command(&lines[next]) {
            break;
        }
        command.push_str(&String::from_utf8_lossy(&lines[next]));
        next += 1;
    }

    (command, next)
}

fn collect_command_until_semicolon(lines: &[Vec<u8>], start: usize) -> (String, usize) {
    let mut command = String::from_utf8_lossy(&lines[start]).to_string();
    let mut next = start + 1;
    while !command_has_terminating_semicolon(&command) && next < lines.len() {
        command.push_str(&String::from_utf8_lossy(&lines[next]));
        next += 1;
    }
    (command, next)
}

fn file_command_without_callback(
    command: &str,
) -> Result<Option<(String, bool)>, crate::ma::error::MaParseError> {
    let tokens = tokenize_command(command)?;
    if !matches!(tokens.first(), Some(Token::Bare(head)) if head == "file") {
        return Ok(None);
    }

    let mut out = vec![Token::Bare("file".to_string())];
    let mut idx = 1usize;
    let mut removed = false;

    while idx < tokens.len() {
        if matches!(tokens.get(idx), Some(Token::Bare(flag)) if flag == "-command") {
            removed = true;
            idx += 1;
            let mut removed_args = 0usize;
            while idx < tokens.len() && removed_args < 2 {
                if matches!(tokens.get(idx), Some(Token::Bare(value)) if value.starts_with('-')) {
                    break;
                }
                idx += 1;
                removed_args += 1;
            }
            continue;
        }
        out.push(tokens[idx].clone());
        idx += 1;
    }

    if !removed {
        return Ok(Some((command.to_string(), false)));
    }

    let mut rewritten = render_command_tokens(&out);
    if command.trim_end().ends_with(';') {
        rewritten.push(';');
    }
    let trailing = command
        .chars()
        .rev()
        .take_while(|ch| matches!(ch, '\n' | '\r'))
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    rewritten.push_str(&trailing);
    Ok(Some((rewritten, true)))
}

fn render_command_tokens(tokens: &[Token]) -> String {
    let mut out = String::new();
    for (index, token) in tokens.iter().enumerate() {
        if index > 0 && !matches!(token, Token::Symbol(')')) {
            let prev = &tokens[index - 1];
            if !matches!(prev, Token::Symbol('(') | Token::Symbol('+'))
                && !matches!(token, Token::Symbol('+'))
            {
                out.push(' ');
            }
        }
        match token {
            Token::Bare(value) => out.push_str(value),
            Token::Quoted(value) => {
                out.push('"');
                out.push_str(&value.replace('\\', "\\\\").replace('"', "\\\""));
                out.push('"');
            }
            Token::Symbol(symbol) => out.push(*symbol),
        }
    }
    out
}

fn rewrite_ma_file_command_paths(
    command: &str,
    compiled_rules: &CompiledPathReplaceRules,
) -> (String, usize) {
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut total = 0usize;

    while cursor < command.len() {
        let Some(next_quote_rel) = command[cursor..].find('"') else {
            out.push_str(&command[cursor..]);
            break;
        };
        let quote_start = cursor + next_quote_rel;
        out.push_str(&command[cursor..quote_start]);

        let (literal, next) = parse_ma_quoted_literal(command, quote_start);
        let Some(raw_literal) = literal else {
            out.push_str(&command[quote_start..]);
            break;
        };

        let literal_slice = &command[quote_start..next];
        let value = unescape_ma_string_literal(&raw_literal);
        if looks_like_scene_path(&value) {
            let (new_value, count) = compiled_rules.apply(&value);
            if count > 0 {
                total += count;
                out.push('"');
                out.push_str(&escape_ma_string(&new_value));
                out.push('"');
            } else {
                out.push_str(literal_slice);
            }
        } else {
            out.push_str(literal_slice);
        }
        cursor = next;
    }

    (out, total)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveScenePathBlock {
    node_type: String,
    node_name: String,
}

fn replacement_targets(
    entries: &[ScenePathEntry],
    replacements: &[(usize, String)],
) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for (index, after_value) in replacements {
        let Some(entry) = entries.get(*index) else {
            continue;
        };
        out.insert(scene_path_entry_fingerprint(entry), after_value.clone());
    }
    out
}

fn start_raw_create_node_block(trimmed: &[u8], line_number: usize) -> Option<ActiveScenePathBlock> {
    if raw_create_node_has_type(trimmed, b"file") {
        return Some(ActiveScenePathBlock {
            node_type: "file".to_string(),
            node_name: extract_script_node_name_from_create(trimmed, line_number),
        });
    }

    if raw_create_node_has_type(trimmed, b"reference") {
        return Some(ActiveScenePathBlock {
            node_type: "reference".to_string(),
            node_name: extract_script_node_name_from_create(trimmed, line_number),
        });
    }

    None
}

fn raw_create_node_has_type(trimmed: &[u8], node_type: &[u8]) -> bool {
    let Some(rest) = trimmed.strip_prefix(b"createNode ") else {
        return false;
    };
    rest.strip_prefix(node_type)
        .is_some_and(|tail| matches!(tail.first(), Some(b' ' | b'\t' | b'\r' | b'\n' | b';')))
}

fn scene_path_entry_from_setattr(
    block: &ActiveScenePathBlock,
    attr: &str,
    value: &str,
) -> Option<ScenePathEntry> {
    if block.node_type == "file" && attr == ".ftn" {
        return Some(ScenePathEntry {
            node_type: "file".to_string(),
            node_name: block.node_name.clone(),
            attr: attr.to_string(),
            value: value.to_string(),
            meta: None,
        });
    }

    if block.node_type == "reference" && is_reference_attr(attr) {
        return Some(ScenePathEntry {
            node_type: "reference".to_string(),
            node_name: block.node_name.clone(),
            attr: attr.to_string(),
            value: value.to_string(),
            meta: None,
        });
    }

    None
}

fn extract_reference_entry_from_raw_file_command(command: &str) -> Option<ScenePathEntry> {
    let path = last_quoted_literal(command).filter(|value| looks_like_scene_path(value))?;
    let node_name = parse_file_command_flag_value(command, "-rfn")
        .unwrap_or_else(|| "<fileCmdRef>".to_string());

    Some(ScenePathEntry {
        node_type: "reference".to_string(),
        node_name,
        attr: ".fn".to_string(),
        value: path,
        meta: None,
    })
}

fn last_quoted_literal(command: &str) -> Option<String> {
    let mut cursor = 0usize;
    let mut last = None;
    while cursor < command.len() {
        let Some(next_quote_rel) = command[cursor..].find('"') else {
            break;
        };
        let quote_start = cursor + next_quote_rel;
        let (literal, next) = parse_ma_quoted_literal(command, quote_start);
        last = literal.map(|value| unescape_ma_string_literal(&value));
        cursor = next;
    }
    last
}

fn parse_file_command_flag_value(command: &str, flag: &str) -> Option<String> {
    let idx = command.find(flag)?;
    let mut cursor = idx + flag.len();
    while cursor < command.len() {
        let ch = command[cursor..].chars().next().unwrap();
        if ch.is_whitespace() {
            cursor += ch.len_utf8();
            continue;
        }
        break;
    }
    if cursor >= command.len() || !command[cursor..].starts_with('"') {
        return None;
    }
    let (literal, _) = parse_ma_quoted_literal(command, cursor);
    literal.map(|s| unescape_ma_string_literal(&s))
}

fn rewrite_last_quoted_literal(command: &str, new_value: &str) -> (String, bool) {
    let mut cursor = 0usize;
    let mut last_range = None;
    while cursor < command.len() {
        let Some(next_quote_rel) = command[cursor..].find('"') else {
            break;
        };
        let quote_start = cursor + next_quote_rel;
        let (literal, next) = parse_ma_quoted_literal(command, quote_start);
        if literal.is_some() {
            last_range = Some((quote_start, next));
        }
        cursor = next;
    }

    let Some((start, end)) = last_range else {
        return (command.to_string(), false);
    };

    let mut out = String::with_capacity(command.len() + new_value.len());
    out.push_str(&command[..start]);
    out.push('"');
    out.push_str(&escape_ma_string(new_value));
    out.push('"');
    out.push_str(&command[end..]);
    (out, true)
}

fn rewrite_setattr_string_command(attr: &str, new_value: &str, original_line: &str) -> String {
    let indent = original_line
        .chars()
        .take_while(|ch| *ch == ' ' || *ch == '\t')
        .collect::<String>();
    format!(
        "{indent}setAttr \"{attr}\" -type \"string\" \"{}\";\n",
        escape_ma_string(new_value)
    )
}

fn scene_path_entry_fingerprint(entry: &ScenePathEntry) -> u64 {
    let mut hasher = DefaultHasher::new();
    entry.node_type.hash(&mut hasher);
    entry.node_name.hash(&mut hasher);
    entry.attr.hash(&mut hasher);
    entry.value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::{
        command_has_terminating_semicolon, ma_file_command_callback_present,
        remove_file_command_callbacks_from_ma, remove_top_level_commands_from_ma,
        replace_raw_scene_paths_in_ma, replace_raw_scene_paths_in_ma_by_index,
    };
    use crate::{PathReplaceMode, PathReplaceRule};

    #[test]
    fn replace_scene_paths_rewrites_file_command_and_multiline_setattr() {
        let input = br#"//Maya ASCII 2026 scene
file -rdi 1 -ns "charA" -rfn "charARN" -op "VERS|2026|"
     -typ "mayaBinary" "rig/charA_v001.mb";
createNode file -n "file1";
    setAttr ".ftn" -type "string" (
        "rig/" +
        "charA_v001.mb"
    );
"#;
        let rules = vec![PathReplaceRule {
            from: "rig/".to_string(),
            to: "asset/".to_string(),
            mode: PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_raw_scene_paths_in_ma(input, &rules);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 2);
        assert!(text.contains("\"asset/charA_v001.mb\""));
        assert!(text.contains("setAttr \".ftn\" -type \"string\" \"asset/charA_v001.mb\";"));
    }

    #[test]
    fn command_terminator_ignores_semicolon_inside_quotes() {
        let command = "file -r -op \"VERS;2026\" \n    -typ \"mayaBinary\" \"rig/charA.mb\"";
        assert!(!command_has_terminating_semicolon(command));
        let terminated = format!("{command};");
        assert!(command_has_terminating_semicolon(&terminated));
    }

    #[test]
    fn replace_scene_paths_keeps_multiline_file_command_with_quoted_semicolon_intact() {
        let input = br#"//Maya ASCII 2026 scene
file -rdi 1 -ns "charA" -rfn "charARN"
     -op "VERS;2026"
     -typ "mayaBinary" "rig/charA_v001.mb";
"#;
        let rules = vec![PathReplaceRule {
            from: "rig/".to_string(),
            to: "asset/".to_string(),
            mode: PathReplaceMode::Literal,
        }];
        let (rewritten, count) = replace_raw_scene_paths_in_ma(input, &rules);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 1);
        assert!(text.contains("-op \"VERS;2026\""));
        assert!(text.contains("\"asset/charA_v001.mb\""));
    }

    #[test]
    fn replace_scene_paths_by_index_changes_only_targeted_entry() {
        let input = br#"file -rdi 1 -ns "charA" -rfn "charARN" -typ "mayaBinary" "shared/asset.mb";
createNode file -n "file1";
    setAttr ".ftn" -type "string" "shared/asset.mb";
"#;
        let (rewritten, count) = replace_raw_scene_paths_in_ma_by_index(
            input,
            &[(1, "textures/hero_diffuse.png".into())],
        );
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(count, 1);
        assert!(text.contains("\"shared/asset.mb\""));
        assert!(text.contains("setAttr \".ftn\" -type \"string\" \"textures/hero_diffuse.png\";"));
    }

    #[test]
    fn remove_top_level_commands_drops_targeted_command_only() {
        let input = br#"requires maya "2026";
python("print(1)");
file -r "safe.ma";
"#;

        let start = input
            .windows("python(\"print(1)\");".len())
            .position(|window| window == b"python(\"print(1)\");")
            .expect("command start");
        let end = start + "python(\"print(1)\");\n".len();

        let (rewritten, removed) = remove_top_level_commands_from_ma(input, &[(start, end)]);
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(removed, 1);
        assert!(!text.contains("python(\"print(1)\")"));
        assert!(text.contains("requires maya \"2026\";"));
        assert!(text.contains("file -r \"safe.ma\";"));
    }

    #[test]
    fn remove_file_command_callbacks_strips_flag_but_keeps_file_statement() {
        let input = br#"file -r -ns "ref" -command "onLoad" "python(\"import os\")" "C:/ref.ma";
"#;
        let end = input.len();
        assert!(ma_file_command_callback_present(input, 0, end));

        let (rewritten, removed) =
            remove_file_command_callbacks_from_ma(input, &[(0, end)]).expect("rewrite");
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(removed, 1);
        assert!(!text.contains("-command"));
        assert!(text.contains("file -r -ns \"ref\" \"C:/ref.ma\";"));
    }
}
