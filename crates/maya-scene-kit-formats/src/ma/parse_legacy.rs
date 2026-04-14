use super::{
    parse_add_attr::parse_add_attr_command,
    parse_create_node::{parse_create_node_command, parse_rename_uid_command},
    parse_driver::parse_comment_line,
    parse_links::{parse_connect_attr_command, parse_relationship_command, parse_select_command},
    parse_references::parse_file_command,
    parse_set_attr::parse_set_attr_command,
    parse_units::{parse_current_unit_command, parse_file_info_command, parse_requires_command},
};
use crate::{
    error::SceneToolError,
    ma::{
        ast::{ParsedAsciiScene, ParsedNodeOp, ParsedSelectBlock, ParsedSelectBlockOp},
        commands::{bare_token, tokenize_command},
    },
    maya_defaults::apply_missing_ascii_scene_defaults,
};

#[derive(Debug)]
enum LegacyCommandItem {
    Comment(String),
    Command(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyCommandKind {
    Requires,
    CurrentUnit,
    FileInfo,
    CreateNode,
    Rename,
    SetAttr,
    AddAttr,
    Select,
    ConnectAttr,
    Relationship,
    File,
}

pub(super) fn parse_ascii_scene_legacy(text: &str) -> Result<ParsedAsciiScene, SceneToolError> {
    let items = split_ascii_items(text)?;
    let mut scene = ParsedAsciiScene::default();
    let mut active_node: Option<usize> = None;
    let mut active_select: Option<usize> = None;

    for item in items {
        match item {
            LegacyCommandItem::Comment(line) => {
                parse_comment_line(&line, &mut scene);
            }
            LegacyCommandItem::Command(command) => {
                let tokens = tokenize_command(&command)?;
                if tokens.is_empty() {
                    continue;
                }
                let command = bare_token(&tokens[0]).unwrap_or_default();
                let Some(kind) = command_kind(command) else {
                    return Err(SceneToolError::UnsupportedAsciiFeature(format!(
                        "unsupported Maya ASCII command: {command}"
                    )));
                };
                match kind {
                    LegacyCommandKind::Requires => {
                        active_node = None;
                        active_select = None;
                        parse_requires_command(&tokens, &mut scene)?;
                    }
                    LegacyCommandKind::CurrentUnit => {
                        active_node = None;
                        active_select = None;
                        parse_current_unit_command(&tokens, &mut scene)?;
                    }
                    LegacyCommandKind::FileInfo => {
                        active_node = None;
                        active_select = None;
                        parse_file_info_command(&tokens, &mut scene)?;
                    }
                    LegacyCommandKind::CreateNode => {
                        active_select = None;
                        let node = parse_create_node_command(&tokens)?;
                        scene.nodes.push(node);
                        active_node = Some(scene.nodes.len() - 1);
                    }
                    LegacyCommandKind::Rename => {
                        let uid = parse_rename_uid_command(&tokens)?;
                        let node_index = active_node.ok_or_else(|| {
                            SceneToolError::Message(
                                "rename -uid must appear inside a createNode block".to_string(),
                            )
                        })?;
                        scene.nodes[node_index].uid = Some(uid);
                    }
                    LegacyCommandKind::SetAttr => {
                        let op = parse_set_attr_command(&tokens)?;
                        if let Some(node_index) = active_node {
                            scene.nodes[node_index].ops.push(ParsedNodeOp::SetAttr(op));
                        } else if let Some(select_index) = active_select {
                            scene.select_blocks[select_index]
                                .ops
                                .push(ParsedSelectBlockOp::SetAttr(op));
                        } else {
                            return Err(SceneToolError::Message(
                                "setAttr must appear inside createNode/select blocks".to_string(),
                            ));
                        }
                    }
                    LegacyCommandKind::AddAttr => {
                        let op = parse_add_attr_command(&tokens)?;
                        if let Some(node_index) = active_node {
                            scene.nodes[node_index].ops.push(ParsedNodeOp::AddAttr(op));
                        } else if let Some(select_index) = active_select {
                            scene.select_blocks[select_index]
                                .ops
                                .push(ParsedSelectBlockOp::AddAttr(op));
                        } else {
                            return Err(SceneToolError::Message(
                                "addAttr must appear inside createNode/select blocks".to_string(),
                            ));
                        }
                    }
                    LegacyCommandKind::Select => {
                        active_node = None;
                        let target = parse_select_command(&tokens)?;
                        scene.select_blocks.push(ParsedSelectBlock {
                            target,
                            notes: vec![],
                            ops: vec![],
                        });
                        active_select = Some(scene.select_blocks.len() - 1);
                    }
                    LegacyCommandKind::ConnectAttr => {
                        active_node = None;
                        active_select = None;
                        scene.links.push(parse_connect_attr_command(&tokens)?);
                    }
                    LegacyCommandKind::Relationship => {
                        active_node = None;
                        active_select = None;
                        scene.links.push(parse_relationship_command(&tokens)?);
                    }
                    LegacyCommandKind::File => {
                        parse_file_command(&tokens, &mut scene)?;
                    }
                }
            }
        }
    }

    apply_missing_ascii_scene_defaults(&mut scene);

    Ok(scene)
}

fn command_kind(name: &str) -> Option<LegacyCommandKind> {
    Some(match name {
        "requires" => LegacyCommandKind::Requires,
        "currentUnit" => LegacyCommandKind::CurrentUnit,
        "fileInfo" => LegacyCommandKind::FileInfo,
        "createNode" => LegacyCommandKind::CreateNode,
        "rename" => LegacyCommandKind::Rename,
        "setAttr" => LegacyCommandKind::SetAttr,
        "addAttr" => LegacyCommandKind::AddAttr,
        "select" => LegacyCommandKind::Select,
        "connectAttr" => LegacyCommandKind::ConnectAttr,
        "relationship" => LegacyCommandKind::Relationship,
        "file" => LegacyCommandKind::File,
        _ => return None,
    })
}

fn split_ascii_items(text: &str) -> Result<Vec<LegacyCommandItem>, SceneToolError> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escape = false;
    let mut paren_depth = 0usize;

    for raw_line in text.split_inclusive('\n') {
        if current.trim().is_empty() && raw_line.trim_start().starts_with("//") {
            current.clear();
            items.push(LegacyCommandItem::Comment(raw_line.trim_end().to_string()));
            continue;
        }

        current.push_str(raw_line);
        for ch in raw_line.chars() {
            if in_string {
                if escape {
                    escape = false;
                    continue;
                }
                if ch == '\\' {
                    escape = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }

            match ch {
                '"' => in_string = true,
                '(' => paren_depth += 1,
                ')' => paren_depth = paren_depth.saturating_sub(1),
                ';' if paren_depth == 0 => {
                    if !current.trim().is_empty() {
                        items.push(LegacyCommandItem::Command(current.trim().to_string()));
                    }
                    current.clear();
                }
                _ => {}
            }
        }
    }

    if in_string || paren_depth != 0 {
        return Err(SceneToolError::Message(
            "unterminated string or parenthesized expression in Maya ASCII".to_string(),
        ));
    }

    if !current.trim().is_empty() {
        items.push(LegacyCommandItem::Command(current.trim().to_string()));
    }

    Ok(items)
}
