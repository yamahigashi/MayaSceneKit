use super::{
    MaParseDiagnostic, MaParseDiagnosticStage, ParsedAsciiSceneDocument,
    parse_add_attr::parse_top_level_add_attr_command,
    parse_create_node::{parse_top_level_create_node_command, parse_top_level_rename_uid_command},
    parse_links::{
        parse_top_level_connect_attr_command, parse_top_level_relationship_command,
        parse_top_level_select_command,
    },
    parse_references::parse_top_level_file_command,
    parse_set_attr::parse_specialized_set_attr_command,
    parse_units::{
        parse_top_level_current_unit_command, parse_top_level_file_info_command,
        parse_top_level_requires_command,
    },
};
use crate::{
    error::SceneToolError,
    ma::ast::{ParsedAsciiScene, ParsedNodeOp, ParsedSelectBlock, ParsedSelectBlockOp},
    maya_defaults::apply_missing_ascii_scene_defaults,
    mel,
};

pub(super) fn parse_ascii_scene_document_from_top_level(
    facts: mel::MelTopLevelFacts,
    strict: bool,
) -> Result<ParsedAsciiSceneDocument, SceneToolError> {
    let mel::MelTopLevelFacts {
        source_text,
        source_encoding,
        diagnostics,
        validation_diagnostics: _,
        items,
    } = facts;
    let mut scene = ParsedAsciiScene::default();
    let mut active_node: Option<usize> = None;
    let mut active_select: Option<usize> = None;

    parse_leading_header_comments(source_text.as_ref(), &mut scene);

    for item in items {
        match item {
            mel::MelTopLevelItemFact::Command(command) => {
                apply_top_level_command(
                    source_text.as_ref(),
                    &command,
                    &mut scene,
                    &mut active_node,
                    &mut active_select,
                    strict,
                )?;
            }
            mel::MelTopLevelItemFact::Proc(proc_def) => {
                active_node = None;
                active_select = None;
                if strict {
                    return Err(SceneToolError::UnsupportedAsciiFeature(format!(
                        "unsupported Maya ASCII command: {}",
                        if proc_def.is_global {
                            "global proc"
                        } else {
                            "proc"
                        }
                    )));
                }
            }
            mel::MelTopLevelItemFact::Other(other) => {
                active_node = None;
                active_select = None;
                if strict {
                    return Err(SceneToolError::UnsupportedAsciiFeature(format!(
                        "unsupported Maya ASCII command: {}",
                        unsupported_statement_label(other.source_text(source_text.as_ref()))
                    )));
                }
            }
        }
    }

    apply_missing_ascii_scene_defaults(&mut scene);

    Ok(ParsedAsciiSceneDocument {
        scene,
        source_encoding,
        diagnostics: diagnostics
            .into_iter()
            .map(|diagnostic| MaParseDiagnostic {
                stage: match diagnostic.stage {
                    mel::MelDiagnosticStage::Decode => MaParseDiagnosticStage::Decode,
                    mel::MelDiagnosticStage::Lex => MaParseDiagnosticStage::Lex,
                    mel::MelDiagnosticStage::Parse => MaParseDiagnosticStage::Parse,
                },
                message: diagnostic.message.into_owned(),
                span_start: diagnostic.span.start,
                span_end: diagnostic.span.end,
            })
            .collect(),
    })
}

fn parse_leading_header_comments(text: &str, scene: &mut ParsedAsciiScene) {
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("//") {
            parse_comment_line(trimmed, scene);
            continue;
        }
        break;
    }
}

fn unsupported_statement_label(text: &str) -> String {
    let trimmed = text.trim_start();
    let label: String = trimmed
        .chars()
        .take_while(|ch| !ch.is_whitespace() && !matches!(ch, ';' | '(' | '{'))
        .collect();
    if label.is_empty() {
        "<statement>".to_string()
    } else {
        label
    }
}

fn apply_top_level_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
    scene: &mut ParsedAsciiScene,
    active_node: &mut Option<usize>,
    active_select: &mut Option<usize>,
    strict: bool,
) -> Result<(), SceneToolError> {
    match command.head.as_ref() {
        "requires" => {
            *active_node = None;
            *active_select = None;
            parse_top_level_requires_command(source_text, command, scene)?;
        }
        "currentUnit" => {
            *active_node = None;
            *active_select = None;
            parse_top_level_current_unit_command(source_text, command, scene)?;
        }
        "fileInfo" => {
            *active_node = None;
            *active_select = None;
            parse_top_level_file_info_command(source_text, command, scene)?;
        }
        "createNode" => {
            *active_select = None;
            let node = parse_top_level_create_node_command(source_text, command)?;
            scene.nodes.push(node);
            *active_node = Some(scene.nodes.len() - 1);
        }
        "rename" => {
            let uid = parse_top_level_rename_uid_command(source_text, command)?;
            let node_index = active_node.ok_or_else(|| {
                SceneToolError::Message("rename -uid must appear inside a createNode block".into())
            })?;
            scene.nodes[node_index].uid = Some(uid);
        }
        "setAttr" => {
            let Some(op) = parse_specialized_set_attr_command(source_text, command)? else {
                return Err(SceneToolError::UnsupportedAsciiFeature(
                    "unsupported setAttr form in Maya ASCII scenes".to_string(),
                ));
            };
            if let Some(node_index) = *active_node {
                scene.nodes[node_index].ops.push(ParsedNodeOp::SetAttr(op));
            } else if let Some(select_index) = *active_select {
                scene.select_blocks[select_index]
                    .ops
                    .push(ParsedSelectBlockOp::SetAttr(op));
            } else {
                return Err(SceneToolError::Message(
                    "setAttr must appear inside createNode/select blocks".to_string(),
                ));
            }
        }
        "addAttr" => {
            let op = parse_top_level_add_attr_command(source_text, command)?;
            if let Some(node_index) = *active_node {
                scene.nodes[node_index].ops.push(ParsedNodeOp::AddAttr(op));
            } else if let Some(select_index) = *active_select {
                scene.select_blocks[select_index]
                    .ops
                    .push(ParsedSelectBlockOp::AddAttr(op));
            } else {
                return Err(SceneToolError::Message(
                    "addAttr must appear inside createNode/select blocks".to_string(),
                ));
            }
        }
        "select" => {
            *active_node = None;
            let target = parse_top_level_select_command(source_text, command)?;
            scene.select_blocks.push(ParsedSelectBlock {
                target,
                notes: vec![],
                ops: vec![],
            });
            *active_select = Some(scene.select_blocks.len() - 1);
        }
        "connectAttr" => {
            *active_node = None;
            *active_select = None;
            scene
                .links
                .push(parse_top_level_connect_attr_command(source_text, command)?);
        }
        "relationship" => {
            *active_node = None;
            *active_select = None;
            scene
                .links
                .push(parse_top_level_relationship_command(source_text, command)?);
        }
        "file" => {
            *active_node = None;
            *active_select = None;
            parse_top_level_file_command(source_text, command, scene)?;
        }
        command_name => {
            *active_node = None;
            *active_select = None;
            if strict {
                return Err(SceneToolError::UnsupportedAsciiFeature(format!(
                    "unsupported Maya ASCII command: {command_name}"
                )));
            }
        }
    }

    Ok(())
}

pub(super) fn parse_comment_line(line: &str, scene: &mut ParsedAsciiScene) {
    if let Some(rest) = line.strip_prefix("//Maya ASCII ") {
        if let Some(version) = rest.strip_suffix(" scene") {
            scene.version = Some(version.trim().to_string());
        }
    } else if let Some(rest) = line.strip_prefix("//Last modified: ") {
        scene.changed = Some(rest.trim().to_string());
    }
}
