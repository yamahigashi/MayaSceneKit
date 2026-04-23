use super::parse_support::{find_flag, normalized_arg_text, raw_item_text};
use crate::{error::SceneToolError, ma::ast::ParsedLinkOp, mel};

pub(super) fn parse_top_level_select_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
) -> Result<String, SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::Select(select)) = command.specialized.as_ref() else {
        return Err(SceneToolError::Message(
            "unsupported select form: only select -ne is parsed in Maya ASCII scenes".to_string(),
        ));
    };
    if find_flag(source_text, &select.flags, "noExpand", "-ne").is_none() {
        return Err(SceneToolError::Message(
            "unsupported select form: only select -ne is parsed in Maya ASCII scenes".to_string(),
        ));
    }
    raw_item_text(source_text, select.targets.first())
        .map(|text| text.into_owned())
        .ok_or_else(|| SceneToolError::Message("select command missing target".to_string()))
}

pub(super) fn parse_top_level_connect_attr_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
) -> Result<ParsedLinkOp, SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::ConnectAttr(connect_attr)) =
        command.specialized.as_ref()
    else {
        return Err(SceneToolError::Message(
            "unsupported connectAttr form in Maya ASCII scenes".to_string(),
        ));
    };
    let src = raw_item_text(source_text, connect_attr.source_attr.as_ref())
        .ok_or_else(|| SceneToolError::Message("connectAttr missing source".to_string()))?;
    let dst = raw_item_text(source_text, connect_attr.target_attr.as_ref())
        .ok_or_else(|| SceneToolError::Message("connectAttr missing destination".to_string()))?;
    let mut mode = 0u8;
    if find_flag(source_text, &connect_attr.flags, "nextAvailable", "-na").is_some() {
        mode |= 0x01;
    }
    if let Some(flag) = find_flag(source_text, &connect_attr.flags, "lock", "-l") {
        let value = normalized_arg_text(source_text, flag.args.first()).unwrap_or("true");
        if matches!(value, "on" | "yes" | "true" | "1") {
            mode |= 0x02;
        }
    }
    Ok(ParsedLinkOp::Connect {
        src: src.to_string(),
        dst: dst.to_string(),
        mode,
    })
}

pub(super) fn parse_top_level_relationship_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
) -> Result<ParsedLinkOp, SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::Relationship(relationship)) =
        command.specialized.as_ref()
    else {
        return Err(SceneToolError::Message(
            "unsupported relationship form in Maya ASCII scenes".to_string(),
        ));
    };
    let kind = raw_item_text(source_text, relationship.relationship.as_ref())
        .ok_or_else(|| SceneToolError::Message("relationship missing kind".to_string()))?;
    let head = raw_item_text(source_text, relationship.members.first())
        .ok_or_else(|| SceneToolError::Message("relationship missing head".to_string()))?;
    let tail = relationship
        .members
        .iter()
        .skip(1)
        .filter_map(|item| raw_item_text(source_text, Some(item)).map(|text| text.into_owned()))
        .collect::<Vec<_>>();
    if tail.is_empty() {
        return Err(SceneToolError::Message(
            "relationship missing tail targets".to_string(),
        ));
    }
    Ok(ParsedLinkOp::Relationship {
        kind: kind.to_string(),
        head: head.to_string(),
        tail,
    })
}
