use super::parse_support::{find_flag, normalized_arg_text, raw_item_text};
#[cfg(test)]
use crate::ma::commands::{Token, bare_token, token_text};
use crate::{error::SceneToolError, ma::ast::ParsedNode, mel};

pub(super) fn parse_top_level_create_node_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
) -> Result<ParsedNode, SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::CreateNode(create_node)) =
        command.specialized.as_ref()
    else {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported createNode form in Maya ASCII scenes".to_string(),
        ));
    };
    let node_type = raw_item_text(source_text, create_node.node_type.as_ref())
        .ok_or_else(|| SceneToolError::AsciiSyntax("createNode missing node type".to_string()))?;
    let name = raw_item_text(source_text, create_node.name.as_ref())
        .ok_or_else(|| SceneToolError::AsciiSyntax("createNode missing -n name".to_string()))?;
    let parent =
        raw_item_text(source_text, create_node.parent.as_ref()).map(|text| text.into_owned());
    let shared = find_flag(source_text, &create_node.flags, "shared", "-s").is_some();
    Ok(ParsedNode {
        node_type: node_type.to_string(),
        name: name.to_string(),
        parent,
        shared,
        uid: None,
        ops: vec![],
    })
}

pub(super) fn parse_top_level_rename_uid_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
) -> Result<String, SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::Rename(rename)) = command.specialized.as_ref() else {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported rename form: only rename -uid is parsed in Maya ASCII scenes".to_string(),
        ));
    };
    let Some(flag) = find_flag(source_text, &rename.flags, "uuid", "-uid") else {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported rename form: only rename -uid is parsed in Maya ASCII scenes".to_string(),
        ));
    };
    raw_item_text(source_text, rename.uuid.as_ref())
        .map(|text| text.into_owned())
        .or_else(|| normalized_arg_text(source_text, flag.args.first()).map(str::to_string))
        .or_else(|| {
            raw_item_text(source_text, rename.source.as_ref()).map(|text| text.into_owned())
        })
        .or_else(|| {
            raw_item_text(source_text, rename.target.as_ref()).map(|text| text.into_owned())
        })
        .ok_or_else(|| SceneToolError::AsciiSyntax("rename -uid missing UUID".to_string()))
}

#[cfg(test)]
pub(super) fn parse_create_node_command(tokens: &[Token]) -> Result<ParsedNode, SceneToolError> {
    let node_type = tokens
        .get(1)
        .and_then(bare_token)
        .ok_or_else(|| SceneToolError::AsciiSyntax("createNode missing node type".to_string()))?;
    let mut name = None;
    let mut parent = None;
    let mut shared = false;
    let mut idx = 2usize;
    while idx < tokens.len() {
        match bare_token(&tokens[idx]).unwrap_or_default() {
            "-s" => {
                shared = true;
                idx += 1;
            }
            "-n" => {
                name = tokens.get(idx + 1).and_then(token_text).map(str::to_string);
                idx += 2;
            }
            "-p" => {
                parent = tokens.get(idx + 1).and_then(token_text).map(str::to_string);
                idx += 2;
            }
            _ => idx += 1,
        }
    }
    let name =
        name.ok_or_else(|| SceneToolError::AsciiSyntax("createNode missing -n name".to_string()))?;
    Ok(ParsedNode {
        node_type: node_type.to_string(),
        name,
        parent,
        shared,
        uid: None,
        ops: vec![],
    })
}

#[cfg(test)]
pub(super) fn parse_rename_uid_command(tokens: &[Token]) -> Result<String, SceneToolError> {
    if bare_token(tokens.get(1).unwrap_or(&Token::Bare(String::new()))) != Some("-uid") {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported rename form: only rename -uid is parsed in Maya ASCII scenes".to_string(),
        ));
    }
    tokens
        .get(2)
        .and_then(token_text)
        .map(str::to_string)
        .ok_or_else(|| SceneToolError::AsciiSyntax("rename -uid missing UUID".to_string()))
}
