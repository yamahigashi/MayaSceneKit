#[cfg(test)]
use crate::ma::commands::Token;
use crate::{
    error::SceneToolError,
    ma::ast::{ParsedAsciiScene, ParsedFileCommand},
    mel,
};

#[cfg(test)]
fn is_supported_legacy_file_flag(flag: &str) -> bool {
    matches!(flag, "-r" | "-rdi" | "-ns" | "-rfn" | "-typ" | "-op")
}

#[cfg(test)]
pub(super) fn parse_file_command(
    tokens: &[Token],
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    use crate::ma::commands::token_text;

    let mut namespace = None;
    let mut reference_node = None;
    let mut file_type = None;
    let mut options = None;
    let mut is_reference = false;
    let mut idx = 1usize;
    while idx < tokens.len() {
        let Some(raw) = tokens.get(idx).and_then(token_text) else {
            idx += 1;
            continue;
        };
        if raw.starts_with('-') && !is_supported_legacy_file_flag(raw) {
            idx += 1;
            continue;
        }
        match raw {
            "-r" | "-rdi" => {
                is_reference = true;
                idx += 1;
            }
            "-ns" => {
                namespace = tokens.get(idx + 1).and_then(token_text).map(str::to_string);
                idx += 2;
            }
            "-rfn" => {
                reference_node = tokens.get(idx + 1).and_then(token_text).map(str::to_string);
                idx += 2;
            }
            "-typ" => {
                file_type = tokens.get(idx + 1).and_then(token_text).map(str::to_string);
                idx += 2;
            }
            "-op" => {
                options = tokens.get(idx + 1).and_then(token_text).map(str::to_string);
                idx += 2;
            }
            _ => {
                idx += 1;
            }
        }
    }
    let path = tokens
        .iter()
        .rev()
        .find_map(token_text)
        .ok_or_else(|| SceneToolError::AsciiSyntax("file command missing path".to_string()))?
        .to_string();
    scene.file_commands.push(ParsedFileCommand {
        path,
        namespace,
        reference_node,
        file_type,
        options,
        is_reference,
    });
    Ok(())
}

pub(super) fn parse_top_level_file_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::File(file)) = command.specialized.as_ref() else {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported file form in Maya ASCII scenes".to_string(),
        ));
    };
    parse_file_command_specialized(source_text, file, scene)
}

fn normalized_arg_text<'a>(
    source_text: &'a str,
    arg: Option<&'a mel::MelNormalizedPositionalArg>,
) -> Option<&'a str> {
    arg.map(|arg| arg.preferred_text(source_text))
}

fn flag_matches(
    source_text: &str,
    flag: &mel::MelNormalizedFlag,
    canonical: &str,
    short: &str,
) -> bool {
    flag.matches_name(source_text, canonical, short)
}

fn parse_file_command_specialized(
    source_text: &str,
    command: &mel::MelSpecializedFileCommand,
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    let mut namespace = None;
    let mut reference_node = None;
    let mut file_type = None;
    let mut options = None;
    let mut is_reference = false;

    for flag in &command.flags {
        if flag_matches(source_text, flag, "reference", "-r")
            || flag_matches(source_text, flag, "referenceDepthInfo", "-rdi")
        {
            is_reference = true;
            continue;
        }
        if flag_matches(source_text, flag, "namespace", "-ns") {
            namespace = normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
            continue;
        }
        if flag_matches(source_text, flag, "referenceNode", "-rfn") {
            reference_node =
                normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
            continue;
        }
        if flag_matches(source_text, flag, "type", "-typ") {
            file_type = normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
            continue;
        }
        if flag_matches(source_text, flag, "options", "-op") {
            options = normalized_arg_text(source_text, flag.args.first()).map(str::to_string);
        }
    }

    let path = command
        .path
        .as_ref()
        .and_then(|item| item.value_text(source_text).map(|value| value.into_owned()))
        .ok_or_else(|| SceneToolError::AsciiSyntax("file command missing path".to_string()))?;
    scene.file_commands.push(ParsedFileCommand {
        path,
        namespace,
        reference_node,
        file_type,
        options,
        is_reference,
    });
    Ok(())
}
