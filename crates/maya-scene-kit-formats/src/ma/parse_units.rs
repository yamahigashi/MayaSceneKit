use super::parse_support::{flag_matches, normalized_arg_text, raw_item_text};
#[cfg(test)]
use crate::ma::commands::{Token, bare_token, token_text};
use crate::{
    error::SceneToolError,
    ma::ast::{ParsedAsciiScene, PluginRequire},
    mel,
};

pub(super) fn parse_top_level_requires_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::Requires(requires)) = command.specialized.as_ref()
    else {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported requires form in Maya ASCII scenes".to_string(),
        ));
    };

    let mut option_tokens = Vec::new();
    for flag in &requires.flags {
        option_tokens.push(flag.source_text(source_text).to_string());
        for arg in &flag.args {
            option_tokens.push(
                normalized_arg_text(source_text, Some(arg))
                    .ok_or_else(|| {
                        SceneToolError::Message("requires flag missing argument".to_string())
                    })?
                    .to_string(),
            );
        }
    }

    let name = raw_item_text(source_text, requires.requirements.first()).ok_or_else(|| {
        SceneToolError::Message("requires command missing plugin name".to_string())
    })?;
    let version = raw_item_text(source_text, requires.requirements.get(1)).ok_or_else(|| {
        SceneToolError::Message("requires command missing plugin version".to_string())
    })?;
    if name == "maya" {
        scene.version = Some(version.to_string());
        return Ok(());
    }

    scene.plugin_requires.push(PluginRequire {
        name: name.to_string(),
        version: version.to_string(),
        options: if option_tokens.is_empty() {
            None
        } else {
            Some(option_tokens.join(" "))
        },
    });
    Ok(())
}

pub(super) fn parse_top_level_current_unit_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::CurrentUnit(current_unit)) =
        command.specialized.as_ref()
    else {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported currentUnit form in Maya ASCII scenes".to_string(),
        ));
    };

    for flag in &current_unit.flags {
        let value = normalized_arg_text(source_text, flag.args.first()).unwrap_or_default();
        if flag_matches(source_text, flag, "linear", "-l") {
            scene.linear_unit = Some(value.to_string());
        } else if flag_matches(source_text, flag, "angle", "-a") {
            scene.angular_unit = Some(value.to_string());
        } else if flag_matches(source_text, flag, "time", "-t") {
            scene.time_unit = Some(value.to_string());
        }
    }

    if scene.linear_unit.is_none() || scene.angular_unit.is_none() || scene.time_unit.is_none() {
        return Err(SceneToolError::Message(
            "currentUnit command is missing one or more unit flags".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn parse_top_level_file_info_command(
    source_text: &str,
    command: &mel::MelTopLevelCommandFact,
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    let Some(mel::MelSpecializedCommandForm::FileInfo(file_info)) = command.specialized.as_ref()
    else {
        return Err(SceneToolError::UnsupportedAsciiFeature(
            "unsupported fileInfo form in Maya ASCII scenes".to_string(),
        ));
    };
    let key = raw_item_text(source_text, file_info.key.as_ref())
        .ok_or_else(|| SceneToolError::Message("fileInfo command missing key".to_string()))?;
    let value = raw_item_text(source_text, file_info.value.as_ref())
        .ok_or_else(|| SceneToolError::Message("fileInfo command missing value".to_string()))?;
    scene.file_info.push((key.to_string(), value.to_string()));
    Ok(())
}

#[cfg(test)]
pub(super) fn parse_requires_command(
    tokens: &[Token],
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    let mut idx = 1usize;
    let mut option_tokens = Vec::new();
    while idx < tokens.len() {
        if matches!(tokens.get(idx), Some(Token::Quoted(_))) {
            break;
        }
        let Some(token) = tokens.get(idx) else {
            break;
        };
        let Some(raw) = bare_token(token) else {
            break;
        };
        if raw == "maya" || !raw.starts_with('-') {
            break;
        }
        option_tokens.push(raw.to_string());
        if idx + 1 < tokens.len() {
            if let Some(value) = bare_token(&tokens[idx + 1]) {
                if !value.starts_with('-') {
                    option_tokens.push(value.to_string());
                    idx += 2;
                    continue;
                }
            }
        }
        idx += 1;
    }

    let Some(name) = tokens.get(idx).and_then(token_text) else {
        return Err(SceneToolError::Message(
            "requires command missing plugin name".to_string(),
        ));
    };
    let Some(version) = tokens.get(idx + 1).and_then(token_text) else {
        return Err(SceneToolError::Message(
            "requires command missing plugin version".to_string(),
        ));
    };
    if name == "maya" {
        scene.version = Some(version.to_string());
        return Ok(());
    }

    scene.plugin_requires.push(PluginRequire {
        name: name.to_string(),
        version: version.to_string(),
        options: if option_tokens.is_empty() {
            None
        } else {
            Some(option_tokens.join(" "))
        },
    });
    Ok(())
}

#[cfg(test)]
pub(super) fn parse_current_unit_command(
    tokens: &[Token],
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    let mut idx = 1usize;
    while idx + 1 < tokens.len() {
        let flag = bare_token(&tokens[idx]).unwrap_or_default();
        let value = token_text(&tokens[idx + 1]).unwrap_or_default();
        match flag {
            "-l" => scene.linear_unit = Some(value.to_string()),
            "-a" => scene.angular_unit = Some(value.to_string()),
            "-t" => scene.time_unit = Some(value.to_string()),
            _ => {}
        }
        idx += 2;
    }
    if scene.linear_unit.is_none() || scene.angular_unit.is_none() || scene.time_unit.is_none() {
        return Err(SceneToolError::Message(
            "currentUnit command is missing one or more unit flags".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn parse_file_info_command(
    tokens: &[Token],
    scene: &mut ParsedAsciiScene,
) -> Result<(), SceneToolError> {
    let key = tokens
        .get(1)
        .and_then(token_text)
        .ok_or_else(|| SceneToolError::Message("fileInfo command missing key".to_string()))?;
    let value = tokens
        .get(2)
        .and_then(token_text)
        .ok_or_else(|| SceneToolError::Message("fileInfo command missing value".to_string()))?;
    scene.file_info.push((key.to_string(), value.to_string()));
    Ok(())
}
