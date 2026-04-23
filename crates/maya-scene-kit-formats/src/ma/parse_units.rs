use super::parse_support::{flag_matches, normalized_arg_text, raw_item_text};
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
