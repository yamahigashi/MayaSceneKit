use crate::scene::{
    SceneToolError,
    dump::{SceneDumpReport, SceneDumpRequireEntry, SceneDumpRequireKind},
    source::{ObservationBundle, ObservationData},
};

pub(crate) fn requires(observation: &ObservationBundle) -> Result<Vec<String>, SceneToolError> {
    match &observation.data {
        ObservationData::Ma { data } => Ok(data.dump_sections().requires.clone()),
        ObservationData::Mb { session } => Ok(session.requires().to_vec()),
    }
}

pub(crate) fn require_entries(
    observation: &ObservationBundle,
) -> Result<Vec<SceneDumpRequireEntry>, SceneToolError> {
    match &observation.data {
        ObservationData::Ma { data } => Ok(data
            .dump_sections()
            .require_entries
            .iter()
            .map(|entry| SceneDumpRequireEntry {
                rendered: entry.rendered.clone(),
                kind: match entry.kind {
                    maya_scene_kit_formats::ma::raw_dump::RawMaRequireKind::MayaVersion => {
                        SceneDumpRequireKind::MayaVersion
                    }
                    maya_scene_kit_formats::ma::raw_dump::RawMaRequireKind::Plugin => {
                        SceneDumpRequireKind::Plugin
                    }
                },
            })
            .collect()),
        ObservationData::Mb { session } => Ok(session.require_entries().to_vec()),
    }
}

pub(crate) fn scene_dump_report(
    observation: &ObservationBundle,
) -> Result<SceneDumpReport, SceneToolError> {
    let require_entries = require_entries(observation)?;
    Ok(SceneDumpReport {
        scene_path: observation.scene_path().to_path_buf(),
        scene_format: observation.scene_format(),
        validation_state: observation.validation_state(),
        requires: require_entries
            .iter()
            .map(|entry| entry.rendered.clone())
            .collect(),
        require_entries,
        script_entries: observation.script_node_entries()?,
    })
}
