use crate::scene::{
    SceneToolError,
    scripts::ScriptNodeEntry,
    source::{ObservationBundle, ObservationData},
};

pub(crate) fn script_node_entries(
    observation: &ObservationBundle,
) -> Result<Vec<ScriptNodeEntry>, SceneToolError> {
    match &observation.data {
        ObservationData::Ma { data } => Ok(crate::scene::source::ma::collect_ma_script_entries(
            data.script_entries(),
        )),
        ObservationData::Mb { session } => Ok(session.script_entries().to_vec()),
    }
}
