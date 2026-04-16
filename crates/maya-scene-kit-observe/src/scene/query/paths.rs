use crate::scene::{
    PathKind, ScenePathEntry, SceneToolError,
    source::{ObservationBundle, ObservationData},
};

pub(crate) fn scene_paths(
    observation: &ObservationBundle,
    kind: PathKind,
) -> Result<Vec<ScenePathEntry>, SceneToolError> {
    let entries = match &observation.data {
        ObservationData::Ma { data } => data.scene_paths().to_vec(),
        ObservationData::Mb { session } => session.scene_paths_all()?.to_vec(),
    };

    Ok(entries
        .into_iter()
        .filter(|entry| match kind {
            PathKind::All => true,
            PathKind::File => {
                crate::scene::observe::mb::canonical_scene_path_entry_kind(entry) == PathKind::File
            }
            PathKind::Reference => {
                crate::scene::observe::mb::canonical_scene_path_entry_kind(entry)
                    == PathKind::Reference
            }
        })
        .collect())
}
