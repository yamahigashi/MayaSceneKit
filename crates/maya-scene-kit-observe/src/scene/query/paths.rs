use crate::scene::{
    SceneToolError,
    paths::{PathKind, ScenePathEntry},
    source::{ObservationBundle, ObservationData, mb},
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
            PathKind::File => mb::canonical_scene_path_entry_kind(entry) == PathKind::File,
            PathKind::Reference => {
                mb::canonical_scene_path_entry_kind(entry) == PathKind::Reference
            }
        })
        .collect())
}
