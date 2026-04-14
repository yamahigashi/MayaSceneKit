// Raw MA path helpers are best-effort text walkers for rewrite/raw tooling.
// Canonical read/report APIs should prefer MA AST extraction.
use crate::ScenePathEntry;

pub fn extract_raw_scene_paths_from_ma(data: &[u8]) -> Vec<ScenePathEntry> {
    crate::ma::selective::extract_raw_selective_sections_from_ma(data).scene_paths
}
