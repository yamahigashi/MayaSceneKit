use std::path::PathBuf;

use crate::scene::schema::SchemaInputs;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::scene) struct SchemaPaths {
    pub(in crate::scene) chunk_schema_root: PathBuf,
    pub(in crate::scene) refedit_schema_file: PathBuf,
    pub(in crate::scene) addattr_schema_file: PathBuf,
    pub(in crate::scene) structural_attr_schema_file: PathBuf,
    pub(in crate::scene) node_info_schema_file: PathBuf,
    pub(in crate::scene) additional_node_info_files: Vec<PathBuf>,
    resolution_error: Option<String>,
}

impl SchemaPaths {
    pub(in crate::scene) fn from_defaults() -> Self {
        Self::from_schema_inputs(&SchemaInputs {
            schema_root: None,
            chunk_schema_root: None,
            addattr_schema_path: None,
            structural_attr_schema_path: None,
            refedit_schema_path: None,
            additional_node_info_paths: &[],
        })
    }

    pub(in crate::scene) fn from_schema_inputs(inputs: &SchemaInputs<'_>) -> Self {
        let default_root = inputs
            .schema_root
            .is_none()
            .then(default_schema_root_resolution)
            .flatten();
        let schema_root = inputs
            .schema_root
            .cloned()
            .unwrap_or_else(|| default_root_path(&default_root));
        let chunk_schema_root = inputs
            .chunk_schema_root
            .cloned()
            .unwrap_or_else(|| schema_root.join("chunks"));
        let refedit_schema_file = inputs
            .refedit_schema_path
            .cloned()
            .unwrap_or_else(|| chunk_schema_root.join("REFE").join("ed.yaml"));
        let addattr_schema_file = inputs
            .addattr_schema_path
            .cloned()
            .unwrap_or_else(|| schema_root.join("add_attr_tokens.yaml"));
        let structural_attr_schema_file = inputs
            .structural_attr_schema_path
            .cloned()
            .unwrap_or_else(|| schema_root.join("structural_attr_handlers.yaml"));
        let node_info_schema_file = schema_root.join("node_info.yaml");

        Self {
            chunk_schema_root,
            refedit_schema_file,
            addattr_schema_file,
            structural_attr_schema_file,
            node_info_schema_file,
            additional_node_info_files: inputs.additional_node_info_paths.to_vec(),
            resolution_error: default_root.and_then(|resolution| resolution.error),
        }
    }

    pub(in crate::scene) fn resolution_error(&self) -> Option<&str> {
        self.resolution_error.as_deref()
    }
}

#[cfg(test)]
fn default_schema_root_dir() -> PathBuf {
    default_root_path(&default_schema_root_resolution())
}

fn schema_root_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("schemas"));
            if let Some(parent) = dir.parent() {
                out.push(parent.join("schemas"));
            }
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    out.push(manifest_dir.join("schemas"));
    for ancestor in manifest_dir.ancestors().skip(1) {
        out.push(ancestor.join("schemas"));
    }
    out
}

#[derive(Debug)]
struct DefaultSchemaRootResolution {
    path: PathBuf,
    error: Option<String>,
}

fn default_schema_root_resolution() -> Option<DefaultSchemaRootResolution> {
    default_schema_root_resolution_from_candidates(schema_root_candidates())
}

fn default_schema_root_resolution_from_candidates(
    candidates: Vec<PathBuf>,
) -> Option<DefaultSchemaRootResolution> {
    for candidate in candidates {
        if candidate.exists() {
            return Some(DefaultSchemaRootResolution {
                path: candidate,
                error: None,
            });
        }
    }

    match super::embedded::schema_root() {
        Ok(path) => Some(DefaultSchemaRootResolution {
            path: path.clone(),
            error: None,
        }),
        Err(err) => Some(DefaultSchemaRootResolution {
            path: PathBuf::from("schemas"),
            error: Some(err),
        }),
    }
}

fn default_root_path(resolution: &Option<DefaultSchemaRootResolution>) -> PathBuf {
    resolution
        .as_ref()
        .map(|resolution| resolution.path.clone())
        .unwrap_or_else(|| PathBuf::from("schemas"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        default_schema_root_dir, default_schema_root_resolution_from_candidates,
        schema_root_candidates,
    };

    #[test]
    fn default_schema_root_dir_prefers_existing_packaged_location() {
        let root = default_schema_root_dir();
        assert!(root.ends_with("schemas"));
        assert!(root.exists());
    }

    #[test]
    fn schema_root_candidates_include_manifest_schema_dir() {
        let manifest_schema_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas");
        assert!(schema_root_candidates().contains(&manifest_schema_dir));
    }

    #[test]
    fn default_schema_root_resolution_uses_embedded_fallback_when_candidates_missing() {
        let resolution =
            default_schema_root_resolution_from_candidates(Vec::new()).expect("resolution");
        assert_eq!(
            resolution.path,
            super::super::embedded::schema_root()
                .expect("embedded schema root")
                .clone()
        );
        assert!(resolution.error.is_none());
    }
}
