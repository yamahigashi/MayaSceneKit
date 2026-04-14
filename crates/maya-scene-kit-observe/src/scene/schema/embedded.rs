use std::{
    env, fs, io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use include_dir::{Dir, include_dir};

static EMBEDDED_SCHEMAS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../schemas");
static MATERIALIZED_SCHEMA_ROOT: OnceLock<Result<PathBuf, String>> = OnceLock::new();

pub(in crate::scene) fn schema_root() -> Result<&'static PathBuf, String> {
    MATERIALIZED_SCHEMA_ROOT
        .get_or_init(materialize_schema_root)
        .as_ref()
        .map_err(Clone::clone)
}

fn materialize_schema_root() -> Result<PathBuf, String> {
    let root = env::temp_dir()
        .join("maya-scene-kit")
        .join(format!("schemas-{}", env!("CARGO_PKG_VERSION")));
    write_embedded_dir(&root, &EMBEDDED_SCHEMAS).map_err(|err| {
        format!(
            "failed to materialize embedded schemas at {}: {err}",
            root.display()
        )
    })?;
    Ok(root)
}

fn write_embedded_dir(root: &Path, dir: &Dir<'_>) -> io::Result<()> {
    fs::create_dir_all(root)?;

    for file in dir.files() {
        let path = root.join(file.path());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, file.contents())?;
    }

    for child in dir.dirs() {
        write_embedded_dir(root, child)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::schema_root;

    #[test]
    fn materialized_schema_root_contains_required_assets() {
        let root = schema_root().expect("schema root");
        assert!(root.join("node_info.yaml").exists());
        assert!(root.join("chunks").join("REFE").join("ed.yaml").exists());
    }
}
