use std::path::Path;

use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, ObservationBundle, ReadStability, SceneToolError,
};

/// Acquires source bytes for editing, retrying once if the file changed during the read.
pub fn read_scene_edit_source(
    path: &Path,
    options: &LoadOptions,
) -> Result<(ObservationBundle, Vec<u8>), SceneToolError> {
    let loader = Loader::new(options.clone());
    read_stable(path, || {
        let source = loader.observe_path_with_bytes(path)?;
        let stability = source.0.source_read_stability();
        Ok((source, stability))
    })
}

pub(super) fn read_stable<T>(
    path: &Path,
    mut read: impl FnMut() -> Result<(T, ReadStability), SceneToolError>,
) -> Result<T, SceneToolError> {
    let (value, stability) = read()?;
    if stability != ReadStability::Unstable {
        return Ok(value);
    }
    drop(value);
    let (value, stability) = read()?;
    if stability == ReadStability::Unstable {
        return Err(SceneToolError::SourceUnstable {
            path: path.to_path_buf(),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_source_uses_first_read_once() {
        let mut calls = 0;
        let value = read_stable(Path::new("Example.ma"), || {
            calls += 1;
            Ok((calls, ReadStability::Stable))
        })
        .unwrap();
        assert_eq!(value, 1);
        assert_eq!(calls, 1);
    }

    #[test]
    fn unstable_source_uses_second_stable_read() {
        let mut calls = 0;
        let value = read_stable(Path::new("Example.ma"), || {
            calls += 1;
            Ok((
                calls,
                if calls == 1 {
                    ReadStability::Unstable
                } else {
                    ReadStability::Stable
                },
            ))
        })
        .unwrap();
        assert_eq!(value, 2);
        assert_eq!(calls, 2);
    }

    #[test]
    fn unstable_source_twice_refuses_with_path() {
        let path = Path::new("Example.ma");
        let mut calls = 0;
        let result = read_stable(path, || {
            calls += 1;
            Ok((calls, ReadStability::Unstable))
        });
        assert!(
            matches!(result, Err(SceneToolError::SourceUnstable { path: changed }) if changed == path)
        );
        assert_eq!(calls, 2);
    }
}
