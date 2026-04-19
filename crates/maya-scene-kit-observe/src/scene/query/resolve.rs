use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::scene::paths::{ScenePathResolution, ScenePathResolutionStatus, ScenePathValueStyle};

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn classify_scene_path_value_style(value: &str) -> ScenePathValueStyle {
    if value.starts_with("//") || value.starts_with("\\\\") {
        return ScenePathValueStyle::UncAbsolute;
    }
    if value.contains("//") {
        return ScenePathValueStyle::DoubleSlashWorkspaceRelative;
    }
    if Path::new(value).is_absolute() || has_windows_drive_prefix(value) {
        return ScenePathValueStyle::Absolute;
    }
    ScenePathValueStyle::PlainRelative
}

fn workspace_relative_suffix(value: &str) -> Option<&str> {
    let (_prefix, suffix) = value.split_once("//")?;
    let suffix = suffix.trim_start_matches('/');
    (!suffix.is_empty()).then_some(suffix)
}

fn resolve_scene_path_candidate(
    raw_value: &str,
    workspace_root: Option<&Path>,
) -> (ScenePathValueStyle, Option<PathBuf>) {
    let style = classify_scene_path_value_style(raw_value);
    let resolved_path = match style {
        ScenePathValueStyle::PlainRelative => workspace_root.and_then(|workspace_root| {
            let trimmed = raw_value.trim_start_matches('/');
            (!trimmed.is_empty()).then(|| workspace_root.join(trimmed))
        }),
        ScenePathValueStyle::Absolute | ScenePathValueStyle::UncAbsolute => {
            Some(PathBuf::from(raw_value))
        }
        ScenePathValueStyle::DoubleSlashWorkspaceRelative => {
            workspace_root.and_then(|workspace_root| {
                workspace_relative_suffix(raw_value).map(|suffix| workspace_root.join(suffix))
            })
        }
    };

    (style, resolved_path)
}

fn lexical_probe_key(path: &Path) -> String {
    lexical_normalize_path_string(&path.to_string_lossy())
}

fn lexical_normalize_path_string(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let mut segments = Vec::new();

    if let Some(stripped) = normalized.strip_prefix("//") {
        for segment in stripped.split('/') {
            push_lexical_segment(&mut segments, segment, 2, false);
        }
        if segments.is_empty() {
            return "//".to_string();
        }
        return format!("//{}", segments.join("/"));
    }

    if has_windows_drive_prefix(&normalized) {
        let drive = normalized.as_bytes()[0] as char;
        let rest = normalized[2..].trim_start_matches('/');
        for segment in rest.split('/') {
            push_lexical_segment(&mut segments, segment, 0, false);
        }
        if segments.is_empty() {
            return format!("{}:/", drive.to_ascii_uppercase());
        }
        return format!("{}:/{}", drive.to_ascii_uppercase(), segments.join("/"));
    }

    if let Some(stripped) = normalized.strip_prefix('/') {
        for segment in stripped.split('/') {
            push_lexical_segment(&mut segments, segment, 0, false);
        }
        if segments.is_empty() {
            return "/".to_string();
        }
        return format!("/{}", segments.join("/"));
    }

    for segment in normalized.split('/') {
        push_lexical_segment(&mut segments, segment, 0, true);
    }
    segments.join("/")
}

fn push_lexical_segment<'a>(
    segments: &mut Vec<&'a str>,
    segment: &'a str,
    protected_prefix_len: usize,
    allow_parent_escape: bool,
) {
    if segment.is_empty() || segment == "." {
        return;
    }
    if segment == ".." {
        if segments.len() > protected_prefix_len && segments.last().copied() != Some("..") {
            segments.pop();
        } else if allow_parent_escape {
            segments.push(segment);
        }
        return;
    }
    segments.push(segment);
}

fn build_resolution_from_candidate(
    style: ScenePathValueStyle,
    resolved_path: Option<PathBuf>,
    probe_cache: &BTreeMap<String, bool>,
) -> ScenePathResolution {
    let status = match resolved_path.as_ref() {
        Some(path)
            if probe_cache
                .get(&lexical_probe_key(path))
                .copied()
                .unwrap_or(false) =>
        {
            ScenePathResolutionStatus::Exists
        }
        Some(_) => ScenePathResolutionStatus::Missing,
        None => ScenePathResolutionStatus::Unresolved,
    };

    ScenePathResolution {
        style,
        resolved_path,
        status,
    }
}

fn resolve_scene_path_candidates_with_probe<F>(
    candidates: Vec<(ScenePathValueStyle, Option<PathBuf>)>,
    mut probe: F,
) -> Vec<ScenePathResolution>
where
    F: FnMut(&Path) -> bool,
{
    let mut probe_cache = BTreeMap::new();
    for (_, path) in &candidates {
        let Some(path) = path.as_deref() else {
            continue;
        };
        let key = lexical_probe_key(path);
        probe_cache
            .entry(key.clone())
            .or_insert_with(|| probe(Path::new(&key)));
    }

    candidates
        .into_iter()
        .map(|(style, resolved_path)| {
            build_resolution_from_candidate(style, resolved_path, &probe_cache)
        })
        .collect()
}

pub fn find_scene_workspace_root(scene_path: impl AsRef<Path>) -> Option<PathBuf> {
    let mut current = scene_path.as_ref().parent()?;
    loop {
        if current.join("workspace.mel").is_file() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

pub fn resolve_scene_path_value(
    raw_value: &str,
    workspace_root: Option<&Path>,
) -> ScenePathResolution {
    let candidate = resolve_scene_path_candidate(raw_value, workspace_root);
    resolve_scene_path_candidates_with_probe(vec![candidate], |path| path.is_file())
        .into_iter()
        .next()
        .expect("single path resolution")
}

pub fn resolve_scene_path_values_batch<'a>(
    raw_values: impl IntoIterator<Item = &'a str>,
    workspace_root: Option<&Path>,
) -> Vec<ScenePathResolution> {
    let candidates = raw_values
        .into_iter()
        .map(|raw_value| resolve_scene_path_candidate(raw_value, workspace_root))
        .collect::<Vec<_>>();
    resolve_scene_path_candidates_with_probe(candidates, |path| path.is_file())
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, fs, path::PathBuf};

    use super::{
        find_scene_workspace_root, lexical_normalize_path_string, resolve_scene_path_candidate,
        resolve_scene_path_candidates_with_probe, resolve_scene_path_value,
        resolve_scene_path_values_batch,
    };
    use crate::scene::paths::{ScenePathResolutionStatus, ScenePathValueStyle};

    #[test]
    fn find_scene_workspace_root_returns_nearest_workspace() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let outer = dir.path().join("workspace");
        let inner = outer.join("shots/shot01");
        fs::create_dir_all(&inner).expect("create dirs");
        fs::write(outer.join("workspace.mel"), "// outer").expect("write outer workspace");
        fs::write(inner.join("workspace.mel"), "// inner").expect("write inner workspace");
        let scene_path = inner.join("scene.ma");
        fs::write(&scene_path, "// scene").expect("write scene");

        assert_eq!(find_scene_workspace_root(&scene_path), Some(inner));
    }

    #[test]
    fn resolve_scene_path_value_marks_relative_without_workspace_unresolved() {
        let resolution = resolve_scene_path_value("textures/albedo.png", None);

        assert_eq!(resolution.style, ScenePathValueStyle::PlainRelative);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Unresolved);
        assert_eq!(resolution.resolved_path, None);
    }

    #[test]
    fn resolve_scene_path_value_joins_plain_relative_to_workspace_root() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("textures")).expect("create textures");
        let target = workspace.join("textures/albedo.png");
        fs::write(&target, "png").expect("write texture");

        let resolution = resolve_scene_path_value("textures/albedo.png", Some(&workspace));

        assert_eq!(resolution.style, ScenePathValueStyle::PlainRelative);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(target));
    }

    #[test]
    fn resolve_scene_path_value_preserves_absolute_paths() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let absolute = dir.path().join("absolute.png");
        fs::write(&absolute, "png").expect("write absolute");

        let resolution =
            resolve_scene_path_value(absolute.to_string_lossy().as_ref(), Some(dir.path()));

        assert_eq!(resolution.style, ScenePathValueStyle::Absolute);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(absolute));
    }

    #[test]
    fn resolve_scene_path_value_uses_suffix_for_maya_double_slash_style() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("sourceimages")).expect("create sourceimages");
        let target = workspace.join("sourceimages/albedo.png");
        fs::write(&target, "png").expect("write texture");

        let resolution =
            resolve_scene_path_value("C:/project//sourceimages/albedo.png", Some(&workspace));

        assert_eq!(
            resolution.style,
            ScenePathValueStyle::DoubleSlashWorkspaceRelative
        );
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(target));
    }

    #[test]
    fn resolve_scene_path_value_preserves_unc_paths() {
        let resolution = resolve_scene_path_value("//server/share/albedo.png", None);

        assert_eq!(resolution.style, ScenePathValueStyle::UncAbsolute);
        assert_eq!(
            resolution.resolved_path,
            Some(PathBuf::from("//server/share/albedo.png"))
        );
        assert_eq!(resolution.status, ScenePathResolutionStatus::Missing);
    }

    #[test]
    fn resolve_scene_path_value_distinguishes_missing_candidates() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(&workspace).expect("create workspace");

        let resolution = resolve_scene_path_value("textures/missing.png", Some(&workspace));

        assert_eq!(resolution.style, ScenePathValueStyle::PlainRelative);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Missing);
        assert_eq!(
            resolution.resolved_path,
            Some(workspace.join("textures/missing.png"))
        );
    }

    #[test]
    fn resolve_scene_path_values_batch_matches_repeated_single_resolution() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("textures")).expect("mkdir textures");
        fs::write(workspace.join("textures/existing.tx"), "tx").expect("write texture");

        let values = [
            "textures/existing.tx",
            "textures/missing.tx",
            "C:/project//textures/existing.tx",
            "//server/share/missing.tx",
        ];
        let batch = resolve_scene_path_values_batch(values, Some(&workspace));
        let singles = values
            .into_iter()
            .map(|value| resolve_scene_path_value(value, Some(&workspace)))
            .collect::<Vec<_>>();

        assert_eq!(batch, singles);
    }

    #[test]
    fn lexical_probe_key_collapses_equivalent_parent_segments() {
        assert_eq!(
            lexical_normalize_path_string("V:/show/assets/../textures/body.tx"),
            lexical_normalize_path_string("v:\\show\\textures\\body.tx")
        );
    }

    #[test]
    fn resolve_scene_path_values_batch_deduplicates_probe_targets() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
        let target = workspace.join("sourceimages/body.tx");
        fs::write(&target, "tx").expect("write target");

        let candidates = [
            resolve_scene_path_candidate("sourceimages/body.tx", Some(&workspace)),
            resolve_scene_path_candidate("sourceimages/./body.tx", Some(&workspace)),
            resolve_scene_path_candidate("assets/../sourceimages/body.tx", Some(&workspace)),
        ];
        let probe_calls = Cell::new(0usize);
        let resolutions = resolve_scene_path_candidates_with_probe(candidates.to_vec(), |path| {
            probe_calls.set(probe_calls.get() + 1);
            path.is_file()
        });

        assert_eq!(probe_calls.get(), 1);
        assert!(
            resolutions
                .iter()
                .all(|resolution| resolution.status == ScenePathResolutionStatus::Exists)
        );
    }

    #[test]
    fn resolve_scene_path_values_batch_preserves_maya_double_slash_parent_segments() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
        let target = workspace.join("sourceimages/body.tx");
        fs::write(&target, "tx").expect("write target");

        let resolution = resolve_scene_path_values_batch(
            ["V:/show/project//assets/../sourceimages/body.tx"],
            Some(&workspace),
        )
        .into_iter()
        .next()
        .expect("batch result");

        assert_eq!(
            resolution.style,
            ScenePathValueStyle::DoubleSlashWorkspaceRelative
        );
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(
            resolution.resolved_path,
            Some(workspace.join("assets/../sourceimages/body.tx"))
        );
    }
}
