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

fn source_relative_path_candidate(
    raw_value: &str,
    style: ScenePathValueStyle,
    source_scene_dir: Option<&Path>,
) -> Option<PathBuf> {
    let source_scene_dir = source_scene_dir?;
    match style {
        ScenePathValueStyle::PlainRelative => {
            let trimmed = raw_value.trim_start_matches('/');
            (!trimmed.is_empty()).then(|| source_scene_dir.join(trimmed))
        }
        ScenePathValueStyle::DoubleSlashWorkspaceRelative => {
            workspace_relative_suffix(raw_value).map(|suffix| source_scene_dir.join(suffix))
        }
        ScenePathValueStyle::Absolute | ScenePathValueStyle::UncAbsolute => None,
    }
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

#[cfg(test)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SceneFileIdentity {
    pub path: PathBuf,
    pub key: String,
    pub canonical: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScenePathResolutionContext {
    pub workspace_root: Option<PathBuf>,
    pub source_scene_path: Option<PathBuf>,
}

impl ScenePathResolutionContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_workspace_root(workspace_root: Option<impl AsRef<Path>>) -> Self {
        Self {
            workspace_root: workspace_root.map(|path| path.as_ref().to_path_buf()),
            source_scene_path: None,
        }
    }

    pub fn for_scene(
        source_scene_path: impl AsRef<Path>,
        workspace_root: Option<impl AsRef<Path>>,
    ) -> Self {
        Self {
            workspace_root: workspace_root.map(|path| path.as_ref().to_path_buf()),
            source_scene_path: Some(source_scene_path.as_ref().to_path_buf()),
        }
    }

    fn source_scene_dir(&self) -> Option<&Path> {
        self.source_scene_path.as_deref()?.parent()
    }
}

pub struct SceneResourceResolver {
    workspace_roots: BTreeMap<String, Option<PathBuf>>,
    file_exists: BTreeMap<String, bool>,
    identities: BTreeMap<String, SceneFileIdentity>,
}

impl SceneResourceResolver {
    pub fn new() -> Self {
        Self {
            workspace_roots: BTreeMap::new(),
            file_exists: BTreeMap::new(),
            identities: BTreeMap::new(),
        }
    }

    pub fn find_scene_workspace_root(&mut self, scene_path: impl AsRef<Path>) -> Option<PathBuf> {
        let scene_path = scene_path.as_ref();
        let key = scene_path
            .parent()
            .map(lexical_probe_key)
            .unwrap_or_else(|| lexical_probe_key(scene_path));
        if let Some(root) = self.workspace_roots.get(&key) {
            return root.clone();
        }
        let root = find_scene_workspace_root_uncached(scene_path);
        self.workspace_roots.insert(key, root.clone());
        root
    }

    pub fn resolve_scene_path_value(
        &mut self,
        raw_value: &str,
        context: &ScenePathResolutionContext,
    ) -> ScenePathResolution {
        let (style, workspace_path) =
            resolve_scene_path_candidate(raw_value, context.workspace_root.as_deref());
        let workspace_resolution = self.resolution_from_candidate(style, workspace_path);
        if workspace_resolution.status == ScenePathResolutionStatus::Exists {
            return workspace_resolution;
        }

        let Some(source_path) =
            source_relative_path_candidate(raw_value, style, context.source_scene_dir())
        else {
            return workspace_resolution;
        };
        let source_resolution = self.resolution_from_candidate(style, Some(source_path));
        if source_resolution.status == ScenePathResolutionStatus::Exists
            || workspace_resolution.status == ScenePathResolutionStatus::Unresolved
        {
            source_resolution
        } else {
            workspace_resolution
        }
    }

    pub fn resolve_scene_path_values<'a>(
        &mut self,
        raw_values: impl IntoIterator<Item = &'a str>,
        context: &ScenePathResolutionContext,
    ) -> Vec<ScenePathResolution> {
        raw_values
            .into_iter()
            .map(|raw_value| self.resolve_scene_path_value(raw_value, context))
            .collect()
    }

    pub fn scene_file_identity(&mut self, path: impl AsRef<Path>) -> SceneFileIdentity {
        let path = path.as_ref();
        let lexical_key = lexical_probe_key(path);
        if let Some(identity) = self.identities.get(&lexical_key) {
            return identity.clone();
        }
        let identity = match path.canonicalize() {
            Ok(canonical_path) => SceneFileIdentity {
                key: lexical_probe_key(&canonical_path),
                path: canonical_path,
                canonical: true,
            },
            Err(_) => SceneFileIdentity {
                key: lexical_key.clone(),
                path: path.to_path_buf(),
                canonical: false,
            },
        };
        self.identities.insert(lexical_key, identity.clone());
        identity
    }

    fn resolution_from_candidate(
        &mut self,
        style: ScenePathValueStyle,
        resolved_path: Option<PathBuf>,
    ) -> ScenePathResolution {
        let status = match resolved_path.as_ref() {
            Some(path) if self.is_file(path) => ScenePathResolutionStatus::Exists,
            Some(_) => ScenePathResolutionStatus::Missing,
            None => ScenePathResolutionStatus::Unresolved,
        };
        ScenePathResolution {
            style,
            resolved_path,
            status,
        }
    }

    fn is_file(&mut self, path: &Path) -> bool {
        let key = lexical_probe_key(path);
        *self
            .file_exists
            .entry(key.clone())
            .or_insert_with(|| Path::new(&key).is_file())
    }
}

impl Default for SceneResourceResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
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

fn find_scene_workspace_root_uncached(scene_path: &Path) -> Option<PathBuf> {
    let mut current = scene_path.parent()?;
    loop {
        if current.join("workspace.mel").is_file() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

pub fn find_scene_workspace_root(scene_path: impl AsRef<Path>) -> Option<PathBuf> {
    SceneResourceResolver::new().find_scene_workspace_root(scene_path)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs,
        path::{Path, PathBuf},
    };

    use super::{
        ScenePathResolutionContext, SceneResourceResolver, find_scene_workspace_root,
        lexical_normalize_path_string, resolve_scene_path_candidate,
        resolve_scene_path_candidates_with_probe,
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
    fn resolve_scene_path_value_marks_relative_without_context_unresolved() {
        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::new();
        let resolution = resolver.resolve_scene_path_value("textures/albedo.png", &context);

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

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let resolution = resolver.resolve_scene_path_value("textures/albedo.png", &context);

        assert_eq!(resolution.style, ScenePathValueStyle::PlainRelative);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(target));
    }

    #[test]
    fn resolve_scene_path_value_preserves_absolute_paths() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let absolute = dir.path().join("absolute.png");
        fs::write(&absolute, "png").expect("write absolute");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::for_scene(
            dir.path().join("scenes/scene.ma"),
            Some(dir.path()),
        );
        let resolution =
            resolver.resolve_scene_path_value(absolute.to_string_lossy().as_ref(), &context);

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

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let resolution =
            resolver.resolve_scene_path_value("C:/project//sourceimages/albedo.png", &context);

        assert_eq!(
            resolution.style,
            ScenePathValueStyle::DoubleSlashWorkspaceRelative
        );
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(target));
    }

    #[test]
    fn resolve_scene_path_value_preserves_unc_paths() {
        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::new();
        let resolution = resolver.resolve_scene_path_value("//server/share/albedo.png", &context);

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

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let resolution = resolver.resolve_scene_path_value("textures/missing.png", &context);

        assert_eq!(resolution.style, ScenePathValueStyle::PlainRelative);
        assert_eq!(resolution.status, ScenePathResolutionStatus::Missing);
        assert_eq!(
            resolution.resolved_path,
            Some(workspace.join("textures/missing.png"))
        );
    }

    #[test]
    fn resolve_scene_path_values_matches_repeated_single_resolution() {
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
        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let batch = resolver.resolve_scene_path_values(values, &context);
        let singles = values
            .into_iter()
            .map(|value| resolver.resolve_scene_path_value(value, &context))
            .collect::<Vec<_>>();

        assert_eq!(batch, singles);
    }

    #[test]
    fn resolver_repeated_resolution_matches_batch_resolution() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("scenes")).expect("mkdir scenes");
        let target = workspace.join("scenes/child.ma");
        fs::write(&target, "// scene").expect("write scene");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let via_resolver = resolver.resolve_scene_path_value("scenes/child.ma", &context);
        let via_batch = resolver
            .resolve_scene_path_values(["scenes/child.ma"], &context)
            .into_iter()
            .next()
            .expect("resolution");

        assert_eq!(via_resolver, via_batch);
    }

    #[test]
    fn resolver_context_uses_source_parent_fallback_without_workspace() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source_dir = dir.path().join("shots");
        fs::create_dir_all(&source_dir).expect("mkdir shots");
        let source = source_dir.join("root.ma");
        let child = source_dir.join("child.ma");
        fs::write(&source, "// root").expect("write root");
        fs::write(&child, "// child").expect("write child");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::for_scene(&source, None::<&Path>);
        let resolution = resolver.resolve_scene_path_value("child.ma", &context);

        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(child));
    }

    #[test]
    fn resolver_context_prefers_existing_workspace_path_over_source_parent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        let source_dir = dir.path().join("shots");
        fs::create_dir_all(workspace.join("assets")).expect("mkdir workspace assets");
        fs::create_dir_all(source_dir.join("assets")).expect("mkdir source assets");
        let source = source_dir.join("scene.ma");
        let workspace_target = workspace.join("assets/texture.tx");
        let source_target = source_dir.join("assets/texture.tx");
        fs::write(&source, "// scene").expect("write scene");
        fs::write(&workspace_target, "workspace").expect("write workspace target");
        fs::write(&source_target, "source").expect("write source target");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::for_scene(&source, Some(&workspace));
        let resolution = resolver.resolve_scene_path_value("assets/texture.tx", &context);

        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(workspace_target));
    }

    #[test]
    fn resolver_context_uses_source_parent_when_workspace_candidate_is_missing() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        let source_dir = dir.path().join("shots");
        fs::create_dir_all(&workspace).expect("mkdir workspace");
        fs::create_dir_all(source_dir.join("assets")).expect("mkdir source assets");
        let source = source_dir.join("scene.ma");
        let source_target = source_dir.join("assets/texture.tx");
        fs::write(&source, "// scene").expect("write scene");
        fs::write(&source_target, "source").expect("write source target");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::for_scene(&source, Some(&workspace));
        let resolution = resolver.resolve_scene_path_value("assets/texture.tx", &context);

        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(source_target));
    }

    #[test]
    fn resolver_context_reports_source_parent_missing_when_no_workspace_exists() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source_dir = dir.path().join("shots");
        fs::create_dir_all(&source_dir).expect("mkdir source");
        let source = source_dir.join("scene.ma");
        fs::write(&source, "// scene").expect("write scene");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::for_scene(&source, None::<&Path>);
        let resolution = resolver.resolve_scene_path_value("assets/missing.tx", &context);

        assert_eq!(resolution.status, ScenePathResolutionStatus::Missing);
        assert_eq!(
            resolution.resolved_path,
            Some(source_dir.join("assets/missing.tx"))
        );
    }

    #[test]
    fn resolver_context_uses_source_parent_for_double_slash_fallback() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        let source_dir = dir.path().join("shots");
        fs::create_dir_all(&workspace).expect("mkdir workspace");
        fs::create_dir_all(source_dir.join("sourceimages")).expect("mkdir sourceimages");
        let source = source_dir.join("scene.ma");
        let source_target = source_dir.join("sourceimages/albedo.png");
        fs::write(&source, "// scene").expect("write scene");
        fs::write(&source_target, "png").expect("write source target");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::for_scene(&source, Some(&workspace));
        let resolution =
            resolver.resolve_scene_path_value("C:/project//sourceimages/albedo.png", &context);

        assert_eq!(
            resolution.style,
            ScenePathValueStyle::DoubleSlashWorkspaceRelative
        );
        assert_eq!(resolution.status, ScenePathResolutionStatus::Exists);
        assert_eq!(resolution.resolved_path, Some(source_target));
    }

    #[test]
    fn lexical_probe_key_collapses_equivalent_parent_segments() {
        assert_eq!(
            lexical_normalize_path_string("V:/show/assets/../textures/body.tx"),
            lexical_normalize_path_string("v:\\show\\textures\\body.tx")
        );
    }

    #[test]
    fn resolve_scene_path_values_deduplicates_probe_targets() {
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
    fn resolve_scene_path_values_preserves_maya_double_slash_parent_segments() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let workspace = dir.path().join("project");
        fs::create_dir_all(workspace.join("sourceimages")).expect("mkdir sourceimages");
        let target = workspace.join("sourceimages/body.tx");
        fs::write(&target, "tx").expect("write target");

        let mut resolver = SceneResourceResolver::new();
        let context = ScenePathResolutionContext::from_workspace_root(Some(&workspace));
        let resolution = resolver
            .resolve_scene_path_values(
                ["V:/show/project//assets/../sourceimages/body.tx"],
                &context,
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
