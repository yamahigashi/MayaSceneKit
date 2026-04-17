use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::UNIX_EPOCH,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scene::{
    LoadOptions, ObservationBundle, SceneDigestSet, SceneToolError,
    dump::SceneDumpReport,
    execution::{
        ExecutionSurface, MelSurfaceCall, MelSurfaceCallSurfaceKind, MelSurfaceCommandMode,
        MelSurfaceDiagnostic, MelSurfaceDiagnosticStage, MelSurfaceFacts, MelSurfaceNormalizedArg,
        MelSurfaceNormalizedCommand, MelSurfaceNormalizedFlag, MelSurfaceNormalizedItem,
        MelSurfaceValidationDiagnostic, ObservedExecutionCatalog, ObservedExecutionSurface,
    },
    paths::{PathKind, ScenePathsReport},
};

const OBSERVE_CACHE_SCHEMA_VERSION: u32 = 1;
const INDEX_FILE: &str = "index.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveCacheIdentity {
    pub cache_schema_version: u32,
    pub scene_sha256: String,
    pub load_options_fingerprint: String,
    pub max_preview: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveFileState {
    pub path: PathBuf,
    pub size: u64,
    pub modified_unix_nanos: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedSceneSnapshot {
    pub identity: ObserveCacheIdentity,
    pub file_state: ObserveFileState,
    pub digests: SceneDigestSet,
    pub paths_report: ScenePathsReport,
    pub dump_report: SceneDumpReport,
    pub execution_catalog: ObservedExecutionCatalogSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedExecutionCatalogSnapshot {
    pub surfaces: Vec<ObservedExecutionSurfaceSnapshot>,
    pub unit_summaries: Vec<crate::scene::ExecutionUnitSummary>,
    pub dependency_facts: Vec<crate::scene::DependencyFact>,
    pub unknown_semantics: Vec<crate::scene::UnknownSemanticFact>,
    pub digests: SceneDigestSet,
    pub coverage_state: crate::scene::ExecutionCoverageState,
    pub coverage_issues: Vec<crate::scene::ExecutionCoverageIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedExecutionSurfaceSnapshot {
    pub surface: ExecutionSurfaceSnapshot,
    pub mel: Option<MelSurfaceFactsSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSurfaceSnapshot {
    pub text: String,
    pub origin: crate::scene::ExecutionOrigin,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MelSurfaceFactsSnapshot {
    pub source_text: String,
    pub diagnostics: Vec<MelSurfaceDiagnosticSnapshot>,
    pub validation_diagnostics: Vec<MelSurfaceValidationDiagnosticSnapshot>,
    pub calls: Vec<MelSurfaceCallSnapshot>,
    pub normalized_commands: Vec<MelSurfaceNormalizedCommandSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MelSurfaceDiagnosticSnapshot {
    pub stage: MelSurfaceDiagnosticStageSnapshot,
    pub message: String,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MelSurfaceValidationDiagnosticSnapshot {
    pub head: Option<String>,
    pub message: String,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MelSurfaceCallSnapshot {
    pub name: String,
    pub surface_kind: MelSurfaceCallSurfaceKindSnapshot,
    pub captured: bool,
    pub literal_first_arg: Option<String>,
    pub dynamic: bool,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MelSurfaceNormalizedArgSnapshot {
    pub text_span: maya_scene_kit_formats::mel::MelSpan,
    pub literal: Option<String>,
    pub dynamic: bool,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MelSurfaceNormalizedFlagSnapshot {
    pub source_span: maya_scene_kit_formats::mel::MelSpan,
    pub canonical_name: Option<String>,
    pub value_shapes: Vec<maya_scene_kit_formats::mel::MelValueShape>,
    pub args: Vec<MelSurfaceNormalizedArgSnapshot>,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MelSurfaceNormalizedItemSnapshot {
    Flag(MelSurfaceNormalizedFlagSnapshot),
    Positional(MelSurfaceNormalizedArgSnapshot),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MelSurfaceNormalizedCommandSnapshot {
    pub schema_name: String,
    pub mode: MelSurfaceCommandModeSnapshot,
    pub items: Vec<MelSurfaceNormalizedItemSnapshot>,
    pub span_start: usize,
    pub span_end: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MelSurfaceDiagnosticStageSnapshot {
    Decode,
    Lex,
    Parse,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MelSurfaceCallSurfaceKindSnapshot {
    Function,
    ShellLike,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MelSurfaceCommandModeSnapshot {
    Create,
    Edit,
    Query,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObserveCacheIndexRecord {
    file_state: ObserveFileState,
    identity: ObserveCacheIdentity,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct ObserveCacheIndex {
    by_path: BTreeMap<String, ObserveCacheIndexRecord>,
}

impl ObserveCacheIdentity {
    pub fn new(
        scene_sha256: impl Into<String>,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> Self {
        Self {
            cache_schema_version: OBSERVE_CACHE_SCHEMA_VERSION,
            scene_sha256: scene_sha256.into(),
            load_options_fingerprint: fingerprint_debug(load_options),
            max_preview,
        }
    }

    fn blob_name(&self) -> String {
        format!(
            "{}-{}-{}.json",
            self.scene_sha256, self.load_options_fingerprint, self.max_preview
        )
    }
}

impl ObservedSceneSnapshot {
    pub fn from_observation(
        observation: &ObservationBundle,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> Result<Self, SceneToolError> {
        let file_state =
            file_state_for_path(observation.scene_path()).map_err(SceneToolError::Io)?;
        let digests = observation.scene_digests(0)?;
        let paths_report = ScenePathsReport {
            scene_path: observation.scene_path().to_path_buf(),
            scene_format: observation.scene_format(),
            validation_state: observation.validation_state(),
            entries: observation.scene_paths(PathKind::All)?,
        };
        let dump_report = observation.scene_dump_report()?;
        let execution_catalog = ObservedExecutionCatalogSnapshot::from_catalog(
            observation.observed_execution_catalog(max_preview)?,
        );
        let identity =
            ObserveCacheIdentity::new(digests.scene_sha256.clone(), load_options, max_preview);

        Ok(Self {
            identity,
            file_state,
            digests,
            paths_report,
            dump_report,
            execution_catalog,
        })
    }
}

impl ObservedExecutionCatalogSnapshot {
    pub fn from_catalog(catalog: ObservedExecutionCatalog) -> Self {
        Self {
            surfaces: catalog
                .surfaces
                .into_iter()
                .map(ObservedExecutionSurfaceSnapshot::from_surface)
                .collect(),
            unit_summaries: catalog.unit_summaries,
            dependency_facts: catalog.dependency_facts,
            unknown_semantics: catalog.unknown_semantics,
            digests: catalog.digests,
            coverage_state: catalog.coverage_state,
            coverage_issues: catalog.coverage_issues,
        }
    }

    pub fn into_catalog(self) -> ObservedExecutionCatalog {
        ObservedExecutionCatalog {
            surfaces: self
                .surfaces
                .into_iter()
                .map(ObservedExecutionSurfaceSnapshot::into_surface)
                .collect(),
            unit_summaries: self.unit_summaries,
            dependency_facts: self.dependency_facts,
            unknown_semantics: self.unknown_semantics,
            digests: self.digests,
            coverage_state: self.coverage_state,
            coverage_issues: self.coverage_issues,
        }
    }
}

impl ObservedExecutionSurfaceSnapshot {
    fn from_surface(surface: ObservedExecutionSurface) -> Self {
        Self {
            surface: ExecutionSurfaceSnapshot::from_surface(surface.surface),
            mel: surface
                .mel
                .map(|facts| MelSurfaceFactsSnapshot::from_facts(facts.as_ref())),
        }
    }

    fn into_surface(self) -> ObservedExecutionSurface {
        ObservedExecutionSurface {
            surface: self.surface.into_surface(),
            mel: self.mel.map(|facts| Arc::new(facts.into_facts())),
        }
    }
}

impl ExecutionSurfaceSnapshot {
    fn from_surface(surface: ExecutionSurface) -> Self {
        Self {
            text: surface.text.to_string(),
            origin: surface.origin,
            preview: surface.preview,
        }
    }

    fn into_surface(self) -> ExecutionSurface {
        ExecutionSurface {
            text: Arc::<str>::from(self.text),
            origin: self.origin,
            preview: self.preview,
        }
    }
}

impl MelSurfaceFactsSnapshot {
    fn from_facts(facts: &MelSurfaceFacts) -> Self {
        Self {
            source_text: facts.source_text.to_string(),
            diagnostics: facts
                .diagnostics
                .iter()
                .cloned()
                .map(MelSurfaceDiagnosticSnapshot::from_diagnostic)
                .collect(),
            validation_diagnostics: facts
                .validation_diagnostics
                .iter()
                .cloned()
                .map(MelSurfaceValidationDiagnosticSnapshot::from_diagnostic)
                .collect(),
            calls: facts
                .calls
                .iter()
                .cloned()
                .map(MelSurfaceCallSnapshot::from_call)
                .collect(),
            normalized_commands: facts
                .normalized_commands
                .iter()
                .cloned()
                .map(MelSurfaceNormalizedCommandSnapshot::from_command)
                .collect(),
        }
    }

    fn into_facts(self) -> MelSurfaceFacts {
        MelSurfaceFacts {
            source_text: Arc::<str>::from(self.source_text),
            diagnostics: self
                .diagnostics
                .into_iter()
                .map(MelSurfaceDiagnosticSnapshot::into_diagnostic)
                .collect(),
            validation_diagnostics: self
                .validation_diagnostics
                .into_iter()
                .map(MelSurfaceValidationDiagnosticSnapshot::into_diagnostic)
                .collect(),
            calls: self
                .calls
                .into_iter()
                .map(MelSurfaceCallSnapshot::into_call)
                .collect(),
            normalized_commands: self
                .normalized_commands
                .into_iter()
                .map(MelSurfaceNormalizedCommandSnapshot::into_command)
                .collect(),
        }
    }
}

impl MelSurfaceDiagnosticSnapshot {
    fn from_diagnostic(diagnostic: MelSurfaceDiagnostic) -> Self {
        Self {
            stage: MelSurfaceDiagnosticStageSnapshot::from_stage(diagnostic.stage),
            message: diagnostic.message.into_owned(),
            span_start: diagnostic.span_start,
            span_end: diagnostic.span_end,
        }
    }

    fn into_diagnostic(self) -> MelSurfaceDiagnostic {
        MelSurfaceDiagnostic {
            stage: self.stage.into_stage(),
            message: self.message.into(),
            span_start: self.span_start,
            span_end: self.span_end,
        }
    }
}

impl MelSurfaceValidationDiagnosticSnapshot {
    fn from_diagnostic(diagnostic: MelSurfaceValidationDiagnostic) -> Self {
        Self {
            head: diagnostic.head.map(|value| value.to_string()),
            message: diagnostic.message.into_owned(),
            span_start: diagnostic.span_start,
            span_end: diagnostic.span_end,
        }
    }

    fn into_diagnostic(self) -> MelSurfaceValidationDiagnostic {
        MelSurfaceValidationDiagnostic {
            head: self.head.map(Arc::<str>::from),
            message: self.message.into(),
            span_start: self.span_start,
            span_end: self.span_end,
        }
    }
}

impl MelSurfaceCallSnapshot {
    fn from_call(call: MelSurfaceCall) -> Self {
        Self {
            name: call.name.to_string(),
            surface_kind: MelSurfaceCallSurfaceKindSnapshot::from_kind(call.surface_kind),
            captured: call.captured,
            literal_first_arg: call.literal_first_arg.map(|value| value.to_string()),
            dynamic: call.dynamic,
            span_start: call.span_start,
            span_end: call.span_end,
        }
    }

    fn into_call(self) -> MelSurfaceCall {
        MelSurfaceCall {
            name: Arc::<str>::from(self.name),
            surface_kind: self.surface_kind.into_kind(),
            captured: self.captured,
            literal_first_arg: self.literal_first_arg.map(Arc::<str>::from),
            dynamic: self.dynamic,
            span_start: self.span_start,
            span_end: self.span_end,
        }
    }
}

impl MelSurfaceNormalizedArgSnapshot {
    fn from_arg(arg: MelSurfaceNormalizedArg) -> Self {
        Self {
            text_span: arg.text_span,
            literal: arg.literal.map(|value| value.to_string()),
            dynamic: arg.dynamic,
            span_start: arg.span_start,
            span_end: arg.span_end,
        }
    }

    fn into_arg(self) -> MelSurfaceNormalizedArg {
        MelSurfaceNormalizedArg {
            text_span: self.text_span,
            literal: self.literal.map(Arc::<str>::from),
            dynamic: self.dynamic,
            span_start: self.span_start,
            span_end: self.span_end,
        }
    }
}

impl MelSurfaceNormalizedFlagSnapshot {
    fn from_flag(flag: MelSurfaceNormalizedFlag) -> Self {
        Self {
            source_span: flag.source_span,
            canonical_name: flag.canonical_name.map(|value| value.to_string()),
            value_shapes: flag.value_shapes,
            args: flag
                .args
                .into_iter()
                .map(MelSurfaceNormalizedArgSnapshot::from_arg)
                .collect(),
            span_start: flag.span_start,
            span_end: flag.span_end,
        }
    }

    fn into_flag(self) -> MelSurfaceNormalizedFlag {
        MelSurfaceNormalizedFlag {
            source_span: self.source_span,
            canonical_name: self.canonical_name.map(Arc::<str>::from),
            value_shapes: self.value_shapes,
            args: self
                .args
                .into_iter()
                .map(MelSurfaceNormalizedArgSnapshot::into_arg)
                .collect(),
            span_start: self.span_start,
            span_end: self.span_end,
        }
    }
}

impl MelSurfaceNormalizedCommandSnapshot {
    fn from_command(command: MelSurfaceNormalizedCommand) -> Self {
        Self {
            schema_name: command.schema_name.to_string(),
            mode: MelSurfaceCommandModeSnapshot::from_mode(command.mode),
            items: command
                .items
                .into_iter()
                .map(MelSurfaceNormalizedItemSnapshot::from_item)
                .collect(),
            span_start: command.span_start,
            span_end: command.span_end,
        }
    }

    fn into_command(self) -> MelSurfaceNormalizedCommand {
        MelSurfaceNormalizedCommand {
            schema_name: Arc::<str>::from(self.schema_name),
            mode: self.mode.into_mode(),
            items: self
                .items
                .into_iter()
                .map(MelSurfaceNormalizedItemSnapshot::into_item)
                .collect(),
            span_start: self.span_start,
            span_end: self.span_end,
        }
    }
}

impl MelSurfaceNormalizedItemSnapshot {
    fn from_item(item: MelSurfaceNormalizedItem) -> Self {
        match item {
            MelSurfaceNormalizedItem::Flag(flag) => {
                Self::Flag(MelSurfaceNormalizedFlagSnapshot::from_flag(flag))
            }
            MelSurfaceNormalizedItem::Positional(arg) => {
                Self::Positional(MelSurfaceNormalizedArgSnapshot::from_arg(arg))
            }
        }
    }

    fn into_item(self) -> MelSurfaceNormalizedItem {
        match self {
            Self::Flag(flag) => MelSurfaceNormalizedItem::Flag(flag.into_flag()),
            Self::Positional(arg) => MelSurfaceNormalizedItem::Positional(arg.into_arg()),
        }
    }
}

impl MelSurfaceDiagnosticStageSnapshot {
    fn from_stage(stage: MelSurfaceDiagnosticStage) -> Self {
        match stage {
            MelSurfaceDiagnosticStage::Decode => Self::Decode,
            MelSurfaceDiagnosticStage::Lex => Self::Lex,
            MelSurfaceDiagnosticStage::Parse => Self::Parse,
        }
    }

    fn into_stage(self) -> MelSurfaceDiagnosticStage {
        match self {
            Self::Decode => MelSurfaceDiagnosticStage::Decode,
            Self::Lex => MelSurfaceDiagnosticStage::Lex,
            Self::Parse => MelSurfaceDiagnosticStage::Parse,
        }
    }
}

impl MelSurfaceCallSurfaceKindSnapshot {
    fn from_kind(kind: MelSurfaceCallSurfaceKind) -> Self {
        match kind {
            MelSurfaceCallSurfaceKind::Function => Self::Function,
            MelSurfaceCallSurfaceKind::ShellLike => Self::ShellLike,
        }
    }

    fn into_kind(self) -> MelSurfaceCallSurfaceKind {
        match self {
            Self::Function => MelSurfaceCallSurfaceKind::Function,
            Self::ShellLike => MelSurfaceCallSurfaceKind::ShellLike,
        }
    }
}

impl MelSurfaceCommandModeSnapshot {
    fn from_mode(mode: MelSurfaceCommandMode) -> Self {
        match mode {
            MelSurfaceCommandMode::Create => Self::Create,
            MelSurfaceCommandMode::Edit => Self::Edit,
            MelSurfaceCommandMode::Query => Self::Query,
            MelSurfaceCommandMode::Unknown => Self::Unknown,
        }
    }

    fn into_mode(self) -> MelSurfaceCommandMode {
        match self {
            Self::Create => MelSurfaceCommandMode::Create,
            Self::Edit => MelSurfaceCommandMode::Edit,
            Self::Query => MelSurfaceCommandMode::Query,
            Self::Unknown => MelSurfaceCommandMode::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObserveCacheStore {
    root: PathBuf,
}

impl ObserveCacheStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load_by_path_if_fresh(
        &self,
        path: &Path,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> io::Result<Option<ObservedSceneSnapshot>> {
        let file_state = file_state_for_path(path)?;
        let Some(record) =
            self.load_index_record_by_path_if_fresh(path, &file_state, load_options, max_preview)?
        else {
            return Ok(None);
        };
        self.load_by_identity(&record.identity)
    }

    pub fn load_by_path_with_hash_fallback(
        &self,
        path: &Path,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> io::Result<Option<ObservedSceneSnapshot>> {
        let file_state = file_state_for_path(path)?;
        if let Some(record) =
            self.load_index_record_by_path_if_fresh(path, &file_state, load_options, max_preview)?
        {
            if let Some(snapshot) = self.load_by_identity(&record.identity)? {
                return Ok(Some(snapshot));
            }
        }

        let identity = ObserveCacheIdentity::new(file_sha256(path)?, load_options, max_preview);
        self.load_by_identity(&identity)
    }

    pub fn load_by_identity(
        &self,
        identity: &ObserveCacheIdentity,
    ) -> io::Result<Option<ObservedSceneSnapshot>> {
        for blob_path in [self.blob_path(identity), self.legacy_blob_path(identity)] {
            match fs::read(&blob_path) {
                Ok(bytes) => {
                    return serde_json::from_slice(&bytes)
                        .map(Some)
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err));
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    }

    pub fn save(&self, snapshot: &ObservedSceneSnapshot) -> io::Result<()> {
        self.save_batch(std::slice::from_ref(snapshot))
    }

    pub fn save_batch(&self, snapshots: &[ObservedSceneSnapshot]) -> io::Result<()> {
        if snapshots.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(self.blobs_dir())?;
        let mut index = self.load_index()?;
        for snapshot in snapshots {
            let blob_path = self.blob_path(&snapshot.identity);
            if !blob_path.exists() {
                write_json_atomic(&blob_path, snapshot)?;
            }
            index.by_path.insert(
                normalized_path_key(&snapshot.file_state.path),
                ObserveCacheIndexRecord {
                    file_state: snapshot.file_state.clone(),
                    identity: snapshot.identity.clone(),
                },
            );
        }
        write_json_atomic(&self.index_path(), &index)
    }
}

fn fingerprint_debug(value: &impl std::fmt::Debug) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{value:?}"));
    format!("{:x}", hasher.finalize())
}

fn file_state_for_path(path: &Path) -> io::Result<ObserveFileState> {
    let metadata = fs::metadata(path)?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_nanos());
    Ok(ObserveFileState {
        path: path.to_path_buf(),
        size: metadata.len(),
        modified_unix_nanos,
    })
}

fn file_sha256(path: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path)?);
    Ok(format!("{:x}", hasher.finalize()))
}

fn normalized_path_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

impl ObserveCacheStore {
    fn index_path(&self) -> PathBuf {
        self.root.join(INDEX_FILE)
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    fn blob_path(&self, identity: &ObserveCacheIdentity) -> PathBuf {
        sharded_blob_path(&self.blobs_dir(), &identity.blob_name())
    }

    fn legacy_blob_path(&self, identity: &ObserveCacheIdentity) -> PathBuf {
        self.blobs_dir().join(identity.blob_name())
    }

    fn load_index(&self) -> io::Result<ObserveCacheIndex> {
        match fs::read(self.index_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(ObserveCacheIndex::default()),
            Err(err) => Err(err),
        }
    }

    fn load_index_record_by_path_if_fresh(
        &self,
        path: &Path,
        file_state: &ObserveFileState,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> io::Result<Option<ObserveCacheIndexRecord>> {
        let index = self.load_index()?;
        let key = normalized_path_key(path);
        Ok(index.by_path.get(&key).cloned().filter(|record| {
            record.file_state.size == file_state.size
                && record.file_state.modified_unix_nanos == file_state.modified_unix_nanos
                && record.identity.load_options_fingerprint == fingerprint_debug(load_options)
                && record.identity.max_preview == max_preview
        }))
    }
}

fn sharded_blob_path(blobs_dir: &Path, blob_name: &str) -> PathBuf {
    let shard_a = blob_name.get(0..2).unwrap_or("__");
    let shard_b = blob_name.get(2..4).unwrap_or("__");
    blobs_dir.join(shard_a).join(shard_b).join(blob_name)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, payload)?;
    fs::rename(temp_path, path)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use tempfile::tempdir;

    use super::{ObserveCacheStore, ObservedSceneSnapshot, write_json_atomic};
    use crate::scene::{LoadOptions, Loader};

    fn write_sample_scene(path: &Path) {
        fs::write(
            path,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"Example\";\n",
                "    setAttr \".b\" -type \"string\" \"print \\\"Example\\\";\";\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"asset/example/file.fbx\";\n",
            ),
        )
        .expect("write sample scene");
    }

    #[test]
    fn observe_snapshot_round_trips_and_renamed_path_hits_by_hash() {
        let dir = tempdir().expect("tmpdir");
        let source = dir.path().join("Example.ma");
        write_sample_scene(&source);

        let observation = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observe source");
        let snapshot =
            ObservedSceneSnapshot::from_observation(&observation, &LoadOptions::default(), 64)
                .expect("snapshot");
        let store = ObserveCacheStore::new(dir.path().join("observe-cache"));
        store.save(&snapshot).expect("save snapshot");

        let loaded = store
            .load_by_path_with_hash_fallback(&source, &LoadOptions::default(), 64)
            .expect("load by original path")
            .expect("snapshot by path");
        assert_eq!(loaded.identity.scene_sha256, snapshot.identity.scene_sha256);

        let renamed = dir.path().join("RenamedExample.ma");
        fs::rename(&source, &renamed).expect("rename scene");
        let loaded = store
            .load_by_path_with_hash_fallback(&renamed, &LoadOptions::default(), 64)
            .expect("load by renamed path")
            .expect("snapshot by hash fallback");
        assert_eq!(loaded.identity.scene_sha256, snapshot.identity.scene_sha256);

        let startup_loaded = store
            .load_by_path_if_fresh(&renamed, &LoadOptions::default(), 64)
            .expect("load startup path");
        assert!(startup_loaded.is_none());
    }

    #[test]
    fn observe_store_reads_legacy_flat_blob_layout() {
        let dir = tempdir().expect("tmpdir");
        let source = dir.path().join("Example.ma");
        write_sample_scene(&source);

        let observation = Loader::new(LoadOptions::default())
            .observe_path(&source)
            .expect("observe source");
        let snapshot =
            ObservedSceneSnapshot::from_observation(&observation, &LoadOptions::default(), 64)
                .expect("snapshot");
        let store = ObserveCacheStore::new(dir.path().join("observe-cache"));
        fs::create_dir_all(store.blobs_dir()).expect("create blobs dir");
        write_json_atomic(&store.legacy_blob_path(&snapshot.identity), &snapshot)
            .expect("write legacy blob");

        let loaded = store
            .load_by_identity(&snapshot.identity)
            .expect("load by identity")
            .expect("snapshot");
        assert_eq!(loaded.identity.scene_sha256, snapshot.identity.scene_sha256);
    }

    #[test]
    fn observe_store_save_batch_round_trips_multiple_snapshots() {
        let dir = tempdir().expect("tmpdir");
        let first = dir.path().join("ExampleA.ma");
        let second = dir.path().join("ExampleB.ma");
        write_sample_scene(&first);
        write_sample_scene(&second);

        let first_observation = Loader::new(LoadOptions::default())
            .observe_path(&first)
            .expect("observe first");
        let second_observation = Loader::new(LoadOptions::default())
            .observe_path(&second)
            .expect("observe second");
        let first_snapshot =
            ObservedSceneSnapshot::from_observation(&first_observation, &LoadOptions::default(), 64)
                .expect("first snapshot");
        let second_snapshot =
            ObservedSceneSnapshot::from_observation(&second_observation, &LoadOptions::default(), 64)
                .expect("second snapshot");
        let store = ObserveCacheStore::new(dir.path().join("observe-cache"));

        store
            .save_batch(&[first_snapshot.clone(), second_snapshot.clone()])
            .expect("save batch");

        let loaded_first = store
            .load_by_path_if_fresh(&first, &LoadOptions::default(), 64)
            .expect("load first")
            .expect("first snapshot");
        let loaded_second = store
            .load_by_path_if_fresh(&second, &LoadOptions::default(), 64)
            .expect("load second")
            .expect("second snapshot");
        assert_eq!(loaded_first.identity.scene_sha256, first_snapshot.identity.scene_sha256);
        assert_eq!(loaded_second.identity.scene_sha256, second_snapshot.identity.scene_sha256);
    }
}
