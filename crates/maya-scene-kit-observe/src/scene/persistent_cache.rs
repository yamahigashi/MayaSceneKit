use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zstd::stream::{decode_all, encode_all};

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
const DB_FILE: &str = "cache.sqlite3";
const OBSERVE_CACHE_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);
const OBSERVE_CACHE_TOUCH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const BLOB_FILE_EXTENSION: &str = "json.zst";
const BLOB_CODEC_ZSTD: &str = "zstd";
const BLOB_COMPRESSION_LEVEL: i32 = 3;

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

#[derive(Debug, Clone)]
struct ObserveCacheIndexRecord {
    file_state: ObserveFileState,
    identity: ObserveCacheIdentity,
    last_accessed_unix_secs: Option<u64>,
    blob: ObserveBlobRef,
}

#[derive(Debug, Clone)]
struct ObserveBlobRef {
    relative_path: PathBuf,
    compressed_size: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Default, Clone)]
struct ObserveCacheIndex {
    by_path: BTreeMap<String, ObserveCacheIndexRecord>,
}

#[derive(Debug, Clone)]
pub struct ObserveCacheAccess {
    pub path: PathBuf,
    pub file_state: ObserveFileState,
    pub identity: ObserveCacheIdentity,
}

#[derive(Debug, Clone)]
pub struct ObserveCacheHit {
    pub snapshot: ObservedSceneSnapshot,
    pub access: ObserveCacheAccess,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ObserveCacheMaintenanceStats {
    pub touched_count: usize,
    pub expired_record_count: usize,
    pub deleted_blob_count: usize,
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
            "{}-{}-{}.{}",
            self.scene_sha256, self.load_options_fingerprint, self.max_preview, BLOB_FILE_EXTENSION
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

    pub fn load_many_by_path_if_fresh_with_access(
        &self,
        paths: &[PathBuf],
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> io::Result<Vec<io::Result<Option<ObserveCacheHit>>>> {
        let conn = self.open_connection()?;
        let now_unix_secs = unix_timestamp_secs(SystemTime::now());
        let load_options_fingerprint = fingerprint_debug(load_options);
        Ok(paths
            .iter()
            .map(|path| {
                self.load_cached_hit_from_connection(
                    &conn,
                    path,
                    &load_options_fingerprint,
                    max_preview,
                    now_unix_secs,
                )
            })
            .collect())
    }

    pub fn load_by_path_if_fresh_with_access(
        &self,
        path: &Path,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> io::Result<Option<ObserveCacheHit>> {
        let conn = self.open_connection()?;
        let load_options_fingerprint = fingerprint_debug(load_options);
        let Some(record) = self.load_index_record_by_path_if_fresh(
            &conn,
            path,
            &load_options_fingerprint,
            max_preview,
        )?
        else {
            return Ok(None);
        };
        let file_state = file_state_for_path(path)?;
        self.hit_from_record(path, file_state, record)
    }

    pub fn load_by_path_if_fresh(
        &self,
        path: &Path,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> io::Result<Option<ObservedSceneSnapshot>> {
        Ok(self
            .load_by_path_if_fresh_with_access(path, load_options, max_preview)?
            .map(|hit| hit.snapshot))
    }

    pub fn load_by_path_with_hash_fallback_with_access(
        &self,
        path: &Path,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> io::Result<Option<ObserveCacheHit>> {
        let file_state = file_state_for_path(path)?;
        let conn = self.open_connection()?;
        let load_options_fingerprint = fingerprint_debug(load_options);
        if let Some(record) = self.find_fresh_record_by_path(
            &conn,
            path,
            &file_state,
            &load_options_fingerprint,
            max_preview,
            unix_timestamp_secs(SystemTime::now()),
        ) {
            if let Some(hit) = self.hit_from_record(path, file_state.clone(), record)? {
                return Ok(Some(hit));
            }
        }

        let identity = ObserveCacheIdentity::new(file_sha256(path)?, load_options, max_preview);
        if !self.identity_has_live_reference(&conn, &identity) {
            return Ok(None);
        }
        let Some(snapshot) = self.load_by_identity_with_connection(&conn, &identity)? else {
            return Ok(None);
        };
        Ok(Some(ObserveCacheHit {
            snapshot,
            access: ObserveCacheAccess {
                path: path.to_path_buf(),
                file_state,
                identity,
            },
        }))
    }

    pub fn load_by_path_with_hash_fallback(
        &self,
        path: &Path,
        load_options: &LoadOptions,
        max_preview: usize,
    ) -> io::Result<Option<ObservedSceneSnapshot>> {
        Ok(self
            .load_by_path_with_hash_fallback_with_access(path, load_options, max_preview)?
            .map(|hit| hit.snapshot))
    }

    pub fn load_by_identity(
        &self,
        identity: &ObserveCacheIdentity,
    ) -> io::Result<Option<ObservedSceneSnapshot>> {
        let conn = self.open_connection()?;
        self.load_by_identity_with_connection(&conn, identity)
    }

    pub fn save(&self, snapshot: &ObservedSceneSnapshot) -> io::Result<()> {
        self.save_batch(std::slice::from_ref(snapshot))
    }

    pub fn save_batch(&self, snapshots: &[ObservedSceneSnapshot]) -> io::Result<()> {
        if snapshots.is_empty() {
            return Ok(());
        }

        let blobs = snapshots
            .iter()
            .map(|snapshot| self.ensure_blob(snapshot))
            .collect::<io::Result<Vec<_>>>()?;
        let mut conn = self.open_connection()?;
        let now_unix_secs = unix_timestamp_secs(SystemTime::now());
        let tx = conn.transaction().map_err(sqlite_io_error)?;
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO path_index (
                    normalized_path,
                    size,
                    modified_unix_nanos,
                    cache_schema_version,
                    scene_sha256,
                    load_options_fingerprint,
                    max_preview,
                    last_accessed_unix_secs,
                    blob_relative_path,
                    blob_codec,
                    blob_compressed_size
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(normalized_path) DO UPDATE SET
                    size=excluded.size,
                    modified_unix_nanos=excluded.modified_unix_nanos,
                    cache_schema_version=excluded.cache_schema_version,
                    scene_sha256=excluded.scene_sha256,
                    load_options_fingerprint=excluded.load_options_fingerprint,
                    max_preview=excluded.max_preview,
                    last_accessed_unix_secs=excluded.last_accessed_unix_secs,
                    blob_relative_path=excluded.blob_relative_path,
                    blob_codec=excluded.blob_codec,
                    blob_compressed_size=excluded.blob_compressed_size",
            )
            .map_err(sqlite_io_error)?;
        for (snapshot, blob) in snapshots.iter().zip(blobs.iter()) {
            stmt.execute(params![
                normalized_path_key(&snapshot.file_state.path),
                u64_to_sql(snapshot.file_state.size)?,
                opt_u128_to_sql(snapshot.file_state.modified_unix_nanos)?,
                i64::from(snapshot.identity.cache_schema_version),
                &snapshot.identity.scene_sha256,
                &snapshot.identity.load_options_fingerprint,
                usize_to_sql(snapshot.identity.max_preview)?,
                u64_to_sql(now_unix_secs)?,
                blob.relative_path.to_string_lossy().to_string(),
                BLOB_CODEC_ZSTD,
                u64_to_sql(blob.compressed_size)?,
            ])
            .map_err(sqlite_io_error)?;
        }
        drop(stmt);
        tx.commit().map_err(sqlite_io_error)
    }

    pub fn touch_many_if_stale(
        &self,
        touched: &[ObserveCacheAccess],
        now: SystemTime,
        min_interval: Duration,
    ) -> io::Result<ObserveCacheMaintenanceStats> {
        let mut conn = self.open_connection()?;
        self.touch_many_if_stale_with_connection(&mut conn, touched, now, min_interval)
    }

    pub fn maintain_batch(
        &self,
        touched: &[ObserveCacheAccess],
        now: SystemTime,
        min_interval: Duration,
        sweep: bool,
    ) -> io::Result<ObserveCacheMaintenanceStats> {
        let mut conn = self.open_connection()?;
        let touched_stats =
            self.touch_many_if_stale_with_connection(&mut conn, touched, now, min_interval)?;
        let sweep_stats = if sweep {
            self.sweep_expired_with_connection(&mut conn, now)?
        } else {
            ObserveCacheMaintenanceStats::default()
        };
        Ok(ObserveCacheMaintenanceStats {
            touched_count: touched_stats.touched_count,
            expired_record_count: sweep_stats.expired_record_count,
            deleted_blob_count: sweep_stats.deleted_blob_count,
        })
    }

    pub fn sweep_expired(&self, now: SystemTime) -> io::Result<ObserveCacheMaintenanceStats> {
        let mut conn = self.open_connection()?;
        self.sweep_expired_with_connection(&mut conn, now)
    }

    pub fn apply_maintenance(
        &self,
        touched: &[ObserveCacheAccess],
        now: SystemTime,
    ) -> io::Result<ObserveCacheMaintenanceStats> {
        self.maintain_batch(touched, now, OBSERVE_CACHE_TOUCH_INTERVAL, true)
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
    fn db_path(&self) -> PathBuf {
        self.root.join(DB_FILE)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn load_index(&self) -> io::Result<ObserveCacheIndex> {
        let conn = self.open_connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT normalized_path, size, modified_unix_nanos, cache_schema_version,
                        scene_sha256, load_options_fingerprint, max_preview, last_accessed_unix_secs,
                        blob_relative_path, blob_compressed_size
                 FROM path_index",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(sqlite_io_error)?;
        let mut by_path = BTreeMap::new();
        for row in rows {
            let (
                path,
                size,
                modified_unix_nanos,
                cache_schema_version,
                scene_sha256,
                load_options_fingerprint,
                max_preview,
                last_accessed_unix_secs,
                blob_relative_path,
                blob_compressed_size,
            ) = row.map_err(sqlite_io_error)?;
            let record = ObserveCacheIndexRecord {
                file_state: ObserveFileState {
                    path: PathBuf::from(&path),
                    size: i64_to_u64(size)?,
                    modified_unix_nanos: opt_i64_to_u128(modified_unix_nanos)?,
                },
                identity: ObserveCacheIdentity {
                    cache_schema_version: i64_to_u32(cache_schema_version)?,
                    scene_sha256,
                    load_options_fingerprint,
                    max_preview: i64_to_usize(max_preview)?,
                },
                last_accessed_unix_secs: opt_i64_to_u64(last_accessed_unix_secs)?,
                blob: ObserveBlobRef {
                    relative_path: PathBuf::from(blob_relative_path),
                    compressed_size: i64_to_u64(blob_compressed_size)?,
                },
            };
            by_path.insert(path, record);
        }
        Ok(ObserveCacheIndex { by_path })
    }

    fn load_index_record_by_path_if_fresh(
        &self,
        conn: &Connection,
        path: &Path,
        load_options_fingerprint: &str,
        max_preview: usize,
    ) -> io::Result<Option<ObserveCacheIndexRecord>> {
        let file_state = file_state_for_path(path)?;
        Ok(self.find_fresh_record_by_path(
            conn,
            path,
            &file_state,
            load_options_fingerprint,
            max_preview,
            unix_timestamp_secs(SystemTime::now()),
        ))
    }

    fn find_fresh_record_by_path(
        &self,
        conn: &Connection,
        path: &Path,
        file_state: &ObserveFileState,
        load_options_fingerprint: &str,
        max_preview: usize,
        now_unix_secs: u64,
    ) -> Option<ObserveCacheIndexRecord> {
        let key = normalized_path_key(path);
        let row = conn
            .query_row(
                "SELECT size, modified_unix_nanos, cache_schema_version, scene_sha256,
                        load_options_fingerprint, max_preview, last_accessed_unix_secs,
                        blob_relative_path, blob_compressed_size
                 FROM path_index
                 WHERE normalized_path = ?1",
                params![key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten();
        let record = row.and_then(
            |(
                size,
                modified_unix_nanos,
                cache_schema_version,
                scene_sha256,
                load_options_fingerprint_row,
                max_preview_row,
                last_accessed_unix_secs,
                blob_relative_path,
                blob_compressed_size,
            )| {
                Some(ObserveCacheIndexRecord {
                    file_state: ObserveFileState {
                        path: path.to_path_buf(),
                        size: i64_to_u64(size).ok()?,
                        modified_unix_nanos: opt_i64_to_u128(modified_unix_nanos).ok()?,
                    },
                    identity: ObserveCacheIdentity {
                        cache_schema_version: i64_to_u32(cache_schema_version).ok()?,
                        scene_sha256,
                        load_options_fingerprint: load_options_fingerprint_row,
                        max_preview: i64_to_usize(max_preview_row).ok()?,
                    },
                    last_accessed_unix_secs: opt_i64_to_u64(last_accessed_unix_secs).ok()?,
                    blob: ObserveBlobRef {
                        relative_path: PathBuf::from(blob_relative_path),
                        compressed_size: i64_to_u64(blob_compressed_size).ok()?,
                    },
                })
            },
        );
        record.filter(|record| {
            !record_expired(
                record.last_accessed_unix_secs,
                now_unix_secs,
                OBSERVE_CACHE_TTL,
            ) && record.file_state.size == file_state.size
                && record.file_state.modified_unix_nanos == file_state.modified_unix_nanos
                && record.identity.load_options_fingerprint == load_options_fingerprint
                && record.identity.max_preview == max_preview
        })
    }

    fn load_cached_hit_from_connection(
        &self,
        conn: &Connection,
        path: &Path,
        load_options_fingerprint: &str,
        max_preview: usize,
        now_unix_secs: u64,
    ) -> io::Result<Option<ObserveCacheHit>> {
        let file_state = match file_state_for_path(path) {
            Ok(file_state) => file_state,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let Some(record) = self.find_fresh_record_by_path(
            conn,
            path,
            &file_state,
            load_options_fingerprint,
            max_preview,
            now_unix_secs,
        ) else {
            return Ok(None);
        };
        self.hit_from_record(path, file_state, record)
    }

    fn hit_from_record(
        &self,
        path: &Path,
        file_state: ObserveFileState,
        record: ObserveCacheIndexRecord,
    ) -> io::Result<Option<ObserveCacheHit>> {
        let conn = self.open_connection()?;
        let Some(snapshot) = self.load_blob_for_record(&conn, &record)? else {
            return Ok(None);
        };
        Ok(Some(ObserveCacheHit {
            snapshot,
            access: ObserveCacheAccess {
                path: path.to_path_buf(),
                file_state,
                identity: record.identity,
            },
        }))
    }

    fn identity_has_live_reference(
        &self,
        conn: &Connection,
        identity: &ObserveCacheIdentity,
    ) -> bool {
        let now_unix_secs = unix_timestamp_secs(SystemTime::now());
        conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM path_index
                WHERE scene_sha256 = ?1
                  AND load_options_fingerprint = ?2
                  AND max_preview = ?3
                  AND (last_accessed_unix_secs IS NULL OR last_accessed_unix_secs >= ?4)
            )",
            params![
                &identity.scene_sha256,
                &identity.load_options_fingerprint,
                usize_to_sql(identity.max_preview).unwrap_or(0),
                u64_to_sql(now_unix_secs.saturating_sub(OBSERVE_CACHE_TTL.as_secs())).unwrap_or(0)
            ],
            |row| row.get::<_, i64>(0),
        )
        .map(|exists| exists != 0)
        .unwrap_or(false)
    }

    fn load_by_identity_with_connection(
        &self,
        conn: &Connection,
        identity: &ObserveCacheIdentity,
    ) -> io::Result<Option<ObservedSceneSnapshot>> {
        let row = conn
            .query_row(
                "SELECT '' as normalized_path, 0 as size, NULL as modified_unix_nanos,
                        cache_schema_version, scene_sha256, load_options_fingerprint,
                        max_preview, last_accessed_unix_secs, blob_relative_path, blob_compressed_size
                 FROM path_index
                 WHERE scene_sha256 = ?1
                   AND load_options_fingerprint = ?2
                   AND max_preview = ?3
                 LIMIT 1",
                params![
                    &identity.scene_sha256,
                    &identity.load_options_fingerprint,
                    usize_to_sql(identity.max_preview)?
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_io_error)?;
        let Some((
            cache_schema_version,
            scene_sha256,
            load_options_fingerprint,
            max_preview,
            last_accessed_unix_secs,
            blob_relative_path,
            blob_compressed_size,
        )) = row
        else {
            return Ok(None);
        };
        let record = ObserveCacheIndexRecord {
            file_state: ObserveFileState {
                path: PathBuf::new(),
                size: 0,
                modified_unix_nanos: None,
            },
            identity: ObserveCacheIdentity {
                cache_schema_version: i64_to_u32(cache_schema_version)?,
                scene_sha256,
                load_options_fingerprint,
                max_preview: i64_to_usize(max_preview)?,
            },
            last_accessed_unix_secs: opt_i64_to_u64(last_accessed_unix_secs)?,
            blob: ObserveBlobRef {
                relative_path: PathBuf::from(blob_relative_path),
                compressed_size: i64_to_u64(blob_compressed_size)?,
            },
        };
        self.load_blob_for_record(conn, &record)
    }

    fn open_connection(&self) -> io::Result<Connection> {
        fs::create_dir_all(&self.root)?;
        let conn = Connection::open(self.db_path()).map_err(sqlite_io_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(sqlite_io_error)?;
        conn.execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS path_index (
                 normalized_path TEXT PRIMARY KEY,
                 size INTEGER NOT NULL,
                 modified_unix_nanos INTEGER NULL,
                 cache_schema_version INTEGER NOT NULL,
                 scene_sha256 TEXT NOT NULL,
                 load_options_fingerprint TEXT NOT NULL,
                 max_preview INTEGER NOT NULL,
                 last_accessed_unix_secs INTEGER NULL,
                 blob_relative_path TEXT NOT NULL,
                 blob_codec TEXT NOT NULL,
                 blob_compressed_size INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS path_index_identity_idx
                 ON path_index(scene_sha256, load_options_fingerprint, max_preview);
             CREATE INDEX IF NOT EXISTS path_index_last_accessed_idx ON path_index(last_accessed_unix_secs);",
        )
        .map_err(sqlite_io_error)?;
        Ok(conn)
    }

    fn touch_many_if_stale_with_connection(
        &self,
        conn: &mut Connection,
        touched: &[ObserveCacheAccess],
        now: SystemTime,
        min_interval: Duration,
    ) -> io::Result<ObserveCacheMaintenanceStats> {
        if touched.is_empty() {
            return Ok(ObserveCacheMaintenanceStats::default());
        }
        let now_unix_secs = unix_timestamp_secs(now);
        let min_unix_secs = now_unix_secs.saturating_sub(min_interval.as_secs());
        let tx = conn.transaction().map_err(sqlite_io_error)?;
        let mut stmt = tx
            .prepare_cached(
                "UPDATE path_index
                 SET last_accessed_unix_secs = ?2
                 WHERE normalized_path = ?1
                   AND (last_accessed_unix_secs IS NULL OR last_accessed_unix_secs < ?3)",
            )
            .map_err(sqlite_io_error)?;
        let mut touched_count = 0usize;
        for access in touched {
            touched_count += stmt
                .execute(params![
                    normalized_path_key(&access.path),
                    u64_to_sql(now_unix_secs)?,
                    u64_to_sql(min_unix_secs)?,
                ])
                .map_err(sqlite_io_error)?;
        }
        drop(stmt);
        tx.commit().map_err(sqlite_io_error)?;
        Ok(ObserveCacheMaintenanceStats {
            touched_count,
            ..ObserveCacheMaintenanceStats::default()
        })
    }

    fn sweep_expired_with_connection(
        &self,
        conn: &mut Connection,
        now: SystemTime,
    ) -> io::Result<ObserveCacheMaintenanceStats> {
        let expired_before = now
            .checked_sub(OBSERVE_CACHE_TTL)
            .map(unix_timestamp_secs)
            .unwrap_or(0);
        let tx = conn.transaction().map_err(sqlite_io_error)?;
        let expired_blob_paths = self.collect_expired_blob_paths(&tx, expired_before)?;
        let expired_record_count: usize = tx
            .query_row(
                "SELECT COUNT(*) FROM path_index
                 WHERE last_accessed_unix_secs IS NOT NULL
                   AND last_accessed_unix_secs < ?1",
                params![u64_to_sql(expired_before)?],
                |row| row.get(0),
            )
            .map_err(sqlite_io_error)?;
        tx.execute(
            "DELETE FROM path_index
             WHERE last_accessed_unix_secs IS NOT NULL
               AND last_accessed_unix_secs < ?1",
            params![u64_to_sql(expired_before)?],
        )
        .map_err(sqlite_io_error)?;
        let live_blob_paths = self.collect_live_blob_paths(&tx)?;
        tx.commit().map_err(sqlite_io_error)?;
        let orphaned_paths = expired_blob_paths
            .into_iter()
            .filter(|path| !live_blob_paths.contains_key(path))
            .collect::<Vec<_>>();
        let deleted_blob_count = delete_blob_files(self.blobs_dir(), &orphaned_paths)?;
        let deleted_temp_count = delete_stale_temp_files(self.blobs_dir())?;
        self.compact_database(conn, expired_record_count > 0)?;
        Ok(ObserveCacheMaintenanceStats {
            touched_count: 0,
            expired_record_count,
            deleted_blob_count: deleted_blob_count + deleted_temp_count,
        })
    }

    fn compact_database(&self, conn: &Connection, reclaim_pages: bool) -> io::Result<()> {
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(sqlite_io_error)?;
        if reclaim_pages {
            conn.execute_batch("VACUUM;").map_err(sqlite_io_error)?;
        }
        Ok(())
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    fn blob_path(&self, relative_path: &Path) -> PathBuf {
        self.blobs_dir().join(relative_path)
    }

    fn ensure_blob(&self, snapshot: &ObservedSceneSnapshot) -> io::Result<ObserveBlobRef> {
        let blob_name = snapshot.identity.blob_name();
        let relative_path = sharded_blob_relative_path(&blob_name);
        let path = self.blob_path(&relative_path);
        if let Ok(metadata) = fs::metadata(&path) {
            return Ok(ObserveBlobRef {
                relative_path,
                compressed_size: metadata.len(),
            });
        }

        let payload = serde_json::to_vec(snapshot)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let compressed = encode_all(std::io::Cursor::new(payload), BLOB_COMPRESSION_LEVEL)
            .map_err(io::Error::other)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp_path = temp_blob_path(&path);
        fs::write(&temp_path, &compressed)?;
        fs::rename(&temp_path, &path)?;
        Ok(ObserveBlobRef {
            relative_path,
            compressed_size: compressed.len() as u64,
        })
    }

    fn load_blob_for_record(
        &self,
        conn: &Connection,
        record: &ObserveCacheIndexRecord,
    ) -> io::Result<Option<ObservedSceneSnapshot>> {
        let path = self.blob_path(&record.blob.relative_path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                self.prune_blob_references(conn, &record.blob.relative_path)?;
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let payload = match decode_all(std::io::Cursor::new(bytes)) {
            Ok(payload) => payload,
            Err(_) => {
                self.prune_blob_references(conn, &record.blob.relative_path)?;
                return Ok(None);
            }
        };
        match serde_json::from_slice::<ObservedSceneSnapshot>(&payload) {
            Ok(mut snapshot) => {
                snapshot.identity = record.identity.clone();
                snapshot.file_state = record.file_state.clone();
                snapshot.paths_report.scene_path = record.file_state.path.clone();
                snapshot.dump_report.scene_path = record.file_state.path.clone();
                Ok(Some(snapshot))
            }
            Err(_) => {
                self.prune_blob_references(conn, &record.blob.relative_path)?;
                Ok(None)
            }
        }
    }

    fn prune_blob_references(&self, conn: &Connection, relative_path: &Path) -> io::Result<()> {
        conn.execute(
            "DELETE FROM path_index WHERE blob_relative_path = ?1",
            params![relative_path.to_string_lossy().to_string()],
        )
        .map_err(sqlite_io_error)?;
        let path = self.blob_path(relative_path);
        let _ = fs::remove_file(path);
        Ok(())
    }

    fn collect_expired_blob_paths(
        &self,
        conn: &Connection,
        expired_before: u64,
    ) -> io::Result<Vec<PathBuf>> {
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT blob_relative_path FROM path_index
                 WHERE last_accessed_unix_secs IS NOT NULL
                   AND last_accessed_unix_secs < ?1",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map(params![u64_to_sql(expired_before)?], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_io_error)?;
        let mut paths = Vec::new();
        for row in rows {
            paths.push(PathBuf::from(row.map_err(sqlite_io_error)?));
        }
        Ok(paths)
    }

    fn collect_live_blob_paths(&self, conn: &Connection) -> io::Result<BTreeMap<PathBuf, ()>> {
        let mut stmt = conn
            .prepare("SELECT DISTINCT blob_relative_path FROM path_index")
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_io_error)?;
        let mut paths = BTreeMap::new();
        for row in rows {
            paths.insert(PathBuf::from(row.map_err(sqlite_io_error)?), ());
        }
        Ok(paths)
    }
}

fn sharded_blob_relative_path(blob_name: &str) -> PathBuf {
    let shard_a = blob_name.get(0..2).unwrap_or("__");
    let shard_b = blob_name.get(2..4).unwrap_or("__");
    PathBuf::from(shard_a).join(shard_b).join(blob_name)
}

fn temp_blob_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_extension("tmp");
    temp
}

fn delete_blob_files(root: PathBuf, relative_paths: &[PathBuf]) -> io::Result<usize> {
    let mut deleted = 0usize;
    for relative_path in relative_paths {
        match fs::remove_file(root.join(relative_path)) {
            Ok(()) => deleted += 1,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(deleted)
}

fn delete_stale_temp_files(root: PathBuf) -> io::Result<usize> {
    let mut deleted = 0usize;
    if !root.exists() {
        return Ok(0);
    }
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "tmp") {
                fs::remove_file(path)?;
                deleted += 1;
            }
        }
    }
    Ok(deleted)
}

fn unix_timestamp_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map_or(0, |duration| duration.as_secs())
}

fn record_expired(last_accessed_unix_secs: Option<u64>, now_unix_secs: u64, ttl: Duration) -> bool {
    let Some(last_accessed_unix_secs) = last_accessed_unix_secs else {
        return false;
    };
    now_unix_secs.saturating_sub(last_accessed_unix_secs) > ttl.as_secs()
}

fn sqlite_io_error(err: rusqlite::Error) -> io::Error {
    io::Error::other(err)
}

fn u64_to_sql(value: u64) -> io::Result<i64> {
    i64::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "u64 overflow for sqlite"))
}

fn usize_to_sql(value: usize) -> io::Result<i64> {
    i64::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "usize overflow for sqlite"))
}

fn opt_u128_to_sql(value: Option<u128>) -> io::Result<Option<i64>> {
    value
        .map(|value| {
            i64::try_from(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "u128 overflow for sqlite"))
        })
        .transpose()
}

fn i64_to_u64(value: i64) -> io::Result<u64> {
    u64::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative sqlite integer"))
}

fn i64_to_u32(value: i64) -> io::Result<u32> {
    u32::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid sqlite integer"))
}

fn i64_to_usize(value: i64) -> io::Result<usize> {
    usize::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid sqlite integer"))
}

fn opt_i64_to_u64(value: Option<i64>) -> io::Result<Option<u64>> {
    value.map(i64_to_u64).transpose()
}

fn opt_i64_to_u128(value: Option<i64>) -> io::Result<Option<u128>> {
    value
        .map(|value| {
            u128::try_from(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid sqlite integer"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        time::{Duration, SystemTime},
    };

    use tempfile::tempdir;

    use super::{
        OBSERVE_CACHE_TOUCH_INTERVAL, OBSERVE_CACHE_TTL, ObserveCacheAccess, ObserveCacheStore,
        ObservedSceneSnapshot, record_expired,
    };
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
        let first_snapshot = ObservedSceneSnapshot::from_observation(
            &first_observation,
            &LoadOptions::default(),
            64,
        )
        .expect("first snapshot");
        let second_snapshot = ObservedSceneSnapshot::from_observation(
            &second_observation,
            &LoadOptions::default(),
            64,
        )
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
        assert_eq!(
            loaded_first.identity.scene_sha256,
            first_snapshot.identity.scene_sha256
        );
        assert_eq!(
            loaded_second.identity.scene_sha256,
            second_snapshot.identity.scene_sha256
        );
    }

    #[test]
    fn observe_store_batch_lookup_matches_single_path_results() {
        let dir = tempdir().expect("tmpdir");
        let first = dir.path().join("ExampleA.ma");
        let second = dir.path().join("ExampleB.ma");
        let missing = dir.path().join("Missing.ma");
        write_sample_scene(&first);
        write_sample_scene(&second);
        write_sample_scene(&missing);

        let first_observation = Loader::new(LoadOptions::default())
            .observe_path(&first)
            .expect("observe first");
        let second_observation = Loader::new(LoadOptions::default())
            .observe_path(&second)
            .expect("observe second");
        let first_snapshot = ObservedSceneSnapshot::from_observation(
            &first_observation,
            &LoadOptions::default(),
            64,
        )
        .expect("first snapshot");
        let second_snapshot = ObservedSceneSnapshot::from_observation(
            &second_observation,
            &LoadOptions::default(),
            64,
        )
        .expect("second snapshot");
        let store = ObserveCacheStore::new(dir.path().join("observe-cache"));

        store
            .save_batch(&[first_snapshot, second_snapshot])
            .expect("save batch");
        fs::remove_file(&missing).expect("remove missing scene");

        let batch = store
            .load_many_by_path_if_fresh_with_access(
                &[missing.clone(), first.clone(), second.clone()],
                &LoadOptions::default(),
                64,
            )
            .expect("batch lookup");

        assert_eq!(batch.len(), 3);
        assert!(batch[0].as_ref().expect("missing result").is_none());
        assert_eq!(
            batch[1]
                .as_ref()
                .expect("first result")
                .as_ref()
                .expect("first hit")
                .snapshot
                .file_state
                .path,
            first
        );
        assert_eq!(
            batch[2]
                .as_ref()
                .expect("second result")
                .as_ref()
                .expect("second hit")
                .snapshot
                .file_state
                .path,
            second
        );

        let single = store
            .load_by_path_if_fresh_with_access(&first, &LoadOptions::default(), 64)
            .expect("single lookup")
            .expect("single hit");
        assert_eq!(
            batch[1]
                .as_ref()
                .expect("first result")
                .as_ref()
                .expect("first hit")
                .snapshot
                .identity
                .scene_sha256,
            single.snapshot.identity.scene_sha256
        );
    }

    #[test]
    fn observe_touch_many_if_stale_skips_recent_accesses() {
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

        let access = ObserveCacheAccess {
            path: snapshot.file_state.path.clone(),
            file_state: snapshot.file_state.clone(),
            identity: snapshot.identity.clone(),
        };
        let stats = store
            .touch_many_if_stale(
                std::slice::from_ref(&access),
                SystemTime::now(),
                OBSERVE_CACHE_TOUCH_INTERVAL,
            )
            .expect("touch recent access");

        assert_eq!(stats.touched_count, 0);
    }

    #[test]
    fn observe_missing_blob_returns_miss_and_prunes_stale_index_rows() {
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

        let blob_relative_path = store
            .load_index()
            .expect("load index")
            .by_path
            .get(&super::normalized_path_key(&source))
            .expect("cached path")
            .blob
            .relative_path
            .clone();
        fs::remove_file(store.blob_path(&blob_relative_path)).expect("remove blob");

        assert!(
            store
                .load_by_path_if_fresh(&source, &LoadOptions::default(), 64)
                .expect("load after missing blob")
                .is_none()
        );
        assert!(
            store
                .load_index()
                .expect("reloaded index")
                .by_path
                .is_empty()
        );
    }

    #[test]
    fn observe_maintenance_expires_records_and_deletes_unreferenced_blobs() {
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

        let conn = store.open_connection().expect("open sqlite");
        let expired_at = SystemTime::now()
            .checked_sub(OBSERVE_CACHE_TTL + Duration::from_secs(5))
            .expect("expired timestamp");
        let expired_unix_secs = super::unix_timestamp_secs(expired_at);
        conn.execute(
            "UPDATE path_index SET last_accessed_unix_secs = ?1",
            [super::u64_to_sql(expired_unix_secs).expect("expired ts")],
        )
        .expect("write expired index");

        let stats = store
            .sweep_expired(SystemTime::now())
            .expect("apply maintenance");

        assert_eq!(stats.expired_record_count, 1);
        assert_eq!(stats.deleted_blob_count, 1);
        assert!(
            store
                .load_index()
                .expect("load trimmed index")
                .by_path
                .is_empty()
        );
        assert!(
            store
                .load_by_identity(&snapshot.identity)
                .expect("load identity after sweep")
                .is_none()
        );
        assert!(record_expired(
            Some(expired_unix_secs),
            super::unix_timestamp_secs(SystemTime::now()),
            OBSERVE_CACHE_TTL
        ));
    }
}
