use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use maya_scene_kit_formats::{
    ma::selective::{self, RawMaSelectiveSections},
    mel::{MelParseBudget, first_mel_parse_budget_limit},
};

use crate::{
    mb::MbParseBudget,
    scene::{
        DependencyFact, ExecutionUnitSummary, SceneDigestSet, SceneToolError, ValidationState,
        core::SceneFormat,
        dump::SceneDumpRequireEntry,
        execution::{
            ExecutionSurface, ObservedExecutionCatalog, ObservedExecutionSurface, catalog,
        },
        mb_read_session::MbReadSession,
        ops,
        paths::{PathKind, ScenePathEntry},
        query,
        schema::{SchemaContext, SchemaInputs},
        scripts::ScriptNodeEntry,
    },
};

const ADAPTIVE_MB_MAX_DEPTH: usize = 128;
const ADAPTIVE_MB_MIN_CHILDREN_PER_GROUP: usize = 262_144;
const ADAPTIVE_MB_MIN_TOTAL_CHUNKS: usize = 1_000_000;
const ADAPTIVE_MB_CHILDREN_PER_GROUP_DIVISOR: usize = 1024;
const ADAPTIVE_MB_TOTAL_CHUNKS_DIVISOR: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum MbParseBudgetMode {
    #[default]
    Adaptive,
    Exact,
}

pub(crate) fn materialize_adaptive_mb_parse_budget(
    source_bytes_len: usize,
    configured_max_parse_bytes: usize,
) -> MbParseBudget {
    let effective_bytes = std::cmp::min(source_bytes_len, configured_max_parse_bytes);
    MbParseBudget {
        max_depth: ADAPTIVE_MB_MAX_DEPTH,
        max_children_per_group: std::cmp::max(
            ADAPTIVE_MB_MIN_CHILDREN_PER_GROUP,
            effective_bytes / ADAPTIVE_MB_CHILDREN_PER_GROUP_DIVISOR,
        ),
        max_total_chunks: std::cmp::max(
            ADAPTIVE_MB_MIN_TOTAL_CHUNKS,
            effective_bytes / ADAPTIVE_MB_TOTAL_CHUNKS_DIVISOR,
        ),
        max_parse_bytes: configured_max_parse_bytes,
    }
}

pub(crate) struct SourceInput<'a> {
    path: &'a Path,
    scene_format: Option<SceneFormat>,
    validation_state: Option<ValidationState>,
    bytes: Option<Vec<u8>>,
    retain_ma_bytes: bool,
}

impl<'a> SourceInput<'a> {
    pub(crate) fn from_path(path: &'a Path) -> Self {
        Self {
            path,
            scene_format: None,
            validation_state: None,
            bytes: None,
            retain_ma_bytes: true,
        }
    }

    pub(crate) fn from_path_without_retained_ma_bytes(path: &'a Path) -> Self {
        Self {
            path,
            scene_format: None,
            validation_state: None,
            bytes: None,
            retain_ma_bytes: false,
        }
    }

    pub(crate) fn from_bytes(
        path: &'a Path,
        scene_format: SceneFormat,
        validation_state: ValidationState,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            path,
            scene_format: Some(scene_format),
            validation_state: Some(validation_state),
            bytes: Some(bytes),
            retain_ma_bytes: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    schema_root: Option<PathBuf>,
    chunk_schema_root: Option<PathBuf>,
    addattr_schema_path: Option<PathBuf>,
    structural_attr_schema_path: Option<PathBuf>,
    refedit_schema_path: Option<PathBuf>,
    additional_node_info_paths: Vec<PathBuf>,
    mb_parse_budget_mode: MbParseBudgetMode,
    mb_parse_budget: MbParseBudget,
    mel_parse_budget: MelParseBudget,
}

impl LoadOptions {
    pub fn with_schema_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.schema_root = Some(path.into());
        self
    }

    pub fn with_chunk_schema_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.chunk_schema_root = Some(path.into());
        self
    }

    pub fn with_addattr_schema_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.addattr_schema_path = Some(path.into());
        self
    }

    pub fn with_structural_attr_schema_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.structural_attr_schema_path = Some(path.into());
        self
    }

    pub fn with_refedit_schema_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.refedit_schema_path = Some(path.into());
        self
    }

    pub fn with_additional_node_info_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.additional_node_info_paths = paths;
        self
    }

    pub fn with_mb_parse_budget(mut self, budget: MbParseBudget) -> Self {
        self.mb_parse_budget_mode = MbParseBudgetMode::Exact;
        self.mb_parse_budget = budget;
        self
    }

    pub fn with_mel_parse_budget(mut self, budget: MelParseBudget) -> Self {
        self.mel_parse_budget = budget;
        self
    }

    pub fn with_max_parse_bytes(mut self, max_bytes: usize) -> Self {
        self.mb_parse_budget.max_parse_bytes = max_bytes;
        self.mel_parse_budget.max_bytes = max_bytes;
        self
    }

    pub(crate) fn schema_inputs(&self) -> SchemaInputs<'_> {
        SchemaInputs {
            schema_root: self.schema_root.as_ref(),
            chunk_schema_root: self.chunk_schema_root.as_ref(),
            addattr_schema_path: self.addattr_schema_path.as_ref(),
            structural_attr_schema_path: self.structural_attr_schema_path.as_ref(),
            refedit_schema_path: self.refedit_schema_path.as_ref(),
            additional_node_info_paths: &self.additional_node_info_paths,
        }
    }

    #[cfg(test)]
    pub(crate) fn mb_parse_budget(&self) -> &MbParseBudget {
        &self.mb_parse_budget
    }

    pub(crate) fn materialize_mb_parse_budget_for_path(
        &self,
        path: &Path,
    ) -> Result<MbParseBudget, SceneToolError> {
        let source_bytes_len = fs::metadata(path)?.len() as usize;
        Ok(self.materialize_mb_parse_budget_for_bytes(source_bytes_len))
    }

    pub(crate) fn materialize_mb_parse_budget_for_bytes(
        &self,
        source_bytes_len: usize,
    ) -> MbParseBudget {
        match self.mb_parse_budget_mode {
            MbParseBudgetMode::Adaptive => materialize_adaptive_mb_parse_budget(
                source_bytes_len,
                self.mb_parse_budget.max_parse_bytes,
            ),
            MbParseBudgetMode::Exact => self.mb_parse_budget,
        }
    }

    #[cfg(test)]
    pub(crate) fn mb_parse_budget_mode(&self) -> MbParseBudgetMode {
        self.mb_parse_budget_mode
    }

    #[cfg(test)]
    pub(crate) fn mel_parse_budget(&self) -> &MelParseBudget {
        &self.mel_parse_budget
    }
}

pub struct Loader {
    options: LoadOptions,
    schema_context: OnceLock<Result<Arc<SchemaContext>, String>>,
}

impl Loader {
    pub fn new(options: LoadOptions) -> Self {
        Self {
            options,
            schema_context: OnceLock::new(),
        }
    }

    fn observe(&self, input: SourceInput<'_>) -> Result<ObservationBundle, SceneToolError> {
        let scene_format = match input.scene_format {
            Some(scene_format) => scene_format,
            None => ops::detect_scene_format(input.path)?,
        };
        let schema_context = match scene_format {
            SceneFormat::Mb => Some(self.schema_context()?),
            SceneFormat::Ma | SceneFormat::Unknown => None,
        };
        ObservationBundle::load(input, scene_format, &self.options, schema_context)
    }

    fn schema_context(&self) -> Result<&Arc<SchemaContext>, SceneToolError> {
        match self.schema_context.get_or_init(|| {
            SchemaContext::from_inputs_cached(&self.options.schema_inputs())
                .map_err(|err| err.to_string())
        }) {
            Ok(context) => Ok(context),
            Err(err) => Err(SceneToolError::Config(err.clone())),
        }
    }

    pub fn observe_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<ObservationBundle, SceneToolError> {
        self.observe(SourceInput::from_path(path.as_ref()))
    }

    pub(crate) fn observe_path_without_retained_ma_bytes(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<ObservationBundle, SceneToolError> {
        self.observe(SourceInput::from_path_without_retained_ma_bytes(
            path.as_ref(),
        ))
    }

    pub fn observe_bytes(
        &self,
        path: impl AsRef<Path>,
        scene_format: SceneFormat,
        validation_state: ValidationState,
        bytes: Vec<u8>,
    ) -> Result<ObservationBundle, SceneToolError> {
        self.observe(SourceInput::from_bytes(
            path.as_ref(),
            scene_format,
            validation_state,
            bytes,
        ))
    }
}

pub struct ObservationBundle {
    scene_path: PathBuf,
    scene_format: SceneFormat,
    validation_state: ValidationState,
    mel_parse_budget: MelParseBudget,
    observed_execution_core: OnceLock<catalog::ObservedExecutionCore>,
    scene_digests: OnceLock<SceneDigestSet>,
    pub(crate) data: ObservationData,
}

pub(crate) struct MaObservationData {
    pub(crate) source_path: PathBuf,
    pub(crate) bytes: OnceLock<Vec<u8>>,
    pub(crate) selective_sections: OnceLock<RawMaSelectiveSections>,
    pub(crate) scene_paths: OnceLock<Vec<ScenePathEntry>>,
}

pub(crate) enum ObservationData {
    Ma { data: Box<MaObservationData> },
    Mb { session: Box<MbReadSession> },
}

impl ObservationBundle {
    pub(crate) fn load(
        input: SourceInput<'_>,
        scene_format: SceneFormat,
        options: &LoadOptions,
        schema_context: Option<&Arc<SchemaContext>>,
    ) -> Result<Self, SceneToolError> {
        let path = input.path;
        match scene_format {
            SceneFormat::Ma => {
                let bytes = match input.bytes {
                    Some(bytes) => bytes,
                    None => fs::read(path)?,
                };
                let sections = selective::extract_raw_selective_sections_from_ma_with_budget(
                    &bytes,
                    &options.mel_parse_budget,
                );
                if let Some(limit) =
                    first_mel_parse_budget_limit(&sections.audit_top_level.diagnostics)
                {
                    return Err(SceneToolError::MelParseBudgetExceeded { limit });
                }
                let selective_sections = OnceLock::new();
                selective_sections
                    .set(sections)
                    .expect("ma selective sections initialized once");
                let retained_bytes = if input.retain_ma_bytes {
                    let stored = OnceLock::new();
                    stored
                        .set(bytes)
                        .expect("ma retained bytes initialized once");
                    stored
                } else {
                    OnceLock::new()
                };
                let data = Box::new(MaObservationData {
                    source_path: path.to_path_buf(),
                    bytes: retained_bytes,
                    selective_sections,
                    scene_paths: OnceLock::new(),
                });
                let validation_state = input.validation_state.unwrap_or_else(|| {
                    if data
                        .selective_sections()
                        .audit_top_level
                        .diagnostics
                        .is_empty()
                    {
                        ValidationState::Validated
                    } else {
                        ValidationState::Partial
                    }
                });
                Ok(Self {
                    scene_path: path.to_path_buf(),
                    scene_format,
                    validation_state,
                    mel_parse_budget: options.mel_parse_budget,
                    observed_execution_core: OnceLock::new(),
                    scene_digests: OnceLock::new(),
                    data: ObservationData::Ma { data },
                })
            }
            SceneFormat::Mb => {
                let schema_context =
                    schema_context.expect("mb observation requires schema context");
                let budget = match input.bytes.as_ref() {
                    Some(bytes) => options.materialize_mb_parse_budget_for_bytes(bytes.len()),
                    None => options.materialize_mb_parse_budget_for_path(path)?,
                };
                let session = match input.bytes {
                    Some(bytes) => MbReadSession::load_raw_bytes(
                        path,
                        bytes,
                        Arc::clone(schema_context),
                        &budget,
                    )?,
                    None => MbReadSession::load_raw(path, Arc::clone(schema_context), &budget)?,
                };
                let validation_state = input
                    .validation_state
                    .unwrap_or(session.integrity()?.validation_state);
                Ok(Self {
                    scene_path: path.to_path_buf(),
                    scene_format,
                    validation_state,
                    mel_parse_budget: options.mel_parse_budget,
                    observed_execution_core: OnceLock::new(),
                    scene_digests: OnceLock::new(),
                    data: ObservationData::Mb {
                        session: Box::new(session),
                    },
                })
            }
            SceneFormat::Unknown => Err(SceneToolError::UnsupportedSceneFormat {
                path: path.to_path_buf(),
                detected: scene_format,
            }),
        }
    }

    pub fn scene_path(&self) -> &Path {
        &self.scene_path
    }

    pub fn scene_format(&self) -> SceneFormat {
        self.scene_format
    }

    pub fn validation_state(&self) -> ValidationState {
        self.validation_state
    }

    pub(crate) fn mel_parse_budget(&self) -> &MelParseBudget {
        &self.mel_parse_budget
    }

    pub fn script_node_entries(&self) -> Result<Vec<ScriptNodeEntry>, SceneToolError> {
        query::scripts::script_node_entries(self)
    }

    pub fn scene_dump_report(&self) -> Result<crate::scene::dump::SceneDumpReport, SceneToolError> {
        query::dump::scene_dump_report(self)
    }

    pub fn scene_paths(&self, kind: PathKind) -> Result<Vec<ScenePathEntry>, SceneToolError> {
        query::paths::scene_paths(self, kind)
    }

    pub fn requires(&self) -> Result<Vec<String>, SceneToolError> {
        query::dump::requires(self)
    }

    pub fn require_entries(&self) -> Result<Vec<SceneDumpRequireEntry>, SceneToolError> {
        query::dump::require_entries(self)
    }

    pub fn execution_surfaces(
        &self,
        max_preview: usize,
    ) -> Result<Vec<ExecutionSurface>, SceneToolError> {
        Ok(self
            .observed_execution_catalog(max_preview)?
            .surfaces
            .into_iter()
            .map(|surface| surface.surface)
            .collect())
    }

    pub fn observed_execution_surfaces(
        &self,
        max_preview: usize,
    ) -> Result<Vec<ObservedExecutionSurface>, SceneToolError> {
        Ok(self.observed_execution_catalog(max_preview)?.surfaces)
    }

    pub fn execution_unit_summaries(
        &self,
        max_preview: usize,
    ) -> Result<Vec<ExecutionUnitSummary>, SceneToolError> {
        Ok(self.observed_execution_catalog(max_preview)?.unit_summaries)
    }

    pub fn dependency_facts(
        &self,
        max_preview: usize,
    ) -> Result<Vec<DependencyFact>, SceneToolError> {
        Ok(self
            .observed_execution_catalog(max_preview)?
            .dependency_facts)
    }

    pub fn scene_digests(&self, max_preview: usize) -> Result<SceneDigestSet, SceneToolError> {
        let _ = max_preview;
        Ok(self.scene_digests_cache()?.clone())
    }

    pub fn observed_execution_catalog(
        &self,
        max_preview: usize,
    ) -> Result<ObservedExecutionCatalog, SceneToolError> {
        self.observed_execution_catalog_with_digests(max_preview, true)
    }

    pub fn observed_execution_catalog_with_digests(
        &self,
        max_preview: usize,
        include_digests: bool,
    ) -> Result<ObservedExecutionCatalog, SceneToolError> {
        let core = self.observed_execution_core()?;
        let digests = if include_digests {
            self.scene_digests_cache()?.clone()
        } else {
            SceneDigestSet {
                scene_sha256: String::new(),
                schema_bundle_sha256: None,
                policy_bundle_sha256: None,
            }
        };
        Ok(catalog::materialize_observed_execution_catalog(
            core,
            max_preview,
            digests,
        ))
    }

    fn observed_execution_core(&self) -> Result<&catalog::ObservedExecutionCore, SceneToolError> {
        if let Some(core) = self.observed_execution_core.get() {
            return Ok(core);
        }

        let core = catalog::build_observed_execution_core(self)?;
        let _ = self.observed_execution_core.set(core);
        Ok(self
            .observed_execution_core
            .get()
            .expect("observed execution core initialized"))
    }

    fn scene_digests_cache(&self) -> Result<&SceneDigestSet, SceneToolError> {
        if let Some(digests) = self.scene_digests.get() {
            return Ok(digests);
        }

        let _ = self.scene_digests.set(catalog::build_scene_digests(self)?);
        Ok(self.scene_digests.get().expect("scene digests initialized"))
    }

    #[cfg(test)]
    pub(crate) fn cached_execution_core_ptr(
        &self,
    ) -> Option<*const catalog::ObservedExecutionCore> {
        self.observed_execution_core.get().map(std::ptr::from_ref)
    }

    #[cfg(test)]
    pub(crate) fn cached_scene_digests_ptr(&self) -> Option<*const SceneDigestSet> {
        self.scene_digests.get().map(std::ptr::from_ref)
    }

    #[cfg(test)]
    pub(crate) fn cached_ma_bytes_ptr(&self) -> Option<*const Vec<u8>> {
        match &self.data {
            ObservationData::Ma { data } => data.bytes.get().map(std::ptr::from_ref),
            ObservationData::Mb { .. } => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn cached_mb_scene_facts_ptr(
        &self,
    ) -> Option<*const crate::scene::mb_read_session::MbSceneFacts> {
        match &self.data {
            ObservationData::Ma { .. } => None,
            ObservationData::Mb { session } => session.cached_scene_facts_ptr(),
        }
    }

    #[cfg(test)]
    pub(crate) fn cached_mb_build_ptr(&self) -> Option<*const crate::scene::ir::SceneBuildOutput> {
        match &self.data {
            ObservationData::Ma { .. } => None,
            ObservationData::Mb { session } => session.cached_build_ptr(),
        }
    }
}
