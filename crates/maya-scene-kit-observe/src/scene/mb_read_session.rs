use std::sync::{Arc, OnceLock};

use crate::{
    mb::{MayaBinaryParseError, MbParseBudget, parse_bytes_with_budget, parse_file_with_budget},
    scene::{
        SceneToolError,
        integrity::{SceneIntegritySummary, summarize_mb_read_integrity_parts},
        ir::{DecodedChunkRecord, RawChunkRecord, SceneBuildOutput, TypeIdResolverStatus},
        mb_extract,
        recover::{
            builder, collect_decode_quality_records, collect_decoded_chunk_records,
            collect_raw_chunk_records_with_budget,
        },
        dump::SceneDumpRequireEntry,
        paths::ScenePathEntry,
        schema::SchemaContext,
        source::mb,
    },
};

pub(crate) struct MbDecodedArtifacts {
    pub(crate) raw_chunks: Vec<RawChunkRecord>,
    pub(crate) decoded_chunks: Vec<DecodedChunkRecord>,
    pub(crate) decode_qualities: Vec<crate::scene::ir::DecodeQualityRecord>,
}

pub(crate) struct MbReadSession {
    pub(crate) mb: crate::mb::MayaBinaryFile,
    schema_context: Arc<SchemaContext>,
    budget: MbParseBudget,
    decoded: OnceLock<Result<Arc<MbDecodedArtifacts>, MayaBinaryParseError>>,
    build: OnceLock<Result<Arc<SceneBuildOutput>, MayaBinaryParseError>>,
    integrity: OnceLock<Result<SceneIntegritySummary, MayaBinaryParseError>>,
    scene_paths: OnceLock<Result<Arc<[ScenePathEntry]>, MayaBinaryParseError>>,
    requires: OnceLock<Arc<[String]>>,
    require_entries: OnceLock<Arc<[SceneDumpRequireEntry]>>,
}

impl MbReadSession {
    pub(crate) fn load_raw(
        path: &std::path::Path,
        schema_context: Arc<SchemaContext>,
        budget: &MbParseBudget,
    ) -> Result<Self, SceneToolError> {
        let mb = parse_file_with_budget(path, budget)?;
        Self::from_mb(mb, schema_context, budget)
    }

    pub(crate) fn load_raw_bytes(
        path: &std::path::Path,
        bytes: Vec<u8>,
        schema_context: Arc<SchemaContext>,
        budget: &MbParseBudget,
    ) -> Result<Self, SceneToolError> {
        let mut mb = parse_bytes_with_budget(bytes, budget)?;
        mb.path = Some(path.to_path_buf());
        Self::from_mb(mb, schema_context, budget)
    }

    fn from_mb(
        mb: crate::mb::MayaBinaryFile,
        schema_context: Arc<SchemaContext>,
        budget: &MbParseBudget,
    ) -> Result<Self, SceneToolError> {
        Ok(Self {
            mb,
            schema_context,
            budget: *budget,
            decoded: OnceLock::new(),
            build: OnceLock::new(),
            integrity: OnceLock::new(),
            scene_paths: OnceLock::new(),
            requires: OnceLock::new(),
            require_entries: OnceLock::new(),
        })
    }

    pub(crate) fn build(&self) -> Result<&SceneBuildOutput, SceneToolError> {
        if let Some(result) = self.build.get() {
            return map_cached_arc_parse_result(result);
        }

        let decoded = self.decoded()?;
        let build = Ok(Arc::new(builder::build_scene_model_from_decoded_chunks(
            Arc::clone(&self.mb.data),
            decoded.raw_chunks.clone(),
            decoded.decoded_chunks.clone(),
            Some(self.schema_context.typeid_resolver()),
            self.schema_context.registry(),
            TypeIdResolverStatus::Provided,
        )));
        let _ = self.build.set(build);
        map_cached_arc_parse_result(self.build.get().expect("mb build initialized"))
    }

    pub(crate) fn integrity(&self) -> Result<&SceneIntegritySummary, SceneToolError> {
        if let Some(result) = self.integrity.get() {
            return map_cached_parse_result(result);
        }

        let decoded = self.decoded()?;
        let integrity = Ok(summarize_mb_read_integrity_parts(
            &TypeIdResolverStatus::Provided,
            &decoded.decode_qualities,
        ));
        let _ = self.integrity.set(integrity);
        map_cached_parse_result(self.integrity.get().expect("mb integrity initialized"))
    }

    pub(crate) fn requires(&self) -> &[String] {
        self.requires
            .get_or_init(|| Arc::from(mb_extract::extract_requires_from_mb(&self.mb)))
            .as_ref()
    }

    pub(crate) fn require_entries(&self) -> &[SceneDumpRequireEntry] {
        self.require_entries
            .get_or_init(|| Arc::from(mb_extract::extract_require_entries_from_mb(&self.mb)))
            .as_ref()
    }

    pub(crate) fn scene_paths_all(&self) -> Result<&[ScenePathEntry], SceneToolError> {
        if let Some(result) = self.scene_paths.get() {
            return map_cached_arc_slice_parse_result(result);
        }

        let build = self.build()?;
        let raw_entries = maya_scene_kit_formats::mb::paths::extract_raw_scene_paths_from_mb(&self.mb);
        let entries = mb::collect_mb_scene_paths(
            &self.mb,
            &build.scene.nodes,
            &build.scene.reference_files,
            &raw_entries,
            &build.artifacts.raw_chunks,
            build.artifacts.raw_source.as_ref(),
        );
        let _ = self.scene_paths.set(Ok(Arc::from(entries)));
        map_cached_arc_slice_parse_result(self.scene_paths.get().expect("mb scene paths initialized"))
    }

    pub(crate) fn budget(&self) -> &MbParseBudget {
        &self.budget
    }

    fn decoded(&self) -> Result<&Arc<MbDecodedArtifacts>, SceneToolError> {
        if let Some(result) = self.decoded.get() {
            return map_cached_parse_result(result);
        }

        let raw_chunks = collect_raw_chunk_records_with_budget(&self.mb, &self.budget)?;
        let decoded_chunks = collect_decoded_chunk_records(
            &raw_chunks,
            self.mb.data.as_ref(),
            self.schema_context.registry(),
        );
        let decode_qualities = collect_decode_quality_records(&decoded_chunks);
        let decoded = Ok(Arc::new(MbDecodedArtifacts {
            raw_chunks,
            decoded_chunks,
            decode_qualities,
        }));
        let _ = self.decoded.set(decoded);
        map_cached_parse_result(self.decoded.get().expect("mb decoded artifacts initialized"))
    }
}

fn map_cached_parse_result<T>(
    result: &Result<T, MayaBinaryParseError>,
) -> Result<&T, SceneToolError> {
    match result {
        Ok(value) => Ok(value),
        Err(err) => Err(SceneToolError::from(err.clone())),
    }
}

fn map_cached_arc_parse_result<T>(
    result: &Result<Arc<T>, MayaBinaryParseError>,
) -> Result<&T, SceneToolError> {
    match result {
        Ok(value) => Ok(value.as_ref()),
        Err(err) => Err(SceneToolError::from(err.clone())),
    }
}

fn map_cached_arc_slice_parse_result<T>(
    result: &Result<Arc<[T]>, MayaBinaryParseError>,
) -> Result<&[T], SceneToolError> {
    match result {
        Ok(value) => Ok(value.as_ref()),
        Err(err) => Err(SceneToolError::from(err.clone())),
    }
}
