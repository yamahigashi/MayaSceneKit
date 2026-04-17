use std::sync::{Arc, OnceLock};

use crate::{
    mb::{MayaBinaryParseError, MbParseBudget, parse_bytes_with_budget, parse_file_with_budget},
    scene::{
        SceneToolError,
        dump::SceneDumpRequireEntry,
        integrity::{SceneIntegritySummary, summarize_mb_read_integrity_parts},
        ir::{
            DecodedChunkRecord, RawChunkRecord, RecoveredNode, ReferenceFileOp, SceneBuildOutput,
            TypeIdResolverStatus,
        },
        mb_extract,
        paths::ScenePathEntry,
        recover::{
            builder, collect_decode_quality_records, collect_decoded_chunk_records,
            collect_raw_chunk_records_with_budget, recover_nodes, recover_reference_files,
        },
        schema::SchemaContext,
        source::mb,
    },
};

pub(crate) struct MbDecodedArtifacts {
    pub(crate) raw_chunks: Vec<RawChunkRecord>,
    pub(crate) decoded_chunks: Vec<DecodedChunkRecord>,
    pub(crate) decode_qualities: Vec<crate::scene::ir::DecodeQualityRecord>,
}

pub(crate) struct MbSceneFacts {
    pub(crate) nodes: Vec<RecoveredNode>,
    pub(crate) reference_files: Vec<ReferenceFileOp>,
}

pub(crate) struct MbReadSession {
    pub(crate) mb: crate::mb::MayaBinaryFile,
    schema_context: Arc<SchemaContext>,
    budget: MbParseBudget,
    decoded: OnceLock<Result<Arc<MbDecodedArtifacts>, MayaBinaryParseError>>,
    scene_facts: OnceLock<Result<Arc<MbSceneFacts>, MayaBinaryParseError>>,
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
            scene_facts: OnceLock::new(),
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
        let scene_facts = self.scene_facts()?;
        let build = Ok(Arc::new(builder::build_scene_model_from_decoded_chunks(
            Arc::clone(&self.mb.data),
            decoded.raw_chunks.clone(),
            decoded.decoded_chunks.clone(),
            scene_facts.nodes.clone(),
            scene_facts.reference_files.clone(),
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

        let scene_facts = self.scene_facts()?;
        let decoded = self.decoded()?;
        let raw_entries =
            maya_scene_kit_formats::mb::paths::extract_raw_scene_paths_from_mb(&self.mb);
        let entries = mb::collect_mb_scene_paths(
            &self.mb,
            &scene_facts.nodes,
            &scene_facts.reference_files,
            &raw_entries,
            &decoded.raw_chunks,
            self.mb.data.as_ref(),
        );
        let _ = self.scene_paths.set(Ok(Arc::from(entries)));
        map_cached_arc_slice_parse_result(
            self.scene_paths.get().expect("mb scene paths initialized"),
        )
    }

    pub(crate) fn budget(&self) -> &MbParseBudget {
        &self.budget
    }

    pub(crate) fn scene_nodes(&self) -> Result<&[RecoveredNode], SceneToolError> {
        Ok(self.scene_facts()?.nodes.as_slice())
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
        map_cached_parse_result(
            self.decoded
                .get()
                .expect("mb decoded artifacts initialized"),
        )
    }

    fn scene_facts(&self) -> Result<&Arc<MbSceneFacts>, SceneToolError> {
        if let Some(result) = self.scene_facts.get() {
            return map_cached_parse_result(result);
        }

        let decoded = self.decoded()?;
        let scene_facts = Ok(Arc::new(MbSceneFacts {
            nodes: recover_nodes(
                &decoded.decoded_chunks,
                Some(self.schema_context.typeid_resolver()),
            ),
            reference_files: recover_reference_files(&decoded.decoded_chunks),
        }));
        let _ = self.scene_facts.set(scene_facts);
        map_cached_parse_result(self.scene_facts.get().expect("mb scene facts initialized"))
    }

    #[cfg(test)]
    pub(crate) fn cached_scene_facts_ptr(&self) -> Option<*const MbSceneFacts> {
        self.scene_facts
            .get()
            .and_then(|result| result.as_ref().ok().map(Arc::as_ptr))
    }

    #[cfg(test)]
    pub(crate) fn cached_build_ptr(&self) -> Option<*const SceneBuildOutput> {
        self.build
            .get()
            .and_then(|result| result.as_ref().ok().map(Arc::as_ptr))
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
