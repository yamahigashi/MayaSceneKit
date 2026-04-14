use std::sync::OnceLock;

use crate::{
    mb::{MayaBinaryParseError, MbParseBudget, parse_bytes_with_budget, parse_file_with_budget},
    scene::{
        SceneToolError,
        context::SchemaInputs,
        integrity::{SceneIntegritySummary, summarize_mb_read_integrity_parts},
        ir::{SceneBuildOutput, TypeIdResolverStatus},
        recover::{
            builder, collect_decode_quality_records, collect_decoded_chunk_records,
            collect_raw_chunk_records_with_budget,
        },
        runtime_assets::RuntimeAssets,
        schema::typeid_map::TypeIdTypeNameResolver,
    },
};

pub(crate) struct MbReadSession {
    pub(crate) mb: crate::mb::MayaBinaryFile,
    assets: RuntimeAssets,
    budget: MbParseBudget,
    typeid_resolver: TypeIdTypeNameResolver,
    build: OnceLock<Result<SceneBuildOutput, MayaBinaryParseError>>,
    integrity: OnceLock<Result<SceneIntegritySummary, MayaBinaryParseError>>,
}

impl MbReadSession {
    pub(crate) fn load_raw(
        path: &std::path::Path,
        schema_inputs: &SchemaInputs<'_>,
        budget: &MbParseBudget,
    ) -> Result<Self, SceneToolError> {
        let mb = parse_file_with_budget(path, budget)?;
        Self::from_mb(mb, schema_inputs, budget)
    }

    pub(crate) fn load_raw_bytes(
        path: &std::path::Path,
        bytes: Vec<u8>,
        schema_inputs: &SchemaInputs<'_>,
        budget: &MbParseBudget,
    ) -> Result<Self, SceneToolError> {
        let mut mb = parse_bytes_with_budget(bytes, budget)?;
        mb.path = Some(path.to_path_buf());
        Self::from_mb(mb, schema_inputs, budget)
    }

    fn from_mb(
        mb: crate::mb::MayaBinaryFile,
        schema_inputs: &SchemaInputs<'_>,
        budget: &MbParseBudget,
    ) -> Result<Self, SceneToolError> {
        let assets = RuntimeAssets::from_schema_inputs(schema_inputs);
        assets.validate_schema_inputs()?;
        let typeid_resolver = assets.build_typeid_typename_resolver()?;
        Ok(Self {
            mb,
            assets,
            budget: *budget,
            typeid_resolver,
            build: OnceLock::new(),
            integrity: OnceLock::new(),
        })
    }

    pub(crate) fn build(&self) -> Result<&SceneBuildOutput, SceneToolError> {
        if let Some(result) = self.build.get() {
            return map_cached_parse_result(result);
        }

        let build = builder::build_scene_model_with_budget(
            &self.mb,
            &self.typeid_resolver,
            self.assets.registry(),
            &self.budget,
        );
        let _ = self.build.set(build);
        map_cached_parse_result(self.build.get().expect("mb build initialized"))
    }

    pub(crate) fn integrity(&self) -> Result<&SceneIntegritySummary, SceneToolError> {
        if let Some(result) = self.integrity.get() {
            return map_cached_parse_result(result);
        }

        let raw_chunks = collect_raw_chunk_records_with_budget(&self.mb, &self.budget)?;
        let decoded_chunks = collect_decoded_chunk_records(
            &raw_chunks,
            self.mb.data.as_ref(),
            self.assets.registry(),
        );
        let decode_qualities = collect_decode_quality_records(&decoded_chunks);
        let integrity = Ok(summarize_mb_read_integrity_parts(
            &TypeIdResolverStatus::Provided,
            &decode_qualities,
        ));
        let _ = self.integrity.set(integrity);
        map_cached_parse_result(self.integrity.get().expect("mb integrity initialized"))
    }

    pub(crate) fn budget(&self) -> &MbParseBudget {
        &self.budget
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
