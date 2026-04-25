use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use once_cell::sync::Lazy;

use super::{SchemaRegistry, locator::SchemaPaths, typeid_map::TypeIdTypeNameResolver};
use crate::scene::SceneToolError;

type CachedSchemaContext = Result<Arc<SchemaContext>, String>;

static SCHEMA_CONTEXT_CACHE: Lazy<Mutex<HashMap<SchemaPaths, CachedSchemaContext>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy)]
pub(crate) struct SchemaInputs<'a> {
    pub(crate) schema_root: Option<&'a PathBuf>,
    pub(crate) chunk_schema_root: Option<&'a PathBuf>,
    pub(crate) addattr_schema_path: Option<&'a PathBuf>,
    pub(crate) structural_attr_schema_path: Option<&'a PathBuf>,
    pub(crate) refedit_schema_path: Option<&'a PathBuf>,
    pub(crate) additional_node_info_paths: &'a [PathBuf],
}

#[derive(Debug, Clone)]
pub(crate) struct SchemaContext {
    registry: Arc<SchemaRegistry>,
    typeid_resolver: TypeIdTypeNameResolver,
}

impl SchemaContext {
    pub(crate) fn from_inputs_cached(
        inputs: &SchemaInputs<'_>,
    ) -> Result<Arc<Self>, SceneToolError> {
        let paths = SchemaPaths::from_schema_inputs(inputs);
        if let Some(cached) = cached_schema_context(&paths) {
            return cached;
        }

        let built = Self::from_paths(paths.clone())
            .map(Arc::new)
            .map_err(|err| err.to_string());
        let mut cache = SCHEMA_CONTEXT_CACHE
            .lock()
            .expect("schema context cache lock poisoned");
        let cached = cache.entry(paths).or_insert(built);
        clone_cached_schema_context(cached)
    }

    fn from_paths(paths: SchemaPaths) -> Result<Self, SceneToolError> {
        let registry = Arc::new(SchemaRegistry::new(paths));
        validate_registry_inputs(registry.as_ref())?;
        let typeid_resolver =
            crate::scene::schema::typeid_map::build_typeid_typename_resolver_with_registry(
                registry.as_ref(),
            )
            .map_err(SceneToolError::Config)?;
        Ok(Self {
            registry,
            typeid_resolver,
        })
    }

    pub(crate) fn registry(&self) -> Arc<SchemaRegistry> {
        Arc::clone(&self.registry)
    }

    pub(crate) fn typeid_resolver(&self) -> &TypeIdTypeNameResolver {
        &self.typeid_resolver
    }

    pub(crate) fn node_execution_semantics(
        &self,
    ) -> Result<Arc<super::node_semantics::NodeExecutionSemantics>, SceneToolError> {
        super::node_semantics::node_execution_semantics_with_registry(self.registry.as_ref())
            .map_err(SceneToolError::Config)
    }
}

fn cached_schema_context(
    paths: &SchemaPaths,
) -> Option<Result<Arc<SchemaContext>, SceneToolError>> {
    let cache = SCHEMA_CONTEXT_CACHE
        .lock()
        .expect("schema context cache lock poisoned");
    cache.get(paths).map(clone_cached_schema_context)
}

fn clone_cached_schema_context(
    cached: &CachedSchemaContext,
) -> Result<Arc<SchemaContext>, SceneToolError> {
    match cached {
        Ok(context) => Ok(Arc::clone(context)),
        Err(err) => Err(SceneToolError::Config(err.clone())),
    }
}

fn validate_registry_inputs(registry: &SchemaRegistry) -> Result<(), SceneToolError> {
    let paths = registry.paths();
    if let Some(err) = paths.resolution_error() {
        return Err(SceneToolError::Config(err.to_string()));
    }
    crate::scene::schema::validate_chunk_schema_pack(&paths.chunk_schema_root)
        .map_err(SceneToolError::Config)?;
    crate::scene::schema::addattr_tokens::validate_add_attr_token_schema_file(
        &paths.addattr_schema_file,
    )
    .map_err(SceneToolError::Config)?;
    crate::scene::schema::node_semantics::validate_node_info_schema_file(
        &paths.node_info_schema_file,
    )
    .map_err(SceneToolError::Config)?;
    for path in &paths.additional_node_info_files {
        crate::scene::schema::node_semantics::validate_node_info_schema_file(path)
            .map_err(SceneToolError::Config)?;
    }
    crate::scene::schema::structural_attr::validate_structural_attr_schema_file(
        &paths.structural_attr_schema_file,
    )
    .map_err(SceneToolError::Config)?;
    crate::scene::schema::refedit::validate_refedit_schema_file(&paths.refedit_schema_file)
        .map_err(SceneToolError::Config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::SchemaContext;
    use crate::scene::{LoadOptions, SceneToolError};

    #[test]
    fn cached_schema_context_reuses_arc_for_identical_inputs() {
        let options = LoadOptions::default();

        let first = SchemaContext::from_inputs_cached(&options.schema_inputs()).expect("first");
        let second = SchemaContext::from_inputs_cached(&options.schema_inputs()).expect("second");

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn cached_schema_context_reuses_config_errors_for_identical_inputs() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let missing_chunk_root = dir.path().join("missing_chunks");
        let options = LoadOptions::default().with_chunk_schema_root(&missing_chunk_root);

        let first = SchemaContext::from_inputs_cached(&options.schema_inputs());
        let second = SchemaContext::from_inputs_cached(&options.schema_inputs());

        match first {
            Err(SceneToolError::Config(message)) => {
                assert!(message.contains("missing_chunks"));
            }
            other => panic!("expected config error, got {other:?}"),
        }
        match second {
            Err(SceneToolError::Config(message)) => {
                assert!(message.contains("missing_chunks"));
            }
            other => panic!("expected config error, got {other:?}"),
        }
    }
}
