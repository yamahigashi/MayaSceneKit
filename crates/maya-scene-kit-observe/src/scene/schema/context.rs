use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use once_cell::sync::Lazy;

use super::{SchemaRegistry, locator::SchemaPaths, typeid_map::TypeIdTypeNameResolver};
use crate::scene::SceneToolError;

type CachedSchemaContext = Result<Arc<SchemaContext>, String>;

static SCHEMA_CONTEXT_CACHE: Lazy<Mutex<HashMap<SchemaPaths, Arc<OnceLock<CachedSchemaContext>>>>> =
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
    schema_bundle_sha256: String,
}

impl SchemaContext {
    pub(crate) fn from_inputs_cached(
        inputs: &SchemaInputs<'_>,
    ) -> Result<Arc<Self>, SceneToolError> {
        let paths = SchemaPaths::from_schema_inputs(inputs);
        if let Some(cached) = cached_schema_context(&paths) {
            return cached;
        }

        let cell = {
            let mut cache = SCHEMA_CONTEXT_CACHE
                .lock()
                .expect("schema context cache lock poisoned");
            Arc::clone(
                cache
                    .entry(paths.clone())
                    .or_insert_with(|| Arc::new(OnceLock::new())),
            )
        };
        let cached = cell.get_or_init(|| {
            Self::from_paths(paths)
                .map(Arc::new)
                .map_err(|err| err.to_string())
        });
        clone_cached_schema_context(cached)
    }

    fn from_paths(paths: SchemaPaths) -> Result<Self, SceneToolError> {
        let registry = Arc::new(SchemaRegistry::new(paths));
        registry.capture_inputs().map_err(SceneToolError::Config)?;
        let (schema_bundle_sha256, typeid_resolver) =
            std::thread::scope(|scope| -> Result<_, SceneToolError> {
                let digest = std::thread::Builder::new()
                    .spawn_scoped(scope, || registry.schema_bundle_sha256())?;
                validate_registry_inputs(registry.as_ref())?;
                let typeid_resolver =
                    crate::scene::schema::typeid_map::build_typeid_typename_resolver_with_registry(
                        registry.as_ref(),
                    )
                    .map_err(SceneToolError::Config)?;
                let schema_bundle_sha256 = digest
                    .join()
                    .map_err(|_| {
                        SceneToolError::Message("schema digest worker panicked".to_owned())
                    })?
                    .map_err(SceneToolError::Config)?;
                Ok((schema_bundle_sha256, typeid_resolver))
            })?;
        Ok(Self {
            registry,
            typeid_resolver,
            schema_bundle_sha256,
        })
    }

    pub(crate) fn schema_bundle_sha256(&self) -> &str {
        &self.schema_bundle_sha256
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
    cache
        .get(paths)
        .and_then(|cell| cell.get())
        .map(clone_cached_schema_context)
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
    crate::scene::schema::validate_chunk_schema_pack(registry).map_err(SceneToolError::Config)?;
    crate::scene::schema::addattr_tokens::validate_add_attr_token_schema_file(registry)
        .map_err(SceneToolError::Config)?;
    crate::scene::schema::node_semantics::validate_node_info_with_registry(registry)
        .map_err(SceneToolError::Config)?;
    crate::scene::schema::structural_attr::validate_structural_attr_schema_file(registry)
        .map_err(SceneToolError::Config)?;
    crate::scene::schema::refedit::validate_refedit_schema_file(
        registry,
        &paths.refedit_schema_file,
    )
    .map_err(SceneToolError::Config)?;
    Ok(())
}

impl crate::scene::LoadOptions {
    pub fn schema_bundle_sha256(&self) -> Result<String, SceneToolError> {
        Ok(SchemaContext::from_inputs_cached(&self.schema_inputs())?
            .schema_bundle_sha256()
            .to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::SchemaContext;
    use crate::scene::{LoadOptions, SceneToolError};

    #[test]
    fn schema_free_ma_digests_ignore_broken_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Example.ma");
        std::fs::write(&path, b"//Maya ASCII 2026 scene\n").unwrap();
        let options = LoadOptions::default().with_schema_root(dir.path().join("ExampleMissing"));
        let loader = crate::scene::Loader::new(options.clone());
        for observation in [
            loader.observe_path_without_retained_ma_bytes(&path),
            loader.observe_paths_path(&path),
            loader.observe_path(&path),
        ] {
            let observation = observation.unwrap();
            let crate::scene::source::loader::ObservationData::Ma { data } = &observation.data
            else {
                panic!("expected MA");
            };
            assert!(data.schema_context.is_none());
        }
        let observation = loader.observe_path(&path).unwrap();
        assert!(
            observation
                .scene_digests(0)
                .unwrap()
                .schema_bundle_sha256
                .is_none()
        );
        let snapshot =
            crate::scene::ObservedSceneSnapshot::from_observation(&observation, &options).unwrap();
        assert!(snapshot.is_none());
        let root = dir.path().join("ExampleCache");
        let store = crate::scene::ObserveCacheStore::new(&root, &options);
        assert!(!root.exists());
        assert!(store.load_by_path_if_fresh(&path).unwrap().is_none());
        let valid_options = LoadOptions::default();
        let observation = crate::scene::Loader::new(valid_options.clone())
            .observe_path(&path)
            .unwrap();
        let snapshot =
            crate::scene::ObservedSceneSnapshot::from_observation(&observation, &valid_options)
                .unwrap()
                .unwrap();
        assert!(snapshot.digests.schema_bundle_sha256.is_none());
        assert_eq!(
            snapshot.identity.schema_bundle_sha256,
            valid_options.schema_bundle_sha256().unwrap()
        );
    }

    #[test]
    fn unreadable_chunk_does_not_disable_other_external_schemas() {
        use super::super::{SchemaLookupContext, SchemaRegistry, locator::SchemaPaths};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("chunks");
        std::fs::create_dir_all(root.join("Example")).unwrap();
        std::fs::create_dir(root.join("Example/Unreadable.yaml")).unwrap();
        std::fs::write(
            root.join("Example/Sample.yaml"),
            "schema_id: ExampleSchema\nform: Example\ntag: Sample\nfields: []\n",
        )
        .unwrap();
        let options = LoadOptions::default().with_chunk_schema_root(&root);
        let registry =
            SchemaRegistry::new(SchemaPaths::from_schema_inputs(&options.schema_inputs()));
        assert!(
            super::super::lookup::lookup_chunk_schema_with_context_and_registry(
                &registry,
                "Example",
                "Sample",
                SchemaLookupContext::default()
            )
            .is_some()
        );
        assert!(
            super::super::lookup::lookup_chunk_schema_with_context_and_registry(
                &registry,
                "Example",
                "Unreadable",
                SchemaLookupContext::default()
            )
            .is_none()
        );
    }

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
