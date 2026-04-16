use std::{path::PathBuf, sync::Arc};

use super::{SchemaRegistry, typeid_map::TypeIdTypeNameResolver};
use crate::scene::SceneToolError;

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
    pub(crate) fn from_inputs(inputs: &SchemaInputs<'_>) -> Result<Self, SceneToolError> {
        let registry = Arc::new(SchemaRegistry::from_schema_inputs(inputs));
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
