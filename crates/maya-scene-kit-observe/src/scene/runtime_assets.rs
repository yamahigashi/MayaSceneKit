use std::sync::Arc;

use crate::scene::{
    SceneToolError,
    context::SchemaInputs,
    schema::{SchemaRegistry, typeid_map::TypeIdTypeNameResolver},
};

#[derive(Debug, Clone)]
pub(crate) struct RuntimeAssets {
    registry: Arc<SchemaRegistry>,
}

impl RuntimeAssets {
    pub(crate) fn from_schema_inputs(schema_inputs: &SchemaInputs<'_>) -> Self {
        Self {
            registry: Arc::new(SchemaRegistry::from_schema_inputs(schema_inputs)),
        }
    }

    pub(crate) fn registry(&self) -> Arc<SchemaRegistry> {
        Arc::clone(&self.registry)
    }

    pub(crate) fn validate_schema_inputs(&self) -> Result<(), SceneToolError> {
        let paths = self.registry.paths();
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

    pub(crate) fn build_typeid_typename_resolver(
        &self,
    ) -> Result<TypeIdTypeNameResolver, SceneToolError> {
        crate::scene::schema::typeid_map::build_typeid_typename_resolver_with_registry(
            self.registry.as_ref(),
        )
        .map_err(SceneToolError::Config)
    }
}
