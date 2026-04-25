use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use once_cell::sync::Lazy;

use super::{
    ChunkSchema,
    addattr_tokens::AddAttrTokenRule,
    locator::SchemaPaths,
    node_semantics::{AngularAttrKind, NodeExecutionSemantics},
    refedit_loader::RefEditSchema,
    structural_attr::StructuralAttrHandlerRule,
};

type ChunkSchemaCache = Mutex<HashMap<(String, String), Option<Arc<ChunkSchema>>>>;
type NodeSemanticsMap = Arc<HashMap<String, HashMap<String, AngularAttrKind>>>;
type NodeSemanticsCache = Mutex<Option<NodeSemanticsMap>>;
type NodeExecutionSemanticsCache = Mutex<Option<Arc<NodeExecutionSemantics>>>;

#[derive(Debug, Default)]
pub(crate) struct SchemaRegistryCaches {
    pub(in crate::scene) chunk_schemas: ChunkSchemaCache,
    pub(in crate::scene) addattr_tokens: Mutex<Option<Arc<HashMap<String, AddAttrTokenRule>>>>,
    pub(in crate::scene) node_semantics: NodeSemanticsCache,
    pub(in crate::scene) node_execution_semantics: NodeExecutionSemanticsCache,
    pub(in crate::scene) structural_attrs: Mutex<Option<Arc<Vec<StructuralAttrHandlerRule>>>>,
    pub(in crate::scene) refedit_schema: Mutex<Option<Option<Arc<RefEditSchema>>>>,
}

#[derive(Debug)]
pub(crate) struct SchemaRegistry {
    paths: SchemaPaths,
    caches: SchemaRegistryCaches,
}

impl SchemaRegistry {
    pub(in crate::scene) fn new(paths: SchemaPaths) -> Self {
        Self {
            paths,
            caches: SchemaRegistryCaches::default(),
        }
    }
    pub(in crate::scene) fn paths(&self) -> &SchemaPaths {
        &self.paths
    }

    pub(crate) fn caches(&self) -> &SchemaRegistryCaches {
        &self.caches
    }
}

pub(crate) fn default_schema_registry() -> &'static SchemaRegistry {
    static DEFAULT: Lazy<SchemaRegistry> =
        Lazy::new(|| SchemaRegistry::new(SchemaPaths::from_defaults()));
    &DEFAULT
}
