use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

use super::{
    ChunkSchema,
    addattr_tokens::AddAttrTokenRule,
    locator::SchemaPaths,
    node_semantics::{AngularAttrKind, NodeExecutionSemantics, ParsedNodeInfo},
    refedit_loader::RefEditSchema,
    structural_attr::StructuralAttrHandlerRule,
};

type SchemaByteCache = Mutex<BTreeMap<PathBuf, Result<Arc<[u8]>, String>>>;

type ChunkSchemaCache = Mutex<HashMap<(String, String), Option<Arc<ChunkSchema>>>>;
type NodeSemanticsMap = Arc<HashMap<String, HashMap<String, AngularAttrKind>>>;
type NodeSemanticsCache = Mutex<Option<NodeSemanticsMap>>;
type NodeExecutionSemanticsCache = Mutex<Option<Arc<NodeExecutionSemantics>>>;
type ParsedNodeInfoCache = Mutex<Option<Result<Arc<ParsedNodeInfo>, String>>>;

#[derive(Debug, Default)]
pub(crate) struct SchemaRegistryCaches {
    pub(in crate::scene) chunk_schemas: ChunkSchemaCache,
    pub(in crate::scene) addattr_tokens: Mutex<Option<Arc<HashMap<String, AddAttrTokenRule>>>>,
    pub(in crate::scene) parsed_node_info: ParsedNodeInfoCache,
    pub(in crate::scene) node_semantics: NodeSemanticsCache,
    pub(in crate::scene) node_execution_semantics: NodeExecutionSemanticsCache,
    pub(in crate::scene) structural_attrs: Mutex<Option<Arc<Vec<StructuralAttrHandlerRule>>>>,
    pub(in crate::scene) refedit_schema: Mutex<Option<Option<Arc<RefEditSchema>>>>,
}

#[derive(Debug)]
pub(crate) struct SchemaRegistry {
    paths: SchemaPaths,
    caches: SchemaRegistryCaches,
    inputs: OnceLock<Result<SchemaData, String>>,
    files: SchemaByteCache,
}

impl SchemaRegistry {
    pub(in crate::scene) fn new(paths: SchemaPaths) -> Self {
        Self {
            paths,
            inputs: OnceLock::new(),
            files: Mutex::new(BTreeMap::new()),
            caches: SchemaRegistryCaches::default(),
        }
    }
    pub(in crate::scene) fn paths(&self) -> &SchemaPaths {
        &self.paths
    }

    pub(crate) fn bytes(&self, path: &Path) -> Result<Arc<[u8]>, String> {
        self.files
            .lock()
            .expect("schema bytes lock poisoned")
            .entry(path.to_owned())
            .or_insert_with(|| {
                fs::read(path)
                    .map(Arc::from)
                    .map_err(|e| format!("{}: {e}", path.display()))
            })
            .clone()
    }

    fn inputs(&self) -> Result<&SchemaData, String> {
        self.inputs
            .get_or_init(|| SchemaData::load(&self.paths))
            .as_ref()
            .map_err(Clone::clone)
    }

    pub(crate) fn capture_inputs(&self) -> Result<(), String> {
        for (_, path) in &self.inputs()?.roles {
            // Cache read failures too; validators determine diagnostic ordering.
            let _ = self.bytes(path);
        }
        Ok(())
    }

    pub(crate) fn schema_bundle_sha256(&self) -> Result<String, String> {
        let inputs = self.inputs()?;
        let mut hasher = Sha256::new();
        for (role, path) in &inputs.roles {
            let bytes = self.bytes(path)?;
            hasher.update((role.len() as u64).to_le_bytes());
            hasher.update(role.as_bytes());
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub(crate) fn chunk_paths(&self) -> Result<&[PathBuf], String> {
        Ok(&self.inputs()?.chunk_paths)
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

#[derive(Debug)]
struct SchemaData {
    chunk_paths: Vec<PathBuf>,
    roles: Vec<(String, PathBuf)>,
}

impl SchemaData {
    fn load(paths: &SchemaPaths) -> Result<Self, String> {
        if let Some(error) = paths.resolution_error() {
            return Err(error.to_owned());
        }
        super::external::validate_chunk_schema_root(&paths.chunk_schema_root)?;
        let mut inputs = vec![
            ("addattr".to_owned(), paths.addattr_schema_file.clone()),
            ("node_info".to_owned(), paths.node_info_schema_file.clone()),
            ("refedit".to_owned(), paths.refedit_schema_file.clone()),
            (
                "structural_attr".to_owned(),
                paths.structural_attr_schema_file.clone(),
            ),
        ];
        let mut chunk_paths = Vec::new();
        let root = &paths.chunk_schema_root;
        for form in fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))? {
            let form = form.map_err(|e| format!("{}: {e}", root.display()))?.path();
            if !form.is_dir() {
                continue;
            }
            let Some(form_name) = form.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            for file in fs::read_dir(&form).map_err(|e| format!("{}: {e}", form.display()))? {
                let path = file.map_err(|e| format!("{}: {e}", form.display()))?.path();
                if path.extension().and_then(|v| v.to_str()) != Some("yaml") {
                    continue;
                }
                let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                let role = format!("chunk/{form_name}/{file_name}");
                inputs.push((role, path.clone()));
                chunk_paths.push(path);
            }
        }
        for (index, path) in paths.additional_node_info_files.iter().enumerate() {
            inputs.push((format!("additional_node_info/{index:020}"), path.clone()));
        }
        inputs.sort();
        chunk_paths.sort();
        Ok(Self {
            chunk_paths,
            roles: inputs,
        })
    }
}
