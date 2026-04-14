use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SchemaInputs<'a> {
    pub(crate) schema_root: Option<&'a PathBuf>,
    pub(crate) chunk_schema_root: Option<&'a PathBuf>,
    pub(crate) addattr_schema_path: Option<&'a PathBuf>,
    pub(crate) structural_attr_schema_path: Option<&'a PathBuf>,
    pub(crate) refedit_schema_path: Option<&'a PathBuf>,
    pub(crate) additional_node_info_paths: &'a [PathBuf],
}
