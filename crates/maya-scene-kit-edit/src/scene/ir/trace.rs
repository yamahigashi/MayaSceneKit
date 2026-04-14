#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChunkRef {
    pub(crate) form: String,
    pub(crate) tag: String,
    pub(crate) node_offset: usize,
    pub(crate) parent_tag: Option<String>,
    pub(crate) chunk_aux: Option<u32>,
    pub(crate) child_alignment: Option<usize>,
    pub(crate) child_header_size: Option<usize>,
    pub(crate) payload_size: usize,
}
