#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Exact,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkTrace {
    pub form: String,
    pub tag: String,
    pub node_offset: usize,
    pub chunk_aux: Option<u32>,
    pub child_alignment: Option<usize>,
    pub child_header_size: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    pub form: String,
    pub tag: String,
    pub node_offset: usize,
    pub parent_tag: Option<String>,
    pub chunk_aux: Option<u32>,
    pub child_alignment: Option<usize>,
    pub child_header_size: Option<usize>,
    pub payload_size: usize,
}
