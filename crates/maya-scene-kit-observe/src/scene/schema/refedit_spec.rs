#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::scene) enum RecordDecodeMode {
    Marker,
    TripletInline,
    TripletPrefixed,
    CountedCStringArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::scene) enum RecordEmitKind {
    Op0,
    Op1,
    Op2,
    Op3,
    Op5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::scene) struct RefEditRecordSpec {
    pub(in crate::scene) opcode: u8,
    pub(in crate::scene) mode: RecordDecodeMode,
    pub(in crate::scene) emit: Option<RecordEmitKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scene) struct RefEditLayoutSpec {
    pub(in crate::scene) name: String,
    pub(in crate::scene) group_list_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scene) struct RefEditSchema {
    pub(in crate::scene) schema_id: String,
    pub(in crate::scene) layouts: Vec<RefEditLayoutSpec>,
    pub(in crate::scene) records: Vec<RefEditRecordSpec>,
}
