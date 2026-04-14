use std::{borrow::Cow, sync::Arc};

use super::{ChunkSchema, SchemaField, SchemaFieldKind};

const SLCT_FIELDS: [SchemaField; 1] = [SchemaField {
    name: Cow::Borrowed("target"),
    kind: SchemaFieldKind::CString {
        allow_eof_termination: true,
    },
}];

const SLCT_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.slct.target.v1"),
    form: Cow::Borrowed("SLCT"),
    tag: Cow::Borrowed("SLCT"),
    handler: Some(Cow::Borrowed("slct.target")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&SLCT_FIELDS),
};

const CONS_CWFL_FIELDS: [SchemaField; 3] = [
    SchemaField {
        name: Cow::Borrowed("mode"),
        kind: SchemaFieldKind::U8,
    },
    SchemaField {
        name: Cow::Borrowed("src"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("dst"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: true,
        },
    },
];

const CONS_CWFL_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.cons.cwfl.v1"),
    form: Cow::Borrowed("CONS"),
    tag: Cow::Borrowed("CWFL"),
    handler: Some(Cow::Borrowed("cons.cwfl")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&CONS_CWFL_FIELDS),
};

const CONS_RELA_FIELDS: [SchemaField; 3] = [
    SchemaField {
        name: Cow::Borrowed("kind"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("head"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("tail"),
        kind: SchemaFieldKind::CStringListRest { min_items: 2 },
    },
];

const CONS_RELA_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.cons.rela.v1"),
    form: Cow::Borrowed("CONS"),
    tag: Cow::Borrowed("RELA"),
    handler: Some(Cow::Borrowed("cons.rela")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&CONS_RELA_FIELDS),
};

const ATTR_STR_FIELDS: [SchemaField; 3] = [
    SchemaField {
        name: Cow::Borrowed("attr_name"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("kind"),
        kind: SchemaFieldKind::U8,
    },
    SchemaField {
        name: Cow::Borrowed("value_raw"),
        kind: SchemaFieldKind::BytesRest { allow_empty: true },
    },
];

const ATTR_STR_ARRAY_FIELDS: [SchemaField; 4] = [
    SchemaField {
        name: Cow::Borrowed("attr_name"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("kind"),
        kind: SchemaFieldKind::U8,
    },
    SchemaField {
        name: Cow::Borrowed("declared_count"),
        kind: SchemaFieldKind::U32BE,
    },
    SchemaField {
        name: Cow::Borrowed("values"),
        kind: SchemaFieldKind::CStringListRest { min_items: 0 },
    },
];

const ATTR_I32_ARRAY_FIELDS: [SchemaField; 3] = [
    SchemaField {
        name: Cow::Borrowed("attr_name"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("kind"),
        kind: SchemaFieldKind::U8,
    },
    SchemaField {
        name: Cow::Borrowed("value_raw"),
        kind: SchemaFieldKind::BytesRest { allow_empty: true },
    },
];

const REFE_ATTR_PAYLOAD_FIELDS: [SchemaField; 3] = [
    SchemaField {
        name: Cow::Borrowed("attr_name"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("kind"),
        kind: SchemaFieldKind::U8,
    },
    SchemaField {
        name: Cow::Borrowed("value_raw"),
        kind: SchemaFieldKind::BytesRest { allow_empty: true },
    },
];

const FREF_REFERENCE_FILE_FIELDS: [SchemaField; 4] = [
    SchemaField {
        name: Cow::Borrowed("path"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("namespace"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("reference_node"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("tail_raw"),
        kind: SchemaFieldKind::BytesRest { allow_empty: true },
    },
];

const RTFT_ATTR_PAYLOAD_FIELDS: [SchemaField; 3] = [
    SchemaField {
        name: Cow::Borrowed("attr_name"),
        kind: SchemaFieldKind::CString {
            allow_eof_termination: false,
        },
    },
    SchemaField {
        name: Cow::Borrowed("kind"),
        kind: SchemaFieldKind::U8,
    },
    SchemaField {
        name: Cow::Borrowed("value_raw"),
        kind: SchemaFieldKind::BytesRest { allow_empty: true },
    },
];

const ATTR_STR_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.str.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("STR "),
    handler: Some(Cow::Borrowed("attr.string")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_STR_FIELDS),
};

const ATTR_STR_ARRAY_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.str_array.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("STR#"),
    handler: Some(Cow::Borrowed("attr.string_array")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_STR_ARRAY_FIELDS),
};

const ATTR_I32_ARRAY_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.i32_array.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("I32#"),
    handler: Some(Cow::Borrowed("attr.int32_array")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_FLGS_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.flgs.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("FLGS"),
    handler: Some(Cow::Borrowed("attr.flgs")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_DBLE_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.dble.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("DBLE"),
    handler: Some(Cow::Borrowed("attr.dble")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_DBL2_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.dbl2.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("DBL2"),
    handler: Some(Cow::Borrowed("attr.dbl2")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_DBL3_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.dbl3.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("DBL3"),
    handler: Some(Cow::Borrowed("attr.dbl3")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_FLT2_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.flt2.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("FLT2"),
    handler: Some(Cow::Borrowed("attr.flt2")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_FLT3_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.flt3.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("FLT3"),
    handler: Some(Cow::Borrowed("attr.flt3")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_MATR_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.matr.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("MATR"),
    handler: Some(Cow::Borrowed("attr.matr")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_CMPD_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.cmpd.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("CMPD"),
    handler: Some(Cow::Borrowed("attr.cmpd")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const ATTR_CMP_LIST_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.attr.cmp_list.v1"),
    form: Cow::Borrowed("ATTR"),
    tag: Cow::Borrowed("CMP#"),
    handler: Some(Cow::Borrowed("attr.cmp_list")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&ATTR_I32_ARRAY_FIELDS),
};

const REFE_ATTR_PAYLOAD_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.refe.attr_payload.v1"),
    form: Cow::Borrowed("REFE"),
    tag: Cow::Borrowed("REFE"),
    handler: Some(Cow::Borrowed("refe.attr_payload")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&REFE_ATTR_PAYLOAD_FIELDS),
};

const FREF_REFERENCE_FILE_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.fref.reference_file.v1"),
    form: Cow::Borrowed("FREF"),
    tag: Cow::Borrowed("FREF"),
    handler: Some(Cow::Borrowed("fref.reference_file")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&FREF_REFERENCE_FILE_FIELDS),
};

const RTFT_ATTR_PAYLOAD_SCHEMA: ChunkSchema = ChunkSchema {
    schema_id: Cow::Borrowed("schema.rtft.attr_payload.v1"),
    form: Cow::Borrowed("RTFT"),
    tag: Cow::Borrowed("STR "),
    handler: Some(Cow::Borrowed("rtft.attr_payload")),
    priority: 0,
    when: None,
    fields: Cow::Borrowed(&RTFT_ATTR_PAYLOAD_FIELDS),
};

pub(super) fn lookup_builtin_schema(form: &str, tag: &str) -> Option<Arc<ChunkSchema>> {
    let schema = match (form, tag) {
        ("SLCT", "SLCT") => &SLCT_SCHEMA,
        ("CONS", "CWFL") => &CONS_CWFL_SCHEMA,
        ("CONS", "RELA") => &CONS_RELA_SCHEMA,
        ("ATTR", "STR ") => &ATTR_STR_SCHEMA,
        ("ATTR", "STR#") => &ATTR_STR_ARRAY_SCHEMA,
        ("ATTR", "I32#") => &ATTR_I32_ARRAY_SCHEMA,
        ("ATTR", "FLGS") => &ATTR_FLGS_SCHEMA,
        ("ATTR", "DBLE") => &ATTR_DBLE_SCHEMA,
        ("ATTR", "DBL2") => &ATTR_DBL2_SCHEMA,
        ("ATTR", "DBL3") => &ATTR_DBL3_SCHEMA,
        ("ATTR", "FLT2") => &ATTR_FLT2_SCHEMA,
        ("ATTR", "FLT3") => &ATTR_FLT3_SCHEMA,
        ("ATTR", "MATR") => &ATTR_MATR_SCHEMA,
        ("ATTR", "CMPD") => &ATTR_CMPD_SCHEMA,
        ("ATTR", "CMP#") => &ATTR_CMP_LIST_SCHEMA,
        ("REFE", "REFE") => &REFE_ATTR_PAYLOAD_SCHEMA,
        ("FREF", "FREF") => &FREF_REFERENCE_FILE_SCHEMA,
        ("RTFT", "STR ") => &RTFT_ATTR_PAYLOAD_SCHEMA,
        _ => return None,
    };
    Some(Arc::new(schema.clone()))
}
