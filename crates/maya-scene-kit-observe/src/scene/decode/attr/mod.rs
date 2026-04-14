mod add_attr;
mod codecs;
mod payload;
mod values;

#[cfg(test)]
pub(crate) use self::add_attr::{
    decode_add_attr_header_flags, decode_add_attr_op_from_attr_chunk,
    parse_add_attr_numeric_tail_payload,
};
#[cfg(test)]
pub(crate) use self::values::{
    decode_attr_value_chunk_to_outcome, decode_attr_value_chunk_to_setattr,
};
pub(crate) use self::{
    payload::decode_attr_payload,
    values::{
        AttrDecodeOutcome, AttrValueHandlerId, attr_value_handler_id_from_schema_handler,
        decode_attr_definition_chunk_to_outcome_with_registry, decode_attr_value_from_handler,
        decode_attr_value_from_schema_fields, validate_attr_handler_payload_shape,
    },
};
