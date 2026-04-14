pub(crate) mod attr;
pub(crate) mod dispatcher;
pub(crate) mod families;

#[cfg(test)]
use self::attr::{decode_add_attr_header_flags, parse_add_attr_numeric_tail_payload};
#[cfg(test)]
use super::ir::AddAttrOp;
use super::ir::NumericValue;

pub(super) fn numeric_f64(value: f64) -> NumericValue {
    NumericValue::from_f64(value)
}

pub(super) fn parse_numeric_literal(value: &str) -> Option<NumericValue> {
    value.trim().parse::<f64>().ok().map(numeric_f64)
}

#[cfg(test)]
pub(super) fn decode_add_attr_op_from_attr_chunk(payload: &[u8]) -> Option<AddAttrOp> {
    self::attr::decode_add_attr_op_from_attr_chunk(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scene::{
        decode::attr::{
            decode_attr_value_chunk_to_setattr, decode_attr_value_from_handler,
            validate_attr_handler_payload_shape,
        },
        ir::{AddAttrValueSpec, FlagState, SetAttrValue, TimeValuePair},
    };

    fn make_attr_value_payload(attr_name: &str, kind: u8, value_raw: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(attr_name.len() + 2 + value_raw.len());
        payload.extend_from_slice(attr_name.as_bytes());
        payload.push(0);
        payload.push(kind);
        payload.extend_from_slice(value_raw);
        payload
    }

    #[test]
    fn decode_add_attr_adbl_payload() {
        let payload: Vec<u8> = vec![
            0x61, 0x44, 0x42, 0x4C, 0x00, 0xB8, 0x40, 0x4A, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, b'n', b'e', b'c', b'k', b'_', b'C', b'0', b'_', b'h', b'e', b'a', b'd',
            b'_', b'j', b'n', b't', b'W', b'0', 0x00, b'w', b'0', 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x44, 0x42, 0x4C, 0x45, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0,
        ];
        let op = decode_add_attr_op_from_attr_chunk(&payload).unwrap();
        assert_eq!(op.short_name, "w0");
        assert_eq!(op.long_name, "neck_C0_head_jntW0");
        assert_eq!(op.type_token, "aDBL");
        assert_eq!(op.header_raw, [0xB8, 0x40, 0x4A, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(op.disconnect_behaviour, Some(0));
        assert_eq!(op.storable, FlagState::True);
        assert_eq!(op.readable, FlagState::True);
        assert_eq!(op.writable, FlagState::True);
        assert_eq!(op.cached_internally, FlagState::True);
        assert_eq!(op.keyable, FlagState::True);
        assert_eq!(op.hidden, FlagState::False);
        assert_eq!(op.multi, FlagState::False);
        assert_eq!(op.index_matters, FlagState::Unknown);
        assert_eq!(op.internal_set, FlagState::False);
        assert_eq!(op.enum_names, None);
        assert_eq!(op.min_value, Some(NumericValue::from_f64(0.0)));
        assert_eq!(op.max_value, None);
        let default = op.default_value.expect("default value");
        assert_eq!(default.value, NumericValue::from_f64(1.0));
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("double".to_string())
        );
    }

    #[test]
    fn decode_add_attr_unknown_token_is_preserved() {
        let payload: Vec<u8> = vec![
            b'a', b'X', b'Y', b'Z', 0, 0xB8, 0x40, 0x4A, 0, 0, 0, 1, 0, 0, 0, 0, b'm', b'y', b'A',
            b't', b't', b'r', 0, b'm', b'a', 0,
        ];
        let op = decode_add_attr_op_from_attr_chunk(&payload).unwrap();
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::UnknownToken {
                token: "aXYZ".to_string()
            }
        );
        assert_eq!(op.long_name, "myAttr");
        assert_eq!(op.short_name, "ma");
    }

    #[test]
    fn decode_add_attr_allows_empty_short_name_and_keeps_flags() {
        let payload: Vec<u8> = vec![
            b'a', b'D', b'B', b'L', 0, 0xD8, 0x60, 0x41, 0, 0, 0, 1, 0, 0, 0, 0, b'm', b'y', b'A',
            b't', b't', b'r', 0, 0,
        ];
        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode addAttr");
        assert_eq!(op.long_name, "myAttr");
        assert_eq!(op.short_name, "myAttr");
        assert_eq!(op.storable, FlagState::False);
        assert_eq!(op.hidden, FlagState::True);
        assert_eq!(op.keyable, FlagState::True);
        assert_eq!(op.multi, FlagState::True);
        assert_eq!(op.index_matters, FlagState::True);
        assert_eq!(op.cached_internally, FlagState::True);
    }

    #[test]
    fn decode_add_attr_tail_recovers_nice_name_min_max_and_explicit_default() {
        let mut payload: Vec<u8> = vec![
            b'a', b'D', b'B', b'L', 0, 0xF8, 0xC0, 0x4E, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"chain_sinewave_wavelength_y\0");
        payload.extend_from_slice(b"chain_sinewave_wavelength_y\0");
        payload.extend_from_slice(b"SineWave length Y\0");
        payload.extend_from_slice(&[0u8; 12]);
        payload.extend_from_slice(&1000.0f64.to_be_bytes());
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&100.0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode addAttr");
        assert_eq!(op.disconnect_behaviour, Some(2));
        assert_eq!(op.nice_name.as_deref(), Some("SineWave length Y"));
        assert_eq!(op.min_value, Some(NumericValue::from_f64(0.0)));
        assert_eq!(op.max_value, Some(NumericValue::from_f64(1000.0)));
        let default = op.default_value.expect("default value");
        assert_eq!(default.value, NumericValue::from_f64(100.0));
    }

    #[test]
    fn decode_add_attr_bool_tail_recovers_non_zero_default() {
        let mut payload: Vec<u8> = vec![
            b'a', b'B', b'O', b'L', 0, 0xF8, 0x40, 0x4E, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"jnt_vis\0");
        payload.extend_from_slice(b"jnt_vis\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0.0f64.to_be_bytes());
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&1.0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode addAttr");
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("bool".to_string())
        );
        assert_eq!(op.min_value, Some(NumericValue::from_f64(0.0)));
        assert_eq!(op.max_value, Some(NumericValue::from_f64(1.0)));
        let default = op.default_value.expect("default value");
        assert_eq!(default.value, NumericValue::from_f64(1.0));
    }

    #[test]
    fn decode_add_attr_range_without_non_zero_default_does_not_emit_default_value() {
        let mut payload: Vec<u8> = vec![
            b'a', b'D', b'B', b'L', 0, 0xF8, 0x40, 0x4E, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"Pin\0");
        payload.extend_from_slice(b"Pin\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0.0f64.to_be_bytes());
        payload.extend_from_slice(&1.0f64.to_be_bytes());
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0.0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode addAttr");
        assert_eq!(op.min_value, Some(NumericValue::from_f64(0.0)));
        assert_eq!(op.max_value, Some(NumericValue::from_f64(1.0)));
        assert_eq!(op.default_value, None);
    }

    #[test]
    fn decode_add_attr_rejects_shifted_name_layout_without_scan() {
        let mut payload: Vec<u8> = vec![
            b'a', b'D', b'B', b'L', 0, 0xD8, 0x60, 0x41, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        // Legacy heuristic decoder accepted this by scanning forward for strings.
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        payload.extend_from_slice(b"myAttr\0myAttr\0");
        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decoded without scanning");
        assert_ne!(op.long_name, "myAttr");
    }

    #[test]
    fn parse_add_attr_numeric_tail_payload_reads_min_and_default() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&0u32.to_be_bytes());
        tail.extend_from_slice(&0.0f64.to_be_bytes());
        tail.extend_from_slice(b"DBLE");
        tail.extend_from_slice(&1.0f64.to_be_bytes());
        let parsed = parse_add_attr_numeric_tail_payload(&tail).expect("tail metadata");
        assert_eq!(parsed.0, Some(0.0));
        assert_eq!(parsed.1, None);
        assert_eq!(parsed.2, 1.0);
    }

    #[test]
    fn parse_add_attr_numeric_tail_payload_reads_min_max_and_default() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&0u32.to_be_bytes());
        tail.extend_from_slice(&0.0f64.to_be_bytes());
        tail.extend_from_slice(&1000.0f64.to_be_bytes());
        tail.extend_from_slice(b"DBLE");
        tail.extend_from_slice(&100.0f64.to_be_bytes());
        let parsed = parse_add_attr_numeric_tail_payload(&tail).expect("tail metadata");
        assert_eq!(parsed.0, Some(0.0));
        assert_eq!(parsed.1, Some(1000.0));
        assert_eq!(parsed.2, 100.0);
    }

    #[test]
    fn parse_add_attr_numeric_tail_payload_rejects_nonzero_prefix_word() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&1u32.to_be_bytes());
        tail.extend_from_slice(&0.0f64.to_be_bytes());
        tail.extend_from_slice(b"DBLE");
        tail.extend_from_slice(&1.0f64.to_be_bytes());
        assert!(parse_add_attr_numeric_tail_payload(&tail).is_none());
    }

    #[test]
    fn decode_add_attr_disconnect_behaviour_from_header_bits() {
        let mut payload: Vec<u8> = vec![
            b'a', b'D', b'B', b'L', 0, 0xF8, 0x40, 0x4A, 0, 0, 0, 1, 0, 0, 0, 0, b'm', b'y', b'A',
            b't', b't', b'r', 0, b'm', b'a', 0,
        ];
        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode dcb=2");
        assert_eq!(op.disconnect_behaviour, Some(2));

        payload[5] = 0xB8;
        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode dcb=0");
        assert_eq!(op.disconnect_behaviour, Some(0));

        payload[5] = 0x78;
        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode dcb=1");
        assert_eq!(op.disconnect_behaviour, Some(1));
    }

    #[test]
    fn decode_add_attr_alnr_proxy_layout_byte_sets_used_as_proxy() {
        let mut payload: Vec<u8> = vec![
            b'a', b'L', b'N', b'R', 1, 0xF8, 0x40, 0x48, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"someProxyAttr\0");
        payload.extend_from_slice(b"someProxyAttr\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode aLNR proxy");
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("doubleLinear".to_string())
        );
        assert!(op.used_as_proxy);
        assert_eq!(op.default_value, None);
    }

    #[test]
    fn decode_add_attr_aagl_proxy_layout_byte_sets_used_as_proxy() {
        let mut payload: Vec<u8> = vec![
            b'a', b'A', b'G', b'L', 1, 0xF8, 0x40, 0x48, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"proxyAngle\0");
        payload.extend_from_slice(b"proxyAngle\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode aAGL proxy");
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("doubleAngle".to_string())
        );
        assert!(op.used_as_proxy);
    }

    #[test]
    fn decode_add_attr_atim_proxy_layout_decodes_time_attr() {
        let mut payload: Vec<u8> = vec![
            b'a', b'T', b'I', b'M', 1, 0xF8, 0x40, 0x48, 0, 0, 0, 2, b'a', b'T', b'I', b'M',
        ];
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(b"proxyMisc01\0");
        payload.extend_from_slice(b"proxyMisc01\0");
        payload.extend_from_slice(&[0u8; 5]);
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode aTIM proxy");
        assert_eq!(op.long_name, "proxyMisc01");
        assert_eq!(op.short_name, "proxyMisc01");
        assert!(op.used_as_proxy);
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("time".to_string())
        );
    }

    #[test]
    fn decode_add_attr_atyp_marker_decodes_matrix_data_type() {
        let mut payload: Vec<u8> = vec![
            b'a', b'T', b'Y', b'P', 1, 0xF8, 0x40, 0x40, 0, 0, 0, 1, b'M', b'A', b'T', b'R',
        ];
        payload.extend_from_slice(b"proxyMisc02\0");
        payload.extend_from_slice(b"proxyMisc02\0");
        payload.extend_from_slice(&[0u8; 5]);

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode aTYP MATR");
        assert_eq!(op.long_name, "proxyMisc02");
        assert_eq!(op.short_name, "proxyMisc02");
        assert!(op.used_as_proxy);
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::DataType("matrix".to_string())
        );
    }

    #[test]
    fn decode_add_attr_afl3_layout_recovers_prefixed_name_and_children() {
        let mut payload: Vec<u8> = vec![
            b'a', b'F', b'L', b'3', 1, 0xF8, 0x44, 0x50, 0, 0, 0, 3, 0, 0, 0, 4,
        ];
        payload.extend_from_slice(b"FLT3DBL3SRT3LNG3proxyComplex00\0");
        payload.extend_from_slice(b"proxyComplex00\0");
        payload.extend_from_slice(&[0u8; 5]);

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode aFL3 proxy");
        assert_eq!(op.long_name, "proxyComplex00");
        assert_eq!(op.short_name, "proxyComplex00");
        assert_eq!(op.number_of_children, Some(3));
        assert!(op.used_as_proxy);
        assert!(op.used_as_color);
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("float3".to_string())
        );
    }

    #[test]
    fn decode_add_attr_adb3_layout_recovers_prefixed_name_and_children() {
        let mut payload: Vec<u8> = vec![
            b'a', b'D', b'B', b'3', 1, 0xF8, 0x40, 0x50, 0, 0, 0, 3, 0, 0, 0, 4,
        ];
        payload.extend_from_slice(b"DBL3FLT3SRT3LNG3proxyComplex01\0");
        payload.extend_from_slice(b"proxyComplex01\0");
        payload.extend_from_slice(&[0u8; 5]);

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode aDB3 proxy");
        assert_eq!(op.long_name, "proxyComplex01");
        assert_eq!(op.short_name, "proxyComplex01");
        assert_eq!(op.number_of_children, Some(3));
        assert!(op.used_as_proxy);
        assert!(!op.used_as_color);
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("double3".to_string())
        );
    }

    #[test]
    fn decode_add_attr_afl2_layout_recovers_prefixed_name_and_children() {
        let mut payload: Vec<u8> = vec![
            b'a', b'F', b'L', b'2', 1, 0xF8, 0x40, 0x50, 0, 0, 0, 2, 0, 0, 0, 4,
        ];
        payload.extend_from_slice(b"FLT2DBL2LNG2SRT2proxyExtra10\0");
        payload.extend_from_slice(b"proxyExtra10\0");
        payload.extend_from_slice(&[0u8; 5]);

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode aFL2 proxy");
        assert_eq!(op.long_name, "proxyExtra10");
        assert_eq!(op.short_name, "proxyExtra10");
        assert_eq!(op.number_of_children, Some(2));
        assert!(op.used_as_proxy);
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("float2".to_string())
        );
    }

    #[test]
    fn decode_add_attr_child_tail_restores_parent_instead_of_nice_name() {
        let mut payload: Vec<u8> = vec![
            b'a', b'D', b'B', b'L', 0, 0xF8, 0x00, 0x68, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"flagCompA\0");
        payload.extend_from_slice(b"fcpa\0");
        payload.extend_from_slice(b"flagComp\0");
        payload.extend_from_slice(&[0u8; 5]);
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode child parent");
        assert_eq!(op.parent.as_deref(), Some("flagComp"));
        assert_eq!(op.nice_name, None);
        assert_eq!(op.default_value, None);
    }

    #[test]
    fn decode_add_attr_enum_tail_does_not_promote_enum_names_to_nice_name() {
        let mut payload: Vec<u8> = vec![
            b'a', b'E', b'N', b'M', 1, 0xF8, 0xC2, 0x4E, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"proxyEnum\0");
        payload.extend_from_slice(b"proxyEnum\0");
        payload.extend_from_slice(b"A:B:C\0");
        payload.extend_from_slice(&[0u8; 8]);
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode enum proxy");
        assert_eq!(op.nice_name, None);
        assert_eq!(op.enum_names.as_deref(), Some("A:B:C"));
        assert!(op.used_as_proxy);
    }

    #[test]
    fn decode_add_attr_enum_tail_recovers_min_max_and_skips_default_zero() {
        let mut payload: Vec<u8> = vec![
            b'a', b'E', b'N', b'M', 1, 0xF8, 0x42, 0x4E, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"proxyExtra05\0");
        payload.extend_from_slice(b"proxyExtra05\0");
        payload.extend_from_slice(b"A:B:C\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0f64.to_be_bytes());
        payload.extend_from_slice(&2f64.to_be_bytes());
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode enum range");
        assert_eq!(op.enum_names.as_deref(), Some("A:B:C"));
        assert_eq!(op.min_value, Some(NumericValue::from_f64(0.0)));
        assert_eq!(op.max_value, Some(NumericValue::from_f64(2.0)));
        assert_eq!(op.default_value, None);
    }

    #[test]
    fn decode_add_attr_asi1_soft_range_from_tail() {
        let mut payload: Vec<u8> = vec![
            b'a', b'S', b'I', b'1', 0, 0xB8, 0x40, 0xCA, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"filmboxTypeID\0");
        payload.extend_from_slice(b"filmboxTypeID\0");
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&5.0f64.to_be_bytes());
        payload.extend_from_slice(&5.0f64.to_be_bytes());
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).unwrap();
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("short".to_string())
        );
        assert_eq!(op.soft_min_value, Some(NumericValue::from_f64(5.0)));
        assert_eq!(op.soft_max_value, Some(NumericValue::from_f64(5.0)));
        assert_eq!(op.internal_set, FlagState::True);
    }

    #[test]
    fn decode_add_attr_asi1_parent_tail_does_not_decode_soft_range() {
        let mut payload: Vec<u8> = vec![
            b'a', b'S', b'I', b'1', 1, 0xF8, 0x00, 0x68, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"proxyComplex03srcShort3X\0");
        payload.extend_from_slice(b"proxyComplex03ss3x\0");
        payload.extend_from_slice(b"proxyComplex03\0");
        payload.extend_from_slice(&[0u8; 5]);
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("decode aSI1 child");
        assert_eq!(op.parent.as_deref(), Some("proxyComplex03"));
        assert_eq!(op.soft_min_value, None);
        assert_eq!(op.soft_max_value, None);
    }

    #[test]
    fn decode_add_attr_aenm_enum_names_from_tail() {
        let mut payload: Vec<u8> = vec![
            b'a', b'E', b'N', b'M', 0, 0xF8, 0xC2, 0x4E, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(b"control_control\0");
        payload.extend_from_slice(b"control_control\0");
        payload.extend_from_slice(b"__________\0");
        payload.extend_from_slice(b"control\0");
        payload.extend_from_slice(&[0u8; 8]);
        payload.extend_from_slice(b"DBLE");
        payload.extend_from_slice(&0f64.to_be_bytes());

        let op = decode_add_attr_op_from_attr_chunk(&payload).expect("aENM decode");
        assert_eq!(
            op.value_spec,
            AddAttrValueSpec::AttrType("enum".to_string())
        );
        assert_eq!(op.enum_names.as_deref(), Some("__________:control"));
    }

    #[test]
    fn decode_add_attr_header_flags_hidden_keyable_and_multi_bits() {
        let flags = decode_add_attr_header_flags(&[0xF8, 0x20, 0x41, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert!(flags.storable);
        assert!(flags.readable);
        assert!(flags.writable);
        assert!(flags.cached_internally);
        assert!(!flags.used_as_color);
        assert!(!flags.has_parent);
        assert!(flags.hidden);
        assert!(!flags.keyable);
        assert!(flags.multi);
        assert!(flags.index_matters);
        assert!(!flags.internal_set);
    }

    #[test]
    fn decode_add_attr_header_flags_index_matters_false_marker() {
        let flags = decode_add_attr_header_flags(&[0xF0, 0x01, 0x41, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert!(!flags.readable);
        assert!(flags.multi);
        assert!(!flags.index_matters);
    }

    #[test]
    fn decode_add_attr_header_flags_used_as_color_and_parent_marker() {
        let flags = decode_add_attr_header_flags(&[0xF8, 0x44, 0x68, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert!(flags.used_as_color);
        assert!(flags.has_parent);
    }

    #[test]
    fn decode_attr_value_dispatches_flgs_handler() {
        let payload = make_attr_value_payload("weights", 0x08, &3u32.to_be_bytes());
        let op = decode_attr_value_chunk_to_setattr("FLGS", &payload).unwrap();
        assert_eq!(op.attr_name_or_path, ".weights");
        assert_eq!(op.array_size, Some(3));
        assert_eq!(op.lock, None);
        assert_eq!(op.keyable, None);
        assert_eq!(op.value, SetAttrValue::None);
    }

    #[test]
    fn decode_attr_value_flgs_kind_25_sets_lock_on() {
        let payload = make_attr_value_payload("tx", 0x25, &[]);
        let op = decode_attr_value_chunk_to_setattr("FLGS", &payload).unwrap();
        assert_eq!(op.attr_name_or_path, ".tx");
        assert_eq!(op.lock, Some(true));
        assert_eq!(op.keyable, None);
        assert_eq!(op.value, SetAttrValue::None);
    }

    #[test]
    fn decode_attr_value_string_kind_21_sets_lock_on() {
        let payload = make_attr_value_payload("customTitleName", 0x21, b"Earth\0");
        let op = decode_attr_value_chunk_to_setattr("STR ", &payload).unwrap();
        assert_eq!(op.attr_name_or_path, ".customTitleName");
        assert_eq!(op.lock, Some(true));
        assert_eq!(op.keyable, None);
        assert_eq!(op.value, SetAttrValue::String("Earth".to_string()));
    }

    #[test]
    fn decode_attr_value_dispatches_string_array_handler() {
        let mut value_raw = Vec::new();
        value_raw.extend_from_slice(&2u32.to_be_bytes());
        value_raw.extend_from_slice(b"left\0right\0");
        let payload = make_attr_value_payload("labels", 0x00, &value_raw);
        let op = decode_attr_value_chunk_to_setattr("STR#", &payload).unwrap();
        assert_eq!(op.attr_name_or_path, ".labels");
        assert_eq!(
            op.value,
            SetAttrValue::StringArray {
                declared_count: 2,
                values: vec!["left".to_string(), "right".to_string()],
            }
        );
    }

    #[test]
    fn decode_attr_value_string_array_preserves_empty_entries() {
        let mut value_raw = Vec::new();
        value_raw.extend_from_slice(&4u32.to_be_bytes());
        value_raw.extend_from_slice(b"left\0\0right\0\0");
        let payload = make_attr_value_payload("labels", 0x00, &value_raw);
        let op = decode_attr_value_chunk_to_setattr("STR#", &payload).unwrap();
        assert_eq!(op.attr_name_or_path, ".labels");
        assert_eq!(
            op.value,
            SetAttrValue::StringArray {
                declared_count: 4,
                values: vec![
                    "left".to_string(),
                    "".to_string(),
                    "right".to_string(),
                    "".to_string(),
                ],
            }
        );
    }

    #[test]
    fn decode_attr_value_dispatches_refe_bridge_to_setattr_none() {
        let payload = make_attr_value_payload("ed", 0x00, &[]);
        assert_eq!(decode_attr_value_chunk_to_setattr("REFE", &payload), None);
    }

    #[test]
    fn decode_attr_value_cmpd_kind_28_decodes_array_size() {
        let payload = make_attr_value_payload("lw", 0x28, &4u32.to_be_bytes());
        let op = decode_attr_value_chunk_to_setattr("CMPD", &payload).unwrap();
        assert_eq!(op.attr_name_or_path, ".lw");
        assert_eq!(op.array_size, Some(4));
        assert_eq!(op.value, SetAttrValue::None);
    }

    #[test]
    fn decode_attr_value_cmpd_time_value_pair() {
        let mut value_raw = Vec::new();
        value_raw.extend_from_slice(&(-11_760_000i64).to_be_bytes());
        value_raw.extend_from_slice(&1.0f64.to_be_bytes());
        let payload = make_attr_value_payload("ktv[0]", 0x20, &value_raw);
        let op = decode_attr_value_chunk_to_setattr("CMPD", &payload).unwrap();
        assert_eq!(op.attr_name_or_path, ".ktv[0]");
        assert_eq!(
            op.value,
            SetAttrValue::TimeValuePairs(vec![TimeValuePair {
                time_ticks: -11_760_000,
                value: NumericValue::from_f64(1.0),
            }])
        );
    }

    #[test]
    fn decode_attr_value_from_handler_decodes_double_scalar() {
        let value_raw = 1.0f64.to_be_bytes().to_vec();
        let op = decode_attr_value_from_handler(
            crate::scene::decode::attr::AttrValueHandlerId::Double,
            "foo",
            0x00,
            &value_raw,
        )
        .unwrap();
        assert_eq!(op.attr_name_or_path, ".foo");
        assert_eq!(op.value, SetAttrValue::Scalar(NumericValue::from_f64(1.0)));
    }

    #[test]
    fn decode_attr_value_from_handler_decodes_matrix_with_variant_padding() {
        let marker = f64::from_bits(0x00000000e7010000);
        let matrix = [
            1.0, 0.0, 0.0, 0.0, //
            0.0, 1.0, 0.0, 0.0, //
            0.0, 0.0, 1.0, 0.0, //
            0.5, 0.0, 0.8, 1.0,
        ];
        let mut words = vec![0.0, marker, 0.0, 0.0, 0.0];
        words.extend_from_slice(&matrix);
        words.extend_from_slice(&[0.0, marker, 0.0]);
        let mut value_raw = Vec::with_capacity(words.len() * 8);
        for word in words {
            value_raw.extend_from_slice(&word.to_bits().to_be_bytes());
        }
        let op = decode_attr_value_from_handler(
            crate::scene::decode::attr::AttrValueHandlerId::Typed(
                crate::typed_value_semantics::TypedValueKind::Matrix,
            ),
            "xm[0]",
            0x20,
            &value_raw,
        )
        .expect("matrix variant decode");
        assert_eq!(op.attr_name_or_path, ".xm[0]");
        let SetAttrValue::TypedNumbers { value_type, values } = op.value else {
            panic!("expected typed matrix values");
        };
        assert_eq!(value_type, "matrix");
        assert_eq!(values.len(), 16);
        assert_eq!(
            values,
            matrix
                .iter()
                .copied()
                .map(NumericValue::from_f64)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn decode_attr_value_from_handler_decodes_nurbs_curve_payload() {
        let mut value_raw = Vec::new();
        value_raw.extend_from_slice(&1u32.to_be_bytes()); // degree
        value_raw.extend_from_slice(&3u32.to_be_bytes()); // spans
        value_raw.extend_from_slice(&0u32.to_be_bytes()); // form
        value_raw.extend_from_slice(&0u32.to_be_bytes()); // not rational
        value_raw.push(3u8); // dimension
        value_raw.extend_from_slice(&4u32.to_be_bytes()); // knot count
        for knot in [0.0f64, 1.0, 2.0, 3.0] {
            value_raw.extend_from_slice(&knot.to_be_bytes());
        }
        value_raw.extend_from_slice(&4u32.to_be_bytes()); // cv count
        let cvs = [
            [0.0f64, 0.0, 0.0],
            [2.0f64, 0.0, 0.0],
            [2.0f64, 1.5, 0.0],
            [0.0f64, 1.5, 0.0],
        ];
        for cv in cvs {
            for value in cv {
                value_raw.extend_from_slice(&value.to_be_bytes());
            }
        }
        let op = decode_attr_value_from_handler(
            crate::scene::decode::attr::AttrValueHandlerId::Typed(
                crate::typed_value_semantics::TypedValueKind::NurbsCurve,
            ),
            "cc",
            0x20,
            &value_raw,
        )
        .expect("nurbs curve decode");
        assert_eq!(op.attr_name_or_path, ".cc");
        let SetAttrValue::NurbsCurve {
            degree,
            spans,
            form,
            is_rational,
            dimension,
            knots,
            cvs,
        } = op.value
        else {
            panic!("expected nurbs curve value");
        };
        assert_eq!(degree, 1);
        assert_eq!(spans, 3);
        assert_eq!(form, 0);
        assert!(!is_rational);
        assert_eq!(dimension, 3);
        assert_eq!(
            knots,
            vec![
                NumericValue::from_f64(0.0),
                NumericValue::from_f64(1.0),
                NumericValue::from_f64(2.0),
                NumericValue::from_f64(3.0),
            ]
        );
        assert_eq!(cvs.len(), 4);
        assert_eq!(
            cvs[2],
            vec![
                NumericValue::from_f64(2.0),
                NumericValue::from_f64(1.5),
                NumericValue::from_f64(0.0),
            ]
        );
    }

    #[test]
    fn validate_attr_handler_payload_shape_for_nurbs_curve() {
        let mut value_raw = Vec::new();
        value_raw.extend_from_slice(&1u32.to_be_bytes()); // degree
        value_raw.extend_from_slice(&3u32.to_be_bytes()); // spans
        value_raw.extend_from_slice(&0u32.to_be_bytes()); // form
        value_raw.extend_from_slice(&0u32.to_be_bytes()); // not rational
        value_raw.push(3u8); // dimension
        value_raw.extend_from_slice(&4u32.to_be_bytes()); // knot count
        for knot in [0.0f64, 1.0, 2.0, 3.0] {
            value_raw.extend_from_slice(&knot.to_be_bytes());
        }
        value_raw.extend_from_slice(&1u32.to_be_bytes()); // cv count
        for value in [0.0f64, 0.0, 0.0] {
            value_raw.extend_from_slice(&value.to_be_bytes());
        }
        assert!(
            validate_attr_handler_payload_shape(
                crate::scene::decode::attr::AttrValueHandlerId::Typed(
                    crate::typed_value_semantics::TypedValueKind::NurbsCurve,
                ),
                0x20,
                &value_raw,
            )
            .is_ok()
        );
        assert!(
            validate_attr_handler_payload_shape(
                crate::scene::decode::attr::AttrValueHandlerId::Typed(
                    crate::typed_value_semantics::TypedValueKind::NurbsCurve,
                ),
                0x21,
                &value_raw,
            )
            .is_err()
        );
    }
}
