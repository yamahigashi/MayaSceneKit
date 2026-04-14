use maya_scene_kit_observe::scene::NumericValue;

pub(crate) fn escape_ma_string(text: &str) -> String {
    maya_scene_kit_formats::ma::text::escape_ma_string(text)
}

pub(crate) fn format_number(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }
    value.to_string()
}

pub(crate) fn format_numeric_value(value: NumericValue) -> String {
    match value {
        NumericValue::Float64Bits(bits) => format_number(f64::from_bits(bits)),
        NumericValue::U32(value) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use maya_scene_kit_observe::scene::NumericValue;

    use super::{format_number, format_numeric_value};

    #[test]
    fn format_number_preserves_non_finite_values_as_tokens() {
        assert_eq!(format_number(f64::NAN), "nan");
        assert_eq!(format_number(f64::INFINITY), "inf");
        assert_eq!(format_number(f64::NEG_INFINITY), "-inf");
    }

    #[test]
    fn format_number_uses_round_trip_safe_rendering() {
        assert_eq!(format_number(28.0), "28");
        assert_eq!(
            format_number(std::f64::consts::FRAC_PI_2),
            "1.5707963267948966"
        );
    }

    #[test]
    fn format_numeric_value_renders_integral_variants() {
        assert_eq!(format_numeric_value(NumericValue::from_u32(7)), "7");
        assert_eq!(format_numeric_value(NumericValue::from_f64(2.5)), "2.5");
    }
}
