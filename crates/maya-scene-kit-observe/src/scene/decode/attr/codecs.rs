use crate::scene::{decode::numeric_f64, ir::NumericValue};

#[derive(Debug, Clone)]
pub(crate) struct ParsedNurbsCurve {
    pub(crate) degree: u32,
    pub(crate) spans: u32,
    pub(crate) form: u32,
    pub(crate) is_rational: bool,
    pub(crate) dimension: usize,
    pub(crate) knots: Vec<NumericValue>,
    pub(crate) cvs: Vec<Vec<NumericValue>>,
}

pub(crate) fn decode_matrix_values(value_raw: &[u8]) -> Option<Vec<NumericValue>> {
    if value_raw.len() == 128 {
        return Some(
            value_raw
                .chunks_exact(8)
                .map(|c| numeric_f64(f64::from_bits(u64::from_be_bytes(c.try_into().unwrap()))))
                .collect(),
        );
    }
    if value_raw.len() < 128 || value_raw.len() % 8 != 0 {
        return None;
    }

    let values = value_raw
        .chunks_exact(8)
        .map(|c| f64::from_bits(u64::from_be_bytes(c.try_into().unwrap())))
        .filter(|v| !(v.is_sign_positive() && *v > 0.0 && v.abs() < 1.0e-300))
        .collect::<Vec<_>>();
    if values.len() < 16 {
        return None;
    }

    let mut best_start: Option<usize> = None;
    let mut best_score: i32 = i32::MIN;
    for start in 0..=values.len() - 16 {
        let window = &values[start..start + 16];
        let score = score_matrix_window(window);
        if score > best_score {
            best_score = score;
            best_start = Some(start);
        }
    }
    let start = best_start?;
    if best_score == i32::MIN {
        return None;
    }

    Some(
        values[start..start + 16]
            .iter()
            .map(|v| numeric_f64(*v))
            .collect(),
    )
}

pub(crate) fn parse_nurbs_curve_value_raw(kind: u8, payload: &[u8]) -> Option<ParsedNurbsCurve> {
    if kind != 0x20 || payload.len() < 25 {
        return None;
    }

    let degree = u32::from_be_bytes(payload[0..4].try_into().ok()?);
    let spans = u32::from_be_bytes(payload[4..8].try_into().ok()?);
    let form = u32::from_be_bytes(payload[8..12].try_into().ok()?);
    let is_rational = u32::from_be_bytes(payload[12..16].try_into().ok()?) != 0;
    let dimension = payload[16] as usize;

    let knot_count = u32::from_be_bytes(payload[17..21].try_into().ok()?) as usize;
    let mut cursor = 21usize;
    let knot_bytes = knot_count.checked_mul(8)?;
    if cursor + knot_bytes > payload.len() {
        return None;
    }
    let mut knots = Vec::with_capacity(knot_count);
    for idx in 0..knot_count {
        let start = cursor + idx * 8;
        let end = start + 8;
        let value = f64::from_bits(u64::from_be_bytes(payload[start..end].try_into().ok()?));
        knots.push(numeric_f64(value));
    }
    cursor += knot_bytes;

    if cursor + 4 > payload.len() {
        return None;
    }
    let cv_count = u32::from_be_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
    cursor += 4;

    let components_per_cv = nurbs_curve_components_per_cv(dimension, is_rational)?;
    let doubles_per_cv = cv_count.checked_mul(components_per_cv)?;
    let cv_bytes = doubles_per_cv.checked_mul(8)?;
    if cursor + cv_bytes > payload.len() {
        return None;
    }
    let mut cvs = Vec::with_capacity(cv_count);
    for cv_idx in 0..cv_count {
        let mut cv = Vec::with_capacity(components_per_cv);
        for component in 0..components_per_cv {
            let start = cursor + (cv_idx * components_per_cv + component) * 8;
            let end = start + 8;
            let value = f64::from_bits(u64::from_be_bytes(payload[start..end].try_into().ok()?));
            cv.push(numeric_f64(value));
        }
        cvs.push(cv);
    }
    cursor += cv_bytes;

    if cursor < payload.len() && payload[cursor..].iter().any(|b| *b != 0) {
        return None;
    }

    Some(ParsedNurbsCurve {
        degree,
        spans,
        form,
        is_rational,
        dimension,
        knots,
        cvs,
    })
}

fn score_matrix_window(window: &[f64]) -> i32 {
    if window.len() != 16 {
        return i32::MIN;
    }
    if window
        .iter()
        .any(|v| !v.is_finite() || v.abs() > 1.0e12 || *v < -1.0e12)
    {
        return i32::MIN;
    }

    let non_zero = window[..15].iter().filter(|v| v.abs() >= 1.0e-9).count();
    if non_zero < 3 {
        return i32::MIN;
    }

    let mut score = 0i32;
    if (window[15] - 1.0).abs() <= 1.0e-6 {
        score += 8;
    }
    for &idx in &[0usize, 5, 10, 15] {
        if (window[idx] - 1.0).abs() <= 1.0e-6 {
            score += 3;
        }
    }
    let zeros = window.iter().filter(|v| v.abs() < 1.0e-9).count() as i32;
    score += zeros;
    score -= (non_zero as i32 - 7).abs();
    score
}

pub(crate) fn nurbs_curve_components_per_cv(dimension: usize, is_rational: bool) -> Option<usize> {
    if dimension == 0 || dimension > 4 {
        return None;
    }
    if is_rational {
        dimension.checked_add(1)
    } else {
        Some(dimension)
    }
}
