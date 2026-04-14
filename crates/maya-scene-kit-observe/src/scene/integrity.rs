use crate::scene::{
    ValidationState,
    ir::{DecodeQualityRecord, SchemaDecodeAttemptResult, TypeIdResolverStatus},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SceneIntegritySummary {
    pub(crate) validation_state: ValidationState,
}

pub(crate) fn summarize_mb_read_integrity_parts(
    typeid_resolver_status: &TypeIdResolverStatus,
    decode_qualities: &[DecodeQualityRecord],
) -> SceneIntegritySummary {
    let resolver_degraded = matches!(
        typeid_resolver_status,
        TypeIdResolverStatus::DefaultLoadFailed { .. }
    );
    let decode_degraded = decode_qualities
        .iter()
        .any(|record| !matches!(record.quality, SchemaDecodeAttemptResult::Exact));

    SceneIntegritySummary {
        validation_state: if resolver_degraded || decode_degraded {
            ValidationState::Partial
        } else {
            ValidationState::Validated
        },
    }
}
