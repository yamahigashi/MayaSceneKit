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
    completeness: &crate::mb::MbCompleteness,
) -> SceneIntegritySummary {
    let resolver_degraded = matches!(
        typeid_resolver_status,
        TypeIdResolverStatus::DefaultLoadFailed { .. }
    );
    let decode_degraded = decode_qualities
        .iter()
        .any(|record| !matches!(record.quality, SchemaDecodeAttemptResult::Exact));

    SceneIntegritySummary {
        validation_state: if resolver_degraded
            || decode_degraded
            || !matches!(completeness, crate::mb::MbCompleteness::Complete)
        {
            ValidationState::Partial
        } else {
            ValidationState::Validated
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mb::{MbCompleteness, MbTruncationReason};

    #[test]
    fn truncated_tree_degrades_otherwise_validated_integrity() {
        let summary = summarize_mb_read_integrity_parts(
            &TypeIdResolverStatus::Provided,
            &[],
            &MbCompleteness::Truncated {
                first_reason: MbTruncationReason::DepthLimit,
                truncated_groups: 1,
            },
        );
        assert_eq!(summary.validation_state, ValidationState::Partial);
    }
}
