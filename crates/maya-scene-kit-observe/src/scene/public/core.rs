use serde::Serialize;

/// Scene container format detected for an input path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SceneFormat {
    /// Maya ASCII text scene.
    Ma,
    /// Maya Binary scene.
    Mb,
    /// Format could not be identified.
    Unknown,
}

impl SceneFormat {
    /// Returns the stable snake_case label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ma => "ma",
            Self::Mb => "mb",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for SceneFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operation policy applied when degraded input must be accepted or rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    /// Reject anything that is not fully validated.
    Strict,
    /// Accept validated and partially recovered scenes.
    BestEffort,
    /// Accept all but structurally invalid scenes for inspection workflows.
    Forensic,
}

impl OperationMode {
    /// Returns the stable snake_case label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::BestEffort => "best_effort",
            Self::Forensic => "forensic",
        }
    }

    /// Returns whether this mode permits a result with the given validation state.
    pub fn allows_state(self, state: ValidationState) -> bool {
        match self {
            Self::Strict => matches!(state, ValidationState::Validated),
            Self::BestEffort => matches!(
                state,
                ValidationState::Validated
                    | ValidationState::Partial
                    | ValidationState::CopiedUnvalidated
            ),
            Self::Forensic => !matches!(state, ValidationState::Invalid),
        }
    }
}

impl std::fmt::Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Integrity summary for a read or conversion result.
///
/// `Validated` means the canonical model was built without known degradation. `Partial` means the
/// scene was recovered but some information was missing or inferred. `CopiedUnvalidated` is used
/// for rewrite operations that preserve bytes without re-validating semantic correctness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationState {
    /// The result was produced from a fully validated scene.
    Validated,
    /// The result was produced from a degraded but still usable recovery path.
    Partial,
    /// The requested operation is not supported for the detected input.
    Unsupported,
    /// The scene is too broken for the requested operation.
    Invalid,
    /// Bytes were copied or rewritten without semantic re-validation.
    CopiedUnvalidated,
}

impl ValidationState {
    /// Returns `true` when the state reflects any degradation from a fully validated read.
    pub fn is_degraded(self) -> bool {
        !matches!(self, Self::Validated)
    }
}

impl std::fmt::Display for ValidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Validated => "validated",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::Invalid => "invalid",
            Self::CopiedUnvalidated => "copied_unvalidated",
        };
        f.write_str(value)
    }
}

/// How Maya ASCII text should be decoded before parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsciiDecodePolicy {
    /// Reject invalid UTF-8 input.
    StrictUtf8,
    /// Permit lossy UTF-8 decoding.
    LossyUtf8,
}

impl std::fmt::Display for AsciiDecodePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::StrictUtf8 => "strict_utf8",
            Self::LossyUtf8 => "lossy_utf8",
        };
        f.write_str(value)
    }
}
