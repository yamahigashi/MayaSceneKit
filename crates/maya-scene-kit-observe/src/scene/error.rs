use std::path::PathBuf;

use maya_scene_kit_formats::ma::error::MaParseError;
use maya_scene_kit_formats::mb::{MayaBinaryParseError, MbParseBudgetLimit};
use maya_scene_kit_formats::mel::MelParseBudgetLimit;
use thiserror::Error;

use super::{AsciiDecodePolicy, SceneFormat, ValidationState};

#[derive(Debug, Error)]
/// Error type used by the core scene library.
pub enum SceneToolError {
    /// Generic domain error with a human-readable message.
    #[error("{0}")]
    Message(String),
    /// The requested API does not support the detected scene format.
    #[error("unsupported scene format: {path} ({detected})")]
    UnsupportedSceneFormat {
        path: PathBuf,
        detected: SceneFormat,
    },
    /// Runtime asset or configuration failure.
    #[error("config error: {0}")]
    Config(String),
    /// Maya ASCII syntax error.
    #[error("ascii syntax error: {0}")]
    AsciiSyntax(String),
    /// Maya ASCII feature exists but is not yet supported by the parser.
    #[error("unsupported ascii feature: {0}")]
    UnsupportedAsciiFeature(String),
    /// Internal encode invariant failure.
    #[error("encode invariant error: {0}")]
    EncodeInvariant(String),
    /// Atomic output write failure.
    #[error("atomic write error: {0}")]
    AtomicWrite(String),
    /// Input text could not be decoded under the selected policy.
    #[error("invalid UTF-8 Maya ASCII input ({policy}): {message}")]
    InvalidUtf8 {
        policy: AsciiDecodePolicy,
        message: String,
    },
    /// The selected operation mode rejected the current validation state.
    #[error(
        "operation rejected by mode {mode}: validation_state={validation_state} issues={issue_count} unknown_entries={unknown_count}"
    )]
    RejectedByMode {
        mode: super::OperationMode,
        validation_state: ValidationState,
        issue_count: usize,
        unknown_count: usize,
    },
    /// Filesystem I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// MEL parse budget exceeded before a trustworthy scene view could be produced.
    #[error("parse budget exceeded: {limit}")]
    MelParseBudgetExceeded { limit: MelParseBudgetLimit },
    /// Maya Binary parse budget exceeded before a trustworthy scene view could be produced.
    #[error("parse budget exceeded: {limit}")]
    MbParseBudgetExceeded { limit: MbParseBudgetLimit },
    /// Maya Binary parse failure.
    #[error(transparent)]
    Parse(MayaBinaryParseError),
}

impl From<MaParseError> for SceneToolError {
    fn from(value: MaParseError) -> Self {
        match value {
            MaParseError::Message(message) => Self::Message(message),
            MaParseError::AsciiSyntax(message) => Self::AsciiSyntax(message),
            MaParseError::UnsupportedAsciiFeature(message) => {
                Self::UnsupportedAsciiFeature(message)
            }
        }
    }
}

impl From<MayaBinaryParseError> for SceneToolError {
    fn from(value: MayaBinaryParseError) -> Self {
        if let Some(limit) = value.budget_limit() {
            Self::MbParseBudgetExceeded { limit }
        } else {
            Self::Parse(value)
        }
    }
}
