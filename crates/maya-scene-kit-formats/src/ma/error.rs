use thiserror::Error;

#[derive(Debug, Error)]
pub enum MaParseError {
    #[error("{0}")]
    Message(String),
    #[error("ascii syntax error: {0}")]
    AsciiSyntax(String),
    #[error("unsupported ascii feature: {0}")]
    UnsupportedAsciiFeature(String),
}
