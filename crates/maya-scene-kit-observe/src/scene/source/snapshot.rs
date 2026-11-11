use std::{
    fs::File,
    io::{Read, Result as IoResult},
    path::Path,
    sync::{Arc, OnceLock},
    time::SystemTime,
};

use sha2::{Digest, Sha256};

use super::loader::LoadOptions;
use crate::{
    mb::MbParseBudgetLimit,
    scene::{MelParseBudgetLimit, SceneFormat, SceneToolError},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileState {
    pub(crate) len: u64,
    pub(crate) modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadStability {
    Stable,
    Unstable,
    Absent,
}

enum SourceFileState {
    Absent,
    Read {
        before: Option<FileState>,
        after: Option<FileState>,
    },
}

pub(crate) struct SourceIdentity {
    sha256: OnceLock<String>,
    file_state: SourceFileState,
}

impl SourceIdentity {
    pub(crate) fn absent() -> Self {
        Self {
            sha256: OnceLock::new(),
            file_state: SourceFileState::Absent,
        }
    }

    pub(crate) fn initial_len(&self, bytes_len: usize) -> usize {
        match &self.file_state {
            SourceFileState::Read {
                before: Some(before),
                ..
            } => usize::try_from(before.len).unwrap_or(usize::MAX),
            _ => bytes_len,
        }
    }

    pub(crate) fn stable_file_state(&self) -> Option<&FileState> {
        match &self.file_state {
            SourceFileState::Read {
                before: Some(before),
                after: Some(after),
            } if before == after => Some(before),
            _ => None,
        }
    }

    pub(crate) fn stability(&self) -> ReadStability {
        match &self.file_state {
            SourceFileState::Absent => ReadStability::Absent,
            _ if self.stable_file_state().is_some() => ReadStability::Stable,
            SourceFileState::Read { .. } => ReadStability::Unstable,
        }
    }
}

enum SourceBytes {
    Ma(Arc<Vec<u8>>),
    Mb(Arc<[u8]>),
    Released,
}

pub(crate) struct SourceSnapshot {
    pub(crate) identity: SourceIdentity,
    bytes: SourceBytes,
}

impl SourceSnapshot {
    pub(crate) fn ma(bytes: Arc<Vec<u8>>, identity: SourceIdentity) -> Self {
        Self {
            identity,
            bytes: SourceBytes::Ma(bytes),
        }
    }

    pub(crate) fn mb(bytes: Arc<[u8]>, identity: SourceIdentity) -> Self {
        Self {
            identity,
            bytes: SourceBytes::Mb(bytes),
        }
    }

    pub(crate) fn sha256(&self) -> Result<&str, SceneToolError> {
        if let Some(hash) = self.identity.sha256.get() {
            return Ok(hash);
        }
        let bytes: &[u8] = match &self.bytes {
            SourceBytes::Ma(bytes) => bytes,
            SourceBytes::Mb(bytes) => bytes,
            SourceBytes::Released => {
                return Err(SceneToolError::Message(
                    "source bytes were released without a digest".into(),
                ));
            }
        };
        Ok(self
            .identity
            .sha256
            .get_or_init(|| format!("{:x}", Sha256::digest(bytes))))
    }

    pub(crate) fn release(&mut self, retain_digest: bool) -> Result<(), SceneToolError> {
        if retain_digest {
            self.sha256()?;
        }
        self.bytes = SourceBytes::Released;
        Ok(())
    }
}

pub(crate) struct AcquiredSource {
    pub(crate) bytes: Vec<u8>,
    pub(crate) identity: SourceIdentity,
}

pub(super) struct SourceReader<'a> {
    path: &'a Path,
    format: SceneFormat,
    file: File,
    before: Option<FileState>,
    head: Vec<u8>,
}

impl<'a> SourceReader<'a> {
    pub(super) fn open(path: &'a Path) -> IoResult<Self> {
        #[cfg(test)]
        super::read_tests::record(super::read_tests::ReadEvent::Open);
        let mut file = File::open(path)?;
        let before = file_state(&file).ok();
        let mut head = Vec::with_capacity(1024);
        (&mut file).take(1024).read_to_end(&mut head)?;
        #[cfg(test)]
        super::read_tests::record(super::read_tests::ReadEvent::Sniff);
        let format = sniff_scene_format(&head).unwrap_or(SceneFormat::Unknown);
        Ok(Self {
            path,
            format,
            file,
            before,
            head,
        })
    }

    pub(super) fn format(&self) -> SceneFormat {
        self.format
    }

    pub(super) fn read(mut self, options: &LoadOptions) -> Result<AcquiredSource, SceneToolError> {
        let format = self.format;
        let source_len = self.before.as_ref().map(|state| state.len);
        let max_bytes = match format {
            SceneFormat::Ma => options.mel_parse_budget().max_bytes,
            SceneFormat::Mb => {
                options
                    .materialize_mb_parse_budget_for_bytes(
                        source_len
                            .and_then(|len| usize::try_from(len).ok())
                            .unwrap_or(self.head.len()),
                    )
                    .max_parse_bytes
            }
            SceneFormat::Unknown => {
                return Err(SceneToolError::UnsupportedSceneFormat {
                    path: self.path.to_path_buf(),
                    detected: format,
                });
            }
        };
        if let Some(len) = source_len {
            check_size(format, len, max_bytes)?;
        }
        let bytes = read_body(&mut self.file, self.head, source_len, max_bytes)?;
        #[cfg(test)]
        super::read_tests::record(super::read_tests::ReadEvent::BodyDone(bytes.len()));
        let after = file_state(&self.file).ok();
        check_size(format, bytes.len() as u64, max_bytes)?;
        Ok(AcquiredSource {
            bytes,
            identity: SourceIdentity {
                sha256: OnceLock::new(),
                file_state: SourceFileState::Read {
                    before: self.before,
                    after,
                },
            },
        })
    }
}

fn file_state(file: &File) -> IoResult<FileState> {
    #[cfg(test)]
    super::read_tests::record(super::read_tests::ReadEvent::Metadata);
    #[cfg(test)]
    if let Some(state) = super::read_tests::SUPPLY
        .with(|s| s.borrow_mut().as_mut().and_then(|s| s.states.pop_front()))
    {
        return state
            .map(|(len, modified)| FileState { len, modified })
            .ok_or_else(|| std::io::Error::other("Example metadata unavailable"));
    }
    let metadata = file.metadata()?;
    Ok(FileState {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn read_body(
    file: &mut File,
    mut head: Vec<u8>,
    source_len: Option<u64>,
    max_bytes: usize,
) -> IoResult<Vec<u8>> {
    #[cfg(test)]
    super::read_tests::record(super::read_tests::ReadEvent::Body);
    #[cfg(test)]
    if let Some(result) = super::read_tests::SUPPLY.with(|s| {
        s.borrow_mut().as_mut().map(|s| {
            s.calls += 1;
            s.bodies
                .pop_front()
                .ok_or_else(|| std::io::Error::other("unexpected scene reread"))
        })
    }) {
        return result;
    }
    let limit = max_bytes.saturating_add(1);
    head.truncate(limit);
    let capacity = source_len
        .and_then(|len| usize::try_from(len).ok())
        .unwrap_or(head.len())
        .min(limit);
    head.reserve_exact(capacity.saturating_sub(head.len()));
    file.take(limit.saturating_sub(head.len()) as u64)
        .read_to_end(&mut head)?;
    Ok(head)
}

fn check_size(format: SceneFormat, len: u64, max_bytes: usize) -> Result<(), SceneToolError> {
    if len > max_bytes as u64 {
        return Err(match format {
            SceneFormat::Ma => SceneToolError::MelParseBudgetExceeded {
                limit: MelParseBudgetLimit::MaxBytes,
            },
            _ => SceneToolError::MbParseBudgetExceeded {
                limit: MbParseBudgetLimit::MaxParseBytes,
            },
        });
    }
    Ok(())
}

pub(crate) fn acquire(
    path: &Path,
    options: &LoadOptions,
) -> Result<AcquiredSource, SceneToolError> {
    SourceReader::open(path)?.read(options)
}

pub(crate) fn detect_scene_format(path: impl AsRef<Path>) -> Result<SceneFormat, SceneToolError> {
    Ok(SourceReader::open(path.as_ref())?.format())
}

pub(crate) fn sniff_scene_format(data: &[u8]) -> Option<SceneFormat> {
    let head = &data[..std::cmp::min(1024, data.len())];
    if head.starts_with(b"FOR4") || head.starts_with(b"FOR8") {
        return Some(SceneFormat::Mb);
    }
    if head
        .windows(b"Maya ASCII".len())
        .any(|window| window == b"Maya ASCII")
    {
        return Some(SceneFormat::Ma);
    }
    None
}
