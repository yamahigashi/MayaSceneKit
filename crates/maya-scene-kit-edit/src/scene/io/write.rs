use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::scene::SceneToolError;

static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// dir_sync_error means replacement succeeded but directory sync failed; ignoring it accepts
/// that the replacement may not survive a crash.
#[derive(Debug)]
pub struct WriteOutcome {
    pub dir_sync_error: Option<std::io::Error>,
}

pub fn write_output_bytes_atomic(
    path: &Path,
    bytes: &[u8],
) -> Result<WriteOutcome, SceneToolError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let (temp_path, mut file) =
        allocate_temp_file(parent, path.file_name().unwrap_or_default(), path)?;

    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(&temp_path);
        return Err(SceneToolError::Io(err));
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(SceneToolError::Io(err));
    }
    drop(file);

    if let Err(err) = replace_existing_file(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(SceneToolError::Io(err));
    }
    Ok(WriteOutcome {
        dir_sync_error: sync_parent_dir(parent).err(),
    })
}

pub(in crate::scene) fn write_bytes_atomic(
    path: &Path,
    bytes: &[u8],
) -> Result<(), SceneToolError> {
    write_output_bytes_atomic(path, bytes).map(|_| ())
}

fn allocate_temp_file(
    parent: &Path,
    file_name: &std::ffi::OsStr,
    destination: &Path,
) -> Result<(PathBuf, fs::File), SceneToolError> {
    let mut last_error = None;
    for _ in 0..32 {
        let temp_path = atomic_temp_path(parent, file_name);
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(err);
            }
            Err(err) => return Err(SceneToolError::Io(err)),
        }
    }

    Err(SceneToolError::AtomicWrite(format!(
        "failed to allocate temporary output for {}: {}",
        destination.display(),
        last_error
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    )))
}

fn atomic_temp_path(parent: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let pid = std::process::id();
    let counter = ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let stem = format!(".{}.tmp-{}-{}", file_name.to_string_lossy(), pid, counter);
    parent.join(stem)
}

#[cfg(unix)]
fn replace_existing_file(temp_path: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(temp_path, destination)
}

#[cfg(windows)]
fn replace_existing_file(temp_path: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let mut from = temp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut to = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let ok = unsafe {
        MoveFileExW(
            from.as_mut_ptr(),
            to.as_mut_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn replace_existing_file(temp_path: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(temp_path, destination)
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> std::io::Result<()> {
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Every test in this binary that changes the current directory must hold this lock.
    static CURRENT_DIR_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn writes_bare_output_name() {
        let _lock = CURRENT_DIR_LOCK.lock().unwrap();
        struct RestoreDirectory(PathBuf);
        impl Drop for RestoreDirectory {
            fn drop(&mut self) {
                std::env::set_current_dir(&self.0).expect("restore current directory");
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let _restore = RestoreDirectory(std::env::current_dir().unwrap());
        std::env::set_current_dir(directory.path()).unwrap();
        let result = write_output_bytes_atomic(Path::new("Example.ma"), b"Example");
        let outcome = result.expect("write bare output name");
        assert!(outcome.dir_sync_error.is_none());
        assert_eq!(fs::read("Example.ma").unwrap(), b"Example");
    }
}
