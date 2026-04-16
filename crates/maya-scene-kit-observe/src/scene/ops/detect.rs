use std::{fs::File, io::Read, path::Path};

use crate::scene::{SceneToolError, core::SceneFormat};

pub(crate) fn detect_scene_format(path: impl AsRef<Path>) -> Result<SceneFormat, SceneToolError> {
    let scene_path = path.as_ref();
    let mut head = [0u8; 1024];
    let mut file = File::open(scene_path)?;
    let bytes_read = file.read(&mut head)?;
    if let Some(format) = sniff_scene_format(&head[..bytes_read]) {
        return Ok(format);
    }
    Ok(SceneFormat::Unknown)
}

fn sniff_scene_format(data: &[u8]) -> Option<SceneFormat> {
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

#[cfg(test)]
mod tests {
    use super::{SceneFormat, sniff_scene_format};

    #[test]
    fn sniff_mb_magic() {
        assert_eq!(sniff_scene_format(b"FOR8xxxx"), Some(SceneFormat::Mb));
    }

    #[test]
    fn sniff_ma_banner() {
        assert_eq!(
            sniff_scene_format(b"//Maya ASCII 2026 scene\n"),
            Some(SceneFormat::Ma)
        );
    }

    #[test]
    fn unknown_when_no_signature() {
        assert_eq!(sniff_scene_format(b"plain text"), None);
    }
}
