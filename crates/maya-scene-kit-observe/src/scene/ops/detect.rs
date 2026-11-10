pub(crate) use crate::scene::source::snapshot::detect_scene_format;

#[cfg(test)]
mod tests {
    use crate::scene::{SceneFormat, source::snapshot::sniff_scene_format};

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
