use std::num::NonZeroUsize;

use maya_mb::{ChunkLayout, FourCC, HeaderFormat, encode_chunk};
use maya_scene_kit_formats::mb::{
    self,
    rewrite::{
        MbOriginalEdits, MbPathStatus, apply_mb_original_edits, collect_mb_path_candidates,
        plan_mb_path_value,
    },
};

fn chunk(tag: &[u8; 4], payload: &[u8], alignment: usize) -> Vec<u8> {
    encode_chunk(
        FourCC::new(*tag),
        0,
        payload,
        ChunkLayout::new(
            NonZeroUsize::new(alignment).unwrap(),
            HeaderFormat::EightByte,
        ),
    )
    .unwrap()
}

fn example_scene() -> Vec<u8> {
    let mut root = b"Maya".to_vec();
    for index in 0..128 {
        let mut form = b"RTFT".to_vec();
        form.extend(chunk(b"CREA", format!("Example{index}\0").as_bytes(), 8));
        form.extend(chunk(
            b"STR ",
            format!("fileTextureName\0\0asset/example/Example{index}.png\0").as_bytes(),
            8,
        ));
        root.extend(chunk(b"FOR8", &form, 4));
    }
    for index in 0..16 {
        for (tag, payload) in [
            (
                b"FREF",
                format!(
                    "asset/example/Example{index}.mb\0Example{index}\0Example{index}RN\0mayaBinary\0"
                ),
            ),
            (
                b"FRDI",
                format!(
                    "\x01asset/example/Example{index}.mb\0Example{index}\0\x01\0Example{index}RN\0VERS|2026|\0mayaBinary\0"
                ),
            ),
        ] {
            let mut form = tag.to_vec();
            form.extend(chunk(tag, payload.as_bytes(), 8));
            root.extend(chunk(b"FOR8", &form, 4));
        }
    }
    chunk(b"FOR8", &root, 1)
}

fn apply_overrides(bytes: &[u8], indices: &[usize]) -> Vec<u8> {
    let parsed = mb::parse_bytes(bytes.to_vec()).unwrap();
    let candidates = collect_mb_path_candidates(bytes, parsed.root(), indices).unwrap();
    let rewritten_records = candidates
        .iter()
        .map(|candidate| {
            let (edit, status) = plan_mb_path_value(
                bytes,
                parsed.root(),
                candidate,
                &format!("asset/example/Sample{}.png", candidate.entry_index),
            )
            .unwrap();
            assert_eq!(status, MbPathStatus::Applied);
            edit.unwrap()
        })
        .collect();
    apply_mb_original_edits(
        bytes,
        parsed.root(),
        &MbOriginalEdits {
            rewritten_records,
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn many_path_overrides_match_sequential_application() {
    let source = example_scene();
    let parsed = mb::parse_bytes(source.clone()).unwrap();
    let entries = mb::paths::extract_raw_scene_paths_from_mb(&parsed).value;
    assert_eq!(entries.len(), 144);
    let indices = (0..entries.len()).collect::<Vec<_>>();
    let candidates = collect_mb_path_candidates(&source, parsed.root(), &indices).unwrap();
    assert_eq!(candidates.len(), 160);
    let batch = apply_overrides(&source, &indices);
    let mut sequential = source;
    for index in indices {
        sequential = apply_overrides(&sequential, &[index]);
    }
    assert_eq!(batch, sequential);
}
