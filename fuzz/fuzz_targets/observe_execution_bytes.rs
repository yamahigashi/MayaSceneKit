#![no_main]

use libfuzzer_sys::fuzz_target;
use maya_scene_kit_observe::scene::{
    core::ValidationState,
    LoadOptions, Loader, MbParseBudget, MelParseBudget, SceneFormat,
};

fuzz_target!(|data: &[u8]| {
    let options = LoadOptions::default()
        .with_mel_parse_budget(MelParseBudget::default().with_max_bytes(256 * 1024))
        .with_mb_parse_budget(MbParseBudget {
            max_depth: 32,
            max_children_per_group: 256,
            max_total_chunks: 4096,
            max_parse_bytes: 256 * 1024,
        });
    let loader = Loader::new(options);

    let _ = loader.observe_execution_bytes(
        "fuzz_input.ma",
        SceneFormat::Ma,
        ValidationState::Partial,
        data.to_vec(),
    );
    let _ = loader.observe_execution_bytes(
        "fuzz_input.mb",
        SceneFormat::Mb,
        ValidationState::Partial,
        data.to_vec(),
    );
});
