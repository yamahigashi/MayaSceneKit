#![no_main]

use libfuzzer_sys::fuzz_target;
use maya_scene_kit_formats::{
    ma::selective::extract_raw_selective_sections_from_ma_with_budget,
    mel::MelParseBudget,
};

fuzz_target!(|data: &[u8]| {
    let budget = MelParseBudget::default().with_max_bytes(256 * 1024);
    let _ = extract_raw_selective_sections_from_ma_with_budget(data, &budget);
});
