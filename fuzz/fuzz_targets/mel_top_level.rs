#![no_main]

use libfuzzer_sys::fuzz_target;
use maya_scene_kit_formats::mel::{
    MelParseBudget, collect_top_level_audit_candidates_from_bytes_with_budget,
};

fuzz_target!(|data: &[u8]| {
    let budget = MelParseBudget::default().with_max_bytes(256 * 1024);
    let _ = collect_top_level_audit_candidates_from_bytes_with_budget(data, &budget);
});
