#![no_main]

use libfuzzer_sys::fuzz_target;
use maya_scene_kit_formats::mb::{MbParseBudget, parse_bytes_with_budget};

fuzz_target!(|data: &[u8]| {
    let budget = MbParseBudget {
        max_depth: 32,
        max_children_per_group: 256,
        max_total_chunks: 4096,
        max_parse_bytes: 256 * 1024,
    };
    let _ = parse_bytes_with_budget(data.to_vec(), &budget);
});
