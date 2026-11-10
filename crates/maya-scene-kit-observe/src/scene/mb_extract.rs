use std::collections::HashSet;

use maya_scene_kit_formats::mb::render_requires_entry;

use crate::{
    mb::{MayaBinaryFile, MbParseBudget, MbSectionScan, extract_head_metadata_with_budget},
    scene::dump::{SceneDumpRequireEntry, SceneDumpRequireKind},
};

pub(super) fn extract_requires_from_mb(
    mb: &MayaBinaryFile,
    budget: &MbParseBudget,
) -> MbSectionScan<Vec<String>> {
    let scanned = extract_require_entries_from_mb(mb, budget);
    MbSectionScan {
        value: scanned
            .value
            .into_iter()
            .map(|entry| entry.rendered)
            .collect(),
        state: scanned.state,
    }
}

pub(super) fn extract_require_entries_from_mb(
    mb: &MayaBinaryFile,
    budget: &MbParseBudget,
) -> MbSectionScan<Vec<SceneDumpRequireEntry>> {
    let metadata = extract_head_metadata_with_budget(mb, budget);
    let vers = metadata.maya_version();
    let mut out = vec![SceneDumpRequireEntry {
        rendered: format!(
            "requires maya \"{}\";",
            maya_scene_kit_formats::ma::text::escape_ma_string(vers)
        ),
        kind: SceneDumpRequireKind::MayaVersion,
    }];
    let mut seen: HashSet<String> = out.iter().map(|entry| entry.rendered.clone()).collect();

    for req in metadata.requires {
        let rendered = render_requires_entry(&req);
        if seen.insert(rendered.clone()) {
            out.push(SceneDumpRequireEntry {
                rendered,
                kind: SceneDumpRequireKind::Plugin,
            });
        }
    }

    MbSectionScan {
        value: out,
        state: metadata.section_state,
    }
}
