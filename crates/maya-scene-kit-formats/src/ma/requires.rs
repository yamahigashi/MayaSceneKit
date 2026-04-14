use std::collections::HashSet;

use crate::ma::{
    raw_dump::{RawMaRequireEntry, RawMaRequireKind},
    rewrite::remove_top_level_commands_from_ma,
    selective::extract_raw_selective_sections_from_ma,
};

pub fn extract_requires_from_ma(data: &[u8]) -> Vec<String> {
    extract_raw_selective_sections_from_ma(data)
        .dump_sections
        .requires
}

pub fn extract_require_entries_from_ma(data: &[u8]) -> Vec<RawMaRequireEntry> {
    extract_raw_selective_sections_from_ma(data)
        .dump_sections
        .require_entries
}

pub fn remove_plugin_requires_from_ma(
    data: &[u8],
    target_rendered: &[String],
) -> (Vec<u8>, Vec<String>) {
    let entries = extract_require_entries_from_ma(data);
    let targets = target_rendered
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<HashSet<_>>();
    let target_all = targets.is_empty();

    let matching = entries
        .iter()
        .filter(|entry| {
            entry.kind == RawMaRequireKind::Plugin
                && (target_all || targets.contains(entry.rendered.as_str()))
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return (data.to_vec(), Vec::new());
    }

    let ranges = matching
        .iter()
        .map(|entry| (entry.start, entry.end))
        .collect::<Vec<_>>();
    let removed = matching
        .iter()
        .map(|entry| entry.rendered.clone())
        .collect::<Vec<_>>();
    let (rewritten, count) = remove_top_level_commands_from_ma(data, &ranges);
    if count == 0 {
        return (data.to_vec(), Vec::new());
    }
    (rewritten, removed)
}

#[cfg(test)]
mod tests {
    use super::{extract_require_entries_from_ma, remove_plugin_requires_from_ma};
    use crate::ma::raw_dump::RawMaRequireKind;

    #[test]
    fn extract_require_entries_classifies_maya_and_plugin_requires() {
        let input = concat!(
            "requires maya \"2026\";\n",
            "requires -nodeType transform \"pluginA\" \"1.0\";\n",
        );

        let entries = extract_require_entries_from_ma(input.as_bytes());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, RawMaRequireKind::MayaVersion);
        assert_eq!(entries[1].kind, RawMaRequireKind::Plugin);
        assert_eq!(
            entries[1].rendered,
            "requires -nodeType transform \"pluginA\" \"1.0\";"
        );
    }

    #[test]
    fn remove_plugin_requires_keeps_maya_version_require() {
        let input = concat!(
            "requires maya \"2026\";\n",
            "requires \"pluginA\" \"1.0\";\n",
            "requires -nodeType transform \"pluginB\" \"2.0\";\n",
            "file -r \"safe.ma\";\n",
        );

        let (rewritten, removed) = remove_plugin_requires_from_ma(
            input.as_bytes(),
            &[String::from("requires \"pluginA\" \"1.0\";")],
        );
        let text = String::from_utf8_lossy(&rewritten);

        assert_eq!(removed, vec!["requires \"pluginA\" \"1.0\";".to_string()]);
        assert!(text.contains("requires maya \"2026\";"));
        assert!(!text.contains("requires \"pluginA\" \"1.0\";"));
        assert!(text.contains("requires -nodeType transform \"pluginB\" \"2.0\";"));
        assert!(text.contains("file -r \"safe.ma\";"));
    }
}
