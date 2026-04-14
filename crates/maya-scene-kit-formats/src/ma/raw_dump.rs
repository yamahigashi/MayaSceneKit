#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawMaRequireKind {
    MayaVersion,
    Plugin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMaRequireEntry {
    pub rendered: String,
    pub kind: RawMaRequireKind,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMaScriptEntry {
    pub name: String,
    pub body: String,
    pub script_type: Option<u32>,
    pub source_type: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawMaDumpSections {
    pub requires: Vec<String>,
    pub require_entries: Vec<RawMaRequireEntry>,
    pub script_entries: Vec<RawMaScriptEntry>,
}

pub fn extract_raw_dump_sections_from_ma(data: &[u8]) -> RawMaDumpSections {
    crate::ma::selective::extract_raw_selective_sections_from_ma(data).dump_sections
}

#[cfg(test)]
mod tests {
    use super::{RawMaRequireKind, extract_raw_dump_sections_from_ma};

    #[test]
    fn raw_dump_sections_collect_requires_and_scripts_together() {
        let input = concat!(
            "requires maya \"2026\";\n",
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
            "    setAttr \".st\" 1;\n",
            "    setAttr \".stp\" 1;\n",
        );

        let sections = extract_raw_dump_sections_from_ma(input.as_bytes());
        assert_eq!(
            sections.requires,
            vec!["requires maya \"2026\";".to_string()]
        );
        assert_eq!(sections.require_entries.len(), 1);
        assert_eq!(
            sections.require_entries[0].rendered,
            "requires maya \"2026\";"
        );
        assert_eq!(
            sections.require_entries[0].kind,
            RawMaRequireKind::MayaVersion
        );
        assert_eq!(sections.script_entries.len(), 1);
        assert_eq!(sections.script_entries[0].name, "scriptNode1");
        assert_eq!(sections.script_entries[0].body, "print \"ok\";");
        assert_eq!(sections.script_entries[0].script_type, Some(1));
        assert_eq!(sections.script_entries[0].source_type, Some(1));
    }
}
