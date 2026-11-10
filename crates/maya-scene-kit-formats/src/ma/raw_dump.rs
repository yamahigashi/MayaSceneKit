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
    pub assignments: Vec<RawMaScriptAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMaScriptAssignment {
    pub attr: String,
    pub string_value: Option<String>,
    pub u32_value: Option<u32>,
    pub start: usize,
    pub end: usize,
}

impl RawMaScriptEntry {
    pub fn last_assignment(&self, attr: &str) -> Option<&RawMaScriptAssignment> {
        self.assignments
            .iter()
            .rev()
            .find(|value| value.attr == attr)
    }

    pub fn body(&self) -> &str {
        self.last_assignment(".b")
            .and_then(|value| value.string_value.as_deref())
            .unwrap_or_default()
    }

    pub fn script_type(&self) -> Option<u32> {
        self.last_assignment(".st")
            .and_then(|value| value.u32_value)
    }

    pub fn source_type(&self) -> Option<u32> {
        self.last_assignment(".stp")
            .and_then(|value| value.u32_value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMaNodeAttrValue {
    pub start: usize,
    pub end: usize,
    pub node_type: String,
    pub node_name: String,
    pub attr: String,
    pub string_value: Option<String>,
    pub u32_value: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawMaNodeAttrSelector {
    pub canonical_attr: String,
    pub node_type: String,
    pub node_name: Option<String>,
    pub attr: String,
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
        assert_eq!(sections.script_entries[0].body(), "print \"ok\";");
        assert_eq!(sections.script_entries[0].script_type(), Some(1));
        assert_eq!(sections.script_entries[0].source_type(), Some(1));
    }
}

#[cfg(test)]
mod assignment_tests {
    use super::extract_raw_dump_sections_from_ma;

    #[test]
    fn script_history_keeps_empty_unreadable_and_resolved_assignments() {
        let input = concat!(
            "createNode script -n ExampleScript;\n",
            "setAttr \".b\" -type \"string\" \"\";\n",
            "setAttr \".st\" 0;\n",
            "select -ne :ExampleScript;\n",
            "setAttr \".a\" -type \"string\" \"Example\";\n",
            "setAttr \".b\" -type \"string\" \"Sample\";\n",
            "rename ExampleScript SampleScript;\n",
            "setAttr \".st\" -1;\n",
            "setAttr \".stp\" 1;\n",
            "select -ne :SampleScript;\n",
            "setAttr \".a\" -type \"string\" 7;\n",
        );
        let dump = extract_raw_dump_sections_from_ma(input.as_bytes());
        assert_eq!(dump.script_entries.len(), 1);
        let node = &dump.script_entries[0];
        assert_eq!(node.name, "SampleScript");
        assert_eq!(
            node.assignments
                .iter()
                .map(|v| v.attr.as_str())
                .collect::<Vec<_>>(),
            [".b", ".st", ".a", ".b", ".st", ".stp", ".a"]
        );
        assert_eq!(node.assignments[0].string_value.as_deref(), Some(""));
        assert_eq!(node.assignments[3].string_value.as_deref(), Some("Sample"));
        assert_eq!(node.assignments[4].u32_value, None);
        assert_eq!(node.assignments[6].string_value, None);
        assert!(
            node.assignments
                .windows(2)
                .all(|pair| pair[0].end <= pair[1].start)
        );
        for assignment in &node.assignments {
            assert!(input[assignment.start..assignment.end].starts_with("setAttr"));
        }
        let duplicate = extract_raw_dump_sections_from_ma(
            concat!(
                "createNode script -n Example; setAttr \".b\" -type \"string\" \"Sample\";",
                "createNode script -n Example; setAttr \".b\" -type \"string\" \"Example\";"
            )
            .as_bytes(),
        );
        assert_eq!(duplicate.script_entries.len(), 2);
        assert_eq!(duplicate.script_entries[0].body(), "Sample");
        assert_eq!(duplicate.script_entries[1].body(), "Example");
    }
}
