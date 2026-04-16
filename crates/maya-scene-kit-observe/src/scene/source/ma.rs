use std::fs;

use maya_scene_kit_formats::{
    ma::{raw_dump::RawMaDumpSections, scripts::RawMaScriptEntry},
    mel,
};

use crate::scene::{ScenePathEntry, ScenePathMeta, ScriptNodeEntry, source::MaObservationData};

impl MaObservationData {
    pub(crate) fn top_level(&self) -> &mel::MelAuditTopLevelFacts {
        &self.selective_sections().audit_top_level
    }

    pub(crate) fn dump_sections(&self) -> &RawMaDumpSections {
        &self.selective_sections().dump_sections
    }

    pub(crate) fn script_entries(&self) -> &[RawMaScriptEntry] {
        self.dump_sections().script_entries.as_slice()
    }

    pub(crate) fn scene_paths(&self) -> &[ScenePathEntry] {
        self.scene_paths
            .get_or_init(|| {
                self.selective_sections()
                    .scene_paths
                    .iter()
                    .map(map_format_scene_path_entry_ref)
                    .collect()
            })
            .as_slice()
    }

    pub(crate) fn selective_sections(
        &self,
    ) -> &maya_scene_kit_formats::ma::selective::RawMaSelectiveSections {
        self.selective_sections
            .get()
            .expect("ma selective sections preloaded during observation load")
    }

    pub(crate) fn bytes(&self) -> Result<&[u8], crate::scene::SceneToolError> {
        if let Some(bytes) = self.bytes.get() {
            return Ok(bytes.as_slice());
        }

        let bytes = fs::read(&self.source_path)?;
        let _ = self.bytes.set(bytes);
        Ok(self
            .bytes
            .get()
            .expect("ma bytes available after lazy reload")
            .as_slice())
    }
}

pub(crate) fn collect_ma_script_entries(entries: &[RawMaScriptEntry]) -> Vec<ScriptNodeEntry> {
    entries
        .iter()
        .map(|entry| ScriptNodeEntry {
            name: entry.name.clone(),
            body: entry.body.clone(),
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn collect_ma_scene_paths(bytes: &[u8]) -> Vec<ScenePathEntry> {
    maya_scene_kit_formats::ma::paths::extract_raw_scene_paths_from_ma(bytes)
        .iter()
        .map(map_format_scene_path_entry_ref)
        .collect()
}

fn map_format_scene_path_entry_ref(
    entry: &maya_scene_kit_formats::ma::types::ScenePathEntry,
) -> ScenePathEntry {
    ScenePathEntry {
        node_type: entry.node_type.clone(),
        node_name: entry.node_name.clone(),
        attr: entry.attr.clone(),
        value: entry.value.clone(),
        meta: entry.meta.as_ref().map(map_format_scene_path_meta_ref),
    }
}

fn map_format_scene_path_meta_ref(
    meta: &maya_scene_kit_formats::ma::types::ScenePathMeta,
) -> ScenePathMeta {
    ScenePathMeta {
        origin: meta.origin.clone(),
        short_name: meta.short_name.clone(),
        reference_node: meta.reference_node.clone(),
        format_hint: meta.format_hint.clone(),
        reference_options: meta.reference_options.clone(),
        color_space: meta.color_space.clone(),
        raw_fields: meta.raw_fields.clone(),
        trace_form: meta.trace_form.clone(),
        trace_tag: meta.trace_tag.clone(),
        trace_node_offset: meta.trace_node_offset,
        trace_child_alignment: meta.trace_child_alignment,
        trace_child_header_size: meta.trace_child_header_size,
    }
}
