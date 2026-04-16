use crate::scene::{
    SceneToolError, ir,
    scripts::ScriptNodeEntry,
    source::{ObservationBundle, ObservationData},
};

pub(crate) fn script_node_entries(
    observation: &ObservationBundle,
) -> Result<Vec<ScriptNodeEntry>, SceneToolError> {
    match &observation.data {
        ObservationData::Ma { data } => Ok(crate::scene::source::ma::collect_ma_script_entries(
            data.script_entries(),
        )),
        ObservationData::Mb { session } => Ok(collect_mb_script_entries(&session.build()?.scene.nodes)),
    }
}

fn collect_mb_script_entries(nodes: &[ir::RecoveredNode]) -> Vec<ScriptNodeEntry> {
    let mut entries = Vec::new();
    for node in nodes {
        if node.node_type != "script" {
            continue;
        }
        let mut bodies = Vec::new();
        for attr in &node.attrs {
            let ir::RecoveredAttrOp::SetAttr(op) = attr else {
                continue;
            };
            if op.attr_name_or_path != ".b" {
                continue;
            }
            let ir::SetAttrValue::String(body) = &op.value else {
                continue;
            };
            if !bodies.iter().any(|existing| existing == body) {
                bodies.push(body.clone());
            }
        }
        if bodies.is_empty() {
            entries.push(ScriptNodeEntry {
                name: node.name.clone(),
                body: String::new(),
            });
            continue;
        }
        for body in bodies {
            entries.push(ScriptNodeEntry {
                name: node.name.clone(),
                body,
            });
        }
    }
    entries
}
