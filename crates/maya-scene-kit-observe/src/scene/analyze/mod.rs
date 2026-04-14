mod checks;

use std::collections::{BTreeSet, HashMap};

use self::checks::{
    attr_shape::check_attr_value_shape_plausibility, decode_quality::check_partial_decode_quality,
    duplicate_uids::check_duplicate_uids, graph_consistency::check_graph_consistency,
    links::check_link_shape_plausibility, refedit::check_refedit_group_counts,
    select::check_select_block_plausibility,
};
use super::ir::{
    AddAttrValueSpec, NodeRecoveryIssue, RecoveredAttrOp, RecoveredNode, RecoveryIssue,
    ReferenceFileOp, SceneArtifacts, SceneModel, SemanticProvenance, SetAttrOp, SetAttrValue,
};

pub(crate) fn analyze_scene_model(
    model: &SceneModel,
    artifacts: &SceneArtifacts,
) -> Vec<NodeRecoveryIssue> {
    let mut out = collect_decode_notes(&model.nodes);
    out.extend(check_partial_decode_quality(artifacts));
    out.extend(check_duplicate_setattr_paths(&model.nodes));
    out.extend(check_attr_value_shape_plausibility(&model.nodes));
    out.extend(check_addattr_emission_plausibility(&model.nodes));
    out.extend(check_refedit_group_counts(&model.nodes));
    out.extend(check_link_shape_plausibility(&model.links));
    out.extend(check_select_block_plausibility(&model.select_blocks));
    out.extend(check_duplicate_uids(&model.nodes));
    out.extend(check_script_nodes_have_body(&model.nodes));
    out.extend(check_graph_consistency(
        &model.nodes,
        &model.links,
        &model.select_blocks,
        &model.reference_files,
    ));
    out.extend(check_reference_semantic_fallbacks(&model.reference_files));
    out
}

fn check_addattr_emission_plausibility(nodes: &[RecoveredNode]) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for node in nodes {
        for attr in &node.attrs {
            let RecoveredAttrOp::AddAttr(op) = attr else {
                continue;
            };
            let AddAttrValueSpec::UnknownToken { token } = &op.value_spec else {
                continue;
            };
            out.push(NodeRecoveryIssue {
                node_type: node.node_type.clone(),
                node_name: node.name.clone(),
                issue: RecoveryIssue::inferred_analysis(
                    &op.attr_name,
                    format!("addAttr type token '{token}' is unknown; emission skipped"),
                ),
            });
        }
    }
    out
}

fn collect_decode_notes(nodes: &[RecoveredNode]) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for node in nodes {
        for issue in &node.decode_notes {
            out.push(NodeRecoveryIssue {
                node_type: node.node_type.clone(),
                node_name: node.name.clone(),
                issue: issue.clone(),
            });
        }
    }
    out
}

fn check_duplicate_setattr_paths(nodes: &[RecoveredNode]) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for node in nodes {
        let mut by_path: HashMap<&str, Vec<&SetAttrOp>> = HashMap::new();
        for attr in &node.attrs {
            let RecoveredAttrOp::SetAttr(op) = attr else {
                continue;
            };
            by_path
                .entry(op.attr_name_or_path.as_str())
                .or_default()
                .push(op);
        }

        let mut duplicates: Vec<(&str, Vec<&SetAttrOp>)> = by_path
            .into_iter()
            .filter(|(_, ops)| ops.len() > 1)
            .collect();
        duplicates.sort_by(|a, b| a.0.cmp(b.0));
        for (attr_path, ops) in duplicates {
            let distinct_ops = ops
                .iter()
                .map(|op| format!("{op:?}"))
                .collect::<BTreeSet<_>>()
                .len();
            if distinct_ops <= 1 {
                continue;
            }
            let size_only = ops.iter().all(|op| {
                op.lock.is_none()
                    && op.keyable.is_none()
                    && op.channel_hint.is_none()
                    && matches!(op.value, SetAttrValue::None)
            });
            if size_only {
                continue;
            }
            out.push(NodeRecoveryIssue {
                node_type: node.node_type.clone(),
                node_name: node.name.clone(),
                issue: RecoveryIssue::inferred_analysis(
                    attr_path,
                    format!(
                        "setAttr for '{attr_path}' appears {} times (distinct payloads: {distinct_ops}) on recovered node",
                        ops.len()
                    ),
                ),
            });
        }
    }

    out
}

fn check_script_nodes_have_body(nodes: &[RecoveredNode]) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for node in nodes {
        if node.node_type != "script" {
            continue;
        }
        let has_script_body = node.attrs.iter().any(|attr| {
            matches!(
                attr,
                RecoveredAttrOp::SetAttr(SetAttrOp {
                    attr_name_or_path,
                    value: SetAttrValue::String(_),
                    ..
                }) if attr_name_or_path == ".b"
            )
        });
        if has_script_body {
            continue;
        }
        out.push(NodeRecoveryIssue {
            node_type: node.node_type.clone(),
            node_name: node.name.clone(),
            issue: RecoveryIssue::inferred_analysis(
                ".b",
                "script node recovered without a body attribute payload",
            ),
        });
    }

    out
}

fn check_reference_semantic_fallbacks(
    reference_files: &[ReferenceFileOp],
) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for reference in reference_files {
        if reference.namespace_defaulted {
            out.push(NodeRecoveryIssue {
                node_type: "reference".to_string(),
                node_name: reference.reference_node.clone(),
                issue: RecoveryIssue::inferred_analysis_with_provenance(
                    ".fn",
                    "reference namespace defaulted from reference node",
                    SemanticProvenance::MissingReferenceNamespace,
                ),
            });
        }
        if reference.file_type_defaulted {
            out.push(NodeRecoveryIssue {
                node_type: "reference".to_string(),
                node_name: reference.reference_node.clone(),
                issue: RecoveryIssue::inferred_analysis_with_provenance(
                    ".fn",
                    "reference file type defaulted to mayaBinary",
                    SemanticProvenance::MissingReferenceFileType,
                ),
            });
        }
        if reference.path_inferred_from_parent_include {
            out.push(NodeRecoveryIssue {
                node_type: "reference".to_string(),
                node_name: reference.reference_node.clone(),
                issue: RecoveryIssue::inferred_analysis_with_provenance(
                    ".fn",
                    "relative nested reference path inferred from parent include path",
                    SemanticProvenance::NestedReferenceIncludePath,
                ),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::check_script_nodes_have_body;
    use crate::scene::ir::{RecoveredAttrOp, RecoveredNode, SetAttrOp, SetAttrValue};

    #[test]
    fn analyzer_reports_script_nodes_without_body_attr() {
        let issues = check_script_nodes_have_body(&[
            RecoveredNode {
                node_type: "script".to_string(),
                name: "missingScriptBody".to_string(),
                parent: None,
                uid: None,
                attrs: vec![],
                decode_notes: vec![],
                create_flags: Default::default(),
            },
            RecoveredNode {
                node_type: "script".to_string(),
                name: "sharedScript".to_string(),
                parent: None,
                uid: None,
                attrs: vec![RecoveredAttrOp::SetAttr(SetAttrOp {
                    attr_name_or_path: ".b".to_string(),
                    array_size: None,
                    channel_hint: None,
                    lock: None,
                    keyable: None,
                    value: SetAttrValue::String("print(\"a\")".to_string()),
                })],
                decode_notes: vec![],
                create_flags: Default::default(),
            },
        ]);

        assert!(issues.iter().any(|issue| {
            issue.node_name == "missingScriptBody"
                && issue
                    .issue
                    .reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("without a body attribute payload")
        }));
    }
}
