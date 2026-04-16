use crate::scene::ir::{NodeRecoveryIssue, RecoveredAttrOp, RecoveredNode, RecoveryIssue};

pub(crate) fn check_refedit_group_counts(nodes: &[RecoveredNode]) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for node in nodes {
        for attr in &node.attrs {
            let RecoveredAttrOp::RefEdit { attr_name, data } = attr else {
                continue;
            };
            for (idx, group) in data.groups.iter().enumerate() {
                let actual = data.grouped_records.get(idx).map(|v| v.len()).unwrap_or(0);
                if actual == group.expected_count as usize {
                    continue;
                }
                out.push(NodeRecoveryIssue {
                    node_type: node.node_type.to_string(),
                    node_name: node.name.clone(),
                    issue: RecoveryIssue::inferred_analysis(
                        attr_name.as_ref(),
                        format!(
                            "reference edit group count mismatch: group='{}' expected={} actual={actual}",
                            group.name, group.expected_count
                        ),
                    ),
                });
            }
            if let Some(unknown_tail) = &data.unknown_tail {
                out.push(NodeRecoveryIssue {
                    node_type: node.node_type.to_string(),
                    node_name: node.name.clone(),
                    issue: RecoveryIssue::inferred_refedit_unknown_tail(
                        attr_name.as_ref(),
                        unknown_tail,
                    ),
                });
            }
        }
    }
    out
}
