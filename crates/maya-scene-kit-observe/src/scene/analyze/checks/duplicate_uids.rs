use std::collections::HashMap;

use crate::scene::ir::{NodeRecoveryIssue, RecoveredNode, RecoveryIssue};

pub(crate) fn check_duplicate_uids(nodes: &[RecoveredNode]) -> Vec<NodeRecoveryIssue> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for node in nodes {
        let Some(uid) = node.uid.as_deref() else {
            continue;
        };
        *counts.entry(uid).or_insert(0) += 1;
    }

    let mut out = Vec::new();
    for node in nodes {
        let Some(uid) = node.uid.as_deref() else {
            continue;
        };
        let count = counts.get(uid).copied().unwrap_or(0);
        if count <= 1 {
            continue;
        }
        out.push(NodeRecoveryIssue {
            node_type: node.node_type.clone(),
            node_name: node.name.clone(),
            issue: RecoveryIssue::inferred_analysis(
                "<uid>",
                format!("uid '{uid}' appears on {count} recovered nodes"),
            ),
        });
    }

    out
}
