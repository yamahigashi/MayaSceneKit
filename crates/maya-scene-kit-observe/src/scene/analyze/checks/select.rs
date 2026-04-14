use crate::scene::ir::{NodeRecoveryIssue, RecoveryIssue, SelectBlock};

pub(crate) fn check_select_block_plausibility(
    select_blocks: &[SelectBlock],
) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for block in select_blocks {
        if block.target.trim().is_empty() {
            out.push(NodeRecoveryIssue {
                node_type: "<scene>".to_string(),
                node_name: "<select>".to_string(),
                issue: RecoveryIssue::inferred_analysis("<select>", "select block target is empty"),
            });
        }
        if block.ops.is_empty() {
            out.push(NodeRecoveryIssue {
                node_type: "<scene>".to_string(),
                node_name: block.target.clone(),
                issue: RecoveryIssue::inferred_analysis(
                    "<select>",
                    "select block has no attribute operations",
                ),
            });
        }
    }
    out
}
