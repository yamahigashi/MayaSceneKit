use std::collections::HashSet;

use crate::scene::ir::{
    LinkOp, NodeRecoveryIssue, RecoveredAttrOp, RecoveredNode, RecoveryIssue, ReferenceFileOp,
    SelectBlock,
};

fn normalize_node_name(value: &str) -> &str {
    value.trim_start_matches(':')
}

fn node_name_from_plug(path: &str) -> &str {
    normalize_node_name(path.split('.').next().unwrap_or(path))
}

pub(crate) fn check_graph_consistency(
    nodes: &[RecoveredNode],
    links: &[LinkOp],
    select_blocks: &[SelectBlock],
    reference_files: &[ReferenceFileOp],
) -> Vec<NodeRecoveryIssue> {
    let known_nodes = nodes
        .iter()
        .map(|node| normalize_node_name(&node.name).to_string())
        .collect::<HashSet<_>>();
    let mut out = Vec::new();

    for link in links {
        match link {
            LinkOp::Connect { src, dst, .. } => {
                for (label, endpoint) in [("src", src.as_str()), ("dst", dst.as_str())] {
                    let node_name = node_name_from_plug(endpoint);
                    if known_nodes.contains(node_name) {
                        continue;
                    }
                    out.push(NodeRecoveryIssue {
                        node_type: "<scene>".to_string(),
                        node_name: endpoint.to_string(),
                        issue: RecoveryIssue::inferred_analysis(
                            "<graph>",
                            format!(
                                "connectAttr {label} endpoint references missing node '{node_name}'"
                            ),
                        ),
                    });
                }
            }
            LinkOp::Relationship { head, tail, .. } => {
                let head_name = node_name_from_plug(head);
                if !known_nodes.contains(head_name) {
                    out.push(NodeRecoveryIssue {
                        node_type: "<scene>".to_string(),
                        node_name: head.clone(),
                        issue: RecoveryIssue::inferred_analysis(
                            "<graph>",
                            format!("relationship head references missing node '{head_name}'"),
                        ),
                    });
                }
                for endpoint in tail {
                    let tail_name = node_name_from_plug(endpoint);
                    if known_nodes.contains(tail_name) {
                        continue;
                    }
                    out.push(NodeRecoveryIssue {
                        node_type: "<scene>".to_string(),
                        node_name: endpoint.clone(),
                        issue: RecoveryIssue::inferred_analysis(
                            "<graph>",
                            format!("relationship tail references missing node '{tail_name}'"),
                        ),
                    });
                }
            }
        }
    }

    for block in select_blocks {
        let target = normalize_node_name(&block.target);
        if known_nodes.contains(target) {
            continue;
        }
        out.push(NodeRecoveryIssue {
            node_type: "<scene>".to_string(),
            node_name: block.target.clone(),
            issue: RecoveryIssue::inferred_analysis(
                "<graph>",
                format!("select target references missing node '{target}'"),
            ),
        });
    }

    for reference in reference_files {
        let node_name = normalize_node_name(&reference.reference_node);
        if known_nodes.contains(node_name) {
            continue;
        }
        out.push(NodeRecoveryIssue {
            node_type: "reference".to_string(),
            node_name: reference.reference_node.to_string(),
            issue: RecoveryIssue::inferred_analysis(
                ".fn",
                format!("reference file record points at missing reference node '{node_name}'"),
            ),
        });
    }

    for node in nodes {
        for attr in &node.attrs {
            let RecoveredAttrOp::RefEdit { attr_name, data } = attr else {
                continue;
            };
            let root_name = normalize_node_name(&data.root_node);
            if known_nodes.contains(root_name) {
                continue;
            }
            out.push(NodeRecoveryIssue {
                node_type: node.node_type.to_string(),
                node_name: node.name.clone(),
                issue: RecoveryIssue::inferred_analysis(
                    attr_name.as_ref(),
                    format!("reference edit root references missing node '{root_name}'"),
                ),
            });
        }
    }

    out
}
