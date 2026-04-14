use crate::scene::ir::{LinkOp, NodeRecoveryIssue, RecoveryIssue};

pub(crate) fn check_link_shape_plausibility(links: &[LinkOp]) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for link in links {
        match link {
            LinkOp::Connect { src, dst, .. } => {
                if !src.contains('.') {
                    out.push(NodeRecoveryIssue {
                        node_type: "<scene>".to_string(),
                        node_name: "<links>".to_string(),
                        issue: RecoveryIssue::inferred_analysis(
                            src,
                            "connect source plug has no '.' separator",
                        ),
                    });
                }
                if !dst.contains('.') {
                    out.push(NodeRecoveryIssue {
                        node_type: "<scene>".to_string(),
                        node_name: "<links>".to_string(),
                        issue: RecoveryIssue::inferred_analysis(
                            dst,
                            "connect destination plug has no '.' separator",
                        ),
                    });
                }
            }
            LinkOp::Relationship {
                kind, head, tail, ..
            } => {
                if kind.trim().is_empty() {
                    out.push(NodeRecoveryIssue {
                        node_type: "<scene>".to_string(),
                        node_name: "<links>".to_string(),
                        issue: RecoveryIssue::inferred_analysis(
                            "<relationship>",
                            "relationship kind is empty",
                        ),
                    });
                }
                if head.trim().is_empty() {
                    out.push(NodeRecoveryIssue {
                        node_type: "<scene>".to_string(),
                        node_name: "<links>".to_string(),
                        issue: RecoveryIssue::inferred_analysis(
                            "<relationship>",
                            "relationship head is empty",
                        ),
                    });
                }
                if tail.is_empty() {
                    out.push(NodeRecoveryIssue {
                        node_type: "<scene>".to_string(),
                        node_name: "<links>".to_string(),
                        issue: RecoveryIssue::inferred_analysis(
                            "<relationship>",
                            "relationship tail is empty",
                        ),
                    });
                }
            }
        }
    }
    out
}
