use crate::{
    scene::ir::{NodeRecoveryIssue, RecoveredAttrOp, RecoveredNode, RecoveryIssue, SetAttrValue},
    typed_value_semantics::{TypedValueKind, TypedValueShape},
};

pub(crate) fn check_attr_value_shape_plausibility(
    nodes: &[RecoveredNode],
) -> Vec<NodeRecoveryIssue> {
    let mut out = Vec::new();
    for node in nodes {
        for attr in &node.attrs {
            let RecoveredAttrOp::SetAttr(op) = attr else {
                continue;
            };
            match &op.value {
                SetAttrValue::StringArray {
                    declared_count,
                    values,
                } if *declared_count != values.len() => {
                    out.push(NodeRecoveryIssue {
                        node_type: node.node_type.clone(),
                        node_name: node.name.clone(),
                        issue: RecoveryIssue::inferred_analysis(
                            &op.attr_name_or_path,
                            format!(
                                "stringArray count mismatch: declared={declared_count}, actual={}",
                                values.len()
                            ),
                        ),
                    });
                }
                SetAttrValue::TypedNumbers { value_type, values } => {
                    let invalid = TypedValueKind::from_name(value_type)
                        .map(|kind| match kind.shape() {
                            TypedValueShape::FixedElements(expected) => values.len() != expected,
                            TypedValueShape::MultipleOf(step) => values.len() % step != 0,
                            _ => false,
                        })
                        .unwrap_or(false);
                    if invalid {
                        out.push(NodeRecoveryIssue {
                            node_type: node.node_type.clone(),
                            node_name: node.name.clone(),
                            issue: RecoveryIssue::inferred_analysis(
                                &op.attr_name_or_path,
                                format!(
                                    "typed value shape mismatch: type={value_type}, values={}",
                                    values.len()
                                ),
                            ),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    out
}
