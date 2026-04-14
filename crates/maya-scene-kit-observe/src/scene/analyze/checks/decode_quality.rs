use std::collections::HashMap;

use crate::scene::ir::{
    NodeRecoveryIssue, RecoveryIssue, SceneArtifacts, SchemaDecodeAttemptResult,
};

pub(crate) fn check_partial_decode_quality(artifacts: &SceneArtifacts) -> Vec<NodeRecoveryIssue> {
    let mut grouped: HashMap<(String, String), usize> = HashMap::new();
    for record in &artifacts.decode_qualities {
        if !matches!(record.quality, SchemaDecodeAttemptResult::Partial) {
            continue;
        }
        *grouped
            .entry((record.chunk_ref.form.clone(), record.chunk_ref.tag.clone()))
            .or_insert(0) += 1;
    }

    let mut out = Vec::new();
    let mut entries = grouped.into_iter().collect::<Vec<_>>();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for ((form, tag), count) in entries {
        out.push(NodeRecoveryIssue {
            node_type: "<scene>".to_string(),
            node_name: format!("{form}:{tag}"),
            issue: RecoveryIssue::inferred_analysis(
                "<decode-quality>",
                format!("partial decode observed for form={form} tag={tag} count={count}"),
            ),
        });
    }

    out
}
