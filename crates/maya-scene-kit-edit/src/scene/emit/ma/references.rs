use std::collections::{HashMap, HashSet};

use maya_scene_kit_observe::scene::model::ReferenceFileOp;

use crate::{
    reference_semantics::{
        derive_parent_reference_node, reference_depth, render_reference_options_clause,
    },
    scene::emit::ma::format::escape_ma_string,
};

pub(crate) fn render_reference_file_ops(reference_files: &[ReferenceFileOp]) -> Vec<String> {
    let order = order_reference_file_ops_for_ma(reference_files);
    let mut lines = Vec::new();

    for idx in &order {
        lines.push(render_reference_file_rdi(&reference_files[*idx]));
    }
    for idx in order {
        if reference_depth(&reference_files[idx].reference_node) == 1 {
            lines.push(render_reference_file_load(&reference_files[idx]));
        }
    }

    lines
}

pub(crate) fn order_reference_file_ops_for_ma(reference_files: &[ReferenceFileOp]) -> Vec<usize> {
    fn visit_reference_subtree(
        idx: usize,
        reference_files: &[ReferenceFileOp],
        children_by_parent: &HashMap<String, Vec<usize>>,
        visited: &mut HashSet<usize>,
        ordered: &mut Vec<usize>,
    ) {
        if !visited.insert(idx) {
            return;
        }
        ordered.push(idx);
        if let Some(children) = children_by_parent.get(reference_files[idx].reference_node.as_ref())
        {
            for child_idx in children {
                visit_reference_subtree(
                    *child_idx,
                    reference_files,
                    children_by_parent,
                    visited,
                    ordered,
                );
            }
        }
    }

    let known_nodes = reference_files
        .iter()
        .map(|reference| reference.reference_node.as_ref())
        .collect::<HashSet<_>>();
    let mut children_by_parent: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, reference) in reference_files.iter().enumerate() {
        if let Some(parent) = derive_parent_reference_node(&reference.reference_node) {
            children_by_parent.entry(parent).or_default().push(idx);
        }
    }

    let mut ordered = Vec::with_capacity(reference_files.len());
    let mut visited = HashSet::new();
    for (idx, reference) in reference_files.iter().enumerate() {
        let is_root_or_orphan = derive_parent_reference_node(&reference.reference_node)
            .map(|parent| !known_nodes.contains(parent.as_str()))
            .unwrap_or(true);
        if is_root_or_orphan {
            visit_reference_subtree(
                idx,
                reference_files,
                &children_by_parent,
                &mut visited,
                &mut ordered,
            );
        }
    }

    for idx in 0..reference_files.len() {
        visit_reference_subtree(
            idx,
            reference_files,
            &children_by_parent,
            &mut visited,
            &mut ordered,
        );
    }

    ordered
}

fn reference_option_part(reference: &ReferenceFileOp) -> String {
    reference
        .options
        .as_ref()
        .and_then(|s| render_reference_options_clause(s).map(|_| s.trim().to_string()))
        .map(|s| format!(" -op \"{}\"", escape_ma_string(&s)))
        .unwrap_or_default()
}

fn render_reference_file_rdi(reference: &ReferenceFileOp) -> String {
    let depth = reference_depth(&reference.reference_node);
    let op_part = reference_option_part(reference);
    format!(
        "file -rdi {depth} -ns \"{}\" -rfn \"{}\"{} -typ \"{}\" \"{}\";",
        escape_ma_string(&reference.namespace),
        escape_ma_string(&reference.reference_node),
        op_part,
        reference.file_type,
        escape_ma_string(&reference.path)
    )
}

fn render_reference_file_load(reference: &ReferenceFileOp) -> String {
    let op_part = reference_option_part(reference);
    format!(
        "file -r -ns \"{}\" -dr 1 -rfn \"{}\"{} -typ \"{}\" \"{}\";",
        escape_ma_string(&reference.namespace),
        escape_ma_string(&reference.reference_node),
        op_part,
        reference.file_type,
        escape_ma_string(&reference.path)
    )
}
