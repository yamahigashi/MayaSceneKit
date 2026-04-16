use std::collections::HashMap;

use maya_scene_kit_observe::scene::model::{LinkOp, SelectBlock, SelectBlockNote, SelectBlockOp};
use maya_scene_kit_observe::scene::recovery::AngularAttrKind;

use crate::scene::emit::ma::{
    add_attr::render_add_attr_op,
    format::escape_ma_string,
    set_attr::{SetAttrRenderContext, render_set_attr_op_with_render_context},
    units::{AngularRenderUnit, TimeRenderContext},
};

pub(in crate::scene) fn render_select_block(
    block: &SelectBlock,
    time_render_context: Option<&TimeRenderContext>,
    angular_render_unit: AngularRenderUnit,
    node_angular_attrs: &HashMap<String, HashMap<String, AngularAttrKind>>,
) -> Vec<String> {
    let set_attr_render_context = SetAttrRenderContext {
        time_render_context,
        angular_render_unit,
        angular_attrs: resolve_select_target_angular_attrs(&block.target, node_angular_attrs),
    };
    let mut lines = vec![format!("select -ne {};", block.target)];
    lines.extend(block.notes.iter().map(render_select_block_note));
    for op in &block.ops {
        match op {
            SelectBlockOp::AddAttr(op) => {
                if let Some(add_attr) = render_add_attr_op(op) {
                    lines.push(format!("\t{add_attr}"));
                }
            }
            SelectBlockOp::SetAttr(op) => lines.push(format!(
                "\t{}",
                render_set_attr_op_with_render_context(op, set_attr_render_context)
            )),
        }
    }
    lines.push(String::new());
    lines
}

pub(crate) fn render_link_op(link: &LinkOp) -> String {
    match link {
        LinkOp::Connect { src, dst, mode, .. } => format_connectattr(src, dst, *mode),
        LinkOp::Relationship {
            kind, head, tail, ..
        } => {
            let tail_render = tail
                .iter()
                .map(|target| format!("\"{}\"", escape_ma_string(target)))
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "relationship \"{}\" \"{}\" {};",
                escape_ma_string(kind),
                escape_ma_string(head),
                tail_render
            )
        }
    }
}

fn render_select_block_note(note: &SelectBlockNote) -> String {
    match note {
        SelectBlockNote::MissingTarget { placeholder } => {
            format!("\t//decode-note: missing SLCT target; emitted placeholder {placeholder}")
        }
    }
}

fn format_connectattr(src: &str, dst: &str, mode: u8) -> String {
    let na_flag = if (mode & 0x01) != 0 { " -na" } else { "" };
    let lock_flag = if (mode & 0x02) != 0 { " -l on" } else { "" };
    format!(
        "connectAttr \"{}\" \"{}\"{}{};",
        escape_ma_string(src),
        escape_ma_string(dst),
        na_flag,
        lock_flag
    )
}

fn resolve_select_target_angular_attrs<'a>(
    target: &str,
    node_angular_attrs: &'a HashMap<String, HashMap<String, AngularAttrKind>>,
) -> Option<&'a HashMap<String, AngularAttrKind>> {
    let mut node_name = target.trim();
    if let Some(stripped) = node_name.strip_prefix(':') {
        node_name = stripped;
    }
    if let Some(last) = node_name.rsplit('|').next() {
        node_name = last;
    }
    node_angular_attrs.get(node_name)
}
