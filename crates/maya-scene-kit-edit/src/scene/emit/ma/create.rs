use std::collections::HashMap;

use maya_scene_kit_observe::scene::{
    model::{LinkOp, SelectBlock, SelectBlockNote, SelectBlockOp},
    recovery::AngularAttrKind,
};

use crate::scene::emit::ma::{
    add_attr::render_add_attr_op,
    format::{
        BareWordPosition, EmitContext, escape_ma_comment, escape_ma_string, render_ma_bare_word,
    },
    set_attr::{SetAttrRenderContext, render_set_attr_op_with_render_context},
    units::{AngularRenderUnit, TimeRenderContext},
};

pub(in crate::scene) fn render_select_block(
    block: &SelectBlock,
    time_render_context: Option<&TimeRenderContext>,
    angular_render_unit: AngularRenderUnit,
    node_angular_attrs: &HashMap<String, HashMap<String, AngularAttrKind>>,
    context: &mut EmitContext,
) -> Vec<String> {
    context.set_target("select", &block.target);
    let target = render_ma_bare_word(
        &block.target,
        BareWordPosition::SelectTarget,
        context,
        "select.target",
    )
    .expect("select targets support quoted literals");
    let set_attr_render_context = SetAttrRenderContext {
        time_render_context,
        angular_render_unit,
        angular_attrs: resolve_select_target_angular_attrs(&block.target, node_angular_attrs),
    };
    let mut lines = vec![format!("select -ne {target};")];
    lines.extend(block.notes.iter().map(render_select_block_note));
    for op in &block.ops {
        match op {
            SelectBlockOp::AddAttr(op) => {
                if let Some(add_attr) = render_add_attr_op(op, context) {
                    lines.push(format!("\t{add_attr}"));
                }
            }
            SelectBlockOp::SetAttr(op) => lines.push(format!(
                "\t{}",
                render_set_attr_op_with_render_context(op, set_attr_render_context, context)
            )),
        }
    }
    lines.push(String::new());
    lines
}

pub(crate) fn render_link_op(link: &LinkOp, context: &mut EmitContext) -> String {
    match link {
        LinkOp::Connect { src, dst, mode, .. } => format_connectattr(src, dst, *mode, context),
        LinkOp::Relationship {
            kind, head, tail, ..
        } => {
            context.set_target("relationship", head);
            let tail_render = tail
                .iter()
                .map(|target| {
                    format!(
                        "\"{}\"",
                        escape_ma_string(target, context, "relationship.tail")
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "relationship \"{}\" \"{}\" {};",
                escape_ma_string(kind, context, "relationship.kind"),
                escape_ma_string(head, context, "relationship.head"),
                tail_render
            )
        }
    }
}

fn render_select_block_note(note: &SelectBlockNote) -> String {
    match note {
        SelectBlockNote::MissingTarget { placeholder } => {
            format!(
                "\t//decode-note: missing SLCT target; emitted placeholder {}",
                escape_ma_comment(placeholder)
            )
        }
    }
}

fn format_connectattr(src: &str, dst: &str, mode: u8, context: &mut EmitContext) -> String {
    context.set_target("connectAttr", src);
    let na_flag = if (mode & 0x01) != 0 { " -na" } else { "" };
    let lock_flag = if (mode & 0x02) != 0 { " -l on" } else { "" };
    format!(
        "connectAttr \"{}\" \"{}\"{}{};",
        escape_ma_string(src, context, "connectAttr.src"),
        escape_ma_string(dst, context, "connectAttr.dst"),
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
