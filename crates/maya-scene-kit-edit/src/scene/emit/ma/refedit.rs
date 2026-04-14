use maya_scene_kit_observe::scene::{RefEditData, RefEditRecord};

use crate::scene::emit::ma::format::escape_ma_string;

pub(crate) fn format_reference_edits_setattr_from_data(
    attr_path: &str,
    data: &RefEditData,
) -> String {
    let mut lines = vec![format!(
        "setAttr \"{attr_path}\" -type \"dataReferenceEdits\" "
    )];
    lines.push(format!("\t\t\"{}\"", escape_ma_string(&data.root_node)));
    for (idx, group) in data.groups.iter().enumerate() {
        lines.push(format!(
            "\t\t\"{}\" {}",
            escape_ma_string(&group.name),
            group.expected_count
        ));
        for rec in data.grouped_records.get(idx).into_iter().flatten() {
            match rec {
                RefEditRecord::Context(node, index) => {
                    lines.push(format!("\t\t\"{}\" {index}", escape_ma_string(node)));
                }
                RefEditRecord::Op0(a, b, c) => {
                    lines.push(format!(
                        "\t\t0 \"{}\" \"{}\" ",
                        escape_ma_string(a),
                        escape_ma_string(b)
                    ));
                    lines.push(format!("\t\t\"{}\"", escape_ma_string(c)));
                }
                RefEditRecord::Op1(args) => {
                    if args.is_empty() {
                        lines.push("\t\t1".to_string());
                    } else {
                        let rendered = args
                            .iter()
                            .map(|arg| format!("\"{}\"", escape_ma_string(arg)))
                            .collect::<Vec<_>>()
                            .join(" ");
                        lines.push(format!("\t\t1 {rendered}"));
                    }
                }
                RefEditRecord::Op2(a, b, c) => {
                    lines.push(format!(
                        "\t\t2 \"{}\" \"{}\" \"{}\"",
                        escape_ma_string(a),
                        escape_ma_string(b),
                        escape_ma_string(c)
                    ));
                }
                RefEditRecord::Op3(a, b, c) => {
                    lines.push(format!(
                        "\t\t3 \"{}\" \"{}\" \"{}\"",
                        escape_ma_string(a),
                        escape_ma_string(b),
                        escape_ma_string(c)
                    ));
                }
                RefEditRecord::Op5 { sub, args } => {
                    let mut render_args = args.clone();
                    while render_args.len() < *sub as usize {
                        render_args.push(String::new());
                    }
                    if render_args.is_empty() {
                        lines.push(format!("\t\t5 {sub}"));
                    } else {
                        let rendered = render_args
                            .iter()
                            .map(|arg| format!("\"{}\"", escape_ma_string(arg)))
                            .collect::<Vec<_>>()
                            .join(" ");
                        lines.push(format!("\t\t5 {sub} {rendered}"));
                    }
                }
            }
        }
    }
    lines.push("\t\t;".to_string());
    lines.join("\n")
}
