use super::{
    parse_ascii_scene, parse_ascii_scene_bytes,
    parse_create_node::parse_top_level_rename_uid_command,
    parse_set_attr::parse_specialized_set_attr_command,
};
use crate::{
    ma::ast::{ParsedAsciiRefEditRecord, ParsedNodeOp, ParsedOpaqueValueItem, ParsedSetAttrValue},
    mel::{self, MelSourceEncoding, MelSpecializedCommandForm},
    model::NumericValue,
};

fn wrap_refedit_fixture(snippet: &str) -> String {
    format!(
        concat!(
            "//Maya ASCII 2026 scene\n",
            "requires maya \"2026\";\n",
            "createNode reference -n \"refNode\";\n",
            "{snippet}\n",
        ),
        snippet = snippet,
    )
}

fn first_refedit_value(scene_text: &str) -> ParsedSetAttrValue {
    let mut scene = parse_ascii_scene(scene_text).expect("parse");
    let ParsedNodeOp::SetAttr(op) = scene.nodes[0].ops.remove(0) else {
        panic!("expected setAttr op");
    };
    op.value
}

fn first_command(scene_text: &str, head: &str) -> mel::MelTopLevelCommandFact {
    let facts = mel::collect_top_level_facts(scene_text);
    *facts
        .items
        .into_iter()
        .find_map(|item| match item {
            mel::MelTopLevelItemFact::Command(command) if command.head.as_ref() == head => {
                Some(command)
            }
            _ => None,
        })
        .expect("command")
}

fn opaque_typed_fixture() -> &'static str {
    include_str!("../../../../tests/fixtures/ma/opaque_typed_attrs.ma")
}

#[test]
fn specialized_rename_uid_command_parses_without_token_fallback() {
    let input = concat!(
        "//Maya ASCII 2026 scene\n",
        "createNode transform -n \"node1\";\n",
        "rename -uid \"12345678-1234-1234-1234-123456789abc\";\n",
    );

    let command = first_command(input, "rename");

    assert!(matches!(
        command.specialized.as_ref(),
        Some(MelSpecializedCommandForm::Rename(_))
    ));
    assert_eq!(
        parse_top_level_rename_uid_command(input, &command).expect("rename -uid"),
        "12345678-1234-1234-1234-123456789abc"
    );
}

#[test]
fn strict_string_entrypoint_rejects_top_level_proc() {
    let input = concat!(
        "//Maya ASCII 2026 scene\n",
        "global proc string hello() { return \"ok\"; }\n",
        "createNode script -n \"script1\";\n",
        "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
    );

    let error = parse_ascii_scene(input).expect_err("strict parse should fail");
    assert_eq!(
        error.to_string(),
        "unsupported ascii feature: unsupported Maya ASCII command: global proc"
    );
}

#[test]
fn bytes_entrypoint_tolerates_non_scene_top_level_items() {
    let input = concat!(
        "//Maya ASCII 2026 scene\n",
        "global proc string hello() { return \"ok\"; }\n",
        "createNode script -n \"script1\";\n",
        "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
    );

    let document = parse_ascii_scene_bytes(input.as_bytes()).expect("tolerant parse");

    assert_eq!(document.scene.nodes.len(), 1);
    assert_eq!(document.scene.nodes[0].node_type, "script");
    assert_eq!(document.scene.nodes[0].name, "script1");
}

#[test]
fn bytes_entrypoint_reports_detected_cp932_encoding() {
    let source = concat!(
        "//Maya ASCII 2026 scene\n",
        "createNode script -n \"script1\";\n",
        "    setAttr \".b\" -type \"string\" \"設定\";\n",
    );
    let (bytes, _, had_errors) = encoding_rs::SHIFT_JIS.encode(source);
    assert!(!had_errors);

    let document = parse_ascii_scene_bytes(bytes.as_ref()).expect("cp932 parse");

    assert_eq!(document.source_encoding, MelSourceEncoding::Cp932);
    assert_eq!(document.scene.nodes[0].name, "script1");
}

#[test]
fn strict_entrypoint_preserves_recognized_opaque_typed_values() {
    let scene = parse_ascii_scene(opaque_typed_fixture()).expect("parse opaque typed scene");

    let mesh_node = scene
        .nodes
        .iter()
        .find(|node| node.name == "meshShape1")
        .expect("mesh node");
    let opaque_values = mesh_node
        .ops
        .iter()
        .filter_map(|op| match op {
            ParsedNodeOp::SetAttr(op) => Some((&op.attr_name_or_path, &op.value)),
            ParsedNodeOp::AddAttr(_) => None,
        })
        .collect::<Vec<_>>();

    assert!(matches!(
        opaque_values[0],
        (
            attr_name,
            ParsedSetAttrValue::OpaqueTyped { value_type, items }
        ) if attr_name == ".fc[0]"
            && value_type == "polyFaces"
            && items.iter().any(|item| item == &ParsedOpaqueValueItem::Bare("mu".to_string()))
    ));
    assert!(matches!(
        opaque_values[1],
        (
            attr_name,
            ParsedSetAttrValue::OpaqueTyped { value_type, items }
        ) if attr_name == ".cd"
            && value_type == "dataPolyComponent"
            && items.iter().any(|item| item == &ParsedOpaqueValueItem::Bare("Index_Data".to_string()))
    ));
    let curve_node = scene
        .nodes
        .iter()
        .find(|node| node.name == "curveShape1")
        .expect("curve node");
    assert!(matches!(
        &curve_node.ops[0],
        ParsedNodeOp::SetAttr(op)
            if matches!(
                &op.value,
                ParsedSetAttrValue::OpaqueTyped { value_type, items }
                    if value_type == "nurbsCurve"
                        && items.iter().any(|item| item == &ParsedOpaqueValueItem::Bare("no".to_string()))
            )
    ));
}

#[test]
fn bytes_entrypoint_preserves_scene_after_opaque_typed_values() {
    let document =
        parse_ascii_scene_bytes(opaque_typed_fixture().as_bytes()).expect("tolerant parse");

    assert_eq!(document.scene.nodes.len(), 4);
    assert!(
        document
            .scene
            .nodes
            .iter()
            .any(|node| node.node_type == "script" && node.name == "scriptNode1")
    );
    assert!(
        document
            .scene
            .nodes
            .iter()
            .any(|node| node.node_type == "file" && node.name == "file1")
    );
}

#[test]
fn polyfaces_continuation_without_type_is_inferred_as_opaque() {
    let input = concat!(
        "//Maya ASCII 2026 scene\n",
        "requires maya \"2026\";\n",
        "createNode mesh -n \"meshShape1\";\n",
        "    setAttr \".fc[0:1]\" -type \"polyFaces\" f 4 0 1 2 3;\n",
        "    setAttr \".fc[2:3]\" f 4 4 5 6 7 mu 0 4 0 1 2 3;\n",
    );

    let scene = parse_ascii_scene(input).expect("parse");
    let mesh_node = scene
        .nodes
        .iter()
        .find(|node| node.name == "meshShape1")
        .expect("mesh node");

    assert!(matches!(
        &mesh_node.ops[1],
        ParsedNodeOp::SetAttr(op)
            if op.attr_name_or_path == ".fc[2:3]"
                && matches!(
                    &op.value,
                    ParsedSetAttrValue::OpaqueTyped { value_type, items }
                        if value_type == "polyFaces"
                            && items.iter().any(|item| item == &ParsedOpaqueValueItem::Bare("mu".to_string()))
                )
    ));
}

#[test]
fn matrix_xform_payload_is_preserved_as_opaque() {
    let input = concat!(
        "//Maya ASCII 2026 scene\n",
        "requires maya \"2026\";\n",
        "createNode transform -n \"node1\";\n",
        "    setAttr \".xm[0]\" -type \"matrix\" \"xform\" 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0;\n",
    );

    let scene = parse_ascii_scene(input).expect("parse");
    let node = scene
        .nodes
        .iter()
        .find(|node| node.name == "node1")
        .unwrap();

    assert!(matches!(
        &node.ops[0],
        ParsedNodeOp::SetAttr(op)
            if matches!(
                &op.value,
                ParsedSetAttrValue::OpaqueTyped { value_type, items }
                    if value_type == "matrix"
                        && items.first() == Some(&ParsedOpaqueValueItem::Quoted("xform".to_string()))
            )
    ));
}

#[test]
fn typed_number_values_accept_positive_exponent_tokens() {
    let input = concat!(
        "//Maya ASCII 2026 scene\n",
        "requires maya \"2026\";\n",
        "createNode mesh -n \"meshShape1\";\n",
        "    setAttr \".n[0]\" -type \"float3\" 1e+20 2 3;\n",
    );

    let scene = parse_ascii_scene(input).expect("parse");
    let node = scene
        .nodes
        .iter()
        .find(|node| node.name == "meshShape1")
        .expect("mesh node");

    assert!(matches!(
        &node.ops[0],
        ParsedNodeOp::SetAttr(op)
            if matches!(
                &op.value,
                ParsedSetAttrValue::TypedNumbers { value_type, values }
                    if value_type == "float3"
                        && values.first().copied() == Some(NumericValue::from_f64(1e20))
            )
    ));
}

#[test]
fn data_reference_edits_op3_fixture_is_preserved() {
    let input = wrap_refedit_fixture(include_str!(
        "../../../../tests/fixtures/refedit/sanitized/case_op3_empty_tail_ed_block01.ma"
    ));
    let value = first_refedit_value(&input);
    let ParsedSetAttrValue::DataReferenceEdits(value) = value else {
        panic!("expected dataReferenceEdits");
    };

    assert_eq!(value.groups.len(), 2);
    assert_eq!(value.groups[0].expected_count, 0);
    assert_eq!(value.groups[1].expected_count, 3);
    assert_eq!(value.groups[1].records.len(), 3);
    assert!(matches!(
        &value.groups[1].records[0],
        ParsedAsciiRefEditRecord::Op3(_, second, third)
            if second.contains("hyperGraphLayout.hyperPosition[") && third.is_empty()
    ));
}

#[test]
fn data_reference_edits_op0_fixture_is_preserved() {
    let input = wrap_refedit_fixture(include_str!(
        "../../../../tests/fixtures/refedit/sanitized/case_op0_flag_payload_ed_block02.ma"
    ));
    let value = first_refedit_value(&input);
    let ParsedSetAttrValue::DataReferenceEdits(value) = value else {
        panic!("expected dataReferenceEdits");
    };

    assert_eq!(value.groups.len(), 2);
    assert_eq!(value.groups[1].records.len(), 3);
    assert!(matches!(
        &value.groups[1].records[0],
        ParsedAsciiRefEditRecord::Op0(_, _, payload) if payload == "-s -r "
    ));
}

#[test]
fn data_reference_edits_op5_fixture_is_preserved() {
    let input = wrap_refedit_fixture(include_str!(
        "../../../../tests/fixtures/refedit/sanitized/case_op5_placeholder_ed_block01.ma"
    ));
    let value = first_refedit_value(&input);
    let ParsedSetAttrValue::DataReferenceEdits(value) = value else {
        panic!("expected dataReferenceEdits");
    };

    assert_eq!(value.root_node, "sym001");
    assert_eq!(value.groups.len(), 2);
    assert_eq!(value.groups[1].records.len(), 3);
    assert!(matches!(
        &value.groups[1].records[0],
        ParsedAsciiRefEditRecord::Op5 { sub, args }
            if *sub == 3
                && args.iter().any(|arg| arg.contains("placeHolderList[1]"))
                && args.last().is_some_and(String::is_empty)
    ));
}

#[test]
fn data_reference_edits_op5_without_empty_tail_is_preserved() {
    let input = wrap_refedit_fixture(concat!(
        "setAttr \".ed\" -type \"dataReferenceEdits\"\n",
        "\t\t\"rootRN\"\n",
        "\t\t\"rootRN\" 1\n",
        "\t\t5 2 \"rootRN\" \"rootNs:shapeSG.dagSetMembers\" \"rootRN.placeHolderList[7]\" \"otherNs:shapeSG.dsm\";\n",
    ));
    let value = first_refedit_value(&input);
    let ParsedSetAttrValue::DataReferenceEdits(value) = value else {
        panic!("expected dataReferenceEdits");
    };

    assert_eq!(value.groups.len(), 1);
    assert_eq!(value.groups[0].records.len(), 1);
    assert!(matches!(
        &value.groups[0].records[0],
        ParsedAsciiRefEditRecord::Op5 { sub, args }
            if *sub == 2
                && args.len() == 4
                && args.first().is_some_and(|arg| arg == "rootRN")
                && args.iter().any(|arg| arg.contains("placeHolderList[7]"))
                && args.last().is_some_and(|arg| arg.ends_with(".dsm"))
    ));
}

#[test]
fn data_reference_edits_op5_special_form_is_available() {
    let input = wrap_refedit_fixture(include_str!(
        "../../../../tests/fixtures/refedit/sanitized/case_op5_placeholder_ed_block01.ma"
    ));
    let command = first_command(&input, "setAttr");
    let special_form = command
        .specialized
        .as_ref()
        .expect("dataReferenceEdits special form");

    let MelSpecializedCommandForm::SetAttr(set_attr) = special_form else {
        panic!("expected setAttr special form");
    };
    assert_eq!(
        set_attr.value_kind,
        mel::MelSetAttrValueKind::DataReferenceEdits
    );
    assert_eq!(set_attr.values.len(), 23);
    assert_eq!(
        set_attr.values[0].value_text(input.as_str()).as_deref(),
        Some("sym001")
    );
    assert_eq!(
        set_attr.values[5].value_text(input.as_str()).as_deref(),
        Some("5")
    );
}

#[test]
fn data_reference_edits_op5_specialized_parser_preserves_groups() {
    let input = wrap_refedit_fixture(include_str!(
        "../../../../tests/fixtures/refedit/sanitized/case_op5_placeholder_ed_block01.ma"
    ));
    let command = first_command(&input, "setAttr");
    let op = parse_specialized_set_attr_command(input.as_str(), &command)
        .expect("specialized parse")
        .expect("specialized setAttr");
    let ParsedSetAttrValue::DataReferenceEdits(value) = op.value else {
        panic!("expected dataReferenceEdits");
    };

    assert_eq!(value.groups.len(), 2);
    assert_eq!(value.groups[1].records.len(), 3);
}

#[test]
fn specialized_set_attr_string_reads_simple_raw_item_without_retokenize() {
    let input = "setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";";
    let command = first_command(input, "setAttr");

    let op = parse_specialized_set_attr_command(input, &command)
        .expect("specialized parse")
        .expect("specialized setAttr");

    assert_eq!(op.value, ParsedSetAttrValue::String("print \"ok\";".into()));
}

#[test]
fn specialized_set_attr_string_reads_grouped_expression_without_retokenize() {
    let input = "setAttr \".b\" -type \"string\" (\"foo\" + \"bar\");";
    let command = first_command(input, "setAttr");

    let op = parse_specialized_set_attr_command(input, &command)
        .expect("specialized parse")
        .expect("specialized setAttr");

    assert_eq!(op.value, ParsedSetAttrValue::String("foobar".into()));
}

#[test]
fn data_reference_edits_mixed_fixture_is_split_into_groups() {
    let input = wrap_refedit_fixture(include_str!(
        "../../../../tests/fixtures/refedit/sanitized/case_mixed_op2_op0_ed_block02.ma"
    ));
    let value = first_refedit_value(&input);
    let ParsedSetAttrValue::DataReferenceEdits(value) = value else {
        panic!("expected dataReferenceEdits");
    };

    assert_eq!(value.groups.len(), 2);
    assert_eq!(value.groups[0].records.len(), 2);
    assert_eq!(value.groups[1].records.len(), 3);
    assert!(matches!(
        &value.groups[0].records[0],
        ParsedAsciiRefEditRecord::Op2(_, second, third)
            if second == "lw[0:15]" && third == " -s 16 0 0"
    ));
    assert!(matches!(
        &value.groups[1].records[0],
        ParsedAsciiRefEditRecord::Op0(_, _, payload) if payload == "-s -r "
    ));
}

#[test]
fn data_reference_edits_empty_fixture_is_preserved() {
    let input = wrap_refedit_fixture(include_str!(
        "../../../../tests/fixtures/refedit/sanitized/case_empty_root_ed_block06.ma"
    ));
    let value = first_refedit_value(&input);
    let ParsedSetAttrValue::DataReferenceEdits(value) = value else {
        panic!("expected dataReferenceEdits");
    };

    assert_eq!(value.root_node, "sym001");
    assert_eq!(value.groups.len(), 1);
    assert_eq!(value.groups[0].expected_count, 0);
    assert!(value.groups[0].records.is_empty());
}
