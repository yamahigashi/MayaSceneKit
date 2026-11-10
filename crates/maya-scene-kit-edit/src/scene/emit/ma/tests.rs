use std::{collections::HashMap, path::Path};

use maya_scene_kit_formats::{
    ma::parse::parse_ascii_scene,
    mb::{HeadMetadata, MbRequiresEntry},
    mel::{MelTopLevelItemFact, collect_top_level_facts},
};
use maya_scene_kit_observe::scene::{
    forensics::{RecoveryForensics, TypeIdResolverStatus},
    model::*,
};

use crate::scene::ops::{BestEffortRenderData, render_best_effort_ma};

struct Rendered {
    maya_ascii: String,
    issues: Vec<maya_scene_kit_observe::scene::forensics::NodeRecoveryIssue>,
}

fn recovered() -> &'static maya_scene_kit_observe::scene::recovery::MbRecoveryBundle {
    static RECOVERED: once_cell::sync::Lazy<
        maya_scene_kit_observe::scene::recovery::MbRecoveryBundle,
    > = once_cell::sync::Lazy::new(|| {
        maya_scene_kit_observe::scene::recovery::recover_mb_scene(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/02/sphere.mb"),
            &Default::default(),
        )
        .unwrap()
    });
    &RECOVERED
}

#[path = "../../../../tests/support/mb_chunks.rs"]
mod mb_chunks;

fn recovered_with_note() -> maya_scene_kit_observe::scene::recovery::MbRecoveryBundle {
    use mb_chunks::{build_mb_chunk, build_mb_form_with_alignment, build_mb_root};
    let bytes = build_mb_root(&[build_mb_form_with_alignment(
        "XFRM",
        &[
            build_mb_chunk("CREA", b"Example\0"),
            build_mb_chunk("EXMP", b"Sample\0"),
        ],
        4,
    )]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.mb");
    std::fs::write(&path, bytes).unwrap();
    maya_scene_kit_observe::scene::recovery::recover_mb_scene(&path, &Default::default()).unwrap()
}

fn node() -> RecoveredNode {
    RecoveredNode {
        node_type: "transform".into(),
        name: "Example".into(),
        parent: None,
        uid: None,
        attrs: vec![],
        decode_notes: vec![],
        create_flags: Default::default(),
    }
}

fn scene() -> RecoveredScene {
    IrSceneModel::default().into()
}

fn render(header: HeadMetadata, scene_model: RecoveredScene, path: &str, name: &str) -> Rendered {
    let result = render_best_effort_ma(BestEffortRenderData {
        metadata: header.into(),
        scene_model,
        forensics: RecoveryForensics {
            raw_chunks: vec![],
            decode_qualities: vec![],
            typeid_resolver_status: TypeIdResolverStatus::Provided,
        },
        issues: vec![],
        source_path: Path::new(path),
        output_name: name,
        angular_attrs_by_node: HashMap::new(),
        embed_metadata: true,
    });
    Rendered {
        maya_ascii: result.maya_ascii,
        issues: result.issues,
    }
}

fn output(header: HeadMetadata, model: RecoveredScene) -> Rendered {
    render(header, model, "asset/example/file.mb", "Example.ma")
}

fn baseline(value: &str) -> String {
    "Example".chars().cycle().take(value.len()).collect()
}

fn hostile_values() -> Vec<String> {
    let mut values: Vec<String> = [
        "\n",
        "\r",
        "\r\n",
        "\t",
        "\"",
        "\\",
        ";",
        "\u{0060}",
        "\0",
        "\u{001a}",
        "\u{007f}",
        "\u{0080}",
        "\u{0085}",
        "\u{009f}",
        "\u{2028}",
        "\u{2029}",
        "\\n",
        "\\x0A",
        "\\\\\"",
        "Sample\\",
        "Example\n\"\\;\u{0060}Sample",
        "Example\npython(\"print(1)\");",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    values.extend(['\u{0001}', '\u{000b}', '\u{000c}', '\u{001f}'].map(|c| c.to_string()));
    values
}

fn heads(text: &str) -> Vec<String> {
    let facts = collect_top_level_facts(text);
    facts
        .items
        .iter()
        .map(|item| match item {
            MelTopLevelItemFact::Command(command) => command.head.to_string(),
            MelTopLevelItemFact::Proc(_) => "<proc>".into(),
            MelTopLevelItemFact::Other(_) => "<other>".into(),
        })
        .collect()
}

fn normalized(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .map(|c| match c {
            '\0' | '\u{001a}' | '\u{0085}' | '\u{2028}' | '\u{2029}' => '\u{fffd}',
            _ => c,
        })
        .collect()
}

fn string_attr(path: &str, value: SetAttrValue) -> RecoveredAttrOp {
    RecoveredAttrOp::SetAttr(SetAttrOp {
        attr_name_or_path: path.into(),
        array_size: None,
        channel_hint: None,
        lock: None,
        keyable: None,
        value,
    })
}

#[test]
fn comments_cannot_add_commands_or_raw_control_characters() {
    for (value, escaped) in [
        ("\0", "\\x00"),
        ("\r", "\\x0D"),
        ("\n", "\\x0A"),
        ("\r\n", "\\x0D\\x0A"),
        ("\t", "\\x09"),
        ("\u{007f}", "\\x7F"),
        ("\u{0080}", "\\x80"),
        ("\u{0085}", "\\x85"),
        ("\u{009f}", "\\x9F"),
        ("\u{2028}", "\\u2028"),
        ("\u{2029}", "\\u2029"),
    ] {
        let rendered = render(HeadMetadata::default(), scene(), "Example.mb", value);
        assert!(
            rendered
                .maya_ascii
                .contains(&format!("//Name: {escaped}\n"))
        );
    }
    for value in hostile_values() {
        for position in 0..6 {
            let make = |value: &str| {
                let mut header = HeadMetadata::default();
                let mut model = scene();
                let mut path = "asset/example/file.mb";
                let mut name = "Example.ma";
                match position {
                    0 => header.chng = Some(value.into()),
                    1 => header.vers = Some(value.into()),
                    2 => path = value,
                    3 => name = value,
                    4 => {
                        let mut node = node();
                        let mut note = recovered_with_note()
                            .scene
                            .nodes
                            .iter()
                            .flat_map(|node| &node.decode_notes)
                            .next()
                            .unwrap()
                            .clone();
                        note.attr_name = value.into();
                        note.reason = Some(value.into());
                        node.decode_notes.push(note);
                        model.nodes.push(node);
                    }
                    _ => model.select_blocks.push(SelectBlock {
                        target: "Example".into(),
                        notes: vec![SelectBlockNote::MissingTarget {
                            placeholder: value.into(),
                        }],
                        ops: vec![],
                        trace: None,
                        confidence: recovered().scene.select_blocks[0].confidence,
                    }),
                }
                render(header, model, path, name)
            };
            let reference = make(&baseline(&value));
            let actual = make(&value);
            assert_eq!(
                heads(&actual.maya_ascii),
                heads(&reference.maya_ascii),
                "position {position}, {value:?}"
            );
            for line in actual
                .maya_ascii
                .split('\n')
                .filter(|line| line.trim_start().starts_with("//"))
            {
                assert!(
                    !line
                        .trim_start_matches('\t')
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')),
                    "{line:?}"
                );
            }
        }
    }
}

fn quoted_scene(value: &str) -> (HeadMetadata, RecoveredScene) {
    let mut header = HeadMetadata {
        vers: Some(value.into()),
        ..Default::default()
    };
    header.file_info.push((value.into(), value.into()));
    header.requires.push(MbRequiresEntry {
        plugin_name: value.into(),
        version: value.into(),
        options: None,
    });
    let mut model = scene();
    let mut node = node();
    node.name = value.into();
    node.parent = Some(value.into());
    node.uid = Some(value.into());
    node.attrs
        .push(string_attr(value, SetAttrValue::String(value.into())));
    node.attrs.push(string_attr(
        ".ExampleArray",
        SetAttrValue::StringArray {
            declared_count: 1,
            values: vec![value.into()],
        },
    ));
    node.attrs.push(string_attr(
        ".ExampleComponents",
        SetAttrValue::ComponentList(vec![value.into()]),
    ));
    model.nodes.push(node);
    model.links.push(LinkOp::Connect {
        src: value.into(),
        dst: value.into(),
        mode: 0,
        trace: None,
        confidence: recovered().scene.select_blocks[0].confidence,
    });
    model.links.push(LinkOp::Relationship {
        kind: value.into(),
        head: value.into(),
        tail: vec![value.into()],
        trace: None,
        confidence: recovered().scene.select_blocks[0].confidence,
    });
    model.reference_files.push(ReferenceFileOp {
        path: value.into(),
        namespace: value.into(),
        reference_node: value.into(),
        file_type: value.into(),
        options: None,
        namespace_defaulted: false,
        file_type_defaulted: false,
        path_inferred_from_parent_include: false,
        trace: None,
        confidence: recovered().scene.select_blocks[0].confidence,
    });
    (header, model)
}

#[test]
fn quoted_data_preserves_command_structure_and_normalized_values() {
    for value in hostile_values() {
        let (header, model) = quoted_scene(&value);
        let actual = output(header, model);
        let (header, model) = quoted_scene(&baseline(&value));
        let reference = output(header, model);
        assert_eq!(
            heads(&actual.maya_ascii),
            heads(&reference.maya_ascii),
            "{value:?}"
        );
        let parsed = parse_ascii_scene(&actual.maya_ascii).unwrap();
        let expected = normalized(&value);
        assert_eq!(
            parsed.file_info,
            vec![(expected.clone(), expected.clone())],
            "{value:?}"
        );
        assert_eq!(parsed.nodes[0].name, expected);
        assert_eq!(parsed.nodes[0].uid.as_deref(), Some(expected.as_str()));
        assert_eq!(parsed.nodes[0].parent.as_deref(), Some(expected.as_str()));
        assert_eq!(parsed.file_commands[0].path, expected);
        let expected_tokens: Vec<Vec<String>> = quoted_tokens(&reference.maya_ascii)
            .into_iter()
            .map(|tokens| {
                tokens
                    .into_iter()
                    .map(|token| {
                        if token == baseline(&value) {
                            normalized(&value)
                        } else {
                            token
                        }
                    })
                    .collect()
            })
            .collect();
        assert_eq!(
            quoted_tokens(&actual.maya_ascii),
            expected_tokens,
            "{value:?}"
        );
    }
}

#[test]
fn unsupported_quoted_characters_are_replaced_and_reported() {
    for value in ["\0", "\u{001a}", "\u{0085}", "\u{2028}", "\u{2029}"] {
        let (header, model) = quoted_scene(value);
        let actual = output(header, model);
        assert!(
            !actual
                .maya_ascii
                .as_bytes()
                .windows(value.len())
                .any(|bytes| bytes == value.as_bytes())
        );
        assert!(actual.maya_ascii.contains('\u{fffd}'));
        assert!(!actual.issues.is_empty());
        assert!(actual.issues.iter().all(|issue| {
            issue
                .issue
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("replaced"))
        }));
    }
}

#[test]
fn invalid_bare_words_are_quoted_and_invalid_units_are_omitted() {
    let mut values = hostile_values();
    values.extend(
        [
            "",
            "-Example",
            "$Example",
            "Example/",
            "Example*",
            "Example#",
            "Example'",
            "Example(",
            "Example)",
            "Example{",
            "Example}",
            "Example<",
            "Example>",
            "Example,",
            "Example\u{200b}",
        ]
        .map(str::to_string),
    );
    for value in values {
        let mut model = scene();
        let mut node = node();
        node.node_type = value.clone().into();
        model.nodes.push(node);
        model.select_blocks.push(SelectBlock {
            target: value.clone(),
            notes: vec![],
            ops: vec![SelectBlockOp::SetAttr(SetAttrOp {
                attr_name_or_path: ".ExampleSelected".into(),
                array_size: None,
                channel_hint: None,
                lock: None,
                keyable: None,
                value: SetAttrValue::String("Sample".into()),
            })],
            trace: None,
            confidence: recovered().scene.select_blocks[0].confidence,
        });
        model.links.push(LinkOp::Connect {
            src: value.clone(),
            dst: "Example.input".into(),
            mode: 0,
            trace: None,
            confidence: recovered().scene.select_blocks[0].confidence,
        });
        let header = HeadMetadata {
            luni: Some(value.clone()),
            auni: Some("deg".into()),
            tuni: Some("film".into()),
            ..Default::default()
        };
        let mut reference_model = model.clone();
        reference_model.nodes[0].node_type = baseline(&value).into();
        reference_model.select_blocks[0].target = baseline(&value);
        let reference = output(
            HeadMetadata {
                luni: Some(baseline(&value)),
                ..Default::default()
            },
            reference_model,
        );
        let actual = output(header, model);
        assert!(heads(&actual.maya_ascii).len() <= heads(&reference.maya_ascii).len());
        assert!(!actual.issues.is_empty(), "{value:?}");
        assert!(actual.maya_ascii.contains(".ExampleSelected"), "{value:?}");
        assert!(actual.maya_ascii.contains("currentUnit -a deg -t film;"));
        assert!(heads(&actual.maya_ascii).contains(&"connectAttr".into()));
        assert!(actual.issues.iter().any(|issue| {
            issue
                .issue
                .reason
                .as_ref()
                .is_some_and(|r| r.contains("quoted invalid bare word"))
        }));
        let create = actual
            .maya_ascii
            .lines()
            .find(|line| line.starts_with("createNode "))
            .unwrap();
        let parsed = parse_ascii_scene(create).unwrap();
        assert_eq!(parsed.nodes[0].node_type, normalized(&value));
    }
    for value in ["Example:Sample", "|Example|Sample", "Example.attr[0:2]"] {
        let mut model = scene();
        let mut node = node();
        node.node_type = value.into();
        model.nodes.push(node);
        model.select_blocks.push(SelectBlock {
            target: value.into(),
            notes: vec![],
            ops: vec![],
            trace: None,
            confidence: recovered().scene.select_blocks[0].confidence,
        });
        let actual = output(HeadMetadata::default(), model);
        assert_eq!(actual.issues.len(), 1);
        assert_eq!(actual.issues[0].issue.attr_name, "createNode.node_type");
        assert!(actual.maya_ascii.contains(&format!("select -ne {value};")));
        assert_eq!(
            parse_ascii_scene(&actual.maya_ascii).unwrap().nodes[0].node_type,
            value
        );
    }
}

#[test]
fn requires_options_preserve_valid_values_and_report_invalid_pairs_once() {
    for options in [
        "-nodeType Example",
        "-nodeType Example -dataType Sample",
        "-nodeType  Example\t-dataType Sample",
    ] {
        let actual = output(
            HeadMetadata {
                requires: vec![MbRequiresEntry {
                    plugin_name: "ExamplePlugin".into(),
                    version: "1.0".into(),
                    options: Some(options.into()),
                }],
                ..Default::default()
            },
            scene(),
        );
        assert!(
            actual
                .maya_ascii
                .contains(&format!("requires {options} \"ExamplePlugin\" \"1.0\";"))
        );
        assert!(actual.issues.is_empty());
    }
    for options in [
        "Example",
        "-nodeType",
        "-nodeType -dataType Sample",
        "-node1 Example",
    ] {
        let entry = MbRequiresEntry {
            plugin_name: "ExamplePlugin".into(),
            version: "1.0".into(),
            options: Some(options.into()),
        };
        let actual = output(
            HeadMetadata {
                requires: vec![entry.clone(), entry],
                ..Default::default()
            },
            scene(),
        );
        assert_eq!(actual.issues.len(), 1);
        assert_eq!(actual.issues[0].issue.attr_name, "requires.options");
        assert_eq!(actual.maya_ascii.matches("//omitted requires").count(), 1);
        assert_eq!(
            heads(&actual.maya_ascii),
            heads(&output(HeadMetadata::default(), scene()).maya_ascii)
        );
    }
}

#[test]
fn select_wildcard_keeps_its_attribute_block() {
    let mut model = scene();
    model.select_blocks.push(SelectBlock {
        target: "pPlaneExample.vtx[*]".into(),
        notes: vec![],
        ops: vec![SelectBlockOp::SetAttr(SetAttrOp {
            attr_name_or_path: ".Example".into(),
            array_size: None,
            channel_hint: None,
            lock: None,
            keyable: None,
            value: SetAttrValue::String("Sample".into()),
        })],
        trace: None,
        confidence: recovered().scene.select_blocks[0].confidence,
    });
    let actual = output(HeadMetadata::default(), model);
    assert!(
        actual
            .maya_ascii
            .contains("select -ne \"pPlaneExample.vtx[*]\";\n\tsetAttr \".Example\"")
    );
}

#[test]
fn emission_issues_preserve_original_values_and_merge_reasons() {
    let mut model = scene();
    let mut node = node();
    node.node_type = "Example\0Sample".into();
    node.name = "Example\nSample".into();
    node.attrs.push(string_attr(
        ".Example\nSample",
        SetAttrValue::StringArray {
            declared_count: 2,
            values: vec!["\0".into(), "\0".into()],
        },
    ));
    model.nodes.push(node);
    let actual = output(HeadMetadata::default(), model);
    assert_eq!(actual.issues.len(), 2);
    assert_eq!(actual.issues[0].node_name, "Example\nSample");
    assert_eq!(actual.issues[0].node_type, "Example\0Sample");
    let reason = actual.issues[0].issue.reason.as_ref().unwrap();
    assert!(reason.contains("quoted") && reason.contains("replaced"));
    assert_eq!(
        actual.issues[1].issue.attr_name,
        "setAttr .Example\nSample value"
    );
}

#[test]
fn reference_edit_padding_is_bounded() {
    let mut model = attr_and_code_scene("Example");
    let RecoveredAttrOp::RefEdit { data, .. } = model.nodes[0].attrs.last_mut().unwrap() else {
        panic!()
    };
    data.grouped_records[0] = vec![RefEditRecord::Op5 {
        sub: 4097,
        args: vec![],
    }];
    let actual = output(HeadMetadata::default(), model);
    assert!(!actual.maya_ascii.contains("5 4097"));
    assert!(
        actual
            .issues
            .iter()
            .any(|issue| issue.issue.attr_name == "refedit.sub")
    );
}

fn attr_and_code_scene(value: &str) -> RecoveredScene {
    let mut model = scene();
    let mut node = node();
    node.node_type = "script".into();
    node.attrs
        .push(string_attr(".b", SetAttrValue::String(value.into())));
    node.attrs.push(string_attr(
        ".Example",
        SetAttrValue::TypedNumbers {
            value_type: value.into(),
            values: vec![NumericValue::from_u32(1)],
        },
    ));
    for spec in [
        AddAttrValueSpec::AttrType(value.into()),
        AddAttrValueSpec::DataType(value.into()),
        AddAttrValueSpec::AttrType("enum".into()),
    ] {
        node.attrs.push(RecoveredAttrOp::AddAttr(AddAttrOp {
            attr_name: value.into(),
            short_name: value.into(),
            long_name: value.into(),
            parent: Some(value.into()),
            number_of_children: None,
            nice_name: Some(value.into()),
            type_token: "Example".into(),
            header_raw: [0; 11],
            disconnect_behaviour: None,
            used_as_proxy: false,
            used_as_color: false,
            storable: FlagState::Unknown,
            readable: FlagState::Unknown,
            writable: FlagState::Unknown,
            cached_internally: FlagState::Unknown,
            hidden: FlagState::Unknown,
            keyable: FlagState::Unknown,
            multi: FlagState::Unknown,
            index_matters: FlagState::Unknown,
            internal_set: FlagState::Unknown,
            default_value: None,
            min_value: None,
            max_value: None,
            soft_min_value: None,
            soft_max_value: None,
            enum_names: Some(value.into()),
            value_spec: spec,
        }));
    }
    node.attrs.push(RecoveredAttrOp::RefEdit {
        attr_name: value.into(),
        data: RefEditData {
            root_node: value.into(),
            groups: vec![RefEditGroup {
                name: value.into(),
                expected_count: 6,
                source: RefEditGroupSource::HeaderList,
                first_offset: 0,
            }],
            grouped_records: vec![vec![
                RefEditRecord::Context(value.into(), 0),
                RefEditRecord::Op0(value.into(), value.into(), value.into()),
                RefEditRecord::Op1(vec![value.into()]),
                RefEditRecord::Op2(value.into(), value.into(), value.into()),
                RefEditRecord::Op3(value.into(), value.into(), value.into()),
                RefEditRecord::Op5 {
                    sub: 1,
                    args: vec![value.into()],
                },
            ]],
            unknown_tail: None,
            parse_stats: Default::default(),
        },
    });
    model.nodes.push(node);
    model.reference_files.push(ReferenceFileOp {
        path: "asset/example/file.ma".into(),
        namespace: "Example".into(),
        reference_node: "ExampleRN".into(),
        file_type: "mayaAscii".into(),
        options: Some(value.into()),
        namespace_defaulted: false,
        file_type_defaulted: false,
        path_inferred_from_parent_include: false,
        trace: None,
        confidence: recovered().scene.select_blocks[0].confidence,
    });
    model
}

fn quoted_tokens(text: &str) -> Vec<Vec<String>> {
    use maya_scene_kit_formats::ma::commands::{Token, tokenize_command};
    collect_top_level_facts(text)
        .items
        .iter()
        .map(|item| {
            let MelTopLevelItemFact::Command(command) = item else {
                panic!("unexpected statement")
            };
            for item in &command.raw_items {
                if item.kind == maya_scene_kit_formats::mel::MelRawShellItemKind::Quoted {
                    let source = &text[item.source_span.start..item.source_span.end];
                    assert!(!source.as_bytes().contains(&b'\n'), "{source:?}");
                    assert!(!source.as_bytes().contains(&b'\r'), "{source:?}");
                }
            }
            tokenize_command(command.source_text(text))
                .unwrap()
                .into_iter()
                .filter_map(|token| match token {
                    Token::Quoted(value) => Some(value),
                    _ => None,
                })
                .collect()
        })
        .collect()
}

#[test]
fn attribute_and_code_strings_round_trip_without_command_injection() {
    for hostile in hostile_values() {
        let value = format!("Example{hostile}Sample");
        let plain = baseline(&value);
        let reference = output(HeadMetadata::default(), attr_and_code_scene(&plain));
        let actual = output(HeadMetadata::default(), attr_and_code_scene(&value));
        assert_eq!(
            heads(&actual.maya_ascii),
            heads(&reference.maya_ascii),
            "{value:?}"
        );
        let expected: Vec<Vec<String>> = quoted_tokens(&reference.maya_ascii)
            .into_iter()
            .map(|tokens| {
                tokens
                    .into_iter()
                    .map(|token| {
                        if token == plain {
                            normalized(&value)
                        } else if token == format!(".{plain}") {
                            format!(".{}", normalized(&value))
                        } else {
                            token
                        }
                    })
                    .collect()
            })
            .collect();
        assert_eq!(quoted_tokens(&actual.maya_ascii), expected, "{value:?}");
        for forbidden in ['\0', '\u{001a}', '\u{0085}', '\u{2028}', '\u{2029}'] {
            if value.contains(forbidden) {
                for position in [
                    "setAttr .b value",
                    "setAttr.value_type",
                    "addAttr.short_name",
                    "refedit.argument",
                    "reference.options",
                ] {
                    assert!(
                        actual
                            .issues
                            .iter()
                            .any(|issue| issue.issue.attr_name == position),
                        "{forbidden:?} {position}: {:?}",
                        actual.issues
                    );
                }
            }

            assert!(
                !actual
                    .maya_ascii
                    .as_bytes()
                    .windows(forbidden.len_utf8())
                    .any(|bytes| bytes == forbidden.to_string().as_bytes())
            );
        }
    }
}
