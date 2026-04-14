use std::sync::Arc;

use maya_mel::{
    maya::{
        MayaCommandRegistry,
        model::{
            MayaNormalizedFlag, MayaRawShellItem, MayaRawShellItemKind, MayaSetAttrValueKind,
            MayaSpecializedCommand,
        },
    },
    sema::{
        self,
        command_norm::{CommandMode as SemaCommandMode, NormalizedCommandItem, PositionalArg},
        command_schema::{
            CommandKind as SemaCommandKind, CommandRegistry, CommandSchema,
            ValueShape as SemaValueShape,
        },
    },
};

use super::{
    FullParseLike, MelNormalizedCommandFact, MelNormalizedCommandItemFact,
    MelNormalizedCommandKind, MelNormalizedCommandMode, MelNormalizedFlag,
    MelNormalizedPositionalArg, MelRawShellItem, MelRawShellItemKind, MelSetAttrValueKind,
    MelSpecializedAddAttrCommand, MelSpecializedCommandForm, MelSpecializedConnectAttrCommand,
    MelSpecializedCreateNodeCommand, MelSpecializedCurrentUnitCommand, MelSpecializedFileCommand,
    MelSpecializedFileInfoCommand, MelSpecializedRelationshipCommand, MelSpecializedRenameCommand,
    MelSpecializedRequiresCommand, MelSpecializedSelectCommand, MelSpecializedSetAttrCommand,
    MelValueShape, display_span,
};

pub(super) fn map_normalized_command(
    parse: &impl FullParseLike,
    registry: &MayaCommandRegistry,
    invoke: sema::NormalizedCommandInvoke,
) -> MelNormalizedCommandFact {
    let schema = registry.lookup(&invoke.schema_name);
    MelNormalizedCommandFact {
        schema_name: invoke.schema_name,
        kind: match invoke.kind {
            SemaCommandKind::Builtin => MelNormalizedCommandKind::Builtin,
            SemaCommandKind::Plugin => MelNormalizedCommandKind::Plugin,
        },
        mode: match invoke.mode {
            SemaCommandMode::Create => MelNormalizedCommandMode::Create,
            SemaCommandMode::Edit => MelNormalizedCommandMode::Edit,
            SemaCommandMode::Query => MelNormalizedCommandMode::Query,
            SemaCommandMode::Unknown => MelNormalizedCommandMode::Unknown,
        },
        items: invoke
            .items
            .into_iter()
            .map(|item| map_normalized_item(parse, item, schema.map(|value| &**value)))
            .collect(),
    }
}

fn map_normalized_item(
    parse: &impl FullParseLike,
    item: NormalizedCommandItem,
    schema: Option<&CommandSchema>,
) -> MelNormalizedCommandItemFact {
    match item {
        NormalizedCommandItem::Flag(flag) => {
            let value_shapes = schema
                .and_then(|schema| {
                    flag.canonical_name
                        .as_deref()
                        .and_then(|canonical_name| lookup_flag_value_shapes(schema, canonical_name))
                })
                .unwrap_or_default();
            MelNormalizedCommandItemFact::Flag(MelNormalizedFlag {
                source_span: display_span(parse, flag.source_range),
                canonical_name: flag.canonical_name,
                value_shapes,
                args: flag
                    .args
                    .into_iter()
                    .map(|arg| map_positional_arg(parse, arg))
                    .collect(),
                span: super::MelSpan::from_text_range(flag.range),
            })
        }
        NormalizedCommandItem::Positional(arg) => {
            MelNormalizedCommandItemFact::Positional(map_positional_arg(parse, arg))
        }
    }
}

fn map_positional_arg(
    parse: &impl FullParseLike,
    arg: PositionalArg,
) -> MelNormalizedPositionalArg {
    let literal = super::mel_calls::shell_word_literal(parse.source_view(), &arg.word);
    MelNormalizedPositionalArg {
        text_span: display_span(parse, arg.range),
        dynamic: literal.is_none(),
        literal: literal.map(Arc::from),
        span: super::MelSpan::from_text_range(arg.range),
    }
}

pub(super) fn map_maya_raw_shell_item(
    parse: &impl FullParseLike,
    item: MayaRawShellItem,
) -> MelRawShellItem {
    MelRawShellItem {
        source_span: display_span(parse, item.span),
        text_span: item.text_range().map(|range| display_span(parse, range)),
        kind: match item.kind {
            MayaRawShellItemKind::Flag => MelRawShellItemKind::Flag,
            MayaRawShellItemKind::Numeric => MelRawShellItemKind::Numeric,
            MayaRawShellItemKind::BareWord => MelRawShellItemKind::Bare,
            MayaRawShellItemKind::QuotedString => MelRawShellItemKind::Quoted,
            MayaRawShellItemKind::Variable
            | MayaRawShellItemKind::GroupedExpr
            | MayaRawShellItemKind::BraceList
            | MayaRawShellItemKind::VectorLiteral
            | MayaRawShellItemKind::Capture => MelRawShellItemKind::Dynamic,
        },
        span: super::MelSpan::from_text_range(item.span),
    }
}

pub(super) fn map_maya_specialized_command(
    parse: &impl FullParseLike,
    command: MayaSpecializedCommand,
) -> Option<MelSpecializedCommandForm> {
    match command {
        MayaSpecializedCommand::Requires(requires) => Some(MelSpecializedCommandForm::Requires(
            MelSpecializedRequiresCommand {
                requirements: requires
                    .requirements
                    .into_iter()
                    .map(|item| map_maya_raw_shell_item(parse, item))
                    .collect(),
                flags: requires
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(requires.span),
            },
        )),
        MayaSpecializedCommand::CurrentUnit(current_unit) => Some(
            MelSpecializedCommandForm::CurrentUnit(MelSpecializedCurrentUnitCommand {
                flags: current_unit
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(current_unit.span),
            }),
        ),
        MayaSpecializedCommand::FileInfo(file_info) => Some(MelSpecializedCommandForm::FileInfo(
            MelSpecializedFileInfoCommand {
                key: file_info
                    .key
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                value: file_info
                    .value
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                flags: file_info
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(file_info.span),
            },
        )),
        MayaSpecializedCommand::CreateNode(create_node) => Some(
            MelSpecializedCommandForm::CreateNode(MelSpecializedCreateNodeCommand {
                node_type: create_node
                    .node_type
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                name: create_node
                    .name
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                parent: create_node
                    .parent
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                flags: create_node
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(create_node.span),
            }),
        ),
        MayaSpecializedCommand::Rename(rename) => Some(MelSpecializedCommandForm::Rename(
            MelSpecializedRenameCommand {
                uuid: rename.uuid.map(|item| map_maya_raw_shell_item(parse, item)),
                source: rename
                    .source
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                target: rename
                    .target
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                flags: rename
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(rename.span),
            },
        )),
        MayaSpecializedCommand::Select(select) => Some(MelSpecializedCommandForm::Select(
            MelSpecializedSelectCommand {
                targets: select
                    .targets
                    .into_iter()
                    .map(|item| map_maya_raw_shell_item(parse, item))
                    .collect(),
                flags: select
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(select.span),
            },
        )),
        MayaSpecializedCommand::SetAttr(set_attr) => Some(MelSpecializedCommandForm::SetAttr(
            MelSpecializedSetAttrCommand {
                attr_path: set_attr
                    .attr_path
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                type_name: set_attr
                    .type_name
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                value_kind: map_maya_set_attr_value_kind(set_attr.value_kind),
                values: set_attr
                    .values
                    .into_iter()
                    .map(|item| map_maya_raw_shell_item(parse, item))
                    .collect(),
                flags: set_attr
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(set_attr.span),
            },
        )),
        MayaSpecializedCommand::AddAttr(add_attr) => Some(MelSpecializedCommandForm::AddAttr(
            MelSpecializedAddAttrCommand {
                flags: add_attr
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                tail: add_attr
                    .tail
                    .into_iter()
                    .map(|item| map_maya_raw_shell_item(parse, item))
                    .collect(),
                span: super::MelSpan::from_text_range(add_attr.span),
            },
        )),
        MayaSpecializedCommand::ConnectAttr(connect_attr) => Some(
            MelSpecializedCommandForm::ConnectAttr(MelSpecializedConnectAttrCommand {
                source_attr: connect_attr
                    .source_attr
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                target_attr: connect_attr
                    .target_attr
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                flags: connect_attr
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(connect_attr.span),
            }),
        ),
        MayaSpecializedCommand::Relationship(relationship) => Some(
            MelSpecializedCommandForm::Relationship(MelSpecializedRelationshipCommand {
                relationship: relationship
                    .relationship
                    .map(|item| map_maya_raw_shell_item(parse, item)),
                members: relationship
                    .members
                    .into_iter()
                    .map(|item| map_maya_raw_shell_item(parse, item))
                    .collect(),
                flags: relationship
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(relationship.span),
            }),
        ),
        MayaSpecializedCommand::File(file) => {
            Some(MelSpecializedCommandForm::File(MelSpecializedFileCommand {
                path: file.path.map(|item| map_maya_raw_shell_item(parse, item)),
                flags: file
                    .flags
                    .into_iter()
                    .map(|flag| map_maya_normalized_flag(parse, flag))
                    .collect(),
                span: super::MelSpan::from_text_range(file.span),
            }))
        }
    }
}

fn map_maya_set_attr_value_kind(kind: MayaSetAttrValueKind) -> MelSetAttrValueKind {
    match kind {
        MayaSetAttrValueKind::TypedNumbers => MelSetAttrValueKind::TypedNumbers,
        MayaSetAttrValueKind::String => MelSetAttrValueKind::String,
        MayaSetAttrValueKind::StringArray => MelSetAttrValueKind::StringArray,
        MayaSetAttrValueKind::Int32Array => MelSetAttrValueKind::Int32Array,
        MayaSetAttrValueKind::ComponentList => MelSetAttrValueKind::ComponentList,
        MayaSetAttrValueKind::OpaqueTyped => MelSetAttrValueKind::OpaqueTyped,
        MayaSetAttrValueKind::MatrixXform => MelSetAttrValueKind::MatrixXform,
        MayaSetAttrValueKind::DataReferenceEdits => MelSetAttrValueKind::DataReferenceEdits,
        MayaSetAttrValueKind::Unknown => MelSetAttrValueKind::Unknown,
    }
}

pub(super) fn map_maya_normalized_flag(
    parse: &impl FullParseLike,
    flag: MayaNormalizedFlag,
) -> MelNormalizedFlag {
    let source_view = parse.source_view();
    MelNormalizedFlag {
        source_span: display_span(parse, flag.source_range),
        canonical_name: flag.canonical_name.map(Arc::from),
        value_shapes: Vec::new(),
        args: flag
            .args
            .into_iter()
            .map(|arg| MelNormalizedPositionalArg {
                text_span: display_span(parse, arg.item.span),
                literal: arg.item.value_text(source_view).map(Arc::from),
                dynamic: matches!(
                    arg.item.kind,
                    MayaRawShellItemKind::Variable
                        | MayaRawShellItemKind::GroupedExpr
                        | MayaRawShellItemKind::BraceList
                        | MayaRawShellItemKind::VectorLiteral
                        | MayaRawShellItemKind::Capture
                ),
                span: super::MelSpan::from_text_range(arg.item.span),
            })
            .collect(),
        span: super::MelSpan::from_text_range(flag.span),
    }
}

fn lookup_flag_value_shapes(
    schema: &CommandSchema,
    canonical_name: &str,
) -> Option<Vec<MelValueShape>> {
    schema.flags.iter().find_map(|flag| {
        (flag.long_name.as_ref() == canonical_name).then(|| {
            flag.value_shapes
                .iter()
                .copied()
                .map(map_value_shape)
                .collect()
        })
    })
}

fn map_value_shape(shape: SemaValueShape) -> MelValueShape {
    match shape {
        SemaValueShape::Bool => MelValueShape::Bool,
        SemaValueShape::Int => MelValueShape::Int,
        SemaValueShape::Float => MelValueShape::Float,
        SemaValueShape::String => MelValueShape::String,
        SemaValueShape::Script => MelValueShape::Script,
        SemaValueShape::StringArray => MelValueShape::StringArray,
        SemaValueShape::FloatTuple(size) => MelValueShape::FloatTuple(size),
        SemaValueShape::IntTuple(size) => MelValueShape::IntTuple(size),
        SemaValueShape::NodeName => MelValueShape::NodeName,
        SemaValueShape::Unknown => MelValueShape::Unknown,
    }
}
