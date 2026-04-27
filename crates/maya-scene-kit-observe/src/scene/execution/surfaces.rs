use std::{collections::HashSet, sync::Arc};

use maya_scene_kit_formats::{
    ma::{raw_dump::RawMaNodeAttrValue, scripts::RawMaScriptEntry},
    mel::{self, MelAuditTopLevelItemFact},
};

use crate::{
    mb::{MbParseBudget, parse_section_chunks_with_hints, resolve_section_layout_hints},
    scene::{
        ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind, ExecutionLanguage,
        ExecutionOrigin, ExecutionSourceRange, ExecutionSurfaceKind, ExecutionTrigger,
        SceneToolError,
        decode::attr::decode_attr_payload,
        recover::collect_raw_chunk_records_with_budget,
        schema::node_semantics::{
            ExecutionDecoder, NodeExecutionProfileKind, NodeExecutionSemantics,
        },
    },
};

const MAX_GENERIC_RAW_TEXT_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ExecutionSurface {
    pub text: Arc<str>,
    pub origin: ExecutionOrigin,
    pub preview: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PreviewWindowSpec {
    pub(crate) text: Arc<str>,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl PreviewWindowSpec {
    pub(crate) fn new(text: Arc<str>, start: usize, end: usize) -> Self {
        Self { text, start, end }
    }

    pub(crate) fn prefix(text: Arc<str>) -> Self {
        let end = text.len().min(24);
        Self {
            text,
            start: 0,
            end,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutionSurfaceRecord {
    pub(crate) text: Arc<str>,
    pub(crate) origin: ExecutionOrigin,
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutionCoverageIssueRecord {
    pub(crate) kind: ExecutionCoverageIssueKind,
    pub(crate) detail: ExecutionCoverageIssueDetail,
    pub(crate) origin: Option<ExecutionOrigin>,
    pub(crate) preview: PreviewWindowSpec,
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutionCoverageCollection {
    pub(crate) surfaces: Vec<ExecutionSurfaceRecord>,
    pub(crate) coverage_issues: Vec<ExecutionCoverageIssueRecord>,
}

pub(crate) fn collect_execution_coverage_from_ma_parts(
    script_nodes: &[RawMaScriptEntry],
    node_attr_values: &[RawMaNodeAttrValue],
    top_level: &mel::MelAuditTopLevelFacts,
    execution_semantics: &NodeExecutionSemantics,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    collect_ma_coverage(
        script_nodes,
        node_attr_values,
        top_level,
        execution_semantics,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn collect_execution_coverage_from_mb(
    mb: &crate::mb::MayaBinaryFile,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    let semantics = crate::scene::schema::node_semantics::node_execution_semantics_with_registry(
        crate::scene::schema::default_schema_registry(),
    )
    .map_err(SceneToolError::Config)?;
    collect_execution_coverage_from_mb_with_budget(
        mb,
        &MbParseBudget::default(),
        semantics.as_ref(),
    )
}

pub(crate) fn collect_execution_coverage_from_mb_with_budget(
    mb: &crate::mb::MayaBinaryFile,
    budget: &MbParseBudget,
    execution_semantics: &NodeExecutionSemantics,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    collect_mb_coverage(mb, budget, execution_semantics)
}

fn collect_ma_coverage(
    script_nodes: &[RawMaScriptEntry],
    node_attr_values: &[RawMaNodeAttrValue],
    top_level: &mel::MelAuditTopLevelFacts,
    execution_semantics: &NodeExecutionSemantics,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    let mut surfaces = collect_ma_script_node_surfaces(script_nodes);
    surfaces.extend(collect_ma_profile_node_attr_surfaces(
        node_attr_values,
        execution_semantics,
    ));
    let coverage_issues = top_level
        .diagnostics
        .iter()
        .map(|diagnostic| {
            let preview_span = top_level.preview_span(diagnostic.span);
            ExecutionCoverageIssueRecord {
                kind: ExecutionCoverageIssueKind::TopLevelDiagnostics,
                detail: ExecutionCoverageIssueDetail::TopLevelDiagnostics {
                    diagnostic: diagnostic.message.to_string(),
                },
                origin: None,
                preview: PreviewWindowSpec::new(
                    top_level.preview_text(),
                    preview_span.start,
                    preview_span.end,
                ),
            }
        })
        .collect::<Vec<_>>();

    let mut coverage_issues = coverage_issues;
    for item in &top_level.items {
        match item {
            MelAuditTopLevelItemFact::Command(command) => {
                match classify_top_level_command(command.head.as_ref()) {
                    MaTopLevelAuditClass::ExecutionSurface | MaTopLevelAuditClass::Ignore => {
                        push_command_surface(
                            &mut surfaces,
                            command.source_text(top_level),
                            ExecutionSurfaceKind::TopLevelCommand,
                            ExecutionTrigger::FileOpen,
                            Some(command.head.to_string()),
                            Some(ExecutionSourceRange {
                                start: command.source_span.start,
                                end: command.source_span.end,
                            }),
                        );
                    }
                    MaTopLevelAuditClass::FileDependencyOnly => {}
                }
                if let Some(callback) = &command.file_command_callback {
                    surfaces.push(ExecutionSurfaceRecord {
                        text: Arc::<str>::from(callback.as_str()),
                        origin: ExecutionOrigin {
                            lang: ExecutionLanguage::Mel,
                            trigger: ExecutionTrigger::FileOpen,
                            surface_kind: ExecutionSurfaceKind::FileCommandCallback,
                            node_name: None,
                            attr_name: Some("-command".to_string()),
                            source_kind: Some("file -command".to_string()),
                            source_range: Some(ExecutionSourceRange {
                                start: command.source_span.start,
                                end: command.source_span.end,
                            }),
                            chunk_form: None,
                            chunk_tag: None,
                            chunk_node_offset: None,
                            ..ExecutionOrigin::without_chunk_address()
                        },
                    });
                }
            }
            MelAuditTopLevelItemFact::Proc(proc_def) => {
                coverage_issues.push(ExecutionCoverageIssueRecord {
                    kind: ExecutionCoverageIssueKind::UnsupportedCoverage,
                    detail: ExecutionCoverageIssueDetail::UnsupportedProcDefinition {
                        is_global: proc_def.is_global,
                    },
                    origin: None,
                    preview: {
                        let preview_span = top_level.preview_span(proc_def.span);
                        PreviewWindowSpec::new(
                            top_level.preview_text(),
                            preview_span.start,
                            preview_span.end,
                        )
                    },
                });
                push_command_surface(
                    &mut surfaces,
                    proc_def.source_text(top_level),
                    ExecutionSurfaceKind::TopLevelProcDefinition,
                    ExecutionTrigger::Unknown,
                    Some("proc_definition".to_string()),
                    Some(ExecutionSourceRange {
                        start: proc_def.source_span.start,
                        end: proc_def.source_span.end,
                    }),
                );
            }
            MelAuditTopLevelItemFact::Other(other) => {
                if let Some(head) = classify_top_level_other(other.source_text(top_level)) {
                    push_command_surface(
                        &mut surfaces,
                        other.source_text(top_level),
                        ExecutionSurfaceKind::TopLevelCommand,
                        ExecutionTrigger::FileOpen,
                        Some(head.to_string()),
                        Some(ExecutionSourceRange {
                            start: other.source_span.start,
                            end: other.source_span.end,
                        }),
                    );
                } else {
                    coverage_issues.push(ExecutionCoverageIssueRecord {
                        kind: ExecutionCoverageIssueKind::UnsupportedCoverage,
                        detail: ExecutionCoverageIssueDetail::UnsupportedTopLevelStatement,
                        origin: None,
                        preview: {
                            let preview_span = top_level.preview_span(other.span);
                            PreviewWindowSpec::new(
                                top_level.preview_text(),
                                preview_span.start,
                                preview_span.end,
                            )
                        },
                    });
                    push_command_surface(
                        &mut surfaces,
                        other.source_text(top_level),
                        ExecutionSurfaceKind::TopLevelOtherStatement,
                        ExecutionTrigger::FileOpen,
                        Some("top_level_other".to_string()),
                        Some(ExecutionSourceRange {
                            start: other.source_span.start,
                            end: other.source_span.end,
                        }),
                    );
                }
            }
        }
    }

    Ok(ExecutionCoverageCollection {
        surfaces,
        coverage_issues,
    })
}

fn collect_ma_script_node_surfaces(
    script_nodes: &[RawMaScriptEntry],
) -> Vec<ExecutionSurfaceRecord> {
    let mut surfaces = Vec::with_capacity(script_nodes.len());

    for node in script_nodes {
        if node.body.is_empty() {
            continue;
        }
        let trigger = node
            .script_type
            .map(script_type_to_trigger)
            .unwrap_or(ExecutionTrigger::Manual);
        let lang = node
            .source_type
            .map(script_source_type_to_language)
            .unwrap_or(ExecutionLanguage::Mel);
        let source_kind = match (node.script_type, node.source_type) {
            (Some(script_type), Some(source_type)) => {
                Some(format!("scriptType={script_type},sourceType={source_type}"))
            }
            (Some(script_type), None) => Some(format!("scriptType={script_type}")),
            (None, Some(source_type)) => Some(format!("sourceType={source_type}")),
            (None, None) => None,
        };
        surfaces.push(ExecutionSurfaceRecord {
            text: Arc::<str>::from(node.body.as_str()),
            origin: ExecutionOrigin {
                lang,
                trigger,
                surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
                node_name: Some(node.name.clone()),
                attr_name: Some(".b".to_string()),
                source_range: None,
                source_kind,
                chunk_form: None,
                chunk_tag: None,
                chunk_node_offset: None,
                ..ExecutionOrigin::without_chunk_address()
            },
        });
    }

    surfaces
}

fn collect_ma_profile_node_attr_surfaces(
    node_attr_values: &[RawMaNodeAttrValue],
    execution_semantics: &NodeExecutionSemantics,
) -> Vec<ExecutionSurfaceRecord> {
    let mut surfaces = Vec::new();
    for value in node_attr_values {
        let node_type = ma_node_attr_effective_node_type(value);
        if node_type.is_empty() {
            continue;
        }
        let attr_name = value.attr.trim_start_matches('.');
        for profile in execution_semantics.profiles_for_node(node_type) {
            match &profile.kind {
                NodeExecutionProfileKind::ScriptNode(profile)
                    if profile.body_attrs.iter().any(|attr| attr == attr_name) =>
                {
                    if value.node_type == "script" && attr_name == "b" {
                        continue;
                    }
                    let Some(body) = value.string_value.as_ref() else {
                        continue;
                    };
                    if body.is_empty() {
                        continue;
                    }
                    let script_type = profile.trigger_attr.as_ref().and_then(|trigger_attr| {
                        ma_node_u32_attr(
                            node_attr_values,
                            node_type,
                            &value.node_name,
                            trigger_attr,
                        )
                    });
                    let source_type = profile.language_attr.as_ref().and_then(|language_attr| {
                        ma_node_u32_attr(
                            node_attr_values,
                            node_type,
                            &value.node_name,
                            language_attr,
                        )
                    });
                    let trigger = match profile.trigger_decoder {
                        Some(ExecutionDecoder::MayaScriptNodeScriptType) => script_type
                            .map(script_type_to_trigger)
                            .unwrap_or(ExecutionTrigger::Manual),
                        _ => ExecutionTrigger::Manual,
                    };
                    let lang = match profile.language_decoder {
                        Some(ExecutionDecoder::MayaScriptNodeSourceType) => source_type
                            .map(script_source_type_to_language)
                            .unwrap_or(ExecutionLanguage::Mel),
                        _ => ExecutionLanguage::Mel,
                    };
                    surfaces.push(ExecutionSurfaceRecord {
                        text: Arc::<str>::from(body.as_str()),
                        origin: ExecutionOrigin {
                            lang,
                            trigger,
                            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
                            node_name: Some(value.node_name.clone()),
                            attr_name: Some(value.attr.clone()),
                            source_range: None,
                            source_kind: script_node_source_kind(script_type, source_type)
                                .or_else(|| Some(attr_name.to_string())),
                            chunk_form: None,
                            chunk_tag: None,
                            chunk_node_offset: None,
                            ..ExecutionOrigin::without_chunk_address()
                        },
                    });
                }
                NodeExecutionProfileKind::AttrCallbacks(profile)
                    if profile
                        .attrs
                        .iter()
                        .any(|attr| attr.short_name == attr_name) =>
                {
                    let Some(body) = value.string_value.as_ref() else {
                        continue;
                    };
                    if body.is_empty() {
                        continue;
                    }
                    surfaces.push(ExecutionSurfaceRecord {
                        text: Arc::<str>::from(body.as_str()),
                        origin: ExecutionOrigin {
                            lang: profile.default_language,
                            trigger: profile.default_trigger,
                            surface_kind: ExecutionSurfaceKind::NodeAttrCallback,
                            node_name: Some(value.node_name.clone()),
                            attr_name: Some(value.attr.clone()),
                            source_range: None,
                            source_kind: execution_semantics
                                .source_label(node_type, attr_name)
                                .map(str::to_string)
                                .or_else(|| Some(attr_name.to_string())),
                            chunk_form: None,
                            chunk_tag: None,
                            chunk_node_offset: None,
                            ..ExecutionOrigin::without_chunk_address()
                        },
                    });
                }
                _ => {}
            }
        }
    }
    surfaces
}

fn ma_node_attr_effective_node_type(value: &RawMaNodeAttrValue) -> &str {
    if !value.node_type.is_empty() {
        return value.node_type.as_str();
    }
    match value.node_name.as_str() {
        "defaultRenderGlobals" => "renderGlobals",
        _ => "",
    }
}

fn ma_node_u32_attr(
    node_attr_values: &[RawMaNodeAttrValue],
    node_type: &str,
    node_name: &str,
    attr_name: &str,
) -> Option<u32> {
    let attr_path = format!(".{attr_name}");
    node_attr_values
        .iter()
        .find(|value| {
            ma_node_attr_effective_node_type(value) == node_type
                && value.node_name == node_name
                && value.attr == attr_path
        })
        .and_then(|value| value.u32_value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaTopLevelAuditClass {
    ExecutionSurface,
    FileDependencyOnly,
    Ignore,
}

fn classify_top_level_command(head: &str) -> MaTopLevelAuditClass {
    match head {
        "python" | "eval" | "evalDeferred" | "exec" | "scriptJob" | "source" | "loadPlugin"
        | "commandPort" | "print" | "warning" | "error" | "confirmDialog" | "headsUpMessage" => {
            MaTopLevelAuditClass::ExecutionSurface
        }
        "file" => MaTopLevelAuditClass::FileDependencyOnly,
        _ => MaTopLevelAuditClass::Ignore,
    }
}

fn classify_top_level_other(source_text: &str) -> Option<&'static str> {
    let trimmed = source_text.trim_start();
    [
        "python",
        "eval",
        "evalDeferred",
        "exec",
        "scriptJob",
        "source",
        "loadPlugin",
        "commandPort",
        "print",
        "warning",
        "error",
        "confirmDialog",
        "headsUpMessage",
    ]
    .into_iter()
    .find(|head| trimmed.starts_with(head) && trimmed[head.len()..].starts_with('('))
}

fn collect_mb_coverage(
    mb: &crate::mb::MayaBinaryFile,
    budget: &MbParseBudget,
    execution_semantics: &NodeExecutionSemantics,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    let mut surfaces = collect_mb_native_script_surfaces(mb, execution_semantics);
    let raw_chunks = collect_raw_chunk_records_with_budget(mb, budget)?;
    let canonical_bodies = surfaces
        .iter()
        .filter_map(|surface| {
            (surface.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody)
                .then_some((surface.origin.chunk_node_offset, surface.text.clone()))
        })
        .collect::<HashSet<_>>();
    let mut seen_raw = HashSet::new();
    for raw in raw_chunks {
        let payload = raw.payload(mb.data.as_ref());
        if !raw_chunk_tag_may_contain_execution_text(raw.chunk_ref.tag.as_str(), payload.len()) {
            continue;
        }
        if !payload_may_contain_audit_marker(payload) {
            continue;
        }
        let Some(text) = decode_raw_chunk_text(raw.chunk_ref.tag.as_str(), payload) else {
            continue;
        };
        if !contains_any_audit_marker(&text) {
            continue;
        }
        if canonical_bodies.contains(&(
            Some(raw.chunk_ref.node_offset),
            Arc::<str>::from(text.as_str()),
        )) {
            continue;
        }
        let key = (
            raw.chunk_ref.form.clone(),
            raw.chunk_ref.tag.clone(),
            raw.chunk_ref.node_offset,
            text.clone(),
        );
        if !seen_raw.insert(key) {
            continue;
        }
        surfaces.push(ExecutionSurfaceRecord {
            text: Arc::<str>::from(text),
            origin: ExecutionOrigin {
                lang: ExecutionLanguage::Unknown,
                trigger: ExecutionTrigger::FileOpen,
                surface_kind: ExecutionSurfaceKind::RawChunkText,
                node_name: None,
                attr_name: None,
                source_range: None,
                source_kind: Some(format!("{}:{}", raw.chunk_ref.form, raw.chunk_ref.tag)),
                chunk_form: Some(raw.chunk_ref.form.clone()),
                chunk_tag: Some(raw.chunk_ref.tag.clone()),
                chunk_node_offset: Some(raw.chunk_ref.node_offset),
                chunk_aux: raw.chunk_ref.chunk_aux,
                chunk_payload_offset: Some(raw.payload_span.start),
                chunk_payload_size: Some(raw.payload_span.len()),
                chunk_child_alignment: raw.chunk_ref.child_alignment,
                chunk_child_header_size: raw.chunk_ref.child_header_size,
            },
        });
    }

    Ok(ExecutionCoverageCollection {
        surfaces,
        coverage_issues: Vec::new(),
    })
}

fn collect_mb_native_script_surfaces(
    mb: &crate::mb::MayaBinaryFile,
    execution_semantics: &NodeExecutionSemantics,
) -> Vec<ExecutionSurfaceRecord> {
    let mut surfaces = Vec::new();
    let mut seen = HashSet::new();

    for child in &mb.root.children {
        let Some(form_type) = child.form_type.as_deref() else {
            continue;
        };
        let (child_alignment, child_header_size) = resolve_section_layout_hints(
            &child.tag,
            child.form_type.as_deref(),
            child.child_alignment,
            child.child_header_size,
        );
        let payload = &mb.data[child.payload_offset..child.payload_end];
        if payload.len() < 4 || &payload[..4] != form_type.as_bytes() {
            continue;
        }

        let parsed =
            parse_section_chunks_with_hints(&payload[4..], child_alignment, child_header_size);
        let selected_node_name = if form_type == "SLCT" {
            parsed.chunks.iter().find_map(|chunk| {
                if chunk.tag != "SLCT" {
                    return None;
                }
                let text = String::from_utf8_lossy(chunk.payload(&payload[4..]));
                let trimmed = text.trim_matches(char::from(0)).trim();
                (!trimmed.is_empty()).then(|| trimmed.trim_start_matches(':').to_string())
            })
        } else {
            None
        };
        let Some(node_type) = form_typeid(form_type)
            .and_then(|typeid| execution_semantics.node_type_for_typeid(typeid))
            .or_else(|| {
                selected_node_name
                    .as_deref()
                    .and_then(mb_default_selected_node_type)
            })
        else {
            continue;
        };
        let profiles = execution_semantics.profiles_for_node(node_type);
        if profiles.is_empty() {
            continue;
        }
        let mut node_name = format!("<{}@0x{:X}>", form_type, child.offset);
        if let Some(selected_node_name) = &selected_node_name {
            node_name = selected_node_name.clone();
        }
        let mut script_type = None;
        let mut source_type = None;
        let mut attr_values = Vec::<(String, Vec<u8>)>::new();

        for chunk in parsed.chunks {
            if chunk.tag == "CREA" {
                if form_type == "SCRP" {
                    if let Some(name) = crate::mb::paths::extract_mb_script_node_name_with_layout(
                        payload,
                        child_alignment,
                        child_header_size,
                    ) {
                        node_name = name;
                    }
                }
                continue;
            }

            let Some((attr_name, _kind, value)) = decode_attr_payload(chunk.payload(&payload[4..]))
            else {
                continue;
            };
            attr_values.push((attr_name, value));
        }

        for profile in profiles {
            if let NodeExecutionProfileKind::ScriptNode(profile) = &profile.kind {
                if let Some(trigger_attr) = &profile.trigger_attr {
                    script_type = attr_values
                        .iter()
                        .find(|(attr, _)| attr == trigger_attr)
                        .and_then(|(_, value)| raw_u32_prefix(value));
                }
                if let Some(language_attr) = &profile.language_attr {
                    source_type = attr_values
                        .iter()
                        .find(|(attr, _)| attr == language_attr)
                        .and_then(|(_, value)| raw_u32_prefix(value));
                }
                let trigger = match profile.trigger_decoder {
                    Some(ExecutionDecoder::MayaScriptNodeScriptType) => script_type
                        .map(script_type_to_trigger)
                        .unwrap_or(ExecutionTrigger::Manual),
                    _ => ExecutionTrigger::Manual,
                };
                let lang = match profile.language_decoder {
                    Some(ExecutionDecoder::MayaScriptNodeSourceType) => source_type
                        .map(script_source_type_to_language)
                        .unwrap_or(ExecutionLanguage::Mel),
                    _ => ExecutionLanguage::Mel,
                };
                let source_kind = script_node_source_kind(script_type, source_type);
                for body_attr in &profile.body_attrs {
                    for (_, value) in attr_values.iter().filter(|(attr, _)| attr == body_attr) {
                        let body = crate::mb::decode_best_effort_script_text(value);
                        if body.is_empty() {
                            continue;
                        }
                        let key = (
                            node_name.clone(),
                            format!("{body_attr}:{body}"),
                            lang.as_str(),
                            trigger.as_str(),
                            child.offset,
                        );
                        if !seen.insert(key) {
                            continue;
                        }
                        surfaces.push(ExecutionSurfaceRecord {
                            text: Arc::<str>::from(body),
                            origin: ExecutionOrigin {
                                lang,
                                trigger,
                                surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
                                node_name: Some(node_name.clone()),
                                attr_name: Some(format!(".{body_attr}")),
                                source_range: None,
                                source_kind: source_kind.clone(),
                                chunk_form: Some(form_type.to_string()),
                                chunk_tag: Some("STR ".to_string()),
                                chunk_node_offset: Some(child.offset),
                                ..ExecutionOrigin::without_chunk_address()
                            },
                        });
                    }
                }
            }
            if let NodeExecutionProfileKind::AttrCallbacks(profile) = &profile.kind {
                for callback_attr in &profile.attrs {
                    for (_, value) in attr_values
                        .iter()
                        .filter(|(attr, _)| attr == &callback_attr.short_name)
                    {
                        let body = crate::mb::decode_best_effort_script_text(value);
                        if body.is_empty() {
                            continue;
                        }
                        let key = (
                            node_name.clone(),
                            format!("{}:{body}", callback_attr.short_name),
                            profile.default_language.as_str(),
                            profile.default_trigger.as_str(),
                            child.offset,
                        );
                        if !seen.insert(key) {
                            continue;
                        }
                        surfaces.push(ExecutionSurfaceRecord {
                            text: Arc::<str>::from(body),
                            origin: ExecutionOrigin {
                                lang: profile.default_language,
                                trigger: profile.default_trigger,
                                surface_kind: ExecutionSurfaceKind::NodeAttrCallback,
                                node_name: Some(node_name.clone()),
                                attr_name: Some(format!(".{}", callback_attr.short_name)),
                                source_range: None,
                                source_kind: Some(callback_attr.display_name.clone()),
                                chunk_form: Some(form_type.to_string()),
                                chunk_tag: Some("STR ".to_string()),
                                chunk_node_offset: Some(child.offset),
                                ..ExecutionOrigin::without_chunk_address()
                            },
                        });
                    }
                }
            }
        }
    }

    surfaces
}

fn form_typeid(form_type: &str) -> Option<u32> {
    let bytes: [u8; 4] = form_type.as_bytes().try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn mb_default_selected_node_type(node_name: &str) -> Option<&'static str> {
    match node_name {
        "defaultRenderGlobals" => Some("renderGlobals"),
        _ => None,
    }
}

fn script_node_source_kind(script_type: Option<u32>, source_type: Option<u32>) -> Option<String> {
    match (script_type, source_type) {
        (Some(script_type), Some(source_type)) => {
            Some(format!("scriptType={script_type},sourceType={source_type}"))
        }
        (Some(script_type), None) => Some(format!("scriptType={script_type}")),
        (None, Some(source_type)) => Some(format!("sourceType={source_type}")),
        (None, None) => None,
    }
}

fn push_command_surface(
    surfaces: &mut Vec<ExecutionSurfaceRecord>,
    command: &str,
    surface_kind: ExecutionSurfaceKind,
    trigger: ExecutionTrigger,
    source_kind: Option<String>,
    source_range: Option<ExecutionSourceRange>,
) {
    surfaces.push(ExecutionSurfaceRecord {
        text: Arc::<str>::from(command),
        origin: ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            trigger,
            surface_kind,
            node_name: None,
            attr_name: None,
            source_kind: Some(source_kind.unwrap_or_else(|| "command".to_string())),
            source_range,
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            ..ExecutionOrigin::without_chunk_address()
        },
    });
}

fn script_type_to_trigger(script_type: u32) -> ExecutionTrigger {
    match script_type {
        0 => ExecutionTrigger::Manual,
        1 => ExecutionTrigger::FileOpen,
        2 | 3 => ExecutionTrigger::GuiOpenClose,
        4 | 5 => ExecutionTrigger::Render,
        6 => ExecutionTrigger::FileOpen,
        7 => ExecutionTrigger::TimeChanged,
        _ => ExecutionTrigger::Unknown,
    }
}

fn script_source_type_to_language(source_type: u32) -> ExecutionLanguage {
    match source_type {
        1 => ExecutionLanguage::Python,
        _ => ExecutionLanguage::Mel,
    }
}

fn decode_text_like_payload(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }

    let mut text = String::from_utf8_lossy(payload).into_owned();
    while text.ends_with('\0') {
        text.pop();
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let total_chars = trimmed.chars().count();
    let printable_chars = trimmed
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .count();
    if total_chars == 0 || printable_chars * 5 < total_chars * 4 {
        return None;
    }
    if !trimmed.chars().any(|ch| ch.is_ascii_alphabetic()) {
        return None;
    }

    Some(trimmed.to_string())
}

fn decode_raw_chunk_text(tag: &str, payload: &[u8]) -> Option<String> {
    if tag == "STR " {
        return None;
    }
    if payload.len() > MAX_GENERIC_RAW_TEXT_PAYLOAD_BYTES {
        return None;
    }
    decode_text_like_payload(payload)
}

fn raw_chunk_tag_may_contain_execution_text(tag: &str, payload_len: usize) -> bool {
    match tag {
        "STR " => true,
        // Reference/path inventory chunks can contain words such as "Source" in
        // exporter metadata, but they are dependency evidence rather than code.
        "FRDI" | "FREF" | "RTFT" => false,
        _ => payload_len <= MAX_GENERIC_RAW_TEXT_PAYLOAD_BYTES,
    }
}

fn payload_may_contain_audit_marker(payload: &[u8]) -> bool {
    contains_ascii_case_insensitive(payload, b"python")
        || contains_ascii_case_insensitive(payload, b"exec")
        || contains_ascii_case_insensitive(payload, b"chr")
        || contains_ascii_case_insensitive(payload, b"eval")
        || contains_ascii_case_insensitive(payload, b"scriptjob")
        || contains_ascii_case_insensitive(payload, b"commandport")
        || contains_ascii_case_insensitive(payload, b"loadplugin")
        || contains_ascii_case_insensitive(payload, b"source")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_any_audit_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_call_like_token(&lower, "python")
        || contains_standalone_token(&lower, "exec")
        || contains_call_like_token(&lower, "chr")
        || contains_standalone_token(&lower, "eval")
        || contains_standalone_token(&lower, "evaldeferred")
        || contains_standalone_token(&lower, "scriptjob")
        || contains_standalone_token(&lower, "commandport")
        || contains_standalone_token(&lower, "loadplugin")
        || contains_standalone_token(&lower, "source")
}

fn contains_call_like_token(text: &str, needle: &str) -> bool {
    let mut search_start = 0usize;
    while let Some(found) = text[search_start..].find(needle) {
        let start = search_start + found;
        let end = start + needle.len();
        let left_ok = start == 0
            || !text[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !left_ok {
            search_start = end;
            continue;
        }
        let mut cursor = end;
        while let Some(ch) = text[cursor..].chars().next() {
            if ch.is_ascii_whitespace() {
                cursor += ch.len_utf8();
                continue;
            }
            if ch == '(' {
                return true;
            }
            break;
        }
        search_start = end;
    }
    false
}

fn contains_standalone_token(text: &str, needle: &str) -> bool {
    let mut search_start = 0usize;
    while let Some(found) = text[search_start..].find(needle) {
        let start = search_start + found;
        let end = start + needle.len();
        let left_ok = start == 0
            || !text[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        let right_ok = end == text.len()
            || !text[end..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if left_ok && right_ok {
            return true;
        }
        search_start = end;
    }
    false
}

fn raw_u32_prefix(value: &[u8]) -> Option<u32> {
    if let Some(bytes) = value.get(..8) {
        let raw = u64::from_be_bytes(bytes.try_into().ok()?);
        let decoded = f64::from_bits(raw);
        if decoded.is_finite() && decoded >= 0.0 {
            return Some(decoded as u32);
        }
    }
    let bytes = value.get(..4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

pub(crate) fn preview_window(text: &str, start: usize, end: usize, max_preview: usize) -> String {
    if text.is_empty() || max_preview == 0 {
        return String::new();
    }
    let start = clamp_char_boundary(text, start);
    let end = clamp_char_boundary(text, end);
    let chars: Vec<char> = text.chars().collect();
    let start_char = text[..start].chars().count();
    let end_char = text[..end].chars().count();
    let width = max_preview.max(16);
    let half = width / 2;
    let left = start_char.saturating_sub(half);
    let right = std::cmp::min(chars.len(), end_char + half);
    let mut s: String = chars[left..right].iter().collect();
    s = s
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    s
}

fn clamp_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use maya_scene_kit_formats::{ma, mel};

    use super::{
        MAX_GENERIC_RAW_TEXT_PAYLOAD_BYTES, collect_execution_coverage_from_ma_parts,
        collect_execution_coverage_from_mb, contains_any_audit_marker, decode_raw_chunk_text,
        payload_may_contain_audit_marker, raw_chunk_tag_may_contain_execution_text,
    };
    use crate::scene::{
        ExecutionSurfaceKind,
        schema::{default_schema_registry, node_semantics::node_execution_semantics_with_registry},
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn ma_surfaces_include_file_command_callback_but_not_proc_definition() {
        let input = concat!(
            "//Maya ASCII 2026 scene\n",
            "file -r -command \"onLoad\" \"python(\\\"import os\\\")\" \"C:/ref.ma\";\n",
            "global proc string hello() { return \"ok\"; }\n",
        );

        let script_entries = ma::scripts::extract_raw_script_entries_from_ma(input.as_bytes());
        let top_level = mel::collect_top_level_audit_candidates_from_bytes(input.as_bytes());
        let semantics = node_execution_semantics_with_registry(default_schema_registry())
            .expect("execution semantics");
        let coverage =
            collect_execution_coverage_from_ma_parts(&script_entries, &[], &top_level, &semantics)
                .expect("coverage");
        let surfaces = coverage.surfaces;

        assert!(surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::FileCommandCallback
                && surface.text.as_ref() == r#"python("import os")"#
        }));
        assert!(surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::TopLevelProcDefinition
                && surface.text.as_ref() == r#"global proc string hello() { return "ok"; }"#
        }));
        assert!(!coverage.coverage_issues.is_empty());
    }

    #[test]
    fn ma_surfaces_include_callback_bearing_top_level_command_and_other_statement() {
        let input = concat!(
            "//Maya ASCII 2026 scene\n",
            "nodeOutliner -e -selectCommand \"eval \\\"hello\\\"\" $myoutliner;\n",
            "string $myoutliner = `nodeOutliner -showInputs true -addCommand \"print(\\\"ok\\\")\"`;\n",
        );

        let script_entries = ma::scripts::extract_raw_script_entries_from_ma(input.as_bytes());
        let top_level = mel::collect_top_level_audit_candidates_from_bytes(input.as_bytes());
        let semantics = node_execution_semantics_with_registry(default_schema_registry())
            .expect("execution semantics");
        let coverage =
            collect_execution_coverage_from_ma_parts(&script_entries, &[], &top_level, &semantics)
                .expect("coverage");

        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::TopLevelCommand
                && surface.origin.source_kind.as_deref() == Some("nodeOutliner")
        }));
        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::TopLevelOtherStatement
                && surface.text.contains("-addCommand")
        }));
        assert!(coverage.coverage_issues.iter().any(|issue| {
            matches!(
                issue.detail,
                crate::scene::evidence::ExecutionCoverageIssueDetail::UnsupportedTopLevelStatement
            )
        }));
    }

    #[test]
    fn ma_surfaces_include_schema_selected_node_attr_callbacks() {
        let input = concat!(
            "createNode script -n \"ExampleScript\";\n",
            "    setAttr \".a\" -type \"string\" \"print \\\"after\\\";\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"before\\\";\";\n",
            "    setAttr \".st\" 1;\n",
            "    setAttr \".stp\" 0;\n",
            "createNode renderGlobals -n \"ExampleRenderGlobals\";\n",
            "    setAttr \".prm\" -type \"string\" \"print \\\"render\\\";\";\n",
            "createNode transform -n \"ExampleTransform\";\n",
            "    setAttr \".a\" -type \"string\" \"print \\\"ignored\\\";\";\n",
        );
        let semantics = node_execution_semantics_with_registry(default_schema_registry())
            .expect("execution semantics");
        let sections = ma::selective::extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(
            input.as_bytes(),
            &maya_scene_kit_formats::mel::MelParseBudget::default(),
            semantics.ma_capture_attr_selectors(),
        );

        let coverage = collect_execution_coverage_from_ma_parts(
            sections.dump_sections.script_entries.as_slice(),
            sections.node_attr_values.as_slice(),
            &sections.audit_top_level,
            &semantics,
        )
        .expect("coverage");

        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody
                && surface.origin.attr_name.as_deref() == Some(".a")
                && surface.text.as_ref() == r#"print "after";"#
        }));
        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody
                && surface.origin.attr_name.as_deref() == Some(".b")
                && surface.text.as_ref() == r#"print "before";"#
        }));
        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                && surface.origin.attr_name.as_deref() == Some(".prm")
                && surface.origin.source_kind.as_deref() == Some("preRenderMel")
                && surface.text.as_ref() == r#"print "render";"#
        }));
        assert!(
            !coverage
                .surfaces
                .iter()
                .any(|surface| { surface.origin.node_name.as_deref() == Some("ExampleTransform") })
        );
    }

    #[test]
    fn raw_marker_detection_requires_standalone_tokens() {
        assert!(contains_any_audit_marker(r#"source "tools/startup.mel""#));
        assert!(contains_any_audit_marker(r#"exec "SampleTool.exe""#));
        assert!(!contains_any_audit_marker(
            "setAttr \".x\" -type \"string\" \"fogSource\";"
        ));
        assert!(!contains_any_audit_marker("socket_blinn1SG"));
    }

    #[test]
    fn raw_payload_prefilter_detects_ascii_audit_markers() {
        assert!(payload_may_contain_audit_marker(b"\0Python\0"));
        assert!(payload_may_contain_audit_marker(b"Exec"));
        assert!(payload_may_contain_audit_marker(b"evalDeferred"));
        assert!(payload_may_contain_audit_marker(b"commandPort"));
        assert!(!payload_may_contain_audit_marker(b"socket_blinn1SG"));
        assert!(!payload_may_contain_audit_marker(b"SampleReferenceNode"));
    }

    #[test]
    fn generic_raw_text_decode_skips_large_binary_payloads() {
        let mut payload = vec![0u8; MAX_GENERIC_RAW_TEXT_PAYLOAD_BYTES + 1];
        payload.extend_from_slice(b"source \"tools/startup.mel\"");

        assert!(!raw_chunk_tag_may_contain_execution_text(
            "DATA",
            payload.len()
        ));
        assert!(raw_chunk_tag_may_contain_execution_text(
            "STR ",
            payload.len()
        ));
        assert!(decode_raw_chunk_text("DATA", &payload).is_none());
    }

    #[test]
    fn reference_metadata_chunks_are_not_raw_execution_candidates() {
        for tag in ["FRDI", "FREF", "RTFT"] {
            assert!(!raw_chunk_tag_may_contain_execution_text(tag, 128));
        }
    }

    #[test]
    fn non_script_str_attrs_do_not_fall_back_to_raw_text() {
        let mut payload = b"ExampleOptions\0 ".to_vec();
        payload.extend_from_slice(b"Viewer_Script_D3D=1;TextureType=Default (Match Source Image);");

        assert!(payload_may_contain_audit_marker(&payload));
        assert!(raw_chunk_tag_may_contain_execution_text(
            "STR ",
            payload.len()
        ));
        assert!(decode_raw_chunk_text("STR ", &payload).is_none());
    }

    #[test]
    fn mb_python_socket_fixture_does_not_promote_scrp_crea_as_raw_surface() {
        let source = repo_root().join("tests/02/sphere.mb");
        let mb = crate::mb::parse_file(&source).expect("parse mb");
        let coverage = collect_execution_coverage_from_mb(&mb).expect("coverage");

        assert!(coverage.surfaces.iter().all(|surface| {
            !(surface.origin.surface_kind == ExecutionSurfaceKind::RawChunkText
                && surface.origin.source_kind.as_deref() == Some("SCRP:CREA"))
        }));
    }
}
