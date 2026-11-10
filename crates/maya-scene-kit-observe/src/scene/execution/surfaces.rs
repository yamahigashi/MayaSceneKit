use std::{collections::HashSet, sync::Arc};

use maya_scene_kit_formats::{
    ma::{raw_dump::RawMaNodeAttrValue, scripts::RawMaScriptEntry},
    mel::{self, MelAuditTopLevelItemFact},
};

use crate::{
    mb::{
        FourCC, LayoutHints, MbChildren, MbCompleteness, MbParseBudget, MbTruncationReason,
        resolve_section_layout_hints, visit_group_chunks_with_layout_with_budget,
    },
    scene::{
        ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind, ExecutionLanguage,
        ExecutionOrigin, ExecutionSourceRange, ExecutionSurfaceKind, ExecutionTrigger,
        SceneToolError,
        decode::{attr::decode_attr_payload, dispatcher::DecoderDispatcher},
        ir::{ChunkRef, DecodedEvent, RawChunkRecord, SchemaDecodeAttemptResult},
        schema::{
            SchemaRegistry,
            locator::SchemaPaths,
            node_semantics::{
                ExecutionDecoder, NodeExecutionProfile, NodeExecutionProfileKind,
                NodeExecutionSemantics,
            },
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
    pub(crate) requires_mel_modeling: bool,
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
    connections: &maya_scene_kit_formats::ma::raw_dump::RawMaConnections,
    top_level: &mel::MelAuditTopLevelFacts,
    execution_semantics: &NodeExecutionSemantics,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    collect_ma_coverage(
        script_nodes,
        node_attr_values,
        connections,
        top_level,
        execution_semantics,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn collect_execution_coverage_from_mb(
    mb: &crate::mb::MayaBinaryFile,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    let registry = Arc::new(SchemaRegistry::new(SchemaPaths::from_defaults()));
    let semantics = crate::scene::schema::node_semantics::node_execution_semantics_with_registry(
        registry.as_ref(),
    )
    .map_err(SceneToolError::Config)?;
    collect_mb_coverage(
        mb,
        &mb.completeness(),
        crate::mb::extract_head_metadata_with_budget(mb, &MbParseBudget::default()).section_state,
        None,
        registry,
        semantics.as_ref(),
    )
}

pub(crate) fn collect_execution_coverage_from_mb_with_budget(
    mb: &crate::mb::MayaBinaryFile,
    completeness: &MbCompleteness,
    extraction_state: crate::mb::MbSectionScanState,
    budget: &MbParseBudget,
    registry: Arc<SchemaRegistry>,
    execution_semantics: &NodeExecutionSemantics,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    collect_mb_coverage(
        mb,
        completeness,
        extraction_state,
        Some(budget),
        registry,
        execution_semantics,
    )
}

fn collect_ma_coverage(
    script_nodes: &[RawMaScriptEntry],
    node_attr_values: &[RawMaNodeAttrValue],
    connections: &maya_scene_kit_formats::ma::raw_dump::RawMaConnections,
    top_level: &mel::MelAuditTopLevelFacts,
    execution_semantics: &NodeExecutionSemantics,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    let mut assignment_issues = collect_ma_script_assignment_issues(script_nodes);
    let (before, mut attributes): (Vec<_>, Vec<_>) = collect_ma_script_node_surfaces(script_nodes)
        .into_iter()
        .partition(|(_, surface)| surface.origin.attr_name.as_deref() == Some(".b"));
    attributes.extend(collect_ma_profile_node_attr_surfaces(
        node_attr_values,
        execution_semantics,
        &mut assignment_issues,
    ));
    attributes.sort_by_key(|(start, _)| *start);
    let (connected, connected_targets, connected_controls) = collect_ma_connections(
        connections,
        script_nodes,
        execution_semantics,
        &mut assignment_issues,
    );
    let mut surfaces: Vec<_> = before
        .into_iter()
        .chain(attributes)
        .map(|(start, mut surface)| {
            if let Some(id) = connections.direct_assignments.get(&start) {
                surface.origin.overwritten_by_connection =
                    connected_targets.get(id).is_some_and(|(node_type, attrs)| {
                        let spelling = surface.origin.attr_name.as_deref().unwrap_or_default();
                        let canonical = execution_semantics
                            .canonical_attr(node_type, spelling)
                            .unwrap_or(spelling.trim_start_matches('.'));
                        attrs.contains(canonical)
                    });
                if connected_controls.contains(id) {
                    surface.origin.lang = ExecutionLanguage::Unknown;
                    surface.origin.trigger = ExecutionTrigger::Unknown;
                }
            }
            surface
        })
        .collect();
    surfaces.extend(connected);
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
    coverage_issues.extend(assignment_issues);
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
                            command.schema_has_script_flag,
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
                        requires_mel_modeling: true,
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
                    false,
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
                        false,
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
                        false,
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

fn connection_destination_attr(
    plug: &maya_scene_kit_formats::ma::raw_dump::RawMaConnectionPlug,
    semantics: &NodeExecutionSemantics,
) -> Option<String> {
    let last = plug.attr.rsplit('.').next()?.split('[').next()?;
    let spelling = format!(".{last}");
    semantics
        .ma_capture_attr_selectors()
        .iter()
        .filter(|selector| {
            selector.attr == spelling
                && (selector.node_type.is_empty()
                    || ma_effective_node_type(
                        plug.node_type.as_deref().unwrap_or_default(),
                        &plug.owner,
                    )
                    .eq_ignore_ascii_case(&selector.node_type))
                && selector
                    .node_name
                    .as_deref()
                    .is_none_or(|name| name == plug.owner)
        })
        .max_by_key(|selector| (!selector.node_type.is_empty(), selector.node_name.is_some()))
        .map(|selector| selector.canonical_attr.clone())
}

type MaConnectedTargets = std::collections::HashMap<u32, (String, HashSet<String>)>;

fn collect_ma_connections(
    connections: &maya_scene_kit_formats::ma::raw_dump::RawMaConnections,
    scripts: &[RawMaScriptEntry],
    semantics: &NodeExecutionSemantics,
    issues: &mut Vec<ExecutionCoverageIssueRecord>,
) -> (
    Vec<ExecutionSurfaceRecord>,
    MaConnectedTargets,
    HashSet<u32>,
) {
    let mut surfaces = Vec::new();
    let mut scripts_by_id = std::collections::HashMap::new();
    for script in scripts {
        for assignment in &script.assignments {
            if let Some(id) = connections.direct_assignments.get(&assignment.start) {
                scripts_by_id.entry(*id).or_insert(script);
            }
        }
    }
    let mut targets = MaConnectedTargets::new();
    let mut controls = HashSet::new();
    for connection in &connections.connections {
        let dst = &connection.destination;
        let node_type =
            ma_effective_node_type(dst.node_type.as_deref().unwrap_or_default(), &dst.owner);
        let canonical = connection_destination_attr(dst, semantics);
        if node_type == "script" && matches!(canonical.as_deref(), Some(".st" | ".stp")) {
            if let Some(id) = dst.history_id {
                controls.insert(id);
            }
        }
    }
    for connection in &connections.connections {
        let src = &connection.source;
        let dst = &connection.destination;
        let node_type =
            ma_effective_node_type(dst.node_type.as_deref().unwrap_or_default(), &dst.owner);
        if dst.is_default && semantics.profiles_for_node(node_type).is_empty() {
            continue;
        }
        let canonical = connection_destination_attr(dst, semantics);
        let history = src.key.and_then(|key| connections.assignments.get(&key));
        let candidate = dst
            .attr
            .rsplit('.')
            .next()
            .unwrap_or(&dst.attr)
            .split('[')
            .next()
            .unwrap_or("");
        let unknown_candidate = node_type.is_empty()
            && !dst.is_default
            && semantics
                .ma_capture_attr_selectors()
                .iter()
                .any(|selector| selector.attr.strip_prefix('.') == Some(candidate))
            && (!semantics.ma_execution_attr_is_ambiguous(candidate)
                || history.is_some()
                || (src.history_id.is_none() && !dst.owner.contains(':')));
        if canonical.is_none() && !unknown_candidate {
            continue;
        }
        let attr = canonical.unwrap_or_else(|| format!(".{candidate}"));
        let mut origin = ExecutionOrigin {
            node_name: Some(dst.owner.clone()),
            attr_name: Some(attr.clone()),
            connection_source_plug: Some(format!("{}.{}", src.owner, src.attr)),
            connection_range: Some(ExecutionSourceRange {
                start: connection.start,
                end: connection.end,
            }),
            source_range: Some(ExecutionSourceRange {
                start: connection.start,
                end: connection.end,
            }),
            ..ExecutionOrigin::without_chunk_address()
        };
        let mut issue = |reason: String, origin: &ExecutionOrigin| {
            issues.push(ExecutionCoverageIssueRecord {
                kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
                detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics { diagnostic: reason },
                origin: Some(origin.clone()),
                preview: PreviewWindowSpec::new(Arc::from(""), 0, 0),
            });
        };
        if node_type.is_empty() || dst.attr.contains(['.', '[']) {
            issue("cannot resolve connection destination".into(), &origin);
            continue;
        }
        if node_type == "script" && matches!(attr.as_str(), ".st" | ".stp") {
            issue(
                "cannot determine connected trigger / language".into(),
                &origin,
            );
            continue;
        }
        if let Some(id) = dst.history_id {
            targets
                .entry(id)
                .or_insert_with(|| (node_type.to_string(), HashSet::new()))
                .1
                .insert(attr.trim_start_matches('.').to_string());
        }
        if node_type == "script" {
            origin.surface_kind = ExecutionSurfaceKind::ScriptNodeBody;
            let script = dst
                .history_id
                .and_then(|id| scripts_by_id.get(&id).copied());
            let (trigger, lang) = script
                .map(ma_script_execution_context)
                .unwrap_or((ExecutionTrigger::Manual, ExecutionLanguage::Mel));
            origin.trigger = trigger;
            origin.lang = lang;
            origin.source_kind = script
                .and_then(|node| script_node_source_kind(node.script_type(), node.source_type()))
                .or_else(|| (attr == ".a").then(|| "a".to_string()));
        } else {
            let Some(template) = ma_callback_origin(node_type, &dst.owner, &attr, semantics) else {
                continue;
            };
            origin = ExecutionOrigin {
                source_range: origin.source_range,
                connection_range: origin.connection_range,
                connection_source_plug: origin.connection_source_plug,
                ..template
            };
        }
        if dst.history_id.is_some_and(|id| controls.contains(&id)) {
            origin.trigger = ExecutionTrigger::Unknown;
            origin.lang = ExecutionLanguage::Unknown;
        }
        if src.history_id.is_none() || src.attr.contains(['.', '[']) {
            issue("cannot resolve connection source".into(), &origin);
            continue;
        }
        let key = src.key.expect("resolved source key");
        if connections.ambiguous_aliases.contains(&key) {
            issue("connection source alias is unresolved".into(), &origin);
        }
        let source_type = src.node_type.as_deref().unwrap_or_default();
        let source_attr = semantics.canonical_attr(source_type, &src.attr);
        if src
            .history_id
            .and_then(|id| connections.incoming.get(&id))
            .is_some_and(|attrs| {
                attrs.iter().any(|attr| {
                    match (source_attr, semantics.canonical_attr(source_type, attr)) {
                        (Some(source), Some(incoming)) => source == incoming,
                        _ => true,
                    }
                })
            })
        {
            issue(
                "connection source has an incoming connection; multiple hops are unresolved".into(),
                &origin,
            );
        }
        let Some(history) = history else {
            issue("connection source has no string assignment".into(), &origin);
            continue;
        };
        for (index, assignment) in history.iter().enumerate() {
            let mut origin = origin.clone();
            origin.overwritten = index + 1 != history.len();
            origin.assignment_index = Some(index);
            origin.connection_source_range = Some(ExecutionSourceRange {
                start: assignment.start,
                end: assignment.end,
            });
            match &assignment.value {
                Some(value) if !value.is_empty() => surfaces.push(ExecutionSurfaceRecord {
                    text: Arc::from(value.as_str()),
                    origin,
                    requires_mel_modeling: true,
                }),
                Some(_) => {}
                None => issue(
                    format!(
                        "cannot read connection source assignment at {}..{}",
                        assignment.start, assignment.end
                    ),
                    &origin,
                ),
            }
        }
    }
    (surfaces, targets, controls)
}

fn collect_ma_script_node_surfaces(
    script_nodes: &[RawMaScriptEntry],
) -> Vec<(usize, ExecutionSurfaceRecord)> {
    let mut surfaces = Vec::new();
    for attr in [".b", ".a"] {
        for node in script_nodes {
            let (trigger, lang) = ma_script_execution_context(node);
            let source_kind = script_node_source_kind(node.script_type(), node.source_type())
                .or_else(|| (attr == ".a").then(|| "a".to_string()));
            let last = node
                .assignments
                .iter()
                .rposition(|value| value.attr == attr);
            for (index, assignment) in node.assignments.iter().enumerate() {
                if assignment.attr != attr {
                    continue;
                }
                let Some(body) = assignment
                    .string_value
                    .as_deref()
                    .filter(|body| !body.is_empty())
                else {
                    continue;
                };
                let overwritten = Some(index) != last;
                surfaces.push((
                    assignment.start,
                    ExecutionSurfaceRecord {
                        text: Arc::from(body),
                        origin: ExecutionOrigin {
                            lang,
                            trigger,
                            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
                            node_name: Some(node.name.clone()),
                            attr_name: Some(attr.to_string()),
                            source_kind: source_kind.clone(),
                            overwritten,
                            assignment_index: overwritten.then_some(index),
                            ..ExecutionOrigin::without_chunk_address()
                        },
                        requires_mel_modeling: true,
                    },
                ));
            }
        }
    }
    surfaces
}

fn ma_script_execution_context(node: &RawMaScriptEntry) -> (ExecutionTrigger, ExecutionLanguage) {
    let trigger = match node.last_assignment(".st") {
        None => ExecutionTrigger::Manual,
        Some(value) => value
            .u32_value
            .map(script_type_to_trigger)
            .unwrap_or(ExecutionTrigger::Unknown),
    };
    let lang = match node.last_assignment(".stp") {
        None => ExecutionLanguage::Mel,
        Some(value) => value
            .u32_value
            .map(script_source_type_to_language)
            .unwrap_or(ExecutionLanguage::Unknown),
    };
    (trigger, lang)
}

fn collect_ma_script_assignment_issues(
    script_nodes: &[RawMaScriptEntry],
) -> Vec<ExecutionCoverageIssueRecord> {
    let mut issues = Vec::new();
    for node in script_nodes {
        let (trigger, lang) = ma_script_execution_context(node);
        let origin = ExecutionOrigin {
            trigger,
            lang,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            node_name: Some(node.name.clone()),
            ..ExecutionOrigin::without_chunk_address()
        };
        if [".st", ".stp"].iter().any(|attr| {
            node.last_assignment(attr)
                .is_some_and(|value| value.u32_value.is_none())
        }) {
            issues.push(ExecutionCoverageIssueRecord {
                kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
                detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
                    diagnostic: "cannot determine trigger / language".to_string(),
                },
                origin: Some(origin.clone()),
                preview: PreviewWindowSpec::new(Arc::from(""), 0, 0),
            });
        }
        for assignment in &node.assignments {
            if matches!(assignment.attr.as_str(), ".b" | ".a") && assignment.string_value.is_none()
            {
                issues.push(ExecutionCoverageIssueRecord {
                    kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
                    detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
                        diagnostic: "cannot read script body assignment".to_string(),
                    },
                    origin: Some(ExecutionOrigin {
                        attr_name: Some(assignment.attr.clone()),
                        source_range: Some(crate::scene::evidence::ExecutionSourceRange {
                            start: assignment.start,
                            end: assignment.end,
                        }),
                        ..origin.clone()
                    }),
                    preview: PreviewWindowSpec::new(Arc::from(""), 0, 0),
                });
            }
        }
    }
    issues
}

fn ma_callback_origin(
    node_type: &str,
    node_name: &str,
    attr: &str,
    semantics: &NodeExecutionSemantics,
) -> Option<ExecutionOrigin> {
    let attr_name = attr.trim_start_matches('.');
    let mut origin = ExecutionOrigin {
        node_name: Some(node_name.to_string()),
        attr_name: Some(attr.to_string()),
        surface_kind: ExecutionSurfaceKind::NodeAttrCallback,
        ..ExecutionOrigin::without_chunk_address()
    };
    for profile in semantics.profiles_for_node(node_type) {
        if let NodeExecutionProfileKind::AttrCallbacks(profile) = &profile.kind {
            if profile
                .attrs
                .iter()
                .any(|candidate| candidate.short_name == attr_name)
            {
                origin.lang = profile.default_language;
                origin.trigger = profile.default_trigger;
                origin.source_kind = semantics
                    .source_label(node_type, attr_name)
                    .map(str::to_string)
                    .or_else(|| Some(attr_name.to_string()));
                return Some(origin);
            }
        }
    }
    if is_generic_execution_attr_name(attr_name) {
        origin.lang = ExecutionLanguage::Mel;
        origin.trigger = generic_execution_attr_trigger(attr_name);
        origin.source_kind = Some(attr_name.to_string());
        return Some(origin);
    }
    None
}

fn collect_ma_profile_node_attr_surfaces(
    node_attr_values: &[RawMaNodeAttrValue],
    execution_semantics: &NodeExecutionSemantics,
    issues: &mut Vec<ExecutionCoverageIssueRecord>,
) -> Vec<(usize, ExecutionSurfaceRecord)> {
    let mut surfaces = Vec::new();
    for value in node_attr_values {
        let node_type = ma_effective_node_type(&value.node_type, &value.node_name);
        if node_type.is_empty() {
            continue;
        }
        let attr_name = value.attr.trim_start_matches('.');
        let mut matched_profile = false;
        for profile in execution_semantics.profiles_for_node(node_type) {
            match &profile.kind {
                NodeExecutionProfileKind::ScriptNode(profile)
                    if profile.body_attrs.iter().any(|attr| attr == attr_name) =>
                {
                    matched_profile = true;
                    if value.node_type == "script" && matches!(attr_name, "b" | "a") {
                        continue;
                    }
                    let Some(body) = value.string_value.as_ref() else {
                        issues.push(unreadable_ma_node_attr_issue(value));
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
                    surfaces.push((
                        value.start,
                        ExecutionSurfaceRecord {
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
                            requires_mel_modeling: true,
                        },
                    ));
                }
                NodeExecutionProfileKind::AttrCallbacks(profile)
                    if profile
                        .attrs
                        .iter()
                        .any(|attr| attr.short_name == attr_name) =>
                {
                    matched_profile = true;
                    let Some(body) = value.string_value.as_ref() else {
                        issues.push(unreadable_ma_node_attr_issue(value));
                        continue;
                    };
                    if body.is_empty() {
                        continue;
                    }
                    surfaces.push((
                        value.start,
                        ExecutionSurfaceRecord {
                            text: Arc::<str>::from(body.as_str()),
                            origin: ma_callback_origin(
                                node_type,
                                &value.node_name,
                                &value.attr,
                                execution_semantics,
                            )
                            .expect("matched callback profile"),
                            requires_mel_modeling: true,
                        },
                    ));
                }
                _ => {}
            }
        }
        if matched_profile || !is_generic_execution_attr_name(attr_name) {
            continue;
        }
        let Some(body) = value.string_value.as_ref() else {
            issues.push(unreadable_ma_node_attr_issue(value));
            continue;
        };
        if body.is_empty() {
            continue;
        }
        surfaces.push((
            value.start,
            ExecutionSurfaceRecord {
                text: Arc::<str>::from(body.as_str()),
                origin: ma_callback_origin(
                    node_type,
                    &value.node_name,
                    &value.attr,
                    execution_semantics,
                )
                .expect("generic callback attribute"),
                requires_mel_modeling: true,
            },
        ));
    }
    surfaces
}

fn unreadable_ma_node_attr_issue(value: &RawMaNodeAttrValue) -> ExecutionCoverageIssueRecord {
    ExecutionCoverageIssueRecord {
        kind: ExecutionCoverageIssueKind::SurfaceDiagnostics,
        detail: ExecutionCoverageIssueDetail::SurfaceDiagnostics {
            diagnostic: "cannot read execution attribute assignment".to_string(),
        },
        origin: Some(ExecutionOrigin {
            lang: ExecutionLanguage::Unknown,
            trigger: ExecutionTrigger::Unknown,
            surface_kind: ExecutionSurfaceKind::NodeAttrCallback,
            node_name: Some(value.node_name.clone()),
            attr_name: Some(value.attr.clone()),
            source_range: Some(ExecutionSourceRange {
                start: value.start,
                end: value.end,
            }),
            ..ExecutionOrigin::without_chunk_address()
        }),
        preview: PreviewWindowSpec::new(Arc::from(""), 0, 0),
    }
}

fn is_generic_execution_attr_name(attr_name: &str) -> bool {
    crate::scene::schema::node_semantics::generic_execution_attr_names()
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(attr_name))
}

fn generic_execution_attr_trigger(attr_name: &str) -> ExecutionTrigger {
    if attr_name.to_ascii_lowercase().contains("render") {
        ExecutionTrigger::Render
    } else {
        ExecutionTrigger::Unknown
    }
}

fn ma_effective_node_type<'a>(node_type: &'a str, node_name: &str) -> &'a str {
    if !node_type.is_empty() {
        return node_type;
    }
    match node_name {
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
            ma_effective_node_type(&value.node_type, &value.node_name) == node_type
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
    completeness: &MbCompleteness,
    extraction_state: crate::mb::MbSectionScanState,
    budget: Option<&MbParseBudget>,
    registry: Arc<SchemaRegistry>,
    execution_semantics: &NodeExecutionSemantics,
) -> Result<ExecutionCoverageCollection, SceneToolError> {
    let (surfaces, mut section_state) = collect_mb_native_script_surfaces(
        mb,
        execution_semantics,
        budget.unwrap_or(&MbParseBudget::default()),
    );
    section_state.merge(extraction_state);
    let mut coverage_issues = Vec::new();
    let dispatcher = DecoderDispatcher::new(registry);

    for child in mb.root().children() {
        if !child.is_group() {
            continue;
        }
        let form = child.form_type().map(|f| f.to_string()).unwrap_or_default();
        let hints = resolve_section_layout_hints(
            child.tag(),
            child.form_type(),
            child
                .child_layout()
                .map_or_else(LayoutHints::new, LayoutHints::from),
        );
        let child_alignment = hints.alignment().map(|a| a.get());
        let child_header_size = hints.header_format().map(|f| f.header_size());
        let payload = &mb.data()[child.payload_offset()..child.payload_end()];
        let inner_data = if payload.len() >= 4 {
            &payload[4..]
        } else {
            &[]
        };

        let visit = |chunk: crate::mb::SectionChunk| {
            if raw_chunk_form_is_known_benign_container(form.as_str()) {
                return;
            }
            if !raw_chunk_tag_may_contain_execution_text(chunk.tag(), chunk.payload_span().len()) {
                return;
            }
            let raw = RawChunkRecord {
                chunk_ref: ChunkRef {
                    form: form.clone(),
                    tag: chunk.tag().to_string(),
                    node_offset: child.offset(),
                    parent_tag: Some(child.tag().to_string()),
                    chunk_aux: Some(chunk.aux()),
                    child_alignment,
                    child_header_size,
                    payload_size: chunk.payload_span().len(),
                },
                payload_span: chunk.payload_span().offset(child.payload_offset() + 4),
            };
            let chunk_payload = raw.payload(mb.data());
            let decoded = dispatcher.decode_with_quality(
                &raw.chunk_ref.form,
                &raw.chunk_ref.tag,
                chunk_payload,
                raw.chunk_ref.node_offset,
                raw.chunk_ref.chunk_aux,
                raw.chunk_ref.child_alignment,
                raw.chunk_ref.child_header_size,
                Some(raw.chunk_ref.form.as_str()),
                raw.chunk_ref.parent_tag.as_deref(),
            );
            if decoded.quality != SchemaDecodeAttemptResult::Failed {
                return;
            }
            if !decoded
                .events
                .iter()
                .all(|event| matches!(event, DecodedEvent::Unknown(_)))
            {
                return;
            }
            let Some(text) = decode_raw_chunk_text(raw.chunk_ref.tag.as_str(), chunk_payload)
            else {
                return;
            };
            let marker = first_payload_audit_marker(chunk_payload)
                .filter(|_| contains_any_audit_marker(&text));
            let (kind, detail) = if let Some(marker) = marker {
                (
                    ExecutionCoverageIssueKind::UnknownRawMbPayload,
                    ExecutionCoverageIssueDetail::UnknownRawMbPayload { marker },
                )
            } else {
                (
                    ExecutionCoverageIssueKind::UnexplainedRawMbPayload,
                    ExecutionCoverageIssueDetail::UnexplainedRawMbPayload {
                        reason: format!(
                            "undecoded text-like MB payload in {}:{}",
                            raw.chunk_ref.form, raw.chunk_ref.tag
                        ),
                    },
                )
            };

            coverage_issues.push(ExecutionCoverageIssueRecord {
                kind,
                detail,
                origin: Some(ExecutionOrigin {
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
                    overwritten: false,
                    assignment_index: None,
                    ..ExecutionOrigin::without_chunk_address()
                }),
                preview: PreviewWindowSpec::prefix(Arc::<str>::from(text)),
            });
        };
        section_state.merge(match budget {
            Some(budget) => {
                visit_group_chunks_with_layout_with_budget(inner_data, hints, 2, budget, visit)?
            }
            None => crate::mb::visit_group_chunks_with_layout(inner_data, hints, visit),
        });
    }

    if let MbCompleteness::Truncated { .. } = completeness {
        let mut reasons = Vec::new();
        let mut reason_kinds = HashSet::new();
        for chunk in mb.walk() {
            let reason = match chunk.children_state() {
                MbChildren::NotExpanded => &MbTruncationReason::DepthLimit,
                MbChildren::Truncated { reason, .. } => reason,
                _ => continue,
            };
            if reason_kinds.insert(std::mem::discriminant(reason)) {
                reasons.push(reason.to_string());
            }
        }
        let reason = format!(
            "MB chunk tree {completeness}; reasons=[{}]",
            reasons.join(", ")
        );
        coverage_issues.push(ExecutionCoverageIssueRecord {
            kind: ExecutionCoverageIssueKind::UnexplainedRawMbPayload,
            preview: PreviewWindowSpec::prefix(Arc::from(reason.as_str())),
            detail: ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason },
            origin: None,
        });
    }

    if matches!(completeness, MbCompleteness::Complete)
        && section_state == crate::mb::MbSectionScanState::Stopped
    {
        let reason = "MB section scan stopped".to_string();
        coverage_issues.push(ExecutionCoverageIssueRecord {
            kind: ExecutionCoverageIssueKind::UnexplainedRawMbPayload,
            preview: PreviewWindowSpec::prefix(Arc::from(reason.as_str())),
            detail: ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason },
            origin: None,
        });
    }
    Ok(ExecutionCoverageCollection {
        surfaces,
        coverage_issues,
    })
}

fn collect_mb_script_body_assignments<'a>(
    body_attrs: &'a [String],
    attr_values: &[(String, Vec<u8>, String, usize)],
    owner_offset: usize,
    seen_offsets: &mut HashSet<(usize, usize)>,
) -> Vec<(bool, usize, &'a str, String)> {
    let mut bodies = Vec::new();
    for body_attr in body_attrs {
        let last = attr_values
            .iter()
            .rposition(|(attr, _, tag, _)| attr == body_attr && tag != "FLGS");
        for (index, (_, value, _, offset)) in attr_values
            .iter()
            .enumerate()
            .filter(|(_, (attr, _, tag, _))| attr == body_attr && tag != "FLGS")
        {
            let body = crate::mb::decode_best_effort_script_text(value);
            if body.is_empty() || !seen_offsets.insert((owner_offset, *offset)) {
                continue;
            }
            bodies.push((Some(index) != last, index, body_attr.as_str(), body));
        }
    }
    bodies.sort_by_key(|(overwritten, index, _, _)| {
        (*overwritten, if *overwritten { *index } else { 0 })
    });
    bodies
}

fn collect_mb_native_script_surfaces(
    mb: &crate::mb::MayaBinaryFile,
    execution_semantics: &NodeExecutionSemantics,
    budget: &MbParseBudget,
) -> (Vec<ExecutionSurfaceRecord>, crate::mb::MbSectionScanState) {
    let mut surfaces = Vec::new();
    let mut state = crate::mb::MbSectionScanState::Complete;
    let mut seen = HashSet::new();
    let mut script_offsets = HashSet::new();

    for child in mb.root().children() {
        if !child.is_group() {
            continue;
        }
        let Some(form_type) = child.form_type().map(|f| f.to_string()) else {
            continue;
        };
        let hints = resolve_section_layout_hints(
            child.tag(),
            child.form_type(),
            child
                .child_layout()
                .map_or_else(LayoutHints::new, LayoutHints::from),
        );
        let child_alignment = hints.alignment().map(|a| a.get());
        let child_header_size = hints.header_format().map(|f| f.header_size());
        let payload = &mb.data()[child.payload_offset()..child.payload_end()];
        if payload.len() < 4 || &payload[..4] != form_type.as_bytes() {
            continue;
        }

        let parsed =
            crate::mb::parse_section_chunks_with_hints_with_budget(&payload[4..], hints, budget);
        state.merge(parsed.state());
        let mut selected_node_name = None;
        let node_type = form_typeid(&form_type)
            .and_then(|typeid| execution_semantics.node_type_for_typeid(typeid));
        let mut node_type = node_type.map(str::to_string);
        if form_type == "SLCT" {
            let selected = parsed.chunks().iter().find_map(|chunk| {
                if chunk.tag() != "SLCT" {
                    return None;
                }
                let text = String::from_utf8_lossy(chunk.payload(&payload[4..]));
                let trimmed = text.trim_matches(char::from(0)).trim();
                (!trimmed.is_empty()).then(|| trimmed.trim_start_matches(':').to_string())
            });
            node_type = node_type.or_else(|| {
                selected
                    .as_deref()
                    .and_then(mb_default_selected_node_type)
                    .map(str::to_string)
            });
            selected_node_name = selected;
        }
        let profiles = node_type
            .as_deref()
            .map(|node_type| execution_semantics.profiles_for_node(node_type))
            .unwrap_or(&[]);
        let mut node_name = format!("<{}@0x{:X}>", form_type, child.offset());
        if let Some(selected_node_name) = &selected_node_name {
            node_name = selected_node_name.clone();
        } else if let Some(decoded_node_name) =
            crate::mb::paths::extract_mb_form_node_name_with_layout(
                payload,
                child_alignment,
                child_header_size,
                budget,
            )
            .value
        {
            node_name = decoded_node_name;
        }
        let mut script_type = None;
        let mut source_type = None;
        let mut attr_values = Vec::<(String, Vec<u8>, String, usize)>::new();

        for chunk in parsed.chunks() {
            if chunk.tag() == "CREA" || (form_type == "SCRP" && chunk.tag() == "FLGS") {
                continue;
            }

            let Some((attr_name, _kind, value)) = decode_attr_payload(chunk.payload(&payload[4..]))
            else {
                continue;
            };
            attr_values.push((
                attr_name,
                value,
                chunk.tag().to_string(),
                chunk.chunk_start(),
            ));
        }

        for profile in profiles {
            if let NodeExecutionProfileKind::ScriptNode(profile) = &profile.kind {
                if let Some(trigger_attr) = &profile.trigger_attr {
                    script_type = attr_values
                        .iter()
                        .rev()
                        .find(|(attr, _, _, _)| attr == trigger_attr)
                        .and_then(|(_, value, tag, _)| mb_script_number(tag, value));
                }
                if let Some(language_attr) = &profile.language_attr {
                    source_type = attr_values
                        .iter()
                        .rev()
                        .find(|(attr, _, _, _)| attr == language_attr)
                        .and_then(|(_, value, tag, _)| mb_script_number(tag, value));
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
                for (overwritten, index, body_attr, body) in collect_mb_script_body_assignments(
                    &profile.body_attrs,
                    &attr_values,
                    child.offset(),
                    &mut script_offsets,
                ) {
                    surfaces.push(ExecutionSurfaceRecord {
                        text: Arc::from(body),
                        origin: ExecutionOrigin {
                            lang,
                            trigger,
                            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
                            node_name: Some(node_name.clone()),
                            attr_name: Some(format!(".{body_attr}")),
                            source_kind: source_kind.clone(),
                            chunk_form: Some(form_type.to_string()),
                            chunk_tag: Some("STR ".to_string()),
                            chunk_node_offset: Some(child.offset()),
                            overwritten,
                            assignment_index: overwritten.then_some(index),
                            ..ExecutionOrigin::without_chunk_address()
                        },
                        requires_mel_modeling: true,
                    });
                }
            }
            if let NodeExecutionProfileKind::AttrCallbacks(profile) = &profile.kind {
                for callback_attr in &profile.attrs {
                    for (_, value, _, _) in attr_values
                        .iter()
                        .filter(|(attr, _, _, _)| attr == &callback_attr.short_name)
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
                            child.offset(),
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
                                chunk_node_offset: Some(child.offset()),
                                ..ExecutionOrigin::without_chunk_address()
                            },
                            requires_mel_modeling: true,
                        });
                    }
                }
            }
        }
        for (attr_name, value, _, _) in &attr_values {
            if profile_matches_attr(profiles, attr_name)
                || !is_generic_execution_attr_name(attr_name.as_str())
            {
                continue;
            }
            let body = crate::mb::decode_best_effort_script_text(value);
            if body.is_empty() {
                continue;
            }
            let key = (
                node_name.clone(),
                format!("{attr_name}:{body}"),
                ExecutionLanguage::Mel.as_str(),
                generic_execution_attr_trigger(attr_name).as_str(),
                child.offset(),
            );
            if !seen.insert(key) {
                continue;
            }
            surfaces.push(ExecutionSurfaceRecord {
                text: Arc::<str>::from(body),
                origin: ExecutionOrigin {
                    lang: ExecutionLanguage::Mel,
                    trigger: generic_execution_attr_trigger(attr_name),
                    surface_kind: ExecutionSurfaceKind::NodeAttrCallback,
                    node_name: Some(node_name.clone()),
                    attr_name: Some(format!(".{attr_name}")),
                    source_range: None,
                    source_kind: Some(attr_name.clone()),
                    chunk_form: Some(form_type.to_string()),
                    chunk_tag: Some("STR ".to_string()),
                    chunk_node_offset: Some(child.offset()),
                    ..ExecutionOrigin::without_chunk_address()
                },
                requires_mel_modeling: true,
            });
        }
    }

    (surfaces, state)
}

fn profile_matches_attr(profiles: &[NodeExecutionProfile], attr_name: &str) -> bool {
    profiles.iter().any(|profile| match &profile.kind {
        NodeExecutionProfileKind::ScriptNode(profile) => {
            profile.body_attrs.iter().any(|attr| attr == attr_name)
                || profile.trigger_attr.as_deref() == Some(attr_name)
                || profile.language_attr.as_deref() == Some(attr_name)
        }
        NodeExecutionProfileKind::AttrCallbacks(profile) => profile
            .attrs
            .iter()
            .any(|attr| attr.short_name == attr_name),
    })
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
    requires_mel_modeling: bool,
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
        requires_mel_modeling,
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

fn raw_chunk_tag_may_contain_execution_text(tag: FourCC, payload_len: usize) -> bool {
    match tag.as_ascii() {
        None => false,
        Some("STR ") => true,
        // Reference/path inventory chunks can contain words such as "Source" in
        // exporter metadata, but they are dependency evidence rather than code.
        Some("FRDI") | Some("FREF") | Some("RTFT") => false,
        _ => payload_len <= MAX_GENERIC_RAW_TEXT_PAYLOAD_BYTES,
    }
}

fn raw_chunk_form_is_known_benign_container(form: &str) -> bool {
    matches!(form, "HEAD")
}

fn first_payload_audit_marker(payload: &[u8]) -> Option<String> {
    [
        "python",
        "exec",
        "chr",
        "eval",
        "scriptjob",
        "commandport",
        "loadplugin",
        "source",
    ]
    .into_iter()
    .find(|marker| contains_ascii_case_insensitive(payload, marker.as_bytes()))
    .map(str::to_string)
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

fn mb_script_number(tag: &str, value: &[u8]) -> Option<u32> {
    matches!(tag, "DBLE" | "FLT " | "LONG" | "SHRT" | "BOOL")
        .then(|| raw_u32_prefix(value))
        .flatten()
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

    use maya_scene_kit_formats::{ma, mb::FourCC, mel};

    use super::{
        ExecutionCoverageCollection, MAX_GENERIC_RAW_TEXT_PAYLOAD_BYTES,
        collect_execution_coverage_from_ma_parts, collect_execution_coverage_from_mb,
        contains_any_audit_marker, decode_raw_chunk_text, first_payload_audit_marker,
        raw_chunk_tag_may_contain_execution_text,
    };
    use crate::scene::{
        ExecutionSurfaceKind,
        evidence::{ExecutionCoverageIssueDetail, ExecutionLanguage, ExecutionTrigger},
        schema::{default_schema_registry, node_semantics::node_execution_semantics_with_registry},
    };

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn build_mb_chunk_with_alignment(
        tag: &str,
        payload: &[u8],
        sibling_alignment: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(payload);
        while (out.len() - 16) % sibling_alignment != 0 {
            out.push(0);
        }
        out
    }

    fn build_mb_chunk(tag: &str, payload: &[u8]) -> Vec<u8> {
        build_mb_chunk_with_alignment(tag, payload, 8)
    }

    fn build_mb_form(form: &str, children: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = form.as_bytes().to_vec();
        for child in children {
            payload.extend_from_slice(child);
        }
        build_mb_chunk_with_alignment("FOR8", &payload, 4)
    }

    fn build_mb_root(children: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = b"Maya".to_vec();
        for child in children {
            payload.extend_from_slice(child);
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"FOR8");
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn script_history_coverage(input: &str, capture: bool) -> ExecutionCoverageCollection {
        let semantics = node_execution_semantics_with_registry(default_schema_registry()).unwrap();
        let sections = ma::selective::extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(
            input.as_bytes(),
            &maya_scene_kit_formats::mel::MelParseBudget::default(),
            semantics.ma_capture_attr_selectors(),
        );
        collect_execution_coverage_from_ma_parts(
            &sections.dump_sections.script_entries,
            if capture {
                &sections.node_attr_values
            } else {
                &[]
            },
            &sections.connections,
            &sections.audit_top_level,
            &semantics,
        )
        .unwrap()
    }

    #[test]
    fn script_history_flags_are_not_assignments() {
        let input = r#"createNode script -n Example; setAttr ".st" 1; setAttr ".stp" 1; setAttr ".b" -type "string" "Example"; setAttr ".a" -type "string" "Sample"; setAttr -l on ".b"; setAttr ".a" -k off; setAttr -k off ".st"; setAttr ".stp" -l on;"#;
        let coverage = script_history_coverage(input, true);
        assert!(
            coverage.coverage_issues.is_empty(),
            "{:?}",
            coverage.coverage_issues
        );
        assert_eq!(coverage.surfaces.len(), 2);
        for surface in coverage.surfaces {
            assert!(!surface.origin.overwritten);
            assert_eq!(surface.origin.trigger, ExecutionTrigger::FileOpen);
            assert_eq!(surface.origin.lang, ExecutionLanguage::Python);
        }
        let entries = ma::scripts::extract_raw_script_entries_from_ma(input.as_bytes());
        assert_eq!(entries[0].assignments.len(), 4);
    }

    #[test]
    fn script_history_rename_collision_keeps_source_order() {
        let entries =
            ma::scripts::extract_raw_script_entries_from_ma(b"createNode script -n :Example;");
        assert_eq!(entries[0].name, "Example");
        for flags in ["", "-ignoreShape "] {
            let input = format!(
                r#"createNode script -n Example; setAttr ".b" -type "string" "Example"; createNode script -n Sample; setAttr ".b" -type "string" "Sample"; select Example; rename {flags}:Example :Sample; select :Sample; setAttr ".b" -type "string" "TestAsset"; rename -uid "Example"; setAttr ".a" -type "string" "Example";"#
            );
            let entries = ma::scripts::extract_raw_script_entries_from_ma(input.as_bytes());
            assert_eq!(entries.len(), 2, "{flags}: {entries:?}");
            assert_eq!(entries[0].name, "Example");
            assert_eq!(entries[1].name, "Sample");
            assert_eq!(entries[0].assignments.len(), 1);
            assert_eq!(entries[1].assignments.len(), 3);
            let coverage = script_history_coverage(&input, true);
            assert_eq!(
                coverage
                    .surfaces
                    .iter()
                    .map(|s| s.text.as_ref())
                    .collect::<Vec<_>>(),
                ["Example", "Sample", "TestAsset", "Example"]
            );
            assert!(!coverage.surfaces[0].origin.overwritten);
            assert!(coverage.surfaces[1].origin.overwritten);
            assert!(!coverage.surfaces[2].origin.overwritten);
        }
    }

    #[test]
    fn mb_script_history_accepts_body_tags_and_rejects_string_numbers() {
        let chunk = |tag: &str, attr: &str, value: &[u8]| {
            let mut payload = format!("{attr}\0\0").into_bytes();
            payload.extend_from_slice(value);
            build_mb_chunk(tag, &payload)
        };
        let bytes = build_mb_root(&[build_mb_form(
            "SCRP",
            &[
                build_mb_chunk("CREA", b"ExampleScript\0"),
                chunk("DBLE", "st", &1.0f64.to_be_bytes()),
                chunk("STR ", "st", &1.0f64.to_be_bytes()),
                chunk("TEXT", "b", b"Example"),
                chunk("FLGS", "b", b"Sample"),
            ],
        )]);
        let mb = crate::mb::parse_bytes(bytes).unwrap();
        let coverage = collect_execution_coverage_from_mb(&mb).unwrap();
        let surfaces: Vec<_> = coverage
            .surfaces
            .iter()
            .filter(|s| s.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody)
            .collect();
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].text.as_ref(), "Example");
        assert_eq!(surfaces[0].origin.trigger, ExecutionTrigger::Manual);
        assert!(!surfaces[0].origin.overwritten);
    }

    #[test]
    fn script_history_unreadable_body_has_one_diagnostic() {
        let input = format!(
            r#"createNode script -n Example; setAttr ".b" -type "string" {};"#,
            "7 ".repeat(600)
        );
        let coverage = script_history_coverage(&input, true);
        assert_eq!(
            coverage.coverage_issues.len(),
            1,
            "{:?}",
            coverage.coverage_issues
        );
        assert!(coverage.surfaces.is_empty());
    }

    #[test]
    fn script_history_surfaces_keep_each_body_and_effective_context() {
        for bodies in [
            vec!["", "Example"],
            vec!["Sample", "Example"],
            vec!["Example", "Sample"],
            vec!["Example", ""],
            vec!["Example", "Example"],
        ] {
            for (numeric, language, trigger) in [
                (
                    "setAttr \".st\" 0; setAttr \".st\" 1; setAttr \".stp\" 0; setAttr \".stp\" 1;",
                    ExecutionLanguage::Python,
                    ExecutionTrigger::FileOpen,
                ),
                (
                    "setAttr \".st\" 1; setAttr \".st\" 0; setAttr \".stp\" 1; setAttr \".stp\" 0;",
                    ExecutionLanguage::Mel,
                    ExecutionTrigger::Manual,
                ),
            ] {
                let mut input = String::from("createNode script -n ExampleScript;\n");
                for body in &bodies {
                    input.push_str(&format!("setAttr \".b\" -type \"string\" \"{body}\";\n"));
                }
                input.push_str(numeric);
                let captured = script_history_coverage(&input, true);
                let uncaptured = script_history_coverage(&input, false);
                let expected: Vec<_> = bodies
                    .iter()
                    .enumerate()
                    .filter(|(_, body)| !body.is_empty())
                    .collect();
                assert_eq!(captured.surfaces.len(), expected.len());
                assert_eq!(captured.surfaces.len(), uncaptured.surfaces.len());
                for ((surface, other), (index, body)) in captured
                    .surfaces
                    .iter()
                    .zip(&uncaptured.surfaces)
                    .zip(expected)
                {
                    assert_eq!(surface.text.as_ref(), *body);
                    assert_eq!(surface.origin, other.origin);
                    assert_eq!(surface.origin.lang, language);
                    assert_eq!(surface.origin.trigger, trigger);
                    assert_eq!(surface.origin.overwritten, index + 1 != bodies.len());
                    assert_eq!(
                        surface.origin.assignment_index,
                        (index + 1 != bodies.len()).then_some(index)
                    );
                }
            }
        }
    }

    #[test]
    fn script_history_preserves_node_identity_and_after_body_order() {
        let input = concat!(
            "createNode script -n :Example; setAttr \".b\" -type \"string\" \"Example\";",
            "setAttr \".a\" -type \"string\" \"Sample\";",
            "createNode renderGlobals -n SampleGlobals; setAttr \".prm\" -type \"string\" \"print 1;\";",
            "rename :Example SampleScript; select -ne SampleScript;",
            "setAttr \".b\" -type \"string\" \"Sample\";",
            "setAttr \".a\" -type \"string\" \"Example\";",
            "setAttr \".st\" 1; setAttr \".stp\" 1;"
        );
        let coverage = script_history_coverage(input, true);
        assert_eq!(coverage.surfaces.len(), 5);
        assert_eq!(
            coverage
                .surfaces
                .iter()
                .map(|s| s.text.as_ref())
                .collect::<Vec<_>>(),
            ["Example", "Sample", "Sample", "print 1;", "Example"]
        );
        for surface in coverage
            .surfaces
            .iter()
            .filter(|s| s.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody)
        {
            assert_eq!(surface.origin.node_name.as_deref(), Some("SampleScript"));
            assert_eq!(surface.origin.trigger, ExecutionTrigger::FileOpen);
            assert_eq!(surface.origin.lang, ExecutionLanguage::Python);
        }
        assert!(coverage.surfaces[0].origin.overwritten);
        assert!(coverage.surfaces[2].origin.overwritten);
        assert!(!coverage.surfaces[1].origin.overwritten);
        assert!(!coverage.surfaces[4].origin.overwritten);
        let input = "createNode script -n Example; setAttr \".a\" -type \"string\" \"Sample\"; setAttr \".b\" -type \"string\" \"Example\";";
        let coverage = script_history_coverage(input, true);
        assert_eq!(
            coverage
                .surfaces
                .iter()
                .map(|s| s.origin.attr_name.as_deref())
                .collect::<Vec<_>>(),
            [Some(".b"), Some(".a")]
        );
        assert_eq!(coverage.surfaces[0].origin.source_kind, None);
        assert_eq!(
            coverage.surfaces[1].origin.source_kind.as_deref(),
            Some("a")
        );
        for surface in coverage.surfaces {
            let json = serde_json::to_value(&surface.origin).unwrap();
            assert!(json.get("overwritten").is_none());
            assert!(json.get("assignment_index").is_none());
        }
    }

    #[test]
    fn script_history_reports_unreadable_final_values_and_body_positions() {
        for invalid in ["-1", "\"1\""] {
            let input = format!(
                "createNode script -n Example; setAttr \".st\" 1; setAttr \".stp\" 1; setAttr \".b\" -type \"string\" \"Example\"; setAttr \".st\" {invalid}; setAttr \".stp\" {invalid}; setAttr \".b\" -type \"string\" 7;"
            );
            let coverage = script_history_coverage(&input, true);
            assert_eq!(coverage.surfaces.len(), 1);
            let surface = &coverage.surfaces[0];
            assert!(surface.origin.overwritten);
            assert_eq!(surface.origin.lang, ExecutionLanguage::Unknown);
            assert_eq!(surface.origin.trigger, ExecutionTrigger::Unknown);
            assert_eq!(coverage.coverage_issues.iter().filter(|issue| matches!(&issue.detail, ExecutionCoverageIssueDetail::SurfaceDiagnostics { diagnostic } if diagnostic == "cannot determine trigger / language")).count(), 1);
            let body_issue = coverage
                .coverage_issues
                .iter()
                .find(|issue| {
                    issue
                        .origin
                        .as_ref()
                        .and_then(|origin| origin.attr_name.as_deref())
                        == Some(".b")
                })
                .unwrap();
            let range = body_issue.origin.as_ref().unwrap().source_range.unwrap();
            assert_eq!(
                &input[range.start..range.end],
                "setAttr \".b\" -type \"string\" 7;"
            );
        }
    }

    #[test]
    fn mb_script_history_keeps_repeated_bodies_and_final_numeric_values() {
        for second in ["Example", "Sample", ""] {
            let body = |attr: &str, text: &str| {
                let mut payload = format!("{attr}\0\0").into_bytes();
                payload.extend_from_slice(text.as_bytes());
                build_mb_chunk("STR ", &payload)
            };
            let number = |tag: &str, attr: &str, value: f64| {
                let mut payload = format!("{attr}\0\0").into_bytes();
                payload.extend_from_slice(&value.to_be_bytes());
                build_mb_chunk(tag, &payload)
            };
            let bytes = build_mb_root(&[build_mb_form(
                "SCRP",
                &[
                    build_mb_chunk("CREA", b"ExampleScript\0"),
                    number("DBLE", "st", 0.0),
                    number("DBLE", "stp", 0.0),
                    body("b", "Example"),
                    body("a", "Sample"),
                    body("b", second),
                    body("a", "Example"),
                    number("DBLE", "st", 1.0),
                    number("DBLE", "stp", 1.0),
                    number("FLGS", "st", 0.0),
                    number("FLGS", "stp", 0.0),
                ],
            )]);
            let mb = crate::mb::parse_bytes(bytes).unwrap();
            let coverage = collect_execution_coverage_from_mb(&mb).unwrap();
            let surfaces: Vec<_> = coverage
                .surfaces
                .iter()
                .filter(|surface| {
                    surface.origin.surface_kind == ExecutionSurfaceKind::ScriptNodeBody
                })
                .collect();
            let expected = if second.is_empty() {
                vec![
                    (".a", "Example", false),
                    (".b", "Example", true),
                    (".a", "Sample", true),
                ]
            } else {
                vec![
                    (".a", "Example", false),
                    (".b", second, false),
                    (".b", "Example", true),
                    (".a", "Sample", true),
                ]
            };
            assert_eq!(surfaces.len(), expected.len());
            for (surface, (attr, text, overwritten)) in surfaces.iter().zip(expected) {
                assert_eq!(surface.origin.attr_name.as_deref(), Some(attr));
                assert_eq!(surface.text.as_ref(), text);
                assert_eq!(surface.origin.overwritten, overwritten);
                assert_eq!(surface.origin.assignment_index.is_some(), overwritten);
                assert_eq!(surface.origin.lang, ExecutionLanguage::Python);
                assert_eq!(surface.origin.trigger, ExecutionTrigger::FileOpen);
            }
            let overwritten: Vec<_> = surfaces
                .iter()
                .filter(|s| s.origin.overwritten)
                .map(|s| s.origin.assignment_index.unwrap())
                .collect();
            assert_eq!(overwritten, [2, 3]);
        }
        let attrs = vec!["b".to_string()];
        let values = vec![
            ("b".to_string(), b"Example".to_vec(), "STR ".to_string(), 8),
            ("b".to_string(), b"Example".to_vec(), "STR ".to_string(), 32),
        ];
        let mut offsets = std::collections::HashSet::new();
        let first_profile =
            super::collect_mb_script_body_assignments(&attrs, &values, 16, &mut offsets);
        let second_profile =
            super::collect_mb_script_body_assignments(&attrs, &values, 16, &mut offsets);
        assert_eq!(first_profile.len(), 2);
        assert!(second_profile.is_empty());
    }

    #[test]
    fn ma_selective_unknown_statements_and_known_surfaces() {
        let semantics = node_execution_semantics_with_registry(default_schema_registry()).unwrap();
        for input in [
            "system \"echo Example\";",
            "evalEcho \"print 1\";",
            "expression -s \"print 1\";",
            "scriptNode -bs \"print 1\" -st 1;",
            "sysFile -delete \"asset/example/file.ma\";",
            "printX \"a\";",
            "sourceFoo \"a\";",
        ] {
            let sections = ma::selective::extract_raw_selective_sections_from_ma(input.as_bytes());
            let coverage = collect_execution_coverage_from_ma_parts(
                &sections.dump_sections.script_entries,
                &[],
                &sections.connections,
                &sections.audit_top_level,
                &semantics,
            )
            .unwrap();
            assert!(
                coverage
                    .surfaces
                    .iter()
                    .any(|surface| surface.origin.surface_kind
                        == ExecutionSurfaceKind::TopLevelOtherStatement
                        && surface.text.as_ref() == input),
                "{input}"
            );
            assert!(coverage.coverage_issues.iter().any(|issue| matches!(issue.detail, crate::scene::evidence::ExecutionCoverageIssueDetail::UnsupportedTopLevelStatement)), "{input}");
        }
        for head in ["python", "eval", "commandPort", "evalDeferred"] {
            for input in [
                format!("{head} \"Example\";"),
                format!("{head}(\"Example\");"),
            ] {
                let sections =
                    ma::selective::extract_raw_selective_sections_from_ma(input.as_bytes());
                let coverage = collect_execution_coverage_from_ma_parts(
                    &[],
                    &[],
                    &sections.connections,
                    &sections.audit_top_level,
                    &semantics,
                )
                .unwrap();
                assert!(
                    coverage
                        .surfaces
                        .iter()
                        .any(|surface| surface.origin.surface_kind
                            == ExecutionSurfaceKind::TopLevelCommand
                            && surface.origin.source_kind.as_deref() == Some(head)
                            && surface.text.as_ref() == input),
                    "{input}"
                );
            }
        }
    }

    #[test]
    fn ma_selective_adjacent_surfaces_match_input_source() {
        let semantics = node_execution_semantics_with_registry(default_schema_registry()).unwrap();
        let sphere = std::fs::read(repo_root().join("tests/02/sphere.ma")).unwrap();
        let synthetic = b"python \"Example\";eval \"Sample\";evalDeferred \"Example\";nodeOutliner -selectCommand \"print 1\";file -r -command \"Example\" \"print 1\" \"asset/example/file.ma\";";
        for input in [sphere.as_slice(), synthetic.as_slice()] {
            let sections = ma::selective::extract_raw_selective_sections_from_ma(input);
            let actual = collect_execution_coverage_from_ma_parts(
                &sections.dump_sections.script_entries,
                &[],
                &sections.connections,
                &sections.audit_top_level,
                &semantics,
            )
            .unwrap();
            let direct_facts = mel::collect_top_level_audit_candidates_from_bytes(input);
            let direct_scripts = ma::scripts::extract_raw_script_entries_from_ma(input);
            let expected = collect_execution_coverage_from_ma_parts(
                &direct_scripts,
                &[],
                &Default::default(),
                &direct_facts,
                &semantics,
            )
            .unwrap();
            assert!(!actual.surfaces.is_empty());
            assert_eq!(actual.surfaces.len(), expected.surfaces.len());
            for (actual, expected) in actual.surfaces.iter().zip(&expected.surfaces) {
                assert_eq!(actual.text, expected.text);
                assert_eq!(actual.origin.source_range, expected.origin.source_range);
                if let Some(range) = &actual.origin.source_range
                    && matches!(
                        actual.origin.surface_kind,
                        ExecutionSurfaceKind::TopLevelCommand
                            | ExecutionSurfaceKind::TopLevelOtherStatement
                            | ExecutionSurfaceKind::TopLevelProcDefinition
                    )
                {
                    assert_eq!(actual.text.as_bytes(), &input[range.start..range.end]);
                }
            }
        }
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
        let coverage = collect_execution_coverage_from_ma_parts(
            &script_entries,
            &[],
            &Default::default(),
            &top_level,
            &semantics,
        )
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
    fn mb_expression_surface_uses_crea_node_name() {
        let crea = build_mb_chunk("CREA", b"ExampleExpression\0");
        let mut ixp_payload = b"ixp\0\0".to_vec();
        ixp_payload.extend_from_slice(b"eval($ExampleBody);");
        let ixp = build_mb_chunk("STR ", &ixp_payload);
        let bytes = build_mb_root(&[build_mb_form("DEXP", &[crea, ixp])]);
        let mb = crate::mb::parse_bytes(bytes).expect("parse synthetic mb");
        let coverage = collect_execution_coverage_from_mb(&mb).expect("coverage");
        let surface = coverage
            .surfaces
            .iter()
            .find(|surface| {
                surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                    && surface.origin.attr_name.as_deref() == Some(".ixp")
            })
            .expect("expression surface");

        assert_eq!(
            surface.origin.node_name.as_deref(),
            Some("ExampleExpression")
        );
        assert_eq!(
            surface.origin.source_kind.as_deref(),
            Some("internalExpression")
        );
        assert_eq!(surface.origin.chunk_form.as_deref(), Some("DEXP"));
        assert_eq!(surface.text.as_ref(), "eval($ExampleBody);");
    }

    #[test]
    fn mb_surfaces_include_unprofiled_execution_shaped_attr_callbacks() {
        let crea = build_mb_chunk("CREA", b"SampleRenderOptionsNode\0");
        let mut callback_payload = b"preRenderMel\0\0".to_vec();
        callback_payload.extend_from_slice(b"print \"SampleCallback\";");
        let callback = build_mb_chunk("STR ", &callback_payload);
        let bytes = build_mb_root(&[build_mb_form("XPLT", &[crea, callback])]);
        let mb = crate::mb::parse_bytes(bytes).expect("parse synthetic mb");
        let coverage = collect_execution_coverage_from_mb(&mb).expect("coverage");

        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                && surface.origin.node_name.as_deref() == Some("SampleRenderOptionsNode")
                && surface.origin.attr_name.as_deref() == Some(".preRenderMel")
                && surface.origin.chunk_form.as_deref() == Some("XPLT")
                && surface.text.as_ref() == r#"print "SampleCallback";"#
        }));
    }

    #[test]
    fn mb_known_non_execution_chunks_do_not_become_raw_execution_surfaces() {
        let cwfl = build_mb_chunk("CWFL", b"\0ExampleSource.out\0ExampleTarget.in\0");
        let crea = build_mb_chunk("CREA", b"ExampleSourceNode\0");
        let bytes = build_mb_root(&[
            build_mb_form("CONS", &[cwfl]),
            build_mb_form("PCTA", &[crea]),
        ]);
        let mb = crate::mb::parse_bytes(bytes).expect("parse synthetic mb");
        let coverage = collect_execution_coverage_from_mb(&mb).expect("coverage");

        assert!(
            coverage.surfaces.iter().all(|surface| {
                surface.origin.surface_kind != ExecutionSurfaceKind::RawChunkText
            })
        );
        assert!(
            coverage.coverage_issues.is_empty(),
            "known decoded non-execution chunks should not produce coverage issues: {:?}",
            coverage.coverage_issues
        );
    }

    #[test]
    fn mb_undecoded_marker_payload_becomes_coverage_issue_not_surface() {
        let payload = b"source \"asset/example/startup.mel\"";
        let bytes = build_mb_root(&[build_mb_form("UNKN", &[build_mb_chunk("DATA", payload)])]);
        let mb = crate::mb::parse_bytes(bytes).expect("parse synthetic mb");
        let coverage = collect_execution_coverage_from_mb(&mb).expect("coverage");

        assert!(
            coverage.surfaces.iter().all(|surface| {
                surface.origin.surface_kind != ExecutionSurfaceKind::RawChunkText
            })
        );
        assert!(coverage.coverage_issues.iter().any(|issue| {
            issue.kind == crate::scene::evidence::ExecutionCoverageIssueKind::UnknownRawMbPayload
                && matches!(
                    &issue.detail,
                    crate::scene::evidence::ExecutionCoverageIssueDetail::UnknownRawMbPayload {
                        marker
                    } if marker == "source"
                )
                && issue
                    .origin
                    .as_ref()
                    .is_some_and(|origin| origin.chunk_form.as_deref() == Some("UNKN"))
        }));
    }

    #[test]
    fn mb_undecoded_text_payload_without_marker_becomes_coverage_issue() {
        let payload = b"system \"asset/example/file.txt\"";
        let bytes = build_mb_root(&[build_mb_form("XPLT", &[build_mb_chunk("DATA", payload)])]);
        let mb = crate::mb::parse_bytes(bytes).expect("parse synthetic mb");
        let coverage = collect_execution_coverage_from_mb(&mb).expect("coverage");

        assert!(
            coverage.surfaces.iter().all(|surface| {
                surface.origin.surface_kind != ExecutionSurfaceKind::RawChunkText
            })
        );
        assert!(
            coverage.coverage_issues.iter().any(|issue| {
                issue
                    .origin
                    .as_ref()
                    .is_some_and(|origin| origin.chunk_form.as_deref() == Some("XPLT"))
                    && issue.preview.text.as_ref().contains("system")
            }),
            "unexplained text-like MB payloads must become coverage uncertainty: {:?}",
            coverage.coverage_issues
        );
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
        let coverage = collect_execution_coverage_from_ma_parts(
            &script_entries,
            &[],
            &Default::default(),
            &top_level,
            &semantics,
        )
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
    fn selected_expression_reaches_node_attribute_surface() {
        let input = b"createNode -name Example expression; select :Example; setAttr \".ixp\" -type \"string\" \"print 1;\";";
        let semantics =
            node_execution_semantics_with_registry(default_schema_registry()).expect("semantics");
        let sections = ma::selective::extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(input, &maya_scene_kit_formats::mel::MelParseBudget::default(), semantics.ma_capture_attr_selectors());
        let coverage = collect_execution_coverage_from_ma_parts(
            &sections.dump_sections.script_entries,
            &sections.node_attr_values,
            &sections.connections,
            &sections.audit_top_level,
            &semantics,
        )
        .expect("coverage");
        assert!(
            coverage
                .surfaces
                .iter()
                .any(
                    |surface| surface.origin.node_name.as_deref() == Some("Example")
                        && surface.origin.attr_name.as_deref() == Some(".ixp")
                        && surface.text.as_ref() == "print 1;"
                )
        );
        assert!(sections.audit_top_level.diagnostics.is_empty());
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
            &sections.connections,
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
    fn ma_surfaces_include_unprofiled_execution_shaped_attr_callbacks() {
        let input = concat!(
            "//Maya ASCII 2026 scene\n",
            "createNode SampleRenderOptions -n \"SampleRenderOptionsNode\";\n",
            "    setAttr \".preRenderMel\" -type \"string\" \"print \\\"SampleCallback\\\";\";\n",
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
            &sections.connections,
            &sections.audit_top_level,
            &semantics,
        )
        .expect("coverage");

        assert!(coverage.surfaces.iter().any(|surface| {
            surface.origin.surface_kind == ExecutionSurfaceKind::NodeAttrCallback
                && surface.origin.node_name.as_deref() == Some("SampleRenderOptionsNode")
                && surface.origin.attr_name.as_deref() == Some(".preRenderMel")
                && surface.text.as_ref() == r#"print "SampleCallback";"#
        }));
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
        assert_eq!(
            first_payload_audit_marker(b"\0Python\0").as_deref(),
            Some("python")
        );
        assert_eq!(first_payload_audit_marker(b"Exec").as_deref(), Some("exec"));
        assert_eq!(
            first_payload_audit_marker(b"evalDeferred").as_deref(),
            Some("eval")
        );
        assert_eq!(
            first_payload_audit_marker(b"commandPort").as_deref(),
            Some("commandport")
        );
        assert!(first_payload_audit_marker(b"socket_blinn1SG").is_none());
        assert!(first_payload_audit_marker(b"SampleReferenceNode").is_none());
    }

    #[test]
    fn generic_raw_text_decode_skips_large_binary_payloads() {
        let mut payload = vec![0u8; MAX_GENERIC_RAW_TEXT_PAYLOAD_BYTES + 1];
        payload.extend_from_slice(b"source \"tools/startup.mel\"");

        assert!(!raw_chunk_tag_may_contain_execution_text(
            FourCC::new(*b"DATA"),
            payload.len()
        ));
        assert!(raw_chunk_tag_may_contain_execution_text(
            FourCC::new(*b"STR "),
            payload.len()
        ));
        assert!(decode_raw_chunk_text("DATA", &payload).is_none());
    }

    #[test]
    fn reference_metadata_chunks_are_not_raw_execution_candidates() {
        for tag in [
            FourCC::new(*b"FRDI"),
            FourCC::new(*b"FREF"),
            FourCC::new(*b"RTFT"),
        ] {
            assert!(!raw_chunk_tag_may_contain_execution_text(tag, 128));
        }
    }

    #[test]
    fn non_script_str_attrs_do_not_fall_back_to_raw_text() {
        let mut payload = b"ExampleOptions\0 ".to_vec();
        payload.extend_from_slice(b"Viewer_Script_D3D=1;TextureType=Default (Match Source Image);");

        assert!(first_payload_audit_marker(&payload).is_some());
        assert!(raw_chunk_tag_may_contain_execution_text(
            FourCC::new(*b"STR "),
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
    #[test]
    fn truncated_groups_keep_preorder_reasons_and_existing_payload_issues() {
        use crate::{mb::MbParseBudget, scene::ExecutionCoverageIssueDetail};
        let bytes = build_mb_root(&[
            build_mb_form(
                "HEAD",
                &[
                    build_mb_chunk("DATA", &[]),
                    build_mb_chunk("DATA", &[]),
                    build_mb_chunk("DATA", &[]),
                    build_mb_chunk("DATA", &[]),
                ],
            ),
            build_mb_form(
                "XPLT",
                &[
                    build_mb_chunk("FOR8", b"HEAD"),
                    build_mb_chunk("FOR8", b"HEAD"),
                    build_mb_chunk("DATA", b"system \"asset/example/file.txt\""),
                ],
            ),
        ]);
        let mb = crate::mb::parse_bytes_with_budget(
            bytes,
            &MbParseBudget {
                max_depth: 2,
                max_children_per_group: 3,
                ..MbParseBudget::default()
            },
        )
        .unwrap();
        let coverage = collect_execution_coverage_from_mb(&mb).unwrap();
        assert_eq!(coverage.coverage_issues.len(), 2);
        let issues: Vec<_> = coverage
            .coverage_issues
            .iter()
            .filter(|issue| issue.origin.is_none())
            .collect();
        assert_eq!(issues.len(), 1);
        let ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason } = &issues[0].detail
        else {
            panic!("unexpected issue");
        };
        assert!(reason.contains("first_reason=ChildLimit"), "{reason}");
        assert!(reason.contains("truncated_groups=3"), "{reason}");
        assert!(
            reason.contains("reasons=[ChildLimit, DepthLimit]"),
            "{reason}"
        );
    }

    #[test]
    fn malformed_slct_scene_has_partial_validation() {
        let bytes = build_mb_root(&[build_mb_form("SLCT", &[build_mb_chunk("SLCT", &[])])]);
        let session = crate::scene::mb_read_session::MbReadSession::load_raw_bytes(
            std::path::Path::new("TestScene.mb"),
            bytes,
            Some(
                crate::scene::schema::SchemaContext::from_inputs_cached(
                    &crate::scene::LoadOptions::default().schema_inputs(),
                )
                .expect("schema context"),
            ),
            &crate::mb::MbParseBudget::default(),
        )
        .expect("session");
        assert_eq!(
            session.integrity().expect("integrity").validation_state,
            crate::scene::ValidationState::Partial
        );
    }

    #[test]
    fn failed_text_chunk_adds_coverage_but_partial_refe_does_not() {
        let payload = b"Example\0\0Example text payload\0";
        for (form, tag, quality, count) in [
            (
                "ATTR",
                "ATTR",
                crate::scene::ir::SchemaDecodeAttemptResult::Failed,
                1,
            ),
            (
                "REFE",
                "REFE",
                crate::scene::ir::SchemaDecodeAttemptResult::Partial,
                0,
            ),
        ] {
            let dispatcher = crate::scene::decode::dispatcher::DecoderDispatcher::new(
                std::sync::Arc::new(crate::scene::schema::SchemaRegistry::new(
                    crate::scene::schema::locator::SchemaPaths::from_defaults(),
                )),
            );
            let result = dispatcher.decode_with_quality(
                form,
                tag,
                payload,
                0,
                None,
                Some(8),
                Some(16),
                Some(form),
                Some("FOR8"),
            );
            assert_eq!(result.quality, quality);
            assert!(matches!(
                result.events.as_slice(),
                [crate::scene::ir::DecodedEvent::Unknown(_)]
            ));
            let bytes = build_mb_root(&[build_mb_form(form, &[build_mb_chunk(tag, payload)])]);
            let mb = crate::mb::parse_bytes(bytes).expect("parse synthetic mb");
            let coverage = collect_execution_coverage_from_mb(&mb).expect("coverage");
            assert_eq!(coverage.coverage_issues.len(), count, "{form}/{tag}");
            assert!(coverage.surfaces.is_empty());
        }
    }
}

#[cfg(test)]
mod section_state_tests {
    use super::*;

    #[test]
    fn native_selection_retains_scan_stop_without_a_profile() {
        let bytes = b"FOR4\0\0\0\x20MayaFOR4\0\0\0\x14SLCTDATA\0\0\0\0DATA\0\0\0\0".to_vec();
        let mb = crate::mb::parse_bytes(bytes).unwrap();
        let registry = crate::scene::schema::default_schema_registry();
        let semantics =
            crate::scene::schema::node_semantics::node_execution_semantics_with_registry(registry)
                .unwrap();
        let budget = MbParseBudget {
            max_children_per_group: 1,
            ..MbParseBudget::default()
        };
        let (surfaces, state) = collect_mb_native_script_surfaces(&mb, semantics.as_ref(), &budget);
        assert!(surfaces.is_empty());
        assert_eq!(state, crate::mb::MbSectionScanState::Stopped);
    }
    #[test]
    fn soft_depth_stop_reaches_one_issue_and_rewrite_refusal() {
        fn chunk(tag: &[u8; 4], aux: u32, payload: &[u8], wide: bool) -> Vec<u8> {
            let mut bytes = tag.to_vec();
            if wide {
                bytes.extend_from_slice(&aux.to_be_bytes());
                bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            } else {
                bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            }
            bytes.extend_from_slice(payload);
            bytes.resize(bytes.len().next_multiple_of(4), 0);
            bytes
        }
        fn group(tag: &[u8; 4], form: &[u8; 4], inner: &[u8], wide: bool) -> Vec<u8> {
            let mut payload = form.to_vec();
            payload.extend_from_slice(inner);
            chunk(tag, 0, &payload, wide)
        }
        let mut nested = chunk(b"DATA", 0, &[], false);
        for _ in 0..130 {
            nested = group(b"FOR4", b"TEST", &nested, false);
        }
        let leaf = chunk(b"DATA", 8, &nested, true);
        let section = group(b"FOR4", b"TEST", &leaf, true);
        let bytes = group(
            b"FOR8",
            b"Maya",
            &group(b"FOR8", b"HEAD", &section, true),
            true,
        );
        let mb = crate::mb::parse_bytes(bytes).unwrap();
        assert!(matches!(mb.completeness(), MbCompleteness::Complete));
        let soft = crate::mb::walk_group_chunks_with_layout(
            &section,
            LayoutHints::new().with_header_format(crate::mb::HeaderFormat::EightByte),
        );
        assert_eq!(soft.state, crate::mb::MbSectionScanState::Stopped);
        let coverage = collect_execution_coverage_from_mb(&mb).unwrap();
        assert_eq!(coverage.coverage_issues.len(), 1);
        assert!(matches!(&coverage.coverage_issues[0].detail,
            ExecutionCoverageIssueDetail::UnexplainedRawMbPayload { reason } if reason == "MB section scan stopped"));
        let error =
            crate::mb::rewrite::require_complete_mb_sections(mb.data(), mb.root()).unwrap_err();
        assert!(error.to_string().contains("depth budget"), "{error}");
    }
}
