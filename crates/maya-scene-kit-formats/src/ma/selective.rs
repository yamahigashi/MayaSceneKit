use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};

use maya_mel::{
    maya::{
        MayaCommandRegistry,
        model::{
            DefaultMayaSelectiveSetAttrSelector, MayaSelectiveCreateNode, MayaSelectiveFile,
            MayaSelectiveItem, MayaSelectiveRequires, MayaSelectiveSetAttr,
            MayaSelectiveSetAttrSelector, MayaTrackedSetAttrAttr,
        },
    },
    parser::{
        LightCommandSurface, LightItem, LightItemSink, LightParseOptions, LightScanSummary,
        LightWord, SourceEncoding, scan_light_bytes_with_options_and_sink_and_then,
    },
    sema::command_schema::{CommandRegistry, ValueShape},
    syntax::{SourceView, TextRange, range_end, range_start},
};

use crate::{
    ScenePathEntry, ScenePathMeta,
    ma::{
        commands::{
            FlagCommandKind, Token, bare_token, command_flag_descriptor, token_text,
            tokenize_command,
        },
        lexer::{
            extract_script_node_name_from_create, is_reference_attr, looks_like_scene_path,
            parse_ma_quoted_literal, parse_setattr_string_command, parse_setattr_string_value,
            parse_setattr_string_value_tail, unescape_ma_string_literal,
        },
        raw_dump::{RawMaDumpSections, RawMaRequireEntry, RawMaRequireKind, RawMaScriptEntry},
    },
    mel::{
        MelAuditSourceStore, MelAuditTopLevelCommandFact, MelAuditTopLevelFacts,
        MelAuditTopLevelItemFact, MelAuditTopLevelOtherFact, MelAuditTopLevelProcFact,
        MelDiagnosticStage, MelParseBudget, MelParseDiagnostic, MelSourceEncoding, MelSpan,
    },
    reference_semantics::{ScenePathAttrKind, classify_scene_path_attr},
};

#[derive(Debug, Clone)]
pub struct RawMaSelectiveSections {
    pub dump_sections: RawMaDumpSections,
    pub scene_paths: Vec<ScenePathEntry>,
    pub audit_top_level: MelAuditTopLevelFacts,
}

fn selective_light_parse_options(budget: &MelParseBudget) -> LightParseOptions {
    LightParseOptions {
        max_prefix_words: 16,
        max_prefix_bytes: 512,
        budgets: budget.to_parse_budgets(),
    }
}

pub fn extract_raw_selective_sections_from_ma(data: &[u8]) -> RawMaSelectiveSections {
    extract_raw_selective_sections_from_ma_with_budget(data, &MelParseBudget::default())
}

pub fn extract_raw_selective_sections_from_ma_with_budget(
    data: &[u8],
    budget: &MelParseBudget,
) -> RawMaSelectiveSections {
    let mut sink = SelectiveScanSink::default();
    scan_light_bytes_with_options_and_sink_and_then(
        data,
        selective_light_parse_options(budget),
        &mut sink,
        |sink, source, report| std::mem::take(sink).finish(source, report),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ActiveCreateBlock {
    Script(ActiveScriptBlock),
    ScenePath(ActiveScenePathBlock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveScriptBlock {
    name: String,
    body: Option<String>,
    script_type: Option<u32>,
    source_type: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveScenePathBlock {
    node_type: String,
    node_name: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LineTracker {
    cursor: usize,
    line_number: usize,
    line_has_indent: bool,
    line_started: bool,
}

impl LineTracker {
    fn advance_to(&mut self, bytes: &[u8], target: usize) {
        while self.cursor < target {
            match bytes[self.cursor] {
                b'\n' => {
                    self.line_number += 1;
                    self.line_has_indent = false;
                    self.line_started = false;
                }
                b' ' | b'\t' if !self.line_started => {
                    self.line_has_indent = true;
                }
                _ => {
                    self.line_started = true;
                }
            }
            self.cursor += 1;
        }
    }

    fn is_indented(&self) -> bool {
        self.line_has_indent
    }

    fn line_number(self) -> usize {
        self.line_number
    }
}

fn start_create_node_block(
    source: SourceView<'_>,
    command_text: &str,
    create_node: &MayaSelectiveCreateNode,
    line_number: usize,
) -> Option<ActiveCreateBlock> {
    let node_type = create_node
        .node_type_range
        .map(|range| decode_range_value(source, range))
        .filter(|value: &String| !value.is_empty())
        .unwrap_or_else(|| parse_create_node_type(command_text).to_string());
    let node_name = create_node
        .name_range
        .map(|range| decode_range_value(source, range))
        .filter(|value: &String| !value.is_empty())
        .unwrap_or_else(|| {
            extract_script_node_name_from_create(command_text.as_bytes(), line_number)
        });

    match node_type.as_str() {
        "script" => Some(ActiveCreateBlock::Script(ActiveScriptBlock {
            name: node_name,
            body: None,
            script_type: None,
            source_type: None,
        })),
        _ => Some(ActiveCreateBlock::ScenePath(ActiveScenePathBlock {
            node_type,
            node_name,
        })),
    }
}

fn apply_setattr_to_active_block(
    source: SourceView<'_>,
    block: &mut ActiveCreateBlock,
    set_attr: &MayaSelectiveSetAttr,
    tracked_attr: Option<MayaTrackedSetAttrAttr>,
    command_text: &str,
    scene_paths: &mut Vec<ScenePathEntry>,
    seen_paths: &mut HashSet<u64>,
) {
    match block {
        ActiveCreateBlock::Script(script) => {
            if matches!(tracked_attr, Some(MayaTrackedSetAttrAttr::B))
                && script.body.is_none()
                && selective_setattr_type_name(source, set_attr) == Some("string")
            {
                if let Some(value) = selective_setattr_string_tail(source, set_attr) {
                    script.body = Some(value);
                    return;
                }
            }
            if let Some((attr, value)) = parse_setattr_string_command(command_text) {
                if attr == ".b" && script.body.is_none() {
                    script.body = Some(value);
                }
                return;
            }

            if let Some((attr, value)) = parse_setattr_scalar_u32_command(command_text) {
                match attr.as_str() {
                    ".st" if script.script_type.is_none() => script.script_type = Some(value),
                    ".stp" if script.source_type.is_none() => script.source_type = Some(value),
                    _ => {}
                }
            }
        }
        ActiveCreateBlock::ScenePath(path_block) => {
            let Some(attr_name) = selective_scene_path_attr_name(source, set_attr, tracked_attr)
            else {
                return;
            };
            let value = selective_setattr_string_tail(source, set_attr)
                .or_else(|| parse_setattr_string_value(command_text));
            let Some(value) = value else {
                return;
            };

            if matches!(
                classify_scene_path_attr(attr_name),
                Some(ScenePathAttrKind::FileTexturePath)
            ) {
                push_path_entry(
                    scene_paths,
                    seen_paths,
                    ScenePathEntry {
                        node_type: path_block.node_type.clone(),
                        node_name: path_block.node_name.clone(),
                        attr: attr_name.to_string(),
                        value,
                        meta: None,
                    },
                );
            } else if path_block.node_type == "reference" && is_reference_attr(attr_name) {
                push_path_entry(
                    scene_paths,
                    seen_paths,
                    ScenePathEntry {
                        node_type: "reference".to_string(),
                        node_name: path_block.node_name.clone(),
                        attr: attr_name.to_string(),
                        value,
                        meta: None,
                    },
                );
            }
        }
    }
}

fn selective_setattr_type_name<'a>(
    source: SourceView<'a>,
    set_attr: &MayaSelectiveSetAttr,
) -> Option<&'a str> {
    let range = set_attr.type_name_range?;
    string_literal_contents(source, range).or_else(|| Some(source.slice(range)))
}

fn selective_setattr_string_tail(
    source: SourceView<'_>,
    set_attr: &MayaSelectiveSetAttr,
) -> Option<String> {
    (selective_setattr_type_name(source, set_attr) == Some("string"))
        .then_some(set_attr.opaque_tail)
        .flatten()
        .and_then(|range| parse_setattr_string_value_tail(source.slice(range)))
}

fn tracked_scene_path_attr_name(
    tracked_attr: Option<MayaTrackedSetAttrAttr>,
) -> Option<&'static str> {
    match tracked_attr {
        Some(MayaTrackedSetAttrAttr::Ftn) => Some(".ftn"),
        Some(MayaTrackedSetAttrAttr::Fn) => Some(".fn"),
        Some(MayaTrackedSetAttrAttr::F) => Some(".f"),
        _ => None,
    }
}

fn selective_scene_path_attr_name<'a>(
    source: SourceView<'a>,
    set_attr: &MayaSelectiveSetAttr,
    tracked_attr: Option<MayaTrackedSetAttrAttr>,
) -> Option<&'a str> {
    if let Some(tracked) = tracked_scene_path_attr_name(tracked_attr) {
        return Some(tracked);
    }
    let attr_path = strip_outer_quotes(source.slice(set_attr.attr_path_range?));
    matches!(
        classify_scene_path_attr(attr_path),
        Some(ScenePathAttrKind::FileTexturePath | ScenePathAttrKind::ReferencePath)
    )
    .then_some(attr_path)
}

fn flush_active_block(
    active_block: &mut Option<ActiveCreateBlock>,
    script_entries: &mut Vec<RawMaScriptEntry>,
) {
    let Some(block) = active_block.take() else {
        return;
    };
    if let ActiveCreateBlock::Script(script) = block {
        script_entries.push(RawMaScriptEntry {
            name: script.name,
            body: script.body.unwrap_or_default(),
            script_type: script.script_type,
            source_type: script.source_type,
        });
    }
}

fn push_path_entry(
    scene_paths: &mut Vec<ScenePathEntry>,
    seen_paths: &mut HashSet<u64>,
    entry: ScenePathEntry,
) {
    if seen_paths.insert(scene_path_entry_fingerprint(&entry)) {
        scene_paths.push(entry);
    }
}

fn scene_path_entry_fingerprint(entry: &ScenePathEntry) -> u64 {
    let mut hasher = DefaultHasher::new();
    entry.node_type.hash(&mut hasher);
    entry.node_name.hash(&mut hasher);
    entry.attr.hash(&mut hasher);
    entry.value.hash(&mut hasher);
    hasher.finish()
}

fn decode_range_value(source: SourceView<'_>, range: TextRange) -> String {
    if let Some(contents) = string_literal_contents(source, range) {
        return unescape_ma_string_literal(contents);
    }
    source.slice(range).to_string()
}

fn string_literal_contents<'a>(source: SourceView<'a>, range: TextRange) -> Option<&'a str> {
    source.slice(range).strip_prefix('"')?.strip_suffix('"')
}

fn normalize_requires_command(command: &str) -> String {
    let mut text = command.split_whitespace().collect::<Vec<_>>().join(" ");
    if !text.ends_with(';') {
        text.push(';');
    }
    text
}

fn extract_reference_entry_from_selective_file_command(
    source: SourceView<'_>,
    file: &MayaSelectiveFile,
    command: &str,
) -> Option<ScenePathEntry> {
    let path = file
        .path_range
        .map(|range| decode_range_value(source, range))
        .filter(|value| looks_like_scene_path(value))?;
    let node_name = parse_file_command_flag_value(command, "-rfn")
        .unwrap_or_else(|| "<fileCmdRef>".to_string());

    Some(ScenePathEntry {
        node_type: "reference".to_string(),
        node_name: node_name.clone(),
        attr: ".fn".to_string(),
        value: path,
        meta: Some(ScenePathMeta {
            origin: "ma-file-cmd".to_string(),
            short_name: None,
            reference_node: Some(node_name),
            format_hint: None,
            reference_options: None,
            color_space: None,
            raw_fields: vec![],
            trace_form: None,
            trace_tag: None,
            trace_node_offset: None,
            trace_child_alignment: None,
            trace_child_header_size: None,
        }),
    })
}

fn parse_file_command_flag_value(command: &str, flag: &str) -> Option<String> {
    let idx = command.find(flag)?;
    let mut cursor = idx + flag.len();
    while cursor < command.len() {
        let ch = command[cursor..].chars().next().unwrap();
        if ch.is_whitespace() {
            cursor += ch.len_utf8();
            continue;
        }
        break;
    }
    if cursor >= command.len() || !command[cursor..].starts_with('"') {
        return None;
    }
    let (literal, _) = parse_ma_quoted_literal(command, cursor);
    literal.map(|s| unescape_ma_string_literal(&s))
}

fn parse_create_node_type(command: &str) -> &str {
    let trimmed = command.trim_start();
    let Some(rest) = trimmed.strip_prefix("createNode ") else {
        return "";
    };
    rest.split_whitespace().next().unwrap_or_default()
}

fn parse_setattr_scalar_u32_command(command: &str) -> Option<(String, u32)> {
    let tokens = tokenize_command(command).ok()?;
    if !matches!(tokens.first().and_then(bare_token), Some("setAttr")) {
        return None;
    }

    let attr_index = tokens
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(idx, token)| matches!(token, Token::Quoted(_)).then_some(idx))?;
    let attr = token_text(tokens.get(attr_index)?)?.to_string();

    let mut idx = attr_index + 1;
    while idx < tokens.len() {
        let Some(flag) = bare_token(tokens.get(idx)?) else {
            break;
        };
        if !flag.starts_with('-') {
            break;
        }
        let descriptor = command_flag_descriptor(FlagCommandKind::SetAttr, flag)?;
        idx += 1 + descriptor.arity;
    }

    let value = parse_u32_token(tokens.get(idx)?)?;
    Some((attr, value))
}

fn parse_u32_token(token: &Token) -> Option<u32> {
    let text = token_text(token)?;
    if let Ok(value) = text.parse::<u32>() {
        return Some(value);
    }
    let value = text.parse::<f64>().ok()?;
    (value.is_finite() && value >= 0.0 && value.fract() == 0.0).then_some(value as u32)
}

fn collect_report_diagnostics(report: &LightScanSummary) -> Vec<MelParseDiagnostic> {
    let mut diagnostics = Vec::new();
    diagnostics.extend(
        report
            .decode_errors
            .iter()
            .map(|diagnostic| MelParseDiagnostic {
                stage: MelDiagnosticStage::Decode,
                message: diagnostic.message.clone(),
                span: mel_span(diagnostic.range),
            }),
    );
    diagnostics.extend(report.errors.iter().map(|diagnostic| MelParseDiagnostic {
        stage: MelDiagnosticStage::Parse,
        message: Cow::Borrowed(diagnostic.message),
        span: mel_span(diagnostic.range),
    }));
    diagnostics
}

fn mel_span(range: TextRange) -> MelSpan {
    MelSpan {
        start: range_start(range) as usize,
        end: range_end(range) as usize,
    }
}

fn map_light_source_encoding(encoding: SourceEncoding) -> MelSourceEncoding {
    match encoding {
        SourceEncoding::Utf8 => MelSourceEncoding::Utf8,
        SourceEncoding::Cp932 => MelSourceEncoding::Cp932,
        SourceEncoding::Gbk => MelSourceEncoding::Gbk,
    }
}

fn selective_encoding_diagnostic(encoding: MelSourceEncoding) -> Option<MelParseDiagnostic> {
    let label = match encoding {
        MelSourceEncoding::Utf8 => return None,
        MelSourceEncoding::Cp932 => "cp932",
        MelSourceEncoding::Gbk => "gbk",
    };
    Some(MelParseDiagnostic {
        stage: MelDiagnosticStage::Decode,
        message: Cow::Owned(format!(
            "non-utf8 MEL source decoded via {label} selective path requires conservative audit coverage"
        )),
        span: MelSpan { start: 0, end: 0 },
    })
}

fn file_command_flag_heuristic_diagnostic(flag: &str) -> MelParseDiagnostic {
    MelParseDiagnostic {
        stage: MelDiagnosticStage::Parse,
        message: Cow::Owned(format!(
            "file {flag} selective extraction relies on heuristic flag parsing and requires conservative audit coverage"
        )),
        span: MelSpan { start: 0, end: 0 },
    }
}

fn tracked_setattr_opaque_tail_diagnostic(attr: &str) -> MelParseDiagnostic {
    MelParseDiagnostic {
        stage: MelDiagnosticStage::Parse,
        message: Cow::Owned(format!(
            "setAttr {attr} selective extraction depends on opaque tail beyond the light-prefix budget and requires conservative audit coverage"
        )),
        span: MelSpan { start: 0, end: 0 },
    }
}

fn is_audit_top_level_command_head(head: &str) -> bool {
    matches!(
        head,
        "python"
            | "eval"
            | "evalDeferred"
            | "scriptJob"
            | "source"
            | "loadPlugin"
            | "commandPort"
            | "print"
            | "warning"
            | "error"
            | "confirmDialog"
            | "headsUpMessage"
    ) || command_schema_has_script_flag(head)
}

fn is_audit_top_level_command_head_cached(head: &str, cache: &mut HashMap<String, bool>) -> bool {
    if let Some(cached) = cache.get(head) {
        return *cached;
    }
    let is_audit_head = is_audit_top_level_command_head(head);
    cache.insert(head.to_string(), is_audit_head);
    is_audit_head
}

fn classify_top_level_other(source_text: &str) -> Option<&'static str> {
    let trimmed = source_text.trim_start();
    [
        "python",
        "eval",
        "evalDeferred",
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
    .find(|head| {
        trimmed
            .strip_prefix(head)
            .is_some_and(|rest| rest.starts_with(char::is_whitespace) || rest.starts_with('('))
    })
}

fn command_schema_has_script_flag(head: &str) -> bool {
    MayaCommandRegistry::new()
        .lookup(head)
        .is_some_and(|schema| {
            schema
                .flags
                .iter()
                .any(|flag| flag.value_shapes.contains(&ValueShape::Script))
        })
}

#[derive(Default)]
struct SelectiveScanSink {
    requires: Vec<String>,
    seen_requires: HashSet<String>,
    require_entries: Vec<RawMaRequireEntry>,
    scene_paths: Vec<ScenePathEntry>,
    seen_paths: HashSet<u64>,
    script_entries: Vec<RawMaScriptEntry>,
    audit_items: Vec<MelAuditTopLevelItemFact>,
    audit_head_cache: HashMap<String, bool>,
    selective_diagnostics: Vec<MelParseDiagnostic>,
    active_block: Option<ActiveCreateBlock>,
    line_tracker: LineTracker,
}

impl LightItemSink for SelectiveScanSink {
    fn on_item(&mut self, source: SourceView<'_>, item: LightItem) {
        let span = match &item {
            LightItem::Proc(proc_def) => proc_def.span,
            LightItem::Command(command) => command.span,
            LightItem::Other { span } => *span,
        };
        let span_start = source.display_range(span).start;
        self.line_tracker
            .advance_to(source.text().as_bytes(), span_start);
        let is_indented = self.line_tracker.is_indented();
        if !is_indented {
            flush_active_block(&mut self.active_block, &mut self.script_entries);
        }

        match item {
            LightItem::Proc(proc_def) if is_indented => {
                self.push_indented_top_level_diagnostic(proc_def.span);
            }
            LightItem::Proc(proc_def) if !is_indented => {
                self.audit_items
                    .push(MelAuditTopLevelItemFact::Proc(MelAuditTopLevelProcFact {
                        is_global: proc_def.is_global,
                        source_span: mel_span(proc_def.span),
                        span: mel_span(proc_def.span),
                    }));
            }
            LightItem::Command(command) => {
                if let Some(item) =
                    selective_item_from_command(source, &command, &mut self.audit_head_cache)
                {
                    if is_indented
                        && selective_item_requires_top_level_context(
                            &item,
                            self.active_block.is_some(),
                        )
                    {
                        self.push_indented_top_level_diagnostic(command.span);
                    }
                    self.on_selective_item(source, item, is_indented);
                }
            }
            LightItem::Other { span } if is_indented => {
                if let Some(head) = classify_top_level_other(source.slice(span)) {
                    self.push_indented_top_level_diagnostic(span);
                    if self.active_block.is_none() {
                        self.audit_items
                            .push(MelAuditTopLevelItemFact::Command(Box::new(
                                MelAuditTopLevelCommandFact {
                                    head: Arc::from(head),
                                    source_span: mel_span(span),
                                    span: mel_span(span),
                                    file_command_callback: None,
                                },
                            )));
                    }
                }
            }
            LightItem::Other { span } if !is_indented => {
                if let Some(head) = classify_top_level_other(source.slice(span)) {
                    self.audit_items
                        .push(MelAuditTopLevelItemFact::Command(Box::new(
                            MelAuditTopLevelCommandFact {
                                head: Arc::from(head),
                                source_span: mel_span(span),
                                span: mel_span(span),
                                file_command_callback: None,
                            },
                        )));
                } else {
                    self.audit_items.push(MelAuditTopLevelItemFact::Other(
                        MelAuditTopLevelOtherFact {
                            source_span: mel_span(span),
                            span: mel_span(span),
                        },
                    ));
                }
            }
            _ => {}
        }
    }
}

impl SelectiveScanSink {
    fn finish(
        mut self,
        source: SourceView<'_>,
        report: LightScanSummary,
    ) -> RawMaSelectiveSections {
        flush_active_block(&mut self.active_block, &mut self.script_entries);

        let diagnostics = collect_report_diagnostics(&report);
        let mut diagnostics = diagnostics;
        diagnostics.extend(self.selective_diagnostics);
        let source_encoding = map_light_source_encoding(report.source_encoding);
        if let Some(diagnostic) = selective_encoding_diagnostic(source_encoding) {
            diagnostics.push(diagnostic);
        }
        let source_store = MelAuditSourceStore::from_relevant_spans(
            source.text(),
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.span)
                .chain(self.audit_items.iter().map(audit_item_source_span)),
        );

        RawMaSelectiveSections {
            dump_sections: RawMaDumpSections {
                requires: self.requires,
                require_entries: self.require_entries,
                script_entries: self.script_entries,
            },
            scene_paths: self.scene_paths,
            audit_top_level: MelAuditTopLevelFacts {
                source_store,
                source_encoding,
                diagnostics,
                items: self.audit_items,
            },
        }
    }

    fn push_indented_top_level_diagnostic(&mut self, span: TextRange) {
        self.selective_diagnostics.push(MelParseDiagnostic {
            stage: MelDiagnosticStage::Parse,
            message: Cow::Borrowed(
                "indented top-level MEL statement requires conservative audit coverage",
            ),
            span: mel_span(span),
        });
    }

    fn on_selective_item(
        &mut self,
        source: SourceView<'_>,
        item: MayaSelectiveItem,
        is_indented: bool,
    ) {
        match item {
            MayaSelectiveItem::Requires(requires) if !is_indented => {
                let normalized = normalize_requires_command(source.slice(requires.span));
                if self.seen_requires.insert(normalized.clone()) {
                    let kind = classify_raw_require_kind(&normalized);
                    self.requires.push(normalized.clone());
                    self.require_entries.push(RawMaRequireEntry {
                        rendered: normalized,
                        kind,
                        start: range_start(requires.span) as usize,
                        end: range_end(requires.span) as usize,
                    });
                }
            }
            MayaSelectiveItem::File(file) if !is_indented => {
                let command_text = source.slice(file.span);
                if file_command_has_flag(command_text, "-rfn") {
                    self.selective_diagnostics
                        .push(file_command_flag_heuristic_diagnostic("-rfn"));
                }
                if file_command_has_flag(command_text, "-command") {
                    self.selective_diagnostics
                        .push(file_command_flag_heuristic_diagnostic("-command"));
                }
                if let Some(entry) =
                    extract_reference_entry_from_selective_file_command(source, &file, command_text)
                {
                    push_path_entry(&mut self.scene_paths, &mut self.seen_paths, entry);
                }
                if let Some(callback) = extract_file_command_callback(command_text) {
                    self.audit_items
                        .push(MelAuditTopLevelItemFact::Command(Box::new(
                            MelAuditTopLevelCommandFact {
                                head: Arc::from("file"),
                                source_span: mel_span(file.span),
                                span: mel_span(file.span),
                                file_command_callback: Some(callback),
                            },
                        )));
                }
            }
            MayaSelectiveItem::CreateNode(create_node) if !is_indented => {
                self.active_block = start_create_node_block(
                    source,
                    source.slice(create_node.span),
                    &create_node,
                    self.line_tracker.line_number(),
                );
            }
            MayaSelectiveItem::SetAttr(set_attr) if is_indented => {
                if let Some(attr) =
                    tracked_opaque_tail_attr_name(self.active_block.as_ref(), &set_attr)
                {
                    self.selective_diagnostics
                        .push(tracked_setattr_opaque_tail_diagnostic(attr));
                }
                if let Some(block) = self.active_block.as_mut() {
                    apply_setattr_to_active_block(
                        source,
                        block,
                        &set_attr,
                        set_attr.tracked_attr,
                        source.slice(set_attr.span),
                        &mut self.scene_paths,
                        &mut self.seen_paths,
                    );
                }
            }
            MayaSelectiveItem::OtherCommand { head_range, span }
                if !is_indented || self.active_block.is_none() =>
            {
                let head = source.slice(head_range);
                if is_audit_top_level_command_head_cached(head, &mut self.audit_head_cache) {
                    self.audit_items
                        .push(MelAuditTopLevelItemFact::Command(Box::new(
                            MelAuditTopLevelCommandFact {
                                head: Arc::from(head),
                                source_span: mel_span(span),
                                span: mel_span(span),
                                file_command_callback: None,
                            },
                        )));
                }
            }
            _ => {}
        }
    }
}

fn classify_raw_require_kind(rendered: &str) -> RawMaRequireKind {
    if rendered.starts_with("requires maya ") {
        RawMaRequireKind::MayaVersion
    } else {
        RawMaRequireKind::Plugin
    }
}

fn selective_item_requires_top_level_context(
    item: &MayaSelectiveItem,
    _has_active_block: bool,
) -> bool {
    match item {
        MayaSelectiveItem::Requires(_)
        | MayaSelectiveItem::File(_)
        | MayaSelectiveItem::CreateNode(_)
        | MayaSelectiveItem::OtherCommand { .. } => true,
        MayaSelectiveItem::SetAttr(_) => false,
    }
}

fn selective_item_from_command(
    source: SourceView<'_>,
    command: &LightCommandSurface,
    audit_head_cache: &mut HashMap<String, bool>,
) -> Option<MayaSelectiveItem> {
    let head = source.slice(command.head_range);
    match head {
        "requires" => Some(MayaSelectiveItem::Requires(MayaSelectiveRequires {
            head_range: command.head_range,
            argument_ranges: collect_non_flag_ranges(&command.words),
            span: command.span,
        })),
        "file" => Some(MayaSelectiveItem::File(MayaSelectiveFile {
            head_range: command.head_range,
            path_range: last_non_flag_range(&command.words),
            span: command.span,
        })),
        "createNode" => {
            let node_type_range = first_non_flag_range(&command.words);
            let node_type = node_type_range.map(|range| strip_outer_quotes(source.slice(range)))?;
            if node_type == "script" {
                return Some(MayaSelectiveItem::CreateNode(MayaSelectiveCreateNode {
                    head_range: command.head_range,
                    node_type_range,
                    name_range: first_flag_arg_range(source, &command.words, &["name", "n"]),
                    parent_range: first_flag_arg_range(source, &command.words, &["parent", "p"]),
                    span: command.span,
                }));
            }
            if node_type.is_empty() {
                return None;
            }
            Some(MayaSelectiveItem::CreateNode(MayaSelectiveCreateNode {
                head_range: command.head_range,
                node_type_range,
                name_range: first_flag_arg_range(source, &command.words, &["name", "n"]),
                parent_range: first_flag_arg_range(source, &command.words, &["parent", "p"]),
                span: command.span,
            }))
        }
        "setAttr" => {
            let attr_path_range = first_setattr_attr_path_range(source, &command.words);
            let type_name_range = first_flag_arg_range(source, &command.words, &["type", "typ"]);
            let tracked_attr = attr_path_range.and_then(|range| {
                DefaultMayaSelectiveSetAttrSelector
                    .classify(strip_outer_quotes(source.slice(range)))
            });
            let attr_path = attr_path_range.map(|range| strip_outer_quotes(source.slice(range)))?;
            if !matches!(attr_path, ".b" | ".st" | ".stp")
                && tracked_attr.is_none()
                && !matches!(
                    classify_scene_path_attr(attr_path),
                    Some(ScenePathAttrKind::FileTexturePath | ScenePathAttrKind::ReferencePath)
                )
            {
                return None;
            }
            Some(MayaSelectiveItem::SetAttr(MayaSelectiveSetAttr {
                head_range: command.head_range,
                attr_path_range,
                type_name_range,
                tracked_attr,
                opaque_tail: command.opaque_tail,
                span: command.span,
            }))
        }
        _ if is_audit_top_level_command_head_cached(head, audit_head_cache) => {
            Some(MayaSelectiveItem::OtherCommand {
                head_range: command.head_range,
                span: command.span,
            })
        }
        _ => None,
    }
}

fn audit_item_source_span(item: &MelAuditTopLevelItemFact) -> MelSpan {
    match item {
        MelAuditTopLevelItemFact::Command(command) => command.source_span,
        MelAuditTopLevelItemFact::Proc(proc_def) => proc_def.source_span,
        MelAuditTopLevelItemFact::Other(other) => other.source_span,
    }
}

fn collect_non_flag_ranges(words: &[LightWord]) -> Vec<TextRange> {
    words.iter().filter_map(non_flag_range).collect()
}

fn first_non_flag_range(words: &[LightWord]) -> Option<TextRange> {
    words.iter().find_map(non_flag_range)
}

fn first_setattr_attr_path_range(source: SourceView<'_>, words: &[LightWord]) -> Option<TextRange> {
    let mut index = 0usize;
    while index < words.len() {
        match words.get(index)? {
            LightWord::Flag { text, .. } => {
                let descriptor =
                    command_flag_descriptor(FlagCommandKind::SetAttr, source.slice(*text));
                index += 1 + descriptor.map_or(0, |descriptor| descriptor.arity);
            }
            word => return non_flag_range(word),
        }
    }
    None
}

fn last_non_flag_range(words: &[LightWord]) -> Option<TextRange> {
    words.iter().rev().find_map(non_flag_range)
}

fn non_flag_range(word: &LightWord) -> Option<TextRange> {
    (!matches!(word, LightWord::Flag { .. })).then_some(word.range())
}

fn first_flag_arg_range(
    source: SourceView<'_>,
    words: &[LightWord],
    names: &[&str],
) -> Option<TextRange> {
    let mut index = 0usize;
    while index < words.len() {
        let LightWord::Flag { text, .. } = &words[index] else {
            index += 1;
            continue;
        };
        let normalized = source.slice(*text).trim_start_matches('-');
        if names.contains(&normalized) {
            return words.get(index + 1).and_then(non_flag_range);
        }
        index += 1;
    }
    None
}

fn strip_outer_quotes(text: &str) -> &str {
    text.strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or(text)
}

fn extract_file_command_callback(command: &str) -> Option<String> {
    if !command.contains("-command") {
        return None;
    }
    let tokens = tokenize_command(command).ok()?;
    if !matches!(tokens.first().and_then(bare_token), Some("file")) {
        return None;
    }

    let mut idx = 1usize;
    while idx < tokens.len() {
        let Some(flag) = bare_token(tokens.get(idx)?) else {
            idx += 1;
            continue;
        };
        if flag != "-command" {
            idx += 1;
            continue;
        }

        let mut cursor = idx + 1;
        let mut args = Vec::new();
        while cursor < tokens.len() {
            let Some(token) = tokens.get(cursor) else {
                break;
            };
            if matches!(token, Token::Bare(value) if value.starts_with('-')) {
                break;
            }
            if let Some(text) = token_text(token) {
                args.push(text.to_string());
            }
            cursor += 1;
        }
        return args
            .get(1)
            .or_else(|| args.last())
            .cloned()
            .filter(|value| !value.trim().is_empty());
    }

    None
}

fn file_command_has_flag(command: &str, target_flag: &str) -> bool {
    tokenize_command(command)
        .ok()
        .map(|tokens| {
            tokens
                .iter()
                .skip(1)
                .any(|token| bare_token(token) == Some(target_flag))
        })
        .unwrap_or_else(|| command.contains(target_flag))
}

fn tracked_opaque_tail_attr_name(
    active_block: Option<&ActiveCreateBlock>,
    set_attr: &MayaSelectiveSetAttr,
) -> Option<&'static str> {
    set_attr.opaque_tail?;
    match active_block? {
        ActiveCreateBlock::Script(_) => {
            matches!(set_attr.tracked_attr, Some(MayaTrackedSetAttrAttr::B)).then_some(".b")
        }
        ActiveCreateBlock::ScenePath(_) => tracked_scene_path_attr_name(set_attr.tracked_attr),
    }
}

#[cfg(test)]
mod tests {
    use encoding_rs::SHIFT_JIS;

    use super::{
        RawMaRequireKind, extract_raw_selective_sections_from_ma,
        extract_raw_selective_sections_from_ma_with_budget,
    };
    use crate::mel::{MelDiagnosticStage, MelParseBudget, MelSourceEncoding};

    fn non_utf8_repro_source(label: &str) -> String {
        let body = format!(
            concat!(
                "string $panelName = `sceneUIReplacement -getNextPanel ",
                "\\\"outlinerPanel\\\" (localizedPanelLabel(\\\"{label}\\\")) `;\\n",
                "if (\\\"\\\" != $panelName) {{\\n",
                "    print $panelName;\\n",
                "}}\\n"
            ),
            label = label,
        );
        format!(
            concat!(
                "//Maya ASCII 2026 scene\n",
                "//Codeset: 932\n",
                "requires maya \"2026\";\n",
                "file -r -rfn \"charARN\" \"rig/charA_v001.mb\";\n",
                "createNode script -n \"uiConfigurationScriptNode\";\n",
                "    setAttr \".b\" -type \"string\" \"{body}\";\n",
                "    setAttr \".st\" 1;\n",
                "    setAttr \".stp\" 1;\n",
                "createNode script -n \"sceneConfigurationScriptNode\";\n",
                "    setAttr \".b\" -type \"string\" \"playbackOptions -min 1 -max 24 -ast 1 -aet 48\";\n",
                "    setAttr \".st\" 1;\n",
                "    setAttr \".stp\" 1;\n",
                "createNode reference -n \"ref1\";\n",
                "    setAttr \".fn\" -type \"string\" \"rig/charA_v001.mb\";\n"
            ),
            body = body,
        )
    }

    #[test]
    fn selective_sections_collect_requires_scripts_and_paths() {
        let input = concat!(
            "requires maya \"2026\";\n",
            "file -r -rfn \"charARN\" \"rig/charA_v001.mb\";\n",
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
            "    setAttr \".st\" 1;\n",
            "    setAttr \".stp\" 1;\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
            "createNode reference -n \"ref1\";\n",
            "    setAttr \".fn\" -type \"string\" \"rig/charA_v001.mb\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(
            sections.dump_sections.requires,
            vec!["requires maya \"2026\";".to_string()]
        );
        assert_eq!(sections.dump_sections.require_entries.len(), 1);
        assert_eq!(
            sections.dump_sections.require_entries[0].kind,
            RawMaRequireKind::MayaVersion
        );
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(sections.dump_sections.script_entries[0].name, "scriptNode1");
        assert_eq!(
            sections.dump_sections.script_entries[0].body,
            "print \"ok\";"
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].script_type,
            Some(1)
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].source_type,
            Some(1)
        );
        assert_eq!(sections.scene_paths.len(), 3);
    }

    #[test]
    fn selective_sections_keep_block_boundaries_on_unindented_commands() {
        let input = concat!(
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
            "rename \"a\" \"b\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ignored\\\";\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(
            sections.dump_sections.script_entries[0].body,
            "print \"ok\";"
        );
    }

    #[test]
    fn selective_sections_tolerate_extra_spacing_in_create_node_script() {
        let input = concat!(
            "createNode     script     -n     \"scrambledScript\";\n",
            "    setAttr \".stp\" 0;\n",
            "    setAttr \".st\" 0;\n",
            "    setAttr \".b\"\n",
            "        -type \"string\"\n",
            "        \"print(\\\"semantic fixture\\\")\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(
            sections.dump_sections.script_entries[0].name,
            "scrambledScript"
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].body,
            "print(\"semantic fixture\")"
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].script_type,
            Some(0)
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].source_type,
            Some(0)
        );
    }

    #[test]
    fn selective_sections_collect_file_command_callback_for_audit_reuse() {
        let input = concat!(
            "file -r -command \"onLoad\" \"python(\\\"import os\\\")\" \"C:/ref.ma\";\n",
            "setAttr \".v\" yes;\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.audit_top_level.items.len(), 1);

        let callback = match &sections.audit_top_level.items[0] {
            crate::mel::MelAuditTopLevelItemFact::Command(command) => {
                command.file_command_callback.as_deref()
            }
            _ => None,
        };
        assert_eq!(callback, Some(r#"python("import os")"#));
        assert!(sections.audit_top_level.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("file -command selective extraction relies on heuristic flag parsing and requires conservative audit coverage")
        }));
    }

    #[test]
    fn selective_sections_report_file_rfn_heuristic_as_diagnostic() {
        let input = "file -r -rfn \"charARN\" \"rig/charA_v001.mb\";\n";

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());

        assert_eq!(sections.scene_paths.len(), 1);
        assert_eq!(sections.scene_paths[0].node_name, "charARN");
        assert!(sections.audit_top_level.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("file -rfn selective extraction relies on heuristic flag parsing and requires conservative audit coverage")
        }));
    }

    #[test]
    fn selective_sections_report_opaque_tail_script_body_as_diagnostic() {
        let body = "opaque tail body";
        let padding = " ".repeat(520);
        let input = format!(
            concat!(
                "createNode script -n \"opaqueTailScript\";\n",
                "    setAttr \".b\" -type \"string\"{padding}\"{body}\";\n",
            ),
            padding = padding,
            body = body
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());

        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(sections.dump_sections.script_entries[0].body, body);
        assert!(sections.audit_top_level.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("setAttr .b selective extraction depends on opaque tail beyond the light-prefix budget and requires conservative audit coverage")
        }));
    }

    #[test]
    fn selective_sections_preserve_proc_items_for_audit_reuse() {
        let sections = extract_raw_selective_sections_from_ma(
            b"global proc string hello() { return \"ok\"; }\n",
        );
        assert!(matches!(
            sections.audit_top_level.items.first(),
            Some(crate::mel::MelAuditTopLevelItemFact::Proc(proc_def))
                if proc_def.is_global
                    && proc_def.source_text(&sections.audit_top_level)
                        == "global proc string hello() { return \"ok\"; }"
        ));
    }

    #[test]
    fn selective_sections_preserve_function_style_audit_heads_without_fallback() {
        let sections = extract_raw_selective_sections_from_ma(b"python(\"print(\\\"hi\\\")\");\n");
        assert!(matches!(
            sections.audit_top_level.items.first(),
            Some(crate::mel::MelAuditTopLevelItemFact::Command(command))
                if command.head.as_ref() == "python"
                    && command.source_text(&sections.audit_top_level)
                        == "python(\"print(\\\"hi\\\")\");"
        ));
    }

    #[test]
    fn selective_sections_preserve_indented_top_level_python_with_diagnostic() {
        let sections =
            extract_raw_selective_sections_from_ma(b"    python(\"print(\\\"hi\\\")\");\n");

        assert!(matches!(
            sections.audit_top_level.items.first(),
            Some(crate::mel::MelAuditTopLevelItemFact::Command(command))
                if command.head.as_ref() == "python"
                    && command.source_text(&sections.audit_top_level)
                        == "python(\"print(\\\"hi\\\")\");"
        ));
        assert!(
            sections
                .audit_top_level
                .diagnostics
                .iter()
                .any(|diagnostic| {
                    diagnostic.stage == MelDiagnosticStage::Parse
                        && diagnostic.message.contains(
                            "indented top-level MEL statement requires conservative audit coverage",
                        )
                })
        );
    }

    #[test]
    fn selective_sections_preserve_indented_top_level_eval_with_diagnostic() {
        let sections =
            extract_raw_selective_sections_from_ma(b"    eval(\"python(\\\"print(1)\\\")\");\n");

        assert!(matches!(
            sections.audit_top_level.items.first(),
            Some(crate::mel::MelAuditTopLevelItemFact::Command(command))
                if command.head.as_ref() == "eval"
                    && command.source_text(&sections.audit_top_level)
                        == "eval(\"python(\\\"print(1)\\\")\");"
        ));
        assert!(
            sections
                .audit_top_level
                .diagnostics
                .iter()
                .any(|diagnostic| {
                    diagnostic.stage == MelDiagnosticStage::Parse
                        && diagnostic.message.contains(
                            "indented top-level MEL statement requires conservative audit coverage",
                        )
                })
        );
    }

    #[test]
    fn selective_sections_do_not_promote_indented_setattr_inside_create_node_block() {
        let sections = extract_raw_selective_sections_from_ma(
            concat!(
                "createNode script -n \"scriptNode1\";\n",
                "    setAttr \".b\" -type \"string\" \"python(\\\"print(1)\\\")\";\n",
            )
            .as_bytes(),
        );

        assert!(sections.audit_top_level.items.is_empty());
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(sections.dump_sections.script_entries[0].name, "scriptNode1");
        assert_eq!(
            sections.dump_sections.script_entries[0].body,
            "python(\"print(1)\")"
        );
    }

    #[test]
    fn selective_sections_preserve_unsupported_top_level_items_for_audit_reuse() {
        let sections = extract_raw_selective_sections_from_ma(b"foo($bar);\n");
        assert!(matches!(
            sections.audit_top_level.items.first(),
            Some(crate::mel::MelAuditTopLevelItemFact::Other(other))
                if other.source_text(&sections.audit_top_level) == "foo($bar);"
        ));
    }

    #[test]
    fn selective_sections_keep_script_and_path_extraction_with_long_setattr_payloads() {
        let long_payload = "1234 ".repeat(400);
        let script_body = format!("print(\"{}\")", "x".repeat(600));
        let script_body_literal = script_body.replace('"', "\\\"");
        let input = format!(
            concat!(
                "createNode script -n \"scriptNode1\";\n",
                "    setAttr \".b\" -type \"string\" \"{script_body}\";\n",
                "    setAttr \".st\" {long_payload};\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
            ),
            script_body = script_body_literal,
            long_payload = long_payload.trim_end(),
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(sections.dump_sections.script_entries[0].body, script_body);
        assert_eq!(
            sections.dump_sections.script_entries[0].script_type,
            Some(1234)
        );
        assert_eq!(sections.scene_paths.len(), 1);
        assert_eq!(sections.scene_paths[0].value, "textures/albedo.png");
    }

    #[test]
    fn selective_sections_ignore_irrelevant_create_nodes_and_setattrs() {
        let input = concat!(
            "createNode transform -n \"ignoredTransform\";\n",
            "    setAttr \".tx\" 1;\n",
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".v\" yes;\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".uvst[0].uvsn\" -type \"string\" \"map1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
            "createNode reference -n \"ref1\";\n",
            "    setAttr \".ptag\" -type \"string\" \"ignored\";\n",
            "    setAttr \".fn\" -type \"string\" \"rig/charA_v001.mb\";\n",
            "rename \"ignored\" \"stillIgnored\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(
            sections.dump_sections.script_entries[0].body,
            "print \"ok\";"
        );
        assert_eq!(sections.scene_paths.len(), 2);
        assert_eq!(sections.scene_paths[0].value, "textures/albedo.png");
        assert_eq!(sections.scene_paths[1].value, "rig/charA_v001.mb");
        assert!(sections.audit_top_level.items.is_empty());
    }

    #[test]
    fn selective_sections_report_unterminated_block_comment_without_optimistic_surfaces() {
        let input = concat!(
            "createNode file -n \"file1\";\n",
            "/* hidden tail\n",
            "file -r -rfn \"charARN\" \"rig/charA_v001.mb\";\n",
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());

        assert!(sections.dump_sections.script_entries.is_empty());
        assert!(sections.scene_paths.is_empty());
        assert!(sections.audit_top_level.items.is_empty());
        assert_eq!(sections.audit_top_level.diagnostics.len(), 1);
        assert_eq!(
            sections.audit_top_level.diagnostics[0].stage,
            MelDiagnosticStage::Parse
        );
        assert_eq!(
            sections.audit_top_level.diagnostics[0].message,
            "unterminated block comment"
        );
    }

    #[test]
    fn selective_sections_report_budget_exceeded_without_surfaces() {
        let input = concat!(
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma_with_budget(
            input.as_bytes(),
            &MelParseBudget::default().with_max_bytes(8),
        );

        assert!(sections.dump_sections.script_entries.is_empty());
        assert!(sections.scene_paths.is_empty());
        assert!(sections.audit_top_level.items.is_empty());
        assert_eq!(sections.audit_top_level.diagnostics.len(), 1);
        assert_eq!(
            sections.audit_top_level.diagnostics[0].message,
            "source exceeds parse budget: max_bytes"
        );
    }

    #[test]
    fn selective_sections_keep_relevant_entries_after_cp932_prefix_line() {
        let source = concat!(
            "//Maya ASCII 2026 scene\n",
            "//Codeset: 932\n",
            "fileInfo \"comment\" \"名前名前名前\";\n",
            "createNode file -n \"file1\";\n",
            "    setAttr \".ftn\" -type \"string\" \"textures/albedo.png\";\n",
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ok\\\";\";\n",
            "    setAttr \".st\" 1;\n",
            "    setAttr \".stp\" 1;\n",
        );
        let (bytes, _, _) = SHIFT_JIS.encode(source);
        let sections = extract_raw_selective_sections_from_ma(bytes.as_ref());

        assert_eq!(sections.scene_paths.len(), 1);
        assert_eq!(sections.scene_paths[0].value, "textures/albedo.png");
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(sections.dump_sections.script_entries[0].name, "scriptNode1");
        assert_eq!(
            sections.dump_sections.script_entries[0].body,
            "print \"ok\";"
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].script_type,
            Some(1)
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].source_type,
            Some(1)
        );
    }

    #[test]
    fn selective_sections_prefilter_keeps_multiline_relevant_setattrs() {
        let input = concat!(
            "createNode script -n \"scriptNode1\";\n",
            "    setAttr \".b\" -type \"string\" (\"print\" +\n",
            "        \"(\\\"ok\\\")\");\n",
            "    setAttr -k off \".v\" yes;\n",
            "createNode file -n \"file1\";\n",
            "    setAttr -l on \".ftn\" -type \"string\" (\"textures/\" +\n",
            "        \"albedo.png\");\n",
            "    setAttr \".uvst[0].uvsn\" -type \"string\" \"map1\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(
            sections.dump_sections.script_entries[0].body,
            "print(\"ok\")"
        );
        assert_eq!(sections.scene_paths.len(), 1);
        assert_eq!(sections.scene_paths[0].value, "textures/albedo.png");
    }

    #[test]
    fn selective_sections_collect_file_texture_name_paths_from_non_file_nodes() {
        let input = concat!(
            "createNode psdFileTex -n \"psdTex1\";\n",
            "    setAttr \".fileTextureName\" -type \"string\" \"sourceimages/layered.psd\";\n",
            "createNode movie -n \"movieTex1\";\n",
            "    setAttr \".fileTextureName\" -type \"string\" \"movies/clip.mov\";\n",
            "createNode customPathNode -n \"customTex1\";\n",
            "    setAttr \".fileTextureName\" -type \"string\" \"textures/custom.tx\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.scene_paths.len(), 3);
        assert_eq!(sections.scene_paths[0].node_type, "psdFileTex");
        assert_eq!(sections.scene_paths[0].attr, ".fileTextureName");
        assert_eq!(sections.scene_paths[0].value, "sourceimages/layered.psd");
        assert_eq!(sections.scene_paths[1].node_type, "movie");
        assert_eq!(sections.scene_paths[2].node_type, "customPathNode");
    }

    #[test]
    fn selective_sections_do_not_collect_reference_attr_on_non_reference_nodes() {
        let input = concat!(
            "createNode customPathNode -n \"customTex1\";\n",
            "    setAttr \".fn\" -type \"string\" \"rig/example_scene.ma\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert!(sections.scene_paths.is_empty());
    }

    #[test]
    fn selective_sections_utf8_control_reports_utf8_encoding() {
        let input = non_utf8_repro_source("アウトライナ プラス");

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());

        assert_eq!(
            sections.audit_top_level.source_encoding,
            MelSourceEncoding::Utf8
        );
        assert_eq!(
            sections.dump_sections.requires,
            vec!["requires maya \"2026\";"]
        );
        assert_eq!(sections.dump_sections.require_entries.len(), 1);
        assert_eq!(sections.dump_sections.script_entries.len(), 2);
        assert_eq!(sections.scene_paths.len(), 2);
        assert_eq!(
            sections.dump_sections.script_entries[0].body,
            "string $panelName = `sceneUIReplacement -getNextPanel \"outlinerPanel\" (localizedPanelLabel(\"アウトライナ プラス\")) `;\nif (\"\" != $panelName) {\n    print $panelName;\n}\n"
        );
    }

    #[test]
    fn selective_sections_cp932_fixture_reports_encoding_and_fail_closed_diagnostic() {
        let input = non_utf8_repro_source("アウトライナ プラス");
        let (bytes, _, had_errors) = encoding_rs::SHIFT_JIS.encode(&input);
        assert!(!had_errors);

        let sections = extract_raw_selective_sections_from_ma(bytes.as_ref());

        assert_eq!(
            sections.audit_top_level.source_encoding,
            MelSourceEncoding::Cp932
        );
        assert_eq!(
            sections.dump_sections.requires,
            vec!["requires maya \"2026\";"]
        );
        assert_eq!(sections.dump_sections.require_entries.len(), 1);
        assert!(sections.audit_top_level.diagnostics.iter().any(|diagnostic| {
            diagnostic.stage == MelDiagnosticStage::Decode
                && diagnostic
                    .message
                    .contains("non-utf8 MEL source decoded via cp932 selective path requires conservative audit coverage")
        }));
    }
}
