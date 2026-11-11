use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};

use maya_mel::{
    maya::model::{MayaSelectiveFile, MayaSelectiveItem, MayaSelectiveRequires},
    parser::{
        LightCommandSurface, LightItem, LightItemSink, LightParseOptions, LightScanSummary,
        LightSourceView, LightWord, SourceEncoding,
        scan_light_bytes_with_options_and_sink_and_then,
    },
    sema::command_schema::{CommandRegistry, ValueShape},
    syntax::{TextRange, range_end, range_start, text_range},
};

use crate::{
    ScenePathEntry, ScenePathMeta,
    ma::{
        block_context::{BlockCommand, BlockContext, BlockTracker, ContextWord, SelectedTarget},
        commands::{
            MAYA_COMMAND_REGISTRY, Token, bare_token, connect_attr_flag_arity, create_node_flag,
            is_file_command_callback_flag, setattr_flag_arity, token_text, tokenize_command,
            unquoted_range_value,
        },
        lexer::{
            is_reference_attr, parse_ma_quoted_literal, parse_setattr_string_value_tail,
            unescape_ma_string_literal,
        },
        parse::validate_string_concat_expression_prefix,
        raw_dump::{
            RawMaConnection, RawMaConnectionAssignment, RawMaConnectionPlug, RawMaConnections,
            RawMaDumpSections, RawMaNodeAttrSelector, RawMaNodeAttrValue, RawMaRequireEntry,
            RawMaRequireKind, RawMaScriptAssignment, RawMaScriptEntry,
        },
        rewrite::last_quoted_literal,
    },
    mel::{
        MelAuditSourceStore, MelAuditTopLevelCommandFact, MelAuditTopLevelFacts,
        MelAuditTopLevelItemFact, MelAuditTopLevelOtherFact, MelAuditTopLevelProcFact,
        MelDiagnosticStage, MelParseBudget, MelParseDiagnostic, MelSourceEncoding, MelSpan,
    },
    reference_semantics::{
        ScenePathAttrKind, classify_scene_path_attr, looks_like_scene_file_path,
    },
};

#[derive(Debug, Clone)]
pub struct RawMaSelectiveSections {
    pub connections: RawMaConnections,
    pub dump_sections: RawMaDumpSections,
    pub scene_paths: Vec<ScenePathEntry>,
    pub node_attr_values: Vec<RawMaNodeAttrValue>,
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
    extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(
        data,
        budget,
        &HashSet::new(),
    )
}

pub fn extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(
    data: &[u8],
    budget: &MelParseBudget,
    node_attr_selectors: &HashSet<RawMaNodeAttrSelector>,
) -> RawMaSelectiveSections {
    let mut sink = SelectiveScanSink {
        selected_node_attr_selectors: node_attr_selectors.clone(),
        execution_attr_names: node_attr_selectors
            .iter()
            .filter_map(|selector| selector.attr.strip_prefix('.').map(str::to_string))
            .collect(),
        ..SelectiveScanSink::default()
    };
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
    Selected(ActiveSelectedNodeBlock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveScriptBlock {
    entry_index: Option<usize>,
    name: String,
    assignments: Vec<RawMaScriptAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveScenePathBlock {
    node_type: String,
    node_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSelectedNodeBlock {
    node_name: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LineTracker {
    cursor: usize,
    line_has_indent: bool,
    line_started: bool,
}

impl LineTracker {
    fn advance_to(&mut self, bytes: &[u8], target: usize) {
        while self.cursor < target {
            match bytes[self.cursor] {
                b'\n' => {
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
}

fn source_raw_bytes(source: LightSourceView<'_>) -> &[u8] {
    source.raw_slice(text_range(0, source.len() as u32))
}

fn source_ascii_slice(source: LightSourceView<'_>, range: TextRange) -> Option<&str> {
    source.try_ascii_slice(range)
}

fn source_decoded_string(source: LightSourceView<'_>, range: TextRange) -> String {
    source.decode_slice(range).text.into_owned()
}

fn source_decoded_cow(source: LightSourceView<'_>, range: TextRange) -> Cow<'_, str> {
    source.decode_slice(range).text
}

fn build_audit_source_store(
    source: LightSourceView<'_>,
    spans: impl IntoIterator<Item = MelSpan>,
) -> MelAuditSourceStore {
    let mut spans = spans
        .into_iter()
        .filter(|span| span.start < span.end)
        .collect::<Vec<_>>();
    spans.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));

    let mut merged = Vec::<MelSpan>::new();
    for span in spans {
        match merged.last_mut() {
            Some(active) if span.start < active.end => {
                active.end = active.end.max(span.end);
            }
            _ => merged.push(span),
        }
    }

    MelAuditSourceStore::from_decoded_fragments(merged.into_iter().map(|span| {
        let range = text_range(span.start as u32, span.end as u32);
        (span, source_decoded_string(source, range))
    }))
}

fn context_binding<'a>(
    source: LightSourceView<'a>,
    context: &'a BlockContext,
    selectors: &HashSet<RawMaNodeAttrSelector>,
) -> Option<(Cow<'a, str>, Cow<'a, str>)> {
    context.binding(source, |node_type| {
        matches!(node_type, "script" | "expression")
            || selectors
                .iter()
                .any(|selector| selector.node_type == node_type)
    })
}

fn start_create_node_block(
    source: LightSourceView<'_>,
    context: &BlockContext,
    selectors: &HashSet<RawMaNodeAttrSelector>,
) -> Option<ActiveCreateBlock> {
    let (node_type, name) = context_binding(source, context, selectors)?;
    Some(match node_type.as_ref() {
        "" => ActiveCreateBlock::Selected(ActiveSelectedNodeBlock {
            node_name: name.to_string(),
        }),
        "script" => ActiveCreateBlock::Script(ActiveScriptBlock {
            entry_index: None,
            name: name.to_string(),
            assignments: Vec::new(),
        }),
        _ => ActiveCreateBlock::ScenePath(ActiveScenePathBlock {
            node_type: node_type.to_string(),
            node_name: name.to_string(),
        }),
    })
}

fn script_attr(attr: &str) -> Option<&'static str> {
    match attr {
        ".b" | ".before" => Some(".b"),
        ".a" | ".after" => Some(".a"),
        ".st" | ".scriptType" => Some(".st"),
        ".stp" | ".sourceType" => Some(".stp"),
        _ => None,
    }
}

fn active_block_node(block: &ActiveCreateBlock) -> (&str, &str) {
    match block {
        ActiveCreateBlock::Script(script) => ("script", &script.name),
        ActiveCreateBlock::ScenePath(block) => (&block.node_type, &block.node_name),
        ActiveCreateBlock::Selected(block) => ("", &block.node_name),
    }
}

struct ParsedSetAttr {
    string_value: Option<String>,
    u32_value: Option<u32>,
    has_value: bool,
}

fn parse_setattr(source: LightSourceView<'_>, command: &LightCommandSurface) -> ParsedSetAttr {
    let mut has_attr = false;
    let mut type_name = None;
    let mut values = Vec::new();
    let mut index = 0;
    let mut valid = true;
    while let Some(word) = command.words.get(index) {
        if let LightWord::Flag { text, .. } = word {
            let flag = source_ascii_slice(source, *text).unwrap_or("");
            let Some(arity) = setattr_flag_arity(flag) else {
                valid = false;
                break;
            };
            if index + arity >= command.words.len() {
                valid = false;
                break;
            }
            if matches!(flag, "-type" | "-typ") {
                type_name = command
                    .words
                    .get(index + 1)
                    .map(|word| decoded_range_value(source, word.range()).into_owned());
            }
            index += 1 + arity;
        } else {
            if !has_attr {
                has_attr = true;
            } else {
                values.push(word.range());
            }
            index += 1;
        }
    }
    let has_value =
        !valid || type_name.is_some() || !values.is_empty() || command.opaque_tail.is_some();
    let string_value = if valid && type_name.as_deref() == Some("string") {
        let mut value_text = values
            .iter()
            .map(|range| source_decoded_cow(source, *range).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(tail) = command.opaque_tail {
            if !value_text.is_empty() {
                value_text.push(' ');
            }
            value_text.push_str(&source_decoded_cow(source, tail));
        }
        value_text.push(';');
        parse_setattr_string_value_tail(&value_text)
    } else {
        None
    };
    let u32_value = if valid && type_name.is_none() && !values.is_empty() {
        let text = source_decoded_cow(source, values[0]);
        text.parse::<u32>().ok().or_else(|| {
            let value = text.parse::<f64>().ok()?;
            (value.is_finite() && value >= 0.0 && value <= u32::MAX as f64 && value.fract() == 0.0)
                .then_some(value as u32)
        })
    } else {
        None
    };
    ParsedSetAttr {
        string_value,
        u32_value,
        has_value,
    }
}

fn flush_active_block(
    active_block: &mut Option<ActiveCreateBlock>,
    script_entries: &mut Vec<RawMaScriptEntry>,
    script_indices: &mut HashMap<String, usize>,
) {
    let Some(block) = active_block.take() else {
        return;
    };
    if let ActiveCreateBlock::Script(script) = block {
        let key = script.name.trim_start_matches(':').to_string();
        if let Some(index) = script
            .entry_index
            .or_else(|| script_indices.get(&key).copied())
        {
            script_entries[index].assignments.extend(script.assignments);
            script_entries[index]
                .assignments
                .sort_by_key(|value| value.start);
        } else {
            script_indices.insert(key.clone(), script_entries.len());
            script_entries.push(RawMaScriptEntry {
                name: key,
                assignments: script.assignments,
            });
        }
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

fn decode_range_value(source: LightSourceView<'_>, range: TextRange) -> String {
    decoded_range_value(source, range).into_owned()
}

fn decoded_range_value(source: LightSourceView<'_>, range: TextRange) -> Cow<'_, str> {
    unquoted_range_value(source_decoded_cow(source, range))
}

fn normalize_requires_command(command: &str) -> String {
    let mut text = command.split_whitespace().collect::<Vec<_>>().join(" ");
    if !text.ends_with(';') {
        text.push(';');
    }
    text
}

fn extract_reference_entry_from_selective_file_command(
    source: LightSourceView<'_>,
    file: &MayaSelectiveFile,
    command: &str,
) -> Option<ScenePathEntry> {
    let path = file
        .path_range
        .map(|range| decode_range_value(source, range))
        .filter(|value| looks_like_scene_file_path(value))
        // Long -op payloads can push the final file path outside the light parser's
        // prefix words. Keep the fast prefix path first and scan the already-decoded
        // full command only for those truncated cases.
        .or_else(|| {
            last_quoted_literal(command).filter(|value| looks_like_scene_file_path(value))
        })?;
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

fn selective_encoding_diagnostic(
    source: LightSourceView<'_>,
    encoding: MelSourceEncoding,
) -> Option<MelParseDiagnostic> {
    if !source_raw_bytes(source).iter().any(|byte| !byte.is_ascii()) {
        return None;
    }
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

fn is_structural_command_head(head: &str) -> bool {
    matches!(
        head,
        "requires"
            | "fileInfo"
            | "currentUnit"
            | "file"
            | "createNode"
            | "setAttr"
            | "addAttr"
            | "deleteAttr"
            | "rename"
            | "select"
            | "connectAttr"
            | "disconnectAttr"
            | "relationship"
            | "lockNode"
            | "parent"
            | "dataStructure"
            | "applyMetadata"
    )
}

fn command_has_execution_expression(
    source: LightSourceView<'_>,
    command: &LightCommandSurface,
) -> (bool, bool) {
    let scan_range = |range: TextRange| {
        let previous = command
            .words
            .iter()
            .map(LightWord::range)
            .chain(std::iter::once(command.head_range))
            .find(|previous| previous.end() == range.start())
            .and_then(|previous| source_decoded_cow(source, previous).chars().next_back());
        text_has_execution_expression(&source_decoded_cow(source, range), previous)
    };
    let words_executable = command.words.iter().any(|word| match word {
        LightWord::Capture { .. } => true,
        LightWord::GroupedExpr { range }
        | LightWord::BraceList { range }
        | LightWord::VectorLiteral { range } => scan_range(*range).0,
        _ => false,
    });
    let (tail_executable, unterminated) = command.opaque_tail.map_or((false, false), scan_range);
    (words_executable || tail_executable, unterminated)
}

fn text_has_execution_expression(text: &str, previous: Option<char>) -> (bool, bool) {
    let mut chars = text.chars();
    let mut quoted = false;
    let mut executable = false;
    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '\\' => {
                    chars.next();
                }
                '"' => quoted = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => quoted = true,
            '/' if chars.as_str().starts_with('/') => {
                for ch in chars.by_ref() {
                    if ch == '\n' {
                        break;
                    }
                }
            }
            '/' if chars.as_str().starts_with('*') => {
                chars.next();
                while let Some(ch) = chars.next() {
                    if ch == '*' && chars.as_str().starts_with('/') {
                        chars.next();
                        break;
                    }
                }
            }
            '\u{60}' => executable = true,
            '(' => {
                let start = text.len() - chars.as_str().len() - 1;
                let preceding = text[..start].chars().next_back().or(previous);
                if !preceding
                    .is_some_and(|ch| ch.is_alphanumeric() || matches!(ch, '_' | ']' | ')' | '}'))
                    && let Ok(consumed) = validate_string_concat_expression_prefix(&text[start..])
                {
                    chars = text[start + consumed..].chars();
                } else {
                    executable = true;
                }
            }
            _ => {}
        }
    }
    (executable, quoted)
}

fn is_audit_top_level_command_head(head: &str) -> bool {
    matches!(
        head,
        "python"
            | "eval"
            | "evalDeferred"
            | "exec"
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
    .find(|head| {
        trimmed
            .strip_prefix(head)
            .is_some_and(|rest| rest.starts_with(char::is_whitespace) || rest.starts_with('('))
    })
}

fn command_schema_has_script_flag(head: &str) -> bool {
    MAYA_COMMAND_REGISTRY.lookup(head).is_some_and(|schema| {
        schema
            .flags
            .iter()
            .any(|flag| flag.value_shapes.contains(&ValueShape::Script))
    })
}

struct ConnectionAssignmentRange {
    command: TextRange,
    value: ConnectionValueRange,
}

enum ConnectionValueRange {
    String(Vec<TextRange>),
    Unreadable,
}

#[derive(Default)]
struct SelectiveScanSink {
    connections: RawMaConnections,
    connection_attrs: HashMap<String, u32>,
    connection_history: HashMap<u64, Vec<ConnectionAssignmentRange>>,
    requires: Vec<String>,
    seen_requires: HashSet<String>,
    require_entries: Vec<RawMaRequireEntry>,
    scene_paths: Vec<ScenePathEntry>,
    seen_paths: HashSet<u64>,
    script_entries: Vec<RawMaScriptEntry>,
    script_indices: HashMap<String, usize>,
    node_attr_values: Vec<RawMaNodeAttrValue>,
    selected_node_attr_selectors: HashSet<RawMaNodeAttrSelector>,
    execution_attr_names: HashSet<String>,
    audit_items: Vec<MelAuditTopLevelItemFact>,
    audit_head_cache: HashMap<String, bool>,
    selective_diagnostics: Vec<MelParseDiagnostic>,
    active_block: Option<ActiveCreateBlock>,
    tracker: BlockTracker,
    line_tracker: LineTracker,
}

impl LightItemSink for SelectiveScanSink {
    fn on_item(&mut self, source: LightSourceView<'_>, item: LightItem) {
        let span = match &item {
            LightItem::Proc(proc_def) => proc_def.span,
            LightItem::Command(command) => command.span,
            LightItem::Other { span } => *span,
        };
        let span_start = range_start(span) as usize;
        self.line_tracker
            .advance_to(source_raw_bytes(source), span_start);
        let is_indented = self.line_tracker.is_indented();

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
                let head = source_ascii_slice(source, command.head_range);
                let structural = head.is_some_and(is_structural_command_head);
                let (expression, unterminated) = if structural {
                    command_has_execution_expression(source, &command)
                } else {
                    (false, false)
                };
                if unterminated {
                    self.selective_diagnostics.push(MelParseDiagnostic {
                        stage: MelDiagnosticStage::Parse,
                        message: Cow::Borrowed("statement reached EOF inside an unterminated string without a semicolon"),
                        span: mel_span(command.span),
                    });
                }
                let context_error = self.update_context(source, &command);
                let diagnostic_start = self.selective_diagnostics.len();
                let indented_top_level = is_indented
                    && !expression
                    && matches!(head, Some("requires" | "file" | "createNode"));
                if indented_top_level {
                    self.push_indented_top_level_diagnostic(command.span);
                }
                if head == Some("connectAttr") {
                    self.collect_connection(source, &command);
                }
                if head == Some("addAttr") {
                    self.collect_connection_aliases(source, &command);
                }
                if head == Some("setAttr") {
                    self.collect_connection_assignment(source, &command);
                    self.collect_setattr(
                        source,
                        &command,
                        !expression
                            && !unterminated
                            && self.selective_diagnostics.len() == diagnostic_start,
                        !unterminated,
                    );
                } else if let Some(item) = selective_item_from_command(source, &command, expression)
                {
                    if is_indented
                        && !expression
                        && !indented_top_level
                        && selective_item_requires_top_level_context(&item)
                    {
                        self.push_indented_top_level_diagnostic(command.span);
                    }
                    self.on_selective_item(source, item);
                }
                if (!expression || head == Some("rename"))
                    && !unterminated
                    && self.selective_diagnostics.len() == diagnostic_start
                {
                    if let Some(message) = context_error {
                        self.push_context_diagnostic(command.span, message);
                    }
                }
                if expression
                    && matches!(head, Some("requires" | "file" | "createNode" | "setAttr"))
                {
                    self.push_top_level_statement(command.span, None);
                }
            }
            LightItem::Other { span } => {
                let span_text = source_decoded_cow(source, span);
                let head = classify_top_level_other(span_text.as_ref());
                if is_indented {
                    self.push_indented_top_level_diagnostic(span);
                } else if span_text.split_whitespace().next() == Some("setAttr") {
                    self.push_context_diagnostic(
                        span,
                        "dynamic execution attribute path requires conservative audit coverage",
                    );
                }
                if span_text.split_whitespace().next() == Some("connectAttr") {
                    self.push_context_diagnostic(span, "cannot determine connectAttr destination");
                }
                self.push_top_level_statement(span, head);
            }
            _ => {}
        }
    }
}

impl SelectiveScanSink {
    fn connection_key(&mut self, id: u32, attr: &str) -> u64 {
        let next = self.connection_attrs.len() as u32;
        let attr_id = *self
            .connection_attrs
            .entry(attr.to_string())
            .or_insert(next);
        (u64::from(id) << 32) | u64::from(attr_id)
    }

    fn connection_attr_key(&mut self, id: u32, node_type: &str, owner: &str, attr: &str) -> u64 {
        let spelling = format!(".{attr}");
        if !(self.execution_attr_names.contains(attr)
            || node_type == "script" && script_attr(&spelling).is_some())
        {
            return self.connection_key(id, attr);
        }
        let canonical = self
            .selected_node_attr_selectors
            .iter()
            .filter(|selector| {
                selector.attr == spelling
                    && (selector.node_type.is_empty()
                        || selector.node_type.eq_ignore_ascii_case(node_type))
                    && selector
                        .node_name
                        .as_deref()
                        .is_none_or(|name| name == owner)
            })
            .max_by_key(|selector| (!selector.node_type.is_empty(), selector.node_name.is_some()))
            .map(|selector| selector.canonical_attr.trim_start_matches('.').to_string())
            .or_else(|| {
                (node_type == "script")
                    .then(|| {
                        script_attr(&spelling)
                            .map(|value| value.trim_start_matches('.').to_string())
                    })
                    .flatten()
            });
        self.connection_key(id, canonical.as_deref().unwrap_or(attr))
    }

    fn connection_plug(
        &mut self,
        source: LightSourceView<'_>,
        plug: &str,
    ) -> Option<RawMaConnectionPlug> {
        let (owner, attr) = plug.split_once('.')?;
        let owner = owner.trim_start_matches(':');
        let target = self.tracker.resolve(owner, source);
        let history_id = self.tracker.history_id(owner);
        let key = history_id.map(|id| {
            self.connection_attr_key(id, target.node_type.as_deref().unwrap_or(""), owner, attr)
        });
        Some(RawMaConnectionPlug {
            owner: owner.to_string(),
            attr: attr.to_string(),
            node_type: if owner.contains('|') {
                None
            } else {
                target.node_type
            },
            is_default: target.is_default
                || (plug.starts_with(':')
                    && matches!(
                        owner,
                        "creasePartition"
                            | "persp"
                            | "perspShape"
                            | "front"
                            | "frontShape"
                            | "side"
                            | "sideShape"
                            | "top"
                            | "topShape"
                    )),
            history_id,
            key,
        })
    }

    fn collect_connection(&mut self, source: LightSourceView<'_>, command: &LightCommandSurface) {
        let mut positional = Vec::new();
        let mut index = 0;
        let mut valid = command.opaque_tail.is_none();
        while let Some(word) = command.words.get(index) {
            if let LightWord::Flag { text, .. } = word {
                let flag = source_ascii_slice(source, *text)
                    .unwrap_or("")
                    .trim_start_matches('-');
                let arity = connect_attr_flag_arity(flag);
                let Some(arity) = arity else {
                    valid = false;
                    break;
                };
                if index + arity >= command.words.len() {
                    valid = false;
                    break;
                }
                if command.words[index + 1..index + 1 + arity]
                    .iter()
                    .any(|arg| static_context_word(source, command, arg).is_none())
                {
                    valid = false;
                }
                index += arity + 1;
            } else {
                if let Some(value) = static_context_word(source, command, word) {
                    positional.push(value.into_owned());
                } else {
                    valid = false;
                }
                index += 1;
            }
        }
        if !valid || positional.len() != 2 {
            self.push_context_diagnostic(command.span, "cannot determine connectAttr destination");
            return;
        }
        if !positional[0].contains('.') {
            self.push_context_diagnostic(command.span, "cannot determine connectAttr destination");
            return;
        }
        let Some(dst) = self.connection_plug(source, &positional[1]) else {
            self.push_context_diagnostic(command.span, "cannot determine connectAttr destination");
            return;
        };
        if let Some(id) = dst.history_id {
            self.connections
                .incoming
                .entry(id)
                .or_default()
                .insert(dst.attr.clone());
        } else {
            self.connections
                .unresolved_incoming
                .entry(dst.owner.clone())
                .or_default()
                .insert(dst.attr.clone());
        }
        let last = dst
            .attr
            .rsplit('.')
            .next()
            .unwrap_or(&dst.attr)
            .split('[')
            .next()
            .unwrap_or("");
        let execution_owner = self.selected_node_attr_selectors.iter().any(|selector| {
            (!selector.node_type.is_empty()
                && dst
                    .node_type
                    .as_deref()
                    .is_some_and(|node_type| selector.node_type.eq_ignore_ascii_case(node_type)))
                || selector.node_name.as_deref() == Some(dst.owner.as_str())
        });
        if !execution_owner
            && !self.execution_attr_names.contains(last)
            && script_attr(&format!(".{last}")).is_none()
            && !matches!(last, "e" | "expression" | "ixp" | "internalExpression")
        {
            return;
        }
        let Some(src) = self.connection_plug(source, &positional[0]) else {
            self.push_context_diagnostic(command.span, "cannot determine connectAttr destination");
            return;
        };
        self.connections.connections.push(RawMaConnection {
            source: src,
            destination: dst,
            start: range_start(command.span) as usize,
            end: range_end(command.span) as usize,
        });
    }

    fn collect_connection_aliases(
        &mut self,
        source: LightSourceView<'_>,
        command: &LightCommandSurface,
    ) {
        let Some(id) = self.tracker.current_history_id else {
            return;
        };
        let mut long = None;
        let mut short = None;
        for words in command.words.windows(2) {
            let flag = source_ascii_slice(source, words[0].range()).unwrap_or("");
            if matches!(flag, "-ln" | "-longName") {
                long = static_context_word(source, command, &words[1]);
            }
            if matches!(flag, "-sn" | "-shortName") {
                short = static_context_word(source, command, &words[1]);
            }
        }
        if let (Some(long), Some(short)) = (long, short) {
            if long != short {
                for attr in [long, short] {
                    let key = self.connection_key(id, &attr);
                    self.connections.ambiguous_aliases.insert(key);
                }
            }
        }
    }

    fn collect_connection_assignment(
        &mut self,
        source: LightSourceView<'_>,
        command: &LightCommandSurface,
    ) {
        let mut index = 0;
        let mut plug = None;
        let mut numeric = true;
        let mut has_value = false;
        let mut typed_string = false;
        let mut explicit_type = false;
        let mut valid = true;
        let mut value_ranges = Vec::new();
        while let Some(word) = command.words.get(index) {
            if let LightWord::Flag { text, .. } = word {
                let flag = source_ascii_slice(source, *text).unwrap_or("");
                let Some(arity) = setattr_flag_arity(flag) else {
                    numeric = false;
                    has_value = true;
                    valid = false;
                    break;
                };
                if index + arity >= command.words.len() && command.opaque_tail.is_none() {
                    valid = false;
                    numeric = false;
                    has_value = true;
                }
                if matches!(flag, "-type" | "-typ") {
                    explicit_type = true;
                    typed_string = command
                        .words
                        .get(index + 1)
                        .is_some_and(|arg| decoded_range_value(source, arg.range()) == "string");
                    if typed_string {
                        numeric = false;
                        has_value = true;
                    }
                }
                index += arity + 1;
                continue;
            }
            if plug.is_none() {
                plug = static_context_word(source, command, word);
                if plug.as_ref().is_none_or(|plug| {
                    plug.split_once('.')
                        .is_none_or(|(_, attr)| attr.contains(['.', '[']))
                }) {
                    return;
                }
            } else {
                value_ranges.push(word.range());
                has_value = true;
                numeric &= source_ascii_slice(source, word.range())
                    .is_some_and(|text| text.parse::<f64>().is_ok());
            }
            index += 1;
        }
        if let Some(tail) = command.opaque_tail {
            value_ranges.push(tail);
            has_value = true;
            numeric = false;
        }
        let Some(plug) = plug else {
            return;
        };
        let Some((owner, attr)) = plug.split_once('.') else {
            return;
        };
        let id = if owner.is_empty() {
            self.tracker.current_history_id
        } else {
            self.tracker.history_id(owner)
        };
        let Some(id) = id else {
            return;
        };
        if attr.contains(['.', '[']) {
            return;
        }
        self.connections
            .direct_assignments
            .insert(range_start(command.span) as usize, id);
        if !has_value || (numeric && !typed_string) {
            return;
        }
        let node_type = if owner.is_empty() {
            context_binding(
                source,
                &self.tracker.context,
                &self.selected_node_attr_selectors,
            )
            .map(|(node_type, _)| node_type.into_owned())
            .unwrap_or_default()
        } else {
            self.tracker
                .resolve(owner, source)
                .node_type
                .unwrap_or_default()
        };
        let key = self.connection_attr_key(id, &node_type, owner, attr);
        let quoted = !explicit_type
            && value_ranges.first().is_some_and(|range| {
                source_decoded_cow(source, *range)
                    .trim_start()
                    .starts_with('"')
            });
        let value = if valid && (typed_string || quoted) {
            ConnectionValueRange::String(value_ranges)
        } else {
            ConnectionValueRange::Unreadable
        };
        self.connection_history
            .entry(key)
            .or_default()
            .push(ConnectionAssignmentRange {
                command: command.span,
                value,
            });
    }

    fn update_context(
        &mut self,
        source: LightSourceView<'_>,
        command: &LightCommandSurface,
    ) -> Option<&'static str> {
        let head = source_ascii_slice(source, command.head_range).unwrap_or("");
        let mut error = None;
        let previous_script_index = self.active_block.as_ref().and_then(|block| match block {
            ActiveCreateBlock::Script(block) => block.entry_index,
            _ => None,
        });
        let mut created_script_index = None;
        let transition = match head {
            "createNode" => {
                let mut index = 0;
                let mut type_word = None;
                let mut name_word = None;
                let mut seen_flags = HashSet::new();
                let mut skip_select = false;
                while let Some(word) = command.words.get(index) {
                    if let LightWord::Flag { text, .. } = word {
                        let spelling = source_ascii_slice(source, *text).unwrap_or("");
                        let Some(flag) = create_node_flag(spelling) else {
                            error.get_or_insert(
                                "createNode has an unknown flag or unsupported flag arity",
                            );
                            index += 1;
                            continue;
                        };
                        if !seen_flags.insert(flag.name) && !flag.allows_multiple {
                            error.get_or_insert("createNode repeats a single-use flag");
                        }
                        let mut first_arg = None;
                        for _ in 0..flag.arity {
                            let Some(arg) = command
                                .words
                                .get(index + 1)
                                .filter(|arg| !matches!(arg, LightWord::Flag { .. }))
                            else {
                                error.get_or_insert("createNode has a missing flag argument");
                                break;
                            };
                            first_arg.get_or_insert(arg);
                            index += 1;
                            while matches!(command.words.get(index + 1),
                                Some(LightWord::GroupedExpr { range })
                                if range.start() == command.words[index].range().end())
                            {
                                index += 1;
                            }
                        }
                        if flag.name == "name" && name_word.is_none() {
                            name_word = first_arg;
                        }
                        skip_select |= flag.name == "skipSelect";
                    } else if type_word.is_none() {
                        type_word = Some(word);
                    } else if !matches!(
                        word,
                        LightWord::GroupedExpr { .. } | LightWord::Capture { .. }
                    ) {
                        error.get_or_insert("createNode has an extra positional argument");
                    }
                    index += 1;
                }
                if type_word
                    .and_then(|word| static_context_word(source, command, word))
                    .is_none()
                {
                    error.get_or_insert("createNode has no static node type or name");
                }
                if name_word
                    .and_then(|word| static_context_word(source, command, word))
                    .is_none()
                {
                    error.get_or_insert("createNode has no static node name; Maya assigns unnamed nodes automatically");
                }
                let context = match (type_word, name_word) {
                    (Some(node_type), Some(name)) if error.is_none() => BlockContext::Node {
                        node_type: ContextWord::Source(node_type.range()),
                        name: ContextWord::Source(name.range()),
                    },
                    _ => BlockContext::None,
                };
                if error.is_some() {
                    if let Some(name) =
                        name_word.and_then(|word| static_context_word(source, command, word))
                    {
                        self.tracker.invalidate_name(&name);
                    }
                }
                if skip_select && error.is_none() {
                    error = Some("createNode skipSelect requires conservative audit coverage");
                }
                BlockCommand::Create {
                    context,
                    skip_select,
                }
            }
            "select" => match selected_targets_from_command(source, command) {
                Ok(transition) => transition,
                Err(message) => {
                    error = Some(message);
                    BlockCommand::Select {
                        targets: Vec::new(),
                        accumulate: false,
                    }
                }
            },
            "rename" => {
                let names: Vec<_> = command
                    .words
                    .iter()
                    .filter(|word| !matches!(word, LightWord::Flag { .. }))
                    .collect();
                match names.as_slice() {
                    [old, new] => match (
                        static_context_word(source, command, old),
                        static_context_word(source, command, new),
                    ) {
                        (Some(old), Some(new)) => BlockCommand::Rename {
                            old: old.into_owned(),
                            new: new.into_owned(),
                        },
                        _ => {
                            error =
                                Some("dynamic rename target requires conservative audit coverage");
                            if static_context_word(source, command, old).is_none() {
                                self.tracker.invalidate_all_names();
                            }
                            for word in [old, new] {
                                if let Some(name) = static_context_word(source, command, word) {
                                    self.tracker.invalidate_name(&name);
                                }
                            }
                            BlockCommand::Preserve
                        }
                    },
                    _ => BlockCommand::Preserve,
                }
            }
            _ => BlockCommand::Preserve,
        };
        match &transition {
            BlockCommand::Rename { old, new } => {
                flush_active_block(
                    &mut self.active_block,
                    &mut self.script_entries,
                    &mut self.script_indices,
                );
                let old = old.trim_start_matches(':');
                let new = new.trim_start_matches(':');
                if old != new
                    && let Some(index) = self.script_indices.remove(old)
                    && !self.tracker.contains_name(new)
                {
                    self.script_entries[index].name = new.to_string();
                    self.script_indices.insert(new.to_string(), index);
                }
            }
            BlockCommand::Create {
                context: BlockContext::Node { name, node_type },
                skip_select,
            } => {
                flush_active_block(
                    &mut self.active_block,
                    &mut self.script_entries,
                    &mut self.script_indices,
                );
                if node_type.value(source) == "script" {
                    let name = name.value(source).trim_start_matches(':').to_string();
                    let index = self.script_entries.len();
                    self.script_entries.push(RawMaScriptEntry {
                        name: name.clone(),
                        assignments: Vec::new(),
                    });
                    self.script_indices.entry(name).or_insert(index);
                    if !skip_select {
                        created_script_index = Some(index);
                    }
                }
            }
            _ => {}
        }
        let renamed = matches!(transition, BlockCommand::Rename { .. });
        let skipped = matches!(
            transition,
            BlockCommand::Create {
                skip_select: true,
                ..
            }
        );
        let created_name = match &transition {
            BlockCommand::Create {
                context: BlockContext::Node { name, .. },
                ..
            } if !self.connections.unresolved_incoming.is_empty() => {
                Some(name.value(source).trim_start_matches(':').to_string())
            }
            _ => None,
        };
        let changed = self.tracker.on_command(transition, source);
        if let Some(name) = created_name
            && let Some(id) = self.tracker.history_id(&name)
            && let Some(attrs) = self.connections.unresolved_incoming.remove(&name)
        {
            self.connections
                .incoming
                .entry(id)
                .or_default()
                .extend(attrs);
        }
        if renamed || changed || skipped {
            if !renamed {
                flush_active_block(
                    &mut self.active_block,
                    &mut self.script_entries,
                    &mut self.script_indices,
                );
            }
            self.active_block = start_create_node_block(
                source,
                &self.tracker.context,
                &self.selected_node_attr_selectors,
            );
            if let Some(ActiveCreateBlock::Script(block)) = self.active_block.as_mut() {
                block.entry_index = if skipped || renamed {
                    previous_script_index
                } else {
                    created_script_index
                }
                .or_else(|| {
                    self.script_indices
                        .get(block.name.trim_start_matches(':'))
                        .copied()
                });
            }
        }
        debug_assert_eq!(
            context_binding(
                source,
                &self.tracker.context,
                &self.selected_node_attr_selectors
            )
            .as_ref()
            .map(|(node_type, name)| (node_type.as_ref(), name.as_ref())),
            self.active_block.as_ref().map(active_block_node)
        );
        error
    }

    fn push_context_diagnostic(&mut self, span: TextRange, message: &'static str) {
        self.selective_diagnostics.push(MelParseDiagnostic {
            stage: MelDiagnosticStage::Parse,
            message: Cow::Borrowed(message),
            span: mel_span(span),
        });
    }

    fn collect_setattr(
        &mut self,
        source: LightSourceView<'_>,
        command: &LightCommandSurface,
        check_attributes: bool,
        check_plug: bool,
    ) {
        let mut index = 0;
        let plug_word = loop {
            let Some(word) = command.words.get(index) else {
                if check_attributes {
                    self.push_context_diagnostic(command.span, "setAttr has no attribute path");
                }
                return;
            };
            if let LightWord::Flag { text, .. } = word {
                let Some(arity) =
                    setattr_flag_arity(source_ascii_slice(source, *text).unwrap_or(""))
                else {
                    return;
                };
                index += 1 + arity;
            } else {
                break word;
            }
        };
        if !matches!(
            plug_word,
            LightWord::QuotedString { .. } | LightWord::BareWord { .. }
        ) {
            if check_plug {
                self.push_context_diagnostic(
                    command.span,
                    "dynamic execution attribute path requires conservative audit coverage",
                );
            }
            return;
        }
        let plug = decoded_range_value(source, plug_word.range());
        let Some((owner, path)) = plug.split_once('.') else {
            if check_attributes {
                self.push_context_diagnostic(command.span, "setAttr has invalid attribute path");
            }
            return;
        };
        let attr = &plug[owner.len()..];
        let last = path
            .rsplit('.')
            .next()
            .unwrap_or(path)
            .split('[')
            .next()
            .unwrap_or(path);
        let matches_attr = |candidate: &str| candidate.strip_prefix('.') == Some(last);
        let any_execution = matches!(
            last,
            "b" | "before" | "a" | "after" | "st" | "scriptType" | "stp" | "sourceType"
        ) || matches!(last, "ixp" | "internalExpression" | "e" | "expression")
            || self.execution_attr_names.contains(last);
        let path_candidate = owner.is_empty()
            && matches!(self.active_block, Some(ActiveCreateBlock::ScenePath(_)))
            && ["fn", "f", "ftn", "fileTextureName", "cs"]
                .iter()
                .any(|name| last.eq_ignore_ascii_case(name));
        if !any_execution && !path_candidate {
            return;
        }
        let (node_type, node_name, is_default) = if owner.is_empty() {
            let Some((node_type, name)) = context_binding(
                source,
                &self.tracker.context,
                &self.selected_node_attr_selectors,
            ) else {
                let relevant_selection = match &self.tracker.context {
                    BlockContext::Selected { targets } => targets.iter().any(|target| {
                        if target.is_default {
                            return false;
                        }
                        match target.node_type.as_deref() {
                            None => any_execution,
                            Some("script") => matches!(
                                last,
                                "b" | "before"
                                    | "a"
                                    | "after"
                                    | "st"
                                    | "scriptType"
                                    | "stp"
                                    | "sourceType"
                            ),
                            Some("expression") => {
                                matches!(last, "e" | "expression" | "ixp" | "internalExpression")
                            }
                            Some(node_type) => {
                                self.selected_node_attr_selectors.iter().any(|selector| {
                                    matches_attr(&selector.attr)
                                        && selector.node_type.eq_ignore_ascii_case(node_type)
                                        && selector
                                            .node_name
                                            .as_deref()
                                            .is_none_or(|name| name == target.name)
                                })
                            }
                        }
                    }),
                    _ => any_execution,
                };
                if check_attributes && relevant_selection && !self.tracker.reported_unbound {
                    self.tracker.reported_unbound = true;
                    let message = if matches!(self.tracker.context, BlockContext::Selected { .. }) {
                        "selected execution attribute has unresolved node type"
                    } else {
                        "relative setAttr has no node context"
                    };
                    self.push_context_diagnostic(command.span, message);
                }
                return;
            };
            let is_default = self.tracker.resolve(&name, source).is_default;
            (
                node_type.into_owned(),
                name.trim_start_matches(':').to_string(),
                is_default,
            )
        } else {
            let target = self.tracker.resolve(owner, source);
            (
                target.node_type.unwrap_or_default(),
                target.name,
                target.is_default,
            )
        };
        let selector = self
            .selected_node_attr_selectors
            .iter()
            .filter(|selector| {
                matches_attr(&selector.attr)
                    && (selector.node_type.is_empty()
                        || selector.node_type.eq_ignore_ascii_case(&node_type))
                    && selector
                        .node_name
                        .as_deref()
                        .is_none_or(|name| name == node_name)
            })
            .max_by_key(|selector| (!selector.node_type.is_empty(), selector.node_name.is_some()));
        let typed_execution = (node_type == "script"
            && matches!(
                last,
                "b" | "before" | "a" | "after" | "st" | "scriptType" | "stp" | "sourceType"
            ))
            || (node_type == "expression"
                && matches!(last, "e" | "expression" | "ixp" | "internalExpression"))
            || selector.is_some_and(|selector| {
                !selector.node_type.is_empty() || selector.node_name.is_some()
            });
        if !path_candidate && path.contains(['.', '[']) {
            if check_attributes
                && (typed_execution || (node_type.is_empty() && !is_default && any_execution))
            {
                self.push_context_diagnostic(
                    command.span,
                    "indexed or compound execution attribute requires conservative audit coverage",
                );
            }
            return;
        }
        let canonical = if node_type == "script" {
            script_attr(attr).map(str::to_string)
        } else {
            None
        }
        .or_else(|| {
            selector
                .filter(|selector| !node_type.is_empty() || selector.node_name.is_some())
                .map(|selector| selector.canonical_attr.clone())
        });
        if node_type.is_empty() && canonical.is_none() {
            if check_attributes
                && !is_default
                && any_execution
                && (!owner.is_empty() || !self.tracker.reported_selected)
            {
                if owner.is_empty() {
                    self.tracker.reported_selected = true;
                }
                let message = if owner.is_empty() {
                    "selected execution attribute has unresolved node type"
                } else {
                    "absolute execution attribute requires conservative audit coverage"
                };
                self.push_context_diagnostic(command.span, message);
            }
            return;
        }
        let collect_path = path_candidate
            && (matches!(
                classify_scene_path_attr(attr),
                Some(ScenePathAttrKind::FileTexturePath)
            ) || (node_type == "reference" && is_reference_attr(attr)));
        if canonical.is_none() && !collect_path {
            return;
        }
        let parsed = parse_setattr(source, command);
        if !parsed.has_value {
            return;
        }
        if node_type == "script"
            && self.selected_node_attr_selectors.iter().any(|selector| {
                selector.node_type == "script"
                    && canonical.as_ref() == Some(&selector.canonical_attr)
            })
            && (parsed.string_value.is_some() || parsed.u32_value.is_some())
        {
            self.node_attr_values.push(RawMaNodeAttrValue {
                start: range_start(command.span) as usize,
                end: range_end(command.span) as usize,
                node_type: node_type.clone(),
                node_name: node_name.clone(),
                attr: canonical.clone().unwrap(),
                string_value: parsed.string_value.clone(),
                u32_value: parsed.u32_value,
            });
        }
        if node_type == "script"
            && canonical
                .as_deref()
                .is_some_and(|attr| script_attr(attr).is_some())
        {
            let canonical = canonical.unwrap();
            if check_attributes
                && command.opaque_tail.is_some()
                && parsed.string_value.is_some()
                && canonical == ".b"
            {
                self.selective_diagnostics.push(MelParseDiagnostic {
                    span: mel_span(command.span),
                    ..tracked_setattr_opaque_tail_diagnostic(".b")
                });
            }
            let assignment = RawMaScriptAssignment {
                string_value: matches!(canonical.as_str(), ".b" | ".a")
                    .then_some(parsed.string_value)
                    .flatten(),
                u32_value: matches!(canonical.as_str(), ".st" | ".stp")
                    .then_some(parsed.u32_value)
                    .flatten(),
                attr: canonical,
                start: range_start(command.span) as usize,
                end: range_end(command.span) as usize,
            };
            if let Some(ActiveCreateBlock::Script(block)) = self.active_block.as_mut() {
                if owner.is_empty()
                    || self.script_indices.get(&node_name).copied() == block.entry_index
                {
                    block.assignments.push(assignment);
                    return;
                }
            }
            if let Some(index) = self.script_indices.get(&node_name) {
                self.script_entries[*index].assignments.push(assignment);
            }
            return;
        }
        if let Some(attr) = canonical {
            self.node_attr_values.push(RawMaNodeAttrValue {
                start: range_start(command.span) as usize,
                end: range_end(command.span) as usize,
                node_type: node_type.clone(),
                node_name: node_name.clone(),
                attr,
                string_value: parsed.string_value.clone(),
                u32_value: parsed.u32_value,
            });
        }
        if let Some(value) = parsed.string_value {
            if collect_path {
                push_path_entry(
                    &mut self.scene_paths,
                    &mut self.seen_paths,
                    ScenePathEntry {
                        node_type,
                        node_name,
                        attr: attr.to_string(),
                        value,
                        meta: None,
                    },
                );
                if check_attributes && command.opaque_tail.is_some() {
                    self.selective_diagnostics.push(MelParseDiagnostic {
                        span: mel_span(command.span),
                        ..tracked_setattr_opaque_tail_diagnostic(attr)
                    });
                }
            }
        }
    }

    fn finish(
        mut self,
        source: LightSourceView<'_>,
        report: LightScanSummary,
    ) -> RawMaSelectiveSections {
        flush_active_block(
            &mut self.active_block,
            &mut self.script_entries,
            &mut self.script_indices,
        );

        let mut diagnostics = collect_report_diagnostics(&report);
        self.selective_diagnostics.retain(|candidate| {
            !diagnostics.iter().any(|earlier| {
                earlier.span.start < candidate.span.end && candidate.span.start < earlier.span.end
            })
        });
        diagnostics.extend(self.selective_diagnostics);
        let source_encoding = map_light_source_encoding(report.source_encoding);
        if let Some(diagnostic) = selective_encoding_diagnostic(source, source_encoding) {
            diagnostics.push(diagnostic);
        }
        let source_store = build_audit_source_store(
            source,
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.span)
                .chain(self.audit_items.iter().map(audit_item_source_span)),
        );

        let referenced: HashSet<_> = self
            .connections
            .connections
            .iter()
            .filter_map(|connection| connection.source.key)
            .collect();
        for (key, ranges) in self.connection_history {
            if !referenced.contains(&key) {
                continue;
            }
            let assignments = ranges
                .into_iter()
                .map(|assignment| {
                    let value = match assignment.value {
                        ConnectionValueRange::Unreadable => None,
                        ConnectionValueRange::String(ranges) => {
                            let mut tail = String::new();
                            for range in ranges {
                                if !tail.is_empty() {
                                    tail.push(' ');
                                }
                                tail.push_str(&source_decoded_cow(source, range));
                            }
                            tail.push(';');
                            parse_setattr_string_value_tail(&tail)
                        }
                    };
                    RawMaConnectionAssignment {
                        start: range_start(assignment.command) as usize,
                        end: range_end(assignment.command) as usize,
                        value,
                    }
                })
                .collect();
            self.connections.assignments.insert(key, assignments);
        }
        RawMaSelectiveSections {
            connections: self.connections,
            dump_sections: RawMaDumpSections {
                requires: self.requires,
                require_entries: self.require_entries,
                script_entries: self.script_entries,
            },
            scene_paths: self.scene_paths,
            node_attr_values: self.node_attr_values,
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

    fn push_top_level_statement(&mut self, span: TextRange, head: Option<&str>) {
        if let Some(head) = head.filter(|head| {
            (!is_structural_command_head(head) || *head == "file")
                && is_audit_top_level_command_head_cached(head, &mut self.audit_head_cache)
        }) {
            self.audit_items
                .push(MelAuditTopLevelItemFact::Command(Box::new(
                    MelAuditTopLevelCommandFact {
                        head: Arc::from(head),
                        source_span: mel_span(span),
                        span: mel_span(span),
                        schema_has_script_flag: command_schema_has_script_flag(head),
                        file_command_callback: None,
                    },
                )));
        } else {
            self.audit_items
                .push(MelAuditTopLevelItemFact::Other(MelAuditTopLevelOtherFact {
                    source_span: mel_span(span),
                    span: mel_span(span),
                }));
        }
    }

    fn on_selective_item(&mut self, source: LightSourceView<'_>, item: MayaSelectiveItem) {
        match item {
            MayaSelectiveItem::Requires(requires) => {
                let command_text = source_decoded_cow(source, requires.span);
                let normalized = normalize_requires_command(command_text.as_ref());
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
            MayaSelectiveItem::File(file) => {
                let command_text = source_decoded_string(source, file.span);
                if file_command_has_flag(&command_text, "-rfn") {
                    self.selective_diagnostics
                        .push(file_command_flag_heuristic_diagnostic("-rfn"));
                }
                if file_command_has_flag(&command_text, "-command") {
                    self.selective_diagnostics
                        .push(file_command_flag_heuristic_diagnostic("-command"));
                }
                if let Some(entry) = extract_reference_entry_from_selective_file_command(
                    source,
                    &file,
                    &command_text,
                ) {
                    push_path_entry(&mut self.scene_paths, &mut self.seen_paths, entry);
                }
                if let Some(callback) = extract_file_command_callback(&command_text) {
                    self.audit_items
                        .push(MelAuditTopLevelItemFact::Command(Box::new(
                            MelAuditTopLevelCommandFact {
                                head: Arc::from("file"),
                                source_span: mel_span(file.span),
                                span: mel_span(file.span),
                                schema_has_script_flag: false,
                                file_command_callback: Some(callback),
                            },
                        )));
                }
            }
            MayaSelectiveItem::CreateNode(_) => {}
            MayaSelectiveItem::SetAttr(_) => {}
            MayaSelectiveItem::OtherCommand { head_range, span } => {
                let head = source_ascii_slice(source, head_range);
                self.push_top_level_statement(span, head);
            }
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

fn selective_item_requires_top_level_context(item: &MayaSelectiveItem) -> bool {
    match item {
        MayaSelectiveItem::Requires(_)
        | MayaSelectiveItem::File(_)
        | MayaSelectiveItem::CreateNode(_)
        | MayaSelectiveItem::OtherCommand { .. } => true,
        MayaSelectiveItem::SetAttr(_) => false,
    }
}

fn selective_item_from_command(
    source: LightSourceView<'_>,
    command: &LightCommandSurface,
    has_execution_expression: bool,
) -> Option<MayaSelectiveItem> {
    let other = MayaSelectiveItem::OtherCommand {
        head_range: command.head_range,
        span: command.span,
    };
    let Some(head) = source_ascii_slice(source, command.head_range).filter(|head| !head.is_empty())
    else {
        return Some(other);
    };
    if !matches!(head, "requires" | "file" | "createNode" | "setAttr") && has_execution_expression {
        return Some(other);
    }
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
        "setAttr" => None,
        _ if is_structural_command_head(head) => None,
        _ => Some(other),
    }
}

fn static_context_word<'a>(
    source: LightSourceView<'a>,
    command: &LightCommandSurface,
    word: &LightWord,
) -> Option<Cow<'a, str>> {
    if matches!(
        word,
        LightWord::Capture { .. }
            | LightWord::GroupedExpr { .. }
            | LightWord::BraceList { .. }
            | LightWord::VectorLiteral { .. }
            | LightWord::Flag { .. }
    ) {
        return None;
    }
    if command.words.iter().any(|next| {
        matches!(next, LightWord::GroupedExpr { range }
        if range.start() == word.range().end())
    }) {
        return None;
    }
    let raw = source_decoded_cow(source, word.range());
    if raw.starts_with('$') {
        return None;
    }
    let value = unquoted_range_value(raw);
    (!value.is_empty()).then_some(value)
}

fn selected_targets_from_command(
    source: LightSourceView<'_>,
    command: &LightCommandSurface,
) -> Result<BlockCommand, &'static str> {
    let mut accumulate = false;
    for word in &command.words {
        if let LightWord::Flag { text, .. } = word {
            match source_ascii_slice(source, *text) {
                Some("-cl" | "-clear" | "-d" | "-deselect") => {
                    return Ok(BlockCommand::Select {
                        targets: Vec::new(),
                        accumulate: false,
                    });
                }
                Some("-add" | "-tgl" | "-toggle") => accumulate = true,
                _ => {}
            }
        }
    }
    let mut targets = Vec::new();
    for word in &command.words {
        if !matches!(word, LightWord::Flag { .. }) {
            let text = static_context_word(source, command, word)
                .ok_or("dynamic select target requires conservative audit coverage")?;
            let target = SelectedTarget::new(&text);
            if !targets
                .iter()
                .any(|previous: &SelectedTarget| previous.name == target.name)
            {
                targets.push(target);
            }
        }
    }
    Ok(BlockCommand::Select {
        targets,
        accumulate,
    })
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

fn last_non_flag_range(words: &[LightWord]) -> Option<TextRange> {
    words.iter().rev().find_map(non_flag_range)
}

fn non_flag_range(word: &LightWord) -> Option<TextRange> {
    (!matches!(word, LightWord::Flag { .. })).then_some(word.range())
}

fn extract_file_command_callback(command: &str) -> Option<String> {
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
        if !is_file_command_callback_flag(flag.as_bytes()) {
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
    let matches_flag = |flag: &str| {
        if target_flag == "-command" {
            is_file_command_callback_flag(flag.as_bytes())
        } else {
            flag == target_flag
        }
    };
    tokenize_command(command)
        .ok()
        .map(|tokens| {
            tokens
                .iter()
                .skip(1)
                .filter_map(bare_token)
                .any(matches_flag)
        })
        .unwrap_or_else(|| {
            command.contains(target_flag) || command.split_ascii_whitespace().any(matches_flag)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use encoding_rs::SHIFT_JIS;

    use super::{
        RawMaRequireKind, extract_raw_selective_sections_from_ma,
        extract_raw_selective_sections_from_ma_with_budget,
        extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors,
    };
    use crate::{
        ma::raw_dump::RawMaNodeAttrSelector,
        mel::{MelDiagnosticStage, MelParseBudget, MelSourceEncoding},
    };

    #[test]
    fn selective_nested_and_opaque_expression_regressions() {
        use crate::mel::MelAuditTopLevelItemFact;
        for padding in [String::new(), "Example ".repeat(70), "Example ".repeat(600)] {
            for (tail, executable, diagnostic) in [
                ("{\x60system \"Example\"\x60}", true, false),
                ("{system(\"Example\")}", true, false),
                ("system(\"echo Example\")", true, false),
                ("Example[0](\"Sample\")", true, false),
                ("<<1, \x60getAttr \"Example.tx\"\x60, 3>>", true, false),
                ("\"Example(1)\x60\"", false, false),
                ("(\"Example\" /* Sample */ + \"Sample\")", false, false),
                ("// \"\n\x60system \"Example\"\x60", true, false),
                ("/* \" */ \x60system \"Example\"\x60", true, false),
                ("// (\nExample", false, false),
                ("/* ( */ Example", false, false),
                ("\\\x60system \"Example\"\x60", true, false),
                ("\"Example", false, true),
            ] {
                let input = format!(
                    "connectAttr Example {padding}{tail}{}",
                    if diagnostic { "" } else { ";" }
                );
                let facts =
                    extract_raw_selective_sections_from_ma(input.as_bytes()).audit_top_level;
                assert_eq!(
                    facts
                        .items
                        .iter()
                        .any(|item| matches!(item, MelAuditTopLevelItemFact::Other(_))),
                    executable,
                    "{input}"
                );
                if !executable {
                    assert!(!facts.diagnostics.is_empty(), "{input}");
                }
            }
        }
    }

    #[test]
    fn selective_structural_expressions_preserve_dedicated_processing() {
        use crate::mel::MelAuditTopLevelItemFact;
        for head in [
            "requires",
            "fileInfo",
            "currentUnit",
            "file",
            "createNode",
            "setAttr",
            "addAttr",
            "deleteAttr",
            "rename",
            "select",
            "connectAttr",
            "disconnectAttr",
            "relationship",
            "lockNode",
            "parent",
            "dataStructure",
            "applyMetadata",
        ] {
            let input = format!("{head} Example (system(\"Example\"));");
            let facts = extract_raw_selective_sections_from_ma(input.as_bytes()).audit_top_level;
            assert!(
                facts
                    .items
                    .iter()
                    .any(|item| matches!(item, MelAuditTopLevelItemFact::Other(_))),
                "{input}"
            );
        }
        let input = "requires maya \"2026\" (system(\"Example\"));\nfile -r -command \"Example\" \"print 1\" (system(\"Example\")) \"asset/example/file.ma\";\ncreateNode script -n \"ExampleScript\" (system(\"Example\"));\n    setAttr \".b\" -type \"string\" \"print 1;\";";
        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.dump_sections.require_entries.len(), 1);
        assert_eq!(sections.scene_paths.len(), 1);
        assert_eq!(sections.dump_sections.script_entries[0].body(), "print 1;");
        assert!(sections.audit_top_level.items.iter().any(|item| matches!(item, MelAuditTopLevelItemFact::Command(command) if command.file_command_callback.is_some())));
        assert_eq!(
            sections
                .audit_top_level
                .items
                .iter()
                .filter(|item| matches!(item, MelAuditTopLevelItemFact::Other(_)))
                .count(),
            3
        );
    }

    #[test]
    fn selective_literal_arguments_and_second_statement() {
        for input in [
            "select -ne \"Example(1)\";",
            "fileInfo \"Example\" \"Sample\x60\";",
            "setAttr \".t\" <<1, 2, 3>>;",
            "setAttr \".t\" -1 -2 -3;",
            "setAttr \".m\" -type \"matrix\" 1 0 0 0 0 1 0 0 0 0 1 0 0 0 0 1;",
            "select -ne \"Example\\\"(Sample\";",
        ] {
            let facts = extract_raw_selective_sections_from_ma(input.as_bytes()).audit_top_level;
            assert!(facts.items.is_empty(), "{input}");
        }
        for head in ["rename", "connectAttr"] {
            for (expression, count) in [
                ("(\"Example\" + \"Sample\")", 0),
                ("(\"Example\" + \x60system \"Sample\"\x60)", 1),
                ("(\"Example\" + system(\"Sample\"))", 1),
            ] {
                let input = format!("{head} Example {expression};");
                let facts =
                    extract_raw_selective_sections_from_ma(input.as_bytes()).audit_top_level;
                assert_eq!(facts.items.len(), count, "{input}");
                if head == "connectAttr" {
                    assert!(!facts.diagnostics.is_empty(), "{input}");
                }
            }
        }
        let input = "select -ne \"Example\";select -ne {system(\"Example\")};";
        let facts = extract_raw_selective_sections_from_ma(input.as_bytes()).audit_top_level;
        assert_eq!(facts.items.len(), 1);
        let span = super::audit_item_source_span(&facts.items[0]);
        assert_eq!(span.start, input.find(';').unwrap() + 1);
        assert_eq!(facts.source_text(span), &input[span.start..]);
    }

    #[test]
    fn selective_unknown_statement_table_preserves_coverage_and_spans() {
        use crate::mel::MelAuditTopLevelItemFact;
        let cases = [
            ("select system(\"echo Example\");", 1, false),
            ("connectAttr python(\"x\") \"Sample.tx\";", 1, true),
            ("rename \"Example\" mm.eval(\"print 1\");", 1, false),
            ("setAttr \".tx\" \x60system \"echo Example\"\x60;", 1, false),
            (
                "createNode transform -n \"Example\";\n    connectAttr \x60system \"echo Example\"\x60 \"Example.tx\" \"Sample.tx\";",
                1,
                true,
            ),
            (
                "file -r -ns \"Example\" \x60system \"echo Example\"\x60 \"asset/example/file.ma\";",
                1,
                false,
            ),
            ("setAttr \".b\" -type \"string\" (\"a\" + \"b\");", 0, true),
            (
                "setAttr \".b\" -type \"string\" ( \"a\" + \"b\" );",
                0,
                true,
            ),
            ("system \"echo Example\";", 1, false),
            ("evalEcho \"print 1\";", 1, false),
            ("expression -s \"print 1\";", 1, false),
            ("scriptNode -bs \"print 1\" -st 1;", 1, false),
            ("sysFile -delete \"asset/example/file.ma\";", 1, false),
            ("system(\"echo Example\");", 1, false),
            ("system\n\"echo Example\";", 1, false),
            ("// Example\nsystem \"echo Example\";", 1, false),
            (";", 1, false),
            ("global string $g;", 1, false),
            ("string $s = \"x\";", 1, false),
            ("int $i = 1;", 1, false),
            ("if (1) system \"echo Example\";", 1, false),
            ("for ($i=0;$i<1;$i++) system \"echo Example\";", 1, false),
            ("while (0) system \"echo Example\";", 1, false),
            ("return;", 1, false),
            (
                "system \"echo Example\"; system \"echo Example\";",
                2,
                false,
            ),
            ("例 \"Example\";", 1, false),
            ("select -ne \x60system \"echo Example\"\x60;", 1, false),
            ("rename \"Example\" (python(\"print 1\"));", 1, true),
            (
                "connectAttr (\"Example\" + system(\"echo Example\") + \".tx\") \"Sample.tx\";",
                1,
                true,
            ),
            (
                "createNode script -n \"ExampleScript\";\n    setAttr \".st\" \x60system \"echo Example\"\x60;",
                1,
                false,
            ),
            (
                "createNode script -n \"ExampleScript\";\n    system \"echo Example\";",
                1,
                true,
            ),
            ("    system \"echo Example\";", 1, true),
            ("setAttr \".example\" -type \"string\" \"Example", 0, true),
            ("", 0, false),
            ("  \n// Example\n", 0, false),
            ("system \"Example\"", 1, false),
            ("    system(\"Example\");", 1, true),
            (
                "createNode script -n \"ExampleScript\";\n    system(\"Example\");",
                1,
                true,
            ),
            ("    string $s = \"Example\";", 1, true),
        ];
        for (input, other_count, diagnostic) in cases {
            let facts = extract_raw_selective_sections_from_ma(input.as_bytes()).audit_top_level;
            let others = facts
                .items
                .iter()
                .filter_map(|item| match item {
                    MelAuditTopLevelItemFact::Other(other) => Some(other),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(others.len(), other_count, "{input}");
            if other_count == 2 {
                assert_eq!(
                    others
                        .iter()
                        .map(|other| facts.source_text(other.source_span))
                        .collect::<Vec<_>>(),
                    ["system \"echo Example\";", "system \"echo Example\";"]
                );
            }
            assert_eq!(!facts.diagnostics.is_empty(), diagnostic, "{input}");
            for other in others {
                assert_eq!(other.span, other.source_span, "{input}");
                let original = &input[other.source_span.start..other.source_span.end];
                assert_eq!(facts.source_text(other.source_span), original, "{input}");
                assert!(!original.is_empty());
                let line = input.as_bytes()[..other.source_span.start]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count()
                    + 1;
                let expected_line = if input.starts_with("//") || input.starts_with("createNode") {
                    2
                } else {
                    1
                };
                assert_eq!(line, expected_line, "{input}");
                assert_eq!(original.ends_with(';'), input.ends_with(';'), "{input}");
            }
        }
    }

    #[test]
    fn selective_string_concat_excludes_only_literal_expressions() {
        use crate::mel::MelAuditTopLevelItemFact;
        for (expression, executable) in [
            ("( \"print 1;\" + \"print 2;\" )", false),
            ("( \"print 1;\" + \x60system \"echo Example\"\x60 )", true),
            ("( \"print 1;\" + system(\"echo Example\") )", true),
            (
                "( \"print 1;\" /* Example */ + // Example\n \"print 2;\" )",
                false,
            ),
        ] {
            for padding in [String::new(), "-keyable 1 ".repeat(16)] {
                let input = format!(
                    "createNode script -n \"ExampleScript\";\n    setAttr \".b\" -type \"string\" {padding}{expression};"
                );
                let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
                assert_eq!(
                    sections
                        .audit_top_level
                        .items
                        .iter()
                        .any(|item| matches!(item, MelAuditTopLevelItemFact::Other(_))),
                    executable,
                    "{input}"
                );
            }
        }
    }

    #[test]
    fn selective_adjacent_cp932_statements_preserve_full_text() {
        let input =
            "//Maya ASCII 2026 scene\n//Codeset: 932\nsystem \"日本語\";system \"Example\";";
        let (bytes, _, errors) = SHIFT_JIS.encode(input);
        assert!(!errors);
        let facts = extract_raw_selective_sections_from_ma(&bytes).audit_top_level;
        let texts = facts
            .items
            .iter()
            .map(|item| facts.source_text(super::audit_item_source_span(item)))
            .collect::<Vec<_>>();
        assert_eq!(texts, ["system \"日本語\";", "system \"Example\";"]);
    }

    #[test]
    fn selective_structural_heads_have_no_script_flags_except_file() {
        for head in [
            "requires",
            "fileInfo",
            "currentUnit",
            "createNode",
            "setAttr",
            "addAttr",
            "deleteAttr",
            "rename",
            "select",
            "connectAttr",
            "disconnectAttr",
            "relationship",
            "lockNode",
            "parent",
            "dataStructure",
            "applyMetadata",
        ] {
            assert!(!super::command_schema_has_script_flag(head), "{head}");
        }
    }

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
            sections.dump_sections.script_entries[0].body(),
            "print \"ok\";"
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].script_type(),
            Some(1)
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].source_type(),
            Some(1)
        );
        assert_eq!(sections.scene_paths.len(), 3);
    }

    #[test]
    fn selective_sections_capture_caller_selected_node_attrs() {
        let input = concat!(
            "createNode script -n \"ExampleScript\";\n",
            "    setAttr \".a\" -type \"string\" \"print \\\"after\\\";\";\n",
            "    setAttr \".st\" 1;\n",
            "createNode renderGlobals -n \"ExampleRenderGlobals\";\n",
            "    setAttr \".prm\" -type \"string\" \"print \\\"render\\\";\";\n",
            "createNode transform -n \"ExampleTransform\";\n",
            "    setAttr \".b\" -type \"string\" \"print \\\"ignored\\\";\";\n",
        );
        let selected = HashSet::from([
            RawMaNodeAttrSelector {
                canonical_attr: ".a".to_string(),
                node_type: "script".to_string(),
                node_name: None,
                attr: ".a".to_string(),
            },
            RawMaNodeAttrSelector {
                canonical_attr: ".st".to_string(),
                node_type: "script".to_string(),
                node_name: None,
                attr: ".st".to_string(),
            },
            RawMaNodeAttrSelector {
                canonical_attr: ".prm".to_string(),
                node_type: "renderGlobals".to_string(),
                node_name: None,
                attr: ".prm".to_string(),
            },
        ]);

        let sections = extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(
            input.as_bytes(),
            &MelParseBudget::default(),
            &selected,
        );

        assert_eq!(sections.node_attr_values.len(), 3);
        assert!(sections.node_attr_values.iter().any(|value| {
            value.node_type == "script"
                && value.node_name == "ExampleScript"
                && value.attr == ".a"
                && value.string_value.as_deref() == Some(r#"print "after";"#)
        }));
        assert!(sections.node_attr_values.iter().any(|value| {
            value.node_type == "script" && value.attr == ".st" && value.u32_value == Some(1)
        }));
        assert!(sections.node_attr_values.iter().any(|value| {
            value.node_type == "renderGlobals"
                && value.node_name == "ExampleRenderGlobals"
                && value.attr == ".prm"
                && value.string_value.as_deref() == Some(r#"print "render";"#)
        }));
    }

    #[test]
    fn selective_sections_keep_block_boundaries_on_unindented_commands() {
        let input = concat!(
            "createNode script -n \"ExampleScript\";\n",
            "rename -uid \"Example\";\n",
            "    setAttr \".b\" -type \"string\" \"print('Example');\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert_eq!(
            sections.dump_sections.script_entries[0].body(),
            "print('Example');"
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
            sections.dump_sections.script_entries[0].body(),
            "print(\"semantic fixture\")"
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].script_type(),
            Some(0)
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].source_type(),
            Some(0)
        );
    }

    #[test]
    fn short_file_callback_is_extracted_with_matching_coverage() {
        let short = extract_raw_selective_sections_from_ma(
            br#"file -r -c "Example" "print(1)" "asset/example/file.ma";"#,
        );
        let long = extract_raw_selective_sections_from_ma(
            br#"file -r -command "Example" "print(1)" "asset/example/file.ma";"#,
        );
        let callbacks = |sections: &super::RawMaSelectiveSections| {
            sections
                .audit_top_level
                .items
                .iter()
                .filter_map(|item| match item {
                    crate::mel::MelAuditTopLevelItemFact::Command(command) => {
                        command.file_command_callback.clone()
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(callbacks(&short), vec!["print(1)".to_string()]);
        assert_eq!(callbacks(&short), callbacks(&long));
        assert_eq!(
            short.audit_top_level.diagnostics,
            long.audit_top_level.diagnostics
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
    fn selective_sections_mark_schema_script_flag_top_level_commands() {
        let sections = extract_raw_selective_sections_from_ma(
            b"nodeOutliner -e -selectCommand \"eval \\\"hello\\\"\" $examplePanel;\n",
        );

        assert!(matches!(
            sections.audit_top_level.items.first(),
            Some(crate::mel::MelAuditTopLevelItemFact::Command(command))
                if command.head.as_ref() == "nodeOutliner"
                    && command.schema_has_script_flag
        ));
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
    fn selective_sections_collect_basename_file_command_reference_path() {
        let input = "file -r -rfn \"ExampleRN\" -typ \"mayaAscii\" \"ExampleScene.ma\";\n";

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());

        assert_eq!(sections.scene_paths.len(), 1);
        assert_eq!(sections.scene_paths[0].node_type, "reference");
        assert_eq!(sections.scene_paths[0].node_name, "ExampleRN");
        assert_eq!(sections.scene_paths[0].attr, ".fn");
        assert_eq!(sections.scene_paths[0].value, "ExampleScene.ma");
    }

    #[test]
    fn selective_sections_collect_file_command_reference_path_after_long_options() {
        let include_chain = (0..32)
            .map(|index| format!("asset/example/Included_{index:02}.mb("))
            .collect::<String>();
        let input = format!(
            concat!(
                "file -r -ns \"Example\" -rfn \"ExampleRN\" ",
                "-op \"VERS|2026|INCL|{include_chain}|LUNI|cm|\"\n",
                "    -typ \"mayaBinary\" \"asset/example/ExampleRig.mb\";\n",
            ),
            include_chain = include_chain,
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());

        assert_eq!(sections.scene_paths.len(), 1);
        assert_eq!(sections.scene_paths[0].node_type, "reference");
        assert_eq!(sections.scene_paths[0].node_name, "ExampleRN");
        assert_eq!(sections.scene_paths[0].attr, ".fn");
        assert_eq!(sections.scene_paths[0].value, "asset/example/ExampleRig.mb");
    }

    #[test]
    fn selective_sections_collect_indexed_reference_file_name_attrs() {
        let input = concat!(
            "createNode reference -n \"ExampleRN\";\n",
            "    setAttr \".fn[0]\" -type \"string\" \"asset/example/ExampleScene.ma\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());

        assert_eq!(sections.scene_paths.len(), 1);
        assert_eq!(sections.scene_paths[0].node_type, "reference");
        assert_eq!(sections.scene_paths[0].node_name, "ExampleRN");
        assert_eq!(sections.scene_paths[0].attr, ".fn[0]");
        assert_eq!(
            sections.scene_paths[0].value,
            "asset/example/ExampleScene.ma"
        );
    }

    #[test]
    fn selective_sections_collect_file_command_and_indexed_reference_paths() {
        let input = concat!(
            "file -r -rfn \"ExampleRN\" -typ \"mayaAscii\" \"ExampleScene.ma\";\n",
            "createNode reference -n \"NestedExampleRN\";\n",
            "    setAttr \".fn[0]\" -type \"string\" \"asset/example/NestedExampleScene.ma\";\n",
        );

        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());

        assert_eq!(sections.scene_paths.len(), 2);
        assert_eq!(sections.scene_paths[0].value, "ExampleScene.ma");
        assert_eq!(sections.scene_paths[1].attr, ".fn[0]");
        assert_eq!(
            sections.scene_paths[1].value,
            "asset/example/NestedExampleScene.ma"
        );
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
        assert_eq!(sections.dump_sections.script_entries[0].body(), body);
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
    fn selective_sections_preserve_shell_style_exec_audit_head() {
        let sections = extract_raw_selective_sections_from_ma(b"exec \"SampleTool.exe\";\n");
        assert!(matches!(
            sections.audit_top_level.items.first(),
            Some(crate::mel::MelAuditTopLevelItemFact::Command(command))
                if command.head.as_ref() == "exec"
                    && command.source_text(&sections.audit_top_level)
                        == "exec \"SampleTool.exe\";"
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
            sections.dump_sections.script_entries[0].body(),
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
        assert_eq!(sections.dump_sections.script_entries[0].body(), script_body);
        assert_eq!(
            sections.dump_sections.script_entries[0].script_type(),
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
            sections.dump_sections.script_entries[0].body(),
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
            sections.dump_sections.script_entries[0].body(),
            "print \"ok\";"
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].script_type(),
            Some(1)
        );
        assert_eq!(
            sections.dump_sections.script_entries[0].source_type(),
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
            sections.dump_sections.script_entries[0].body(),
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
        let input = non_utf8_repro_source("アウトライナ プラス").replace("//Codeset: 932\n", "");

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
            sections.dump_sections.script_entries[0].body(),
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

#[cfg(test)]
mod context_regressions {
    use super::*;

    #[test]
    fn create_node_without_static_name_leaves_context_unknown() {
        for command in ["createNode script;", "createNode script -p Sample;"] {
            let input = format!("{command} setAttr \".b\" -type \"string\" \"Example\";");
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.audit_top_level.diagnostics.len(), 2, "{command}");
            assert!(
                sections.audit_top_level.diagnostics[0]
                    .message
                    .contains("static node name")
            );
            assert_eq!(
                sections
                    .audit_top_level
                    .source_text(sections.audit_top_level.diagnostics[0].span),
                command
            );
            assert!(sections.dump_sections.script_entries.is_empty());
        }
    }

    #[test]
    fn create_node_rejects_repeated_flags_and_extra_positionals() {
        for command in [
            "createNode script -n Example -n Sample;",
            "createNode script -n Example -name Sample;",
            "createNode script -n Example -p Sample -parent Example;",
            "createNode script -n Example -ss -skipSelect;",
            "createNode script -n Example -s -shared;",
            "createNode script Sample -n Example;",
            "createNode script transform;",
        ] {
            let sections = extract_raw_selective_sections_from_ma(command.as_bytes());
            assert_eq!(sections.audit_top_level.diagnostics.len(), 1, "{command}");
            assert_eq!(
                sections
                    .audit_top_level
                    .source_text(sections.audit_top_level.diagnostics[0].span),
                command
            );
            assert!(
                sections.dump_sections.script_entries.is_empty(),
                "{command}"
            );
        }
    }

    #[test]
    fn invalid_create_node_does_not_reuse_an_earlier_type() {
        for command in [
            "createNode transform -n Example -example 1;",
            "createNode -example 1 transform -n Example;",
            "createNode transform -n Example -p;",
            "createNode transform -n Example -name Sample;",
        ] {
            let input = format!(
                "createNode script -n Example; {command} select Example; setAttr \".b\" -type \"string\" \"Sample\";"
            );
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.audit_top_level.diagnostics.len(), 2, "{command}");
            assert_eq!(
                sections.audit_top_level.diagnostics[1].message,
                "selected execution attribute has unresolved node type"
            );
            assert!(
                sections
                    .dump_sections
                    .script_entries
                    .iter()
                    .all(|entry| entry.body().is_empty())
            );
        }
    }

    #[test]
    fn create_node_flag_spellings_require_one_dash() {
        for (name, expected) in [
            ("n", 1),
            ("name", 1),
            ("p", 1),
            ("parent", 1),
            ("s", 0),
            ("shared", 0),
            ("ss", 0),
            ("skipSelect", 0),
        ] {
            assert_eq!(
                create_node_flag(&format!("-{name}")).map(|flag| flag.arity),
                Some(expected)
            );
            for prefix in ["", "--", "---"] {
                assert_eq!(
                    create_node_flag(&format!("{prefix}{name}")).map(|flag| flag.arity),
                    None
                );
            }
        }
        for command in [
            "createNode script --n Example;",
            "createNode ---name Example script;",
        ] {
            let sections = extract_raw_selective_sections_from_ma(command.as_bytes());
            assert_eq!(sections.audit_top_level.diagnostics.len(), 1);
            assert!(sections.dump_sections.script_entries.is_empty());
        }
    }

    #[test]
    fn create_node_flags_follow_schema_and_reject_ambiguous_context() {
        for (flag, expected) in [
            ("-n", 1),
            ("-name", 1),
            ("-p", 1),
            ("-parent", 1),
            ("-s", 0),
            ("-shared", 0),
            ("-ss", 0),
            ("-skipSelect", 0),
        ] {
            assert_eq!(
                create_node_flag(flag).map(|flag| flag.arity),
                Some(expected)
            );
        }
        for create in [
            "createNode -n \"Example\" script",
            "createNode script -n \"Example\"",
            "createNode \"script\" -name \"Example\"",
            "createNode -p Sample -n Example -s script",
            "createNode -shared -name Example script -parent Sample",
        ] {
            let input = format!("{create}; setAttr \".b\" -type \"string\" \"Example\";");
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            let entry = &sections.dump_sections.script_entries[0];
            assert_eq!(entry.name, "Example", "{create}");
            assert_eq!(entry.body(), "Example", "{create}");
            assert!(sections.audit_top_level.diagnostics.is_empty(), "{create}");
        }
        for parent in ["(system(\"Example\"))", "system(\"Example\")"] {
            let input = format!(
                "createNode -p {parent} -n Example script; setAttr \".b\" -type \"string\" \"Example\";"
            );
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.dump_sections.script_entries[0].body(), "Example");
            assert!(
                sections
                    .audit_top_level
                    .items
                    .iter()
                    .any(|item| matches!(item, MelAuditTopLevelItemFact::Other(_)))
            );
        }
        for flag in ["-ss", "-skipSelect"] {
            let input = format!(
                "createNode {flag} -n Example script; setAttr \".b\" -type \"string\" \"Sample\"; select Example; setAttr \".b\" -type \"string\" \"Example\";"
            );
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.audit_top_level.diagnostics.len(), 2);
            assert_eq!(
                sections.audit_top_level.diagnostics[0].message,
                "createNode skipSelect requires conservative audit coverage"
            );
            assert!(
                sections
                    .dump_sections
                    .script_entries
                    .iter()
                    .any(|entry| entry.name == "Example" && entry.body() == "Example")
            );
            assert!(
                sections
                    .audit_top_level
                    .diagnostics
                    .iter()
                    .any(|d| d.message == "relative setAttr has no node context")
            );
        }
        for create in [
            "createNode -example Sample script -n Example",
            "createNode script -n Example -parent",
            "createNode script -n Example -p -shared",
            "createNode script -n",
            "createNode $Example -n Example",
            "createNode script -n $Example",
        ] {
            let input = format!("{create}; setAttr \".b\" -type \"string\" \"Example\";");
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.audit_top_level.diagnostics.len(), 2, "{create}");
            assert!(
                sections
                    .audit_top_level
                    .diagnostics
                    .iter()
                    .any(|d| d.message.starts_with("createNode")),
                "{create}"
            );
            assert!(
                sections
                    .audit_top_level
                    .diagnostics
                    .iter()
                    .any(|d| d.message == "relative setAttr has no node context"),
                "{create}"
            );
            assert!(sections.dump_sections.script_entries.is_empty(), "{create}");
        }
        for (command, name) in [
            (
                r#"createNode script -n "Example:Sample Name";"#,
                "Example:Sample Name",
            ),
            (r#"createNode script -n ":Example";"#, "Example"),
            (
                r#"createNode script -n "Example\"Sample";"#,
                "Example\"Sample",
            ),
            (
                "createNode script\n    -n \"Example\"\n    -p Sample;",
                "Example",
            ),
        ] {
            let sections = extract_raw_selective_sections_from_ma(command.as_bytes());
            assert!(sections.audit_top_level.diagnostics.is_empty(), "{command}");
            assert_eq!(sections.dump_sections.script_entries[0].name, name);
        }
        let sections = extract_raw_selective_sections_from_ma(
            b"createNode -p Sample script -n Example -ss; select Example; setAttr \".b\" -type \"string\" \"Example\";",
        );
        assert_eq!(sections.audit_top_level.diagnostics.len(), 1);
        assert_eq!(
            sections.audit_top_level.diagnostics[0].message,
            "createNode skipSelect requires conservative audit coverage"
        );
        assert_eq!(sections.dump_sections.script_entries[0].body(), "Example");
        for command in [
            r#"createNode script -n Example("Sample");"#,
            r#"createNode script("Sample") -n Example;"#,
        ] {
            let input = format!("{command} setAttr \".b\" -type \"string\" \"Example\";");
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert!(sections.dump_sections.script_entries.is_empty());
            assert_eq!(sections.audit_top_level.diagnostics.len(), 1);
            assert_eq!(
                sections.audit_top_level.diagnostics[0].message,
                "relative setAttr has no node context"
            );
            assert_eq!(
                sections
                    .audit_top_level
                    .items
                    .iter()
                    .filter(|item| matches!(item, MelAuditTopLevelItemFact::Other(_)))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn script_body_binding_ignores_layout_and_preserving_commands() {
        for separator in [
            "\n",
            " ",
            "/**/",
            "\n// Example comment\n",
            "\nfile -r \"asset/example/file.ma\";\n",
            "\ncurrentUnit -t film;\n",
            "\nfileInfo \"Example\" \"Sample\";\n",
        ] {
            let input = format!(
                "createNode script -n \"Example\";{separator}setAttr \".b\" -type \"string\" \"print('Example')\";"
            );
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.dump_sections.script_entries[0].name, "Example");
            assert_eq!(
                sections.dump_sections.script_entries[0].body(),
                "print('Example')",
                "{separator}"
            );
        }

        let sections = extract_raw_selective_sections_from_ma(
            b"createNode script -n \"Example\"; createNode transform -n \"Sample\"; setAttr \".b\" -type \"string\" \"Example\";");
        assert_eq!(sections.dump_sections.script_entries[0].name, "Example");
        assert_eq!(sections.dump_sections.script_entries[0].body(), "");
        assert!(sections.audit_top_level.diagnostics.is_empty());
        let sections = extract_raw_selective_sections_from_ma(
            b"    requires \"Example\" \"1\";\n    file -r -command \"Example\" \"print 1\" \"asset/example/file.ma\";\n    createNode script -n \"Example\";\n    setAttr \".b\" -type \"string\" \"Example\";");
        assert_eq!(sections.dump_sections.require_entries.len(), 1);
        assert_eq!(sections.scene_paths[0].value, "asset/example/file.ma");
        assert_eq!(sections.dump_sections.script_entries[0].body(), "Example");
        assert!(sections.audit_top_level.items.iter().any(|item| matches!(item, MelAuditTopLevelItemFact::Command(command) if command.file_command_callback.is_some())));
        assert_eq!(
            sections
                .audit_top_level
                .diagnostics
                .iter()
                .filter(|d| d.message.contains("indented top-level"))
                .count(),
            3
        );
    }

    #[test]
    fn relative_attribute_diagnostics_follow_selection_intervals() {
        for input in [
            "setAttr \".tx\" 1; setAttr \".b\" -type \"string\" \"Example\";",
            "createNode;",
            "setAttr;",
            "select -ne Example; setAttr \".b\" -type \"string\" \"Example\";",
            "select -r Example; setAttr \".before\" -type \"string\" \"Example\";",
            "select -add Example; setAttr \".ixp\" -type \"string\" \"Example\";",
            "select Example; setAttr \".stp\" 1;",
        ] {
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.audit_top_level.diagnostics.len(), 1, "{input}");
            let diagnostic = &sections.audit_top_level.diagnostics[0];
            assert_eq!(diagnostic.stage, MelDiagnosticStage::Parse);
            let (statement, message) = if input.starts_with("select") {
                (
                    input.split_once("; ").unwrap().1,
                    "selected execution attribute has unresolved node type",
                )
            } else if input == "createNode;" {
                (input, "createNode has no static node type or name")
            } else if input == "setAttr;" {
                (input, "setAttr has no attribute path")
            } else {
                (
                    "setAttr \".b\" -type \"string\" \"Example\";",
                    "relative setAttr has no node context",
                )
            };
            assert_eq!(diagnostic.message, message);
            assert_eq!(
                sections.audit_top_level.source_text(diagnostic.span),
                statement
            );
        }
    }
}

#[cfg(test)]
mod resolved_context_regressions {
    use super::*;

    #[test]
    fn selected_created_nodes_resume_typed_collection() {
        for selection in [
            "-ne Example",
            "-r Example",
            "-add Example",
            "Example",
            ":Example",
        ] {
            let input = format!(
                "createNode script -n \"Example\"; select {selection}; setAttr \".b\" -type \"string\" \"print('Example')\";"
            );
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert!(
                sections
                    .dump_sections
                    .script_entries
                    .iter()
                    .any(|entry| entry.name == "Example" && entry.body() == "print('Example')"),
                "{selection}"
            );
            assert!(
                sections.audit_top_level.diagnostics.is_empty(),
                "{selection}"
            );
        }
        let selectors = HashSet::from([RawMaNodeAttrSelector {
            canonical_attr: ".ixp".into(),
            node_type: "expression".into(),
            node_name: None,
            attr: ".ixp".into(),
        }]);
        let sections = extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(
            b"createNode expression -n \"Example\"; select Example; setAttr \".ixp\" -type \"string\" \"print 1;\";",
            &MelParseBudget::default(), &selectors);
        assert_eq!(sections.node_attr_values[0].node_type, "expression");
        assert_eq!(sections.node_attr_values[0].node_name, "Example");
        assert_eq!(
            sections.node_attr_values[0].string_value.as_deref(),
            Some("print 1;")
        );
    }

    #[test]
    fn default_selection_and_static_create_arguments_preserve_coverage() {
        for input in [
            "select -ne :time1; setAttr \".st\" 1;",
            "select -r :defaultRenderGlobals; setAttr \".before\" -type \"string\" \"Example\";",
        ] {
            assert!(
                extract_raw_selective_sections_from_ma(input.as_bytes())
                    .audit_top_level
                    .diagnostics
                    .is_empty(),
                "{input}"
            );
        }
        let sections = extract_raw_selective_sections_from_ma(b"createNode script -n \"Example\" (system(\"Example\")); setAttr \".b\" -type \"string\" \"Example\";");
        assert_eq!(sections.dump_sections.script_entries[0].body(), "Example");
        assert_eq!(sections.audit_top_level.items.len(), 1);
        assert!(matches!(
            sections.audit_top_level.items[0],
            MelAuditTopLevelItemFact::Other(_)
        ));
    }

    #[test]
    fn malformed_context_and_unbound_intervals_keep_diagnostic_priority() {
        let cases = [
            (
                "setAttr \".tx\" 1; select -cl; setAttr \".ty\" 2; createNode transform -n \"Example\"; select -d Example; setAttr \".tx\" 3; setAttr \".ty\" 4;",
                0,
            ),
            (
                "createNode script -n \"Example\"; createNode $Example; setAttr \".b\" -type \"string\" \"Example\";",
                2,
            ),
            (
                "createNode script -n \"Example\"; createNode script -n $Example; setAttr \".b\" -type \"string\" \"Example\";",
                2,
            ),
            ("    createNode;", 1),
            (
                "createNode; setAttr; setAttr \".tx\" 1; setAttr \".ty\" 2;",
                2,
            ),
            ("select $Example; setAttr \".tx\" 1;", 1),
            ("select \x60system \"Example\"\x60; setAttr \".tx\" 1;", 0),
        ];
        for (input, count) in cases {
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.audit_top_level.diagnostics.len(), count, "{input}");
            for diagnostic in &sections.audit_top_level.diagnostics {
                assert_eq!(diagnostic.stage, MelDiagnosticStage::Parse);
                assert_eq!(
                    sections.audit_top_level.source_text(diagnostic.span),
                    &input[diagnostic.span.start..diagnostic.span.end]
                );
            }
            assert!(
                sections
                    .dump_sections
                    .script_entries
                    .iter()
                    .all(|entry| entry.body().is_empty()),
                "{input}"
            );
        }
        for select in [
            "select;",
            "select -cl;",
            "select -cl Example;",
            "select -d Example;",
        ] {
            assert!(
                extract_raw_selective_sections_from_ma(select.as_bytes())
                    .audit_top_level
                    .diagnostics
                    .is_empty()
            );
        }
    }
}

#[cfg(test)]
mod selection_fix_regressions {
    use super::*;

    fn body(input: &str, owner: &str) {
        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        assert!(
            sections
                .dump_sections
                .script_entries
                .iter()
                .any(|entry| entry.name == owner && entry.body() == "Example"),
            "{input}"
        );
        assert!(
            sections.audit_top_level.diagnostics.is_empty(),
            "{input}: {:?}",
            sections.audit_top_level.diagnostics
        );
    }

    fn diagnostic(input: &str, statement: &str, message: &str) {
        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        let diagnostic = sections
            .audit_top_level
            .diagnostics
            .iter()
            .find(|d| d.message == message)
            .unwrap_or_else(|| panic!("{input}: {:?}", sections.audit_top_level.diagnostics));
        assert_eq!(diagnostic.stage, MelDiagnosticStage::Parse);
        assert_eq!(
            sections.audit_top_level.source_text(diagnostic.span),
            statement
        );
    }

    #[test]
    fn setattr_flag_aliases_preserve_body() {
        for flags in [
            "-cb on",
            "-channelBox on",
            "-keyable on",
            "-lock off",
            "-size 1",
            "-capacityHint 1",
            "-caching off",
            "-alteredValue",
            "-clamp",
        ] {
            body(
                &format!(
                    "createNode script -n Example; setAttr {flags} \".b\" -type \"string\" \"Example\";"
                ),
                "Example",
            );
        }
    }

    #[test]
    fn invalid_and_deferred_attribute_paths_are_diagnosed() {
        diagnostic(
            "createNode script -n Example; setAttr on 1;",
            "setAttr on 1;",
            "setAttr has invalid attribute path",
        );
        for attr in [
            "b",
            "a",
            "st",
            "stp",
            "ixp",
            "before",
            "after",
            "scriptType",
            "sourceType",
            "internalExpression",
        ] {
            let statement = format!("setAttr \"Example.{attr}\" 1;");
            diagnostic(
                &statement,
                &statement,
                "absolute execution attribute requires conservative audit coverage",
            );
        }
        for (attr, canonical) in [
            ("before", ".b"),
            ("after", ".a"),
            ("scriptType", ".st"),
            ("sourceType", ".stp"),
        ] {
            let input = format!("createNode script -n Example; setAttr \".{attr}\" 1;");
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            let assignment = &sections.dump_sections.script_entries[0].assignments[0];
            assert_eq!(assignment.attr, canonical);
            if matches!(canonical, ".b" | ".a") {
                assert!(assignment.string_value.is_none());
            } else {
                assert_eq!(assignment.u32_value, Some(1));
            }
        }
    }

    #[test]
    fn colon_selection_requires_known_default_or_created_node() {
        body(
            "createNode script -n time1; select :time1; setAttr \".b\" -type \"string\" \"Example\";",
            "time1",
        );
        diagnostic(
            "createNode script; select :Example; setAttr \".b\" 1;",
            "setAttr \".b\" 1;",
            "selected execution attribute has unresolved node type",
        );

        diagnostic(
            "select :Example; setAttr \".b\" 1;",
            "setAttr \".b\" 1;",
            "selected execution attribute has unresolved node type",
        );
        body(
            "createNode script -n Example; select :Example; setAttr \".b\" -type \"string\" \"Example\";",
            "Example",
        );
    }

    #[test]
    fn multi_selection_and_accumulation_preserve_execution_owner() {
        for select in [
            "select Example Sample;",
            "select Example :time1;",
            "select Sample; select -add Example;",
            "select Example; select -tgl Sample;",
        ] {
            body(
                &format!(
                    "createNode script -n Example; createNode transform -n Sample; {select} setAttr \".b\" -type \"string\" \"Example\";"
                ),
                "Example",
            );
        }
        for select in [
            "select Example Unknown;",
            "select Example Sample;",
            "select Example; select -add Unknown;",
            "select Example; select -tgl Sample;",
        ] {
            diagnostic(
                &format!(
                    "createNode script -n Example; createNode expression -n Sample; {select} setAttr \".b\" 1;"
                ),
                "setAttr \".b\" 1;",
                "selected execution attribute has unresolved node type",
            );
        }
    }

    #[test]
    fn rename_and_duplicate_names_keep_first_registered_type() {
        body(
            "createNode script -n Example; createNode transform -n Sample; rename Sample TestAsset; rename Example Sample; select Sample; setAttr \".b\" -type \"string\" \"Example\";",
            "Sample",
        );
        body(
            "createNode script -n Example; rename Example Sample; setAttr \".b\" -type \"string\" \"Example\";",
            "Sample",
        );
        let sections = extract_raw_selective_sections_from_ma(b"createNode transform -n Example; createNode script -n Example; select Example; setAttr \".b\" -type \"string\" \"Example\";");
        assert_eq!(sections.dump_sections.script_entries.len(), 1);
        assert!(
            sections.dump_sections.script_entries[0]
                .assignments
                .is_empty()
        );
    }

    #[test]
    fn create_flags_resolve_type_and_skip_selection_fails_closed() {
        for create in [
            "createNode -n \"Example\" script;",
            "createNode -p \"Sample\" script -n \"Example\";",
            "createNode \"script\" -name \"Example\";",
        ] {
            body(
                &format!("{create} select Example; setAttr \".b\" -type \"string\" \"Example\";"),
                "Example",
            );
        }
        for flag in ["-ss", "-skipSelect"] {
            let statement = format!("createNode transform -n Sample {flag};");
            let input = format!(
                "createNode script -n Example; {statement} setAttr \".b\" -type \"string\" \"Example\";"
            );
            let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
            assert_eq!(sections.dump_sections.script_entries[0].body(), "Example");
            assert_eq!(sections.audit_top_level.diagnostics.len(), 1);

            diagnostic(
                &format!("createNode script -n Example; {statement}"),
                &statement,
                "createNode skipSelect requires conservative audit coverage",
            );
        }
    }

    #[test]
    fn selected_diagnostics_are_once_per_interval() {
        let input = b"setAttr \".b\" 1; select -cl Example; setAttr \".a\" 1; createNode transform -n Example; select -d Example; setAttr \".st\" 1; select Sample; select; setAttr \".b\" 2;";
        let sections = extract_raw_selective_sections_from_ma(input);
        assert_eq!(sections.audit_top_level.diagnostics.len(), 3);
        for (d, statement) in sections.audit_top_level.diagnostics.iter().zip([
            "setAttr \".b\" 1;",
            "setAttr \".st\" 1;",
            "setAttr \".b\" 2;",
        ]) {
            assert_eq!(d.stage, MelDiagnosticStage::Parse);
            assert_eq!(d.message, "relative setAttr has no node context");
            assert_eq!(sections.audit_top_level.source_text(d.span), statement);
        }
        let selectors = HashSet::from([RawMaNodeAttrSelector {
            canonical_attr: ".exampleCallback".into(),
            node_type: "ExampleType".into(),
            node_name: None,
            attr: ".exampleCallback".into(),
        }]);
        let sections = extract_raw_selective_sections_from_ma_with_budget_and_node_attr_selectors(
            b"select Example; setAttr \".exampleCallback\" -type \"string\" \"Example\";",
            &MelParseBudget::default(),
            &selectors,
        );
        let d = &sections.audit_top_level.diagnostics[0];
        assert_eq!(d.stage, MelDiagnosticStage::Parse);
        assert_eq!(
            d.message,
            "selected execution attribute has unresolved node type"
        );
        assert_eq!(
            sections.audit_top_level.source_text(d.span),
            "setAttr \".exampleCallback\" -type \"string\" \"Example\";"
        );
        let input = "select Example; setAttr \".b\" 1; setAttr \".st\" 1; select Sample; setAttr \".ixp\" 1; setAttr \".stp\" 1;";
        let sections = extract_raw_selective_sections_from_ma(input.as_bytes());
        let diagnostics = &sections.audit_top_level.diagnostics;
        assert_eq!(diagnostics.len(), 2);
        for (d, statement) in diagnostics
            .iter()
            .zip(["setAttr \".b\" 1;", "setAttr \".ixp\" 1;"])
        {
            assert_eq!(d.stage, MelDiagnosticStage::Parse);
            assert_eq!(
                d.message,
                "selected execution attribute has unresolved node type"
            );
            assert_eq!(sections.audit_top_level.source_text(d.span), statement);
        }
    }
}

#[cfg(test)]
mod standalone_ui_regression {
    use super::*;

    #[test]
    fn standalone_ui_statements_survive_retained_node_context() {
        let statements = [
            "string $example = \"Example\";",
            "string $sample = \"Sample\";",
            "string $testAsset = \"TestAsset\";",
            "formLayout -e Example;",
            "showWindow Example;",
            "string $testScene = \"TestScene\";",
            "nodeOutliner -e Example;",
            "nodeOutliner -e Sample;",
        ];
        for selection in ["select Sample;", "select :time1;", ""] {
            let input = format!(
                "createNode transform -n Example;\nrename Example Sample;\n{selection}\n{}\n    {}\n    {}\n    {}\n{}\n{}\n{}\n{}\nsetAttr \".b\" 1;",
                statements[0],
                statements[1],
                statements[2],
                statements[3],
                statements[4],
                statements[5],
                statements[6],
                statements[7]
            );
            let facts = extract_raw_selective_sections_from_ma(input.as_bytes()).audit_top_level;
            let captured: Vec<_> = facts
                .items
                .iter()
                .map(|item| facts.source_text(audit_item_source_span(item)))
                .collect();
            assert_eq!(captured, statements, "{selection}");
            assert_eq!(
                facts
                    .items
                    .iter()
                    .filter(|item| matches!(item, MelAuditTopLevelItemFact::Other(_)))
                    .count(),
                5
            );
            assert_eq!(facts.diagnostics.len(), 3);
            for (diagnostic, statement) in facts.diagnostics.iter().zip(&statements[1..4]) {
                assert_eq!(diagnostic.stage, MelDiagnosticStage::Parse);
                assert_eq!(
                    diagnostic.message,
                    "indented top-level MEL statement requires conservative audit coverage"
                );
                assert_eq!(facts.source_text(diagnostic.span), *statement);
            }
        }
    }
}
