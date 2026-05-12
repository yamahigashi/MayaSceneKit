use std::{borrow::Cow, fmt, sync::Arc};

use maya_mel::{
    ast::SourceFile,
    parser::{DecodeDiagnostic, Parse, ParseBudgets, ParseError, SharedParse, SourceEncoding},
    sema::{self, DiagnosticSeverity as SemaDiagnosticSeverity},
    syntax::{LexDiagnostic, SourceMap, SourceView, TextRange, range_end, range_start},
};
use serde::{Deserialize, Serialize};

#[path = "mel_calls.rs"]
mod mel_calls;
#[path = "mel_map.rs"]
mod mel_map;
#[path = "mel_top_level.rs"]
mod mel_top_level;

pub use self::{
    mel_calls::{
        collect_call_facts, collect_call_facts_from_bytes,
        collect_call_facts_from_bytes_with_budget, collect_call_facts_shared,
        collect_call_facts_shared_with_budget, collect_call_facts_with_budget,
        collect_expression_call_facts, collect_expression_call_facts_shared_with_budget,
        collect_expression_call_facts_with_budget,
    },
    mel_top_level::{
        collect_top_level_audit_candidates_from_bytes,
        collect_top_level_audit_candidates_from_bytes_with_budget, collect_top_level_facts,
        collect_top_level_facts_from_bytes, collect_top_level_facts_from_bytes_with_budget,
        collect_top_level_facts_shared, collect_top_level_facts_shared_with_budget,
        collect_top_level_facts_with_budget,
    },
};

const DEFAULT_MAX_PARSE_BYTES: usize = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAX_NESTING_DEPTH: usize = 2048;
const DEFAULT_MAX_TOKENS: usize = 512_000_000;
const DEFAULT_MAX_STATEMENTS: usize = 4_000_000;
const DEFAULT_MAX_LITERAL_BYTES: usize = 100 * 1024 * 1024;

pub(super) trait FullParseLike {
    fn syntax(&self) -> &SourceFile;
    fn source_text(&self) -> &str;
    fn source_view(&self) -> SourceView<'_>;
    fn source_map(&self) -> &SourceMap;
    fn decode_errors(&self) -> &[DecodeDiagnostic];
    fn lex_errors(&self) -> &[LexDiagnostic];
    fn parse_errors(&self) -> &[ParseError];
}

impl FullParseLike for Parse {
    fn syntax(&self) -> &SourceFile {
        &self.syntax
    }

    fn source_text(&self) -> &str {
        &self.source_text
    }

    fn source_view(&self) -> SourceView<'_> {
        Parse::source_view(self)
    }

    fn source_map(&self) -> &SourceMap {
        &self.source_map
    }

    fn decode_errors(&self) -> &[DecodeDiagnostic] {
        &self.decode_errors
    }

    fn lex_errors(&self) -> &[LexDiagnostic] {
        &self.lex_errors
    }

    fn parse_errors(&self) -> &[ParseError] {
        &self.errors
    }
}

impl FullParseLike for SharedParse {
    fn syntax(&self) -> &SourceFile {
        &self.syntax
    }

    fn source_text(&self) -> &str {
        self.source_text.as_ref()
    }

    fn source_view(&self) -> SourceView<'_> {
        SharedParse::source_view(self)
    }

    fn source_map(&self) -> &SourceMap {
        &self.source_map
    }

    fn decode_errors(&self) -> &[DecodeDiagnostic] {
        &self.decode_errors
    }

    fn lex_errors(&self) -> &[LexDiagnostic] {
        &self.lex_errors
    }

    fn parse_errors(&self) -> &[ParseError] {
        &self.errors
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MelSpan {
    pub start: usize,
    pub end: usize,
}

impl MelSpan {
    fn from_text_range(range: TextRange) -> Self {
        Self {
            start: range_start(range) as usize,
            end: range_end(range) as usize,
        }
    }

    fn slice<'a>(&self, source: &'a str) -> &'a str {
        source.get(self.start..self.end).unwrap_or("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelDiagnosticStage {
    Decode,
    Lex,
    Parse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelSourceEncoding {
    Utf8,
    Cp932,
    Gbk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MelParseBudget {
    pub max_bytes: usize,
    pub max_nesting_depth: usize,
    pub max_tokens: usize,
    pub max_statements: usize,
    pub max_literal_bytes: usize,
}

impl Default for MelParseBudget {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_PARSE_BYTES,
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_statements: DEFAULT_MAX_STATEMENTS,
            max_literal_bytes: DEFAULT_MAX_LITERAL_BYTES,
        }
    }
}

impl MelParseBudget {
    pub fn to_parse_budgets(self) -> ParseBudgets {
        ParseBudgets {
            max_bytes: self.max_bytes,
            max_nesting_depth: self.max_nesting_depth * self.max_bytes / DEFAULT_MAX_PARSE_BYTES,
            max_tokens: self.max_tokens * self.max_bytes / DEFAULT_MAX_PARSE_BYTES,
            max_statements: self.max_statements * self.max_bytes / DEFAULT_MAX_PARSE_BYTES,
            max_literal_bytes: self.max_literal_bytes * self.max_bytes / DEFAULT_MAX_PARSE_BYTES,
        }
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelParseBudgetLimit {
    MaxBytes,
    MaxTokens,
    MaxStatements,
    MaxNestingDepth,
    MaxLiteralBytes,
}

impl MelParseBudgetLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxBytes => "max_bytes",
            Self::MaxTokens => "max_tokens",
            Self::MaxStatements => "max_statements",
            Self::MaxNestingDepth => "max_nesting_depth",
            Self::MaxLiteralBytes => "max_literal_bytes",
        }
    }
}

impl fmt::Display for MelParseBudgetLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelCallSurfaceKind {
    Function,
    ShellLike,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelNormalizedCommandKind {
    Builtin,
    Plugin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelNormalizedCommandMode {
    Create,
    Edit,
    Query,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MelValueShape {
    Bool,
    Int,
    Float,
    String,
    Script,
    StringArray,
    FloatTuple(u8),
    IntTuple(u8),
    NodeName,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelParseDiagnostic {
    pub stage: MelDiagnosticStage,
    pub message: Cow<'static, str>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelValidationDiagnostic {
    pub head: Option<Arc<str>>,
    pub message: Cow<'static, str>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelCallFact {
    pub name: Arc<str>,
    pub surface_kind: MelCallSurfaceKind,
    pub captured: bool,
    pub literal_first_arg: Option<Arc<str>>,
    pub dynamic: bool,
    pub span: MelSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MelStringAssemblyMarker {
    Concat,
    VariableReference,
}

impl MelStringAssemblyMarker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Concat => "concat",
            Self::VariableReference => "variable_reference",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MelResolvedStringKind {
    Literal,
    ProcReference,
    AssembledLiteral,
    Dynamic,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MelSinkArgKind {
    Python,
    Eval,
    EvalDeferred,
    CallbackFlag,
    ScriptJobPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSinkArgFact {
    pub sink_kind: MelSinkArgKind,
    pub resolved_kind: MelResolvedStringKind,
    pub span: MelSpan,
    pub command_name: Option<Arc<str>>,
    pub flag_name: Option<Arc<str>>,
    pub rendered_text: Option<Arc<str>>,
    pub markers: Vec<MelStringAssemblyMarker>,
    pub code_like: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelCodeLikeValueFact {
    pub resolved_kind: MelResolvedStringKind,
    pub span: MelSpan,
    pub rendered_text: Arc<str>,
    pub markers: Vec<MelStringAssemblyMarker>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelParseFacts {
    pub source_text: Arc<str>,
    pub source_encoding: MelSourceEncoding,
    pub diagnostics: Vec<MelParseDiagnostic>,
    pub validation_diagnostics: Vec<MelValidationDiagnostic>,
    pub calls: Vec<MelCallFact>,
    pub normalized_invokes: Vec<MelNormalizedInvokeFact>,
    pub sink_arg_facts: Vec<MelSinkArgFact>,
    pub code_like_value_facts: Vec<MelCodeLikeValueFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelNormalizedInvokeFact {
    pub span: MelSpan,
    pub command: MelNormalizedCommandFact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelNormalizedPositionalArg {
    pub text_span: MelSpan,
    pub literal: Option<Arc<str>>,
    pub dynamic: bool,
    pub span: MelSpan,
}

impl MelNormalizedPositionalArg {
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        self.text_span.slice(source)
    }

    pub fn preferred_text<'a>(&'a self, source: &'a str) -> &'a str {
        self.literal.as_deref().unwrap_or_else(|| self.text(source))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelNormalizedFlag {
    pub source_span: MelSpan,
    pub canonical_name: Option<Arc<str>>,
    pub value_shapes: Vec<MelValueShape>,
    pub args: Vec<MelNormalizedPositionalArg>,
    pub span: MelSpan,
}

impl MelNormalizedFlag {
    pub fn source_text<'a>(&self, source: &'a str) -> &'a str {
        self.source_span.slice(source)
    }

    pub fn matches_name(&self, source: &str, canonical: &str, short: &str) -> bool {
        self.canonical_name.as_deref() == Some(canonical) || self.source_text(source) == short
    }

    pub fn preferred_name<'a>(&'a self, source: &'a str) -> &'a str {
        self.canonical_name
            .as_deref()
            .unwrap_or_else(|| self.source_text(source))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelRawShellItemKind {
    Flag,
    Numeric,
    Bare,
    Quoted,
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelRawShellItem {
    pub source_span: MelSpan,
    pub text_span: Option<MelSpan>,
    pub kind: MelRawShellItemKind,
    pub span: MelSpan,
}

impl MelRawShellItem {
    pub fn source_text<'a>(&self, source: &'a str) -> &'a str {
        self.source_span.slice(source)
    }

    pub fn lexical_value_text<'a>(&self, source: &'a str) -> Option<&'a str> {
        let text = self.text_span?.slice(source);
        match self.kind {
            MelRawShellItemKind::Numeric | MelRawShellItemKind::Bare => Some(text),
            MelRawShellItemKind::Quoted => text
                .strip_prefix('"')
                .and_then(|text| text.strip_suffix('"')),
            MelRawShellItemKind::Flag | MelRawShellItemKind::Dynamic => None,
        }
    }

    pub fn value_text<'a>(&'a self, source: &'a str) -> Option<Cow<'a, str>> {
        let text = self.lexical_value_text(source)?;
        match self.kind {
            MelRawShellItemKind::Quoted => {
                decode_quoted_inner_text(text, QuotedDecodePolicy::ShellWord).map(Cow::Owned)
            }
            MelRawShellItemKind::Numeric | MelRawShellItemKind::Bare => Some(Cow::Borrowed(text)),
            MelRawShellItemKind::Flag | MelRawShellItemKind::Dynamic => None,
        }
    }

    pub fn preferred_text<'a>(&'a self, source: &'a str) -> Cow<'a, str> {
        self.value_text(source)
            .unwrap_or_else(|| Cow::Borrowed(self.source_text(source)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotedDecodePolicy {
    ShellWord,
    LiteralExpr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MelSpecializedCommandForm {
    Requires(MelSpecializedRequiresCommand),
    CurrentUnit(MelSpecializedCurrentUnitCommand),
    FileInfo(MelSpecializedFileInfoCommand),
    CreateNode(MelSpecializedCreateNodeCommand),
    Rename(MelSpecializedRenameCommand),
    Select(MelSpecializedSelectCommand),
    SetAttr(MelSpecializedSetAttrCommand),
    AddAttr(MelSpecializedAddAttrCommand),
    ConnectAttr(MelSpecializedConnectAttrCommand),
    Relationship(MelSpecializedRelationshipCommand),
    File(MelSpecializedFileCommand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MelSetAttrValueKind {
    TypedNumbers,
    String,
    StringArray,
    Int32Array,
    ComponentList,
    OpaqueTyped,
    MatrixXform,
    DataReferenceEdits,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedSetAttrCommand {
    pub attr_path: Option<MelRawShellItem>,
    pub type_name: Option<MelRawShellItem>,
    pub value_kind: MelSetAttrValueKind,
    pub values: Vec<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedRequiresCommand {
    pub requirements: Vec<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedCurrentUnitCommand {
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedFileInfoCommand {
    pub key: Option<MelRawShellItem>,
    pub value: Option<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedCreateNodeCommand {
    pub node_type: Option<MelRawShellItem>,
    pub name: Option<MelRawShellItem>,
    pub parent: Option<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedRenameCommand {
    pub uuid: Option<MelRawShellItem>,
    pub source: Option<MelRawShellItem>,
    pub target: Option<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedSelectCommand {
    pub targets: Vec<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedAddAttrCommand {
    pub flags: Vec<MelNormalizedFlag>,
    pub tail: Vec<MelRawShellItem>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedConnectAttrCommand {
    pub source_attr: Option<MelRawShellItem>,
    pub target_attr: Option<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedRelationshipCommand {
    pub relationship: Option<MelRawShellItem>,
    pub members: Vec<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelSpecializedFileCommand {
    pub path: Option<MelRawShellItem>,
    pub flags: Vec<MelNormalizedFlag>,
    pub span: MelSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MelNormalizedCommandItemFact {
    Flag(MelNormalizedFlag),
    Positional(MelNormalizedPositionalArg),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelNormalizedCommandFact {
    pub schema_name: Arc<str>,
    pub kind: MelNormalizedCommandKind,
    pub mode: MelNormalizedCommandMode,
    pub items: Vec<MelNormalizedCommandItemFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelTopLevelCommandFact {
    pub head: Arc<str>,
    pub captured: bool,
    pub source_span: MelSpan,
    pub raw_items: Vec<MelRawShellItem>,
    pub span: MelSpan,
    pub normalized: Option<MelNormalizedCommandFact>,
    pub specialized: Option<MelSpecializedCommandForm>,
}

impl MelTopLevelCommandFact {
    pub fn source_text<'a>(&self, source: &'a str) -> &'a str {
        self.source_span.slice(source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelTopLevelProcFact {
    pub name: Arc<str>,
    pub is_global: bool,
    pub source_span: MelSpan,
    pub span: MelSpan,
}

impl MelTopLevelProcFact {
    pub fn source_text<'a>(&self, source: &'a str) -> &'a str {
        self.source_span.slice(source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelTopLevelOtherFact {
    pub source_span: MelSpan,
    pub span: MelSpan,
}

impl MelTopLevelOtherFact {
    pub fn source_text<'a>(&self, source: &'a str) -> &'a str {
        self.source_span.slice(source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MelTopLevelItemFact {
    Command(Box<MelTopLevelCommandFact>),
    Proc(MelTopLevelProcFact),
    Other(MelTopLevelOtherFact),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelTopLevelFacts {
    pub source_text: Arc<str>,
    pub source_encoding: MelSourceEncoding,
    pub diagnostics: Vec<MelParseDiagnostic>,
    pub validation_diagnostics: Vec<MelValidationDiagnostic>,
    pub items: Vec<MelTopLevelItemFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelAuditTopLevelFacts {
    pub source_store: MelAuditSourceStore,
    pub source_encoding: MelSourceEncoding,
    pub diagnostics: Vec<MelParseDiagnostic>,
    pub items: Vec<MelAuditTopLevelItemFact>,
}

impl MelAuditTopLevelFacts {
    pub fn source_text(&self, span: MelSpan) -> &str {
        self.source_store.source_text(span)
    }

    pub fn preview_text(&self) -> Arc<str> {
        self.source_store.preview_text()
    }

    pub fn preview_span(&self, span: MelSpan) -> MelSpan {
        self.source_store.preview_span(span)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelAuditSourceStore {
    text: Arc<str>,
    fragments: Vec<MelAuditSourceFragment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MelAuditSourceFragment {
    source_span: MelSpan,
    text_span: MelSpan,
}

impl MelAuditSourceStore {
    pub fn from_relevant_spans(
        source_text: &str,
        spans: impl IntoIterator<Item = MelSpan>,
    ) -> Self {
        let mut spans = spans
            .into_iter()
            .filter(|span| span.start < span.end)
            .collect::<Vec<_>>();
        spans.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));

        let mut merged = Vec::<MelSpan>::new();
        for span in spans {
            match merged.last_mut() {
                Some(active) if span.start <= active.end => {
                    active.end = active.end.max(span.end);
                }
                _ => merged.push(span),
            }
        }

        let mut compact = String::new();
        let mut fragments = Vec::with_capacity(merged.len());
        for source_span in merged {
            let text_start = compact.len();
            compact.push_str(source_span.slice(source_text));
            let text_end = compact.len();
            fragments.push(MelAuditSourceFragment {
                source_span,
                text_span: MelSpan {
                    start: text_start,
                    end: text_end,
                },
            });
        }

        Self {
            text: Arc::from(compact),
            fragments,
        }
    }

    pub fn from_decoded_fragments(fragments: impl IntoIterator<Item = (MelSpan, String)>) -> Self {
        let mut compact = String::new();
        let mut source_fragments = Vec::new();
        for (source_span, text) in fragments {
            if source_span.start >= source_span.end {
                continue;
            }
            let text_start = compact.len();
            compact.push_str(&text);
            let text_end = compact.len();
            source_fragments.push(MelAuditSourceFragment {
                source_span,
                text_span: MelSpan {
                    start: text_start,
                    end: text_end,
                },
            });
        }

        Self {
            text: Arc::from(compact),
            fragments: source_fragments,
        }
    }

    pub fn source_text(&self, source_span: MelSpan) -> &str {
        self.remap_span_inner(source_span)
            .map(|span| span.slice(self.text.as_ref()))
            .unwrap_or("")
    }

    pub fn preview_text(&self) -> Arc<str> {
        Arc::clone(&self.text)
    }

    pub fn preview_span(&self, source_span: MelSpan) -> MelSpan {
        if source_span.start == source_span.end {
            return MelSpan { start: 0, end: 0 };
        }
        self.remap_span_inner(source_span)
            .unwrap_or(MelSpan { start: 0, end: 0 })
    }

    fn remap_span_inner(&self, source_span: MelSpan) -> Option<MelSpan> {
        let index = self
            .fragments
            .partition_point(|fragment| fragment.source_span.end <= source_span.start);
        let fragment = self.fragments.get(index)?;
        if source_span.start < fragment.source_span.start
            || source_span.end > fragment.source_span.end
        {
            return None;
        }
        if source_span == fragment.source_span {
            return Some(fragment.text_span);
        }
        if fragment.source_span.end - fragment.source_span.start
            != fragment.text_span.end - fragment.text_span.start
        {
            return None;
        }

        let start = fragment.text_span.start + (source_span.start - fragment.source_span.start);
        let end = fragment.text_span.start + (source_span.end - fragment.source_span.start);
        Some(MelSpan { start, end })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MelAuditTopLevelItemFact {
    Command(Box<MelAuditTopLevelCommandFact>),
    Proc(MelAuditTopLevelProcFact),
    Other(MelAuditTopLevelOtherFact),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelAuditTopLevelCommandFact {
    pub head: Arc<str>,
    pub source_span: MelSpan,
    pub span: MelSpan,
    pub schema_has_script_flag: bool,
    pub file_command_callback: Option<String>,
}

impl MelAuditTopLevelCommandFact {
    pub fn source_text<'a>(&self, facts: &'a MelAuditTopLevelFacts) -> &'a str {
        facts.source_text(self.source_span)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelAuditTopLevelProcFact {
    pub is_global: bool,
    pub source_span: MelSpan,
    pub span: MelSpan,
}

impl MelAuditTopLevelProcFact {
    pub fn source_text<'a>(&self, facts: &'a MelAuditTopLevelFacts) -> &'a str {
        facts.source_text(self.source_span)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MelAuditTopLevelOtherFact {
    pub source_span: MelSpan,
    pub span: MelSpan,
}

impl MelAuditTopLevelOtherFact {
    pub fn source_text<'a>(&self, facts: &'a MelAuditTopLevelFacts) -> &'a str {
        facts.source_text(self.source_span)
    }
}

pub(super) fn span_key(range: TextRange) -> (usize, usize) {
    (range_start(range) as usize, range_end(range) as usize)
}

pub(super) fn display_span(parse: &impl FullParseLike, range: TextRange) -> MelSpan {
    let display_range = parse.source_map().display_range(range);
    MelSpan {
        start: display_range.start,
        end: display_range.end,
    }
}

pub(super) fn map_source_encoding(encoding: SourceEncoding) -> MelSourceEncoding {
    match encoding {
        SourceEncoding::Utf8 => MelSourceEncoding::Utf8,
        SourceEncoding::Cp932 => MelSourceEncoding::Cp932,
        SourceEncoding::Gbk => MelSourceEncoding::Gbk,
    }
}

pub(super) fn collect_diagnostics(parse: &impl FullParseLike) -> Vec<MelParseDiagnostic> {
    let mut diagnostics = Vec::new();
    diagnostics.extend(
        parse
            .decode_errors()
            .iter()
            .map(|diagnostic| MelParseDiagnostic {
                stage: MelDiagnosticStage::Decode,
                message: diagnostic.message.clone(),
                span: MelSpan::from_text_range(diagnostic.range),
            }),
    );
    diagnostics.extend(
        parse
            .lex_errors()
            .iter()
            .map(|diagnostic| diagnostic_from_lex(MelDiagnosticStage::Lex, diagnostic)),
    );
    diagnostics.extend(
        parse
            .parse_errors()
            .iter()
            .map(|diagnostic| MelParseDiagnostic {
                stage: MelDiagnosticStage::Parse,
                message: Cow::Borrowed(diagnostic.message),
                span: MelSpan::from_text_range(diagnostic.range),
            }),
    );
    diagnostics
}

pub fn mel_parse_budget_limit_from_message(message: &str) -> Option<MelParseBudgetLimit> {
    let limit = message.strip_prefix("source exceeds parse budget: ")?;
    match limit {
        "max_bytes" => Some(MelParseBudgetLimit::MaxBytes),
        "max_tokens" => Some(MelParseBudgetLimit::MaxTokens),
        "max_statements" => Some(MelParseBudgetLimit::MaxStatements),
        "max_nesting_depth" => Some(MelParseBudgetLimit::MaxNestingDepth),
        "max_literal_bytes" => Some(MelParseBudgetLimit::MaxLiteralBytes),
        _ => None,
    }
}

pub fn mel_parse_budget_limit_from_diagnostic(
    diagnostic: &MelParseDiagnostic,
) -> Option<MelParseBudgetLimit> {
    (diagnostic.stage == MelDiagnosticStage::Parse)
        .then_some(())
        .and_then(|_| mel_parse_budget_limit_from_message(diagnostic.message.as_ref()))
}

pub fn first_mel_parse_budget_limit(
    diagnostics: &[MelParseDiagnostic],
) -> Option<MelParseBudgetLimit> {
    diagnostics
        .iter()
        .find_map(mel_parse_budget_limit_from_diagnostic)
}

fn diagnostic_from_lex(
    stage: MelDiagnosticStage,
    diagnostic: &LexDiagnostic,
) -> MelParseDiagnostic {
    MelParseDiagnostic {
        stage,
        message: Cow::Owned(diagnostic.message.to_string()),
        span: MelSpan::from_text_range(diagnostic.range),
    }
}

pub(super) fn collect_sema_validation_diagnostics(
    diagnostics: &[sema::Diagnostic],
) -> Vec<MelValidationDiagnostic> {
    diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == SemaDiagnosticSeverity::Error)
        .map(|diagnostic| MelValidationDiagnostic {
            head: None,
            message: Cow::Owned(diagnostic.message.to_string()),
            span: MelSpan::from_text_range(diagnostic.range),
        })
        .collect()
}

fn decode_quoted_text(text: &str, policy: QuotedDecodePolicy) -> Option<String> {
    let mut chars = text.chars();
    let quote = chars.next()?;
    match policy {
        QuotedDecodePolicy::ShellWord if quote != '"' => return None,
        QuotedDecodePolicy::LiteralExpr if quote != '"' && quote != '\'' => return None,
        QuotedDecodePolicy::ShellWord | QuotedDecodePolicy::LiteralExpr => {}
    }
    if !text.ends_with(quote) || text.len() < 2 {
        return None;
    }

    let mut out = String::new();
    let mut escape = false;
    for ch in text[quote.len_utf8()..text.len() - quote.len_utf8()].chars() {
        if escape {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                '\'' => out.push('\''),
                '"' => out.push('"'),
                other => match policy {
                    QuotedDecodePolicy::ShellWord => {
                        out.push('\\');
                        out.push(other);
                    }
                    QuotedDecodePolicy::LiteralExpr => out.push(other),
                },
            }
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        out.push(ch);
    }
    if escape {
        match policy {
            QuotedDecodePolicy::ShellWord => out.push('\\'),
            QuotedDecodePolicy::LiteralExpr => return None,
        }
    }
    Some(out)
}

fn decode_quoted_inner_text(text: &str, policy: QuotedDecodePolicy) -> Option<String> {
    let mut out = String::new();
    let mut escape = false;

    for ch in text.chars() {
        if escape {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                '\'' => out.push('\''),
                '"' => out.push('"'),
                other => match policy {
                    QuotedDecodePolicy::ShellWord => {
                        out.push('\\');
                        out.push(other);
                    }
                    QuotedDecodePolicy::LiteralExpr => out.push(other),
                },
            }
            escape = false;
            continue;
        }

        if ch == '\\' {
            escape = true;
            continue;
        }
        out.push(ch);
    }

    if escape {
        match policy {
            QuotedDecodePolicy::ShellWord => out.push('\\'),
            QuotedDecodePolicy::LiteralExpr => return None,
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, sync::Arc};

    use super::{
        MelAuditSourceStore, MelDiagnosticStage, MelParseBudget, MelParseBudgetLimit,
        MelParseDiagnostic, MelSpan, first_mel_parse_budget_limit,
        mel_parse_budget_limit_from_message,
    };

    #[test]
    fn default_mel_parse_budget_uses_workspace_byte_cap() {
        let budget = MelParseBudget::default();

        assert_eq!(budget.max_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(budget.max_nesting_depth, 2048);
        assert_eq!(budget.max_tokens, 512_000_000);
        assert_eq!(budget.max_statements, 4_000_000);
        assert_eq!(budget.max_literal_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn classify_all_supported_budget_messages() {
        assert_eq!(
            mel_parse_budget_limit_from_message("source exceeds parse budget: max_bytes"),
            Some(MelParseBudgetLimit::MaxBytes)
        );
        assert_eq!(
            mel_parse_budget_limit_from_message("source exceeds parse budget: max_tokens"),
            Some(MelParseBudgetLimit::MaxTokens)
        );
        assert_eq!(
            mel_parse_budget_limit_from_message("source exceeds parse budget: max_statements"),
            Some(MelParseBudgetLimit::MaxStatements)
        );
        assert_eq!(
            mel_parse_budget_limit_from_message("source exceeds parse budget: max_nesting_depth"),
            Some(MelParseBudgetLimit::MaxNestingDepth)
        );
        assert_eq!(
            mel_parse_budget_limit_from_message("source exceeds parse budget: max_literal_bytes"),
            Some(MelParseBudgetLimit::MaxLiteralBytes)
        );
    }

    #[test]
    fn first_budget_limit_ignores_non_parse_diagnostics() {
        let diagnostics = vec![
            MelParseDiagnostic {
                stage: MelDiagnosticStage::Decode,
                message: Cow::Borrowed("decode"),
                span: MelSpan { start: 0, end: 0 },
            },
            MelParseDiagnostic {
                stage: MelDiagnosticStage::Parse,
                message: Cow::Borrowed("source exceeds parse budget: max_bytes"),
                span: MelSpan { start: 0, end: 0 },
            },
        ];

        assert_eq!(
            first_mel_parse_budget_limit(&diagnostics),
            Some(MelParseBudgetLimit::MaxBytes)
        );
    }

    #[test]
    fn audit_source_store_retains_only_requested_slices() {
        let source: Arc<str> = Arc::from("alpha();\nbeta();\ngamma();\n");
        let store = MelAuditSourceStore::from_relevant_spans(
            &source,
            [MelSpan { start: 0, end: 8 }, MelSpan { start: 17, end: 26 }],
        );

        assert_eq!(store.source_text(MelSpan { start: 0, end: 8 }), "alpha();");
        assert_eq!(
            store.source_text(MelSpan { start: 17, end: 26 }),
            "gamma();\n"
        );

        let beta_preview = store.preview_span(MelSpan { start: 8, end: 16 });
        assert_eq!(beta_preview, MelSpan { start: 0, end: 0 });
        assert!(store.preview_text().len() < source.len());
    }

    #[test]
    fn audit_source_store_keeps_zero_length_preview_empty() {
        let source: Arc<str> = Arc::from("python(\"hi\");\n");
        let store =
            MelAuditSourceStore::from_relevant_spans(&source, [MelSpan { start: 0, end: 13 }]);

        assert_eq!(
            store.preview_span(MelSpan { start: 4, end: 4 }),
            MelSpan { start: 0, end: 0 }
        );
        assert_eq!(store.source_text(MelSpan { start: 4, end: 4 }), "");
    }

    #[test]
    fn audit_source_store_decoded_fragment_preserves_exact_source_span() {
        let store = MelAuditSourceStore::from_decoded_fragments([(
            MelSpan { start: 10, end: 14 },
            "sample".to_string(),
        )]);

        assert_eq!(store.source_text(MelSpan { start: 10, end: 14 }), "sample");
        assert_eq!(
            store.preview_span(MelSpan { start: 10, end: 14 }),
            MelSpan { start: 0, end: 6 }
        );
        assert_eq!(store.source_text(MelSpan { start: 11, end: 13 }), "");
    }
}
