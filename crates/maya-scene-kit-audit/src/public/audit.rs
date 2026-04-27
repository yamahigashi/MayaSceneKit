use std::path::PathBuf;

use maya_scene_kit_observe::scene::{
    core::{SceneFormat, ValidationState},
    evidence::{
        DependencyFact, ExecutionCoverageIssue, ExecutionCoverageState, ExecutionOrigin,
        ExecutionUnitSummary, SceneDigestSet, UnknownSemanticFact,
    },
    paths::ScenePathResolutionStatus,
};
use serde::{Deserialize, Serialize};

/// Audit execution options that belong to the judgment layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditOptions {
    pub profile: AuditProfile,
    pub budgets: AnalysisBudgets,
}

impl AuditOptions {
    pub fn strict_default() -> Self {
        Self {
            profile: AuditProfile::StrictDefault,
            budgets: AnalysisBudgets::default(),
        }
    }

    pub fn hardened_untrusted() -> Self {
        Self {
            profile: AuditProfile::HardenedUntrusted,
            budgets: AnalysisBudgets::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProfile {
    StrictDefault,
    HardenedUntrusted,
}

impl AuditProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictDefault => "strict_default",
            Self::HardenedUntrusted => "hardened_untrusted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisBudgets {
    pub max_dependencies: usize,
    pub max_units: usize,
}

impl Default for AnalysisBudgets {
    fn default() -> Self {
        Self {
            max_dependencies: 1024,
            max_units: 1024,
        }
    }
}

/// One rule hit produced by script auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    /// Stable finding identifier emitted by the audit engine.
    pub code: AuditFindingCode,
    /// Severity assigned to this finding.
    pub severity: AuditSeverity,
    /// Report-local surface index for provenance lookup.
    pub surface_index: usize,
    /// Sink category that matched.
    pub sink: AuditSinkKind,
    /// Rule text when the finding came from a user rule.
    pub rule: Option<String>,
    /// Human-readable finding summary.
    pub detail: AuditFindingDetail,
    /// Evidence strings captured for debugging and reporting.
    pub evidence: Vec<AuditEvidence>,
    /// Finding-specific preview when a more relevant snippet than the surface preview is known.
    pub preview_override: Option<String>,
}

/// Non-malicious review signal emitted by script auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReviewSignal {
    /// Stable review identifier emitted by the audit engine.
    pub code: AuditReviewCode,
    /// Report-local surface index for provenance lookup.
    pub surface_index: usize,
    /// Human-readable review summary.
    pub detail: AuditReviewDetail,
    /// Evidence strings captured for debugging and reporting.
    pub evidence: Vec<AuditEvidence>,
    /// Review-specific preview when a more relevant snippet than the surface preview is known.
    pub preview_override: Option<String>,
}

/// Scene-level notice emitted by audit before surface analysis could proceed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditNotice {
    /// Stable notice identifier emitted by the audit layer.
    pub code: AuditNoticeCode,
    /// Severity assigned to this notice.
    pub severity: AuditSeverity,
    /// Human-readable notice message.
    pub message: String,
}

impl AuditNotice {
    pub fn parse_budget_exceeded(limit: impl std::fmt::Display) -> Self {
        Self {
            code: AuditNoticeCode::ParseBudgetExceeded,
            severity: AuditSeverity::Info,
            message: format!("parse budget exceeded: {limit}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditFindingCode {
    CommandPort,
    CustomRuleMatch,
    MelCallbackFlag,
    MelEval,
    MelEvalDeferred,
    MelExec,
    MelParseDiagnostics,
    MelPython,
    MelScriptjob,
    ObfuscationMarkers,
    PythonBodyAssembly,
    PythonCompile,
    PythonCtypes,
    PythonEval,
    PythonImport,
    PythonParseFailure,
    PythonSubprocess,
    PythonSocket,
    PythonUnresolvedCallTarget,
    PythonExec,
    UnknownExecutionLanguage,
    UnknownExecutionTrigger,
}

impl AuditFindingCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommandPort => "command_port",
            Self::CustomRuleMatch => "custom_rule_match",
            Self::MelCallbackFlag => "mel_callback_flag",
            Self::MelEval => "mel_eval",
            Self::MelEvalDeferred => "mel_evaldeferred",
            Self::MelExec => "mel_exec",
            Self::MelParseDiagnostics => "mel_parse_diagnostics",
            Self::MelPython => "mel_python",
            Self::MelScriptjob => "mel_scriptjob",
            Self::ObfuscationMarkers => "obfuscation_markers",
            Self::PythonBodyAssembly => "python_body_assembly",
            Self::PythonCompile => "python_pycompile",
            Self::PythonCtypes => "python_ctypes",
            Self::PythonEval => "python_pyeval",
            Self::PythonImport => "python_pyimport",
            Self::PythonParseFailure => "python_parse_failure",
            Self::PythonSubprocess => "python_subprocess",
            Self::PythonSocket => "python_socket",
            Self::PythonUnresolvedCallTarget => "python_unresolved_call_target",
            Self::PythonExec => "python_pyexec",
            Self::UnknownExecutionLanguage => "unknown_execution_language",
            Self::UnknownExecutionTrigger => "unknown_execution_trigger",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReviewCode {
    MelCallbackBody,
    MelCallbackProcReference,
    MelBodyAssemblyWithoutSink,
}

impl AuditReviewCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MelCallbackBody => "mel_callback_body",
            Self::MelCallbackProcReference => "mel_callback_proc_reference",
            Self::MelBodyAssemblyWithoutSink => "mel_body_assembly_without_sink",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditNoticeCode {
    ParseBudgetExceeded,
}

impl AuditNoticeCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParseBudgetExceeded => "parse_budget_exceeded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditFindingDetail {
    Static { value: StaticAuditFindingDetail },
    SourceKindCapability { message: String },
    CustomRuleMatch,
    FreeText { message: String },
}

impl AuditFindingDetail {
    pub fn sort_key(&self) -> &str {
        match self {
            Self::Static { value } => value.message(),
            Self::SourceKindCapability { message } => message,
            Self::CustomRuleMatch => "custom audit rule matched execution surface",
            Self::FreeText { message } => message,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditReviewDetail {
    Static { value: StaticAuditReviewDetail },
    FreeText { message: String },
}

impl AuditReviewDetail {
    pub fn sort_key(&self) -> &str {
        match self {
            Self::Static { value } => value.message(),
            Self::FreeText { message } => message,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticAuditFindingDetail {
    CustomRuleMatch,
    DynamicOrAssembledEvalBodyDetected,
    DynamicOrAssembledEvalDeferredBodyDetected,
    DynamicOrAssembledMelPythonBridgeDetected,
    ExecutionSurfaceLanguageCouldNotBeInferred,
    ExecutionSurfaceTriggerCouldNotBeInferred,
    EvalFixedLiteralBodyDetected,
    EvalDeferredFixedLiteralBodyDetected,
    MelExecCommandDetected,
    MelParseDiagnosticsPresent,
    PythonBodyAssemblyMarkersDetected,
    PythonCallTargetCouldNotBeResolved,
    PythonCompileDetected,
    PythonEvalDetected,
    PythonExecDetected,
    PythonParseFailed,
    ScriptBearingMelCallbackFlagDetected,
    ScriptJobHookDetected,
    SubprocessCapabilityDetected,
    SocketCapabilityDetected,
    CommandPortOpensCommandSocket,
    CtypesCapabilityDetected,
    MelPythonLiteralBridgeNotAutoAllowed,
}

impl StaticAuditFindingDetail {
    pub fn message(self) -> &'static str {
        match self {
            Self::CustomRuleMatch => "custom audit rule matched execution surface",
            Self::DynamicOrAssembledEvalBodyDetected => "dynamic or assembled eval body detected",
            Self::DynamicOrAssembledEvalDeferredBodyDetected => {
                "dynamic or assembled evalDeferred body detected"
            }
            Self::DynamicOrAssembledMelPythonBridgeDetected => {
                "dynamic or assembled MEL -> python(...) bridge detected"
            }
            Self::ExecutionSurfaceLanguageCouldNotBeInferred => {
                "execution surface language could not be inferred"
            }
            Self::ExecutionSurfaceTriggerCouldNotBeInferred => {
                "execution surface trigger could not be inferred"
            }
            Self::EvalFixedLiteralBodyDetected => "eval fixed-literal body detected",
            Self::EvalDeferredFixedLiteralBodyDetected => {
                "evalDeferred fixed-literal body detected"
            }
            Self::MelExecCommandDetected => "MEL exec command detected",
            Self::MelParseDiagnosticsPresent => {
                "MEL parse diagnostics present; audit blocked on unresolved MEL semantics"
            }
            Self::PythonBodyAssemblyMarkersDetected => {
                "Python body-assembly / obfuscation markers detected"
            }
            Self::PythonCallTargetCouldNotBeResolved => {
                "Python call target could not be resolved without executing dynamic dispatch"
            }
            Self::PythonCompileDetected => "Python compile detected",
            Self::PythonEvalDetected => "Python eval detected",
            Self::PythonExecDetected => "Python exec detected",
            Self::PythonParseFailed => {
                "Python parse failed; audit blocked on unresolved Python semantics"
            }
            Self::ScriptBearingMelCallbackFlagDetected => {
                "script-bearing MEL callback flag detected"
            }
            Self::ScriptJobHookDetected => "scriptJob hook detected",
            Self::SubprocessCapabilityDetected => "subprocess capability detected",
            Self::SocketCapabilityDetected => "socket capability detected",
            Self::CommandPortOpensCommandSocket => "commandPort opens a command socket",
            Self::CtypesCapabilityDetected => "ctypes / native library capability detected",
            Self::MelPythonLiteralBridgeNotAutoAllowed => {
                "MEL -> python(...) fixed-literal bridge is not auto-allowed"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticAuditReviewDetail {
    MelCallbackBodyDetected,
    MelCallbackProcReferenceDetected,
    MelBodyAssemblyWithoutSinkDetected,
}

impl StaticAuditReviewDetail {
    pub fn message(self) -> &'static str {
        match self {
            Self::MelCallbackBodyDetected => {
                "MEL callback flag embeds inline script body; derived analysis determines whether it remains review-only or is denied"
            }
            Self::MelCallbackProcReferenceDetected => {
                "MEL callback flag references a proc name; offline behavior remains runtime-dependent"
            }
            Self::MelBodyAssemblyWithoutSinkDetected => {
                "assembled MEL body reconstructs code-like text in execution context without a proven execution sink"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvidence {
    FreeText {
        value: String,
    },
    KeyValue {
        key: AuditEvidenceKey,
        value: String,
    },
}

impl AuditEvidence {
    pub fn sort_key(&self) -> (&str, &str) {
        match self {
            Self::FreeText { value } => ("", value),
            Self::KeyValue { key, value } => (key.as_str(), value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvidenceKey {
    Command,
    Flag,
    CallbackTarget,
    NodeName,
}

impl AuditEvidenceKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Flag => "flag",
            Self::CallbackTarget => "callback_target",
            Self::NodeName => "node_name",
        }
    }
}

/// Report-local surface catalog used by audit findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSurface {
    /// Provenance for the triggering surface.
    pub origin: ExecutionOrigin,
    /// Short preview around the matched content.
    pub preview: String,
    /// Whether the surface was observed directly or derived by audit.
    pub derivation: AuditSurfaceDerivation,
}

/// Derivation metadata for report-local audit surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSurfaceDerivation {
    Observed,
    MelPythonLiteralBridge,
    MelCallbackLiteral,
}

impl AuditSurfaceDerivation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::MelPythonLiteralBridge => "mel_python_literal_bridge",
            Self::MelCallbackLiteral => "mel_callback_literal",
        }
    }
}

/// Aggregate report returned by script auditing operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// Source scene path.
    pub scene_path: PathBuf,
    /// Detected source scene format.
    pub scene_format: SceneFormat,
    /// Audit profile used for policy decisions.
    pub profile: AuditProfile,
    /// Integrity summary shared with other read-only APIs.
    pub validation_state: ValidationState,
    /// Effective user-supplied inline and file-backed rules.
    pub effective_rules: Vec<String>,
    /// Number of directly observed surfaces inspected before rule evaluation.
    pub surface_count: usize,
    /// Observe-owned execution coverage summary.
    pub coverage_state: ExecutionCoverageState,
    /// Observe-owned coverage issues that forced conservative blocking.
    pub coverage_issues: Vec<ExecutionCoverageIssue>,
    /// Whether the report was blocked because the input could not be fully understood.
    pub blocked_on_uncertainty: bool,
    /// Disposition chosen by the policy layer.
    pub disposition: AuditDisposition,
    /// Observe-owned unit summaries.
    pub unit_summaries: Vec<ExecutionUnitSummary>,
    /// Observe-owned dependency facts.
    pub dependency_facts: Vec<DependencyFact>,
    /// Observe-owned uncertainty facts.
    pub unknown_semantics: Vec<UnknownSemanticFact>,
    /// Stable digests describing the scene and audit environment.
    pub digests: SceneDigestSet,
    /// Scene-level notices emitted before or alongside surface analysis.
    pub notices: Vec<AuditNotice>,
    /// Report-local surface catalog.
    pub surfaces: Vec<AuditSurface>,
    /// Review-only signals emitted for the scene.
    pub review_signals: Vec<AuditReviewSignal>,
    /// Findings emitted for the scene.
    pub findings: Vec<AuditFinding>,
}

/// Aggregate report returned by recursive reference graph auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditGraphReport {
    /// Root scenes supplied by the caller.
    pub roots: Vec<AuditGraphRoot>,
    /// Unique scene audit reports produced during the graph run.
    pub reports: Vec<AuditReport>,
    /// Reference edges discovered during traversal. Duplicate edges are preserved.
    pub edges: Vec<AuditReferenceEdge>,
    /// Traversal or child-scene issues that affected the aggregate disposition.
    pub traversal_issues: Vec<AuditTraversalIssue>,
    /// Aggregate disposition across reports and traversal issues.
    pub disposition: AuditDisposition,
}

impl AuditGraphReport {
    pub fn finding_count(&self) -> usize {
        self.reports
            .iter()
            .map(AuditReport::finding_count)
            .sum::<usize>()
    }

    pub fn review_signal_count(&self) -> usize {
        self.reports
            .iter()
            .map(AuditReport::review_signal_count)
            .sum::<usize>()
    }

    pub fn notice_count(&self) -> usize {
        self.reports
            .iter()
            .map(AuditReport::notice_count)
            .sum::<usize>()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditGraphRoot {
    pub path: PathBuf,
    pub identity: Option<String>,
    pub report_index: Option<usize>,
    pub issue_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReferenceEdge {
    pub source_identity: String,
    pub source_path: PathBuf,
    pub raw_target: String,
    pub resolved_path: Option<PathBuf>,
    pub resolution_status: ScenePathResolutionStatus,
    pub target_identity: Option<String>,
    pub target_report_index: Option<usize>,
    pub issue_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTraversalIssue {
    pub kind: AuditTraversalIssueKind,
    pub scene_path: Option<PathBuf>,
    pub source_path: Option<PathBuf>,
    pub raw_target: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTraversalIssueKind {
    UnresolvedReference,
    MissingReference,
    Cycle,
    DepthLimit,
    SceneLimit,
    LoadFailed,
}

impl AuditReport {
    /// Returns the number of findings in the report.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Returns the number of review signals in the report.
    pub fn review_signal_count(&self) -> usize {
        self.review_signals.len()
    }

    /// Returns the number of top-level notices in the report.
    pub fn notice_count(&self) -> usize {
        self.notices.len()
    }

    /// Returns `true` when the report was blocked by a parse budget exceed notice.
    pub fn is_parse_budget_blocked(&self) -> bool {
        self.notices
            .iter()
            .any(|notice| notice.code == AuditNoticeCode::ParseBudgetExceeded)
    }

    /// Returns the report-local surface referenced by the finding.
    pub fn surface_for(&self, finding: &AuditFinding) -> &AuditSurface {
        &self.surfaces[finding.surface_index]
    }

    /// Returns the report-local surface referenced by the review signal.
    pub fn surface_for_review(&self, review: &AuditReviewSignal) -> &AuditSurface {
        &self.surfaces[review.surface_index]
    }

    /// Returns the effective preview for the finding, preferring any finding-specific override.
    pub fn finding_preview<'a>(&'a self, finding: &'a AuditFinding) -> &'a str {
        finding
            .preview_override
            .as_deref()
            .filter(|preview| !preview.is_empty())
            .unwrap_or_else(|| self.surface_for(finding).preview.as_str())
    }

    /// Returns the effective preview for the review signal, preferring any review-specific override.
    pub fn review_preview<'a>(&'a self, review: &'a AuditReviewSignal) -> &'a str {
        review
            .preview_override
            .as_deref()
            .filter(|preview| !preview.is_empty())
            .unwrap_or_else(|| self.surface_for_review(review).preview.as_str())
    }
}

/// Alias for a single audit finding.
pub type AuditHit = AuditFinding;

/// Alias for the script audit report returned by public APIs.
pub type ScriptAuditReport = AuditReport;

/// Severity assigned to an audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    /// Informational note.
    Info,
    /// Low confidence or low-impact signal.
    Low,
    /// Medium severity signal.
    Medium,
    /// High severity signal.
    High,
    /// Critical severity signal.
    Critical,
}

impl AuditSeverity {
    /// Returns the stable snake_case label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDisposition {
    Allow,
    AllowWithNotice,
    Review,
    DenyMalicious,
    DenyUncertain,
}

impl AuditDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowWithNotice => "allow_with_notice",
            Self::Review => "review",
            Self::DenyMalicious => "deny_malicious",
            Self::DenyUncertain => "deny_uncertain",
        }
    }
}

/// Sink category associated with an audit match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSinkKind {
    /// No concrete sink was inferred.
    None,
    /// MEL callback-bearing flag.
    MelCallbackFlag,
    /// MEL `python(...)`.
    MelPython,
    /// MEL `eval`.
    MelEval,
    /// MEL `evalDeferred`.
    MelEvalDeferred,
    /// MEL `exec`.
    MelExec,
    /// MEL `scriptJob`.
    MelScriptJob,
    /// MEL `source`.
    MelSource,
    /// MEL `commandPort`.
    MelCommandPort,
    /// MEL `loadPlugin`.
    MelLoadPlugin,
    /// Python `exec`.
    PyExec,
    /// Python `eval`.
    PyEval,
    /// Python `compile`.
    PyCompile,
    /// Python import surface.
    PyImport,
    /// Python subprocess surface.
    PySubprocess,
    /// Python socket surface.
    PySocket,
    /// Python ctypes surface.
    PyCtypes,
}

impl AuditSinkKind {
    /// Returns the stable snake_case label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MelCallbackFlag => "mel_callback_flag",
            Self::MelPython => "mel_python",
            Self::MelEval => "mel_eval",
            Self::MelEvalDeferred => "mel_eval_deferred",
            Self::MelExec => "mel_exec",
            Self::MelScriptJob => "mel_script_job",
            Self::MelSource => "mel_source",
            Self::MelCommandPort => "mel_command_port",
            Self::MelLoadPlugin => "mel_load_plugin",
            Self::PyExec => "py_exec",
            Self::PyEval => "py_eval",
            Self::PyCompile => "py_compile",
            Self::PyImport => "py_import",
            Self::PySubprocess => "py_subprocess",
            Self::PySocket => "py_socket",
            Self::PyCtypes => "py_ctypes",
        }
    }
}
