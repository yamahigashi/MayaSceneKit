use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExecutionSourceRange {
    pub start: usize,
    pub end: usize,
}

/// Provenance for a single observed execution surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionOrigin {
    /// Language associated with the extracted surface.
    pub lang: ExecutionLanguage,
    /// Lifecycle trigger associated with the extracted surface.
    pub trigger: ExecutionTrigger,
    /// High-level surface category.
    pub surface_kind: ExecutionSurfaceKind,
    /// Script node name when the surface came from a node body.
    pub node_name: Option<String>,
    /// Attribute name when the surface came from an attribute payload.
    pub attr_name: Option<String>,
    /// Source-specific descriptor such as `scriptType=1`.
    pub source_kind: Option<String>,
    /// Source byte range when the surface maps directly to MA command text.
    pub source_range: Option<ExecutionSourceRange>,
    /// Raw chunk form when the surface came from MB payloads.
    pub chunk_form: Option<String>,
    /// Raw chunk tag when the surface came from MB payloads.
    pub chunk_tag: Option<String>,
    /// Chunk node offset when raw MB provenance is available.
    pub chunk_node_offset: Option<usize>,
    /// Raw chunk aux value when raw MB provenance is available.
    pub chunk_aux: Option<u32>,
    /// Absolute payload start offset when raw MB provenance is available.
    pub chunk_payload_offset: Option<usize>,
    /// Payload size in bytes when raw MB provenance is available.
    pub chunk_payload_size: Option<usize>,
    /// Child alignment hint used to decode the owning MB section.
    pub chunk_child_alignment: Option<usize>,
    /// Child header-size hint used to decode the owning MB section.
    pub chunk_child_header_size: Option<usize>,
}

impl ExecutionOrigin {
    pub fn without_chunk_address() -> Self {
        Self {
            lang: ExecutionLanguage::Unknown,
            trigger: ExecutionTrigger::Unknown,
            surface_kind: ExecutionSurfaceKind::RawChunkText,
            node_name: None,
            attr_name: None,
            source_kind: None,
            source_range: None,
            chunk_form: None,
            chunk_tag: None,
            chunk_node_offset: None,
            chunk_aux: None,
            chunk_payload_offset: None,
            chunk_payload_size: None,
            chunk_child_alignment: None,
            chunk_child_header_size: None,
        }
    }
}

/// Script language inferred for an observed execution surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLanguage {
    /// MEL surface.
    Mel,
    /// Python surface.
    Python,
    /// Language could not be inferred.
    Unknown,
}

impl ExecutionLanguage {
    /// Returns the stable snake_case label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mel => "mel",
            Self::Python => "python",
            Self::Unknown => "unknown",
        }
    }
}

/// Trigger associated with an observed execution surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTrigger {
    /// Trigger could not be inferred.
    Unknown,
    /// Manual invocation only.
    Manual,
    /// File open trigger.
    FileOpen,
    /// File close trigger.
    FileClose,
    /// GUI open or close trigger.
    GuiOpenClose,
    /// Render trigger.
    Render,
    /// Timeline or time-change trigger.
    TimeChanged,
    /// Generic event hook trigger.
    EventHook,
}

impl ExecutionTrigger {
    /// Returns the stable snake_case label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Manual => "manual",
            Self::FileOpen => "file_open",
            Self::FileClose => "file_close",
            Self::GuiOpenClose => "gui_open_close",
            Self::Render => "render",
            Self::TimeChanged => "time_changed",
            Self::EventHook => "event_hook",
        }
    }

    /// Returns `true` when the trigger implies automatic execution.
    pub fn is_autorun(self) -> bool {
        !matches!(self, Self::Unknown | Self::Manual)
    }
}

/// Source category used to construct an observed execution surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSurfaceKind {
    /// Script node body text.
    ScriptNodeBody,
    /// `file -command` callback text.
    FileCommandCallback,
    /// Top-level MEL command text.
    TopLevelCommand,
    /// Top-level MEL proc definition text.
    TopLevelProcDefinition,
    /// Top-level unsupported MEL statement text.
    TopLevelOtherStatement,
    /// Raw MB chunk text.
    RawChunkText,
}

impl ExecutionSurfaceKind {
    /// Returns the stable snake_case label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScriptNodeBody => "script_node_body",
            Self::FileCommandCallback => "file_command_callback",
            Self::TopLevelCommand => "top_level_command",
            Self::TopLevelProcDefinition => "top_level_proc_definition",
            Self::TopLevelOtherStatement => "top_level_other_statement",
            Self::RawChunkText => "raw_chunk_text",
        }
    }
}

/// Coverage state for execution-surface extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCoverageState {
    /// Coverage is complete enough to allow a clean audit.
    Complete,
    /// Coverage is partial and must be treated as blocked-on-uncertainty.
    Incomplete,
    /// Coverage is not supported for this input shape.
    Unsupported,
}

impl ExecutionCoverageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Stable category for a coverage issue emitted by execution-surface extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCoverageIssueKind {
    /// The file-level MEL parser reported diagnostics.
    TopLevelDiagnostics,
    /// A specific surface reported MEL diagnostics.
    SurfaceDiagnostics,
    /// Coverage for this input format is intentionally conservative.
    UnsupportedCoverage,
}

impl ExecutionCoverageIssueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TopLevelDiagnostics => "top_level_diagnostics",
            Self::SurfaceDiagnostics => "surface_diagnostics",
            Self::UnsupportedCoverage => "unsupported_coverage",
        }
    }
}

/// A fact describing why execution-surface coverage is incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCoverageIssue {
    pub kind: ExecutionCoverageIssueKind,
    pub detail: ExecutionCoverageIssueDetail,
    pub origin: Option<ExecutionOrigin>,
    pub preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecutionCoverageIssueDetail {
    TopLevelDiagnostics { diagnostic: String },
    SurfaceDiagnostics { diagnostic: String },
    UnsupportedProcDefinition { is_global: bool },
    UnsupportedTopLevelStatement,
}

/// Unit-level effect summary derived from an observed execution unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEffectClass {
    PureComputation,
    DiagnosticOutput,
    SceneReadOnly,
    SceneMutation,
    UIImpact,
    HookRegistration,
    ExternalDependency,
    DynamicEvaluation,
    Unknown,
}

impl ExecutionEffectClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PureComputation => "pure_computation",
            Self::DiagnosticOutput => "diagnostic_output",
            Self::SceneReadOnly => "scene_read_only",
            Self::SceneMutation => "scene_mutation",
            Self::UIImpact => "ui_impact",
            Self::HookRegistration => "hook_registration",
            Self::ExternalDependency => "external_dependency",
            Self::DynamicEvaluation => "dynamic_evaluation",
            Self::Unknown => "unknown",
        }
    }
}

/// Confidence assigned to an effect summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectCertainty {
    Proven,
    Uncertain,
}

impl EffectCertainty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Uncertain => "uncertain",
        }
    }
}

/// Additional semantic subtype used when broad effect classes are too coarse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSemanticClass {
    General,
    OperationalConfigWrite,
    SceneDataWrite,
    ScriptBearingWrite,
    DependencyWrite,
    UnknownWrite,
}

impl ExecutionSemanticClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::OperationalConfigWrite => "operational_config_write",
            Self::SceneDataWrite => "scene_data_write",
            Self::ScriptBearingWrite => "script_bearing_write",
            Self::DependencyWrite => "dependency_write",
            Self::UnknownWrite => "unknown_write",
        }
    }
}

/// Summary of a single execution unit observed from a scene.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionUnitSummary {
    pub origin: ExecutionOrigin,
    pub effect: ExecutionEffectClass,
    pub semantic_class: ExecutionSemanticClass,
    pub certainty: EffectCertainty,
    pub preview: String,
    pub reasons: Vec<ExecutionReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticExecutionReason {
    SurfaceLanguageUnknown,
    NormalizedMelFactsUnavailable,
    MelDiagnosticsPreventProvenEffectSummary,
    NoMelCommandInvocationDetected,
    ExecutionUnitBodyEmpty,
    DiagnosticMelOutputDetected,
    PythonParseFailurePreventsProvenEffectSummary,
    PythonRaiseDetected,
    UnresolvedPythonCallTargetDetected,
    PythonUnitEmpty,
    NoSideEffectingPythonConstructsDetected,
    PythonPrintDetected,
    ReadOnlyMelOptionVarQueryDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionReasonTemplate {
    DynamicMelCommandDetected,
    HookLikeMelCommandDetected,
    ExternalDependencyMelCommandDetected,
    SceneMutatingMelCommandDetected,
    UiImpactingMelCommandDetected,
    ReadOnlyMelCommandDetected,
    UnclassifiedMelCommandDetected,
    DynamicPythonCallDetected,
    ExternalPythonCapabilityDetected,
    UnclassifiedPythonCallDetected,
    PythonImportDetected,
    PythonImportFromDetected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecutionReason {
    Static {
        value: StaticExecutionReason,
    },
    Named {
        template: ExecutionReasonTemplate,
        value: String,
    },
    FlagOnCommand {
        flag_name: String,
        command_name: String,
    },
}

/// Risk bucket assigned to a reported dependency fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRiskClass {
    Informational,
    Review,
    Uncertain,
}

impl DependencyRiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Review => "review",
            Self::Uncertain => "uncertain",
        }
    }
}

/// High-level dependency category observed from a scene.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyFactKind {
    Require,
    ReferencePath,
    FilePath,
    SourceCommand,
    LoadPluginCommand,
    FileCommandCallback,
}

impl DependencyFactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Require => "require",
            Self::ReferencePath => "reference_path",
            Self::FilePath => "file_path",
            Self::SourceCommand => "source_command",
            Self::LoadPluginCommand => "load_plugin_command",
            Self::FileCommandCallback => "file_command_callback",
        }
    }
}

/// Report-only dependency evidence discovered from a scene.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyFact {
    pub kind: DependencyFactKind,
    pub risk: DependencyRiskClass,
    pub target: String,
    pub detail: DependencyFactDetail,
    pub origin: Option<ExecutionOrigin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DependencyFactDetail {
    Require,
    ScenePath { node_type: String, attr: String },
    MelDependencyObserved { command_name: String },
    FileCommandCallbackObserved,
}

/// Observe-owned uncertainty detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownSemanticFact {
    pub origin: ExecutionOrigin,
    pub detail: UnknownSemanticDetail,
    pub preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnknownSemanticDetail {
    PrimaryReason { reason: ExecutionReason },
    GenericUncertain,
}

/// Stable digests describing the observed scene and audit environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SceneDigestSet {
    pub scene_sha256: String,
    pub schema_bundle_sha256: Option<String>,
    pub policy_bundle_sha256: Option<String>,
}
