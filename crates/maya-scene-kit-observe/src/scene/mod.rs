pub(crate) mod analyze;
mod context;
pub(crate) mod decode;
mod error;
mod integrity;
pub(crate) mod ir;
mod mb_extract;
mod mb_read_session;
pub mod observe;
mod ops;
mod patterns;
mod recover;
mod runtime_assets;
pub(crate) mod schema;

pub(crate) mod public {
    mod core;
    mod dump;
    mod evidence;
    mod inspect;
    mod paths;
    mod recovery;
    mod scripts;

    pub use self::{
        core::{AsciiDecodePolicy, OperationMode, SceneFormat, ValidationState},
        dump::{SceneDumpReport, SceneDumpRequireEntry, SceneDumpRequireKind},
        evidence::{
            DependencyFact, DependencyFactDetail, DependencyFactKind, DependencyRiskClass,
            EffectCertainty, ExecutionCoverageIssue, ExecutionCoverageIssueDetail,
            ExecutionCoverageIssueKind, ExecutionCoverageState, ExecutionEffectClass,
            ExecutionLanguage, ExecutionOrigin, ExecutionReason, ExecutionReasonTemplate,
            ExecutionSemanticClass, ExecutionSourceRange, ExecutionSurfaceKind, ExecutionTrigger,
            ExecutionUnitSummary, SceneDigestSet, StaticExecutionReason, UnknownSemanticDetail,
            UnknownSemanticFact,
        },
        inspect::{MbInspectNode, MbInspectOptions, MbInspectReport},
        paths::{
            PathKind, ScenePathEntry, ScenePathMeta, ScenePathResolution,
            ScenePathResolutionStatus, ScenePathValueStyle, ScenePathsReport,
        },
        recovery::{
            AddAttrDefaultValue, AddAttrOp, AddAttrValueSpec, AngularAttrKind, ChunkRef,
            ChunkTrace, Confidence, CreateNodeFlags, DecodeQualityRecord, FlagState, LinkOp,
            MbRecoveryBundle, NodeRecoveryIssue, NumericValue, RawChunkRecord, RecoveredAttrOp,
            RecoveredNode, RecoveryIssue, RecoveryIssueKind, RefEditData, RefEditGroup,
            RefEditGroupSource, RefEditParseStats, RefEditRecord, RefEditUnknownTail,
            ReferenceFileOp, SceneArtifacts, SceneBuildOutput, SceneModel, SchemaDecodeAttempt,
            SchemaDecodeAttemptResult, SelectBlock, SelectBlockNote, SelectBlockOp,
            SemanticProvenance, SetAttrOp, SetAttrValue, SkinWeightPair, SkinWeightRow,
            TimeValuePair, TypeIdResolverStatus, recover_mb_scene,
            validate_additional_node_info_paths,
        },
        scripts::{ScriptNodeEntriesReport, ScriptNodeEntry, ScriptNodeReport},
    };
}

pub use self::{
    error::SceneToolError,
    observe::{
        LoadOptions, Loader, ObservationBundle, check_script_nodes,
        check_script_nodes_with_options, collect_scene_dump, collect_scene_dump_with_options,
        collect_scene_paths, collect_scene_paths_with_options, collect_script_node_entries,
        collect_script_node_entries_with_options, detect_scene_format, find_scene_workspace_root,
        inspect_mb, inspect_mb_with_max_parse_bytes, resolve_scene_path_value,
    },
    public::{
        AddAttrDefaultValue, AddAttrOp, AddAttrValueSpec, AngularAttrKind, AsciiDecodePolicy,
        ChunkRef, ChunkTrace, Confidence, CreateNodeFlags, DecodeQualityRecord, DependencyFact,
        DependencyFactDetail, DependencyFactKind, DependencyRiskClass, EffectCertainty,
        ExecutionCoverageIssue, ExecutionCoverageIssueDetail, ExecutionCoverageIssueKind,
        ExecutionCoverageState, ExecutionEffectClass, ExecutionLanguage, ExecutionOrigin,
        ExecutionReason, ExecutionReasonTemplate, ExecutionSemanticClass, ExecutionSourceRange,
        ExecutionSurfaceKind, ExecutionTrigger, ExecutionUnitSummary, FlagState, LinkOp,
        MbInspectNode, MbInspectOptions, MbInspectReport, MbRecoveryBundle, NodeRecoveryIssue,
        NumericValue, OperationMode, PathKind, RawChunkRecord, RecoveredAttrOp, RecoveredNode,
        RecoveryIssue, RecoveryIssueKind, RefEditData, RefEditGroup, RefEditGroupSource,
        RefEditParseStats, RefEditRecord, RefEditUnknownTail, ReferenceFileOp, SceneArtifacts,
        SceneBuildOutput, SceneDigestSet, SceneDumpReport, SceneDumpRequireEntry,
        SceneDumpRequireKind, SceneFormat, SceneModel, ScenePathEntry, ScenePathMeta,
        ScenePathResolution, ScenePathResolutionStatus, ScenePathValueStyle, ScenePathsReport,
        SchemaDecodeAttempt, SchemaDecodeAttemptResult, ScriptNodeEntriesReport, ScriptNodeEntry,
        ScriptNodeReport, SelectBlock, SelectBlockNote, SelectBlockOp, SemanticProvenance,
        SetAttrOp, SetAttrValue, SkinWeightPair, SkinWeightRow, StaticExecutionReason,
        TimeValuePair, TypeIdResolverStatus, UnknownSemanticDetail, UnknownSemanticFact,
        ValidationState, recover_mb_scene, validate_additional_node_info_paths,
    },
};

pub use maya_scene_kit_formats::mb::{MbParseBudget, MbParseBudgetLimit};
pub use maya_scene_kit_formats::mel::{MelParseBudget, MelParseBudgetLimit};
