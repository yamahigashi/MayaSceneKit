pub(crate) mod analyze;
pub mod core;
pub(crate) mod decode;
pub mod dump;
pub mod evidence;
mod error;
pub mod execution;
pub mod forensics;
mod integrity;
pub mod inspect;
pub(crate) mod ir;
mod mb_extract;
mod mb_read_session;
pub mod model;
mod ops;
mod patterns;
pub mod paths;
pub(crate) mod query;
mod recover;
pub mod recovery;
pub mod scripts;
pub(crate) mod source;
pub(crate) mod schema;
#[cfg(test)]
mod observe;

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
            AngularAttrKind, MbRecoveryBundle, recover_mb_scene,
            validate_additional_node_info_paths,
        },
        scripts::{ScriptNodeEntriesReport, ScriptNodeEntry, ScriptNodeReport},
    };
}

pub use self::{
    error::SceneToolError,
    query::resolve::{find_scene_workspace_root, resolve_scene_path_value},
    source::{
        LoadOptions, Loader, ObservationBundle, check_script_nodes,
        check_script_nodes_with_options, collect_scene_dump, collect_scene_dump_with_options,
        collect_scene_paths, collect_scene_paths_with_options, collect_script_node_entries,
        collect_script_node_entries_with_options, detect_scene_format,
    },
    inspect::{inspect_mb, inspect_mb_with_max_parse_bytes},
    public::{
        AsciiDecodePolicy, OperationMode, SceneFormat, ValidationState,
    },
};

pub(crate) use self::public::{
    DependencyFact, DependencyFactDetail, DependencyFactKind, DependencyRiskClass,
    EffectCertainty, ExecutionCoverageIssue, ExecutionCoverageIssueDetail,
    ExecutionCoverageIssueKind, ExecutionCoverageState, ExecutionEffectClass,
    ExecutionLanguage, ExecutionOrigin, ExecutionReason, ExecutionReasonTemplate,
    ExecutionSemanticClass, ExecutionSourceRange, ExecutionSurfaceKind, ExecutionTrigger,
    ExecutionUnitSummary, SceneDigestSet, StaticExecutionReason, UnknownSemanticDetail,
    UnknownSemanticFact,
};

pub use maya_scene_kit_formats::mb::{MbParseBudget, MbParseBudgetLimit};
pub use maya_scene_kit_formats::mel::{MelParseBudget, MelParseBudgetLimit};
