use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fs, io,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use chrono::Local;
use gpui::{prelude::*, *};
use gpui_component::{
    Disableable, Icon, IconName, IconNamed, Root, Sizable, WindowExt,
    button::{Button, ButtonVariants},
    dialog::Dialog,
    input::{Escape as InputEscape, Input, InputEvent, InputState},
    menu::PopupMenuItem,
    radio::{Radio, RadioGroup},
    resizable::{h_resizable, resizable_panel, v_resizable},
    scroll::{ScrollableElement, ScrollbarShow},
    spinner::Spinner,
    tab::{Tab, TabBar},
    table::{Column, ColumnSort, Table, TableDelegate, TableEvent, TableState},
    theme::Theme,
};
use maya_scene_kit_audit::{
    audit::{
        ScriptAuditPlan, audit_observation, audit_script_nodes_with_options,
        build_parse_budget_blocked_audit_report, build_script_audit_plan,
    },
    scene::{
        AllowlistHash, AllowlistSource, AuditAllowRef, AuditAllowlist, AuditCacheAccess,
        AuditCacheStore, AuditEvidence, AuditFindingDetail, AuditOptions, AuditReport,
        AuditSeverity, AuditedSceneSnapshot, StaticAuditFindingDetail, fingerprint_audit_plan,
    },
};
use maya_scene_kit_edit::scene::{
    CompositeSceneEditsStageResult, ExecutionCleanPreview, ExecutionCleanTarget,
    MayaAsciiConversionReport, PathOwnerDeletePreview, PathOwnerDeleteTarget, PathReplaceChanges,
    PathReplaceMode, PathReplaceOverride, PathReplacePreview, PathReplaceRule,
    PathReplaceStageResult, SceneEditIntent, SceneEditPlan, StagedSceneArtifact,
    clean_target_for_execution_origin, collect_raw_chunks,
    preview_replace_scene_path_candidates_in_report_with_options,
    preview_replace_scene_paths_with_overrides_in_report_with_options, save_staged_artifact,
    stage_maya_ascii_with_options, stage_replace_scene_paths_with_overrides_in_report_with_options,
    stage_scene_edit_plan_with_options,
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, ObserveCacheAccess, ObserveCacheStore, ObservedSceneSnapshot,
    ScenePathResolutionContext, SceneResourceResolver, SceneToolError,
    collect_scene_paths_with_options,
    core::{SceneFormat, ValidationState},
    dump::{SceneDumpReport, SceneDumpRequireEntry, SceneDumpRequireKind},
    evidence::{ExecutionOrigin, ExecutionSurfaceKind},
    find_scene_workspace_root,
    paths::{
        PathKind, ScenePathResolution, ScenePathResolutionStatus, ScenePathValueStyle,
        ScenePathsReport,
    },
};
use serde::Deserialize;

use self::plugins::{
    PluginActionScope, PluginRegistry, build_audit_plugin_context, build_file_plugin_context,
    default_plugin_dir_from_state_path, spawn_plugin_action,
};
use crate::{
    default_analysis_cache_root, default_state_path,
    i18n::I18n,
    menu_bar::TopMenuBar,
    model::{
        AuditModePreference, AutoAnalyzeParallelismPreference, BackupLocationPreference,
        JobHistoryEntry, LocalePreference, PersistedState, PersistedTableColumnWidth, RecentInput,
        ResultTab, StatusFilter, SupportedLocale, WorkspaceLayoutPreference, bulk_enabled,
        normalize_ignored_folder_name, save_enabled,
    },
    persistence::{
        AllowlistLoadError, UserAllowlistDocument, UserAllowlistEntry, app_allowlist_path,
        load_allowlists, load_persisted_state, next_persist_save_sequence, save_persisted_state,
        user_allowlist_path,
    },
};

actions!(
    gui_menu,
    [
        MenuSelectFolder,
        MenuReloadFolder,
        FocusSearch,
        MenuRecentFolderUnavailable,
        MenuRecentFolder0,
        MenuRecentFolder1,
        MenuRecentFolder2,
        MenuRecentFolder3,
        MenuRecentFolder4,
        MenuRecentFolder5,
        MenuRecentFolder6,
        MenuRecentFolder7,
        MenuRecentFolder8,
        MenuRecentFolder9,
        MenuSaveSelected,
        MenuSaveAll,
        MenuClearWorkspace,
        MenuEditUndo,
        MenuEditRedo,
        MenuEditUndoUnavailable,
        MenuEditRedoUnavailable,
        MenuEditClean,
        MenuEditDeleteUiConfigurationScriptNode,
        MenuEditReplace,
        MenuEditToAscii,
        MenuExitApplication,
        TableSelectAll,
        MenuLocaleEnglish,
        MenuLocaleChinese,
        MenuLocaleJapanese,
        MenuBackupLocationSameDirectory,
        MenuBackupLocationBackupFolder,
        MenuLayoutVerticalSplit,
        MenuLayoutHorizontalSplit,
        MenuAutoAnalyzeParallelism1,
        MenuAutoAnalyzeParallelism2,
        MenuAutoAnalyzeParallelism4,
        MenuAutoAnalyzeParallelism8,
        MenuAutoAnalyzeParallelism16,
        MenuAutoAnalyzeParallelism32,
        MenuToggleAnalysisCache,
        MenuPurgeAnalysisCache,
        MenuReloadAllowlists,
        MenuManageAllowlists,
        MenuEditMaxBytes,
        MenuToggleIgnoreFolderNames,
        MenuEditIgnoredFolderNames
    ]
);

#[derive(Action, Clone, PartialEq, Eq, Deserialize)]
#[action(namespace = gui_menu, no_json)]
pub struct MenuRemoveRecentFolderByPath {
    pub path: String,
}

const ROOT_BG: u32 = 0xf4f1ec;
const PANEL_BG: u32 = 0xfffcf7;
const PANEL_ALT_BG: u32 = 0xf0ebe2;
pub(crate) const BORDER: u32 = 0xd8cec0;
pub(crate) const TEXT: u32 = 0x2e251d;
const MUTED: u32 = 0x6f665c;
const ACCENT: u32 = 0x105c66;
const ACCENT_SOFT: u32 = 0xd8eef0;
const WARN_SOFT: u32 = 0xf5ead7;
const ERROR_SOFT: u32 = 0xf3d8d2;
const SUCCESS_SOFT: u32 = 0xdceee0;
const ROW_STATE_MARK_WIDTH: f32 = 4.0;
const AUDIT_RESULTS_PER_FILE: usize = 16;
const AUTO_ANALYZE_DEBOUNCE: Duration = Duration::from_millis(150);
const FILE_DIALOG_UI_BLOCK_RELEASE_DELAY: Duration = Duration::from_millis(300);
const MAX_RECENT_FOLDERS: usize = 10;
const TABLE_CONTEXT: &str = "Table";

struct AppAssets;

#[derive(Clone, Copy)]
enum AppIconName {
    GitPullRequestArrow,
    FileImage,
    BadgeCheck,
    FileQuestionMark,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllowlistManagerTab {
    User,
    App,
}

#[derive(Clone, Debug)]
struct AllowlistManagerState {
    app: AllowlistManagerLayer,
    user: AllowlistManagerLayer,
    selected: AllowlistManagerTab,
    pending_remove: Option<PendingAllowlistRemoval>,
}

#[derive(Clone, Debug)]
struct AllowlistManagerLayer {
    path: Option<PathBuf>,
    document: Result<UserAllowlistDocument, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingAllowlistRemoval {
    index: usize,
    expected: UserAllowlistEntry,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StartupBannerImportance {
    Warning,
    Error,
}

struct GuiShell {
    window_handle: AnyWindowHandle,
    staged_audit_dispatch_pending: bool,
    audit_allowlist: AuditAllowlist,
    audit_plan: Arc<ScriptAuditPlan>,
    audit_plan_fingerprint: String,
    app_allowlist_path: Option<PathBuf>,
    user_allowlist_path: Option<PathBuf>,
    allowlist_load_errors: Vec<AllowlistLoadError>,
    allowlist_manager: Option<AllowlistManagerState>,
    audit_show_allowed: bool,
    audit_allowed_total: usize,
    state: PersistedState,
    rows: Vec<SceneRow>,
    row_id_to_index: HashMap<u64, usize>,
    visible_rows: Vec<usize>,
    menu_bar: TopMenuBar,
    focus_handle: FocusHandle,
    search_input: Entity<InputState>,
    path_search_input: Entity<InputState>,
    audit_search_input: Entity<InputState>,
    path_edit_input: Entity<InputState>,
    replace_from_input: Entity<InputState>,
    replace_to_input: Entity<InputState>,
    file_table: Entity<TableState<FileTableDelegate>>,
    file_table_focus_handle: FocusHandle,
    path_table: Entity<TableState<PathTableDelegate>>,
    path_table_focus_handle: FocusHandle,
    path_table_summary: PathTableSummary,
    audit_table: Entity<TableState<AuditTableDelegate>>,
    replace_preview_table: Entity<TableState<ReplacePreviewTableDelegate>>,
    audit_all_rows: Vec<AuditResultRow>,
    audit_rows: Vec<AuditTableRow>,
    file_sort: FileTableSort,
    path_sort: PathTableSort,
    path_order_snapshot: Option<PathOrderSnapshot>,
    audit_sort: AuditTableSort,
    next_row_id: u64,
    next_row_job_id: u64,
    audit_refresh_batch_depth: usize,
    mutation_banner_depth: usize,
    mutation_rejected_rows: BTreeSet<u64>,
    audit_refresh_pending: bool,
    #[cfg(test)]
    audit_refresh_count: usize,
    selection_anchor: Option<usize>,
    selected_auto_analyze_generation: u64,
    workspace_auto_analyze_generation: u64,
    file_dialog_block_generation: u64,
    auto_analyze_queue: AutoAnalyzeQueueState,
    file_dialog_ui_blocked: bool,
    undo_stack: Vec<GuiEditHistoryEntry>,
    redo_stack: Vec<GuiEditHistoryEntry>,
    next_edit_history_sequence: u64,
    next_edit_history_commit_sequence: u64,
    pending_edit_transactions: BTreeMap<u64, PendingEditTransaction>,
    completed_edit_history: BTreeMap<u64, Option<GuiEditHistoryEntry>>,
    workspace_auto_analyze_started_at: Option<Instant>,
    file_table_viewport_range: Range<usize>,
    workspace_scan_state: WorkspaceScanState,
    cache_restore_generation: u64,
    cache_restore_state: CacheRestoreState,
    cache_write_generation: u64,
    cache_write_state: CacheWriteState,
    cache_maintenance_generation: u64,
    cache_maintenance_state: CacheMaintenanceState,
    cache_restore_refresh_state: CacheRestoreRefreshState,
    auto_analyze_refresh_state: AutoAnalyzeRefreshState,
    path_resolution_refresh_state: PathResolutionRefreshState,
    persist_flush_state: PersistFlushState,
    active_path_edit: Option<Vec<(u64, usize)>>,
    path_search_in_flight: bool,
    selected_path_rows: BTreeSet<PathEditTargets>,
    path_selection_anchor: Option<PathEditTargets>,
    suppress_next_path_focus_out_clear: bool,
    path_table_dedup: bool,
    path_dirty_only: bool,
    path_search_query: String,
    audit_table_dedup: bool,
    audit_dirty_only: bool,
    audit_search_query: String,
    selected_audit_keys: BTreeSet<AuditResultRowKey>,
    audit_selection_anchor: Option<AuditResultRowKey>,
    path_type_filter: BTreeSet<PathTypeFilter>,
    path_form_filter: BTreeSet<PathFormFilter>,
    path_resolution_filter: BTreeSet<PathResolutionBadge>,
    audit_severity_filter: BTreeSet<AuditSeverityFilter>,
    audit_detail_dialog: Option<AuditDetailDialogState>,
    audit_detail_code_request: u64,
    audit_detail_allow_request: u64,
    audit_allow_in_flight: bool,
    plugin_registry: PluginRegistry,
    status_message: Option<BannerMessage>,
    startup_banner: Option<(StartupBannerImportance, BannerMessage)>,
    settings_save_disabled_path: Option<PathBuf>,
    settings_save_skip_logged: bool,
    max_bytes_dialog: Option<MaxBytesDialogState>,
    ignore_folder_names_dialog: Option<IgnoreFolderNamesDialogState>,
    replace_dialog: Option<ReplaceDialogState>,
    path_collect_dialog: Option<PathCollectDialogState>,
    observe_cache_root: PathBuf,
    audit_cache_root: PathBuf,
    exit_confirmation_pending: bool,
    bypass_next_exit_warning: bool,
    _subscriptions: Vec<Subscription>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AutoAnalyzePriority {
    High,
    Viewport,
    Low,
}

#[derive(Debug, Default)]
struct AutoAnalyzeQueueState {
    generation: u64,
    pending_high: VecDeque<u64>,
    pending_viewport: VecDeque<u64>,
    pending_low: VecDeque<u64>,
    in_flight: BTreeSet<u64>,
}

#[derive(Debug, Default)]
struct CacheRestoreState {
    pending: VecDeque<u64>,
    total_count: usize,
    completed_count: usize,
    in_flight: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum WorkspaceScanKind {
    #[default]
    ReplaceAll,
    Rescan,
}

#[derive(Debug, Default)]
struct WorkspaceScanState {
    generation: u64,
    in_flight: bool,
    kind: WorkspaceScanKind,
}

#[derive(Debug, Default)]
struct CacheWriteState {
    pending_observe_order: VecDeque<String>,
    pending_audit_order: VecDeque<String>,
    pending_observe: BTreeMap<String, ObservedSceneSnapshot>,
    pending_audit: BTreeMap<String, AuditedSceneSnapshot>,
    debounce_generation: u64,
    debounce_pending: bool,
    in_flight: bool,
    error_count: usize,
    first_error: Option<String>,
}

#[derive(Debug, Default)]
struct CacheMaintenanceState {
    pending_observe_order: VecDeque<String>,
    pending_audit_order: VecDeque<String>,
    pending_observe: BTreeMap<String, ObserveCacheAccess>,
    pending_audit: BTreeMap<String, AuditCacheAccess>,
    pending_sweep: bool,
    debounce_generation: u64,
    debounce_pending: bool,
    periodic_sweep_generation: u64,
    in_flight: bool,
    error_count: usize,
    first_error: Option<String>,
}

#[derive(Debug, Default)]
struct CacheRestoreRefreshState {
    visible_generation: u64,
    full_generation: u64,
    pending_visible_row_ids: BTreeSet<u64>,
    pending_full_refresh: bool,
    pending_completion_count: usize,
}

#[derive(Debug, Default)]
struct AutoAnalyzeRefreshState {
    membership_dirty: bool,
    membership_timer_pending: bool,
    membership_generation: u64,
    visible_generation: u64,
    full_generation: u64,
    pending_visible_row_ids: BTreeSet<u64>,
    pending_full_refresh: bool,
    pending_completion_count: usize,
}

#[derive(Debug, Default)]
struct PathResolutionRefreshState {
    debounce_generation: u64,
    debounce_pending: bool,
    in_flight: bool,
    pending_priority_row_ids: BTreeSet<u64>,
    pending_backlog_row_ids: BTreeSet<u64>,
}

#[derive(Debug, Default)]
struct PersistFlushState {
    generation: u64,
    in_flight: bool,
    dirty: bool,
    workspace_paths_dirty: bool,
}

impl AutoAnalyzeQueueState {
    fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.pending_high.clear();
        self.pending_viewport.clear();
        self.pending_low.clear();
        self.in_flight.clear();
    }

    fn clear_pending_high(&mut self) {
        self.pending_high.clear();
    }

    fn clear_pending_low(&mut self) {
        self.pending_low.clear();
    }

    fn replace_pending_viewport(&mut self, row_ids: impl IntoIterator<Item = u64>) {
        self.pending_viewport.clear();
        for row_id in row_ids {
            self.enqueue(row_id, AutoAnalyzePriority::Viewport);
        }
    }

    fn enqueue(&mut self, row_id: u64, priority: AutoAnalyzePriority) {
        if self.in_flight.contains(&row_id) {
            return;
        }
        let pending_high = self.pending_high.iter().any(|queued| *queued == row_id);
        let pending_viewport = self.pending_viewport.iter().any(|queued| *queued == row_id);
        let pending_low = self.pending_low.iter().any(|queued| *queued == row_id);
        match priority {
            AutoAnalyzePriority::High => {
                if pending_high {
                    return;
                }
                if pending_viewport {
                    self.pending_viewport.retain(|queued| *queued != row_id);
                }
                if pending_low {
                    self.pending_low.retain(|queued| *queued != row_id);
                }
                self.pending_high.push_back(row_id);
            }
            AutoAnalyzePriority::Viewport => {
                if pending_high || pending_viewport {
                    return;
                }
                if pending_low {
                    self.pending_low.retain(|queued| *queued != row_id);
                }
                self.pending_viewport.push_back(row_id);
            }
            AutoAnalyzePriority::Low => {
                if pending_high || pending_viewport || pending_low {
                    return;
                }
                self.pending_low.push_back(row_id);
            }
        }
    }

    fn enqueue_many(
        &mut self,
        row_ids: impl IntoIterator<Item = u64>,
        priority: AutoAnalyzePriority,
    ) {
        for row_id in row_ids {
            self.enqueue(row_id, priority);
        }
    }

    fn pop_next(&mut self, allow_low_priority: bool) -> Option<u64> {
        if let Some(row_id) = self.pending_high.pop_front() {
            self.in_flight.insert(row_id);
            return Some(row_id);
        }
        if let Some(row_id) = self.pending_viewport.pop_front() {
            self.in_flight.insert(row_id);
            return Some(row_id);
        }
        if !allow_low_priority {
            return None;
        }
        let row_id = self.pending_low.pop_front()?;
        self.in_flight.insert(row_id);
        Some(row_id)
    }

    fn complete(&mut self, row_id: u64) {
        self.in_flight.remove(&row_id);
    }

    fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    fn remaining_count(&self) -> usize {
        self.pending_high.len()
            + self.pending_viewport.len()
            + self.pending_low.len()
            + self.in_flight.len()
    }
}

type PathEditTargets = Vec<(u64, usize)>;

#[derive(Clone, Debug, Default)]
struct PathOrderSnapshot {
    order_by_target: BTreeMap<(u64, usize), usize>,
}

#[derive(Clone)]
struct GuiEditHistoryEntry {
    transitions: Vec<RowEditTransition>,
}

#[derive(Clone)]
struct RowEditTransition {
    row_id: u64,
    before: SceneRowEditState,
    after: SceneRowEditState,
}

#[derive(Clone)]
struct SceneRowEditState {
    audit_report: Option<AuditReport>,
    audit_file_state: Option<GuiFileState>,
    status: FileStatus,
    findings: usize,
    replace_changes: Option<PathReplaceChanges>,
    audit_plan_fingerprint: Option<String>,
    replace_artifact_generation: Option<u64>,
    staged: Staged,
    applied_replace_preview: Option<PathReplacePreview>,
}

struct PendingEditTransaction {
    row_ids: Vec<u64>,
    before_states: BTreeMap<u64, SceneRowEditState>,
    successful_after_states: BTreeMap<u64, SceneRowEditState>,
    remaining_row_ids: BTreeSet<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathEditKeyboardOutcome {
    Ignore,
    SuppressForIme,
    Apply,
    Cancel,
}

fn path_edit_keyboard_outcome(key: &str, has_marked_text: bool) -> PathEditKeyboardOutcome {
    if has_marked_text && matches!(key, "enter" | "escape") {
        return PathEditKeyboardOutcome::SuppressForIme;
    }

    match key {
        "enter" => PathEditKeyboardOutcome::Apply,
        "escape" => PathEditKeyboardOutcome::Cancel,
        _ => PathEditKeyboardOutcome::Ignore,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AuditResultItemKind {
    Finding,
    DumpRequire,
    DumpScriptNode,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AuditResultRowKey {
    row_id: u64,
    item_kind: AuditResultItemKind,
    item_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditDetailTab {
    Code,
    Details,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditDetailFieldKind {
    Allowed,
    AllowHash,
    RuleId,
    Sink,
    Node,
    Attribute,
    Surface,
    Trigger,
    Language,
    Source,
    Line,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditDetailField {
    kind: AuditDetailFieldKind,
    raw: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditResultRow {
    allowed: Option<AllowlistSource>,
    key: AuditResultRowKey,
    scene_name: String,
    severity: AuditSeverity,
    summary: String,
    code: String,
    sink: String,
    node: String,
    preview: String,
    provenance: Vec<String>,
    detail_fields: Vec<AuditDetailField>,
    source_line: Option<usize>,
    evidence: Vec<String>,
    dirty: bool,
    clean_target: Option<ExecutionCleanTarget>,
    clean_state: AuditRowCleanState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditTableRow {
    allowed: Option<AllowlistSource>,
    key: AuditResultRowKey,
    row_keys: Vec<AuditResultRowKey>,
    selected: bool,
    scene_name: String,
    scene_names: Vec<String>,
    severity: AuditSeverity,
    summary: String,
    code: String,
    sink: String,
    node: String,
    preview: String,
    provenance: Vec<String>,
    detail_fields: Vec<AuditDetailField>,
    source_line: Option<usize>,
    evidence: Vec<String>,
    dirty: bool,
    clean_target: Option<ExecutionCleanTarget>,
    clean_state: AuditRowCleanState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditTableModel {
    rows: Vec<AuditTableRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditReportIdentity {
    Analysis(u64),
    Staged(u64),
}

#[derive(Clone, Debug)]
struct AuditDetailDialogState {
    key: AuditResultRowKey,
    active_tab: AuditDetailTab,
    code_input: Entity<InputState>,
    preview_text: String,
    code_text: SharedString,
    code: AuditDetailCodeState,
    code_target: Option<AuditDetailCodeTarget>,
    code_generation: u64,
    report_identity: Option<AuditReportIdentity>,
    allow_form: Option<AllowFormState>,
}

#[derive(Clone, Debug)]
struct AllowFormState {
    reason_input: Entity<InputState>,
    checked_codes: BTreeSet<String>,
    request: Option<u64>,
    error: Option<AllowAddError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AllowAddError {
    FileChanged,
    VerificationRefused,
    AuditFailed(String),
    WriteFailed { path: PathBuf, error: String },
    Rejected { reason_key: &'static str },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditAllowMaterial {
    root_origin: ExecutionOrigin,
    hash: AllowlistHash,
    offered_codes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AuditDetailCodeState {
    NotApplicable,
    Loading {
        request: u64,
    },
    Loaded {
        derived: bool,
        allow: Box<AuditAllowMaterial>,
    },
    NotFound,
    Ambiguous,
    Failed {
        error: String,
    },
    Unavailable,
    FileChanged,
    TooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditDetailCodeTarget {
    origin: ExecutionOrigin,
    derived: bool,
}

enum GuiAnalysisSource {
    Unanalyzed,
    Content(maya_scene_kit_observe::scene::paths::SceneSourceFingerprint),
    Metadata(GuiFileState),
    Unavailable,
}

impl GuiAnalysisSource {
    fn for_row(row: &SceneRow) -> Self {
        if let Some(source) = row
            .paths_report
            .as_ref()
            .and_then(|report| report.source.as_ref())
            .filter(|source| !source.sha256.is_empty())
        {
            Self::Content(source.clone())
        } else if let Some(state) = row.audit_file_state {
            Self::Metadata(state)
        } else if row.paths_report.is_some()
            || row.audit_report.is_some()
            || row.dump_report.is_some()
            || row.analyzed_audit_mode.is_some()
        {
            Self::Unavailable
        } else {
            Self::Unanalyzed
        }
    }

    fn matches_acquisition(
        &self,
        source: &maya_scene_kit_observe::scene::paths::SceneSourceFingerprint,
        file_state: Option<GuiFileState>,
    ) -> bool {
        match self {
            Self::Unanalyzed => true,
            Self::Content(expected) => expected == source,
            Self::Metadata(expected) => Some(*expected) == file_state,
            Self::Unavailable => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GuiFileState {
    size: u64,
    modified_unix_nanos: Option<u128>,
}

impl GuiFileState {
    fn read(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        Ok(Self {
            size: metadata.len(),
            modified_unix_nanos: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos()),
        })
    }
}

#[derive(Clone, Debug)]
struct IgnoreFolderNamesDialogState {
    draft_names: Vec<String>,
    name_input: Entity<InputState>,
}

#[derive(Clone, Debug)]
struct MaxBytesDialogState {
    input: Entity<InputState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditDetailViewModel {
    key: AuditResultRowKey,
    row_keys: Vec<AuditResultRowKey>,
    scene_name: String,
    scene_names: Vec<String>,
    severity: AuditSeverity,
    summary: String,
    code: String,
    sink: String,
    preview: String,
    provenance: Vec<String>,
    detail_fields: Vec<AuditDetailField>,
    source_line: Option<usize>,
    evidence: Vec<String>,
    clean_target: Option<ExecutionCleanTarget>,
    clean_state: AuditRowCleanState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AuditRowCleanState {
    Unsupported,
    Available,
    Staged,
    BlockedByOtherDirty,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AuditSeverityFilter {
    Info,
    Low,
    MediumPlus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PathTypeFilter {
    Reference,
    File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PathFormFilter {
    Rel,
    Abs,
}

struct SceneRow {
    id: u64,
    path: PathBuf,
    name: String,
    size: u64,
    modified: Option<SystemTime>,
    selected: bool,
    status: FileStatus,
    busy: Option<(RowOperation, u64)>,
    findings: usize,
    scene_workspace_root: Option<PathBuf>,
    audit_report: Option<AuditReport>,
    audit_file_state: Option<GuiFileState>,
    audit_generation: u64,
    display_audit_plan_fingerprint: Option<String>,
    staged_audit_recheck: Option<StagedAuditRecheck>,
    paths_report: Option<ScenePathsReport>,
    dump_report: Option<SceneDumpReport>,
    analyzed_audit_mode: Option<AuditModePreference>,
    replace_changes: Option<PathReplaceChanges>,
    audit_plan_fingerprint: Option<String>,
    path_resolution_cache: BTreeMap<usize, PathResolutionCacheEntry>,
    missing_path_count_cache: Option<usize>,
    path_resolution_revision: u64,
    replace_generation: u64,
    replace_artifact_generation: Option<u64>,
    staged: Staged,
    restage_rollback: Option<RestageRollback>,
    applied_replace_preview: Option<PathReplacePreview>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DiscoveredSceneFile {
    path: PathBuf,
    name: String,
    size: u64,
    modified: Option<SystemTime>,
    scene_workspace_root: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PathResolutionCacheEntry {
    effective_value: String,
    resolution: ScenePathResolution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PathResolutionBadge {
    Exists,
    Missing,
    Unresolved,
}

#[derive(Clone)]
struct FileTableRow {
    id: u64,
    selected: bool,
    dirty: bool,
    is_processing: bool,
    tone: u32,
    state_mark: Option<RowStateMark>,
    name: String,
    has_scene_workspace: bool,
    status: String,
    findings: String,
    missing: String,
    size: String,
    modified: String,
}

struct FileTableDelegate {
    view: Option<Entity<GuiShell>>,
    focus_handle: Option<FocusHandle>,
    locale: SupportedLocale,
    columns: Vec<Column>,
    rows: Vec<FileTableRow>,
}

#[derive(Clone)]
struct PathTableRow {
    skip_lines: Vec<String>,
    edit_targets: PathEditTargets,
    captured_order: Option<usize>,
    path_kind: PathTypeFilter,
    owner_deletable: bool,
    owner_deleted: bool,
    selected: bool,
    scene: String,
    node: String,
    value: String,
    value_style: Option<ScenePathValueStyle>,
    dirty: bool,
    resolution_badge: Option<PathResolutionBadge>,
    editable: bool,
    editing: bool,
    preview_only: bool,
}

struct PathTableDelegate {
    view: Option<Entity<GuiShell>>,
    locale: SupportedLocale,
    rows: Vec<PathTableRow>,
    show_scene_column: bool,
    sort: PathTableSort,
    columns: Vec<Column>,
}

struct ReplacePreviewTableDelegate {
    view: Option<Entity<GuiShell>>,
    locale: SupportedLocale,
    rows: Vec<ReplaceDialogPreviewRow>,
    sort: ReplaceDialogSort,
    columns: Vec<Column>,
}

struct AuditTableDelegate {
    view: Option<Entity<GuiShell>>,
    locale: SupportedLocale,
    rows: Vec<AuditTableRow>,
    sort: AuditTableSort,
    columns: Vec<Column>,
}

struct PathTableModel {
    rows: Vec<PathTableRow>,
    has_report_rows: bool,
    show_scene_column: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PathTableSummary {
    row_count: usize,
    has_report_rows: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplaceDialogPreviewRow {
    before_value: String,
    after_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplaceDialogPreviewSignature {
    from_value: String,
    to_value: String,
    replace_mode: PathReplaceMode,
    path_type_filter: BTreeSet<PathTypeFilter>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplaceDialogSortKey {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReplaceDialogSort {
    key: ReplaceDialogSortKey,
    direction: ColumnSort,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplaceDialogPreviewState {
    previewable_row_ids: Vec<u64>,
    failed_files: Vec<String>,
    matched_count: usize,
    applied_count: usize,
    items: Vec<ReplaceDialogPreviewRow>,
    planned_overrides: Vec<(u64, Vec<PathReplaceOverride>)>,
}

#[derive(Clone, Debug)]
struct ReplaceDialogSourceCacheEntry {
    report: ScenePathsReport,
    base_overrides: BTreeMap<usize, String>,
}

#[derive(Clone, Debug)]
struct ReplaceDialogState {
    captured_generations: BTreeMap<u64, u64>,
    captured_row_ids: Vec<u64>,
    path_targets: Option<BTreeMap<u64, BTreeSet<usize>>>,
    path_type_filter: BTreeSet<PathTypeFilter>,
    replace_mode: PathReplaceMode,
    preview_sort: ReplaceDialogSort,
    is_previewing: bool,
    generation: u64,
    source_cache: BTreeMap<u64, ReplaceDialogSourceCacheEntry>,
    preview_signature: Option<ReplaceDialogPreviewSignature>,
    preview: Option<ReplaceDialogPreviewState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathCollectRewriteMode {
    CopyOnly,
    Absolute,
    WorkspaceDoubleSlashRelative,
    PlainRelative,
}

#[derive(Clone, Debug)]
struct PathCollectDialogState {
    edit_targets: PathEditTargets,
    rewrite_mode: PathCollectRewriteMode,
    workspace_root: PathBuf,
    folder_input: Entity<InputState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathSortKey {
    Kind,
    Scene,
    Node,
    Path,
    CapturedOrder,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SearchTarget {
    FileList,
    Paths,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuditSortKey {
    Scene,
    Severity,
    Summary,
    Code,
    Node,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileSortKey {
    Name,
    Workspace,
    Status,
    Findings,
    Missing,
    Size,
    Modified,
}

#[derive(Clone, Copy)]
struct FileTableSort {
    key: FileSortKey,
    direction: ColumnSort,
}

#[derive(Clone, Copy)]
struct PathTableSort {
    key: PathSortKey,
    direction: ColumnSort,
}

#[derive(Clone, Copy)]
struct AuditTableSort {
    key: AuditSortKey,
    direction: ColumnSort,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RowOperation {
    Analyze,
    ReauditStaged,
    Clean,
    DeleteOwnerNodes,
    Replace,
    ToAscii,
    Save,
}

enum BannerMessage {
    AllowlistAdded {
        count: usize,
    },
    AllowlistAlreadyPresent,
    AllowlistRemoved {
        label: String,
    },
    AllowlistFileChanged,
    AllowlistReadFailed {
        path: PathBuf,
        error: String,
    },
    AllowlistWriteFailed {
        path: PathBuf,
        error: String,
    },
    AllowlistsReloaded {
        count: usize,
        stale_rows: usize,
    },
    PersistFailed(String),
    CachePurged,
    WorkspaceLoaded {
        count: usize,
        path: PathBuf,
    },
    AnalyzeCompleted {
        name: String,
        elapsed: Duration,
    },
    WorkspaceAutoAnalyzeCompleted {
        count: usize,
        elapsed: Duration,
    },
    WorkspaceCleared,
    InlinePathEditFailed(String),
    SelectFilesFirst,
    SelectedFilesNeedReaudit,
    Raw(String),
    SaveInProgress,
    RowMutationBusy {
        name: String,
        operation: RowOperation,
    },
    RowMutationMissing,
    EditRowsSkipped {
        busy: usize,
        staged: usize,
        name: String,
        stale: usize,
        missing_artifacts: usize,
        skipped: usize,
        changed: Option<usize>,
        saving: bool,
        details: Vec<String>,
    },
    BusyRowsSkipped {
        count: usize,
        saving: bool,
    },
    AnalysisStagedPreserved {
        name: String,
    },
    NothingDirtyToSave,
    NothingSelectedDirtyToSave,
    NothingToUndo,
    NothingToRedo,
}

struct AnalyzeRowResult {
    audit_plan_fingerprint: String,
    audit_file_state: Option<GuiFileState>,
    audit_report: AuditReport,
    paths_report: Option<ScenePathsReport>,
    dump_report: Option<SceneDumpReport>,
    observe_snapshot: Option<ObservedSceneSnapshot>,
    audit_snapshot: Option<AuditedSceneSnapshot>,
    audit_mode: AuditModePreference,
    elapsed: Duration,
}

#[derive(Clone, PartialEq, Eq)]
enum FileStatus {
    Idle,
    Audited,
    Dirty,
    Saved,
    SavedWithWarning(String),
    Error(String),
}

impl FileStatus {
    fn filter_matches(&self, filter: StatusFilter) -> bool {
        match filter {
            StatusFilter::All => true,
            StatusFilter::Dirty => matches!(self, Self::Dirty),
            StatusFilter::Error => matches!(self, Self::Error(_)),
            StatusFilter::Audited => matches!(
                self,
                Self::Audited | Self::Saved | Self::SavedWithWarning(_)
            ),
            StatusFilter::Processing => false,
        }
    }

    fn label(&self, i18n: &I18n) -> String {
        match self {
            Self::Idle => i18n.text("file_status.idle"),
            Self::Audited => i18n.text("file_status.audited"),
            Self::Dirty => i18n.text("file_status.dirty"),
            Self::Saved => i18n.text("file_status.saved"),
            Self::SavedWithWarning(message) => message.clone(),
            Self::Error(message) => {
                if message.is_empty() {
                    i18n.text("file_status.error")
                } else {
                    i18n.format(
                        "file_status.error_with_message",
                        &[("message", message.clone())],
                    )
                }
            }
        }
    }

    fn tone(&self) -> u32 {
        match self {
            Self::Dirty | Self::SavedWithWarning(_) => WARN_SOFT,
            Self::Saved => SUCCESS_SOFT,
            Self::Error(_) => ERROR_SOFT,
            Self::Idle | Self::Audited => PANEL_BG,
        }
    }
}

impl ReplaceDialogState {
    fn invalidate_preview(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.is_previewing = false;
        self.preview_signature = None;
    }

    fn can_apply(&self, signature: &ReplaceDialogPreviewSignature) -> bool {
        let Some(preview_signature) = self.preview_signature.as_ref() else {
            return false;
        };
        let Some(preview) = self.preview.as_ref() else {
            return false;
        };
        !self.is_previewing
            && preview_signature == signature
            && preview
                .planned_overrides
                .iter()
                .any(|(_, overrides)| !overrides.is_empty())
    }
}

impl IgnoreFolderNamesDialogState {
    fn can_apply(&self, state: &PersistedState) -> bool {
        self.draft_names != state.ignored_folder_names
    }
}

impl MaxBytesDialogState {
    fn parsed_value(&self, cx: &App) -> Option<Option<usize>> {
        max_bytes_dialog::parse_max_bytes_input(&self.input.read(cx).value())
    }

    fn can_apply(&self, state: &PersistedState, cx: &App) -> bool {
        self.parsed_value(cx)
            .is_some_and(|value| value != state.max_bytes)
    }
}

impl SceneRow {
    fn status_label(&self, i18n: &I18n) -> String {
        self.busy.map_or_else(
            || self.status.label(i18n),
            |(operation, _)| operation_label(i18n, operation),
        )
    }

    fn status_tone(&self) -> u32 {
        if self.is_processing() {
            PANEL_ALT_BG
        } else {
            self.status.tone()
        }
    }

    fn status_filter_matches(&self, filter: StatusFilter) -> bool {
        if self.is_processing() {
            matches!(filter, StatusFilter::All | StatusFilter::Processing)
        } else {
            self.status.filter_matches(filter)
        }
    }

    fn from_path(id: u64, path: PathBuf) -> Option<Self> {
        let metadata = fs::metadata(&path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        detect_format(&path)?;
        let scene_workspace_root = find_scene_workspace_root(&path);
        Some(Self {
            id,
            name: path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("scene")
                .to_string(),
            modified: metadata.modified().ok(),
            size: metadata.len(),
            path,
            scene_workspace_root,
            ..Self::new_unloaded_row(id)
        })
    }

    fn from_discovered_file(id: u64, file: DiscoveredSceneFile) -> Self {
        Self {
            id,
            path: file.path,
            name: file.name,
            size: file.size,
            modified: file.modified,
            scene_workspace_root: file.scene_workspace_root,
            ..Self::new_unloaded_row(id)
        }
    }

    fn new_unloaded_row(id: u64) -> Self {
        Self {
            id,
            path: PathBuf::new(),
            name: String::new(),
            size: 0,
            modified: None,
            selected: false,
            status: FileStatus::Idle,
            busy: None,
            findings: 0,
            scene_workspace_root: None,
            audit_report: None,
            audit_file_state: None,
            audit_generation: 0,
            display_audit_plan_fingerprint: None,
            staged_audit_recheck: None,
            paths_report: None,
            dump_report: None,
            analyzed_audit_mode: None,
            replace_changes: None,
            staged: Staged::None,
            restage_rollback: None,
            applied_replace_preview: None,
            audit_plan_fingerprint: None,
            path_resolution_cache: BTreeMap::new(),
            missing_path_count_cache: None,
            path_resolution_revision: 0,
            replace_generation: 0,
            replace_artifact_generation: None,
        }
    }

    fn set_audit_report(&mut self, report: Option<AuditReport>, file_state: Option<GuiFileState>) {
        self.audit_report = report;
        self.audit_file_state = file_state;
        self.audit_generation += 1;
    }

    fn refresh_scene_workspace_root(&mut self) {
        self.scene_workspace_root = find_scene_workspace_root(&self.path);
    }

    fn invalidate_path_resolution_state(&mut self) {
        self.path_resolution_revision = self.path_resolution_revision.wrapping_add(1);
        self.path_resolution_cache.clear();
        self.missing_path_count_cache = None;
    }

    fn refresh_path_resolution_cache(&mut self) {
        let Some(report) = self.display_paths_report() else {
            self.invalidate_path_resolution_state();
            return;
        };

        let context =
            ScenePathResolutionContext::for_scene(&self.path, self.scene_workspace_root.as_ref());
        let effective_values = report
            .entries
            .iter()
            .enumerate()
            .map(|(entry_index, entry)| {
                (
                    entry_index,
                    self.staged
                        .overrides()
                        .get(&entry_index)
                        .cloned()
                        .unwrap_or_else(|| entry.value.clone()),
                )
            })
            .collect::<Vec<_>>();
        let mut resolver = SceneResourceResolver::new();
        let resolutions = resolver.resolve_scene_path_values(
            effective_values
                .iter()
                .map(|(_, effective_value)| effective_value.as_str()),
            &context,
        );
        self.path_resolution_cache = effective_values
            .into_iter()
            .zip(resolutions)
            .map(|((entry_index, effective_value), resolution)| {
                (
                    entry_index,
                    PathResolutionCacheEntry {
                        effective_value,
                        resolution,
                    },
                )
            })
            .collect();
        self.refresh_missing_path_count_cache();
    }

    fn refresh_missing_path_count_cache(&mut self) {
        let Some(report) = self.display_paths_report() else {
            self.missing_path_count_cache = None;
            return;
        };

        if self.path_resolution_cache.len() != report.entries.len() {
            self.missing_path_count_cache = None;
            return;
        }

        self.missing_path_count_cache = Some(
            report
                .entries
                .iter()
                .enumerate()
                .filter(|(entry_index, entry)| {
                    let effective_value = self
                        .staged
                        .overrides()
                        .get(entry_index)
                        .map(String::as_str)
                        .unwrap_or(entry.value.as_str());
                    let resolution = self.path_resolution(*entry_index, effective_value);
                    resolution.is_some_and(|resolution| {
                        matches!(resolution.status, ScenePathResolutionStatus::Missing)
                    })
                })
                .count(),
        );
    }

    fn set_path_resolution_state(
        &mut self,
        scene_workspace_root: Option<PathBuf>,
        path_resolution_cache: BTreeMap<usize, PathResolutionCacheEntry>,
        missing_path_count_cache: Option<usize>,
    ) {
        self.scene_workspace_root = scene_workspace_root;
        self.path_resolution_cache = path_resolution_cache;
        self.missing_path_count_cache = missing_path_count_cache;
    }

    fn path_resolution(
        &self,
        entry_index: usize,
        effective_value: &str,
    ) -> Option<&ScenePathResolution> {
        if let Some(cached) = self.path_resolution_cache.get(&entry_index) {
            if cached.effective_value == effective_value {
                return Some(&cached.resolution);
            }
        }
        None
    }

    fn path_resolution_fallback(
        &self,
        entry_index: usize,
        effective_value: &str,
    ) -> Option<ScenePathResolution> {
        let report = self.display_paths_report()?;
        report.entries.get(entry_index)?;
        let context =
            ScenePathResolutionContext::for_scene(&self.path, self.scene_workspace_root.as_ref());
        Some(SceneResourceResolver::new().resolve_scene_path_value(effective_value, &context))
    }

    fn dirty(&self) -> bool {
        match &self.staged {
            Staged::None => false,
            Staged::Replace {
                overrides,
                artifact,
                ..
            } => artifact.is_some() || !overrides.is_empty(),
            Staged::SceneEdits {
                clean,
                owner_delete,
                overrides,
                artifact,
                ..
            } => {
                artifact.is_some()
                    || !overrides.is_empty()
                    || !clean.targets.is_empty()
                    || !owner_delete.targets.is_empty()
            }
            Staged::ToAscii { artifact, .. } => artifact.is_some(),
        }
    }

    fn has_staged_edits(&self) -> bool {
        !matches!(self.staged, Staged::None)
    }

    fn effective_findings_count(&self) -> usize {
        self.display_audit_report()
            .map(|report| report.finding_count() - report.allowed_finding_count())
            .unwrap_or_else(|| {
                if self.staged.reports().audit_report.is_some() {
                    0
                } else {
                    self.findings
                }
            })
    }

    fn sync_findings_count(&mut self) {
        self.findings = self.effective_findings_count();
    }

    fn current_staged_audit_report(&self) -> Option<&AuditReport> {
        let reports = self.staged.reports();
        self.display_audit_plan_fingerprint
            .as_ref()
            .filter(|current| reports.audit_plan_fingerprint.as_ref() == Some(*current))
            .and(reports.audit_report.as_ref())
    }

    fn display_audit_report(&self) -> Option<&AuditReport> {
        self.current_staged_audit_report()
            .or(self.audit_report.as_ref())
    }

    fn display_audit_report_identity(&self) -> Option<AuditReportIdentity> {
        if self.current_staged_audit_report().is_some() {
            Some(AuditReportIdentity::Staged(
                self.staged.reports().audit_generation,
            ))
        } else {
            self.audit_report
                .as_ref()
                .map(|_| AuditReportIdentity::Analysis(self.audit_generation))
        }
    }

    fn display_paths_report(&self) -> Option<&ScenePathsReport> {
        self.paths_report.as_ref()
    }

    fn display_dump_report(&self) -> Option<&SceneDumpReport> {
        self.dump_report.as_ref()
    }

    fn missing_path_count(&self) -> Option<usize> {
        self.missing_path_count_cache
    }

    fn needs_path_resolution_refresh(&self) -> bool {
        self.display_paths_report().is_some()
            && (self.missing_path_count_cache.is_none()
                || self
                    .display_paths_report()
                    .is_some_and(|report| self.path_resolution_cache.len() != report.entries.len()))
    }

    fn scene_edits_are_staged(&self) -> bool {
        matches!(self.staged, Staged::SceneEdits { .. })
    }

    fn analysis_current_for(&self, audit_mode: AuditModePreference) -> bool {
        self.analyzed_audit_mode == Some(audit_mode)
            && self.audit_report.is_some()
            && self.audit_report.as_ref().is_some_and(|report| {
                report.is_parse_budget_blocked()
                    || (self.paths_report.is_some() && self.dump_report.is_some())
            })
    }

    fn mark_analysis_stale(&mut self) {
        self.analyzed_audit_mode = None;
    }

    fn is_processing(&self) -> bool {
        self.busy.is_some()
    }

    fn replace_artifact_is_current(&self) -> bool {
        matches!(self.staged, Staged::Replace { .. })
            && !self.staged.overrides().is_empty()
            && self.staged.artifact().is_some()
            && self.replace_artifact_generation == Some(self.replace_generation)
    }

    fn clean_source_for_targets(
        &self,
        targets: &BTreeSet<ExecutionCleanTarget>,
    ) -> Result<Option<maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>, String> {
        let targets = targets
            .iter()
            .filter(|target| {
                !matches!(
                    target,
                    ExecutionCleanTarget::ScriptNode { .. }
                        | ExecutionCleanTarget::PluginRequire { .. }
                )
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if targets.is_empty() {
            return Ok(None);
        }
        let retained = targets
            .intersection(&self.staged.clean().targets)
            .next()
            .is_some();
        let pending_source =
            if retained {
                Some(
                    self.staged.clean().source.as_ref().ok_or_else(|| {
                        "missing recorded clean observation fingerprint".to_string()
                    })?,
                )
            } else {
                None
            };
        let has_new_targets = targets
            .difference(&self.staged.clean().targets)
            .next()
            .is_some();
        let source = if has_new_targets {
            let audit_digest = self
                .audit_report
                .as_ref()
                .map(|report| report.digests.scene_sha256.as_str());
            let audit_source = self
                .paths_report
                .as_ref()
                .and_then(|report| report.source.as_ref())
                .filter(|source| {
                    !source.sha256.is_empty() && Some(source.sha256.as_str()) == audit_digest
                })
                .ok_or_else(|| "missing original clean observation fingerprint".to_string())?;
            if pending_source.is_some_and(|source| source != audit_source) {
                return Err("clean observation does not match the pending clean targets".into());
            }
            audit_source
        } else {
            pending_source
                .ok_or_else(|| "missing recorded clean observation fingerprint".to_string())?
        };
        Ok(Some(source.clone()))
    }

    fn replace_preview(&self) -> &Option<PathReplacePreview> {
        match &self.staged {
            Staged::Replace { preview, .. } => preview,
            _ => &self.applied_replace_preview,
        }
    }

    fn edit_state(&self) -> SceneRowEditState {
        SceneRowEditState {
            audit_report: self.audit_report.clone(),
            audit_file_state: self.audit_file_state,
            status: self.status.clone(),
            findings: self.findings,
            staged: self.staged.clone(),
            applied_replace_preview: self.applied_replace_preview.clone(),
            replace_changes: self.replace_changes.clone(),
            audit_plan_fingerprint: self.audit_plan_fingerprint.clone(),
            replace_artifact_generation: self.replace_artifact_generation,
        }
    }

    fn apply_edit_state(&mut self, state: &SceneRowEditState) -> Result<(), MutateBlocked> {
        check_row_mutation(Some(self), RowMutation::HistoryRestore)?;
        self.set_audit_report(state.audit_report.clone(), state.audit_file_state);
        self.status = state.status.clone();
        self.findings = state.findings;
        self.staged = state.staged.clone();
        self.applied_replace_preview = state.applied_replace_preview.clone();
        self.replace_changes = state.replace_changes.clone();
        self.audit_plan_fingerprint = state.audit_plan_fingerprint.clone();
        self.replace_generation = self
            .replace_generation
            .checked_add(1)
            .expect("replace generation exhausted");
        self.replace_artifact_generation = state.replace_artifact_generation;
        if let Staged::Replace { artifact, .. } = &mut self.staged {
            *artifact = None;
            self.replace_artifact_generation = None;
        }
        if matches!(self.staged, Staged::None) {
            self.replace_changes = None;
            self.applied_replace_preview = None;
        }
        self.sync_findings_count();
        self.refresh_missing_path_count_cache();
        Ok(())
    }
}

impl SceneRowEditState {
    fn same_as(&self, other: &Self) -> bool {
        self.status == other.status
            && self.findings == other.findings
            && self.staged.same_as(&other.staged)
            && self.applied_replace_preview == other.applied_replace_preview
            && self.replace_changes == other.replace_changes
            && self.replace_artifact_generation == other.replace_artifact_generation
    }
}

fn ascii_report_same(
    left: &Option<MayaAsciiConversionReport>,
    right: &Option<MayaAsciiConversionReport>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.output_path == right.output_path
                && left.scene_format == right.scene_format
                && left.operation_mode == right.operation_mode
                && left.validation_state == right.validation_state
                && left.raw_chunk_count == right.raw_chunk_count
                && left.raw_payload_size_total == right.raw_payload_size_total
                && left.unknown_payload_size_total == right.unknown_payload_size_total
                && left.decode_quality_distribution.len() == right.decode_quality_distribution.len()
                && left.issues.len() == right.issues.len()
                && left.raw_chunks.len() == right.raw_chunks.len()
                && left.unknown_inventory.len() == right.unknown_inventory.len()
        }
        _ => false,
    }
}

#[allow(clippy::large_enum_variant)]
enum SavePromotion {
    ToAscii,
    Unanalyzed,
    Reports(StagedReports),
}

impl SceneRow {
    fn save_promotion(&self) -> SavePromotion {
        match &self.staged {
            Staged::ToAscii { .. } => SavePromotion::ToAscii,
            Staged::None => SavePromotion::Unanalyzed,
            Staged::Replace { .. } | Staged::SceneEdits { .. } => {
                SavePromotion::Reports(self.staged.reports().clone())
            }
        }
    }
}

enum RowJobResult {
    Analyze(Box<AnalyzeRowResult>),
    ReauditStaged {
        report_generation: u64,
        plan_fingerprint: String,
        result: Result<Box<AnalyzeRowResult>, String>,
    },
    SceneEdits {
        source: maya_scene_kit_observe::scene::paths::SceneSourceFingerprint,
        clean_source: Option<maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>,
        replace_changes: Option<PathReplaceChanges>,
        replace_preview: Option<PathReplacePreview>,
        staged: CompositeSceneEditsStageResult,
        audit_mode: AuditModePreference,
        staged_audit_report: AuditReport,
        audit_plan_fingerprint: String,
        staged_paths_report: ScenePathsReport,
        staged_dump_report: SceneDumpReport,
        staged_source_bytes: Vec<u8>,
    },
    ToAscii {
        destination_source: Option<maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>,
        report: MayaAsciiConversionReport,
        artifact: StagedSceneArtifact,
    },
    Save {
        promotion: SavePromotion,
        observation_error: Option<String>,
        saved_paths_report: Option<ScenePathsReport>,
        replace_changes: Option<PathReplaceChanges>,
        replace_preview: Option<PathReplacePreview>,
        output_path: PathBuf,
        audit_file_state: Option<GuiFileState>,
    },
}

mod allowlist_manager_dialog;
mod audit_detail_dialog;
mod auto_analyze;
mod cache_maintenance;
mod cache_restore;
mod cache_write;
mod helpers;
mod ignore_dialog;
mod jobs;
mod max_bytes_dialog;
mod menu;
mod staged;
use staged::*;
mod mutation;
use mutation::*;
mod path;
mod path_edit;
mod persist_flush;
mod plugins;
mod render;
mod replace_dialog;
mod results;
mod shell;
mod tables;
mod workspace;

#[cfg(test)]
use self::tables::*;
#[cfg(test)]
use self::workspace::exit_warning_required_for_rows;
use self::{helpers::*, results::*};

#[cfg(test)]
mod tests;

fn badge(text: &str, background: u32, foreground: u32) -> impl IntoElement {
    div()
        .flex_shrink_0()
        .px_2()
        .py_1()
        .rounded_sm()
        .bg(rgb(background))
        .text_sm()
        .text_color(rgb(foreground))
        .whitespace_nowrap()
        .child(text.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowStateMark {
    Modified,
    Error,
    Saved,
}

impl RowStateMark {
    fn soft(self) -> u32 {
        match self {
            Self::Modified => WARN_SOFT,
            Self::Error => ERROR_SOFT,
            Self::Saved => SUCCESS_SOFT,
        }
    }

    fn strong(self) -> u32 {
        match self {
            Self::Modified => 0x8a6116,
            Self::Error => 0x8a3a32,
            Self::Saved => 0x256c2c,
        }
    }
}

fn state_badge(text: &str, mark: RowStateMark) -> impl IntoElement {
    div()
        .flex_shrink_0()
        .px_2()
        .rounded_sm()
        .border_1()
        .border_color(rgb(mark.strong()))
        .bg(rgb(mark.soft()))
        .text_sm()
        .text_color(rgb(mark.strong()))
        .whitespace_nowrap()
        .child(text.to_string())
}

fn icon_badge(icon: AppIconName, background: u32, foreground: u32) -> impl IntoElement {
    div()
        .px_1p5()
        .py_1()
        .rounded_sm()
        .bg(rgb(background))
        .text_color(rgb(foreground))
        .flex()
        .items_center()
        .justify_center()
        .child(Icon::new(icon).small())
}

fn path_kind_badge(kind: PathTypeFilter) -> impl IntoElement {
    let (background, foreground) = match kind {
        PathTypeFilter::Reference => (ACCENT_SOFT, ACCENT),
        PathTypeFilter::File => (WARN_SOFT, 0x8a6116),
    };

    div()
        .px_1p5()
        .py_1()
        .rounded_sm()
        .bg(rgb(background))
        .text_sm()
        .text_color(rgb(foreground))
        .flex()
        .items_center()
        .justify_center()
        .child(Icon::new(path_type_icon(kind)).small())
}

fn severity_label(i18n: &I18n, severity: AuditSeverity) -> String {
    match severity {
        AuditSeverity::Info => i18n.text("severity.info"),
        AuditSeverity::Low => i18n.text("severity.low"),
        AuditSeverity::Medium => i18n.text("severity.medium"),
        AuditSeverity::High => i18n.text("severity.high"),
        AuditSeverity::Critical => i18n.text("severity.critical"),
    }
}

fn audit_filter_label(i18n: &I18n, filter: AuditSeverityFilter) -> String {
    match filter {
        AuditSeverityFilter::Info => i18n.text("severity.info"),
        AuditSeverityFilter::Low => i18n.text("severity.low"),
        AuditSeverityFilter::MediumPlus => i18n.text("severity.medium_plus"),
    }
}

fn path_type_filter_label(i18n: &I18n, filter: PathTypeFilter) -> String {
    match filter {
        PathTypeFilter::Reference => i18n.text("path_type.reference"),
        PathTypeFilter::File => i18n.text("path_type.file"),
    }
}

fn path_form_filter_label(i18n: &I18n, filter: PathFormFilter) -> String {
    match filter {
        PathFormFilter::Rel => i18n.text("path_form.rel"),
        PathFormFilter::Abs => i18n.text("path_form.abs"),
    }
}

impl IconNamed for AppIconName {
    fn path(self) -> SharedString {
        match self {
            Self::GitPullRequestArrow => "icons/layers-2.svg",
            Self::FileImage => "icons/file-image.svg",
            Self::BadgeCheck => "icons/badge-check.svg",
            Self::FileQuestionMark => "icons/file-question-mark.svg",
        }
        .into()
    }
}

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        match path {
            "icons/layers-2.svg" => Ok(Some(Cow::Borrowed(include_bytes!(
                "../../resources/icons/layers-2.svg"
            )))),
            "icons/file-image.svg" => Ok(Some(Cow::Borrowed(include_bytes!(
                "../../resources/icons/file-image.svg"
            )))),
            "icons/badge-check.svg" => Ok(Some(Cow::Borrowed(include_bytes!(
                "../../resources/icons/badge-check.svg"
            )))),
            "icons/file-question-mark.svg" => Ok(Some(Cow::Borrowed(include_bytes!(
                "../../resources/icons/file-question-mark.svg"
            )))),
            _ => gpui_component_assets::Assets.load(path),
        }
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut entries = gpui_component_assets::Assets.list(path)?;
        if matches!(path, "" | "." | "icons") {
            entries.push("icons/layers-2.svg".into());
            entries.push("icons/file-image.svg".into());
            entries.push("icons/badge-check.svg".into());
            entries.push("icons/file-question-mark.svg".into());
        }
        entries.sort();
        entries.dedup();
        Ok(entries)
    }
}

fn path_type_icon(filter: PathTypeFilter) -> AppIconName {
    match filter {
        PathTypeFilter::Reference => AppIconName::GitPullRequestArrow,
        PathTypeFilter::File => AppIconName::FileImage,
    }
}

fn path_resolution_filter_label(i18n: &I18n, filter: PathResolutionBadge) -> String {
    match filter {
        PathResolutionBadge::Exists => i18n.text("label.path_exists"),
        PathResolutionBadge::Missing => i18n.text("label.path_missing"),
        PathResolutionBadge::Unresolved => i18n.text("label.path_unresolved"),
    }
}

fn path_resolution_icon(filter: PathResolutionBadge) -> Option<AppIconName> {
    match filter {
        PathResolutionBadge::Exists => Some(AppIconName::BadgeCheck),
        PathResolutionBadge::Missing => Some(AppIconName::FileQuestionMark),
        PathResolutionBadge::Unresolved => None,
    }
}

fn audit_severity_colors(severity: AuditSeverity) -> (u32, u32, u32) {
    match severity {
        AuditSeverity::Critical => (0xf7d5d2, 0xe7b8b1, 0x8a271e),
        AuditSeverity::High => (0xf8e1d0, 0xf0c39f, 0x994b00),
        AuditSeverity::Medium => (0xf5ead7, 0xe8d0a6, 0x8a6116),
        AuditSeverity::Low => (0xdff0f5, 0xb9dae2, 0x0f5f6d),
        AuditSeverity::Info => (0xe8e3da, 0xd0c6b8, 0x645a4d),
    }
}

fn audit_filter_colors(filter: AuditSeverityFilter) -> (u32, u32, u32) {
    match filter {
        AuditSeverityFilter::Info => audit_severity_colors(AuditSeverity::Info),
        AuditSeverityFilter::Low => audit_severity_colors(AuditSeverity::Low),
        AuditSeverityFilter::MediumPlus => audit_severity_colors(AuditSeverity::High),
    }
}

fn apply_app_theme_overrides(cx: &mut App) {
    let theme = Theme::global_mut(cx);
    theme.scrollbar_show = ScrollbarShow::Always;
    theme.overlay = if theme.is_dark() {
        rgba(0x88888888).into()
    } else {
        rgba(0x8888888d).into()
    };
}

fn init_gui_app(cx: &mut App) {
    gpui_component::init(cx);
    apply_app_theme_overrides(cx);
    crate::menu_bar::init(cx);
    cx.on_window_closed(|cx| {
        if cx.windows().is_empty() {
            cx.quit();
        }
    })
    .detach();
    cx.bind_keys([
        KeyBinding::new("ctrl-a", TableSelectAll, Some(TABLE_CONTEXT)),
        KeyBinding::new("cmd-a", TableSelectAll, Some(TABLE_CONTEXT)),
        KeyBinding::new("secondary-o", MenuSelectFolder, None),
        KeyBinding::new("f5", MenuReloadFolder, None),
        KeyBinding::new("secondary-s", MenuSaveSelected, None),
        KeyBinding::new("secondary-shift-s", MenuSaveAll, None),
        KeyBinding::new("ctrl-shift-z", MenuEditRedo, None),
        KeyBinding::new("ctrl-y", MenuEditRedo, None),
        KeyBinding::new("ctrl-z", MenuEditUndo, None),
        KeyBinding::new("secondary-f", FocusSearch, None),
        // Typing "/" inside any text input must still insert the character.
        KeyBinding::new("/", FocusSearch, Some("!Input")),
    ]);
    cx.set_menus(build_app_menus(
        &PersistedState::default(),
        &I18n::new(SupportedLocale::English),
        false,
        false,
    ));
}

pub fn run() {
    Application::new()
        .with_assets(AppAssets)
        .run(|cx: &mut App| {
            init_gui_app(cx);
            let bounds = Bounds::centered(None, size(px(1380.0), px(900.0)), cx);
            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    titlebar: Some(TitlebarOptions {
                        title: Some("Maya Scene File Audit Tool".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                |window, cx| {
                    let menu_bar = TopMenuBar::new(window, cx);
                    let shell = cx.new(|cx| GuiShell::new(menu_bar, window, cx));
                    let file_table = shell.read(cx).file_table.clone();
                    let file_table_for_sub = file_table.clone();
                    let path_table = shell.read(cx).path_table.clone();
                    let path_table_for_sub = path_table.clone();
                    let audit_table = shell.read(cx).audit_table.clone();
                    let audit_table_for_sub = audit_table.clone();
                    let shell_for_file_table = shell.clone();
                    let shell_for_path_table = shell.clone();
                    let shell_for_audit_table = shell.clone();
                    let shell_view = shell.clone();
                    shell.update(cx, |shell, cx| {
                        shell.refresh_app_menus(window, cx);
                        shell.bind_file_table(shell_view.clone(), cx);
                        shell.schedule_workspace_auto_analysis_if_enabled(window, cx);
                        cx.focus_self(window);
                    });
                    cx.subscribe(&file_table, move |_, event: &TableEvent, cx| match event {
                        TableEvent::SelectRow(_) => {
                            file_table_for_sub.update(cx, |table, cx| {
                                table.clear_selection(cx);
                            });
                        }
                        TableEvent::ColumnWidthsChanged(widths) => {
                            let widths = widths.clone();
                            let persisted_widths = file_table_for_sub.update(cx, |table, _| {
                                table.delegate_mut().apply_widths(&widths);
                                table.delegate().persisted_column_widths()
                            });
                            shell_for_file_table.update(cx, |shell, _| {
                                shell.set_file_table_column_widths(persisted_widths);
                            });
                        }
                        _ => {}
                    })
                    .detach();
                    cx.subscribe(&path_table, move |_, event: &TableEvent, cx| match event {
                        TableEvent::SelectRow(_) => {
                            path_table_for_sub.update(cx, |table, cx| {
                                table.clear_selection(cx);
                            });
                        }
                        TableEvent::ColumnWidthsChanged(widths) => {
                            let widths = widths.clone();
                            let persisted_widths = path_table_for_sub.update(cx, |table, _| {
                                table.delegate_mut().apply_widths(&widths);
                                table.delegate().persisted_column_widths()
                            });
                            shell_for_path_table.update(cx, |shell, _| {
                                shell.set_path_table_column_widths(persisted_widths);
                            });
                        }
                        _ => {}
                    })
                    .detach();
                    cx.subscribe(&audit_table, move |_, event: &TableEvent, cx| match event {
                        TableEvent::SelectRow(_) => {
                            audit_table_for_sub.update(cx, |table, cx| {
                                table.clear_selection(cx);
                            });
                        }
                        TableEvent::ColumnWidthsChanged(widths) => {
                            let widths = widths.clone();
                            let persisted_widths = audit_table_for_sub.update(cx, |table, _| {
                                table.delegate_mut().apply_widths(&widths);
                                table.delegate().persisted_column_widths()
                            });
                            shell_for_audit_table.update(cx, |shell, _| {
                                shell.set_audit_table_column_widths(persisted_widths);
                            });
                        }
                        _ => {}
                    })
                    .detach();
                    cx.new(|cx| Root::new(shell, window, cx))
                },
            )
            .expect("open gui shell");
            cx.activate(true);
        });
}
