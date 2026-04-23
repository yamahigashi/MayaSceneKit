use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fs, io,
    ops::Range,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use chrono::Local;
use gpui::{prelude::*, *};
use gpui_component::{
    Disableable, Icon, IconName, IconNamed, Root, Sizable, WindowExt,
    button::{Button, ButtonVariants},
    dialog::Dialog,
    input::{Input, InputEvent, InputState},
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
        audit_observation, audit_script_nodes_with_options,
        build_parse_budget_blocked_audit_report, build_script_audit_plan,
    },
    scene::{
        AuditCacheAccess, AuditCacheStore, AuditEvidence, AuditFindingDetail, AuditOptions,
        AuditReport, AuditSeverity, AuditedSceneSnapshot, StaticAuditFindingDetail,
        fingerprint_audit_plan,
    },
};
use maya_scene_kit_edit::scene::{
    CompositeSceneEditsStageResult, ExecutionCleanPreview, ExecutionCleanTarget,
    MayaAsciiConversionReport, PathOwnerDeletePreview, PathOwnerDeleteTarget, PathReplaceMode,
    PathReplaceOverride, PathReplacePreview, PathReplaceRule, StagedSceneArtifact,
    clean_target_for_execution_origin, collect_raw_chunks,
    preview_replace_scene_path_candidates_in_report_with_options,
    preview_replace_scene_paths_with_overrides_in_report_with_options, save_staged_artifact,
    stage_maya_ascii_with_options, stage_replace_scene_paths_with_overrides_in_report_with_options,
    stage_scene_edits_in_report_with_bytes_with_options, stage_scene_edits_with_options,
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, ObserveCacheAccess, ObserveCacheStore, ObservedSceneSnapshot,
    collect_scene_paths_with_options,
    core::{SceneFormat, ValidationState},
    dump::{SceneDumpReport, SceneDumpRequireEntry, SceneDumpRequireKind},
    evidence::{ExecutionOrigin, ExecutionSurfaceKind},
    find_scene_workspace_root,
    paths::{
        PathKind, ScenePathResolution, ScenePathResolutionStatus, ScenePathValueStyle,
        ScenePathsReport,
    },
    resolve_scene_path_value, resolve_scene_path_values_batch,
};
use serde::Deserialize;

use crate::{
    default_analysis_cache_root,
    i18n::I18n,
    menu_bar::TopMenuBar,
    model::{
        AuditModePreference, AutoAnalyzeParallelismPreference, BackupLocationPreference,
        JobHistoryEntry, LocalePreference, PersistedState, PersistedTableColumnWidth, RecentInput,
        ResultTab, StatusFilter, SupportedLocale, WorkspaceLayoutPreference, bulk_enabled,
        normalize_ignored_folder_name, save_enabled,
    },
    persistence::{load_persisted_state, save_persisted_state},
};

actions!(
    gui_menu,
    [
        MenuSelectFolder,
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
        FileTableSelectAll,
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
const AUDIT_RESULTS_PER_FILE: usize = 16;
const AUTO_ANALYZE_DEBOUNCE: Duration = Duration::from_millis(150);
const FILE_DIALOG_UI_BLOCK_RELEASE_DELAY: Duration = Duration::from_millis(300);
const MAX_RECENT_FOLDERS: usize = 10;
const FILE_TABLE_CONTEXT: &str = "Table";

struct AppAssets;

#[derive(Clone, Copy)]
enum AppIconName {
    GitPullRequestArrow,
    FileImage,
    BadgeCheck,
    FileQuestionMark,
}

struct GuiShell {
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
    path_table_summary: PathTableSummary,
    audit_table: Entity<TableState<AuditTableDelegate>>,
    audit_all_rows: Vec<AuditResultRow>,
    audit_rows: Vec<AuditTableRow>,
    file_sort: FileTableSort,
    path_sort: PathTableSort,
    path_order_snapshot: Option<PathOrderSnapshot>,
    audit_sort: AuditTableSort,
    next_row_id: u64,
    selection_anchor: Option<usize>,
    selected_auto_analyze_generation: u64,
    workspace_auto_analyze_generation: u64,
    file_dialog_block_generation: u64,
    auto_analyze_queue: AutoAnalyzeQueueState,
    file_dialog_ui_blocked: bool,
    save_jobs_in_flight: usize,
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
    status_message: Option<BannerMessage>,
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
    status: FileStatus,
    findings: usize,
    clean_preview: Option<ExecutionCleanPreview>,
    replace_preview: Option<PathReplacePreview>,
    ascii_report: Option<MayaAsciiConversionReport>,
    path_owner_delete_preview: Option<PathOwnerDeletePreview>,
    dirty_artifact: Option<StagedSceneArtifact>,
    dirty_kind: Option<DirtyKind>,
    pending_clean_targets: BTreeSet<ExecutionCleanTarget>,
    pending_path_owner_delete_targets: BTreeSet<PathOwnerDeleteTarget>,
    staged_audit_mode: Option<AuditModePreference>,
    staged_audit_report: Option<AuditReport>,
    staged_paths_report: Option<ScenePathsReport>,
    staged_dump_report: Option<SceneDumpReport>,
    staged_source_bytes: Option<Vec<u8>>,
    path_overrides: BTreeMap<usize, String>,
    replace_generation: u64,
    replace_artifact_generation: Option<u64>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditResultRow {
    key: AuditResultRowKey,
    scene_name: String,
    severity: AuditSeverity,
    summary: String,
    code: String,
    sink: String,
    preview: String,
    provenance: Vec<String>,
    source_line: Option<usize>,
    evidence: Vec<String>,
    dirty: bool,
    clean_target: Option<ExecutionCleanTarget>,
    clean_state: AuditRowCleanState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditTableRow {
    key: AuditResultRowKey,
    row_keys: Vec<AuditResultRowKey>,
    selected: bool,
    scene_name: String,
    scene_names: Vec<String>,
    severity: AuditSeverity,
    summary: String,
    code: String,
    sink: String,
    preview: String,
    provenance: Vec<String>,
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

#[derive(Clone, Debug)]
struct AuditDetailDialogState {
    key: AuditResultRowKey,
    preview_input: Entity<InputState>,
    preview_text: String,
    evidence_input: Entity<InputState>,
    evidence_text: String,
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
    findings: usize,
    scene_workspace_root: Option<PathBuf>,
    audit_report: Option<AuditReport>,
    paths_report: Option<ScenePathsReport>,
    dump_report: Option<SceneDumpReport>,
    analyzed_audit_mode: Option<AuditModePreference>,
    clean_preview: Option<ExecutionCleanPreview>,
    replace_preview: Option<PathReplacePreview>,
    ascii_report: Option<MayaAsciiConversionReport>,
    path_owner_delete_preview: Option<PathOwnerDeletePreview>,
    dirty_artifact: Option<StagedSceneArtifact>,
    dirty_kind: Option<DirtyKind>,
    pending_clean_targets: BTreeSet<ExecutionCleanTarget>,
    pending_path_owner_delete_targets: BTreeSet<PathOwnerDeleteTarget>,
    staged_audit_mode: Option<AuditModePreference>,
    staged_audit_report: Option<AuditReport>,
    staged_paths_report: Option<ScenePathsReport>,
    staged_dump_report: Option<SceneDumpReport>,
    staged_source_bytes: Option<Vec<u8>>,
    path_overrides: BTreeMap<usize, String>,
    path_resolution_cache: BTreeMap<usize, PathResolutionCacheEntry>,
    missing_path_count_cache: Option<usize>,
    path_resolution_revision: u64,
    replace_generation: u64,
    replace_artifact_generation: Option<u64>,
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
enum AuditSortKey {
    Scene,
    Severity,
    Summary,
    Code,
    Sink,
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
    Clean,
    DeleteOwnerNodes,
    Replace,
    ToAscii,
    Save,
}

enum BannerMessage {
    PersistFailed(String),
    CachePurged,
    WorkspaceLoaded { count: usize, path: PathBuf },
    AnalyzeCompleted { name: String, elapsed: Duration },
    WorkspaceAutoAnalyzeCompleted { count: usize, elapsed: Duration },
    WorkspaceCleared,
    InlinePathEditFailed(String),
    SelectFilesFirst,
    Raw(String),
    NothingDirtyToSave,
    NothingSelectedDirtyToSave,
    NothingToUndo,
    NothingToRedo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirtyKind {
    SceneEdits,
    Replace,
    ToAscii,
}

struct AnalyzeRowResult {
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
    Processing(RowOperation),
    Audited,
    Dirty,
    Saved,
    Error(String),
}

impl FileStatus {
    fn is_processing(&self) -> bool {
        matches!(self, Self::Processing(_))
    }

    fn filter_matches(&self, filter: StatusFilter) -> bool {
        match filter {
            StatusFilter::All => true,
            StatusFilter::Dirty => matches!(self, Self::Dirty),
            StatusFilter::Error => matches!(self, Self::Error(_)),
            StatusFilter::Audited => matches!(self, Self::Audited | Self::Saved),
            StatusFilter::Processing => matches!(self, Self::Processing(_)),
        }
    }

    fn label(&self, i18n: &I18n) -> String {
        match self {
            Self::Idle => i18n.text("file_status.idle"),
            Self::Processing(operation) => operation_label(i18n, *operation),
            Self::Audited => i18n.text("file_status.audited"),
            Self::Dirty => i18n.text("file_status.dirty"),
            Self::Saved => i18n.text("file_status.saved"),
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
            Self::Dirty => WARN_SOFT,
            Self::Saved => SUCCESS_SOFT,
            Self::Error(_) => ERROR_SOFT,
            Self::Processing(_) => PANEL_ALT_BG,
            Self::Idle | Self::Audited => PANEL_BG,
        }
    }
}

impl ReplaceDialogState {
    fn invalidate_preview(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.is_previewing = false;
        self.preview_signature = None;
        self.preview = None;
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
            findings: 0,
            scene_workspace_root: None,
            audit_report: None,
            paths_report: None,
            dump_report: None,
            analyzed_audit_mode: None,
            clean_preview: None,
            replace_preview: None,
            ascii_report: None,
            path_owner_delete_preview: None,
            dirty_artifact: None,
            dirty_kind: None,
            pending_clean_targets: BTreeSet::new(),
            pending_path_owner_delete_targets: BTreeSet::new(),
            staged_audit_mode: None,
            staged_audit_report: None,
            staged_paths_report: None,
            staged_dump_report: None,
            staged_source_bytes: None,
            path_overrides: BTreeMap::new(),
            path_resolution_cache: BTreeMap::new(),
            missing_path_count_cache: None,
            path_resolution_revision: 0,
            replace_generation: 0,
            replace_artifact_generation: None,
        }
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

        let workspace_root = self.scene_workspace_root.as_deref();
        let effective_values = report
            .entries
            .iter()
            .enumerate()
            .map(|(entry_index, entry)| {
                (
                    entry_index,
                    self.path_overrides
                        .get(&entry_index)
                        .cloned()
                        .unwrap_or_else(|| entry.value.clone()),
                )
            })
            .collect::<Vec<_>>();
        let resolutions = resolve_scene_path_values_batch(
            effective_values
                .iter()
                .map(|(_, effective_value)| effective_value.as_str()),
            workspace_root,
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
                        .path_overrides
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
        Some(resolve_scene_path_value(
            effective_value,
            self.scene_workspace_root.as_deref(),
        ))
    }

    fn dirty(&self) -> bool {
        self.dirty_artifact.is_some()
            || !self.path_overrides.is_empty()
            || !self.pending_clean_targets.is_empty()
            || !self.pending_path_owner_delete_targets.is_empty()
    }

    fn effective_findings_count(&self) -> usize {
        self.staged_audit_report
            .as_ref()
            .map(|report| report.findings.len())
            .or_else(|| {
                self.audit_report
                    .as_ref()
                    .map(|report| report.findings.len())
            })
            .unwrap_or(self.findings)
    }

    fn sync_findings_count(&mut self) {
        self.findings = self.effective_findings_count();
    }

    fn display_audit_report(&self) -> Option<&AuditReport> {
        self.audit_report.as_ref()
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
        matches!(self.dirty_kind, Some(DirtyKind::SceneEdits))
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
        self.status.is_processing()
    }

    fn replace_artifact_is_current(&self) -> bool {
        self.dirty_kind == Some(DirtyKind::Replace)
            && !self.path_overrides.is_empty()
            && self.dirty_artifact.is_some()
            && self.replace_artifact_generation == Some(self.replace_generation)
    }

    fn edit_state(&self) -> SceneRowEditState {
        SceneRowEditState {
            status: self.status.clone(),
            findings: self.findings,
            clean_preview: self.clean_preview.clone(),
            replace_preview: self.replace_preview.clone(),
            ascii_report: self.ascii_report.clone(),
            path_owner_delete_preview: self.path_owner_delete_preview.clone(),
            dirty_artifact: self.dirty_artifact.clone(),
            dirty_kind: self.dirty_kind,
            pending_clean_targets: self.pending_clean_targets.clone(),
            pending_path_owner_delete_targets: self.pending_path_owner_delete_targets.clone(),
            staged_audit_mode: self.staged_audit_mode,
            staged_audit_report: self.staged_audit_report.clone(),
            staged_paths_report: self.staged_paths_report.clone(),
            staged_dump_report: self.staged_dump_report.clone(),
            staged_source_bytes: self.staged_source_bytes.clone(),
            path_overrides: self.path_overrides.clone(),
            replace_generation: self.replace_generation,
            replace_artifact_generation: self.replace_artifact_generation,
        }
    }

    fn apply_edit_state(&mut self, state: &SceneRowEditState) {
        self.status = state.status.clone();
        self.findings = state.findings;
        self.clean_preview = state.clean_preview.clone();
        self.replace_preview = state.replace_preview.clone();
        self.ascii_report = state.ascii_report.clone();
        self.path_owner_delete_preview = state.path_owner_delete_preview.clone();
        self.dirty_artifact = state.dirty_artifact.clone();
        self.dirty_kind = state.dirty_kind;
        self.pending_clean_targets = state.pending_clean_targets.clone();
        self.pending_path_owner_delete_targets = state.pending_path_owner_delete_targets.clone();
        self.staged_audit_mode = state.staged_audit_mode;
        self.staged_audit_report = state.staged_audit_report.clone();
        self.staged_paths_report = state.staged_paths_report.clone();
        self.staged_dump_report = state.staged_dump_report.clone();
        self.staged_source_bytes = state.staged_source_bytes.clone();
        self.path_overrides = state.path_overrides.clone();
        self.replace_generation = state.replace_generation;
        self.replace_artifact_generation = state.replace_artifact_generation;
        self.sync_findings_count();
        self.refresh_missing_path_count_cache();
    }
}

impl SceneRowEditState {
    fn same_as(&self, other: &Self) -> bool {
        self.status == other.status
            && self.findings == other.findings
            && self.clean_preview == other.clean_preview
            && self.replace_preview == other.replace_preview
            && self.path_owner_delete_preview == other.path_owner_delete_preview
            && self.dirty_artifact == other.dirty_artifact
            && self.dirty_kind == other.dirty_kind
            && self.pending_clean_targets == other.pending_clean_targets
            && self.pending_path_owner_delete_targets == other.pending_path_owner_delete_targets
            && self.staged_audit_mode == other.staged_audit_mode
            && self.path_overrides == other.path_overrides
            && self.replace_generation == other.replace_generation
            && self.replace_artifact_generation == other.replace_artifact_generation
            && ascii_report_same(&self.ascii_report, &other.ascii_report)
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
enum RowJobResult {
    Analyze(AnalyzeRowResult),
    SceneEdits {
        staged: CompositeSceneEditsStageResult,
        audit_mode: AuditModePreference,
        staged_audit_report: AuditReport,
        staged_paths_report: ScenePathsReport,
        staged_dump_report: SceneDumpReport,
        staged_source_bytes: Vec<u8>,
    },
    ToAscii {
        report: MayaAsciiConversionReport,
        artifact: StagedSceneArtifact,
    },
    Save {
        output_path: PathBuf,
    },
}

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
mod path;
mod path_edit;
mod persist_flush;
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
        KeyBinding::new("ctrl-a", FileTableSelectAll, Some(FILE_TABLE_CONTEXT)),
        KeyBinding::new("cmd-a", FileTableSelectAll, Some(FILE_TABLE_CONTEXT)),
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
