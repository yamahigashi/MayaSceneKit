use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalePreference {
    #[default]
    System,
    English,
    Chinese,
    Japanese,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuditModePreference {
    #[default]
    StrictDefault,
    HardenedUntrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackupLocationPreference {
    SameDirectory,
    #[default]
    BackupFolder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLayoutPreference {
    #[default]
    TopBottom,
    LeftRight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AutoAnalyzeParallelismPreference {
    One,
    Two,
    #[default]
    Four,
    Eight,
    Sixteen,
    ThirtyTwo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SupportedLocale {
    #[default]
    English,
    Chinese,
    Japanese,
}

impl LocalePreference {
    pub fn resolve(self) -> SupportedLocale {
        match self {
            Self::System => detect_system_locale(),
            Self::English => SupportedLocale::English,
            Self::Chinese => SupportedLocale::Chinese,
            Self::Japanese => SupportedLocale::Japanese,
        }
    }
}

impl SupportedLocale {
    pub fn from_locale_tag(tag: &str) -> Self {
        let normalized = tag.trim().replace('_', "-").to_ascii_lowercase();
        if normalized.starts_with("zh") {
            return Self::Chinese;
        }
        if normalized.starts_with("ja") {
            return Self::Japanese;
        }
        Self::English
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResultTab {
    #[default]
    Overview,
    #[serde(alias = "dump")]
    Audit,
    Paths,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StatusFilter {
    #[default]
    All,
    Dirty,
    Error,
    Audited,
    Processing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedWorkspaceFile {
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentInput {
    pub path: PathBuf,
    #[serde(default)]
    pub was_directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryEntry {
    pub operation: String,
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub summary: String,
    #[serde(default)]
    pub failed: bool,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedTableColumnWidth {
    pub key: String,
    pub width_px: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(default)]
    pub workspace_root: Option<PathBuf>,
    #[serde(default)]
    pub locale: LocalePreference,
    #[serde(default)]
    pub audit_mode: AuditModePreference,
    #[serde(default)]
    pub backup_location: BackupLocationPreference,
    #[serde(default)]
    pub workspace_layout: WorkspaceLayoutPreference,
    #[serde(default)]
    pub workspace_auto_analyze: bool,
    #[serde(default)]
    pub auto_analyze_parallelism: AutoAnalyzeParallelismPreference,
    #[serde(default)]
    pub max_bytes: Option<usize>,
    #[serde(default = "default_ignore_folder_names_enabled")]
    pub ignore_folder_names_enabled: bool,
    #[serde(default = "default_ignored_folder_names")]
    pub ignored_folder_names: Vec<String>,
    #[serde(default)]
    pub active_tab: ResultTab,
    #[serde(default)]
    pub status_filter: StatusFilter,
    #[serde(default)]
    pub file_list_findings_only: bool,
    #[serde(default)]
    pub file_list_missing_only: bool,
    #[serde(default)]
    pub file_list_dirty_only: bool,
    #[serde(default)]
    pub search_query: String,
    #[serde(default)]
    pub workspace_files: Vec<PersistedWorkspaceFile>,
    #[serde(default)]
    pub recent_inputs: Vec<RecentInput>,
    #[serde(default)]
    pub job_history: Vec<JobHistoryEntry>,
    #[serde(default)]
    pub last_opened_input: Option<RecentInput>,
    #[serde(default)]
    pub file_table_column_widths: Vec<PersistedTableColumnWidth>,
    #[serde(default)]
    pub path_table_column_widths: Vec<PersistedTableColumnWidth>,
    #[serde(default)]
    pub audit_table_column_widths: Vec<PersistedTableColumnWidth>,
}

fn default_ignore_folder_names_enabled() -> bool {
    true
}

fn default_ignored_folder_names() -> Vec<String> {
    ["backup", "autosave"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub fn normalize_ignored_folder_name(name: &str) -> Option<String> {
    let normalized = name.trim();
    if normalized.is_empty() || matches!(normalized, "." | "..") || normalized.contains(['/', '\\'])
    {
        return None;
    }
    Some(normalized.to_string())
}

pub fn normalize_ignored_folder_names(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut normalized: Vec<String> = Vec::new();
    for name in names {
        let Some(name) = normalize_ignored_folder_name(&name) else {
            continue;
        };
        if normalized
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        normalized.push(name);
    }
    normalized
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            workspace_root: None,
            locale: LocalePreference::default(),
            audit_mode: AuditModePreference::default(),
            backup_location: BackupLocationPreference::default(),
            workspace_layout: WorkspaceLayoutPreference::default(),
            workspace_auto_analyze: false,
            auto_analyze_parallelism: AutoAnalyzeParallelismPreference::default(),
            max_bytes: None,
            ignore_folder_names_enabled: default_ignore_folder_names_enabled(),
            ignored_folder_names: default_ignored_folder_names(),
            active_tab: ResultTab::default(),
            status_filter: StatusFilter::default(),
            file_list_findings_only: false,
            file_list_missing_only: false,
            file_list_dirty_only: false,
            search_query: String::new(),
            workspace_files: Vec::new(),
            recent_inputs: Vec::new(),
            job_history: Vec::new(),
            last_opened_input: None,
            file_table_column_widths: Vec::new(),
            path_table_column_widths: Vec::new(),
            audit_table_column_widths: Vec::new(),
        }
    }
}

impl PersistedState {
    pub fn auto_analyze_parallelism_limit(&self) -> usize {
        self.auto_analyze_parallelism.limit()
    }

    pub fn normalize_ignore_folder_settings(&mut self) {
        self.ignored_folder_names =
            normalize_ignored_folder_names(std::mem::take(&mut self.ignored_folder_names));
    }

    pub fn set_ignored_folder_names(&mut self, names: Vec<String>) {
        self.ignored_folder_names = normalize_ignored_folder_names(names);
    }

    pub fn workspace_root_path(&self) -> Option<PathBuf> {
        self.workspace_root.clone()
    }

    pub fn workspace_paths(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for entry in &self.workspace_files {
            push_unique(&mut out, &entry.path);
        }

        if out.is_empty() {
            if let Some(input) = self.last_opened_input.as_ref() {
                push_unique(&mut out, &input.path);
            }
            for input in &self.recent_inputs {
                push_unique(&mut out, &input.path);
            }
        }

        out
    }

    pub fn replace_workspace_paths(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        self.workspace_files = paths
            .into_iter()
            .map(|path| PersistedWorkspaceFile { path })
            .collect();
    }

    pub fn set_workspace_root(&mut self, path: Option<PathBuf>) {
        self.workspace_root = path;
    }

    pub fn recent_folders(&self, limit: usize) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for input in &self.recent_inputs {
            if input.was_directory {
                push_unique(&mut out, &input.path);
            }
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    pub fn remove_recent_folder_by_display(
        &mut self,
        display: &str,
        limit: usize,
    ) -> Option<PathBuf> {
        let target = self
            .recent_folders(limit)
            .into_iter()
            .find(|path| path.display().to_string() == display)?;
        self.recent_inputs
            .retain(|input| !(input.was_directory && input.path == target));
        if self
            .last_opened_input
            .as_ref()
            .is_some_and(|input| input.was_directory && input.path == target)
        {
            self.last_opened_input = None;
        }
        Some(target)
    }
}

impl AutoAnalyzeParallelismPreference {
    pub const ALL: [Self; 6] = [
        Self::One,
        Self::Two,
        Self::Four,
        Self::Eight,
        Self::Sixteen,
        Self::ThirtyTwo,
    ];

    pub const fn limit(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
            Self::Sixteen => 16,
            Self::ThirtyTwo => 32,
        }
    }
}

fn push_unique(out: &mut Vec<PathBuf>, path: &Path) {
    if !out.iter().any(|existing| existing == path) {
        out.push(path.to_path_buf());
    }
}

pub fn bulk_enabled(selected_count: usize) -> bool {
    selected_count >= 1
}

pub fn save_enabled(dirty_count: usize) -> bool {
    dirty_count > 0
}

fn detect_system_locale() -> SupportedLocale {
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        let Some(value) = std::env::var_os(key) else {
            continue;
        };
        let tag = value.to_string_lossy();
        if !tag.trim().is_empty() {
            return SupportedLocale::from_locale_tag(&tag);
        }
    }
    SupportedLocale::English
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        AuditModePreference, AutoAnalyzeParallelismPreference, BackupLocationPreference,
        JobHistoryEntry, LocalePreference, PersistedState, RecentInput, ResultTab, StatusFilter,
        SupportedLocale, WorkspaceLayoutPreference, normalize_ignored_folder_name,
        normalize_ignored_folder_names, save_enabled,
    };

    #[test]
    fn locale_preference_resolves_explicit_overrides() {
        assert_eq!(
            LocalePreference::English.resolve(),
            SupportedLocale::English
        );
        assert_eq!(
            LocalePreference::Chinese.resolve(),
            SupportedLocale::Chinese
        );
        assert_eq!(
            LocalePreference::Japanese.resolve(),
            SupportedLocale::Japanese
        );
    }

    #[test]
    fn supported_locale_parses_system_tags() {
        assert_eq!(
            SupportedLocale::from_locale_tag("zh_CN.UTF-8"),
            SupportedLocale::Chinese
        );
        assert_eq!(
            SupportedLocale::from_locale_tag("ja_JP.UTF-8"),
            SupportedLocale::Japanese
        );
        assert_eq!(
            SupportedLocale::from_locale_tag("en-US"),
            SupportedLocale::English
        );
        assert_eq!(
            SupportedLocale::from_locale_tag("fr_FR"),
            SupportedLocale::English
        );
    }

    #[test]
    fn workspace_paths_falls_back_to_legacy_state() {
        let state = PersistedState {
            workspace_root: Some(PathBuf::from("tests/02")),
            locale: LocalePreference::Japanese,
            audit_mode: AuditModePreference::HardenedUntrusted,
            backup_location: BackupLocationPreference::BackupFolder,
            workspace_layout: WorkspaceLayoutPreference::TopBottom,
            workspace_auto_analyze: true,
            auto_analyze_parallelism: AutoAnalyzeParallelismPreference::Four,
            max_bytes: None,
            ignore_folder_names_enabled: true,
            ignored_folder_names: vec!["backup".to_string(), "autosave".to_string()],
            active_tab: ResultTab::Audit,
            status_filter: StatusFilter::Dirty,
            file_list_findings_only: false,
            file_list_missing_only: false,
            file_list_dirty_only: false,
            search_query: String::new(),
            workspace_files: vec![],
            recent_inputs: vec![
                RecentInput {
                    path: PathBuf::from("tests/02/sphere.ma"),
                    was_directory: false,
                },
                RecentInput {
                    path: PathBuf::from("tests/02/sphere.mb"),
                    was_directory: false,
                },
            ],
            job_history: vec![JobHistoryEntry {
                operation: "audit".into(),
                input: PathBuf::from("tests/02/sphere.mb"),
                output: None,
                summary: "ok".into(),
                failed: false,
                timestamp: None,
            }],
            last_opened_input: Some(RecentInput {
                path: PathBuf::from("tests/02/sphere.ma"),
                was_directory: false,
            }),
            file_table_column_widths: Vec::new(),
            path_table_column_widths: Vec::new(),
            audit_table_column_widths: Vec::new(),
        };

        assert_eq!(state.workspace_root_path(), Some(PathBuf::from("tests/02")));

        assert_eq!(
            state.workspace_paths(),
            vec![
                PathBuf::from("tests/02/sphere.ma"),
                PathBuf::from("tests/02/sphere.mb")
            ]
        );
    }

    #[test]
    fn enablement_rules_match_workspace_contract() {
        assert!(save_enabled(1));
        assert!(!save_enabled(0));
    }

    #[test]
    fn persisted_state_default_enables_configured_ignore_folder_names() {
        let state = PersistedState::default();
        assert_eq!(
            state.auto_analyze_parallelism,
            AutoAnalyzeParallelismPreference::Four
        );
        assert_eq!(state.auto_analyze_parallelism_limit(), 4);
        assert!(state.ignore_folder_names_enabled);
        assert_eq!(state.ignored_folder_names, vec!["backup", "autosave"]);
    }

    #[test]
    fn auto_analyze_parallelism_limits_match_supported_presets() {
        assert_eq!(
            AutoAnalyzeParallelismPreference::ALL.map(AutoAnalyzeParallelismPreference::limit),
            [1, 2, 4, 8, 16, 32]
        );
    }

    #[test]
    fn ignore_folder_name_normalization_rejects_invalid_values() {
        assert_eq!(
            normalize_ignored_folder_name(" backup "),
            Some("backup".to_string())
        );
        assert_eq!(normalize_ignored_folder_name(""), None);
        assert_eq!(normalize_ignored_folder_name("."), None);
        assert_eq!(normalize_ignored_folder_name(".."), None);
        assert_eq!(normalize_ignored_folder_name("cache/tmp"), None);
        assert_eq!(normalize_ignored_folder_name("cache\\tmp"), None);
    }

    #[test]
    fn ignore_folder_names_normalization_deduplicates_case_insensitively() {
        assert_eq!(
            normalize_ignored_folder_names(vec![
                " backup ".to_string(),
                "AUTOSAVE".to_string(),
                "backup".to_string(),
                "cache".to_string(),
                String::new(),
            ]),
            vec![
                "backup".to_string(),
                "AUTOSAVE".to_string(),
                "cache".to_string()
            ]
        );
    }

    #[test]
    fn workspace_layout_default_is_top_bottom() {
        assert_eq!(
            WorkspaceLayoutPreference::default(),
            WorkspaceLayoutPreference::TopBottom
        );
        assert_eq!(
            PersistedState::default().workspace_layout,
            WorkspaceLayoutPreference::TopBottom
        );
    }

    #[test]
    fn recent_folders_filters_non_directories_and_limits_results() {
        let state = PersistedState {
            recent_inputs: (0..12)
                .map(|ix| RecentInput {
                    path: PathBuf::from(format!("tests/{ix:02}")),
                    was_directory: ix % 2 == 0,
                })
                .collect(),
            ..PersistedState::default()
        };

        assert_eq!(
            state.recent_folders(4),
            vec![
                PathBuf::from("tests/00"),
                PathBuf::from("tests/02"),
                PathBuf::from("tests/04"),
                PathBuf::from("tests/06"),
            ]
        );
    }

    #[test]
    fn remove_recent_folder_by_display_removes_matching_directory_entry() {
        let mut state = PersistedState {
            recent_inputs: vec![
                RecentInput {
                    path: PathBuf::from("tests/00"),
                    was_directory: true,
                },
                RecentInput {
                    path: PathBuf::from("tests/02"),
                    was_directory: true,
                },
            ],
            ..PersistedState::default()
        };

        assert_eq!(
            state.remove_recent_folder_by_display("tests/02", 10),
            Some(PathBuf::from("tests/02"))
        );
        assert_eq!(state.recent_folders(10), vec![PathBuf::from("tests/00")]);
    }
}
