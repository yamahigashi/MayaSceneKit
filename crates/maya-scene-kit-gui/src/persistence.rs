use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::model::PersistedState;

const APP_DIR: &str = "maya-scene-kit";
const STATE_FILE: &str = "gui-state.json";
const ANALYSIS_CACHE_DIR: &str = "analysis-cache";

pub fn app_allowlist_path(exe_path: Option<&Path>) -> Option<PathBuf> {
    exe_path
        .and_then(Path::parent)
        .map(|parent| parent.join("allowlist.json"))
}

pub fn user_allowlist_path(state_path: &Path) -> Option<PathBuf> {
    state_path
        .parent()
        .map(|parent| parent.join("allowlist.json"))
}

#[derive(Debug)]
pub struct AllowlistLoadError {
    pub path: PathBuf,
    pub error: String,
}

pub struct LoadedAllowlists {
    pub allowlist: maya_scene_kit_audit::scene::AuditAllowlist,
    pub errors: Vec<AllowlistLoadError>,
}

pub fn load_allowlists(app_path: Option<&Path>, user_path: Option<&Path>) -> LoadedAllowlists {
    use maya_scene_kit_audit::scene::{AllowlistSource, AuditAllowlist};
    let mut errors = Vec::new();
    let mut load = |path: Option<&Path>, source| {
        let Some(path) = path else {
            return AuditAllowlist::default();
        };
        let result = match fs::read_to_string(path) {
            Ok(text) => {
                AuditAllowlist::from_json(text.strip_prefix('\u{feff}').unwrap_or(&text), source)
                    .map_err(|error| error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return AuditAllowlist::default();
            }
            Err(error) => Err(error.to_string()),
        };
        result.unwrap_or_else(|error| {
            errors.push(AllowlistLoadError {
                path: path.to_path_buf(),
                error,
            });
            AuditAllowlist::default()
        })
    };
    let app = load(app_path, AllowlistSource::App);
    let user = load(user_path, AllowlistSource::User);
    LoadedAllowlists {
        allowlist: AuditAllowlist::merge([app, user]),
        errors,
    }
}

pub fn default_state_path() -> PathBuf {
    if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata).join(APP_DIR).join(STATE_FILE);
        }
    }

    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(config_home).join(APP_DIR).join(STATE_FILE);
    }

    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join(APP_DIR)
            .join(STATE_FILE);
    }

    PathBuf::from(STATE_FILE)
}

pub fn default_analysis_cache_root() -> PathBuf {
    if cfg!(windows) {
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local_appdata)
                .join(APP_DIR)
                .join(ANALYSIS_CACHE_DIR);
        }
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata)
                .join(APP_DIR)
                .join(ANALYSIS_CACHE_DIR);
        }
    }

    if let Some(cache_home) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(cache_home)
            .join(APP_DIR)
            .join(ANALYSIS_CACHE_DIR);
    }

    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join(APP_DIR)
            .join(ANALYSIS_CACHE_DIR);
    }

    PathBuf::from(ANALYSIS_CACHE_DIR)
}

pub fn load_persisted_state() -> io::Result<PersistedState> {
    match load_persisted_state_from(&default_state_path()) {
        Ok(state) => Ok(state),
        Err(err) if err.kind() == io::ErrorKind::InvalidData => Ok(PersistedState::default()),
        Err(err) => Err(err),
    }
}

pub fn save_persisted_state(state: &PersistedState) -> io::Result<()> {
    save_persisted_state_to(&default_state_path(), state)
}

fn load_persisted_state_from(path: &Path) -> io::Result<PersistedState> {
    match fs::read(path) {
        Ok(bytes) => {
            let mut state: PersistedState = serde_json::from_slice(&bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            state.normalize_ignore_folder_settings();
            Ok(state)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(PersistedState::default()),
        Err(err) => Err(err),
    }
}

fn save_persisted_state_to(path: &Path, state: &PersistedState) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut normalized = state.clone();
    normalized.normalize_ignore_folder_settings();
    let payload = serde_json::to_vec_pretty(&normalized)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    fs::write(path, payload)
}

#[cfg(test)]
mod tests {
    use std::{fs, io, path::PathBuf};

    use tempfile::tempdir;

    use super::{load_persisted_state_from, save_persisted_state_to};
    use crate::model::{
        AuditModePreference, AutoAnalyzeParallelismPreference, BackupLocationPreference,
        JobHistoryEntry, LocalePreference, PersistedState, PersistedTableColumnWidth,
        PersistedWorkspaceFile, RecentInput, ResultTab, StatusFilter, WorkspaceLayoutPreference,
    };

    #[test]
    fn allowlist_paths_are_pure_and_preserve_relative_parents() {
        use super::{app_allowlist_path, user_allowlist_path};
        use std::path::Path;
        assert_eq!(
            app_allowlist_path(Some(Path::new("Example/bin/ExampleApp"))),
            Some("Example/bin/allowlist.json".into())
        );
        assert_eq!(
            user_allowlist_path(Path::new("Example/config/gui-state.json")),
            Some("Example/config/allowlist.json".into())
        );
        assert_eq!(app_allowlist_path(None), None);
        assert_eq!(
            user_allowlist_path(Path::new("gui-state.json")),
            Some("allowlist.json".into())
        );
    }

    #[test]
    fn allowlist_loading_is_layered_and_reports_only_failed_layers() {
        use super::load_allowlists;
        let dir = tempdir().unwrap();
        let app = dir.path().join("ExampleApp/allowlist.json");
        let user = dir.path().join("ExampleUser/allowlist.json");
        let missing = load_allowlists(Some(&app), Some(&user));
        assert_eq!(missing.allowlist.len_entries(), 0);
        assert!(missing.errors.is_empty());
        let absent = load_allowlists(None, None);
        assert!(absent.allowlist.is_empty());
        assert!(absent.errors.is_empty());
        fs::create_dir_all(app.parent().unwrap()).unwrap();
        fs::create_dir_all(user.parent().unwrap()).unwrap();
        let h1 = format!("sha256:{}", "11".repeat(32));
        let h2 = format!("sha256:{}", "22".repeat(32));
        let entry = serde_json::json!({"hash":h1,"codes":["mel_exec"],"label":"Example","preview":"Example preview","reason":"Example reason","added_at":"2026-11-07","added_by":"Example"});
        let app_json = serde_json::json!({"version":1,"entries":[entry]}).to_string();
        fs::write(&app, &app_json).unwrap();
        fs::write(&user, "{").unwrap();
        let invalid = load_allowlists(Some(&app), Some(&user));
        assert_eq!(invalid.allowlist.len_entries(), 1);
        assert_eq!(invalid.errors.len(), 1);
        assert_eq!(invalid.errors[0].path, user);
        assert!(invalid.errors[0].error.contains("invalid allowlist JSON"));
        let user_json = serde_json::json!({"version":1,"entries":[
            {"hash":h1,"codes":["mel_exec","mel_eval"],"label":"Sample","preview":"Sample","reason":"Sample","added_at":"Sample","added_by":"Sample"},
            {"hash":h2,"codes":["mel_exec"]}
        ]}).to_string();
        fs::write(&user, user_json).unwrap();
        let valid = load_allowlists(Some(&app), Some(&user));
        assert_eq!(valid.allowlist.len_entries(), 2);
        assert!(valid.errors.is_empty());
        let expected = maya_scene_kit_audit::scene::AuditAllowlist::merge([
            maya_scene_kit_audit::scene::AuditAllowlist::from_json(
                &app_json,
                maya_scene_kit_audit::scene::AllowlistSource::App,
            )
            .unwrap(),
            maya_scene_kit_audit::scene::AuditAllowlist::from_json(
                &serde_json::json!({"version":1,"entries":[
                    {"hash":h1,"codes":["mel_eval"]}, {"hash":h2,"codes":["mel_exec"]}
                ]})
                .to_string(),
                maya_scene_kit_audit::scene::AllowlistSource::User,
            )
            .unwrap(),
        ]);
        let plan = maya_scene_kit_audit::audit::build_script_audit_plan(vec![], 64).unwrap();
        assert_eq!(
            maya_scene_kit_audit::scene::fingerprint_audit_plan(
                &plan.clone().with_allowlist(valid.allowlist.clone())
            ),
            maya_scene_kit_audit::scene::fingerprint_audit_plan(&plan.with_allowlist(expected)),
        );
        assert_eq!(
            valid
                .allowlist
                .entry_metadata(&h1.parse().unwrap())
                .unwrap()
                .reason
                .as_deref(),
            Some("Example reason")
        );
        fs::write(&app, format!("\u{feff}{app_json}")).unwrap();
        let bom = load_allowlists(Some(&app), None);
        assert_eq!(bom.allowlist.len_entries(), 1);
        assert!(bom.errors.is_empty());
        fs::remove_file(&user).unwrap();
        fs::create_dir(&user).unwrap();
        let unreadable = load_allowlists(Some(&app), Some(&user));
        assert_eq!(unreadable.allowlist.len_entries(), 1);
        assert_eq!(unreadable.errors.len(), 1);
        assert_eq!(unreadable.errors[0].path, user);
    }

    #[test]
    fn persistence_round_trips_workspace_state() {
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("gui-state.json");
        let state = PersistedState {
            workspace_root: Some(PathBuf::from("tests/02")),
            locale: LocalePreference::Japanese,
            audit_mode: AuditModePreference::HardenedUntrusted,
            backup_location: BackupLocationPreference::SameDirectory,
            workspace_layout: WorkspaceLayoutPreference::LeftRight,
            workspace_auto_analyze: true,
            auto_analyze_parallelism: AutoAnalyzeParallelismPreference::ThirtyTwo,
            analysis_cache_enabled: false,
            max_bytes: Some(123456789),
            ignore_folder_names_enabled: false,
            ignored_folder_names: vec!["cache".to_string(), "publish".to_string()],
            active_tab: ResultTab::Audit,
            status_filter: StatusFilter::Dirty,
            file_list_findings_only: true,
            file_list_missing_only: false,
            file_list_no_workspace_only: true,
            file_list_dirty_only: true,
            search_query: "env".to_string(),
            workspace_files: vec![PersistedWorkspaceFile {
                path: PathBuf::from("tests/02/sphere.mb"),
            }],
            recent_inputs: vec![RecentInput {
                path: PathBuf::from("tests/02/sphere.mb"),
                was_directory: false,
            }],
            job_history: vec![JobHistoryEntry {
                operation: "audit".to_string(),
                input: PathBuf::from("tests/02/sphere.mb"),
                output: None,
                summary: "ok".to_string(),
                failed: false,
                timestamp: Some("2026-03-25T12:00:00Z".to_string()),
            }],
            last_opened_input: None,
            file_table_column_widths: vec![PersistedTableColumnWidth {
                key: "name".to_string(),
                width_px: 640,
            }],
            path_table_column_widths: vec![PersistedTableColumnWidth {
                key: "path".to_string(),
                width_px: 720,
            }],
            audit_table_column_widths: vec![PersistedTableColumnWidth {
                key: "summary".to_string(),
                width_px: 360,
            }],
        };

        save_persisted_state_to(&path, &state).expect("save state");
        let restored = load_persisted_state_from(&path).expect("load state");
        assert_eq!(restored, state);
    }

    #[test]
    fn missing_state_defaults_cleanly() {
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("missing.json");
        let restored = load_persisted_state_from(&path).expect("default state");
        assert_eq!(restored, PersistedState::default());
    }

    #[test]
    fn invalid_json_is_rejected_by_strict_loader() {
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("broken.json");
        fs::write(&path, "{ not valid json").expect("write invalid state");
        let err = load_persisted_state_from(&path).expect_err("invalid json should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn legacy_dump_tab_state_loads_as_audit() {
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("legacy.json");
        fs::write(
            &path,
            r#"{
  "active_tab": "dump"
}"#,
        )
        .expect("write legacy state");

        let restored = load_persisted_state_from(&path).expect("load legacy state");

        assert_eq!(restored.active_tab, ResultTab::Audit);
    }

    #[test]
    fn legacy_state_without_workspace_layout_defaults_to_top_bottom() {
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("legacy-layout.json");
        fs::write(
            &path,
            r#"{
  "backup_location": "backup_folder"
}"#,
        )
        .expect("write legacy state");

        let restored = load_persisted_state_from(&path).expect("load legacy state");

        assert_eq!(
            restored.workspace_layout,
            WorkspaceLayoutPreference::TopBottom
        );
        assert_eq!(
            restored.auto_analyze_parallelism,
            AutoAnalyzeParallelismPreference::Four
        );
    }

    #[test]
    fn legacy_state_without_file_list_filters_defaults_to_false() {
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("legacy-filters.json");
        fs::write(
            &path,
            r#"{
  "search_query": "hero"
}"#,
        )
        .expect("write legacy state");

        let restored = load_persisted_state_from(&path).expect("load legacy state");

        assert!(!restored.file_list_findings_only);
        assert!(!restored.file_list_missing_only);
        assert!(!restored.file_list_no_workspace_only);
        assert!(!restored.file_list_dirty_only);
        assert!(restored.file_table_column_widths.is_empty());
        assert!(restored.path_table_column_widths.is_empty());
        assert!(restored.audit_table_column_widths.is_empty());
    }

    #[test]
    fn legacy_state_without_auto_analyze_parallelism_defaults_to_four() {
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("legacy-auto-analyze-parallelism.json");
        fs::write(
            &path,
            r#"{
  "workspace_auto_analyze": true
}"#,
        )
        .expect("write legacy state");

        let restored = load_persisted_state_from(&path).expect("load legacy state");

        assert!(restored.workspace_auto_analyze);
        assert_eq!(
            restored.auto_analyze_parallelism,
            AutoAnalyzeParallelismPreference::Four
        );
        assert!(restored.analysis_cache_enabled);
    }
}
