use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::model::PersistedState;

const APP_DIR: &str = "maya-scene-kit";
const STATE_FILE: &str = "gui-state.json";

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
            max_bytes: Some(123456789),
            ignore_folder_names_enabled: false,
            ignored_folder_names: vec!["cache".to_string(), "publish".to_string()],
            active_tab: ResultTab::Audit,
            status_filter: StatusFilter::Dirty,
            file_list_findings_only: true,
            file_list_missing_only: false,
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
    }
}
