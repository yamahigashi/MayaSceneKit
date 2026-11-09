use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserAllowlistDocument {
    pub(crate) version: u64,
    pub(crate) entries: Vec<UserAllowlistEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserAllowlistEntry {
    pub(crate) hash: maya_scene_kit_audit::scene::AllowlistHash,
    pub(crate) codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) added_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) added_by: Option<String>,
}

pub(crate) struct AllowlistEntryDraft<'a> {
    pub(crate) node: Option<&'a str>,
    pub(crate) attr: Option<&'a str>,
    pub(crate) body: &'a str,
    pub(crate) reason: &'a str,
    pub(crate) codes: &'a std::collections::BTreeSet<String>,
}

pub(crate) fn build_user_allowlist_entry(
    hash: maya_scene_kit_audit::scene::AllowlistHash,
    draft: AllowlistEntryDraft<'_>,
    now: std::time::SystemTime,
    added_by: Option<String>,
) -> UserAllowlistEntry {
    let reason = draft.reason.trim();
    UserAllowlistEntry {
        hash,
        codes: draft.codes.iter().cloned().collect(),
        label: Some(format!(
            "{}{}",
            draft.node.unwrap_or("-"),
            draft
                .attr
                .map(|attr| format!(" {attr}"))
                .unwrap_or_default()
        )),
        preview: Some(
            draft
                .body
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(120)
                .collect(),
        ),
        reason: (!reason.is_empty()).then(|| reason.to_string()),
        added_at: Some(format_allowlist_timestamp(now)),
        added_by,
    }
}

pub(crate) fn current_user_name() -> Option<String> {
    select_user_name(std::env::var("USERNAME").ok(), std::env::var("USER").ok())
}

fn select_user_name(username: Option<String>, user: Option<String>) -> Option<String> {
    username
        .filter(|name| !name.is_empty())
        .or_else(|| user.filter(|name| !name.is_empty()))
}

pub(crate) fn format_allowlist_timestamp(now: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(now).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub(crate) fn read_user_allowlist(path: &Path) -> Result<UserAllowlistDocument, String> {
    read_allowlist_document(path, maya_scene_kit_audit::scene::AllowlistSource::User)
}

pub(crate) fn read_allowlist_document(
    path: &Path,
    source: maya_scene_kit_audit::scene::AllowlistSource,
) -> Result<UserAllowlistDocument, String> {
    use maya_scene_kit_audit::scene::AuditAllowlist;
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(UserAllowlistDocument {
                version: 1,
                entries: Vec::new(),
            });
        }
        Err(error) => return Err(error.to_string()),
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    AuditAllowlist::from_json(text, source).map_err(|error| error.to_string())?;
    serde_json::from_str(text).map_err(|error| error.to_string())
}

pub(crate) fn add_user_allowlist_entry(
    path: &Path,
    entry: &UserAllowlistEntry,
) -> Result<usize, String> {
    use std::collections::BTreeSet;
    let mut document = read_user_allowlist(path)?;
    let existing_codes: BTreeSet<_> = document
        .entries
        .iter()
        .filter(|existing| existing.hash == entry.hash)
        .flat_map(|existing| existing.codes.iter().cloned())
        .collect();
    let new_codes: BTreeSet<_> = entry
        .codes
        .iter()
        .filter(|code| !existing_codes.contains(*code))
        .cloned()
        .collect();
    let count = new_codes.len();
    if let Some(existing) = document
        .entries
        .iter_mut()
        .find(|existing| existing.hash == entry.hash)
    {
        let before = existing.clone();
        if existing.label.is_none() {
            existing.label.clone_from(&entry.label);
        }
        if existing.preview.is_none() {
            existing.preview.clone_from(&entry.preview);
        }
        if existing.reason.is_none() {
            existing.reason.clone_from(&entry.reason);
        }
        if count == 0 && *existing == before {
            return Ok(0);
        }
        let mut seen = BTreeSet::new();
        existing.codes.retain(|code| seen.insert(code.clone()));
        existing.codes.extend(new_codes);
    } else {
        let mut entry = entry.clone();
        entry.codes = new_codes.into_iter().collect();
        document.entries.push(entry);
    }
    write_user_allowlist_document(path, &document)?;
    Ok(count)
}

fn write_user_allowlist_document(
    path: &Path,
    document: &UserAllowlistDocument,
) -> Result<(), String> {
    use maya_scene_kit_audit::scene::{AllowlistSource, AuditAllowlist};
    let mut bytes = serde_json::to_vec_pretty(document).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    AuditAllowlist::from_json(
        std::str::from_utf8(&bytes).map_err(|error| error.to_string())?,
        AllowlistSource::User,
    )
    .map_err(|error| error.to_string())?;
    maya_scene_kit_edit::scene::write_output_bytes_atomic(path, &bytes)
        .map_err(|error| error.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RemoveAllowlistEntryError {
    Read(String),
    FileChanged,
    Write(String),
}

pub(crate) fn remove_user_allowlist_entry(
    path: &Path,
    index: usize,
    expected: &UserAllowlistEntry,
) -> Result<(), RemoveAllowlistEntryError> {
    let mut document = read_user_allowlist(path).map_err(RemoveAllowlistEntryError::Read)?;
    if document.entries.get(index) != Some(expected) {
        return Err(RemoveAllowlistEntryError::FileChanged);
    }
    document.entries.remove(index);
    write_user_allowlist_document(path, &document).map_err(RemoveAllowlistEntryError::Write)
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

static LAST_SAVED_SEQUENCE: Mutex<u64> = Mutex::new(0);
static NEXT_SAVE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub fn next_persist_save_sequence() -> u64 {
    NEXT_SAVE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

pub fn save_persisted_state(state: &PersistedState, sequence: u64) -> io::Result<()> {
    save_persisted_state_to(&default_state_path(), state, sequence, &LAST_SAVED_SEQUENCE)
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

fn save_persisted_state_to(
    path: &Path,
    state: &PersistedState,
    sequence: u64,
    last_saved: &Mutex<u64>,
) -> io::Result<()> {
    let mut last_saved = last_saved
        .lock()
        .map_err(|error| io::Error::other(error.to_string()))?;
    if sequence <= *last_saved {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut normalized = state.clone();
    normalized.normalize_ignore_folder_settings();
    let payload = serde_json::to_vec_pretty(&normalized)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let result = maya_scene_kit_edit::scene::write_output_bytes_atomic(path, &payload)
        .map_err(|error| io::Error::other(error.to_string()));
    if result.is_ok() || fs::read(path).is_ok_and(|bytes| bytes == payload) {
        *last_saved = sequence;
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{fs, io, path::PathBuf, sync::Mutex};

    use tempfile::tempdir;

    use super::{load_persisted_state_from, save_persisted_state_to};
    use crate::model::{
        AuditModePreference, AutoAnalyzeParallelismPreference, BackupLocationPreference,
        JobHistoryEntry, LocalePreference, PersistedState, PersistedTableColumnWidth,
        PersistedWorkspaceFile, RecentInput, ResultTab, StatusFilter, WorkspaceLayoutPreference,
    };

    const A0: &str = r#"{"hash":"sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20","codes":["mel_exec"],"label":"ExampleApp"}"#;
    const A1: &str = r#"{"hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","codes":["mel_python"],"label":"Sample"}"#;
    const U0: &str = r#"{"hash":"sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20","codes":["mel_exec","mel_python"],"label":"ExampleScriptNode","preview":"Example preview\nSample preview","reason":"Example reason","added_at":"2026-11-07T09:30:00Z","added_by":"Example"}"#;
    const U1: &str = r#"{"hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","codes":["mel_eval"]}"#;
    const U2: &str = r#"{"hash":"sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20","codes":["mel_python"],"label":"Sample"}"#;
    const E0: &str = "{\n  \"version\": 1,\n  \"entries\": []\n}\n";
    const E1: &str = r#"{
  "version": 1,
  "entries": [
    {
      "hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "codes": [
        "mel_eval"
      ]
    }
  ]
}
"#;
    const E2: &str = r#"{
  "version": 1,
  "entries": [
    {
      "hash": "sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20",
      "codes": [
        "mel_python"
      ],
      "label": "Sample"
    }
  ]
}
"#;

    fn document_json(records: &[&str]) -> String {
        format!("{{\"version\":1,\"entries\":[{}]}}\n", records.join(","))
    }

    #[test]
    fn older_snapshot_cannot_overwrite_newer_snapshot() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let gate = Mutex::new(0);
        let state_a = PersistedState::default();
        let mut state_b = state_a.clone();
        state_b.last_opened_input = Some(RecentInput {
            path: "Example.ma".into(),
            was_directory: false,
        });
        save_persisted_state_to(&path, &state_b, 2, &gate).expect("save B");
        save_persisted_state_to(&path, &state_a, 1, &gate).expect("skip A");
        assert_eq!(load_persisted_state_from(&path).expect("load B"), state_b);
    }

    #[test]
    fn failed_save_allows_retry_with_same_sequence() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::create_dir(&path).expect("create obstruction");
        let gate = Mutex::new(0);
        let state = PersistedState::default();
        assert!(save_persisted_state_to(&path, &state, 1, &gate).is_err());
        assert_eq!(*gate.lock().expect("lock"), 0);
        fs::remove_dir(&path).expect("remove obstruction");
        save_persisted_state_to(&path, &state, 1, &gate).expect("retry");
        assert_eq!(*gate.lock().expect("lock"), 1);
        assert_eq!(load_persisted_state_from(&path).expect("load"), state);
    }

    #[test]
    fn successful_save_leaves_no_temporary_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        save_persisted_state_to(&path, &PersistedState::default(), 1, &Mutex::new(0))
            .expect("save");
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read directory")
            .map(|entry| entry.expect("entry").path())
            .collect();
        assert_eq!(entries, vec![path]);
    }

    #[test]
    fn allowlist_document_reader_preserves_sources_and_order() {
        use maya_scene_kit_audit::scene::AllowlistSource;

        use super::read_allowlist_document;
        let dir = tempdir().unwrap();
        for (folder, source, records) in [
            ("ExampleApp", AllowlistSource::App, [A0, A1]),
            ("ExampleUser", AllowlistSource::User, [U0, U1]),
        ] {
            let path = dir.path().join(folder).join("allowlist.json");
            let empty = read_allowlist_document(&path, source).unwrap();
            assert_eq!(empty.version, 1);
            assert!(empty.entries.is_empty());
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, document_json(&records)).unwrap();
            let document = read_allowlist_document(&path, source).unwrap();
            assert_eq!(document.version, 1);
            assert_eq!(
                document.entries,
                records.map(
                    |record| serde_json::from_str::<super::UserAllowlistEntry>(record).unwrap()
                )
            );
            for (invalid, prefix) in [
                ("{", "invalid allowlist JSON:"),
                (
                    r#"{"version":2,"entries":[]}"#,
                    "unsupported allowlist version: 2",
                ),
                (
                    r#"{"version":1,"entries":[],"Example":true}"#,
                    "invalid allowlist JSON:",
                ),
            ] {
                fs::write(&path, invalid).unwrap();
                let error = read_allowlist_document(&path, source).unwrap_err();
                if prefix.starts_with("unsupported") {
                    assert_eq!(error, prefix);
                } else {
                    assert!(error.starts_with(prefix), "{error}");
                }
            }
        }
    }

    #[test]
    fn remove_user_allowlist_entry_preserves_other_entries() {
        use maya_scene_kit_audit::scene::{AllowlistSource, AuditAllowlist};

        use super::{
            RemoveAllowlistEntryError, UserAllowlistEntry, read_user_allowlist,
            remove_user_allowlist_entry,
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("ExampleUser/allowlist.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let [u0, u1, u2] =
            [U0, U1, U2].map(|record| serde_json::from_str::<UserAllowlistEntry>(record).unwrap());
        for (input, expected, bytes, remaining) in [
            (document_json(&[U0, U1]), &u0, E1, vec![u1.clone()]),
            (E1.to_string(), &u1, E0, vec![]),
            (document_json(&[U0, U2]), &u0, E2, vec![u2.clone()]),
        ] {
            fs::write(&path, input).unwrap();
            assert_eq!(remove_user_allowlist_entry(&path, 0, expected), Ok(()));
            assert!(path.is_file());
            assert_eq!(fs::read(&path).unwrap(), bytes.as_bytes());
            assert_eq!(read_user_allowlist(&path).unwrap().entries, remaining);
            AuditAllowlist::from_json(bytes, AllowlistSource::User).unwrap();
        }
        let input = document_json(&[U0, U1]);
        fs::write(&path, &input).unwrap();
        for (index, expected) in [(0, &u2), (2, &u0)] {
            assert_eq!(
                remove_user_allowlist_entry(&path, index, expected),
                Err(RemoveAllowlistEntryError::FileChanged)
            );
            assert_eq!(fs::read(&path).unwrap(), input.as_bytes());
        }
        for (original, changed) in [
            ("ExampleScriptNode", "SampleScriptNode"),
            ("Example reason", "Sample reason"),
        ] {
            let changed_entry = U0.replace(original, changed);
            let changed_file = document_json(&[&changed_entry, U1]);
            fs::write(&path, &changed_file).unwrap();
            assert_eq!(
                remove_user_allowlist_entry(&path, 0, &u0),
                Err(RemoveAllowlistEntryError::FileChanged)
            );
            assert_eq!(fs::read(&path).unwrap(), changed_file.as_bytes());
        }
        fs::write(&path, "{").unwrap();
        assert!(matches!(
            remove_user_allowlist_entry(&path, 0, &u0),
            Err(RemoveAllowlistEntryError::Read(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"{");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(matches!(
            remove_user_allowlist_entry(&path, 0, &u0),
            Err(RemoveAllowlistEntryError::Read(_))
        ));
        assert!(fs::read_dir(&path).unwrap().next().is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            struct RestoreMode(PathBuf);
            impl Drop for RestoreMode {
                fn drop(&mut self) {
                    fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755)).unwrap();
                }
            }
            fs::remove_dir(&path).unwrap();
            let input = document_json(&[U0]);
            fs::write(&path, &input).unwrap();
            let parent = path.parent().unwrap();
            let _restore = RestoreMode(parent.to_path_buf());
            fs::set_permissions(parent, fs::Permissions::from_mode(0o555)).unwrap();
            if tempfile::NamedTempFile::new_in(parent).is_ok() {
                eprintln!(
                    "Unix Write case skipped: parent mode 0o555 still permits temporary files"
                );
                return;
            }
            assert!(matches!(
                remove_user_allowlist_entry(&path, 0, &u0),
                Err(RemoveAllowlistEntryError::Write(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), input.as_bytes());
        }
    }

    #[test]
    fn user_name_selection_skips_empty_values() {
        for (username, user, expected) in [
            (Some("Example"), Some("Sample"), Some("Example")),
            (Some(""), Some("Sample"), Some("Sample")),
            (None, Some("Sample"), Some("Sample")),
            (Some("Example"), None, Some("Example")),
            (Some(""), Some(""), None),
            (None, Some(""), None),
            (Some(""), None, None),
            (None, None, None),
        ] {
            assert_eq!(
                super::select_user_name(username.map(str::to_string), user.map(str::to_string))
                    .as_deref(),
                expected,
            );
        }
    }

    #[test]
    fn user_allowlist_entry_writer() {
        use std::{
            collections::BTreeSet,
            time::{Duration, SystemTime},
        };

        use maya_scene_kit_audit::scene::{AllowlistSource, AuditAllowlist};

        use super::*;
        let dir = tempdir().unwrap();
        let path = dir.path().join("ExampleUser/allowlist.json");
        let hash = "sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20";
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1794043800);
        let codes = BTreeSet::from(["mel_exec".to_string()]);
        let build = |body, reason| {
            build_user_allowlist_entry(
                hash.parse().unwrap(),
                AllowlistEntryDraft {
                    node: Some("ExampleScriptNode"),
                    attr: Some(".b"),
                    body,
                    reason,
                    codes: &codes,
                },
                now,
                Some("Example".to_string()),
            )
        };
        let entry = build("exec \"Example\"", " Example reason ");
        assert_eq!(entry.reason.as_deref(), Some("Example reason"));
        assert_eq!(build("exec \"Example\"", "  ").reason, None);
        let long = build(&"例".repeat(121), "");
        assert_eq!(long.preview.as_deref(), Some("例".repeat(120).as_str()));
        assert_eq!(add_user_allowlist_entry(&path, &entry).unwrap(), 1);
        let expected = concat!(
            "{\n  \"version\": 1,\n  \"entries\": [\n    {\n",
            "      \"hash\": \"sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20\",\n",
            "      \"codes\": [\n        \"mel_exec\"\n      ],\n",
            "      \"label\": \"ExampleScriptNode .b\",\n",
            "      \"preview\": \"exec \\\"Example\\\"\",\n",
            "      \"reason\": \"Example reason\",\n",
            "      \"added_at\": \"2026-11-07T09:30:00Z\",\n",
            "      \"added_by\": \"Example\"\n    }\n  ]\n}\n",
        );
        assert_eq!(fs::read(&path).unwrap(), expected.as_bytes());
        let other = serde_json::json!({"hash":format!("sha256:{}", "11".repeat(32)),"codes":["mel_eval"],"label":"Sample"});
        fs::write(
            &path,
            serde_json::json!({"version":1,"entries":[other.clone()]}).to_string(),
        )
        .unwrap();
        assert_eq!(add_user_allowlist_entry(&path, &entry).unwrap(), 1);
        let document = read_user_allowlist(&path).unwrap();
        assert_eq!(serde_json::to_value(&document.entries[0]).unwrap(), other);
        assert_eq!(document.entries[1], entry);
        let mut incoming = entry.clone();
        incoming.codes = vec!["mel_exec".into(), "mel_python".into()];
        let existing = serde_json::json!({"hash":hash,"codes":["mel_eval","mel_exec","mel_eval"],"label":"Sample","preview":"Sample","reason":"Sample","added_at":"Sample","added_by":"Sample"});
        fs::write(
            &path,
            serde_json::json!({"version":1,"entries":[existing]}).to_string(),
        )
        .unwrap();
        assert_eq!(add_user_allowlist_entry(&path, &incoming).unwrap(), 1);
        let merged = read_user_allowlist(&path).unwrap().entries.remove(0);
        assert_eq!(merged.codes, ["mel_eval", "mel_exec", "mel_python"]);
        for metadata in [
            merged.label,
            merged.preview,
            merged.reason,
            merged.added_at,
            merged.added_by,
        ] {
            assert_eq!(metadata.as_deref(), Some("Sample"));
        }
        fs::write(
            &path,
            serde_json::json!({"version":1,"entries":[{"hash":hash,"codes":["mel_eval"]}]})
                .to_string(),
        )
        .unwrap();
        assert_eq!(add_user_allowlist_entry(&path, &entry).unwrap(), 1);
        let filled = read_user_allowlist(&path).unwrap().entries.remove(0);
        assert_eq!(filled.label, entry.label);
        assert_eq!(filled.preview, entry.preview);
        assert_eq!(filled.reason, entry.reason);
        assert_eq!(filled.added_at, None);
        assert_eq!(filled.added_by, None);
        for invalid in [
            "".to_string(),
            "  \n".to_string(),
            "{".to_string(),
            "{\"version\":2,\"entries\":[]}".to_string(),
            serde_json::json!({"version":1,"entries":[{"hash":hash,"codes":[]}]}).to_string(),
            "{\"version\":1,\"entries\":[],\"Example\":true}".to_string(),
        ] {
            fs::write(&path, &invalid).unwrap();
            assert!(add_user_allowlist_entry(&path, &entry).is_err());
            assert_eq!(fs::read(&path).unwrap(), invalid.as_bytes());
        }
        fs::write(&path, "\u{feff}{\"version\":1,\"entries\":[]}").unwrap();
        assert!(read_user_allowlist(&path).unwrap().entries.is_empty());
        assert_eq!(add_user_allowlist_entry(&path, &long).unwrap(), 1);
        let bytes = fs::read(&path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.starts_with('\u{feff}'));
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
        assert!(!text.contains(&"例".repeat(121)));
        assert!(AuditAllowlist::from_json(text, AllowlistSource::User).is_ok());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(add_user_allowlist_entry(&path, &entry).is_err());
        assert!(fs::read_dir(&path).unwrap().next().is_none());
    }

    #[test]
    fn allowlist_paths_are_pure_and_preserve_relative_parents() {
        use std::path::Path;

        use super::{app_allowlist_path, user_allowlist_path};
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

        save_persisted_state_to(&path, &state, 1, &Mutex::new(0)).expect("save state");
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

    #[test]
    fn distributed_app_allowlist_is_valid() {
        let text = include_str!("../../../dist/allowlist.json");
        let allowlist = maya_scene_kit_audit::scene::AuditAllowlist::from_json(
            text,
            maya_scene_kit_audit::scene::AllowlistSource::App,
        )
        .expect("dist/allowlist.json must load as an app allowlist");
        assert!(allowlist.len_entries() > 0);
    }
}
