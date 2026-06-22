use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use serde::{Deserialize, Serialize};

use super::{AuditResultRowKey, AuditTableRow, SceneRow, build_file_operation_paths};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::gui) enum PluginActionScope {
    FileList,
    Detail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gui) struct PluginAction {
    pub id: String,
    pub label: String,
    pub scopes: Vec<PluginActionScope>,
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::gui) struct PluginRegistry {
    actions: Vec<PluginAction>,
}

#[derive(Debug, Deserialize)]
struct PluginManifest {
    #[serde(default)]
    actions: Vec<PluginActionManifest>,
}

#[derive(Debug, Deserialize)]
struct PluginActionManifest {
    id: String,
    label: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    scopes: Vec<PluginActionScope>,
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(in crate::gui) struct FilePluginContext {
    scope: PluginActionScope,
    selection_count: usize,
    items: Vec<FilePluginItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct FilePluginItem {
    row_id: u64,
    path: String,
    name: String,
    dirty: bool,
    status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(in crate::gui) struct AuditPluginContext {
    scope: PluginActionScope,
    selection_count: usize,
    items: Vec<AuditPluginItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct AuditPluginItem {
    row_id: u64,
    item_index: usize,
    scene_name: String,
    summary: String,
    code: String,
    sink: String,
    preview: String,
    provenance: Vec<String>,
    source_line: Option<usize>,
    evidence: Vec<String>,
}

pub(in crate::gui) fn default_plugin_dir_from_state_path(state_path: &Path) -> PathBuf {
    state_path
        .parent()
        .map(|parent| parent.join("plugins"))
        .unwrap_or_else(|| PathBuf::from("plugins"))
}

#[cfg(test)]
pub(in crate::gui) fn run_plugin_action(
    action: &PluginAction,
    payload: &impl Serialize,
) -> io::Result<()> {
    let payload = serialize_plugin_payload(payload)?;
    let mut child = spawn_plugin_child(action)?;
    write_plugin_payload(&mut child, &payload)?;
    child.wait()?;
    Ok(())
}

pub(in crate::gui) fn spawn_plugin_action(
    action: &PluginAction,
    payload: &impl Serialize,
) -> io::Result<()> {
    // Serialize and spawn synchronously so payload-encoding and launch failures
    // still surface to the caller, but move the potentially blocking stdin write
    // and process wait onto a background thread. The menu callback runs on the GUI
    // thread, so a large payload or a slow-reading plugin must never block it here.
    let payload = serialize_plugin_payload(payload)?;
    let mut child = spawn_plugin_child(action)?;
    thread::spawn(move || {
        let _ = write_plugin_payload(&mut child, &payload);
        let _ = child.wait();
    });
    Ok(())
}

fn serialize_plugin_payload(payload: &impl Serialize) -> io::Result<Vec<u8>> {
    serde_json::to_vec(payload).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn spawn_plugin_child(action: &PluginAction) -> io::Result<std::process::Child> {
    Command::new(&action.command)
        .args(&action.args)
        .env("MAYA_SCENE_KIT_PLUGIN_ACTION_ID", &action.id)
        .env("MAYA_SCENE_KIT_PLUGIN_ACTION_LABEL", &action.label)
        .stdin(Stdio::piped())
        .spawn()
}

fn write_plugin_payload(child: &mut std::process::Child, payload: &[u8]) -> io::Result<()> {
    // Take ownership of the pipe so it is closed (EOF) when this scope ends, even
    // when the plugin does not consume the whole payload.
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(payload)?;
    }
    Ok(())
}

pub(in crate::gui) fn build_file_plugin_context(
    rows: &[SceneRow],
    row_id: u64,
) -> Option<FilePluginContext> {
    let paths = build_file_operation_paths(rows, row_id)?;
    let target = rows.iter().find(|row| row.id == row_id)?;
    let selected_rows = if target.selected {
        rows.iter()
            .filter(|row| row.selected)
            .collect::<Vec<&SceneRow>>()
    } else {
        vec![target]
    };
    if selected_rows.is_empty() {
        return None;
    }
    let items = selected_rows
        .into_iter()
        .zip(paths)
        .map(|(row, path)| FilePluginItem {
            row_id: row.id,
            path: path.display().to_string(),
            name: row.name.clone(),
            dirty: row.dirty(),
            status: file_status_key(row),
        })
        .collect::<Vec<_>>();
    Some(FilePluginContext {
        scope: PluginActionScope::FileList,
        selection_count: items.len(),
        items,
    })
}

pub(in crate::gui) fn build_audit_plugin_context(
    rows: &[AuditTableRow],
    key: &AuditResultRowKey,
) -> Option<AuditPluginContext> {
    let target = rows.iter().find(|row| &row.key == key)?;
    let action_rows = if target.selected {
        rows.iter()
            .filter(|row| row.selected)
            .collect::<Vec<&AuditTableRow>>()
    } else {
        vec![target]
    };
    if action_rows.is_empty() {
        return None;
    }
    let items = action_rows
        .into_iter()
        .map(|row| AuditPluginItem {
            row_id: row.key.row_id,
            item_index: row.key.item_index,
            scene_name: row.scene_name.clone(),
            summary: row.summary.clone(),
            code: row.code.clone(),
            sink: row.sink.clone(),
            preview: row.preview.clone(),
            provenance: row.provenance.clone(),
            source_line: row.source_line,
            evidence: row.evidence.clone(),
        })
        .collect::<Vec<_>>();
    Some(AuditPluginContext {
        scope: PluginActionScope::Detail,
        selection_count: items.len(),
        items,
    })
}

impl PluginRegistry {
    pub(in crate::gui) fn load_from_dir(dir: &Path) -> Self {
        let mut actions = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return Self { actions };
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        paths.sort();

        for path in paths {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(manifest) = serde_json::from_slice::<PluginManifest>(&bytes) else {
                continue;
            };
            actions.extend(
                manifest
                    .actions
                    .into_iter()
                    .filter_map(PluginAction::from_manifest),
            );
        }

        Self { actions }
    }

    pub(in crate::gui) fn actions_for_scope(&self, scope: PluginActionScope) -> Vec<PluginAction> {
        self.actions
            .iter()
            .filter(|action| action.scopes.contains(&scope))
            .cloned()
            .collect()
    }

    #[cfg(test)]
    pub(in crate::gui) fn action_for_test(
        id: &str,
        label: &str,
        scope: PluginActionScope,
        command: &str,
        args: Vec<String>,
    ) -> PluginAction {
        PluginAction {
            id: id.to_string(),
            label: label.to_string(),
            scopes: vec![scope],
            command: command.to_string(),
            args,
        }
    }
}

impl PluginAction {
    fn from_manifest(manifest: PluginActionManifest) -> Option<Self> {
        if !manifest.enabled
            || manifest.id.trim().is_empty()
            || manifest.label.trim().is_empty()
            || manifest.command.trim().is_empty()
            || manifest.scopes.is_empty()
        {
            return None;
        }
        Some(Self {
            id: manifest.id,
            label: manifest.label,
            scopes: manifest.scopes,
            command: manifest.command,
            args: manifest.args,
        })
    }
}

fn default_enabled() -> bool {
    true
}

fn file_status_key(row: &SceneRow) -> String {
    match &row.status {
        super::FileStatus::Idle => "idle",
        super::FileStatus::Processing(_) => "processing",
        super::FileStatus::Audited => "audited",
        super::FileStatus::Dirty => "dirty",
        super::FileStatus::Saved => "saved",
        super::FileStatus::Error(_) => "error",
    }
    .to_string()
}
