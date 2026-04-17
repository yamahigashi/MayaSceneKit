use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    audit::ScriptAuditPlan,
    scene::{AuditOptions, AuditReport},
};

const AUDIT_CACHE_SCHEMA_VERSION: u32 = 1;
const INDEX_FILE: &str = "index.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCacheIdentity {
    pub cache_schema_version: u32,
    pub scene_sha256: String,
    pub audit_options_fingerprint: String,
    pub audit_plan_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFileState {
    pub path: PathBuf,
    pub size: u64,
    pub modified_unix_nanos: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditedSceneSnapshot {
    pub identity: AuditCacheIdentity,
    pub file_state: AuditFileState,
    pub report: AuditReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditCacheIndexRecord {
    file_state: AuditFileState,
    identity: AuditCacheIdentity,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct AuditCacheIndex {
    by_path: BTreeMap<String, AuditCacheIndexRecord>,
}

impl AuditCacheIdentity {
    pub fn new(
        scene_sha256: impl Into<String>,
        options: AuditOptions,
        plan_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            cache_schema_version: AUDIT_CACHE_SCHEMA_VERSION,
            scene_sha256: scene_sha256.into(),
            audit_options_fingerprint: fingerprint_debug(&options),
            audit_plan_fingerprint: plan_fingerprint.into(),
        }
    }

    fn blob_name(&self) -> String {
        format!(
            "{}-{}-{}.json",
            self.scene_sha256, self.audit_options_fingerprint, self.audit_plan_fingerprint
        )
    }
}

impl AuditedSceneSnapshot {
    pub fn new(
        report: AuditReport,
        options: AuditOptions,
        plan_fingerprint: impl Into<String>,
    ) -> io::Result<Self> {
        let file_state = file_state_for_path(&report.scene_path)?;
        let identity = AuditCacheIdentity::new(
            report.digests.scene_sha256.clone(),
            options,
            plan_fingerprint,
        );
        Ok(Self {
            identity,
            file_state,
            report,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuditCacheStore {
    root: PathBuf,
}

impl AuditCacheStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load_by_path_if_fresh(
        &self,
        path: &Path,
        options: AuditOptions,
        plan_fingerprint: &str,
    ) -> io::Result<Option<AuditedSceneSnapshot>> {
        let file_state = file_state_for_path(path)?;
        let Some(record) =
            self.load_index_record_by_path_if_fresh(path, &file_state, options, plan_fingerprint)?
        else {
            return Ok(None);
        };
        self.load_by_identity(&record.identity)
    }

    pub fn load_by_path_with_hash_fallback(
        &self,
        path: &Path,
        options: AuditOptions,
        plan_fingerprint: &str,
    ) -> io::Result<Option<AuditedSceneSnapshot>> {
        let file_state = file_state_for_path(path)?;
        if let Some(record) =
            self.load_index_record_by_path_if_fresh(path, &file_state, options, plan_fingerprint)?
        {
            if let Some(snapshot) = self.load_by_identity(&record.identity)? {
                return Ok(Some(snapshot));
            }
        }

        let identity = AuditCacheIdentity::new(file_sha256(path)?, options, plan_fingerprint);
        self.load_by_identity(&identity)
    }

    pub fn load_by_identity(
        &self,
        identity: &AuditCacheIdentity,
    ) -> io::Result<Option<AuditedSceneSnapshot>> {
        for blob_path in [self.blob_path(identity), self.legacy_blob_path(identity)] {
            match fs::read(&blob_path) {
                Ok(bytes) => {
                    return serde_json::from_slice(&bytes)
                        .map(Some)
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err));
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    }

    pub fn save(&self, snapshot: &AuditedSceneSnapshot) -> io::Result<()> {
        self.save_batch(std::slice::from_ref(snapshot))
    }

    pub fn save_batch(&self, snapshots: &[AuditedSceneSnapshot]) -> io::Result<()> {
        if snapshots.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(self.blobs_dir())?;
        let mut index = self.load_index()?;
        for snapshot in snapshots {
            let blob_path = self.blob_path(&snapshot.identity);
            if !blob_path.exists() {
                write_json_atomic(&blob_path, snapshot)?;
            }
            index.by_path.insert(
                normalized_path_key(&snapshot.file_state.path),
                AuditCacheIndexRecord {
                    file_state: snapshot.file_state.clone(),
                    identity: snapshot.identity.clone(),
                },
            );
        }
        write_json_atomic(&self.index_path(), &index)
    }
}

pub fn fingerprint_audit_plan(plan: &ScriptAuditPlan) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", plan.effective_rules()));
    hasher.update(plan.max_preview().to_le_bytes());
    format!("{:x}", hasher.finalize())
}

fn fingerprint_debug(value: &impl std::fmt::Debug) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{value:?}"));
    format!("{:x}", hasher.finalize())
}

fn file_state_for_path(path: &Path) -> io::Result<AuditFileState> {
    let metadata = fs::metadata(path)?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_nanos());
    Ok(AuditFileState {
        path: path.to_path_buf(),
        size: metadata.len(),
        modified_unix_nanos,
    })
}

fn file_sha256(path: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path)?);
    Ok(format!("{:x}", hasher.finalize()))
}

fn normalized_path_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

impl AuditCacheStore {
    fn index_path(&self) -> PathBuf {
        self.root.join(INDEX_FILE)
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    fn blob_path(&self, identity: &AuditCacheIdentity) -> PathBuf {
        sharded_blob_path(&self.blobs_dir(), &identity.blob_name())
    }

    fn legacy_blob_path(&self, identity: &AuditCacheIdentity) -> PathBuf {
        self.blobs_dir().join(identity.blob_name())
    }

    fn load_index(&self) -> io::Result<AuditCacheIndex> {
        match fs::read(self.index_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(AuditCacheIndex::default()),
            Err(err) => Err(err),
        }
    }

    fn load_index_record_by_path_if_fresh(
        &self,
        path: &Path,
        file_state: &AuditFileState,
        options: AuditOptions,
        plan_fingerprint: &str,
    ) -> io::Result<Option<AuditCacheIndexRecord>> {
        let index = self.load_index()?;
        let key = normalized_path_key(path);
        let options_fingerprint = fingerprint_debug(&options);
        Ok(index.by_path.get(&key).cloned().filter(|record| {
            record.file_state.size == file_state.size
                && record.file_state.modified_unix_nanos == file_state.modified_unix_nanos
                && record.identity.audit_options_fingerprint == options_fingerprint
                && record.identity.audit_plan_fingerprint == plan_fingerprint
        }))
    }
}

fn sharded_blob_path(blobs_dir: &Path, blob_name: &str) -> PathBuf {
    let shard_a = blob_name.get(0..2).unwrap_or("__");
    let shard_b = blob_name.get(2..4).unwrap_or("__");
    blobs_dir.join(shard_a).join(shard_b).join(blob_name)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, payload)?;
    fs::rename(temp_path, path)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use tempfile::tempdir;

    use super::{AuditCacheStore, AuditedSceneSnapshot, fingerprint_audit_plan, write_json_atomic};
    use crate::{
        audit::{audit_script_nodes_with_options, build_script_audit_plan},
        scene::{AuditOptions, LoadOptions},
    };

    fn write_sample_scene(path: &Path) {
        fs::write(
            path,
            concat!(
                "//Maya ASCII 2026 scene\n",
                "requires maya \"2026\";\n",
                "createNode script -n \"Example\";\n",
                "    setAttr \".b\" -type \"string\" \"print \\\"Example\\\";\";\n",
                "createNode file -n \"file1\";\n",
                "    setAttr \".ftn\" -type \"string\" \"asset/example/file.fbx\";\n",
            ),
        )
        .expect("write sample scene");
    }

    #[test]
    fn audit_snapshot_round_trips_and_renamed_path_hits_by_hash() {
        let dir = tempdir().expect("tmpdir");
        let source = dir.path().join("Example.ma");
        write_sample_scene(&source);

        let plan = build_script_audit_plan(vec![], 64).expect("plan");
        let plan_fingerprint = fingerprint_audit_plan(&plan);
        let options = AuditOptions::strict_default();
        let report =
            audit_script_nodes_with_options(&source, &plan, &LoadOptions::default(), options)
                .expect("audit report");
        let snapshot =
            AuditedSceneSnapshot::new(report, options, plan_fingerprint.clone()).expect("snapshot");
        let store = AuditCacheStore::new(dir.path().join("audit-cache"));
        store.save(&snapshot).expect("save snapshot");

        let loaded = store
            .load_by_path_with_hash_fallback(&source, options, &plan_fingerprint)
            .expect("load by original path")
            .expect("snapshot by path");
        assert_eq!(loaded.identity.scene_sha256, snapshot.identity.scene_sha256);

        let renamed = dir.path().join("RenamedExample.ma");
        fs::rename(&source, &renamed).expect("rename scene");
        let loaded = store
            .load_by_path_with_hash_fallback(&renamed, options, &plan_fingerprint)
            .expect("load by renamed path")
            .expect("snapshot by hash fallback");
        assert_eq!(loaded.identity.scene_sha256, snapshot.identity.scene_sha256);

        let startup_loaded = store
            .load_by_path_if_fresh(&renamed, options, &plan_fingerprint)
            .expect("load startup path");
        assert!(startup_loaded.is_none());
    }

    #[test]
    fn audit_store_reads_legacy_flat_blob_layout() {
        let dir = tempdir().expect("tmpdir");
        let source = dir.path().join("Example.ma");
        write_sample_scene(&source);

        let plan = build_script_audit_plan(vec![], 64).expect("plan");
        let plan_fingerprint = fingerprint_audit_plan(&plan);
        let options = AuditOptions::strict_default();
        let report =
            audit_script_nodes_with_options(&source, &plan, &LoadOptions::default(), options)
                .expect("audit report");
        let snapshot =
            AuditedSceneSnapshot::new(report, options, plan_fingerprint).expect("snapshot");
        let store = AuditCacheStore::new(dir.path().join("audit-cache"));
        fs::create_dir_all(store.blobs_dir()).expect("create blobs dir");
        write_json_atomic(&store.legacy_blob_path(&snapshot.identity), &snapshot)
            .expect("write legacy blob");

        let loaded = store
            .load_by_identity(&snapshot.identity)
            .expect("load by identity")
            .expect("snapshot");
        assert_eq!(loaded.identity.scene_sha256, snapshot.identity.scene_sha256);
    }

    #[test]
    fn audit_store_save_batch_round_trips_multiple_snapshots() {
        let dir = tempdir().expect("tmpdir");
        let first = dir.path().join("ExampleA.ma");
        let second = dir.path().join("ExampleB.ma");
        write_sample_scene(&first);
        write_sample_scene(&second);

        let plan = build_script_audit_plan(vec![], 64).expect("plan");
        let plan_fingerprint = fingerprint_audit_plan(&plan);
        let options = AuditOptions::strict_default();
        let first_report =
            audit_script_nodes_with_options(&first, &plan, &LoadOptions::default(), options)
                .expect("first audit report");
        let second_report =
            audit_script_nodes_with_options(&second, &plan, &LoadOptions::default(), options)
                .expect("second audit report");
        let first_snapshot =
            AuditedSceneSnapshot::new(first_report, options, plan_fingerprint.clone())
                .expect("first snapshot");
        let second_snapshot =
            AuditedSceneSnapshot::new(second_report, options, plan_fingerprint.clone())
                .expect("second snapshot");
        let store = AuditCacheStore::new(dir.path().join("audit-cache"));

        store
            .save_batch(&[first_snapshot.clone(), second_snapshot.clone()])
            .expect("save batch");

        let loaded_first = store
            .load_by_path_if_fresh(&first, options, &plan_fingerprint)
            .expect("load first")
            .expect("first snapshot");
        let loaded_second = store
            .load_by_path_if_fresh(&second, options, &plan_fingerprint)
            .expect("load second")
            .expect("second snapshot");
        assert_eq!(loaded_first.identity.scene_sha256, first_snapshot.identity.scene_sha256);
        assert_eq!(loaded_second.identity.scene_sha256, second_snapshot.identity.scene_sha256);
    }
}
