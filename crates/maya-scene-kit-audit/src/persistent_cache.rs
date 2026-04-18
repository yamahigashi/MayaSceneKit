use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zstd::stream::{decode_all, encode_all};

use crate::{
    audit::ScriptAuditPlan,
    scene::{AuditOptions, AuditReport},
};

const AUDIT_CACHE_SCHEMA_VERSION: u32 = 1;
const DB_FILE: &str = "cache.sqlite3";
const AUDIT_CACHE_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);
const AUDIT_CACHE_TOUCH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const BLOB_FILE_EXTENSION: &str = "json.zst";
const BLOB_CODEC_ZSTD: &str = "zstd";
const BLOB_COMPRESSION_LEVEL: i32 = 3;

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

#[derive(Debug, Clone)]
struct AuditCacheIndexRecord {
    file_state: AuditFileState,
    identity: AuditCacheIdentity,
    last_accessed_unix_secs: Option<u64>,
    blob: AuditBlobRef,
}

#[derive(Debug, Clone)]
struct AuditBlobRef {
    relative_path: PathBuf,
    compressed_size: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Default, Clone)]
struct AuditCacheIndex {
    by_path: BTreeMap<String, AuditCacheIndexRecord>,
}

#[derive(Debug, Clone)]
pub struct AuditCacheAccess {
    pub path: PathBuf,
    pub file_state: AuditFileState,
    pub identity: AuditCacheIdentity,
}

#[derive(Debug, Clone)]
pub struct AuditCacheHit {
    pub snapshot: AuditedSceneSnapshot,
    pub access: AuditCacheAccess,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AuditCacheMaintenanceStats {
    pub touched_count: usize,
    pub expired_record_count: usize,
    pub deleted_blob_count: usize,
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
            "{}-{}-{}.{}",
            self.scene_sha256,
            self.audit_options_fingerprint,
            self.audit_plan_fingerprint,
            BLOB_FILE_EXTENSION
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

    pub fn load_many_by_path_if_fresh_with_access(
        &self,
        paths: &[PathBuf],
        options: AuditOptions,
        plan_fingerprint: &str,
    ) -> io::Result<Vec<io::Result<Option<AuditCacheHit>>>> {
        let conn = self.open_connection()?;
        let now_unix_secs = unix_timestamp_secs(SystemTime::now());
        let options_fingerprint = fingerprint_debug(&options);
        Ok(paths
            .iter()
            .map(|path| {
                self.load_cached_hit_from_connection(
                    &conn,
                    path,
                    &options_fingerprint,
                    plan_fingerprint,
                    now_unix_secs,
                )
            })
            .collect())
    }

    pub fn load_by_path_if_fresh_with_access(
        &self,
        path: &Path,
        options: AuditOptions,
        plan_fingerprint: &str,
    ) -> io::Result<Option<AuditCacheHit>> {
        let conn = self.open_connection()?;
        let options_fingerprint = fingerprint_debug(&options);
        let Some(record) = self.load_index_record_by_path_if_fresh(
            &conn,
            path,
            &options_fingerprint,
            plan_fingerprint,
        )?
        else {
            return Ok(None);
        };
        let file_state = file_state_for_path(path)?;
        self.hit_from_record(path, file_state, record)
    }

    pub fn load_by_path_if_fresh(
        &self,
        path: &Path,
        options: AuditOptions,
        plan_fingerprint: &str,
    ) -> io::Result<Option<AuditedSceneSnapshot>> {
        Ok(self
            .load_by_path_if_fresh_with_access(path, options, plan_fingerprint)?
            .map(|hit| hit.snapshot))
    }

    pub fn load_by_path_with_hash_fallback_with_access(
        &self,
        path: &Path,
        options: AuditOptions,
        plan_fingerprint: &str,
    ) -> io::Result<Option<AuditCacheHit>> {
        let file_state = file_state_for_path(path)?;
        let conn = self.open_connection()?;
        let options_fingerprint = fingerprint_debug(&options);
        if let Some(record) = self.find_fresh_record_by_path(
            &conn,
            path,
            &file_state,
            &options_fingerprint,
            plan_fingerprint,
            unix_timestamp_secs(SystemTime::now()),
        ) {
            if let Some(hit) = self.hit_from_record(path, file_state.clone(), record)? {
                return Ok(Some(hit));
            }
        }

        let identity = AuditCacheIdentity::new(file_sha256(path)?, options, plan_fingerprint);
        if !self.identity_has_live_reference(&conn, &identity) {
            return Ok(None);
        }
        let Some(snapshot) = self.load_by_identity_with_connection(&conn, &identity)? else {
            return Ok(None);
        };
        Ok(Some(AuditCacheHit {
            snapshot,
            access: AuditCacheAccess {
                path: path.to_path_buf(),
                file_state,
                identity,
            },
        }))
    }

    pub fn load_by_path_with_hash_fallback(
        &self,
        path: &Path,
        options: AuditOptions,
        plan_fingerprint: &str,
    ) -> io::Result<Option<AuditedSceneSnapshot>> {
        Ok(self
            .load_by_path_with_hash_fallback_with_access(path, options, plan_fingerprint)?
            .map(|hit| hit.snapshot))
    }

    pub fn load_by_identity(
        &self,
        identity: &AuditCacheIdentity,
    ) -> io::Result<Option<AuditedSceneSnapshot>> {
        let conn = self.open_connection()?;
        self.load_by_identity_with_connection(&conn, identity)
    }

    pub fn save(&self, snapshot: &AuditedSceneSnapshot) -> io::Result<()> {
        self.save_batch(std::slice::from_ref(snapshot))
    }

    pub fn save_batch(&self, snapshots: &[AuditedSceneSnapshot]) -> io::Result<()> {
        if snapshots.is_empty() {
            return Ok(());
        }

        let mut conn = self.open_connection()?;
        let now_unix_secs = unix_timestamp_secs(SystemTime::now());
        let tx = conn.transaction().map_err(sqlite_io_error)?;
        for snapshot in snapshots {
            let blob = self.ensure_blob(snapshot)?;
            tx.execute(
                "INSERT INTO path_index (
                    normalized_path,
                    size,
                    modified_unix_nanos,
                    cache_schema_version,
                    scene_sha256,
                    audit_options_fingerprint,
                    audit_plan_fingerprint,
                    last_accessed_unix_secs,
                    blob_relative_path,
                    blob_codec,
                    blob_compressed_size
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                ON CONFLICT(normalized_path) DO UPDATE SET
                    size=excluded.size,
                    modified_unix_nanos=excluded.modified_unix_nanos,
                    cache_schema_version=excluded.cache_schema_version,
                    scene_sha256=excluded.scene_sha256,
                    audit_options_fingerprint=excluded.audit_options_fingerprint,
                    audit_plan_fingerprint=excluded.audit_plan_fingerprint,
                    last_accessed_unix_secs=excluded.last_accessed_unix_secs,
                    blob_relative_path=excluded.blob_relative_path,
                    blob_codec=excluded.blob_codec,
                    blob_compressed_size=excluded.blob_compressed_size",
                params![
                    normalized_path_key(&snapshot.file_state.path),
                    u64_to_sql(snapshot.file_state.size)?,
                    opt_u128_to_sql(snapshot.file_state.modified_unix_nanos)?,
                    i64::from(snapshot.identity.cache_schema_version),
                    &snapshot.identity.scene_sha256,
                    &snapshot.identity.audit_options_fingerprint,
                    &snapshot.identity.audit_plan_fingerprint,
                    u64_to_sql(now_unix_secs)?,
                    blob.relative_path.to_string_lossy().to_string(),
                    BLOB_CODEC_ZSTD,
                    u64_to_sql(blob.compressed_size)?,
                ],
            )
            .map_err(sqlite_io_error)?;
        }
        tx.commit().map_err(sqlite_io_error)
    }

    pub fn touch_many_if_stale(
        &self,
        touched: &[AuditCacheAccess],
        now: SystemTime,
        min_interval: Duration,
    ) -> io::Result<AuditCacheMaintenanceStats> {
        if touched.is_empty() {
            return Ok(AuditCacheMaintenanceStats::default());
        }
        let mut conn = self.open_connection()?;
        let now_unix_secs = unix_timestamp_secs(now);
        let min_unix_secs = now_unix_secs.saturating_sub(min_interval.as_secs());
        let mut touched_count = 0usize;
        let tx = conn.transaction().map_err(sqlite_io_error)?;
        for access in touched {
            touched_count += tx
                .execute(
                    "UPDATE path_index
                     SET last_accessed_unix_secs = ?2
                     WHERE normalized_path = ?1
                       AND (last_accessed_unix_secs IS NULL OR last_accessed_unix_secs < ?3)",
                    params![
                        normalized_path_key(&access.path),
                        u64_to_sql(now_unix_secs)?,
                        u64_to_sql(min_unix_secs)?,
                    ],
                )
                .map_err(sqlite_io_error)?;
        }
        tx.commit().map_err(sqlite_io_error)?;
        Ok(AuditCacheMaintenanceStats {
            touched_count,
            ..AuditCacheMaintenanceStats::default()
        })
    }

    pub fn sweep_expired(&self, now: SystemTime) -> io::Result<AuditCacheMaintenanceStats> {
        let mut conn = self.open_connection()?;
        let expired_before = now
            .checked_sub(AUDIT_CACHE_TTL)
            .map(unix_timestamp_secs)
            .unwrap_or(0);
        let tx = conn.transaction().map_err(sqlite_io_error)?;
        let expired_blob_paths = self.collect_expired_blob_paths(&tx, expired_before)?;
        let expired_record_count: usize = tx
            .query_row(
                "SELECT COUNT(*) FROM path_index
                 WHERE last_accessed_unix_secs IS NOT NULL
                   AND last_accessed_unix_secs < ?1",
                params![u64_to_sql(expired_before)?],
                |row| row.get(0),
            )
            .map_err(sqlite_io_error)?;
        tx.execute(
            "DELETE FROM path_index
             WHERE last_accessed_unix_secs IS NOT NULL
               AND last_accessed_unix_secs < ?1",
            params![u64_to_sql(expired_before)?],
        )
        .map_err(sqlite_io_error)?;
        let live_blob_paths = self.collect_live_blob_paths(&tx)?;
        tx.commit().map_err(sqlite_io_error)?;
        let orphaned_paths = expired_blob_paths
            .into_iter()
            .filter(|path| !live_blob_paths.contains_key(path))
            .collect::<Vec<_>>();
        let deleted_blob_count = delete_blob_files(self.blobs_dir(), &orphaned_paths)?;
        let deleted_temp_count = delete_stale_temp_files(self.blobs_dir())?;
        Ok(AuditCacheMaintenanceStats {
            touched_count: 0,
            expired_record_count,
            deleted_blob_count: deleted_blob_count + deleted_temp_count,
        })
    }

    pub fn apply_maintenance(
        &self,
        touched: &[AuditCacheAccess],
        now: SystemTime,
    ) -> io::Result<AuditCacheMaintenanceStats> {
        let touched_stats = self.touch_many_if_stale(touched, now, AUDIT_CACHE_TOUCH_INTERVAL)?;
        let sweep_stats = self.sweep_expired(now)?;
        Ok(AuditCacheMaintenanceStats {
            touched_count: touched_stats.touched_count,
            expired_record_count: sweep_stats.expired_record_count,
            deleted_blob_count: sweep_stats.deleted_blob_count,
        })
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
    fn db_path(&self) -> PathBuf {
        self.root.join(DB_FILE)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn load_index(&self) -> io::Result<AuditCacheIndex> {
        let conn = self.open_connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT normalized_path, size, modified_unix_nanos, cache_schema_version,
                        scene_sha256, audit_options_fingerprint, audit_plan_fingerprint,
                        last_accessed_unix_secs, blob_relative_path, blob_compressed_size
                 FROM path_index",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(sqlite_io_error)?;
        let mut by_path = BTreeMap::new();
        for row in rows {
            let (
                path,
                size,
                modified_unix_nanos,
                cache_schema_version,
                scene_sha256,
                audit_options_fingerprint,
                audit_plan_fingerprint,
                last_accessed_unix_secs,
                blob_relative_path,
                blob_compressed_size,
            ) = row.map_err(sqlite_io_error)?;
            by_path.insert(
                path.clone(),
                AuditCacheIndexRecord {
                    file_state: AuditFileState {
                        path: PathBuf::from(&path),
                        size: i64_to_u64(size)?,
                        modified_unix_nanos: opt_i64_to_u128(modified_unix_nanos)?,
                    },
                    identity: AuditCacheIdentity {
                        cache_schema_version: i64_to_u32(cache_schema_version)?,
                        scene_sha256,
                        audit_options_fingerprint,
                        audit_plan_fingerprint,
                    },
                    last_accessed_unix_secs: opt_i64_to_u64(last_accessed_unix_secs)?,
                    blob: AuditBlobRef {
                        relative_path: PathBuf::from(blob_relative_path),
                        compressed_size: i64_to_u64(blob_compressed_size)?,
                    },
                },
            );
        }
        Ok(AuditCacheIndex { by_path })
    }

    fn load_index_record_by_path_if_fresh(
        &self,
        conn: &Connection,
        path: &Path,
        options_fingerprint: &str,
        plan_fingerprint: &str,
    ) -> io::Result<Option<AuditCacheIndexRecord>> {
        let file_state = file_state_for_path(path)?;
        Ok(self.find_fresh_record_by_path(
            conn,
            path,
            &file_state,
            options_fingerprint,
            plan_fingerprint,
            unix_timestamp_secs(SystemTime::now()),
        ))
    }

    fn find_fresh_record_by_path(
        &self,
        conn: &Connection,
        path: &Path,
        file_state: &AuditFileState,
        options_fingerprint: &str,
        plan_fingerprint: &str,
        now_unix_secs: u64,
    ) -> Option<AuditCacheIndexRecord> {
        let key = normalized_path_key(path);
        let row = conn
            .query_row(
                "SELECT size, modified_unix_nanos, cache_schema_version, scene_sha256,
                        audit_options_fingerprint, audit_plan_fingerprint, last_accessed_unix_secs,
                        blob_relative_path, blob_compressed_size
                 FROM path_index
                 WHERE normalized_path = ?1",
                params![key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten();
        let record = row.and_then(
            |(
                size,
                modified_unix_nanos,
                cache_schema_version,
                scene_sha256,
                audit_options_fingerprint,
                audit_plan_fingerprint,
                last_accessed_unix_secs,
                blob_relative_path,
                blob_compressed_size,
            )| {
                Some(AuditCacheIndexRecord {
                    file_state: AuditFileState {
                        path: path.to_path_buf(),
                        size: i64_to_u64(size).ok()?,
                        modified_unix_nanos: opt_i64_to_u128(modified_unix_nanos).ok()?,
                    },
                    identity: AuditCacheIdentity {
                        cache_schema_version: i64_to_u32(cache_schema_version).ok()?,
                        scene_sha256,
                        audit_options_fingerprint,
                        audit_plan_fingerprint,
                    },
                    last_accessed_unix_secs: opt_i64_to_u64(last_accessed_unix_secs).ok()?,
                    blob: AuditBlobRef {
                        relative_path: PathBuf::from(blob_relative_path),
                        compressed_size: i64_to_u64(blob_compressed_size).ok()?,
                    },
                })
            },
        );
        record.filter(|record| {
            !record_expired(
                record.last_accessed_unix_secs,
                now_unix_secs,
                AUDIT_CACHE_TTL,
            ) && record.file_state.size == file_state.size
                && record.file_state.modified_unix_nanos == file_state.modified_unix_nanos
                && record.identity.audit_options_fingerprint == options_fingerprint
                && record.identity.audit_plan_fingerprint == plan_fingerprint
        })
    }

    fn load_cached_hit_from_connection(
        &self,
        conn: &Connection,
        path: &Path,
        options_fingerprint: &str,
        plan_fingerprint: &str,
        now_unix_secs: u64,
    ) -> io::Result<Option<AuditCacheHit>> {
        let file_state = match file_state_for_path(path) {
            Ok(file_state) => file_state,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let Some(record) = self.find_fresh_record_by_path(
            conn,
            path,
            &file_state,
            options_fingerprint,
            plan_fingerprint,
            now_unix_secs,
        ) else {
            return Ok(None);
        };
        self.hit_from_record(path, file_state, record)
    }

    fn hit_from_record(
        &self,
        path: &Path,
        file_state: AuditFileState,
        record: AuditCacheIndexRecord,
    ) -> io::Result<Option<AuditCacheHit>> {
        let conn = self.open_connection()?;
        let Some(snapshot) = self.load_blob_for_record(&conn, &record)? else {
            return Ok(None);
        };
        Ok(Some(AuditCacheHit {
            snapshot,
            access: AuditCacheAccess {
                path: path.to_path_buf(),
                file_state,
                identity: record.identity,
            },
        }))
    }

    fn identity_has_live_reference(
        &self,
        conn: &Connection,
        identity: &AuditCacheIdentity,
    ) -> bool {
        let now_unix_secs = unix_timestamp_secs(SystemTime::now());
        conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM path_index
                WHERE scene_sha256 = ?1
                  AND audit_options_fingerprint = ?2
                  AND audit_plan_fingerprint = ?3
                  AND (last_accessed_unix_secs IS NULL OR last_accessed_unix_secs >= ?4)
            )",
            params![
                &identity.scene_sha256,
                &identity.audit_options_fingerprint,
                &identity.audit_plan_fingerprint,
                u64_to_sql(now_unix_secs.saturating_sub(AUDIT_CACHE_TTL.as_secs())).unwrap_or(0)
            ],
            |row| row.get::<_, i64>(0),
        )
        .map(|exists| exists != 0)
        .unwrap_or(false)
    }

    fn load_by_identity_with_connection(
        &self,
        conn: &Connection,
        identity: &AuditCacheIdentity,
    ) -> io::Result<Option<AuditedSceneSnapshot>> {
        let row = conn
            .query_row(
                "SELECT cache_schema_version, scene_sha256, audit_options_fingerprint,
                        audit_plan_fingerprint, last_accessed_unix_secs, blob_relative_path,
                        blob_compressed_size
                 FROM path_index
                 WHERE scene_sha256 = ?1
                   AND audit_options_fingerprint = ?2
                   AND audit_plan_fingerprint = ?3
                 LIMIT 1",
                params![
                    &identity.scene_sha256,
                    &identity.audit_options_fingerprint,
                    &identity.audit_plan_fingerprint
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_io_error)?;
        let Some((
            cache_schema_version,
            scene_sha256,
            audit_options_fingerprint,
            audit_plan_fingerprint,
            last_accessed_unix_secs,
            blob_relative_path,
            blob_compressed_size,
        )) = row
        else {
            return Ok(None);
        };
        let record = AuditCacheIndexRecord {
            file_state: AuditFileState {
                path: PathBuf::new(),
                size: 0,
                modified_unix_nanos: None,
            },
            identity: AuditCacheIdentity {
                cache_schema_version: i64_to_u32(cache_schema_version)?,
                scene_sha256,
                audit_options_fingerprint,
                audit_plan_fingerprint,
            },
            last_accessed_unix_secs: opt_i64_to_u64(last_accessed_unix_secs)?,
            blob: AuditBlobRef {
                relative_path: PathBuf::from(blob_relative_path),
                compressed_size: i64_to_u64(blob_compressed_size)?,
            },
        };
        self.load_blob_for_record(conn, &record)
    }

    fn open_connection(&self) -> io::Result<Connection> {
        fs::create_dir_all(&self.root)?;
        let conn = Connection::open(self.db_path()).map_err(sqlite_io_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(sqlite_io_error)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS path_index (
                 normalized_path TEXT PRIMARY KEY,
                 size INTEGER NOT NULL,
                 modified_unix_nanos INTEGER NULL,
                 cache_schema_version INTEGER NOT NULL,
                 scene_sha256 TEXT NOT NULL,
                 audit_options_fingerprint TEXT NOT NULL,
                 audit_plan_fingerprint TEXT NOT NULL,
                 last_accessed_unix_secs INTEGER NULL,
                 blob_relative_path TEXT NOT NULL,
                 blob_codec TEXT NOT NULL,
                 blob_compressed_size INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS path_index_identity_idx
                 ON path_index(scene_sha256, audit_options_fingerprint, audit_plan_fingerprint);
             CREATE INDEX IF NOT EXISTS path_index_last_accessed_idx ON path_index(last_accessed_unix_secs);",
        )
        .map_err(sqlite_io_error)?;
        Ok(conn)
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    fn blob_path(&self, relative_path: &Path) -> PathBuf {
        self.blobs_dir().join(relative_path)
    }

    fn ensure_blob(&self, snapshot: &AuditedSceneSnapshot) -> io::Result<AuditBlobRef> {
        let blob_name = snapshot.identity.blob_name();
        let relative_path = sharded_blob_relative_path(&blob_name);
        let path = self.blob_path(&relative_path);
        if let Ok(metadata) = fs::metadata(&path) {
            return Ok(AuditBlobRef {
                relative_path,
                compressed_size: metadata.len(),
            });
        }

        let payload = serde_json::to_vec(snapshot)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let compressed = encode_all(std::io::Cursor::new(payload), BLOB_COMPRESSION_LEVEL)
            .map_err(io::Error::other)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp_path = temp_blob_path(&path);
        fs::write(&temp_path, &compressed)?;
        fs::rename(&temp_path, &path)?;
        Ok(AuditBlobRef {
            relative_path,
            compressed_size: compressed.len() as u64,
        })
    }

    fn load_blob_for_record(
        &self,
        conn: &Connection,
        record: &AuditCacheIndexRecord,
    ) -> io::Result<Option<AuditedSceneSnapshot>> {
        let path = self.blob_path(&record.blob.relative_path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                self.prune_blob_references(conn, &record.blob.relative_path)?;
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let payload = match decode_all(std::io::Cursor::new(bytes)) {
            Ok(payload) => payload,
            Err(_) => {
                self.prune_blob_references(conn, &record.blob.relative_path)?;
                return Ok(None);
            }
        };
        match serde_json::from_slice::<AuditedSceneSnapshot>(&payload) {
            Ok(mut snapshot) => {
                snapshot.identity = record.identity.clone();
                snapshot.file_state = record.file_state.clone();
                snapshot.report.scene_path = record.file_state.path.clone();
                Ok(Some(snapshot))
            }
            Err(_) => {
                self.prune_blob_references(conn, &record.blob.relative_path)?;
                Ok(None)
            }
        }
    }

    fn prune_blob_references(&self, conn: &Connection, relative_path: &Path) -> io::Result<()> {
        conn.execute(
            "DELETE FROM path_index WHERE blob_relative_path = ?1",
            params![relative_path.to_string_lossy().to_string()],
        )
        .map_err(sqlite_io_error)?;
        let _ = fs::remove_file(self.blob_path(relative_path));
        Ok(())
    }

    fn collect_expired_blob_paths(
        &self,
        conn: &Connection,
        expired_before: u64,
    ) -> io::Result<Vec<PathBuf>> {
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT blob_relative_path FROM path_index
                 WHERE last_accessed_unix_secs IS NOT NULL
                   AND last_accessed_unix_secs < ?1",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map(params![u64_to_sql(expired_before)?], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_io_error)?;
        let mut paths = Vec::new();
        for row in rows {
            paths.push(PathBuf::from(row.map_err(sqlite_io_error)?));
        }
        Ok(paths)
    }

    fn collect_live_blob_paths(&self, conn: &Connection) -> io::Result<BTreeMap<PathBuf, ()>> {
        let mut stmt = conn
            .prepare("SELECT DISTINCT blob_relative_path FROM path_index")
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_io_error)?;
        let mut paths = BTreeMap::new();
        for row in rows {
            paths.insert(PathBuf::from(row.map_err(sqlite_io_error)?), ());
        }
        Ok(paths)
    }
}

fn sharded_blob_relative_path(blob_name: &str) -> PathBuf {
    let shard_a = blob_name.get(0..2).unwrap_or("__");
    let shard_b = blob_name.get(2..4).unwrap_or("__");
    PathBuf::from(shard_a).join(shard_b).join(blob_name)
}

fn temp_blob_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_extension("tmp");
    temp
}

fn delete_blob_files(root: PathBuf, relative_paths: &[PathBuf]) -> io::Result<usize> {
    let mut deleted = 0usize;
    for relative_path in relative_paths {
        match fs::remove_file(root.join(relative_path)) {
            Ok(()) => deleted += 1,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(deleted)
}

fn delete_stale_temp_files(root: PathBuf) -> io::Result<usize> {
    let mut deleted = 0usize;
    if !root.exists() {
        return Ok(0);
    }
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "tmp") {
                fs::remove_file(path)?;
                deleted += 1;
            }
        }
    }
    Ok(deleted)
}

fn unix_timestamp_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map_or(0, |duration| duration.as_secs())
}

fn record_expired(last_accessed_unix_secs: Option<u64>, now_unix_secs: u64, ttl: Duration) -> bool {
    let Some(last_accessed_unix_secs) = last_accessed_unix_secs else {
        return false;
    };
    now_unix_secs.saturating_sub(last_accessed_unix_secs) > ttl.as_secs()
}

fn sqlite_io_error(err: rusqlite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn u64_to_sql(value: u64) -> io::Result<i64> {
    i64::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "u64 overflow for sqlite"))
}

fn opt_u128_to_sql(value: Option<u128>) -> io::Result<Option<i64>> {
    value
        .map(|value| {
            i64::try_from(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "u128 overflow for sqlite"))
        })
        .transpose()
}

fn i64_to_u64(value: i64) -> io::Result<u64> {
    u64::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative sqlite integer"))
}

fn i64_to_u32(value: i64) -> io::Result<u32> {
    u32::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid sqlite integer"))
}

fn opt_i64_to_u64(value: Option<i64>) -> io::Result<Option<u64>> {
    value.map(i64_to_u64).transpose()
}

fn opt_i64_to_u128(value: Option<i64>) -> io::Result<Option<u128>> {
    value
        .map(|value| {
            u128::try_from(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid sqlite integer"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        time::{Duration, SystemTime},
    };

    use tempfile::tempdir;

    use super::{
        AUDIT_CACHE_TOUCH_INTERVAL, AUDIT_CACHE_TTL, AuditCacheAccess, AuditCacheStore,
        AuditedSceneSnapshot, fingerprint_audit_plan, record_expired,
    };
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
        assert_eq!(
            loaded_first.identity.scene_sha256,
            first_snapshot.identity.scene_sha256
        );
        assert_eq!(
            loaded_second.identity.scene_sha256,
            second_snapshot.identity.scene_sha256
        );
    }

    #[test]
    fn audit_store_batch_lookup_matches_single_path_results() {
        let dir = tempdir().expect("tmpdir");
        let first = dir.path().join("ExampleA.ma");
        let second = dir.path().join("ExampleB.ma");
        let missing = dir.path().join("Missing.ma");
        write_sample_scene(&first);
        write_sample_scene(&second);
        write_sample_scene(&missing);

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
            .save_batch(&[first_snapshot, second_snapshot])
            .expect("save batch");
        fs::remove_file(&missing).expect("remove missing scene");

        let batch = store
            .load_many_by_path_if_fresh_with_access(
                &[missing.clone(), first.clone(), second.clone()],
                options,
                &plan_fingerprint,
            )
            .expect("batch lookup");

        assert_eq!(batch.len(), 3);
        assert!(batch[0].as_ref().expect("missing result").is_none());
        assert_eq!(
            batch[1]
                .as_ref()
                .expect("first result")
                .as_ref()
                .expect("first hit")
                .snapshot
                .file_state
                .path,
            first
        );
        assert_eq!(
            batch[2]
                .as_ref()
                .expect("second result")
                .as_ref()
                .expect("second hit")
                .snapshot
                .file_state
                .path,
            second
        );

        let single = store
            .load_by_path_if_fresh_with_access(&first, options, &plan_fingerprint)
            .expect("single lookup")
            .expect("single hit");
        assert_eq!(
            batch[1]
                .as_ref()
                .expect("first result")
                .as_ref()
                .expect("first hit")
                .snapshot
                .identity
                .scene_sha256,
            single.snapshot.identity.scene_sha256
        );
    }

    #[test]
    fn audit_touch_many_if_stale_skips_recent_accesses() {
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

        let access = AuditCacheAccess {
            path: snapshot.file_state.path.clone(),
            file_state: snapshot.file_state.clone(),
            identity: snapshot.identity.clone(),
        };
        let stats = store
            .touch_many_if_stale(
                std::slice::from_ref(&access),
                SystemTime::now(),
                AUDIT_CACHE_TOUCH_INTERVAL,
            )
            .expect("touch recent access");

        assert_eq!(stats.touched_count, 0);
    }

    #[test]
    fn audit_corrupt_blob_returns_miss_and_prunes_stale_index_rows() {
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

        let blob_relative_path = store
            .load_index()
            .expect("load index")
            .by_path
            .get(&super::normalized_path_key(&source))
            .expect("cached path")
            .blob
            .relative_path
            .clone();
        fs::write(store.blob_path(&blob_relative_path), b"not-zstd").expect("corrupt blob");

        assert!(
            store
                .load_by_path_if_fresh(&source, options, &plan_fingerprint)
                .expect("load after corrupt blob")
                .is_none()
        );
        assert!(
            store
                .load_index()
                .expect("reloaded index")
                .by_path
                .is_empty()
        );
    }

    #[test]
    fn audit_maintenance_expires_records_and_deletes_unreferenced_blobs() {
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
        store.save(&snapshot).expect("save snapshot");

        let conn = store.open_connection().expect("open sqlite");
        let expired_at = SystemTime::now()
            .checked_sub(AUDIT_CACHE_TTL + Duration::from_secs(5))
            .expect("expired timestamp");
        let expired_unix_secs = super::unix_timestamp_secs(expired_at);
        conn.execute(
            "UPDATE path_index SET last_accessed_unix_secs = ?1",
            [super::u64_to_sql(expired_unix_secs).expect("expired ts")],
        )
        .expect("write expired index");

        let stats = store
            .sweep_expired(SystemTime::now())
            .expect("apply maintenance");

        assert_eq!(stats.expired_record_count, 1);
        assert_eq!(stats.deleted_blob_count, 1);
        assert!(
            store
                .load_index()
                .expect("load trimmed index")
                .by_path
                .is_empty()
        );
        assert!(
            store
                .load_by_identity(&snapshot.identity)
                .expect("load identity after sweep")
                .is_none()
        );
        assert!(record_expired(
            Some(expired_unix_secs),
            super::unix_timestamp_secs(SystemTime::now()),
            AUDIT_CACHE_TTL
        ));
    }
}
