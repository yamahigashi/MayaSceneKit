use std::{
    fs,
    time::{Duration, UNIX_EPOCH},
};

use maya_scene_kit_audit::{
    audit::{audit_observation, build_script_audit_plan},
    scene::{AuditCacheStore, AuditOptions, AuditedSceneSnapshot, fingerprint_audit_plan},
};
use maya_scene_kit_observe::scene::{
    LoadOptions, Loader, ObserveCacheStore, ObservedSceneSnapshot, SceneFormat, ValidationState,
};

fn inputs() -> [(SceneFormat, &'static str, Vec<u8>); 2] {
    [
        (
            SceneFormat::Ma,
            "Example.ma",
            b"//Maya ASCII 2026 scene\nrequires maya \"2026\";\n".to_vec(),
        ),
        (
            SceneFormat::Mb,
            "Example.mb",
            b"FOR4\0\0\0\x04Maya".to_vec(),
        ),
    ]
}

#[test]
fn delayed_snapshots_preserve_load_state_and_miss_changed_files() {
    for (_, name, bytes) in inputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        let old_time = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old_time)
            .unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let options = LoadOptions::default();
        let observation = Loader::new(options.clone())
            .observe_analysis_path(&path)
            .unwrap();
        let plan = build_script_audit_plan(vec![], 64).unwrap();
        let profile = AuditOptions::strict_default();
        let report = audit_observation(&observation, &plan, profile).unwrap();
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("file_state").is_none());
        fs::write(
            &path,
            b"//Maya ASCII 2026 scene\n// Example changed contents\n",
        )
        .unwrap();
        let observed = ObservedSceneSnapshot::from_observation(&observation, &options)
            .unwrap()
            .expect("cacheable schema");
        let audited =
            AuditedSceneSnapshot::new(report, profile, fingerprint_audit_plan(&plan), &options)
                .unwrap()
                .expect("cacheable schema");
        for (size, modified) in [
            (
                observed.file_state.size,
                observed.file_state.modified_unix_nanos,
            ),
            (
                audited.file_state.size,
                audited.file_state.modified_unix_nanos,
            ),
        ] {
            assert_eq!(size, metadata.len());
            assert_eq!(
                modified,
                Some(old_time.duration_since(UNIX_EPOCH).unwrap().as_nanos())
            );
        }
        let observe_store = ObserveCacheStore::new(dir.path().join("ExampleObserve"), &options);
        observe_store.save(&observed).unwrap();
        assert!(
            observe_store
                .load_by_path_if_fresh(&path)
                .unwrap()
                .is_none()
        );
        assert!(
            observe_store
                .load_many_by_path_if_fresh_with_access(std::slice::from_ref(&path))
                .unwrap()
                .pop()
                .unwrap()
                .unwrap()
                .is_none()
        );
        let audit_store = AuditCacheStore::new(dir.path().join("ExampleAudit"), &options);
        audit_store.save(&audited).unwrap();
        let fingerprint = fingerprint_audit_plan(&plan);
        assert!(
            audit_store
                .load_by_path_if_fresh(&path, profile, &fingerprint)
                .unwrap()
                .is_none()
        );
        assert!(
            audit_store
                .load_many_by_path_if_fresh_with_access(
                    std::slice::from_ref(&path),
                    profile,
                    &fingerprint
                )
                .unwrap()
                .pop()
                .unwrap()
                .unwrap()
                .is_none()
        );
        fs::remove_file(&path).unwrap();
        assert!(ObservedSceneSnapshot::from_observation(&observation, &options).is_ok());
        assert!(AuditedSceneSnapshot::new(audited.report, profile, fingerprint, &options).is_ok());
    }
}

#[test]
fn bytes_observations_do_not_create_cache_snapshots() {
    for (format, name, bytes) in inputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, &bytes).unwrap();
        let options = LoadOptions::default();
        let observation = Loader::new(options.clone())
            .observe_analysis_bytes(&path, format, ValidationState::Validated, bytes)
            .unwrap();
        let plan = build_script_audit_plan(vec![], 64).unwrap();
        let profile = AuditOptions::strict_default();
        let report = audit_observation(&observation, &plan, profile).unwrap();
        let observed = ObservedSceneSnapshot::from_observation(&observation, &options);
        let audited =
            AuditedSceneSnapshot::new(report, profile, fingerprint_audit_plan(&plan), &options);
        assert!(observed.is_err());
        assert!(audited.is_err());
        let root = dir.path().join("ExampleCache");
        if let Ok(Some(snapshot)) = observed {
            ObserveCacheStore::new(&root, &options)
                .save(&snapshot)
                .unwrap();
        }
        if let Ok(Some(snapshot)) = audited {
            AuditCacheStore::new(&root, &options)
                .save(&snapshot)
                .unwrap();
        }
        assert!(!root.exists());
    }
}
