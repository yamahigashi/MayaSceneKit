use maya_scene_kit_audit::{
    audit::{audit_observation, audit_observation_with_digests, build_script_audit_plan},
    scene::{AuditDisposition, AuditOptions},
};
use maya_scene_kit_observe::scene::{LoadOptions, Loader};
use sha2::{Digest, Sha256};

#[test]
fn audit_keeps_the_analysed_source_after_disk_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    let bytes = concat!(
        "//Maya ASCII 2026 scene\n",
        "createNode script -n ExampleScript;\n",
        "setAttr \".b\" -type \"string\" \"import os; os.system('echo Example')\";\n",
        "setAttr \".st\" 1; setAttr \".stp\" 1;\n",
    );
    std::fs::write(&path, bytes).unwrap();
    let loader = Loader::new(LoadOptions::default());
    let observation = loader.observe_audit_path(&path).unwrap();
    let execution = loader.observe_execution_path(&path).unwrap();
    std::fs::write(&path, "//Maya ASCII 2026 scene\n").unwrap();
    let plan = build_script_audit_plan(vec![], 96).unwrap();
    let expected = format!("{:x}", Sha256::digest(bytes.as_bytes()));
    let report = audit_observation(&observation, &plan, AuditOptions::strict_default()).unwrap();
    assert_eq!(report.digests.scene_sha256, expected);
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
    let without_digests =
        audit_observation_with_digests(&observation, &plan, AuditOptions::strict_default(), false)
            .unwrap();
    assert!(without_digests.digests.scene_sha256.is_empty());
    assert_eq!(without_digests.disposition, report.disposition);
    assert_eq!(execution.scene_digests(0).unwrap().scene_sha256, expected);
    assert_eq!(
        execution
            .observed_execution_catalog(96)
            .unwrap()
            .digests
            .scene_sha256,
        expected
    );
}
