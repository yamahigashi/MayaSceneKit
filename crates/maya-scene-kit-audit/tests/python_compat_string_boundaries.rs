use maya_scene_kit_audit::{
    audit::{audit_script_nodes, build_script_audit_plan},
    scene::AuditDisposition,
};

#[test]
fn python2_multiline_print_preserves_later_mel_system_finding() {
    let body = "import maya.mel as mm\nprint \"\"\"Sample\nSample\n\"\"\"\nmm.eval('system(\"Example\");')\n";
    let escaped = body
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Example.ma");
    std::fs::write(
        &path,
        format!(
            "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"ExampleScript\";\nsetAttr \".st\" 1;\nsetAttr \".stp\" 1;\nsetAttr \".b\" -type \"string\" \"{escaped}\";\n"
        ),
    )
    .unwrap();
    let plan = build_script_audit_plan(vec![], 64).unwrap();
    let report = audit_script_nodes(&path, &plan).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == "mel_system")
    );
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
}
