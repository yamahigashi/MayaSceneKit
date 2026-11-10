use maya_scene_kit_audit::{
    audit::{audit_script_nodes_with_options, build_script_audit_plan},
    scene::{
        AuditDisposition, AuditFindingCode, AuditOptions, ExecutionLanguage, audit_source_text,
    },
};
use maya_scene_kit_observe::scene::LoadOptions;

#[test]
fn fstring_and_statement_introspection_have_matching_evidence_in_sources_and_scenes() {
    let expression = "print.__self__.__import__('os').system('echo Example')";
    let sources = [expression.to_string(), format!("f\"{{{expression}}}\"")];
    let mut source_codes = Vec::new();
    let plan = build_script_audit_plan(vec![], 64).unwrap();
    let directory = tempfile::tempdir().unwrap();
    for (index, source) in sources.iter().enumerate() {
        let report = audit_source_text(source, ExecutionLanguage::Python).unwrap();
        assert_ne!(report.disposition, AuditDisposition::AllowWithNotice);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == AuditFindingCode::PythonBodyAssembly)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == AuditFindingCode::PythonUnresolvedCallTarget)
        );
        let mut codes: Vec<_> = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect();
        codes.sort_unstable();
        codes.dedup();
        source_codes.push(codes);
        let escaped = source.replace('\\', "\\\\").replace('"', "\\\"");
        let path = directory.path().join(format!("Example{index}.ma"));
        std::fs::write(&path, format!("//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"Example\";\nsetAttr \".stp\" 1;\nsetAttr \".st\" 1;\nsetAttr \".b\" -type \"string\" \"{escaped}\";\n")).unwrap();
        let scene = audit_script_nodes_with_options(
            &path,
            &plan,
            &LoadOptions::default(),
            AuditOptions::strict_default(),
        )
        .unwrap();
        assert_ne!(scene.disposition, AuditDisposition::AllowWithNotice);
        for code in [
            AuditFindingCode::PythonBodyAssembly,
            AuditFindingCode::PythonUnresolvedCallTarget,
        ] {
            assert!(scene.findings.iter().any(|finding| finding.code == code));
        }
    }
    assert_eq!(source_codes[0], source_codes[1]);
}
