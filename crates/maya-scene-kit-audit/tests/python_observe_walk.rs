use maya_scene_kit_audit::scene::{ExecutionLanguage, audit_source_text};

#[test]
fn nested_python_bridges_preserve_parent_origin_and_uncertainty() {
    let bridge = "mm.eval('system(\"echo Example\");')";
    let control = audit_source_text(
        &format!("import maya.mel as mm\n{bridge}"),
        ExecutionLanguage::Python,
    )
    .unwrap();
    assert!(control.blocked_on_uncertainty);
    let mut missed = Vec::new();
    for body in [
        format!("try: {bridge}\nexcept* Exception: pass"),
        format!("try: pass\nexcept* Exception: pass\nelse: {bridge}"),
        format!("try: pass\nexcept* Exception: pass\nfinally: {bridge}"),
        format!("match 1:\n    case _: {bridge}"),
        format!("[sample for sample in [] if {bridge}]"),
        format!("def Example(sample={bridge}): pass"),
        "match 1:\n    case _:\n        cmd = 'system(\"echo Example\");'\n        mm.eval(cmd)"
            .to_string(),
        "try: pass\nexcept* Exception:\n    cmd = 'system(\"echo Example\");'\n    mm.eval(cmd)"
            .to_string(),
    ] {
        let source = format!("import maya.mel as mm\n{body}");
        let report = audit_source_text(&source, ExecutionLanguage::Python).unwrap();
        if report.surface_count != 2 {
            missed.push(source);
            continue;
        }
        assert_eq!(
            report.blocked_on_uncertainty,
            control.blocked_on_uncertainty
        );
        let parent = &report.surfaces[0].origin;
        let child = &report.surfaces[1];
        assert_eq!(parent.lang, ExecutionLanguage::Python);
        assert_eq!(child.origin.lang, ExecutionLanguage::Mel);
        assert_eq!(child.preview, "system(\"echo Example\");");
        assert_eq!(child.origin.trigger, parent.trigger);
        assert_eq!(child.origin.node_name, parent.node_name);
        assert_eq!(child.origin.attr_name, parent.attr_name);
        assert_eq!(child.origin.source_range, parent.source_range);
        assert_eq!(
            child.origin.source_kind.as_deref(),
            Some("python->maya.mel.eval literal bridge")
        );
    }
    assert!(missed.is_empty(), "missing bridges: {missed:#?}");
}
