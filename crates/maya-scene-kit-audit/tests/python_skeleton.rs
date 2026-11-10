use maya_scene_kit_audit::{
    audit::{audit_script_nodes, build_script_audit_plan},
    scene::{AuditDisposition, AuditReport},
};

fn audit_python(body: &str) -> AuditReport {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("Example.ma");
    let escaped = body
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t");
    std::fs::write(&path, format!("//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"Example\";\n    setAttr \".st\" 1;\n    setAttr \".stp\" 1;\n    setAttr \".b\" -type \"string\" \"{escaped}\";\n")).unwrap();
    audit_script_nodes(&path, &build_script_audit_plan(vec![], 64).unwrap()).unwrap()
}

fn assert_finding(body: &str, expected_code: &str) {
    use rustpython_parser::Parse;
    rustpython_parser::ast::Suite::parse(body, "Example").expect("script must use AST analysis");
    let report = audit_python(body);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == expected_code),
        "missing AST finding: {:?}",
        report.findings
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.code.as_str().contains("parse")),
        "{:?}",
        report.findings
    );
    assert_eq!(report.disposition, AuditDisposition::DenyMalicious);
}

macro_rules! script_test {
    ($name:ident, $source:literal) => {
        #[test]
        fn $name() {
            assert_finding($source, "python_pyimport");
        }
    };
}

script_test!(
    class_base,
    "class Example(__import__('os').system('echo Example') or object):\n    pass\n"
);
script_test!(
    argument_annotation,
    "def Example(sample: __import__('os').system('echo Example')):\n    pass\n"
);
script_test!(
    return_annotation,
    "def Example() -> __import__('os').system('echo Example'):\n    pass\n"
);
script_test!(
    class_keyword,
    "class Example(metaclass=__import__('os').system('echo Example') or type):\n    pass\n"
);
script_test!(
    format_spec,
    "f\"{0:{__import__('os').system('echo Example')}}\"\n"
);
script_test!(
    function_type_bound,
    "def Example[T: __import__('os').system('echo Example')]():\n    pass\n"
);
script_test!(
    class_type_bound,
    "class Example[T: __import__('os').system('echo Example')]:\n    pass\n"
);
script_test!(
    type_alias_value,
    "type Example = __import__('os').system('echo Example')\n"
);
script_test!(
    annotated_assignment,
    "sample: __import__('os').system('echo Example')\n"
);
script_test!(
    decorator_call,
    "@__import__('os').system('echo Example')\ndef Example():\n    pass\n"
);
script_test!(
    match_guard,
    "match 1:\n    case _ if __import__('os').system('echo Example'):\n        pass\n"
);
script_test!(
    try_star_handler,
    "try:\n    pass\nexcept* Exception:\n    __import__('os').system('echo Example')\n"
);
script_test!(
    comprehension_if,
    "[sample for sample in [1] if __import__('os').system('echo Example')]\n"
);
script_test!(
    lambda_default,
    "lambda sample=__import__('os').system('echo Example'): sample\n"
);

#[test]
fn first_comprehension_iterable_preserves_enclosing_finding() {
    assert_finding(
        "import os as helper\ndata = [sample for sample in [(helper := \"Example\")]]\nhelper.system(\"echo Example\")",
        "python_subprocess",
    );
}
