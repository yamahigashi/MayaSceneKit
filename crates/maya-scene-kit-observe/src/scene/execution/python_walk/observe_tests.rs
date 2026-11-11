use super::summarize_python_surface;
use crate::scene::{
    EffectCertainty, ExecutionEffectClass,
    execution::python_source::{collect_static_maya_mel_eval_payloads, parse_python_compat_suite},
};

const PAYLOAD: &str = "system(\"echo Example\");";
const BRIDGE: &str = "mm.eval('system(\"echo Example\");')";
const PROCESS: &str = "__import__('os').system('echo Example')";

fn added_positions(call: &str) -> Vec<String> {
    let mut sources = Vec::new();
    for prefix in ["def", "async def"] {
        for args in [
            format!("sample={call}, /"),
            format!("sample={call}"),
            format!("*, sample={call}"),
            format!("sample: {call}, /"),
            format!("sample: {call}"),
            format!("*sample: {call}"),
            format!("*, sample: {call}"),
            format!("**sample: {call}"),
        ] {
            sources.push(format!("{prefix} Example({args}): pass"));
        }
        sources.push(format!("@{call}\n{prefix} Example(): pass"));
        sources.push(format!("{prefix} Example() -> {call}: pass"));
        sources.push(format!("{prefix} Example[T: {call}](): pass"));
    }
    sources.extend([
        format!("@{call}\nclass Example: pass"),
        format!("class Example[T: {call}]: pass"),
        format!("class Example({call} or object): pass"),
        format!("class Example(metaclass={call}): pass"),
        format!("type Example[T: {call}] = int"),
        format!("type Example = {call}"),
        format!("sample: {call}"),
        format!("lambda sample={call}: sample"),
        format!("f'''{{{call}}}'''"),
        format!("f'''{{0:{{{call}}}}}'''"),
    ]);
    for (open, result, close) in [
        ("[", "sample", "]"),
        ("{", "sample", "}"),
        ("{", "sample: sample", "}"),
        ("(", "sample", ")"),
    ] {
        for generators in [
            format!("for sample in {call}"),
            format!("for sample in [] if {call}"),
            format!("for sample in [] for value in {call}"),
            format!("for sample in [] for value in [] if {call}"),
        ] {
            sources.push(format!("{open}{result} {generators}{close}"));
        }
    }
    sources
}

#[test]
fn added_expression_positions_report_effects() {
    let mut missed = Vec::new();
    for source in added_positions(PROCESS) {
        assert!(
            parse_python_compat_suite(&source, crate::scene::MelParseBudget::default().max_bytes)
                .is_some(),
            "{source}"
        );
        if summarize_python_surface(&source, crate::scene::MelParseBudget::default().max_bytes).0
            == ExecutionEffectClass::PureComputation
        {
            missed.push(source);
        }
    }
    assert!(missed.is_empty(), "missed: {missed:#?}");
}

#[test]
fn added_expression_positions_extract_bridges() {
    let mut missed = Vec::new();
    for source in added_positions(BRIDGE) {
        let source = format!("import maya.mel as mm\n{source}");
        assert!(
            parse_python_compat_suite(&source, crate::scene::MelParseBudget::default().max_bytes)
                .is_some(),
            "{source}"
        );
        if collect_static_maya_mel_eval_payloads(
            &source,
            crate::scene::MelParseBudget::default().max_bytes,
        ) != [PAYLOAD]
        {
            missed.push(source);
        }
    }
    assert!(missed.is_empty(), "missed: {missed:#?}");
}

#[test]
fn added_statement_positions_extract_bridges() {
    let mut sources = vec![
        format!("for sample[{BRIDGE}] in []: pass"),
        format!("async for sample[{BRIDGE}] in []: pass"),
        format!("with Example as sample[{BRIDGE}]: pass"),
        format!("async with Example as sample[{BRIDGE}]: pass"),
        format!("sample[{BRIDGE}] = 1"),
        format!("sample[{BRIDGE}]: int = 1"),
        format!("sample[{BRIDGE}] += 1"),
        format!("del sample[{BRIDGE}]"),
        format!("cmd = '{PAYLOAD}'\ndel sample[mm.eval(cmd)], cmd, sample[mm.eval(cmd)]"),
        format!("try: pass\nexcept {BRIDGE}: pass"),
        format!("raise Example from {BRIDGE}"),
        format!("match {BRIDGE}:\n    case _: pass"),
        format!("match 1:\n    case _ if {BRIDGE}: pass"),
        format!("match 1:\n    case _: {BRIDGE}"),
    ];
    for source in [
        format!("try: {BRIDGE}\nexcept* Exception: pass"),
        format!("try: pass\nexcept* {BRIDGE}: pass"),
        format!("try: pass\nexcept* Exception: {BRIDGE}"),
        format!("try: pass\nexcept* Exception: pass\nelse: {BRIDGE}"),
        format!("try: pass\nexcept* Exception: pass\nfinally: {BRIDGE}"),
    ] {
        sources.push(source);
    }
    let mut missed = Vec::new();
    for source in sources {
        let source = format!("import maya.mel as mm\n{source}");
        assert!(
            parse_python_compat_suite(&source, crate::scene::MelParseBudget::default().max_bytes)
                .is_some(),
            "{source}"
        );
        if collect_static_maya_mel_eval_payloads(
            &source,
            crate::scene::MelParseBudget::default().max_bytes,
        ) != [PAYLOAD]
        {
            missed.push(source);
        }
    }
    assert!(missed.is_empty(), "missed: {missed:#?}");
}

#[test]
fn new_bodies_resolve_local_strings_and_restore_outer_bindings() {
    for body in [
        "match 1:\n    case _:\n        cmd = 'print \"Sample\";'\n        mm.eval(cmd)",
        "try:\n    cmd = 'print \"Sample\";'\n    mm.eval(cmd)\nexcept* Exception: pass",
        "try: pass\nexcept* Exception:\n    cmd = 'print \"Sample\";'\n    mm.eval(cmd)",
        "try: pass\nexcept* Exception: pass\nelse:\n    cmd = 'print \"Sample\";'\n    mm.eval(cmd)",
        "try: pass\nexcept* Exception: pass\nfinally:\n    cmd = 'print \"Sample\";'\n    mm.eval(cmd)",
        "match 1:\n    case _:\n        import maya.mel as sample\n        sample.eval('print \"Sample\";')\n        import Example as mm",
    ] {
        let source =
            format!("import maya.mel as mm\ncmd = 'print \"Example\";'\n{body}\nmm.eval(cmd)");
        assert!(
            parse_python_compat_suite(&source, crate::scene::MelParseBudget::default().max_bytes)
                .is_some()
        );
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                &source,
                crate::scene::MelParseBudget::default().max_bytes
            ),
            ["print \"Sample\";", "print \"Example\";"],
            "{source}"
        );
    }
}

#[test]
fn new_body_captures_invalidate_only_local_strings() {
    for pattern in [
        "cmd",
        "[cmd]",
        "[*cmd]",
        "{'Example': cmd}",
        "{'Example': _, **cmd}",
        "Example(cmd)",
        "Example(sample=cmd)",
        "[1 as cmd]",
        "[cmd] | (cmd,)",
    ] {
        let source = format!(
            "import maya.mel as mm\ncmd = 'print \"Example\";'\nmatch sample:\n    case {pattern}:\n        mm.eval(cmd)\n        {BRIDGE}\nmm.eval(cmd)"
        );
        assert!(
            parse_python_compat_suite(&source, crate::scene::MelParseBudget::default().max_bytes)
                .is_some(),
            "{source}"
        );
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                &source,
                crate::scene::MelParseBudget::default().max_bytes
            ),
            [PAYLOAD, "print \"Example\";"],
            "{source}"
        );
    }
    let source = format!(
        "import maya.mel as mm\ncmd = 'print \"Example\";'\ntry: pass\nexcept* Exception as cmd:\n    mm.eval(cmd)\n    {BRIDGE}\nmm.eval(cmd)"
    );
    assert_eq!(
        collect_static_maya_mel_eval_payloads(
            &source,
            crate::scene::MelParseBudget::default().max_bytes
        ),
        [PAYLOAD, "print \"Example\";"]
    );
}

#[test]
fn existing_binding_notifications_preserve_order() {
    for body in [
        "for cmd in mm.eval(cmd):\n    mm.eval(cmd)",
        "with mm.eval(cmd) as cmd, mm.eval(cmd): pass",
        "del cmd, sample[mm.eval(cmd)]",
    ] {
        let source = format!("import maya.mel as mm\ncmd = 'print \"Example\";'\n{body}");
        let expected = if body.starts_with("del") { 0 } else { 1 };
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                &source,
                crate::scene::MelParseBudget::default().max_bytes
            )
            .len(),
            expected
        );
        assert_eq!(
            summarize_python_surface(&source, crate::scene::MelParseBudget::default().max_bytes).2,
            EffectCertainty::Uncertain
        );
    }
    for body in [
        "[mm.eval(cmd) for cmd in []]",
        "try: pass\nexcept Exception as cmd: mm.eval(cmd)",
        "(cmd := 'print \"Sample\";')\nmm.eval(cmd)",
    ] {
        let source = format!("import maya.mel as mm\ncmd = 'print \"Example\";'\n{body}");
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                &source,
                crate::scene::MelParseBudget::default().max_bytes
            ),
            ["print \"Example\";"]
        );
    }
}

#[test]
fn existing_expression_positions_are_visited_once() {
    for source in [
        format!("[{BRIDGE} for sample in []]"),
        format!("{{{BRIDGE} for sample in []}}"),
        format!("{{{BRIDGE}: 1 for sample in []}}"),
        format!("({BRIDGE} for sample in [])"),
        format!("Example(sample={BRIDGE})"),
        format!("mm.eval('print \"Sample\";', sample={BRIDGE})"),
    ] {
        let payloads = collect_static_maya_mel_eval_payloads(
            &format!("import maya.mel as mm\n{source}"),
            crate::scene::MelParseBudget::default().max_bytes,
        );
        assert_eq!(
            payloads
                .iter()
                .filter(|value| value.as_str() == PAYLOAD)
                .count(),
            1
        );
    }
    let summary = summarize_python_surface(
        "Example(sample=Sample())",
        crate::scene::MelParseBudget::default().max_bytes,
    );
    assert_eq!(summary.3.len(), 2);
    let summary = summarize_python_surface(
        "import maya.mel as mm\nmm.eval('print \"Example\";', sample=Example())",
        crate::scene::MelParseBudget::default().max_bytes,
    );
    assert_eq!(summary.2, EffectCertainty::Uncertain);
    assert_eq!(summary.3.len(), 2);
}

#[test]
fn literals_empty_input_and_parse_failures_preserve_semantics() {
    let annotation = format!("import maya.mel as mm\nsample: '''{BRIDGE}'''");
    assert!(
        collect_static_maya_mel_eval_payloads(
            &annotation,
            crate::scene::MelParseBudget::default().max_bytes
        )
        .is_empty()
    );
    assert_eq!(
        summarize_python_surface(
            &annotation,
            crate::scene::MelParseBudget::default().max_bytes
        )
        .2,
        EffectCertainty::Proven
    );
    for source in [
        "",
        "1 + 2",
        "sample: 'Example()'",
        "match sample:\n    case Example.Value: pass\n    case Example(sample=Example.Value): pass\n    case {'Example': [None, *_]}: pass",
    ] {
        assert!(
            parse_python_compat_suite(source, crate::scene::MelParseBudget::default().max_bytes)
                .is_some()
        );
        let summary =
            summarize_python_surface(source, crate::scene::MelParseBudget::default().max_bytes);
        assert_eq!(summary.0, ExecutionEffectClass::PureComputation);
        assert_eq!(summary.2, EffectCertainty::Proven);
        assert!(
            collect_static_maya_mel_eval_payloads(
                source,
                crate::scene::MelParseBudget::default().max_bytes
            )
            .is_empty()
        );
    }
    for source in [
        "import maya.mel as mm\nmm.eval(f'Example')",
        "import maya.mel as mm\nmm.eval(Example)",
        "import maya.mel as mm\nmm.eval()",
        "def (",
    ] {
        assert!(
            collect_static_maya_mel_eval_payloads(
                source,
                crate::scene::MelParseBudget::default().max_bytes
            )
            .is_empty()
        );
        assert_eq!(
            summarize_python_surface(source, crate::scene::MelParseBudget::default().max_bytes).2,
            EffectCertainty::Uncertain
        );
    }
}

#[test]
fn isolated_imports_and_nested_bodies_preserve_uncertainty() {
    for (body, expected_payloads) in [
        (
            "try: pass\nexcept* Exception: import maya.mel as mm",
            &["print 1;"][..],
        ),
        (
            "try: pass\nexcept* Exception: from maya import mel as mm",
            &["print 1;"][..],
        ),
        (
            "match sample:\n    case _: import maya.mel as mm",
            &["print 1;"][..],
        ),
        (
            "match sample:\n    case _:\n        try: pass\n        except* Exception: import maya.mel as mm",
            &["print 1;"][..],
        ),
        (
            "try:\n    match sample:\n        case _: import maya.mel as mm\nexcept* Exception: pass",
            &["print 1;"][..],
        ),
        (
            "match sample:\n    case _:\n        def Example(): import maya.mel as mm",
            &[][..],
        ),
        (
            "try:\n    class Example: from maya import mel as mm\nexcept* Exception: pass",
            &[][..],
        ),
    ] {
        let source = format!("{body}\nmm.eval('print 1;')");
        assert!(
            parse_python_compat_suite(&source, crate::scene::MelParseBudget::default().max_bytes)
                .is_some(),
            "{source}"
        );
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                &source,
                crate::scene::MelParseBudget::default().max_bytes
            ),
            expected_payloads,
            "{source}"
        );
        assert_eq!(
            summarize_python_surface(&source, crate::scene::MelParseBudget::default().max_bytes).2,
            EffectCertainty::Uncertain,
            "{source}"
        );
    }
    for body in [
        "try: pass\nexcept* Exception as cmd: pass\nexcept* Sample: mm.eval(cmd)",
        "match sample:\n    case 1:\n        match sample:\n            case cmd: mm.eval(cmd)\n    case _: mm.eval(cmd)",
        "try: cmd = 'print 2;'\nexcept* Exception: pass\nelse: mm.eval(cmd)\nfinally: mm.eval(cmd)",
    ] {
        let source = format!("import maya.mel as mm\ncmd = 'print 1;'\n{body}");
        let payloads = collect_static_maya_mel_eval_payloads(
            &source,
            crate::scene::MelParseBudget::default().max_bytes,
        );
        assert!(!payloads.is_empty(), "{source}");
        assert!(payloads.iter().all(|s| s == "print 1;"), "{source}");
        assert_eq!(
            summarize_python_surface(&source, crate::scene::MelParseBudget::default().max_bytes).2,
            EffectCertainty::Uncertain,
            "{source}"
        );
    }
}

#[test]
fn local_body_bridges_and_existing_reason_sets_are_preserved() {
    for body in [
        "match sample:\n    case _:\n        cmd = 'print 1;'\n        mm.eval(cmd)",
        "try:\n    cmd = 'print 1;'\n    mm.eval(cmd)\nexcept* Exception: pass",
        "try: pass\nexcept* Exception:\n    cmd = 'print 1;'\n    mm.eval(cmd)",
        "try:\n    cmd = 'print 1;'\n    mm.eval(cmd)\nexcept Exception: pass",
    ] {
        let source = format!("import maya.mel as mm\n{body}");
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                &source,
                crate::scene::MelParseBudget::default().max_bytes
            ),
            ["print 1;"]
        );
        assert_eq!(
            summarize_python_surface(&source, crate::scene::MelParseBudget::default().max_bytes).2,
            EffectCertainty::Proven
        );
    }
    for source in [
        "Example(sample=Sample())",
        "{Example(): Sample()}",
        "[Example(Sample()) for sample in []]",
        "try: Example()\nexcept Sample(): pass",
        "match Example():\n    case _ if Sample(): pass",
    ] {
        let reasons =
            summarize_python_surface(source, crate::scene::MelParseBudget::default().max_bytes).3;
        for name in ["Example", "Sample"] {
            assert!(
                reasons.iter().any(|reason| matches!(reason,
                crate::scene::ExecutionReason::Named {
                    template: crate::scene::ExecutionReasonTemplate::UnclassifiedPythonCallDetected,
                    value,
                } if value == name)),
                "{source}: {reasons:?}"
            );
        }
    }
}

fn depth_source(shape: &str, depth: usize, sink: &str) -> String {
    match shape {
        "if" => format!(
            "if True: pass\n{}else: {sink}",
            "elif True: pass\n".repeat(depth - 1)
        ),
        "list" => format!("{}{sink}{}", "[".repeat(depth), "]".repeat(depth)),
        "unary" => format!("{}{sink}", "-".repeat(depth)),
        "call" => format!("{}{sink}{}", "Example(".repeat(depth), ")".repeat(depth)),
        "power" => format!("{}{sink}", "2**".repeat(depth)),
        "lambda" => format!("{}{sink}", "lambda: ".repeat(depth)),
        "binary" => format!("{}{sink}", "1 + ".repeat(depth)),
        "parentheses" => format!("{}{sink}{}", "(".repeat(depth), ")".repeat(depth)),
        "def" | "class" | "with" | "try" | "match" => {
            let mut source = String::new();
            let step = if shape == "match" { 2 } else { 1 };
            for level in 0..depth {
                let indent = " ".repeat(level * step);
                let header = match shape {
                    "def" => "def Example():",
                    "class" => "class Example:",
                    "with" => "with sample:",
                    "try" => "try:",
                    "match" => "match sample:",
                    _ => unreachable!(),
                };
                source.push_str(&format!("{indent}{header}\n"));
                if shape == "match" {
                    source.push_str(&format!("{indent} case _:\n"));
                }
            }
            source.push_str(&format!("{}{sink}\n", " ".repeat(depth * step)));
            if shape == "try" {
                for level in (0..depth).rev() {
                    source.push_str(&format!("{}except Exception: pass\n", " ".repeat(level)));
                }
            }
            source
        }
        "comprehension" => format!(
            "{}{sink}{}",
            "[sample for sample in [] if ".repeat(depth),
            "]".repeat(depth)
        ),
        "pattern" => format!(
            "match sample:\n case {}None{} if {sink}: pass",
            "[".repeat(depth),
            "]".repeat(depth)
        ),
        _ => unreachable!(),
    }
}

#[test]
fn visitors_preserve_depth_on_two_mib_stack() {
    for (shape, effect_depth, bridge_depth) in [
        ("if", 1124, 1124),
        ("list", 945, 945),
        ("unary", 1035, 1035),
        ("call", 945, 945),
        ("power", 1035, 1035),
        ("lambda", 1035, 1035),
        ("binary", 1036, 1036),
        ("parentheses", 500, 500),
        ("def", 973, 973),
        ("class", 973, 973),
        ("with", 1124, 1124),
        ("try", 1124, 1124),
        ("match", 1124, 1124),
        ("comprehension", 686, 686),
        ("fstring", 494, 494),
        ("pattern", 2719, 2719),
    ] {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                if shape == "fstring" {
                    let program = nested_fstring_suite(effect_depth, "ExampleSink()");
                    assert_sink_reason(&fstring_reasons(&program));
                    let program = nested_fstring_suite(bridge_depth, BRIDGE);
                    assert_eq!(
                        crate::scene::execution::python_source::tests::collect_payloads_from_suite(
                            &program
                        ),
                        [PAYLOAD]
                    );
                    return;
                }
                let source = depth_source(shape, effect_depth, "ExampleSink()");
                assert!(
                    parse_python_compat_suite(
                        &source,
                        crate::scene::MelParseBudget::default().max_bytes
                    )
                    .is_some()
                );
                assert_sink_reason(
                    &summarize_python_surface(
                        &source,
                        crate::scene::MelParseBudget::default().max_bytes,
                    )
                    .3,
                );
                let source = format!(
                    "import maya.mel as mm\n{}",
                    depth_source(shape, bridge_depth, BRIDGE)
                );
                assert_eq!(
                    collect_static_maya_mel_eval_payloads(
                        &source,
                        crate::scene::MelParseBudget::default().max_bytes
                    ),
                    [PAYLOAD]
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

#[test]
fn captured_and_restored_bindings_keep_visitors_consistent() {
    for (body, expected_payloads) in [
        ("match sample:\n    case cmd: mm.eval(cmd)", &[][..]),
        (
            "match sample:\n    case [cmd] if mm.eval(cmd): pass",
            &[][..],
        ),
        (
            "match sample:\n    case mm: mm.eval('print 1;')",
            &["print 1;"][..],
        ),
        (
            "match sample:\n    case mm if mm.eval('print 1;'): pass",
            &["print 1;"][..],
        ),
        ("try: pass\nexcept* Exception as cmd: mm.eval(cmd)", &[][..]),
        (
            "try: pass\nexcept* Exception as mm: mm.eval('print 1;')",
            &["print 1;"][..],
        ),
    ] {
        let source = format!("import maya.mel as mm\ncmd = 'print 1;'\n{body}");
        assert!(
            parse_python_compat_suite(&source, crate::scene::MelParseBudget::default().max_bytes)
                .is_some()
        );
        assert_eq!(
            collect_static_maya_mel_eval_payloads(
                &source,
                crate::scene::MelParseBudget::default().max_bytes
            ),
            expected_payloads,
            "{source}"
        );
        assert_eq!(
            summarize_python_surface(&source, crate::scene::MelParseBudget::default().max_bytes).2,
            EffectCertainty::Uncertain,
            "{source}"
        );
    }
    let source = "import maya.mel as mm\ntry:\n    cmd = 'print 1;'\nexcept* Exception: pass\nelse: mm.eval(cmd)";
    assert!(
        collect_static_maya_mel_eval_payloads(
            source,
            crate::scene::MelParseBudget::default().max_bytes
        )
        .is_empty()
    );
    assert_eq!(
        summarize_python_surface(source, crate::scene::MelParseBudget::default().max_bytes).2,
        EffectCertainty::Uncertain
    );
}

#[test]
fn modified_body_bindings_make_later_bridges_uncertain() {
    for body in [
        "try: pass\nexcept* Exception: import Example as cmd",
        "match sample:\n    case _: mm = 'Example'",
        "try: pass\nexcept* Exception: cmd = 'print 2;'",
        "match sample:\n    case _: cmd = 'print 2;'",
        "try:\n    cmd = 'print 2;'\nexcept* Exception: pass\nelse: mm.eval(cmd)",
        "try: pass\nexcept* Exception: import Example as mm",
        "match sample:\n    case _:\n        def Example(): cmd = 'print 2;'",
        "match sample:\n    case _:\n        class Example: import Example as mm",
    ] {
        let source = format!("import maya.mel as mm\ncmd = 'print 1;'\n{body}\nmm.eval(cmd)");
        let payloads = collect_static_maya_mel_eval_payloads(
            &source,
            crate::scene::MelParseBudget::default().max_bytes,
        );
        assert!(payloads.iter().all(|s| s == "print 1;"), "{source}");
        assert!(!payloads.is_empty());
        assert_eq!(
            summarize_python_surface(&source, crate::scene::MelParseBudget::default().max_bytes).2,
            EffectCertainty::Uncertain,
            "{source}"
        );
    }
}

fn nested_fstring_suite(depth: usize, sink: &str) -> rustpython_parser::ast::Suite {
    use rustpython_parser::ast;
    let mut suite = parse_python_compat_suite(
        &format!("import maya.mel as mm\n{sink}"),
        crate::scene::MelParseBudget::default().max_bytes,
    )
    .unwrap();
    let ast::Stmt::Expr(statement) = suite.last_mut().unwrap() else {
        unreachable!()
    };
    let ast::Stmt::Expr(template) =
        parse_python_compat_suite("f'{0}'", crate::scene::MelParseBudget::default().max_bytes)
            .unwrap()
            .pop()
            .unwrap()
    else {
        unreachable!()
    };
    let ast::Expr::JoinedStr(template) = *template.value else {
        unreachable!()
    };
    for _ in 0..depth {
        let mut wrapper = template.clone();
        let ast::Expr::FormattedValue(formatted) = &mut wrapper.values[0] else {
            unreachable!()
        };
        std::mem::swap(&mut statement.value, &mut formatted.value);
        *statement.value = ast::Expr::JoinedStr(wrapper);
    }
    suite
}

fn fstring_reasons(program: &[rustpython_parser::ast::Stmt]) -> Vec<crate::scene::ExecutionReason> {
    let mut visitor = super::PythonEffectVisitor::default();
    super::walk_suite(&mut visitor, program);
    visitor.finish().3
}

fn assert_sink_reason(reasons: &[crate::scene::ExecutionReason]) {
    assert!(
        reasons.iter().any(|reason| matches!(reason,
            crate::scene::ExecutionReason::Named {
                template: crate::scene::ExecutionReasonTemplate::UnclassifiedPythonCallDetected,
                value,
            } if value == "ExampleSink"
        )),
        "innermost call was not visited: {reasons:?}"
    );
}
