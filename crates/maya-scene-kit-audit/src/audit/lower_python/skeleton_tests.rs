use super::*;

fn assert_import(source: &str) {
    let signals = collect_python_signals(source);
    assert!(
        !signals
            .iter()
            .any(|signal| matches!(signal, PythonSignal::ParseFailure { .. })),
        "{signals:?}"
    );
    assert!(
        signals.iter().any(|signal| matches!(
            signal,
            PythonSignal::Call {
                kind: PythonCallKind::Import,
                ..
            }
        )),
        "{signals:?}"
    );
}

#[test]
fn unvisited_positions_produce_ast_signals() {
    for source in [
        "class Example(__import__('os')): pass",
        "def Example(sample: __import__('os')): pass",
        "def Example() -> __import__('os'): pass",
        "class Example(metaclass=__import__('os')): pass",
        "f\"{0:{__import__('os')}}\"",
        "def Example[T: __import__('os')](): pass",
        "class Example[T: __import__('os')]: pass",
        "type Example = __import__('os')",
    ] {
        assert_import(source);
    }
}

#[test]
fn visited_positions_preserve_signals() {
    let expected = collect_python_signals("__import__('os').system('echo Example')");
    for source in [
        "sample: __import__('os').system('echo Example')",
        "@__import__('os').system('echo Example')\ndef Example(): pass",
        "match 1:\n    case _ if __import__('os').system('echo Example'): pass",
        "try:\n    pass\nexcept* Exception:\n    __import__('os').system('echo Example')",
        "[sample for sample in [1] if __import__('os').system('echo Example')]",
        "lambda sample=__import__('os').system('echo Example'): sample",
    ] {
        assert_eq!(collect_python_signals(source), expected, "{source}");
    }
}

#[test]
fn deeply_nested_binary_expression() {
    let source = format!("{}__import__('os')", "1 + ".repeat(500));
    assert_import(&source);
}

#[test]
fn with_and_handler_bindings_change_after_expression() {
    let source = "import maya.cmds as sample\nwith Example() as sample, sample.file('asset/example/file.ma', open=True):\n    pass";
    assert!(
        !collect_python_signals(source)
            .iter()
            .any(|signal| matches!(signal, PythonSignal::Maya(_)))
    );
    let source = "import maya.cmds as sample\ntry:\n    pass\nexcept sample.file('asset/example/file.ma', open=True) as sample:\n    sample.file('asset/example/file.ma', open=True)";
    assert_eq!(
        collect_python_signals(source)
            .iter()
            .filter(|signal| matches!(signal, PythonSignal::Maya(_)))
            .count(),
        1
    );
}

#[test]
fn first_comprehension_iterable_preserves_enclosing_alias() {
    let source = "import os as helper\ndata = [sample for sample in [(helper := \"Example\")]]\nhelper.system(\"echo Example\")";
    assert!(collect_python_signals(source).iter().any(|signal| matches!(
        signal,
        PythonSignal::Capability(PythonCapabilityKind::Subprocess)
    )));
}

fn depth_source(shape: &str, depth: usize) -> String {
    let sink = "__import__('os')";
    match shape {
        "if" => format!(
            "if True: pass\n{}else: {}",
            "elif True: pass\n".repeat(depth - 1),
            sink
        ),
        "list" => format!("{}{}{}", "[".repeat(depth), sink, "]".repeat(depth)),
        "unary" => format!("{}{}", "-".repeat(depth), sink),
        "call" => format!("{}{}{}", "Example(".repeat(depth), sink, ")".repeat(depth)),
        "power" => format!("{}{}", "2**".repeat(depth), sink),
        "lambda" => format!("{}{}", "lambda: ".repeat(depth), sink),
        _ => panic!("unknown shape"),
    }
}

macro_rules! depth_test {
    ($name:ident, $shape:literal, $depth:literal) => {
        #[test]
        fn $name() {
            std::thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(|| assert_import(&depth_source($shape, $depth)))
                .unwrap()
                .join()
                .unwrap();
        }
    };
}

depth_test!(deeply_nested_if_elif, "if", 271);
depth_test!(deeply_nested_lists, "list", 537);
depth_test!(deeply_nested_unary_minus, "unary", 565);
depth_test!(deeply_nested_calls, "call", 537);
depth_test!(deeply_nested_power_chain, "power", 565);
depth_test!(deeply_nested_lambdas, "lambda", 565);

fn maya_count(source: &str) -> usize {
    assert!(ast::Suite::parse(source, "Example").is_ok());
    collect_python_signals(source)
        .iter()
        .filter(|signal| matches!(signal, PythonSignal::Maya(_)))
        .count()
}

#[test]
fn definition_names_clear_after_headers() {
    for definition in [
        "class sample(sample.file('asset/example/file.ma', open=True)):\n    sample.file('asset/example/file.ma', open=True)",
        "def sample(value: sample.file('asset/example/file.ma', open=True)):\n    sample.file('asset/example/file.ma', open=True)",
        "async def sample() -> sample.file('asset/example/file.ma', open=True):\n    sample.file('asset/example/file.ma', open=True)",
    ] {
        assert_eq!(
            maya_count(&format!(
                "import maya.cmds as sample\n{definition}\nsample.file('asset/example/file.ma', open=True)"
            )),
            1,
            "{definition}"
        );
    }
}

#[test]
fn class_body_preserves_outer_alias_without_function_local_shadowing() {
    assert_eq!(
        maya_count(
            "import maya.cmds as sample\ndef Example(sample):\n    class TestAsset:\n        sample.file('asset/example/file.ma', open=True)"
        ),
        0
    );
    assert_eq!(
        maya_count(
            "import maya.cmds as sample\ndef Example(value):\n    class TestAsset:\n        sample.file('asset/example/file.ma', open=True)"
        ),
        1
    );
    assert_eq!(
        maya_count(
            "import maya.cmds as sample\nclass Example:\n    sample.file('asset/example/file.ma', open=True)\n    sample = None"
        ),
        1
    );
}

#[test]
fn lambda_arguments_shadow_only_the_body() {
    assert_eq!(
        maya_count(
            "import maya.cmds as sample\n(lambda sample=sample.file('asset/example/file.ma', open=True): sample.file('asset/example/file.ma', open=True))\nsample.file('asset/example/file.ma', open=True)"
        ),
        2
    );
}

#[test]
fn comprehension_target_shadows_after_iterable_and_restores_outer_alias() {
    assert_eq!(
        maya_count(
            "import maya.cmds as sample\n[sample.file('asset/example/file.ma', open=True) for sample in sample.file('asset/example/file.ma', open=True) if sample.file('asset/example/file.ma', open=True)]\nsample.file('asset/example/file.ma', open=True)"
        ),
        2
    );
}

#[test]
fn conditional_alias_bindings_are_unresolved_after_control_flow() {
    for body in [
        "for value in []:\n    import maya.cmds as sample",
        "try:\n    import maya.cmds as sample\nexcept Exception:\n    pass",
        "match value:\n    case 1:\n        import maya.cmds as sample",
    ] {
        let source = format!("{body}\nsample.file('asset/example/file.ma', open=True)");
        assert!(ast::Suite::parse(&source, "Example").is_ok());
        let signals = collect_python_signals(&source);
        assert_eq!(
            signals
                .iter()
                .filter(|signal| matches!(signal, PythonSignal::MayaUncertain { .. }))
                .count(),
            1,
            "{body}: {signals:?}"
        );
        assert!(
            !signals
                .iter()
                .any(|signal| matches!(signal, PythonSignal::Maya(_))),
            "{body}: {signals:?}"
        );
    }
}

#[test]
fn type_parameter_walk_can_be_called_by_an_external_visitor() {
    use maya_scene_kit_observe::scene::execution::python_walk::walk_type_param;
    let suite = ast::Suite::parse("def Example[T: __import__('os')](): pass", "Example").unwrap();
    let ast::Stmt::FunctionDef(function) = &suite[0] else {
        panic!("expected function")
    };
    let mut visitor = SignalVisitor::default();
    walk_type_param(&mut visitor, &function.type_params[0]);
    assert!(visitor.signals.iter().any(|signal| matches!(
        signal,
        PythonSignal::Call {
            kind: PythonCallKind::Import,
            ..
        }
    )));
}
