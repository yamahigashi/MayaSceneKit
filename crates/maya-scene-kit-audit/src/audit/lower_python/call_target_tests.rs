use super::*;

fn unresolved(source: &str) -> usize {
    collect_python_signals(
        source,
        maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes,
    )
    .iter()
    .filter(|signal| matches!(signal, PythonSignal::UnresolvedCallTarget { .. }))
    .count()
}

fn marker_count(source: &str, marker: &str) -> usize {
    collect_python_signals(
        source,
        maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes,
    )
    .iter()
    .filter_map(|signal| match signal {
        PythonSignal::HardMarker { markers } => Some(markers),
        _ => None,
    })
    .flatten()
    .filter(|value| value.as_str() == marker)
    .count()
}

#[test]
fn unresolved_targets_and_named_callables_are_distinguished() {
    for (source, targets) in [
        (
            "def Example(): pass\nExample = sample\nExample()",
            vec!["Example()"],
        ),
        (
            "def Example(): pass\ndef Sample(Example):\n    Example()",
            vec!["Example()"],
        ),
        ("unknown()", vec!["unknown"]),
        ("obj.method()", vec!["obj"]),
        ("factory()()", vec!["factory", "factory"]),
        ("sample[0]()", vec!["sample"]),
        ("(sample if condition else other)()", vec!["sample"]),
        ("(sample or other)()", vec!["sample"]),
        ("(sample := unknown)()", vec!["sample"]),
        ("async def Example():\n    (await sample)()", vec!["await"]),
        ("def Example(callback):\n    callback()", vec!["callback()"]),
        ("for sample in values:\n    sample()", vec!["sample()"]),
        ("with context as sample:\n    sample()", vec!["sample()"]),
    ] {
        let expected: Vec<_> = targets
            .iter()
            .map(|target| source.rfind(target).unwrap())
            .collect();
        assert_unresolved_positions(source, &expected);
    }
    for source in [
        "print('Example')",
        "len([])",
        "range(2)",
        "import os\nos.path.join('Example', 'Sample')",
        "from sample import Example\nrun = Example\nrun()",
        "def Example(): pass\nExample()",
        "class Example: pass\nExample()",
        "from sample import QWidget\nclass Example(QWidget): pass\nExample()",
        "run = lambda: None\nrun()",
        "log = len\nlog([])",
        "def Example(node):\n    node.split('|')",
        "import maya.cmds as cmds\nfor node in cmds.ls():\n    node.split('|')",
        "import pymel.core as pm\npm.PyNode('Example').attr('Sample').set(1)",
        "import maya.api.OpenMaya as om\nom.MSelectionList().add('Example')",
        "super().setObjectName('Example')",
        "super().__getattribute__('Example')",
    ] {
        assert_eq!(unresolved(source), 0, "{source}");
    }
    for method in [
        "system",
        "popen",
        "execl",
        "execv",
        "spawnl",
        "posix_spawn",
        "remove",
        "unlink",
        "write",
        "writelines",
        "load",
        "loads",
        "Popen",
        "CDLL",
        "WinDLL",
        "PyDLL",
        "OleDLL",
        "eval",
        "exec",
        "compile",
        "__import__",
    ] {
        for receiver in ["factory()", "sample[0]"] {
            let source = format!("def factory(): pass\nsample = []\n{receiver}.{method}()");
            if matches!(method, "write" | "writelines") {
                assert_unresolved_positions(&source, &[]);
                assert_eq!(
                    collect_python_signals(
                        &source,
                        maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes
                    )
                    .iter()
                    .filter(|signal| matches!(
                        signal,
                        PythonSignal::Capability(PythonCapabilityKind::FileWrite)
                    ))
                    .count(),
                    1,
                    "{source}"
                );
            } else {
                assert_unresolved_positions(&source, &[source.rfind(receiver).unwrap()]);
            }
            let call = parse_python_suite(&source).unwrap().pop().unwrap();
            let ast::Stmt::Expr(statement) = call else {
                panic!("expected expression")
            };
            let ast::Expr::Call(call) = statement.value.as_ref() else {
                panic!("expected call")
            };
            assert!(
                SignalVisitor::default().unresolved_target(&call.func, &Binding::default()),
                "{source}"
            );
        }
    }
    assert_eq!(unresolved("def factory(): pass\nfactory()()"), 1);
}

#[test]
fn decorated_definitions_and_implicit_calls_are_checked() {
    for (source, targets) in [
        (
            "@sample\ndef Example(): pass\nExample()",
            vec!["sample", "Example()"],
        ),
        (
            "from sample import decorate\n@decorate\ndef Example(): pass\nExample()",
            vec!["Example()"],
        ),
        ("@sample[0]\ndef Example(): pass", vec!["sample"]),
        ("class Example(metaclass=sample): pass", vec!["sample"]),
        (
            "class Example(factory()): pass\nExample()",
            vec!["factory", "Example()"],
        ),
        (
            "class Example(__import__('sample')): pass\nExample()",
            vec!["Example()"],
        ),
    ] {
        let expected: Vec<_> = targets
            .iter()
            .map(|target| source.rfind(target).unwrap())
            .collect();
        assert_unresolved_positions(source, &expected);
    }
    let signals = collect_python_signals(
        "@exec\ndef Example(): pass",
        maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes,
    );
    assert_eq!(
        signals
            .iter()
            .filter(|signal| matches!(
                signal,
                PythonSignal::Call {
                    kind: PythonCallKind::Exec,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_unresolved_positions("@exec\ndef Example(): pass", &[]);
    assert!(
        collect_python_signals(
            "def Example():\n    exec('Example')\nExample()",
            maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes
        )
        .iter()
        .any(|signal| matches!(
            signal,
            PythonSignal::Call {
                kind: PythonCallKind::Exec,
                ..
            }
        ))
    );
    assert!(
        collect_python_signals(
            "class Example:\n    exec('Example')\nExample()",
            maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes
        )
        .iter()
        .any(|signal| matches!(
            signal,
            PythonSignal::Call {
                kind: PythonCallKind::Exec,
                ..
            }
        ))
    );
}

#[test]
fn builtin_mutations_and_existing_binding_signals_are_preserved() {
    for source in [
        "import sys\nsys.modules[key].print = exec\nprint('Example')",
        "import sys\nmodules = sys.modules\nmodules[key] = sample\nprint('Example')",
        "import builtins\nbuiltins.print = exec\nprint('Example')",
        "import builtins\nbuiltins.print = exec\nlog = print\nlog('Example')",
    ] {
        let target = if source.contains("log('Example')") {
            "log('Example')"
        } else {
            "print('Example')"
        };
        assert_unresolved_positions(source, &[source.rfind(target).unwrap()]);
    }
    assert_unresolved_positions("from sample import *\nprint('Example')", &[21]);
    assert_eq!(
        unresolved("import builtins\nprint('Example')\nbuiltins.print = exec\nprint('Sample')"),
        1
    );
    for source in [
        "(print := exec)('Example')",
        "match exec:\n    case print:\n        print('Example')",
        "import os\nos.system('echo Example')",
    ] {
        assert!(
            collect_python_signals(
                source,
                maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes
            )
            .iter()
            .any(|signal| matches!(
                signal,
                PythonSignal::Call { .. } | PythonSignal::Capability(_)
            )),
            "{source}"
        );
    }
}

#[test]
fn introspection_attributes_are_marked_at_each_occurrence() {
    for receiver in ["print", "obj"] {
        for marker in [
            "__import__",
            "__builtins__",
            "__globals__",
            "__subclasses__",
            "__code__",
            "__closure__",
            "__self__",
        ] {
            for suffix in ["", "()"] {
                let source = format!("{receiver}.{marker}{suffix}");
                assert_eq!(marker_count(&source, marker), 1, "{source}");
            }
        }
        assert_eq!(
            marker_count(
                &format!("{receiver}.__getattribute__(sample)"),
                "__getattribute__"
            ),
            1
        );
        for suffix in ["", "('Example')"] {
            assert_eq!(
                marker_count(
                    &format!("{receiver}.__getattribute__{suffix}"),
                    "__getattribute__"
                ),
                0
            );
        }
        for marker in ["__class__", "__dict__"] {
            assert_eq!(marker_count(&format!("{receiver}.{marker}"), marker), 0);
            assert_unresolved_positions(&format!("{receiver}.{marker}[0]()"), &[0]);
        }
    }
    let signals = collect_python_signals(
        "f\"{print.__self__.__import__('os').system('echo Example')}\"",
        maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes,
    );
    assert!(
        !signals
            .iter()
            .any(|signal| matches!(signal, PythonSignal::ParseFailure { .. }))
    );
}

#[test]
fn successful_text_scan_tracks_positions_and_excludes_comments() {
    for (source, marker, count) in [
        ("'__import__'", "__import__", 1),
        ("from builtins import builtins", "builtins", 2),
        ("import builtins as builtins", "builtins", 2),
        ("from  builtins import print", "builtins", 1),
        ("__import__('os')", "__import__", 1),
        ("obj.__import__('os')", "__import__", 1),
        ("obj.__import__; obj.__import__", "__import__", 2),
        ("'Example é'; obj.__import__; '__import__'", "__import__", 2),
        ("'__builtins__'", "builtins", 0),
        ("'__builtins__'", "__builtins__", 1),
        ("'Example_builtins'; 'ébuiltins'", "builtins", 0),
        ("# __import__\nprint('Example')", "__import__", 0),
        ("'Example # __import__'", "__import__", 1),
        ("'''Example\n__import__'''", "__import__", 1),
        ("print '__import__'", "__import__", 1),
        ("print obj.__import__", "__import__", 2),
    ] {
        assert_eq!(marker_count(source, marker), count, "{source}");
    }
}

fn assert_unresolved_positions(source: &str, expected: &[usize]) {
    let mut actual: Vec<usize> = collect_python_signals(
        source,
        maya_scene_kit_observe::scene::MelParseBudget::default().max_bytes,
    )
    .iter()
    .filter_map(|signal| match signal {
        PythonSignal::UnresolvedCallTarget { message } => Some(
            message
                .split("at byte ")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap(),
        ),
        _ => None,
    })
    .collect();
    actual.sort_unstable();
    assert_eq!(actual, expected, "{source}");
}

#[test]
fn decorator_factory_calls_have_one_signal_per_position() {
    for source in [
        "from functools import wraps\n@wraps(print)\ndef Example(): pass",
        "from sample import Slot\n@Slot()\ndef Example(): pass",
        "from sample import factory\n@factory()\nclass Example: pass",
    ] {
        assert_unresolved_positions(source, &[]);
    }
    let source = "@sample(1)\ndef Example(): pass";
    assert_unresolved_positions(source, &[1]);
    let source = "from sample import factory\n@factory()\ndef Example(): pass\nExample()";
    assert_unresolved_positions(source, &[source.rfind("Example()").unwrap()]);
}

#[test]
fn local_class_bases_preserve_constructor_identity() {
    assert_unresolved_positions(
        "from sample import Widget\nclass Base(object): pass\nclass Child(Base, Widget): pass\nclass Example(Child): pass\nExample()",
        &[],
    );
    for header in ["factory()", "sample[0]"] {
        let source =
            format!("from sample import factory, sample\nclass Example({header}): pass\nExample()");
        assert_unresolved_positions(&source, &[source.rfind("Example()").unwrap()]);
    }
}

#[test]
fn unrelated_module_assignments_preserve_builtins() {
    for target in ["sys.modules", "modules"] {
        let source = format!(
            "import sys\nmodules = sys.modules\n{target}['Example'] = None\nprint('Example')\nlen([])"
        );
        assert_unresolved_positions(&source, &[]);
        for key in ["'builtins'", "'__builtin__'", "key"] {
            let source = format!(
                "import sys\nmodules = sys.modules\n{target}[{key}] = None\nprint('Example')\nlen([])"
            );
            assert_unresolved_positions(
                &source,
                &[source.find("print(").unwrap(), source.find("len(").unwrap()],
            );
        }
    }
}

#[test]
fn value_method_receivers_preserve_named_parts() {
    for receiver in [
        "(a - b)",
        "(-a)",
        "f'{a}_{b}'",
        "'Example'",
        "[a]",
        "(a, b)",
        "{'Example': a}",
        "{a}",
        "(a == b)",
        "(a or b)",
    ] {
        let source = format!("def Example(a, b):\n    {receiver}.sample()");
        assert_unresolved_positions(&source, &[]);
    }
    for receiver in ["(a if a else b)", "(a := b)"] {
        let source = format!("def Example(a, b):\n    {receiver}.sample()");
        assert_unresolved_positions(&source, &[source.find(receiver).unwrap()]);
    }
}

#[test]
fn wildcard_imports_name_non_builtin_calls() {
    assert_unresolved_positions(
        "from maya.cmds import *\nfile(q=True)\nls(sl=True)\npolySphere()",
        &[],
    );
    assert_unresolved_positions("from sample import *\nExample()\nExample.method()", &[]);
    let source = "from sample import *\nprint('Example')";
    assert_unresolved_positions(source, &[source.find("print(").unwrap()]);
}

#[test]
fn imported_markers_use_identifier_occurrences() {
    for module in ["six.moves", "om", "rom"] {
        let source = format!("from {module} import builtins");
        assert_eq!(marker_count(&source, "builtins"), 1, "{source}");
        let mut visitor = SignalVisitor {
            source: &source,
            ..SignalVisitor::default()
        };
        visitor.enter(ScopeKind::Module, LocalBindings::default());
        walk_suite(&mut visitor, &parse_python_suite(&source).unwrap());
        let range = visitor.import_module_range(
            ast::text_size::TextRange::new(0.into(), (source.len() as u32).into()),
            module,
        );
        assert_eq!(range.start().to_usize(), 5, "{source}");
        let positions: Vec<_> = visitor
            .marker_occurrences
            .iter()
            .filter(|(label, _)| label == "builtins")
            .map(|(_, range)| range.start().to_usize())
            .collect();
        assert_eq!(
            positions,
            vec![source.find("builtins").unwrap()],
            "{source}"
        );
    }
}
