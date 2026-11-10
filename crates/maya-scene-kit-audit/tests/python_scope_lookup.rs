use maya_scene_kit_audit::scene::{AuditFindingCode, ExecutionLanguage, audit_source_text};

#[test]
fn outer_callable_bindings_are_visible_in_nested_scopes() {
    let mut missed = Vec::new();
    for (binding, call, expected) in [
        (
            "run = exec",
            "run(\"print('Example')\")",
            AuditFindingCode::PythonExec,
        ),
        (
            "from os import system as s",
            "s('echo Example')",
            AuditFindingCode::PythonSubprocess,
        ),
    ] {
        for body in [
            format!("def Example():\n    {call}"),
            format!("async def Example():\n    {call}"),
            format!("def Example():\n    def Sample():\n        {call}"),
            format!("lambda: {call}"),
            format!("[{call} for sample in []]"),
            format!("{{{call} for sample in []}}"),
            format!("{{sample: {call} for sample in []}}"),
            format!("({call} for sample in [])"),
        ] {
            let source = format!("{binding}\n{body}");
            let report = audit_source_text(&source, ExecutionLanguage::Python).unwrap();
            if !report
                .findings
                .iter()
                .any(|finding| finding.code == expected)
            {
                missed.push(source);
            }
        }
    }
    assert!(missed.is_empty(), "missed bindings: {missed:#?}");
}

fn count(source: &str, code: AuditFindingCode) -> usize {
    audit_source_text(source, ExecutionLanguage::Python)
        .unwrap()
        .findings
        .iter()
        .filter(|finding| finding.code == code)
        .count()
}

#[test]
fn lexical_bindings_shadow_all_outer_categories() {
    let mut failures = Vec::new();
    for (binding, name, call, code) in [
        (
            "run = exec",
            "run",
            "run('Example')",
            AuditFindingCode::PythonExec,
        ),
        (
            "from os import system as s",
            "s",
            "s('echo Example')",
            AuditFindingCode::PythonSubprocess,
        ),
        (
            "import os as sample",
            "sample",
            "sample.system('echo Example')",
            AuditFindingCode::PythonSubprocess,
        ),
        ("", "exec", "exec('Example')", AuditFindingCode::PythonExec),
        (
            "",
            "open",
            "open('asset/example/file.ma')",
            AuditFindingCode::PythonFileOpen,
        ),
    ] {
        for args in [
            format!("{name}, /"),
            name.to_string(),
            format!("*, {name}"),
            format!("*{name}"),
            format!("**{name}"),
        ] {
            for body in [
                format!("def Example({args}):\n    {call}"),
                format!("lambda {args}: {call}"),
            ] {
                let source = format!("{binding}\n{body}");
                if count(&source, code) != 0 {
                    failures.push(source);
                }
            }
        }
        for body in [
            format!("def Example():\n    {call}\n    {name} = None"),
            format!("def Example():\n    {call}\n    {name}: object"),
            format!("def Example():\n    {call}\n    ({name} := None)"),
            format!("def Example():\n    {call}\n    match None:\n        case {name}: pass"),
            format!("def Example():\n    for {name} in []:\n        {call}"),
            format!("def Example():\n    with Example() as {name}:\n        {call}"),
            format!(
                "def Example():\n    try: pass\n    except Exception as {name}:\n        {call}"
            ),
            format!("def Example():\n    import sample as {name}\n    {call}"),
            format!("def Example():\n    def {name}(): pass\n    {call}"),
            format!("[{call} for {name} in []]"),
        ] {
            let source = format!("{binding}\n{body}");
            if count(&source, code) != 0 {
                failures.push(source);
            }
        }
    }
    assert!(failures.is_empty(), "shadowed sinks: {failures:#?}");
}

#[test]
fn class_frames_are_visible_only_to_their_own_body() {
    for body in [
        "def Sample():\n        run('Example')",
        "sample = lambda: run('Example')",
        "sample = [run('Example') for value in []]",
        "class Sample:\n        run('Example')",
    ] {
        let source =
            format!("run = exec\nclass Example:\n    run = print\n    run('Example')\n    {body}");
        assert_eq!(count(&source, AuditFindingCode::PythonExec), 1, "{source}");
    }
    let source = "run = exec\nclass Example:\n    run = print\n    [run('Example') for value in run('Example')]";
    assert_eq!(count(source, AuditFindingCode::PythonExec), 1);
    let source = "run = exec\nclass Example:\n    run('Example')\n    run = print";
    assert_eq!(count(source, AuditFindingCode::PythonExec), 1);
}

#[test]
fn declaration_writes_preserve_dangerous_candidates() {
    for source in [
        "def Example():\n    global exec\n    exec('Example')",
        "def Example():\n    global exec\n    exec = print\nexec('Example')",
        "run = exec\ndef Example():\n    global run\n    run('Example')",
        "run = print\ndef Example():\n    global run\n    run = exec\n    run('Example')",
        "run = exec\ndef Example():\n    global run\n    run = print\nrun('Example')",
        "def run(): pass\ndef Example():\n    global run\n    run = exec\nrun('Example')",
        "run = print\ndef Example():\n    if True:\n        global run\n    run = exec\nrun('Example')",
        "def Example():\n    run = exec\n    def Sample():\n        nonlocal run\n        run('Example')",
        "def Example():\n    run = print\n    def Sample():\n        nonlocal run\n        run = exec\n        run('Example')",
        "def Example():\n    run = print\n    class Sample:\n        run = print\n        def TestAsset():\n            nonlocal run\n            run = exec\n    run('Example')",
        "run = exec\ndef Example():\n    global run\n    del run\nrun('Example')",
        "def Example():\n    run = exec\n    def Sample():\n        nonlocal run\n        del run\n    run('Example')",
        "run = print\ndef Example():\n    global run\n    run = exec\n    def Sample():\n        run('Example')",
    ] {
        assert!(count(source, AuditFindingCode::PythonExec) > 0, "{source}");
    }
    let source = "run = exec\ndef Example():\n    run = print\n    def Sample():\n        global run\n        run('Example')\n    run('Example')";
    assert_eq!(count(source, AuditFindingCode::PythonExec), 1);
}

#[test]
fn binding_forms_record_callable_values_and_restore_outer_scopes() {
    let source = "import maya.cmds as sample\nsample.file = run = sample.file\nrun('asset/example/file.ma', open=True)";
    assert_eq!(count(source, AuditFindingCode::PythonMayaFile), 1);

    for body in [
        "(run := exec)\nrun('Example')",
        "run: object = exec\nrun('Example')",
        "match exec:\n    case run:\n        run('Example')",
        "for run in [exec]:\n    run('Example')",
        "with exec as run:\n    run('Example')",
        "try: pass\nexcept exec as run:\n    run('Example')",
        "[run('Example') for run in [exec]]",
        "[(run := exec) for sample in []]\nrun('Example')",
    ] {
        assert!(count(body, AuditFindingCode::PythonExec) > 0, "{body}");
    }
    for body in [
        "def Example(run): pass",
        "lambda run: run('Example')",
        "[run('Example') for run in []]",
        "def Example():\n    for run in []: pass",
        "def Example():\n    with Example() as run: pass",
        "def Example():\n    try: pass\n    except Exception as run: pass",
        "def Example():\n    match None:\n        case run: pass",
        "def Example():\n    import sample as run",
        "def Example():\n    def run(): pass",
        "def Example():\n    (run := None)",
    ] {
        let source = format!("run = exec\n{body}\nrun('Example')");
        assert_eq!(count(&source, AuditFindingCode::PythonExec), 1, "{source}");
    }
}

#[test]
fn outer_modules_and_assembled_strings_follow_callable_lookup() {
    for call in ["sample.system('echo Example')", "run(body)"] {
        for nested in [
            format!("def Example():\n    {call}"),
            format!("async def Example():\n    {call}"),
            format!("def Example():\n    def Sample():\n        {call}"),
            format!("class Example:\n    {call}"),
            format!("lambda: {call}"),
            format!("[{call} for value in []]"),
            format!("{{{call} for value in []}}"),
            format!("{{value: {call} for value in []}}"),
            format!("({call} for value in [])"),
        ] {
            let source = format!(
                "import os as sample\nrun = exec\nbody = 'print(' + '\"Example\")'\n{nested}"
            );
            let report = audit_source_text(&source, ExecutionLanguage::Python).unwrap();
            if call.starts_with("sample") {
                assert!(
                    report
                        .findings
                        .iter()
                        .any(|finding| finding.code == AuditFindingCode::PythonSubprocess),
                    "{source}"
                );
            } else {
                let finding = report
                    .findings
                    .iter()
                    .find(|finding| finding.code == AuditFindingCode::PythonExec)
                    .unwrap_or_else(|| panic!("{source}"));
                assert!(
                    format!("{:?}", finding.evidence).contains(" + "),
                    "{source}"
                );
            }
        }
    }
    for body in ["body", "*, body", "*body", "**body", "body, /"] {
        let source =
            format!("body = 'print(' + '\"Example\")'\ndef Example({body}):\n    exec(body)");
        let report = audit_source_text(&source, ExecutionLanguage::Python).unwrap();
        assert!(
            !format!("{:?}", report.findings).contains(" + "),
            "{source}"
        );
    }
}

#[test]
fn hidden_dangerous_targets_remain_unresolved_unless_proven_callable() {
    for source in [
        "unknown('Example')",
        "def Example(exec):\n    exec('Example')",
        "run = exec\nlambda run: run('Example')",
        "from os import system as s\n[s('echo Example') for s in []]",
        "import os as sample\ndef Example():\n    sample.system('echo Example')\n    (sample := None)",
        "run = exec\nrun = None\nrun('Example')",
        "def Example(open):\n    open('asset/example/file.ma')",
        "exec = print\nexec = None\nexec('Example')",
        "exec = print\nexec = lambda: None\ndef Example():\n    global exec\n    exec = None\nexec('Example')",
    ] {
        assert_eq!(
            count(source, AuditFindingCode::PythonUnresolvedCallTarget),
            1,
            "{source}"
        );
        assert_eq!(count(source, AuditFindingCode::PythonExec), 0, "{source}");
    }
    for source in [
        "exec = print\nexec('Example')",
        "def exec(sample): pass\nexec('Example')",
        "exec = lambda sample: None\nexec('Example')",
        "run = exec\nrun = print\nrun('Example')",
        "run = exec\ndef run(sample): pass\nrun('Example')",
        "run = exec\nrun = lambda sample: None\nrun('Example')",
        "import maya.cmds as sample\ndef Example(sample):\n    sample.file(query=True)",
    ] {
        assert_eq!(
            count(source, AuditFindingCode::PythonUnresolvedCallTarget),
            0,
            "{source}"
        );
    }
}

#[test]
fn first_comprehension_iterables_do_not_apply_named_bindings() {
    for source in [
        "import os as sample\n[value for value in [(sample := 'Example')]]\nsample.system('echo Example')",
        "run = exec\n[value for value in [(run := print)]]\nrun('Example')",
        "run = exec\ndef Example():\n    run('Example')\n    [value for value in [(run := print)]]",
    ] {
        let code = if source.starts_with("import") {
            AuditFindingCode::PythonSubprocess
        } else {
            AuditFindingCode::PythonExec
        };
        assert_eq!(count(source, code), 1, "{source}");
    }
}

#[test]
fn conditional_and_deferred_writes_do_not_erase_dangerous_candidates() {
    let source = "run = exec\nif Example:\n    run = print\nrun = print\nrun('Example')";
    assert_eq!(count(source, AuditFindingCode::PythonExec), 0);
    assert_eq!(
        count(source, AuditFindingCode::PythonUnresolvedCallTarget),
        0
    );

    for source in [
        "run = exec\n[(run := print) for sample in []]\nrun('Example')",
        "run = exec\nif Example:\n    run = print\nrun('Example')",
        "from os import system as run\nif Example:\n    run = print\nrun('echo Example')",
        "run = exec\ndef Example():\n    class Sample:\n        global run\n        run = print\nrun('Example')",
        "run = exec\ndef Example():\n    global run\n    if Sample:\n        run = print\n    run('Example')",
    ] {
        let code = if source.starts_with("from") {
            AuditFindingCode::PythonSubprocess
        } else {
            AuditFindingCode::PythonExec
        };
        assert_eq!(count(source, code), 1, "{source}");
    }
}

#[test]
fn handler_cleanup_and_safe_imports_preserve_binding_identity() {
    let source = "run = print\ntry: pass\nexcept exec as run:\n    pass\nrun('Example')";
    assert_eq!(count(source, AuditFindingCode::PythonExec), 0);
    assert_eq!(
        count(source, AuditFindingCode::PythonUnresolvedCallTarget),
        1
    );
    for source in [
        "from builtins import print as exec\nexec('Example')",
        "import builtins\nexec = builtins.print\nexec('Example')",
    ] {
        assert_eq!(
            count(source, AuditFindingCode::PythonUnresolvedCallTarget),
            0,
            "{source}"
        );
    }
}

#[test]
fn comprehension_named_bindings_escape_to_enclosing_scope() {
    let mut missed = Vec::new();
    for expression in [
        "[(helper := os) for sample in [0]]",
        "[sample for sample in [0] if (helper := os)]",
        "[sample for sample in [0] for other in [(helper := os)]]",
    ] {
        for source in [
            format!("import os\n{expression}\nhelper.system('echo Example')"),
            format!(
                "import os\ndef Example():\n    {expression}\n    helper.system('echo Example')"
            ),
        ] {
            if count(&source, AuditFindingCode::PythonSubprocess) != 1 {
                missed.push(source);
            }
        }
    }
    assert!(missed.is_empty(), "missing enclosing bindings: {missed:#?}");
}

#[test]
fn conditional_maya_import_alternatives_remain_uncertain() {
    use maya_scene_kit_audit::scene::AuditReviewCode;

    let mut missed = Vec::new();
    for body in [
        "if example_condition:\n    from maya.cmds import file as example_call\nelse:\n    example_call = Example",
        "if example_condition:\n    example_call = Example\nelif sample_condition:\n    from maya.cmds import file as example_call\nelse:\n    example_call = Sample",
        "try:\n    from maya.cmds import file as example_call\nexcept Exception:\n    example_call = Example",
        "for sample in Example:\n    from maya.cmds import file as example_call\nelse:\n    example_call = Example",
        "while example_condition:\n    from maya.cmds import file as example_call\nelse:\n    example_call = Example",
        "match Example:\n    case 0:\n        from maya.cmds import file as example_call\n    case _:\n        example_call = Example",
    ] {
        let source = format!("{body}\nexample_call(q=True)");
        let report = audit_source_text(&source, ExecutionLanguage::Python).unwrap();
        if !report.blocked_on_uncertainty
            || report.unknown_semantics.is_empty()
            || !report.review_signals.iter().any(|review| {
                review.code == AuditReviewCode::PythonMayaUncertain
                    && report
                        .unknown_semantics
                        .iter()
                        .any(|fact| fact.origin == report.surfaces[review.surface_index].origin)
            })
        {
            missed.push(source);
        }
    }
    assert!(
        missed.is_empty(),
        "lost conditional alternatives: {missed:#?}"
    );
}

#[test]
fn annotations_preserve_existing_bindings_and_builtin_fallback() {
    let mut missed = Vec::new();
    for source in [
        "exec: int\nexec('Example')",
        "run = exec\nrun: object\nrun('Example')",
        "class Example:\n    exec: int\n    exec('Example')",
        "run = exec\nclass Example:\n    run: object\n    run('Example')",
        "def Example():\n    run = exec\n    run: object\n    run('Example')",
    ] {
        if count(source, AuditFindingCode::PythonExec) != 1
            || count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 0
        {
            missed.push(source);
        }
    }
    assert!(missed.is_empty(), "annotation changed binding: {missed:#?}");
}

#[test]
fn deletion_restores_outer_lookup_but_keeps_function_locals_unbound() {
    let mut missed = Vec::new();
    for source in [
        "exec = print\ndel exec\nexec('Example')",
        "run = exec\nclass Example:\n    run = print\n    del run\n    run('Example')",
        "class Example:\n    exec = print\n    del exec\n    exec('Example')",
    ] {
        if count(source, AuditFindingCode::PythonExec) != 1
            || count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 0
        {
            missed.push(source);
        }
    }
    for source in [
        "run = exec\ndef Example():\n    run = print\n    del run\n    run('Example')",
        "def Example():\n    run = print\n    del run\n    run('Example')",
    ] {
        if count(source, AuditFindingCode::PythonExec) != 0
            || count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 1
        {
            missed.push(source);
        }
    }
    assert!(missed.is_empty(), "incorrect deletion lookup: {missed:#?}");
}

#[test]
fn parameter_defaults_capture_values_in_the_enclosing_scope() {
    let mut missed = Vec::new();
    for source in [
        "run = exec\nlambda run=run: run('Example')",
        "def Example(run=exec):\n    run('Example')",
        "async def Example(run=exec):\n    run('Example')",
        "def Example(run=exec, /):\n    run('Example')",
        "def Example(*, run=exec):\n    run('Example')",
        "run = exec\ndef run(run=run):\n    run('Example')",
        "run = exec\ndef Example(run=run, sample=(run := print)):\n    run('Example')",
        "class Example:\n    run = exec\n    def Sample(run=run):\n        run('Example')",
    ] {
        if count(source, AuditFindingCode::PythonExec) != 1
            || count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 0
        {
            missed.push(source);
        }
    }
    assert!(missed.is_empty(), "lost parameter defaults: {missed:#?}");
}

#[test]
fn first_comprehension_iterable_values_use_the_enclosing_scope() {
    let mut missed = Vec::new();
    for expression in [
        "[run('Example') for run in [run]]",
        "{run('Example') for run in [run]}",
        "{0: run('Example') for run in [run]}",
        "(run('Example') for run in [run])",
        "[sample('Example') for run in [run] for sample in [run] if sample]",
    ] {
        let source = format!("run = exec\n{expression}");
        if count(&source, AuditFindingCode::PythonExec) != 1
            || count(&source, AuditFindingCode::PythonUnresolvedCallTarget) != 0
        {
            missed.push(source);
        }
    }
    assert!(missed.is_empty(), "lost first iterable values: {missed:#?}");
}

#[test]
fn conditional_callable_candidates_reach_finally_and_following_calls() {
    let mut missed = Vec::new();
    for body in [
        "if Example:\n    run = exec\nelse:\n    run = print",
        "if Example:\n    run = print\nelif Sample:\n    run = exec\nelse:\n    run = print",
        "try:\n    run = exec\nexcept Exception:\n    run = print",
        "try:\n    pass\nexcept Exception:\n    run = exec\nelse:\n    run = print\nfinally:\n    pass",
        "for sample in Example:\n    run = exec\nelse:\n    run = print",
        "while Example:\n    run = exec\nelse:\n    run = print",
        "match Example:\n    case 0:\n        run = exec\n    case _:\n        run = print",
    ] {
        let source = format!("run = print\n{body}\nrun('Example')");
        if count(&source, AuditFindingCode::PythonExec) != 1 {
            missed.push(source);
        }
    }
    let source = "run = print\ntry:\n    run = exec\nexcept Exception:\n    run = print\nfinally:\n    run('Example')";
    if count(source, AuditFindingCode::PythonExec) != 1 {
        missed.push(source.to_string());
    }
    let source = "run = print\ntry:\n    run = exec\nexcept Exception:\n    pass\nfinally:\n    run = print\nrun('Example')";
    if count(source, AuditFindingCode::PythonExec) != 0
        || count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 0
    {
        missed.push(source.to_string());
    }
    assert!(missed.is_empty(), "lost branch semantics: {missed:#?}");
}

#[test]
fn wildcard_imports_block_builtin_fallback_but_preserve_explicit_bindings() {
    let mut failures = Vec::new();
    for source in [
        "from sample import *\nprint = len\nprint('Example')",
        "from sample import *\nprint('Example')",
        "from sample import *\nexec('Example')",
        "from sample import *\ndef Example():\n    print('Example')",
        "class Example:\n    from sample import *\n    print('Example')",
    ] {
        if count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 1
            || count(source, AuditFindingCode::PythonExec) != 0
        {
            failures.push(source);
        }
    }
    for source in [
        "from maya.cmds import *\nfile(q=True)",
        "from sample import *\nExample('Example')",
        "from sample import *\nfrom builtins import print\nprint('Example')",
        "class Example:\n    from sample import *\n    def Sample():\n        print('Example')",
    ] {
        if count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 0 {
            failures.push(source);
        }
    }
    assert!(
        failures.is_empty(),
        "incorrect wildcard lookup: {failures:#?}"
    );
}

#[test]
fn literal_iteration_targets_share_assignment_destructuring() {
    let mut failures = Vec::new();
    for source in [
        "for example, sample in [(exec, print)]:\n    example('Example')",
        "for [example, sample] in [[exec, print]]:\n    example('Example')",
        "for example, sample in [(print, print), (exec, print)]:\n    example('Example')",
        "for (example, sample), other in [((exec, print), 0)]:\n    example('Example')",
        "[example('Example') for example, sample in [(exec, print)]]",
        "{example('Example') for example, sample in [(exec, print)]}",
        "{0: example('Example') for example, sample in [(exec, print)]}",
        "(example('Example') for example, sample in [(exec, print)])",
        "run = exec\n[run('Example') for run, sample in [(run, print)]]",
    ] {
        if count(source, AuditFindingCode::PythonExec) != 1
            || count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 0
        {
            failures.push(source);
        }
    }
    for source in [
        "run = exec\nfor run, sample in Example:\n    run('Example')",
        "run = exec\nfor run, sample in [(print,)]:\n    run('Example')",
        "run = exec\n[run('Example') for run, sample in [Example]]",
    ] {
        if count(source, AuditFindingCode::PythonExec) != 0
            || count(source, AuditFindingCode::PythonUnresolvedCallTarget) != 1
        {
            failures.push(source);
        }
    }
    assert!(
        failures.is_empty(),
        "lost iterable destructuring: {failures:#?}"
    );
}

#[test]
fn assignment_forms_preserve_concrete_and_unresolved_targets() {
    assert_eq!(
        count(
            "run = exec\nrun += [sample]\nrun('Example')",
            AuditFindingCode::PythonUnresolvedCallTarget
        ),
        1
    );
    for source in [
        "example, *sample = exec, print\nexample('Example')",
        "run: object = exec\nrun('Example')",
    ] {
        assert_eq!(count(source, AuditFindingCode::PythonExec), 1, "{source}");
        assert_eq!(
            count(source, AuditFindingCode::PythonUnresolvedCallTarget),
            0,
            "{source}"
        );
    }
    let deleted = "run = exec\ndel run\nrun('Example')";
    assert_eq!(count(deleted, AuditFindingCode::PythonExec), 0);
    assert_eq!(
        count(deleted, AuditFindingCode::PythonUnresolvedCallTarget),
        1
    );
    assert_eq!(
        count(
            "from sample import *\nprint('Example')",
            AuditFindingCode::PythonUnresolvedCallTarget
        ),
        1
    );
    assert_eq!(
        count(
            "from sample import *\nprint = len\nprint('Example')",
            AuditFindingCode::PythonUnresolvedCallTarget
        ),
        1
    );
}
