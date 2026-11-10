use std::collections::HashSet;

use rustpython_parser::Parse;

use super::*;

#[derive(Default)]
struct Recorder {
    events: Vec<String>,
    nodes: HashSet<(&'static str, usize)>,
    variants: HashSet<String>,
    scopes: Vec<&'static str>,
}

fn scope_name(scope: PythonScope<'_>) -> &'static str {
    match scope {
        PythonScope::FunctionBody { .. } => "function",
        PythonScope::AsyncFunctionBody { .. } => "async_function",
        PythonScope::ClassBody { .. } => "class",
        PythonScope::LambdaBody { .. } => "lambda",
        PythonScope::Comprehension { .. } => "comprehension",
    }
}

impl Recorder {
    fn record<T: std::fmt::Debug>(&mut self, category: &'static str, node: &T) {
        assert!(
            self.nodes
                .insert((category, std::ptr::from_ref(node) as usize)),
            "duplicate {node:?}"
        );
        let debug = format!("{node:?}");
        self.variants
            .insert(format!("{category}:{}", debug.split('(').next().unwrap()));
    }
}

impl PythonAstVisitor for Recorder {
    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        self.record("stmt", stmt);
        walk_stmt(self, stmt);
    }
    fn visit_expr(&mut self, expr: &ast::Expr) {
        self.record("expr", expr);
        if let ast::Expr::Name(name) = expr {
            self.events.push(name.id.to_string());
        }
        walk_expr(self, expr);
    }
    fn visit_pattern(&mut self, pattern: &ast::Pattern) {
        self.record("pattern", pattern);
        walk_pattern(self, pattern);
    }
    fn visit_type_param(&mut self, param: &ast::TypeParam) {
        self.record("param", param);
        walk_type_param(self, param);
    }
    fn enter_scope(&mut self, scope: PythonScope<'_>) {
        let name = scope_name(scope);
        self.scopes.push(name);
        self.events.push(format!("enter:{name}"));
    }
    fn leave_scope(&mut self, scope: PythonScope<'_>) {
        let name = scope_name(scope);
        assert_eq!(self.scopes.pop(), Some(name));
        self.events.push(format!("leave:{name}"));
    }
    fn at_point(&mut self, point: PythonWalkPoint<'_>) {
        self.events.push(
            match point {
                PythonWalkPoint::AfterForIter(_) => "for",
                PythonWalkPoint::AfterWithVars(_) => "with",
                PythonWalkPoint::AfterDeleteTarget(_) => "delete",
                PythonWalkPoint::BeforeHandlerBody(_) => "handler",
                PythonWalkPoint::AfterComprehensionIter(_) => "generator",
            }
            .to_string(),
        );
    }
}

fn record(source: &str) -> Recorder {
    let suite = ast::Suite::parse(source, "Example").unwrap();
    let mut recorder = Recorder::default();
    walk_suite(&mut recorder, &suite);
    assert!(recorder.scopes.is_empty());
    recorder
}

#[test]
fn function_header_order() {
    for prefix in ["", "async "] {
        let source = format!(
            "@ExampleDecorator\n{prefix}def Example[T: ExampleBound, **P, *Ts](a: ExamplePosOnly = ExampleDefaultA, /, b: ExampleArg = ExampleDefaultB, *args: ExampleVararg, c: ExampleKeyword = ExampleDefaultC, **kwargs: ExampleKwarg) -> ExampleReturn:\n    ExampleBody\n"
        );
        let scope = if prefix.is_empty() {
            "function"
        } else {
            "async_function"
        };
        assert_eq!(
            record(&source).events,
            [
                "ExampleDefaultA",
                "ExampleDefaultB",
                "ExampleDefaultC",
                "ExampleDecorator",
                "ExampleBound",
                "ExamplePosOnly",
                "ExampleArg",
                "ExampleVararg",
                "ExampleKeyword",
                "ExampleKwarg",
                "ExampleReturn",
                &format!("enter:{scope}"),
                "ExampleBody",
                &format!("leave:{scope}")
            ]
        );
    }
}

#[test]
fn class_header_and_nested_scope_order() {
    assert_eq!(record("@ExampleDecorator\nclass Example[T: ExampleBound](ExampleBase, metaclass=ExampleMeta):\n    def Sample():\n        pass\n").events, ["ExampleDecorator", "ExampleBound", "ExampleBase", "ExampleMeta", "enter:class", "enter:function", "leave:function", "leave:class"]);
    let mut suite = ast::Suite::parse(
        "class Example:\n    pass\ndef Sample():\n    pass\nasync def Test():\n    pass\n",
        "Example",
    )
    .unwrap();
    for stmt in &mut suite {
        match stmt {
            ast::Stmt::ClassDef(s) => s.body.clear(),
            ast::Stmt::FunctionDef(s) => s.body.clear(),
            ast::Stmt::AsyncFunctionDef(s) => s.body.clear(),
            _ => unreachable!(),
        }
    }
    let mut recorder = Recorder::default();
    walk_suite(&mut recorder, &suite);
    assert_eq!(
        recorder.events,
        [
            "enter:class",
            "leave:class",
            "enter:function",
            "leave:function",
            "enter:async_function",
            "leave:async_function"
        ]
    );
}

#[test]
fn intermediate_hook_order() {
    assert_eq!(record("with ExampleContext as ExampleTarget, SampleContext:\n    ExampleBody\ntry:\n    ExampleTry\nexcept ExampleType as ExampleError:\n    ExampleHandler\nexcept:\n    SampleHandler\nelse:\n    ExampleElse\nfinally:\n    ExampleFinally\nfor ExampleTarget in ExampleIter:\n    ExampleBody\nelse:\n    ExampleElse\ndel ExampleA, ExampleB\n").events,
        ["ExampleContext", "ExampleTarget", "with", "SampleContext", "with", "ExampleBody", "ExampleTry", "ExampleType", "handler", "ExampleHandler", "handler", "SampleHandler", "ExampleElse", "ExampleFinally", "ExampleTarget", "ExampleIter", "for", "ExampleBody", "ExampleElse", "ExampleA", "delete", "ExampleB", "delete"]);
}

#[test]
fn comprehension_and_lambda_order() {
    assert_eq!(record("[ExampleResult for ExampleTarget in ExampleIter if ExampleIf for SampleTarget in SampleIter if SampleIf]\nlambda sample=ExampleDefault: ExampleBody\n").events,
        ["ExampleIter", "enter:comprehension", "ExampleTarget", "generator", "ExampleIf", "SampleTarget", "SampleIter", "generator", "SampleIf", "ExampleResult", "leave:comprehension", "ExampleDefault", "enter:lambda", "ExampleBody", "leave:lambda"]);
}

#[test]
fn all_ast_variants_are_visited_once_per_node() {
    let recorder = record(
        r#"
import example
from example import sample
@ExampleDecorator
def Example[T: ExampleBound, **P, *Ts](sample: ExampleAnnotation = ExampleDefault) -> ExampleReturn:
    global ExampleGlobal
    nonlocal ExampleOuter
    return sample
async def Sample():
    async for sample in ExampleIter:
        await ExampleCall()
    async with ExampleContext as sample:
        pass
class Test[T: ExampleBound](ExampleBase, metaclass=ExampleMeta):
    pass
del ExampleTarget
sample = 1
sample += 2
sample: ExampleAnnotation = 3
type ExampleAlias[T: ExampleBound] = ExampleValue
for sample in ExampleIter:
    if sample:
        continue
    else:
        break
else:
    pass
while ExampleCondition:
    pass
with ExampleContext as sample:
    pass
try:
    raise ExampleError from ExampleCause
except ExampleError:
    pass
else:
    pass
finally:
    pass
try:
    pass
except* ExampleError:
    pass
assert ExampleCondition, ExampleMessage
sample and other
(sample := other)
sample + other
-sample
lambda sample=ExampleDefault: sample
sample if condition else other
{sample: other, **ExampleMapping}
{sample}
[sample for sample in ExampleIter if ExampleCondition]
{sample for sample in ExampleIter}
{sample: other for sample in ExampleIter}
(sample for sample in ExampleIter)
yield sample
yield from ExampleIter
sample < other
ExampleCall(*ExampleArgs, sample=ExampleKeyword, **ExampleKeywords)
f"Example {sample:{ExampleFormat}}"
sample.attribute
sample[ExampleLower:ExampleUpper:ExampleStep]
[sample]
(sample, other)
match sample:
    case Example.Value:
        pass
    case None:
        pass
    case [sample, *other]:
        pass
    case {"Example": sample}:
        pass
    case Example(sample, value=other):
        pass
    case (1 | 2) as sample if ExampleGuard:
        pass
"#,
    );
    let expected = [
        ("stmt", "FunctionDef AsyncFunctionDef ClassDef Return Delete Assign TypeAlias AugAssign AnnAssign For AsyncFor While If With AsyncWith Match Raise Try TryStar Assert Import ImportFrom Global Nonlocal Expr Pass Break Continue"),
        ("expr", "BoolOp NamedExpr BinOp UnaryOp Lambda IfExp Dict Set ListComp SetComp DictComp GeneratorExp Await Yield YieldFrom Compare Call FormattedValue JoinedStr Constant Attribute Subscript Starred Name List Tuple Slice"),
        ("pattern", "MatchValue MatchSingleton MatchSequence MatchMapping MatchClass MatchStar MatchAs MatchOr"),
        ("param", "TypeVar ParamSpec TypeVarTuple"),
    ].into_iter().flat_map(|(category, names)| names.split_whitespace().map(move |name| format!("{category}:{name}"))).collect::<HashSet<_>>();
    assert_eq!(recorder.variants, expected);
}

#[test]
fn named_expression_visits_target_before_value() {
    assert_eq!(record("(sample := Example)").events, ["sample", "Example"]);
}
