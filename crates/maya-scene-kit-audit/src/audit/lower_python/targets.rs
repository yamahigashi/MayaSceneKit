use super::*;

// This is the language's builtin-name vocabulary, not an effect or safety classification.
pub(super) fn builtin_callable(name: &str) -> bool {
    matches!(
        name,
        "abs"
            | "aiter"
            | "all"
            | "anext"
            | "any"
            | "ascii"
            | "bin"
            | "bool"
            | "breakpoint"
            | "bytearray"
            | "bytes"
            | "callable"
            | "chr"
            | "classmethod"
            | "compile"
            | "complex"
            | "delattr"
            | "dict"
            | "dir"
            | "divmod"
            | "enumerate"
            | "eval"
            | "exec"
            | "filter"
            | "float"
            | "format"
            | "frozenset"
            | "getattr"
            | "globals"
            | "hasattr"
            | "hash"
            | "help"
            | "hex"
            | "id"
            | "input"
            | "int"
            | "isinstance"
            | "issubclass"
            | "iter"
            | "len"
            | "list"
            | "locals"
            | "map"
            | "max"
            | "memoryview"
            | "min"
            | "next"
            | "object"
            | "oct"
            | "open"
            | "ord"
            | "pow"
            | "print"
            | "property"
            | "range"
            | "repr"
            | "reversed"
            | "round"
            | "set"
            | "setattr"
            | "slice"
            | "sorted"
            | "staticmethod"
            | "str"
            | "sum"
            | "super"
            | "tuple"
            | "type"
            | "vars"
            | "zip"
            | "__import__"
            | "BaseException"
            | "Exception"
            | "ArithmeticError"
            | "AssertionError"
            | "AttributeError"
            | "EOFError"
            | "ImportError"
            | "IndexError"
            | "KeyError"
            | "LookupError"
            | "NameError"
            | "NotImplementedError"
            | "OSError"
            | "IOError"
            | "OverflowError"
            | "RuntimeError"
            | "StopIteration"
            | "SyntaxError"
            | "SystemError"
            | "SystemExit"
            | "TypeError"
            | "UnboundLocalError"
            | "UnicodeError"
            | "ValueError"
            | "ZeroDivisionError"
            | "Warning"
            | "BaseExceptionGroup"
            | "ExceptionGroup"
            | "BlockingIOError"
            | "BrokenPipeError"
            | "BufferError"
            | "ChildProcessError"
            | "ConnectionAbortedError"
            | "ConnectionError"
            | "ConnectionRefusedError"
            | "ConnectionResetError"
            | "DeprecationWarning"
            | "EncodingWarning"
            | "FileExistsError"
            | "FileNotFoundError"
            | "FloatingPointError"
            | "FutureWarning"
            | "GeneratorExit"
            | "ImportWarning"
            | "IndentationError"
            | "InterruptedError"
            | "IsADirectoryError"
            | "KeyboardInterrupt"
            | "MemoryError"
            | "ModuleNotFoundError"
            | "NotADirectoryError"
            | "PendingDeprecationWarning"
            | "PermissionError"
            | "ProcessLookupError"
            | "RecursionError"
            | "ReferenceError"
            | "ResourceWarning"
            | "RuntimeWarning"
            | "StopAsyncIteration"
            | "SyntaxWarning"
            | "TabError"
            | "TimeoutError"
            | "UnicodeDecodeError"
            | "UnicodeEncodeError"
            | "UnicodeTranslateError"
            | "UnicodeWarning"
            | "UserWarning"
            | "EnvironmentError"
            | "PythonFinalizationError"
            | "WindowsError"
            | "StandardError"
            | "basestring"
            | "long"
            | "unicode"
            | "xrange"
            | "raw_input"
            | "reduce"
            | "reload"
            | "unichr"
    )
}

fn sensitive_method(name: &str) -> bool {
    matches!(
        name,
        "system"
            | "popen"
            | "execl"
            | "execv"
            | "spawnl"
            | "posix_spawn"
            | "remove"
            | "unlink"
            | "write"
            | "writelines"
            | "load"
            | "loads"
            | "Popen"
            | "CDLL"
            | "WinDLL"
            | "PyDLL"
            | "OleDLL"
            | "eval"
            | "exec"
            | "compile"
            | "__import__"
    )
}

impl SignalVisitor<'_> {
    pub(super) fn unresolved_target(&self, expr: &ast::Expr, binding: &Binding) -> bool {
        match expr {
            ast::Expr::Name(name) => {
                if self.builtin_poisoned && self.is_builtin_fallback(name.id.as_str()) {
                    return true;
                }
                !binding.known_safe && !binding.statically_named
            }
            ast::Expr::Attribute(attr) => {
                if binding.statically_named {
                    return false;
                }
                let mut receiver = attr.value.as_ref();
                while let ast::Expr::Attribute(parent) = receiver {
                    receiver = &parent.value;
                }
                match receiver {
                    ast::Expr::Call(_) | ast::Expr::Subscript(_) => {
                        sensitive_method(attr.attr.as_str())
                    }
                    ast::Expr::Name(name) => !self.has_named_receiver(name.id.as_str()),
                    _ => !self.named_value_parts(receiver),
                }
            }
            ast::Expr::Lambda(_) => false,
            _ => true,
        }
    }

    fn named_value_parts(&self, expr: &ast::Expr) -> bool {
        match expr {
            ast::Expr::Name(name) => self.has_named_receiver(name.id.as_str()),
            ast::Expr::Attribute(attr) => self.named_value_parts(&attr.value),
            ast::Expr::Constant(_) => true,
            ast::Expr::BinOp(value) => {
                self.named_value_parts(&value.left) && self.named_value_parts(&value.right)
            }
            ast::Expr::UnaryOp(value) => self.named_value_parts(&value.operand),
            ast::Expr::JoinedStr(value) => {
                value.values.iter().all(|part| self.named_value_parts(part))
            }
            ast::Expr::FormattedValue(value) => {
                self.named_value_parts(&value.value)
                    && value
                        .format_spec
                        .as_deref()
                        .is_none_or(|part| self.named_value_parts(part))
            }
            ast::Expr::List(value) => value.elts.iter().all(|part| self.named_value_parts(part)),
            ast::Expr::Tuple(value) => value.elts.iter().all(|part| self.named_value_parts(part)),
            ast::Expr::Set(value) => value.elts.iter().all(|part| self.named_value_parts(part)),
            ast::Expr::Dict(value) => value
                .keys
                .iter()
                .flatten()
                .chain(&value.values)
                .all(|part| self.named_value_parts(part)),
            ast::Expr::Compare(value) => {
                self.named_value_parts(&value.left)
                    && value
                        .comparators
                        .iter()
                        .all(|part| self.named_value_parts(part))
            }
            ast::Expr::BoolOp(value) => {
                value.values.iter().all(|part| self.named_value_parts(part))
            }
            _ => false,
        }
    }

    pub(super) fn named_class_constructor(&self, expr: &ast::Expr) -> bool {
        let mut root = expr;
        while let ast::Expr::Attribute(attr) = root {
            root = &attr.value;
        }
        let ast::Expr::Name(name) = root else {
            return false;
        };
        let binding = self.resolve_value(expr);
        (!self.builtin_poisoned && self.is_builtin_fallback(name.id.as_str()))
            || (binding.statically_named && (!binding.modules.is_empty() || binding.local_class))
    }

    pub(super) fn check_implicit_call(&mut self, expr: &ast::Expr) {
        self.visit_call(&ast::ExprCall {
            range: expr.range(),
            func: Box::new(expr.clone()),
            args: Vec::new(),
            keywords: Vec::new(),
        });
    }

    pub(super) fn poisons_builtins(&self, target: &ast::Expr) -> bool {
        match target {
            ast::Expr::Attribute(attr) => {
                self.resolve_value(&attr.value)
                    .modules
                    .iter()
                    .any(|module| module == "builtins")
                    || self.poisons_builtins(&attr.value)
            }
            ast::Expr::Subscript(value) => {
                self.resolve_value(&value.value)
                    .modules
                    .iter()
                    .any(|module| module == "sys.modules")
                    && match value.slice.as_ref() {
                        ast::Expr::Constant(key) => {
                            matches!(&key.value, ast::Constant::Str(name) if matches!(name.as_str(), "builtins" | "__builtin__"))
                        }
                        _ => true,
                    }
                    || self.poisons_builtins(&value.value)
            }
            _ => false,
        }
    }
}
