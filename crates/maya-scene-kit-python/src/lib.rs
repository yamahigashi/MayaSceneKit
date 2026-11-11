mod api;
mod json;
mod schema;

use maya_scene_kit_observe::scene::SceneToolError;
use pyo3::{create_exception, exceptions::PyException, prelude::*, types::PyModule};
use serde_json::Value;

create_exception!(maya_scene_kit_native, MayaSceneKitError, PyException);

#[pyfunction(signature = (path, max_depth=None, preview_bytes=24, max_bytes=None))]
fn inspect_mb(
    py: Python<'_>,
    path: String,
    max_depth: Option<usize>,
    preview_bytes: usize,
    max_bytes: Option<usize>,
) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::inspect_mb_json(&path, max_depth, preview_bytes, max_bytes)
            .map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pyfunction(signature = (path, max_bytes=None))]
fn dump_scripts(path: String, max_bytes: Option<usize>) -> PyResult<String> {
    api::dump_scripts_text(&path, max_bytes).map_err(scene_tool_error_to_pyerr)
}

#[pyfunction(signature = (path, max_bytes=None))]
fn dump_requires(path: String, max_bytes: Option<usize>) -> PyResult<String> {
    api::dump_requires_text(&path, max_bytes).map_err(scene_tool_error_to_pyerr)
}

#[pyfunction(signature = (path, kind="all", max_bytes=None))]
fn collect_paths(
    py: Python<'_>,
    path: String,
    kind: &str,
    max_bytes: Option<usize>,
) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::collect_paths_json(&path, kind, max_bytes).map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pyfunction(signature = (
    path,
    rules = Vec::<String>::new(),
    max_preview = 96,
    include_digests = true,
    node_info_paths = Vec::<String>::new(),
    max_bytes = None,
    recursive = true,
    allowlist_paths = Vec::<String>::new()
))]
fn audit(
    py: Python<'_>,
    path: String,
    rules: Vec<String>,
    max_preview: usize,
    include_digests: bool,
    node_info_paths: Vec<String>,
    max_bytes: Option<usize>,
    recursive: bool,
    allowlist_paths: Vec<String>,
) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::audit_json(
            &path,
            &rules,
            max_preview,
            include_digests,
            &node_info_paths,
            &allowlist_paths,
            recursive,
            max_bytes,
        )
        .map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pyfunction(signature = (source, language))]
fn audit_source_text(py: Python<'_>, source: &str, language: &str) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::audit_source_text_json(source, language).map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pyfunction(signature = (path, max_bytes=None))]
fn preview_clean(py: Python<'_>, path: String, max_bytes: Option<usize>) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::preview_clean_json(&path, max_bytes).map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pyfunction(signature = (input_path, output_path, max_bytes=None))]
fn clean(
    py: Python<'_>,
    input_path: String,
    output_path: String,
    max_bytes: Option<usize>,
) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::clean_json(&input_path, &output_path, max_bytes).map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pyfunction(signature = (path, rules, max_bytes=None))]
fn preview_replace(
    py: Python<'_>,
    path: String,
    rules: Vec<(String, String)>,
    max_bytes: Option<usize>,
) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::preview_replace_json(&path, &rules, max_bytes).map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pyfunction(signature = (input_path, output_path, rules, max_bytes=None))]
fn replace(
    py: Python<'_>,
    input_path: String,
    output_path: String,
    rules: Vec<(String, String)>,
    max_bytes: Option<usize>,
) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::replace_json(&input_path, &output_path, &rules, max_bytes)
            .map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pyfunction(signature = (
    input_path,
    output_path,
    mode = "best_effort",
    embed_metadata = false,
    node_info_paths = Vec::<String>::new(),
    max_bytes = None
))]
fn to_ascii(
    py: Python<'_>,
    input_path: String,
    output_path: String,
    mode: &str,
    embed_metadata: bool,
    node_info_paths: Vec<String>,
    max_bytes: Option<usize>,
) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::to_ascii_json(
            &input_path,
            &output_path,
            mode,
            embed_metadata,
            &node_info_paths,
            max_bytes,
        )
        .map_err(scene_tool_error_to_pyerr)?,
    )
}

#[pymodule]
fn maya_scene_kit_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("MayaSceneKitError", m.py().get_type::<MayaSceneKitError>())?;
    m.add_function(wrap_pyfunction!(inspect_mb, m)?)?;
    m.add_function(wrap_pyfunction!(dump_scripts, m)?)?;
    m.add_function(wrap_pyfunction!(dump_requires, m)?)?;
    m.add_function(wrap_pyfunction!(collect_paths, m)?)?;
    m.add_function(wrap_pyfunction!(audit, m)?)?;
    m.add_function(wrap_pyfunction!(audit_source_text, m)?)?;
    m.add_function(wrap_pyfunction!(preview_clean, m)?)?;
    m.add_function(wrap_pyfunction!(clean, m)?)?;
    m.add_function(wrap_pyfunction!(preview_replace, m)?)?;
    m.add_function(wrap_pyfunction!(replace, m)?)?;
    m.add_function(wrap_pyfunction!(to_ascii, m)?)?;
    Ok(())
}

fn value_to_py(py: Python<'_>, value: Value) -> PyResult<PyObject> {
    let json = PyModule::import(py, "json")?;
    let text = serde_json::to_string(&value).map_err(|err| {
        MayaSceneKitError::new_err((format!("failed to render json: {err}"), "json"))
    })?;
    Ok(json.call_method1("loads", (text,))?.unbind())
}

fn scene_tool_error_to_pyerr(err: SceneToolError) -> PyErr {
    MayaSceneKitError::new_err((err.to_string(), scene_tool_error_category(&err)))
}

fn scene_tool_error_category(err: &SceneToolError) -> &'static str {
    match err {
        SceneToolError::Message(_) => "message",
        SceneToolError::UnsupportedSceneFormat { .. } => "unsupported_scene_format",
        SceneToolError::Config(_) => "config",
        SceneToolError::AsciiSyntax(_) => "ascii_syntax",
        SceneToolError::UnsupportedAsciiFeature(_) => "unsupported_ascii_feature",
        SceneToolError::EncodeInvariant(_) => "encode_invariant",
        SceneToolError::AtomicWrite(_) => "atomic_write",
        SceneToolError::InvalidUtf8 { .. } => "invalid_utf8",
        SceneToolError::RejectedByMode { .. } => "rejected_by_mode",
        SceneToolError::Io(_) => "io",
        SceneToolError::MelParseBudgetExceeded { .. } => "mel_parse_budget_exceeded",
        SceneToolError::PythonParseBudgetExceeded { .. } => "python_parse_budget_exceeded",
        SceneToolError::MbParseBudgetExceeded { .. } => "mb_parse_budget_exceeded",
        SceneToolError::Parse(_) => "parse",
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use pyo3::{
        prelude::*,
        types::{PyDict, PyModule},
    };

    use super::{MayaSceneKitError, maya_scene_kit_native};

    #[test]
    fn source_audit_binding_returns_reports_and_configuration_errors() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new(py, "maya_scene_kit_native").expect("native module");
            maya_scene_kit_native(&module).expect("register native functions");
            let function = module
                .getattr("audit_source_text")
                .expect("source function");
            for (language, source, disposition) in [
                ("python", "print('Example')", "allow_with_notice"),
                ("mel", "print(\"Example\");", "allow_with_notice"),
                ("python", "exec('print(1)')", "deny_malicious"),
                ("python", "if :", "deny_malicious"),
            ] {
                let value = function.call1((source, language)).expect("source report");
                let report = value.downcast::<PyDict>().expect("report dictionary");
                assert_eq!(
                    report
                        .get_item("disposition")
                        .unwrap()
                        .unwrap()
                        .extract::<String>()
                        .unwrap(),
                    disposition
                );
                assert_eq!(
                    report
                        .get_item("scene_path")
                        .unwrap()
                        .unwrap()
                        .extract::<String>()
                        .unwrap(),
                    ""
                );
                assert!(report.contains("findings").unwrap());
                assert!(report.contains("coverage_state").unwrap());
                assert!(report.contains("blocked_on_uncertainty").unwrap());
                assert!(!report.contains("reports").unwrap());
            }
            for language in ["unknown", "Python", "", "python2"] {
                let error = function
                    .call1(("", language))
                    .expect_err("invalid language");
                assert!(error.is_instance_of::<MayaSceneKitError>(py));
                let (_, category) = error
                    .value(py)
                    .getattr("args")
                    .unwrap()
                    .extract::<(String, String)>()
                    .unwrap();
                assert_eq!(category, "config");
            }
        });
    }

    #[test]
    fn python_package_exports_the_registered_source_function() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let native = PyModule::new(py, "maya_scene_kit_native").expect("native module");
            maya_scene_kit_native(&native).expect("register native functions");
            let package = PyModule::new(py, "example_package").expect("test package");
            package.add("__package__", "example_package").unwrap();
            package.add("__path__", Vec::<String>::new()).unwrap();
            let modules = PyModule::import(py, "sys")
                .unwrap()
                .getattr("modules")
                .unwrap();
            modules.set_item("example_package", &package).unwrap();
            modules
                .set_item("example_package.maya_scene_kit_native", &native)
                .unwrap();
            let source =
                CString::new(include_str!("../python/maya_scene_kit/__init__.py")).unwrap();
            py.run(source.as_c_str(), Some(&package.dict()), None)
                .expect("import package exports");
            let function = package
                .getattr("audit_source_text")
                .expect("package source function");
            assert!(function.is(&native.getattr("audit_source_text").unwrap()));
            assert!(
                package
                    .getattr("__all__")
                    .unwrap()
                    .extract::<Vec<String>>()
                    .unwrap()
                    .contains(&"audit_source_text".to_string())
            );
            let value = function.call1(("print('Example')", "python")).unwrap();
            assert_eq!(
                value
                    .get_item("disposition")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "allow_with_notice"
            );
            modules
                .del_item("example_package.maya_scene_kit_native")
                .unwrap();
            modules.del_item("example_package").unwrap();
        });
    }
}
