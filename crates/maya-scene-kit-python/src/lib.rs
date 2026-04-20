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
    max_bytes = None
))]
fn audit(
    py: Python<'_>,
    path: String,
    rules: Vec<String>,
    max_preview: usize,
    include_digests: bool,
    node_info_paths: Vec<String>,
    max_bytes: Option<usize>,
) -> PyResult<PyObject> {
    value_to_py(
        py,
        api::audit_json(
            &path,
            &rules,
            max_preview,
            include_digests,
            &node_info_paths,
            max_bytes,
        )
        .map_err(scene_tool_error_to_pyerr)?,
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
        SceneToolError::MbParseBudgetExceeded { .. } => "mb_parse_budget_exceeded",
        SceneToolError::Parse(_) => "parse",
    }
}
