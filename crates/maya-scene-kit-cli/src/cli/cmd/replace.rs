use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use super::super::fs::collect_scene_files;
use crate::{
    cli::runtime_context::materialize_options,
    scene::{
        OperationMode, PathReplaceMode, PathReplaceRule, SceneToolError,
        replace_scene_paths_with_options,
    },
};

fn parse_replace_rules(raw: Vec<String>) -> Result<Vec<PathReplaceRule>, String> {
    let mut out = Vec::new();
    for r in raw {
        let (from, to) = r
            .split_once('=')
            .ok_or_else(|| format!("invalid --rule '{r}', expected FROM=TO"))?;
        if from.is_empty() {
            return Err(format!("invalid --rule '{r}', FROM must not be empty"));
        }
        out.push(PathReplaceRule {
            from: from.to_string(),
            to: to.to_string(),
            mode: PathReplaceMode::Literal,
        });
    }
    if out.is_empty() {
        return Err("no --rule specified".to_string());
    }
    Ok(out)
}

pub(crate) fn run_replace_paths(
    input: &Path,
    out: Option<&PathBuf>,
    out_dir: Option<&PathBuf>,
    rules_raw: Vec<String>,
    node_info_paths: &[PathBuf],
    max_bytes: Option<usize>,
) -> i32 {
    crate::cli::stdout::with_stdout(|stdout_output| {
        if out.is_some() && out_dir.is_some() {
            eprintln!("error: --out and --out-dir are mutually exclusive");
            return 2;
        }

        let rules = match parse_replace_rules(rules_raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        };
        let options = materialize_options(node_info_paths, max_bytes)
            .with_operation_mode(OperationMode::Forensic);

        let files =
            match collect_scene_files(input).map(|collection| collection.warn_and_take_files()) {
                Ok(v) if !v.is_empty() => v,
                Ok(_) => {
                    eprintln!("error: no .ma/.mb files found: {}", input.display());
                    return 2;
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            };

        if input.is_file() {
            let src = &files[0];
            if out_dir.is_some() {
                eprintln!("error: --out-dir is for directory input");
                return 2;
            }
            let Some(dst) = out else {
                eprintln!("error: --out is required for single file input");
                return 2;
            };

            match replace_scene_paths_with_options(src, dst, &rules, &options) {
                Ok(r) => {
                    let _ = writeln!(
                        stdout_output,
                        "written={} format={} mode={} state={} replaced={}",
                        r.output_path.display(),
                        r.scene_format,
                        r.operation_mode,
                        r.validation_state,
                        r.replaced_count
                    );
                    write_replace_skips(stdout_output, &r);
                    0
                }
                Err(SceneToolError::Io(e)) => {
                    eprintln!("error: {e}");
                    2
                }
                Err(e) => {
                    eprintln!("scene error: {e}");
                    1
                }
            }
        } else {
            if out.is_some() {
                eprintln!("error: --out is for single file input. use --out-dir");
                return 2;
            }
            let Some(root) = out_dir else {
                eprintln!("error: --out-dir is required for directory input");
                return 2;
            };
            if let Err(e) = fs::create_dir_all(root) {
                eprintln!("error: {e}");
                return 2;
            }

            for src in files {
                let rel = src.strip_prefix(input).unwrap_or(src.as_path());
                let dst = root.join(rel);
                match replace_scene_paths_with_options(&src, &dst, &rules, &options) {
                    Ok(r) => {
                        let _ = writeln!(
                            stdout_output,
                            "written={} format={} mode={} state={} replaced={}",
                            r.output_path.display(),
                            r.scene_format,
                            r.operation_mode,
                            r.validation_state,
                            r.replaced_count
                        );
                        write_replace_skips(stdout_output, &r);
                    }
                    Err(SceneToolError::Io(e)) => {
                        eprintln!("error: {e}");
                        return 2;
                    }
                    Err(e) => {
                        eprintln!("scene error: {e}");
                        return 1;
                    }
                }
            }
            0
        }
    })
}

fn write_replace_skips(output: &mut impl std::io::Write, result: &crate::scene::PathReplaceResult) {
    if let Some(skipped) = &result.skipped
        && skipped.total() > 0
    {
        let offset = skipped
            .unterminated_tail_from
            .map_or_else(|| "none".to_string(), |offset| offset.to_string());
        let _ = writeln!(
            output,
            "skipped non_utf8={} non_canonical_escape={} unrepresentable={} crosses_concat_boundary={} unterminated_tail={} unterminated_tail_from={}",
            skipped.non_utf8,
            skipped.non_canonical_escape,
            skipped.unrepresentable,
            skipped.crosses_concat_boundary,
            skipped.unterminated_tail,
            offset
        );
    }
}
