use std::path::{Path, PathBuf};

use super::super::fs::{
    CliOutputError, collect_scene_files, render_scene_paths_collection_json,
    render_scene_paths_json, render_scene_paths_text, write_scene_paths,
};
use crate::{cli::runtime_context::load_options, scene::PathKind};

pub(crate) fn parse_path_kind(kind: &str) -> PathKind {
    match kind {
        "file" => PathKind::File,
        "reference" => PathKind::Reference,
        _ => PathKind::All,
    }
}

pub(crate) fn run_paths(
    input: &Path,
    kind: PathKind,
    out: Option<&PathBuf>,
    out_dir: Option<&PathBuf>,
    json_output: bool,
    node_info_paths: &[PathBuf],
    max_bytes: Option<usize>,
) -> i32 {
    if out.is_some() && out_dir.is_some() {
        eprintln!("error: --out and --out-dir are mutually exclusive");
        return 2;
    }

    let files = match collect_scene_files(input) {
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
    let load_options = load_options(node_info_paths, max_bytes);

    if input.is_file() {
        let file = &files[0];
        if let Some(out_dir) = out_dir {
            eprintln!(
                "error: --out-dir ({}) is for directory input. use --out for single file: {}",
                out_dir.display(),
                file.display()
            );
            return 2;
        }

        if let Some(out_file) = out {
            match write_scene_paths(file, kind, out_file, json_output, &load_options) {
                Ok(()) => {
                    println!("written={}", out_file.display());
                    return 0;
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return match e {
                        CliOutputError::Scene(crate::scene::SceneToolError::Io(_)) => 2,
                        _ => 1,
                    };
                }
            }
        }

        let rendered = if json_output {
            render_scene_paths_json(file, kind, &load_options)
        } else {
            render_scene_paths_text(file, kind, &load_options)
        };
        match rendered {
            Ok(text) => {
                print!("{text}");
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                match e {
                    CliOutputError::Scene(crate::scene::SceneToolError::Io(_)) => 2,
                    _ => 1,
                }
            }
        }
    } else {
        if let Some(out_file) = out {
            eprintln!(
                "error: --out is for single file input. use --out-dir for directory input: {}",
                out_file.display()
            );
            return 2;
        }

        if let Some(root) = out_dir {
            if let Err(e) = std::fs::create_dir_all(root) {
                eprintln!("error: {e}");
                return 2;
            }
            for file in files {
                let rel = file.strip_prefix(input).unwrap_or(file.as_path());
                let mut out_path = root.join(rel);
                let file_name = out_path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "scene".to_string());
                out_path.set_file_name(if json_output {
                    format!("{file_name}.scene_paths.json")
                } else {
                    format!("{file_name}.scene_paths.txt")
                });
                match write_scene_paths(&file, kind, &out_path, json_output, &load_options) {
                    Ok(()) => println!("written={}", out_path.display()),
                    Err(e) => {
                        eprintln!("error: {e}");
                        return match e {
                            CliOutputError::Scene(crate::scene::SceneToolError::Io(_)) => 2,
                            _ => 1,
                        };
                    }
                }
            }
            0
        } else {
            if json_output {
                match render_scene_paths_collection_json(&files, kind, input, &load_options) {
                    Ok(text) => {
                        print!("{text}");
                        return 0;
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        return match e {
                            CliOutputError::Scene(crate::scene::SceneToolError::Io(_)) => 2,
                            _ => 1,
                        };
                    }
                }
            }
            for file in files {
                match render_scene_paths_text(&file, kind, &load_options) {
                    Ok(text) => {
                        println!("===== {} =====", file.display());
                        print!("{text}");
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        return match e {
                            CliOutputError::Scene(crate::scene::SceneToolError::Io(_)) => 2,
                            _ => 1,
                        };
                    }
                }
            }
            0
        }
    }
}
