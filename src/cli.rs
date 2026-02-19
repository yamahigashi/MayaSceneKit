use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, ArgAction, Command};
use regex::Regex;
use serde_json::json;

use crate::parser::{Chunk, MayaBinaryParseError, parse_file};
use crate::scene::{
    PathKind, PathReplaceRule, SceneToolError, collect_scene_paths, collect_script_node_entries,
    convert_to_maya_ascii, dump_requires, dump_script_nodes, remove_script_nodes,
    replace_scene_paths,
};

pub fn main(argv: Vec<String>) -> i32 {
    let normalized = normalize_argv(argv);
    let matches = build_parser().try_get_matches_from(
        std::iter::once("maya-scene-kit".to_string()).chain(normalized.into_iter()),
    );

    let matches = match matches {
        Ok(m) => m,
        Err(e) => {
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
            let _ = e.print();
            return code;
        }
    };

    match matches.subcommand() {
        Some(("inspect", m)) => {
            let path = m.get_one::<PathBuf>("path").unwrap();
            let max_depth = m.get_one::<usize>("max-depth").copied();
            let preview_bytes = *m.get_one::<usize>("preview-bytes").unwrap_or(&24);
            run_inspect(path, max_depth, preview_bytes)
        }
        Some(("dump", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let out = m.get_one::<PathBuf>("out");
            let out_dir = m.get_one::<PathBuf>("out-dir");
            let stdout = m.get_flag("stdout");
            run_dump(input, out, out_dir, stdout)
        }
        Some(("paths", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let kind = parse_path_kind(
                m.get_one::<String>("kind")
                    .map(|s| s.as_str())
                    .unwrap_or("all"),
            );
            let out = m.get_one::<PathBuf>("out");
            let out_dir = m.get_one::<PathBuf>("out-dir");
            let stdout = m.get_flag("stdout");
            let json_output = m.get_flag("json");
            run_paths(input, kind, out, out_dir, stdout, json_output)
        }
        Some(("audit", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let rules = m
                .get_many::<String>("rule")
                .map(|v| v.map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            let rule_files = m
                .get_many::<PathBuf>("rule-file")
                .map(|v| v.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let ignore_case = m.get_flag("ignore-case");
            let regex = m.get_flag("regex");
            let json_output = m.get_flag("json");
            let summary_only = m.get_flag("summary-only");
            let only_hit_nodes = m.get_flag("only-hit-nodes");
            let max_preview = *m.get_one::<usize>("max-preview").unwrap_or(&96);
            run_script_audit(
                input,
                rules,
                rule_files,
                ignore_case,
                regex,
                json_output,
                summary_only,
                only_hit_nodes,
                max_preview,
            )
        }
        Some(("to-ascii", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let output = m.get_one::<PathBuf>("output").unwrap();
            let keep_all_links = m.get_flag("keep-all-links");
            run_to_ascii(input, output, keep_all_links)
        }
        Some(("clean", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let output = m.get_one::<PathBuf>("output").unwrap();
            run_script_clean(input, output)
        }
        Some(("replace", m)) => {
            let input = m.get_one::<PathBuf>("input").unwrap();
            let out = m.get_one::<PathBuf>("out");
            let out_dir = m.get_one::<PathBuf>("out-dir");
            let rules_raw = m
                .get_many::<String>("rule")
                .map(|v| v.map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            let rule_files = m
                .get_many::<PathBuf>("rule-file")
                .map(|v| v.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            run_replace_paths(input, out, out_dir, rules_raw, rule_files)
        }
        _ => 2,
    }
}

fn build_parser() -> Command {
    Command::new("maya-scene-kit")
        .about("Standalone utilities for Maya scene files (.mb/.ma).")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("inspect")
                .arg(
                    Arg::new("path")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("max-depth")
                        .long("max-depth")
                        .value_parser(clap::value_parser!(usize)),
                )
                .arg(
                    Arg::new("preview-bytes")
                        .long("preview-bytes")
                        .default_value("24")
                        .value_parser(clap::value_parser!(usize)),
                ),
        )
        .subcommand(
            Command::new("dump")
                .about("Dump requires + script nodes from file or directory")
                .arg(
                    Arg::new("input")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("out")
                        .long("out")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Output file (single input only)"),
                )
                .arg(
                    Arg::new("out-dir")
                        .long("out-dir")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Output directory (directory input only)"),
                )
                .arg(
                    Arg::new("stdout")
                        .long("stdout")
                        .action(ArgAction::SetTrue)
                        .help("Write dump to stdout"),
                ),
        )
        .subcommand(
            Command::new("paths")
                .about("Extract file/reference paths from file or directory")
                .arg(
                    Arg::new("input")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("kind")
                        .long("kind")
                        .default_value("all")
                        .value_parser(["all", "file", "reference"])
                        .help("Path kind to extract"),
                )
                .arg(
                    Arg::new("out")
                        .long("out")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Output file (single input only)"),
                )
                .arg(
                    Arg::new("out-dir")
                        .long("out-dir")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Output directory (directory input only)"),
                )
                .arg(
                    Arg::new("stdout")
                        .long("stdout")
                        .action(ArgAction::SetTrue)
                        .help("Write extracted paths to stdout"),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Output JSON"),
                ),
        )
        .subcommand(
            Command::new("audit")
                .about("Audit script node bodies with NG rules")
                .arg(
                    Arg::new("input")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("rule")
                        .long("rule")
                        .action(ArgAction::Append)
                        .num_args(1)
                        .value_parser(clap::value_parser!(String))
                        .help("Rule pattern (can be repeated)"),
                )
                .arg(
                    Arg::new("rule-file")
                        .long("rule-file")
                        .action(ArgAction::Append)
                        .num_args(1)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Rule file path (1 rule per line, can be repeated)"),
                )
                .arg(
                    Arg::new("ignore-case")
                        .long("ignore-case")
                        .action(ArgAction::SetTrue),
                )
                .arg(Arg::new("regex").long("regex").action(ArgAction::SetTrue))
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("summary-only")
                        .long("summary-only")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("only-hit-nodes")
                        .long("only-hit-nodes")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("max-preview")
                        .long("max-preview")
                        .default_value("96")
                        .value_parser(clap::value_parser!(usize)),
                ),
        )
        .subcommand(
            Command::new("to-ascii")
                .arg(
                    Arg::new("input")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("output")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("keep-all-links")
                        .long("keep-all-links")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("clean")
                .arg(
                    Arg::new("input")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("output")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("replace")
                .about("Replace file/reference paths in scene files")
                .arg(
                    Arg::new("input")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("rule")
                        .long("rule")
                        .action(ArgAction::Append)
                        .num_args(1)
                        .value_parser(clap::value_parser!(String))
                        .help("Replacement rule: FROM=TO (repeatable)"),
                )
                .arg(
                    Arg::new("rule-file")
                        .long("rule-file")
                        .action(ArgAction::Append)
                        .num_args(1)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Rule file path (1 rule per line as FROM=TO, can be repeated)"),
                )
                .arg(
                    Arg::new("out")
                        .long("out")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Output file (single input only)"),
                )
                .arg(
                    Arg::new("out-dir")
                        .long("out-dir")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Output directory (directory input only)"),
                ),
        )
}

fn normalize_argv(argv: Vec<String>) -> Vec<String> {
    if argv.is_empty() {
        return argv;
    }
    let commands = [
        "inspect", "dump", "paths", "audit", "to-ascii", "clean", "replace", "help",
    ];
    let first = &argv[0];
    if commands.contains(&first.as_str()) || first.starts_with('-') {
        return argv;
    }
    let p = Path::new(first);
    if p.is_file() || p.is_dir() {
        return std::iter::once("audit".to_string())
            .chain(argv.into_iter())
            .collect();
    }
    argv
}

fn parse_path_kind(kind: &str) -> PathKind {
    match kind {
        "file" => PathKind::File,
        "reference" => PathKind::Reference,
        _ => PathKind::All,
    }
}

fn run_inspect(path: &PathBuf, max_depth: Option<usize>, preview_bytes: usize) -> i32 {
    match parse_file(path) {
        Ok(mb) => {
            print_chunk(&mb.data, &mb.root, 0, max_depth, preview_bytes);
            0
        }
        Err(MayaBinaryParseError::Io(e)) => {
            eprintln!("error: {e}");
            2
        }
        Err(e) => {
            eprintln!("parse error: {e}");
            1
        }
    }
}

fn run_dump(input: &Path, out: Option<&PathBuf>, out_dir: Option<&PathBuf>, stdout: bool) -> i32 {
    if out.is_some() && out_dir.is_some() {
        eprintln!("error: --out and --out-dir are mutually exclusive");
        return 2;
    }

    if stdout && (out.is_some() || out_dir.is_some()) {
        eprintln!("error: --stdout cannot be used with --out/--out-dir");
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

    if files.len() == 1 {
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
            match write_scene_dump(file, out_file) {
                Ok(()) => {
                    println!("written={}", out_file.display());
                    return 0;
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

        match render_scene_dump_text(file) {
            Ok(text) => {
                print!("{text}");
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
        if let Some(out_file) = out {
            eprintln!(
                "error: --out is for single file input. use --out-dir for directory input: {}",
                out_file.display()
            );
            return 2;
        }

        if let Some(root) = out_dir {
            if let Err(e) = fs::create_dir_all(root) {
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
                out_path.set_file_name(format!("{file_name}.scene_dump.txt"));
                match write_scene_dump(&file, &out_path) {
                    Ok(()) => println!("written={}", out_path.display()),
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
        } else {
            for file in files {
                match render_scene_dump_text(&file) {
                    Ok(text) => {
                        println!("===== {} =====", file.display());
                        print!("{text}");
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
    }
}

fn run_paths(
    input: &Path,
    kind: PathKind,
    out: Option<&PathBuf>,
    out_dir: Option<&PathBuf>,
    stdout: bool,
    json_output: bool,
) -> i32 {
    if out.is_some() && out_dir.is_some() {
        eprintln!("error: --out and --out-dir are mutually exclusive");
        return 2;
    }

    if stdout && (out.is_some() || out_dir.is_some()) {
        eprintln!("error: --stdout cannot be used with --out/--out-dir");
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

    if files.len() == 1 {
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
            match write_scene_paths(file, kind, out_file, json_output) {
                Ok(()) => {
                    println!("written={}", out_file.display());
                    return 0;
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

        let rendered = if json_output {
            render_scene_paths_json(file, kind)
        } else {
            render_scene_paths_text(file, kind)
        };
        match rendered {
            Ok(text) => {
                print!("{text}");
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
        if let Some(out_file) = out {
            eprintln!(
                "error: --out is for single file input. use --out-dir for directory input: {}",
                out_file.display()
            );
            return 2;
        }

        if let Some(root) = out_dir {
            if let Err(e) = fs::create_dir_all(root) {
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
                match write_scene_paths(&file, kind, &out_path, json_output) {
                    Ok(()) => println!("written={}", out_path.display()),
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
        } else {
            if json_output {
                match render_scene_paths_collection_json(&files, kind, input) {
                    Ok(text) => {
                        print!("{text}");
                        return 0;
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
            for file in files {
                match render_scene_paths_text(&file, kind) {
                    Ok(text) => {
                        println!("===== {} =====", file.display());
                        print!("{text}");
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
    }
}

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
        });
    }
    if out.is_empty() {
        return Err("no --rule specified".to_string());
    }
    Ok(out)
}

fn run_replace_paths(
    input: &Path,
    out: Option<&PathBuf>,
    out_dir: Option<&PathBuf>,
    rules_raw: Vec<String>,
    rule_files: Vec<PathBuf>,
) -> i32 {
    if out.is_some() && out_dir.is_some() {
        eprintln!("error: --out and --out-dir are mutually exclusive");
        return 2;
    }

    let mut merged_rules = rules_raw;
    for rule_file in rule_files {
        let text = match fs::read_to_string(&rule_file) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: {}: {e}", rule_file.display());
                return 2;
            }
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            merged_rules.push(trimmed.to_string());
        }
    }

    let rules = match parse_replace_rules(merged_rules) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

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

    if files.len() == 1 {
        let src = &files[0];
        if out_dir.is_some() {
            eprintln!("error: --out-dir is for directory input");
            return 2;
        }
        let Some(dst) = out else {
            eprintln!("error: --out is required for single file input");
            return 2;
        };

        match replace_scene_paths(src, dst, &rules) {
            Ok(r) => {
                println!(
                    "written={} format={} replaced={}",
                    r.output_path.display(),
                    r.scene_format,
                    r.replaced_count
                );
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
            match replace_scene_paths(&src, &dst, &rules) {
                Ok(r) => println!(
                    "written={} format={} replaced={}",
                    r.output_path.display(),
                    r.scene_format,
                    r.replaced_count
                ),
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
}

#[derive(Debug, Clone)]
struct AuditHit {
    path: String,
    format: String,
    node: String,
    rule: String,
    preview: String,
}

#[derive(Debug, Clone)]
enum CompiledRule {
    Regex { raw: String, re: Regex },
}

const DEFAULT_AUDIT_RULES: &[&str] = &["python(", "eval", "exec"];

fn run_script_audit(
    input: &Path,
    inline_rules: Vec<String>,
    rule_files: Vec<PathBuf>,
    ignore_case: bool,
    regex_mode: bool,
    json_output: bool,
    summary_only: bool,
    only_hit_nodes: bool,
    max_preview: usize,
) -> i32 {
    let mut raw_rules: Vec<String> = inline_rules
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    for rule_file in rule_files {
        let text = match fs::read_to_string(&rule_file) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: {}: {e}", rule_file.display());
                return 2;
            }
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            raw_rules.push(trimmed.to_string());
        }
    }

    if raw_rules.is_empty() {
        raw_rules = DEFAULT_AUDIT_RULES.iter().map(|s| s.to_string()).collect();
        eprintln!("using default rules: {}", raw_rules.join(", "));
    }

    let mut rules = Vec::new();
    for raw in raw_rules {
        if regex_mode {
            let mut builder = regex::RegexBuilder::new(&raw);
            builder.case_insensitive(ignore_case);
            let re = match builder.build() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: invalid regex '{raw}': {e}");
                    return 2;
                }
            };
            rules.push(CompiledRule::Regex { raw, re });
        } else {
            let escaped = regex::escape(&raw);
            let starts_word = raw
                .chars()
                .next()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
            let ends_word = raw
                .chars()
                .last()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
            let pattern = format!(
                "{}{}{}",
                if starts_word { r"\b" } else { "" },
                escaped,
                if ends_word { r"\b" } else { "" }
            );
            let mut builder = regex::RegexBuilder::new(&pattern);
            builder.case_insensitive(ignore_case);
            let re = match builder.build() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: invalid rule '{raw}': {e}");
                    return 2;
                }
            };
            rules.push(CompiledRule::Regex { raw, re });
        }
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

    let mut all_hits: Vec<AuditHit> = Vec::new();
    let mut file_summaries = Vec::new();

    for file in &files {
        let report = match collect_script_node_entries(file) {
            Ok(r) => r,
            Err(SceneToolError::Io(e)) => {
                eprintln!("error: {e}");
                return 2;
            }
            Err(e) => {
                eprintln!("scene error: {e}");
                return 1;
            }
        };

        let mut file_hit_count = 0usize;
        for entry in report.entries {
            let node_hits = find_hits_in_body(
                &entry.body,
                &rules,
                max_preview,
                &file.display().to_string(),
                &report.scene_format,
                &entry.name,
            );
            if !node_hits.is_empty() {
                file_hit_count += node_hits.len();
                all_hits.extend(node_hits);
            } else if only_hit_nodes {
                // intentionally skip non-hit nodes from any verbose output path
            }
        }

        file_summaries.push((
            file.display().to_string(),
            report.scene_format,
            file_hit_count,
        ));
    }

    if json_output {
        let doc = json!({
            "input": input.display().to_string(),
            "files": file_summaries.iter().map(|(path, format, hit_count)| json!({
                "path": path,
                "format": format,
                "hits": hit_count,
            })).collect::<Vec<_>>(),
            "hit_count": all_hits.len(),
            "hits": all_hits.iter().map(|h| json!({
                "path": h.path,
                "format": h.format,
                "node": h.node,
                "rule": h.rule,
                "preview": h.preview,
            })).collect::<Vec<_>>(),
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: failed to render json: {e}");
                return 1;
            }
        }
    } else if summary_only {
        for (path, format, hit_count) in &file_summaries {
            println!("path={path} format={format} ng_hits={hit_count}");
        }
        println!("total_hits={}", all_hits.len());
    } else {
        for (path, format, hit_count) in &file_summaries {
            println!("path={path} format={format} ng_hits={hit_count}");
        }
        for hit in &all_hits {
            println!(
                "- path={} node={} rule={} preview=\"{}\"",
                hit.path, hit.node, hit.rule, hit.preview
            );
        }
        println!("total_hits={}", all_hits.len());
    }

    if all_hits.is_empty() { 0 } else { 10 }
}

fn find_hits_in_body(
    body: &str,
    rules: &[CompiledRule],
    max_preview: usize,
    path: &str,
    format: &str,
    node: &str,
) -> Vec<AuditHit> {
    let mut hits = Vec::new();

    for rule in rules {
        match rule {
            CompiledRule::Regex { raw, re } => {
                if let Some(m) = re.find(body) {
                    hits.push(AuditHit {
                        path: path.to_string(),
                        format: format.to_string(),
                        node: node.to_string(),
                        rule: raw.clone(),
                        preview: preview_window(body, m.start(), m.end(), max_preview),
                    });
                }
            }
        }
    }

    hits
}

fn preview_window(text: &str, start: usize, end: usize, max_preview: usize) -> String {
    if text.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = text.chars().collect();
    let start_char = text[..start].chars().count();
    let end_char = text[..end].chars().count();
    let width = max_preview.max(16);
    let half = width / 2;
    let left = start_char.saturating_sub(half);
    let right = std::cmp::min(chars.len(), end_char + half);
    let mut s: String = chars[left..right].iter().collect();
    s = s
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    s
}

fn run_to_ascii(input: &PathBuf, output: &PathBuf, keep_all_links: bool) -> i32 {
    match convert_to_maya_ascii(input, output, keep_all_links) {
        Ok(path) => {
            println!("written: {}", path.display());
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
}

fn run_script_clean(input: &PathBuf, output: &PathBuf) -> i32 {
    match remove_script_nodes(input, output) {
        Ok(result) => {
            println!(
                "written={} format={} removed={}",
                result.output_path.display(),
                result.scene_format,
                result.removed_count()
            );
            for name in result.removed_nodes {
                println!("- {name}");
            }
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
}

fn write_scene_dump(input: &Path, output: &Path) -> Result<(), SceneToolError> {
    let text = render_scene_dump_text(input)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, text)?;
    Ok(())
}

fn write_scene_paths(
    input: &Path,
    kind: PathKind,
    output: &Path,
    json_output: bool,
) -> Result<(), SceneToolError> {
    let text = if json_output {
        render_scene_paths_json(input, kind)?
    } else {
        render_scene_paths_text(input, kind)?
    };
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, text)?;
    Ok(())
}

fn render_scene_paths_text(input: &Path, kind: PathKind) -> Result<String, SceneToolError> {
    let report = collect_scene_paths(input, kind)?;
    let kind_label = match kind {
        PathKind::All => "all",
        PathKind::File => "file",
        PathKind::Reference => "reference",
    };
    let mut out = format!(
        "# maya-scene-kit Scene Paths\nsource: {}\nformat: {}\nkind: {}\ncount: {}\n",
        report.scene_path.display(),
        report.scene_format,
        kind_label,
        report.entries.len()
    );

    for e in report.entries {
        let value = e
            .value
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        out.push_str(&format!(
            "- node_type={} node={} attr={} value=\"{}\"\n",
            e.node_type, e.node_name, e.attr, value
        ));
        if let Some(meta) = e.meta {
            let mut bits = Vec::new();
            bits.push(format!("origin={}", meta.origin));
            if let Some(v) = meta.short_name {
                bits.push(format!("short_name={}", v));
            }
            if let Some(v) = meta.reference_node {
                bits.push(format!("reference_node={}", v));
            }
            if let Some(v) = meta.format_hint {
                bits.push(format!("format_hint={}", v));
            }
            if let Some(v) = meta.color_space {
                bits.push(format!("color_space={}", v));
            }
            if !meta.raw_fields.is_empty() {
                bits.push(format!("raw_fields={}", meta.raw_fields.join("|")));
            }
            out.push_str(&format!("  meta: {}\n", bits.join(" ")));
        }
    }
    Ok(out)
}

fn render_scene_paths_json(input: &Path, kind: PathKind) -> Result<String, SceneToolError> {
    let report = collect_scene_paths(input, kind)?;
    let kind_label = match kind {
        PathKind::All => "all",
        PathKind::File => "file",
        PathKind::Reference => "reference",
    };
    let doc = json!({
        "source": report.scene_path.display().to_string(),
        "format": report.scene_format,
        "kind": kind_label,
        "count": report.entries.len(),
        "entries": report.entries.into_iter().map(|e| json!({
            "node_type": e.node_type,
            "node": e.node_name,
            "attr": e.attr,
            "value": e.value,
            "meta": e.meta.as_ref().map(|m| json!({
                "origin": m.origin,
                "short_name": m.short_name,
                "reference_node": m.reference_node,
                "format_hint": m.format_hint,
                "color_space": m.color_space,
                "raw_fields": m.raw_fields,
            })),
        })).collect::<Vec<_>>()
    });
    serde_json::to_string_pretty(&doc)
        .map(|s| format!("{s}\n"))
        .map_err(|e| SceneToolError::Message(format!("failed to render json: {e}")))
}

fn render_scene_paths_collection_json(
    files: &[PathBuf],
    kind: PathKind,
    input: &Path,
) -> Result<String, SceneToolError> {
    let kind_label = match kind {
        PathKind::All => "all",
        PathKind::File => "file",
        PathKind::Reference => "reference",
    };
    let mut items = Vec::new();
    for file in files {
        let report = collect_scene_paths(file, kind)?;
        items.push(json!({
            "source": report.scene_path.display().to_string(),
            "format": report.scene_format,
            "count": report.entries.len(),
            "entries": report.entries.into_iter().map(|e| json!({
                "node_type": e.node_type,
                "node": e.node_name,
                "attr": e.attr,
                "value": e.value,
                "meta": e.meta.as_ref().map(|m| json!({
                    "origin": m.origin,
                    "short_name": m.short_name,
                    "reference_node": m.reference_node,
                    "format_hint": m.format_hint,
                    "color_space": m.color_space,
                    "raw_fields": m.raw_fields,
                })),
            })).collect::<Vec<_>>()
        }));
    }
    let doc = json!({
        "input": input.display().to_string(),
        "kind": kind_label,
        "file_count": items.len(),
        "files": items,
    });
    serde_json::to_string_pretty(&doc)
        .map(|s| format!("{s}\n"))
        .map_err(|e| SceneToolError::Message(format!("failed to render json: {e}")))
}

fn render_scene_dump_text(input: &Path) -> Result<String, SceneToolError> {
    let requires_text = render_requires_dump_text(input)?;
    let script_text = render_script_dump_text(input)?;
    Ok(format!(
        "# maya-scene-kit Scene Dump\nsource: {}\n\n{}\n{}",
        input.display(),
        requires_text,
        script_text
    ))
}

fn render_script_dump_text(input: &Path) -> Result<String, SceneToolError> {
    let temp = unique_temp_path("script");
    let _ = dump_script_nodes(input, &temp)?;
    let text = fs::read_to_string(&temp)?;
    let _ = fs::remove_file(&temp);
    Ok(text)
}

fn render_requires_dump_text(input: &Path) -> Result<String, SceneToolError> {
    let temp = unique_temp_path("requires");
    let _ = dump_requires(input, &temp)?;
    let text = fs::read_to_string(&temp)?;
    let _ = fs::remove_file(&temp);
    Ok(text)
}

fn unique_temp_path(kind: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("maya_mb_read_{kind}_{pid}_{nanos}.txt"))
}

fn collect_scene_files(input: &Path) -> std::io::Result<Vec<PathBuf>> {
    if input.is_file() {
        return Ok(if is_scene_file(input) {
            vec![input.to_path_buf()]
        } else {
            Vec::new()
        });
    }

    let mut out = Vec::new();
    let mut stack = vec![input.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if is_scene_file(&path) {
                out.push(path);
            }
        }
    }

    out.sort();
    Ok(out)
}

fn is_scene_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("ma") | Some("mb")
    )
}

fn print_chunk(
    file_data: &[u8],
    chunk: &Chunk,
    depth: usize,
    max_depth: Option<usize>,
    preview_bytes: usize,
) {
    if let Some(max_d) = max_depth {
        if depth > max_d {
            return;
        }
    }

    let indent = "  ".repeat(depth);
    let mut line = format!(
        "{indent}{} off=0x{:08X} aux=0x{:08X} size={}",
        chunk.tag, chunk.offset, chunk.aux, chunk.size
    );
    if let Some(form) = &chunk.form_type {
        line.push_str(&format!(" form={form}"));
        if chunk.is_group() && !chunk.children_parsed {
            line.push_str(" opaque=1");
        }
    } else {
        let preview = payload_preview(file_data, chunk, preview_bytes);
        if !preview.is_empty() {
            line.push_str(&format!(" data='{preview}'"));
        }
    }
    println!("{line}");

    for child in &chunk.children {
        print_chunk(file_data, child, depth + 1, max_depth, preview_bytes);
    }
}

fn payload_preview(data: &[u8], chunk: &Chunk, preview_bytes: usize) -> String {
    if preview_bytes == 0 || chunk.size == 0 {
        return String::new();
    }
    let end = std::cmp::min(chunk.payload_end, chunk.payload_offset + preview_bytes);
    let raw = &data[chunk.payload_offset..end];
    let text: String = raw
        .iter()
        .map(|b| {
            if (32..=126).contains(b) {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    text.trim_end_matches('\0').to_string()
}
