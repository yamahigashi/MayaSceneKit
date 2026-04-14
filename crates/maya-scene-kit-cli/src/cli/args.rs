use std::path::PathBuf;

use clap::{Arg, ArgAction, Command};

pub(super) fn build_parser() -> Command {
    Command::new("maya-scene-kit")
        .about("Standalone utilities for Maya scene files (.mb/.ma).")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("inspect")
                .about("Inspect Maya Binary chunk structure")
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
                )
                .arg(max_bytes_arg()),
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
                .arg(node_info_arg())
                .arg(max_bytes_arg()),
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
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Output JSON"),
                )
                .arg(node_info_arg())
                .arg(max_bytes_arg()),
        )
        .subcommand(
            Command::new("audit")
                .about("Audit execution surfaces with built-in policy and optional literal markers")
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
                        .help("Additional literal marker that emits custom_rule_match (repeatable)"),
                )
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("summary-only")
                        .long("summary-only")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("max-preview")
                        .long("max-preview")
                        .default_value("0")
                        .help("Preview width for audit hit excerpts; 0 disables preview output")
                        .value_parser(clap::value_parser!(usize)),
                )
                .arg(node_info_arg())
                .arg(max_bytes_arg()),
        )
        .subcommand(
            Command::new("to-ascii")
                .about("Convert Maya Binary (.mb) scenes to Maya ASCII (.ma)")
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
                    Arg::new("issues-json")
                        .long("issues-json")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Write structured decode/recovery issues as JSON"),
                )
                .arg(
                    Arg::new("write-unknown-blobs")
                        .long("write-unknown-blobs")
                        .action(ArgAction::SetTrue)
                        .help(
                            "Materialize large unknown payloads as sidecar .bin files next to --issues-json",
                        ),
                )
                .arg(node_info_arg())
                .arg(max_bytes_arg())
                .arg(
                    Arg::new("embed-metadata")
                        .long("embed-metadata")
                        .action(ArgAction::SetTrue)
                        .help("Embed source path metadata comments in generated .ma output"),
                )
                .arg(
                    Arg::new("mode")
                        .long("mode")
                        .default_value("best-effort")
                        .value_parser(["strict", "best-effort", "forensic"])
                        .help("Conversion execution mode"),
                ),
        )
        .subcommand(
            Command::new("clean")
                .about("Remove script nodes and save in forensic mode")
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
                .arg(node_info_arg())
                .arg(max_bytes_arg()),
        )
        .subcommand(
            Command::new("replace")
                .about("Replace file/reference paths in scene files in forensic mode")
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
                .arg(node_info_arg())
                .arg(max_bytes_arg()),
        )
}

fn node_info_arg() -> Arg {
    Arg::new("node-info")
        .long("node-info")
        .action(ArgAction::Append)
        .num_args(1)
        .value_parser(clap::value_parser!(PathBuf))
        .help("Additional node_info YAML overlay (repeatable)")
}

fn max_bytes_arg() -> Arg {
    Arg::new("max-bytes")
        .long("max-bytes")
        .value_parser(clap::value_parser!(usize))
        .help("Maximum parse size in bytes for Maya scene input")
}

pub(super) fn normalize_argv(argv: Vec<String>) -> Vec<String> {
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
    argv
}
