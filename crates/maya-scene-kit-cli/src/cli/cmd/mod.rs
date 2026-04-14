mod audit;
mod dump;
mod inspect;
mod paths;
mod replace;
mod script_clean;
mod to_ascii;

pub(crate) use self::{
    audit::{ScriptAuditArgs, run_script_audit},
    dump::run_dump,
    inspect::run_inspect,
    paths::{parse_path_kind, run_paths},
    replace::run_replace_paths,
    script_clean::run_script_clean,
    to_ascii::run_to_ascii,
};
use crate::scene::OperationMode;

pub(crate) fn parse_operation_mode(raw: &str) -> OperationMode {
    match raw {
        "strict" => OperationMode::Strict,
        "forensic" => OperationMode::Forensic,
        _ => OperationMode::BestEffort,
    }
}
