use std::borrow::Cow;

use crate::{error::SceneToolError, ma::values::parse_f64_token, mel, model::NumericValue};

pub(super) fn normalized_arg_text<'a>(
    source_text: &'a str,
    arg: Option<&'a mel::MelNormalizedPositionalArg>,
) -> Option<&'a str> {
    arg.map(|arg| arg.preferred_text(source_text))
}

pub(super) fn raw_item_text<'a>(
    source_text: &'a str,
    item: Option<&'a mel::MelRawShellItem>,
) -> Option<Cow<'a, str>> {
    item.map(|item| item.preferred_text(source_text))
}

pub(super) fn flag_matches(
    source_text: &str,
    flag: &mel::MelNormalizedFlag,
    canonical: &str,
    short: &str,
) -> bool {
    flag.matches_name(source_text, canonical, short)
}

pub(super) fn find_flag<'a>(
    source_text: &str,
    flags: &'a [mel::MelNormalizedFlag],
    canonical: &str,
    short: &str,
) -> Option<&'a mel::MelNormalizedFlag> {
    flags
        .iter()
        .find(|flag| flag_matches(source_text, flag, canonical, short))
}

pub(super) fn parse_numeric_token(value: &str) -> Result<NumericValue, SceneToolError> {
    Ok(NumericValue::from_f64(parse_f64_token(value)?))
}
