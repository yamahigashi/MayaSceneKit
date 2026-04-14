use once_cell::sync::Lazy;
use regex::Regex;

pub(super) static SKIN_WEIGHT_LIST_SINGLE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^wl\[(\d+)\]\.w$").unwrap());
pub(super) static SKIN_WEIGHT_LIST_RANGE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^wl\[(\d+):(\d+)\]\.w$").unwrap());
