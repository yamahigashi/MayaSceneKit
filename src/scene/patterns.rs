use once_cell::sync::Lazy;
use regex::Regex;

pub(super) static CREATE_SCRIPT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bcreateNode\s+script\b").unwrap());
pub(super) static NODE_NAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"-n\s+"([^"]+)""#).unwrap());
pub(super) static SCRIPT_NODE_NAME_FALLBACK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new("([A-Za-z0-9_:|]+ScriptNode)\\x00").unwrap());
pub(super) static NODE_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new("([A-Za-z_|][A-Za-z0-9_:|]*)\\x00").unwrap());
pub(super) static UUID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
        .unwrap()
});
pub(super) static SKINCLUSTER_INDEX_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:ma|ifcl|lw)\[\d+\]$").unwrap());
pub(super) static SKINCLUSTER_DST_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?P<node>[^.]+)\.(?:ma|ifcl|lw)\[(?P<index>\d+)\]$").unwrap());
pub(super) static SKIN_WEIGHT_SINGLE_INDEX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^wl\[\d+\]\.w\[(\d+)\]$").unwrap());
pub(super) static SKIN_WEIGHT_RANGE_INDEX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^wl\[\d+\]\.w\[(\d+):(\d+)\]$").unwrap());
pub(super) static SETATTR_ARRAY_SIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^setAttr -s (\d+) "\.([A-Za-z_][A-Za-z0-9_]*)";$"#).unwrap());
pub(super) static PLUG_INDEX_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?P<attr>[A-Za-z_][A-Za-z0-9_]*)\[(?P<index>\d+)\]$").unwrap());

pub(super) const ALLOWED_NAMESPACE_NODE_NAMES: &[&str] = &[
    "time1",
    "defaultRenderGlobals",
    "defaultResolution",
    "defaultRenderQuality",
    "defaultRenderUtilityList1",
    "defaultRenderingList1",
    "defaultTextureList1",
    "defaultShaderList1",
    "initialShadingGroup",
    "initialParticleSE",
    "defaultLightSet",
    "renderPartition",
    "renderGlobalsList1",
    "postProcessList1",
    "hardwareRenderingGlobals",
    "hyperGraphLayout",
];

pub(super) const BOOL_ATTRS: &[&str] = &["v", "o", "rnd", "vir", "vif", "g", "ro", "fprt", "cfe"];
pub(super) const ARRAY_SIZE_ATTRS: &[&str] = &["lnk", "slnk", "st", "s", "p", "dli", "rlmi", "ni"];
