use crate::{
    ma::ast::ParsedAsciiScene,
    unit_semantics::{
        DEFAULT_ANGULAR_UNIT, DEFAULT_LINEAR_UNIT, DEFAULT_TICKS_PER_SECOND, DEFAULT_TIME_UNIT,
    },
};

pub const DEFAULT_MAYA_VERSION: &str = "unknown";

pub(crate) fn apply_missing_ascii_scene_defaults(scene: &mut ParsedAsciiScene) {
    if scene.version.is_none() {
        scene.version = Some(DEFAULT_MAYA_VERSION.to_string());
    }
    if scene.linear_unit.is_none() {
        scene.linear_unit = Some(DEFAULT_LINEAR_UNIT.to_string());
    }
    if scene.angular_unit.is_none() {
        scene.angular_unit = Some(DEFAULT_ANGULAR_UNIT.to_string());
    }
    if scene.time_unit.is_none() {
        scene.time_unit = Some(DEFAULT_TIME_UNIT.to_string());
    }
    if scene.time_duration.is_none() {
        scene.time_duration = Some(DEFAULT_TICKS_PER_SECOND.to_string());
    }
}
