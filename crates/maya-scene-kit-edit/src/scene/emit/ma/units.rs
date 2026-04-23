use maya_scene_kit_observe::scene::model::RecoveredHeader;

use crate::unit_semantics::{
    DEFAULT_TICKS_PER_SECOND, normalize_angular_unit, normalize_time_unit,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AngularRenderUnit {
    Degree,
    Radian,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TimeRenderContext {
    pub(super) unit: TimeRenderUnit,
    pub(super) ticks_per_second: f64,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum TimeRenderUnit {
    Game,
    Film,
    Pal,
    Ntsc,
    Show,
    Palf,
    Ntscf,
    Sec,
    Min,
    Hour,
    MilliSec,
}

impl TimeRenderUnit {
    pub(super) fn units_per_second(self) -> f64 {
        match self {
            TimeRenderUnit::Game => 15.0,
            TimeRenderUnit::Film => 24.0,
            TimeRenderUnit::Pal => 25.0,
            TimeRenderUnit::Ntsc => 30.0,
            TimeRenderUnit::Show => 48.0,
            TimeRenderUnit::Palf => 50.0,
            TimeRenderUnit::Ntscf => 60.0,
            TimeRenderUnit::Sec => 1.0,
            TimeRenderUnit::Min => 1.0 / 60.0,
            TimeRenderUnit::Hour => 1.0 / 3600.0,
            TimeRenderUnit::MilliSec => 1000.0,
        }
    }
}

fn parse_time_render_unit(unit: &str) -> Option<TimeRenderUnit> {
    match normalize_time_unit(unit).as_str() {
        "game" => Some(TimeRenderUnit::Game),
        "film" => Some(TimeRenderUnit::Film),
        "pal" => Some(TimeRenderUnit::Pal),
        "ntsc" => Some(TimeRenderUnit::Ntsc),
        "show" => Some(TimeRenderUnit::Show),
        "palf" => Some(TimeRenderUnit::Palf),
        "ntscf" => Some(TimeRenderUnit::Ntscf),
        "sec" => Some(TimeRenderUnit::Sec),
        "min" => Some(TimeRenderUnit::Min),
        "hour" => Some(TimeRenderUnit::Hour),
        "millisec" => Some(TimeRenderUnit::MilliSec),
        _ => None,
    }
}

pub(crate) fn build_time_render_context(metadata: &RecoveredHeader) -> Option<TimeRenderContext> {
    let unit = metadata.tuni.as_deref().and_then(parse_time_render_unit)?;
    let ticks_per_second = metadata
        .tdur
        .as_deref()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| *value > 0.0)
        .unwrap_or_else(|| DEFAULT_TICKS_PER_SECOND.parse::<f64>().unwrap());
    Some(TimeRenderContext {
        unit,
        ticks_per_second,
    })
}

pub(crate) fn build_angular_render_unit(metadata: &RecoveredHeader) -> AngularRenderUnit {
    metadata
        .auni
        .as_deref()
        .map(parse_angular_render_unit)
        .unwrap_or(AngularRenderUnit::Degree)
}

fn parse_angular_render_unit(unit: &str) -> AngularRenderUnit {
    match normalize_angular_unit(unit).as_str() {
        "degree" | "deg" => AngularRenderUnit::Degree,
        "radian" | "rad" => AngularRenderUnit::Radian,
        _ => AngularRenderUnit::Unknown,
    }
}
