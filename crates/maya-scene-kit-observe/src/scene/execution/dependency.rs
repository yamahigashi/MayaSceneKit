use std::collections::HashSet;

use super::catalog::ObservedExecutionSurfaceCore;
use crate::scene::{
    DependencyFact, DependencyFactDetail, DependencyFactKind, DependencyRiskClass, SceneToolError,
    source::{ObservationBundle, ObservationData},
};

pub(super) fn collect_dependency_facts(
    observation: &ObservationBundle,
    observed: &[ObservedExecutionSurfaceCore],
) -> Result<Vec<DependencyFact>, SceneToolError> {
    let mut facts = Vec::new();
    match &observation.data {
        ObservationData::Ma { data } => {
            let requires = &data.dump_sections().requires;
            let scene_paths = &data.selective_sections().scene_paths;
            facts.reserve(requires.len() + scene_paths.len());
            let mut scene_path_seen = HashSet::with_capacity(scene_paths.len());

            for require in requires {
                push_static_dependency_fact_if_unique(
                    &mut facts,
                    &mut scene_path_seen,
                    DependencyFactKind::Require,
                    require,
                    DependencyFactDetail::Require,
                    DependencyRiskClass::Informational,
                );
            }

            for entry in scene_paths {
                let kind = if entry.node_type == "reference" {
                    DependencyFactKind::ReferencePath
                } else {
                    DependencyFactKind::FilePath
                };
                push_simple_dependency_fact_if_unique(
                    &mut facts,
                    &mut scene_path_seen,
                    kind,
                    &entry.value,
                    || {
                        build_scene_path_dependency_fact(
                            kind,
                            entry.node_type.as_str(),
                            entry.attr.as_str(),
                            &entry.value,
                        )
                    },
                );
            }
        }
        ObservationData::Mb { session } => {
            let requires = observation.requires()?;
            let scene_paths =
                maya_scene_kit_formats::mb::paths::extract_raw_scene_paths_from_mb(&session.mb);
            let base_fact_count = requires.len() + scene_paths.len();
            facts.reserve(base_fact_count);
            let mut seen = HashSet::with_capacity(base_fact_count);

            for require in &requires {
                push_static_dependency_fact_if_unique(
                    &mut facts,
                    &mut seen,
                    DependencyFactKind::Require,
                    require,
                    DependencyFactDetail::Require,
                    DependencyRiskClass::Informational,
                );
            }

            for entry in &scene_paths {
                let kind = if entry.node_type == "reference" {
                    DependencyFactKind::ReferencePath
                } else {
                    DependencyFactKind::FilePath
                };
                push_simple_dependency_fact_if_unique(
                    &mut facts,
                    &mut seen,
                    kind,
                    &entry.value,
                    || {
                        build_scene_path_dependency_fact(
                            kind,
                            entry.node_type.as_str(),
                            entry.attr.as_str(),
                            &entry.value,
                        )
                    },
                );
            }
        }
    }

    let mut seen = HashSet::new();
    for surface in observed {
        if let Some(mel) = &surface.mel {
            for call in &mel.calls {
                let kind = match call.name.as_ref() {
                    "source" => Some(DependencyFactKind::SourceCommand),
                    "loadPlugin" => Some(DependencyFactKind::LoadPluginCommand),
                    _ => None,
                };
                let Some(kind) = kind else {
                    continue;
                };
                let source_kind = surface.origin.source_kind.as_deref().unwrap_or_default();
                let target = call
                    .literal_first_arg
                    .as_deref()
                    .unwrap_or(surface.text.as_ref());
                push_dependency_fact_if_unique(
                    &mut facts,
                    &mut seen,
                    kind,
                    target,
                    source_kind,
                    || DependencyFact {
                        kind,
                        risk: promote_dependency_risk(
                            classify_dependency_risk(target),
                            DependencyRiskClass::Review,
                        ),
                        target: target.to_string(),
                        detail: DependencyFactDetail::MelDependencyObserved {
                            command_name: call.name.to_string(),
                        },
                        origin: Some(surface.origin.clone()),
                    },
                );
            }
        }

        if surface.origin.surface_kind
            == crate::scene::evidence::ExecutionSurfaceKind::FileCommandCallback
        {
            let source_kind = surface.origin.source_kind.as_deref().unwrap_or_default();
            push_dependency_fact_if_unique(
                &mut facts,
                &mut seen,
                DependencyFactKind::FileCommandCallback,
                &surface.text,
                source_kind,
                || DependencyFact {
                    kind: DependencyFactKind::FileCommandCallback,
                    risk: DependencyRiskClass::Review,
                    target: surface.text.to_string(),
                    detail: DependencyFactDetail::FileCommandCallbackObserved,
                    origin: Some(surface.origin.clone()),
                },
            );
        }
    }

    Ok(facts)
}

pub(crate) fn build_scene_path_dependency_fact(
    kind: DependencyFactKind,
    node_type: &str,
    attr: &str,
    value: &str,
) -> DependencyFact {
    DependencyFact {
        kind,
        risk: classify_dependency_risk(value),
        target: value.to_string(),
        detail: DependencyFactDetail::ScenePath {
            node_type: node_type.to_string(),
            attr: attr.to_string(),
        },
        origin: None,
    }
}

pub(crate) fn classify_dependency_risk(value: &str) -> DependencyRiskClass {
    let trimmed = value.trim();
    let bytes = trimmed.as_bytes();
    if bytes.starts_with(b"\\\\")
        || bytes.starts_with(b"//")
        || bytes.first() == Some(&b'/')
        || bytes.get(1) == Some(&b':')
    {
        return DependencyRiskClass::Uncertain;
    }
    if trimmed.contains("..") {
        return DependencyRiskClass::Review;
    }
    DependencyRiskClass::Informational
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DependencyFactSimpleSeenKey<'a> {
    kind: DependencyFactKind,
    target: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DependencyFactSeenKey<'a> {
    kind: DependencyFactKind,
    target: &'a str,
    source_kind: &'a str,
}

fn push_static_dependency_fact_if_unique<'a>(
    out: &mut Vec<DependencyFact>,
    seen: &mut HashSet<DependencyFactSimpleSeenKey<'a>>,
    kind: DependencyFactKind,
    target: &'a str,
    detail: DependencyFactDetail,
    risk: DependencyRiskClass,
) {
    if mark_simple_dependency_fact_seen(seen, kind, target) {
        out.push(DependencyFact {
            kind,
            risk,
            target: target.to_string(),
            detail,
            origin: None,
        });
    }
}

fn push_simple_dependency_fact_if_unique<'a>(
    out: &mut Vec<DependencyFact>,
    seen: &mut HashSet<DependencyFactSimpleSeenKey<'a>>,
    kind: DependencyFactKind,
    target: &'a str,
    build: impl FnOnce() -> DependencyFact,
) {
    if mark_simple_dependency_fact_seen(seen, kind, target) {
        out.push(build());
    }
}

fn mark_simple_dependency_fact_seen<'a>(
    seen: &mut HashSet<DependencyFactSimpleSeenKey<'a>>,
    kind: DependencyFactKind,
    target: &'a str,
) -> bool {
    seen.insert(DependencyFactSimpleSeenKey { kind, target })
}

fn push_dependency_fact_if_unique<'a>(
    out: &mut Vec<DependencyFact>,
    seen: &mut HashSet<DependencyFactSeenKey<'a>>,
    kind: DependencyFactKind,
    target: &'a str,
    source_kind: &'a str,
    build: impl FnOnce() -> DependencyFact,
) {
    if mark_dependency_fact_seen(seen, kind, target, source_kind) {
        out.push(build());
    }
}

fn mark_dependency_fact_seen<'a>(
    seen: &mut HashSet<DependencyFactSeenKey<'a>>,
    kind: DependencyFactKind,
    target: &'a str,
    source_kind: &'a str,
) -> bool {
    seen.insert(DependencyFactSeenKey {
        kind,
        target,
        source_kind,
    })
}

fn promote_dependency_risk(
    current: DependencyRiskClass,
    minimum: DependencyRiskClass,
) -> DependencyRiskClass {
    if dependency_risk_rank(current) > dependency_risk_rank(minimum) {
        current
    } else {
        minimum
    }
}

fn dependency_risk_rank(risk: DependencyRiskClass) -> u8 {
    match risk {
        DependencyRiskClass::Informational => 0,
        DependencyRiskClass::Review => 1,
        DependencyRiskClass::Uncertain => 2,
    }
}
