use maya_scene_kit_formats::mel::MelValueShape;

use super::{MelSurfaceCommandMode, MelSurfaceNormalizedCommand, MelSurfaceNormalizedItem};
use crate::scene::{
    EffectCertainty, ExecutionEffectClass, ExecutionReason, ExecutionReasonTemplate,
    ExecutionSemanticClass, StaticExecutionReason,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptFlagPayloadKind {
    ProcReference,
    ExecutableBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScriptFlagSemantics<'a> {
    flag_name: &'a str,
    payload_kind: ScriptFlagPayloadKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectRule {
    pub(crate) effect: ExecutionEffectClass,
    pub(crate) semantic_class: ExecutionSemanticClass,
    pub(crate) certainty: EffectCertainty,
    reason_kind: ReasonKind,
    explicit_reason: Option<ExecutionReason>,
}

impl EffectRule {
    const fn new(
        effect: ExecutionEffectClass,
        semantic_class: ExecutionSemanticClass,
        certainty: EffectCertainty,
        reason_kind: ReasonKind,
    ) -> Self {
        Self {
            effect,
            semantic_class,
            certainty,
            reason_kind,
            explicit_reason: None,
        }
    }

    fn with_explicit_reason(mut self, reason: ExecutionReason) -> Self {
        self.explicit_reason = Some(reason);
        self
    }

    pub(crate) fn reason(&self, name: &str) -> ExecutionReason {
        if let Some(reason) = &self.explicit_reason {
            return reason.clone();
        }
        match self.reason_kind {
            ReasonKind::MelDynamicCommand => {
                named_reason(ExecutionReasonTemplate::DynamicMelCommandDetected, name)
            }
            ReasonKind::MelHookLikeCommand => {
                named_reason(ExecutionReasonTemplate::HookLikeMelCommandDetected, name)
            }
            ReasonKind::MelExternalDependencyCommand => named_reason(
                ExecutionReasonTemplate::ExternalDependencyMelCommandDetected,
                name,
            ),
            ReasonKind::MelSceneMutationCommand => named_reason(
                ExecutionReasonTemplate::SceneMutatingMelCommandDetected,
                name,
            ),
            ReasonKind::MelUiImpactCommand => {
                named_reason(ExecutionReasonTemplate::UiImpactingMelCommandDetected, name)
            }
            ReasonKind::MelDiagnosticOutput => {
                static_reason(StaticExecutionReason::DiagnosticMelOutputDetected)
            }
            ReasonKind::MelReadOnlyCommand => {
                named_reason(ExecutionReasonTemplate::ReadOnlyMelCommandDetected, name)
            }
            ReasonKind::PythonDiagnosticOutput => {
                static_reason(StaticExecutionReason::PythonPrintDetected)
            }
            ReasonKind::PythonDynamicCall => {
                named_reason(ExecutionReasonTemplate::DynamicPythonCallDetected, name)
            }
            ReasonKind::PythonExternalCapability => named_reason(
                ExecutionReasonTemplate::ExternalPythonCapabilityDetected,
                name,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReasonKind {
    MelDynamicCommand,
    MelHookLikeCommand,
    MelExternalDependencyCommand,
    MelSceneMutationCommand,
    MelUiImpactCommand,
    MelDiagnosticOutput,
    MelReadOnlyCommand,
    PythonDiagnosticOutput,
    PythonDynamicCall,
    PythonExternalCapability,
}

pub(crate) fn classify_mel_command(name: &str) -> Option<EffectRule> {
    match name {
        "python" | "eval" => Some(EffectRule::new(
            ExecutionEffectClass::DynamicEvaluation,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ReasonKind::MelDynamicCommand,
        )),
        "scriptJob" | "evalDeferred" => Some(EffectRule::new(
            ExecutionEffectClass::HookRegistration,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ReasonKind::MelHookLikeCommand,
        )),
        "source" | "loadPlugin" | "file" => Some(EffectRule::new(
            ExecutionEffectClass::ExternalDependency,
            ExecutionSemanticClass::DependencyWrite,
            EffectCertainty::Proven,
            ReasonKind::MelExternalDependencyCommand,
        )),
        "setAttr" | "addAttr" | "connectAttr" | "disconnectAttr" | "createNode" | "delete"
        | "rename" | "parent" | "playbackOptions" | "currentUnit" | "optionVar" => {
            Some(default_mutation_rule(name))
        }
        "warning" | "error" | "confirmDialog" | "headsUpMessage" => Some(EffectRule::new(
            ExecutionEffectClass::UIImpact,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ReasonKind::MelUiImpactCommand,
        )),
        "print" => Some(EffectRule::new(
            ExecutionEffectClass::DiagnosticOutput,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ReasonKind::MelDiagnosticOutput,
        )),
        "getAttr" | "ls" | "objExists" | "attributeQuery" | "referenceQuery" | "getPanel"
        | "animCurveEditor" | "clipEditor" | "dopeSheetEditor" | "grid" | "hyperGraph"
        | "modelEditor" | "modelPanel" | "nodeEditor" | "outlinerEditor" | "outlinerPanel"
        | "paneLayout" | "panelConfiguration" | "panelHistory" | "panel" | "posePanel"
        | "sceneUIReplacement" | "scriptedPanel" | "shapePanel" | "stereoCameraView"
        | "viewManip" | "workspaceControl" => Some(EffectRule::new(
            ExecutionEffectClass::SceneReadOnly,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ReasonKind::MelReadOnlyCommand,
        )),
        _ => None,
    }
}

pub(crate) fn classify_mel_command_with_semantics(
    source_text: &str,
    command: &MelSurfaceNormalizedCommand,
    fallback_name: &str,
) -> Option<EffectRule> {
    let name = if command.schema_name.is_empty() {
        fallback_name
    } else {
        command.schema_name.as_ref()
    };

    if let Some(flag) = first_script_flag_semantics(source_text, command) {
        return Some(
            EffectRule::new(
                ExecutionEffectClass::HookRegistration,
                ExecutionSemanticClass::General,
                EffectCertainty::Uncertain,
                ReasonKind::MelHookLikeCommand,
            )
            .with_explicit_reason(ExecutionReason::FlagOnCommand {
                flag_name: flag.flag_name.to_string(),
                command_name: name.to_string(),
            }),
        );
    }

    if name == "optionVar" {
        return Some(match command.mode {
            MelSurfaceCommandMode::Query => EffectRule::new(
                ExecutionEffectClass::SceneReadOnly,
                ExecutionSemanticClass::General,
                EffectCertainty::Proven,
                ReasonKind::MelReadOnlyCommand,
            )
            .with_explicit_reason(static_reason(
                StaticExecutionReason::ReadOnlyMelOptionVarQueryDetected,
            )),
            _ => default_mutation_rule(name),
        });
    }

    if is_ui_editor_command(name) {
        return Some(match command.mode {
            MelSurfaceCommandMode::Query => EffectRule::new(
                ExecutionEffectClass::SceneReadOnly,
                ExecutionSemanticClass::General,
                EffectCertainty::Proven,
                ReasonKind::MelReadOnlyCommand,
            ),
            MelSurfaceCommandMode::Create
            | MelSurfaceCommandMode::Edit
            | MelSurfaceCommandMode::Unknown => EffectRule::new(
                ExecutionEffectClass::UIImpact,
                ExecutionSemanticClass::General,
                EffectCertainty::Proven,
                ReasonKind::MelUiImpactCommand,
            ),
        });
    }

    let base = classify_mel_command(name)?;
    if base.effect != ExecutionEffectClass::SceneMutation {
        return Some(base);
    }
    let semantic_class = match name {
        "playbackOptions" | "currentUnit" => ExecutionSemanticClass::OperationalConfigWrite,
        "createNode" | "delete" | "rename" | "parent" => ExecutionSemanticClass::SceneDataWrite,
        "setAttr" | "addAttr" | "connectAttr" | "disconnectAttr" => {
            classify_mutation_target(source_text, command)
        }
        _ => base.semantic_class,
    };

    Some(EffectRule {
        semantic_class,
        ..base
    })
}

pub(crate) fn classify_python_call_target(name: &str) -> Option<EffectRule> {
    match name {
        "print" => Some(EffectRule::new(
            ExecutionEffectClass::DiagnosticOutput,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ReasonKind::PythonDiagnosticOutput,
        )),
        "exec" | "eval" | "compile" | "__import__" => Some(EffectRule::new(
            ExecutionEffectClass::DynamicEvaluation,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ReasonKind::PythonDynamicCall,
        )),
        "os.system" | "os.popen" | "subprocess.call" | "subprocess.run" | "subprocess.Popen"
        | "socket.socket" | "ctypes.CDLL" | "ctypes.PyDLL" | "ctypes.WinDLL" | "ctypes.OleDLL"
        | "open" => Some(EffectRule::new(
            ExecutionEffectClass::ExternalDependency,
            ExecutionSemanticClass::DependencyWrite,
            EffectCertainty::Proven,
            ReasonKind::PythonExternalCapability,
        )),
        _ => None,
    }
}

pub(crate) fn effect_rank(effect: ExecutionEffectClass) -> u8 {
    match effect {
        ExecutionEffectClass::PureComputation => 0,
        ExecutionEffectClass::DiagnosticOutput => 1,
        ExecutionEffectClass::SceneReadOnly => 2,
        ExecutionEffectClass::UIImpact => 3,
        ExecutionEffectClass::ExternalDependency => 4,
        ExecutionEffectClass::DynamicEvaluation => 5,
        ExecutionEffectClass::HookRegistration => 6,
        ExecutionEffectClass::SceneMutation => 7,
        ExecutionEffectClass::Unknown => 8,
    }
}

fn default_mutation_rule(name: &str) -> EffectRule {
    let semantic_class = match name {
        "playbackOptions" | "currentUnit" => ExecutionSemanticClass::OperationalConfigWrite,
        "createNode" | "delete" | "rename" | "parent" => ExecutionSemanticClass::SceneDataWrite,
        _ => ExecutionSemanticClass::UnknownWrite,
    };
    EffectRule::new(
        ExecutionEffectClass::SceneMutation,
        semantic_class,
        EffectCertainty::Proven,
        ReasonKind::MelSceneMutationCommand,
    )
}

fn static_reason(value: StaticExecutionReason) -> ExecutionReason {
    ExecutionReason::Static { value }
}

fn named_reason(template: ExecutionReasonTemplate, value: &str) -> ExecutionReason {
    ExecutionReason::Named {
        template,
        value: value.to_string(),
    }
}

fn classify_mutation_target(
    _source_text: &str,
    command: &MelSurfaceNormalizedCommand,
) -> ExecutionSemanticClass {
    let Some(target) = first_positional_literal(command) else {
        return ExecutionSemanticClass::UnknownWrite;
    };
    classify_attr_target(target)
}

fn first_script_flag_semantics<'a>(
    source_text: &'a str,
    command: &'a MelSurfaceNormalizedCommand,
) -> Option<ScriptFlagSemantics<'a>> {
    command.items.iter().find_map(|item| match item {
        MelSurfaceNormalizedItem::Flag(flag)
            if flag.value_shapes.contains(&MelValueShape::Script)
                && flag
                    .iter_script_args()
                    .any(|arg| classify_script_flag_payload_kind(arg, source_text).is_some()) =>
        {
            let payload_kind = flag
                .iter_script_args()
                .filter_map(|arg| classify_script_flag_payload_kind(arg, source_text))
                .find(|kind| *kind == ScriptFlagPayloadKind::ExecutableBody)
                .unwrap_or(ScriptFlagPayloadKind::ProcReference);
            Some(ScriptFlagSemantics {
                flag_name: flag.preferred_name(source_text),
                payload_kind,
            })
        }
        MelSurfaceNormalizedItem::Flag(_) | MelSurfaceNormalizedItem::Positional(_) => None,
    })
}

fn is_bare_callback_identifier(text: &str) -> bool {
    let mut chars = text.trim().chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !matches!(first, 'a'..='z' | 'A'..='Z' | '_') {
        return false;
    }
    chars.all(|ch| matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_'))
}

fn classify_script_flag_payload_kind(
    arg: &super::MelSurfaceNormalizedArg,
    source_text: &str,
) -> Option<ScriptFlagPayloadKind> {
    let text = arg.preferred_text(source_text).trim();
    if text.is_empty() || is_empty_callback_placeholder(text) {
        return None;
    }
    Some(match arg.literal.as_deref() {
        Some(literal) if !arg.dynamic && is_bare_callback_identifier(literal) => {
            ScriptFlagPayloadKind::ProcReference
        }
        _ => ScriptFlagPayloadKind::ExecutableBody,
    })
}

fn is_empty_callback_placeholder(text: &str) -> bool {
    let trimmed = text.trim();
    let Some(inner) = trimmed
        .strip_prefix('{')
        .and_then(|text| text.strip_suffix('}'))
    else {
        return false;
    };
    inner.trim().is_empty()
}

fn is_ui_editor_command(name: &str) -> bool {
    matches!(
        name,
        "animCurveEditor"
            | "clipEditor"
            | "dopeSheetEditor"
            | "grid"
            | "hyperGraph"
            | "modelEditor"
            | "modelPanel"
            | "nodeEditor"
            | "outlinerEditor"
            | "outlinerPanel"
            | "paneLayout"
            | "panelConfiguration"
            | "panelHistory"
            | "panel"
            | "posePanel"
            | "sceneUIReplacement"
            | "scriptedPanel"
            | "shapePanel"
            | "stereoCameraView"
            | "viewManip"
            | "workspaceControl"
    )
}

fn first_positional_literal(command: &MelSurfaceNormalizedCommand) -> Option<&str> {
    command.items.iter().find_map(|item| match item {
        MelSurfaceNormalizedItem::Positional(arg) => arg.literal.as_deref(),
        MelSurfaceNormalizedItem::Flag(_) => None,
    })
}

fn classify_attr_target(target: &str) -> ExecutionSemanticClass {
    let attr = target
        .rsplit('.')
        .next()
        .map(|segment| format!(".{segment}"))
        .unwrap_or_default();

    match attr.as_str() {
        ".b" | ".st" | ".stp" => ExecutionSemanticClass::ScriptBearingWrite,
        _ if attr.is_empty() => ExecutionSemanticClass::UnknownWrite,
        _ => ExecutionSemanticClass::SceneDataWrite,
    }
}

#[cfg(test)]
mod tests {
    use maya_scene_kit_formats::mel::{MelSpan, MelValueShape};

    use super::{
        EffectRule, classify_mel_command, classify_mel_command_with_semantics,
        classify_python_call_target, effect_rank,
    };
    use crate::scene::{
        EffectCertainty, ExecutionEffectClass, ExecutionReason, ExecutionSemanticClass,
        StaticExecutionReason,
        observe::{
            MelSurfaceCommandMode, MelSurfaceNormalizedArg, MelSurfaceNormalizedCommand,
            MelSurfaceNormalizedFlag, MelSurfaceNormalizedItem,
        },
    };

    fn text_span(source: &str, text: &str) -> MelSpan {
        let start = source.find(text).expect("text span");
        MelSpan {
            start,
            end: start + text.len(),
        }
    }

    fn assert_rule(
        rule: EffectRule,
        effect: ExecutionEffectClass,
        semantic_class: ExecutionSemanticClass,
        certainty: EffectCertainty,
        reason: ExecutionReason,
    ) {
        assert_eq!(rule.effect, effect);
        assert_eq!(rule.semantic_class, semantic_class);
        assert_eq!(rule.certainty, certainty);
        assert_eq!(rule.reason("print"), reason);
    }

    #[test]
    fn mel_registry_classifies_known_commands() {
        let print = classify_mel_command("print").expect("print rule");
        assert_rule(
            print,
            ExecutionEffectClass::DiagnosticOutput,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ExecutionReason::Static {
                value: StaticExecutionReason::DiagnosticMelOutputDetected,
            },
        );

        let eval = classify_mel_command("eval").expect("eval rule");
        assert_eq!(eval.effect, ExecutionEffectClass::DynamicEvaluation);

        let source = classify_mel_command("source").expect("source rule");
        assert_eq!(source.effect, ExecutionEffectClass::ExternalDependency);
    }

    #[test]
    fn mel_registry_uses_target_sensitive_semantics_for_setattr() {
        let source = r#"setAttr "script1.b";"#;
        let command = MelSurfaceNormalizedCommand {
            schema_name: "setAttr".into(),
            mode: MelSurfaceCommandMode::Create,
            items: vec![MelSurfaceNormalizedItem::Positional(
                MelSurfaceNormalizedArg {
                    text_span: text_span(source, r#""script1.b""#),
                    literal: Some("script1.b".into()),
                    dynamic: false,
                    span_start: 0,
                    span_end: 10,
                },
            )],
            span_start: 0,
            span_end: 10,
        };
        let rule =
            classify_mel_command_with_semantics(source, &command, "setAttr").expect("setAttr rule");
        assert_eq!(rule.effect, ExecutionEffectClass::SceneMutation);
        assert_eq!(
            rule.semantic_class,
            ExecutionSemanticClass::ScriptBearingWrite
        );
    }

    #[test]
    fn script_typed_ui_flag_is_hook_registration() {
        let source = r#"modelEditor -editorChanged "safeProc" modelPanel4;"#;
        let command = MelSurfaceNormalizedCommand {
            schema_name: "modelEditor".into(),
            mode: MelSurfaceCommandMode::Edit,
            items: vec![
                MelSurfaceNormalizedItem::Flag(MelSurfaceNormalizedFlag {
                    source_span: text_span(source, "-editorChanged"),
                    canonical_name: Some("editorChanged".into()),
                    value_shapes: vec![MelValueShape::Script],
                    args: vec![MelSurfaceNormalizedArg {
                        text_span: text_span(source, r#""safeProc""#),
                        literal: Some("safeProc".into()),
                        dynamic: false,
                        span_start: 0,
                        span_end: 10,
                    }],
                    span_start: 0,
                    span_end: 10,
                }),
                MelSurfaceNormalizedItem::Positional(MelSurfaceNormalizedArg {
                    text_span: text_span(source, "modelPanel4"),
                    literal: Some("modelPanel4".into()),
                    dynamic: false,
                    span_start: 11,
                    span_end: 22,
                }),
            ],
            span_start: 0,
            span_end: 22,
        };

        let rule = classify_mel_command_with_semantics(source, &command, "modelEditor")
            .expect("hook rule");
        assert_eq!(rule.effect, ExecutionEffectClass::HookRegistration);
        assert_eq!(rule.certainty, EffectCertainty::Uncertain);
        assert_eq!(
            rule.reason("modelEditor"),
            ExecutionReason::FlagOnCommand {
                flag_name: "editorChanged".to_string(),
                command_name: "modelEditor".to_string(),
            }
        );
    }

    #[test]
    fn inline_script_typed_ui_flag_is_uncertain_hook_registration() {
        let source = r#"modelEditor -editorChanged "python(\"import os\")" modelPanel4;"#;
        let command = MelSurfaceNormalizedCommand {
            schema_name: "modelEditor".into(),
            mode: MelSurfaceCommandMode::Edit,
            items: vec![
                MelSurfaceNormalizedItem::Flag(MelSurfaceNormalizedFlag {
                    source_span: text_span(source, "-editorChanged"),
                    canonical_name: Some("editorChanged".into()),
                    value_shapes: vec![MelValueShape::Script],
                    args: vec![MelSurfaceNormalizedArg {
                        text_span: text_span(source, r#""python(\"import os\")""#),
                        literal: Some(r#"python("import os")"#.into()),
                        dynamic: false,
                        span_start: 0,
                        span_end: 20,
                    }],
                    span_start: 0,
                    span_end: 20,
                }),
                MelSurfaceNormalizedItem::Positional(MelSurfaceNormalizedArg {
                    text_span: text_span(source, "modelPanel4"),
                    literal: Some("modelPanel4".into()),
                    dynamic: false,
                    span_start: 21,
                    span_end: 32,
                }),
            ],
            span_start: 0,
            span_end: 32,
        };

        let rule = classify_mel_command_with_semantics(source, &command, "modelEditor")
            .expect("hook rule");
        assert_eq!(rule.effect, ExecutionEffectClass::HookRegistration);
        assert_eq!(rule.certainty, EffectCertainty::Uncertain);
    }

    #[test]
    fn empty_script_placeholder_falls_back_to_ui_impact() {
        let source = r#"outlinerEditor -e -selectCommand "{}" outlinerPanel1;"#;
        let command = MelSurfaceNormalizedCommand {
            schema_name: "outlinerEditor".into(),
            mode: MelSurfaceCommandMode::Edit,
            items: vec![
                MelSurfaceNormalizedItem::Flag(MelSurfaceNormalizedFlag {
                    source_span: text_span(source, "-selectCommand"),
                    canonical_name: Some("selectCommand".into()),
                    value_shapes: vec![MelValueShape::Script],
                    args: vec![MelSurfaceNormalizedArg {
                        text_span: text_span(source, r#""{}""#),
                        literal: Some("{}".into()),
                        dynamic: false,
                        span_start: 0,
                        span_end: 2,
                    }],
                    span_start: 0,
                    span_end: 2,
                }),
                MelSurfaceNormalizedItem::Positional(MelSurfaceNormalizedArg {
                    text_span: text_span(source, "outlinerPanel1"),
                    literal: Some("outlinerPanel1".into()),
                    dynamic: false,
                    span_start: 3,
                    span_end: 16,
                }),
            ],
            span_start: 0,
            span_end: 16,
        };

        let rule = classify_mel_command_with_semantics(source, &command, "outlinerEditor")
            .expect("ui impact rule");
        assert_eq!(rule.effect, ExecutionEffectClass::UIImpact);
        assert_eq!(rule.certainty, EffectCertainty::Proven);
    }

    #[test]
    fn option_var_query_is_read_only() {
        let source = "optionVar -q;";
        let command = MelSurfaceNormalizedCommand {
            schema_name: "optionVar".into(),
            mode: MelSurfaceCommandMode::Query,
            items: vec![],
            span_start: 0,
            span_end: 0,
        };

        let rule =
            classify_mel_command_with_semantics(source, &command, "optionVar").expect("rule");
        assert_eq!(rule.effect, ExecutionEffectClass::SceneReadOnly);
        assert_eq!(
            rule.reason("optionVar"),
            ExecutionReason::Static {
                value: StaticExecutionReason::ReadOnlyMelOptionVarQueryDetected,
            }
        );
    }

    #[test]
    fn model_editor_edit_without_script_flag_is_ui_impact() {
        let source = "modelEditor -e;";
        let command = MelSurfaceNormalizedCommand {
            schema_name: "modelEditor".into(),
            mode: MelSurfaceCommandMode::Edit,
            items: vec![],
            span_start: 0,
            span_end: 0,
        };

        let rule =
            classify_mel_command_with_semantics(source, &command, "modelEditor").expect("rule");
        assert_eq!(rule.effect, ExecutionEffectClass::UIImpact);
    }

    #[test]
    fn python_registry_classifies_known_calls() {
        let print = classify_python_call_target("print").expect("print rule");
        assert_rule(
            print,
            ExecutionEffectClass::DiagnosticOutput,
            ExecutionSemanticClass::General,
            EffectCertainty::Proven,
            ExecutionReason::Static {
                value: StaticExecutionReason::PythonPrintDetected,
            },
        );

        let exec = classify_python_call_target("exec").expect("exec rule");
        assert_eq!(exec.effect, ExecutionEffectClass::DynamicEvaluation);

        let subprocess = classify_python_call_target("subprocess.run").expect("subprocess rule");
        assert_eq!(subprocess.effect, ExecutionEffectClass::ExternalDependency);
    }

    #[test]
    fn registry_returns_none_for_unclassified_names() {
        assert!(classify_mel_command("totallyUnknownMel").is_none());
        assert!(classify_python_call_target("totally_unknown_py_call").is_none());
    }

    #[test]
    fn effect_rank_matches_expected_order() {
        assert!(
            effect_rank(ExecutionEffectClass::DiagnosticOutput)
                > effect_rank(ExecutionEffectClass::PureComputation)
        );
        assert!(
            effect_rank(ExecutionEffectClass::Unknown)
                > effect_rank(ExecutionEffectClass::SceneMutation)
        );
    }
}
