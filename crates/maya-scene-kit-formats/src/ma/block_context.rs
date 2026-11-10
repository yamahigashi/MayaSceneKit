use std::{borrow::Cow, collections::HashMap};

use maya_mel::{parser::LightSourceView, syntax::TextRange};

use super::commands::unquoted_range_value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContextWord {
    Source(TextRange),
    Owned(String),
}

impl ContextWord {
    pub(crate) fn value<'a>(&'a self, source: LightSourceView<'a>) -> Cow<'a, str> {
        match self {
            Self::Source(range) => unquoted_range_value(source.decode_slice(*range).text),
            Self::Owned(value) => Cow::Borrowed(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectedTarget {
    pub(crate) name: String,
    pub(crate) node_type: Option<String>,
    pub(crate) is_default: bool,
}

impl SelectedTarget {
    pub(crate) fn new(name: &str) -> Self {
        Self {
            is_default: name.trim_start_matches(':') != "defaultRenderGlobals"
                && is_default_node(name.trim_start_matches(':')),
            name: name.trim_start_matches(':').to_string(),
            node_type: None,
        }
    }
}

fn is_default_node(name: &str) -> bool {
    matches!(
        name,
        "time1"
            | "renderPartition"
            | "defaultRenderGlobals"
            | "defaultRenderingList1"
            | "defaultShaderList1"
            | "postProcessList1"
            | "defaultRenderUtilityList1"
            | "lightList1"
            | "defaultTextureList1"
            | "initialShadingGroup"
            | "initialParticleSE"
            | "defaultLightSet"
            | "defaultObjectSet"
            | "hardwareRenderGlobals"
            | "defaultColorMgtGlobals"
            | "defaultResolution"
            | "hardwareRenderingGlobals"
            | "ikSystem"
            | "openPBR"
            | "renderGlobalsList1"
            | "standardSurface1"
    )
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum BlockContext {
    #[default]
    None,
    Node {
        node_type: ContextWord,
        name: ContextWord,
    },
    Selected {
        targets: Vec<SelectedTarget>,
    },
}

impl BlockContext {
    pub(crate) fn binding<'a>(
        &'a self,
        source: LightSourceView<'a>,
        execution_type: impl Fn(&str) -> bool,
    ) -> Option<(Cow<'a, str>, Cow<'a, str>)> {
        match self {
            Self::None => None,
            Self::Node { node_type, name } => Some((node_type.value(source), name.value(source))),
            Self::Selected { targets } => {
                if let [target] = targets.as_slice() {
                    return Some((
                        Cow::Borrowed(target.node_type.as_deref().unwrap_or("")),
                        Cow::Borrowed(&target.name),
                    ));
                }
                let mut execution = None;
                for target in targets {
                    match target.node_type.as_deref() {
                        Some(node_type) if execution_type(node_type) => {
                            if execution.is_some() {
                                return None;
                            }
                            execution = Some((
                                Cow::Borrowed(node_type),
                                Cow::Borrowed(target.name.as_str()),
                            ));
                        }
                        None if !target.is_default => return None,
                        _ => {}
                    }
                }
                execution
            }
        }
    }
}

pub(crate) enum BlockCommand {
    Preserve,
    Create {
        context: BlockContext,
        skip_select: bool,
    },
    Select {
        targets: Vec<SelectedTarget>,
        accumulate: bool,
    },
    Rename {
        old: String,
        new: String,
    },
}

pub(crate) struct BlockTracker {
    pub(crate) context: BlockContext,
    context_is_named_owner: bool,
    pub(crate) reported_unbound: bool,
    pub(crate) reported_selected: bool,
    node_types: HashMap<String, Option<ContextWord>>,
}

impl Default for BlockTracker {
    fn default() -> Self {
        Self {
            context: BlockContext::None,
            context_is_named_owner: false,
            reported_unbound: false,
            reported_selected: false,
            node_types: HashMap::from([(
                "defaultRenderGlobals".to_string(),
                Some(ContextWord::Owned("renderGlobals".to_string())),
            )]),
        }
    }
}

impl BlockTracker {
    pub(crate) fn contains_name(&self, name: &str) -> bool {
        self.node_types.contains_key(name.trim_start_matches(':'))
    }

    pub(crate) fn resolve(&self, name: &str, source: LightSourceView<'_>) -> SelectedTarget {
        let mut target = SelectedTarget::new(name);
        target.node_type = self
            .node_types
            .get(&target.name)
            .and_then(Option::as_ref)
            .map(|word| word.value(source).into_owned());
        target
    }

    pub(crate) fn invalidate_all_names(&mut self) {
        for node_type in self.node_types.values_mut() {
            *node_type = None;
        }
    }

    pub(crate) fn invalidate_name(&mut self, name: &str) {
        self.node_types
            .insert(name.trim_start_matches(':').to_string(), None);
    }

    pub(crate) fn on_command(
        &mut self,
        command: BlockCommand,
        source: LightSourceView<'_>,
    ) -> bool {
        let context = match command {
            BlockCommand::Preserve => return false,
            BlockCommand::Rename { old, new } => {
                let old = old.trim_start_matches(':');
                let new = new.trim_start_matches(':');
                if old == new {
                    return false;
                }
                let collision = self.node_types.contains_key(new);
                if let Some(node_type) = self.node_types.remove(old)
                    && !collision
                {
                    self.node_types.insert(new.to_string(), node_type);
                }
                if collision {
                    if let BlockContext::Node { name, .. } = &self.context
                        && name.value(source).trim_start_matches(':') == old
                    {
                        self.context_is_named_owner = false;
                    }
                    return false;
                }
                match &mut self.context {
                    BlockContext::Node { name, .. }
                        if self.context_is_named_owner
                            && name.value(source).trim_start_matches(':') == old =>
                    {
                        *name = ContextWord::Owned(new.to_string());
                        return true;
                    }
                    BlockContext::Selected { targets } => {
                        let mut changed = false;
                        for target in targets {
                            if target.name == old {
                                target.name = new.to_string();
                                changed = true;
                            }
                        }
                        return changed;
                    }
                    _ => return false,
                }
            }
            BlockCommand::Create {
                context,
                skip_select,
            } => {
                if let BlockContext::Node { node_type, name } = &context {
                    let decoded_name = name.value(source);
                    let name = decoded_name.trim_start_matches(':');
                    let value = Some(node_type.clone());
                    if !skip_select {
                        self.context_is_named_owner = !self.node_types.contains_key(name);
                    }
                    self.node_types.entry(name.to_string()).or_insert(value);
                }
                if skip_select {
                    return false;
                } else {
                    context
                }
            }
            BlockCommand::Select {
                mut targets,
                accumulate,
            } => {
                self.context_is_named_owner = true;
                if !targets.is_empty() && accumulate {
                    match &self.context {
                        BlockContext::Node { node_type, name } => {
                            let decoded_name = name.value(source);
                            let name = decoded_name.trim_start_matches(':');
                            if !targets.iter().any(|target| target.name == name) {
                                targets.push(SelectedTarget {
                                    name: name.to_string(),
                                    node_type: Some(node_type.value(source).into_owned()),
                                    is_default: false,
                                });
                            }
                        }
                        BlockContext::Selected { targets: previous } => {
                            for target in previous {
                                if !targets.iter().any(|next| next.name == target.name) {
                                    targets.push(target.clone());
                                }
                            }
                        }
                        BlockContext::None => {}
                    }
                }
                for target in &mut targets {
                    if let Some(node_type) = self.node_types.get(&target.name) {
                        target.node_type = node_type
                            .as_ref()
                            .map(|word| word.value(source).into_owned());
                        target.is_default = false;
                    }
                }
                if targets.is_empty() {
                    BlockContext::None
                } else {
                    BlockContext::Selected { targets }
                }
            }
        };
        if !matches!(context, BlockContext::None) {
            self.reported_unbound = false;
        }
        self.reported_selected = false;
        self.context = context;
        true
    }
}
