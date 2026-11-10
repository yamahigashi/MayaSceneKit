use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectedTarget {
    pub(crate) name: String,
    pub(crate) node_type: Option<String>,
    pub(crate) is_default: bool,
}

impl SelectedTarget {
    pub(crate) fn new(name: &str) -> Self {
        Self {
            is_default: name.starts_with(':') && is_default_node(name.trim_start_matches(':')),
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
        node_type: String,
        name: String,
    },
    Selected {
        targets: Vec<SelectedTarget>,
    },
}

impl BlockContext {
    pub(crate) fn binding(&self, execution_type: impl Fn(&str) -> bool) -> Option<(&str, &str)> {
        match self {
            Self::None => None,
            Self::Node { node_type, name } => Some((node_type, name)),
            Self::Selected { targets } => {
                if let [target] = targets.as_slice() {
                    return Some((target.node_type.as_deref().unwrap_or(""), &target.name));
                }
                let mut execution = None;
                for target in targets {
                    match target.node_type.as_deref() {
                        Some(node_type) if execution_type(node_type) => {
                            if execution.is_some() {
                                return None;
                            }
                            execution = Some((node_type, target.name.as_str()));
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
        named: bool,
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
    pub(crate) reported_unbound: bool,
    pub(crate) reported_selected: bool,
    node_types: Option<HashMap<String, String>>,
}

impl Default for BlockTracker {
    fn default() -> Self {
        Self {
            context: BlockContext::None,
            reported_unbound: false,
            reported_selected: false,
            node_types: Some(HashMap::new()),
        }
    }
}

impl BlockTracker {
    pub(crate) fn for_source(data: &[u8]) -> Self {
        // A select head must contain these literal bytes in every supported encoding.
        let may_select = match std::str::from_utf8(data) {
            Ok(text) => text.contains("select"),
            Err(_) => data.windows(6).any(|word| word == b"select"),
        };
        Self {
            node_types: may_select.then(HashMap::new),
            ..Self::default()
        }
    }

    pub(crate) fn on_command(&mut self, command: BlockCommand) -> bool {
        let context = match command {
            BlockCommand::Preserve => return false,
            BlockCommand::Rename { old, new } => {
                let old = old.trim_start_matches(':');
                let new = new.trim_start_matches(':');
                if let Some(types) = &mut self.node_types {
                    if let Some(node_type) = types.remove(old) {
                        types.insert(new.to_string(), node_type);
                    }
                }
                match &mut self.context {
                    BlockContext::Node { name, .. } if name.trim_start_matches(':') == old => {
                        *name = new.to_string();
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
                named,
                skip_select,
            } => {
                if named {
                    if let (Some(types), BlockContext::Node { node_type, name }) =
                        (&mut self.node_types, &context)
                    {
                        types.insert(name.trim_start_matches(':').to_string(), node_type.clone());
                    }
                }
                if skip_select {
                    BlockContext::None
                } else {
                    context
                }
            }
            BlockCommand::Select {
                mut targets,
                accumulate,
            } => {
                if !targets.is_empty() && accumulate {
                    match &self.context {
                        BlockContext::Node { node_type, name } => {
                            let name = name.trim_start_matches(':');
                            if !targets.iter().any(|target| target.name == name) {
                                targets.push(SelectedTarget {
                                    name: name.to_string(),
                                    node_type: Some(node_type.clone()),
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
                    if let Some(node_type) = self
                        .node_types
                        .as_ref()
                        .and_then(|types| types.get(&target.name))
                    {
                        target.node_type = Some(node_type.clone());
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
