use rustpython_parser::ast;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MayaKind {
    File,
    SysFile,
    ScriptJob,
    CommandPort,
    ScriptNode,
    LoadPlugin,
    EvalDeferred,
    Callback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MayaCall {
    pub target: String,
    pub kind: MayaKind,
    pub operations: Vec<String>,
    pub flags: Vec<String>,
    pub critical: bool,
    pub uncertainty: Vec<String>,
}

impl MayaCall {
    fn action(&mut self, operation: &str) {
        if !self.operations.iter().any(|value| value == operation) {
            self.operations.push(operation.to_string());
        }
    }

    fn uncertain(&mut self, reason: &str) {
        if !self.uncertainty.iter().any(|value| value == reason) {
            self.uncertainty.push(reason.to_string());
        }
    }
}

pub(super) fn classify(target: &str, call: &ast::ExprCall) -> Option<MayaCall> {
    let (module, member) = target.rsplit_once('.')?;
    let pymel = matches!(
        module,
        "pymel.core" | "pymel.core.system" | "pymel.core.general"
    );
    let (kind, implicit) = if module == "maya.cmds" || pymel {
        match member {
            "file" => (MayaKind::File, None),
            "sysFile" => (MayaKind::SysFile, None),
            "scriptJob" => (MayaKind::ScriptJob, None),
            "commandPort" => (MayaKind::CommandPort, None),
            "scriptNode" => (MayaKind::ScriptNode, None),
            "loadPlugin" => (MayaKind::LoadPlugin, None),
            "evalDeferred" => (MayaKind::EvalDeferred, None),
            "saveFile" | "saveAs" if pymel => (MayaKind::File, Some("save")),
            "openFile" if pymel => (MayaKind::File, Some("open")),
            "newFile" if pymel => (MayaKind::File, Some("newFile")),
            "importFile" if pymel => (MayaKind::File, Some("import")),
            "createReference" if pymel => (MayaKind::File, Some("reference")),
            "exportAll"
            | "exportSelected"
            | "exportAnim"
            | "exportSelectedAnim"
            | "exportAnimFromReference"
            | "exportSelectedAnimFromReference"
            | "exportAsReference"
            | "exportAsSegment"
            | "exportSelectedNoReference"
            | "exportUnloadedReferences"
            | "exportEdits"
                if pymel =>
            {
                (MayaKind::File, Some(member))
            }
            _ => return None,
        }
    } else {
        let (api, class) = module.rsplit_once('.')?;
        if !matches!(api, "maya.OpenMaya" | "maya.api.OpenMaya" | "pymel.api")
            || !matches!(
                class,
                "MMessage"
                    | "MSceneMessage"
                    | "MDGMessage"
                    | "MEventMessage"
                    | "MNodeMessage"
                    | "MDagMessage"
                    | "MConditionMessage"
                    | "MTimerMessage"
                    | "MCommandMessage"
                    | "MLockMessage"
                    | "MObjectSetMessage"
                    | "MPolyMessage"
                    | "MUiMessage"
                    | "MUserEventMessage"
                    | "MModelMessage"
                    | "MContainerMessage"
                    | "MAnimMessage"
                    | "MCameraSetMessage"
            )
        {
            return None;
        }
        (MayaKind::Callback, None)
    };
    let mut result = MayaCall {
        target: target.to_string(),
        kind,
        operations: Vec::new(),
        flags: Vec::new(),
        critical: kind == MayaKind::SysFile,
        uncertainty: Vec::new(),
    };
    let mut flags = Vec::new();
    for keyword in &call.keywords {
        let Some(name) = keyword.arg.as_ref() else {
            result.uncertain("keyword map prevents complete operation resolution");
            continue;
        };
        let name = normalize_flag(kind, name.as_str());
        if !literal(&keyword.value) {
            result.uncertain("dynamic Maya flag value");
        }
        if flags.iter().any(|(existing, _)| *existing == name) {
            result.uncertain("duplicate flag aliases prevent complete operation resolution");
        }
        result
            .flags
            .push(format!("{name}={}", value_label(&keyword.value)));
        flags.push((name, &keyword.value));
    }
    let unpacking = call
        .args
        .iter()
        .any(|arg| matches!(arg, ast::Expr::Starred(_)));
    if unpacking {
        result.uncertain("positional unpacking prevents complete operation resolution");
    }
    let args: Vec<_> = call
        .args
        .iter()
        .filter(|arg| !matches!(arg, ast::Expr::Starred(_)))
        .collect();
    let supports_query = matches!(
        kind,
        MayaKind::File | MayaKind::CommandPort | MayaKind::ScriptNode
    );
    let query = supports_query
        && flags
            .iter()
            .any(|(name, value)| *name == "query" && boolean(value) == Some(true));
    let unresolved_mode = unpacking
        || call.keywords.iter().any(|keyword| keyword.arg.is_none())
        || flags.iter().any(|(name, value)| {
            let mode_flag = match kind {
                MayaKind::CommandPort => matches!(*name, "query" | "listPorts" | "close"),
                MayaKind::LoadPlugin => *name == "pluginPath",
                MayaKind::ScriptNode => *name == "query",
                _ => false,
            };
            mode_flag && boolean(value).is_none()
        });
    let mut inspection = false;
    let mut inactive_action = false;
    let mut removal = false;
    let mut port_name = !args.is_empty();
    let mut port_name_known = args.first().is_some_and(|value| literal(value));
    let mut plugin_path = false;
    let mut callback = false;
    for (name, value) in &flags {
        let name = *name;
        let active = boolean(value);
        if name == "query" && supports_query {
            if active.is_none() {
                result.uncertain("dynamic query flag");
            }
            continue;
        }
        match kind {
            MayaKind::File => {
                if matches!(
                    name,
                    "save"
                        | "open"
                        | "newFile"
                        | "import"
                        | "reference"
                        | "exportAll"
                        | "exportSelected"
                        | "exportAnim"
                        | "exportSelectedAnim"
                        | "exportAnimFromReference"
                        | "exportSelectedAnimFromReference"
                        | "exportAsReference"
                        | "exportAsSegment"
                        | "exportSelectedNoReference"
                        | "exportUnloadedReferences"
                        | "exportEdits"
                        | "force"
                ) {
                    match active {
                        Some(true) => {
                            result.action(name);
                            result.critical |= name == "save" || name.starts_with("export");
                        }
                        Some(false) => {
                            inactive_action = true;
                        }
                        None => result.uncertain("dynamic file action flag"),
                    }
                } else if !matches!(
                    name,
                    "sceneName"
                        | "type"
                        | "options"
                        | "namespace"
                        | "returnNewNodes"
                        | "ignoreVersion"
                        | "preserveReferences"
                        | "prompt"
                        | "defaultNamespace"
                        | "mergeNamespacesOnClash"
                        | "referenceNode"
                        | "withoutCopyNumber"
                        | "shortName"
                        | "expandName"
                        | "unresolvedName"
                ) {
                    result.uncertain("unknown file flag");
                } else if !literal(value) {
                    result.uncertain("dynamic file modifier");
                }
            }
            MayaKind::SysFile => {
                if matches!(name, "delete" | "makeDir" | "removeEmptyDir") {
                    match active {
                        Some(true) => result.action(name),
                        Some(false) => inactive_action = true,
                        None => result.uncertain("dynamic filesystem action flag"),
                    }
                } else if matches!(name, "rename" | "move" | "copy") {
                    match active {
                        Some(false) => inactive_action = true,
                        Some(true) => result.uncertain("filesystem destination is not a path"),
                        None => result.action(name),
                    }
                } else {
                    result.uncertain("unknown filesystem operation flag");
                }
            }
            MayaKind::ScriptJob => {
                if matches!(
                    name,
                    "event"
                        | "conditionTrue"
                        | "conditionFalse"
                        | "conditionChange"
                        | "attributeChange"
                        | "attributeAdded"
                        | "attributeDeleted"
                        | "connectionChange"
                        | "timeChange"
                        | "idleEvent"
                        | "nodeDeleted"
                        | "uiDeleted"
                ) {
                    result.action(name);
                    callback = true;
                } else if matches!(name, "listJobs" | "listEvents" | "listConditions") {
                    if active == Some(true) {
                        inspection = true;
                    } else if active.is_none() {
                        result.uncertain("dynamic hook inspection flag");
                    }
                } else if name == "exists" {
                    inspection = true;
                } else if matches!(name, "kill" | "killAll") {
                    removal |= name == "kill" || active != Some(false);
                } else if !matches!(
                    name,
                    "parent"
                        | "protected"
                        | "permanent"
                        | "runOnce"
                        | "killWithScene"
                        | "replacePrevious"
                        | "compressUndo"
                        | "disregardIndex"
                        | "allChildren"
                        | "force"
                ) || !literal(value)
                {
                    result.uncertain("unknown or dynamic hook modifier");
                }
            }
            MayaKind::CommandPort => match name {
                "name" => {
                    port_name = true;
                    port_name_known = literal(value);
                }
                "listPorts" => {
                    inspection |= active == Some(true);
                    if active.is_none() {
                        result.uncertain("dynamic port inspection flag");
                    }
                }
                "close" => {
                    removal |= active != Some(false);
                    if active.is_none() {
                        result.uncertain("dynamic port close flag");
                    }
                }
                "sourceType" | "securityWarning" | "prefix" | "echoOutput" | "noreturn"
                | "returnNumCommands" | "pickleOutput" | "bufferSize" => {
                    if !literal(value) {
                        result.uncertain("dynamic port modifier");
                    }
                }
                _ => result.uncertain("unknown port flag"),
            },
            MayaKind::ScriptNode => {
                match name {
                    "beforeScript" | "afterScript" => {
                        if !query && !unresolved_mode {
                            result.action(name);
                            callback = true;
                        }
                        if !literal(value) {
                            result.uncertain("unresolved script body");
                        }
                    }
                    "scriptType" => {
                        if !query && !unresolved_mode {
                            result.action(name);
                        }
                        if !literal(value) {
                            result.uncertain("dynamic script type");
                        }
                    }
                    "executeBefore" | "executeAfter" => {
                        if active == Some(true) {
                            result.action(name);
                        } else if active.is_none() {
                            result.uncertain("dynamic script execution flag");
                        }
                    }
                    "sourceType" => {
                        if !literal(value) {
                            result.uncertain("dynamic source type");
                        }
                    }
                    "name" | "edit" | "ignoreReferenceEdits" => {
                        if !literal(value) {
                            result.uncertain("dynamic script modifier");
                        }
                    }
                    _ => result.uncertain("unknown script node flag"),
                }
                if query
                    && matches!(name, "beforeScript" | "afterScript" | "scriptType")
                    && boolean(value).is_none()
                    && literal(value)
                {
                    result.uncertain("query conflicts with script node action value");
                    result.action(name);
                }
            }
            MayaKind::LoadPlugin => match name {
                "allPlugins" => {
                    if active == Some(true) {
                        result.action("loadAllPlugins");
                    } else if active.is_none() {
                        result.uncertain("dynamic plugin selection");
                    }
                }
                "pluginPath" => {
                    plugin_path = active == Some(true);
                    if active.is_none() {
                        result.uncertain("dynamic plugin path lookup");
                    }
                }
                "addCallback" => {
                    result.action("addCallback");
                    callback = true;
                }
                "removeCallback" => removal = true,
                "quiet" | "name" => {
                    if !literal(value) {
                        result.uncertain("dynamic plugin modifier");
                    }
                }
                _ => result.uncertain("unknown plugin flag"),
            },
            MayaKind::EvalDeferred => match name {
                "list" => {
                    inspection = active == Some(true);
                    if active.is_none() {
                        result.uncertain("dynamic deferred inspection flag");
                    }
                }
                "evaluateNext" | "lowPriority" | "lowestPriority" => {
                    if active.is_none() {
                        result.uncertain("dynamic scheduling flag");
                    }
                }
                _ => result.uncertain("unknown deferred execution flag"),
            },
            MayaKind::Callback => {
                result.uncertain("callback registration keyword arguments are unresolved")
            }
        }
    }
    if let Some(operation) = implicit {
        result.action(operation);
        result.critical |= operation == "save" || operation.starts_with("export");
    }
    match kind {
        MayaKind::CommandPort => {
            if port_name && !port_name_known {
                result.uncertain("dynamic port name");
            }
            if port_name && !query && !inspection && !removal && !unresolved_mode {
                if port_name_known {
                    result.action("open");
                } else {
                    result.uncertain("dynamic port name");
                }
            }
        }
        MayaKind::LoadPlugin => {
            if !args.is_empty() && !plugin_path && !unresolved_mode {
                result.action("load");
            }
            inspection |= plugin_path;
            if plugin_path && !result.operations.is_empty() {
                result.uncertain("plugin path lookup conflicts with loading");
            }
        }
        MayaKind::EvalDeferred if !args.is_empty() => {
            result.action("schedule");
            result.flags.push(format!(
                "body={}",
                if literal(args[0]) {
                    "literal"
                } else {
                    "unresolved"
                }
            ));
            callback = true;
        }
        MayaKind::Callback => {
            if member.starts_with("add") && member.ends_with("Callback") {
                result.action(member);
                callback = true;
            } else if matches!(member, "removeCallback" | "removeCallbacks") {
                removal = true;
            } else if member.starts_with("get")
                || matches!(
                    member,
                    "currentCallbackId" | "nodeCallbacks" | "isListening" | "conditionNames"
                )
            {
                inspection = true;
            } else {
                result.uncertain("unrecognized message operation");
            }
        }
        _ => {}
    }
    if removal {
        result.uncertain("hook or port removal requires review");
    }
    if callback {
        result.uncertain("registered script or callback body has not been fully analyzed");
    }
    if (query || inspection) && !result.operations.is_empty() {
        result.uncertain("inspection and action flags conflict");
    }
    if result.operations.is_empty() && !inspection && !inactive_action && !query && !removal {
        result.uncertain("Maya operation could not be determined");
    }
    Some(result)
}

fn boolean(value: &ast::Expr) -> Option<bool> {
    match value {
        ast::Expr::Constant(value) => match &value.value {
            ast::Constant::Bool(value) => Some(*value),
            ast::Constant::Int(value) if value.to_string() == "0" => Some(false),
            ast::Constant::Int(value) if value.to_string() == "1" => Some(true),
            _ => None,
        },
        _ => None,
    }
}

fn literal(value: &ast::Expr) -> bool {
    match value {
        ast::Expr::Constant(_) => true,
        ast::Expr::List(value) => value.elts.iter().all(literal),
        ast::Expr::Tuple(value) => value.elts.iter().all(literal),
        _ => false,
    }
}

fn value_label(value: &ast::Expr) -> String {
    match value {
        ast::Expr::Constant(value) => match &value.value {
            ast::Constant::Bool(value) => value.to_string(),
            ast::Constant::Str(value) => value.clone(),
            ast::Constant::Int(value) => value.to_string(),
            _ => "literal".to_string(),
        },
        _ if literal(value) => "literal".to_string(),
        _ => "unresolved".to_string(),
    }
}

fn normalize_flag(kind: MayaKind, name: &str) -> &str {
    if name == "q" {
        return "query";
    }
    match (kind, name) {
        (MayaKind::File, "s") => "save",
        (MayaKind::File, "o") => "open",
        (MayaKind::File, "new") => "newFile",
        (MayaKind::File, "i") => "import",
        (MayaKind::File, "r") => "reference",
        (MayaKind::File, "f") | (MayaKind::ScriptJob, "f") => "force",
        (MayaKind::File, "ea") => "exportAll",
        (MayaKind::File, "es") => "exportSelected",
        (MayaKind::File, "ean") => "exportAnim",
        (MayaKind::File, "esa") => "exportSelectedAnim",
        (MayaKind::File, "ear") => "exportAnimFromReference",
        (MayaKind::File, "esar") => "exportSelectedAnimFromReference",
        (MayaKind::File, "er") => "exportAsReference",
        (MayaKind::File, "eas") => "exportAsSegment",
        (MayaKind::File, "esn") => "exportSelectedNoReference",
        (MayaKind::File, "eur") => "exportUnloadedReferences",
        (MayaKind::File, "ee") => "exportEdits",
        (MayaKind::File, "sn") => "sceneName",
        (MayaKind::File, "typ") => "type",
        (MayaKind::File, "op") => "options",
        (MayaKind::File, "ns") => "namespace",
        (MayaKind::File, "rnn") => "returnNewNodes",
        (MayaKind::File, "iv") => "ignoreVersion",
        (MayaKind::File, "pr") => "preserveReferences",
        (MayaKind::File, "pmt") => "prompt",
        (MayaKind::File, "dns") => "defaultNamespace",
        (MayaKind::File, "mnc") => "mergeNamespacesOnClash",
        (MayaKind::File, "rfn") => "referenceNode",
        (MayaKind::File, "wcn") => "withoutCopyNumber",
        (MayaKind::File, "shn") => "shortName",
        (MayaKind::File, "exn") => "expandName",
        (MayaKind::File, "un") => "unresolvedName",
        (MayaKind::SysFile, "del") => "delete",
        (MayaKind::SysFile, "ren") => "rename",
        (MayaKind::SysFile, "mov") => "move",
        (MayaKind::SysFile, "cp") => "copy",
        (MayaKind::SysFile, "md") => "makeDir",
        (MayaKind::SysFile, "red") => "removeEmptyDir",
        (MayaKind::ScriptJob, "e") => "event",
        (MayaKind::ScriptJob, "ct") => "conditionTrue",
        (MayaKind::ScriptJob, "cf") => "conditionFalse",
        (MayaKind::ScriptJob, "cc") => "conditionChange",
        (MayaKind::ScriptJob, "ac") => "attributeChange",
        (MayaKind::ScriptJob, "aa") => "attributeAdded",
        (MayaKind::ScriptJob, "ad") => "attributeDeleted",
        (MayaKind::ScriptJob, "con") => "connectionChange",
        (MayaKind::ScriptJob, "tc") => "timeChange",
        (MayaKind::ScriptJob, "ie") => "idleEvent",
        (MayaKind::ScriptJob, "nd") => "nodeDeleted",
        (MayaKind::ScriptJob, "uid") => "uiDeleted",
        (MayaKind::ScriptJob, "lj") => "listJobs",
        (MayaKind::ScriptJob, "le") => "listEvents",
        (MayaKind::ScriptJob, "lc") => "listConditions",
        (MayaKind::ScriptJob, "ex") => "exists",
        (MayaKind::ScriptJob, "k") => "kill",
        (MayaKind::ScriptJob, "ka") => "killAll",
        (MayaKind::ScriptJob, "p") => "parent",
        (MayaKind::ScriptJob, "pro") => "protected",
        (MayaKind::ScriptJob, "per") => "permanent",
        (MayaKind::ScriptJob, "ro") => "runOnce",
        (MayaKind::ScriptJob, "kws") => "killWithScene",
        (MayaKind::ScriptJob, "rp") => "replacePrevious",
        (MayaKind::ScriptJob, "cu") => "compressUndo",
        (MayaKind::ScriptJob, "dri") => "disregardIndex",
        (MayaKind::ScriptJob, "alc") => "allChildren",
        (MayaKind::CommandPort, "n")
        | (MayaKind::ScriptNode, "n")
        | (MayaKind::LoadPlugin, "n") => "name",
        (MayaKind::CommandPort, "lp") => "listPorts",
        (MayaKind::CommandPort, "cl") => "close",
        (MayaKind::CommandPort, "stp") | (MayaKind::ScriptNode, "stp") => "sourceType",
        (MayaKind::CommandPort, "sw") => "securityWarning",
        (MayaKind::CommandPort, "pre") => "prefix",
        (MayaKind::CommandPort, "eo") => "echoOutput",
        (MayaKind::CommandPort, "nr") => "noreturn",
        (MayaKind::CommandPort, "rnc") => "returnNumCommands",
        (MayaKind::CommandPort, "po") => "pickleOutput",
        (MayaKind::CommandPort, "bs") => "bufferSize",
        (MayaKind::ScriptNode, "bs") => "beforeScript",
        (MayaKind::ScriptNode, "as") => "afterScript",
        (MayaKind::ScriptNode, "st") => "scriptType",
        (MayaKind::ScriptNode, "eb") => "executeBefore",
        (MayaKind::ScriptNode, "ea") => "executeAfter",
        (MayaKind::ScriptNode, "e") => "edit",
        (MayaKind::ScriptNode, "ire") => "ignoreReferenceEdits",
        (MayaKind::LoadPlugin, "a") => "allPlugins",
        (MayaKind::LoadPlugin, "qt") => "quiet",
        (MayaKind::LoadPlugin, "ac") => "addCallback",
        (MayaKind::LoadPlugin, "rc") => "removeCallback",
        (MayaKind::LoadPlugin, "pp") => "pluginPath",
        (MayaKind::EvalDeferred, "ls") => "list",
        (MayaKind::EvalDeferred, "en") => "evaluateNext",
        (MayaKind::EvalDeferred, "lp") => "lowPriority",
        (MayaKind::EvalDeferred, "lpst") => "lowestPriority",
        _ => name,
    }
}
