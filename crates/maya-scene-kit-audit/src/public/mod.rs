pub mod audit;

pub mod allowlist {
    use std::{collections::BTreeMap, fmt, str::FromStr};

    use maya_scene_kit_observe::scene::evidence::ExecutionOrigin;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use sha2::{Digest, Sha256};

    /// Digest of the observed body and its execution context.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct AllowlistHash([u8; 32]);

    impl fmt::Display for AllowlistHash {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("sha256:")?;
            for byte in self.0 {
                write!(f, "{byte:02x}")?;
            }
            Ok(())
        }
    }

    impl FromStr for AllowlistHash {
        type Err = AuditAllowlistError;

        fn from_str(value: &str) -> Result<Self, Self::Err> {
            let hex = value
                .strip_prefix("sha256:")
                .filter(|hex| {
                    hex.len() == 64
                        && hex
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .ok_or_else(|| AuditAllowlistError::InvalidHash {
                    value: value.into(),
                })?;
            let mut bytes = [0; 32];
            for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
                let nibble = |b: u8| {
                    if b.is_ascii_digit() {
                        b - b'0'
                    } else {
                        b - b'a' + 10
                    }
                };
                *byte = nibble(pair[0]) * 16 + nibble(pair[1]);
            }
            Ok(Self(bytes))
        }
    }

    impl Serialize for AllowlistHash {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(self)
        }
    }

    impl<'de> Deserialize<'de> for AllowlistHash {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            String::deserialize(deserializer)?
                .parse()
                .map_err(serde::de::Error::custom)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AllowlistSource {
        App,
        User,
    }

    impl AllowlistSource {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::App => "app",
                Self::User => "user",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AuditAllowRef {
        pub hash: AllowlistHash,
        pub source: AllowlistSource,
    }

    #[derive(Debug)]
    pub enum AuditAllowlistError {
        InvalidJson { message: String },
        UnsupportedVersion { version: u64 },
        InvalidHash { value: String },
        EmptyCodes { entry_index: usize },
    }

    impl fmt::Display for AuditAllowlistError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidJson { message } => write!(f, "invalid allowlist JSON: {message}"),
                Self::UnsupportedVersion { version } => {
                    write!(f, "unsupported allowlist version: {version}")
                }
                Self::InvalidHash { value } => write!(f, "invalid allowlist hash: {value}"),
                Self::EmptyCodes { entry_index } => {
                    write!(f, "allowlist entry {entry_index} has no codes")
                }
            }
        }
    }

    impl std::error::Error for AuditAllowlistError {}

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Document {
        version: u64,
        entries: Vec<Entry>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        hash: String,
        codes: Vec<String>,
        #[serde(default, rename = "label")]
        _label: Option<String>,
        #[serde(default, rename = "preview")]
        _preview: Option<String>,
        #[serde(default, rename = "reason")]
        _reason: Option<String>,
        #[serde(default, rename = "added_at")]
        _added_at: Option<String>,
        #[serde(default, rename = "added_by")]
        _added_by: Option<String>,
    }

    /// Validated, merged exact body/code permissions. Earlier layers retain provenance.
    #[derive(Debug, Clone, Default)]
    pub struct AuditAllowlist {
        entries: BTreeMap<(AllowlistHash, String), AllowlistSource>,
    }

    impl AuditAllowlist {
        pub fn from_json(text: &str, source: AllowlistSource) -> Result<Self, AuditAllowlistError> {
            let document: Document =
                serde_json::from_str(text).map_err(|error| AuditAllowlistError::InvalidJson {
                    message: error.to_string(),
                })?;
            if document.version != 1 {
                return Err(AuditAllowlistError::UnsupportedVersion {
                    version: document.version,
                });
            }
            let mut result = Self::default();
            for (entry_index, entry) in document.entries.into_iter().enumerate() {
                let hash = entry.hash.parse()?;
                if entry.codes.is_empty() {
                    return Err(AuditAllowlistError::EmptyCodes { entry_index });
                }
                for code in entry.codes {
                    if code.is_empty() {
                        return Err(AuditAllowlistError::InvalidJson {
                            message: format!(
                                "allowlist entry {entry_index} contains an empty code"
                            ),
                        });
                    }
                    result.entries.insert((hash, code), source);
                }
            }
            Ok(result)
        }

        pub fn merge(layers: impl IntoIterator<Item = Self>) -> Self {
            let mut result = Self::default();
            for layer in layers {
                for (key, source) in layer.entries {
                    result.entries.entry(key).or_insert(source);
                }
            }
            result
        }

        pub fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        pub(crate) fn lookup(&self, hash: &AllowlistHash, code: &str) -> Option<AuditAllowRef> {
            self.entries
                .get(&(*hash, code.to_owned()))
                .map(|source| AuditAllowRef {
                    hash: *hash,
                    source: *source,
                })
        }

        pub(crate) fn canonical_digest(&self) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(b"msk-allow-entries-v1\0");
            hasher.update((self.entries.len() as u64).to_le_bytes());
            for ((hash, code), source) in &self.entries {
                hasher.update(hash.0);
                hash_string(&mut hasher, code);
                hasher.update([match source {
                    AllowlistSource::App => 0,
                    AllowlistSource::User => 1,
                }]);
            }
            hasher.finalize().into()
        }
    }

    fn hash_string(hasher: &mut Sha256, value: &str) {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }

    /// Hashes the text exactly as observe produced it, without further normalization.
    pub fn allowlist_surface_hash(origin: &ExecutionOrigin, text: &str) -> AllowlistHash {
        let mut hasher = Sha256::new();
        hasher.update(b"msk-allow-v1\0");
        for value in [
            origin.lang.as_str(),
            origin.surface_kind.as_str(),
            origin.attr_name.as_deref().unwrap_or_default(),
            origin.trigger.as_str(),
            origin.source_kind.as_deref().unwrap_or_default(),
            text,
        ] {
            hash_string(&mut hasher, value);
        }
        AllowlistHash(hasher.finalize().into())
    }
}

#[cfg(test)]
mod allowlist_tests {
    use super::allowlist::*;
    use crate::{audit::build_script_audit_plan, scene::fingerprint_audit_plan};
    use maya_scene_kit_observe::scene::evidence::{
        ExecutionLanguage, ExecutionOrigin, ExecutionSourceRange, ExecutionSurfaceKind,
        ExecutionTrigger,
    };
    use serde_json::json;

    fn origin() -> ExecutionOrigin {
        ExecutionOrigin {
            lang: ExecutionLanguage::Mel,
            surface_kind: ExecutionSurfaceKind::ScriptNodeBody,
            attr_name: Some(".b".into()),
            trigger: ExecutionTrigger::FileOpen,
            ..ExecutionOrigin::without_chunk_address()
        }
    }

    fn list(entries: serde_json::Value, source: AllowlistSource) -> AuditAllowlist {
        AuditAllowlist::from_json(&json!({"version":1,"entries":entries}).to_string(), source)
            .unwrap()
    }

    #[test]
    fn allowlist_hash_vector_and_context() {
        let origin = origin();
        let body = "exec(\"Example\");";
        let hash = allowlist_surface_hash(&origin, body);
        assert_eq!(
            hash.to_string(),
            "sha256:6e6630043ff4e0231a87e952dfc140faaff4698b475e290f33a242e155abf674"
        );
        assert_eq!(hash.to_string().parse::<AllowlistHash>().unwrap(), hash);
        assert_eq!(
            serde_json::from_str::<AllowlistHash>(&serde_json::to_string(&hash).unwrap()).unwrap(),
            hash
        );
        macro_rules! different {
            ($field:ident, $value:expr) => {{
                let mut changed = origin.clone();
                changed.$field = $value;
                assert_ne!(
                    allowlist_surface_hash(&changed, body),
                    hash,
                    stringify!($field)
                );
            }};
        }
        different!(lang, ExecutionLanguage::Python);
        different!(surface_kind, ExecutionSurfaceKind::NodeAttrCallback);
        different!(attr_name, Some(".a".into()));
        different!(trigger, ExecutionTrigger::Manual);
        different!(source_kind, Some("Example".into()));
        for changed in [
            body.replace("Example", "Sample"),
            body.replace("Example", "Examplf"),
            format!("{body} "),
            format!("{body}\n"),
            format!("{body}\r\n"),
        ] {
            assert_ne!(allowlist_surface_hash(&origin, &changed), hash);
        }
        assert_ne!(
            allowlist_surface_hash(&origin, &format!("{body}\n")),
            allowlist_surface_hash(&origin, &format!("{body}\r\n"))
        );
        macro_rules! same {
            ($field:ident, $value:expr) => {{
                let mut changed = origin.clone();
                changed.$field = Some($value);
                assert_eq!(
                    allowlist_surface_hash(&changed, body),
                    hash,
                    stringify!($field)
                );
            }};
        }
        same!(node_name, "ExampleScriptNode".into());
        same!(source_range, ExecutionSourceRange { start: 0, end: 1 });
        same!(chunk_form, "FOR4".into());
        same!(chunk_tag, "TEST".into());
        same!(chunk_node_offset, 1);
        same!(chunk_aux, 1);
        same!(chunk_payload_offset, 2);
        same!(chunk_payload_size, 3);
        same!(chunk_child_alignment, 4);
        same!(chunk_child_header_size, 8);
        let mut absent = origin.clone();
        absent.attr_name = None;
        let mut empty = absent.clone();
        empty.attr_name = Some(String::new());
        assert_eq!(
            allowlist_surface_hash(&absent, body),
            allowlist_surface_hash(&empty, body)
        );
    }

    #[test]
    fn allowlist_json_validation_and_layer_precedence() {
        let hash = allowlist_surface_hash(&origin(), "exec(\"Example\");");
        let mut manual = origin();
        manual.trigger = ExecutionTrigger::Manual;
        let hash2 = allowlist_surface_hash(&manual, "exec(\"Example\");");
        let entry = json!({"hash":hash,"codes":["mel_exec"]});
        let metadata = json!({"hash":hash,"codes":["mel_exec"],"label":"Example","preview":"Example","reason":"Example","added_at":"2026-11-07","added_by":"example-user"});
        let app = list(json!([entry]), AllowlistSource::App);
        assert_eq!(
            app.canonical_digest(),
            list(json!([metadata]), AllowlistSource::App).canonical_digest()
        );
        assert!(list(json!([]), AllowlistSource::User).is_empty());
        assert!(AuditAllowlist::default().is_empty());
        let parse = |document: serde_json::Value| {
            AuditAllowlist::from_json(&document.to_string(), AllowlistSource::App)
        };
        assert!(matches!(
            parse(json!({"version":2,"entries":[]})),
            Err(AuditAllowlistError::UnsupportedVersion { version: 2 })
        ));
        assert!(matches!(
            parse(json!({"version":1,"entries":[{"hash":hash,"codes":[]}]})),
            Err(AuditAllowlistError::EmptyCodes { entry_index: 0 })
        ));
        for invalid in [
            "sha256:00".to_string(),
            format!("sha256:{}", hash.to_string()[7..].to_uppercase()),
            format!("{hash} "),
            hash.to_string().replacen("sha256:", "md5:", 1),
            format!("sha256:{}", "g".repeat(64)),
        ] {
            assert!(matches!(
                parse(json!({"version":1,"entries":[{"hash":invalid,"codes":["mel_exec"]}]})),
                Err(AuditAllowlistError::InvalidHash { .. })
            ));
            assert!(invalid.parse::<AllowlistHash>().is_err());
            assert!(serde_json::from_value::<AllowlistHash>(json!(invalid)).is_err());
        }
        for invalid in [
            json!({"version":1,"entries":[],"extra":true}),
            json!({"version":1,"entries":[{"hash":hash,"codes":["mel_exec"],"extra":true}]}),
            json!({"version":1,"entries":[{"hash":hash,"codes":[""]}]}),
            json!({"version":"1","entries":[]}),
        ] {
            assert!(matches!(
                parse(invalid),
                Err(AuditAllowlistError::InvalidJson { .. })
            ));
        }
        assert!(matches!(
            AuditAllowlist::from_json("{", AllowlistSource::App),
            Err(AuditAllowlistError::InvalidJson { .. })
        ));
        assert!(matches!(
            parse(json!({"version":2,"entries":[],"extra":true})),
            Err(AuditAllowlistError::InvalidJson { .. })
        ));
        assert!(matches!(
            parse(json!({"version":2,"entries":[{"hash":"bad","codes":[]}]})),
            Err(AuditAllowlistError::UnsupportedVersion { .. })
        ));
        assert!(matches!(
            parse(json!({"version":1,"entries":[{"hash":"bad","codes":[]}]})),
            Err(AuditAllowlistError::InvalidHash { .. })
        ));
        assert!(matches!(
            parse(
                json!({"version":1,"entries":[{"hash":hash,"codes":[]},{"hash":"bad","codes":["mel_exec"]}]})
            ),
            Err(AuditAllowlistError::EmptyCodes { entry_index: 0 })
        ));
        let arbitrary = list(
            json!([{"hash":hash,"codes":["python_pyexec","custom_rule_match","python_exec","example_unknown"]}]),
            AllowlistSource::User,
        );
        for code in [
            "python_pyexec",
            "custom_rule_match",
            "python_exec",
            "example_unknown",
        ] {
            assert!(arbitrary.lookup(&hash, code).is_some());
        }
        let user = list(
            json!([{"hash":hash,"codes":["mel_exec","mel_eval"]}]),
            AllowlistSource::User,
        );
        let other = list(
            json!([{"hash":hash2,"codes":["mel_python"]}]),
            AllowlistSource::User,
        );
        let merged = AuditAllowlist::merge([app.clone(), user.clone(), other.clone()]);
        assert_eq!(
            merged.lookup(&hash, "mel_exec").unwrap().source,
            AllowlistSource::App
        );
        assert_eq!(
            merged.lookup(&hash, "mel_eval").unwrap().source,
            AllowlistSource::User
        );
        assert_eq!(
            merged.lookup(&hash2, "mel_python").unwrap().source,
            AllowlistSource::User
        );
        let expected = AuditAllowlist::merge([
            app.clone(),
            list(
                json!([{"hash":hash,"codes":["mel_eval"]},{"hash":hash2,"codes":["mel_python"]}]),
                AllowlistSource::User,
            ),
        ]);
        assert_eq!(merged.canonical_digest(), expected.canonical_digest());
        assert_eq!(
            AuditAllowlist::merge([user, app, other])
                .lookup(&hash, "mel_exec")
                .unwrap()
                .source,
            AllowlistSource::User
        );
        assert!(AuditAllowlist::merge([]).is_empty());
    }

    #[test]
    fn allowlist_plan_fingerprint_is_canonical_and_empty_compatible() {
        let plan = build_script_audit_plan(vec![], 64).unwrap();
        let fingerprint = fingerprint_audit_plan(&plan);
        let expected = if usize::BITS == 64 {
            "9b3f437efff889198d09e4aa020ec1badd32e3bbe3d6161fa0c41e526aa9f5f1"
        } else {
            "b7aaf7542765ede5b774dcf911800f6bce37c8ceaf6508b528be0a4987138cff"
        };
        assert_eq!(fingerprint, expected);
        assert_eq!(
            fingerprint_audit_plan(&plan.clone().with_allowlist(AuditAllowlist::default())),
            fingerprint
        );
        let hash = allowlist_surface_hash(&origin(), "exec(\"Example\");");
        let entries =
            json!([{"hash":hash,"codes":["mel_exec"]},{"hash":hash,"codes":["mel_eval"]}]);
        let changed = |entries, source| {
            fingerprint_audit_plan(&plan.clone().with_allowlist(list(entries, source)))
        };
        let single = changed(
            json!([{"hash":hash,"codes":["mel_exec"]}]),
            AllowlistSource::App,
        );
        assert_ne!(single, fingerprint);
        assert_ne!(
            single,
            changed(
                json!([{"hash":hash,"codes":["mel_eval"]}]),
                AllowlistSource::App
            )
        );
        assert_ne!(
            single,
            changed(
                json!([{"hash":hash,"codes":["mel_exec"]}]),
                AllowlistSource::User
            )
        );
        let canonical = changed(entries, AllowlistSource::App);
        for equivalent in [
            json!([{"hash":hash,"codes":["mel_eval"]},{"hash":hash,"codes":["mel_exec"]}]),
            json!([{"hash":hash,"codes":["mel_exec","mel_exec"]},{"hash":hash,"codes":["mel_eval"]},{"hash":hash,"codes":["mel_exec"]}]),
            json!([{"hash":hash,"codes":["mel_exec"],"label":"Example"},{"hash":hash,"codes":["mel_eval"],"reason":"Sample"}]),
        ] {
            assert_eq!(canonical, changed(equivalent, AllowlistSource::App));
        }
    }
}
