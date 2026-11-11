use super::*;

#[derive(Clone, Default)]
pub(super) struct CleanEdits {
    pub(super) targets: BTreeSet<ExecutionCleanTarget>,
    pub(super) preview: Option<ExecutionCleanPreview>,
    pub(super) source: Option<maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>,
}

#[derive(Clone, Default)]
pub(super) struct OwnerEdits {
    pub(super) targets: BTreeSet<PathOwnerDeleteTarget>,
    pub(super) preview: Option<PathOwnerDeletePreview>,
}

#[derive(Clone, Default)]
pub(super) struct StagedReports {
    pub(super) source: Option<maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>,
    pub(super) audit_mode: Option<AuditModePreference>,
    pub(super) audit_report: Option<AuditReport>,
    pub(super) audit_plan_fingerprint: Option<String>,
    pub(super) paths_report: Option<ScenePathsReport>,
    pub(super) dump_report: Option<SceneDumpReport>,
    pub(super) source_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Default)]
pub(super) enum Staged {
    #[default]
    None,
    Replace {
        source: Option<maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>,
        overrides: BTreeMap<usize, String>,
        preview: Option<PathReplacePreview>,
        artifact: Option<StagedSceneArtifact>,
    },
    SceneEdits {
        clean: CleanEdits,
        owner_delete: OwnerEdits,
        overrides: BTreeMap<usize, String>,
        artifact: Option<StagedSceneArtifact>,
        staged_reports: Box<StagedReports>,
    },
    ToAscii {
        destination_source: Option<maya_scene_kit_observe::scene::paths::SceneSourceFingerprint>,
        report: Option<MayaAsciiConversionReport>,
        artifact: Option<StagedSceneArtifact>,
    },
}

impl Staged {
    pub(super) fn source(
        &self,
    ) -> Option<&maya_scene_kit_observe::scene::paths::SceneSourceFingerprint> {
        match self {
            Self::Replace { source, .. } => source.as_ref(),
            Self::SceneEdits { staged_reports, .. } => staged_reports.source.as_ref(),
            Self::None | Self::ToAscii { .. } => None,
        }
    }

    pub(super) fn overrides(&self) -> &BTreeMap<usize, String> {
        static EMPTY: BTreeMap<usize, String> = BTreeMap::new();
        match self {
            Self::Replace { overrides, .. } | Self::SceneEdits { overrides, .. } => overrides,
            Self::None | Self::ToAscii { .. } => &EMPTY,
        }
    }

    pub(super) fn clean(&self) -> &CleanEdits {
        static EMPTY: CleanEdits = CleanEdits {
            targets: BTreeSet::new(),
            preview: None,
            source: None,
        };
        match self {
            Self::SceneEdits { clean, .. } => clean,
            _ => &EMPTY,
        }
    }

    pub(super) fn owner_delete(&self) -> &OwnerEdits {
        static EMPTY: OwnerEdits = OwnerEdits {
            targets: BTreeSet::new(),
            preview: None,
        };
        match self {
            Self::SceneEdits { owner_delete, .. } => owner_delete,
            _ => &EMPTY,
        }
    }

    pub(super) fn reports(&self) -> &StagedReports {
        static EMPTY: StagedReports = StagedReports {
            source: None,
            audit_mode: None,
            audit_report: None,
            audit_plan_fingerprint: None,
            paths_report: None,
            dump_report: None,
            source_bytes: None,
        };
        match self {
            Self::SceneEdits { staged_reports, .. } => staged_reports,
            _ => &EMPTY,
        }
    }

    pub(super) fn artifact(&self) -> &Option<StagedSceneArtifact> {
        match self {
            Self::Replace { artifact, .. }
            | Self::SceneEdits { artifact, .. }
            | Self::ToAscii { artifact, .. } => artifact,
            Self::None => &None,
        }
    }

    pub(super) fn same_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (
                Self::Replace {
                    overrides: a,
                    preview: b,
                    artifact: c,
                    source: source_a,
                },
                Self::Replace {
                    overrides: x,
                    preview: y,
                    artifact: z,
                    source: source_b,
                },
            ) => a == x && b == y && c == z && source_a == source_b,
            (
                Self::SceneEdits {
                    clean: a,
                    owner_delete: b,
                    overrides: c,
                    artifact: d,
                    ..
                },
                Self::SceneEdits {
                    clean: w,
                    owner_delete: x,
                    overrides: y,
                    artifact: z,
                    ..
                },
            ) => {
                self.source() == other.source()
                    && a.targets == w.targets
                    && a.preview == w.preview
                    && a.source == w.source
                    && b.targets == x.targets
                    && b.preview == x.preview
                    && c == y
                    && d == z
            }
            (
                Self::ToAscii {
                    report: a,
                    artifact: b,
                    destination_source: source_a,
                },
                Self::ToAscii {
                    report: x,
                    artifact: y,
                    destination_source: source_b,
                },
            ) => ascii_report_same(a, x) && b == y && source_a == source_b,
            _ => false,
        }
    }
}

pub(super) struct RestageRollback {
    staged: Staged,
    preview: Option<PathReplacePreview>,
    changes: Option<PathReplaceChanges>,
    artifact_current: bool,
}

impl SceneRow {
    pub(super) fn remember_restage(&mut self) {
        if self.restage_rollback.is_none() {
            self.restage_rollback = Some(RestageRollback {
                staged: self.staged.clone(),
                preview: self.applied_replace_preview.clone(),
                changes: self.replace_changes.clone(),
                artifact_current: self.replace_artifact_is_current(),
            });
        }
    }

    pub(super) fn rollback_restage(&mut self) {
        if let Some(previous) = self.restage_rollback.take() {
            self.staged = previous.staged;
            self.applied_replace_preview = previous.preview;
            self.replace_changes = previous.changes;
            self.replace_artifact_generation =
                previous.artifact_current.then_some(self.replace_generation);
            self.sync_findings_count();
            self.invalidate_path_resolution_state();
        }
    }
}
