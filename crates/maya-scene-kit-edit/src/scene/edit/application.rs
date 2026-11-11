use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use maya_scene_kit_formats::mb::rewrite as binary;

use crate::scene::{
    ExecutionCleanTarget, PathOwnerDeleteTarget, SceneEditChange, SceneEditChanges,
    SceneEditIntent, SceneEditLocator, SceneEditStatus, ScenePathEntryChange, ScenePathOutcome,
};

pub(super) struct Applied<T> {
    pub bytes: Vec<u8>,
    pub changes: T,
}

pub(super) fn change(
    intent: &SceneEditIntent,
    locator: SceneEditLocator,
    before: Vec<u8>,
    after: Vec<u8>,
) -> SceneEditChange {
    SceneEditChange {
        intent: intent.clone(),
        locator,
        before,
        after,
        status: SceneEditStatus::Applied,
        reason: "applied to original source".into(),
        covered_by: None,
        superseded_by: None,
    }
}

pub(super) fn absorbed(record: &mut SceneEditChange, outer: &SceneEditLocator, deletion: bool) {
    if deletion {
        record.status = SceneEditStatus::Covered;
        record.reason = "covered by an enclosing deletion".into();
        record.covered_by = Some(outer.clone());
    } else {
        record.status = SceneEditStatus::Superseded;
        record.reason = "superseded by deletion".into();
        record.superseded_by = Some(outer.clone());
    }
    record.after.clear();
}

pub(super) fn range_locator(range: &Range<usize>) -> SceneEditLocator {
    SceneEditLocator::MaRange {
        start: range.start,
        end: range.end,
    }
}

pub(super) fn form_locator(form: &str, node_offset: usize) -> SceneEditLocator {
    SceneEditLocator::MbForm {
        form: form.into(),
        node_offset,
    }
}

pub(super) fn record_locator(locator: &binary::MbPayloadLocator) -> SceneEditLocator {
    SceneEditLocator::MbRecord {
        form: locator.form.clone(),
        node_offset: locator.node_offset,
        chunk_start: locator.chunk_start,
    }
}

pub(super) fn summarize(changes: &mut SceneEditChanges) {
    changes.physical_deletion_count = changes
        .records
        .iter()
        .filter(|record| {
            record.status == SceneEditStatus::Applied
                && match &record.intent {
                    SceneEditIntent::Path(_)
                    | SceneEditIntent::Clean(ExecutionCleanTarget::FileCommandCallback {
                        ..
                    }) => false,
                    _ => record.locator != SceneEditLocator::Unresolved,
                }
        })
        .map(|record| &record.locator)
        .collect::<BTreeSet<_>>()
        .len();
    changes
        .records
        .sort_by(|a, b| (&a.intent, &a.locator).cmp(&(&b.intent, &b.locator)));
    let mut entries = BTreeMap::<usize, Vec<SceneEditStatus>>::new();
    for record in &changes.records {
        if let SceneEditIntent::Path(value) = &record.intent {
            entries
                .entry(value.entry_index)
                .or_default()
                .push(record.status);
            if record.status == SceneEditStatus::Applied {
                changes.path_replacements.replacement_count += 1;
            }
        }
    }
    for (entry_index, states) in entries {
        let outcome = if states
            .iter()
            .all(|state| *state == SceneEditStatus::Superseded)
        {
            changes.superseded_path_override_count += 1;
            ScenePathOutcome::Superseded
        } else if states
            .iter()
            .all(|state| *state == SceneEditStatus::Applied)
        {
            ScenePathOutcome::Replaced
        } else if states
            .iter()
            .all(|state| *state == SceneEditStatus::Unchanged)
        {
            ScenePathOutcome::Unchanged
        } else if states
            .iter()
            .all(|state| *state == SceneEditStatus::Skipped)
        {
            ScenePathOutcome::Skipped
        } else {
            ScenePathOutcome::Mixed
        };
        changes.path_entries.push(ScenePathEntryChange {
            entry_index,
            outcome,
        });
    }
}

pub(super) fn cleaned_targets(changes: &SceneEditChanges) -> Vec<ExecutionCleanTarget> {
    changes
        .records
        .iter()
        .filter_map(|record| {
            if record.status != SceneEditStatus::Applied {
                return None;
            }
            match &record.intent {
                SceneEditIntent::Clean(target) => Some(target.clone()),
                _ => None,
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn deleted_owners(changes: &SceneEditChanges) -> Vec<PathOwnerDeleteTarget> {
    changes
        .records
        .iter()
        .filter_map(|record| {
            if !matches!(
                record.status,
                SceneEditStatus::Applied | SceneEditStatus::Covered
            ) || record.locator == SceneEditLocator::Unresolved
            {
                return None;
            }
            match &record.intent {
                SceneEditIntent::DeleteOwner(target) => Some(target.clone()),
                _ => None,
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn normalized_away(intent: SceneEditIntent) -> SceneEditChange {
    SceneEditChange {
        intent,
        locator: SceneEditLocator::Unresolved,
        before: Vec::new(),
        after: Vec::new(),
        status: SceneEditStatus::Covered,
        reason: "removed by target normalization".into(),
        covered_by: None,
        superseded_by: None,
    }
}
