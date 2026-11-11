use super::*;

pub(super) fn edit_error_message(error: &SceneToolError, reanalysis_required: &str) -> String {
    if matches!(
        error,
        SceneToolError::SourceChanged { .. } | SceneToolError::SourceUnstable { .. }
    ) {
        format!("{reanalysis_required}: {error}")
    } else {
        error.to_string()
    }
}

#[derive(Clone, Copy)]
pub(super) enum RowMutation {
    Job(RowOperation),
    PathEdit,
    SceneEdit,
    HistoryRestore,
    CacheRestore,
    ReplaceArtifact,
}

pub(super) enum MutateBlocked {
    Missing,
    Edit {
        name: String,
    },
    StalePreview {
        name: String,
    },
    Busy {
        name: String,
        operation: RowOperation,
    },
    Staged {
        name: String,
    },
}

impl MutateBlocked {
    pub(super) fn into_banner(self) -> BannerMessage {
        match self {
            Self::Missing => BannerMessage::RowMutationMissing,
            Self::Edit { name } => MutationRejections {
                blocked: vec![(0, Self::Edit { name })],
                changed: Some(0),
                ..Default::default()
            }
            .banner()
            .expect("edit rejection"),
            Self::StalePreview { name } => BannerMessage::EditRowsSkipped {
                busy: 0,
                staged: 0,
                stale: 1,
                name,
                missing_artifacts: 0,
                skipped: 0,
                changed: Some(0),
                saving: false,
                details: Vec::new(),
            },
            Self::Busy {
                operation: RowOperation::Save,
                ..
            } => BannerMessage::SaveInProgress,
            Self::Busy { name, operation } => BannerMessage::RowMutationBusy { name, operation },
            Self::Staged { name } => BannerMessage::AnalysisStagedPreserved { name },
        }
    }
}

#[derive(Default)]
pub(super) struct MutationRejections {
    pub(super) blocked: Vec<(u64, MutateBlocked)>,
    pub(super) skipped: usize,
    pub(super) missing_artifacts: usize,
    pub(super) changed: Option<usize>,
}

impl MutationRejections {
    pub(super) fn busy_count(&self) -> usize {
        self.blocked
            .iter()
            .filter(|(_, blocked)| matches!(blocked, MutateBlocked::Busy { .. }))
            .count()
    }

    fn is_empty(&self) -> bool {
        self.blocked.is_empty() && self.skipped == 0 && self.missing_artifacts == 0
    }

    pub(super) fn banner(&self) -> Option<BannerMessage> {
        let count = self.busy_count();
        let staged = self
            .blocked
            .iter()
            .filter(|(_, b)| matches!(b, MutateBlocked::Edit { .. } | MutateBlocked::Staged { .. }))
            .count();
        let stale = self
            .blocked
            .iter()
            .filter(|(_, b)| matches!(b, MutateBlocked::StalePreview { .. }))
            .count();
        let skipped = self.skipped
            + self
                .blocked
                .iter()
                .filter(|(_, b)| matches!(b, MutateBlocked::Missing))
                .count();
        let saving = self.blocked.iter().any(|(_, b)| {
            matches!(
                b,
                MutateBlocked::Busy {
                    operation: RowOperation::Save,
                    ..
                }
            )
        });
        if staged + stale + skipped + self.missing_artifacts > 0 || self.changed.is_some() {
            let name = self
                .blocked
                .iter()
                .find_map(|(_, b)| match b {
                    MutateBlocked::Edit { name }
                    | MutateBlocked::Staged { name }
                    | MutateBlocked::StalePreview { name }
                    | MutateBlocked::Busy { name, .. } => Some(name.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            return Some(BannerMessage::EditRowsSkipped {
                busy: count,
                staged,
                stale,
                name,
                missing_artifacts: self.missing_artifacts,
                skipped,
                changed: self.changed,
                saving,
                details: Vec::new(),
            });
        }
        (count > 0).then_some(BannerMessage::BusyRowsSkipped { count, saving })
    }
}

pub(super) fn check_row_mutation(
    row: Option<&SceneRow>,
    op: RowMutation,
) -> Result<(), MutateBlocked> {
    let row = row.ok_or(MutateBlocked::Missing)?;
    if let Some((operation, _)) = row.busy {
        return Err(MutateBlocked::Busy {
            name: row.name.clone(),
            operation,
        });
    }
    if matches!(
        op,
        RowMutation::Job(RowOperation::Analyze) | RowMutation::CacheRestore
    ) && row.has_staged_edits()
    {
        return Err(MutateBlocked::Staged {
            name: row.name.clone(),
        });
    }
    if (matches!(op, RowMutation::Job(RowOperation::ToAscii)) && row.has_staged_edits())
        || (matches!(row.staged, Staged::ToAscii { .. })
            && !matches!(
                op,
                RowMutation::HistoryRestore | RowMutation::Job(RowOperation::Save)
            ))
    {
        return Err(MutateBlocked::Edit {
            name: row.name.clone(),
        });
    }
    Ok(())
}

impl GuiShell {
    pub(super) fn can_mutate(&self, row_id: u64, op: RowMutation) -> Result<(), MutateBlocked> {
        check_row_mutation(
            self.index_of_row_id(row_id)
                .and_then(|index| self.rows.get(index)),
            op,
        )
    }

    pub(super) fn admit_mutation(
        &mut self,
        row_id: u64,
        op: RowMutation,
        cx: &mut Context<Self>,
    ) -> bool {
        match self.can_mutate(row_id, op) {
            Ok(()) => true,
            Err(MutateBlocked::Missing) => false,
            Err(blocked) => {
                self.status_message = Some(blocked.into_banner());
                cx.notify();
                false
            }
        }
    }

    pub(super) fn row_ids_for_indices(&self, indices: &[usize]) -> Vec<u64> {
        indices
            .iter()
            .filter_map(|index| self.rows.get(*index).map(|row| row.id))
            .collect()
    }

    pub(super) fn mutation_targets(
        &self,
        row_ids: impl IntoIterator<Item = u64>,
        op: RowMutation,
    ) -> (Vec<usize>, MutationRejections) {
        let mut seen = BTreeSet::new();
        let mut indices = Vec::new();
        let mut rejected = MutationRejections::default();
        for row_id in row_ids {
            if !seen.insert(row_id) {
                continue;
            }
            match self.can_mutate(row_id, op) {
                Ok(()) => {
                    if let Some(index) = self.index_of_row_id(row_id) {
                        indices.push(index);
                    }
                }
                Err(blocked) => rejected.blocked.push((row_id, blocked)),
            }
        }
        if indices.is_empty()
            && rejected
                .blocked
                .iter()
                .any(|(_, reason)| !matches!(reason, MutateBlocked::Busy { .. }))
        {
            rejected.changed = Some(0);
        }
        (indices, rejected)
    }

    pub(super) fn report_mutation_rejections(
        &mut self,
        mut rejected: MutationRejections,
        cx: &mut Context<Self>,
    ) {
        if self.mutation_banner_depth > 0 {
            rejected
                .blocked
                .retain(|(id, _)| self.mutation_rejected_rows.insert(*id));
        }
        let Some(banner) = rejected.banner() else {
            return;
        };
        self.merge_mutation_banner(banner);
        cx.notify();
    }

    pub(super) fn merge_mutation_banner(&mut self, banner: BannerMessage) {
        let Some(current) = self.status_message.take() else {
            self.status_message = Some(banner);
            return;
        };
        let mut summary = BannerMessage::EditRowsSkipped {
            busy: 0,
            staged: 0,
            stale: 0,
            missing_artifacts: 0,
            skipped: 0,
            changed: None,
            saving: false,
            name: String::new(),
            details: Vec::new(),
        };
        let BannerMessage::EditRowsSkipped {
            busy,
            staged,
            stale,
            missing_artifacts,
            skipped,
            changed,
            saving,
            name,
            details,
        } = &mut summary
        else {
            unreachable!()
        };
        for part in [current, banner] {
            match part {
                BannerMessage::EditRowsSkipped {
                    busy: b,
                    staged: e,
                    stale: s,
                    missing_artifacts: m,
                    skipped: k,
                    changed: c,
                    saving: v,
                    name: n,
                    details: d,
                } => {
                    *busy += b;
                    *staged += e;
                    *stale += s;
                    *missing_artifacts += m;
                    *skipped += k;
                    if let Some(c) = c {
                        *changed = Some(changed.unwrap_or(0) + c);
                    }
                    *saving |= v;
                    if name.is_empty() {
                        *name = n;
                    }
                    details.extend(d);
                }
                BannerMessage::BusyRowsSkipped { count, saving: v } => {
                    *busy += count;
                    *saving |= v;
                }
                other => details.push(render_banner_message(&self.i18n(), &other)),
            }
        }
        self.status_message = Some(summary);
    }

    pub(super) fn reject_changed_report_source(
        &mut self,
        row_id: u64,
        error: &SceneToolError,
        cx: &mut Context<Self>,
    ) -> bool {
        if !matches!(
            error,
            SceneToolError::SourceChanged { .. } | SceneToolError::SourceUnstable { .. }
        ) {
            return false;
        }
        if let Some(index) = self.index_of_row_id(row_id) {
            let message =
                edit_error_message(error, &self.i18n().text("banner.edit_requires_reanalysis"));
            self.rows[index].status = FileStatus::Error(message.clone());
            self.report_edit_detail(message);
            self.refresh_file_table(cx);
            cx.notify();
        }
        true
    }

    pub(super) fn report_edit_detail(&mut self, message: String) {
        if matches!(
            self.status_message,
            Some(BannerMessage::EditRowsSkipped { .. } | BannerMessage::BusyRowsSkipped { .. })
        ) {
            self.merge_mutation_banner(BannerMessage::Raw(message));
        } else {
            self.status_message = Some(BannerMessage::Raw(message));
        }
    }

    pub(super) fn with_mutation_targets(
        &mut self,
        row_ids: Vec<u64>,
        op: RowMutation,
        cx: &mut Context<Self>,
        apply: impl FnOnce(&mut Self, Vec<usize>, &mut Context<Self>),
    ) {
        self.with_audit_refresh_batch(cx, |shell, cx| {
            let previous_banner = if shell.mutation_banner_depth == 0 {
                shell.mutation_rejected_rows.clear();
                shell.status_message.take()
            } else {
                None
            };
            shell.mutation_banner_depth += 1;
            let (indices, rejected) = shell.mutation_targets(row_ids, op);
            if !indices.is_empty() || rejected.is_empty() {
                apply(shell, indices, cx);
            }
            shell.report_mutation_rejections(rejected, cx);
            shell.mutation_banner_depth -= 1;
            if shell.status_message.is_none() {
                shell.status_message = previous_banner;
            }
        })
    }

    pub(super) fn with_path_mutations(
        &mut self,
        targets: PathEditTargets,
        cx: &mut Context<Self>,
        apply: impl FnOnce(&mut Self, PathEditTargets, &mut Context<Self>),
    ) {
        let row_ids = targets.iter().map(|(row_id, _)| *row_id).collect();
        self.with_mutation_targets(row_ids, RowMutation::PathEdit, cx, |shell, indices, cx| {
            let accepted = shell
                .row_ids_for_indices(&indices)
                .into_iter()
                .collect::<BTreeSet<_>>();
            let targets = targets
                .into_iter()
                .filter(|(row_id, _)| accepted.contains(row_id))
                .collect();
            apply(shell, targets, cx);
        });
    }

    pub(super) fn admit_history_restore(
        &mut self,
        row_ids: impl IntoIterator<Item = u64>,
        cx: &mut Context<Self>,
    ) -> bool {
        let row_ids = row_ids
            .into_iter()
            .filter(|id| self.index_of_row_id(*id).is_some())
            .collect::<Vec<_>>();
        if row_ids.is_empty() {
            return true;
        }
        if self.block_workspace_change_while_saving(cx) {
            return false;
        }
        for row_id in row_ids {
            if self.index_of_row_id(row_id).is_some()
                && !self.admit_mutation(row_id, RowMutation::HistoryRestore, cx)
            {
                return false;
            }
        }
        true
    }

    pub(super) fn next_row_job_id(&mut self) -> u64 {
        let job_id = self.next_row_job_id;
        self.next_row_job_id = self
            .next_row_job_id
            .checked_add(1)
            .expect("row job ID exhausted");
        job_id
    }

    pub(super) fn accept_job_completion(
        &mut self,
        job: (u64, u64),
        operation: RowOperation,
        edit_sequence: Option<u64>,
    ) -> Option<usize> {
        let (row_id, job_id) = job;
        let index = self.index_of_row_id(row_id);
        if let Some(index) = index {
            if self.rows[index]
                .busy
                .is_some_and(|(_, current)| current == job_id)
            {
                self.rows[index].busy = None;
                return Some(index);
            }
            self.record_job(
                operation_key(operation),
                self.rows[index].path.clone(),
                None,
                "Discarded stale job result.".into(),
                false,
            );
        }
        if let Some(sequence) = edit_sequence {
            self.complete_edit_transaction_failure(sequence, row_id);
        }
        None
    }
}
