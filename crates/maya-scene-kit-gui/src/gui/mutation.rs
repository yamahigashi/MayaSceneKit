use super::*;

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
    blocked: Vec<MutateBlocked>,
}

impl MutationRejections {
    pub(super) fn busy_count(&self) -> usize {
        self.blocked
            .iter()
            .filter(|blocked| matches!(blocked, MutateBlocked::Busy { .. }))
            .count()
    }

    fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }

    pub(super) fn banner(&self) -> Option<BannerMessage> {
        let count = self.busy_count();
        (count > 0).then(|| BannerMessage::BusyRowsSkipped {
            count,
            saving: self.blocked.iter().any(|blocked| {
                matches!(
                    blocked,
                    MutateBlocked::Busy {
                        operation: RowOperation::Save,
                        ..
                    }
                )
            }),
        })
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
                Err(blocked) => rejected.blocked.push(blocked),
            }
        }
        (indices, rejected)
    }

    pub(super) fn report_mutation_rejections(
        &mut self,
        rejected: MutationRejections,
        cx: &mut Context<Self>,
    ) {
        let banner = rejected.banner().or_else(|| {
            rejected
                .blocked
                .into_iter()
                .find_map(|blocked| match blocked {
                    MutateBlocked::Missing => None,
                    other => Some(other.into_banner()),
                })
        });
        let Some(banner) = banner else {
            return;
        };
        if let Some(current_banner) = self.status_message.take() {
            self.record_job(
                "mutation-skipped",
                self.state.workspace_root_path().unwrap_or_default(),
                None,
                render_banner_message(&self.i18n(), &banner),
                false,
            );
            self.status_message = Some(current_banner);
        } else {
            self.status_message = Some(banner);
        }
        cx.notify();
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
