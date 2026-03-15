use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConvergentClusterMode {
    GuardianMajority,
    ExperimentalNestedGuardian,
}

#[derive(Debug, Clone)]
struct CommitteeState {
    members: usize,
    threshold: usize,
    online_members: usize,
    equivocation_budget: usize,
}

impl CommitteeState {
    fn can_issue_certificate(&self) -> bool {
        self.online_members >= self.threshold
    }

    fn conflicting_certificates_possible(&self) -> bool {
        self.equivocation_budget >= (2 * self.threshold).saturating_sub(self.members)
    }
}

#[derive(Debug, Clone)]
struct WitnessState {
    assigned: bool,
    online: bool,
    checkpoint_fresh: bool,
    registry_fresh: bool,
}

impl Default for WitnessState {
    fn default() -> Self {
        Self {
            assigned: true,
            online: true,
            checkpoint_fresh: true,
            registry_fresh: true,
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatorState {
    id: usize,
    online: bool,
    supported_epoch: u64,
    registry_epoch: u64,
    guardian: CommitteeState,
    witness: WitnessState,
    partition: usize,
}

impl ValidatorState {
    fn can_vote_for_epoch(&self, epoch: u64, mode: ConvergentClusterMode) -> bool {
        if !self.online || self.supported_epoch != epoch || self.registry_epoch != epoch {
            return false;
        }
        if !self.guardian.can_issue_certificate() {
            return false;
        }
        if matches!(mode, ConvergentClusterMode::ExperimentalNestedGuardian) {
            return self.witness.assigned
                && self.witness.online
                && self.witness.checkpoint_fresh
                && self.witness.registry_fresh;
        }
        true
    }
}

#[derive(Debug, Clone)]
struct ClusterState {
    mode: ConvergentClusterMode,
    epoch: u64,
    validators: Vec<ValidatorState>,
}

impl ClusterState {
    fn quorum_threshold(&self) -> usize {
        (self.validators.len() / 2) + 1
    }

    fn eligible_voters(&self) -> Vec<usize> {
        self.validators
            .iter()
            .filter(|validator| validator.can_vote_for_epoch(self.epoch, self.mode))
            .map(|validator| validator.id)
            .collect()
    }

    fn can_finalize(&self) -> bool {
        self.eligible_voters().len() >= self.quorum_threshold()
    }

    fn can_finalize_in_partition(&self, partition: usize) -> bool {
        self.validators
            .iter()
            .filter(|validator| validator.partition == partition)
            .filter(|validator| validator.can_vote_for_epoch(self.epoch, self.mode))
            .count()
            >= self.quorum_threshold()
    }

    fn conflicting_finalization_possible(&self) -> bool {
        let partitions: BTreeSet<usize> = self
            .validators
            .iter()
            .map(|validator| validator.partition)
            .collect();
        let partitions_list = partitions.iter().copied().collect::<Vec<_>>();
        partitions_list.iter().copied().any(|left| {
            partitions
                .iter()
                .copied()
                .filter(|right| *right != left)
                .any(|right| {
                    self.can_finalize_in_partition(left) && self.can_finalize_in_partition(right)
                })
        })
    }

    fn any_committee_can_equivocate(&self) -> bool {
        self.validators
            .iter()
            .any(|validator| validator.guardian.conflicting_certificates_possible())
    }
}

fn validator(
    id: usize,
    partition: usize,
    guardian: CommitteeState,
    witness: WitnessState,
) -> ValidatorState {
    ValidatorState {
        id,
        online: true,
        supported_epoch: 7,
        registry_epoch: 7,
        guardian,
        witness,
        partition,
    }
}

fn safe_guardian_committee() -> CommitteeState {
    CommitteeState {
        members: 4,
        threshold: 3,
        online_members: 4,
        equivocation_budget: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_registry_reads_prevent_quorum() {
        let mut validators = vec![
            validator(0, 0, safe_guardian_committee(), WitnessState::default()),
            validator(1, 0, safe_guardian_committee(), WitnessState::default()),
            validator(2, 0, safe_guardian_committee(), WitnessState::default()),
            validator(3, 0, safe_guardian_committee(), WitnessState::default()),
            validator(4, 0, safe_guardian_committee(), WitnessState::default()),
        ];
        validators[0].registry_epoch = 6;
        validators[1].registry_epoch = 6;
        validators[2].registry_epoch = 6;

        let cluster = ClusterState {
            mode: ConvergentClusterMode::GuardianMajority,
            epoch: 7,
            validators,
        };

        assert!(!cluster.can_finalize());
    }

    #[test]
    fn delayed_checkpoints_pause_experimental_finalization() {
        let mut validators = vec![
            validator(0, 0, safe_guardian_committee(), WitnessState::default()),
            validator(1, 0, safe_guardian_committee(), WitnessState::default()),
            validator(2, 0, safe_guardian_committee(), WitnessState::default()),
            validator(3, 0, safe_guardian_committee(), WitnessState::default()),
            validator(4, 0, safe_guardian_committee(), WitnessState::default()),
        ];
        validators[0].witness.checkpoint_fresh = false;
        validators[1].witness.checkpoint_fresh = false;
        validators[2].witness.checkpoint_fresh = false;

        let cluster = ClusterState {
            mode: ConvergentClusterMode::ExperimentalNestedGuardian,
            epoch: 7,
            validators,
        };

        assert!(!cluster.can_finalize());
    }

    #[test]
    fn committee_partial_outage_preserves_safety_but_can_stop_liveness() {
        let mut validators = vec![
            validator(0, 0, safe_guardian_committee(), WitnessState::default()),
            validator(1, 0, safe_guardian_committee(), WitnessState::default()),
            validator(2, 0, safe_guardian_committee(), WitnessState::default()),
            validator(3, 0, safe_guardian_committee(), WitnessState::default()),
            validator(4, 0, safe_guardian_committee(), WitnessState::default()),
        ];
        validators[0].guardian.online_members = 2;
        validators[1].guardian.online_members = 2;
        validators[2].guardian.online_members = 2;

        let cluster = ClusterState {
            mode: ConvergentClusterMode::GuardianMajority,
            epoch: 7,
            validators,
        };

        assert!(!cluster.can_finalize());
        assert!(!cluster.any_committee_can_equivocate());
    }

    #[test]
    fn mixed_version_epoch_upgrade_requires_epoch_convergence() {
        let mut validators = vec![
            validator(0, 0, safe_guardian_committee(), WitnessState::default()),
            validator(1, 0, safe_guardian_committee(), WitnessState::default()),
            validator(2, 0, safe_guardian_committee(), WitnessState::default()),
            validator(3, 0, safe_guardian_committee(), WitnessState::default()),
            validator(4, 0, safe_guardian_committee(), WitnessState::default()),
        ];
        validators[0].supported_epoch = 8;
        validators[0].registry_epoch = 8;
        validators[1].supported_epoch = 8;
        validators[1].registry_epoch = 8;
        validators[2].registry_epoch = 6;

        let epoch7_cluster = ClusterState {
            mode: ConvergentClusterMode::GuardianMajority,
            epoch: 7,
            validators: validators.clone(),
        };
        let epoch8_cluster = ClusterState {
            mode: ConvergentClusterMode::GuardianMajority,
            epoch: 8,
            validators,
        };

        assert!(!epoch7_cluster.can_finalize());
        assert!(!epoch8_cluster.can_finalize());
    }

    #[test]
    fn log_rollback_attempts_are_rejected_by_checkpoint_monotonicity() {
        let mut validators = vec![
            validator(0, 0, safe_guardian_committee(), WitnessState::default()),
            validator(1, 0, safe_guardian_committee(), WitnessState::default()),
            validator(2, 0, safe_guardian_committee(), WitnessState::default()),
            validator(3, 0, safe_guardian_committee(), WitnessState::default()),
            validator(4, 0, safe_guardian_committee(), WitnessState::default()),
        ];
        validators[0].witness.registry_fresh = false;
        validators[1].witness.registry_fresh = false;
        validators[2].witness.registry_fresh = false;

        let cluster = ClusterState {
            mode: ConvergentClusterMode::ExperimentalNestedGuardian,
            epoch: 7,
            validators,
        };

        assert!(!cluster.can_finalize());
    }

    #[test]
    fn partitions_cannot_finalize_conflicting_blocks_without_dual_majorities() {
        let validators = vec![
            validator(0, 0, safe_guardian_committee(), WitnessState::default()),
            validator(1, 0, safe_guardian_committee(), WitnessState::default()),
            validator(2, 0, safe_guardian_committee(), WitnessState::default()),
            validator(3, 1, safe_guardian_committee(), WitnessState::default()),
            validator(4, 1, safe_guardian_committee(), WitnessState::default()),
        ];
        let cluster = ClusterState {
            mode: ConvergentClusterMode::GuardianMajority,
            epoch: 7,
            validators,
        };

        assert!(cluster.can_finalize_in_partition(0));
        assert!(!cluster.can_finalize_in_partition(1));
        assert!(!cluster.conflicting_finalization_possible());
    }
}
