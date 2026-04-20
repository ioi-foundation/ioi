use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AftClusterMode {
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
    fn can_vote_for_epoch(&self, epoch: u64, mode: AftClusterMode) -> bool {
        if !self.online || self.supported_epoch != epoch || self.registry_epoch != epoch {
            return false;
        }
        if !self.guardian.can_issue_certificate() {
            return false;
        }
        if matches!(mode, AftClusterMode::ExperimentalNestedGuardian) {
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
    mode: AftClusterMode,
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
#[path = "network_simulator/tests.rs"]
mod tests;
