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
        mode: AftClusterMode::GuardianMajority,
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
        mode: AftClusterMode::ExperimentalNestedGuardian,
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
        mode: AftClusterMode::GuardianMajority,
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
        mode: AftClusterMode::GuardianMajority,
        epoch: 7,
        validators: validators.clone(),
    };
    let epoch8_cluster = ClusterState {
        mode: AftClusterMode::GuardianMajority,
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
        mode: AftClusterMode::ExperimentalNestedGuardian,
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
        mode: AftClusterMode::GuardianMajority,
        epoch: 7,
        validators,
    };

    assert!(cluster.can_finalize_in_partition(0));
    assert!(!cluster.can_finalize_in_partition(1));
    assert!(!cluster.conflicting_finalization_possible());
}
