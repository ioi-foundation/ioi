//! Generic protected operational lifecycle transitions (M1.5 m1-5b).
//!
//! This family is deliberately separate from [`super::system_activation`]:
//! the bootstrap `SystemLifecycleOperation` is closed at sequences one and
//! two by canon, while these ops run at sequence three or later over the
//! live chain. The op-by-predecessor legality table here is the normative
//! machine form of the table in
//! `docs/architecture/foundations/common-objects-and-envelopes.md`
//! (`AutonomousSystemProtectedTransitionProposalEnvelope`); the unit tests
//! pin the two against each other. Constitutional amendment,
//! migration/succession, dissolution, and network enrollment retain their
//! named owner families and are intentionally absent.

use serde::{Deserialize, Serialize};

/// Observable lifecycle statuses reachable by the generic protected ops.
///
/// `Degraded` is an observed posture only: it may be a legal predecessor but
/// no proposal may target it, so it never appears as a resulting status.
/// Succession, dissolution, and enrollment statuses belong to their named
/// owner families and are not represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedLifecycleStatus {
    /// Fully operational.
    Active,
    /// Observed impaired posture; never an op target.
    Degraded,
    /// Deliberately paused; trivially resumable.
    Paused,
    /// Protected hold pending reinstatement.
    Suspended,
    /// Long-term intentional sleep.
    Dormant,
    /// Under governed recovery.
    Recovering,
    /// Isolated pending investigation or release.
    Quarantined,
    /// Withdrawn from service; evidence retained.
    Retired,
    /// Immutable end-of-life archive.
    Archived,
    /// Authority-revoked; only decommission remains.
    Revoked,
    /// Terminal: no further transition exists.
    Decommissioned,
}

impl ProtectedLifecycleStatus {
    /// Canonical status name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Suspended => "suspended",
            Self::Dormant => "dormant",
            Self::Recovering => "recovering",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
            Self::Archived => "archived",
            Self::Revoked => "revoked",
            Self::Decommissioned => "decommissioned",
        }
    }

    /// Parse a canonical status name.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "active" => Self::Active,
            "degraded" => Self::Degraded,
            "paused" => Self::Paused,
            "suspended" => Self::Suspended,
            "dormant" => Self::Dormant,
            "recovering" => Self::Recovering,
            "quarantined" => Self::Quarantined,
            "retired" => Self::Retired,
            "archived" => Self::Archived,
            "revoked" => Self::Revoked,
            "decommissioned" => Self::Decommissioned,
            _ => return None,
        })
    }
}

/// Declared reversibility class of a protected transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionIrreversibility {
    /// A declared inverse op exists.
    Reversible,
    /// No inverse op; later arcs may still continue end-of-life.
    OneWay,
    /// No further transition of any kind.
    Terminal,
}

impl TransitionIrreversibility {
    /// Canonical name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::OneWay => "one_way",
            Self::Terminal => "terminal",
        }
    }
}

/// The fourteen generic protected operational transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedTransitionOp {
    /// `active | degraded -> paused`.
    Pause,
    /// `paused -> active`.
    Resume,
    /// `active | degraded | paused -> suspended`.
    Suspend,
    /// `suspended -> active`.
    Reinstate,
    /// `active | paused -> dormant`.
    EnterDormancy,
    /// `dormant -> active`.
    Wake,
    /// `degraded | suspended | quarantined -> recovering`.
    BeginRecovery,
    /// `recovering -> active`.
    CompleteRecovery,
    /// `active | degraded | paused | recovering -> quarantined`.
    Quarantine,
    /// `quarantined -> active`.
    ReleaseQuarantine,
    /// `active | paused | suspended | dormant -> retired` (one-way).
    Retire,
    /// `retired -> archived` (one-way).
    Archive,
    /// any non-terminal `-> revoked` (one-way, protected).
    Revoke,
    /// `retired | archived | revoked -> decommissioned` (terminal).
    Decommission,
}

impl ProtectedTransitionOp {
    /// Every op, in canonical table order.
    pub const ALL: [Self; 14] = [
        Self::Pause,
        Self::Resume,
        Self::Suspend,
        Self::Reinstate,
        Self::EnterDormancy,
        Self::Wake,
        Self::BeginRecovery,
        Self::CompleteRecovery,
        Self::Quarantine,
        Self::ReleaseQuarantine,
        Self::Retire,
        Self::Archive,
        Self::Revoke,
        Self::Decommission,
    ];

    /// Canonical op name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Suspend => "suspend",
            Self::Reinstate => "reinstate",
            Self::EnterDormancy => "enter_dormancy",
            Self::Wake => "wake",
            Self::BeginRecovery => "begin_recovery",
            Self::CompleteRecovery => "complete_recovery",
            Self::Quarantine => "quarantine",
            Self::ReleaseQuarantine => "release_quarantine",
            Self::Retire => "retire",
            Self::Archive => "archive",
            Self::Revoke => "revoke",
            Self::Decommission => "decommission",
        }
    }

    /// Parse a canonical op name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == value)
    }

    /// Exact wallet.network operation scope. Authority for one transition
    /// kind is never authority for another.
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::Pause => "scope:autonomous_system.lifecycle.pause",
            Self::Resume => "scope:autonomous_system.lifecycle.resume",
            Self::Suspend => "scope:autonomous_system.lifecycle.suspend",
            Self::Reinstate => "scope:autonomous_system.lifecycle.reinstate",
            Self::EnterDormancy => "scope:autonomous_system.lifecycle.enter_dormancy",
            Self::Wake => "scope:autonomous_system.lifecycle.wake",
            Self::BeginRecovery => "scope:autonomous_system.lifecycle.begin_recovery",
            Self::CompleteRecovery => "scope:autonomous_system.lifecycle.complete_recovery",
            Self::Quarantine => "scope:autonomous_system.lifecycle.quarantine",
            Self::ReleaseQuarantine => "scope:autonomous_system.lifecycle.release_quarantine",
            Self::Retire => "scope:autonomous_system.lifecycle.retire",
            Self::Archive => "scope:autonomous_system.lifecycle.archive",
            Self::Revoke => "scope:autonomous_system.lifecycle.revoke",
            Self::Decommission => "scope:autonomous_system.lifecycle.decommission",
        }
    }

    /// Declared reversibility class.
    pub fn irreversibility(self) -> TransitionIrreversibility {
        match self {
            Self::Retire | Self::Archive | Self::Revoke => TransitionIrreversibility::OneWay,
            Self::Decommission => TransitionIrreversibility::Terminal,
            _ => TransitionIrreversibility::Reversible,
        }
    }

    /// Legal predecessor statuses, exactly mirroring the canon table.
    pub fn legal_predecessors(self) -> &'static [ProtectedLifecycleStatus] {
        use ProtectedLifecycleStatus as S;
        match self {
            Self::Pause => &[S::Active, S::Degraded],
            Self::Resume => &[S::Paused],
            Self::Suspend => &[S::Active, S::Degraded, S::Paused],
            Self::Reinstate => &[S::Suspended],
            Self::EnterDormancy => &[S::Active, S::Paused],
            Self::Wake => &[S::Dormant],
            Self::BeginRecovery => &[S::Degraded, S::Suspended, S::Quarantined],
            Self::CompleteRecovery => &[S::Recovering],
            Self::Quarantine => &[S::Active, S::Degraded, S::Paused, S::Recovering],
            Self::ReleaseQuarantine => &[S::Quarantined],
            Self::Retire => &[S::Active, S::Paused, S::Suspended, S::Dormant],
            Self::Archive => &[S::Retired],
            Self::Revoke => &[
                S::Active,
                S::Degraded,
                S::Paused,
                S::Suspended,
                S::Dormant,
                S::Recovering,
                S::Quarantined,
                S::Retired,
                S::Archived,
            ],
            Self::Decommission => &[S::Retired, S::Archived, S::Revoked],
        }
    }

    /// Resulting status, exactly mirroring the canon table.
    pub fn resulting_status(self) -> ProtectedLifecycleStatus {
        use ProtectedLifecycleStatus as S;
        match self {
            Self::Pause => S::Paused,
            Self::Resume | Self::Reinstate | Self::Wake | Self::CompleteRecovery
            | Self::ReleaseQuarantine => S::Active,
            Self::Suspend => S::Suspended,
            Self::EnterDormancy => S::Dormant,
            Self::BeginRecovery => S::Recovering,
            Self::Quarantine => S::Quarantined,
            Self::Retire => S::Retired,
            Self::Archive => S::Archived,
            Self::Revoke => S::Revoked,
            Self::Decommission => S::Decommissioned,
        }
    }

    /// Whether this op may lawfully leave `predecessor`.
    pub fn admits_predecessor(self, predecessor: ProtectedLifecycleStatus) -> bool {
        self.legal_predecessors().contains(&predecessor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_op_round_trips_its_canonical_name_and_scope() {
        for op in ProtectedTransitionOp::ALL {
            assert_eq!(ProtectedTransitionOp::parse(op.as_str()), Some(op));
            assert_eq!(
                op.required_scope(),
                format!("scope:autonomous_system.lifecycle.{}", op.as_str()),
            );
        }
    }

    #[test]
    fn scopes_are_distinct_per_op_and_disjoint_from_bootstrap() {
        let mut scopes: Vec<&str> = ProtectedTransitionOp::ALL
            .into_iter()
            .map(ProtectedTransitionOp::required_scope)
            .collect();
        scopes.sort_unstable();
        scopes.dedup();
        assert_eq!(scopes.len(), 14, "every op owns a distinct scope");
        assert!(!scopes.contains(&"scope:autonomous_system.lifecycle.initialize"));
        assert!(!scopes.contains(&"scope:autonomous_system.lifecycle.activate"));
    }

    #[test]
    fn degraded_is_observed_only_and_never_a_result() {
        for op in ProtectedTransitionOp::ALL {
            assert_ne!(
                op.resulting_status(),
                ProtectedLifecycleStatus::Degraded,
                "{} must not target the observed degraded posture",
                op.as_str(),
            );
        }
    }

    #[test]
    fn irreversibility_classes_match_canon() {
        use ProtectedTransitionOp as O;
        use TransitionIrreversibility as I;
        for op in O::ALL {
            let expected = match op {
                O::Retire | O::Archive | O::Revoke => I::OneWay,
                O::Decommission => I::Terminal,
                _ => I::Reversible,
            };
            assert_eq!(op.irreversibility(), expected, "{}", op.as_str());
        }
    }

    #[test]
    fn terminal_states_admit_no_further_ops_except_the_canon_end_of_life_arcs() {
        use ProtectedLifecycleStatus as S;
        for op in ProtectedTransitionOp::ALL {
            assert!(
                !op.admits_predecessor(S::Decommissioned),
                "decommissioned is terminal; {} must not leave it",
                op.as_str(),
            );
        }
        // archived and revoked continue only into decommission.
        for op in ProtectedTransitionOp::ALL {
            if op != ProtectedTransitionOp::Decommission {
                assert!(
                    !op.admits_predecessor(S::Archived) || op == ProtectedTransitionOp::Revoke,
                    "archived continues only into revoke or decommission, not {}",
                    op.as_str(),
                );
                assert!(
                    !op.admits_predecessor(S::Revoked),
                    "revoked continues only into decommission, not {}",
                    op.as_str(),
                );
            }
        }
    }

    #[test]
    fn legality_matrix_matches_the_canon_table_exactly() {
        // One row per canon table line; any drift here must be a deliberate
        // canon change first.
        let canon: &[(&str, &[&str], &str)] = &[
            ("pause", &["active", "degraded"], "paused"),
            ("resume", &["paused"], "active"),
            ("suspend", &["active", "degraded", "paused"], "suspended"),
            ("reinstate", &["suspended"], "active"),
            ("enter_dormancy", &["active", "paused"], "dormant"),
            ("wake", &["dormant"], "active"),
            (
                "begin_recovery",
                &["degraded", "suspended", "quarantined"],
                "recovering",
            ),
            ("complete_recovery", &["recovering"], "active"),
            (
                "quarantine",
                &["active", "degraded", "paused", "recovering"],
                "quarantined",
            ),
            ("release_quarantine", &["quarantined"], "active"),
            (
                "retire",
                &["active", "paused", "suspended", "dormant"],
                "retired",
            ),
            ("archive", &["retired"], "archived"),
            (
                "revoke",
                &[
                    "active",
                    "degraded",
                    "paused",
                    "suspended",
                    "dormant",
                    "recovering",
                    "quarantined",
                    "retired",
                    "archived",
                ],
                "revoked",
            ),
            ("decommission", &["retired", "archived", "revoked"], "decommissioned"),
        ];
        assert_eq!(canon.len(), ProtectedTransitionOp::ALL.len());
        for (name, predecessors, result) in canon {
            let op = ProtectedTransitionOp::parse(name).expect(name);
            let actual: Vec<&str> = op
                .legal_predecessors()
                .iter()
                .map(|status| status.as_str())
                .collect();
            assert_eq!(&actual, predecessors, "{name} predecessors");
            assert_eq!(op.resulting_status().as_str(), *result, "{name} result");
        }
    }
}
