//! AFT-CB R5 stage 2 — the boundary-ring MEMBERSHIP simulator (n ≤ 8).
//!
//! Extends the estate's abstract-simulation idiom (state machines over
//! counts and records, not network executions) with a multi-member ring
//! driving the REAL stage-1 membership types: journal-guarded single
//! final-ack per member, n-of-n seal assembly over the LIVE ring
//! configuration, assurance-preserving handover as the only strong-ring
//! transition, typed re-genesis lineage severing, custody-gated bond
//! release, beacon sortition, and watchtower records that gate nothing.
//!
//! The five R5 sim gates live in this module's tests:
//! (a) one withholder freezes seal cadence while the live tier produces;
//! (b) three-Byzantine-of-four equivocation yields ZERO conflicting
//!     seals (uniqueness DERIVED from the honest journal, not enforced
//!     by the seal map);
//! (c) succession without reconstruction refuses bond release;
//! (d) handover end-to-end + lineage queries: handover preserves
//!     lineage, a re-genesis root severs it — never continuity;
//! (e) seat assignment reproduces deterministically from the beacon,
//!     and a seal verifies identically with and without watchtower
//!     countersignatures.

use ioi_types::app::{
    build_assurance_preserving_handover, AccountId, AssurancePreservingHandover,
    BoundaryRingConfig, HandoverAcceptance, HandoverApproval, RingConfigClose,
    WatchtowerCountersignRecord,
};
use std::collections::{BTreeMap, BTreeSet};

/// One simulated ring member: honesty flag and the A3 journal.
#[derive(Debug, Clone)]
pub struct SimMember {
    /// Whether the member follows the honest single-final-ack rule.
    pub honest: bool,
    /// The journal: slot → the ONE root this member final-acked.
    pub journal: BTreeMap<u64, [u8; 32]>,
    /// Whether the member is currently withholding acks entirely.
    pub withholding: bool,
}

/// The membership simulator state.
#[derive(Debug, Clone)]
pub struct BoundaryRingMembershipSim {
    /// The live ring configuration (seals need ITS n-of-n).
    pub config: BoundaryRingConfig,
    /// Closed predecessor configurations, by version.
    pub closed_configs: BTreeMap<u64, BoundaryRingConfig>,
    /// Member state, keyed by account.
    pub members: BTreeMap<AccountId, SimMember>,
    /// Final-ack shares in existence: (member, slot, root).
    pub acks: BTreeSet<(AccountId, u64, [u8; 32])>,
    /// Assembled seals: slot → every root sealed for it. Uniqueness is
    /// ASSERTED by the gates, never enforced here — the map can hold a
    /// conflict if the discipline fails, which is exactly what the
    /// drills probe.
    pub seals: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    /// The live tier's block height — advances independently of seals.
    pub live_tier_height: u64,
    /// Re-genesis roots declared during the run (event ordinals).
    pub regenesis_events: Vec<u64>,
    /// Watchtower countersignatures received (from ANYONE); nothing in
    /// this simulator reads them back.
    pub watchtower_records: Vec<WatchtowerCountersignRecord>,
    /// Monotone protocol-event counter.
    pub event_counter: u64,
}

impl BoundaryRingMembershipSim {
    /// Builds a simulator over a fresh configuration; `honest` flags
    /// align with `config.members` order.
    pub fn new(config: BoundaryRingConfig, honest: &[bool]) -> Result<Self, String> {
        if config.members.len() != honest.len() {
            return Err("honesty flags must cover every member".into());
        }
        if config.members.len() > 8 {
            return Err("the membership simulator models rings up to n = 8".into());
        }
        let members = config
            .members
            .iter()
            .zip(honest)
            .map(|(account, flag)| {
                (
                    *account,
                    SimMember {
                        honest: *flag,
                        journal: BTreeMap::new(),
                        withholding: false,
                    },
                )
            })
            .collect();
        Ok(Self {
            config,
            closed_configs: BTreeMap::new(),
            members,
            acks: BTreeSet::new(),
            seals: BTreeMap::new(),
            live_tier_height: 0,
            regenesis_events: Vec::new(),
            watchtower_records: Vec::new(),
            event_counter: 0,
        })
    }

    /// The live tier produces a block: ALWAYS possible — no seal rule
    /// appears in this path (two-tier separation).
    pub fn live_tier_produce(&mut self) -> u64 {
        self.live_tier_height += 1;
        self.event_counter += 1;
        self.live_tier_height
    }

    /// An honest member final-acks (slot, root) under the A3 journal
    /// guard: one root per slot, forever.
    pub fn honest_final_ack(
        &mut self,
        account: &AccountId,
        slot: u64,
        root: [u8; 32],
    ) -> Result<(), String> {
        let member = self
            .members
            .get_mut(account)
            .ok_or_else(|| "unknown member".to_string())?;
        if !member.honest {
            return Err("byzantine members do not use the honest ack path".into());
        }
        if member.withholding {
            return Err("member is withholding".into());
        }
        if let Some(journaled) = member.journal.get(&slot) {
            if *journaled != root {
                return Err("journal occupied: single final-ack discipline refuses".into());
            }
            return Ok(());
        }
        member.journal.insert(slot, root);
        self.acks.insert((*account, slot, root));
        self.event_counter += 1;
        Ok(())
    }

    /// A Byzantine member emits ANY share, any number of times — no
    /// journal binds it.
    pub fn byzantine_emit(
        &mut self,
        account: &AccountId,
        slot: u64,
        root: [u8; 32],
    ) -> Result<(), String> {
        let member = self
            .members
            .get(account)
            .ok_or_else(|| "unknown member".to_string())?;
        if member.honest {
            return Err("honest members cannot take the byzantine path".into());
        }
        self.acks.insert((*account, slot, root));
        self.event_counter += 1;
        Ok(())
    }

    /// Attempts to assemble a seal for (slot, root): n-of-n over the
    /// LIVE configuration — every current member's share must exist.
    pub fn try_seal(&mut self, slot: u64, root: [u8; 32]) -> Result<bool, String> {
        for account in &self.config.members {
            if !self.acks.contains(&(*account, slot, root)) {
                return Ok(false);
            }
        }
        self.seals.entry(slot).or_default().insert(root);
        self.event_counter += 1;
        Ok(true)
    }

    /// True iff any slot carries two different sealed roots — the
    /// disaster the uniqueness gates assert never happens.
    pub fn has_conflicting_seals(&self) -> bool {
        self.seals.values().any(|roots| roots.len() > 1)
    }

    /// Executes the assurance-preserving handover: the ONLY transition
    /// that replaces the strong ring. On success the old configuration
    /// closes and the new one becomes live (new members default honest
    /// and un-journaled).
    pub fn handover(
        &mut self,
        new_config: BoundaryRingConfig,
        approvals: &[HandoverApproval],
        acceptances: &[HandoverAcceptance],
    ) -> Result<AssurancePreservingHandover, String> {
        let handover =
            build_assurance_preserving_handover(&self.config, &new_config, approvals, acceptances)?;
        self.event_counter += 1;
        let mut closed = self.config.clone();
        closed.closed_by = Some(RingConfigClose {
            successor_version: new_config.version,
            closed_at_event: self.event_counter,
        });
        self.closed_configs.insert(closed.version, closed);
        for account in &new_config.members {
            self.members.entry(*account).or_insert(SimMember {
                honest: true,
                journal: BTreeMap::new(),
                withholding: false,
            });
        }
        self.config = new_config;
        Ok(handover)
    }

    /// Declares a re-genesis root at the current event ordinal.
    pub fn declare_regenesis(&mut self) -> u64 {
        self.event_counter += 1;
        self.regenesis_events.push(self.event_counter);
        self.event_counter
    }

    /// Records a watchtower countersignature — from ANYONE. Nothing in
    /// this simulator ever reads these back: they gate nothing.
    pub fn record_watchtower(&mut self, record: WatchtowerCountersignRecord) {
        self.watchtower_records.push(record);
    }
}

#[cfg(test)]
#[path = "ring_membership_sim/tests.rs"]
mod tests;
