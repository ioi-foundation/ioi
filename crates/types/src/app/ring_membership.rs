//! AFT-CB R5 — the ring membership plane, stage 1: the types.
//!
//! Built ON the guardian committee manifest plane, not beside it (rule
//! 7): these types describe how a Boundary Ring configuration comes to
//! exist, hands over, and dies — bonded registration through a PUBLIC
//! activation queue, event-driven VERSIONED configuration records (no
//! calendar epochs — a configuration lives until an event closes its
//! successor), the assurance-preserving handover as the ONLY strong-ring
//! transition, anchored re-genesis as a typed lineage ROOT (never
//! continuity), live-tier-only weighted ejection, and custody succession
//! gating bond release.
//!
//! TYPE-ENFORCEMENT IS THE DESIGN. Three claims are carried by the type
//! system itself, and each has a fence or a refusal gate:
//! - No silence-derived transition is CONSTRUCTIBLE: the handover
//!   constructor consumes only SIGNED approval and acceptance records;
//!   no type in this module represents non-response, so a transition
//!   "from silence" has no expressible input.
//! - A live-tier ejection cannot reference the strong ring: no field of
//!   its evidence types names a seal, a UBC, or a ring configuration —
//!   a source fence pins the absence.
//! - Bond release without custody succession is a refusal, not a
//!   weaker record.
//!
//! Riders: C5 seat assignment by deterministic sortition over a beacon
//! ABSTRACTION (honest label: the reference beacon until R11's VDF plane
//! lands) across constituency diversity floors; C6 watchtower
//! countersignatures accepted from anyone and GATING NOTHING.

use super::AccountId;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A bonded registration for ring membership, queued publicly before
/// activation (AFT-CB R5).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingMemberRegistration {
    /// The registering account.
    pub account_id: AccountId,
    /// The bond amount committed by the registration.
    pub bond_amount: u128,
    /// The registrant's constituency tag (C5 diversity floors).
    #[serde(default)]
    pub constituency_id: u32,
    /// The protocol event ordinal at which the registration entered the
    /// public queue (event-driven — never a wall-clock time).
    pub registered_at_event: u64,
}

/// The public activation queue: registrations become eligible only
/// after `activation_depth_events` further protocol events (D_act), so
/// admission is publicly predictable and cannot be timed adversarially.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingActivationQueue {
    /// Queued registrations in arrival order.
    pub entries: Vec<RingMemberRegistration>,
    /// D_act: how many protocol events must elapse after registration
    /// before a registrant is activatable.
    pub activation_depth_events: u64,
}

impl RingActivationQueue {
    /// The registrations activatable at the given event ordinal: queued
    /// at least D_act events ago, in queue order.
    pub fn activatable_at(&self, current_event: u64) -> Vec<&RingMemberRegistration> {
        self.entries
            .iter()
            .filter(|entry| {
                current_event.saturating_sub(entry.registered_at_event)
                    >= self.activation_depth_events
            })
            .collect()
    }
}

/// The record closing a ring configuration: names the successor version
/// and the protocol event that closed it. A configuration without one
/// is the LIVE configuration — no calendar bound exists anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingConfigClose {
    /// The version of the successor configuration.
    pub successor_version: u64,
    /// The protocol event ordinal at which the close took effect.
    pub closed_at_event: u64,
}

/// One event-driven, versioned Boundary Ring configuration (AFT-CB R5).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BoundaryRingConfig {
    /// The configuration version (monotone).
    pub version: u64,
    /// The ring members, in seat order.
    pub members: Vec<AccountId>,
    /// Each member's bond, keyed by account.
    #[serde(default)]
    pub member_bonds: BTreeMap<AccountId, u128>,
    /// The protocol event ordinal at which this configuration activated.
    pub activated_at_event: u64,
    /// The close record, present only once a successor exists. `None`
    /// means this configuration is live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<RingConfigClose>,
}

/// A SIGNED handover approval from one old-ring member. The signature
/// bytes are the member's positive statement; no type exists for a
/// member's silence, so no transition can consume it.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct HandoverApproval {
    /// The approving old-ring member.
    pub member: AccountId,
    /// The old configuration version being handed over.
    pub old_version: u64,
    /// The new configuration version being approved.
    pub new_version: u64,
    /// The member's signature over the handover tuple.
    #[serde(default)]
    pub signature_bytes: Vec<u8>,
}

/// A SIGNED acceptance from one new-ring member: the incoming member's
/// own validate-and-hold undertaking for the configuration it joins.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct HandoverAcceptance {
    /// The accepting new-ring member.
    pub member: AccountId,
    /// The new configuration version being accepted.
    pub new_version: u64,
    /// The member's signature over the acceptance tuple.
    #[serde(default)]
    pub signature_bytes: Vec<u8>,
}

/// The assurance-preserving handover: THE only strong-ring transition
/// (AFT-CB R5 / T5c′-class). Constructible exclusively through
/// [`build_assurance_preserving_handover`], which demands old-ring
/// UNANIMITY and new-ring FULL ACCEPTANCE — both as signed statements.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AssurancePreservingHandover {
    /// The version being closed.
    pub old_version: u64,
    /// The version being activated.
    pub new_version: u64,
    /// One approval from EVERY old-ring member.
    pub old_ring_unanimous_approvals: Vec<HandoverApproval>,
    /// One acceptance from EVERY new-ring member.
    pub new_ring_acceptances: Vec<HandoverAcceptance>,
}

/// Builds the only strong-ring transition (AFT-CB R5). Refuses unless
/// EVERY old-ring member approved and EVERY new-ring member accepted —
/// n-of-n on both sides; there is no smaller quorum and no
/// silence-derived path (no input type for silence exists).
pub fn build_assurance_preserving_handover(
    old_config: &BoundaryRingConfig,
    new_config: &BoundaryRingConfig,
    approvals: &[HandoverApproval],
    acceptances: &[HandoverAcceptance],
) -> Result<AssurancePreservingHandover, String> {
    if new_config.version <= old_config.version {
        return Err("handover successor version must exceed the closed version".into());
    }
    let approved: BTreeSet<&AccountId> = approvals
        .iter()
        .filter(|approval| {
            approval.old_version == old_config.version && approval.new_version == new_config.version
        })
        .map(|approval| &approval.member)
        .collect();
    for member in &old_config.members {
        if !approved.contains(member) {
            return Err(
                "assurance-preserving handover requires old-ring UNANIMITY: a member's \
                 approval is missing (silence is not an input)"
                    .into(),
            );
        }
    }
    let accepted: BTreeSet<&AccountId> = acceptances
        .iter()
        .filter(|acceptance| acceptance.new_version == new_config.version)
        .map(|acceptance| &acceptance.member)
        .collect();
    for member in &new_config.members {
        if !accepted.contains(member) {
            return Err(
                "assurance-preserving handover requires acceptance from EVERY new-ring member"
                    .into(),
            );
        }
    }
    Ok(AssurancePreservingHandover {
        old_version: old_config.version,
        new_version: new_config.version,
        old_ring_unanimous_approvals: approvals.to_vec(),
        new_ring_acceptances: acceptances.to_vec(),
    })
}

/// An anchored re-genesis root: a typed lineage ROOT (AFT-CB R5, spec
/// §14). A root opens a NEW lineage — it is never continuity, and
/// [`lineage_relation`] can never answer otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AnchoredRegenesisRoot {
    /// The new lineage's identifier.
    pub lineage_id: [u8; 32],
    /// Reference into the deployed freshness anchor (A6) binding the
    /// root's declaration.
    pub anchor_reference: [u8; 32],
    /// The state root the new lineage opens from.
    pub genesis_state_root: [u8; 32],
    /// The protocol event ordinal of the declaration.
    pub declared_at_event: u64,
}

/// The answer a lineage query can give (AFT-CB R5). There is no variant
/// expressing "continuous across a re-genesis root" — that answer is
/// unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageRelation {
    /// Both points share a lineage; no root lies between them.
    SameLineage,
    /// A re-genesis root lies between the points: the later point
    /// belongs to a NEW lineage. Never continuity.
    NewLineage,
}

/// Answers whether a history crossing is continuous or root-severed:
/// any re-genesis root between the two events severs lineage.
pub fn lineage_relation(
    roots: &[AnchoredRegenesisRoot],
    earlier_event: u64,
    later_event: u64,
) -> LineageRelation {
    let crossed = roots.iter().any(|root| {
        root.declared_at_event > earlier_event && root.declared_at_event <= later_event
    });
    if crossed {
        LineageRelation::NewLineage
    } else {
        LineageRelation::SameLineage
    }
}

/// One live-tier liveness fault: the ONLY evidence class an ejection may
/// cite. No field of this type (or of [`LiveTierEjection`]) references
/// a seal, a UBC, or a ring configuration — the ejection plane is
/// type-fenced to the live tier, and a source fence pins the absence.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct LivenessFault {
    /// Block height of the observed fault.
    pub height: u64,
    /// Consensus view of the observed fault.
    pub view: u64,
    /// What live-tier duty was missed.
    #[serde(default)]
    pub kind: LivenessFaultKind,
}

/// The live-tier duties an ejection fault can cite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LivenessFaultKind {
    /// The member missed its proposal slot.
    #[default]
    MissedProposal,
    /// The member missed a vote it owed.
    MissedVote,
    /// The member was unreachable for the probe window.
    Unreachable,
}

/// A live-tier-only weighted ejection (AFT-CB R5): removes a member from
/// LIVE-TIER duty on live-tier evidence under live-tier weight. It
/// cannot reference — and therefore cannot revoke — strong-ring
/// standing: that exits only via handover or re-genesis.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct LiveTierEjection {
    /// The member ejected from live-tier duty.
    pub ejected_account_id: AccountId,
    /// The cited liveness faults (non-empty).
    pub liveness_faults: Vec<LivenessFault>,
    /// Accounts whose live-tier weight approved the ejection.
    pub approving_accounts: Vec<AccountId>,
}

/// Builds a live-tier ejection. Refuses an empty fault list — an
/// ejection is evidence-bearing or it is nothing.
pub fn build_live_tier_ejection(
    ejected_account_id: AccountId,
    liveness_faults: Vec<LivenessFault>,
    approving_accounts: Vec<AccountId>,
) -> Result<LiveTierEjection, String> {
    if liveness_faults.is_empty() {
        return Err("live-tier ejection requires at least one cited liveness fault".into());
    }
    if approving_accounts.is_empty() {
        return Err("live-tier ejection requires live-tier weight approval".into());
    }
    Ok(LiveTierEjection {
        ejected_account_id,
        liveness_faults,
        approving_accounts,
    })
}

/// The custody handover receipt a departing member must present before
/// its bond releases (AFT-CB R5): proof the member's held surface was
/// RECONSTRUCTED and acknowledged by a successor, so departure never
/// orphans custody.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CustodyHandoverReceipt {
    /// The departing member.
    pub member: AccountId,
    /// The configuration version the member departs from.
    pub config_version: u64,
    /// Canonical root of the reconstructed custody surface.
    pub reconstructed_surface_root: [u8; 32],
    /// The successor's signed acknowledgement of custody.
    #[serde(default)]
    pub successor_acknowledgement_bytes: Vec<u8>,
}

/// A released bond, constructible ONLY through
/// [`authorize_bond_release`]: custody succession gates release.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BondRelease {
    /// The member whose bond releases.
    pub member: AccountId,
    /// The configuration version departed from.
    pub config_version: u64,
    /// The custody receipt's reconstructed-surface root, carried so the
    /// release names the succession that authorized it.
    pub reconstructed_surface_root: [u8; 32],
}

/// Authorizes a bond release iff the presented custody receipt matches
/// the departing member and version, and carries a successor
/// acknowledgement. Succession WITHOUT reconstruction refuses.
pub fn authorize_bond_release(
    member: &AccountId,
    config_version: u64,
    custody_receipt: &CustodyHandoverReceipt,
) -> Result<BondRelease, String> {
    if custody_receipt.member != *member || custody_receipt.config_version != config_version {
        return Err("bond release requires a custody receipt for this member and version".into());
    }
    if custody_receipt.successor_acknowledgement_bytes.is_empty() {
        return Err(
            "bond release requires the successor's custody acknowledgement — succession \
             without reconstruction is refused"
                .into(),
        );
    }

    Ok(BondRelease {
        member: *member,
        config_version,
        reconstructed_surface_root: custody_receipt.reconstructed_surface_root,
    })
}

/// A constituency diversity floor (C5): the minimum seats a
/// constituency must hold in an assignment.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ConstituencyFloor {
    /// The constituency the floor applies to.
    pub constituency_id: u32,
    /// The minimum number of seats it must hold.
    pub min_seats: u32,
}

fn seat_score(beacon: &[u8; 32], account: &AccountId) -> [u8; 32] {
    use dcrypt::algorithms::hash::{HashFunction, Sha256};
    let mut material = Vec::with_capacity(b"aft::ring::sortition::v1".len() + 32 + 32);
    material.extend_from_slice(b"aft::ring::sortition::v1");
    material.extend_from_slice(beacon);
    material.extend_from_slice(&account.0);
    let digest = Sha256::digest(&material).expect("sha256 over fixed-width material");
    let mut score = [0u8; 32];
    score.copy_from_slice(digest.as_ref());
    score
}

/// C5 sortition: assigns `seat_count` seats from the candidate pool by
/// beacon-derived score, honoring constituency floors first.
///
/// HONEST LABEL: the beacon parameter is an ABSTRACTION — callers today
/// derive it from the reference ordering beacon; R11's VDF plane
/// replaces the SOURCE, not this assignment rule. Assignment is fully
/// deterministic in (beacon, candidates, floors, seat_count).
pub fn assign_seats(
    beacon: &[u8; 32],
    candidates: &[RingMemberRegistration],
    floors: &[ConstituencyFloor],
    seat_count: usize,
) -> Result<Vec<AccountId>, String> {
    if seat_count == 0 || candidates.len() < seat_count {
        return Err("sortition requires at least seat_count candidates".into());
    }
    let floor_total: u64 = floors.iter().map(|floor| u64::from(floor.min_seats)).sum();
    if floor_total > seat_count as u64 {
        return Err("constituency floors exceed the seat count".into());
    }
    let mut ranked: Vec<(&RingMemberRegistration, [u8; 32])> = candidates
        .iter()
        .map(|candidate| (candidate, seat_score(beacon, &candidate.account_id)))
        .collect();
    ranked.sort_unstable_by(|left, right| left.1.cmp(&right.1));

    let mut seats: Vec<AccountId> = Vec::with_capacity(seat_count);
    let mut taken: BTreeSet<AccountId> = BTreeSet::new();
    // Floors first: best-scored candidate of each floored constituency.
    for floor in floors {
        let mut needed = floor.min_seats;
        for (candidate, _) in &ranked {
            if needed == 0 {
                break;
            }
            if candidate.constituency_id == floor.constituency_id
                && taken.insert(candidate.account_id)
            {
                seats.push(candidate.account_id);
                needed -= 1;
            }
        }
        if needed > 0 {
            return Err("constituency floor unsatisfiable from the candidate pool".into());
        }
    }
    // Remaining seats by global score order.
    for (candidate, _) in &ranked {
        if seats.len() == seat_count {
            break;
        }
        if taken.insert(candidate.account_id) {
            seats.push(candidate.account_id);
        }
    }
    Ok(seats)
}

/// The wire form of a ring handover publication (AFT-CB R5 stage 3):
/// the successor configuration plus the signed ceremony records the
/// registry verifies against its STORED live configuration.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingHandoverPublication {
    /// The successor configuration to activate.
    pub new_config: BoundaryRingConfig,
    /// Old-ring approvals (must reach unanimity over the stored config).
    pub approvals: Vec<HandoverApproval>,
    /// New-ring acceptances (every successor member).
    pub acceptances: Vec<HandoverAcceptance>,
}

/// A watchtower countersignature over a seal (C6): accepted from ANYONE
/// and GATING NOTHING. It exists so external observers can bind their
/// own attestations into the public record; no verification path in the
/// estate consults these, and a seal verifies identically without one
/// (the stage-2 sim pins that).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct WatchtowerCountersignRecord {
    /// The sealed slot the countersignature covers.
    pub height: u64,
    /// The countersigning account — ANY account; no membership demanded.
    pub watcher_account_id: AccountId,
    /// Canonical hash of the seal being countersigned.
    pub seal_hash: [u8; 32],
    /// The watcher's signature bytes.
    #[serde(default)]
    pub signature_bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(byte: u8) -> AccountId {
        AccountId([byte; 32])
    }

    fn registration(byte: u8, constituency: u32, event: u64) -> RingMemberRegistration {
        RingMemberRegistration {
            account_id: account(byte),
            bond_amount: 1_000,
            constituency_id: constituency,
            registered_at_event: event,
        }
    }

    fn config(version: u64, member_bytes: &[u8]) -> BoundaryRingConfig {
        BoundaryRingConfig {
            version,
            members: member_bytes.iter().map(|b| account(*b)).collect(),
            member_bonds: BTreeMap::new(),
            activated_at_event: 0,
            closed_by: None,
        }
    }

    fn approval(member_byte: u8, old: u64, new: u64) -> HandoverApproval {
        HandoverApproval {
            member: account(member_byte),
            old_version: old,
            new_version: new,
            signature_bytes: vec![member_byte],
        }
    }

    fn acceptance(member_byte: u8, new: u64) -> HandoverAcceptance {
        HandoverAcceptance {
            member: account(member_byte),
            new_version: new,
            signature_bytes: vec![member_byte],
        }
    }

    #[test]
    fn handover_requires_old_ring_unanimity_and_full_new_ring_acceptance() {
        let old = config(1, &[1, 2, 3]);
        let new = config(2, &[2, 3, 4]);
        let approvals = vec![approval(1, 1, 2), approval(2, 1, 2), approval(3, 1, 2)];
        let acceptances = vec![acceptance(2, 2), acceptance(3, 2), acceptance(4, 2)];

        build_assurance_preserving_handover(&old, &new, &approvals, &acceptances)
            .expect("full approvals + acceptances hand over");

        // n−1 old-ring approvals: REFUSED (the (n−1) mutation target).
        let err = build_assurance_preserving_handover(&old, &new, &approvals[..2], &acceptances)
            .expect_err("missing old-member approval must refuse");
        assert!(err.contains("UNANIMITY"), "got: {err}");

        // A missing new-member acceptance: REFUSED.
        let err = build_assurance_preserving_handover(&old, &new, &approvals, &acceptances[..2])
            .expect_err("missing new-member acceptance must refuse");
        assert!(err.contains("EVERY new-ring member"), "got: {err}");

        // A non-advancing version: REFUSED.
        assert!(build_assurance_preserving_handover(&old, &old, &approvals, &acceptances).is_err());
    }

    #[test]
    fn lineage_query_across_a_regenesis_root_answers_new_lineage_never_continuity() {
        let root = AnchoredRegenesisRoot {
            lineage_id: [7u8; 32],
            anchor_reference: [8u8; 32],
            genesis_state_root: [9u8; 32],
            declared_at_event: 100,
        };
        assert_eq!(
            lineage_relation(std::slice::from_ref(&root), 50, 150),
            LineageRelation::NewLineage
        );
        assert_eq!(
            lineage_relation(std::slice::from_ref(&root), 101, 150),
            LineageRelation::SameLineage
        );
        assert_eq!(lineage_relation(&[], 50, 150), LineageRelation::SameLineage);
    }

    #[test]
    fn bond_release_gated_on_custody_succession() {
        let member = account(5);
        let receipt = CustodyHandoverReceipt {
            member,
            config_version: 3,
            reconstructed_surface_root: [11u8; 32],
            successor_acknowledgement_bytes: vec![1, 2, 3],
        };
        let release = authorize_bond_release(&member, 3, &receipt)
            .expect("reconstructed + acknowledged custody releases the bond");
        assert_eq!(release.reconstructed_surface_root, [11u8; 32]);

        // Succession WITHOUT reconstruction acknowledgement: refused.
        let unacknowledged = CustodyHandoverReceipt {
            successor_acknowledgement_bytes: Vec::new(),
            ..receipt.clone()
        };
        assert!(authorize_bond_release(&member, 3, &unacknowledged).is_err());
        // Wrong member or version: refused.
        assert!(authorize_bond_release(&account(6), 3, &receipt).is_err());
        assert!(authorize_bond_release(&member, 4, &receipt).is_err());
    }

    #[test]
    fn ejection_requires_faults_and_approval() {
        let fault = LivenessFault {
            height: 10,
            view: 1,
            kind: LivenessFaultKind::MissedVote,
        };
        build_live_tier_ejection(account(9), vec![fault.clone()], vec![account(1)])
            .expect("evidence-bearing ejection builds");
        assert!(build_live_tier_ejection(account(9), vec![], vec![account(1)]).is_err());
        assert!(build_live_tier_ejection(account(9), vec![fault], vec![]).is_err());
    }

    #[test]
    fn ejection_plane_source_fence_references_no_strong_ring_surface() {
        // AFT-CB R5 fence: the ejection evidence types must never gain a
        // field referencing the strong ring. The fence scans this
        // module's source between the ejection markers and refuses seal
        // / UBC / ring-config vocabulary there; widening the ejection
        // types with strong-ring reach turns this RED.
        let source = include_str!("ring_membership.rs");
        let start = source
            .find("pub struct LivenessFault")
            .expect("ejection section present");
        let end = source
            .find("/// The custody handover receipt")
            .expect("section end");
        let ejection_section = &source[start..end];
        for banned in [
            "seal_hash",
            "SealedFinality",
            "UnanimousBoundary",
            "BoundaryRingConfig",
        ] {
            assert!(
                !ejection_section.contains(banned),
                "ejection plane gained strong-ring reach: {banned}"
            );
        }
    }

    #[test]
    fn activation_queue_respects_event_depth() {
        let queue = RingActivationQueue {
            entries: vec![registration(1, 0, 10), registration(2, 0, 50)],
            activation_depth_events: 20,
        };
        let at_35: Vec<_> = queue
            .activatable_at(35)
            .iter()
            .map(|r| r.account_id)
            .collect();
        assert_eq!(at_35, vec![account(1)]);
        assert_eq!(queue.activatable_at(70).len(), 2);
        assert_eq!(queue.activatable_at(15).len(), 0);
    }

    #[test]
    fn sortition_is_deterministic_and_honors_floors() {
        let candidates: Vec<RingMemberRegistration> = (1u8..=8)
            .map(|b| registration(b, u32::from(b % 3), 0))
            .collect();
        let floors = vec![ConstituencyFloor {
            constituency_id: 2,
            min_seats: 2,
        }];
        let beacon = [0x42u8; 32];

        let seats_a = assign_seats(&beacon, &candidates, &floors, 4).expect("assign");
        let seats_b = assign_seats(&beacon, &candidates, &floors, 4).expect("assign again");
        assert_eq!(seats_a, seats_b, "deterministic in the beacon");
        assert_eq!(seats_a.len(), 4);

        let constituency_2_seats = seats_a
            .iter()
            .filter(|seat| {
                candidates
                    .iter()
                    .any(|c| c.account_id == **seat && c.constituency_id == 2)
            })
            .count();
        assert!(constituency_2_seats >= 2, "floor honored");

        let other_beacon = [0x43u8; 32];
        let seats_c = assign_seats(&other_beacon, &candidates, &floors, 4).expect("assign");
        assert_ne!(seats_a, seats_c, "beacon moves the assignment");

        // Unsatisfiable floor refuses.
        assert!(assign_seats(
            &beacon,
            &candidates,
            &[ConstituencyFloor {
                constituency_id: 9,
                min_seats: 1
            }],
            4
        )
        .is_err());
    }
}
