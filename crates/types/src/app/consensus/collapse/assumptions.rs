// AFT-CB R6 — the assumption lattice (T6): every certificate profile
// carries a machine-readable assumption label; composition reports the
// MEET — the weakest finality-bearing constituent's rank, the UNION of
// consumed assumptions, and the AND of the `pq` bit. Trust composition
// becomes type-checked: adding a certificate profile without a label is
// a compile error (the wildcard-free match in [`label_of`]), and a
// collapse object's effective guarantee is exactly what its weakest
// finality-bearing part earned — never what a caller hoped, and never
// weaker than truth either: an evidence-only constituent (a continuity
// binding, a typed root) contributes its assumptions and its `pq` bit
// but claims no finality, so it can neither grant a rank nor be blamed
// for one.
//
// Rider (C9, the finality menu): per-effect typed finality classes with
// the assumption vector recorded on receipts, so applications choose
// finality explicitly and receipts prove which class authorized each
// effect (spec §19).
//
// The ledger ids mirror whitepaper §5.3 (A1–A10). A10 appears here for
// completeness of the id space; no shipped profile cites it (the
// succession extension is design-open — three formulations refuted; see
// the AFT-CB program record).

use std::collections::BTreeSet;

/// The assumption-ledger ids (whitepaper §5.3, A1–A10).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum AssumptionId {
    /// Cryptographic primitives (collision-resistant hashing, EUF-CMA
    /// signatures) are unbroken.
    A1,
    /// Minimal Honesty Axiom: at least one boundary member is honest.
    A2,
    /// Journal-guarded single-final-ack discipline holds per member.
    A3,
    /// Retriever reach: published bulletin objects are fetchable by the
    /// parties the protocol obliges to fetch them.
    A4,
    /// Live-tier weight + partial-synchrony bounds over the honest mesh.
    A5,
    /// The deployed freshness anchor is live and unequivocating.
    A6,
    /// Bond and slashing values are economically binding.
    A7,
    /// Custody storage integrity over the retention window.
    A8,
    /// Physical-time drift bound for the VDF succession clock.
    A9,
    /// Succession-path observation (PROVISIONAL — no shipped profile may
    /// cite it while §16 is design-open).
    A10,
}

/// Strength rank of a finality guarantee, ordered weakest-first so the
/// MEET is the minimum. A rank names what the constituent's own theorem
/// earns — never what a stronger sibling earns beside it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum GuaranteeRank {
    /// Observational finality only: honest-majority-of-observers class
    /// evidence (observer reports, witness lanes). Gates nothing above
    /// its own lane.
    Observational,
    /// Live-tier BFT finality under the engine's weight + synchrony
    /// bounds (A5-class).
    LiveTierBft,
    /// Sealed all-but-one boundary finality (the UBC ladder: A1+A2+A3).
    SealedAllButOne,
    /// Sealed and bound into the deployed freshness anchor (adds A6).
    SealedAnchored,
}

/// A certificate profile's assumption label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssumptionLabel {
    /// The finality rank this certificate can support on its own, or
    /// `None` for evidence-only constituents (continuity bindings, typed
    /// roots): they contribute assumptions and the `pq` bit but claim no
    /// finality, so they neither grant nor degrade a rank.
    pub finality_rank: Option<GuaranteeRank>,
    /// The assumption-ledger entries this certificate consumes.
    pub assumes: BTreeSet<AssumptionId>,
    /// True only when EVERY cryptographic primitive in this profile's
    /// verification chain is post-quantum.
    pub pq: bool,
}

/// Every certificate profile that can constitute a collapse object or a
/// finality-receipt basis. EXHAUSTIVE: [`label_of`] matches without a
/// wildcard, so adding a profile here without deciding its label is a
/// compile error — that is the T6 mechanism, not a style preference.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum CertificateProfile {
    /// Live-tier quorum certificate (pairing/BLS-class aggregate).
    LiveQuorumCert,
    /// Guardian committee certificate bound to a proposal (ed25519).
    GuardianCommitteeCert,
    /// Witness certificate (witness-augmented lanes).
    WitnessCert,
    /// Observer sealing countersignature (advisory observation lane).
    ObserverCert,
    /// Unanimous Boundary Close (n-of-n, attribution-preserving).
    UnanimousBoundaryClose,
    /// A UBC whose seal is additionally bound into the deployed
    /// freshness anchor. A single profile on purpose: a meet can only
    /// report the weakest constituent, so an UPGRADE (seal + anchor)
    /// must arrive as one certificate, never as a composition.
    AnchoredBoundaryClose,
    /// The labeled non-succinct reference continuity binding (HashPcdV1).
    /// Evidence-only: it binds history under A1; it finalizes nothing.
    HashPcdReference,
    /// An anchored re-genesis root record. A root, never continuity and
    /// never finality: the new lineage's finality comes from the new
    /// lineage's own certificates (spec §14).
    RegenesisRoot,
}

impl CertificateProfile {
    /// Every variant, for census-style iteration. [`label_of`]'s
    /// wildcard-free match is the completeness gate for labels; the
    /// `certificate_profile_all_is_exhaustive` test pins this list's
    /// length so a new variant must be added here too.
    pub const ALL: [CertificateProfile; 8] = [
        CertificateProfile::LiveQuorumCert,
        CertificateProfile::GuardianCommitteeCert,
        CertificateProfile::WitnessCert,
        CertificateProfile::ObserverCert,
        CertificateProfile::UnanimousBoundaryClose,
        CertificateProfile::AnchoredBoundaryClose,
        CertificateProfile::HashPcdReference,
        CertificateProfile::RegenesisRoot,
    ];
}

/// The single authority on what each profile's label is.
pub fn label_of(profile: CertificateProfile) -> AssumptionLabel {
    use AssumptionId::*;
    use CertificateProfile::*;
    use GuaranteeRank::*;
    match profile {
        LiveQuorumCert => AssumptionLabel {
            finality_rank: Some(LiveTierBft),
            assumes: BTreeSet::from([A1, A5]),
            // Pairing-based aggregate signatures: not post-quantum.
            pq: false,
        },
        GuardianCommitteeCert => AssumptionLabel {
            finality_rank: Some(LiveTierBft),
            assumes: BTreeSet::from([A1, A5]),
            // ed25519: not post-quantum.
            pq: false,
        },
        WitnessCert => AssumptionLabel {
            finality_rank: Some(Observational),
            assumes: BTreeSet::from([A1]),
            pq: false,
        },
        ObserverCert => AssumptionLabel {
            finality_rank: Some(Observational),
            assumes: BTreeSet::from([A1, A4]),
            pq: false,
        },
        UnanimousBoundaryClose => AssumptionLabel {
            finality_rank: Some(SealedAllButOne),
            assumes: BTreeSet::from([A1, A2, A3]),
            pq: false,
        },
        AnchoredBoundaryClose => AssumptionLabel {
            finality_rank: Some(SealedAnchored),
            assumes: BTreeSet::from([A1, A2, A3, A6]),
            pq: false,
        },
        HashPcdReference => AssumptionLabel {
            // Evidence-only: an honest hash binding under A1 — sound
            // continuity, no finality claim (the Q6 disposition).
            finality_rank: None,
            assumes: BTreeSet::from([A1]),
            // Hash-only construction: post-quantum.
            pq: true,
        },
        RegenesisRoot => AssumptionLabel {
            // Evidence-only: a typed root records the anchored basis of
            // a NEW lineage; it finalizes nothing in any lineage.
            finality_rank: None,
            assumes: BTreeSet::from([A1, A2, A3, A6]),
            pq: false,
        },
    }
}

/// The effective guarantee of a composition: minimum rank over the
/// finality-bearing constituents, UNION of all consumed assumptions
/// (consuming more is weaker), AND of `pq` over ALL constituents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveGuarantee {
    /// `None` when no constituent bears finality: an evidence-only
    /// composition has NO finality rank, and callers must treat that as
    /// a refusal, never a default.
    pub rank: Option<GuaranteeRank>,
    /// Union of every assumption-ledger entry the composition consumes.
    pub assumes: BTreeSet<AssumptionId>,
    /// AND of every constituent's `pq` bit.
    pub pq: bool,
    /// The profiles that produced this meet, for receipts and forensics.
    pub constituents: BTreeSet<CertificateProfile>,
}

/// Computes the meet over a non-empty composition. Returns `None` for an
/// empty composition: an object with no labeled constituent has no
/// guarantee at all — not even an evidence-only one.
pub fn assumption_meet(profiles: &[CertificateProfile]) -> Option<EffectiveGuarantee> {
    if profiles.is_empty() {
        return None;
    }
    let mut rank: Option<GuaranteeRank> = None;
    let mut assumes = BTreeSet::new();
    let mut pq = true;
    for p in profiles {
        let l = label_of(*p);
        if let Some(r) = l.finality_rank {
            rank = Some(match rank {
                Some(current) if current <= r => current,
                _ => r,
            });
        }
        assumes.extend(l.assumes);
        pq = pq && l.pq;
    }
    Some(EffectiveGuarantee {
        rank,
        assumes,
        pq,
        constituents: profiles.iter().copied().collect(),
    })
}

/// The finality menu (spec §19): per-effect typed classes. Applications
/// choose explicitly; receipts prove which class authorized each effect.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum FinalityClass {
    /// Live-tier BFT finality (seconds-class, cheapest).
    LiveQc,
    /// UBC super-finality (seal cadence, bond-backed).
    Sealed,
    /// Sealed plus the deployed freshness anchor (dearest).
    SealedAnchored,
}

/// The minimum rank each finality class honestly requires.
pub fn required_rank(class: FinalityClass) -> GuaranteeRank {
    match class {
        FinalityClass::LiveQc => GuaranteeRank::LiveTierBft,
        FinalityClass::Sealed => GuaranteeRank::SealedAllButOne,
        FinalityClass::SealedAnchored => GuaranteeRank::SealedAnchored,
    }
}

/// A finality receipt: the self-contained statement of what was trusted
/// when an effect was authorized. Constructed only through
/// [`FinalityReceipt::issue`], which refuses a class the composition's
/// meet cannot honestly support — there is no downgrade-and-issue path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityReceipt {
    /// The finality class that authorized the effect.
    pub class: FinalityClass,
    /// The full assumption vector of the authorizing composition.
    pub guarantee: EffectiveGuarantee,
    /// Declared latency parameter for the class at issue time (ms).
    pub declared_latency_ms: u64,
    /// Declared price parameter for the class at issue time (integer
    /// milliunits of the deployment's billing currency).
    pub declared_price_milliunits: u64,
}

impl FinalityReceipt {
    /// Issues a receipt iff the composition's meet supports the class.
    pub fn issue(
        class: FinalityClass,
        profiles: &[CertificateProfile],
        declared_latency_ms: u64,
        declared_price_milliunits: u64,
    ) -> Result<FinalityReceipt, FinalityRefusal> {
        let guarantee =
            assumption_meet(profiles).ok_or(FinalityRefusal::EmptyComposition)?;
        let achieved = guarantee.rank.ok_or(FinalityRefusal::NoFinalityBearer)?;
        if achieved < required_rank(class) {
            return Err(FinalityRefusal::RankBelowClass { class, achieved });
        }
        Ok(FinalityReceipt {
            class,
            guarantee,
            declared_latency_ms,
            declared_price_milliunits,
        })
    }
}

/// Typed refusals for finality issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityRefusal {
    /// No labeled constituent at all: nothing exists to grade.
    EmptyComposition,
    /// Every constituent is evidence-only: no finality claim exists.
    NoFinalityBearer,
    /// The composition's meet is below the requested class.
    RankBelowClass {
        /// The finality class that was requested.
        class: FinalityClass,
        /// The rank the composition's meet actually achieved.
        achieved: GuaranteeRank,
    },
}

impl CanonicalCollapseObject {
    /// The certificate profiles this collapse object's SHAPE claims as
    /// its finality basis, derived from its populated parts — never from
    /// a caller's assertion. Advisory observation is NOT basis: a sealed
    /// slot's finality rests on the UBC alone (the two-tier separation),
    /// so observer countersignatures never appear here. Verifying that
    /// the claimed parts are themselves valid remains the collapse
    /// validators' job — this derivation grades, it does not verify.
    pub fn constituent_profiles(&self) -> Vec<CertificateProfile> {
        let mut profiles = vec![CertificateProfile::HashPcdReference];
        if self.sealing.is_some() {
            profiles.push(CertificateProfile::UnanimousBoundaryClose);
        } else {
            profiles.push(CertificateProfile::GuardianCommitteeCert);
        }
        profiles
    }

    /// The collapse object's effective guarantee: the meet over its
    /// shape-derived constituents.
    pub fn effective_guarantee(&self) -> Option<EffectiveGuarantee> {
        assumption_meet(&self.constituent_profiles())
    }
}
