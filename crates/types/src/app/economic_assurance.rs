//! Offline-verifiable economic assurance for AFT accountability evidence.
//!
//! This module proves only a floor on distinct collateral that an objective
//! accountability proof can slash. It deliberately does not price silence,
//! withholding, acquisition, bribery, liquidity, or validator supply.

use crate::app::consensus::{SlashableCollateralV1, VerifiedGuaranteeV1};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Domain separator for complete bond-snapshot commitments.
pub const BOND_SNAPSHOT_V1_DOMAIN: &[u8] = b"ioi::aft::bond-snapshot::v1\0";
/// Domain separator for the exact distinct collateral set selected by a proof.
pub const COLLATERAL_SET_V1_DOMAIN: &[u8] = b"ioi::aft::collateral-set::v1\0";
/// Domain separator for accountability-evidence commitments.
pub const ACCOUNTABILITY_EVIDENCE_V1_DOMAIN: &[u8] = b"ioi::aft::accountability-evidence::v1\0";
/// Domain separator for complete economic-assurance claims.
pub const ECONOMIC_ASSURANCE_V1_DOMAIN: &[u8] = b"ioi::aft::economic-assurance::v1\0";

/// Wire version for the M6 economic-assurance objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicAssuranceVersionV1 {
    /// Initial distinct-collateral proof schema.
    V1,
}

/// Objective behavior named by the slashing predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashableBehaviorV1 {
    /// Two incompatible signatures under one configuration and signing duty.
    ConflictingSignedStatements,
    /// A signed availability/resource assertion contradicted by its verifier.
    InvalidSignedAttestation,
    /// Absence of a message or signature. This is intentionally unpriceable.
    WithholdingOrSilence,
}

impl SlashableBehaviorV1 {
    fn is_objectively_priceable(self) -> bool {
        !matches!(self, Self::WithholdingOrSilence)
    }
}

/// Transferable evidence that names the members whose bonds are implicated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityEvidenceV1 {
    /// Schema discriminator.
    pub schema_version: EconomicAssuranceVersionV1,
    /// Exact consensus configuration in which the duty existed.
    pub configuration_hash: [u8; 32],
    /// Behavior established by the evidence verifier.
    pub behavior: SlashableBehaviorV1,
    /// Commitment to the executable evidence predicate.
    pub evidence_predicate_hash: [u8; 32],
    /// Commitment to the transferable proof bytes/transcript.
    pub evidence_hash: [u8; 32],
    /// Distinct configuration members named by the proof.
    pub implicated_members: BTreeSet<[u8; 32]>,
    /// End of the period in which the proof remains challengeable/slashable.
    pub challenge_horizon_end: u64,
}

impl AccountabilityEvidenceV1 {
    /// Domain-separated commitment to the complete evidence descriptor.
    pub fn commitment(&self) -> Result<[u8; 32], EconomicAssuranceError> {
        commitment(ACCOUNTABILITY_EVIDENCE_V1_DOMAIN, self)
    }
}

/// One bond as observed in the committed snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollateralBondV1 {
    /// Unique staking/bond record identifier.
    pub bond_id: [u8; 32],
    /// Unique underlying collateral-lot identifier. Distinct bond IDs that
    /// point at the same lot cannot be counted twice.
    pub collateral_id: [u8; 32],
    /// Configuration member exclusively controlling this bond.
    pub owner_member_hash: [u8; 32],
    /// Asset identifier; unlike assets are never summed.
    pub asset_id_hash: [u8; 32],
    /// Canonical unsigned decimal amount in base units.
    pub amount_base_units: String,
    /// Configuration for which this lot is exclusively slashable.
    pub exclusive_configuration_hash: [u8; 32],
    /// First height/time at which the lock is effective.
    pub locked_from: u64,
    /// Last height/time through which the lock is effective.
    pub locked_until: u64,
    /// Last height/time at which evidence can trigger the contract.
    pub challenge_horizon_end: u64,
    /// Exact objective evidence predicate accepted by the contract.
    pub evidence_predicate_hash: [u8; 32],
    /// Exact enforceable slashing contract/code identity.
    pub slashing_contract_hash: [u8; 32],
    /// Active claims on the same lot. Any entry makes the lot ineligible for
    /// this proof, rather than applying an unverifiable haircut.
    pub active_encumbrance_hashes: BTreeSet<[u8; 32]>,
    /// Whether withdrawal has already begun or completed.
    pub withdrawal_pending: bool,
}

/// Complete state view from which distinct collateral is selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondSnapshotV1 {
    /// Schema discriminator.
    pub schema_version: EconomicAssuranceVersionV1,
    /// Height/time at which locks and encumbrances were read.
    pub snapshot_height: u64,
    /// Configuration whose bonds are represented.
    pub configuration_hash: [u8; 32],
    /// Canonically ordered bonds. The verifier requires strictly increasing
    /// bond IDs so equivalent sets have one portable representation.
    pub bonds: Vec<CollateralBondV1>,
}

impl BondSnapshotV1 {
    /// Domain-separated root of the complete snapshot.
    pub fn commitment(&self) -> Result<[u8; 32], EconomicAssuranceError> {
        commitment(BOND_SNAPSHOT_V1_DOMAIN, self)
    }
}

/// Explicit conversion assumptions. Native-asset proofs leave this absent;
/// cross-asset displays must expose every oracle and validity assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValuationAssumptionsV1 {
    /// Asset in which the derived display value is denominated.
    pub quote_asset_id_hash: [u8; 32],
    /// Oracle/provider and aggregation-rule commitment.
    pub oracle_profile_hash: [u8; 32],
    /// Snapshot time of the observation.
    pub observed_at: u64,
    /// Last time at which the observation may be used.
    pub valid_until: u64,
    /// Canonical positive rational numerator.
    pub price_numerator: String,
    /// Canonical positive rational denominator.
    pub price_denominator: String,
}

/// Claimed output of the independent collateral verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicAssuranceV1 {
    /// Schema discriminator.
    pub schema_version: EconomicAssuranceVersionV1,
    /// Single asset whose base units are counted.
    pub asset_id_hash: [u8; 32],
    /// Exact distinct slashable floor in canonical unsigned decimal units.
    pub amount_base_units: String,
    /// Exact configuration implicated by the evidence.
    pub configuration_hash: [u8; 32],
    /// Commitment to the selected, distinct collateral lots.
    pub collateral_set_hash: [u8; 32],
    /// Commitment to the complete bond and encumbrance snapshot.
    pub bond_snapshot_root: [u8; 32],
    /// Height/time at which the snapshot was evaluated.
    pub snapshot_height: u64,
    /// Earliest lock expiry among all counted lots.
    pub locked_until: u64,
    /// Evidence challenge/slashing horizon.
    pub challenge_horizon_end: u64,
    /// Exact objective behavior and evidence-rule commitment.
    pub evidence_predicate: SlashableBehaviorV1,
    /// Commitment to the exact evidence predicate.
    pub evidence_predicate_hash: [u8; 32],
    /// Common slashing contract enforced by every counted lot.
    pub slashing_contract_hash: [u8; 32],
    /// Optional, fully visible conversion assumptions. They never change the
    /// native base-unit floor above.
    pub valuation_assumptions: Option<ValuationAssumptionsV1>,
}

impl EconomicAssuranceV1 {
    /// Portable domain-separated claim commitment.
    pub fn commitment(&self) -> Result<[u8; 32], EconomicAssuranceError> {
        commitment(ECONOMIC_ASSURANCE_V1_DOMAIN, self)
    }

    /// Project the verified claim into the guarantee-vector coordinate.
    fn coordinate(&self) -> Result<SlashableCollateralV1, EconomicAssuranceError> {
        let valuation_assumptions_hash = self
            .valuation_assumptions
            .as_ref()
            .map(|value| commitment(ECONOMIC_ASSURANCE_V1_DOMAIN, value))
            .transpose()?;
        Ok(SlashableCollateralV1 {
            asset_id_hash: self.asset_id_hash,
            amount_base_units: self.amount_base_units.clone(),
            collateral_set_hash: self.collateral_set_hash,
            bond_snapshot_root: self.bond_snapshot_root,
            locked_until: self.locked_until,
            evidence_rule_hash: self.evidence_predicate_hash,
            slashing_contract_hash: self.slashing_contract_hash,
            valuation_assumptions_hash,
        })
    }
}

/// Opaque result: only the independent verifier can create an assurance that
/// policy or a receipt may attach to a verified guarantee vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEconomicAssuranceV1 {
    assurance: EconomicAssuranceV1,
    proof_commitment: [u8; 32],
}

impl VerifiedEconomicAssuranceV1 {
    /// Borrow the exact verifier-derived assurance.
    pub fn assurance(&self) -> &EconomicAssuranceV1 {
        &self.assurance
    }

    /// Commitment that binds evidence, snapshot, and derived claim.
    pub fn proof_commitment(&self) -> [u8; 32] {
        self.proof_commitment
    }

    /// Add this independently verified coordinate to an already verified
    /// guarantee vector. The base vector cannot provide or strengthen it.
    pub fn attach_to(
        &self,
        base: &VerifiedGuaranteeV1,
    ) -> Result<VerifiedGuaranteeV1, EconomicAssuranceError> {
        let coordinate = self.assurance.coordinate()?;
        base.with_verified_collateral(coordinate, self.proof_commitment)
            .map_err(|error| EconomicAssuranceError::GuaranteeVector(error.to_string()))
    }
}

/// Stateless offline verifier for the M6 proof package.
#[derive(Debug, Default, Clone, Copy)]
pub struct EconomicAssuranceVerifierV1;

impl EconomicAssuranceVerifierV1 {
    /// Recompute the collateral floor and require byte-for-value equality with
    /// the claimed assurance. No caller-supplied amount is trusted.
    pub fn verify(
        evidence: &AccountabilityEvidenceV1,
        snapshot: &BondSnapshotV1,
        claimed: &EconomicAssuranceV1,
    ) -> Result<VerifiedEconomicAssuranceV1, EconomicAssuranceError> {
        validate_nonzero("configuration_hash", evidence.configuration_hash)?;
        validate_nonzero("evidence_predicate_hash", evidence.evidence_predicate_hash)?;
        validate_nonzero("evidence_hash", evidence.evidence_hash)?;
        if evidence.implicated_members.is_empty() {
            return Err(EconomicAssuranceError::NoImplicatedMembers);
        }
        if !evidence.behavior.is_objectively_priceable() {
            return Err(EconomicAssuranceError::UnpriceableBehavior);
        }
        if evidence.configuration_hash != snapshot.configuration_hash {
            return Err(EconomicAssuranceError::ConfigurationMismatch);
        }
        if snapshot.snapshot_height > evidence.challenge_horizon_end {
            return Err(EconomicAssuranceError::ChallengeHorizonExpired);
        }
        if snapshot.bonds.is_empty() {
            return Err(EconomicAssuranceError::NoCollateral);
        }

        let mut prior_bond = None;
        let mut collateral_ids = BTreeSet::new();
        let mut covered_members = BTreeSet::new();
        let mut amount = "0".to_string();
        let mut common_asset = None;
        let mut common_contract = None;
        let mut minimum_lock = u64::MAX;

        for bond in &snapshot.bonds {
            validate_bond(bond, evidence, snapshot.snapshot_height)?;
            if prior_bond.is_some_and(|prior| prior >= bond.bond_id) {
                return Err(EconomicAssuranceError::NonCanonicalOrDuplicateBond);
            }
            prior_bond = Some(bond.bond_id);
            if !collateral_ids.insert(bond.collateral_id) {
                return Err(EconomicAssuranceError::DuplicateCollateralLot);
            }
            if !evidence
                .implicated_members
                .contains(&bond.owner_member_hash)
            {
                return Err(EconomicAssuranceError::UnimplicatedBondOwner);
            }
            covered_members.insert(bond.owner_member_hash);
            common_asset = require_common(
                common_asset,
                bond.asset_id_hash,
                EconomicAssuranceError::MixedAssets,
            )?;
            common_contract = require_common(
                common_contract,
                bond.slashing_contract_hash,
                EconomicAssuranceError::MixedSlashingContracts,
            )?;
            amount = add_decimal(&amount, &bond.amount_base_units);
            minimum_lock = minimum_lock.min(bond.locked_until);
        }
        if covered_members != evidence.implicated_members {
            return Err(EconomicAssuranceError::MissingImplicatedMemberBond);
        }

        let bond_snapshot_root = snapshot.commitment()?;
        let collateral_set_hash = commitment(
            COLLATERAL_SET_V1_DOMAIN,
            &collateral_ids.iter().copied().collect::<Vec<_>>(),
        )?;
        let derived = EconomicAssuranceV1 {
            schema_version: EconomicAssuranceVersionV1::V1,
            asset_id_hash: common_asset.expect("non-empty snapshot established an asset"),
            amount_base_units: amount,
            configuration_hash: evidence.configuration_hash,
            collateral_set_hash,
            bond_snapshot_root,
            snapshot_height: snapshot.snapshot_height,
            locked_until: minimum_lock,
            challenge_horizon_end: evidence.challenge_horizon_end,
            evidence_predicate: evidence.behavior,
            evidence_predicate_hash: evidence.evidence_predicate_hash,
            slashing_contract_hash: common_contract
                .expect("non-empty snapshot established a slashing contract"),
            // Valuation is display metadata supplied by the claimant. Validate
            // and retain it, but never use it to inflate native units.
            valuation_assumptions: claimed.valuation_assumptions.clone(),
        };
        validate_valuation(
            derived.valuation_assumptions.as_ref(),
            snapshot.snapshot_height,
        )?;
        if &derived != claimed {
            return Err(EconomicAssuranceError::ClaimMismatch);
        }

        let evidence_hash = evidence.commitment()?;
        let assurance_hash = derived.commitment()?;
        let proof_commitment = commitment(
            ECONOMIC_ASSURANCE_V1_DOMAIN,
            &(evidence_hash, bond_snapshot_root, assurance_hash),
        )?;
        Ok(VerifiedEconomicAssuranceV1 {
            assurance: derived,
            proof_commitment,
        })
    }
}

/// Typed offline-verification refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EconomicAssuranceError {
    /// A required commitment is the all-zero sentinel.
    #[error("required commitment is zero: {0}")]
    ZeroCommitment(&'static str),
    /// Accountability evidence names no member.
    #[error("accountability evidence names no implicated members")]
    NoImplicatedMembers,
    /// Silence and withholding do not produce objective slashable evidence.
    #[error("withholding or silence cannot be priced as slashable collateral")]
    UnpriceableBehavior,
    /// Evidence and bond snapshot refer to different configurations.
    #[error("evidence and bond snapshot configuration differ")]
    ConfigurationMismatch,
    /// Snapshot is already beyond the evidence challenge horizon.
    #[error("evidence challenge horizon expired before the snapshot")]
    ChallengeHorizonExpired,
    /// No collateral was supplied.
    #[error("bond snapshot contains no collateral")]
    NoCollateral,
    /// Bond IDs are unsorted or duplicated.
    #[error("bond IDs must be strictly increasing and unique")]
    NonCanonicalOrDuplicateBond,
    /// Two bond records name the same underlying collateral lot.
    #[error("underlying collateral lot was counted more than once")]
    DuplicateCollateralLot,
    /// A bond is not exclusively assigned to the evidence configuration.
    #[error("bond is shared with or assigned to another configuration")]
    SharedCollateral,
    /// The bond was not locked at the snapshot.
    #[error("bond was not locked at the snapshot height")]
    UnlockedCollateral,
    /// The lock ends before the evidence challenge horizon.
    #[error("bond lock expires before the evidence challenge horizon")]
    ExpiredCollateral,
    /// The lot has another active claim.
    #[error("bond has an active encumbrance")]
    EncumberedCollateral,
    /// Withdrawal has begun.
    #[error("bond withdrawal is pending")]
    WithdrawalPending,
    /// Bond's predicate differs from the proof predicate.
    #[error("bond does not accept the accountability evidence predicate")]
    EvidencePredicateMismatch,
    /// Bond owner was not named by the accountability proof.
    #[error("bond owner is not implicated by the accountability proof")]
    UnimplicatedBondOwner,
    /// At least one named member lacks a qualifying bond.
    #[error("an implicated member has no qualifying bond")]
    MissingImplicatedMemberBond,
    /// Unlike native assets cannot be summed without an economic model.
    #[error("collateral proof mixes distinct native assets")]
    MixedAssets,
    /// Different enforcement contracts cannot form one exact floor.
    #[error("collateral proof mixes slashing contracts")]
    MixedSlashingContracts,
    /// Amount is not canonical positive unsigned decimal.
    #[error("bond amount is not canonical positive unsigned decimal")]
    InvalidAmount,
    /// Valuation metadata is incomplete, invalid, or stale.
    #[error("valuation assumptions are incomplete or expired")]
    InvalidValuationAssumptions,
    /// Caller-reported assurance differs from independent recomputation.
    #[error("claimed economic assurance differs from verifier-derived result")]
    ClaimMismatch,
    /// RFC 8785/JCS encoding failed.
    #[error("canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    /// SHA-256 commitment construction failed.
    #[error("commitment hashing failed: {0}")]
    CommitmentHash(String),
    /// Verified vector attachment failed.
    #[error("guarantee-vector attachment failed: {0}")]
    GuaranteeVector(String),
}

fn validate_bond(
    bond: &CollateralBondV1,
    evidence: &AccountabilityEvidenceV1,
    snapshot_height: u64,
) -> Result<(), EconomicAssuranceError> {
    for (name, hash) in [
        ("bond_id", bond.bond_id),
        ("collateral_id", bond.collateral_id),
        ("owner_member_hash", bond.owner_member_hash),
        ("asset_id_hash", bond.asset_id_hash),
        ("slashing_contract_hash", bond.slashing_contract_hash),
    ] {
        validate_nonzero(name, hash)?;
    }
    validate_positive_decimal(&bond.amount_base_units)?;
    if bond.exclusive_configuration_hash != evidence.configuration_hash {
        return Err(EconomicAssuranceError::SharedCollateral);
    }
    if snapshot_height < bond.locked_from || snapshot_height > bond.locked_until {
        return Err(EconomicAssuranceError::UnlockedCollateral);
    }
    if bond.locked_until < evidence.challenge_horizon_end
        || bond.challenge_horizon_end < evidence.challenge_horizon_end
    {
        return Err(EconomicAssuranceError::ExpiredCollateral);
    }
    if !bond.active_encumbrance_hashes.is_empty() {
        return Err(EconomicAssuranceError::EncumberedCollateral);
    }
    if bond.withdrawal_pending {
        return Err(EconomicAssuranceError::WithdrawalPending);
    }
    if bond.evidence_predicate_hash != evidence.evidence_predicate_hash {
        return Err(EconomicAssuranceError::EvidencePredicateMismatch);
    }
    Ok(())
}

fn validate_valuation(
    valuation: Option<&ValuationAssumptionsV1>,
    snapshot_height: u64,
) -> Result<(), EconomicAssuranceError> {
    let Some(valuation) = valuation else {
        return Ok(());
    };
    if valuation.quote_asset_id_hash == [0; 32]
        || valuation.oracle_profile_hash == [0; 32]
        || valuation.observed_at > snapshot_height
        || valuation.valid_until < snapshot_height
        || validate_positive_decimal(&valuation.price_numerator).is_err()
        || validate_positive_decimal(&valuation.price_denominator).is_err()
    {
        return Err(EconomicAssuranceError::InvalidValuationAssumptions);
    }
    Ok(())
}

fn validate_nonzero(name: &'static str, value: [u8; 32]) -> Result<(), EconomicAssuranceError> {
    if value == [0; 32] {
        Err(EconomicAssuranceError::ZeroCommitment(name))
    } else {
        Ok(())
    }
}

fn validate_positive_decimal(value: &str) -> Result<(), EconomicAssuranceError> {
    if value.is_empty()
        || value == "0"
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        Err(EconomicAssuranceError::InvalidAmount)
    } else {
        Ok(())
    }
}

fn add_decimal(left: &str, right: &str) -> String {
    let mut carry = 0u8;
    let mut out = Vec::with_capacity(left.len().max(right.len()) + 1);
    let mut left = left.bytes().rev();
    let mut right = right.bytes().rev();
    loop {
        let lhs = left.next().map(|byte| byte - b'0');
        let rhs = right.next().map(|byte| byte - b'0');
        if lhs.is_none() && rhs.is_none() {
            break;
        }
        let sum = lhs.unwrap_or(0) + rhs.unwrap_or(0) + carry;
        out.push(b'0' + (sum % 10));
        carry = sum / 10;
    }
    if carry != 0 {
        out.push(b'0' + carry);
    }
    out.reverse();
    String::from_utf8(out).expect("decimal addition emits ASCII")
}

fn require_common<T: Copy + PartialEq>(
    current: Option<T>,
    next: T,
    mismatch: EconomicAssuranceError,
) -> Result<Option<T>, EconomicAssuranceError> {
    match current {
        Some(current) if current != next => Err(mismatch),
        Some(current) => Ok(Some(current)),
        None => Ok(Some(next)),
    }
}

fn commitment<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], EconomicAssuranceError> {
    let canonical = serde_jcs::to_vec(value)
        .map_err(|error| EconomicAssuranceError::CanonicalEncoding(error.to_string()))?;
    let mut material = Vec::with_capacity(domain.len() + canonical.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(&canonical);
    let digest = DcryptSha256::digest(&material)
        .map_err(|error| EconomicAssuranceError::CommitmentHash(error.to_string()))?;
    digest
        .as_ref()
        .try_into()
        .map_err(|_| EconomicAssuranceError::CommitmentHash("non-32-byte SHA-256".into()))
}

#[cfg(test)]
mod tests;
