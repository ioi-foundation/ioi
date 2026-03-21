/// 6-byte short ID is sufficient for mempool deduplication within a short time window.
pub type ShortTxId = [u8; 6];

/// A bandwidth-optimized representation of a block for gossip.
#[derive(Encode, Decode, Debug, Clone)]
pub struct CompactBlock {
    /// The full block header.
    pub header: BlockHeader,
    /// Short identifiers for all transactions in the block.
    /// Peers use this list to reconstruct the block from their local mempool.
    pub short_ids: Vec<ShortTxId>,
    /// Full bytes of transactions that the proposer predicts peers might miss (optional).
    pub prefilled_txs: Vec<ChainTransaction>,
}

/// Published bulletin-board commitment for a slot's eligible transaction surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinCommitment {
    /// Target block height / slot.
    pub height: u64,
    /// Objective slot cutoff timestamp in milliseconds.
    pub cutoff_timestamp_ms: u64,
    /// Canonical root of the admitted bulletin-board entries.
    pub bulletin_root: [u8; 32],
    /// Number of admitted entries summarized by this commitment.
    pub entry_count: u32,
}

/// A single published bulletin-board entry for the public AFT transaction surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinSurfaceEntry {
    /// Target block height / slot.
    pub height: u64,
    /// Canonical transaction hash admitted to the bulletin surface.
    pub tx_hash: [u8; 32],
}

/// Compact proof family for proof-carrying canonical ordering.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalOrderProofSystem {
    /// Reference verifier: proof bytes are a canonical hash over public inputs.
    #[default]
    HashBindingV1,
    /// Commitment-level witness verified against the block's public transaction surface.
    CommittedSurfaceV1,
}

/// Public inputs all validators can verify cheaply when checking a canonical order certificate.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderPublicInputs {
    /// Slot / height being ordered.
    pub height: u64,
    /// Canonical root hash of the parent state.
    pub parent_state_root_hash: [u8; 32],
    /// Bulletin commitment hash used to derive the eligible set.
    pub bulletin_commitment_hash: [u8; 32],
    /// Public randomness beacon for the slot.
    pub randomness_beacon: [u8; 32],
    /// Canonical root of the ordered transaction set.
    pub ordered_transactions_root_hash: [u8; 32],
    /// Canonical root hash of the resulting state.
    pub resulting_state_root_hash: [u8; 32],
    /// Objective slot cutoff bound into the order certificate.
    pub cutoff_timestamp_ms: u64,
}

/// Compact proof envelope for a canonical order certificate.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderProof {
    /// Proof system used to validate the order certificate.
    #[serde(default)]
    pub proof_system: CanonicalOrderProofSystem,
    /// Canonical hash of the encoded public inputs.
    #[serde(default)]
    pub public_inputs_hash: [u8; 32],
    /// Opaque proof bytes.
    #[serde(default)]
    pub proof_bytes: Vec<u8>,
}

/// First-class recoverability artifact for a canonical bulletin / order surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinAvailabilityCertificate {
    /// Slot / height whose bulletin surface is being certified.
    pub height: u64,
    /// Canonical hash of the bulletin commitment the certificate is bound to.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical recoverability root over the bound bulletin / ordering / state surface.
    /// This is a commitment-only seed: it does not encode witness assignment,
    /// shard layout, or any exploratory coded-recovery carrier by itself.
    #[serde(default)]
    pub recoverability_root: [u8; 32],
}

/// Deterministic retrievability profile bound to a canonical bulletin surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinRetrievabilityProfile {
    /// Slot / height whose bulletin surface is being profiled.
    pub height: u64,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bound bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical recoverability root carried by the bound bulletin availability certificate.
    #[serde(default)]
    pub recoverability_root: [u8; 32],
    /// Number of deterministic retrievability shards for the slot surface.
    pub shard_count: u16,
    /// Threshold of shards required to reconstruct the slot surface.
    pub recovery_threshold: u16,
    /// Threshold of custody attestations required to treat the slot as endogenous.
    pub custody_threshold: u16,
}

/// Deterministic shard-manifest commitment over one canonical bulletin surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinShardManifest {
    /// Slot / height whose bulletin surface is being manifested.
    pub height: u64,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bound bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the governing retrievability profile.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical recoverability root carried by the bound bulletin availability certificate.
    #[serde(default)]
    pub recoverability_root: [u8; 32],
    /// Number of admitted bulletin entries committed by the manifest.
    pub entry_count: u32,
    /// Number of deterministic retrievability shards committed by the manifest.
    pub shard_count: u16,
    /// Threshold of shards required to reconstruct the slot surface.
    pub recovery_threshold: u16,
    /// Canonical commitment over the deterministic shard layout.
    #[serde(default)]
    pub shard_commitment_root: [u8; 32],
}

/// One deterministic shard-to-custodian assignment entry.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinCustodyAssignmentEntry {
    /// Shard index assigned to one custodian.
    pub shard_index: u16,
    /// Account responsible for serving the named shard on the cold path.
    #[serde(default)]
    pub custodian_account_id: AccountId,
}

/// Deterministic custody-assignment object naming which validators are responsible for one slot's
/// retrievability shards.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinCustodyAssignment {
    /// Slot / height whose bulletin surface is being assigned for custody.
    pub height: u64,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bound bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the governing retrievability profile.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical hash of the bound shard manifest.
    #[serde(default)]
    pub bulletin_shard_manifest_hash: [u8; 32],
    /// Canonical hash of the validator set that governs the deterministic custody assignment.
    #[serde(default)]
    pub validator_set_commitment_hash: [u8; 32],
    /// Threshold of named custodians required to sustain endogenous retrievability.
    pub custody_threshold: u16,
    /// Deterministic custodian assignments for each shard index.
    #[serde(default)]
    pub assignments: Vec<BulletinCustodyAssignmentEntry>,
}

/// Compact custody receipt binding a deterministic shard manifest into ordinary AFT state.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinCustodyReceipt {
    /// Slot / height whose bulletin surface is being acknowledged.
    pub height: u64,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bound bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the governing retrievability profile.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical hash of the bound shard manifest.
    #[serde(default)]
    pub bulletin_shard_manifest_hash: [u8; 32],
    /// Number of custody participants named by the receipt.
    pub custodian_count: u16,
    /// Threshold of custody participants required by the receipt.
    pub custody_threshold: u16,
    /// Canonical commitment over the custody acknowledgement surface.
    #[serde(default)]
    pub custody_root: [u8; 32],
}

/// One deterministic served-shard acknowledgement bound to a custody-response object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinCustodyServedShard {
    /// Shard index being served.
    pub shard_index: u16,
    /// Custodian that served the named shard.
    #[serde(default)]
    pub custodian_account_id: AccountId,
    /// Number of bulletin entries covered by the served shard.
    pub served_entry_count: u32,
    /// Canonical hash of the deterministic served-shard payload.
    #[serde(default)]
    pub served_shard_hash: [u8; 32],
}

/// Deterministic positive custody-response object proving that the assigned shard surface can be
/// served from protocol-native bulletin data.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinCustodyResponse {
    /// Slot / height whose bulletin surface is being served.
    pub height: u64,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bound bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the governing retrievability profile.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical hash of the bound shard manifest.
    #[serde(default)]
    pub bulletin_shard_manifest_hash: [u8; 32],
    /// Canonical hash of the governing custody assignment.
    #[serde(default)]
    pub bulletin_custody_assignment_hash: [u8; 32],
    /// Canonical hash of the governing custody receipt.
    #[serde(default)]
    pub bulletin_custody_receipt_hash: [u8; 32],
    /// Deterministic served-shard acknowledgements derived from the bulletin surface.
    #[serde(default)]
    pub served_shards: Vec<BulletinCustodyServedShard>,
}

/// Objective negative-evidence family for endogenous bulletin retrievability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BulletinRetrievabilityChallengeKind {
    /// The slot is closed but no retrievability profile is protocol-visible.
    #[default]
    MissingRetrievabilityProfile,
    /// The slot carries a profile but no shard manifest.
    MissingShardManifest,
    /// The slot carries a shard manifest that contradicts the bound slot surface.
    ContradictoryShardManifest,
    /// The slot carries a profile and manifest but no custody assignment.
    MissingCustodyAssignment,
    /// The slot carries a custody assignment that contradicts the governing manifest or validator
    /// set.
    ContradictoryCustodyAssignment,
    /// The slot carries a profile and manifest but no custody receipt.
    MissingCustodyReceipt,
    /// The slot carries a custody receipt that contradicts the bound manifest.
    ContradictoryCustodyReceipt,
    /// The slot carries the custody plane but no positive custody-response object.
    MissingCustodyResponse,
    /// The slot carries a custody response that does not match the bound shard assignments or
    /// deterministic shard payloads.
    InvalidCustodyResponse,
    /// The slot carries the retrievability objects but no bulletin entries.
    MissingSurfaceEntries,
    /// The slot carries bulletin entries that do not reconstruct the canonical bulletin surface.
    InvalidSurfaceEntries,
}

/// Objective fail-closed evidence that a slot's bulletin surface is not endogenously retrievable.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinRetrievabilityChallenge {
    /// Slot / height whose bulletin surface is being challenged.
    pub height: u64,
    /// Challenge family.
    #[serde(default)]
    pub kind: BulletinRetrievabilityChallengeKind,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bound bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the governing retrievability profile, when one exists.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical hash of the governing shard manifest, when one exists.
    #[serde(default)]
    pub bulletin_shard_manifest_hash: [u8; 32],
    /// Canonical hash of the governing custody assignment, when one exists.
    #[serde(default)]
    pub bulletin_custody_assignment_hash: [u8; 32],
    /// Canonical hash of the governing custody receipt, when one exists.
    #[serde(default)]
    pub bulletin_custody_receipt_hash: [u8; 32],
    /// Canonical hash of the governing custody response, when one exists.
    #[serde(default)]
    pub bulletin_custody_response_hash: [u8; 32],
    /// Human-readable explanation of the fail-closed retrievability condition.
    #[serde(default)]
    pub details: String,
}

/// Declares which exploratory recovery-carrier family a capsule or reveal is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCodingFamily {
    /// Deterministic single-witness scaffold derived from the committed bulletin surface.
    #[default]
    DeterministicScaffoldV1,
    /// Transparent preimage over the committed slot surface, not a non-trivial coded shard.
    TransparentCommittedSurfaceV1,
    /// Parametric k-of-(k+1) systematic XOR parity carrier over the publication-oriented slot payload.
    SystematicXorKOfKPlus1V1,
    /// Parametric k-of-n GF(256) systematic carrier over the publication-oriented slot payload.
    SystematicGf256KOfNV1,
}

/// Compact recovery coding descriptor carried across capsules, share materials, and recovered
/// bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct RecoveryCodingDescriptor {
    /// Coding family semantics.
    #[serde(default)]
    pub family: RecoveryCodingFamily,
    /// Total number of witness shares in the deterministic plan.
    pub share_count: u16,
    /// Threshold of matching shares required for reconstruction.
    pub recovery_threshold: u16,
}

impl Default for RecoveryCodingDescriptor {
    fn default() -> Self {
        Self::deterministic_scaffold()
    }
}

impl RecoveryCodingDescriptor {
    /// Default single-witness scaffold geometry.
    pub const fn deterministic_scaffold() -> Self {
        Self {
            family: RecoveryCodingFamily::DeterministicScaffoldV1,
            share_count: 1,
            recovery_threshold: 1,
        }
    }

    /// Returns the number of data shards implied by the descriptor.
    pub const fn data_shard_count(self) -> u16 {
        self.recovery_threshold
    }

    /// Returns the number of parity shards implied by the descriptor.
    pub const fn parity_shard_count(self) -> u16 {
        self.share_count.saturating_sub(self.recovery_threshold)
    }

    /// Whether the descriptor requires a recoverable slot payload carrier.
    pub const fn uses_recoverable_payload(self) -> bool {
        matches!(
            self.family,
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1
                | RecoveryCodingFamily::SystematicGf256KOfNV1
        )
    }

    /// Whether the descriptor is the transparent committed-surface lane.
    pub const fn is_transparent_committed_surface(self) -> bool {
        matches!(
            self.family,
            RecoveryCodingFamily::TransparentCommittedSurfaceV1
        )
    }

    /// Whether the descriptor is the deterministic scaffold lane.
    pub const fn is_deterministic_scaffold(self) -> bool {
        matches!(self.family, RecoveryCodingFamily::DeterministicScaffoldV1)
    }

    /// Whether the descriptor is in the XOR parity family.
    pub const fn is_systematic_xor_parity_family(self) -> bool {
        matches!(self.family, RecoveryCodingFamily::SystematicXorKOfKPlus1V1)
    }

    /// Whether the descriptor is in the GF(256) k-of-n family.
    pub const fn is_systematic_gf256_k_of_n_family(self) -> bool {
        matches!(self.family, RecoveryCodingFamily::SystematicGf256KOfNV1)
    }

    /// Human-readable family/geometry label for diagnostics.
    pub fn label(self) -> String {
        match self.family {
            RecoveryCodingFamily::DeterministicScaffoldV1 => "deterministic scaffold".into(),
            RecoveryCodingFamily::TransparentCommittedSurfaceV1 => {
                format!(
                    "transparent committed surface {}-of-{}",
                    self.recovery_threshold, self.share_count
                )
            }
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => {
                format!(
                    "systematic xor parity {}-of-{}",
                    self.recovery_threshold, self.share_count
                )
            }
            RecoveryCodingFamily::SystematicGf256KOfNV1 => {
                format!(
                    "systematic gf256 {}-of-{}",
                    self.recovery_threshold, self.share_count
                )
            }
        }
    }

    /// Checks that the descriptor's family and geometry are internally consistent.
    pub fn validate(self) -> Result<(), String> {
        if self.share_count == 0 {
            return Err("recovery coding descriptor has zero share count".into());
        }
        if self.recovery_threshold == 0 {
            return Err("recovery coding descriptor has zero recovery threshold".into());
        }
        if self.recovery_threshold > self.share_count {
            return Err("recovery coding descriptor recovery threshold exceeds share count".into());
        }

        match self.family {
            RecoveryCodingFamily::DeterministicScaffoldV1 => {
                if self.share_count != 1 || self.recovery_threshold != 1 {
                    return Err(
                        "deterministic scaffold descriptor requires share_count = recovery_threshold = 1"
                            .into(),
                    );
                }
            }
            RecoveryCodingFamily::TransparentCommittedSurfaceV1 => {
                if self.recovery_threshold < 2 {
                    return Err(
                        "transparent committed-surface descriptor requires threshold at least two"
                            .into(),
                    );
                }
            }
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => {
                if self.recovery_threshold < 2 {
                    return Err(
                        "systematic xor parity descriptor requires threshold at least two".into(),
                    );
                }
                if self.share_count != self.recovery_threshold.saturating_add(1) {
                    return Err(
                        "systematic xor parity descriptor requires share_count = recovery_threshold + 1"
                            .into(),
                    );
                }
            }
            RecoveryCodingFamily::SystematicGf256KOfNV1 => {
                if self.recovery_threshold < 2 {
                    return Err(
                        "systematic gf256 descriptor requires threshold at least two".into(),
                    );
                }
                if self.share_count < self.recovery_threshold.saturating_add(2) {
                    return Err(
                        "systematic gf256 descriptor requires at least two parity shares".into(),
                    );
                }
                if self.parity_shard_count() > u16::from(u8::MAX) {
                    return Err(
                        "systematic gf256 descriptor supports at most 255 parity shares".into(),
                    );
                }
                if self.share_count > u16::from(u8::MAX) + 1 {
                    return Err(
                        "systematic gf256 descriptor supports at most 256 total shares".into(),
                    );
                }
            }
        }

        Ok(())
    }

    /// Resolves this descriptor into the abstract recovery-family contract it
    /// satisfies.
    pub fn family_contract(self) -> Result<RecoveryFamilyContract, String> {
        self.validate()?;
        Ok(RecoveryFamilyContract { descriptor: self })
    }
}

/// Abstract recovery-family contract satisfied by all admitted exploratory
/// recovery carriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryFamilyContract {
    descriptor: RecoveryCodingDescriptor,
}

impl RecoveryFamilyContract {
    /// Returns the validated descriptor this contract is bound to.
    pub const fn descriptor(self) -> RecoveryCodingDescriptor {
        self.descriptor
    }

    /// Human-readable contract label for diagnostics and theorem text.
    pub const fn theorem_label(self) -> &'static str {
        match self.descriptor.family {
            RecoveryCodingFamily::DeterministicScaffoldV1 => "deterministic scaffold",
            RecoveryCodingFamily::TransparentCommittedSurfaceV1 => "transparent committed surface",
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => "systematic xor recovery family",
            RecoveryCodingFamily::SystematicGf256KOfNV1 => "systematic gf256 recovery family",
        }
    }

    /// Whether this family is a true coded recoverable-payload carrier.
    pub const fn supports_coded_payload_reconstruction(self) -> bool {
        matches!(
            self.descriptor.family,
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1
                | RecoveryCodingFamily::SystematicGf256KOfNV1
        )
    }

    /// Whether this family requires a recoverable slot payload carrier.
    pub const fn uses_recoverable_payload(self) -> bool {
        self.descriptor.uses_recoverable_payload()
    }

    /// Domain separator for coded share commitments under this family contract.
    pub fn coded_share_commitment_domain(self) -> Result<&'static [u8], String> {
        match self.descriptor.family {
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => Ok(
                b"aft::recovery::multi_witness::systematic_xor_k_of_k_plus_1::share_commitment::v1",
            ),
            RecoveryCodingFamily::SystematicGf256KOfNV1 => {
                Ok(b"aft::recovery::multi_witness::systematic_gf256_k_of_n::share_commitment::v1")
            }
            RecoveryCodingFamily::TransparentCommittedSurfaceV1
            | RecoveryCodingFamily::DeterministicScaffoldV1 => Err(
                "coded share commitment domain requires a coded recovery-family contract".into(),
            ),
        }
    }

    /// Encodes a recoverable slot payload into the canonical shard plan for
    /// this family contract.
    pub fn encode_payload_shards(self, payload_bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        match self.descriptor.family {
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => {
                encode_systematic_xor_k_of_k_plus_1_shards(
                    payload_bytes,
                    self.descriptor.recovery_threshold,
                )
            }
            RecoveryCodingFamily::SystematicGf256KOfNV1 => encode_systematic_gf256_k_of_n_shards(
                payload_bytes,
                self.descriptor.share_count,
                self.descriptor.recovery_threshold,
            ),
            RecoveryCodingFamily::TransparentCommittedSurfaceV1
            | RecoveryCodingFamily::DeterministicScaffoldV1 => Err(
                "coded recovery shard encoding requires a coded recovery-family contract".into(),
            ),
        }
    }

    /// Reconstructs recoverable payload bytes from the public reveal set under
    /// this family contract.
    pub fn recover_payload_bytes_from_materials(
        self,
        materials: &[RecoveryShareMaterial],
    ) -> Result<Vec<u8>, String> {
        match self.descriptor.family {
            RecoveryCodingFamily::SystematicGf256KOfNV1 => {
                if materials
                    .iter()
                    .any(|material| material.coding != self.descriptor)
                {
                    return Err(
                        "recoverable slot payload reconstruction requires a uniform gf256 materialization kind"
                            .into(),
                    );
                }
                recover_systematic_gf256_k_of_n_slot_payload_bytes(materials)
            }
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => {
                if materials
                    .iter()
                    .any(|material| !is_systematic_xor_parity_coding(material.coding))
                {
                    return Err(
                        "recoverable slot payload reconstruction requires a uniform parity-family materialization kind"
                            .into(),
                    );
                }
                recover_systematic_xor_k_of_k_plus_1_slot_payload_bytes(materials)
            }
            RecoveryCodingFamily::TransparentCommittedSurfaceV1
            | RecoveryCodingFamily::DeterministicScaffoldV1 => Err(
                "recoverable slot payload reconstruction requires non-transparent coded share reveals"
                    .into(),
            ),
        }
    }
}

/// Exploratory witness-coded recovery capsule for constructive lower-bound variants.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveryCapsule {
    /// Slot / height whose recovery surface is being bound.
    pub height: u64,
    /// Declares whether the capsule is a true coded carrier or a deterministic scaffold.
    #[serde(default)]
    pub coding: RecoveryCodingDescriptor,
    /// Compact root committing the assigned witness recovery committee.
    #[serde(default)]
    pub recovery_committee_root_hash: [u8; 32],
    /// Commitment to the slot surface recoverable from threshold shares.
    #[serde(default)]
    pub payload_commitment_hash: [u8; 32],
    /// Commitment to the coding / shard layout referenced by witness shares.
    #[serde(default)]
    pub coding_root_hash: [u8; 32],
    /// Deterministic recovery-window close bound to the capsule.
    pub recovery_window_close_ms: u64,
}

/// Exploratory witness certificate binding one assigned recovery share to a capsule.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveryWitnessCertificate {
    /// Slot / height whose recovery capsule is being witnessed.
    pub height: u64,
    /// Witness committee epoch.
    pub epoch: u64,
    /// Hash of the registered witness manifest that carries the recovery duty.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Canonical hash of the bound recovery capsule.
    #[serde(default)]
    pub recovery_capsule_hash: [u8; 32],
    /// Commitment to the witness's coded share.
    #[serde(default)]
    pub share_commitment_hash: [u8; 32],
}

/// Compact public receipt revealing that one assigned witness bound a share to one slot surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveryShareReceipt {
    /// Slot / height whose recovery share is being published.
    pub height: u64,
    /// Witness manifest that revealed the share receipt.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Commitment of the candidate slot surface / block the share supports.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Commitment to the witness's coded share.
    #[serde(default)]
    pub share_commitment_hash: [u8; 32],
}

/// Canonical compact slot payload used by exploratory witness-coded recovery experiments.
///
/// This payload is intentionally smaller than the full bulletin surface. It is
/// the first honest payload carrier we can derive endogenously today without
/// reintroducing dense reconstruction onto the validator hot path.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV1 {
    /// Slot / height whose compact payload is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the compact slot payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Ordered transaction hashes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_hashes: Vec<[u8; 32]>,
}

/// Canonical widened slot payload used by the intermediate coded-share experiments.
///
/// This keeps the same compact certificate carrier as `RecoverableSlotPayloadV1`
/// but widens the ordered payload from transaction hashes to canonical encoded
/// ordered transaction bytes so the recovery lane can reconstruct a real slot
/// payload rather than only a digest list.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV2 {
    /// Slot / height whose widened payload is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the widened slot payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Canonical ordered transaction bytes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_bytes: Vec<Vec<u8>>,
}

/// Canonical publication-oriented slot payload used by the live coded-share experiments.
///
/// This keeps the widened ordered transaction bytes from `RecoverableSlotPayloadV2`
/// and adds canonical encoded publication-bundle bytes so the shard lane can
/// recover the already-derived publication artifact surface without reaching
/// outside current endogenous finalization artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV3 {
    /// Slot / height whose publication-oriented payload is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the widened slot payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical parent block hash carried by the committed slot header.
    #[serde(default)]
    pub parent_block_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Canonical ordered transaction bytes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_bytes: Vec<Vec<u8>>,
    /// Canonical encoded publication-bundle bytes derived from the same slot surface.
    #[serde(default)]
    pub canonical_order_publication_bundle_bytes: Vec<u8>,
}

/// Canonical close-extraction slot payload derived from the live coded-share experiments.
///
/// This extends `RecoverableSlotPayloadV3` with the exact canonical
/// bulletin-close bytes that the positive ordering lane ultimately needs to
/// materialize the ordinary close surface. The close object is still verified
/// from the recovered publication bundle, but `V4` makes that full positive
/// close-extraction surface explicit.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV4 {
    /// Slot / height whose close-extraction payload is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the close-extraction payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical parent block hash carried by the committed slot header.
    #[serde(default)]
    pub parent_block_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Canonical ordered transaction bytes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_bytes: Vec<Vec<u8>>,
    /// Canonical encoded publication-bundle bytes derived from the same slot surface.
    #[serde(default)]
    pub canonical_order_publication_bundle_bytes: Vec<u8>,
    /// Canonical encoded bulletin-close bytes derived from the verifying publication bundle.
    #[serde(default)]
    pub canonical_bulletin_close_bytes: Vec<u8>,
}

/// Explicit extractable bulletin-surface payload derived from the live coded-share experiments.
///
/// This extends `RecoverableSlotPayloadV4` with the exact bulletin-surface
/// artifacts that the registry's extracted closed-slot surface depends on:
/// canonical encoded bulletin-availability bytes plus the sorted bulletin
/// entry surface itself.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV5 {
    /// Slot / height whose full extractable bulletin surface is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the full extractable surface.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical parent block hash carried by the committed slot header.
    #[serde(default)]
    pub parent_block_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Canonical ordered transaction bytes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_bytes: Vec<Vec<u8>>,
    /// Canonical encoded publication-bundle bytes derived from the same slot surface.
    #[serde(default)]
    pub canonical_order_publication_bundle_bytes: Vec<u8>,
    /// Canonical encoded bulletin-close bytes derived from the verifying publication bundle.
    #[serde(default)]
    pub canonical_bulletin_close_bytes: Vec<u8>,
    /// Canonical encoded bulletin-availability bytes extracted from the recovered bundle.
    #[serde(default)]
    pub canonical_bulletin_availability_certificate_bytes: Vec<u8>,
    /// Sorted canonical bulletin-entry surface extracted from the recovered bundle.
    #[serde(default)]
    pub bulletin_surface_entries: Vec<BulletinSurfaceEntry>,
}

/// Cold-path share-reveal material for one exploratory witness-coded recovery share.
///
/// The current constructive route supports either a transparent preimage over
/// already committed slot-surface facts, the parametric XOR parity family, or
/// bounded GF(256) systematic shards over a publication-oriented recoverable
/// slot payload. This keeps reveal verification cold-path and deterministic
/// while testing whether non-trivial coded recovery can stay endogenous to the
/// current protocol surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveryShareMaterial {
    /// Slot / height whose recovery share is being revealed.
    pub height: u64,
    /// Witness manifest that owns the revealed share commitment.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Commitment of the candidate slot surface / block this reveal supports.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Declares whether this material is a true coded shard or a transparent preimage.
    #[serde(default)]
    pub coding: RecoveryCodingDescriptor,
    /// Position of this share inside the deterministic threshold-k plan.
    pub share_index: u16,
    /// Commitment hash bound by the witness certificate and derived receipt.
    #[serde(default)]
    pub share_commitment_hash: [u8; 32],
    /// Material bytes that hash to `share_commitment_hash`.
    #[serde(default)]
    pub material_bytes: Vec<u8>,
}

impl RecoveryShareMaterial {
    /// Derives the compact public share receipt for this revealed share material.
    pub fn to_recovery_share_receipt(&self) -> RecoveryShareReceipt {
        RecoveryShareReceipt {
            height: self.height,
            witness_manifest_hash: self.witness_manifest_hash,
            block_commitment_hash: self.block_commitment_hash,
            share_commitment_hash: self.share_commitment_hash,
        }
    }
}

/// Compact public resolution object proving that threshold-many share reveals
/// reconstruct one verifying positive canonical-order close surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveredPublicationBundle {
    /// Slot / height whose publication bundle was recovered.
    pub height: u64,
    /// Block commitment anchoring the recovered slot payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical parent block hash recovered from the same slot surface.
    #[serde(default)]
    pub parent_block_commitment_hash: [u8; 32],
    /// Reveal semantics used by the recovered share set.
    #[serde(default)]
    pub coding: RecoveryCodingDescriptor,
    /// Distinct witness manifests whose public reveals supported the recovery.
    #[serde(default)]
    pub supporting_witness_manifest_hashes: Vec<[u8; 32]>,
    /// Canonical hash of the reconstructed `RecoverableSlotPayloadV4`.
    #[serde(default)]
    pub recoverable_slot_payload_hash: [u8; 32],
    /// Canonical hash of the reconstructed `RecoverableSlotPayloadV5`.
    #[serde(default)]
    pub recoverable_full_surface_hash: [u8; 32],
    /// Canonical hash of the verifying recovered publication bundle bytes.
    #[serde(default)]
    pub canonical_order_publication_bundle_hash: [u8; 32],
    /// Canonical hash of the verifying recovered bulletin-close bytes.
    #[serde(default)]
    pub canonical_bulletin_close_hash: [u8; 32],
}

/// Compact archival descriptor for a recovered-history segment.
///
/// This is a cold-path publication object. It names a recovered-history range,
/// commits to the recovered publication-bundle hashes inside that range, and
/// chains to the previous archived segment without enlarging hot-path messages.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistorySegment {
    /// First recovered slot height covered by this archived segment.
    pub start_height: u64,
    /// Last recovered slot height covered by this archived segment.
    pub end_height: u64,
    /// Canonical hash of the archived recovered-history profile that governs this segment.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile activation that governs this
    /// segment.
    #[serde(default)]
    pub archived_profile_activation_hash: [u8; 32],
    /// Canonical recovered-publication bundle hash for the oldest slot in range.
    #[serde(default)]
    pub first_recovered_publication_bundle_hash: [u8; 32],
    /// Canonical recovered-publication bundle hash for the newest slot in range.
    #[serde(default)]
    pub last_recovered_publication_bundle_hash: [u8; 32],
    /// Canonical hash of the immediately previous archived recovered-history segment.
    #[serde(default)]
    pub previous_archived_segment_hash: [u8; 32],
    /// Canonical root hash of the recovered-publication bundle hashes in this range.
    #[serde(default)]
    pub segment_root_hash: [u8; 32],
    /// First height inside this segment's exact-overlap anchor, or zero when absent.
    pub overlap_start_height: u64,
    /// Last height inside this segment's exact-overlap anchor, or zero when absent.
    pub overlap_end_height: u64,
    /// Canonical root hash of the overlap anchor's recovered-publication bundle hashes.
    #[serde(default)]
    pub overlap_root_hash: [u8; 32],
}

/// Published update rule for archived recovered-history checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub enum ArchivedRecoveredHistoryCheckpointUpdateRule {
    /// Publish a fresh archival checkpoint for every published archived segment/page tip.
    #[default]
    EveryPublishedSegmentV1,
}

/// Compact active profile naming the archived recovered-history availability geometry.
///
/// This keeps the archival retention and exact-overlap page geometry protocol-native
/// instead of leaving it as an implementation-side constant.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistoryProfile {
    /// Height horizon through which archived checkpoints are retained.
    pub retention_horizon: u64,
    /// Restart-page window width used by archived exact-overlap paging.
    pub restart_page_window: u64,
    /// Restart-page overlap width used by archived exact-overlap paging.
    pub restart_page_overlap: u64,
    /// Number of recovered windows folded into one archived segment page.
    pub windows_per_segment: u64,
    /// Number of segments folded into one archived page range.
    pub segments_per_fold: u64,
    /// Published checkpoint update rule for this archived-history profile.
    #[serde(default)]
    pub checkpoint_update_rule: ArchivedRecoveredHistoryCheckpointUpdateRule,
}

/// Cold-path activation event making archived recovered-history profile evolution protocol-native.
///
/// This object names which archived profile governs archived recovered-history outputs starting at
/// one archived tip end height. Historical replay must validate archived objects against the
/// profile hash they reference and the activation chain that made that profile active.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistoryProfileActivation {
    /// Canonical hash of the archived recovered-history profile that becomes active.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the previously active archived recovered-history profile, or zero at
    /// bootstrap.
    #[serde(default)]
    pub previous_archived_profile_hash: [u8; 32],
    /// First archived tip end height governed by `archived_profile_hash`.
    pub activation_end_height: u64,
    /// Optional canonical hash of the first archived checkpoint tip governed by this profile.
    #[serde(default)]
    pub activation_checkpoint_hash: [u8; 32],
}

/// Content-addressed archived restart payload for one archived recovered-history segment.
///
/// This is the cold-path restart-consumer surface. It archives the recovered
/// restart block-header entries needed to resume bounded ancestry lookup when
/// the retained recovered publication surface is no longer locally available.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredRestartPage {
    /// Canonical hash of the archived recovered-history segment this page satisfies.
    #[serde(default)]
    pub segment_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile that governs this page.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile activation that governs this
    /// page.
    #[serde(default)]
    pub archived_profile_activation_hash: [u8; 32],
    /// First height covered by the archived restart page.
    pub start_height: u64,
    /// Last height covered by the archived restart page.
    pub end_height: u64,
    /// Archived recovered restart headers for the covered range.
    #[serde(default)]
    pub restart_headers: Vec<RecoveredRestartBlockHeaderEntry>,
}

/// Compact archival checkpoint naming the current archived recovered-history tip.
///
/// This is the cold-path bootstrap surface for restart-time ancestry paging. It
/// commits to the latest archived segment/page pair, the covered height range,
/// and the previous checkpoint hash so archived recovered-history availability
/// is named by AFT itself instead of inferred from local retained state.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistoryCheckpoint {
    /// First height covered by the latest archived range.
    pub covered_start_height: u64,
    /// Last height covered by the latest archived range.
    pub covered_end_height: u64,
    /// Canonical hash of the archived recovered-history profile that governs this checkpoint.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile activation that governs this
    /// checkpoint.
    #[serde(default)]
    pub archived_profile_activation_hash: [u8; 32],
    /// Canonical hash of the latest archived recovered-history segment.
    #[serde(default)]
    pub latest_archived_segment_hash: [u8; 32],
    /// Canonical hash of the latest archived recovered restart-page payload.
    #[serde(default)]
    pub latest_archived_restart_page_hash: [u8; 32],
    /// Canonical hash of the previous archived recovered-history checkpoint.
    #[serde(default)]
    pub previous_archived_checkpoint_hash: [u8; 32],
}

/// Compact archival retention receipt binding an archived checkpoint to the
/// validator-set commitment currently retaining it.
///
/// This is the cold-path accountability surface that says the current archived
/// recovered-history checkpoint is not only named by AFT, but is also retained
/// by the active validator-set commitment through a declared height horizon.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistoryRetentionReceipt {
    /// First height covered by the retained archived checkpoint.
    pub covered_start_height: u64,
    /// Last height covered by the retained archived checkpoint.
    pub covered_end_height: u64,
    /// Canonical hash of the archived recovered-history profile that governs this receipt.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile activation that governs this
    /// receipt.
    #[serde(default)]
    pub archived_profile_activation_hash: [u8; 32],
    /// Canonical hash of the retained archived recovered-history checkpoint.
    #[serde(default)]
    pub archived_checkpoint_hash: [u8; 32],
    /// Canonical hash of the validator-set commitment retaining this checkpoint.
    #[serde(default)]
    pub validator_set_commitment_hash: [u8; 32],
    /// Height through which this archived checkpoint is retained.
    pub retained_through_height: u64,
}

/// Off-chain witness-local delivery envelope for an assigned recovery share.
///
/// This is deliberately not a hot-path publication object. It exists so the
/// assigned witness committee can durably store the exact share material it is
/// about to bind in its signed witness certificate before any member signs.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AssignedRecoveryShareEnvelopeV1 {
    /// Canonical hash of the bound recovery capsule.
    #[serde(default)]
    pub recovery_capsule_hash: [u8; 32],
    /// Share commitment the witness statement is expected to sign.
    #[serde(default)]
    pub expected_share_commitment_hash: [u8; 32],
    /// Full cold-path share material the witness stores for later reveal.
    #[serde(default)]
    pub share_material: RecoveryShareMaterial,
}

impl AssignedRecoveryShareEnvelopeV1 {
    /// Reconstructs the signed recovery binding this envelope is expected to satisfy.
    pub fn recovery_binding(&self) -> GuardianWitnessRecoveryBinding {
        GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: self.recovery_capsule_hash,
            share_commitment_hash: self.expected_share_commitment_hash,
        }
    }

    /// Checks the envelope's basic witness-local invariants before it is stored.
    pub fn validate_for_witness(
        &self,
        expected_manifest_hash: [u8; 32],
        expected_height: u64,
    ) -> Result<(), String> {
        if self.recovery_capsule_hash == [0u8; 32] {
            return Err(
                "assigned recovery share envelope is missing a recovery capsule hash".into(),
            );
        }
        if self.expected_share_commitment_hash == [0u8; 32] {
            return Err(
                "assigned recovery share envelope is missing an expected share commitment hash"
                    .into(),
            );
        }
        if self.share_material.height != expected_height {
            return Err(
                "assigned recovery share envelope height does not match the signed witness statement"
                    .into(),
            );
        }
        if self.share_material.witness_manifest_hash != expected_manifest_hash {
            return Err(
                "assigned recovery share envelope witness manifest does not match the assigned witness"
                    .into(),
            );
        }
        if self.share_material.share_commitment_hash != self.expected_share_commitment_hash {
            return Err(
                "assigned recovery share envelope material does not match the expected share commitment hash"
                    .into(),
            );
        }
        if self.share_material.block_commitment_hash == [0u8; 32] {
            return Err(
                "assigned recovery share envelope is missing the bound block commitment hash"
                    .into(),
            );
        }
        self.share_material.coding.validate().map_err(|error| {
            format!("assigned recovery share envelope has invalid coding: {error}")
        })?;
        if self.share_material.share_index >= self.share_material.coding.share_count {
            return Err("assigned recovery share envelope share index exceeds share count".into());
        }
        if self.share_material.material_bytes.is_empty() {
            return Err("assigned recovery share envelope is missing share material bytes".into());
        }
        Ok(())
    }
}

/// Compact public claim that an assigned recovery share was missing at window close.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct MissingRecoveryShare {
    /// Slot / height whose recovery share is missing.
    pub height: u64,
    /// Witness manifest that failed to reveal its assigned share.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Canonical hash of the bound recovery capsule.
    #[serde(default)]
    pub recovery_capsule_hash: [u8; 32],
    /// Deterministic recovery-window close used to make missingness objective.
    pub recovery_window_close_ms: u64,
}

/// Canonical closed bulletin object binding the publication surface to a unique slot close.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalBulletinClose {
    /// Slot / height whose bulletin surface is being closed.
    pub height: u64,
    /// Objective cutoff timestamp the close commits to.
    pub cutoff_timestamp_ms: u64,
    /// Canonical hash of the bulletin commitment carried by the close.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bulletin availability certificate carried by the close.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the deterministic bulletin retrievability profile carried by the close.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical hash of the deterministic bulletin shard manifest carried by the close.
    #[serde(default)]
    pub bulletin_shard_manifest_hash: [u8; 32],
    /// Canonical hash of the deterministic bulletin custody receipt carried by the close.
    #[serde(default)]
    pub bulletin_custody_receipt_hash: [u8; 32],
    /// Number of admitted bulletin entries sealed by the close.
    pub entry_count: u32,
}

/// Compact receipt carried by the live protocol for a publication surface's availability binding.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct PublicationAvailabilityReceipt {
    /// Slot / height whose publication surface is being summarized.
    pub height: u64,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical root of the ordered transaction surface.
    #[serde(default)]
    pub ordered_transactions_root_hash: [u8; 32],
    /// Canonical root of the resulting post-state.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Compact recoverability / availability receipt root bound into the live frontier.
    #[serde(default)]
    pub receipt_root: [u8; 32],
}

/// Compact signed publication-frontier summary carried in the block header preimage.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct PublicationFrontier {
    /// Slot / height whose publication surface is summarized.
    pub height: u64,
    /// Consensus view that carried this signed frontier.
    pub view: u64,
    /// Monotone slot counter for the publication trace.
    pub counter: u64,
    /// Canonical hash of the previous slot's publication frontier.
    #[serde(default)]
    pub parent_frontier_hash: [u8; 32],
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical root of the ordered live message / transaction surface.
    #[serde(default)]
    pub ordered_transactions_root_hash: [u8; 32],
    /// Canonical hash of the compact availability receipt carried by the frontier.
    #[serde(default)]
    pub availability_receipt_hash: [u8; 32],
}

/// First objective contradiction family for publication-frontier disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PublicationFrontierContradictionKind {
    /// Two same-slot frontiers disagree on the signed compact publication summary.
    #[default]
    ConflictingFrontier,
    /// A frontier does not extend the previous published / committed frontier.
    StaleParentLink,
}

/// Short objective contradiction witness over compact publication-frontier summaries.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct PublicationFrontierContradiction {
    /// Slot / height whose frontier is contradicted.
    pub height: u64,
    /// Contradiction family.
    #[serde(default)]
    pub kind: PublicationFrontierContradictionKind,
    /// The candidate frontier being rejected.
    #[serde(default)]
    pub candidate_frontier: PublicationFrontier,
    /// The conflicting same-slot frontier or the expected predecessor frontier.
    #[serde(default)]
    pub reference_frontier: PublicationFrontier,
}

/// Atomic publication bundle for the ordering bulletin surface and its canonical order object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderPublicationBundle {
    /// Slot bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment: BulletinCommitment,
    /// Published bulletin surface entries for the slot.
    #[serde(default)]
    pub bulletin_entries: Vec<BulletinSurfaceEntry>,
    /// First-class bulletin availability certificate bound to the order surface.
    #[serde(default)]
    pub bulletin_availability_certificate: BulletinAvailabilityCertificate,
    /// Deterministic retrievability profile bound to the same bulletin surface.
    #[serde(default)]
    pub bulletin_retrievability_profile: BulletinRetrievabilityProfile,
    /// Deterministic shard manifest bound to the same bulletin surface.
    #[serde(default)]
    pub bulletin_shard_manifest: BulletinShardManifest,
    /// Deterministic custody receipt bound to the same bulletin surface.
    #[serde(default)]
    pub bulletin_custody_receipt: BulletinCustodyReceipt,
    /// Canonical order certificate over the same bulletin surface.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
}

/// Locally derived canonical execution object for a slot's proof-carried ordering surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderExecutionObject {
    /// Slot bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment: BulletinCommitment,
    /// Published bulletin surface entries for the slot.
    #[serde(default)]
    pub bulletin_entries: Vec<BulletinSurfaceEntry>,
    /// Explicit bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate: BulletinAvailabilityCertificate,
    /// Deterministic bulletin retrievability profile.
    #[serde(default)]
    pub bulletin_retrievability_profile: BulletinRetrievabilityProfile,
    /// Deterministic bulletin shard manifest.
    #[serde(default)]
    pub bulletin_shard_manifest: BulletinShardManifest,
    /// Deterministic bulletin custody receipt.
    #[serde(default)]
    pub bulletin_custody_receipt: BulletinCustodyReceipt,
    /// Canonical bulletin-close object derived from the publication surface.
    #[serde(default)]
    pub bulletin_close: CanonicalBulletinClose,
    /// Canonical order certificate bound to the same surface.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
}

/// Protocol-visible positive reconstruction outcome for one closed bulletin surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinReconstructionCertificate {
    /// Slot / height whose bulletin surface was reconstructed endogenously.
    pub height: u64,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bound bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the governing retrievability profile.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical hash of the governing shard manifest.
    #[serde(default)]
    pub bulletin_shard_manifest_hash: [u8; 32],
    /// Canonical hash of the governing custody assignment.
    #[serde(default)]
    pub bulletin_custody_assignment_hash: [u8; 32],
    /// Canonical hash of the governing custody receipt.
    #[serde(default)]
    pub bulletin_custody_receipt_hash: [u8; 32],
    /// Canonical hash of the governing custody response.
    #[serde(default)]
    pub bulletin_custody_response_hash: [u8; 32],
    /// Canonical hash of the bound canonical bulletin close.
    #[serde(default)]
    pub canonical_bulletin_close_hash: [u8; 32],
    /// Canonical hash of the bound canonical-order certificate.
    #[serde(default)]
    pub canonical_order_certificate_hash: [u8; 32],
    /// Number of entries reconstructed from protocol objects.
    pub reconstructed_entry_count: u32,
    /// Canonical bulletin root recovered by the reconstruction path.
    #[serde(default)]
    pub reconstructed_bulletin_root: [u8; 32],
}

/// Protocol-visible fail-closed bulletin reconstruction outcome dominated by objective
/// retrievability evidence.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinReconstructionAbort {
    /// Slot / height whose bulletin reconstruction failed closed.
    pub height: u64,
    /// Retrievability challenge family that dominated the positive lane.
    #[serde(default)]
    pub kind: BulletinRetrievabilityChallengeKind,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bound bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the governing retrievability profile, when one exists.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical hash of the governing shard manifest, when one exists.
    #[serde(default)]
    pub bulletin_shard_manifest_hash: [u8; 32],
    /// Canonical hash of the governing custody receipt, when one exists.
    #[serde(default)]
    pub bulletin_custody_receipt_hash: [u8; 32],
    /// Canonical hash of the challenge that triggered this fail-closed reconstruction outcome.
    #[serde(default)]
    pub bulletin_retrievability_challenge_hash: [u8; 32],
    /// Canonical hash of the paired canonical-order abort.
    #[serde(default)]
    pub canonical_order_abort_hash: [u8; 32],
    /// Human-readable explanation of the fail-closed reconstruction outcome.
    #[serde(default)]
    pub details: String,
}

/// Objective negative outcome for ordering extraction when the proof-carried surface is missing or
/// invalid.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalOrderAbortReason {
    /// The committed block does not carry the required canonical-order certificate.
    #[default]
    MissingOrderCertificate,
    /// The committed block does not carry the required signed publication frontier.
    MissingPublicationFrontier,
    /// The committed block's bulletin surface cannot be reconstructed canonically.
    BulletinSurfaceReconstructionFailure,
    /// The reconstructed bulletin surface does not match the proof-carried bulletin commitment.
    BulletinSurfaceMismatch,
    /// The committed block's bulletin-close object is invalid or cannot be derived.
    InvalidBulletinClose,
    /// The committed block's canonical-order certificate is dominated by objective omissions.
    OmissionDominated,
    /// The certificate, bulletin commitment, or availability certificate height does not match
    /// the slot height.
    CertificateHeightMismatch,
    /// The certificate randomness beacon does not match the canonical slot schedule.
    RandomnessMismatch,
    /// The certificate ordered-transactions root does not match the committed block surface.
    OrderedTransactionsRootMismatch,
    /// The certificate resulting-state root does not match the committed block surface.
    ResultingStateRootMismatch,
    /// The canonical-order proof public-input binding is inconsistent.
    InvalidPublicInputsHash,
    /// The bulletin availability certificate or its recoverability binding is invalid.
    InvalidBulletinAvailabilityCertificate,
    /// The proof binding carried by the order certificate is invalid.
    InvalidProofBinding,
    /// A same-slot compact publication frontier conflicts with an already published frontier.
    PublicationFrontierConflict,
    /// A compact publication frontier does not extend the previous frontier.
    PublicationFrontierStale,
    /// Distinct recovered publication bundles disagree on the recovered slot surface.
    RecoverySupportConflict,
    /// Published recovery receipts / missingness make threshold reconstruction impossible.
    RecoveryThresholdImpossible,
    /// Protocol-native negative evidence dominates the endogenous retrievability surface.
    RetrievabilityChallengeDominated,
}

/// Canonical abort object emitted when local ordering extraction fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderAbort {
    /// Slot / height whose ordering surface aborted.
    pub height: u64,
    /// Objective reason the close path was rejected.
    #[serde(default)]
    pub reason: CanonicalOrderAbortReason,
    /// Human-readable extraction failure detail.
    #[serde(default)]
    pub details: String,
    /// Canonical hash of the bulletin commitment carried by the candidate certificate, if present.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bulletin availability certificate carried by the candidate
    /// certificate, if present.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the locally derived bulletin-close object, if derivation succeeded.
    #[serde(default)]
    pub bulletin_close_hash: [u8; 32],
    /// Canonical hash of the candidate canonical-order certificate, if present.
    #[serde(default)]
    pub canonical_order_certificate_hash: [u8; 32],
}

/// Canonical close-or-abort outcome tag shared across ordering and sealing collapse surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalCollapseKind {
    /// The positive close path survived all objective checks.
    #[default]
    Close,
    /// Objective negative evidence dominated the close path.
    Abort,
}

/// Ordering-side component of the protocol-wide canonical collapse object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderingCollapse {
    /// Slot / height whose ordering surface collapsed.
    pub height: u64,
    /// Whether ordering resolved to the positive close or negative abort path.
    #[serde(default)]
    pub kind: CanonicalCollapseKind,
    /// Canonical hash of the ordering bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the ordering bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the deterministic ordering bulletin retrievability profile.
    #[serde(default)]
    pub bulletin_retrievability_profile_hash: [u8; 32],
    /// Canonical hash of the deterministic ordering bulletin shard manifest.
    #[serde(default)]
    pub bulletin_shard_manifest_hash: [u8; 32],
    /// Canonical hash of the deterministic ordering bulletin custody receipt.
    #[serde(default)]
    pub bulletin_custody_receipt_hash: [u8; 32],
    /// Canonical hash of the ordering bulletin-close object.
    #[serde(default)]
    pub bulletin_close_hash: [u8; 32],
    /// Canonical hash of the canonical-order certificate when the positive close path survives.
    #[serde(default)]
    pub canonical_order_certificate_hash: [u8; 32],
}

/// Sealing-side component of the protocol-wide canonical collapse object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalSealingCollapse {
    /// Epoch in which the sealing surface was derived.
    pub epoch: u64,
    /// Slot / height whose sealing surface collapsed.
    pub height: u64,
    /// Consensus view of the sealed slot.
    pub view: u64,
    /// Whether sealing resolved to the positive close or negative abort path.
    #[serde(default)]
    pub kind: CanonicalCollapseKind,
    /// Finality tier admitted by the canonical sealing outcome.
    #[serde(default)]
    pub finality_tier: FinalityTier,
    /// Underlying sealing collapse state carried by the proof.
    #[serde(default)]
    pub collapse_state: CollapseState,
    /// Canonical root of the observer transcript surface.
    #[serde(default)]
    pub transcripts_root: [u8; 32],
    /// Canonical root of the observer challenge surface.
    #[serde(default)]
    pub challenges_root: [u8; 32],
    /// Canonical hash of the decisive sealing close-or-abort object.
    #[serde(default)]
    pub resolution_hash: [u8; 32],
}

/// Protocol-wide close-or-abort object persisted with AFT durable state.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseObject {
    /// Slot / height whose public execution surface collapsed.
    pub height: u64,
    /// Canonical hash of the previous slot's predecessor commitment.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
    /// Rolling accumulator hash binding this collapse object to the full prior continuity chain.
    #[serde(default)]
    pub continuity_accumulator_hash: [u8; 32],
    /// Recursive proof-carrying continuity step for this collapse object.
    #[serde(default)]
    pub continuity_recursive_proof: CanonicalCollapseRecursiveProof,
    /// Ordering outcome for the slot.
    #[serde(default)]
    pub ordering: CanonicalOrderingCollapse,
    /// Sealing outcome for the slot, when the block carries a sealed-finality proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing: Option<CanonicalSealingCollapse>,
    /// Canonical root hash of the committed transaction surface.
    #[serde(default)]
    pub transactions_root_hash: [u8; 32],
    /// Canonical root hash of the committed post-state.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Canonical hash of the latest archived recovered-history checkpoint named by ordinary
    /// canonical history at this slot.
    #[serde(default)]
    pub archived_recovered_history_checkpoint_hash: [u8; 32],
    /// Canonical hash of the governing archived recovered-history profile activation referenced by
    /// ordinary canonical history at this slot.
    #[serde(default)]
    pub archived_recovered_history_profile_activation_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history retention receipt referenced by ordinary
    /// canonical history at this slot.
    #[serde(default)]
    pub archived_recovered_history_retention_receipt_hash: [u8; 32],
}

/// Compact durable prefix entry exposed to replay / checkpoint consumers.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalReplayPrefixEntry {
    /// Slot / height of the durable prefix entry.
    pub height: u64,
    /// Canonical root hash of the committed post-state for this slot.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Canonical block hash / next-parent hash when objectively derivable from the recovered slot
    /// surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_block_commitment_hash: Option<[u8; 32]>,
    /// Canonical parent block hash carried by this slot when objectively derivable from the
    /// recovered slot surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_block_commitment_hash: Option<[u8; 32]>,
    /// Canonical hash of this slot's collapse predecessor commitment.
    #[serde(default)]
    pub canonical_collapse_commitment_hash: [u8; 32],
    /// Canonical hash of the previous slot's collapse predecessor commitment.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
    /// Whether ordering resolved to the positive close or negative abort path.
    #[serde(default)]
    pub ordering_kind: CanonicalCollapseKind,
    /// Canonical hash of the close-or-abort ordering resolution carried by this slot.
    #[serde(default)]
    pub ordering_resolution_hash: [u8; 32],
    /// Canonical hash of the latest compact publication frontier when one exists for this slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_frontier_hash: Option<[u8; 32]>,
    /// Whether the ordinary extracted bulletin surface is present for this slot.
    #[serde(default)]
    pub extracted_bulletin_surface_present: bool,
    /// Canonical hash of the archived recovered-history checkpoint named by ordinary canonical
    /// history at this slot, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_recovered_history_checkpoint_hash: Option<[u8; 32]>,
    /// Canonical hash of the governing archived recovered-history profile activation named by
    /// ordinary canonical history at this slot, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_recovered_history_profile_activation_hash: Option<[u8; 32]>,
    /// Canonical hash of the archived recovered-history retention receipt named by ordinary
    /// canonical history at this slot, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_recovered_history_retention_receipt_hash: Option<[u8; 32]>,
}

/// Compact ordinary-AFT continuation anchor naming the deeper historical continuation root.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AftHistoricalContinuationAnchor {
    /// Canonical hash of the historical checkpoint named by ordinary AFT history.
    #[serde(default)]
    pub checkpoint_hash: [u8; 32],
    /// Canonical hash of the governing historical profile activation named by ordinary AFT
    /// history.
    #[serde(default)]
    pub profile_activation_hash: [u8; 32],
    /// Canonical hash of the retention receipt binding the historical checkpoint into ordinary AFT
    /// history.
    #[serde(default)]
    pub retention_receipt_hash: [u8; 32],
}

/// AFT-native alias for the compact archived checkpoint carried by the ordinary historical
/// continuation surface.
pub type AftHistoricalCheckpoint = ArchivedRecoveredHistoryCheckpoint;

/// AFT-native alias for the profile that governs the ordinary historical continuation surface.
pub type AftHistoricalProfile = ArchivedRecoveredHistoryProfile;

/// AFT-native alias for the activation that governs the ordinary historical continuation surface.
pub type AftHistoricalProfileActivation = ArchivedRecoveredHistoryProfileActivation;

/// AFT-native alias for the retention receipt that binds the ordinary historical continuation
/// surface into authoritative AFT state.
pub type AftHistoricalRetentionReceipt = ArchivedRecoveredHistoryRetentionReceipt;

/// Ordinary AFT historical-continuation bundle carried alongside the recovered-state surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AftHistoricalRetrievabilitySurface {
    /// Compact anchor named by ordinary canonical AFT history.
    pub anchor: AftHistoricalContinuationAnchor,
    /// Historical checkpoint reached by the ordinary continuation anchor.
    pub checkpoint: AftHistoricalCheckpoint,
    /// Governing historical profile activation reached by the ordinary continuation anchor.
    pub profile_activation: AftHistoricalProfileActivation,
    /// Retention receipt binding the anchored continuation into authoritative AFT state.
    pub retention_receipt: AftHistoricalRetentionReceipt,
}

/// Compact recovered header entry exposed to bounded restart / ancestry consumers.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveredCanonicalHeaderEntry {
    /// Slot / height of the recovered header entry.
    pub height: u64,
    /// Canonical view carried by the recovered slot surface.
    #[serde(default)]
    pub view: u64,
    /// Canonical block hash / next-parent hash recovered for this slot.
    #[serde(default)]
    pub canonical_block_commitment_hash: [u8; 32],
    /// Canonical parent block hash carried by the recovered slot surface.
    #[serde(default)]
    pub parent_block_commitment_hash: [u8; 32],
    /// Canonical ordered-transactions root hash carried by the recovered slot surface.
    #[serde(default)]
    pub transactions_root_hash: [u8; 32],
    /// Canonical resulting state root carried by the recovered slot surface.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Canonical predecessor collapse commitment hash that this slot extends.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
}

impl RecoveredCanonicalHeaderEntry {
    /// Builds the restart-only synthetic quorum certificate certified by this recovered slot.
    pub fn synthetic_quorum_certificate(&self) -> QuorumCertificate {
        QuorumCertificate {
            height: self.height,
            view: self.view,
            block_hash: self.canonical_block_commitment_hash,
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        }
    }
}

/// Compact recovered certified-header entry exposed to bounded restart / QC consumers.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveredCertifiedHeaderEntry {
    /// Recovered canonical-header identity for this certified slot.
    pub header: RecoveredCanonicalHeaderEntry,
    /// Synthetic parent QC implied by the bounded recovered prefix for this slot.
    #[serde(default)]
    pub certified_parent_quorum_certificate: QuorumCertificate,
    /// Canonical resulting state root carried by the certified parent slot.
    #[serde(default)]
    pub certified_parent_resulting_state_root_hash: [u8; 32],
}

impl RecoveredCertifiedHeaderEntry {
    /// Builds the restart-only synthetic quorum certificate certified by this recovered slot.
    pub fn certified_quorum_certificate(&self) -> QuorumCertificate {
        self.header.synthetic_quorum_certificate()
    }
}

/// Restart-only recovered block-header cache entry for bounded QC/header lookup.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct RecoveredRestartBlockHeaderEntry {
    /// Compact recovered certified-header linkage for this slot.
    pub certified_header: RecoveredCertifiedHeaderEntry,
    /// Restart-only synthetic block header derived from the recovered closed-slot surface.
    pub header: BlockHeader,
}

impl RecoveredRestartBlockHeaderEntry {
    /// Builds the restart-only synthetic quorum certificate certified by this recovered slot.
    pub fn certified_quorum_certificate(&self) -> QuorumCertificate {
        self.certified_header.certified_quorum_certificate()
    }
}

/// AFT-native alias for the compact replay-prefix entry exposed to restart and replay consumers.
pub type AftRecoveredReplayEntry = CanonicalReplayPrefixEntry;

/// AFT-native alias for the compact recovered consensus-header entry exposed to restart consumers.
pub type AftRecoveredConsensusHeaderEntry = RecoveredCanonicalHeaderEntry;

/// AFT-native alias for the compact recovered certified-header entry exposed to restart consumers.
pub type AftRecoveredCertifiedHeaderEntry = RecoveredCertifiedHeaderEntry;

/// AFT-native alias for the restart-only recovered block-header cache entry exposed to restart
/// consumers.
pub type AftRecoveredRestartHeaderEntry = RecoveredRestartBlockHeaderEntry;

/// AFT-native recovered-state contract consumed by replay, restart, and bounded ancestry
/// continuation.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AftRecoveredStateSurface {
    /// Compact durable replay prefix recovered for the requested height window.
    #[serde(default)]
    pub replay_prefix: Vec<AftRecoveredReplayEntry>,
    /// Compact recovered consensus-header prefix for the requested height window.
    #[serde(default)]
    pub consensus_headers: Vec<AftRecoveredConsensusHeaderEntry>,
    /// Compact recovered certified-header prefix for the requested height window.
    #[serde(default)]
    pub certified_headers: Vec<AftRecoveredCertifiedHeaderEntry>,
    /// Restart-only recovered block-header cache entries for the requested height window.
    #[serde(default)]
    pub restart_headers: Vec<AftRecoveredRestartHeaderEntry>,
    /// Ordinary historical continuation bundle named by canonical AFT history at the recovered tip,
    /// when deeper paging beyond the retained suffix is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub historical_retrievability: Option<AftHistoricalRetrievabilitySurface>,
}

/// Backward-compatible alias for the older continuation-only vocabulary.
pub type AftHistoricalContinuationSurface = AftHistoricalRetrievabilitySurface;

/// Summary of how much of an AFT recovered-state surface a consensus engine accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AftRecoveredStateObservationStats {
    /// Number of recovered consensus-header entries accepted by the engine.
    pub accepted_consensus_headers: usize,
    /// Number of recovered certified-header entries accepted by the engine.
    pub accepted_certified_headers: usize,
    /// Number of recovered restart-header entries accepted by the engine.
    pub accepted_restart_headers: usize,
}

impl AftRecoveredStateObservationStats {
    /// Returns true when the engine accepted at least one recovered-state hint.
    pub fn accepted_any(&self) -> bool {
        self.accepted_consensus_headers > 0
            || self.accepted_certified_headers > 0
            || self.accepted_restart_headers > 0
    }
}

/// One cold-path page of exact-overlap recovered certified-branch ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCertifiedBranchPage {
    /// First height covered by this page.
    pub start_height: u64,
    /// Last height covered by this page.
    pub end_height: u64,
    /// Exact-overlap window ranges grouped into segment slices.
    pub segments: Vec<Vec<(u64, u64)>>,
}

/// Deterministic cold-path cursor for paging older recovered certified-branch pages.
///
/// The cursor starts from an already loaded bounded recovered suffix and then
/// pages one older exact-overlap segment fold at a time while keeping only the
/// current loaded page plus the next overlap candidate in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCertifiedBranchCursor {
    loaded_page: RecoveredCertifiedBranchPage,
    next_page_end_height: u64,
    next_overlap_candidate_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
}

/// Backwards-compatible alias for a cold-path recovered certified-branch page.
pub type RecoveredSegmentFoldPage = RecoveredCertifiedBranchPage;
/// Backwards-compatible alias for a cold-path recovered certified-branch cursor.
pub type RecoveredSegmentFoldCursor = RecoveredCertifiedBranchCursor;

impl RecoveredCertifiedBranchCursor {
    /// Builds a cursor for paging older recovered segment folds that precede an
    /// already loaded bounded suffix ending at `end_height`.
    pub fn new(
        end_height: u64,
        window: u64,
        overlap: u64,
        windows_per_segment: u64,
        segments_per_fold: u64,
        initial_fold_count: u64,
    ) -> Result<Self, String> {
        if end_height == 0 {
            return Err("recovered segment-fold cursor requires a non-zero end height".into());
        }
        if window == 0
            || windows_per_segment == 0
            || segments_per_fold == 0
            || initial_fold_count == 0
        {
            return Err(
                "recovered segment-fold cursor requires non-zero window, segment, and fold budgets"
                    .into(),
            );
        }

        let initial_start_height = recovered_segment_fold_start_height(
            end_height,
            window,
            overlap,
            windows_per_segment,
            segments_per_fold,
            initial_fold_count,
        );
        let loaded_page = RecoveredCertifiedBranchPage {
            start_height: initial_start_height,
            end_height,
            segments: recovered_segment_ranges(
                initial_start_height,
                end_height,
                window,
                overlap,
                windows_per_segment,
            ),
        };

        let next_page_end_height = if loaded_page.start_height <= 1 {
            0
        } else {
            loaded_page.start_height
                + recovered_segment_fold_overlap(
                    window,
                    overlap,
                    windows_per_segment,
                    segments_per_fold,
                )?
                - 1
        };
        let next_overlap_candidate_height = if next_page_end_height == 0 {
            0
        } else {
            next_page_end_height
        };

        Ok(Self {
            loaded_page,
            next_page_end_height,
            next_overlap_candidate_height,
            window,
            overlap,
            windows_per_segment,
            segments_per_fold,
        })
    }

    /// Returns the currently loaded bounded recovered page.
    pub fn loaded_page(&self) -> &RecoveredCertifiedBranchPage {
        &self.loaded_page
    }

    /// Returns the oldest height currently loaded by this cursor.
    pub fn oldest_loaded_height(&self) -> u64 {
        self.loaded_page.start_height
    }

    /// Returns the end height that the next older page will cover, if any.
    pub fn next_page_end_height(&self) -> Option<u64> {
        (self.next_page_end_height > 0).then_some(self.next_page_end_height)
    }

    /// Returns the overlap height the next older page must match, if any.
    pub fn next_overlap_candidate_height(&self) -> Option<u64> {
        (self.next_overlap_candidate_height > 0).then_some(self.next_overlap_candidate_height)
    }

    /// Returns the next older exact-overlap page the cursor expects, if any.
    pub fn expected_next_page(&self) -> Result<Option<RecoveredCertifiedBranchPage>, String> {
        let Some(end_height) = self.next_page_end_height() else {
            return Ok(None);
        };

        let fold_span = recovered_segment_fold_span(
            self.window,
            self.overlap,
            self.windows_per_segment,
            self.segments_per_fold,
        )?;
        let start_height = end_height
            .saturating_sub(fold_span.saturating_sub(1))
            .max(1);
        Ok(Some(RecoveredCertifiedBranchPage {
            start_height,
            end_height,
            segments: recovered_segment_ranges(
                start_height,
                end_height,
                self.window,
                self.overlap,
                self.windows_per_segment,
            ),
        }))
    }

    /// Accepts the next older page after validating that it is the exact page
    /// this cursor expects to load.
    pub fn accept_page(&mut self, page: &RecoveredCertifiedBranchPage) -> Result<(), String> {
        let Some(expected) = self.expected_next_page()? else {
            return Err("recovered certified-branch cursor is already exhausted".into());
        };
        if page != &expected {
            return Err(format!(
                "recovered certified-branch cursor expected page {}..={} but received {}..={}",
                expected.start_height, expected.end_height, page.start_height, page.end_height
            ));
        }

        self.loaded_page = page.clone();
        self.next_page_end_height = if page.start_height <= 1 {
            0
        } else {
            page.start_height
                + recovered_segment_fold_overlap(
                    self.window,
                    self.overlap,
                    self.windows_per_segment,
                    self.segments_per_fold,
                )?
                - 1
        };
        self.next_overlap_candidate_height = self.next_page_end_height;
        Ok(())
    }

    /// Returns and consumes the next older exact-overlap page, if any.
    pub fn next_page(&mut self) -> Result<Option<RecoveredCertifiedBranchPage>, String> {
        let Some(page) = self.expected_next_page()? else {
            return Ok(None);
        };
        self.accept_page(&page)?;
        Ok(Some(page))
    }
}

/// Validates that a recovered page covers exactly the heights it claims.
pub fn validate_recovered_page_coverage<T, F>(
    page: &RecoveredCertifiedBranchPage,
    entries: &[T],
    height_of: F,
    label: &str,
) -> Result<(), String>
where
    F: Fn(&T) -> u64,
{
    if page.start_height == 0 || page.end_height == 0 || page.end_height < page.start_height {
        return Err(format!(
            "{label} page has an invalid height range {}..={}",
            page.start_height, page.end_height
        ));
    }
    let expected_len = usize::try_from(page.end_height - page.start_height + 1)
        .map_err(|_| format!("{label} page length overflow"))?;
    if entries.len() != expected_len {
        return Err(format!(
            "{label} page {}..={} expected {} entries but loaded {}",
            page.start_height,
            page.end_height,
            expected_len,
            entries.len()
        ));
    }
    if let Some(first) = entries.first() {
        let first_height = height_of(first);
        if first_height != page.start_height {
            return Err(format!(
                "{label} page {}..={} started at loaded height {}",
                page.start_height, page.end_height, first_height
            ));
        }
    }
    if let Some(last) = entries.last() {
        let last_height = height_of(last);
        if last_height != page.end_height {
            return Err(format!(
                "{label} page {}..={} ended at loaded height {}",
                page.start_height, page.end_height, last_height
            ));
        }
    }
    for pair in entries.windows(2) {
        let previous_height = height_of(&pair[0]);
        let next_height = height_of(&pair[1]);
        if next_height != previous_height + 1 {
            return Err(format!(
                "{label} page {}..={} is not consecutive at heights {} then {}",
                page.start_height, page.end_height, previous_height, next_height
            ));
        }
    }
    Ok(())
}

fn recovered_window_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
) -> Vec<(u64, u64)> {
    if start_height == 0 || end_height == 0 || window == 0 || end_height < start_height {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let mut ranges = Vec::new();
    let step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let mut next_start = start_height;

    loop {
        let next_end = next_start
            .saturating_add(window.saturating_sub(1))
            .min(end_height);
        ranges.push((next_start, next_end));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(step);
    }

    ranges
}

fn recovered_segment_step(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Result<u64, String> {
    if window == 0 || windows_per_segment == 0 {
        return Err("recovered segment step requires non-zero window and segment width".into());
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    Ok(raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1))
}

fn recovered_segment_span(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Result<u64, String> {
    if window == 0 || windows_per_segment == 0 {
        return Err("recovered segment span requires non-zero window and segment width".into());
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    Ok(window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1))))
}

fn recovered_segment_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Vec<Vec<(u64, u64)>> {
    if start_height == 0
        || end_height == 0
        || window == 0
        || windows_per_segment == 0
        || end_height < start_height
    {
        return Vec::new();
    }

    let Ok(segment_span) = recovered_segment_span(window, overlap, windows_per_segment) else {
        return Vec::new();
    };
    let Ok(segment_step) = recovered_segment_step(window, overlap, windows_per_segment) else {
        return Vec::new();
    };

    let mut next_start = start_height;
    let mut segments = Vec::new();

    loop {
        let next_end = next_start
            .saturating_add(segment_span.saturating_sub(1))
            .min(end_height);
        segments.push(recovered_window_ranges(
            next_start, next_end, window, overlap,
        ));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(segment_step);
    }

    segments
}

fn recovered_segment_fold_span(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Result<u64, String> {
    if segments_per_fold == 0 {
        return Err("recovered segment-fold span requires a non-zero fold width".into());
    }

    let segment_span = recovered_segment_span(window, overlap, windows_per_segment)?;
    let segment_step = recovered_segment_step(window, overlap, windows_per_segment)?;
    Ok(segment_span
        .saturating_add(segment_step.saturating_mul(segments_per_fold.saturating_sub(1))))
}

fn recovered_segment_fold_step(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Result<u64, String> {
    if segments_per_fold == 0 {
        return Err("recovered segment-fold step requires a non-zero fold width".into());
    }

    let segment_step = recovered_segment_step(window, overlap, windows_per_segment)?;
    Ok(segment_step
        .saturating_mul(segments_per_fold.saturating_sub(1))
        .max(1))
}

fn recovered_segment_fold_overlap(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Result<u64, String> {
    let fold_span =
        recovered_segment_fold_span(window, overlap, windows_per_segment, segments_per_fold)?;
    let fold_step =
        recovered_segment_fold_step(window, overlap, windows_per_segment, segments_per_fold)?;
    Ok(fold_span.saturating_sub(fold_step))
}

pub(super) fn recovered_segment_fold_start_height(
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    fold_count: u64,
) -> u64 {
    if end_height == 0
        || window == 0
        || windows_per_segment == 0
        || segments_per_fold == 0
        || fold_count == 0
    {
        return 0;
    }

    let Ok(fold_span) =
        recovered_segment_fold_span(window, overlap, windows_per_segment, segments_per_fold)
    else {
        return 0;
    };
    let Ok(fold_step) =
        recovered_segment_fold_step(window, overlap, windows_per_segment, segments_per_fold)
    else {
        return 0;
    };
    let covered_span =
        fold_span.saturating_add(fold_step.saturating_mul(fold_count.saturating_sub(1)));
    end_height
        .saturating_sub(covered_span.saturating_sub(1))
        .max(1)
}
