// Path: crates/consensus/src/aft/authenticated_quorum.rs

//! Authenticated native-AFT vote and quorum-certificate verification.
//!
//! The AFT engine historically aggregated [`ConsensusVote`]s into a
//! [`QuorumCertificate`] by counting distinct `voter` account ids, and
//! re-checked a received certificate by summing declared validator weight while
//! discarding the signature bytes entirely. Neither step proved that the named
//! account actually signed anything, so a certificate was only ever as
//! trustworthy as the peer that handed it over.
//!
//! This module supplies the missing proof. Every admitted vote and every
//! accepted certificate is re-derived from raw key material:
//!
//! ```text
//! raw Ed25519 or ML-DSA-44 public key
//!   -> account_id_from_key_material(suite, key)      (canonical derivation)
//!   -> ActiveKeyRecord::public_key_hash              (authoritative binding)
//!   -> ValidatorV1 named by the vote's `voter`       (effective-set membership)
//!   -> Ed25519 signature over the native vote preimage
//! ```
//!
//! Every step is fail-closed: an unknown account, an unavailable key, a suite
//! mismatch, a key that is not yet active at the voted height, a duplicate
//! signer, wrong block coordinates, malformed bytes, or a signature that does
//! not verify all produce an error rather than a silently-dropped check.
//!
//! ## Wire compatibility
//!
//! Nothing here changes a byte on the wire. The preimage in
//! [`consensus_vote_signing_bytes`] is exactly the tuple the existing signing
//! sites already produce, and the key material is recovered out-of-band via
//! [`ValidatorKeyRegistry`] rather than added to [`ConsensusVote`] or
//! [`QuorumCertificate`]. See [`ValidatorKeyRegistry`] for how a node learns
//! the keys it needs without a new message type.

use ioi_api::consensus::{
    NativeAftFinalizedEvidence, NativeAftMembershipMember, NativeAftQuorumSigner,
};
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_crypto::sign::dilithium::{MldsaPublicKey, MldsaSignature};
use ioi_types::app::{
    account_id_from_key_material, AccountId, AftTimeoutVoteV1, ConsensusVote, QuorumCertificate,
    SignatureSuite, ValidatorSetV1, ValidatorV1, ViewChangeVote,
};
use ioi_types::codec;
use ioi_types::config::AftSafetyMode;
use ioi_types::error::ConsensusError;
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use std::collections::{BTreeMap, BTreeSet};

/// The exact byte string a validator signs when voting for a block.
///
/// This is the *native* AFT preimage: a plain canonical SCALE encoding of the
/// `(height, view, block_hash)` tuple, 48 bytes, with **no** domain separator.
/// It is reproduced here verbatim from the signing sites in the validator
/// orchestration so verification and signing cannot drift apart. Changing it
/// would be a wire break, so it is deliberately not "improved" with a domain
/// tag: this function exists to verify what the network actually signs today.
pub fn consensus_vote_signing_bytes(
    height: u64,
    view: u64,
    block_hash: &[u8; 32],
) -> Result<Vec<u8>, ConsensusError> {
    codec::to_bytes_canonical(&(height, view, *block_hash)).map_err(|error| {
        ConsensusError::BlockVerificationFailed(format!(
            "failed to encode consensus vote preimage: {error}"
        ))
    })
}

/// The exact byte string the validator runtime signs for a view-change vote.
///
/// Like [`consensus_vote_signing_bytes`], this preserves the existing wire
/// preimage rather than inventing a new domain separator after deployment.
pub fn view_change_vote_signing_bytes(height: u64, view: u64) -> Result<Vec<u8>, ConsensusError> {
    codec::to_bytes_canonical(&(height, view)).map_err(|error| {
        ConsensusError::BlockVerificationFailed(format!(
            "failed to encode view-change vote preimage: {error}"
        ))
    })
}

/// A public key that some validator's `consensus_key` record may bind to.
#[derive(Clone)]
pub struct ValidatorPublicKey {
    suite: SignatureSuite,
    /// Canonical raw key bytes (32 bytes for Ed25519). This is the form the
    /// offline `ioi-finality` verifier consumes and the form
    /// `account_id_from_key_material` reduces every encoding to.
    raw: Vec<u8>,
    verifier: ValidatorVerifier,
}

#[derive(Clone)]
enum ValidatorVerifier {
    Ed25519(PublicKey),
    MlDsa44(MldsaPublicKey),
}

impl ValidatorPublicKey {
    /// The signature suite this key belongs to.
    pub fn suite(&self) -> SignatureSuite {
        self.suite
    }

    /// The canonical raw public key bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The derived key hash, i.e. exactly the value an [`ioi_types::app::ActiveKeyRecord`]
    /// stores in `public_key_hash`.
    pub fn key_hash(&self) -> Result<[u8; 32], ConsensusError> {
        account_id_from_key_material(self.suite, &self.raw).map_err(|error| {
            ConsensusError::BlockVerificationFailed(format!(
                "failed to derive validator key hash: {error}"
            ))
        })
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match &self.verifier {
            ValidatorVerifier::Ed25519(key) => key.verify(message, signature),
            ValidatorVerifier::MlDsa44(key) => MldsaSignature::from_bytes(signature)
                .and_then(|signature| key.verify(message, &signature))
                .is_ok(),
        }
    }
}

impl std::fmt::Debug for ValidatorPublicKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatorPublicKey")
            .field("suite", &self.suite)
            .field("raw_len", &self.raw.len())
            .finish_non_exhaustive()
    }
}

/// Reads one unsigned-varint from `bytes`, returning the value and the tail.
fn read_uvarint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return bytes.get(index + 1..).map(|rest| (value, rest));
        }
        shift += 7;
    }
    None
}

/// Recovers the public key inlined in an identity-multihash [`PeerId`].
///
/// libp2p encodes small keys (Ed25519 among them) as an *identity* multihash:
/// the "digest" is the protobuf-encoded public key itself, so the key is
/// already present in every `PeerId` the transport authenticated. Larger keys
/// (RSA) are hashed instead and carry no recoverable material; those return
/// `None` rather than a guess.
///
/// The parse is self-validating: the recovered key must reproduce exactly the
/// `PeerId` it came from, so a misparse can never yield an attacker-chosen key.
pub fn public_key_from_peer_id(peer: &PeerId) -> Option<PublicKey> {
    let bytes = peer.to_bytes();
    let (code, rest) = read_uvarint(&bytes)?;
    // 0x00 is the identity multihash code; anything else hashed the key away.
    if code != 0 {
        return None;
    }
    let (length, digest) = read_uvarint(rest)?;
    if digest.len() as u64 != length {
        return None;
    }
    let key = PublicKey::try_decode_protobuf(digest).ok()?;
    (key.to_peer_id() == *peer).then_some(key)
}

/// Public keys this node can use to check native AFT signatures.
///
/// On-chain validator records bind only a *hash* of the consensus key, so a
/// node cannot verify a vote from the validator set alone — it needs the raw
/// key. This registry collects raw keys from the two places they are already
/// available without any wire change:
///
/// * [`learn_local_public_key`](Self::learn_local_public_key) — the node's own
///   libp2p keypair, which covers every self-vote and replay.
/// * [`learn_peer_id`](Self::learn_peer_id) — the key inlined in an
///   Ed25519 `PeerId`, which covers every peer the transport has authenticated.
///
/// Entries are keyed by the derived key hash, which is precisely the value
/// `ActiveKeyRecord::public_key_hash` holds. Lookup is therefore itself the
/// binding step, and a validator that rotates its consensus key away from its
/// account id stays representable.
#[derive(Clone, Debug, Default)]
pub struct ValidatorKeyRegistry {
    keys: BTreeMap<[u8; 32], ValidatorPublicKey>,
}

impl ValidatorKeyRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a libp2p Ed25519 public key, returning the key hash it binds to.
    pub fn learn_public_key(&mut self, key: &PublicKey) -> Result<[u8; 32], ConsensusError> {
        let raw = key
            .clone()
            .try_into_ed25519()
            .map_err(|_| {
                ConsensusError::BlockVerificationFailed(
                    "native AFT votes are Ed25519; refusing to register a non-Ed25519 key".into(),
                )
            })?
            .to_bytes()
            .to_vec();
        let entry = ValidatorPublicKey {
            suite: SignatureSuite::ED25519,
            raw,
            verifier: ValidatorVerifier::Ed25519(key.clone()),
        };
        let hash = entry.key_hash()?;
        self.keys.insert(hash, entry);
        Ok(hash)
    }

    /// Records canonical raw key bytes for an explicitly declared suite.
    ///
    /// ML-DSA keys cannot be recovered from a libp2p peer id, so they arrive
    /// through the rooted validator identity map. The suite is never inferred
    /// from attacker-controlled length alone.
    pub fn learn_raw_public_key(
        &mut self,
        suite: SignatureSuite,
        raw: &[u8],
    ) -> Result<[u8; 32], ConsensusError> {
        let verifier = match suite {
            SignatureSuite::ED25519 => {
                let key =
                    libp2p::identity::ed25519::PublicKey::try_from_bytes(raw).map_err(|_| {
                        ConsensusError::BlockVerificationFailed(
                            "malformed raw Ed25519 native AFT consensus key".into(),
                        )
                    })?;
                ValidatorVerifier::Ed25519(PublicKey::from(key))
            }
            SignatureSuite::ML_DSA_44 => {
                if raw.len() != 1312 {
                    return Err(ConsensusError::BlockVerificationFailed(format!(
                        "malformed ML-DSA-44 native AFT consensus key: expected 1312 bytes, got {}",
                        raw.len()
                    )));
                }
                let key = MldsaPublicKey::from_bytes(raw).map_err(|error| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "malformed ML-DSA-44 native AFT consensus key: {error}"
                    ))
                })?;
                ValidatorVerifier::MlDsa44(key)
            }
            _ => {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "unsupported native AFT consensus key suite {suite:?}"
                )))
            }
        };
        let entry = ValidatorPublicKey {
            suite,
            raw: raw.to_vec(),
            verifier,
        };
        let hash = entry.key_hash()?;
        self.keys.insert(hash, entry);
        Ok(hash)
    }

    /// Records this node's own consensus key.
    pub fn learn_local_public_key(&mut self, key: &PublicKey) -> Result<[u8; 32], ConsensusError> {
        self.learn_public_key(key)
    }

    /// Records the key inlined in `peer`, if it carries one.
    ///
    /// Returns the bound key hash, or `None` when the peer id hashes its key
    /// away. A `None` here is not an error: it simply means this peer's votes
    /// stay unverifiable until its key arrives another way, and unverifiable
    /// votes are refused rather than trusted.
    pub fn learn_peer_id(&mut self, peer: &PeerId) -> Option<[u8; 32]> {
        let key = public_key_from_peer_id(peer)?;
        self.learn_public_key(&key).ok()
    }

    /// Looks up the key material bound to `key_hash`.
    pub fn get(&self, key_hash: &[u8; 32]) -> Option<&ValidatorPublicKey> {
        self.keys.get(key_hash)
    }

    /// Number of distinct keys held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the registry holds no keys at all.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// One signer whose signature over the exact native preimage verified, carried
/// together with the raw key material that verification actually used.
///
/// This is the material a downstream finality bridge needs and cannot recompute
/// from chain state, because the validator set stores only key hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSigner {
    /// The validator-set member whose record bound this key.
    pub account_id: AccountId,
    /// The suite the member's `consensus_key` declares.
    pub suite: SignatureSuite,
    /// Canonical raw public key bytes used to verify `signature`.
    pub public_key: Vec<u8>,
    /// The signature that verified over the native vote preimage.
    pub signature: Vec<u8>,
}

/// One independently rebound member of the complete effective validator set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMember {
    pub account_id: AccountId,
    pub suite: SignatureSuite,
    pub public_key: Vec<u8>,
    pub weight: u128,
}

/// Exact committee geometry for the normative PQ optimistic profile.
///
/// The profile is deliberately count-based: every member has one unit of
/// voting authority, `n = 3f + 1`, and a certificate requires `q = 2f + 1`
/// distinct ML-DSA-44 signatures. Weighted or mixed-suite memberships remain
/// separately labelled compatibility profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqOptimisticQuorumGeometryV1 {
    /// Number of voting members.
    pub n: u32,
    /// Declared Byzantine fault bound.
    pub f: u32,
    /// Required distinct signer count.
    pub q: u32,
}

/// Validates and derives the exact M2 normative quorum geometry.
pub fn pq_optimistic_quorum_geometry(
    set: &ValidatorSetV1,
) -> Result<PqOptimisticQuorumGeometryV1, ConsensusError> {
    let n = u32::try_from(set.validators.len()).map_err(|_| {
        ConsensusError::BlockVerificationFailed(
            "PQ optimistic validator count exceeds the v1 geometry range".into(),
        )
    })?;
    if n == 0 || (n - 1) % 3 != 0 {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "PQ optimistic membership requires exact n=3f+1 geometry, got n={n}"
        )));
    }
    if set
        .validators
        .windows(2)
        .any(|pair| pair[0].account_id >= pair[1].account_id)
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "PQ optimistic membership must be strictly sorted by account id with no duplicates"
                .into(),
        ));
    }
    if set
        .validators
        .iter()
        .any(|validator| validator.consensus_key.suite != SignatureSuite::ML_DSA_44)
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "PQ optimistic membership requires ML-DSA-44 for every validator".into(),
        ));
    }
    if set.validators.iter().any(|validator| validator.weight != 1)
        || set.total_weight != u128::from(n)
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "PQ optimistic v1 is unit-weight and refuses weighted authority".into(),
        ));
    }
    let f = (n - 1) / 3;
    let q = f.saturating_mul(2).saturating_add(1);
    Ok(PqOptimisticQuorumGeometryV1 { n, f, q })
}

/// A quorum certificate whose every signer was re-verified from raw key
/// material against the effective validator set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedQuorum {
    /// The certificate exactly as verified.
    pub quorum_certificate: QuorumCertificate,
    /// Distinct signers, in certificate order, each with verified key material.
    pub signers: Vec<VerifiedSigner>,
    /// Complete effective membership, rebound to raw key material.
    pub members: Vec<VerifiedMember>,
    /// First height at which this exact set applies.
    pub membership_effective_from_height: u64,
    /// The safety mode whose threshold this certificate was held to.
    pub safety_mode: AftSafetyMode,
    /// Voting members declared by the effective set at the certified height.
    pub total_voting_members: u64,
    /// The signer count the running mode required.
    pub quorum_threshold: u64,
}

impl VerifiedQuorum {
    /// Distinct members whose signature over this exact certificate verified.
    ///
    /// Never a count of signature bytes present, and never a weight sum.
    pub fn distinct_member_signatures_verified(&self) -> u64 {
        self.signers.len() as u64
    }

    /// The Byzantine fault count an `n`-member membership honestly tolerates
    /// under `n >= 3f + 1`, i.e. `f = (n - 1) / 3`.
    pub fn byzantine_fault_tolerance(&self) -> u64 {
        self.total_voting_members.saturating_sub(1) / 3
    }

    /// Whether this certificate may back a `bft_consensus_aft_v1` export.
    ///
    /// Deliberately stricter than the running-mode threshold. The export claims
    /// classical BFT, so it requires all of:
    ///
    /// * [`AftSafetyMode::ClassicBft`] — the majority and guardian modes carry
    ///   different assumptions and are never relabelled as `3f+1`/`2f+1`;
    /// * a membership that tolerates at least one fault (`f >= 1`), because a
    ///   membership tolerating zero faults is single-authority under a BFT label;
    /// * `n >= 3f + 1` declared members;
    /// * `>= 2f + 1` *distinct verified signers*, counted from signatures that
    ///   actually verified — not from declared weight.
    pub fn qualifies_bft_consensus_aft_v1(&self) -> bool {
        if !matches!(self.safety_mode, AftSafetyMode::ClassicBft) {
            return false;
        }
        let tolerance = self.byzantine_fault_tolerance();
        if tolerance == 0 {
            return false;
        }
        let minimum_members = tolerance.saturating_mul(3).saturating_add(1);
        let minimum_signers = tolerance.saturating_mul(2).saturating_add(1);
        self.total_voting_members >= minimum_members
            && self.distinct_member_signatures_verified() >= minimum_signers
    }

    /// Whether the verified certificate satisfies the exact normative PQ
    /// optimistic profile rather than merely a classical BFT threshold.
    pub fn qualifies_pq_optimistic_aft_v1(&self) -> bool {
        if !matches!(self.safety_mode, AftSafetyMode::ClassicBft) {
            return false;
        }
        let n = self.total_voting_members;
        if n == 0 || self.members.len() as u64 != n || (n - 1) % 3 != 0 {
            return false;
        }
        let f = (n - 1) / 3;
        if f == 0 {
            return false;
        }
        let member_ids: BTreeSet<AccountId> = self
            .members
            .iter()
            .filter(|member| member.suite == SignatureSuite::ML_DSA_44 && member.weight == 1)
            .map(|member| member.account_id)
            .collect();
        if member_ids.len() as u64 != n {
            return false;
        }
        let signer_ids: BTreeSet<AccountId> = self
            .signers
            .iter()
            .filter(|signer| signer.suite == SignatureSuite::ML_DSA_44)
            .map(|signer| signer.account_id)
            .collect();
        self.quorum_threshold == 2 * f + 1
            && signer_ids.len() == self.signers.len()
            && signer_ids.is_subset(&member_ids)
            && signer_ids.len() as u64 >= self.quorum_threshold
    }
}

/// Looks up `account` in `set`, failing closed when it is not a member.
fn member_of<'a>(
    set: &'a ValidatorSetV1,
    account: &AccountId,
) -> Result<&'a ValidatorV1, ConsensusError> {
    set.validators
        .iter()
        .find(|validator| validator.account_id == *account)
        .ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(format!(
                "vote from {} is not an effective validator-set member",
                hex::encode(account.as_ref())
            ))
        })
}

/// Verifies one signature against the validator-set record named by `account`.
///
/// This is the single binding routine shared by loose votes and by each
/// signature inside a certificate, so the two paths cannot diverge.
fn verify_member_signature(
    account: &AccountId,
    height: u64,
    view: u64,
    block_hash: &[u8; 32],
    signature: &[u8],
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedSigner, ConsensusError> {
    let preimage = consensus_vote_signing_bytes(height, view, block_hash)?;
    verify_member_signature_over_preimage(
        account,
        height,
        signature,
        set,
        registry,
        &preimage,
        &format!(
            "H={} V={} block={}",
            height,
            view,
            hex::encode(block_hash.get(..4).unwrap_or_default())
        ),
    )
}

fn verify_member_signature_over_preimage(
    account: &AccountId,
    height: u64,
    signature: &[u8],
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
    preimage: &[u8],
    coordinates: &str,
) -> Result<VerifiedSigner, ConsensusError> {
    let validator = member_of(set, account)?;
    let record = &validator.consensus_key;

    if height < record.since_height {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "consensus key for {} is not active until height {}, but the vote is for height {}",
            hex::encode(account.as_ref()),
            record.since_height,
            height
        )));
    }

    if !matches!(
        record.suite,
        SignatureSuite::ED25519 | SignatureSuite::ML_DSA_44
    ) {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "consensus key suite {:?} for {} is not verifiable on the native AFT vote path",
            record.suite,
            hex::encode(account.as_ref())
        )));
    }

    // The lookup is the binding: the registry is keyed by the derived key hash,
    // so a hit means this raw key really does hash to what the chain authorized.
    let key = registry.get(&record.public_key_hash).ok_or_else(|| {
        ConsensusError::BlockVerificationFailed(format!(
            "no raw public key available for the consensus key authorized to {}",
            hex::encode(account.as_ref())
        ))
    })?;

    if key.suite() != record.suite {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "registered key suite {:?} does not match the authorized suite {:?} for {}",
            key.suite(),
            record.suite,
            hex::encode(account.as_ref())
        )));
    }

    // Re-derive rather than trust the registry's own indexing.
    if key.key_hash()? != record.public_key_hash {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "registered public key does not derive the consensus key hash authorized to {}",
            hex::encode(account.as_ref())
        )));
    }

    if signature.is_empty() {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "empty signature from {}",
            hex::encode(account.as_ref())
        )));
    }

    if !key.verify(preimage, signature) {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "signature from {} does not verify over {}",
            hex::encode(account.as_ref()),
            coordinates,
        )));
    }

    Ok(VerifiedSigner {
        account_id: *account,
        suite: record.suite,
        public_key: key.raw().to_vec(),
        signature: signature.to_vec(),
    })
}

fn verify_member_key(
    validator: &ValidatorV1,
    height: u64,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedMember, ConsensusError> {
    let record = &validator.consensus_key;
    if height < record.since_height {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "consensus key for {} is not active until height {}, but the quorum is for height {}",
            hex::encode(validator.account_id.as_ref()),
            record.since_height,
            height
        )));
    }
    if !matches!(
        record.suite,
        SignatureSuite::ED25519 | SignatureSuite::ML_DSA_44
    ) {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "consensus key suite {:?} for {} is not exportable on the native AFT finality path",
            record.suite,
            hex::encode(validator.account_id.as_ref())
        )));
    }
    let key = registry.get(&record.public_key_hash).ok_or_else(|| {
        ConsensusError::BlockVerificationFailed(format!(
            "no raw public key available for effective validator-set member {}",
            hex::encode(validator.account_id.as_ref())
        ))
    })?;
    if key.suite() != record.suite || key.key_hash()? != record.public_key_hash {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "registered key does not match the effective validator-set record for {}",
            hex::encode(validator.account_id.as_ref())
        )));
    }
    let derived_account =
        account_id_from_key_material(record.suite, key.raw()).map_err(|error| {
            ConsensusError::BlockVerificationFailed(format!(
                "failed to derive native AFT member account: {error}"
            ))
        })?;
    if derived_account != validator.account_id.0 {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "effective validator {} uses a rotated consensus key that the current portable finality contract cannot bind to the header account",
            hex::encode(validator.account_id.as_ref())
        )));
    }
    Ok(VerifiedMember {
        account_id: validator.account_id,
        suite: record.suite,
        public_key: key.raw().to_vec(),
        weight: validator.weight,
    })
}

/// Verifies a single loose vote before it may enter a vote pool.
///
/// `expected` pins the block coordinates the caller is willing to accept, so a
/// vote that verifies cryptographically but names a different slot is still
/// refused.
pub fn verify_consensus_vote(
    vote: &ConsensusVote,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedSigner, ConsensusError> {
    verify_member_signature(
        &vote.voter,
        vote.height,
        vote.view,
        &vote.block_hash,
        &vote.signature,
        set,
        registry,
    )
}

/// Verifies a view-change vote before it may influence a timeout quorum.
pub fn verify_view_change_vote(
    vote: &ViewChangeVote,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedSigner, ConsensusError> {
    let preimage = view_change_vote_signing_bytes(vote.height, vote.view)?;
    verify_member_signature_over_preimage(
        &vote.voter,
        vote.height,
        &vote.signature,
        set,
        registry,
        &preimage,
        &format!("view-change H={} V={}", vote.height, vote.view),
    )
}

/// Verifies a normative PQ timeout vote over its complete versioned authority
/// scope. The caller separately pins `vote.scope` to the configured scope.
pub fn verify_aft_timeout_vote(
    vote: &AftTimeoutVoteV1,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
) -> Result<VerifiedSigner, ConsensusError> {
    vote.validate_shape()
        .map_err(ConsensusError::BlockVerificationFailed)?;
    let preimage = vote
        .signing_bytes()
        .map_err(ConsensusError::BlockVerificationFailed)?;
    verify_member_signature_over_preimage(
        &vote.voter,
        vote.height,
        &vote.signature,
        set,
        registry,
        &preimage,
        &format!(
            "AFT timeout H={} V={} network={} configuration={} epoch={}",
            vote.height,
            vote.view,
            hex::encode(&vote.scope.network_id[..4]),
            hex::encode(&vote.scope.configuration_hash[..4]),
            vote.scope.epoch,
        ),
    )
}

/// Independently re-verifies a quorum certificate, whether it arrived from a
/// peer or was just assembled locally from the vote pool.
///
/// Checks, in order: a non-empty signature list, distinct signers, every
/// signature over the certificate's own exact coordinates, membership and key
/// binding per signer, and finally the running mode's signer threshold.
///
/// Note that an empty certificate is refused in *every* safety mode. The legacy
/// weight-summing path accepted an empty certificate outright under the
/// majority and guardian modes; on this authenticated path "no signatures" is
/// never a quorum.
pub fn verify_quorum_certificate(
    qc: &QuorumCertificate,
    set: &ValidatorSetV1,
    registry: &ValidatorKeyRegistry,
    safety_mode: AftSafetyMode,
    threshold: usize,
) -> Result<VerifiedQuorum, ConsensusError> {
    if qc.signatures.is_empty() {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "quorum certificate for height {} carries no signatures",
            qc.height
        )));
    }

    let members = set
        .validators
        .iter()
        .map(|validator| verify_member_key(validator, qc.height, registry))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen: BTreeSet<AccountId> = BTreeSet::new();
    let mut signers = Vec::with_capacity(qc.signatures.len());
    for (voter, signature) in &qc.signatures {
        if !seen.insert(*voter) {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "quorum certificate repeats signer {}: one key signing twice is one signer, not a quorum",
                hex::encode(voter.as_ref())
            )));
        }
        signers.push(verify_member_signature(
            voter,
            qc.height,
            qc.view,
            &qc.block_hash,
            signature,
            set,
            registry,
        )?);
    }

    let threshold = threshold as u64;
    let verified = signers.len() as u64;
    if verified < threshold {
        return Err(ConsensusError::BlockVerificationFailed(format!(
            "quorum certificate for height {} verified {verified} distinct signers, below the {threshold} required",
            qc.height
        )));
    }

    Ok(VerifiedQuorum {
        quorum_certificate: qc.clone(),
        signers,
        members,
        membership_effective_from_height: set.effective_from_height,
        safety_mode,
        total_voting_members: set.validators.len() as u64,
        quorum_threshold: threshold,
    })
}

/// A finalized native quorum certificate, released exactly once per committed
/// block after the safety gadget's guard and collapse gates have passed.
///
/// The carried certificate is the finalized block's **own** certificate — the
/// `qc_parent` the two-chain rule committed — not the child certificate whose
/// arrival triggered the commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AftFinalizedQuorumEvent {
    /// The finalized block's own quorum certificate.
    pub quorum_certificate: QuorumCertificate,
    /// Every signer re-verified at finalization time, with raw key material.
    pub signers: Vec<VerifiedSigner>,
    /// Complete effective membership, including non-signers.
    pub members: Vec<VerifiedMember>,
    /// First height at which the membership applies.
    pub membership_effective_from_height: u64,
    /// The safety mode in force when the block finalized.
    pub safety_mode: AftSafetyMode,
    /// Voting members declared by the effective set at the finalized height.
    pub total_voting_members: u64,
    /// Faults the membership honestly tolerates under `n >= 3f + 1`.
    pub byzantine_fault_tolerance: u64,
    /// The signer count the running mode required.
    pub quorum_threshold: u64,
    /// Distinct members whose signature verified over this certificate.
    pub distinct_member_signatures_verified: u64,
    /// Whether this evidence may back a `bft_consensus_aft_v1` export.
    pub bft_consensus_aft_v1_qualified: bool,
    /// Whether exact unit-weight `n=3f+1`, `q=2f+1`, all-ML-DSA geometry was
    /// verified for the normative PQ optimistic profile.
    pub pq_optimistic_aft_v1_qualified: bool,
}

impl AftFinalizedQuorumEvent {
    /// Builds the event from a verified quorum.
    pub fn from_verified(verified: VerifiedQuorum) -> Self {
        let byzantine_fault_tolerance = verified.byzantine_fault_tolerance();
        let distinct_member_signatures_verified = verified.distinct_member_signatures_verified();
        let bft_consensus_aft_v1_qualified = verified.qualifies_bft_consensus_aft_v1();
        let pq_optimistic_aft_v1_qualified = verified.qualifies_pq_optimistic_aft_v1();
        Self {
            quorum_certificate: verified.quorum_certificate,
            signers: verified.signers,
            members: verified.members,
            membership_effective_from_height: verified.membership_effective_from_height,
            safety_mode: verified.safety_mode,
            total_voting_members: verified.total_voting_members,
            byzantine_fault_tolerance,
            quorum_threshold: verified.quorum_threshold,
            distinct_member_signatures_verified,
            bft_consensus_aft_v1_qualified,
            pq_optimistic_aft_v1_qualified,
        }
    }

    /// The dedup identity of the finalized block: height and certified hash.
    pub fn dedup_key(&self) -> (u64, [u8; 32]) {
        (
            self.quorum_certificate.height,
            self.quorum_certificate.block_hash,
        )
    }
}

impl From<VerifiedSigner> for NativeAftQuorumSigner {
    fn from(signer: VerifiedSigner) -> Self {
        Self {
            account_id: signer.account_id,
            suite: signer.suite,
            public_key: signer.public_key,
            signature: signer.signature,
        }
    }
}

impl From<VerifiedMember> for NativeAftMembershipMember {
    fn from(member: VerifiedMember) -> Self {
        Self {
            account_id: member.account_id,
            suite: member.suite,
            public_key: member.public_key,
        }
    }
}

impl From<AftFinalizedQuorumEvent> for NativeAftFinalizedEvidence {
    fn from(event: AftFinalizedQuorumEvent) -> Self {
        Self {
            quorum_certificate: event.quorum_certificate,
            signers: event.signers.into_iter().map(Into::into).collect(),
            members: event.members.into_iter().map(Into::into).collect(),
            membership_effective_from_height: event.membership_effective_from_height,
            total_voting_members: event.total_voting_members,
            byzantine_fault_tolerance: event.byzantine_fault_tolerance,
            quorum_threshold: event.quorum_threshold,
            distinct_member_signatures_verified: event.distinct_member_signatures_verified,
            bft_consensus_aft_v1_qualified: event.bft_consensus_aft_v1_qualified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::SigningKeyPair;
    use ioi_crypto::security::SecurityLevel;
    use ioi_crypto::sign::dilithium::MldsaScheme;
    use ioi_types::app::ActiveKeyRecord;
    use libp2p::identity::Keypair;

    fn validator_from(keypair: &Keypair, weight: u128, since_height: u64) -> ValidatorV1 {
        let encoded = keypair.public().encode_protobuf();
        let hash = account_id_from_key_material(SignatureSuite::ED25519, &encoded).unwrap();
        ValidatorV1 {
            account_id: AccountId(hash),
            weight,
            consensus_key: ActiveKeyRecord {
                suite: SignatureSuite::ED25519,
                public_key_hash: hash,
                since_height,
            },
        }
    }

    fn set_of(keypairs: &[Keypair]) -> ValidatorSetV1 {
        let validators: Vec<ValidatorV1> = keypairs
            .iter()
            .map(|keypair| validator_from(keypair, 1, 1))
            .collect();
        ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: validators.len() as u128,
            validators,
        }
    }

    fn registry_of(keypairs: &[Keypair]) -> ValidatorKeyRegistry {
        let mut registry = ValidatorKeyRegistry::new();
        for keypair in keypairs {
            registry.learn_public_key(&keypair.public()).unwrap();
        }
        registry
    }

    fn signed_vote(
        keypair: &Keypair,
        height: u64,
        view: u64,
        block_hash: [u8; 32],
    ) -> ConsensusVote {
        let preimage = consensus_vote_signing_bytes(height, view, &block_hash).unwrap();
        let encoded = keypair.public().encode_protobuf();
        ConsensusVote {
            height,
            view,
            block_hash,
            voter: AccountId(
                account_id_from_key_material(SignatureSuite::ED25519, &encoded).unwrap(),
            ),
            signature: keypair.sign(&preimage).unwrap(),
        }
    }

    fn pq_set(n: u8) -> ValidatorSetV1 {
        let validators = (1..=n)
            .map(|index| ValidatorV1 {
                account_id: AccountId([index; 32]),
                weight: 1,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::ML_DSA_44,
                    public_key_hash: [index; 32],
                    since_height: 1,
                },
            })
            .collect::<Vec<_>>();
        ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: validators.len() as u128,
            validators,
        }
    }

    fn pq_verified_quorum(n: u8, signer_count: u8) -> VerifiedQuorum {
        let set = pq_set(n);
        let members = set
            .validators
            .iter()
            .map(|validator| VerifiedMember {
                account_id: validator.account_id,
                suite: validator.consensus_key.suite,
                public_key: vec![validator.account_id.0[0]; 32],
                weight: validator.weight,
            })
            .collect::<Vec<_>>();
        let signers = members
            .iter()
            .take(signer_count as usize)
            .map(|member| VerifiedSigner {
                account_id: member.account_id,
                suite: member.suite,
                public_key: member.public_key.clone(),
                signature: vec![member.account_id.0[0]; 64],
            })
            .collect::<Vec<_>>();
        let f = u64::from(n.saturating_sub(1) / 3);
        VerifiedQuorum {
            quorum_certificate: QuorumCertificate::default(),
            signers,
            members,
            membership_effective_from_height: 1,
            safety_mode: AftSafetyMode::ClassicBft,
            total_voting_members: u64::from(n),
            quorum_threshold: 2 * f + 1,
        }
    }

    #[test]
    fn pq_optimistic_geometry_is_exactly_three_f_plus_one_and_two_f_plus_one() {
        assert_eq!(
            pq_optimistic_quorum_geometry(&pq_set(4)).unwrap(),
            PqOptimisticQuorumGeometryV1 { n: 4, f: 1, q: 3 }
        );
        assert_eq!(
            pq_optimistic_quorum_geometry(&pq_set(7)).unwrap(),
            PqOptimisticQuorumGeometryV1 { n: 7, f: 2, q: 5 }
        );
    }

    #[test]
    fn pq_quorums_intersect_in_at_least_f_plus_one_members() {
        // Exhaust every quorum pair for representative exact geometries. This
        // checks the set property consumed by safety, not only the arithmetic
        // used to derive q.
        for f in [1u32, 2, 3] {
            let n = 3 * f + 1;
            let q = 2 * f + 1;
            let limit = 1u32 << n;
            for left in 0..limit {
                if left.count_ones() < q {
                    continue;
                }
                for right in 0..limit {
                    if right.count_ones() < q {
                        continue;
                    }
                    assert!(
                        (left & right).count_ones() >= f + 1,
                        "n={n} q={q} left={left:#b} right={right:#b}"
                    );
                }
            }
            assert!(n - f >= q, "honest capacity must be able to form q");
        }

        // Algebraic regression over a much wider range catches overflow or a
        // future formula drift without exponential enumeration.
        for f in 1u64..=10_000 {
            let n = 3 * f + 1;
            let q = 2 * f + 1;
            assert_eq!(2 * q - n, f + 1);
            assert_eq!(n - f, q);
        }
    }

    #[test]
    fn pq_optimistic_geometry_rejects_ambiguous_or_non_pq_authority() {
        assert!(pq_optimistic_quorum_geometry(&pq_set(5)).is_err());

        let mut mixed = pq_set(4);
        mixed.validators[3].consensus_key.suite = SignatureSuite::ED25519;
        assert!(pq_optimistic_quorum_geometry(&mixed).is_err());

        let mut weighted = pq_set(4);
        weighted.validators[3].weight = 2;
        weighted.total_weight = 5;
        assert!(pq_optimistic_quorum_geometry(&weighted).is_err());

        let mut wrong_total = pq_set(4);
        wrong_total.total_weight = 5;
        assert!(pq_optimistic_quorum_geometry(&wrong_total).is_err());

        let mut duplicate = pq_set(4);
        duplicate.validators[3].account_id = duplicate.validators[2].account_id;
        assert!(pq_optimistic_quorum_geometry(&duplicate).is_err());
    }

    #[test]
    fn pq_optimistic_qualification_is_fail_closed() {
        assert!(pq_verified_quorum(4, 3).qualifies_pq_optimistic_aft_v1());
        assert!(!pq_verified_quorum(4, 2).qualifies_pq_optimistic_aft_v1());
        assert!(!pq_verified_quorum(1, 1).qualifies_pq_optimistic_aft_v1());

        let mut weighted = pq_verified_quorum(4, 3);
        weighted.members[0].weight = 2;
        assert!(!weighted.qualifies_pq_optimistic_aft_v1());

        let mut duplicate_signer = pq_verified_quorum(4, 3);
        duplicate_signer.signers[2].account_id = duplicate_signer.signers[1].account_id;
        assert!(!duplicate_signer.qualifies_pq_optimistic_aft_v1());

        let mut compatibility_mode = pq_verified_quorum(4, 3);
        compatibility_mode.safety_mode = AftSafetyMode::GuardianMajority;
        assert!(!compatibility_mode.qualifies_pq_optimistic_aft_v1());
    }

    #[test]
    fn vote_preimage_is_the_plain_scale_tuple_the_network_signs() {
        let bytes = consensus_vote_signing_bytes(7, 2, &[9u8; 32]).unwrap();
        // 8-byte height + 8-byte view + 32-byte hash, no domain separator.
        assert_eq!(bytes.len(), 48);
        assert_eq!(
            bytes,
            codec::to_bytes_canonical(&(7u64, 2u64, [9u8; 32])).unwrap()
        );
    }

    #[test]
    fn genuine_vote_verifies_and_reports_raw_key_material() {
        let keys: Vec<Keypair> = (0..4).map(|_| Keypair::generate_ed25519()).collect();
        let set = set_of(&keys);
        let registry = registry_of(&keys);
        let vote = signed_vote(&keys[0], 5, 1, [3u8; 32]);

        let verified = verify_consensus_vote(&vote, &set, &registry).unwrap();
        assert_eq!(verified.account_id, vote.voter);
        assert_eq!(verified.suite, SignatureSuite::ED25519);
        assert_eq!(verified.public_key.len(), 32);
        assert_eq!(verified.signature, vote.signature);
    }

    #[test]
    fn genuine_ml_dsa_44_vote_verifies_and_replays_fail_closed() {
        let keypair = MldsaScheme::new(SecurityLevel::Level2)
            .generate_keypair()
            .unwrap();
        let public_key = keypair.public_key().to_bytes();
        let key_hash =
            account_id_from_key_material(SignatureSuite::ML_DSA_44, &public_key).unwrap();
        let validator = ValidatorV1 {
            account_id: AccountId(key_hash),
            weight: 1,
            consensus_key: ActiveKeyRecord {
                suite: SignatureSuite::ML_DSA_44,
                public_key_hash: key_hash,
                since_height: 1,
            },
        };
        let set = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 1,
            validators: vec![validator],
        };
        let mut registry = ValidatorKeyRegistry::new();
        assert_eq!(
            registry
                .learn_raw_public_key(SignatureSuite::ML_DSA_44, &public_key)
                .unwrap(),
            key_hash
        );

        let block_hash = [0xabu8; 32];
        let preimage = consensus_vote_signing_bytes(8, 3, &block_hash).unwrap();
        let signature = keypair.sign(&preimage).unwrap().to_bytes();
        let vote = ConsensusVote {
            height: 8,
            view: 3,
            block_hash,
            voter: AccountId(key_hash),
            signature,
        };

        let verified = verify_consensus_vote(&vote, &set, &registry).unwrap();
        assert_eq!(verified.suite, SignatureSuite::ML_DSA_44);
        assert_eq!(verified.public_key, public_key);

        let mut replayed = vote.clone();
        replayed.view += 1;
        assert!(verify_consensus_vote(&replayed, &set, &registry).is_err());

        let mut wrong_suite_set = set;
        wrong_suite_set.validators[0].consensus_key.suite = SignatureSuite::ED25519;
        assert!(verify_consensus_vote(&vote, &wrong_suite_set, &registry).is_err());
    }

    #[test]
    fn peer_id_round_trips_to_the_key_it_inlines() {
        let keypair = Keypair::generate_ed25519();
        let peer = keypair.public().to_peer_id();
        let recovered = public_key_from_peer_id(&peer).expect("ed25519 peer id inlines its key");
        assert_eq!(recovered, keypair.public());
    }

    #[test]
    fn registry_learns_the_hash_the_validator_record_binds() {
        let keypair = Keypair::generate_ed25519();
        let validator = validator_from(&keypair, 1, 1);
        let mut registry = ValidatorKeyRegistry::new();
        let hash = registry.learn_public_key(&keypair.public()).unwrap();
        assert_eq!(hash, validator.consensus_key.public_key_hash);
        assert!(registry
            .get(&validator.consensus_key.public_key_hash)
            .is_some());
    }
}
