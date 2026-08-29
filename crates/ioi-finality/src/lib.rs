//! Source-neutral v2 recognized-effect checkpoint emission and offline verification.
//!
//! Agentgres is IOI's current runtime owner and may call the emitter, but no
//! universal type or verifier rule below depends on Agentgres. Unsupported
//! profile/certificate semantics refuse before signature verification.
//!
//! Two canonical `ioi.ordering-admission-finality-profile.v1` members are
//! implemented: `single_authority`/`single_authority_v1` and
//! `bft_consensus`/`bft_consensus_aft_v1`. AFT is IOI's implementation of the
//! BFT member, not a sixth profile, so it is spelled with the canonical member
//! and carries its own certificate variant.
//!
//! ## What a verified claim does and does not establish
//!
//! The claim returned by [`verify_bundle`] establishes only the axes this code
//! actually recomputes — today `integrity` and `availability`, and only when the
//! declared verifier contract lists them with inputs this crate validated. It
//! never promotes an axis because a profile sounds stronger. In particular a
//! verified `bft_consensus` quorum does **not** establish `non_equivocation`:
//! a quorum certificate over one checkpoint says nothing about whether the same
//! members also signed a conflicting checkpoint at the same view, which is a
//! witness/transparency obligation with its own contract. `currentness` and
//! `authority_admission` remain refused for both profiles.
//!
//! ## Why the quorum floors exist
//!
//! A `bft_consensus` label and a single issuer signature are not peer safety.
//! [`verify_bundle`] therefore refuses a `bft_consensus_aft_v1` certificate
//! unless a declared membership of distinct members with distinct keys produced
//! a quorum of distinct verified signatures over the exact message the evidence
//! names, under a membership that tolerates at least one Byzantine fault,
//! satisfies `n >= 3f + 1`, and meets `2q > n + f`. That last bound, not the
//! familiar `2f + 1`, is the one that actually holds for every `n`: at
//! `n = 5, f = 1` two `2f + 1` quorums can intersect in exactly the Byzantine
//! member, so `2f + 1` alone would admit conflicting "honest" quorums.
//!
//! ## Two vote bindings, and why they must never be confused
//!
//! `bft_consensus_aft_v1` evidence declares a `vote_binding` naming which bytes
//! the members signed. The distinction is load-bearing:
//!
//! * [`NATIVE_AFT_VOTE_BINDING`] imports the `QuorumCertificate` the live AFT
//!   path already produced. The members signed the native SCALE
//!   `(height, view, block_hash)` payload, reproduced here through the same
//!   `ioi_types` codec the validator uses, so this bridge cannot drift from the
//!   algorithm it imports and adds no peer round to it. Membership is not taken
//!   on the issuer's word: each declared key is put through the chain's own
//!   `AccountId` derivation and the resulting set must equal the certified
//!   block header's committed `validator_set` exactly — a field inside the
//!   header's signing preimage, and therefore covered by the very hash the
//!   votes signed. This is the only binding a runtime may present as native AFT
//!   evidence. See [`emit_native_aft_consensus`].
//! * [`CHECKPOINT_VOTE_BINDING`] is this crate's own round over a prepared
//!   checkpoint. It is an honest quorum over an honest message, but it is *not*
//!   native AFT evidence: the AFT algorithm never signed a checkpoint. It is
//!   retained as a non-runtime surface only, and the Agentgres production
//!   adapter refuses it.
//!
//! The verifier reports the binding on [`VerifiedQuorum::vote_binding`]. A
//! relying party that needs native consensus safety must read that field: the
//! `bft_consensus_aft_v1` variant alone does not distinguish the two.
//!
//! ## What the native binding does not establish
//!
//! The imported quorum certifies **a block**. Nothing in it commits to this
//! checkpoint's recognized effect, so the checkpoint's association with that
//! block is declared by the issuer and recomputed by nobody; see
//! [`VerifiedNativeAftBlock::effect_committed_in_block`]. Separately, the live
//! engine does not itself verify these signatures — it forms a quorum on a vote
//! count and discards the signature bytes — so a claim here is never "consensus
//! accepted it" but only "these bytes verify offline", which is strictly
//! stronger. Finally, the native preimage carries no domain separator and no
//! chain identifier. That is a property of the AFT algorithm, preserved rather
//! than patched; the block hash covers the parent, state roots, and validator
//! set, so a cross-chain replay would have to be the same block.
//!
//! ## Certificate compatibility
//!
//! `FinalityCertificate` v1 cannot honestly bind peer quorum evidence in its
//! originally registered shape: every field is typed and closed, so there is
//! nowhere to put a membership, a threshold, or per-member signatures. Rather
//! than mint a successor certificate version — which would cascade into
//! `ReceiptCheckpoint` v3 and `ReceiptProofBundle` v3 for a field no
//! already-implemented variant may carry — this crate adds one
//! **variant-conditional** field, `consensus_evidence`, that the schema
//! *requires* for `bft_consensus_aft_v1`. Because the field is absent from a
//! `single_authority_v1` certificate, its JCS preimage, `body_hash`, signature
//! message, and signature are byte-identical to those issued before the field
//! existed. The repository schema dialect implements no negation keyword, so
//! refusing the field on a non-BFT variant is this verifier's obligation rather
//! than the schema's: see [`verify_variant_evidence_presence`], which both the
//! emitter and the verifier run. `ReceiptCheckpoint` v1 and `ReceiptProofBundle`
//! v1 are untouched and remain refused by this verifier.

#![forbid(unsafe_code)]

mod runtime_v3;
pub use runtime_v3::*;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ioi_api::crypto::{SerializableKey, SigningKey, VerifyingKey};
use ioi_crypto::sign::eddsa::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::generated::architecture_contracts::{
    architecture_contract_schema_hash, validate_architecture_contract,
};
use ioi_types::app::{
    account_id_from_key_material, canonical_transactions_root, Block, BlockHeader,
    ChainTransaction, SignatureSuite,
};
use ioi_types::codec::{from_bytes_canonical, to_bytes_canonical};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const BUNDLE_V2: &str = "schema://ioi/foundations/receipt-proof-bundle/v2";
const CHECKPOINT_V2: &str = "schema://ioi/foundations/receipt-checkpoint/v2";
const CONFLICT_BINDING_V1: &str = "schema://ioi/foundations/conflict-authority-binding/v1";
const RECOGNITION_V1: &str = "schema://ioi/foundations/recognition-class/v1";
const AVAILABILITY_V1: &str = "schema://ioi/foundations/availability-manifest/v1";
const RETENTION_V1: &str = "schema://ioi/foundations/retention-class/v1";
const VERIFIER_V1: &str = "schema://ioi/foundations/verifier-contract/v1";
const CERTIFICATE_V1: &str = "schema://ioi/foundations/finality-certificate/v1";
const CONSENSUS_EVIDENCE_V1: &str = "ioi.bft-consensus-evidence.v1";
const CONSENSUS_MEMBERSHIP_DOMAIN: &str = "ioi.bft-consensus-membership.v1";
const CONSENSUS_VOTE_DOMAIN: &str = "ioi.bft-consensus-vote.v1";

/// `vote_binding` for evidence imported from the live AFT consensus path. The
/// members signed the native `(height, view, block_hash)` payload; this crate
/// re-verifies those exact bytes and never asks for a second round.
pub const NATIVE_AFT_VOTE_BINDING: &str = "native_aft_quorum_certificate_v1";

/// `vote_binding` for the fresh, non-runtime round this crate can also collect
/// over a prepared checkpoint. It is a real quorum over a real message, but it
/// is **not** native AFT evidence and no runtime path may present it as such.
pub const CHECKPOINT_VOTE_BINDING: &str = "checkpoint_quorum_v1";

/// Names the exact preimage native AFT voters sign, so the artifact states the
/// signed bytes instead of leaving a relying party to assume them.
const NATIVE_AFT_VOTE_DOMAIN: &str = "ioi.aft-consensus-vote.scale-height-view-block-hash.v1";

/// The only implemented checkpoint/block association. See
/// [`VerifiedNativeAftBlock::effect_committed_in_block`].
const DECLARED_ASSOCIATION: &str = "declared_association_v1";

/// Explicit successor association for a durable, full native block. Unlike
/// [`DECLARED_ASSOCIATION`], every byte named by this mode can be recomputed:
/// the certified header, ordered transactions, transaction root, operation
/// coverage, and the pre/post state roots.
pub const FULL_BLOCK_EFFECT_COMMITMENT: &str = "full_block_effect_commitment_v1";

const FULL_BLOCK_OPERATION_ROOT_DOMAIN: &str = "ioi.full-block-operation-root.scale.v1";

/// The exact native AFT vote preimage: SCALE over `(height, view, block_hash)`,
/// which is byte-for-byte what `codec::to_bytes_canonical(&vote_payload)`
/// produces at every validator vote site. It is reproduced through the same
/// `ioi_types` codec rather than re-implemented, so this bridge cannot drift
/// from the algorithm it imports.
///
/// Note what these bytes do **not** carry: no domain separator and no chain
/// identifier. That is a property of the AFT algorithm, which this bridge
/// preserves rather than "fixes" — adding a separator here would verify bytes
/// no validator ever signed. See the replay nonclaim on [`VerifiedQuorum`].
pub fn native_aft_vote_message(
    height: u64,
    view: u64,
    block_hash: &[u8; 32],
) -> Result<Vec<u8>, VerificationError> {
    to_bytes_canonical(&(height, view, *block_hash))
        .map_err(|error| VerificationError::Field(format!("native AFT vote payload: {error}")))
}

/// Canonical `ioi.ordering-admission-finality-profile.v1` member set, owned by
/// `docs/architecture/foundations/canonical-enums.md`. A wire `profile` value
/// outside this set is refused; a label is never a wire value.
const CANONICAL_PROFILES: [&str; 5] = [
    "single_authority",
    "replicated_single_authority",
    "threshold_authority",
    "bft_consensus",
    "external_chain_finality",
];

/// The exact `(canonical member, certificate variant)` pairs this crate emits
/// and verifies. Every other canonical member refuses as unimplemented rather
/// than degrading to a weaker one it could check.
const IMPLEMENTED_PROFILES: [(&str, &str); 2] = [
    ("single_authority", "single_authority_v1"),
    ("bft_consensus", "bft_consensus_aft_v1"),
];

/// Compatibility labels from the canonical-enums compatibility map. The left
/// value is a label used in design prose; the right value is the canonical
/// member it resolves to before admission. Canonical members resolve to
/// themselves and are handled by [`CANONICAL_PROFILES`].
const PROFILE_LABEL_ALIASES: [(&str, &str); 3] = [
    ("replicated_cft", "replicated_single_authority"),
    ("aft", "bft_consensus"),
    ("external_finality", "external_chain_finality"),
];

/// Labels the canonical map deliberately refuses to resolve to one member.
const UNRESOLVABLE_PROFILE_LABELS: [&str; 1] = ["witnessed_threshold"];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("unsupported bundle version: {0}")]
    UnsupportedVersion(String),
    #[error("unsupported profile semantics: profile={profile} variant={variant}")]
    UnsupportedProfile { profile: String, variant: String },
    #[error(
        "profile label {label} does not resolve to one canonical member: decompose it into \
         threshold_authority when the witnesses hold admission authority shares, or into a \
         witness contract layered over the declared profile when they only attest to a head"
    )]
    AmbiguousProfileLabel { label: String },
    #[error("unknown profile label: {0}")]
    UnknownProfileLabel(String),
    #[error("consensus evidence refused: {0}")]
    ConsensusEvidence(String),
    #[error("unsupported verifier axis: {0}")]
    UnsupportedAxis(String),
    #[error("unsupported recognition semantics: class={class} derivation={derivation}")]
    UnsupportedRecognition { class: String, derivation: String },
    #[error("contract validation failed for {contract}: {detail}")]
    Contract {
        contract: &'static str,
        detail: String,
    },
    #[error("missing or malformed field: {0}")]
    Field(String),
    #[error("binding mismatch: {0}")]
    Binding(String),
    #[error("cryptographic verification failed: {0}")]
    Crypto(String),
}

/// The peer-quorum facts a `bft_consensus_aft_v1` certificate established, each
/// recomputed offline. This is the whole quorum claim: it does not extend to
/// non-equivocation, freshness, or authority admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedQuorum {
    pub membership_ref: String,
    pub membership_hash: String,
    pub membership_epoch: u64,
    pub view: u64,
    pub total_voting_members: u64,
    pub byzantine_fault_tolerance: u64,
    pub quorum_threshold: u64,
    /// Distinct declared members whose signature over the exact message named by
    /// `vote_binding` verified. Never a count of signature bytes present.
    pub distinct_member_signatures_verified: u64,
    /// Which bytes the members actually signed: [`NATIVE_AFT_VOTE_BINDING`] for
    /// evidence imported from the live consensus path, or
    /// [`CHECKPOINT_VOTE_BINDING`] for this crate's own non-runtime round.
    /// A relying party that needs native AFT safety must read this field —
    /// the `bft_consensus_aft_v1` variant alone does not distinguish them.
    pub vote_binding: String,
    /// Present only under [`NATIVE_AFT_VOTE_BINDING`]. `None` says no native
    /// block was claimed or checked, never that one was assumed.
    pub certified_block: Option<VerifiedNativeAftBlock>,
}

/// The native AFT block facts recomputed from durable header bytes. Every field
/// here was derived, not read off the certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedNativeAftBlock {
    pub block_height: u64,
    pub block_view: u64,
    pub block_hash: String,
    pub block_payload_ref: String,
    /// True when the durable header bytes were supplied and re-hashed to
    /// `block_hash`, and the declared membership derived exactly onto the
    /// header's own committed `validator_set`. False only on the predecessor
    /// path, where the bundle carries no payloads for a prior checkpoint; the
    /// predecessor's membership is still pinned by the `membership_hash`
    /// equality that `INV-42` enforces against this checkpoint.
    pub block_bytes_reverified: bool,
    /// Always `false` today, and deliberately so. The native quorum certifies
    /// **the block**; nothing in it commits to this checkpoint's recognized
    /// effect. Establishing that needs the execution seam that puts the effect
    /// into the block, plus a new named `effect_commitment` mode. A relying
    /// party must not read a verified quorum as peer agreement on the effect.
    pub effect_committed_in_block: bool,
}

/// One recognized operation's exact position in a native full block.
///
/// The transaction bytes are carried rather than only their hash so changed-
/// byte replay is refused even if a caller presents a stale cached digest. A
/// complete binding has exactly one row for every transaction, in block order,
/// with contiguous operation sequences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAftOperationBinding {
    pub operation_sequence: u64,
    pub transaction_index: u64,
    pub transaction_bytes: Vec<u8>,
}

/// Structural facts recomputed from a full native block whose header is the
/// exact header certified by AFT.
///
/// This result establishes the block/effect association only. It must be
/// combined with [`VerifiedQuorum`] before a caller claims peer finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedNativeAftEffectBlock {
    pub block_height: u64,
    pub block_view: u64,
    pub block_hash: String,
    pub transaction_count: u64,
    pub transaction_root: String,
    pub first_operation_sequence: Option<u64>,
    pub last_operation_sequence: Option<u64>,
    pub operation_root: String,
    pub previous_state_root: Vec<u8>,
    pub resulting_state_root: Vec<u8>,
    pub full_block_bytes_reverified: bool,
    pub effect_committed_in_block: bool,
    /// Native blocks do not commit individual receipt bytes today. This stays
    /// false until an explicit block/header successor adds that commitment.
    pub receipts_committed_in_block: bool,
}

/// Recompute the association between a native AFT-finalized header and every
/// operation in the durable full block that owns that header.
///
/// This is the execution-association primitive for an explicit successor
/// bundle. It intentionally does not reinterpret ReceiptCheckpoint v1/v2 or
/// ReceiptProofBundle v1/v2. A caller must separately verify the quorum in
/// [`NativeAftFinalizedBlock`]; this function proves only that the exact block
/// certified there contains the exact ordered transaction bytes and state
/// transition supplied here.
pub fn verify_native_aft_full_block_effects(
    finalized: &NativeAftFinalizedBlock,
    full_block_bytes: &[u8],
    bindings: &[NativeAftOperationBinding],
    expected_previous_state_root: &[u8],
    expected_resulting_state_root: &[u8],
) -> Result<VerifiedNativeAftEffectBlock, VerificationError> {
    let certified_header: BlockHeader = from_bytes_canonical(&finalized.block_header_bytes)
        .map_err(|error| refuse_evidence(format!("certified header does not decode: {error}")))?;
    let block: Block<ChainTransaction> = from_bytes_canonical(full_block_bytes)
        .map_err(|error| refuse_evidence(format!("full block does not decode: {error}")))?;

    let full_header_bytes = to_bytes_canonical(&block.header)
        .map_err(|error| refuse_evidence(format!("full block header does not encode: {error}")))?;
    if full_header_bytes != finalized.block_header_bytes || block.header != certified_header {
        return Err(refuse_evidence(
            "full block header is not byte-for-byte the quorum-certified header",
        ));
    }

    let certificate = &finalized.quorum_certificate;
    let block_hash: [u8; 32] = block
        .header
        .hash()
        .map_err(|error| refuse_evidence(format!("full block header does not hash: {error}")))?
        .as_slice()
        .try_into()
        .map_err(|_| refuse_evidence("full block header hash is not 32 bytes"))?;
    if block_hash != certificate.block_hash
        || block.header.height != certificate.height
        || block.header.view != certificate.view
    {
        return Err(refuse_evidence(
            "full block height/view/hash does not match the native quorum certificate",
        ));
    }

    let transaction_root = canonical_transactions_root(&block.transactions).map_err(|error| {
        refuse_evidence(format!(
            "full block transaction root does not derive: {error}"
        ))
    })?;
    if transaction_root != block.header.transactions_root {
        return Err(refuse_evidence(
            "full block transactions do not derive onto the certified header transaction root",
        ));
    }
    if block.header.parent_state_root.as_ref() != expected_previous_state_root {
        return Err(refuse_evidence(
            "recognized effect previous state root is not the certified block parent state root",
        ));
    }
    if block.header.state_root.as_ref() != expected_resulting_state_root {
        return Err(refuse_evidence(
            "recognized effect resulting state root is not the certified block state root",
        ));
    }
    if bindings.len() != block.transactions.len() {
        return Err(refuse_evidence(format!(
            "operation binding covers {} rows but the certified block contains {} transactions",
            bindings.len(),
            block.transactions.len()
        )));
    }

    let mut operation_rows = Vec::with_capacity(bindings.len());
    let mut first_sequence = None;
    let mut previous_sequence: Option<u64> = None;
    for (index, (binding, transaction)) in
        bindings.iter().zip(block.transactions.iter()).enumerate()
    {
        let expected_index = u64::try_from(index)
            .map_err(|_| refuse_evidence("transaction index does not fit in u64"))?;
        if binding.transaction_index != expected_index {
            return Err(refuse_evidence(format!(
                "operation binding index {} is not the block position {expected_index}",
                binding.transaction_index
            )));
        }
        if let Some(previous) = previous_sequence {
            if previous.checked_add(1) != Some(binding.operation_sequence) {
                return Err(refuse_evidence(
                    "operation binding sequence is duplicated, reordered, or has a gap",
                ));
            }
        } else {
            first_sequence = Some(binding.operation_sequence);
        }
        let canonical_transaction = to_bytes_canonical(transaction).map_err(|error| {
            refuse_evidence(format!(
                "block transaction {index} does not encode: {error}"
            ))
        })?;
        if canonical_transaction != binding.transaction_bytes {
            return Err(refuse_evidence(format!(
                "operation binding bytes differ from certified block transaction {index}"
            )));
        }
        let transaction_hash = transaction.hash().map_err(|error| {
            refuse_evidence(format!("transaction {index} does not hash: {error}"))
        })?;
        operation_rows.push((
            binding.operation_sequence,
            binding.transaction_index,
            transaction_hash,
        ));
        previous_sequence = Some(binding.operation_sequence);
    }

    let operation_root_bytes =
        to_bytes_canonical(&(FULL_BLOCK_OPERATION_ROOT_DOMAIN.as_bytes(), &operation_rows))
            .map_err(|error| {
                refuse_evidence(format!("operation root material does not encode: {error}"))
            })?;

    Ok(VerifiedNativeAftEffectBlock {
        block_height: block.header.height,
        block_view: block.header.view,
        block_hash: hash_prefixed(&block_hash),
        transaction_count: block.transactions.len() as u64,
        transaction_root: format!("sha256:{}", hex::encode(&transaction_root)),
        first_operation_sequence: first_sequence,
        last_operation_sequence: previous_sequence,
        operation_root: hash_bytes(&operation_root_bytes),
        previous_state_root: block.header.parent_state_root.0,
        resulting_state_root: block.header.state_root.0,
        full_block_bytes_reverified: true,
        effect_committed_in_block: true,
        receipts_committed_in_block: false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedClaim {
    pub checkpoint_id: String,
    pub domain_id: String,
    pub authority_epoch: u64,
    pub issuer_key_id: String,
    pub issuer_public_key: String,
    /// The canonical member carried on the wire, never a resolved label.
    pub profile: String,
    pub certificate_variant: String,
    /// Exactly the axes this verifier recomputed. Never widened by profile.
    pub established_axes: Vec<String>,
    /// Present only for `bft_consensus`; `None` says no quorum was claimed or
    /// checked, never that a quorum was assumed.
    pub quorum: Option<VerifiedQuorum>,
}

/// Axes this crate refuses for every profile, because it does not check them.
/// Named so a relying party reads the boundary from the code rather than
/// inferring it from an empty result.
pub const UNESTABLISHED_AXES: [&str; 5] = [
    "valid_as_of",
    "currentness",
    "non_equivocation",
    "authority_admission",
    "economic_recognition",
];

/// Resolve one ordering/finality **label** to its canonical member before
/// admission. Canonical members resolve to themselves; the compatibility labels
/// resolve per `canonical-enums.md`; `witnessed_threshold` deliberately refuses
/// because it conflates two separable guarantees. The result is the only value
/// that may appear on the wire — this function is an ingest step, and a label is
/// never itself a schema value.
pub fn resolve_profile_label(label: &str) -> Result<&'static str, VerificationError> {
    for member in CANONICAL_PROFILES {
        if member == label {
            return Ok(member);
        }
    }
    for (alias, member) in PROFILE_LABEL_ALIASES {
        if alias == label {
            return Ok(member);
        }
    }
    if UNRESOLVABLE_PROFILE_LABELS.contains(&label) {
        return Err(VerificationError::AmbiguousProfileLabel {
            label: label.to_owned(),
        });
    }
    Err(VerificationError::UnknownProfileLabel(label.to_owned()))
}

/// The certificate variant this crate implements for one canonical member, or
/// `None` when the member is canonical but unimplemented here.
fn implemented_variant(member: &str) -> Option<&'static str> {
    for (profile, variant) in IMPLEMENTED_PROFILES {
        if profile == member {
            return Some(variant);
        }
    }
    None
}

/// Read the wire profile/variant pair and admit it only when it is an exactly
/// implemented canonical pair. A compatibility label on the wire refuses here
/// rather than being resolved, because resolution happens before admission.
fn admitted_profile(
    checkpoint: &Value,
    certificate: &Value,
) -> Result<(&'static str, &'static str), VerificationError> {
    let profile = text(checkpoint, "profile")?;
    let variant = text(certificate, "certificate_variant")?;
    for (member, expected) in IMPLEMENTED_PROFILES {
        if member == profile && expected == variant {
            return Ok((member, expected));
        }
    }
    Err(VerificationError::UnsupportedProfile { profile, variant })
}

fn object(value: &Value) -> Result<&Map<String, Value>, VerificationError> {
    value
        .as_object()
        .ok_or_else(|| VerificationError::Field("expected object".into()))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, VerificationError> {
    object(value)?
        .get(name)
        .ok_or_else(|| VerificationError::Field(name.into()))
}

fn text(value: &Value, name: &str) -> Result<String, VerificationError> {
    field(value, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| VerificationError::Field(name.into()))
}

fn number(value: &Value, name: &str) -> Result<u64, VerificationError> {
    field(value, name)?
        .as_u64()
        .ok_or_else(|| VerificationError::Field(name.into()))
}

fn boolean(value: &Value, name: &str) -> Result<bool, VerificationError> {
    field(value, name)?
        .as_bool()
        .ok_or_else(|| VerificationError::Field(name.into()))
}

fn array<'a>(value: &'a Value, name: &str) -> Result<&'a [Value], VerificationError> {
    field(value, name)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| VerificationError::Field(name.into()))
}

fn validate(contract: &'static str, value: &Value) -> Result<(), VerificationError> {
    validate_architecture_contract(contract, value)
        .map_err(|detail| VerificationError::Contract { contract, detail })
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn hash_value(value: &Value) -> Result<String, VerificationError> {
    serde_jcs::to_vec(value)
        .map(|bytes| hash_bytes(&bytes))
        .map_err(|error| VerificationError::Field(format!("JCS encoding: {error}")))
}

fn without(value: &Value, keys: &[&str]) -> Result<Value, VerificationError> {
    let mut copy = object(value)?.clone();
    for key in keys {
        copy.remove(*key);
    }
    Ok(Value::Object(copy))
}

fn check_eq(
    actual: impl AsRef<str>,
    expected: impl AsRef<str>,
    label: &str,
) -> Result<(), VerificationError> {
    if actual.as_ref() == expected.as_ref() {
        Ok(())
    } else {
        Err(VerificationError::Binding(label.into()))
    }
}

fn material_root(
    domain: &str,
    materials: &[Value],
) -> Result<(String, Vec<(u64, String)>), VerificationError> {
    let mut rows = Vec::with_capacity(materials.len());
    let mut seen = BTreeSet::new();
    for material in materials {
        let sequence = number(material, "sequence")?;
        if !seen.insert(sequence) {
            return Err(VerificationError::Binding(format!(
                "duplicate sequence {sequence}"
            )));
        }
        let computed = hash_value(field(material, "body")?)?;
        check_eq(
            &computed,
            text(material, "body_hash")?,
            "material body hash",
        )?;
        rows.push((sequence, computed));
    }
    rows.sort_by_key(|row| row.0);
    for pair in rows.windows(2) {
        if pair[1].0 != pair[0].0 + 1 {
            return Err(VerificationError::Binding(
                "material sequence gap or reorder".into(),
            ));
        }
    }
    let hashes = rows
        .iter()
        .map(|(_, hash)| Value::String(hash.clone()))
        .collect();
    Ok((
        hash_value(&json!({"domain": domain, "hashes": Value::Array(hashes)}))?,
        rows,
    ))
}

fn state_root(entries: &[Value]) -> Result<String, VerificationError> {
    let mut state = BTreeMap::<String, String>::new();
    for entry in entries {
        let key = text(entry, "key")?;
        let value_hash = text(entry, "value_hash")?;
        if state.insert(key.clone(), value_hash).is_some() {
            return Err(VerificationError::Binding(format!(
                "duplicate state key {key}"
            )));
        }
    }
    hash_value(&json!({"domain":"ioi.sorted-state-jcs-sha256.v1","entries":state}))
}

fn state_map(entries: &[Value]) -> Result<BTreeMap<String, String>, VerificationError> {
    let mut state = BTreeMap::new();
    for entry in entries {
        let key = text(entry, "key")?;
        let value_hash = text(entry, "value_hash")?;
        if state.insert(key.clone(), value_hash).is_some() {
            return Err(VerificationError::Binding(format!(
                "duplicate state key {key}"
            )));
        }
    }
    Ok(state)
}

fn verify_touched_state(
    binding: &Value,
    previous_entries: &[Value],
    resulting_entries: &[Value],
) -> Result<(), VerificationError> {
    let previous = state_map(previous_entries)?;
    let resulting = state_map(resulting_entries)?;
    let mut touched = BTreeSet::new();
    for object in array(binding, "touched_objects")? {
        let object_ref = text(object, "object_ref")?;
        if !touched.insert(object_ref.clone()) {
            return Err(VerificationError::Binding(format!(
                "duplicate touched object {object_ref}"
            )));
        }
        let previous_version = number(object, "previous_version")?;
        let resulting_version = number(object, "resulting_version")?;
        if previous_version.checked_add(1) != Some(resulting_version) {
            return Err(VerificationError::Binding(format!(
                "non-contiguous object version {object_ref}"
            )));
        }
        match (previous.get(&object_ref), field(object, "previous_head")?) {
            (None, Value::Null) if previous_version == 0 => {}
            (Some(actual), Value::String(declared))
                if previous_version > 0 && actual == declared => {}
            _ => {
                return Err(VerificationError::Binding(format!(
                    "previous touched-object head {object_ref}"
                )))
            }
        }
        let actual_result = resulting.get(&object_ref).ok_or_else(|| {
            VerificationError::Binding(format!("missing resulting touched object {object_ref}"))
        })?;
        check_eq(
            actual_result,
            text(object, "resulting_head")?,
            "resulting touched-object head",
        )?;
    }

    let keys: BTreeSet<&String> = previous.keys().chain(resulting.keys()).collect();
    for key in keys {
        if previous.get(key) != resulting.get(key) && !touched.contains(key.as_str()) {
            return Err(VerificationError::Binding(format!(
                "state changed outside touched objects: {key}"
            )));
        }
    }
    Ok(())
}

fn range(value: &Value, name: &str) -> Result<(u64, u64), VerificationError> {
    let range = field(value, name)?;
    Ok((number(range, "first")?, number(range, "last")?))
}

fn recognized_effect_hash(
    checkpoint: &Value,
    operation_root: &str,
    receipt_root: &str,
    previous_state_root: &str,
    resulting_state_root: &str,
) -> Result<String, VerificationError> {
    let conflict_surface = without(
        field(checkpoint, "conflict_authority_binding")?,
        &["effect_hash", "binding_hash"],
    )?;
    hash_value(&json!({
        "domain": "ioi.recognized-effect.v1",
        "domain_id": text(checkpoint, "domain_id")?,
        "authority_epoch": number(checkpoint, "authority_epoch")?,
        "authority_revocation_epoch": number(checkpoint, "authority_revocation_epoch")?,
        "operation_root": operation_root,
        "receipt_root": receipt_root,
        "previous_state_root": previous_state_root,
        "resulting_state_root": resulting_state_root,
        "conflict_authority_surface": conflict_surface,
    }))
}

fn verify_material_range(
    checkpoint: &Value,
    name: &str,
    rows: &[(u64, String)],
) -> Result<(), VerificationError> {
    let (first, last) = range(checkpoint, name)?;
    match (rows.first(), rows.last()) {
        (Some(first_row), Some(last_row)) if first_row.0 == first && last_row.0 == last => Ok(()),
        _ => Err(VerificationError::Binding(format!(
            "{name} does not match supplied material"
        ))),
    }
}

/// Returns the supplied payload bytes, keyed by `payload_ref`, so a later step
/// can read a payload this function already hash-checked instead of decoding
/// and trusting it a second time.
fn verify_availability(
    checkpoint: &Value,
    bundle: &Value,
) -> Result<BTreeMap<String, Vec<u8>>, VerificationError> {
    let manifest = field(checkpoint, "availability_manifest")?;
    validate(AVAILABILITY_V1, manifest)?;
    validate(RETENTION_V1, field(manifest, "retention")?)?;
    let expected_manifest_hash = hash_value(&without(manifest, &["manifest_hash"])?)?;
    check_eq(
        &expected_manifest_hash,
        text(manifest, "manifest_hash")?,
        "availability manifest hash",
    )?;
    check_eq(
        &expected_manifest_hash,
        text(checkpoint, "availability_manifest_hash")?,
        "checkpoint availability manifest hash",
    )?;
    check_eq(
        text(manifest, "availability_verifier_contract_ref")?,
        text(
            field(checkpoint, "verifier_contract")?,
            "verifier_contract_id",
        )?,
        "availability verifier contract ref",
    )?;
    check_eq(
        text(manifest, "availability_verifier_contract_hash")?,
        text(checkpoint, "verifier_contract_hash")?,
        "availability verifier contract hash",
    )?;
    check_eq(
        text(field(manifest, "retention")?, "retention_class")?,
        text(checkpoint, "retention_class")?,
        "checkpoint retention class",
    )?;

    let supplied = array(bundle, "availability_payloads")?;
    let retention = field(manifest, "retention")?;
    let minimum_copies = number(retention, "minimum_copies")? as usize;
    let independent_failure_domains = number(retention, "independent_failure_domains")? as usize;
    let mut supplied_by_ref = BTreeMap::new();
    for payload in supplied {
        let payload_ref = text(payload, "payload_ref")?;
        let bytes = BASE64
            .decode(text(payload, "payload_base64")?)
            .map_err(|error| VerificationError::Field(format!("payload base64: {error}")))?;
        if supplied_by_ref.insert(payload_ref.clone(), bytes).is_some() {
            return Err(VerificationError::Binding(format!(
                "duplicate availability payload {payload_ref}"
            )));
        }
    }
    let declared = array(manifest, "payloads")?;
    if supplied_by_ref.len() != declared.len() {
        return Err(VerificationError::Binding(
            "availability payload coverage".into(),
        ));
    }
    for payload in declared {
        let payload_ref = text(payload, "payload_ref")?;
        let bytes = supplied_by_ref
            .get(&payload_ref)
            .ok_or_else(|| VerificationError::Binding(format!("missing payload {payload_ref}")))?;
        check_eq(
            hash_bytes(bytes),
            text(payload, "payload_hash")?,
            "availability payload hash",
        )?;
        if number(payload, "byte_length")? != bytes.len() as u64 {
            return Err(VerificationError::Binding(
                "availability payload length".into(),
            ));
        }
        if array(payload, "location_refs")?.len() < minimum_copies {
            return Err(VerificationError::Binding(
                "availability minimum copies".into(),
            ));
        }
        if array(payload, "failure_domain_refs")?.len() < independent_failure_domains {
            return Err(VerificationError::Binding(
                "availability independent failure domains".into(),
            ));
        }
    }
    Ok(supplied_by_ref)
}

fn refuse_evidence(detail: impl Into<String>) -> VerificationError {
    VerificationError::ConsensusEvidence(detail.into())
}

/// JCS hash over exactly the membership-defining surface: every evidence field
/// except the recorded hash, the votes cast under it, the view, and the
/// certified block. Binding it means a membership, threshold, fault-model, or
/// vote-binding swap cannot hide behind a quorum that verified against a
/// different set. The view and the certified block are excluded on purpose —
/// each identifies one decision, not the membership, and successive checkpoints
/// inside one authority epoch advance both while the membership must not move.
/// The vote message binds the view and the block identity separately, and
/// `INV-42` compares this hash across adjacent checkpoints, so including either
/// would make that comparison always fail rather than catch a real swap.
fn consensus_membership_hash(evidence: &Value) -> Result<String, VerificationError> {
    hash_value(&json!({
        "domain": CONSENSUS_MEMBERSHIP_DOMAIN,
        "membership": without(
            evidence,
            &["membership_hash", "votes", "view", "certified_block"],
        )?,
    }))
}

/// The exact bytes every declared voting member signs. Binding institution,
/// authority epoch, membership, view, and checkpoint body means one member
/// signature cannot be replayed into another institution, epoch, membership,
/// view, or batch.
fn consensus_vote_message(
    domain_id: &str,
    authority_epoch: u64,
    membership_hash: &str,
    view: u64,
    checkpoint_hash: &str,
) -> Vec<u8> {
    format!(
        "{CONSENSUS_VOTE_DOMAIN}\0{domain_id}\0{authority_epoch}\0{membership_hash}\0{view}\0{checkpoint_hash}"
    )
    .into_bytes()
}

/// `consensus_evidence` is required for the BFT variant and forbidden for every
/// other one. The schema states the required direction; the forbidden direction
/// is stated only here, because the repository schema dialect implements no
/// negation keyword. Both the emitter and the verifier call this, so no artifact
/// this crate produces or accepts carries quorum evidence under a variant whose
/// preimage must not contain it.
fn verify_variant_evidence_presence(
    certificate: &Value,
    variant: &str,
) -> Result<(), VerificationError> {
    let present = object(certificate)?.contains_key("consensus_evidence");
    match (variant, present) {
        ("bft_consensus_aft_v1", true) => Ok(()),
        ("bft_consensus_aft_v1", false) => Err(refuse_evidence(
            "bft_consensus_aft_v1 certificate carries no consensus evidence",
        )),
        (_, false) => Ok(()),
        (other, true) => Err(refuse_evidence(format!(
            "{other} certificate must not carry consensus evidence"
        ))),
    }
}

/// `certified_block` is required under the native binding and forbidden under
/// the checkpoint-round binding. The schema states the required direction only,
/// so — exactly as with `consensus_evidence` itself — the forbidden direction is
/// this verifier's obligation. Both the emitter and the verifier call this, so
/// no artifact this crate produces or accepts staples a native block onto a
/// quorum that never signed one.
fn verify_binding_block_presence(
    evidence: &Value,
    vote_binding: &str,
) -> Result<(), VerificationError> {
    let present = object(evidence)?.contains_key("certified_block");
    match (vote_binding, present) {
        (NATIVE_AFT_VOTE_BINDING, true) => Ok(()),
        (NATIVE_AFT_VOTE_BINDING, false) => Err(refuse_evidence(
            "native AFT evidence carries no certified block",
        )),
        (CHECKPOINT_VOTE_BINDING, false) => Ok(()),
        (CHECKPOINT_VOTE_BINDING, true) => Err(refuse_evidence(
            "a checkpoint-round quorum must not carry a certified block: its members signed the checkpoint, not a block",
        )),
        (other, _) => Err(refuse_evidence(format!("unknown vote binding {other}"))),
    }
}

/// Recompute the native AFT block facts from the durable header bytes and pin
/// the declared membership to the block's own committed voter set.
///
/// This is the step that makes an imported quorum mean something. The header
/// bytes are re-hashed to the certified `block_hash`; the height and view are
/// read out of the decoded header rather than trusted from the certificate; and
/// every declared member's public key is put through the exact `AccountId`
/// derivation the chain uses, with the resulting set required to equal the
/// header's `validator_set` exactly. Because `validator_set` sits inside the
/// header's signing preimage, it is covered by the very hash the votes signed —
/// so the eligible-voter list is imported from consensus, not asserted here.
fn verify_certified_block(
    evidence: &Value,
    view: u64,
    member_account_ids: &BTreeSet<[u8; 32]>,
    payloads: Option<&BTreeMap<String, Vec<u8>>>,
) -> Result<([u8; 32], u64, VerifiedNativeAftBlock), VerificationError> {
    let block = field(evidence, "certified_block")?;
    check_eq(
        text(block, "vote_message_domain")?,
        NATIVE_AFT_VOTE_DOMAIN,
        "native AFT vote message domain",
    )?;
    let commitment = text(block, "effect_commitment")?;
    if commitment != DECLARED_ASSOCIATION {
        return Err(refuse_evidence(format!(
            "unimplemented effect commitment {commitment}: this verifier establishes no association it cannot recompute"
        )));
    }
    let block_height = number(block, "block_height")?;
    let declared_hash = text(block, "block_hash")?;
    let block_payload_ref = text(block, "block_payload_ref")?;
    let raw_hash: [u8; 32] = hex::decode(
        declared_hash
            .strip_prefix("sha256:")
            .ok_or_else(|| refuse_evidence("certified block hash is not a sha256: digest"))?,
    )
    .map_err(|error| VerificationError::Crypto(error.to_string()))?
    .try_into()
    .map_err(|_| refuse_evidence("certified block hash is not 32 bytes"))?;

    let mut verified = VerifiedNativeAftBlock {
        block_height,
        block_view: view,
        block_hash: declared_hash,
        block_payload_ref: block_payload_ref.clone(),
        block_bytes_reverified: false,
        effect_committed_in_block: false,
    };

    // The predecessor path supplies no payloads. Say so in the claim rather
    // than silently reporting the same confidence as a re-derived block.
    let Some(payloads) = payloads else {
        return Ok((raw_hash, block_height, verified));
    };
    let bytes = payloads.get(&block_payload_ref).ok_or_else(|| {
        refuse_evidence(format!(
            "certified block payload {block_payload_ref} is not carried by the availability manifest"
        ))
    })?;
    let header: BlockHeader = from_bytes_canonical(bytes).map_err(|error| {
        refuse_evidence(format!("certified block header does not decode: {error}"))
    })?;
    let recomputed = header.hash().map_err(|error| {
        refuse_evidence(format!("certified block header does not hash: {error}"))
    })?;
    if recomputed.as_slice() != raw_hash.as_slice() {
        return Err(refuse_evidence(
            "supplied block header does not hash to the certified block hash",
        ));
    }
    if header.height != block_height {
        return Err(refuse_evidence(format!(
            "certified block declares height {block_height} but the header carries {}",
            header.height
        )));
    }
    if header.view != view {
        return Err(refuse_evidence(format!(
            "consensus evidence declares view {view} but the certified header carries {}",
            header.view
        )));
    }
    // The header's committed voter set is the only membership statement that
    // consensus itself signed. An empty one cannot pin anything, so it refuses
    // rather than vacuously matching.
    if header.validator_set.is_empty() {
        return Err(refuse_evidence(
            "certified block header commits no validator set, so no declared membership can be bound to it",
        ));
    }
    let mut committed = BTreeSet::new();
    for entry in &header.validator_set {
        let account: [u8; 32] = entry.as_slice().try_into().map_err(|_| {
            refuse_evidence("certified block header carries a malformed validator account id")
        })?;
        if !committed.insert(account) {
            return Err(refuse_evidence(
                "certified block header repeats a validator account id",
            ));
        }
    }
    if &committed != member_account_ids {
        return Err(refuse_evidence(
            "declared membership does not derive onto the certified block's committed validator set",
        ));
    }
    verified.block_bytes_reverified = true;
    Ok((raw_hash, block_height, verified))
}

/// Recompute the whole peer-quorum claim offline. Every branch refuses; none
/// treats the `bft_consensus` label, the issuer signature, or the presence of
/// signature bytes as evidence that peers agreed.
fn verify_consensus_evidence(
    checkpoint: &Value,
    certificate: &Value,
    checkpoint_hash: &str,
    payloads: Option<&BTreeMap<String, Vec<u8>>>,
) -> Result<VerifiedQuorum, VerificationError> {
    let evidence = field(certificate, "consensus_evidence")?;
    check_eq(
        text(evidence, "schema_version")?,
        CONSENSUS_EVIDENCE_V1,
        "consensus evidence schema version",
    )?;
    if text(evidence, "fault_model")? != "byzantine" {
        return Err(refuse_evidence(
            "bft_consensus requires a declared byzantine fault model",
        ));
    }
    if text(evidence, "synchrony_model")? != "partial_synchrony" {
        return Err(refuse_evidence(
            "bft_consensus requires a declared partial-synchrony model: AFT reaches a decision through views and timeouts, which asserts nothing under full asynchrony",
        ));
    }
    let vote_binding = text(evidence, "vote_binding")?;
    verify_binding_block_presence(evidence, &vote_binding)?;

    let declared_members = number(evidence, "total_voting_members")?;
    let tolerated = number(evidence, "byzantine_fault_tolerance")?;
    let threshold = number(evidence, "quorum_threshold")?;
    if tolerated == 0 {
        return Err(refuse_evidence(
            "a membership tolerating zero byzantine faults is single_authority under a bft label",
        ));
    }
    let minimum_members = tolerated
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| refuse_evidence("declared byzantine fault tolerance overflows"))?;
    if declared_members < minimum_members {
        return Err(refuse_evidence(format!(
            "membership of {declared_members} cannot tolerate {tolerated} byzantine faults, which needs {minimum_members}"
        )));
    }
    let minimum_threshold = tolerated
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| refuse_evidence("declared byzantine fault tolerance overflows"))?;
    if threshold < minimum_threshold {
        return Err(refuse_evidence(format!(
            "quorum threshold {threshold} is below the {minimum_threshold} required to tolerate {tolerated} byzantine faults"
        )));
    }
    // `2f + 1` is only the right floor when `n == 3f + 1`. For any larger
    // membership it is too weak: two quorums of `2f + 1` out of `n = 5, f = 1`
    // can intersect in exactly the one Byzantine member, so both could be
    // "honest" quorums for conflicting decisions. The intersection condition
    // that actually holds for every `n` is `2q > n + f`.
    let safety_threshold = declared_members
        .checked_add(tolerated)
        .map(|total| total / 2 + 1)
        .ok_or_else(|| refuse_evidence("declared membership overflows"))?;
    if threshold < safety_threshold {
        return Err(refuse_evidence(format!(
            "quorum threshold {threshold} cannot guarantee that two quorums intersect in an honest member: {declared_members} members tolerating {tolerated} byzantine faults need {safety_threshold}"
        )));
    }
    if threshold > declared_members {
        return Err(refuse_evidence(
            "quorum threshold exceeds the declared membership",
        ));
    }
    if vote_binding == NATIVE_AFT_VOTE_BINDING {
        // The native engine forms a QC at `((n * 2) / 3) + 1` in its
        // `ClassicBft` safety mode. Its guardian modes fire at `(n / 2) + 1`,
        // which is a simple majority and tolerates no Byzantine fault at all.
        // A certificate declaring `fault_model: byzantine` may therefore not be
        // backed by a guardian-majority quorum, so the imported threshold must
        // meet the classic rule rather than merely the engine's configured one.
        let native_threshold = declared_members
            .checked_mul(2)
            .map(|scaled| scaled / 3 + 1)
            .ok_or_else(|| refuse_evidence("declared membership overflows"))?;
        if threshold < native_threshold {
            return Err(refuse_evidence(format!(
                "quorum threshold {threshold} is below the native classic-BFT rule ((2n/3)+1 = {native_threshold}) for {declared_members} members: a simple-majority guardian quorum is not byzantine evidence"
            )));
        }
    }

    let members = array(evidence, "members")?;
    if members.len() as u64 != declared_members {
        return Err(refuse_evidence(
            "declared member count does not match the supplied membership",
        ));
    }
    let mut member_keys = BTreeMap::new();
    let mut distinct_keys = BTreeSet::new();
    let mut member_account_ids = BTreeSet::new();
    for member in members {
        let member_ref = text(member, "member_ref")?;
        let public_key = text(member, "public_key")?;
        if !distinct_keys.insert(public_key.clone()) {
            return Err(refuse_evidence(format!(
                "duplicate member public key at {member_ref}: one key holding several seats is one signer, not a quorum"
            )));
        }
        // The chain names validators by `AccountId`, never by public key, so a
        // declared key only becomes a membership claim once it is put through
        // the chain's own derivation. Doing it here — with the same function
        // the validator uses — is what lets the certified block's committed
        // voter set be compared against declared keys at all.
        let key_bytes = hex::decode(&public_key)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let account_id = account_id_from_key_material(SignatureSuite::ED25519, &key_bytes)
            .map_err(|error| {
                refuse_evidence(format!(
                    "member {member_ref} account id derivation: {error}"
                ))
            })?;
        if !member_account_ids.insert(account_id) {
            return Err(refuse_evidence(format!(
                "duplicate member account id at {member_ref}"
            )));
        }
        if member_keys.insert(member_ref.clone(), public_key).is_some() {
            return Err(refuse_evidence(format!("duplicate member {member_ref}")));
        }
    }

    let membership_hash = consensus_membership_hash(evidence)?;
    check_eq(
        &membership_hash,
        text(evidence, "membership_hash")?,
        "consensus membership hash",
    )?;

    let view = number(evidence, "view")?;
    // The two bindings verify different bytes, and that difference is the whole
    // point: the native binding re-derives the message the live consensus path
    // already signed, while the checkpoint binding re-derives a message this
    // crate defined. Neither is allowed to stand in for the other.
    let (message, certified_block) = match vote_binding.as_str() {
        NATIVE_AFT_VOTE_BINDING => {
            let (block_hash, block_height, verified_block) =
                verify_certified_block(evidence, view, &member_account_ids, payloads)?;
            (
                native_aft_vote_message(block_height, view, &block_hash)?,
                Some(verified_block),
            )
        }
        CHECKPOINT_VOTE_BINDING => (
            consensus_vote_message(
                &text(checkpoint, "domain_id")?,
                number(checkpoint, "authority_epoch")?,
                &membership_hash,
                view,
                checkpoint_hash,
            ),
            None,
        ),
        other => return Err(refuse_evidence(format!("unknown vote binding {other}"))),
    };
    let mut voted = BTreeSet::new();
    for vote in array(evidence, "votes")? {
        let member_ref = text(vote, "member_ref")?;
        let public_key = member_keys
            .get(&member_ref)
            .ok_or_else(|| refuse_evidence(format!("vote from undeclared member {member_ref}")))?;
        if !voted.insert(member_ref.clone()) {
            return Err(refuse_evidence(format!("duplicate vote from {member_ref}")));
        }
        let key_bytes = hex::decode(public_key)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let signature_bytes = hex::decode(text(vote, "signature")?)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let public = Ed25519PublicKey::from_bytes(&key_bytes)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let signature = Ed25519Signature::from_bytes(&signature_bytes)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        public.verify(&message, &signature).map_err(|_| {
            refuse_evidence(format!(
                "member {member_ref} did not sign the {vote_binding} message for this membership and view"
            ))
        })?;
    }
    let verified = voted.len() as u64;
    if verified < threshold {
        return Err(refuse_evidence(format!(
            "{verified} verified member signatures is below the declared quorum threshold {threshold}"
        )));
    }

    if vote_binding == CHECKPOINT_VOTE_BINDING {
        // This crate's own round is aggregated by one of the voters, so the
        // issuer must be in the set it is reporting on. The native binding is
        // deliberately the opposite: the portable finality issuer is not an AFT
        // validator and must not be required to be one. Issuer authority there
        // comes from `trusted_issuer`; peer safety comes only from the votes
        // verified above. Conflating the two is exactly the failure this whole
        // bridge exists to avoid.
        let issuer_public_key = text(certificate, "issuer_public_key")?;
        let issuer_member = member_keys
            .iter()
            .find(|(_, key)| **key == issuer_public_key)
            .map(|(member_ref, _)| member_ref.clone())
            .ok_or_else(|| refuse_evidence("certificate issuer is not a declared voting member"))?;
        if !voted.contains(&issuer_member) {
            return Err(refuse_evidence(format!(
                "certificate issuer {issuer_member} aggregated a quorum it did not vote in"
            )));
        }
    }

    Ok(VerifiedQuorum {
        membership_ref: text(evidence, "membership_ref")?,
        membership_hash,
        membership_epoch: number(evidence, "membership_epoch")?,
        view,
        total_voting_members: declared_members,
        byzantine_fault_tolerance: tolerated,
        quorum_threshold: threshold,
        distinct_member_signatures_verified: verified,
        vote_binding,
        certified_block,
    })
}

fn verify_certificate_signature(certificate: &Value) -> Result<(), VerificationError> {
    let expected_body_hash = hash_value(&without(certificate, &["body_hash", "signature"])?)?;
    check_eq(
        &expected_body_hash,
        text(certificate, "body_hash")?,
        "certificate body hash",
    )?;
    let public_bytes = hex::decode(text(certificate, "issuer_public_key")?)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let signature_bytes = hex::decode(text(certificate, "signature")?)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let public_key = Ed25519PublicKey::from_bytes(&public_bytes)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let signature = Ed25519Signature::from_bytes(&signature_bytes)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let message = format!("ioi.finality-certificate.v1\0{expected_body_hash}");
    public_key
        .verify(message.as_bytes(), &signature)
        .map_err(|error| VerificationError::Crypto(error.to_string()))
}

fn verify_signature(certificate: &Value, trusted: &Value) -> Result<(), VerificationError> {
    check_eq(
        text(certificate, "issuer_key_id")?,
        text(trusted, "issuer_key_id")?,
        "trusted issuer key id",
    )?;
    check_eq(
        text(certificate, "issuer_public_key")?,
        text(trusted, "issuer_public_key")?,
        "trusted issuer public key",
    )?;
    verify_certificate_signature(certificate)
}

fn verify_checkpoint_envelope(checkpoint: &Value) -> Result<(), VerificationError> {
    let certificate = field(checkpoint, "finality_certificate")?;
    let (_, variant) = admitted_profile(checkpoint, certificate)?;
    verify_variant_evidence_presence(certificate, variant)?;
    validate(CHECKPOINT_V2, checkpoint)?;
    let expected_schema = architecture_contract_schema_hash(CHECKPOINT_V2)
        .ok_or_else(|| VerificationError::Field("checkpoint schema hash registry".into()))?;
    check_eq(
        expected_schema,
        text(checkpoint, "schema_hash")?,
        "checkpoint schema hash",
    )?;

    let binding = field(checkpoint, "conflict_authority_binding")?;
    validate(CONFLICT_BINDING_V1, binding)?;
    let binding_hash = hash_value(&without(binding, &["binding_hash"])?)?;
    check_eq(
        &binding_hash,
        text(binding, "binding_hash")?,
        "conflict/authority binding hash",
    )?;
    check_eq(
        &binding_hash,
        text(checkpoint, "conflict_authority_binding_hash")?,
        "checkpoint conflict/authority binding hash",
    )?;
    let recognition = field(checkpoint, "recognition")?;
    validate(RECOGNITION_V1, recognition)?;
    check_eq(
        &binding_hash,
        text(recognition, "binding_hash")?,
        "recognition conflict/authority binding hash",
    )?;
    if field(binding, "invariant_domain_refs")? != field(recognition, "invariant_domain_refs")? {
        return Err(VerificationError::Binding(
            "recognition invariant-domain binding".into(),
        ));
    }
    check_eq(
        text(binding, "effect_hash")?,
        text(recognition, "effect_hash")?,
        "recognition effect hash",
    )?;

    let verifier = field(checkpoint, "verifier_contract")?;
    validate(VERIFIER_V1, verifier)?;
    let verifier_hash = hash_value(&without(verifier, &["verifier_contract_hash"])?)?;
    check_eq(
        &verifier_hash,
        text(verifier, "verifier_contract_hash")?,
        "verifier contract hash",
    )?;
    check_eq(
        &verifier_hash,
        text(checkpoint, "verifier_contract_hash")?,
        "checkpoint verifier contract hash",
    )?;
    check_eq(
        &verifier_hash,
        text(certificate, "verifier_contract_hash")?,
        "certificate verifier contract hash",
    )?;
    check_eq(
        text(verifier, "verifier_contract_id")?,
        text(certificate, "verifier_contract_ref")?,
        "certificate verifier contract ref",
    )?;

    let manifest = field(checkpoint, "availability_manifest")?;
    validate(AVAILABILITY_V1, manifest)?;
    validate(RETENTION_V1, field(manifest, "retention")?)?;
    let manifest_hash = hash_value(&without(manifest, &["manifest_hash"])?)?;
    check_eq(
        &manifest_hash,
        text(manifest, "manifest_hash")?,
        "availability manifest hash",
    )?;
    check_eq(
        &manifest_hash,
        text(checkpoint, "availability_manifest_hash")?,
        "checkpoint availability manifest hash",
    )?;
    check_eq(
        text(field(manifest, "retention")?, "retention_class")?,
        text(checkpoint, "retention_class")?,
        "checkpoint retention class",
    )?;
    check_eq(
        text(manifest, "availability_verifier_contract_ref")?,
        text(verifier, "verifier_contract_id")?,
        "availability verifier contract ref",
    )?;
    check_eq(
        text(manifest, "availability_verifier_contract_hash")?,
        &verifier_hash,
        "availability verifier contract hash",
    )?;

    validate(CERTIFICATE_V1, certificate)?;
    let checkpoint_hash = hash_value(&without(
        checkpoint,
        &["body_hash", "finality_certificate"],
    )?)?;
    check_eq(
        &checkpoint_hash,
        text(checkpoint, "body_hash")?,
        "checkpoint body hash",
    )?;
    check_eq(
        &checkpoint_hash,
        text(certificate, "checkpoint_hash")?,
        "certificate checkpoint hash",
    )?;
    for name in [
        "domain_id",
        "authority_epoch",
        "authority_revocation_epoch",
        "operation_range",
        "receipt_range",
        "profile_contract_version",
        "profile",
    ] {
        if field(checkpoint, name)? != field(certificate, name)? {
            return Err(VerificationError::Binding(format!("certificate {name}")));
        }
    }
    verify_certificate_signature(certificate)?;
    if variant == "bft_consensus_aft_v1" {
        // A predecessor is verified from the checkpoint alone: the bundle
        // carries availability payloads for its own checkpoint, not for a prior
        // one. Native block bytes are therefore unavailable here, which
        // `VerifiedNativeAftBlock::block_bytes_reverified` reports honestly
        // rather than papering over. The predecessor's membership is still
        // pinned, because `verify_bundle` requires its `membership_hash` to
        // equal this checkpoint's, and this checkpoint's membership was bound
        // to its own certified block.
        verify_consensus_evidence(checkpoint, certificate, &checkpoint_hash, None)?;
    }
    Ok(())
}

pub fn verify_bundle(bundle: &Value) -> Result<VerifiedClaim, VerificationError> {
    let version = text(bundle, "schema_version").unwrap_or_else(|_| "missing".into());
    if version != "ioi.foundations.receipt-proof-bundle.v2" {
        return Err(VerificationError::UnsupportedVersion(version));
    }
    let checkpoint = field(bundle, "checkpoint")?;
    let certificate = field(checkpoint, "finality_certificate")?;
    let (profile, variant) = admitted_profile(checkpoint, certificate)?;
    // Preflight the variant-specific evidence before schema validation so a
    // relabelled certificate gets the precise fail-closed refusal instead of
    // being mistaken for a generic malformed document.
    verify_variant_evidence_presence(certificate, variant)?;
    validate(BUNDLE_V2, bundle)?;
    validate(CHECKPOINT_V2, checkpoint)?;
    validate(
        CONFLICT_BINDING_V1,
        field(checkpoint, "conflict_authority_binding")?,
    )?;
    validate(RECOGNITION_V1, field(checkpoint, "recognition")?)?;
    validate(VERIFIER_V1, field(checkpoint, "verifier_contract")?)?;
    validate(CERTIFICATE_V1, field(checkpoint, "finality_certificate")?)?;

    let verifier = field(checkpoint, "verifier_contract")?;
    let verifier_profiles: BTreeSet<String> = array(verifier, "supported_profile_members")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let verifier_variants: BTreeSet<String> = array(verifier, "supported_certificate_variants")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    if !verifier_profiles.contains(profile) || !verifier_variants.contains(variant) {
        return Err(VerificationError::Binding(
            "verifier profile/certificate support".into(),
        ));
    }
    let mut verifier_axis_inputs = BTreeMap::new();
    for entry in array(verifier, "axes")? {
        let axis = text(entry, "axis")?;
        let required_inputs: BTreeSet<String> = array(entry, "required_input_contract_ids")?
            .iter()
            .map(|input| {
                input
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| VerificationError::Field("required_input_contract_ids".into()))
            })
            .collect::<Result<_, _>>()?;
        if verifier_axis_inputs
            .insert(axis.clone(), required_inputs)
            .is_some()
        {
            return Err(VerificationError::Binding(format!(
                "duplicate verifier axis: {axis}"
            )));
        }
    }
    let verifier_axes: BTreeSet<String> = verifier_axis_inputs.keys().cloned().collect();
    let requested_axes: Vec<String> = array(bundle, "requested_axes")?
        .iter()
        .map(|axis| axis.as_str().unwrap_or("").to_owned())
        .collect();
    for axis in &requested_axes {
        if (axis != "integrity" && axis != "availability") || !verifier_axes.contains(axis.as_str())
        {
            return Err(VerificationError::UnsupportedAxis(axis.clone()));
        }
    }
    let claimed_axes: BTreeSet<String> = array(certificate, "claimed_axes")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    for axis in &claimed_axes {
        if (axis != "integrity" && axis != "availability") || !verifier_axes.contains(axis.as_str())
        {
            return Err(VerificationError::UnsupportedAxis(axis.clone()));
        }
    }
    for axis in &requested_axes {
        if !claimed_axes.contains(axis) {
            return Err(VerificationError::Binding(format!(
                "requested axis not certified: {axis}"
            )));
        }
    }
    let validated_contracts: BTreeSet<&str> = [
        BUNDLE_V2,
        CHECKPOINT_V2,
        CONFLICT_BINDING_V1,
        RECOGNITION_V1,
        AVAILABILITY_V1,
        RETENTION_V1,
        VERIFIER_V1,
        CERTIFICATE_V1,
    ]
    .into_iter()
    .collect();
    for axis in &claimed_axes {
        let required_inputs = verifier_axis_inputs
            .get(axis)
            .ok_or_else(|| VerificationError::UnsupportedAxis(axis.clone()))?;
        for required in required_inputs {
            if !validated_contracts.contains(required.as_str()) {
                return Err(VerificationError::Binding(format!(
                    "unavailable verifier input contract for {axis}: {required}"
                )));
            }
        }
    }
    if claimed_axes.contains("availability") {
        let manifest = field(checkpoint, "availability_manifest")?;
        if text(manifest, "claim_status")? != "verified" {
            return Err(VerificationError::Binding(
                "availability axis requires a verified manifest".into(),
            ));
        }
        if array(manifest, "payloads")?.is_empty() {
            return Err(VerificationError::Binding(
                "availability axis requires at least one payload".into(),
            ));
        }
        if text(field(manifest, "retention")?, "retention_class")? == "ephemeral_until_ack" {
            return Err(VerificationError::Binding(
                "availability axis refuses ephemeral retention".into(),
            ));
        }
    }

    let expected_bundle_schema = architecture_contract_schema_hash(BUNDLE_V2)
        .ok_or_else(|| VerificationError::Field("bundle schema hash registry".into()))?;
    let expected_checkpoint_schema = architecture_contract_schema_hash(CHECKPOINT_V2)
        .ok_or_else(|| VerificationError::Field("checkpoint schema hash registry".into()))?;
    check_eq(
        expected_bundle_schema,
        text(bundle, "schema_hash")?,
        "bundle schema hash",
    )?;
    check_eq(
        expected_checkpoint_schema,
        text(checkpoint, "schema_hash")?,
        "checkpoint schema hash",
    )?;

    let binding = field(checkpoint, "conflict_authority_binding")?;
    let binding_hash = hash_value(&without(binding, &["binding_hash"])?)?;
    check_eq(
        &binding_hash,
        text(binding, "binding_hash")?,
        "conflict/authority binding hash",
    )?;
    check_eq(
        &binding_hash,
        text(checkpoint, "conflict_authority_binding_hash")?,
        "checkpoint conflict/authority binding hash",
    )?;
    check_eq(
        &binding_hash,
        text(field(checkpoint, "recognition")?, "binding_hash")?,
        "recognition conflict/authority binding hash",
    )?;
    if field(binding, "invariant_domain_refs")?
        != field(field(checkpoint, "recognition")?, "invariant_domain_refs")?
    {
        return Err(VerificationError::Binding(
            "recognition invariant-domain binding".into(),
        ));
    }

    let verifier_hash = hash_value(&without(verifier, &["verifier_contract_hash"])?)?;
    check_eq(
        &verifier_hash,
        text(verifier, "verifier_contract_hash")?,
        "verifier contract hash",
    )?;
    check_eq(
        &verifier_hash,
        text(checkpoint, "verifier_contract_hash")?,
        "checkpoint verifier contract hash",
    )?;
    check_eq(
        &verifier_hash,
        text(certificate, "verifier_contract_hash")?,
        "certificate verifier contract hash",
    )?;
    check_eq(
        text(verifier, "verifier_contract_id")?,
        text(certificate, "verifier_contract_ref")?,
        "certificate verifier contract ref",
    )?;

    let (operation_root, operations) =
        material_root("ioi.operation-root.v1", array(bundle, "operations")?)?;
    let (receipt_root, receipts) =
        material_root("ioi.individual-receipt-root.v1", array(bundle, "receipts")?)?;
    check_eq(
        &operation_root,
        text(checkpoint, "operation_root")?,
        "operation root",
    )?;
    check_eq(
        &receipt_root,
        text(checkpoint, "receipt_root")?,
        "receipt root",
    )?;
    verify_material_range(checkpoint, "operation_range", &operations)?;
    verify_material_range(checkpoint, "receipt_range", &receipts)?;
    if operations.len() != receipts.len() {
        return Err(VerificationError::Binding(
            "operation/individual-receipt cardinality".into(),
        ));
    }

    let previous_state_root = state_root(array(bundle, "previous_state_entries")?)?;
    let resulting_state_root = state_root(array(bundle, "resulting_state_entries")?)?;
    let previous_state_version =
        number(field(checkpoint, "previous_state_commitment")?, "version")?;
    let resulting_state_version =
        number(field(checkpoint, "resulting_state_commitment")?, "version")?;
    if previous_state_version.checked_add(1) != Some(resulting_state_version) {
        return Err(VerificationError::Binding(
            "checkpoint state-version continuity".into(),
        ));
    }
    verify_touched_state(
        binding,
        array(bundle, "previous_state_entries")?,
        array(bundle, "resulting_state_entries")?,
    )?;
    check_eq(
        &previous_state_root,
        text(field(checkpoint, "previous_state_commitment")?, "root")?,
        "previous state root",
    )?;
    check_eq(
        resulting_state_root.clone(),
        text(field(checkpoint, "resulting_state_commitment")?, "root")?,
        "resulting state root",
    )?;
    let effect_hash = recognized_effect_hash(
        checkpoint,
        &operation_root,
        &receipt_root,
        &previous_state_root,
        &resulting_state_root,
    )?;
    check_eq(
        &effect_hash,
        text(binding, "effect_hash")?,
        "recognized effect binding",
    )?;
    check_eq(
        &effect_hash,
        text(field(checkpoint, "recognition")?, "effect_hash")?,
        "recognition effect binding",
    )?;

    let previous_checkpoint = field(bundle, "previous_checkpoint")?;
    match (
        field(checkpoint, "previous_checkpoint_ref")?,
        field(checkpoint, "previous_checkpoint_hash")?,
        previous_checkpoint,
    ) {
        (Value::Null, Value::Null, Value::Null) => {}
        (Value::String(expected_ref), Value::String(expected_hash), previous)
            if previous.is_object() =>
        {
            verify_checkpoint_envelope(previous)?;
            check_eq(
                expected_ref,
                text(previous, "checkpoint_id")?,
                "previous checkpoint ref",
            )?;
            check_eq(
                expected_hash,
                text(previous, "body_hash")?,
                "previous checkpoint hash",
            )?;
            check_eq(
                text(checkpoint, "previous_canonical_head")?,
                text(previous, "resulting_canonical_head")?,
                "predecessor canonical head",
            )?;
            check_eq(
                text(checkpoint, "domain_id")?,
                text(previous, "domain_id")?,
                "predecessor domain",
            )?;
            check_eq(
                number(checkpoint, "authority_epoch")?.to_string(),
                number(previous, "authority_epoch")?.to_string(),
                "unadmitted predecessor authority change",
            )?;
            check_eq(
                number(checkpoint, "authority_revocation_epoch")?.to_string(),
                number(previous, "authority_revocation_epoch")?.to_string(),
                "unadmitted predecessor revocation-epoch change",
            )?;
            let previous_certificate = field(previous, "finality_certificate")?;
            check_eq(
                text(certificate, "issuer_key_id")?,
                text(previous_certificate, "issuer_key_id")?,
                "unadmitted predecessor issuer-key change",
            )?;
            check_eq(
                text(certificate, "issuer_public_key")?,
                text(previous_certificate, "issuer_public_key")?,
                "unadmitted predecessor issuer-public-key change",
            )?;
            // A profile change is an admitted cutover operation, never an
            // adjacent-checkpoint edit (`INV-41`); refusing it here also stops a
            // stronger-profile history from being continued under a weaker one.
            check_eq(
                text(checkpoint, "profile")?,
                text(previous, "profile")?,
                "unadmitted predecessor profile change",
            )?;
            check_eq(
                text(certificate, "certificate_variant")?,
                text(previous_certificate, "certificate_variant")?,
                "unadmitted predecessor certificate-variant change",
            )?;
            if variant == "bft_consensus_aft_v1" {
                // Membership bounds the authority that rests on the quorum, so
                // it may not move inside one authority epoch (`INV-42`).
                check_eq(
                    text(field(certificate, "consensus_evidence")?, "membership_hash")?,
                    text(
                        field(previous_certificate, "consensus_evidence")?,
                        "membership_hash",
                    )?,
                    "unadmitted predecessor consensus-membership change",
                )?;
            }
            if field(checkpoint, "previous_state_commitment")?
                != field(previous, "resulting_state_commitment")?
            {
                return Err(VerificationError::Binding(
                    "predecessor state commitment".into(),
                ));
            }
            let (current_operation_first, _) = range(checkpoint, "operation_range")?;
            let (_, previous_operation_last) = range(previous, "operation_range")?;
            let (current_receipt_first, _) = range(checkpoint, "receipt_range")?;
            let (_, previous_receipt_last) = range(previous, "receipt_range")?;
            if previous_operation_last.checked_add(1) != Some(current_operation_first)
                || previous_receipt_last.checked_add(1) != Some(current_receipt_first)
            {
                return Err(VerificationError::Binding(
                    "predecessor range continuity".into(),
                ));
            }
        }
        _ => {
            return Err(VerificationError::Binding(
                "previous checkpoint presence".into(),
            ))
        }
    }
    if previous_checkpoint.is_null() {
        let (operation_first, _) = range(checkpoint, "operation_range")?;
        let (receipt_first, _) = range(checkpoint, "receipt_range")?;
        if operation_first != 0
            || receipt_first != 0
            || number(field(checkpoint, "previous_state_commitment")?, "version")? != 0
        {
            return Err(VerificationError::Binding(
                "genesis checkpoint continuity".into(),
            ));
        }
    }

    let expected_head = hash_value(
        &json!({"domain":"ioi.canonical-head.v1","previous":text(checkpoint,"previous_canonical_head")?,"operations":operation_root,"state":resulting_state_root,"receipts":receipt_root}),
    )?;
    check_eq(
        expected_head,
        text(checkpoint, "resulting_canonical_head")?,
        "resulting canonical head",
    )?;
    let payloads = verify_availability(checkpoint, bundle)?;

    let checkpoint_hash = hash_value(&without(
        checkpoint,
        &["body_hash", "finality_certificate"],
    )?)?;
    check_eq(
        &checkpoint_hash,
        text(checkpoint, "body_hash")?,
        "checkpoint body hash",
    )?;
    check_eq(
        &checkpoint_hash,
        text(certificate, "checkpoint_hash")?,
        "certificate checkpoint hash",
    )?;
    for name in [
        "domain_id",
        "authority_epoch",
        "authority_revocation_epoch",
        "operation_range",
        "receipt_range",
        "profile_contract_version",
        "profile",
    ] {
        if field(checkpoint, name)? != field(certificate, name)? {
            return Err(VerificationError::Binding(format!("certificate {name}")));
        }
    }
    let trusted = field(bundle, "trusted_issuer")?;
    check_eq(
        number(checkpoint, "authority_epoch")?.to_string(),
        number(trusted, "authority_epoch")?.to_string(),
        "authority epoch",
    )?;
    check_eq(
        number(checkpoint, "authority_revocation_epoch")?.to_string(),
        number(trusted, "revocation_epoch")?.to_string(),
        "authority revocation epoch",
    )?;
    check_eq(
        text(checkpoint, "domain_id")?,
        text(trusted, "domain_id")?,
        "trusted domain",
    )?;
    verify_signature(certificate, trusted)?;
    // The issuer signature is checked first so quorum evidence is never read out
    // of a certificate whose own binding has not been established.
    let quorum = if variant == "bft_consensus_aft_v1" {
        Some(verify_consensus_evidence(
            checkpoint,
            certificate,
            &checkpoint_hash,
            Some(&payloads),
        )?)
    } else {
        None
    };

    let bundle_hash = hash_value(&without(bundle, &["bundle_hash"])?)?;
    check_eq(bundle_hash, text(bundle, "bundle_hash")?, "bundle hash")?;
    Ok(VerifiedClaim {
        checkpoint_id: text(checkpoint, "checkpoint_id")?,
        domain_id: text(checkpoint, "domain_id")?,
        authority_epoch: number(checkpoint, "authority_epoch")?,
        issuer_key_id: text(certificate, "issuer_key_id")?,
        issuer_public_key: text(certificate, "issuer_public_key")?,
        profile: profile.to_owned(),
        certificate_variant: variant.to_owned(),
        established_axes: requested_axes,
        quorum,
    })
}

/// One template whose checkpoint body is fully derived and hashed, but whose
/// certificate is not yet issued. It exists because peer votes can only be cast
/// over a batch that is already decided: for `bft_consensus` the members sign
/// [`PreparedCheckpoint::vote_message`], and only then is the certificate
/// aggregated and signed. `consensus_evidence` lives inside the certificate,
/// which is excluded from the checkpoint body hash, so installing votes later
/// cannot move the batch they were cast over.
#[derive(Debug, Clone)]
pub struct PreparedCheckpoint {
    bundle: Value,
    profile: &'static str,
    certificate_variant: &'static str,
    checkpoint_hash: String,
    vote_message: Option<Vec<u8>>,
    vote_binding: Option<String>,
}

impl PreparedCheckpoint {
    /// The canonical member this checkpoint was prepared under.
    pub fn profile(&self) -> &'static str {
        self.profile
    }

    /// The certificate variant the finalizer will issue.
    pub fn certificate_variant(&self) -> &'static str {
        self.certificate_variant
    }

    /// The decided checkpoint body hash the certificate will bind.
    pub fn checkpoint_hash(&self) -> &str {
        &self.checkpoint_hash
    }

    /// The exact bytes each declared voting member signs. `None` for a profile
    /// whose admission does not take peer votes, and also `None` under
    /// [`NATIVE_AFT_VOTE_BINDING`], where the quorum was already cast over a
    /// decided block — never an empty message that would let a caller collect
    /// signatures over nothing.
    pub fn vote_message(&self) -> Option<&[u8]> {
        self.vote_message.as_deref()
    }

    /// Which bytes this checkpoint's quorum is expected to have signed, or
    /// `None` for a non-BFT variant.
    pub fn vote_binding(&self) -> Option<&str> {
        self.vote_binding.as_deref()
    }
}

/// One declared member's vote over [`PreparedCheckpoint::vote_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BftVote {
    pub member_ref: String,
    /// Hex-encoded Ed25519 signature over the prepared vote message.
    pub signature: String,
}

/// Derive and hash one caller-supplied v2 template under a resolved
/// ordering/finality profile. `profile_label` is resolved through the canonical
/// compatibility map before admission, and the resolved member must equal the
/// canonical member already written on the wire — a label is never accepted as
/// a wire value. Every derived field is overwritten from the supplied material.
pub fn prepare_checkpoint(
    mut bundle: Value,
    profile_label: &str,
) -> Result<PreparedCheckpoint, VerificationError> {
    let member = resolve_profile_label(profile_label)?;
    let wire_profile = text(field(&bundle, "checkpoint")?, "profile")?;
    let wire_variant = text(
        field(field(&bundle, "checkpoint")?, "finality_certificate")?,
        "certificate_variant",
    )?;
    if wire_profile != member {
        return Err(VerificationError::UnsupportedProfile {
            profile: wire_profile,
            variant: wire_variant,
        });
    }
    let variant = match implemented_variant(member) {
        Some(variant) if variant == wire_variant => variant,
        _ => {
            return Err(VerificationError::UnsupportedProfile {
                profile: wire_profile,
                variant: wire_variant,
            })
        }
    };
    let recognition = field(field(&bundle, "checkpoint")?, "recognition")?;
    let recognition_class = text(recognition, "recognition_class")?;
    let derivation = text(recognition, "derivation_status")?;
    if !matches!(recognition_class.as_str(), "K2" | "K3")
        || derivation != "resolved"
        || !boolean(recognition, "canonical_effect")?
        || !boolean(recognition, "ordinary_admission_permitted")?
    {
        return Err(VerificationError::UnsupportedRecognition {
            class: recognition_class,
            derivation,
        });
    }
    let bundle_schema_hash = architecture_contract_schema_hash(BUNDLE_V2)
        .ok_or_else(|| VerificationError::Field("bundle schema hash registry".into()))?
        .to_owned();
    let checkpoint_schema_hash = architecture_contract_schema_hash(CHECKPOINT_V2)
        .ok_or_else(|| VerificationError::Field("checkpoint schema hash registry".into()))?
        .to_owned();
    object_mut(&mut bundle)?.insert("schema_hash".into(), Value::String(bundle_schema_hash));
    let (operation_root, operations) = material_root_rewrite(
        "ioi.operation-root.v1",
        array_mut(&mut bundle, "operations")?,
    )?;
    let (receipt_root, receipts) = material_root_rewrite(
        "ioi.individual-receipt-root.v1",
        array_mut(&mut bundle, "receipts")?,
    )?;
    let previous_state_root = state_root(array(&bundle, "previous_state_entries")?)?;
    let resulting_state_root = state_root(array(&bundle, "resulting_state_entries")?)?;

    let checkpoint = field_mut(&mut bundle, "checkpoint")?;
    object_mut(checkpoint)?.insert("schema_hash".into(), Value::String(checkpoint_schema_hash));
    set_range(checkpoint, "operation_range", &operations)?;
    set_range(checkpoint, "receipt_range", &receipts)?;
    set_text(checkpoint, "operation_root", operation_root.clone())?;
    set_text(checkpoint, "receipt_root", receipt_root.clone())?;
    set_text(
        field_mut(checkpoint, "previous_state_commitment")?,
        "root",
        previous_state_root.clone(),
    )?;
    set_text(
        field_mut(checkpoint, "resulting_state_commitment")?,
        "root",
        resulting_state_root.clone(),
    )?;
    let effect_hash = recognized_effect_hash(
        checkpoint,
        &operation_root,
        &receipt_root,
        &previous_state_root,
        &resulting_state_root,
    )?;
    set_text(
        field_mut(checkpoint, "conflict_authority_binding")?,
        "effect_hash",
        effect_hash.clone(),
    )?;
    set_text(
        field_mut(checkpoint, "recognition")?,
        "effect_hash",
        effect_hash,
    )?;
    let binding = field_mut(checkpoint, "conflict_authority_binding")?;
    let binding_hash = hash_value(&without(binding, &["binding_hash"])?)?;
    set_text(binding, "binding_hash", binding_hash.clone())?;
    set_text(
        checkpoint,
        "conflict_authority_binding_hash",
        binding_hash.clone(),
    )?;
    set_text(
        field_mut(checkpoint, "recognition")?,
        "binding_hash",
        binding_hash,
    )?;
    let verifier = field_mut(checkpoint, "verifier_contract")?;
    let verifier_hash = hash_value(&without(verifier, &["verifier_contract_hash"])?)?;
    set_text(verifier, "verifier_contract_hash", verifier_hash.clone())?;
    set_text(checkpoint, "verifier_contract_hash", verifier_hash.clone())?;
    let verifier_id = text(
        field(checkpoint, "verifier_contract")?,
        "verifier_contract_id",
    )?;
    let manifest = field_mut(checkpoint, "availability_manifest")?;
    set_text(manifest, "availability_verifier_contract_ref", verifier_id)?;
    set_text(
        manifest,
        "availability_verifier_contract_hash",
        verifier_hash,
    )?;
    let manifest_hash = hash_value(&without(manifest, &["manifest_hash"])?)?;
    set_text(manifest, "manifest_hash", manifest_hash.clone())?;
    set_text(checkpoint, "availability_manifest_hash", manifest_hash)?;
    let previous_head = text(checkpoint, "previous_canonical_head")?;
    let resulting_head = hash_value(
        &json!({"domain":"ioi.canonical-head.v1","previous":previous_head,"operations":operation_root,"state":resulting_state_root,"receipts":receipt_root}),
    )?;
    set_text(checkpoint, "resulting_canonical_head", resulting_head)?;
    let checkpoint_hash = hash_value(&without(
        checkpoint,
        &["body_hash", "finality_certificate"],
    )?)?;
    set_text(checkpoint, "body_hash", checkpoint_hash.clone())?;

    let domain_id = text(checkpoint, "domain_id")?;
    let authority_epoch = number(checkpoint, "authority_epoch")?;
    let certificate = field_mut(checkpoint, "finality_certificate")?;
    verify_variant_evidence_presence(certificate, variant)?;
    let mut vote_binding = None;
    let vote_message = if variant == "bft_consensus_aft_v1" {
        let evidence = field_mut(certificate, "consensus_evidence")?;
        if !array(evidence, "votes")?.is_empty() {
            return Err(refuse_evidence(
                "a prepared template carries no votes: for a checkpoint round the members sign the prepared vote message, and for native AFT the quorum already exists and is supplied to finalize_native_aft_consensus",
            ));
        }
        let binding = text(evidence, "vote_binding")?;
        verify_binding_block_presence(evidence, &binding)?;
        let membership_hash = consensus_membership_hash(evidence)?;
        set_text(evidence, "membership_hash", membership_hash.clone())?;
        let view = number(evidence, "view")?;
        vote_binding = Some(binding.clone());
        match binding.as_str() {
            // Native AFT votes were cast over an already-decided block before
            // this checkpoint existed. There is no message for a caller to sign
            // here, and offering one would invite exactly the second signature
            // round this bridge exists to avoid.
            NATIVE_AFT_VOTE_BINDING => None,
            CHECKPOINT_VOTE_BINDING => Some(consensus_vote_message(
                &domain_id,
                authority_epoch,
                &membership_hash,
                view,
                &checkpoint_hash,
            )),
            other => return Err(refuse_evidence(format!("unknown vote binding {other}"))),
        }
    } else {
        None
    };

    Ok(PreparedCheckpoint {
        bundle,
        profile: member,
        certificate_variant: variant,
        checkpoint_hash,
        vote_message,
        vote_binding,
    })
}

/// Issue, sign, and fully re-verify the certificate over a prepared checkpoint.
fn finalize(
    prepared: PreparedCheckpoint,
    votes: &[BftVote],
    issuer_key_id: &str,
    signing_key: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    let PreparedCheckpoint {
        mut bundle,
        certificate_variant: variant,
        checkpoint_hash,
        ..
    } = prepared;
    let checkpoint = field_mut(&mut bundle, "checkpoint")?;
    let verifier_id = text(
        field(checkpoint, "verifier_contract")?,
        "verifier_contract_id",
    )?;
    let verifier_hash = text(checkpoint, "verifier_contract_hash")?;

    let certificate_fields = [
        "domain_id",
        "authority_epoch",
        "authority_revocation_epoch",
        "operation_range",
        "receipt_range",
        "profile_contract_version",
        "profile",
    ]
    .into_iter()
    .map(|name| Ok((name, field(checkpoint, name)?.clone())))
    .collect::<Result<Vec<_>, VerificationError>>()?;
    let trusted_domain = field(checkpoint, "domain_id")?.clone();
    let trusted_epoch = field(checkpoint, "authority_epoch")?.clone();
    let trusted_revocation_epoch = field(checkpoint, "authority_revocation_epoch")?.clone();
    let public_key = signing_key
        .public_key()
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let certificate = field_mut(checkpoint, "finality_certificate")?;
    set_text(certificate, "checkpoint_hash", checkpoint_hash)?;
    for (name, value) in certificate_fields {
        object_mut(certificate)?.insert(name.into(), value);
    }
    set_text(certificate, "verifier_contract_ref", verifier_id)?;
    set_text(certificate, "verifier_contract_hash", verifier_hash)?;
    set_text(certificate, "issuer_key_id", issuer_key_id.to_owned())?;
    set_text(
        certificate,
        "issuer_public_key",
        hex::encode(public_key.to_bytes()),
    )?;
    // Votes are installed before the certificate body hash, so the issuer
    // signature commits to the exact quorum rather than merely accompanying it.
    if variant == "bft_consensus_aft_v1" {
        let installed = votes
            .iter()
            .map(|vote| json!({"member_ref": vote.member_ref, "signature": vote.signature}))
            .collect::<Vec<_>>();
        let evidence = field_mut(certificate, "consensus_evidence")?;
        object_mut(evidence)?.insert("votes".into(), Value::Array(installed));
    } else if !votes.is_empty() {
        return Err(refuse_evidence(format!(
            "{variant} admission takes no peer votes"
        )));
    }
    let certificate_hash = hash_value(&without(certificate, &["body_hash", "signature"])?)?;
    set_text(certificate, "body_hash", certificate_hash.clone())?;
    let message = format!("ioi.finality-certificate.v1\0{certificate_hash}");
    let signature = signing_key
        .sign(message.as_bytes())
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    set_text(certificate, "signature", hex::encode(signature.to_bytes()))?;
    let trusted = field_mut(&mut bundle, "trusted_issuer")?;
    set_text(trusted, "issuer_key_id", issuer_key_id.to_owned())?;
    set_text(
        trusted,
        "issuer_public_key",
        hex::encode(public_key.to_bytes()),
    )?;
    object_mut(trusted)?.insert("domain_id".into(), trusted_domain);
    object_mut(trusted)?.insert("authority_epoch".into(), trusted_epoch);
    object_mut(trusted)?.insert("revocation_epoch".into(), trusted_revocation_epoch);
    let bundle_hash = hash_value(&without(&bundle, &["bundle_hash"])?)?;
    set_text(&mut bundle, "bundle_hash", bundle_hash)?;
    verify_bundle(&bundle)?;
    Ok(bundle)
}

/// Issue and sign a `single_authority_v1` certificate over a prepared
/// checkpoint. Refuses a checkpoint prepared under any other member.
pub fn finalize_single_authority(
    prepared: PreparedCheckpoint,
    issuer_key_id: &str,
    signing_key: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    if prepared.certificate_variant != "single_authority_v1" {
        return Err(VerificationError::UnsupportedProfile {
            profile: prepared.profile.to_owned(),
            variant: prepared.certificate_variant.to_owned(),
        });
    }
    finalize(prepared, &[], issuer_key_id, signing_key)
}

/// Aggregate a peer quorum into a `bft_consensus_aft_v1` certificate and sign
/// it. The supplied votes must be signatures over
/// [`PreparedCheckpoint::vote_message`] by distinct declared members; the full
/// quorum is re-verified from the finished bundle before it is returned, so an
/// insufficient, duplicated, undeclared, or unrelated vote set refuses here
/// rather than shipping a certificate whose label outruns its evidence.
pub fn finalize_bft_consensus(
    prepared: PreparedCheckpoint,
    votes: &[BftVote],
    issuer_key_id: &str,
    signing_key: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    if prepared.certificate_variant != "bft_consensus_aft_v1" {
        return Err(VerificationError::UnsupportedProfile {
            profile: prepared.profile.to_owned(),
            variant: prepared.certificate_variant.to_owned(),
        });
    }
    // This entry point collects a fresh round. Pointing it at a native-bound
    // template would install checkpoint-round signatures under a binding that
    // claims imported consensus evidence, which is the precise substitution the
    // native path exists to prevent.
    if prepared.vote_binding.as_deref() != Some(CHECKPOINT_VOTE_BINDING) {
        return Err(refuse_evidence(
            "finalize_bft_consensus collects a fresh checkpoint round; a native_aft_quorum_certificate_v1 template must go through finalize_native_aft_consensus",
        ));
    }
    finalize(prepared, votes, issuer_key_id, signing_key)
}

// -- Native AFT bridge -------------------------------------------------------

/// The runtime input type. Re-exported so Agentgres and other runtime callers
/// hand over the *actual* consensus type rather than a parallel copy that could
/// drift from it.
pub use ioi_types::app::QuorumCertificate;

/// One declared voting member of the native AFT membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAftMember {
    /// Stable `node://` reference for the seat.
    pub member_ref: String,
    /// The member's raw 32-byte Ed25519 public key. The chain stores only a
    /// hash of this key on `ValidatorV1`, so the key itself has to be supplied
    /// here; it is checked by deriving the `AccountId` and requiring it to
    /// appear in the certified block's own committed validator set.
    pub public_key: [u8; 32],
}

/// A block the native AFT path already finalized, with the certificate that
/// finalized it. This is the exact seam between live consensus and portable
/// finality: nothing in it is minted by this crate, and every field is
/// re-derived before it is believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAftFinalizedBlock {
    /// SCALE-encoded `BlockHeader` of the committed block, exactly as the block
    /// store holds it. Re-hashed here to the certified block hash.
    pub block_header_bytes: Vec<u8>,
    /// The certificate produced by the live consensus path.
    pub quorum_certificate: QuorumCertificate,
    /// The membership the certificate was formed under.
    pub members: Vec<NativeAftMember>,
    /// Stable `node-membership://` reference for that membership.
    pub membership_ref: String,
    /// The membership epoch this set belongs to.
    pub membership_epoch: u64,
    /// `protocol://` reference for the consensus protocol that produced it.
    pub consensus_protocol_ref: String,
    /// Byzantine faults the membership is declared to tolerate.
    pub byzantine_fault_tolerance: u64,
}

/// Translate a native `QuorumCertificate` into `consensus_evidence`, checking
/// every step rather than transcribing it.
///
/// The certificate arrives from an engine that does **not** itself verify these
/// signatures — it forms a quorum on a vote count and discards the signature
/// bytes. So this function treats the QC strictly as a *claim*: it re-derives
/// the signed preimage, resolves each signer's `AccountId` against the declared
/// keys, and hands the result to the ordinary verifier, which checks the
/// signatures cryptographically. Nothing is believed because consensus accepted
/// it.
fn native_evidence_from_certificate(
    finalized: &NativeAftFinalizedBlock,
    block_payload_ref: &str,
) -> Result<(Value, Vec<BftVote>), VerificationError> {
    let certificate = &finalized.quorum_certificate;
    // The aggregate fields are dead in the current engine (always empty, never
    // read). If one is ever populated, this bridge has no BLS verification and
    // must refuse rather than silently ignore evidence it did not check.
    if !certificate.aggregated_signature.is_empty() || !certificate.signers_bitfield.is_empty() {
        return Err(refuse_evidence(
            "quorum certificate carries an aggregated BLS signature, which this bridge does not verify: it refuses rather than counting only the explicit signature list",
        ));
    }
    if certificate.height == 0 {
        return Err(refuse_evidence(
            "genesis carries no quorum: the engine short-circuits height 0 without checking anything",
        ));
    }

    let header: BlockHeader = from_bytes_canonical(&finalized.block_header_bytes)
        .map_err(|error| refuse_evidence(format!("block header does not decode: {error}")))?;
    let recomputed = header
        .hash()
        .map_err(|error| refuse_evidence(format!("block header does not hash: {error}")))?;
    if recomputed.as_slice() != certificate.block_hash.as_slice() {
        return Err(refuse_evidence(
            "supplied block header does not hash to the block the quorum certificate names",
        ));
    }
    if header.height != certificate.height || header.view != certificate.view {
        return Err(refuse_evidence(
            "quorum certificate height/view does not match the certified block header",
        ));
    }

    let mut by_account = BTreeMap::new();
    let mut members = Vec::with_capacity(finalized.members.len());
    for member in &finalized.members {
        let account_id = account_id_from_key_material(SignatureSuite::ED25519, &member.public_key)
            .map_err(|error| {
                refuse_evidence(format!(
                    "member {} account id derivation: {error}",
                    member.member_ref
                ))
            })?;
        if by_account
            .insert(account_id, member.member_ref.clone())
            .is_some()
        {
            return Err(refuse_evidence(format!(
                "duplicate member account id at {}",
                member.member_ref
            )));
        }
        members.push(json!({
            "member_ref": member.member_ref,
            "public_key": hex::encode(member.public_key),
        }));
    }
    members.sort_by(|left, right| {
        left["member_ref"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["member_ref"].as_str().unwrap_or_default())
    });

    let mut votes = Vec::with_capacity(certificate.signatures.len());
    let mut seen = BTreeSet::new();
    for (voter, signature) in &certificate.signatures {
        let member_ref = by_account.get(&voter.0).ok_or_else(|| {
            refuse_evidence(
                "quorum certificate carries a signature from an account outside the declared membership",
            )
        })?;
        if !seen.insert(member_ref.clone()) {
            return Err(refuse_evidence(format!(
                "quorum certificate repeats a signature from {member_ref}: the engine's own weight check does not deduplicate voters, so this bridge must"
            )));
        }
        votes.push(BftVote {
            member_ref: member_ref.clone(),
            signature: hex::encode(signature),
        });
    }

    let evidence = json!({
        "schema_version": CONSENSUS_EVIDENCE_V1,
        "consensus_protocol_ref": finalized.consensus_protocol_ref,
        "vote_binding": NATIVE_AFT_VOTE_BINDING,
        "membership_ref": finalized.membership_ref,
        "membership_epoch": finalized.membership_epoch,
        "fault_model": "byzantine",
        "synchrony_model": "partial_synchrony",
        "total_voting_members": members.len() as u64,
        "byzantine_fault_tolerance": finalized.byzantine_fault_tolerance,
        "quorum_threshold": (members.len() as u64) * 2 / 3 + 1,
        "view": certificate.view,
        "members": Value::Array(members),
        "votes": Value::Array(Vec::new()),
        "membership_hash": format!("sha256:{}", "0".repeat(64)),
        "certified_block": {
            "block_height": certificate.height,
            "block_hash": hash_prefixed(&certificate.block_hash),
            "block_payload_ref": block_payload_ref,
            "vote_message_domain": NATIVE_AFT_VOTE_DOMAIN,
            "effect_commitment": DECLARED_ASSOCIATION,
        },
    });
    Ok((evidence, votes))
}

fn hash_prefixed(bytes: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(bytes))
}

/// Emit a `bft_consensus_aft_v1` bundle from a block the native AFT path
/// already finalized. This is the runtime entry point.
///
/// The caller supplies a v2 template whose availability manifest already
/// declares the block-header payload (and whose `availability_payloads` already
/// carry its bytes), because retention, locations, and failure domains are
/// deployment facts this crate must not invent. Everything about the quorum is
/// derived here from `finalized` and then re-verified end to end by
/// [`verify_bundle`] before the bundle is returned, so an insufficient,
/// duplicated, undeclared, or unrelated quorum refuses at emission rather than
/// shipping a certificate whose label outruns its evidence.
///
/// ## What a returned bundle establishes, and what it does not
///
/// It establishes that a quorum of members — each holding a distinct key that
/// derives into the certified block's own committed validator set — produced
/// verified Ed25519 signatures over the exact native AFT preimage for that
/// block, at a threshold meeting the classic-BFT rule. It establishes nothing
/// about non-equivocation, and in particular it does **not** establish that the
/// block commits to this checkpoint's recognized effect; see
/// [`VerifiedNativeAftBlock::effect_committed_in_block`].
pub fn emit_native_aft_consensus(
    mut bundle: Value,
    finalized: &NativeAftFinalizedBlock,
    issuer_key_id: &str,
    signing_key: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    let certificate = field(field(&bundle, "checkpoint")?, "finality_certificate")?;
    let block_payload_ref = text(
        field(field(certificate, "consensus_evidence")?, "certified_block")?,
        "block_payload_ref",
    )?;
    let (evidence, votes) = native_evidence_from_certificate(finalized, &block_payload_ref)?;

    // The header bytes must be the ones the manifest already publishes, or the
    // block a verifier can retrieve would not be the block that was certified.
    let declared = array(
        field(field(&bundle, "checkpoint")?, "availability_manifest")?,
        "payloads",
    )?
    .iter()
    .any(|payload| {
        text(payload, "payload_ref").ok().as_deref() == Some(block_payload_ref.as_str())
            && text(payload, "payload_hash").ok() == Some(hash_bytes(&finalized.block_header_bytes))
    });
    if !declared {
        return Err(refuse_evidence(format!(
            "availability manifest does not declare {block_payload_ref} with the supplied block header bytes"
        )));
    }

    let checkpoint = field_mut(&mut bundle, "checkpoint")?;
    let certificate = field_mut(checkpoint, "finality_certificate")?;
    object_mut(certificate)?.insert("consensus_evidence".into(), evidence);

    let prepared = prepare_checkpoint(bundle, "bft_consensus")?;
    if prepared.vote_binding.as_deref() != Some(NATIVE_AFT_VOTE_BINDING) {
        return Err(refuse_evidence(
            "native AFT emission prepared a template that is not native-bound",
        ));
    }
    finalize(prepared, &votes, issuer_key_id, signing_key)
}

/// Finalize and sign one caller-supplied `single_authority` v2 template. Every
/// derived field is overwritten, then the complete result is verified before it
/// is returned. Retained with its original signature and behaviour; it is
/// [`prepare_checkpoint`] plus [`finalize_single_authority`].
pub fn emit_single_authority(
    bundle: Value,
    issuer_key_id: &str,
    signing_key: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    let prepared = prepare_checkpoint(bundle, "single_authority")?;
    finalize_single_authority(prepared, issuer_key_id, signing_key)
}

fn object_mut(value: &mut Value) -> Result<&mut Map<String, Value>, VerificationError> {
    value
        .as_object_mut()
        .ok_or_else(|| VerificationError::Field("expected mutable object".into()))
}
fn field_mut<'a>(value: &'a mut Value, name: &str) -> Result<&'a mut Value, VerificationError> {
    object_mut(value)?
        .get_mut(name)
        .ok_or_else(|| VerificationError::Field(name.into()))
}
fn array_mut<'a>(
    value: &'a mut Value,
    name: &str,
) -> Result<&'a mut Vec<Value>, VerificationError> {
    field_mut(value, name)?
        .as_array_mut()
        .ok_or_else(|| VerificationError::Field(name.into()))
}
fn set_text(value: &mut Value, name: &str, text: String) -> Result<(), VerificationError> {
    object_mut(value)?.insert(name.into(), Value::String(text));
    Ok(())
}
fn set_range(
    value: &mut Value,
    name: &str,
    rows: &[(u64, String)],
) -> Result<(), VerificationError> {
    let first = rows
        .first()
        .ok_or_else(|| VerificationError::Binding("empty material range".into()))?
        .0;
    let last = rows
        .last()
        .ok_or_else(|| VerificationError::Binding("empty material range".into()))?
        .0;
    object_mut(value)?.insert(name.into(), json!({"first":first,"last":last}));
    Ok(())
}
fn material_root_rewrite(
    domain: &str,
    materials: &mut [Value],
) -> Result<(String, Vec<(u64, String)>), VerificationError> {
    for material in materials.iter_mut() {
        let hash = hash_value(field(material, "body")?)?;
        set_text(material, "body_hash", hash)?;
    }
    material_root(domain, materials)
}

#[cfg(test)]
mod tests;
