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
//! at least a `2f + 1` quorum of distinct verified signatures over the exact
//! checkpoint, under a membership that tolerates at least one Byzantine fault
//! and satisfies `n >= 3f + 1`.
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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ioi_api::crypto::{SerializableKey, SigningKey, VerifyingKey};
use ioi_crypto::sign::eddsa::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::generated::architecture_contracts::{
    architecture_contract_schema_hash, validate_architecture_contract,
};
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
    /// Distinct declared members whose signature over this exact checkpoint
    /// verified. Never a count of signature bytes present.
    pub distinct_member_signatures_verified: u64,
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

fn verify_availability(checkpoint: &Value, bundle: &Value) -> Result<(), VerificationError> {
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
    Ok(())
}

fn refuse_evidence(detail: impl Into<String>) -> VerificationError {
    VerificationError::ConsensusEvidence(detail.into())
}

/// JCS hash over exactly the membership-defining surface: every evidence field
/// except the recorded hash, the votes cast under it, and the view. Binding it
/// means a membership, threshold, or fault-model swap cannot hide behind a
/// quorum that verified against a different set. The view is excluded on
/// purpose — it identifies one decision, not the membership, and successive
/// checkpoints inside one authority epoch advance the view while the membership
/// must not move. The vote message binds the view separately.
fn consensus_membership_hash(evidence: &Value) -> Result<String, VerificationError> {
    hash_value(&json!({
        "domain": CONSENSUS_MEMBERSHIP_DOMAIN,
        "membership": without(evidence, &["membership_hash", "votes", "view"])?,
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

/// Recompute the whole peer-quorum claim offline. Every branch refuses; none
/// treats the `bft_consensus` label, the issuer signature, or the presence of
/// signature bytes as evidence that peers agreed.
fn verify_consensus_evidence(
    checkpoint: &Value,
    certificate: &Value,
    checkpoint_hash: &str,
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
    if threshold > declared_members {
        return Err(refuse_evidence(
            "quorum threshold exceeds the declared membership",
        ));
    }

    let members = array(evidence, "members")?;
    if members.len() as u64 != declared_members {
        return Err(refuse_evidence(
            "declared member count does not match the supplied membership",
        ));
    }
    let mut member_keys = BTreeMap::new();
    let mut distinct_keys = BTreeSet::new();
    for member in members {
        let member_ref = text(member, "member_ref")?;
        let public_key = text(member, "public_key")?;
        if !distinct_keys.insert(public_key.clone()) {
            return Err(refuse_evidence(format!(
                "duplicate member public key at {member_ref}: one key holding several seats is one signer, not a quorum"
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
    let message = consensus_vote_message(
        &text(checkpoint, "domain_id")?,
        number(checkpoint, "authority_epoch")?,
        &membership_hash,
        view,
        checkpoint_hash,
    );
    let mut voted = BTreeSet::new();
    for vote in array(evidence, "votes")? {
        let member_ref = text(vote, "member_ref")?;
        let public_key = member_keys
            .get(&member_ref)
            .ok_or_else(|| refuse_evidence(format!("vote from undeclared member {member_ref}")))?;
        if !voted.insert(member_ref.clone()) {
            return Err(refuse_evidence(format!("duplicate vote from {member_ref}")));
        }
        let key_bytes =
            hex::decode(public_key).map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let signature_bytes = hex::decode(text(vote, "signature")?)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let public = Ed25519PublicKey::from_bytes(&key_bytes)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let signature = Ed25519Signature::from_bytes(&signature_bytes)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        public.verify(&message, &signature).map_err(|_| {
            refuse_evidence(format!(
                "member {member_ref} did not sign this checkpoint under this membership and view"
            ))
        })?;
    }
    let verified = voted.len() as u64;
    if verified < threshold {
        return Err(refuse_evidence(format!(
            "{verified} verified member signatures is below the declared quorum threshold {threshold}"
        )));
    }

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

    Ok(VerifiedQuorum {
        membership_ref: text(evidence, "membership_ref")?,
        membership_hash,
        membership_epoch: number(evidence, "membership_epoch")?,
        view,
        total_voting_members: declared_members,
        byzantine_fault_tolerance: tolerated,
        quorum_threshold: threshold,
        distinct_member_signatures_verified: verified,
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
        verify_consensus_evidence(checkpoint, certificate, &checkpoint_hash)?;
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
    verify_availability(checkpoint, bundle)?;

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
    /// whose admission does not take peer votes — never an empty message that
    /// would let a caller collect signatures over nothing.
    pub fn vote_message(&self) -> Option<&[u8]> {
        self.vote_message.as_deref()
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
    let vote_message = if variant == "bft_consensus_aft_v1" {
        let evidence = field_mut(certificate, "consensus_evidence")?;
        if !array(evidence, "votes")?.is_empty() {
            return Err(refuse_evidence(
                "a prepared template carries no votes: members sign the prepared vote message, then the quorum is supplied to finalize_bft_consensus",
            ));
        }
        let membership_hash = consensus_membership_hash(evidence)?;
        set_text(evidence, "membership_hash", membership_hash.clone())?;
        let view = number(evidence, "view")?;
        Some(consensus_vote_message(
            &domain_id,
            authority_epoch,
            &membership_hash,
            view,
            &checkpoint_hash,
        ))
    } else {
        None
    };

    Ok(PreparedCheckpoint {
        bundle,
        profile: member,
        certificate_variant: variant,
        checkpoint_hash,
        vote_message,
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
    finalize(prepared, votes, issuer_key_id, signing_key)
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
