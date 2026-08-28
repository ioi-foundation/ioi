//! Source-neutral v2 recognized-effect checkpoint emission and offline verification.
//!
//! Agentgres is IOI's current runtime owner and may call the emitter, but no
//! universal type or verifier rule below depends on Agentgres. Unsupported
//! profile/certificate semantics refuse before signature verification.

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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("unsupported bundle version: {0}")]
    UnsupportedVersion(String),
    #[error("unsupported profile semantics: profile={profile} variant={variant}")]
    UnsupportedProfile { profile: String, variant: String },
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedClaim {
    pub checkpoint_id: String,
    pub domain_id: String,
    pub authority_epoch: u64,
    pub profile: String,
    pub certificate_variant: String,
    pub established_axes: Vec<String>,
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
    validate(CHECKPOINT_V2, checkpoint)?;
    let certificate = field(checkpoint, "finality_certificate")?;
    let profile = text(checkpoint, "profile")?;
    let variant = text(certificate, "certificate_variant")?;
    if profile != "single_authority" || variant != "single_authority_v1" {
        return Err(VerificationError::UnsupportedProfile { profile, variant });
    }
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
    verify_certificate_signature(certificate)
}

pub fn verify_bundle(bundle: &Value) -> Result<VerifiedClaim, VerificationError> {
    let version = text(bundle, "schema_version").unwrap_or_else(|_| "missing".into());
    if version != "ioi.foundations.receipt-proof-bundle.v2" {
        return Err(VerificationError::UnsupportedVersion(version));
    }
    validate(BUNDLE_V2, bundle)?;
    let checkpoint = field(bundle, "checkpoint")?;
    validate(CHECKPOINT_V2, checkpoint)?;
    validate(
        CONFLICT_BINDING_V1,
        field(checkpoint, "conflict_authority_binding")?,
    )?;
    validate(RECOGNITION_V1, field(checkpoint, "recognition")?)?;
    validate(VERIFIER_V1, field(checkpoint, "verifier_contract")?)?;
    validate(CERTIFICATE_V1, field(checkpoint, "finality_certificate")?)?;

    let certificate = field(checkpoint, "finality_certificate")?;
    let profile = text(checkpoint, "profile")?;
    let variant = text(certificate, "certificate_variant")?;
    if profile != "single_authority" || variant != "single_authority_v1" {
        return Err(VerificationError::UnsupportedProfile { profile, variant });
    }
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
    if !verifier_profiles.contains(profile.as_str())
        || !verifier_variants.contains(variant.as_str())
    {
        return Err(VerificationError::Binding(
            "verifier profile/certificate support".into(),
        ));
    }
    let verifier_axes: BTreeSet<String> = array(verifier, "axes")?
        .iter()
        .map(|entry| text(entry, "axis"))
        .collect::<Result<_, _>>()?;
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
    if claimed_axes.contains("availability")
        && text(field(checkpoint, "availability_manifest")?, "claim_status")? != "verified"
    {
        return Err(VerificationError::Binding(
            "availability axis requires a verified manifest".into(),
        ));
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

    let bundle_hash = hash_value(&without(bundle, &["bundle_hash"])?)?;
    check_eq(bundle_hash, text(bundle, "bundle_hash")?, "bundle hash")?;
    Ok(VerifiedClaim {
        checkpoint_id: text(checkpoint, "checkpoint_id")?,
        domain_id: text(checkpoint, "domain_id")?,
        authority_epoch: number(checkpoint, "authority_epoch")?,
        profile: "single_authority".into(),
        certificate_variant: "single_authority_v1".into(),
        established_axes: requested_axes,
    })
}

/// Finalize and sign one caller-supplied v2 template for the only production
/// semantics currently implemented by this crate. Every derived field is
/// overwritten, then the complete result is verified before it is returned.
pub fn emit_single_authority(
    mut bundle: Value,
    issuer_key_id: &str,
    signing_key: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    let profile = text(field(&bundle, "checkpoint")?, "profile")?;
    let variant = text(
        field(field(&bundle, "checkpoint")?, "finality_certificate")?,
        "certificate_variant",
    )?;
    if profile != "single_authority" || variant != "single_authority_v1" {
        return Err(VerificationError::UnsupportedProfile { profile, variant });
    }
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
    set_text(
        manifest,
        "availability_verifier_contract_ref",
        verifier_id.clone(),
    )?;
    set_text(
        manifest,
        "availability_verifier_contract_hash",
        verifier_hash.clone(),
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
