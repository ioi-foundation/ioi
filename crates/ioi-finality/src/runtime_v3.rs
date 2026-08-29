//! Explicit runtime receipt-proof successor.
//!
//! v1 and v2 model state as a sorted JCS map. The production validator instead
//! commits a native state-tree root in each block header, so reusing v2 would
//! silently change its meaning. This module defines a closed v3 bundle and v2
//! certificate whose verifier binds the exact native block, every ordered
//! transaction, every individual execution receipt, the native pre/post state
//! roots, availability bytes, the active profile epoch, and the writer fence.

use super::*;
use ioi_api::chain::{BlockExecutionReceipt, BLOCK_EXECUTION_RECEIPT_DOMAIN};
use ioi_types::config::RuntimeFinalityProfile;
use serde::de::DeserializeOwned;

pub const RUNTIME_BUNDLE_V3: &str = "ioi.foundations.receipt-proof-bundle.v3";
pub const RUNTIME_CHECKPOINT_V3: &str = "ioi.foundations.receipt-checkpoint.v3";
pub const RUNTIME_CERTIFICATE_V2: &str = "ioi.finality-certificate.v2";
pub const RUNTIME_PROFILE_CONTRACT_V1: &str = "ioi.ordering-admission-finality-profile.v1";
pub const RUNTIME_VERIFIER_V3: &str = "ioi.runtime-receipt-proof-verifier.v3";

const OPERATION_ROOT_DOMAIN: &str = "ioi.runtime-block-operations.v1";
const RECEIPT_ROOT_DOMAIN: &str = "ioi.runtime-block-receipts.v1";
const MEMBERSHIP_ROOT_DOMAIN: &str = "ioi.runtime-native-aft-membership.v1";
const JCS_SAFE_U64: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRangeV1 {
    pub first: u64,
    pub last: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMaterialV3 {
    pub sequence: u64,
    pub body: Value,
    pub body_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStateCommitmentV1 {
    pub algorithm: String,
    pub height: u64,
    pub root_base64: String,
    pub root_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWriterFenceV1 {
    pub profile_epoch: u64,
    pub writer_identity: String,
    pub fence_token: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePayloadDeclarationV1 {
    pub payload_ref: String,
    pub payload_hash: String,
    pub byte_length: u64,
    pub location_ref: String,
    pub failure_domain_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAvailabilityManifestV1 {
    pub schema_version: String,
    pub manifest_id: String,
    pub manifest_hash: String,
    pub retention_class: String,
    pub retention_policy_root: String,
    pub payloads: Vec<RuntimePayloadDeclarationV1>,
    pub failure_behavior: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAvailabilityPayloadV1 {
    pub payload_ref: String,
    pub payload_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTrustedIssuerV1 {
    pub issuer_key_id: String,
    pub issuer_public_key: String,
    pub domain_id: String,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAftMemberV2 {
    pub member_ref: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAftVoteV2 {
    pub member_ref: String,
    pub account_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeNativeAftEvidenceV2 {
    pub schema_version: String,
    pub consensus_protocol_ref: String,
    pub membership_ref: String,
    pub membership_epoch: u64,
    pub fault_model: String,
    pub synchrony_model: String,
    pub total_voting_members: u64,
    pub byzantine_fault_tolerance: u64,
    pub quorum_threshold: u64,
    pub block_height: u64,
    pub block_view: u64,
    pub block_hash: String,
    pub vote_message_domain: String,
    pub effect_commitment: String,
    pub membership_hash: String,
    pub members: Vec<RuntimeAftMemberV2>,
    pub votes: Vec<RuntimeAftVoteV2>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFinalityCertificateV2 {
    pub schema_version: String,
    pub certificate_domain: String,
    pub certificate_variant: String,
    pub certificate_id: String,
    pub domain_id: String,
    pub authority_epoch: u64,
    pub authority_revocation_epoch: u64,
    pub checkpoint_hash: String,
    pub operation_range: RuntimeRangeV1,
    pub receipt_range: RuntimeRangeV1,
    pub profile_contract_version: String,
    pub profile: String,
    pub profile_epoch: u64,
    pub writer_identity: String,
    pub fence_token: u64,
    pub claimed_axes: Vec<String>,
    pub verifier_contract_ref: String,
    pub verifier_contract_hash: String,
    pub issuer_key_id: String,
    pub issuer_public_key: String,
    pub body_hash: String,
    pub signature_suite: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_aft_evidence: Option<RuntimeNativeAftEvidenceV2>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCheckpointV3 {
    pub schema_version: String,
    pub checkpoint_domain: String,
    pub checkpoint_id: String,
    pub body_hash: String,
    pub domain_id: String,
    pub authority_epoch: u64,
    pub authority_revocation_epoch: u64,
    pub operation_range: RuntimeRangeV1,
    pub receipt_range: RuntimeRangeV1,
    pub previous_checkpoint_ref: Option<String>,
    pub previous_checkpoint_hash: Option<String>,
    pub previous_canonical_head: String,
    pub resulting_canonical_head: String,
    pub previous_state_commitment: RuntimeStateCommitmentV1,
    pub resulting_state_commitment: RuntimeStateCommitmentV1,
    pub operation_root: String,
    pub receipt_root: String,
    pub profile_contract_version: String,
    pub profile: String,
    pub writer_fence: RuntimeWriterFenceV1,
    pub authority_policy_root: String,
    pub governance_policy_root: String,
    pub availability_policy_root: String,
    pub availability_manifest: RuntimeAvailabilityManifestV1,
    pub availability_manifest_hash: String,
    pub verifier_contract_ref: String,
    pub verifier_contract_hash: String,
    pub durability_class: String,
    pub finality_certificate: RuntimeFinalityCertificateV2,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReceiptProofBundleV3 {
    pub schema_version: String,
    pub bundle_domain: String,
    pub bundle_id: String,
    pub bundle_hash: String,
    pub checkpoint: RuntimeCheckpointV3,
    pub operations: Vec<RuntimeMaterialV3>,
    pub receipts: Vec<RuntimeMaterialV3>,
    pub availability_payloads: Vec<RuntimeAvailabilityPayloadV1>,
    pub trusted_issuer: RuntimeTrustedIssuerV1,
    pub requested_axes: Vec<String>,
    pub compatibility_behavior: String,
}

/// Inputs the runtime owns and the emitter must never invent.
pub struct RuntimeBundleV3Input<'a> {
    pub bundle_id: &'a str,
    pub checkpoint_id: &'a str,
    pub certificate_id: &'a str,
    pub availability_manifest_id: &'a str,
    pub block_payload_ref: &'a str,
    pub domain_id: &'a str,
    pub authority_epoch: u64,
    pub authority_revocation_epoch: u64,
    pub profile: RuntimeFinalityProfile,
    pub profile_epoch: u64,
    pub writer_identity: &'a str,
    pub fence_token: u64,
    pub operation_sequence_first: u64,
    pub receipt_sequence_first: u64,
    pub previous_checkpoint_ref: Option<&'a str>,
    pub previous_checkpoint_hash: Option<&'a str>,
    pub authority_policy_root: &'a str,
    pub governance_policy_root: &'a str,
    pub availability_policy_root: &'a str,
    pub retention_policy_root: &'a str,
    pub location_ref: &'a str,
    pub failure_domain_ref: &'a str,
    pub verifier_contract_hash: &'a str,
    pub issuer_key_id: &'a str,
    pub block: &'a Block<ChainTransaction>,
    pub receipts: &'a [BlockExecutionReceipt],
    pub native_aft: Option<&'a NativeAftFinalizedBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedRuntimeClaimV3 {
    pub checkpoint_id: String,
    pub domain_id: String,
    pub authority_epoch: u64,
    pub authority_revocation_epoch: u64,
    pub profile: String,
    pub certificate_variant: String,
    pub profile_epoch: u64,
    pub writer_identity: String,
    pub fence_token: u64,
    pub previous_canonical_head: String,
    pub resulting_canonical_head: String,
    pub operation_count: u64,
    pub receipt_count: u64,
    pub native_quorum_verified: bool,
    pub effect_committed_in_block: bool,
    pub receipts_committed_in_block: bool,
    pub established_axes: Vec<String>,
}

fn safe_u64(value: u64, field: &str) -> Result<(), VerificationError> {
    if value > JCS_SAFE_U64 {
        return Err(VerificationError::Field(format!(
            "{field} exceeds the JCS safe-integer bound"
        )));
    }
    Ok(())
}

fn require_hash(value: &str, field: &str) -> Result<(), VerificationError> {
    let Some(raw) = value.strip_prefix("sha256:") else {
        return Err(VerificationError::Field(field.into()));
    };
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(VerificationError::Field(field.into()));
    }
    Ok(())
}

fn require_nonempty(value: &str, field: &str) -> Result<(), VerificationError> {
    if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(VerificationError::Field(field.into()));
    }
    Ok(())
}

fn json_value<T: Serialize>(value: &T, field: &str) -> Result<Value, VerificationError> {
    serde_json::to_value(value)
        .map_err(|error| VerificationError::Field(format!("{field}: {error}")))
}

fn json_from_value<T: DeserializeOwned>(value: Value, field: &str) -> Result<T, VerificationError> {
    serde_json::from_value(value)
        .map_err(|error| VerificationError::Field(format!("{field}: {error}")))
}

fn checkpoint_preimage(checkpoint: &RuntimeCheckpointV3) -> Result<Value, VerificationError> {
    let value = json_value(checkpoint, "runtime checkpoint JSON")?;
    without(&value, &["body_hash", "finality_certificate"])
}

fn certificate_preimage(
    certificate: &RuntimeFinalityCertificateV2,
) -> Result<Value, VerificationError> {
    let value = json_value(certificate, "runtime certificate JSON")?;
    without(&value, &["body_hash", "signature"])
}

fn bundle_preimage(bundle: &RuntimeReceiptProofBundleV3) -> Result<Value, VerificationError> {
    let value = json_value(bundle, "runtime bundle JSON")?;
    without(&value, &["bundle_hash"])
}

fn state_commitment(height: u64, root: &[u8]) -> RuntimeStateCommitmentV1 {
    RuntimeStateCommitmentV1 {
        algorithm: "ioi.native-block-state-root.v1".into(),
        height,
        root_base64: BASE64.encode(root),
        root_hash: hash_bytes(root),
    }
}

fn material_range(first: u64, len: usize) -> Result<RuntimeRangeV1, VerificationError> {
    if len == 0 {
        return Err(VerificationError::Field(
            "runtime effect contains no operations".into(),
        ));
    }
    let last = first
        .checked_add(len as u64 - 1)
        .ok_or_else(|| VerificationError::Field("material range overflow".into()))?;
    safe_u64(last, "material range")?;
    Ok(RuntimeRangeV1 { first, last })
}

fn build_materials(
    input: &RuntimeBundleV3Input<'_>,
) -> Result<(Vec<RuntimeMaterialV3>, Vec<RuntimeMaterialV3>), VerificationError> {
    if input.receipts.len() != input.block.transactions.len() {
        return Err(VerificationError::Binding(
            "one execution receipt per block transaction".into(),
        ));
    }
    let mut operations = Vec::with_capacity(input.block.transactions.len());
    let mut receipts = Vec::with_capacity(input.receipts.len());
    for (index, (transaction, receipt)) in input
        .block
        .transactions
        .iter()
        .zip(input.receipts.iter())
        .enumerate()
    {
        let operation_sequence = input
            .operation_sequence_first
            .checked_add(index as u64)
            .ok_or_else(|| VerificationError::Field("operation sequence overflow".into()))?;
        let receipt_sequence = input
            .receipt_sequence_first
            .checked_add(index as u64)
            .ok_or_else(|| VerificationError::Field("receipt sequence overflow".into()))?;
        let tx_hash = transaction
            .hash()
            .map_err(|error| VerificationError::Field(error.to_string()))?;
        if receipt.block_height != input.block.header.height
            || receipt.transaction_index != index as u64
            || receipt.transaction_hash != tx_hash
        {
            return Err(VerificationError::Binding(format!(
                "receipt {index} does not bind its block transaction"
            )));
        }
        let operation_body = json!({
            "transaction_index": index as u64,
            "transaction_hash": hash_prefixed(&tx_hash),
            "transaction_base64": BASE64.encode(to_bytes_canonical(transaction).map_err(VerificationError::Field)?),
        });
        operations.push(RuntimeMaterialV3 {
            sequence: operation_sequence,
            body_hash: hash_value(&operation_body)?,
            body: operation_body,
        });
        let receipt_body = receipt
            .body()
            .map_err(|error| VerificationError::Field(error.to_string()))?;
        receipts.push(RuntimeMaterialV3 {
            sequence: receipt_sequence,
            body_hash: hash_value(&receipt_body)?,
            body: receipt_body,
        });
    }
    Ok((operations, receipts))
}

fn native_evidence_v2(
    finalized: &NativeAftFinalizedBlock,
) -> Result<RuntimeNativeAftEvidenceV2, VerificationError> {
    let certificate = &finalized.quorum_certificate;
    if !certificate.aggregated_signature.is_empty() || !certificate.signers_bitfield.is_empty() {
        return Err(refuse_evidence(
            "runtime v3 does not verify aggregated BLS quorum fields",
        ));
    }
    let mut by_account = BTreeMap::new();
    let mut members = Vec::with_capacity(finalized.members.len());
    for member in &finalized.members {
        let account = account_id_from_key_material(SignatureSuite::ED25519, &member.public_key)
            .map_err(|error| refuse_evidence(format!("member account id: {error}")))?;
        if by_account
            .insert(account, member.member_ref.clone())
            .is_some()
        {
            return Err(refuse_evidence("duplicate member account id"));
        }
        members.push(RuntimeAftMemberV2 {
            member_ref: member.member_ref.clone(),
            public_key: hex::encode(member.public_key),
        });
    }
    members.sort_by(|left, right| left.member_ref.cmp(&right.member_ref));
    let membership_hash = hash_value(&json!({
        "domain": MEMBERSHIP_ROOT_DOMAIN,
        "consensus_protocol_ref": finalized.consensus_protocol_ref,
        "membership_ref": finalized.membership_ref,
        "membership_epoch": finalized.membership_epoch,
        "fault_model": "byzantine",
        "synchrony_model": "partial_synchrony",
        "total_voting_members": members.len() as u64,
        "byzantine_fault_tolerance": finalized.byzantine_fault_tolerance,
        "members": members,
    }))?;
    let mut votes = Vec::with_capacity(certificate.signatures.len());
    let mut seen = BTreeSet::new();
    for (account, signature) in &certificate.signatures {
        let member_ref = by_account
            .get(&account.0)
            .ok_or_else(|| refuse_evidence("quorum vote is outside the declared membership"))?;
        if !seen.insert(member_ref.clone()) {
            return Err(refuse_evidence("quorum repeats one member"));
        }
        votes.push(RuntimeAftVoteV2 {
            member_ref: member_ref.clone(),
            account_id: hex::encode(account.0),
            signature: hex::encode(signature),
        });
    }
    votes.sort_by(|left, right| left.member_ref.cmp(&right.member_ref));
    Ok(RuntimeNativeAftEvidenceV2 {
        schema_version: "ioi.native-aft-runtime-evidence.v2".into(),
        consensus_protocol_ref: finalized.consensus_protocol_ref.clone(),
        membership_ref: finalized.membership_ref.clone(),
        membership_epoch: finalized.membership_epoch,
        fault_model: "byzantine".into(),
        synchrony_model: "partial_synchrony".into(),
        total_voting_members: members.len() as u64,
        byzantine_fault_tolerance: finalized.byzantine_fault_tolerance,
        quorum_threshold: members.len() as u64 * 2 / 3 + 1,
        block_height: certificate.height,
        block_view: certificate.view,
        block_hash: hash_prefixed(&certificate.block_hash),
        vote_message_domain: NATIVE_AFT_VOTE_DOMAIN.into(),
        effect_commitment: FULL_BLOCK_EFFECT_COMMITMENT.into(),
        membership_hash,
        members,
        votes,
    })
}

/// Emit and self-verify an explicit v3 runtime bundle.
pub fn emit_runtime_bundle_v3(
    input: RuntimeBundleV3Input<'_>,
    signing_key: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    for (field, value) in [
        ("bundle_id", input.bundle_id),
        ("checkpoint_id", input.checkpoint_id),
        ("certificate_id", input.certificate_id),
        ("availability_manifest_id", input.availability_manifest_id),
        ("block_payload_ref", input.block_payload_ref),
        ("domain_id", input.domain_id),
        ("writer_identity", input.writer_identity),
        ("location_ref", input.location_ref),
        ("failure_domain_ref", input.failure_domain_ref),
        ("issuer_key_id", input.issuer_key_id),
    ] {
        require_nonempty(value, field)?;
    }
    if input.block.header.height == 0 {
        return Err(VerificationError::Binding(
            "runtime effects cannot occupy the genesis block".into(),
        ));
    }
    match (
        input.previous_checkpoint_ref,
        input.previous_checkpoint_hash,
    ) {
        (None, None) => {}
        (Some(reference), Some(hash)) => {
            require_nonempty(reference, "previous_checkpoint_ref")?;
            require_hash(hash, "previous_checkpoint_hash")?;
        }
        _ => {
            return Err(VerificationError::Binding(
                "previous checkpoint ref/hash must be supplied together".into(),
            ))
        }
    }
    for (field, value) in [
        ("authority_policy_root", input.authority_policy_root),
        ("governance_policy_root", input.governance_policy_root),
        ("availability_policy_root", input.availability_policy_root),
        ("retention_policy_root", input.retention_policy_root),
        ("verifier_contract_hash", input.verifier_contract_hash),
    ] {
        require_hash(value, field)?;
    }
    safe_u64(input.authority_epoch, "authority_epoch")?;
    safe_u64(
        input.authority_revocation_epoch,
        "authority_revocation_epoch",
    )?;
    safe_u64(input.profile_epoch, "profile_epoch")?;
    safe_u64(input.fence_token, "fence_token")?;

    let (operations, receipts) = build_materials(&input)?;
    let operation_range = material_range(input.operation_sequence_first, operations.len())?;
    let receipt_range = material_range(input.receipt_sequence_first, receipts.len())?;
    let operation_values = json_value(&operations, "runtime operations JSON")?;
    let receipt_values = json_value(&receipts, "runtime receipts JSON")?;
    let (operation_root, _) = material_root(
        OPERATION_ROOT_DOMAIN,
        operation_values
            .as_array()
            .ok_or_else(|| VerificationError::Field("operations".into()))?,
    )?;
    let (receipt_root, _) = material_root(
        RECEIPT_ROOT_DOMAIN,
        receipt_values
            .as_array()
            .ok_or_else(|| VerificationError::Field("receipts".into()))?,
    )?;

    let full_block_bytes = to_bytes_canonical(input.block).map_err(VerificationError::Field)?;
    let block_hash: [u8; 32] = input
        .block
        .header
        .hash()
        .map_err(|error| VerificationError::Field(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| VerificationError::Field("block hash".into()))?;
    let payload = RuntimePayloadDeclarationV1 {
        payload_ref: input.block_payload_ref.into(),
        payload_hash: hash_bytes(&full_block_bytes),
        byte_length: full_block_bytes.len() as u64,
        location_ref: input.location_ref.into(),
        failure_domain_ref: input.failure_domain_ref.into(),
    };
    let mut availability_manifest = RuntimeAvailabilityManifestV1 {
        schema_version: "ioi.runtime-availability-manifest.v1".into(),
        manifest_id: input.availability_manifest_id.into(),
        manifest_hash: String::new(),
        retention_class: "durable_local".into(),
        retention_policy_root: input.retention_policy_root.into(),
        payloads: vec![payload],
        failure_behavior: "fail_closed".into(),
    };
    availability_manifest.manifest_hash = hash_value(&without(
        &json_value(&availability_manifest, "runtime availability JSON")?,
        &["manifest_hash"],
    )?)?;

    let native_aft_evidence = match (input.profile, input.native_aft) {
        (RuntimeFinalityProfile::BftConsensusAftV1, Some(finalized)) => {
            let header_bytes =
                to_bytes_canonical(&input.block.header).map_err(VerificationError::Field)?;
            if header_bytes != finalized.block_header_bytes
                || finalized.quorum_certificate.block_hash != block_hash
            {
                return Err(refuse_evidence(
                    "runtime block is not the block named by native AFT finality",
                ));
            }
            Some(native_evidence_v2(finalized)?)
        }
        (RuntimeFinalityProfile::BftConsensusAftV1, None) => {
            return Err(refuse_evidence(
                "bft runtime bundle has no native AFT quorum",
            ))
        }
        (RuntimeFinalityProfile::SingleAuthorityV1, None) => None,
        (RuntimeFinalityProfile::SingleAuthorityV1, Some(_)) => {
            return Err(refuse_evidence(
                "single-authority runtime bundle must not carry peer quorum evidence",
            ))
        }
    };
    let public_key = signing_key
        .public_key()
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let profile = input.profile.canonical_member().to_owned();
    let variant = input.profile.certificate_variant().to_owned();
    let verifier_contract_ref = format!(
        "verifier-contract://ioi/runtime-receipt-proof-v3/{}",
        input.profile.certificate_variant()
    );
    let mut certificate = RuntimeFinalityCertificateV2 {
        schema_version: RUNTIME_CERTIFICATE_V2.into(),
        certificate_domain: RUNTIME_CERTIFICATE_V2.into(),
        certificate_variant: variant.clone(),
        certificate_id: input.certificate_id.into(),
        domain_id: input.domain_id.into(),
        authority_epoch: input.authority_epoch,
        authority_revocation_epoch: input.authority_revocation_epoch,
        checkpoint_hash: String::new(),
        operation_range: operation_range.clone(),
        receipt_range: receipt_range.clone(),
        profile_contract_version: RUNTIME_PROFILE_CONTRACT_V1.into(),
        profile: profile.clone(),
        profile_epoch: input.profile_epoch,
        writer_identity: input.writer_identity.into(),
        fence_token: input.fence_token,
        claimed_axes: vec!["integrity".into(), "availability".into()],
        verifier_contract_ref: verifier_contract_ref.clone(),
        verifier_contract_hash: input.verifier_contract_hash.into(),
        issuer_key_id: input.issuer_key_id.into(),
        issuer_public_key: hex::encode(public_key.to_bytes()),
        body_hash: String::new(),
        signature_suite: "ed25519".into(),
        signature: String::new(),
        native_aft_evidence,
    };
    let mut checkpoint = RuntimeCheckpointV3 {
        schema_version: RUNTIME_CHECKPOINT_V3.into(),
        checkpoint_domain: RUNTIME_CHECKPOINT_V3.into(),
        checkpoint_id: input.checkpoint_id.into(),
        body_hash: String::new(),
        domain_id: input.domain_id.into(),
        authority_epoch: input.authority_epoch,
        authority_revocation_epoch: input.authority_revocation_epoch,
        operation_range,
        receipt_range,
        previous_checkpoint_ref: input.previous_checkpoint_ref.map(str::to_owned),
        previous_checkpoint_hash: input.previous_checkpoint_hash.map(str::to_owned),
        previous_canonical_head: hash_prefixed(&input.block.header.parent_hash),
        resulting_canonical_head: hash_prefixed(&block_hash),
        previous_state_commitment: state_commitment(
            input.block.header.height.saturating_sub(1),
            input.block.header.parent_state_root.as_ref(),
        ),
        resulting_state_commitment: state_commitment(
            input.block.header.height,
            input.block.header.state_root.as_ref(),
        ),
        operation_root,
        receipt_root,
        profile_contract_version: RUNTIME_PROFILE_CONTRACT_V1.into(),
        profile,
        writer_fence: RuntimeWriterFenceV1 {
            profile_epoch: input.profile_epoch,
            writer_identity: input.writer_identity.into(),
            fence_token: input.fence_token,
        },
        authority_policy_root: input.authority_policy_root.into(),
        governance_policy_root: input.governance_policy_root.into(),
        availability_policy_root: input.availability_policy_root.into(),
        availability_manifest_hash: availability_manifest.manifest_hash.clone(),
        availability_manifest,
        verifier_contract_ref,
        verifier_contract_hash: input.verifier_contract_hash.into(),
        durability_class: "device_flush".into(),
        finality_certificate: certificate.clone(),
    };
    checkpoint.body_hash = hash_value(&checkpoint_preimage(&checkpoint)?)?;
    certificate.checkpoint_hash = checkpoint.body_hash.clone();
    certificate.body_hash = hash_value(&certificate_preimage(&certificate)?)?;
    let message = format!("{RUNTIME_CERTIFICATE_V2}\0{}", certificate.body_hash);
    certificate.signature = hex::encode(
        signing_key
            .sign(message.as_bytes())
            .map_err(|error| VerificationError::Crypto(error.to_string()))?
            .to_bytes(),
    );
    checkpoint.finality_certificate = certificate;
    let trusted_issuer = RuntimeTrustedIssuerV1 {
        issuer_key_id: input.issuer_key_id.into(),
        issuer_public_key: hex::encode(public_key.to_bytes()),
        domain_id: input.domain_id.into(),
        authority_epoch: input.authority_epoch,
        revocation_epoch: input.authority_revocation_epoch,
    };
    let mut bundle = RuntimeReceiptProofBundleV3 {
        schema_version: RUNTIME_BUNDLE_V3.into(),
        bundle_domain: RUNTIME_BUNDLE_V3.into(),
        bundle_id: input.bundle_id.into(),
        bundle_hash: String::new(),
        checkpoint,
        operations,
        receipts,
        availability_payloads: vec![RuntimeAvailabilityPayloadV1 {
            payload_ref: input.block_payload_ref.into(),
            payload_base64: BASE64.encode(full_block_bytes),
        }],
        trusted_issuer,
        requested_axes: vec!["integrity".into(), "availability".into()],
        compatibility_behavior: "v1_v2_and_unknown_versions_refused".into(),
    };
    bundle.bundle_hash = hash_value(&bundle_preimage(&bundle)?)?;
    let value = json_value(&bundle, "runtime bundle JSON")?;
    verify_runtime_bundle_v3(&value)?;
    Ok(value)
}

fn verify_native_quorum_v2(
    evidence: &RuntimeNativeAftEvidenceV2,
    header: &BlockHeader,
) -> Result<NativeAftFinalizedBlock, VerificationError> {
    if evidence.schema_version != "ioi.native-aft-runtime-evidence.v2"
        || evidence.fault_model != "byzantine"
        || evidence.synchrony_model != "partial_synchrony"
        || evidence.vote_message_domain != NATIVE_AFT_VOTE_DOMAIN
        || evidence.effect_commitment != FULL_BLOCK_EFFECT_COMMITMENT
    {
        return Err(refuse_evidence("native AFT runtime evidence contract"));
    }
    let n = evidence.total_voting_members;
    let f = evidence.byzantine_fault_tolerance;
    let q = evidence.quorum_threshold;
    for (field, value) in [
        ("membership_epoch", evidence.membership_epoch),
        ("total_voting_members", n),
        ("byzantine_fault_tolerance", f),
        ("quorum_threshold", q),
        ("block_height", evidence.block_height),
        ("block_view", evidence.block_view),
    ] {
        safe_u64(value, field)?;
    }
    let minimum_members = f
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| refuse_evidence("native AFT threshold overflow"))?;
    let expected_quorum = n
        .checked_mul(2)
        .map(|value| value / 3 + 1)
        .ok_or_else(|| refuse_evidence("native AFT quorum overflow"))?;
    if f == 0 || n < minimum_members || q != expected_quorum {
        return Err(refuse_evidence("native AFT BFT threshold contract"));
    }
    if q.saturating_mul(2) <= n.saturating_add(f) || q > n {
        return Err(refuse_evidence("native AFT quorum intersection contract"));
    }
    if evidence.members.len() as u64 != n || (evidence.votes.len() as u64) < q {
        return Err(refuse_evidence("native AFT member/vote count"));
    }
    let expected_membership_hash = hash_value(&json!({
        "domain": MEMBERSHIP_ROOT_DOMAIN,
        "consensus_protocol_ref": evidence.consensus_protocol_ref,
        "membership_ref": evidence.membership_ref,
        "membership_epoch": evidence.membership_epoch,
        "fault_model": evidence.fault_model,
        "synchrony_model": evidence.synchrony_model,
        "total_voting_members": evidence.total_voting_members,
        "byzantine_fault_tolerance": evidence.byzantine_fault_tolerance,
        "members": evidence.members,
    }))?;
    check_eq(
        &expected_membership_hash,
        &evidence.membership_hash,
        "runtime AFT membership hash",
    )?;

    let raw_hash: [u8; 32] = hex::decode(
        evidence
            .block_hash
            .strip_prefix("sha256:")
            .ok_or_else(|| VerificationError::Field("block_hash".into()))?,
    )
    .map_err(|error| VerificationError::Crypto(error.to_string()))?
    .try_into()
    .map_err(|_| VerificationError::Field("block_hash".into()))?;
    let header_hash = header
        .hash()
        .map_err(|error| VerificationError::Field(error.to_string()))?;
    if header_hash.as_slice() != raw_hash
        || header.height != evidence.block_height
        || header.view != evidence.block_view
    {
        return Err(refuse_evidence("runtime AFT certified block identity"));
    }

    let mut by_ref = BTreeMap::new();
    let mut accounts = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut native_members = Vec::with_capacity(evidence.members.len());
    for member in &evidence.members {
        let key: [u8; 32] = hex::decode(&member.public_key)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?
            .try_into()
            .map_err(|_| VerificationError::Field("member public key".into()))?;
        if !keys.insert(key) {
            return Err(refuse_evidence("duplicate native AFT public key"));
        }
        let account = account_id_from_key_material(SignatureSuite::ED25519, &key)
            .map_err(|error| refuse_evidence(format!("member account id: {error}")))?;
        if !accounts.insert(account)
            || by_ref
                .insert(member.member_ref.clone(), (key, account))
                .is_some()
        {
            return Err(refuse_evidence("duplicate native AFT member"));
        }
        native_members.push(NativeAftMember {
            member_ref: member.member_ref.clone(),
            public_key: key,
        });
    }
    let committed: BTreeSet<[u8; 32]> = header
        .validator_set
        .iter()
        .map(|value| {
            value
                .as_slice()
                .try_into()
                .map_err(|_| refuse_evidence("malformed committed validator account"))
        })
        .collect::<Result<_, _>>()?;
    if committed.len() != header.validator_set.len() || committed != accounts {
        return Err(refuse_evidence(
            "runtime AFT membership differs from the certified header",
        ));
    }

    let message = native_aft_vote_message(evidence.block_height, evidence.block_view, &raw_hash)?;
    let mut voted = BTreeSet::new();
    let mut signatures = Vec::with_capacity(evidence.votes.len());
    for vote in &evidence.votes {
        let (key, account) = by_ref
            .get(&vote.member_ref)
            .ok_or_else(|| refuse_evidence("vote from undeclared member"))?;
        if !voted.insert(vote.member_ref.clone()) || vote.account_id != hex::encode(account) {
            return Err(refuse_evidence("duplicate or reassigned native AFT vote"));
        }
        let signature_bytes = hex::decode(&vote.signature)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let public = Ed25519PublicKey::from_bytes(key)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let signature = Ed25519Signature::from_bytes(&signature_bytes)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        public
            .verify(&message, &signature)
            .map_err(|_| refuse_evidence(format!("member {} signature", vote.member_ref)))?;
        signatures.push((ioi_types::app::AccountId(*account), signature_bytes));
    }
    Ok(NativeAftFinalizedBlock {
        block_header_bytes: to_bytes_canonical(header).map_err(VerificationError::Field)?,
        quorum_certificate: QuorumCertificate {
            height: evidence.block_height,
            view: evidence.block_view,
            block_hash: raw_hash,
            signatures,
            aggregated_signature: Vec::new(),
            signers_bitfield: Vec::new(),
        },
        members: native_members,
        membership_ref: evidence.membership_ref.clone(),
        membership_epoch: evidence.membership_epoch,
        consensus_protocol_ref: evidence.consensus_protocol_ref.clone(),
        byzantine_fault_tolerance: evidence.byzantine_fault_tolerance,
    })
}

/// Offline-verify only the explicit v3 runtime contract. v1/v2 and unknown
/// versions refuse before any field is interpreted.
pub fn verify_runtime_bundle_v3(
    bundle: &Value,
) -> Result<VerifiedRuntimeClaimV3, VerificationError> {
    let version = bundle
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or("missing");
    if version != RUNTIME_BUNDLE_V3 {
        return Err(VerificationError::UnsupportedVersion(version.into()));
    }
    let bundle: RuntimeReceiptProofBundleV3 =
        json_from_value(bundle.clone(), "runtime bundle JSON")?;
    for (field, value) in [
        ("bundle_id", bundle.bundle_id.as_str()),
        ("checkpoint_id", bundle.checkpoint.checkpoint_id.as_str()),
        (
            "certificate_id",
            bundle
                .checkpoint
                .finality_certificate
                .certificate_id
                .as_str(),
        ),
        ("domain_id", bundle.checkpoint.domain_id.as_str()),
        (
            "writer_identity",
            bundle.checkpoint.writer_fence.writer_identity.as_str(),
        ),
        (
            "issuer_key_id",
            bundle
                .checkpoint
                .finality_certificate
                .issuer_key_id
                .as_str(),
        ),
    ] {
        require_nonempty(value, field)?;
    }
    if bundle.bundle_domain != RUNTIME_BUNDLE_V3
        || bundle.compatibility_behavior != "v1_v2_and_unknown_versions_refused"
        || bundle.requested_axes != ["integrity", "availability"]
    {
        return Err(VerificationError::Binding("runtime bundle contract".into()));
    }
    check_eq(
        hash_value(&bundle_preimage(&bundle)?)?,
        &bundle.bundle_hash,
        "runtime bundle hash",
    )?;
    let checkpoint = &bundle.checkpoint;
    let certificate = &checkpoint.finality_certificate;
    if checkpoint.schema_version != RUNTIME_CHECKPOINT_V3
        || checkpoint.checkpoint_domain != RUNTIME_CHECKPOINT_V3
        || certificate.schema_version != RUNTIME_CERTIFICATE_V2
        || certificate.certificate_domain != RUNTIME_CERTIFICATE_V2
        || checkpoint.profile_contract_version != RUNTIME_PROFILE_CONTRACT_V1
        || certificate.profile_contract_version != RUNTIME_PROFILE_CONTRACT_V1
        || checkpoint.durability_class != "device_flush"
        || checkpoint.verifier_contract_ref != certificate.verifier_contract_ref
        || checkpoint.verifier_contract_hash != certificate.verifier_contract_hash
    {
        return Err(VerificationError::Binding(
            "runtime checkpoint/certificate contract".into(),
        ));
    }
    require_hash(&checkpoint.verifier_contract_hash, "verifier_contract_hash")?;
    for (field, value) in [
        (
            "authority_policy_root",
            checkpoint.authority_policy_root.as_str(),
        ),
        (
            "governance_policy_root",
            checkpoint.governance_policy_root.as_str(),
        ),
        (
            "availability_policy_root",
            checkpoint.availability_policy_root.as_str(),
        ),
        (
            "retention_policy_root",
            checkpoint
                .availability_manifest
                .retention_policy_root
                .as_str(),
        ),
    ] {
        require_hash(value, field)?;
    }
    for (field, value) in [
        ("authority_epoch", checkpoint.authority_epoch),
        (
            "authority_revocation_epoch",
            checkpoint.authority_revocation_epoch,
        ),
        ("profile_epoch", checkpoint.writer_fence.profile_epoch),
        ("fence_token", checkpoint.writer_fence.fence_token),
    ] {
        safe_u64(value, field)?;
    }
    match (
        checkpoint.previous_checkpoint_ref.as_deref(),
        checkpoint.previous_checkpoint_hash.as_deref(),
    ) {
        (None, None) => {}
        (Some(reference), Some(hash)) => {
            require_nonempty(reference, "previous_checkpoint_ref")?;
            require_hash(hash, "previous_checkpoint_hash")?;
        }
        _ => {
            return Err(VerificationError::Binding(
                "previous checkpoint ref/hash must be supplied together".into(),
            ))
        }
    }
    let expected_checkpoint_hash = hash_value(&checkpoint_preimage(checkpoint)?)?;
    check_eq(
        &expected_checkpoint_hash,
        &checkpoint.body_hash,
        "runtime checkpoint hash",
    )?;
    check_eq(
        &expected_checkpoint_hash,
        &certificate.checkpoint_hash,
        "runtime certificate checkpoint hash",
    )?;
    let expected_certificate_hash = hash_value(&certificate_preimage(certificate)?)?;
    check_eq(
        &expected_certificate_hash,
        &certificate.body_hash,
        "runtime certificate body hash",
    )?;

    for same in [
        checkpoint.domain_id == certificate.domain_id,
        checkpoint.authority_epoch == certificate.authority_epoch,
        checkpoint.authority_revocation_epoch == certificate.authority_revocation_epoch,
        checkpoint.operation_range == certificate.operation_range,
        checkpoint.receipt_range == certificate.receipt_range,
        checkpoint.profile == certificate.profile,
        checkpoint.writer_fence.profile_epoch == certificate.profile_epoch,
        checkpoint.writer_fence.writer_identity == certificate.writer_identity,
        checkpoint.writer_fence.fence_token == certificate.fence_token,
    ] {
        if !same {
            return Err(VerificationError::Binding(
                "runtime checkpoint/certificate field".into(),
            ));
        }
    }
    let trusted = &bundle.trusted_issuer;
    if trusted.issuer_key_id != certificate.issuer_key_id
        || trusted.issuer_public_key != certificate.issuer_public_key
        || trusted.domain_id != certificate.domain_id
        || trusted.authority_epoch != certificate.authority_epoch
        || trusted.revocation_epoch != certificate.authority_revocation_epoch
        || certificate.signature_suite != "ed25519"
    {
        return Err(VerificationError::Binding("runtime trusted issuer".into()));
    }
    let public_bytes = hex::decode(&certificate.issuer_public_key)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let signature_bytes = hex::decode(&certificate.signature)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let public = Ed25519PublicKey::from_bytes(&public_bytes)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let signature = Ed25519Signature::from_bytes(&signature_bytes)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    public
        .verify(
            format!("{RUNTIME_CERTIFICATE_V2}\0{}", certificate.body_hash).as_bytes(),
            &signature,
        )
        .map_err(|_| VerificationError::Crypto("runtime certificate signature".into()))?;

    let profile = match (
        checkpoint.profile.as_str(),
        certificate.certificate_variant.as_str(),
    ) {
        ("bft_consensus", "bft_consensus_aft_v1") => RuntimeFinalityProfile::BftConsensusAftV1,
        ("single_authority", "single_authority_v1") => RuntimeFinalityProfile::SingleAuthorityV1,
        (profile, variant) => {
            return Err(VerificationError::UnsupportedProfile {
                profile: profile.into(),
                variant: variant.into(),
            })
        }
    };
    let expected_verifier_ref = format!(
        "verifier-contract://ioi/runtime-receipt-proof-v3/{}",
        profile.certificate_variant()
    );
    if certificate.verifier_contract_ref != expected_verifier_ref {
        return Err(VerificationError::Binding(
            "runtime profile verifier contract ref".into(),
        ));
    }
    if certificate.claimed_axes != ["integrity", "availability"] {
        return Err(VerificationError::UnsupportedAxis(
            "runtime certificate axes".into(),
        ));
    }

    let operation_values = json_value(&bundle.operations, "runtime operations JSON")?;
    let receipt_values = json_value(&bundle.receipts, "runtime receipts JSON")?;
    let (operation_root, operation_rows) = material_root(
        OPERATION_ROOT_DOMAIN,
        operation_values
            .as_array()
            .ok_or_else(|| VerificationError::Field("operations".into()))?,
    )?;
    let (receipt_root, receipt_rows) = material_root(
        RECEIPT_ROOT_DOMAIN,
        receipt_values
            .as_array()
            .ok_or_else(|| VerificationError::Field("receipts".into()))?,
    )?;
    check_eq(
        operation_root,
        &checkpoint.operation_root,
        "runtime operation root",
    )?;
    check_eq(
        receipt_root,
        &checkpoint.receipt_root,
        "runtime receipt root",
    )?;
    if operation_rows.len() != receipt_rows.len() || operation_rows.is_empty() {
        return Err(VerificationError::Binding(
            "one receipt per runtime operation".into(),
        ));
    }
    if checkpoint.operation_range
        != material_range(checkpoint.operation_range.first, operation_rows.len())?
        || checkpoint.receipt_range
            != material_range(checkpoint.receipt_range.first, receipt_rows.len())?
    {
        return Err(VerificationError::Binding("runtime material range".into()));
    }

    let manifest = &checkpoint.availability_manifest;
    if manifest.schema_version != "ioi.runtime-availability-manifest.v1"
        || manifest.retention_class != "durable_local"
        || manifest.failure_behavior != "fail_closed"
        || manifest.payloads.len() != 1
        || bundle.availability_payloads.len() != 1
    {
        return Err(VerificationError::Binding(
            "runtime availability contract".into(),
        ));
    }
    require_nonempty(&manifest.manifest_id, "availability manifest id")?;
    let expected_manifest_hash = hash_value(&without(
        &json_value(manifest, "runtime availability JSON")?,
        &["manifest_hash"],
    )?)?;
    check_eq(
        &expected_manifest_hash,
        &manifest.manifest_hash,
        "runtime manifest hash",
    )?;
    check_eq(
        &expected_manifest_hash,
        &checkpoint.availability_manifest_hash,
        "runtime checkpoint manifest hash",
    )?;
    let declaration = &manifest.payloads[0];
    let supplied = &bundle.availability_payloads[0];
    for (field, value) in [
        ("payload_ref", declaration.payload_ref.as_str()),
        ("location_ref", declaration.location_ref.as_str()),
        (
            "failure_domain_ref",
            declaration.failure_domain_ref.as_str(),
        ),
    ] {
        require_nonempty(value, field)?;
    }
    require_hash(&declaration.payload_hash, "runtime payload hash")?;
    if declaration.payload_ref != supplied.payload_ref {
        return Err(VerificationError::Binding("runtime payload ref".into()));
    }
    let full_block_bytes = BASE64
        .decode(&supplied.payload_base64)
        .map_err(|error| VerificationError::Field(error.to_string()))?;
    if declaration.byte_length != full_block_bytes.len() as u64
        || declaration.payload_hash != hash_bytes(&full_block_bytes)
    {
        return Err(VerificationError::Binding("runtime payload bytes".into()));
    }
    let block: Block<ChainTransaction> = from_bytes_canonical(&full_block_bytes)
        .map_err(|error| VerificationError::Field(format!("runtime block: {error}")))?;
    if block.header.height == 0 {
        return Err(VerificationError::Binding(
            "runtime effects cannot occupy the genesis block".into(),
        ));
    }
    for (field, value) in [
        ("block height", block.header.height),
        ("block view", block.header.view),
        ("block gas_used", block.header.gas_used),
        ("operation range first", checkpoint.operation_range.first),
        ("operation range last", checkpoint.operation_range.last),
        ("receipt range first", checkpoint.receipt_range.first),
        ("receipt range last", checkpoint.receipt_range.last),
    ] {
        safe_u64(value, field)?;
    }
    let transaction_root = canonical_transactions_root(&block.transactions)
        .map_err(|error| VerificationError::Binding(error.to_string()))?;
    if transaction_root != block.header.transactions_root {
        return Err(VerificationError::Binding(
            "runtime block transaction root".into(),
        ));
    }
    let block_hash: [u8; 32] = block
        .header
        .hash()
        .map_err(|error| VerificationError::Field(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| VerificationError::Field("runtime block hash".into()))?;
    if checkpoint.previous_canonical_head != hash_prefixed(&block.header.parent_hash)
        || checkpoint.resulting_canonical_head != hash_prefixed(&block_hash)
    {
        return Err(VerificationError::Binding(
            "runtime canonical block heads".into(),
        ));
    }
    for (commitment, expected_height, expected_root) in [
        (
            &checkpoint.previous_state_commitment,
            block.header.height.saturating_sub(1),
            block.header.parent_state_root.as_ref(),
        ),
        (
            &checkpoint.resulting_state_commitment,
            block.header.height,
            block.header.state_root.as_ref(),
        ),
    ] {
        if commitment.algorithm != "ioi.native-block-state-root.v1"
            || commitment.height != expected_height
            || commitment.root_hash != hash_bytes(expected_root)
            || BASE64.decode(&commitment.root_base64).ok().as_deref() != Some(expected_root)
        {
            return Err(VerificationError::Binding("runtime state root".into()));
        }
    }

    let mut bindings = Vec::with_capacity(bundle.operations.len());
    for (index, (operation, transaction)) in bundle
        .operations
        .iter()
        .zip(block.transactions.iter())
        .enumerate()
    {
        safe_u64(operation.sequence, "operation sequence")?;
        let expected_sequence = checkpoint
            .operation_range
            .first
            .checked_add(index as u64)
            .ok_or_else(|| VerificationError::Binding("operation sequence overflow".into()))?;
        let transaction_bytes = BASE64
            .decode(
                operation
                    .body
                    .get("transaction_base64")
                    .and_then(Value::as_str)
                    .ok_or_else(|| VerificationError::Field("transaction_base64".into()))?,
            )
            .map_err(|error| VerificationError::Field(error.to_string()))?;
        let tx_hash = transaction
            .hash()
            .map_err(|error| VerificationError::Field(error.to_string()))?;
        let expected_body = json!({
            "transaction_index": index as u64,
            "transaction_hash": hash_prefixed(&tx_hash),
            "transaction_base64": BASE64.encode(
                to_bytes_canonical(transaction).map_err(VerificationError::Field)?
            ),
        });
        if operation.sequence != expected_sequence
            || operation.body != expected_body
            || transaction_bytes
                != to_bytes_canonical(transaction).map_err(VerificationError::Field)?
        {
            return Err(VerificationError::Binding(format!(
                "runtime operation {index}"
            )));
        }
        bindings.push(NativeAftOperationBinding {
            operation_sequence: operation.sequence,
            transaction_index: index as u64,
            transaction_bytes,
        });
    }
    if bindings.len() != block.transactions.len() {
        return Err(VerificationError::Binding(
            "runtime operation coverage".into(),
        ));
    }
    let mut receipt_gas = 0_u64;
    for (index, (receipt, transaction)) in bundle
        .receipts
        .iter()
        .zip(block.transactions.iter())
        .enumerate()
    {
        safe_u64(receipt.sequence, "receipt sequence")?;
        let expected_sequence = checkpoint
            .receipt_range
            .first
            .checked_add(index as u64)
            .ok_or_else(|| VerificationError::Binding("receipt sequence overflow".into()))?;
        let tx_hash = transaction
            .hash()
            .map_err(|error| VerificationError::Field(error.to_string()))?;
        let receipt_body = object(&receipt.body)?;
        let gas = receipt_body
            .get("gas_used")
            .and_then(Value::as_u64)
            .ok_or_else(|| VerificationError::Field("receipt gas_used".into()))?;
        safe_u64(gas, "receipt gas_used")?;
        receipt_gas = receipt_gas
            .checked_add(gas)
            .ok_or_else(|| VerificationError::Binding("receipt gas overflow".into()))?;
        let proof_hash = receipt_body
            .get("proof_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| VerificationError::Field("receipt proof_hash".into()))?;
        require_hash(proof_hash, "receipt proof_hash")?;
        if receipt.sequence != expected_sequence
            || receipt_body.len() != 10
            || receipt_body.get("schema").and_then(Value::as_str)
                != Some("ioi.block-execution-receipt")
            || receipt_body.get("version").and_then(Value::as_u64) != Some(1)
            || receipt_body.get("domain").and_then(Value::as_str)
                != Some(BLOCK_EXECUTION_RECEIPT_DOMAIN)
            || receipt_body.get("block_height").and_then(Value::as_u64) != Some(block.header.height)
            || receipt_body
                .get("transaction_index")
                .and_then(Value::as_u64)
                != Some(index as u64)
            || receipt_body.get("transaction_hash").and_then(Value::as_str)
                != Some(hash_prefixed(&tx_hash).as_str())
            || receipt_body.get("outcome").and_then(Value::as_str) != Some("success")
            || receipt_body
                .get("proof_present")
                .and_then(Value::as_bool)
                .is_none()
        {
            return Err(VerificationError::Binding(format!(
                "runtime receipt {index}"
            )));
        }
    }
    if bundle.receipts.len() != block.transactions.len() || receipt_gas != block.header.gas_used {
        return Err(VerificationError::Binding(
            "runtime receipt coverage/gas".into(),
        ));
    }

    let (native_quorum_verified, effect_committed_in_block) =
        match (profile, certificate.native_aft_evidence.as_ref()) {
            (RuntimeFinalityProfile::BftConsensusAftV1, Some(evidence)) => {
                let finalized = verify_native_quorum_v2(evidence, &block.header)?;
                let effect = verify_native_aft_full_block_effects(
                    &finalized,
                    &full_block_bytes,
                    &bindings,
                    block.header.parent_state_root.as_ref(),
                    block.header.state_root.as_ref(),
                )?;
                (true, effect.effect_committed_in_block)
            }
            (RuntimeFinalityProfile::BftConsensusAftV1, None) => {
                return Err(refuse_evidence(
                    "runtime BFT certificate has no native quorum",
                ))
            }
            (RuntimeFinalityProfile::SingleAuthorityV1, None) => (false, true),
            (RuntimeFinalityProfile::SingleAuthorityV1, Some(_)) => {
                return Err(refuse_evidence(
                    "single authority carries native quorum evidence",
                ))
            }
        };

    Ok(VerifiedRuntimeClaimV3 {
        checkpoint_id: checkpoint.checkpoint_id.clone(),
        domain_id: checkpoint.domain_id.clone(),
        authority_epoch: checkpoint.authority_epoch,
        authority_revocation_epoch: checkpoint.authority_revocation_epoch,
        profile: checkpoint.profile.clone(),
        certificate_variant: certificate.certificate_variant.clone(),
        profile_epoch: checkpoint.writer_fence.profile_epoch,
        writer_identity: checkpoint.writer_fence.writer_identity.clone(),
        fence_token: checkpoint.writer_fence.fence_token,
        previous_canonical_head: checkpoint.previous_canonical_head.clone(),
        resulting_canonical_head: checkpoint.resulting_canonical_head.clone(),
        operation_count: bundle.operations.len() as u64,
        receipt_count: bundle.receipts.len() as u64,
        native_quorum_verified,
        effect_committed_in_block,
        receipts_committed_in_block: false,
        established_axes: bundle.requested_axes,
    })
}
