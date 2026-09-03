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
    pub signature_suite: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHashAsyncEvidenceV1 {
    pub schema_version: String,
    pub consensus_protocol_ref: String,
    pub membership_ref: String,
    pub membership_epoch: u64,
    pub fault_model: String,
    pub synchrony_model: String,
    /// This profile has no private threshold setup or DKG. Membership
    /// enrollment and authenticated-channel provisioning remain explicit
    /// assumptions and are deliberately not described as "no setup".
    pub private_threshold_setup: bool,
    pub membership_enrollment_required: bool,
    pub private_authenticated_channels_required: bool,
    pub pq_authenticated_channels_required: bool,
    pub post_quantum: bool,
    /// Canonical terminal virtual-block header. For a parent catch-up receipt,
    /// this proves the subject is the exact high-QC ancestor extended by the
    /// asynchronous decision rather than silently relabeling it as native QC
    /// finality.
    pub terminal_block_header_base64: String,
    pub certificate_base64: String,
    pub witness_base64: String,
    pub validator_set_base64: String,
    /// Complete membership in exact member-index order.
    pub members: Vec<RuntimeAftMemberV2>,
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
    /// Requirements, achieved evidence meet, and transform trace are distinct.
    pub assurance: RuntimeAssuranceV1,
    pub verifier_contract_ref: String,
    pub verifier_contract_hash: String,
    pub issuer_key_id: String,
    pub issuer_public_key: String,
    pub body_hash: String,
    pub signature_suite: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_aft_evidence: Option<RuntimeNativeAftEvidenceV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_async_evidence: Option<RuntimeHashAsyncEvidenceV1>,
}

/// Coordinate-wise assurance carried by the runtime certificate. The verifier
/// recomputes this object from the embedded evidence before policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceV1 {
    /// Assurance-envelope version.
    pub schema_version: String,
    /// Policy requirements evaluated by the issuer and verifier.
    pub requirements: GuaranteeRequirementsV1,
    /// Certificate-derived evidence meet, never a caller-selected vector.
    pub achieved: GuaranteeVectorV1,
    /// Domain-separated canonical commitment to `achieved`.
    pub achieved_commitment: String,
    /// Independently verified coordinate transformations; empty in M4.
    pub transformations: Vec<GuaranteeTransformV1>,
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
    pub hash_async: Option<&'a NativeAftHashAsyncFinalizedBlock>,
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
    /// Coordinate-wise assurance recomputed from the embedded evidence.
    pub assurance: GuaranteeVectorV1,
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
    let block_hash: [u8; 32] = input
        .block
        .header
        .hash()
        .map_err(|error| VerificationError::Field(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| VerificationError::Field("runtime block hash".into()))?;
    let block_operation = json!({
        "schema": "ioi.runtime-block-transition-operation.v1",
        "height": input.block.header.height,
        "view": input.block.header.view,
        "previous_canonical_head": hash_prefixed(&input.block.header.parent_hash),
        "resulting_canonical_head": hash_prefixed(&block_hash),
        "previous_state_root": hash_bytes(input.block.header.parent_state_root.as_ref()),
        "resulting_state_root": hash_bytes(input.block.header.state_root.as_ref()),
        "transaction_count": input.block.transactions.len() as u64,
    });
    let block_receipt = json!({
        "schema": "ioi.runtime-block-transition-receipt.v1",
        "height": input.block.header.height,
        "resulting_canonical_head": hash_prefixed(&block_hash),
        "resulting_state_root": hash_bytes(input.block.header.state_root.as_ref()),
        "transaction_count": input.block.transactions.len() as u64,
        "execution_gas_accounted_by_individual_receipts": input.block.header.gas_used,
        "outcome": "success",
    });
    let mut operations = Vec::with_capacity(input.block.transactions.len() + 1);
    operations.push(RuntimeMaterialV3 {
        sequence: input.operation_sequence_first,
        body_hash: hash_value(&block_operation)?,
        body: block_operation,
    });
    let mut receipts = Vec::with_capacity(input.receipts.len() + 1);
    receipts.push(RuntimeMaterialV3 {
        sequence: input.receipt_sequence_first,
        body_hash: hash_value(&block_receipt)?,
        body: block_receipt,
    });
    for (index, (transaction, receipt)) in input
        .block
        .transactions
        .iter()
        .zip(input.receipts.iter())
        .enumerate()
    {
        let operation_sequence = input
            .operation_sequence_first
            .checked_add(index as u64 + 1)
            .ok_or_else(|| VerificationError::Field("operation sequence overflow".into()))?;
        let receipt_sequence = input
            .receipt_sequence_first
            .checked_add(index as u64 + 1)
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
        let signature_suite = native_signature_suite_name(member.signature_suite)?;
        let account = account_id_from_key_material(member.signature_suite, &member.public_key)
            .map_err(|error| refuse_evidence(format!("member account id: {error}")))?;
        if by_account
            .insert(account, member.member_ref.clone())
            .is_some()
        {
            return Err(refuse_evidence("duplicate member account id"));
        }
        members.push(RuntimeAftMemberV2 {
            member_ref: member.member_ref.clone(),
            signature_suite: signature_suite.into(),
            public_key: hex::encode(&member.public_key),
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

fn hash_async_evidence_v1(
    finalized: &NativeAftHashAsyncFinalizedBlock,
) -> Result<RuntimeHashAsyncEvidenceV1, VerificationError> {
    finalized
        .certificate
        .validate_with_witness(&finalized.witness)
        .map_err(refuse_evidence)?;
    let instance = &finalized.certificate.decision.instance;
    if finalized.members.len() != instance.geometry.n as usize
        || finalized.membership_epoch != instance.scope.epoch
    {
        return Err(refuse_evidence(
            "hash-async membership cardinality or epoch",
        ));
    }
    let members = finalized
        .members
        .iter()
        .map(|member| {
            Ok(RuntimeAftMemberV2 {
                member_ref: member.member_ref.clone(),
                signature_suite: native_signature_suite_name(member.signature_suite)?.into(),
                public_key: hex::encode(&member.public_key),
            })
        })
        .collect::<Result<Vec<_>, VerificationError>>()?;
    Ok(RuntimeHashAsyncEvidenceV1 {
        schema_version: "ioi.native-aft-hash-async-evidence.v1".into(),
        consensus_protocol_ref: "protocol://ioi/aft/hash-async/v1".into(),
        membership_ref: finalized.membership_ref.clone(),
        membership_epoch: finalized.membership_epoch,
        fault_model: "static_byzantine_f_lt_n_over_3".into(),
        synchrony_model: "asynchronous_randomized_termination".into(),
        private_threshold_setup: false,
        membership_enrollment_required: true,
        private_authenticated_channels_required: true,
        pq_authenticated_channels_required: true,
        post_quantum: true,
        terminal_block_header_base64: BASE64.encode(&finalized.terminal_block_header_bytes),
        certificate_base64: BASE64
            .encode(to_bytes_canonical(&finalized.certificate).map_err(VerificationError::Field)?),
        witness_base64: BASE64
            .encode(to_bytes_canonical(&finalized.witness).map_err(VerificationError::Field)?),
        validator_set_base64: BASE64.encode(
            to_bytes_canonical(&finalized.validator_set).map_err(VerificationError::Field)?,
        ),
        members,
    })
}

fn parse_sha256_array(value: &str, field: &str) -> Result<[u8; 32], VerificationError> {
    require_hash(value, field)?;
    let decoded = hex::decode(&value[7..])
        .map_err(|error| VerificationError::Field(format!("{field}: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| VerificationError::Field(field.into()))
}

fn runtime_assurance_v1(
    native: Option<&RuntimeNativeAftEvidenceV2>,
    hash_async: Option<&RuntimeHashAsyncEvidenceV1>,
    domain_id: &str,
    availability_manifest_hash: &str,
) -> Result<RuntimeAssuranceV1, VerificationError> {
    let domain_hash = conflict_domain_id_commitment(domain_id)
        .map_err(|error| VerificationError::Field(error.to_string()))?;
    let availability_hash =
        parse_sha256_array(availability_manifest_hash, "availability_manifest_hash")?;
    let mut vector = match (native, hash_async) {
        (Some(evidence), None) => {
            let all_pq = !evidence.members.is_empty()
                && evidence
                    .members
                    .iter()
                    .all(|member| member.signature_suite == "ml-dsa-44");
            let profile = if all_pq {
                CertificateProfile::PqLiveQuorumCert
            } else {
                CertificateProfile::ClassicalSignedLiveQuorumCert
            };
            let mut vector = guarantee_vector_of(profile);
            let n = u32::try_from(evidence.total_voting_members)
                .map_err(|_| VerificationError::Field("assurance committee_n".into()))?;
            let f = u32::try_from(evidence.byzantine_fault_tolerance)
                .map_err(|_| VerificationError::Field("assurance fault_bound_f".into()))?;
            let q = u32::try_from(evidence.quorum_threshold)
                .map_err(|_| VerificationError::Field("assurance quorum_q".into()))?;
            vector.safety.model = SafetyModelV1::QuorumIntersectionBft;
            vector.safety.committee_n = Some(n);
            vector.safety.fault_bound_f = Some(f);
            vector.safety.quorum_q = Some(q);
            vector.safety.configuration_hash = Some(parse_sha256_array(
                &evidence.membership_hash,
                "native membership_hash",
            )?);
            vector.safety.conflict_domain_hash = Some(domain_hash);
            vector.liveness.adversary = AdversaryModelV1::StaticByzantine;
            vector.liveness.committee_n = Some(n);
            vector.liveness.fault_bound_f = Some(f);
            vector.crypto.consensus_pq = all_pq;
            vector.crypto.channel_pq = false;
            vector.crypto.externalization_pq = false;
            vector.crypto.end_to_end_pq = false;
            vector.crypto.primitive_suites = BTreeSet::from([
                PrimitiveSuiteV1::Sha256,
                if all_pq {
                    PrimitiveSuiteV1::MlDsa44
                } else {
                    PrimitiveSuiteV1::Ed25519
                },
                PrimitiveSuiteV1::Unresolved,
            ]);
            vector.constituent_hashes.insert(parse_sha256_array(
                &hash_value(&json_value(evidence, "native assurance evidence")?)?,
                "native assurance evidence hash",
            )?);
            vector
        }
        (None, Some(evidence)) => {
            let certificate_bytes = BASE64
                .decode(&evidence.certificate_base64)
                .map_err(|error| VerificationError::Field(error.to_string()))?;
            let certificate: AftAsyncExecutedBlockCertificateV1 =
                from_bytes_canonical(&certificate_bytes)
                    .map_err(|error| VerificationError::Field(error.to_string()))?;
            let instance = &certificate.decision.instance;
            let mut vector = guarantee_vector_of(CertificateProfile::HashAsyncOrderingCert);
            vector.safety.model = SafetyModelV1::QuorumIntersectionBft;
            vector.safety.committee_n = Some(instance.geometry.n.into());
            vector.safety.fault_bound_f = Some(instance.geometry.f.into());
            vector.safety.quorum_q = Some(instance.geometry.quorum.into());
            vector.safety.configuration_hash = Some(instance.scope.configuration_hash);
            vector.safety.conflict_domain_hash = Some(domain_hash);
            vector.liveness = LivenessCoordinateV1 {
                termination: TerminationV1::RandomizedAsynchronous,
                network: NetworkAssumptionV1::AsynchronousPrivateAuthenticatedChannels,
                adversary: AdversaryModelV1::StaticByzantine,
                committee_n: Some(instance.geometry.n.into()),
                fault_bound_f: Some(instance.geometry.f.into()),
                private_authenticated_channels: true,
            };
            vector.crypto.consensus_pq = evidence.post_quantum;
            // The receipt carries the channel requirement but not a channel
            // transcript proof, so M4 deliberately leaves this coordinate false.
            vector.crypto.channel_pq = false;
            vector.crypto.externalization_pq = false;
            vector.crypto.end_to_end_pq = false;
            vector.crypto.private_threshold_setup = evidence.private_threshold_setup;
            vector.crypto.primitive_suites = BTreeSet::from([
                PrimitiveSuiteV1::Sha256,
                PrimitiveSuiteV1::MlDsa44,
                PrimitiveSuiteV1::PqAuthenticatedChannel,
                PrimitiveSuiteV1::Unresolved,
            ]);
            vector.availability.custody_threshold = Some(instance.geometry.quorum.into());
            vector.constituent_hashes.insert(parse_sha256_array(
                &hash_value(&json_value(evidence, "hash-async assurance evidence")?)?,
                "hash-async assurance evidence hash",
            )?);
            vector
        }
        (None, None) => guarantee_vector_of(CertificateProfile::HashPcdReference),
        (Some(_), Some(_)) => {
            return Err(refuse_evidence(
                "runtime assurance refuses multiple finality variants",
            ))
        }
    };
    vector.accountability = match (native, hash_async) {
        (Some(_), None) | (None, Some(_)) => AccountabilityV1::Transferable,
        _ => AccountabilityV1::None,
    };
    vector.availability = AvailabilityCoordinateV1 {
        publication_retrievable: true,
        custody_threshold: vector.availability.custody_threshold.or(Some(1)),
        retention_horizon: None,
    };
    vector.externalization = ExternalizationCoordinateV1 {
        mode: ExternalizationModeV1::NotClaimed,
        at_most_once: false,
        adapter_profile_hash: None,
    };
    vector.constituent_hashes.insert(availability_hash);
    vector.theorem_ids.insert("T6".into());
    vector.validate().map_err(|error| {
        VerificationError::Binding(format!("runtime assurance vector: {error}"))
    })?;

    let requirements = GuaranteeRequirementsV1 {
        minimum_finality_rank: vector.safety.finality_rank,
        configuration_hash: vector.safety.configuration_hash,
        conflict_domain_hash: vector.safety.conflict_domain_hash,
        require_consensus_pq: vector.crypto.consensus_pq,
        require_no_private_threshold_setup: !vector.crypto.private_threshold_setup,
        require_publication_retrievable: true,
        ..Default::default()
    };
    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[vector.clone()])
        .map_err(|error| VerificationError::Binding(format!("runtime assurance meet: {error}")))?;
    if !requirements.is_satisfied_by(&verified) {
        return Err(refuse_evidence(
            "runtime assurance does not satisfy its own requirements",
        ));
    }
    let achieved = verified.into_achieved();
    let achieved_commitment = format!(
        "sha256:{}",
        hex::encode(achieved.commitment().map_err(|error| {
            VerificationError::Binding(format!("runtime assurance commitment: {error}"))
        })?)
    );
    Ok(RuntimeAssuranceV1 {
        schema_version: "ioi.runtime-assurance.v1".into(),
        requirements,
        achieved,
        achieved_commitment,
        transformations: Vec::new(),
    })
}

fn verify_hash_async_subject_relation(
    finalized: &NativeAftHashAsyncFinalizedBlock,
    subject: &Block<ChainTransaction>,
) -> Result<(), VerificationError> {
    let subject_header_bytes =
        to_bytes_canonical(&subject.header).map_err(VerificationError::Field)?;
    if subject_header_bytes != finalized.block_header_bytes {
        return Err(refuse_evidence(
            "hash-async receipt subject header differs from the admitted block",
        ));
    }
    let terminal_header: BlockHeader = from_bytes_canonical(&finalized.terminal_block_header_bytes)
        .map_err(|error| {
            VerificationError::Field(format!("hash-async terminal header: {error}"))
        })?;
    let terminal_header_bytes =
        to_bytes_canonical(&terminal_header).map_err(VerificationError::Field)?;
    if terminal_header_bytes != finalized.terminal_block_header_bytes {
        return Err(refuse_evidence(
            "hash-async terminal header is not canonically encoded",
        ));
    }
    let subject_hash: [u8; 32] = subject
        .header
        .hash()
        .map_err(|error| VerificationError::Field(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| VerificationError::Field("hash-async subject hash".into()))?;
    let terminal_hash: [u8; 32] = terminal_header
        .hash()
        .map_err(|error| VerificationError::Field(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| VerificationError::Field("hash-async terminal hash".into()))?;
    let instance = &finalized.certificate.decision.instance;
    if terminal_hash != finalized.certificate.decision.block_hash
        || terminal_header.height != instance.height
    {
        return Err(refuse_evidence(
            "hash-async terminal header is not the certified decision block",
        ));
    }
    if subject_hash == terminal_hash {
        if subject.header != terminal_header {
            return Err(refuse_evidence(
                "hash-async terminal subject does not equal its certified header",
            ));
        }
        return Ok(());
    }
    if subject.header.height.saturating_add(1) != terminal_header.height
        || terminal_header.parent_hash != subject_hash
        || instance.fallback_start.highest_qc.height != subject.header.height
        || instance.fallback_start.highest_qc.block_hash != subject_hash
    {
        return Err(refuse_evidence(
            "hash-async parent subject is not the certified terminal block's direct high-QC ancestor",
        ));
    }
    Ok(())
}

/// Emit and self-verify an explicit v3 runtime bundle.
pub fn emit_runtime_bundle_v3(
    input: RuntimeBundleV3Input<'_>,
    signing_key: &Ed25519PrivateKey,
) -> Result<Value, VerificationError> {
    let public_key = signing_key
        .public_key()
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    emit_runtime_bundle_v3_with_signer(input, public_key.to_bytes(), "ed25519", |message| {
        signing_key
            .sign(message)
            .map(|signature| signature.to_bytes().to_vec())
            .map_err(|error| VerificationError::Crypto(error.to_string()))
    })
}

/// PQ issuer variant for the normative AFT receipt path. The embedded
/// consensus evidence is unchanged; only the source-neutral checkpoint issuer
/// signature changes from Ed25519 to ML-DSA-44.
pub fn emit_runtime_bundle_v3_pq(
    input: RuntimeBundleV3Input<'_>,
    signing_key: &MldsaKeyPair,
) -> Result<Value, VerificationError> {
    emit_runtime_bundle_v3_with_signer(
        input,
        signing_key.public_key().to_bytes(),
        "ml-dsa-44",
        |message| {
            signing_key
                .private_key()
                .sign(message)
                .map(|signature| signature.to_bytes())
                .map_err(|error| VerificationError::Crypto(error.to_string()))
        },
    )
}

fn emit_runtime_bundle_v3_with_signer<F>(
    input: RuntimeBundleV3Input<'_>,
    issuer_public_key: Vec<u8>,
    issuer_signature_suite: &str,
    sign: F,
) -> Result<Value, VerificationError>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, VerificationError>,
{
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

    let (native_aft_evidence, hash_async_evidence) =
        match (input.profile, input.native_aft, input.hash_async) {
            (RuntimeFinalityProfile::BftConsensusAftV1, Some(finalized), None) => {
                let header_bytes =
                    to_bytes_canonical(&input.block.header).map_err(VerificationError::Field)?;
                if header_bytes != finalized.block_header_bytes
                    || finalized.quorum_certificate.block_hash != block_hash
                {
                    return Err(refuse_evidence(
                        "runtime block is not the block named by native AFT finality",
                    ));
                }
                (Some(native_evidence_v2(finalized)?), None)
            }
            (RuntimeFinalityProfile::BftConsensusAftV1, None, Some(finalized)) => {
                verify_hash_async_subject_relation(finalized, input.block)?;
                (None, Some(hash_async_evidence_v1(finalized)?))
            }
            (RuntimeFinalityProfile::BftConsensusAftV1, None, None) => {
                return Err(refuse_evidence(
                    "bft runtime bundle has no native AFT quorum",
                ))
            }
            (RuntimeFinalityProfile::BftConsensusAftV1, Some(_), Some(_)) => {
                return Err(refuse_evidence(
                    "bft runtime bundle carries two finality variants",
                ))
            }
            (RuntimeFinalityProfile::SingleAuthorityV1, None, None) => (None, None),
            (RuntimeFinalityProfile::SingleAuthorityV1, _, _) => {
                return Err(refuse_evidence(
                    "single-authority runtime bundle must not carry peer quorum evidence",
                ))
            }
        };
    let profile = input.profile.canonical_member().to_owned();
    let variant = input.profile.certificate_variant().to_owned();
    let verifier_contract_ref = format!(
        "verifier-contract://ioi/runtime-receipt-proof-v3/{}",
        input.profile.certificate_variant()
    );
    let assurance = runtime_assurance_v1(
        native_aft_evidence.as_ref(),
        hash_async_evidence.as_ref(),
        input.domain_id,
        &availability_manifest.manifest_hash,
    )?;
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
        assurance,
        verifier_contract_ref: verifier_contract_ref.clone(),
        verifier_contract_hash: input.verifier_contract_hash.into(),
        issuer_key_id: input.issuer_key_id.into(),
        issuer_public_key: hex::encode(&issuer_public_key),
        body_hash: String::new(),
        signature_suite: issuer_signature_suite.into(),
        signature: String::new(),
        native_aft_evidence,
        hash_async_evidence,
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
    certificate.signature = hex::encode(sign(message.as_bytes())?);
    checkpoint.finality_certificate = certificate;
    let trusted_issuer = RuntimeTrustedIssuerV1 {
        issuer_key_id: input.issuer_key_id.into(),
        issuer_public_key: hex::encode(&issuer_public_key),
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
        let suite = native_signature_suite(&member.signature_suite)?;
        let key = hex::decode(&member.public_key)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        if !keys.insert((suite, key.clone())) {
            return Err(refuse_evidence("duplicate native AFT public key"));
        }
        let account = account_id_from_key_material(suite, &key)
            .map_err(|error| refuse_evidence(format!("member account id: {error}")))?;
        if !accounts.insert(account)
            || by_ref
                .insert(member.member_ref.clone(), (suite, key.clone(), account))
                .is_some()
        {
            return Err(refuse_evidence("duplicate native AFT member"));
        }
        native_members.push(NativeAftMember {
            member_ref: member.member_ref.clone(),
            signature_suite: suite,
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
        let (suite, key, account) = by_ref
            .get(&vote.member_ref)
            .ok_or_else(|| refuse_evidence("vote from undeclared member"))?;
        if !voted.insert(vote.member_ref.clone()) || vote.account_id != hex::encode(account) {
            return Err(refuse_evidence("duplicate or reassigned native AFT vote"));
        }
        let signature_bytes = hex::decode(&vote.signature)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        verify_native_signature(*suite, key, &message, &signature_bytes)
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

fn verify_hash_async_qc(
    qc: &QuorumCertificate,
    members: &[(SignatureSuite, Vec<u8>, ioi_types::app::AccountId)],
    quorum: usize,
) -> Result<(), VerificationError> {
    if qc.height == 0 {
        return if qc == &QuorumCertificate::default() {
            Ok(())
        } else {
            Err(refuse_evidence("non-canonical hash-async genesis QC"))
        };
    }
    if !qc.aggregated_signature.is_empty() || !qc.signers_bitfield.is_empty() {
        return Err(refuse_evidence(
            "hash-async safe-state QC uses an unsupported aggregate signature",
        ));
    }
    if qc.signatures.len() < quorum {
        return Err(refuse_evidence(format!(
            "hash-async safe-state QC has {} signatures below q={quorum}",
            qc.signatures.len()
        )));
    }
    let message = native_aft_vote_message(qc.height, qc.view, &qc.block_hash)?;
    let mut seen = BTreeSet::new();
    for (account, signature) in &qc.signatures {
        if !seen.insert(*account) {
            return Err(refuse_evidence("hash-async safe-state QC repeats a signer"));
        }
        let (suite, key, _) = members
            .iter()
            .find(|(_, _, member)| member == account)
            .ok_or_else(|| refuse_evidence("hash-async safe-state QC signer is not enrolled"))?;
        verify_native_signature(*suite, key, &message, signature)?;
    }
    Ok(())
}

fn verify_hash_async_fallback_start(
    instance: &ioi_types::app::AftAsyncInstanceV1,
    members: &[(SignatureSuite, Vec<u8>, ioi_types::app::AccountId)],
) -> Result<(), VerificationError> {
    let quorum = instance.geometry.quorum as usize;
    let start = &instance.fallback_start;
    for timeout in &start.trigger_certificate.consecutive_timeout_certificates {
        if timeout.votes.len() < quorum {
            return Err(refuse_evidence(format!(
                "hash-async timeout certificate for view {} has {} votes below q={quorum}",
                timeout.view,
                timeout.votes.len()
            )));
        }
        for vote in &timeout.votes {
            let (suite, key, _) = members
                .iter()
                .find(|(_, _, member)| member == &vote.voter)
                .ok_or_else(|| refuse_evidence("hash-async timeout voter is not enrolled"))?;
            let message = vote.signing_bytes().map_err(VerificationError::Field)?;
            verify_native_signature(*suite, key, &message, &vote.signature)?;
            verify_hash_async_qc(&vote.highest_qc, members, quorum)?;
            verify_hash_async_qc(&vote.locked_qc, members, quorum)?;
        }
    }
    verify_hash_async_qc(&start.highest_qc, members, quorum)?;
    verify_hash_async_qc(&start.locked_qc, members, quorum)?;
    Ok(())
}

fn verify_hash_async_evidence_v1(
    evidence: &RuntimeHashAsyncEvidenceV1,
    block: &Block<ChainTransaction>,
) -> Result<(), VerificationError> {
    if evidence.schema_version != "ioi.native-aft-hash-async-evidence.v1"
        || evidence.consensus_protocol_ref != "protocol://ioi/aft/hash-async/v1"
        || evidence.fault_model != "static_byzantine_f_lt_n_over_3"
        || evidence.synchrony_model != "asynchronous_randomized_termination"
        || evidence.private_threshold_setup
        || !evidence.membership_enrollment_required
        || !evidence.private_authenticated_channels_required
        || !evidence.pq_authenticated_channels_required
        || !evidence.post_quantum
    {
        return Err(refuse_evidence("hash-async evidence contract"));
    }
    let certificate_bytes = BASE64
        .decode(&evidence.certificate_base64)
        .map_err(|error| VerificationError::Field(error.to_string()))?;
    let witness_bytes = BASE64
        .decode(&evidence.witness_base64)
        .map_err(|error| VerificationError::Field(error.to_string()))?;
    let validator_set_bytes = BASE64
        .decode(&evidence.validator_set_base64)
        .map_err(|error| VerificationError::Field(error.to_string()))?;
    let terminal_header_bytes = BASE64
        .decode(&evidence.terminal_block_header_base64)
        .map_err(|error| VerificationError::Field(error.to_string()))?;
    let certificate: ioi_types::app::AftAsyncExecutedBlockCertificateV1 =
        from_bytes_canonical(&certificate_bytes).map_err(|error| {
            VerificationError::Field(format!("hash-async certificate: {error}"))
        })?;
    let witness: ioi_types::app::AftAsyncSelectedBatchWitnessV1 =
        from_bytes_canonical(&witness_bytes)
            .map_err(|error| VerificationError::Field(format!("hash-async witness: {error}")))?;
    let set: ValidatorSetV1 = from_bytes_canonical(&validator_set_bytes)
        .map_err(|error| VerificationError::Field(format!("hash-async validator set: {error}")))?;
    let terminal_header: BlockHeader =
        from_bytes_canonical(&terminal_header_bytes).map_err(|error| {
            VerificationError::Field(format!("hash-async terminal header: {error}"))
        })?;
    if to_bytes_canonical(&terminal_header).map_err(VerificationError::Field)?
        != terminal_header_bytes
    {
        return Err(refuse_evidence(
            "hash-async terminal header is not canonically encoded",
        ));
    }
    certificate
        .validate_with_witness(&witness)
        .map_err(refuse_evidence)?;
    let instance = &certificate.decision.instance;
    if evidence.membership_epoch != instance.scope.epoch
        || evidence.members.len() != instance.geometry.n as usize
    {
        return Err(refuse_evidence("hash-async membership geometry"));
    }

    let mut member_refs = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    let mut raw_members = Vec::with_capacity(evidence.members.len());
    let mut previous_account = None;
    if set.effective_from_height != evidence.membership_epoch
        || set.validators.len() != evidence.members.len()
        || set.total_weight != set.validators.len() as u128
    {
        return Err(refuse_evidence("hash-async validator-set geometry"));
    }
    for (member, validator) in evidence.members.iter().zip(&set.validators) {
        if !member_refs.insert(member.member_ref.clone()) {
            return Err(refuse_evidence("duplicate hash-async member reference"));
        }
        let suite = native_signature_suite(&member.signature_suite)?;
        if suite != SignatureSuite::ML_DSA_44 {
            return Err(refuse_evidence("hash-async member is not ML-DSA-44"));
        }
        let public_key = hex::decode(&member.public_key)
            .map_err(|error| VerificationError::Crypto(error.to_string()))?;
        let account = account_id_from_key_material(suite, &public_key)
            .map_err(|error| refuse_evidence(format!("hash-async member account: {error}")))?;
        if !accounts.insert(account) {
            return Err(refuse_evidence("duplicate hash-async member account"));
        }
        if previous_account.is_some_and(|previous| previous >= account) {
            return Err(refuse_evidence(
                "hash-async validator set is not canonically account-ordered",
            ));
        }
        previous_account = Some(account);
        if validator.account_id != ioi_types::app::AccountId(account)
            || validator.weight != 1
            || validator.consensus_key.suite != suite
            || validator.consensus_key.public_key_hash != account
            || validator.consensus_key.since_height > instance.height
        {
            return Err(refuse_evidence("hash-async validator key binding"));
        }
        raw_members.push((suite, public_key, ioi_types::app::AccountId(account)));
    }
    if canonical_validator_set_hash(&set).map_err(VerificationError::Field)?
        != instance.scope.configuration_hash
        || block.header.validator_set
            != set
                .validators
                .iter()
                .map(|member| member.account_id.0.to_vec())
                .collect::<Vec<_>>()
        || terminal_header.validator_set != block.header.validator_set
    {
        return Err(refuse_evidence("hash-async rooted membership binding"));
    }
    verify_hash_async_fallback_start(instance, &raw_members)?;
    let subject_hash: [u8; 32] = block
        .header
        .hash()
        .map_err(|error| VerificationError::Field(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| VerificationError::Field("hash-async block hash".into()))?;
    let terminal_hash: [u8; 32] = terminal_header
        .hash()
        .map_err(|error| VerificationError::Field(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| VerificationError::Field("hash-async terminal block hash".into()))?;
    let terminal_view = instance
        .fallback_start
        .trigger_certificate
        .consecutive_timeout_certificates
        .last()
        .map(|timeout| timeout.view.saturating_add(1))
        .ok_or_else(|| refuse_evidence("hash-async fallback terminal view"))?;
    let first = raw_members
        .first()
        .ok_or_else(|| refuse_evidence("hash-async empty membership"))?;
    if certificate.decision.block_hash != terminal_hash
        || instance.height != terminal_header.height
        || terminal_view != terminal_header.view
        || terminal_header.parent_qc
            != ioi_types::app::aft_async_canonical_qc_reference(&instance.fallback_start.highest_qc)
        || (terminal_header.height > 1
            && terminal_header.parent_hash != instance.fallback_start.highest_qc.block_hash)
        || terminal_header.producer_account_id != first.2
        || terminal_header.producer_key_suite != first.0
        || terminal_header.producer_pubkey != first.1
        || !terminal_header.signature.is_empty()
    {
        return Err(refuse_evidence("hash-async virtual block binding"));
    }

    let verify_indexed = |index: u16,
                          account: ioi_types::app::AccountId,
                          message: &[u8],
                          signature: &[u8]|
     -> Result<(), VerificationError> {
        let (suite, key, expected) = raw_members
            .get(index as usize)
            .ok_or_else(|| refuse_evidence("hash-async signer index"))?;
        if account != *expected {
            return Err(refuse_evidence("hash-async signer account/index"));
        }
        verify_native_signature(*suite, key, message, signature)
    };
    for selected in &witness.selected {
        let availability = &selected.availability_certificate;
        for vote in &availability.votes {
            let message = ioi_types::app::AftAsyncProposalAvailabilityVoteV1::signing_bytes(
                &availability.descriptor,
                vote.member_index,
                vote.voter,
            )
            .map_err(VerificationError::Field)?;
            verify_indexed(vote.member_index, vote.voter, &message, &vote.signature)?;
        }
    }
    for vote in &certificate.ordering.votes {
        let message = ioi_types::app::AftAsyncDecisionVoteV1::signing_bytes(
            &certificate.ordering.decision,
            vote.member_index,
            vote.voter,
        )
        .map_err(VerificationError::Field)?;
        verify_indexed(vote.member_index, vote.voter, &message, &vote.signature)?;
    }
    for vote in &certificate.votes {
        let message = ioi_types::app::AftAsyncExecutedBlockVoteV1::signing_bytes(
            &certificate.decision,
            vote.member_index,
            vote.voter,
        )
        .map_err(VerificationError::Field)?;
        verify_indexed(vote.member_index, vote.voter, &message, &vote.signature)?;
    }
    let selected = witness
        .canonical_transactions(&certificate.ordering)
        .map_err(refuse_evidence)?;
    if ioi_types::app::canonical_transactions_root(&selected).map_err(VerificationError::Field)?
        != terminal_header.transactions_root
    {
        return Err(refuse_evidence(
            "hash-async selected witness does not match the terminal transactions root",
        ));
    }
    if subject_hash == terminal_hash {
        if block.header != terminal_header
            || !hash_async_executed_batch_matches(&selected, &block.transactions)
        {
            return Err(refuse_evidence(
                "hash-async executed transactions differ from the complete ordered witness",
            ));
        }
    } else if block.header.height.saturating_add(1) != terminal_header.height
        || terminal_header.parent_hash != subject_hash
        || instance.fallback_start.highest_qc.height != block.header.height
        || instance.fallback_start.highest_qc.block_hash != subject_hash
    {
        return Err(refuse_evidence(
            "hash-async subject is not the certified terminal block or its direct high-QC parent",
        ));
    }
    Ok(())
}

pub(crate) fn hash_async_executed_batch_matches(
    selected: &[ChainTransaction],
    executed: &[ChainTransaction],
) -> bool {
    selected == executed
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
    {
        return Err(VerificationError::Binding("runtime trusted issuer".into()));
    }
    let public_bytes = hex::decode(&certificate.issuer_public_key)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let signature_bytes = hex::decode(&certificate.signature)
        .map_err(|error| VerificationError::Crypto(error.to_string()))?;
    let message = format!("{RUNTIME_CERTIFICATE_V2}\0{}", certificate.body_hash);
    match certificate.signature_suite.as_str() {
        "ed25519" => {
            let public = Ed25519PublicKey::from_bytes(&public_bytes)
                .map_err(|error| VerificationError::Crypto(error.to_string()))?;
            let signature = Ed25519Signature::from_bytes(&signature_bytes)
                .map_err(|error| VerificationError::Crypto(error.to_string()))?;
            public
                .verify(message.as_bytes(), &signature)
                .map_err(|_| VerificationError::Crypto("runtime certificate signature".into()))?;
        }
        "ml-dsa-44" => verify_native_signature(
            SignatureSuite::ML_DSA_44,
            &public_bytes,
            message.as_bytes(),
            &signature_bytes,
        )?,
        other => {
            return Err(refuse_evidence(format!(
                "unsupported runtime certificate signature suite {other}"
            )))
        }
    }

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

    let expected_block_operation = json!({
        "schema": "ioi.runtime-block-transition-operation.v1",
        "height": block.header.height,
        "view": block.header.view,
        "previous_canonical_head": hash_prefixed(&block.header.parent_hash),
        "resulting_canonical_head": hash_prefixed(&block_hash),
        "previous_state_root": hash_bytes(block.header.parent_state_root.as_ref()),
        "resulting_state_root": hash_bytes(block.header.state_root.as_ref()),
        "transaction_count": block.transactions.len() as u64,
    });
    let block_operation = bundle
        .operations
        .first()
        .ok_or_else(|| VerificationError::Binding("runtime block operation absent".into()))?;
    if block_operation.sequence != checkpoint.operation_range.first
        || block_operation.body != expected_block_operation
        || block_operation.body_hash != hash_value(&expected_block_operation)?
    {
        return Err(VerificationError::Binding(
            "runtime block transition operation".into(),
        ));
    }
    let expected_block_receipt = json!({
        "schema": "ioi.runtime-block-transition-receipt.v1",
        "height": block.header.height,
        "resulting_canonical_head": hash_prefixed(&block_hash),
        "resulting_state_root": hash_bytes(block.header.state_root.as_ref()),
        "transaction_count": block.transactions.len() as u64,
        "execution_gas_accounted_by_individual_receipts": block.header.gas_used,
        "outcome": "success",
    });
    let block_receipt = bundle
        .receipts
        .first()
        .ok_or_else(|| VerificationError::Binding("runtime block receipt absent".into()))?;
    if block_receipt.sequence != checkpoint.receipt_range.first
        || block_receipt.body != expected_block_receipt
        || block_receipt.body_hash != hash_value(&expected_block_receipt)?
    {
        return Err(VerificationError::Binding(
            "runtime block transition receipt".into(),
        ));
    }

    let mut bindings = Vec::with_capacity(block.transactions.len());
    for (index, (operation, transaction)) in bundle
        .operations
        .iter()
        .skip(1)
        .zip(block.transactions.iter())
        .enumerate()
    {
        safe_u64(operation.sequence, "operation sequence")?;
        let expected_sequence = checkpoint
            .operation_range
            .first
            .checked_add(index as u64 + 1)
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
    if bindings.len() != block.transactions.len()
        || bundle.operations.len() != block.transactions.len() + 1
    {
        return Err(VerificationError::Binding(
            "runtime operation coverage".into(),
        ));
    }
    let mut receipt_gas = 0_u64;
    for (index, (receipt, transaction)) in bundle
        .receipts
        .iter()
        .skip(1)
        .zip(block.transactions.iter())
        .enumerate()
    {
        safe_u64(receipt.sequence, "receipt sequence")?;
        let expected_sequence = checkpoint
            .receipt_range
            .first
            .checked_add(index as u64 + 1)
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
    if bundle.receipts.len() != block.transactions.len() + 1 || receipt_gas != block.header.gas_used
    {
        return Err(VerificationError::Binding(
            "runtime receipt coverage/gas".into(),
        ));
    }

    let (native_quorum_verified, effect_committed_in_block) = match (
        profile,
        certificate.native_aft_evidence.as_ref(),
        certificate.hash_async_evidence.as_ref(),
    ) {
        (RuntimeFinalityProfile::BftConsensusAftV1, Some(evidence), None) => {
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
        (RuntimeFinalityProfile::BftConsensusAftV1, None, Some(evidence)) => {
            verify_hash_async_evidence_v1(evidence, &block)?;
            (true, true)
        }
        (RuntimeFinalityProfile::BftConsensusAftV1, None, None) => {
            return Err(refuse_evidence(
                "runtime BFT certificate has no native quorum",
            ))
        }
        (RuntimeFinalityProfile::BftConsensusAftV1, Some(_), Some(_)) => {
            return Err(refuse_evidence(
                "runtime BFT certificate carries two quorum variants",
            ))
        }
        (RuntimeFinalityProfile::SingleAuthorityV1, None, None) => (false, true),
        (RuntimeFinalityProfile::SingleAuthorityV1, _, _) => {
            return Err(refuse_evidence(
                "single authority carries native quorum evidence",
            ))
        }
    };

    let expected_assurance = runtime_assurance_v1(
        certificate.native_aft_evidence.as_ref(),
        certificate.hash_async_evidence.as_ref(),
        &checkpoint.domain_id,
        &checkpoint.availability_manifest_hash,
    )?;
    if certificate.assurance.schema_version != "ioi.runtime-assurance.v1"
        || certificate.assurance.requirements != expected_assurance.requirements
        || certificate.assurance.transformations != expected_assurance.transformations
        || certificate.assurance.achieved_commitment != expected_assurance.achieved_commitment
    {
        return Err(refuse_evidence("runtime assurance envelope mismatch"));
    }
    let verified_assurance = CertificateOnlyGuaranteeVerifierV1::verify_claim(
        &[expected_assurance.achieved],
        &certificate.assurance.achieved,
        &certificate.assurance.transformations,
    )
    .map_err(|error| refuse_evidence(format!("runtime assurance verification: {error}")))?;
    if !certificate
        .assurance
        .requirements
        .is_satisfied_by(&verified_assurance)
    {
        return Err(refuse_evidence(
            "runtime assurance requirements are not satisfied",
        ));
    }

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
        assurance: verified_assurance.into_achieved(),
    })
}
