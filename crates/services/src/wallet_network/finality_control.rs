//! Wallet-owned authorization for runtime ordering/finality profile cutovers.
//!
//! This service operation does not change the active profile. It consumes a
//! separately scoped set of one-shot wallet approvals and records their exact
//! operation hash in canonical chain state. The validator may act on it only
//! after the containing block is itself admitted through Agentgres under the
//! prior profile.

use super::handlers;
use super::keys::approval_effect_consumption_receipt_key;
use super::support::block_timestamp_ms;
use super::{
    ApprovalGrantConsumptionReceipt, ConsumeApprovalGrantForEffectV2Params,
    ExpectedPrincipalAuthorityBinding,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const AUTHORIZE_FINALITY_PROFILE_CUTOVER_METHOD: &str = "authorize_finality_profile_cutover@v1";
pub const FINALITY_PROFILE_CUTOVER_SCOPE: &str =
    "scope:autonomous_system.ordering_admission_finality_profile_change";
pub const GOVERNED_FINALITY_PROFILE_CUTOVER_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum GovernedRollbackKindV1 {
    SuccessorCutover,
    Freeze,
}

/// Exact owner-authored cutover request. `operation_hash` covers every field
/// except the approval consumptions. Each consumption signs a distinct,
/// domain-separated request derived from this hash and its exact authority
/// binding, allowing a real threshold without colliding in the wallet's
/// request-keyed approval history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct GovernedFinalityProfileCutoverV1 {
    pub schema_version: u16,
    pub operation_hash: [u8; 32],
    pub cutover_id: String,
    pub domain_id: String,
    pub expected_from_profile: String,
    pub expected_from_profile_contract_version: String,
    pub expected_from_writer_identity: String,
    pub expected_from_profile_epoch: u64,
    pub expected_from_fence_token: u64,
    pub expected_prior_canonical_head: String,
    pub to_profile: String,
    pub to_profile_contract_version: String,
    pub to_writer_identity: String,
    pub to_fence_token: u64,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub approval_threshold: u32,
    pub activation_not_before_ms: u64,
    pub activation_checkpoint_height: u64,
    pub rollback_kind: GovernedRollbackKindV1,
    pub rollback_executor_writer_identity: String,
    pub rollback_authorization_refs: Vec<String>,
    pub rollback_target_profile: Option<String>,
}

#[derive(Encode)]
struct GovernedFinalityProfileCutoverHashMaterial<'a> {
    domain: &'static str,
    schema_version: u16,
    cutover_id: &'a str,
    domain_id: &'a str,
    expected_from_profile: &'a str,
    expected_from_profile_contract_version: &'a str,
    expected_from_writer_identity: &'a str,
    expected_from_profile_epoch: u64,
    expected_from_fence_token: u64,
    expected_prior_canonical_head: &'a str,
    to_profile: &'a str,
    to_profile_contract_version: &'a str,
    to_writer_identity: &'a str,
    to_fence_token: u64,
    authority_epoch: u64,
    revocation_epoch: u64,
    approval_threshold: u32,
    activation_not_before_ms: u64,
    activation_checkpoint_height: u64,
    rollback_kind: &'a GovernedRollbackKindV1,
    rollback_executor_writer_identity: &'a str,
    rollback_authorization_refs: &'a [String],
    rollback_target_profile: &'a Option<String>,
}

impl GovernedFinalityProfileCutoverV1 {
    pub fn compute_operation_hash(&self) -> Result<[u8; 32], TransactionError> {
        let bytes = codec::to_bytes_canonical(&GovernedFinalityProfileCutoverHashMaterial {
            domain: "ioi.wallet-network.governed-finality-profile-cutover.v1",
            schema_version: self.schema_version,
            cutover_id: &self.cutover_id,
            domain_id: &self.domain_id,
            expected_from_profile: &self.expected_from_profile,
            expected_from_profile_contract_version: &self.expected_from_profile_contract_version,
            expected_from_writer_identity: &self.expected_from_writer_identity,
            expected_from_profile_epoch: self.expected_from_profile_epoch,
            expected_from_fence_token: self.expected_from_fence_token,
            expected_prior_canonical_head: &self.expected_prior_canonical_head,
            to_profile: &self.to_profile,
            to_profile_contract_version: &self.to_profile_contract_version,
            to_writer_identity: &self.to_writer_identity,
            to_fence_token: self.to_fence_token,
            authority_epoch: self.authority_epoch,
            revocation_epoch: self.revocation_epoch,
            approval_threshold: self.approval_threshold,
            activation_not_before_ms: self.activation_not_before_ms,
            activation_checkpoint_height: self.activation_checkpoint_height,
            rollback_kind: &self.rollback_kind,
            rollback_executor_writer_identity: &self.rollback_executor_writer_identity,
            rollback_authorization_refs: &self.rollback_authorization_refs,
            rollback_target_profile: &self.rollback_target_profile,
        })
        .map_err(TransactionError::Invalid)?;
        ioi_crypto::algorithms::hash::sha256(&bytes)
            .map_err(|error| TransactionError::Invalid(error.to_string()))
    }

    pub fn verify_shape(&self) -> Result<(), TransactionError> {
        if self.schema_version != GOVERNED_FINALITY_PROFILE_CUTOVER_SCHEMA_VERSION {
            return Err(TransactionError::Invalid(
                "governed finality cutover schema mismatch".into(),
            ));
        }
        if self.compute_operation_hash()? != self.operation_hash {
            return Err(TransactionError::Invalid(
                "governed finality cutover operation hash mismatch".into(),
            ));
        }
        if self.cutover_id.is_empty()
            || self.domain_id.is_empty()
            || self.expected_from_writer_identity.is_empty()
            || self.to_writer_identity.is_empty()
            || self.rollback_executor_writer_identity.is_empty()
            || self.authority_epoch == 0
            || self.approval_threshold == 0
            || self.to_fence_token <= self.expected_from_fence_token
            || self.activation_checkpoint_height == 0
        {
            return Err(TransactionError::Invalid(
                "governed finality cutover has an empty or non-monotonic coordinate".into(),
            ));
        }
        if !matches!(
            self.expected_from_profile.as_str(),
            "bft_consensus" | "single_authority"
        ) || !matches!(
            self.to_profile.as_str(),
            "bft_consensus" | "single_authority"
        ) || self.expected_from_profile == self.to_profile
        {
            return Err(TransactionError::Invalid(
                "governed finality cutover must name two distinct canonical profiles".into(),
            ));
        }
        if !is_sha256_label(&self.expected_prior_canonical_head) {
            return Err(TransactionError::Invalid(
                "governed finality cutover canonical head is malformed".into(),
            ));
        }
        match (&self.rollback_kind, &self.rollback_target_profile) {
            (GovernedRollbackKindV1::SuccessorCutover, Some(target))
                if target == &self.expected_from_profile => {}
            (GovernedRollbackKindV1::Freeze, None) => {}
            _ => {
                return Err(TransactionError::Invalid(
                    "governed finality cutover rollback target is invalid".into(),
                ))
            }
        }
        Ok(())
    }
}

fn is_sha256_label(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AuthorizeFinalityProfileCutoverParamsV1 {
    pub operation: GovernedFinalityProfileCutoverV1,
    pub approvals: Vec<ConsumeApprovalGrantForEffectV2Params>,
}

#[derive(Encode)]
struct GovernedCutoverApprovalRequestHashMaterial<'a> {
    domain: &'static str,
    operation_hash: [u8; 32],
    principal_ref: &'a str,
    required_scope: &'a str,
    authority_id: [u8; 32],
    approval_authority_snapshot_hash: [u8; 32],
    binding_ref: &'a str,
    binding_version: u64,
    binding_hash: [u8; 32],
}

pub fn governed_cutover_approval_request_hash(
    operation_hash: [u8; 32],
    expected: &ExpectedPrincipalAuthorityBinding,
) -> Result<[u8; 32], TransactionError> {
    let bytes = codec::to_bytes_canonical(&GovernedCutoverApprovalRequestHashMaterial {
        domain: "ioi.wallet-network.governed-finality-profile-cutover-approval-request.v1",
        operation_hash,
        principal_ref: &expected.principal_ref,
        required_scope: &expected.required_scope,
        authority_id: expected.approval_authority.authority_id,
        approval_authority_snapshot_hash: expected.approval_authority_snapshot_hash,
        binding_ref: &expected.coordinates.binding_ref,
        binding_version: expected.coordinates.binding_version,
        binding_hash: expected.coordinates.binding_hash,
    })
    .map_err(TransactionError::Invalid)?;
    ioi_crypto::algorithms::hash::sha256(&bytes)
        .map_err(|error| TransactionError::Invalid(error.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct FinalityProfileCutoverAuthorizationReceiptV1 {
    pub schema_version: u16,
    pub operation_hash: [u8; 32],
    pub cutover_id: String,
    pub authority_refs: Vec<String>,
    pub approval_request_hashes: Vec<[u8; 32]>,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
}

pub(crate) fn authorize_finality_profile_cutover(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: AuthorizeFinalityProfileCutoverParamsV1,
) -> Result<(), TransactionError> {
    params.operation.verify_shape()?;
    let weakening = params.operation.expected_from_profile == "bft_consensus"
        && params.operation.to_profile == "single_authority";
    if weakening
        && (params.operation.approval_threshold < 2
            || params.operation.activation_not_before_ms <= block_timestamp_ms(ctx)
            || params.operation.activation_checkpoint_height <= ctx.block_height
            || params.operation.rollback_executor_writer_identity
                == params.operation.to_writer_identity
            || params.operation.rollback_authorization_refs.is_empty()
            || params
                .operation
                .rollback_authorization_refs
                .iter()
                .any(|reference| reference == &params.operation.to_writer_identity))
    {
        return Err(TransactionError::Invalid(
            "INV-42 weakening requires a separate threshold, future delay/checkpoint, and independent rollback or freeze"
                .into(),
        ));
    }
    if params.approvals.len() < params.operation.approval_threshold as usize {
        return Err(TransactionError::Invalid(
            "governed finality cutover approval threshold is unmet".into(),
        ));
    }
    let mut authorities = BTreeSet::new();
    let mut consumptions = BTreeSet::new();
    let mut approval_request_hashes = BTreeSet::new();
    for approval in &params.approvals {
        let expected_request_hash = governed_cutover_approval_request_hash(
            params.operation.operation_hash,
            &approval.expected_principal_authority,
        )?;
        if approval.request_hash != expected_request_hash
            || approval.expected_target_label != FINALITY_PROFILE_CUTOVER_SCOPE
            || approval.expected_max_usages != 1
            || approval.expected_principal_authority.required_scope
                != FINALITY_PROFILE_CUTOVER_SCOPE
            || approval
                .expected_principal_authority
                .coordinates
                .binding_version
                != params.operation.authority_epoch
        {
            return Err(TransactionError::Invalid(
                "governed finality cutover approval does not bind the exact operation/scope/authority epoch"
                    .into(),
            ));
        }
        if !authorities.insert(
            approval
                .expected_principal_authority
                .approval_authority
                .authority_id,
        ) || !consumptions.insert(approval.consumption_id)
            || !approval_request_hashes.insert(approval.request_hash)
        {
            return Err(TransactionError::Invalid(
                "governed finality cutover approvals are not distinct".into(),
            ));
        }
    }
    if authorities.len() < params.operation.approval_threshold as usize {
        return Err(TransactionError::Invalid(
            "governed finality cutover distinct-authority threshold is unmet".into(),
        ));
    }
    for approval in params.approvals {
        let receipt_key = approval_effect_consumption_receipt_key(&approval.consumption_id);
        handlers::approval::consume_approval_grant_for_effect_v2(state, ctx, approval)?;
        let receipt_bytes = state.get(&receipt_key)?.ok_or_else(|| {
            TransactionError::Invalid(
                "governed finality cutover approval consumption produced no receipt".into(),
            )
        })?;
        let receipt: ApprovalGrantConsumptionReceipt = codec::from_bytes_canonical(&receipt_bytes)
            .map_err(|error| {
                TransactionError::Invalid(format!(
                    "governed finality cutover approval receipt is unreadable: {error}"
                ))
            })?;
        if receipt.issued_revocation_epoch != params.operation.revocation_epoch {
            return Err(TransactionError::Invalid(
                "governed finality cutover approval revocation epoch mismatch".into(),
            ));
        }
    }
    let receipt = FinalityProfileCutoverAuthorizationReceiptV1 {
        schema_version: 1,
        operation_hash: params.operation.operation_hash,
        cutover_id: params.operation.cutover_id,
        authority_refs: authorities
            .into_iter()
            .map(|authority| format!("wallet-approval-authority://{}", hex::encode(authority)))
            .collect(),
        approval_request_hashes: approval_request_hashes.into_iter().collect(),
        authority_epoch: params.operation.authority_epoch,
        revocation_epoch: params.operation.revocation_epoch,
    };
    let key = [
        b"finality_profile_cutover_authorization_receipt::".as_slice(),
        receipt.operation_hash.as_slice(),
    ]
    .concat();
    let bytes = codec::to_bytes_canonical(&receipt).map_err(TransactionError::Invalid)?;
    if let Some(existing) = state.get(&key)? {
        if existing != bytes {
            return Err(TransactionError::Invalid(
                "governed finality cutover authorization receipt conflicts".into(),
            ));
        }
        return Ok(());
    }
    state.insert(&key, &bytes)?;
    Ok(())
}
