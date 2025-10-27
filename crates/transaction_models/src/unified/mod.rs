// Path: crates/transaction_models/src/unified/mod.rs

use crate::utxo::{UTXOModel, UTXOTransactionProof};
use async_trait::async_trait;
use depin_sdk_api::chain::ChainView;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::error::ErrorCode;
use depin_sdk_api::identity::CredentialsView;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::vm::ExecutionContext;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_telemetry::sinks::{error_metrics, service_metrics};
use depin_sdk_types::app::{
    evidence_id, write_validator_sets, ActiveKeyRecord, ApplicationTransaction, ChainTransaction,
    SignatureSuite, StateEntry, SystemPayload, ValidatorV1,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{StateError, TransactionError};
use depin_sdk_types::keys::{
    active_service_key, ACCOUNT_ID_TO_PUBKEY_PREFIX, EVIDENCE_REGISTRY_KEY, GOVERNANCE_KEY,
    UPGRADE_ARTIFACT_PREFIX, UPGRADE_MANIFEST_PREFIX, UPGRADE_PENDING_PREFIX, VALIDATOR_SET_KEY,
};
use depin_sdk_types::service_configs::{
    ActiveServiceMeta, GovernancePolicy, GovernanceSigner, MethodPermission,
};
use libp2p::identity::PublicKey as Libp2pPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UnifiedProof<P> {
    UTXO(UTXOTransactionProof<P>),
    Application,
    System,
}

#[derive(Clone, Debug)]
pub struct UnifiedTransactionModel<CS: CommitmentScheme + Clone> {
    utxo_model: UTXOModel<CS>,
}

impl<CS: CommitmentScheme + Clone> UnifiedTransactionModel<CS> {
    pub fn new(scheme: CS) -> Self {
        Self {
            utxo_model: UTXOModel::new(scheme),
        }
    }
}

/// A helper to validate the format of a service ID.
fn validate_service_id(id: &str) -> Result<(), TransactionError> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(TransactionError::Invalid(format!(
            "Invalid service_id format: '{}'. Must be lowercase alphanumeric with underscores.",
            id
        )));
    }
    Ok(())
}

#[async_trait]
impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for UnifiedTransactionModel<CS>
where
    <CS as CommitmentScheme>::Proof: Serialize + for<'de> serde::Deserialize<'de> + Clone,
{
    type Transaction = ChainTransaction;
    type CommitmentScheme = CS;
    type Proof = UnifiedProof<CS::Proof>;

    fn create_coinbase_transaction(
        &self,
        block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        let utxo_tx = self
            .utxo_model
            .create_coinbase_transaction(block_height, recipient)?;
        Ok(ChainTransaction::Application(ApplicationTransaction::UTXO(
            utxo_tx,
        )))
    }

    fn validate_stateless(&self, _tx: &Self::Transaction) -> Result<(), TransactionError> {
        Ok(())
    }

    async fn apply_payload<ST, CV>(
        &self,
        chain_ref: &CV,
        state: &mut dyn StateAccessor,
        tx: &Self::Transaction,
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + Send
            + Sync
            + 'static,
        CV: ChainView<Self::CommitmentScheme, ST> + Send + Sync + ?Sized,
    {
        // NOTE: Nonce logic is now correctly handled in the IdentityHub ante handler.
        match tx {
            ChainTransaction::Application(app_tx) => match app_tx {
                ApplicationTransaction::UTXO(utxo_tx) => {
                    self.utxo_model
                        .apply_payload(chain_ref, state, utxo_tx, ctx)
                        .await
                }
                ApplicationTransaction::DeployContract { code, header, .. } => {
                    let workload = chain_ref.workload_container();
                    let public_key_bytes = state
                        .get(&[ACCOUNT_ID_TO_PUBKEY_PREFIX, header.account_id.as_ref()].concat())?
                        .ok_or(TransactionError::UnauthorizedByCredentials)?;

                    let (_address, state_delta) = workload
                        .deploy_contract(code.clone(), public_key_bytes)
                        .await
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                    if !state_delta.is_empty() {
                        let versioned_delta: Vec<(Vec<u8>, Vec<u8>)> = state_delta
                            .into_iter()
                            .map(|(key, value)| {
                                let entry = StateEntry {
                                    value,
                                    block_height: ctx.block_height,
                                };
                                codec::to_bytes_canonical(&entry).map(|bytes| (key, bytes))
                            })
                            .collect::<Result<_, _>>()?;
                        state.batch_set(&versioned_delta)?;
                    }
                    Ok(())
                }
                ApplicationTransaction::CallContract {
                    address,
                    input_data,
                    gas_limit,
                    header,
                    ..
                } => {
                    let code_key = [b"contract_code::".as_ref(), address.as_ref()].concat();
                    let stored_bytes = state.get(&code_key)?.ok_or_else(|| {
                        TransactionError::Invalid("Contract not found".to_string())
                    })?;
                    let stored_entry: StateEntry = codec::from_bytes_canonical(&stored_bytes)?;
                    let code = stored_entry.value;

                    let public_key_bytes = state
                        .get(&[ACCOUNT_ID_TO_PUBKEY_PREFIX, header.account_id.as_ref()].concat())?
                        .ok_or(TransactionError::UnauthorizedByCredentials)?;

                    let workload = chain_ref.workload_container();
                    let exec_context = ExecutionContext {
                        caller: public_key_bytes,
                        block_height: ctx.block_height,
                        gas_limit: *gas_limit,
                        contract_address: address.clone(),
                    };

                    let (_output, (inserts, deletes)) = workload
                        .execute_loaded_contract(code, input_data.clone(), exec_context)
                        .await
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                    for key in deletes {
                        state.delete(&key)?;
                    }

                    if !inserts.is_empty() {
                        let versioned_inserts: Vec<(Vec<u8>, Vec<u8>)> = inserts
                            .into_iter()
                            .map(|(key, value)| {
                                let entry = StateEntry {
                                    value,
                                    block_height: ctx.block_height,
                                };
                                codec::to_bytes_canonical(&entry).map(|bytes| (key, bytes))
                            })
                            .collect::<Result<_, _>>()?;
                        state.batch_set(&versioned_inserts)?;
                    }
                    Ok(())
                }
            },
            ChainTransaction::System(sys_tx) => {
                ctx.signer_account_id = sys_tx.header.account_id;

                match &sys_tx.payload {
                    SystemPayload::CallService {
                        service_id,
                        method,
                        params,
                    } => {
                        const MAX_PARAMS_LEN: usize = 64 * 1024;
                        if params.len() > MAX_PARAMS_LEN {
                            return Err(TransactionError::Invalid(
                                "Service call params exceed size limit".into(),
                            ));
                        }
                        validate_service_id(service_id)?;

                        let meta_key = active_service_key(service_id);
                        let meta_bytes = state.get(&meta_key)?.ok_or_else(|| {
                            TransactionError::Unsupported(format!(
                                "Service '{}' is not active",
                                service_id
                            ))
                        })?;
                        let meta: ActiveServiceMeta = codec::from_bytes_canonical(&meta_bytes)?;

                        let disabled_key = [meta_key.as_slice(), b"::disabled"].concat();
                        if state.get(&disabled_key)?.is_some() {
                            return Err(TransactionError::Unsupported(format!(
                                "Service '{}' is administratively disabled",
                                service_id
                            )));
                        }

                        let permission = meta.methods.get(method).ok_or_else(|| {
                            TransactionError::Unsupported(format!(
                                "Method '{}' not found in service '{}' ABI",
                                method, service_id
                            ))
                        })?;
                        match permission {
                            MethodPermission::Internal => {
                                if !ctx.is_internal {
                                    return Err(TransactionError::Invalid(
                                        "Internal method cannot be called via transaction".into(),
                                    ));
                                }
                            }
                            MethodPermission::Governance => {
                                let policy_bytes = state.get(GOVERNANCE_KEY)?.ok_or_else(|| {
                                    TransactionError::State(StateError::KeyNotFound)
                                })?;
                                let policy: GovernancePolicy =
                                    codec::from_bytes_canonical(&policy_bytes)?;
                                match policy.signer {
                                    GovernanceSigner::Single(gov_account_id) => {
                                        if ctx.signer_account_id != gov_account_id {
                                            return Err(TransactionError::Invalid(
                                                "Caller is not the governance account".into(),
                                            ));
                                        }
                                    }
                                }
                            }
                            MethodPermission::User => {}
                        }

                        tracing::debug!(
                            target = "service_dispatch",
                            "dispatching CallService: {}::{} (params_len={})",
                            service_id,
                            method,
                            params.len()
                        );
                        let service = ctx
                            .services
                            .services()
                            .find(|s| s.id() == service_id)
                            .ok_or_else(|| {
                                TransactionError::Unsupported(format!(
                                    "Service '{}' not found or not enabled",
                                    service_id
                                ))
                            })?;

                        tracing::debug!(
                            target = "service_dispatch",
                            "invoking {}::{}",
                            service.id(),
                            method
                        );
                        let start = std::time::Instant::now();
                        let result = service
                            .handle_service_call(state, method, params, ctx)
                            .await;
                        let latency = start.elapsed().as_secs_f64();
                        service_metrics().observe_service_dispatch_latency(
                            service.id(),
                            method,
                            latency,
                        );
                        if let Err(e) = &result {
                            error_metrics().inc_error("service_dispatch", e.code());
                            service_metrics().inc_dispatch_error(service.id(), method, e.code());
                        }
                        result
                    }
                    SystemPayload::StoreModule { manifest, artifact } => {
                        let manifest_hash = sha256(manifest.as_bytes())?;
                        let artifact_hash = sha256(artifact)?;
                        let manifest_key = [UPGRADE_MANIFEST_PREFIX, &manifest_hash].concat();
                        let artifact_key = [UPGRADE_ARTIFACT_PREFIX, &artifact_hash].concat();
                        if state.get(&manifest_key)?.is_none() {
                            state.insert(&manifest_key, manifest.as_bytes())?;
                        }
                        if state.get(&artifact_key)?.is_none() {
                            state.insert(&artifact_key, artifact)?;
                        }
                        Ok(())
                    }
                    SystemPayload::SwapModule {
                        service_id,
                        manifest_hash,
                        artifact_hash,
                        activation_height,
                    } => {
                        let policy_bytes = state
                            .get(GOVERNANCE_KEY)?
                            .ok_or(TransactionError::State(StateError::KeyNotFound))?;
                        let policy: GovernancePolicy = codec::from_bytes_canonical(&policy_bytes)?;
                        match policy.signer {
                            GovernanceSigner::Single(gov_id) => {
                                tracing::warn!(
                                    target = "governance",
                                    "SwapModule auth check: signer_account_id={} gov_id={}",
                                    hex::encode(ctx.signer_account_id.as_ref()),
                                    hex::encode(gov_id.as_ref())
                                );
                                if ctx.signer_account_id != gov_id {
                                    return Err(TransactionError::Invalid(
                                        "Caller is not the governance account".into(),
                                    ));
                                }
                            }
                        }
                        validate_service_id(service_id)?;
                        let manifest_key = [UPGRADE_MANIFEST_PREFIX, manifest_hash].concat();
                        if state.get(&manifest_key)?.is_none() {
                            return Err(TransactionError::Invalid(format!(
                                "Manifest not found for hash {}",
                                hex::encode(manifest_hash)
                            )));
                        }
                        let artifact_key = [UPGRADE_ARTIFACT_PREFIX, artifact_hash].concat();
                        if state.get(&artifact_key)?.is_none() {
                            return Err(TransactionError::Invalid(format!(
                                "Artifact not found for hash {}",
                                hex::encode(artifact_hash)
                            )));
                        }
                        let key =
                            [UPGRADE_PENDING_PREFIX, &activation_height.to_le_bytes()].concat();
                        let mut pending: Vec<(String, [u8; 32], [u8; 32])> = state
                            .get(&key)?
                            .and_then(|b| codec::from_bytes_canonical(&b).ok())
                            .unwrap_or_default();
                        pending.push((service_id.clone(), *manifest_hash, *artifact_hash));
                        state.insert(&key, &codec::to_bytes_canonical(&pending)?)?;
                        Ok(())
                    }
                    #[allow(deprecated)]
                    SystemPayload::RotateKey(proof) => {
                        let params_bytes = codec::to_bytes_canonical(proof)?;
                        let service = ctx
                            .services
                            .services()
                            .find(|s| s.id() == "identity_hub")
                            .ok_or(TransactionError::Unsupported(
                                "IdentityHub service not found".into(),
                            ))?;
                        service
                            .handle_service_call(state, "rotate_key@v1", &params_bytes, ctx)
                            .await
                    }
                    #[allow(deprecated)]
                    SystemPayload::Vote {
                        proposal_id,
                        option,
                    } => {
                        let params_bytes = codec::to_bytes_canonical(&(*proposal_id, *option))?;
                        let service = ctx
                            .services
                            .services()
                            .find(|s| s.id() == "governance")
                            .ok_or(TransactionError::Unsupported(
                                "Governance service not found".into(),
                            ))?;
                        service
                            .handle_service_call(state, "vote@v1", &params_bytes, ctx)
                            .await
                    }
                    SystemPayload::Stake { public_key, amount } => {
                        if chain_ref.consensus_type() != ConsensusType::ProofOfStake {
                            return Err(TransactionError::Unsupported(
                                "Stake operations are not supported on non-PoS chains".into(),
                            ));
                        }
                        let staker_account_id = sys_tx.header.account_id;
                        let target_activation = ctx.block_height + 2;

                        let maybe_blob_bytes = state.get(VALIDATOR_SET_KEY)?;
                        let mut sets = maybe_blob_bytes
                            .as_ref()
                            .map(|b| depin_sdk_types::app::read_validator_sets(b))
                            .transpose()?
                            .unwrap_or_default();

                        if sets
                            .next
                            .as_ref()
                            .map_or(true, |n| n.effective_from_height != target_activation)
                        {
                            let mut new_next =
                                sets.next.clone().unwrap_or_else(|| sets.current.clone());
                            new_next.effective_from_height = target_activation;
                            sets.next = Some(new_next);
                        }
                        let next_vs = sets.next.as_mut().ok_or_else(|| {
                            TransactionError::Invalid(
                                "Could not access pending validator set for staking".to_string(),
                            )
                        })?;

                        if let Some(validator) = next_vs
                            .validators
                            .iter_mut()
                            .find(|v| v.account_id == staker_account_id)
                        {
                            validator.weight = validator.weight.saturating_add(*amount as u128);
                        } else {
                            let creds = ctx
                                .services
                                .get::<depin_sdk_services::identity::IdentityHub>()
                                .ok_or_else(|| {
                                    TransactionError::Unsupported(
                                        "IdentityHub service not found for staking".into(),
                                    )
                                })?
                                .get_credentials(state, &staker_account_id)?;
                            let active_cred = creds[0].as_ref().ok_or_else(|| {
                                TransactionError::Invalid("Staker has no active key".to_string())
                            })?;

                            next_vs.validators.push(ValidatorV1 {
                                account_id: staker_account_id,
                                weight: *amount as u128,
                                consensus_key: ActiveKeyRecord {
                                    suite: active_cred.suite,
                                    public_key_hash: active_cred.public_key_hash,
                                    since_height: active_cred.activation_height,
                                },
                            });

                            let pubkey_map_key =
                                [ACCOUNT_ID_TO_PUBKEY_PREFIX, staker_account_id.as_ref()].concat();
                            if state.get(&pubkey_map_key)?.is_none() {
                                let pk_to_store = match sys_tx.signature_proof.suite {
                                    SignatureSuite::Ed25519 => {
                                        if Libp2pPublicKey::try_decode_protobuf(public_key).is_ok()
                                        {
                                            public_key.clone()
                                        } else {
                                            let ed = libp2p::identity::ed25519::PublicKey::try_from_bytes(
                                            &sys_tx.signature_proof.public_key
                                        ).map_err(|_| TransactionError::Invalid("Malformed Ed25519 key".into()))?;
                                            libp2p::identity::PublicKey::from(ed).encode_protobuf()
                                        }
                                    }
                                    SignatureSuite::Dilithium2 => {
                                        sys_tx.signature_proof.public_key.clone()
                                    }
                                };
                                state.insert(&pubkey_map_key, &pk_to_store)?;
                            }
                        }

                        next_vs
                            .validators
                            .sort_by(|a, b| a.account_id.cmp(&b.account_id));
                        next_vs.total_weight = next_vs.validators.iter().map(|v| v.weight).sum();
                        state.insert(VALIDATOR_SET_KEY, &write_validator_sets(&sets)?)?;
                        Ok(())
                    }
                    SystemPayload::Unstake { amount } => {
                        if chain_ref.consensus_type() != ConsensusType::ProofOfStake {
                            return Err(TransactionError::Unsupported(
                                "Unstake operations are not supported on non-PoS chains".into(),
                            ));
                        }
                        let staker_account_id = sys_tx.header.account_id;
                        let target_activation = ctx.block_height + 2;
                        let maybe_blob_bytes = state.get(VALIDATOR_SET_KEY)?;
                        let blob_bytes = maybe_blob_bytes.ok_or_else(|| {
                            TransactionError::Invalid(
                                "Validator set does not exist to unstake from".into(),
                            )
                        })?;
                        let mut sets = depin_sdk_types::app::read_validator_sets(&blob_bytes)?;

                        if sets
                            .next
                            .as_ref()
                            .map_or(true, |n| n.effective_from_height != target_activation)
                        {
                            let mut new_next =
                                sets.next.clone().unwrap_or_else(|| sets.current.clone());
                            new_next.effective_from_height = target_activation;
                            sets.next = Some(new_next);
                        }
                        let next_vs = sets.next.as_mut().ok_or_else(|| {
                            TransactionError::Invalid(
                                "Could not access pending validator set for unstaking".to_string(),
                            )
                        })?;

                        let mut validator_found = false;
                        next_vs.validators.retain_mut(|v| {
                            if v.account_id == staker_account_id {
                                validator_found = true;
                                v.weight = v.weight.saturating_sub(*amount as u128);
                                v.weight > 0
                            } else {
                                true
                            }
                        });
                        if !validator_found {
                            return Err(TransactionError::Invalid(
                                "Staker not in validator set".into(),
                            ));
                        }
                        next_vs
                            .validators
                            .sort_by(|a, b| a.account_id.cmp(&b.account_id));
                        next_vs.total_weight = next_vs.validators.iter().map(|v| v.weight).sum();
                        state.insert(VALIDATOR_SET_KEY, &write_validator_sets(&sets)?)?;
                        Ok(())
                    }
                    SystemPayload::ReportMisbehavior { report } => {
                        let reporter_id = &sys_tx.header.account_id;
                        let vs_blob_bytes = state
                            .get(VALIDATOR_SET_KEY)?
                            .ok_or(TransactionError::State(StateError::KeyNotFound))?;
                        let vs_sets = depin_sdk_types::app::read_validator_sets(&vs_blob_bytes)?;
                        if !vs_sets
                            .current
                            .validators
                            .iter()
                            .any(|v| v.account_id == *reporter_id)
                        {
                            return Err(TransactionError::Invalid(
                                "Reporter is not an active validator.".into(),
                            ));
                        }
                        let handled_evidence: BTreeSet<[u8; 32]> = state
                            .get(EVIDENCE_REGISTRY_KEY)?
                            .as_deref()
                            .map(|b| codec::from_bytes_canonical(b).unwrap_or_default())
                            .unwrap_or_default();
                        let mut new_handled_evidence = handled_evidence;
                        let id = evidence_id(report)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                        if !new_handled_evidence.insert(id) {
                            return Err(TransactionError::Invalid(
                                "Duplicate evidence: this offense has already been penalized."
                                    .to_string(),
                            ));
                        }
                        state.insert(
                            EVIDENCE_REGISTRY_KEY,
                            &codec::to_bytes_canonical(&new_handled_evidence)?,
                        )?;
                        let penalty_mechanism = chain_ref.get_penalty_mechanism();
                        match penalty_mechanism.apply_penalty(state, report).await {
                            Ok(()) => Ok(()),
                            Err(e) => {
                                log::warn!("[Penalty] Report rejected: {}", e);
                                Err(e)
                            }
                        }
                    }
                    _ => Err(TransactionError::Unsupported(
                        "Unhandled SystemPayload variant".into(),
                    )),
                }
            }
        }
    }

    fn generate_proof<S>(
        &self,
        tx: &Self::Transaction,
        state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            ChainTransaction::Application(ApplicationTransaction::UTXO(utxo_tx)) => self
                .utxo_model
                .generate_proof(utxo_tx, state)
                .map(UnifiedProof::UTXO),
            ChainTransaction::Application(_) => Ok(UnifiedProof::Application),
            ChainTransaction::System(_) => Ok(UnifiedProof::System),
        }
    }

    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match proof {
            UnifiedProof::UTXO(utxo_proof) => self.utxo_model.verify_proof(utxo_proof, state),
            UnifiedProof::Application => Ok(true),
            UnifiedProof::System => Ok(true),
        }
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        codec::to_bytes_canonical(tx).map_err(TransactionError::Serialization)
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        codec::from_bytes_canonical(data)
            .map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}
