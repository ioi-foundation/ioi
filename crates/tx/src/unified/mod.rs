// Path: crates/tx/src/unified/mod.rs

use crate::utxo::{UTXOModel, UTXOTransactionProof};
use async_trait::async_trait;
use ioi_api::chain::ChainView;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::error::ErrorCode;
use ioi_api::state::{
    service_namespace_prefix, NamespacedStateAccess, ProofProvider, StateAccess, StateManager,
};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_api::vm::ExecutionContext;
// REMOVED: use ioi_consensus::PenaltiesService;
use ioi_telemetry::sinks::{error_metrics, service_metrics};
use ioi_types::app::{
    ApplicationTransaction, ChainStatus, ChainTransaction, StateEntry, SystemPayload,
};
use ioi_types::codec;
use ioi_types::error::{StateError, TransactionError};
use ioi_types::keys::active_service_key;
use ioi_types::keys::GOVERNANCE_KEY;
use ioi_types::service_configs::{
    ActiveServiceMeta, GovernancePolicy, GovernanceSigner, MethodPermission,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub enum UnifiedProof<P> {
    UTXO(UTXOTransactionProof<P>),
    Application, // no reads proven
    System,      // no reads proven
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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + Debug
        + Encode
        + Decode,
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
        state: &mut dyn StateAccess,
        tx: &Self::Transaction,
        ctx: &mut TxContext<'_>,
    ) -> Result<(Self::Proof, u64), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ProofProvider
            + Send
            + Sync
            + 'static,
        CV: ChainView<Self::CommitmentScheme, ST> + Send + Sync + ?Sized,
    {
        match tx {
            ChainTransaction::Application(app_tx) => match app_tx {
                ApplicationTransaction::UTXO(utxo_tx) => {
                    let (p, gas) = self
                        .utxo_model
                        .apply_payload(chain_ref, state, utxo_tx, ctx)
                        .await?;
                    Ok((UnifiedProof::UTXO(p), gas))
                }
                ApplicationTransaction::DeployContract { code, header, .. } => {
                    let workload = chain_ref.workload_container();
                    let public_key_bytes = state
                        .get(
                            &[
                                ioi_types::keys::ACCOUNT_ID_TO_PUBKEY_PREFIX,
                                header.account_id.as_ref(),
                            ]
                            .concat(),
                        )?
                        .ok_or(TransactionError::UnauthorizedByCredentials)?;

                    let (_address, state_delta) = workload
                        .deploy_contract(code.clone(), public_key_bytes)
                        .await
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                    let fuel_costs = &workload.config().fuel_costs;
                    let mut gas_used = fuel_costs.base_cost;

                    if !state_delta.is_empty() {
                        let versioned_delta: Vec<(Vec<u8>, Vec<u8>)> = state_delta
                            .into_iter()
                            .map(|(key, value)| {
                                // Accumulate gas for storage writes
                                gas_used += (key.len() as u64 + value.len() as u64)
                                    * fuel_costs.state_set_per_byte;

                                let entry = StateEntry {
                                    value,
                                    block_height: ctx.block_height,
                                };
                                codec::to_bytes_canonical(&entry).map(|bytes| (key, bytes))
                            })
                            .collect::<Result<_, _>>()?;
                        state.batch_set(&versioned_delta)?;
                    }
                    Ok((UnifiedProof::Application, gas_used))
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
                        .get(
                            &[
                                ioi_types::keys::ACCOUNT_ID_TO_PUBKEY_PREFIX,
                                header.account_id.as_ref(),
                            ]
                            .concat(),
                        )?
                        .ok_or(TransactionError::UnauthorizedByCredentials)?;

                    let workload = chain_ref.workload_container();
                    let exec_context = ExecutionContext {
                        caller: public_key_bytes,
                        block_height: ctx.block_height,
                        gas_limit: *gas_limit,
                        contract_address: address.clone(),
                    };

                    let (output, (inserts, deletes)) = workload
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
                    Ok((UnifiedProof::Application, output.gas_used))
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

                        tracing::debug!(
                            target = "service_dispatch",
                            "incoming CallService: {}::{} (params_len={})",
                            service_id,
                            method,
                            params.len()
                        );

                        // --- KERNEL-SPACE DISPATCH ---
                        if service_id == "penalties" {
                            let service_arc = ctx
                                .services
                                .services()
                                .find(|s| s.id() == "penalties")
                                .ok_or(TransactionError::Unsupported(
                                    "Penalties service inactive".into(),
                                ))?;

                            // Privileged Call: Pass raw state, NOT namespaced.
                            // service_arc is Arc<dyn BlockchainService>, so we call the trait method.
                            service_arc
                                .handle_service_call(state, method, params, ctx)
                                .await?;
                            return Ok((UnifiedProof::System, 0));
                        }

                        // --- USER-SPACE DISPATCH ---
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
                                    tracing::warn!(
                                        target = "service_dispatch",
                                        "permission denied: internal method via txn: service='{}' method='{}' signer={}",
                                        service_id,
                                        method,
                                        hex::encode(ctx.signer_account_id.as_ref())
                                    );
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

                        // Create the namespaced state wrapper and dispatch.
                        let prefix = service_namespace_prefix(service.id());
                        let mut namespaced_state = NamespacedStateAccess::new(state, prefix, &meta);

                        tracing::debug!(
                            target = "service_dispatch",
                            "invoking {}::{}",
                            service.id(),
                            method
                        );
                        let start = std::time::Instant::now();
                        let result = service
                            .handle_service_call(&mut namespaced_state, method, params, ctx)
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
                        result?;
                    }
                }
                // TODO: Add gas accounting for system transactions
                Ok((UnifiedProof::System, 0))
            }
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
