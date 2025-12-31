// Path: crates/tx/src/settlement/mod.rs

use async_trait::async_trait;
use ioi_api::chain::ChainView;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{ProofProvider, StateAccess, StateManager};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_types::app::{SettlementPayload, SettlementTransaction};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize}; // [FIX] Kept Serialize, removed Deserialize warning if unused but types derive it
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct SettlementModel<CS: CommitmentScheme> {
    _commitment_scheme: CS,
}

impl<CS: CommitmentScheme + Clone> SettlementModel<CS> {
    pub fn new(scheme: CS) -> Self {
        Self {
            _commitment_scheme: scheme,
        }
    }
}

// Canonical keys for settlement objects (bonds, channels, etc.)
const BOND_PREFIX: &[u8] = b"settle::bond::";
// const CHANNEL_PREFIX: &[u8] = b"settle::channel::";

#[async_trait]
impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for SettlementModel<CS>
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
    type Transaction = SettlementTransaction;
    type CommitmentScheme = CS;
    type Proof = ();

    fn create_coinbase_transaction(
        &self,
        _block_height: u64,
        _recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        Err(TransactionError::Unsupported(
            "Coinbase not supported in settlement model".into(),
        ))
    }

    fn validate_stateless(&self, _tx: &Self::Transaction) -> Result<(), TransactionError> {
        Ok(())
    }

    async fn apply_payload<ST, CV>(
        &self,
        _chain: &CV,
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
        let gas_used = 1000;

        match &tx.payload {
            SettlementPayload::Transfer { to, amount } => {
                let sender = ctx.signer_account_id;
                let sender_key = [b"balance::", sender.as_ref()].concat();
                let receiver_key = [b"balance::", to.as_ref()].concat();

                let sender_bal: u128 = state
                    .get(&sender_key)?
                    .and_then(|b| codec::from_bytes_canonical(&b).ok())
                    .unwrap_or(0);

                if sender_bal < *amount {
                    return Err(TransactionError::InsufficientFunds);
                }

                let receiver_bal: u128 = state
                    .get(&receiver_key)?
                    .and_then(|b| codec::from_bytes_canonical(&b).ok())
                    .unwrap_or(0);

                let new_sender_bal = sender_bal - amount;
                let new_receiver_bal = receiver_bal + amount;

                state.insert(
                    &sender_key,
                    &codec::to_bytes_canonical(&new_sender_bal).unwrap(),
                )?;
                state.insert(
                    &receiver_key,
                    &codec::to_bytes_canonical(&new_receiver_bal).unwrap(),
                )?;
            }

            // [FIX] Correctly ignore unused fields
            SettlementPayload::Commit {
                session_id,
                bond_amount,
                policy_hash: _,
                receipt_root: _,
            } => {
                // Lock funds for a session
                let sender = ctx.signer_account_id;
                let sender_key = [b"balance::", sender.as_ref()].concat();
                let sender_bal: u128 = state
                    .get(&sender_key)?
                    .and_then(|b| codec::from_bytes_canonical(&b).ok())
                    .unwrap_or(0);

                if sender_bal < *bond_amount {
                    return Err(TransactionError::InsufficientFunds);
                }

                // Deduct from sender
                let new_sender_bal = sender_bal - bond_amount;
                state.insert(
                    &sender_key,
                    &codec::to_bytes_canonical(&new_sender_bal).unwrap(),
                )?;

                // Create Bond record
                let bond_key = [BOND_PREFIX, session_id].concat();
                if state.get(&bond_key)?.is_some() {
                    return Err(TransactionError::Invalid("Session ID collision".into()));
                }

                state.insert(&bond_key, &codec::to_bytes_canonical(bond_amount).unwrap())?;
            }

            SettlementPayload::Settle {
                summary,
                payer_sig: _,
                provider_sig: _,
            } => {
                let bond_key = [BOND_PREFIX, &summary.session_id].concat();
                let bonded_amount: u128 = state
                    .get(&bond_key)?
                    .and_then(|b| codec::from_bytes_canonical(&b).ok())
                    .ok_or(TransactionError::Invalid("Session bond not found".into()))?;

                if summary.final_amount > bonded_amount {
                    return Err(TransactionError::Invalid(
                        "Settlement amount exceeds bond".into(),
                    ));
                }

                // Transfer final_amount to Provider
                let provider_key = [b"balance::", summary.provider_id.as_ref()].concat();
                let provider_bal: u128 = state
                    .get(&provider_key)?
                    .and_then(|b| codec::from_bytes_canonical(&b).ok())
                    .unwrap_or(0);
                let new_provider_bal = provider_bal + summary.final_amount;
                state.insert(
                    &provider_key,
                    &codec::to_bytes_canonical(&new_provider_bal).unwrap(),
                )?;

                // Refund remaining to Payer
                let refund = bonded_amount - summary.final_amount;
                if refund > 0 {
                    let payer_key = [b"balance::", summary.payer_id.as_ref()].concat();
                    let payer_bal: u128 = state
                        .get(&payer_key)?
                        .and_then(|b| codec::from_bytes_canonical(&b).ok())
                        .unwrap_or(0);
                    let new_payer_bal = payer_bal + refund;
                    state.insert(
                        &payer_key,
                        &codec::to_bytes_canonical(&new_payer_bal).unwrap(),
                    )?;
                }

                // Close bond
                state.delete(&bond_key)?;
            }

            SettlementPayload::Escalate { session_id, .. } => {
                // Mark session as disputed
                let bond_key = [BOND_PREFIX, session_id].concat();
                if state.get(&bond_key)?.is_none() {
                    return Err(TransactionError::Invalid("Session bond not found".into()));
                }
                let dispute_key = [b"dispute::", session_id.as_slice()].concat();
                let bond_val = state.get(&bond_key)?.unwrap();
                state.delete(&bond_key)?;
                state.insert(&dispute_key, &bond_val)?;
            }

            // [FIX] Correctly ignore unused field
            SettlementPayload::Bridge {
                target_chain,
                payload,
                receipt: _,
            } => {
                let nonce_key = [b"outbox::nonce::", target_chain.as_bytes()].concat();
                let nonce: u64 = state
                    .get(&nonce_key)?
                    .and_then(|b| codec::from_bytes_canonical(&b).ok())
                    .unwrap_or(0);

                let outbox_key = [
                    b"outbox::queue::",
                    target_chain.as_bytes(),
                    &nonce.to_be_bytes(),
                ]
                .concat();
                state.insert(&outbox_key, payload)?;

                let next_nonce = nonce + 1;
                state.insert(&nonce_key, &codec::to_bytes_canonical(&next_nonce).unwrap())?;
            }
        }

        Ok(((), gas_used))
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        codec::to_bytes_canonical(tx).map_err(TransactionError::Serialization)
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        codec::from_bytes_canonical(data)
            .map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}
