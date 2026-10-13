// Path: crates/tx/src/settlement/mod.rs

use crate::system::validation::{enforce_credential_policy, verify_signature};
use async_trait::async_trait;
use ioi_api::chain::ChainView;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::namespaced::ReadOnlyNamespacedStateAccess;
use ioi_api::state::{service_namespace_prefix, ProofProvider, StateAccess, StateManager};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, SettlementPayload, SettlementSummary,
    SettlementTransaction, SignatureProof,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
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
/// A disputed session's bond record (`dispute::` ‖ session id), moved here unchanged by Escalate.
const DISPUTE_PREFIX: &[u8] = b"dispute::";
/// A settled session's tombstone (`settled::` ‖ session id). Commit refuses a session id
/// that has one, so a doubly-signed summary can pay at most once.
const SETTLED_TOMBSTONE_PREFIX: &[u8] = b"settled::";
/// Account balance key prefix (`balance::` ‖ account id).
const BALANCE_PREFIX: &[u8] = b"balance::";
/// Domain separator of the settlement summary signatures.
const SUMMARY_SIGNING_DOMAIN: &[u8] = b"ioi::settlement::summary::v1\0";

/// The record Commit stores under the bond key (SCALE-encoded). Escalate moves it
/// unchanged to the dispute key.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BondRecordV1 {
    /// The account that committed the bond (the Commit transaction's signer).
    pub payer: AccountId,
    /// The counterparty the bond backs.
    pub provider_id: AccountId,
    /// The bonded amount, debited from the payer at Commit.
    pub amount: u128,
    /// The policy hash named at Commit.
    pub policy_hash: [u8; 32],
}

fn bond_key(session_id: &[u8; 32]) -> Vec<u8> {
    [BOND_PREFIX, session_id.as_slice()].concat()
}

fn dispute_key(session_id: &[u8; 32]) -> Vec<u8> {
    [DISPUTE_PREFIX, session_id.as_slice()].concat()
}

fn settled_key(session_id: &[u8; 32]) -> Vec<u8> {
    [SETTLED_TOMBSTONE_PREFIX, session_id.as_slice()].concat()
}

fn balance_key(account: &AccountId) -> Vec<u8> {
    [BALANCE_PREFIX, account.as_ref()].concat()
}

/// Reads a balance; an absent or undecodable value reads as 0, as in the Transfer arm.
fn read_balance(state: &dyn StateAccess, key: &[u8]) -> Result<u128, TransactionError> {
    Ok(state
        .get(key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or(0))
}

fn encode_balance(balance: &u128) -> Result<Vec<u8>, TransactionError> {
    codec::to_bytes_canonical(balance).map_err(TransactionError::Serialization)
}

/// The exact message both summary signatures cover:
/// `b"ioi::settlement::summary::v1\0" ‖ SCALE(chain_id) ‖ SCALE(summary) ‖ SCALE(expires_at_height)`,
/// where `chain_id` is the executing chain's id (u32 LE) and `expires_at_height` is u64 LE.
fn summary_sign_bytes(
    chain_id: ChainId,
    summary: &SettlementSummary,
    expires_at_height: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(SUMMARY_SIGNING_DOMAIN);
    message.extend_from_slice(&chain_id.encode());
    message.extend_from_slice(&summary.encode());
    message.extend_from_slice(&expires_at_height.encode());
    message
}

/// Verifies `proof` over `message` as a signature by `party`'s ACTIVE credential.
///
/// This follows the credential path of `verify_stateful_authorization`
/// (crates/tx/src/system/validation.rs): it reads `party`'s credentials through the
/// identity hub's credentials view, binds the proof's key to them with
/// `account_id_from_key_material` and `enforce_credential_policy`, then checks the
/// signature with `verify_signature`. It only reads state. Unlike the outer
/// signature, it has no bootstrap path: an account with no active credential
/// cannot authorize a settlement (fail-closed).
fn verify_party_signature(
    state: &dyn StateAccess,
    ctx: &TxContext<'_>,
    party: &AccountId,
    proof: &SignatureProof,
    message: &[u8],
) -> Result<(), TransactionError> {
    let creds_view = ctx.services.services().find_map(|s| s.as_credentials_view());
    let creds = if let Some(view) = &creds_view {
        let meta_key = active_service_key(view.id());
        let meta_bytes = state.get(&meta_key)?.ok_or_else(|| {
            TransactionError::Unsupported(format!("Service '{}' is not active", view.id()))
        })?;
        let meta: ActiveServiceMeta = codec::from_bytes_canonical(&meta_bytes)?;

        let prefix = service_namespace_prefix(view.id());
        let namespaced_state = ReadOnlyNamespacedStateAccess::new(state, prefix, &meta);
        view.get_credentials(&namespaced_state, party)?
    } else {
        [None, None]
    };

    let derived_pk_hash = account_id_from_key_material(proof.suite, &proof.public_key)?;
    let accept_staged = creds_view
        .as_ref()
        .is_none_or(|v| v.accept_staged_during_grace());
    enforce_credential_policy(
        &creds,
        proof.suite,
        &derived_pk_hash,
        ctx.block_height,
        accept_staged,
    )?;

    verify_signature(proof.suite, &proof.public_key, message, &proof.signature)
        .map_err(TransactionError::InvalidSignature)
}

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

            // Lock funds for a session. Every refusal precedes the first write.
            SettlementPayload::Commit {
                session_id,
                provider_id,
                bond_amount,
                policy_hash,
                receipt_root: _,
            } => {
                let bond_k = bond_key(session_id);
                // Pre-existing refusal (no R test): an open bond already uses this session id.
                if state.get(&bond_k)?.is_some() {
                    return Err(TransactionError::Invalid("Session ID collision".into()));
                }
                // R9 (re-Commit arm): a disputed session id is never re-bonded.
                if state.get(&dispute_key(session_id))?.is_some() {
                    return Err(TransactionError::Invalid(
                        "Session ID is under dispute".into(),
                    ));
                }
                // R5: a settled session id is never re-bonded, so its summary cannot pay again.
                if state.get(&settled_key(session_id))?.is_some() {
                    return Err(TransactionError::Invalid(
                        "Session ID already settled".into(),
                    ));
                }

                let payer = ctx.signer_account_id;
                let payer_k = balance_key(&payer);
                let payer_bal = read_balance(&*state, &payer_k)?;
                // Pre-existing refusal (no R test): the payer must cover the bond.
                if payer_bal < *bond_amount {
                    return Err(TransactionError::InsufficientFunds);
                }

                let record = BondRecordV1 {
                    payer,
                    provider_id: *provider_id,
                    amount: *bond_amount,
                    policy_hash: *policy_hash,
                };
                let record_bytes =
                    codec::to_bytes_canonical(&record).map_err(TransactionError::Serialization)?;
                let new_payer_bal = encode_balance(&(payer_bal - *bond_amount))?;

                // Writes: only after every check above.
                state.insert(&payer_k, &new_payer_bal)?;
                state.insert(&bond_k, &record_bytes)?;
            }

            // Cooperative close. Anyone may relay a doubly-signed summary; every refusal
            // precedes the first write.
            SettlementPayload::Settle {
                summary,
                expires_at_height,
                payer_sig,
                provider_sig,
            } => {
                // R7: unilateral close has no challenge window yet (FU-N5-2): refused.
                if summary.mode != 0 {
                    return Err(TransactionError::Unsupported(
                        "Unilateral close is not supported: no challenge window".into(),
                    ));
                }

                let bond_k = bond_key(&summary.session_id);
                // R9 (Settle arm) and R5 (replay): no open bond under this session id.
                let bond: BondRecordV1 = match state.get(&bond_k)? {
                    Some(bytes) => codec::from_bytes_canonical(&bytes)
                        .map_err(TransactionError::Deserialization)?,
                    None => {
                        return Err(TransactionError::Invalid("Session bond not found".into()))
                    }
                };

                // R3: the summary's payer must be the payer recorded at Commit.
                if summary.payer_id != bond.payer {
                    return Err(TransactionError::Invalid(
                        "Summary payer is not the bond's payer".into(),
                    ));
                }
                // R1: the summary's provider must be the provider the bond backs.
                if summary.provider_id != bond.provider_id {
                    return Err(TransactionError::Invalid(
                        "Summary provider is not the bond's provider".into(),
                    ));
                }
                // Pre-existing refusal (no R test): the payment cannot exceed the bond.
                if summary.final_amount > bond.amount {
                    return Err(TransactionError::Invalid(
                        "Settlement amount exceeds bond".into(),
                    ));
                }
                // R10: an expired authorization is refused.
                if ctx.block_height > *expires_at_height {
                    return Err(TransactionError::Invalid(
                        "Settlement authorization expired".into(),
                    ));
                }

                let message = summary_sign_bytes(ctx.chain_id, summary, *expires_at_height);
                // R2a, R2b, R8: payer_sig must be the payer's ACTIVE credential over this message.
                verify_party_signature(&*state, ctx, &bond.payer, payer_sig, &message)?;
                // R11, R8: provider_sig must be the provider's ACTIVE credential over this message.
                verify_party_signature(&*state, ctx, &bond.provider_id, provider_sig, &message)?;

                // Compute every new value before the first write. The payer and provider
                // keys may coincide, so the refund is added on top of the provider credit.
                let provider_k = balance_key(&bond.provider_id);
                let payer_k = balance_key(&bond.payer);
                let new_provider_bal = read_balance(&*state, &provider_k)?
                    .checked_add(summary.final_amount)
                    .ok_or_else(|| TransactionError::Invalid("Provider balance overflow".into()))?;
                let refund = bond.amount - summary.final_amount;
                let payer_base = if payer_k == provider_k {
                    new_provider_bal
                } else {
                    read_balance(&*state, &payer_k)?
                };
                let new_payer_bal = payer_base
                    .checked_add(refund)
                    .ok_or_else(|| TransactionError::Invalid("Payer balance overflow".into()))?;
                let provider_bytes = encode_balance(&new_provider_bal)?;
                let payer_bytes = encode_balance(&new_payer_bal)?;
                let tombstone = codec::to_bytes_canonical(&ctx.block_height)
                    .map_err(TransactionError::Serialization)?;

                // Writes (R4): pay, refund, close the bond, tombstone the session id.
                state.insert(&provider_k, &provider_bytes)?;
                if refund > 0 {
                    state.insert(&payer_k, &payer_bytes)?;
                }
                state.delete(&bond_k)?;
                state.insert(&settled_key(&summary.session_id), &tombstone)?;
            }

            // Mark a session as disputed. Every refusal precedes the first write.
            // FU-N5-1: frozen, fail-closed. No arm releases or resolves a dispute (that
            // needs the judiciary design), so a disputed bond and the debited appeal bond
            // stay locked: never paid out, refunded, re-bonded or drawable.
            SettlementPayload::Escalate {
                session_id,
                evidence: _,
                bond: appeal_bond,
            } => {
                let bond_k = bond_key(session_id);
                let dispute_k = dispute_key(session_id);
                // R9 (second-Escalate arm): a session already under dispute.
                if state.get(&dispute_k)?.is_some() {
                    return Err(TransactionError::Invalid(
                        "Session is already under dispute".into(),
                    ));
                }
                // Pre-existing refusal (no R test): no open bond under this session id.
                let bond_bytes = state
                    .get(&bond_k)?
                    .ok_or(TransactionError::Invalid("Session bond not found".into()))?;
                let bond: BondRecordV1 = codec::from_bytes_canonical(&bond_bytes)
                    .map_err(TransactionError::Deserialization)?;

                let signer = ctx.signer_account_id;
                // R6a: only the bond's payer or provider may escalate.
                if signer != bond.payer && signer != bond.provider_id {
                    return Err(TransactionError::Invalid(
                        "Escalation signer is not a party to the session".into(),
                    ));
                }
                let signer_k = balance_key(&signer);
                let signer_bal = read_balance(&*state, &signer_k)?;
                // New (no R test of its own): the signer must cover the appeal bond.
                if signer_bal < *appeal_bond {
                    return Err(TransactionError::InsufficientFunds);
                }
                let new_signer_bal = encode_balance(&(signer_bal - *appeal_bond))?;

                // Writes (R6b): debit the appeal bond, move the bond record unchanged.
                state.insert(&signer_k, &new_signer_bal)?;
                state.delete(&bond_k)?;
                state.insert(&dispute_k, &bond_bytes)?;
            }

            // [NEW] UpgradeLiability Payload
            // Allows upgrading a prior receipt or action to a higher liability level (Tier 2->3).
            SettlementPayload::UpgradeLiability {
                receipt,
                target_level: _,
                bond_amount,
                zk_proof,
            } => {
                // 1. Check if the receipt is valid and not already disputed
                // (Simplified: check if receipt hash exists in a local log or recent blocks cache)

                // 2. Process Bond (if target_level requires it)
                if let Some(amount) = bond_amount {
                    let sender = ctx.signer_account_id;
                    let sender_key = [b"balance::", sender.as_ref()].concat();
                    let sender_bal: u128 = state
                        .get(&sender_key)?
                        .and_then(|b| codec::from_bytes_canonical(&b).ok())
                        .unwrap_or(0);

                    if sender_bal < *amount {
                        return Err(TransactionError::InsufficientFunds);
                    }

                    let new_sender_bal = sender_bal - amount;
                    state.insert(
                        &sender_key,
                        &codec::to_bytes_canonical(&new_sender_bal).unwrap(),
                    )?;

                    // Store the upgrade bond
                    let upgrade_key = [
                        b"liability::upgrade::",
                        receipt.canonical_payload_hash.as_ref(),
                    ]
                    .concat();
                    state.insert(&upgrade_key, &codec::to_bytes_canonical(amount).unwrap())?;
                }

                // 3. Process ZK Proof (if target_level requires it)
                if let Some(proof) = zk_proof {
                    // In a real implementation, this would invoke the verifier registry.
                    // For now, we just log that a proof was submitted.
                    let proof_key = [
                        b"liability::proof::",
                        receipt.canonical_payload_hash.as_ref(),
                    ]
                    .concat();
                    state.insert(&proof_key, &proof)?;
                }
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

#[cfg(test)]
mod tests;
