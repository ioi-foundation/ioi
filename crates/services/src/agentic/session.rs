// Path: crates/services/src/agentic/session.rs

use ioi_api::{
    crypto::{SerializableKey, VerifyingKey},
    state::StateAccess,
};
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_types::{app::AccountId, codec, error::TransactionError};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// An incremental promise to pay for work within a session.
/// Matches Whitepaper §3.2.6 Normative Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PaymentTicket {
    /// Unique session identifier.
    pub session_id: [u8; 32],
    /// Identity of the provider being paid.
    pub provider_id: AccountId,
    /// Hash binding the ticket to pricing and dispute rules.
    pub terms_hash: [u8; 32],
    /// Monotonic counter to prevent replay.
    pub seq: u64,
    /// Total cumulative amount authorized for this session so far.
    pub cumulative_amount: u128,
    /// Merkle root of the receipt history included in this payment step.
    pub receipt_root: [u8; 32],
    /// Signature from the Payer authorizing this ticket.
    pub payer_sig: Vec<u8>,
}

impl PaymentTicket {
    /// Serializes the ticket for signing (excluding the signature itself).
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut temp = self.clone();
        temp.payer_sig = Vec::new();
        codec::to_bytes_canonical(&temp).map_err(TransactionError::Serialization)
    }

    /// Verifies the ticket against the Payer's public key and session state.
    pub fn verify(
        &self,
        payer_pk: &[u8],
        expected_provider: &AccountId,
        last_seq: u64,
        last_amount: u128,
    ) -> Result<(), TransactionError> {
        // 1. Identity Binding
        if &self.provider_id != expected_provider {
            return Err(TransactionError::Invalid("Provider ID mismatch".into()));
        }

        // 2. Monotonicity Check (§3.2.2)
        if self.seq <= last_seq {
            return Err(TransactionError::Invalid(format!(
                "Non-monotonic sequence: {} <= {}",
                self.seq, last_seq
            )));
        }
        if self.cumulative_amount < last_amount {
            return Err(TransactionError::Invalid(format!(
                "Non-monotonic amount: {} < {}",
                self.cumulative_amount, last_amount
            )));
        }

        // 3. Signature Verification
        let sign_bytes = self.to_sign_bytes()?;

        // For Phase 1, we assume Ed25519. In full implementation, we'd check the suite.
        let pk = Ed25519PublicKey::from_bytes(payer_pk)
            .map_err(|e| TransactionError::Invalid(format!("Invalid public key: {}", e)))?;

        let sig = Ed25519Signature::from_bytes(&self.payer_sig)
            .map_err(|e| TransactionError::Invalid(format!("Invalid signature format: {}", e)))?;

        pk.verify(&sign_bytes, &sig)
            .map_err(|e| TransactionError::InvalidSignature(e.to_string()))
    }
}

/// Helper to check if the payer has enough balance on Mainnet to cover the commitment.
/// This connects the off-chain session to the on-chain settlement layer.
pub fn check_solvency(
    state: &dyn StateAccess,
    payer_id: &AccountId,
    amount: u128,
) -> Result<(), TransactionError> {
    // In the Settlement Model, balance key is "balance::{account_id}"
    let key = [b"balance::", payer_id.as_ref()].concat();

    let balance_bytes = state
        .get(&key)
        .map_err(TransactionError::State)?
        .ok_or(TransactionError::InsufficientFunds)?;

    let balance: u128 = codec::from_bytes_canonical(&balance_bytes)
        .map_err(|_| TransactionError::Deserialization("Invalid balance format".into()))?;

    if balance < amount {
        return Err(TransactionError::InsufficientFunds);
    }

    Ok(())
}
