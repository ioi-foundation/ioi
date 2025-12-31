// Path: crates/types/src/app/settlement.rs
use crate::app::{AccountId, Receipt, SettlementSummary};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The specific action being requested by a SettlementTransaction.
///
/// This enum maps directly to the "Verification Ladder" defined in the Whitepaper (§7).
/// It enables agents to escalate the level of economic finality for their actions.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SettlementPayload {
    /// Rung 0: Simple Transfer (The "Gas" funding mechanism).
    /// Used to fund Validator or User accounts to pay for network services.
    Transfer {
        /// The destination account ID.
        to: AccountId,
        /// The amount of tokens to transfer.
        amount: u128,
    },

    /// Rung 2: Bonded Commitment (The "Promise").
    /// An agent locks funds to back a stream of off-chain work.
    /// Defined in Whitepaper §8 (Artifact Hierarchy).
    Commit {
        /// The unique ID of the session or task being bonded.
        session_id: [u8; 32],
        /// The amount of Labor Gas tokens locked as collateral.
        bond_amount: u128,
        /// The hash of the policy rules governing slashing conditions.
        policy_hash: [u8; 32],
        /// The Merkle root of the off-chain receipt history accumulated so far.
        receipt_root: [u8; 32],
    },

    /// Rung 2/3: Session Settlement (The "Invoice").
    /// Cooperative close of a state channel or burst session.
    /// Defined in Whitepaper §3.2.4 (SettlementSummary).
    Settle {
        /// The final accounting statement agreed upon by both parties.
        summary: SettlementSummary,
        /// The signature of the Payer (User Node) authorizing payment.
        payer_sig: Vec<u8>,
        /// The signature of the Provider Node claiming payment.
        provider_sig: Vec<u8>,
    },

    /// Rung 4: Dispute Escalation (The "Lawsuit").
    /// Submitting a Challenge Package to the Judiciary for arbitration.
    /// Defined in Whitepaper §10.2.2.
    Escalate {
        /// The ID of the session being disputed.
        session_id: [u8; 32],
        /// The "Challenge Package" containing the contested receipt and proof.
        evidence: super::ChallengePackage,
        /// The "Appeal Bond" required to pay for arbitration costs if the challenge is frivolous.
        bond: u128,
    },

    /// Rung 3: Cross-Chain Intent (The "Export").
    /// An agent proves it has the right to move funds or state to another chain (Atomic Composability).
    /// Defined in Whitepaper §4.4.2.
    Bridge {
        /// The identifier of the target chain (e.g., "eth-mainnet", "cosmoshub-4").
        target_chain: String,
        /// The raw payload for the target chain (e.g., EVM CallData, IBC Packet).
        payload: Vec<u8>,
        /// The receipt proving the agent generated this intent correctly under policy.
        receipt: Receipt,
    },
}
