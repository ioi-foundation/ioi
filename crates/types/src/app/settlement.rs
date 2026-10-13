// Path: crates/types/src/app/settlement.rs
use crate::app::{AccountId, Receipt, SettlementSummary, SignatureProof};
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
    ///
    /// The transaction signer is the payer: the bond is debited from the signer's
    /// balance, and the bond record names the signer as payer and `provider_id` as
    /// the counterparty. A `session_id` is single-use: it is refused while a bond or
    /// a dispute is open under it, and after it has been settled.
    Commit {
        /// The unique ID of the session or task being bonded.
        session_id: [u8; 32],
        /// The counterparty the bond backs: the only provider a cooperative close
        /// of this session may pay.
        provider_id: AccountId,
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
    ///
    /// Only a cooperative close (`summary.mode == 0`) is accepted; a unilateral close
    /// has no challenge window and is refused. Both signatures are over the same
    /// domain-separated message:
    ///
    /// `b"ioi::settlement::summary::v1\0" ‖ SCALE(chain_id) ‖ SCALE(summary) ‖ SCALE(expires_at_height)`
    ///
    /// where `chain_id` is the executing chain's `ChainId` (4-byte little-endian `u32`)
    /// and `expires_at_height` is an 8-byte little-endian `u64`. The summary's
    /// `payer_id` and `provider_id` must equal the payer and provider recorded in the
    /// session's bond. Any account may relay a doubly-signed summary.
    Settle {
        /// The final accounting statement agreed upon by both parties.
        summary: SettlementSummary,
        /// The last block height at which this authorization may execute. It is part of
        /// the signed message, so it cannot be extended by the relayer.
        expires_at_height: u64,
        /// The signature of the Payer (User Node) authorizing payment, made with the
        /// payer account's active credential.
        payer_sig: SignatureProof,
        /// The signature of the Provider Node claiming payment, made with the
        /// provider account's active credential.
        provider_sig: SignatureProof,
    },

    /// Rung 4: Dispute Escalation (The "Lawsuit").
    /// Submitting a Challenge Package to the Judiciary for arbitration.
    /// Defined in Whitepaper §10.2.2.
    ///
    /// The signer must be the session's payer or provider; the appeal `bond` is
    /// debited from the signer, and the session's bond moves to the dispute record.
    /// No release or resolution path for a dispute exists yet (named residual
    /// FU-N5-1): a disputed bond is frozen.
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

    /// [NEW] UpgradeLiability Payload
    /// Allows upgrading a prior receipt or action to a higher liability level (Tier 2->3).
    UpgradeLiability {
        /// The receipt of the action to upgrade.
        receipt: Receipt,
        /// The target liability level (e.g., 3 for Cross-Chain).
        target_level: u8,
        /// Optional additional bond amount required for the upgrade.
        bond_amount: Option<u128>,
        /// Optional ZK proof verifying the validity of the upgrade.
        zk_proof: Option<Vec<u8>>,
    },
}
