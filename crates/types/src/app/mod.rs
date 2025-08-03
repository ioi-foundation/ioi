// Path: crates/core/src/app/mod.rs
//! Core application-level data structures like Blocks and Transactions.

use dcrypt::algorithms::hash::{sha2::Sha256 as DcryptSha256, HashFunction};
use dcrypt::algorithms::ByteSerializable;
use serde::{Deserialize, Serialize};

/// Represents the current status of the blockchain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChainStatus {
    /// The current block height.
    pub height: u64,
    /// The timestamp of the latest block.
    pub latest_timestamp: u64,
    /// The total number of transactions processed.
    pub total_transactions: u64,
    /// A flag indicating if the chain is actively running.
    pub is_running: bool,
}

/// A block in the blockchain, generic over the transaction type.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Block<T: Clone> {
    /// The header of the block containing metadata.
    pub header: BlockHeader,
    /// A list of transactions included in the block.
    pub transactions: Vec<T>,
}

/// The header of a block, containing metadata and commitments.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// The height of this block.
    pub height: u64,
    /// The hash of the previous block's header.
    pub prev_hash: Vec<u8>,
    /// The root hash of the state tree after applying this block's transactions.
    pub state_root: Vec<u8>,
    /// The root hash of the transactions in this block.
    pub transactions_root: Vec<u8>,
    /// The timestamp when the block was created.
    pub timestamp: u64,
    /// The full, sorted list of PeerIds (in bytes) that constituted the validator
    /// set when this block was created.
    pub validator_set: Vec<Vec<u8>>,
}

/// An input for a UTXO transaction, pointing to a previous output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The hash of the transaction containing the output being spent.
    pub tx_hash: Vec<u8>,
    /// The index of the output in the previous transaction.
    pub output_index: u32,
    /// The signature authorizing the spending of the output.
    pub signature: Vec<u8>,
}

/// An output for a UTXO transaction, creating a new unspent output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The value of the output.
    pub value: u64,
    /// The public key of the recipient.
    pub public_key: Vec<u8>,
}

/// A transaction following the UTXO model.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UTXOTransaction {
    /// A list of inputs to be spent.
    pub inputs: Vec<Input>,
    /// A list of new outputs to be created.
    pub outputs: Vec<Output>,
}

impl UTXOTransaction {
    /// Computes the hash of the transaction.
    pub fn hash(&self) -> Vec<u8> {
        let serialized = serde_json::to_vec(self).unwrap();
        DcryptSha256::digest(&serialized).unwrap().to_bytes()
    }
}

/// A top-level enum representing any transaction the chain can process.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolTransaction {
    /// A transaction initiated by a user or application.
    Application(ApplicationTransaction),
    /// A privileged transaction for system-level changes.
    System(SystemTransaction),
}

/// An enum wrapping all possible user-level transaction models.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ApplicationTransaction {
    /// A transaction for a UTXO-based ledger.
    UTXO(UTXOTransaction),
    /// A transaction to deploy a new smart contract.
    DeployContract {
        /// The bytecode of the contract.
        code: Vec<u8>,
        /// The signer's public key for signature verification.
        signer_pubkey: Vec<u8>,
        /// The transaction signature.
        signature: Vec<u8>,
    },
    /// A transaction to call a method on an existing smart contract.
    CallContract {
        /// The address of the contract to call.
        address: Vec<u8>,
        /// The ABI-encoded input data for the contract call.
        input_data: Vec<u8>,
        /// The maximum gas allowed for this transaction.
        gas_limit: u64,
        /// The signer's public key for signature verification.
        signer_pubkey: Vec<u8>,
        /// The transaction signature.
        signature: Vec<u8>,
    },
}

impl ApplicationTransaction {
    /// Creates a stable, serializable payload for signing by clearing signature fields.
    pub fn to_signature_payload(&self) -> Vec<u8> {
        let mut temp = self.clone();
        // Clear signature fields before serializing to create a stable payload
        match &mut temp {
            ApplicationTransaction::DeployContract {
                signer_pubkey,
                signature,
                ..
            } => {
                signer_pubkey.clear();
                signature.clear();
            }
            ApplicationTransaction::CallContract {
                signer_pubkey,
                signature,
                ..
            } => {
                signer_pubkey.clear();
                signature.clear();
            }
            ApplicationTransaction::UTXO(_) => {} // UTXO has its own signing mechanism
        }
        serde_json::to_vec(&temp).unwrap()
    }
}

/// A privileged transaction for performing system-level state changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SystemTransaction {
    /// The specific action being requested.
    pub payload: SystemPayload,
    /// A signature authorizing the action.
    pub signature: Vec<u8>,
}

/// The specific action being requested by a SystemTransaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SystemPayload {
    /// Updates the set of authorities for a Proof-of-Authority chain.
    UpdateAuthorities {
        /// The new list of authority PeerIDs.
        new_authorities: Vec<Vec<u8>>,
    },
    /// Stakes a certain amount for a validator.
    Stake {
        /// The amount to stake.
        amount: u64,
    },
    /// Unstakes a certain amount for a validator.
    Unstake {
        /// The amount to unstake.
        amount: u64,
    },
}