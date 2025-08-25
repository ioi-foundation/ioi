// Path: crates/transaction_models/src/account/mod.rs
use async_trait::async_trait;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_types::error::TransactionError;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccountTransaction {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub amount: u64,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
}

// NEW: Define the proof structure for an account-based transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountTransactionProof<P> {
    /// The state key for the sender's account.
    pub account_key: Vec<u8>,
    /// The serialized `Account` state *before* the transaction.
    pub account_value: Vec<u8>,
    /// The cryptographic inclusion proof from the state manager.
    pub inclusion_proof: P,
}

#[derive(Debug, Clone, Default)]
pub struct AccountConfig {
    pub initial_balance: u64,
}

#[derive(Debug, Clone)]
pub struct AccountModel<CS: CommitmentScheme> {
    config: AccountConfig,
    _commitment_scheme: CS,
}

impl<CS: CommitmentScheme> AccountModel<CS> {
    pub fn new(commitment_scheme: CS) -> Self {
        Self {
            config: AccountConfig::default(),
            _commitment_scheme: commitment_scheme,
        }
    }

    pub fn with_config(commitment_scheme: CS, config: AccountConfig) -> Self {
        Self {
            config,
            _commitment_scheme: commitment_scheme,
        }
    }

    fn get_account<S: StateManager + ?Sized>(
        &self,
        state: &S,
        key: &[u8],
    ) -> Result<Account, TransactionError> {
        let value = state.get(key)?;
        match value {
            Some(data) => self.decode_account(&data),
            None => Ok(Account {
                balance: self.config.initial_balance,
                nonce: 0,
            }),
        }
    }

    fn decode_account(&self, data: &[u8]) -> Result<Account, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn encode_account(&self, account: &Account) -> Vec<u8> {
        serde_json::to_vec(account).unwrap()
    }
}

#[async_trait]
impl<CS: CommitmentScheme + Send + Sync> TransactionModel for AccountModel<CS>
where
    // Add this bound so we can serialize the proof
    <CS as CommitmentScheme>::Proof: Serialize + for<'de> Deserialize<'de>,
{
    type Transaction = AccountTransaction;
    type CommitmentScheme = CS;
    // UPDATE: Use our new generic proof structure.
    type Proof = AccountTransactionProof<CS::Proof>;

    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        let sender_account = self.get_account(state, &tx.from)?;
        if sender_account.balance < tx.amount {
            return Err(TransactionError::Invalid(
                "Insufficient balance".to_string(),
            ));
        }
        if sender_account.nonce != tx.nonce {
            return Err(TransactionError::Invalid("Invalid nonce".to_string()));
        }
        Ok(())
    }

    async fn apply<ST>(
        &self,
        tx: &Self::Transaction,
        workload: &WorkloadContainer<ST>,
        _block_height: u64,
    ) -> Result<(), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + Send
            + Sync
            + 'static,
    {
        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;
        self.validate(tx, &*state)?;

        let sender_key = tx.from.clone();
        let mut sender_account = self.get_account(&*state, &sender_key)?;
        sender_account.balance -= tx.amount;
        sender_account.nonce += 1;
        state.insert(&sender_key, &self.encode_account(&sender_account))?;

        let receiver_key = tx.to.clone();
        let mut receiver_account = self.get_account(&*state, &receiver_key)?;
        receiver_account.balance = receiver_account
            .balance
            .checked_add(tx.amount)
            .ok_or(TransactionError::Invalid("Balance overflow".to_string()))?;
        state.insert(&receiver_key, &self.encode_account(&receiver_account))?;

        Ok(())
    }

    fn create_coinbase_transaction(
        &self,
        _block_height: u64,
        _recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        Err(TransactionError::Invalid(
            "Coinbase not supported for account model".to_string(),
        ))
    }

    // IMPLEMENT: generate_proof
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
        // 1. Get the sender's account key.
        let key = tx.from.clone();

        // 2. Fetch the sender's account state from the state manager.
        let value = state.get(&key)?.ok_or_else(|| {
            TransactionError::Invalid("Sender account for proof generation not found".to_string())
        })?;

        // 3. Create the inclusion proof for that key-value pair.
        let inclusion_proof = state.create_proof(&key).ok_or_else(|| {
            TransactionError::Invalid("Failed to create inclusion proof for account".to_string())
        })?;

        Ok(AccountTransactionProof {
            account_key: key,
            account_value: value,
            inclusion_proof,
        })
    }

    // IMPLEMENT: verify_proof
    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        // 1. Get the state root we are verifying against.
        let root_commitment = state.root_commitment();

        // 2. Verify the account's inclusion proof.
        let is_valid = state.verify_proof(
            // <-- FIX: Call verify_proof as a method on the state object
            &root_commitment,
            &proof.inclusion_proof,
            &proof.account_key,
            &proof.account_value,
        );

        Ok(is_valid)
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}
