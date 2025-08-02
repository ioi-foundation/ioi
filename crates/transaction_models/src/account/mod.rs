// Path: crates/transaction_models/src/account/mod.rs
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
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

impl<CS: CommitmentScheme + Send + Sync> TransactionModel for AccountModel<CS> {
    type Transaction = AccountTransaction;
    type CommitmentScheme = CS;
    type Proof = ();

    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
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
        Ok(true)
    }

    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        if !self.validate(tx, state)? {
            return Err(TransactionError::Invalid("Validation failed".to_string()));
        }

        let sender_key = tx.from.clone();
        let mut sender_account = self.get_account(state, &sender_key)?;
        sender_account.balance -= tx.amount;
        sender_account.nonce += 1;
        state.insert(&sender_key, &self.encode_account(&sender_account))?;

        let receiver_key = tx.to.clone();
        let mut receiver_account = self.get_account(state, &receiver_key)?;
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

    fn generate_proof<S>(
        &self,
        _tx: &Self::Transaction,
        _state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        Ok(())
    }

    fn verify_proof<S>(&self, _proof: &Self::Proof, _state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        Ok(true)
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}
