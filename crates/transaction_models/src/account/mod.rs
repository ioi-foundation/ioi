// Path: crates/transaction_models/src/account/mod.rs
use async_trait::async_trait;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_types::codec;
use depin_sdk_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AccountTransaction {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub amount: u64,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountTransactionProof<P> {
    pub account_key: Vec<u8>,
    pub account_value: Vec<u8>,
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

    fn get_account<S: StateAccessor + ?Sized>(
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
        codec::from_bytes_canonical(data)
            .map_err(|e| TransactionError::Deserialization(e.to_string()))
    }

    fn encode_account(&self, account: &Account) -> Vec<u8> {
        codec::to_bytes_canonical(account)
    }
}

#[async_trait]
impl<CS: CommitmentScheme + Send + Sync> TransactionModel for AccountModel<CS>
where
    <CS as CommitmentScheme>::Proof: Serialize + for<'de> Deserialize<'de>,
{
    type Transaction = AccountTransaction;
    type CommitmentScheme = CS;
    type Proof = AccountTransactionProof<CS::Proof>;

    fn validate_stateless(&self, _tx: &Self::Transaction) -> Result<(), TransactionError> {
        Ok(())
    }

    async fn apply_payload<ST, CV>(
        &self,
        _chain: &CV,
        state: &mut dyn StateAccessor,
        tx: &Self::Transaction,
        _ctx: TxContext<'_>,
    ) -> Result<(), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + Send
            + Sync
            + 'static,
        CV: depin_sdk_api::chain::ChainView<Self::CommitmentScheme, ST> + Send + Sync + ?Sized,
    {
        // Perform stateful validation just-in-time
        let sender_account = self.get_account(state, &tx.from)?;
        if sender_account.balance < tx.amount {
            return Err(TransactionError::Invalid(
                "Insufficient balance".to_string(),
            ));
        }
        if sender_account.nonce != tx.nonce {
            return Err(TransactionError::Invalid("Invalid nonce".to_string()));
        }

        // Apply state changes
        let mut new_sender_account = sender_account;
        new_sender_account.balance -= tx.amount;
        new_sender_account.nonce += 1;
        state.insert(&tx.from, &self.encode_account(&new_sender_account))?;

        let mut receiver_account = self.get_account(state, &tx.to)?;
        receiver_account.balance = receiver_account
            .balance
            .checked_add(tx.amount)
            .ok_or(TransactionError::Invalid("Balance overflow".to_string()))?;
        state.insert(&tx.to, &self.encode_account(&receiver_account))?;

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
        tx: &Self::Transaction,
        state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        let key = tx.from.clone();
        let value = state.get(&key)?.ok_or_else(|| {
            TransactionError::Invalid("Sender account for proof generation not found".to_string())
        })?;
        let inclusion_proof = state.create_proof(&key).ok_or_else(|| {
            TransactionError::Invalid("Failed to create inclusion proof for account".to_string())
        })?;
        Ok(AccountTransactionProof {
            account_key: key,
            account_value: value,
            inclusion_proof,
        })
    }

    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        let root_commitment = state.root_commitment();
        let is_valid = state.verify_proof(
            &root_commitment,
            &proof.inclusion_proof,
            &proof.account_key,
            &proof.account_value,
        );
        Ok(is_valid)
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        Ok(codec::to_bytes_canonical(tx))
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        codec::from_bytes_canonical(data)
            .map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}