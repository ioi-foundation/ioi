// Path: crates/transaction_models/src/hybrid/mod.rs

use crate::account::{AccountConfig, AccountModel, AccountTransaction};
use crate::utxo::{UTXOConfig, UTXOModel, UTXOTransaction};
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::TransactionError;
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HybridTransaction {
    Account(AccountTransaction),
    UTXO(UTXOTransaction),
}

#[derive(Debug, Clone)]
pub enum HybridProof {
    // FIX: Match the inner models' proof types, which are now `()`.
    Account(()),
    UTXO(()),
}

#[derive(Debug, Clone, Default)]
pub struct HybridConfig {
    pub account_config: AccountConfig,
    pub utxo_config: UTXOConfig,
}

#[derive(Debug, Clone)]
pub struct HybridModel<CS: CommitmentScheme> {
    account_model: AccountModel<CS>,
    utxo_model: UTXOModel<CS>,
}

impl<CS: CommitmentScheme + Clone> HybridModel<CS> {
    pub fn new(scheme: CS) -> Self {
        Self {
            account_model: AccountModel::new(scheme.clone()),
            utxo_model: UTXOModel::new(scheme),
        }
    }
    pub fn with_config(scheme: CS, config: HybridConfig) -> Self {
        Self {
            account_model: AccountModel::with_config(scheme.clone(), config.account_config),
            utxo_model: UTXOModel::with_config(scheme, config.utxo_config),
        }
    }
}

impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for HybridModel<CS> {
    type Transaction = HybridTransaction;
    type CommitmentScheme = CS;
    type Proof = HybridProof;

    fn create_coinbase_transaction(
        &self,
        block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        let utxo_coinbase = self
            .utxo_model
            .create_coinbase_transaction(block_height, recipient)?;
        Ok(HybridTransaction::UTXO(utxo_coinbase))
    }

    // FIX: Add the required `where` clause to the method signature.
    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            HybridTransaction::Account(account_tx) => self.account_model.validate(account_tx, state),
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.validate(utxo_tx, state),
        }
    }

    // FIX: Add the required `where` clause.
    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            HybridTransaction::Account(account_tx) => self.account_model.apply(account_tx, state),
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.apply(utxo_tx, state),
        }
    }

    // FIX: Add the required `where` clause.
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
        match tx {
            HybridTransaction::Account(account_tx) => {
                self.account_model.generate_proof(account_tx, state)?;
                Ok(HybridProof::Account(()))
            }
            HybridTransaction::UTXO(utxo_tx) => {
                self.utxo_model.generate_proof(utxo_tx, state)?;
                Ok(HybridProof::UTXO(()))
            }
        }
    }

    // FIX: Add the required `where` clause.
    fn verify_proof<S>(
        &self,
        proof: &Self::Proof,
        state: &S,
    ) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match proof {
            HybridProof::Account(account_proof) => {
                self.account_model.verify_proof(account_proof, state)
            }
            HybridProof::UTXO(utxo_proof) => self.utxo_model.verify_proof(utxo_proof, state),
        }
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}