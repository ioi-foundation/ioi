//! Hybrid transaction model implementation

use std::fmt::Debug;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::state::StateManager;
use crate::utxo::{UTXOModel, UTXOTransaction, UTXOProof};
use crate::account::{AccountModel, AccountTransaction, AccountProof};

/// Hybrid transaction enum
#[derive(Debug, Clone)]
pub enum HybridTransaction<CS: CommitmentScheme> {
    /// UTXO-based transaction
    UTXO(UTXOTransaction),
    /// Account-based transaction
    Account(AccountTransaction),
}

/// Hybrid proof enum
#[derive(Debug, Clone)]
pub enum HybridProof<CS: CommitmentScheme> {
    /// UTXO-based proof
    UTXO(UTXOProof<CS::Proof>),
    /// Account-based proof
    Account(AccountProof<CS::Proof>),
}

/// Hybrid transaction model with any commitment scheme
pub struct HybridModel<CS: CommitmentScheme> {
    /// UTXO model
    utxo_model: UTXOModel<CS>,
    /// Account model
    account_model: AccountModel<CS>,
}

impl<CS: CommitmentScheme> HybridModel<CS> {
    /// Create a new hybrid model
    pub fn new(commitment_scheme: CS) -> Self {
        Self {
            utxo_model: UTXOModel::new(commitment_scheme.clone()),
            account_model: AccountModel::new(commitment_scheme),
        }
    }
}

impl<CS: CommitmentScheme> TransactionModel<CS> for HybridModel<CS> {
    type Transaction = HybridTransaction<CS>;
    type Proof = HybridProof<CS>;
    
    fn validate(&self, tx: &Self::Transaction, commitment: &CS::Commitment) -> bool {
        // Delegate to the appropriate model based on transaction type
        match tx {
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.validate(utxo_tx, commitment),
            HybridTransaction::Account(account_tx) => self.account_model.validate(account_tx, commitment),
        }
    }
    
    fn apply(&self, tx: &Self::Transaction, state: &mut dyn StateManager<CS>) -> Result<(), String> {
        // Delegate to the appropriate model based on transaction type
        match tx {
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.apply(utxo_tx, state),
            HybridTransaction::Account(account_tx) => self.account_model.apply(account_tx, state),
        }
    }
}
