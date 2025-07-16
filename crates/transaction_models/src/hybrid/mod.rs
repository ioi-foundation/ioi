// Fixed implementation for hybrid transaction model

use crate::account::{AccountModel, AccountProof, AccountTransaction};
use crate::utxo::{UTXOModel, UTXOProof, UTXOTransaction};
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::TransactionError;
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use std::any::Any;

/// Hybrid transaction that can be either UTXO or account-based
#[derive(Debug, Clone)]
pub enum HybridTransaction {
    /// UTXO-based transaction
    UTXO(UTXOTransaction),
    /// Account-based transaction
    Account(AccountTransaction),
}

/// Hybrid proof that can be either UTXO or account-based
#[derive(Debug, Clone)]
pub enum HybridProof {
    /// UTXO-based proof
    UTXO(UTXOProof),
    /// Account-based proof
    Account(AccountProof),
}

/// Hybrid transaction model configuration
#[derive(Clone)]
pub struct HybridConfig {
    /// UTXO model configuration
    pub utxo_config: crate::utxo::UTXOConfig,
    /// Account model configuration
    pub account_config: crate::account::AccountConfig,
    /// Whether to enforce fee payment in UTXO mode
    pub require_fee: bool,
    /// Minimum fee amount (if required)
    pub min_fee: u64,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            utxo_config: crate::utxo::UTXOConfig::default(),
            account_config: crate::account::AccountConfig::default(),
            require_fee: false,
            min_fee: 0,
        }
    }
}

/// Hybrid-specific operations
pub trait HybridOperations {
    /// Get access to the underlying UTXO model.
    fn utxo_model(&self) -> &UTXOModel<Self::CommitmentScheme>;

    /// Get access to the underlying account model.
    fn account_model(&self) -> &AccountModel<Self::CommitmentScheme>;

    /// Associated type for the commitment scheme
    type CommitmentScheme: CommitmentScheme;

    /// Create a cross-model transaction (e.g., UTXO input with account output).
    ///
    /// This is a placeholder for more complex hybrid operations that might be
    /// supported in a real implementation.
    fn create_cross_model_transaction(&self) -> Result<HybridTransaction, TransactionError> {
        Err(TransactionError::Other("Not implemented".to_string()))
    }
}

/// Hybrid transaction model implementation
pub struct HybridModel<CS: CommitmentScheme + Clone> {
    /// UTXO model
    utxo_model: UTXOModel<CS>,
    /// Account model
    account_model: AccountModel<CS>,
    /// Model configuration
    config: HybridConfig,
    /// Commitment scheme
    scheme: CS,
}

impl<CS: CommitmentScheme + Clone> HybridModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new hybrid model with default configuration.
    pub fn new(scheme: CS) -> Self {
        Self {
            utxo_model: UTXOModel::new(scheme.clone()),
            account_model: AccountModel::new(scheme.clone()),
            config: HybridConfig::default(),
            scheme,
        }
    }

    /// Create a new hybrid model with custom configuration.
    pub fn with_config(scheme: CS, config: HybridConfig) -> Self {
        Self {
            utxo_model: UTXOModel::with_config(scheme.clone(), config.utxo_config.clone()),
            account_model: AccountModel::with_config(scheme.clone(), config.account_config.clone()),
            config,
            scheme,
        }
    }

    /// Get model configuration.
    pub fn config(&self) -> &HybridConfig {
        &self.config
    }

    /// Get the commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }
}

impl<CS: CommitmentScheme + Clone> TransactionModel for HybridModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Transaction = HybridTransaction;
    type Proof = HybridProof;
    type CommitmentScheme = CS;

    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.validate(utxo_tx, state),
            HybridTransaction::Account(account_tx) => {
                self.account_model.validate(account_tx, state)
            }
        }
    }

    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        // Additional hybrid-specific validation
        if self.config.require_fee {
            // Check if fee is paid (implementation depends on fee model)
            // This is a placeholder for a real fee verification
            let _fee_paid = match tx {
                HybridTransaction::UTXO(_utxo_tx) => {
                    // For UTXO, fee is implicit (input value - output value)
                    true
                }
                HybridTransaction::Account(_account_tx) => {
                    // For account, fee might be explicit or implicit
                    // This is a simplified check
                    true
                }
            };
        }

        // Delegate to appropriate model
        match tx {
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.apply(utxo_tx, state),
            HybridTransaction::Account(account_tx) => self.account_model.apply(account_tx, state),
        }
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
        match tx {
            HybridTransaction::UTXO(utxo_tx) => self
                .utxo_model
                .generate_proof(utxo_tx, state)
                .map(HybridProof::UTXO),
            HybridTransaction::Account(account_tx) => self
                .account_model
                .generate_proof(account_tx, state)
                .map(HybridProof::Account),
        }
    }

    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match proof {
            HybridProof::UTXO(utxo_proof) => self.utxo_model.verify_proof(utxo_proof, state),
            HybridProof::Account(account_proof) => {
                self.account_model.verify_proof(account_proof, state)
            }
        }
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        let mut data = Vec::new();

        match tx {
            HybridTransaction::UTXO(utxo_tx) => {
                // Add type byte (0 for UTXO)
                data.push(0);

                // Serialize UTXO transaction
                let utxo_data = self.utxo_model.serialize_transaction(utxo_tx)?;
                data.extend_from_slice(&utxo_data);
            }
            HybridTransaction::Account(account_tx) => {
                // Add type byte (1 for Account)
                data.push(1);

                // Serialize account transaction
                let account_data = self.account_model.serialize_transaction(account_tx)?;
                data.extend_from_slice(&account_data);
            }
        }

        Ok(data)
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        if data.is_empty() {
            return Err(TransactionError::SerializationError(
                "Empty data".to_string(),
            ));
        }

        let tx_type = data[0];
        let tx_data = &data[1..];

        match tx_type {
            0 => {
                // UTXO transaction
                let utxo_tx = self.utxo_model.deserialize_transaction(tx_data)?;
                Ok(HybridTransaction::UTXO(utxo_tx))
            }
            1 => {
                // Account transaction
                let account_tx = self.account_model.deserialize_transaction(tx_data)?;
                Ok(HybridTransaction::Account(account_tx))
            }
            _ => Err(TransactionError::SerializationError(format!(
                "Unknown transaction type: {}",
                tx_type
            ))),
        }
    }

    fn get_model_extensions(&self) -> Option<&dyn Any> {
        Some(self as &dyn Any)
    }
}

impl<CS: CommitmentScheme + Clone> HybridOperations for HybridModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type CommitmentScheme = CS;

    fn utxo_model(&self) -> &UTXOModel<Self::CommitmentScheme> {
        &self.utxo_model
    }

    fn account_model(&self) -> &AccountModel<Self::CommitmentScheme> {
        &self.account_model
    }
}
