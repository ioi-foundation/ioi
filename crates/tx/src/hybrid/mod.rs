// Path: crates/tx/src/hybrid/mod.rs
use crate::account::{AccountConfig, AccountModel, AccountTransaction, AccountTransactionProof};
use crate::utxo::{UTXOConfig, UTXOModel, UTXOTransaction, UTXOTransactionProof};
use async_trait::async_trait;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{ProofProvider, StateAccess, StateManager};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum HybridTransaction {
    Account(AccountTransaction),
    UTXO(UTXOTransaction),
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub enum HybridProof<AP, UP> {
    Account(AccountTransactionProof<AP>),
    UTXO(UTXOTransactionProof<UP>),
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

#[async_trait]
impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for HybridModel<CS>
where
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Encode + Decode + Debug,
{
    type Transaction = HybridTransaction;
    type CommitmentScheme = CS;
    type Proof = HybridProof<CS::Proof, CS::Proof>;

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

    fn validate_stateless(&self, tx: &Self::Transaction) -> Result<(), TransactionError> {
        match tx {
            HybridTransaction::Account(account_tx) => {
                self.account_model.validate_stateless(account_tx)
            }
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.validate_stateless(utxo_tx),
        }
    }

    async fn apply_payload<ST, CV>(
        &self,
        chain: &CV,
        state: &mut dyn StateAccess,
        tx: &Self::Transaction,
        ctx: &mut TxContext<'_>,
    ) -> Result<(Self::Proof, u64), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ProofProvider
            + Send
            + Sync
            + 'static,
        CV: ioi_api::chain::ChainView<Self::CommitmentScheme, ST> + Send + Sync + ?Sized,
    {
        match tx {
            HybridTransaction::Account(account_tx) => {
                let (proof, gas) = self
                    .account_model
                    .apply_payload(chain, state, account_tx, ctx)
                    .await?;
                Ok((HybridProof::Account(proof), gas))
            }
            HybridTransaction::UTXO(utxo_tx) => {
                let (proof, gas) = self
                    .utxo_model
                    .apply_payload(chain, state, utxo_tx, ctx)
                    .await?;
                Ok((HybridProof::UTXO(proof), gas))
            }
        }
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        codec::to_bytes_canonical(tx).map_err(TransactionError::Serialization)
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        codec::from_bytes_canonical(data)
            .map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}