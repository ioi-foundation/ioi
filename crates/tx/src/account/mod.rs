// Path: crates/tx/src/account/mod.rs
use async_trait::async_trait;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{ProofProvider, StateAccess, StateManager};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_types::codec;
use ioi_types::error::TransactionError;
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
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct AccountTransactionProof<P> {
    pub account_key: Vec<u8>,
    pub account_value: Option<Vec<u8>>, // None means non-membership
    pub membership_proof: P,
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

    fn get_account<S: StateAccess + ?Sized>(
        &self,
        state: &S,
        key: &[u8],
    ) -> Result<Account, TransactionError> {
        let value = state.get(key)?;
        match value {
            Some(data) => self.decode_account(&data),
            None => Ok(Account {
                balance: self.config.initial_balance,
            }),
        }
    }

    fn decode_account(&self, data: &[u8]) -> Result<Account, TransactionError> {
        codec::from_bytes_canonical(data)
            .map_err(|e| TransactionError::Deserialization(e.to_string()))
    }

    fn encode_account(&self, account: &Account) -> Result<Vec<u8>, TransactionError> {
        codec::to_bytes_canonical(account).map_err(TransactionError::Serialization)
    }
}

#[async_trait]
impl<CS: CommitmentScheme + Send + Sync> TransactionModel for AccountModel<CS>
where
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Encode + Decode + std::fmt::Debug,
{
    type Transaction = AccountTransaction;
    type CommitmentScheme = CS;
    type Proof = AccountTransactionProof<CS::Proof>;

    fn validate_stateless(&self, _tx: &Self::Transaction) -> Result<(), TransactionError> {
        Ok(())
    }

    async fn apply_payload<ST, CV>(
        &self,
        chain: &CV,
        state: &mut dyn StateAccess,
        tx: &Self::Transaction,
        _ctx: &mut TxContext<'_>,
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
        // --- 1) Read pre-state via overlay (for execution logic) ---
        let sender_account = self.get_account(state, &tx.from)?;

        // --- 2) Generate anchored proof from the immutable backend ---
        let backend_arc = chain.workload_container().state_tree();
        let backend_guard = backend_arc.read().await;
        let backend = &*backend_guard;
        let pre_root = backend.root_commitment();
        let (membership, membership_proof) = backend
            .get_with_proof_at(&pre_root, &tx.from)
            .map_err(TransactionError::State)?;
        let account_value = match membership {
            ioi_types::app::Membership::Present(v) => Some(v),
            ioi_types::app::Membership::Absent => None,
        };
        let proof = AccountTransactionProof {
            account_key: tx.from.clone(),
            account_value,
            membership_proof,
        };

        // --- 3) Stateful checks (NO nonce check here; it's an ante handler concern) ---
        if sender_account.balance < tx.amount {
            return Err(TransactionError::InsufficientFunds);
        }

        // --- 4) Apply writes to overlay ---
        let mut new_sender_account = sender_account;
        new_sender_account.balance -= tx.amount;
        state.insert(&tx.from, &self.encode_account(&new_sender_account)?)?;

        let mut receiver_account = self.get_account(state, &tx.to)?;
        receiver_account.balance = receiver_account
            .balance
            .checked_add(tx.amount)
            .ok_or(TransactionError::BalanceOverflow)?;
        state.insert(&tx.to, &self.encode_account(&receiver_account)?)?;

        // TODO: Calculate actual gas usage
        Ok((proof, 0))
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

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        codec::to_bytes_canonical(tx).map_err(TransactionError::Serialization)
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        codec::from_bytes_canonical(data)
            .map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}