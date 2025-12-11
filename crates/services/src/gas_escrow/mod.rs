// Path: crates/services/src/gas_escrow/mod.rs
use async_trait::async_trait;
use ioi_api::impl_service_base;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::keys::{ACCOUNT_KEY_PREFIX, GAS_ESCROW_KEY_PREFIX};
use parity_scale_codec::{Decode, Encode};

#[derive(Encode, Decode, Debug, Default, Clone)]
pub struct Account {
    pub balance: u64,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct EscrowEntry {
    pub account: Vec<u8>,
    pub amount: u64,
}

pub trait GasEscrowHandler: BlockchainService {
    fn bond<S: StateAccess + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        max_gas: u64,
    ) -> Result<(), TransactionError>;

    fn settle<S: StateAccess + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        gas_used: u64,
        quality_score: f32,
    ) -> Result<(), TransactionError>;
}

pub struct GasEscrowService;

impl GasEscrowService {
    fn account_key(user_account: &[u8]) -> Vec<u8> {
        [ACCOUNT_KEY_PREFIX, user_account].concat()
    }
    fn escrow_key(user_account: &[u8]) -> Vec<u8> {
        [GAS_ESCROW_KEY_PREFIX, user_account].concat()
    }
    fn get_account<S: StateAccess + ?Sized>(
        &self,
        state: &S,
        user_account: &[u8],
    ) -> Result<Account, TransactionError> {
        let key = Self::account_key(user_account);
        let bytes = state
            .get(&key)
            .map_err(TransactionError::State)?
            .unwrap_or_default();
        codec::from_bytes_canonical(&bytes)
            .map_err(|e| TransactionError::Deserialization(e))
            .or(Ok(Account::default()))
    }
}

impl_service_base!(GasEscrowService, "gas_escrow");

#[async_trait]
impl UpgradableService for GasEscrowService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(vec![])
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

impl GasEscrowHandler for GasEscrowService {
    fn bond<S: StateAccess + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        max_gas: u64,
    ) -> Result<(), TransactionError> {
        let mut account = self.get_account(state, user_account)?;
        if account.balance < max_gas {
            return Err(TransactionError::InsufficientFunds);
        }
        let escrow_entry = EscrowEntry {
            account: user_account.to_vec(),
            amount: max_gas,
        };
        account.balance -= max_gas;
        let updates = &[
            (
                Self::account_key(user_account),
                codec::to_bytes_canonical(&account).map_err(TransactionError::Serialization)?,
            ),
            (
                Self::escrow_key(user_account),
                codec::to_bytes_canonical(&escrow_entry)
                    .map_err(TransactionError::Serialization)?,
            ),
        ];
        state.batch_set(updates).map_err(TransactionError::State)?;
        Ok(())
    }

    fn settle<S: StateAccess + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        gas_used: u64,
        _quality_score: f32,
    ) -> Result<(), TransactionError> {
        let escrow_key = Self::escrow_key(user_account);
        let escrow_bytes = state
            .get(&escrow_key)
            .map_err(TransactionError::State)?
            .ok_or(TransactionError::Invalid("No escrow found for user".into()))?;
        state.delete(&escrow_key).map_err(TransactionError::State)?;
        let escrow: EscrowEntry = codec::from_bytes_canonical(&escrow_bytes)
            .map_err(TransactionError::Deserialization)?;
        if gas_used > escrow.amount {
            return Err(TransactionError::Invalid(
                "gas_used exceeds bonded amount".to_string(),
            ));
        }
        let refund = escrow.amount - gas_used;
        let mut account = self.get_account(state, user_account)?;
        account.balance += refund;
        let account_bytes =
            codec::to_bytes_canonical(&account).map_err(TransactionError::Serialization)?;
        state
            .insert(&Self::account_key(user_account), &account_bytes)
            .map_err(TransactionError::State)?;
        Ok(())
    }
}
